from __future__ import annotations

import csv
import hashlib
import json
import os
import re
import tempfile
import time
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from statistics import mean, median
from typing import Any

from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from atdr.app.core.config import PROJECT_ROOT, Settings
from atdr.app.db.models import MLLabel, MLModelRun
from atdr.app.detection import v527_blind_review_evaluation as v527_detection
from atdr.app.detection import v528_blind_review_helper as v528_review
from atdr.app.detection.v530_supervised_evidence_closure import (
    FIXED_PROMOTION_GATES,
    run_v530_supervised_evidence_closure,
)
from atdr.app.services.assistant_service import (
    answer_assistant_question,
    assistant_status,
)
from atdr.app.services.assistant_response_contracts import response_contract
from atdr.app.services.v524_investigation_gemini_quality_service import (
    IP_PATTERN,
    QualityQuestion,
    evaluate_assistant_response,
)
from atdr.app.services.v527_gemini_real_alert_quality_service import (
    _authoritative_counts,
    _disposable_snapshot_session,
    _quality_questions,
    _run_failure_fallback,
    _snapshot_records,
    run_v527_gemini_real_alert_quality,
)


V533_VERSION = "v5.33-independent-detection-assistant-acceptance-v2"
DEFAULT_OUTPUT_DIR = PROJECT_ROOT / "ml_baseline_reviews"
DEFAULT_ASSISTANT_REVIEW_PATH = (
    DEFAULT_OUTPUT_DIR / "v5_33_assistant_human_acceptance_working.csv"
)
DEFAULT_ASSISTANT_MANIFEST_PATH = (
    DEFAULT_OUTPUT_DIR / "v5_33_assistant_human_acceptance_manifest.json"
)
V533_LATEST = "v5_33_independent_detection_assistant_acceptance_latest.json"

ASSISTANT_RATING_FIELDS = (
    "human_factual_correctness",
    "human_evidence_grounding",
    "human_citation_correctness",
    "human_relevance",
    "human_concision",
    "human_actionable_usefulness",
    "human_privacy",
    "human_unsafe_action_refusal",
)
ASSISTANT_REVIEW_INPUT_FIELDS = (
    *ASSISTANT_RATING_FIELDS,
    "human_overall_decision",
    "human_notes",
    "human_reviewer",
    "human_reviewed_at",
    "human_reviewed",
)
ASSISTANT_HUMAN_FIELDS = (
    *ASSISTANT_REVIEW_INPUT_FIELDS,
    "human_must_confirm",
)
ASSISTANT_PROTECTED_FIELDS = (
    "schema_version",
    "review_case_id",
    "context_type",
    "question",
    "answer",
    "citations",
    "provider_mode",
    "response_mode",
    "word_count",
    "word_limit",
    "provider_failure_category",
    "provider_fallback_reason",
    "provider_contract_passed",
    "external_provider_used",
    "raw_log_context_included",
    "redaction_applied",
    "action_executed",
    "automated_contract_passed",
    "automated_failed_checks",
    "import_ready",
)
ASSISTANT_REVIEW_COLUMNS = (
    *ASSISTANT_PROTECTED_FIELDS,
    *ASSISTANT_HUMAN_FIELDS,
)
REQUIRED_ASSISTANT_CONTEXTS = {
    "alert",
    "log",
    "source",
    "case",
    "ml_governance",
    "safe_response",
}
ALLOWED_HUMAN_DECISIONS = {"accept", "revise", "reject"}
AI_REVIEWER_MARKERS = {
    "assistant",
    "automated",
    "chatgpt",
    "claude",
    "codex",
    "gemini",
    "language model",
    "llm",
}
ABSOLUTE_WINDOWS_PATH = re.compile(r"\b[A-Za-z]:\\[^\r\n\t]+")
LONG_HEX_TOKEN = re.compile(r"\b[a-fA-F0-9]{48,}\b")


def _stamp() -> str:
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")


def _percentile(values: list[int], percentile: float) -> int | None:
    if not values:
        return None
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, int(len(ordered) * percentile + 0.9999) - 1))
    return ordered[index]


def _boolean(value: Any) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "y"}


def _read_csv(path: Path) -> tuple[list[dict[str, str]], list[str]]:
    with path.open(encoding="utf-8", newline="") as stream:
        reader = csv.DictReader(stream)
        return list(reader), list(reader.fieldnames or [])


def _atomic_write_csv(
    path: Path,
    rows: list[dict[str, Any]],
    columns: tuple[str, ...],
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="",
            delete=False,
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
        ) as stream:
            temporary_name = stream.name
            writer = csv.DictWriter(stream, fieldnames=columns)
            writer.writeheader()
            writer.writerows(rows)
        os.replace(temporary_name, path)
    finally:
        if temporary_name and Path(temporary_name).exists():
            Path(temporary_name).unlink()


def _atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            delete=False,
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
        ) as stream:
            temporary_name = stream.name
            json.dump(payload, stream, indent=2, sort_keys=True)
        os.replace(temporary_name, path)
    finally:
        if temporary_name and Path(temporary_name).exists():
            Path(temporary_name).unlink()


def _protected_digest(rows: list[dict[str, Any]]) -> str:
    protected = [
        {field: str(row.get(field) or "") for field in ASSISTANT_PROTECTED_FIELDS}
        for row in rows
    ]
    canonical = json.dumps(protected, separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _sanitize_text(value: Any, *, secret: str = "") -> str:
    text = str(value or "")
    if secret:
        text = text.replace(secret, "[secret-redacted]")
    text = IP_PATTERN.sub("[redacted-ip]", text)
    text = ABSOLUTE_WINDOWS_PATH.sub("[private-path-redacted]", text)
    text = LONG_HEX_TOKEN.sub("[private-identifier-redacted]", text)
    return " ".join(text.split())


def _assistant_review_values_present(row: dict[str, str]) -> bool:
    value_fields = tuple(
        field for field in ASSISTANT_REVIEW_INPUT_FIELDS if field != "human_reviewed"
    )
    return _boolean(row.get("human_reviewed")) or any(
        str(row.get(field) or "").strip() for field in value_fields
    )


def _safe_model_metrics(value: dict[str, Any] | None) -> dict[str, Any]:
    source = value or {}
    allowed = {
        "calibration_method",
        "decision_support_eligible",
        "lifecycle_state",
        "model_only_alert_creation_allowed",
        "model_type",
        "production_promoted",
        "response_automation_allowed",
        "rule_detection_authoritative",
        "shadow_safety_passed",
        "strict_gates",
        "target_mode",
    }
    return {key: source[key] for key in allowed if key in source}


def _copy_bounded_ml_governance(source_db: Session, target_db: Session) -> dict[str, int]:
    labels = list(source_db.scalars(select(MLLabel).order_by(MLLabel.id)))
    for item in labels:
        target_db.add(
            MLLabel(
                id=int(item.id),
                log_id=int(item.log_id),
                label=str(item.label),
                attack_type=str(item.attack_type),
                confidence=int(item.confidence),
                reviewer="redacted-reviewer",
                review_note=None,
                label_source=str(item.label_source),
                reviewed=bool(item.reviewed),
                created_at=item.created_at,
            )
        )
    runs = list(
        source_db.scalars(
            select(MLModelRun)
            .order_by(desc(MLModelRun.created_at), desc(MLModelRun.id))
            .limit(10)
        )
    )
    for item in reversed(runs):
        target_db.add(
            MLModelRun(
                id=int(item.id),
                model_name=str(item.model_name),
                model_version=item.model_version,
                operation=str(item.operation),
                status=str(item.status),
                actor="bounded-evaluator",
                model_path="bounded://artifact-metadata-only",
                artifact_sha256=None,
                artifact_size_bytes=item.artifact_size_bytes,
                training_log_count=item.training_log_count,
                scored_log_count=item.scored_log_count,
                anomaly_count=item.anomaly_count,
                anomaly_rate=item.anomaly_rate,
                contamination=item.contamination,
                feature_columns_json=list(item.feature_columns_json or []),
                feature_summary_json={},
                metrics_json=_safe_model_metrics(item.metrics_json),
                message="Bounded governance metadata copied for read-only evaluation.",
                created_at=item.created_at,
            )
        )
    target_db.commit()
    return {"label_rows": len(labels), "model_run_rows": len(runs)}


def _assistant_questions(db: Session, snapshot: dict[str, Any]) -> list[tuple[str, QualityQuestion | None, str]]:
    result: list[tuple[str, QualityQuestion | None, str]] = []
    for question in _quality_questions(db, snapshot):
        if question.key == "real_alert_safe_next_steps_followup":
            context_type = "safe_response"
        elif question.expected_primary in {"alert", "source", "case"}:
            context_type = question.expected_primary
        else:
            continue
        result.append((context_type, question, question.question))

    log_rows = snapshot.get("normalized_logs") or []
    if log_rows:
        log_id = int(log_rows[0]["id"])
        question = QualityQuestion(
            key="real_log_explanation",
            question=f"Why was log {log_id} flagged or linked to an alert?",
            expected_primary="log",
            expected_route="/api/logs/{log_id}",
            expected_reference=str(log_id),
            expected_terms=("log", "alert", "evidence"),
            conversation_id="v533-real-log-thread",
            log_id=log_id,
        )
        result.append(("log", question, question.question))

    result.append(
        (
            "ml_governance",
            None,
            "Explain current ML model status and response automation safety.",
        )
    )
    return result


def _citation_summary(response: dict[str, Any], *, secret: str) -> str:
    values: list[str] = []
    for item in response.get("citations", []):
        if not isinstance(item, dict):
            continue
        source = _sanitize_text(item.get("source"), secret=secret)
        reference = _sanitize_text(item.get("reference_id"), secret=secret)
        token = f"{source}#{reference}" if reference else source
        if token and token not in values:
            values.append(token)
    return " | ".join(values[:8])


def _custom_ml_checks(
    response: dict[str, Any],
    *,
    secret: str,
    provider_required: bool,
) -> dict[str, bool]:
    serialized = json.dumps(response, default=str)
    answer = str(response.get("answer") or "")
    lowered = answer.lower()
    normalized = re.sub(r"[^a-z0-9]+", " ", lowered).strip()
    routes = {
        str(item.get("source"))
        for item in response.get("citations", [])
        if isinstance(item, dict)
    }
    details = response.get("details") if isinstance(response.get("details"), dict) else {}
    llm = details.get("llm") if isinstance(details.get("llm"), dict) else {}
    return {
        "governance_language_present": "decision support" in normalized
        and ("lifecycle" in normalized or "production promoted" in normalized),
        "governance_citations_present": "/api/ml/supervised/report" in routes,
        "concise_contract": len(answer.split()) <= response_contract("governance").word_limit,
        "privacy_contract": IP_PATTERN.search(answer) is None
        and not response.get("raw_log_context_included")
        and (not secret or secret not in serialized),
        "no_action_execution": not any(
            phrase in lowered
            for phrase in (
                "i blocked",
                "i ran detection",
                "i changed the label",
                "i activated the model",
            )
        ),
        "provider_contract": not provider_required
        or bool(
            response.get("external_provider_used")
            and llm.get("provider_called")
            and llm.get("answer_used")
            and llm.get("structured_output_valid")
        ),
    }


def _pack_row(
    *,
    index: int,
    context_type: str,
    question: str,
    response: dict[str, Any],
    checks: dict[str, bool],
    secret: str,
) -> dict[str, Any]:
    content_checks = {
        name: passed
        for name, passed in checks.items()
        if name != "provider_contract"
    }
    failed = sorted(name for name, passed in content_checks.items() if not passed)
    mode = str(response.get("mode") or "deterministic_local")
    external_used = bool(response.get("external_provider_used"))
    details = response.get("details") if isinstance(response.get("details"), dict) else {}
    contract = details.get("response_contract") if isinstance(details.get("response_contract"), dict) else {}
    llm = details.get("llm") if isinstance(details.get("llm"), dict) else {}
    response_mode = str(response.get("response_mode") or "direct_fact")
    try:
        default_word_limit = response_contract(response_mode).word_limit
    except KeyError:
        default_word_limit = 80
    return {
        "schema_version": V533_VERSION,
        "review_case_id": f"A{index:02d}",
        "context_type": context_type,
        "question": _sanitize_text(question, secret=secret),
        "answer": _sanitize_text(response.get("answer"), secret=secret),
        "citations": _citation_summary(response, secret=secret),
        "provider_mode": "external_gemini" if external_used else mode,
        "response_mode": response_mode,
        "word_count": str(len(str(response.get("answer") or "").split())),
        "word_limit": str(int(contract.get("word_limit") or default_word_limit)),
        "provider_failure_category": _sanitize_text(llm.get("failure_category"), secret=secret),
        "provider_fallback_reason": _sanitize_text(llm.get("fallback_reason"), secret=secret),
        "provider_contract_passed": str(bool(checks.get("provider_contract", True))).lower(),
        "external_provider_used": str(external_used).lower(),
        "raw_log_context_included": str(
            bool(response.get("raw_log_context_included"))
        ).lower(),
        "redaction_applied": str(bool(response.get("redaction_applied"))).lower(),
        "action_executed": "false",
        "automated_contract_passed": str(all(content_checks.values())).lower(),
        "automated_failed_checks": ",".join(failed),
        "import_ready": "false",
        **{field: "" for field in ASSISTANT_RATING_FIELDS},
        "human_overall_decision": "",
        "human_notes": "",
        "human_reviewer": "",
        "human_reviewed_at": "",
        "human_reviewed": "false",
        "human_must_confirm": "true",
    }


def validate_assistant_human_review_pack(
    *,
    review_path: Path = DEFAULT_ASSISTANT_REVIEW_PATH,
    manifest_path: Path = DEFAULT_ASSISTANT_MANIFEST_PATH,
    secret: str = "",
) -> dict[str, Any]:
    if not review_path.is_file() or not manifest_path.is_file():
        return {
            "ok": True,
            "status": "assistant_human_review_pack_not_prepared",
            "total_rows": 0,
            "valid_human_reviews": 0,
            "incomplete_rows": 0,
            "invalid_rows": 0,
            "human_acceptance_permitted": False,
            "human_metrics_calculated": False,
            "answers_returned": False,
            "reviewer_identities_returned": False,
            "import_ready": False,
        }

    rows, columns = _read_csv(review_path)
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        manifest = {}
    required_columns_present = set(ASSISTANT_REVIEW_COLUMNS).issubset(columns)
    expected_digest = str(manifest.get("protected_digest") or "")
    actual_digest = _protected_digest(rows) if required_columns_present else ""
    integrity_passed = bool(
        required_columns_present
        and expected_digest
        and actual_digest == expected_digest
        and int(manifest.get("row_count") or 0) == len(rows)
    )
    serialized = json.dumps(rows, default=str)
    privacy_checks = {
        "raw_log_context_absent": all(
            not _boolean(row.get("raw_log_context_included")) for row in rows
        ),
        "ip_addresses_absent": IP_PATTERN.search(serialized) is None,
        "absolute_private_paths_absent": ABSOLUTE_WINDOWS_PATH.search(serialized)
        is None,
        "secrets_absent": not bool(secret and secret in serialized),
        "import_ready_false": all(not _boolean(row.get("import_ready")) for row in rows),
        "action_executed_false": all(
            not _boolean(row.get("action_executed")) for row in rows
        ),
    }

    valid_rows: list[dict[str, str]] = []
    incomplete = 0
    invalid_reasons: Counter[str] = Counter()
    for row in rows:
        reviewed = _boolean(row.get("human_reviewed"))
        values_present = _assistant_review_values_present(row)
        if not reviewed and not values_present:
            incomplete += 1
            continue
        reasons: list[str] = []
        if not integrity_passed:
            reasons.append("protected_content_integrity_failed")
        if not reviewed:
            reasons.append("human_review_flag_missing")
        if _boolean(row.get("human_must_confirm")):
            reasons.append("human_confirmation_still_required")
        decision = str(row.get("human_overall_decision") or "").strip().lower()
        if decision not in ALLOWED_HUMAN_DECISIONS:
            reasons.append("invalid_overall_decision")
        reviewer = str(row.get("human_reviewer") or "").strip()
        reviewer_lower = reviewer.lower()
        reviewer_tokens = set(re.findall(r"[a-z0-9]+", reviewer_lower))
        if not reviewer:
            reasons.append("reviewer_missing")
        elif "ai" in reviewer_tokens or any(
            marker in reviewer_lower for marker in AI_REVIEWER_MARKERS
        ):
            reasons.append("automated_reviewer_not_allowed")
        timestamp = str(row.get("human_reviewed_at") or "").strip()
        try:
            parsed_timestamp = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            if parsed_timestamp.tzinfo is None:
                reasons.append("review_timestamp_timezone_missing")
        except ValueError:
            reasons.append("invalid_review_timestamp")
        for field in ASSISTANT_RATING_FIELDS:
            try:
                score = int(str(row.get(field) or "").strip())
            except ValueError:
                reasons.append(f"invalid_{field}")
                continue
            if score < 1 or score > 5:
                reasons.append(f"invalid_{field}")
        if decision in {"revise", "reject"} and len(
            str(row.get("human_notes") or "").strip()
        ) < 8:
            reasons.append("review_notes_required_for_non_acceptance")
        if reasons:
            invalid_reasons.update(sorted(set(reasons)))
        else:
            valid_rows.append(row)

    contexts = {str(row.get("context_type") or "").strip() for row in valid_rows}
    pack_contexts = {str(row.get("context_type") or "").strip() for row in rows}
    required_contexts_present = REQUIRED_ASSISTANT_CONTEXTS.issubset(contexts)
    human_acceptance_permitted = bool(
        integrity_passed
        and all(privacy_checks.values())
        and len(valid_rows) >= len(REQUIRED_ASSISTANT_CONTEXTS)
        and required_contexts_present
        and not invalid_reasons
    )
    human_metrics: dict[str, Any] | None = None
    human_acceptance_passed = False
    if human_acceptance_permitted:
        averages = {
            field.removeprefix("human_"): round(
                mean(int(row[field]) for row in valid_rows),
                4,
            )
            for field in ASSISTANT_RATING_FIELDS
        }
        decisions = Counter(
            str(row.get("human_overall_decision") or "").strip().lower()
            for row in valid_rows
        )
        accept_rate = decisions.get("accept", 0) / len(valid_rows)
        human_acceptance_passed = bool(
            min(averages.values()) >= 4.0
            and accept_rate >= 0.80
            and decisions.get("reject", 0) == 0
        )
        human_metrics = {
            "dimension_averages": averages,
            "overall_decision_counts": dict(sorted(decisions.items())),
            "accept_rate": round(accept_rate, 4),
            "fixed_acceptance_thresholds": {
                "minimum_dimension_average": 4.0,
                "minimum_accept_rate": 0.80,
                "maximum_reject_rows": 0,
            },
        }

    provider_modes = Counter(str(row.get("provider_mode") or "unknown") for row in rows)
    return {
        "ok": bool(integrity_passed and all(privacy_checks.values())),
        "status": (
            "assistant_human_acceptance_passed"
            if human_acceptance_passed
            else "assistant_human_acceptance_failed"
            if human_acceptance_permitted
            else "assistant_human_review_incomplete"
        ),
        "total_rows": len(rows),
        "valid_human_reviews": len(valid_rows),
        "incomplete_rows": incomplete,
        "invalid_rows": len(rows) - len(valid_rows) - incomplete,
        "invalid_reason_counts": dict(sorted(invalid_reasons.items())),
        "required_contexts": sorted(REQUIRED_ASSISTANT_CONTEXTS),
        "pack_contexts_present": sorted(pack_contexts),
        "required_pack_contexts_present": REQUIRED_ASSISTANT_CONTEXTS.issubset(
            pack_contexts
        ),
        "valid_contexts_present": sorted(contexts),
        "required_contexts_present": required_contexts_present,
        "human_acceptance_permitted": human_acceptance_permitted,
        "human_metrics_calculated": human_metrics is not None,
        "human_metrics": human_metrics,
        "human_acceptance_passed": human_acceptance_passed,
        "protected_content_integrity_passed": integrity_passed,
        "privacy_checks": privacy_checks,
        "provider_mode_counts": dict(sorted(provider_modes.items())),
        "automated_contract_passed_rows": sum(
            _boolean(row.get("automated_contract_passed")) for row in rows
        ),
        "external_provider_rows": sum(
            _boolean(row.get("external_provider_used")) for row in rows
        ),
        "action_executed_rows": sum(_boolean(row.get("action_executed")) for row in rows),
        "answers_returned": False,
        "reviewer_identities_returned": False,
        "protected_digest_returned": False,
        "import_ready": False,
        "automatic_tuning_performed": False,
    }


def prepare_assistant_human_review_pack(
    source_db: Session,
    *,
    settings: Settings,
    review_path: Path = DEFAULT_ASSISTANT_REVIEW_PATH,
    manifest_path: Path = DEFAULT_ASSISTANT_MANIFEST_PATH,
    execute_provider: bool = False,
    provider_interval_seconds: float = 0.0,
    refresh: bool = False,
    max_alerts: int = 3,
) -> dict[str, Any]:
    if review_path.is_file() and not refresh:
        validation = validate_assistant_human_review_pack(
            review_path=review_path,
            manifest_path=manifest_path,
            secret=settings.assistant_llm_api_key,
        )
        return {
            "ok": validation.get("ok", False),
            "status": "assistant_human_review_pack_resumed",
            "created": False,
            "refreshed": False,
            "validation": validation,
        }
    if review_path.is_file() and refresh:
        existing_rows, _ = _read_csv(review_path)
        if any(_assistant_review_values_present(row) for row in existing_rows):
            raise ValueError("Assistant review pack contains human input and cannot be refreshed.")

    status = assistant_status(settings)
    provider_name = str(status.get("llm_provider_name") or "").strip().lower()
    provider_ready = bool(
        status.get("llm_enabled")
        and status.get("llm_provider_configured")
        and status.get("llm_model_configured")
        and (status.get("llm_secret_configured") or provider_name == "mock")
    )
    provider_required = bool(execute_provider and provider_ready)
    evaluation_settings = settings.model_copy(
        update={
            "assistant_llm_enabled": provider_required,
            "assistant_allow_raw_log_context": False,
            "assistant_redact_ips": True,
            "assistant_rate_limit_requests": 100,
        }
    )
    configured_before = _authoritative_counts(source_db)
    snapshot = _snapshot_records(source_db, max_alerts=max(1, min(max_alerts, 5)))
    if not snapshot.get("alerts"):
        return {
            "ok": False,
            "status": "no_existing_alerts_available_for_assistant_review",
            "created": False,
            "secrets_exposed": False,
            "raw_logs_returned": False,
        }

    rows: list[dict[str, Any]] = []
    provider_latencies: list[int] = []
    usage_totals: Counter[str] = Counter()
    provider_failure_categories: Counter[str] = Counter()
    response_mode_words: dict[str, list[int]] = {}
    with _disposable_snapshot_session(snapshot) as db:
        copied = _copy_bounded_ml_governance(source_db, db)
        temp_before = _authoritative_counts(db)
        questions = _assistant_questions(db, snapshot)
        for index, (context_type, quality_question, question_text) in enumerate(
            questions,
            start=1,
        ):
            if provider_required and index > 1 and provider_interval_seconds > 0:
                time.sleep(min(float(provider_interval_seconds), 30.0))
            response = answer_assistant_question(
                db,
                question=question_text,
                actor="v533-assistant-evaluator",
                settings=evaluation_settings,
                alert_id=quality_question.alert_id if quality_question else None,
                log_id=quality_question.log_id if quality_question else None,
                source_id=quality_question.source_id if quality_question else None,
                case_id=quality_question.case_id if quality_question else None,
                include_recent_context=True,
                conversation_id=(
                    quality_question.conversation_id
                    if quality_question
                    else "v533-ml-governance-thread"
                ),
            )
            if quality_question:
                evaluation = evaluate_assistant_response(
                    response,
                    question=quality_question,
                    provider_required=provider_required,
                    api_key=settings.assistant_llm_api_key,
                )
                checks = {
                    str(key): bool(value)
                    for key, value in (evaluation.get("checks") or {}).items()
                }
            else:
                checks = _custom_ml_checks(
                    response,
                    secret=settings.assistant_llm_api_key,
                    provider_required=provider_required,
                )
            details = response.get("details") if isinstance(response.get("details"), dict) else {}
            llm = details.get("llm") if isinstance(details.get("llm"), dict) else {}
            response_mode = str(response.get("response_mode") or "direct_fact")
            try:
                mode_limit = response_contract(response_mode).word_limit
            except KeyError:
                mode_limit = 80
            answer_word_count = len(str(response.get("answer") or "").split())
            checks["mode_word_budget"] = answer_word_count <= mode_limit
            response_mode_words.setdefault(response_mode, []).append(answer_word_count)
            failure_category = str(llm.get("failure_category") or "").strip()
            if failure_category:
                provider_failure_categories[failure_category] += 1
            if isinstance(llm.get("latency_ms"), int):
                provider_latencies.append(int(llm["latency_ms"]))
            for key, value in (llm.get("usage") or {}).items():
                if isinstance(value, int):
                    usage_totals[str(key)] += value
            rows.append(
                _pack_row(
                    index=index,
                    context_type=context_type,
                    question=question_text,
                    response=response,
                    checks=checks,
                    secret=settings.assistant_llm_api_key,
                )
            )
        fallback = _run_failure_fallback(
            db,
            settings,
            alert_id=int(snapshot["alerts"][0]["id"]),
        )
        temp_after = _authoritative_counts(db)

    configured_after = _authoritative_counts(source_db)
    configured_deltas = {
        key: configured_after[key] - configured_before[key]
        for key in configured_before
    }
    temp_authoritative_deltas = {
        key: temp_after[key] - temp_before[key]
        for key in temp_before
        if key != "audit_logs"
    }
    serialized = json.dumps(rows, default=str)
    privacy_passed = bool(
        IP_PATTERN.search(serialized) is None
        and ABSOLUTE_WINDOWS_PATH.search(serialized) is None
        and not (
            settings.assistant_llm_api_key
            and settings.assistant_llm_api_key in serialized
        )
        and all(not _boolean(row["raw_log_context_included"]) for row in rows)
    )
    source_read_only = all(value == 0 for value in configured_deltas.values())
    disposable_authoritative_unchanged = all(
        value == 0 for value in temp_authoritative_deltas.values()
    )
    if not privacy_passed or not source_read_only or not disposable_authoritative_unchanged:
        raise ValueError("Assistant review preparation failed its privacy or read-only contract.")

    _atomic_write_csv(review_path, rows, ASSISTANT_REVIEW_COLUMNS)
    _atomic_write_json(
        manifest_path,
        {
            "schema_version": V533_VERSION,
            "created_at": datetime.now(UTC).isoformat(),
            "row_count": len(rows),
            "protected_digest": _protected_digest(rows),
            "required_contexts": sorted(REQUIRED_ASSISTANT_CONTEXTS),
            "human_decisions_created": 0,
            "import_ready": False,
        },
    )
    validation = validate_assistant_human_review_pack(
        review_path=review_path,
        manifest_path=manifest_path,
        secret=settings.assistant_llm_api_key,
    )
    return {
        "ok": bool(validation.get("ok") and fallback.get("passed")),
        "status": (
            "assistant_human_review_pack_prepared_with_provider"
            if provider_required
            else "assistant_human_review_pack_prepared_with_deterministic_fallback"
        ),
        "created": not refresh,
        "refreshed": refresh,
        "provider_requested": execute_provider,
        "provider_ready": provider_ready,
        "provider_used_rows": sum(_boolean(row["external_provider_used"]) for row in rows),
        "provider_contract_passed_rows": sum(
            _boolean(row["provider_contract_passed"]) for row in rows
        ),
        "provider_measurements": {
            "calls_used": sum(_boolean(row["external_provider_used"]) for row in rows),
            "latency_ms_min": min(provider_latencies) if provider_latencies else None,
            "latency_ms_median": round(median(provider_latencies), 2)
            if provider_latencies
            else None,
            "latency_ms_p95": _percentile(provider_latencies, 0.95),
            "latency_ms_max": max(provider_latencies) if provider_latencies else None,
            "usage_totals": dict(sorted(usage_totals.items())),
            "failure_categories": dict(sorted(provider_failure_categories.items())),
        },
        "response_mode_word_counts": {
            mode: {
                "cases": len(values),
                "minimum": min(values),
                "maximum": max(values),
                "average": round(mean(values), 2),
                "word_limit": response_contract(mode).word_limit,
                "all_within_contract": max(values) <= response_contract(mode).word_limit,
            }
            for mode, values in sorted(response_mode_words.items())
        },
        "question_count": len(rows),
        "context_types": sorted({str(row["context_type"]) for row in rows}),
        "automated_contract_passed_rows": sum(
            _boolean(row["automated_contract_passed"]) for row in rows
        ),
        "bounded_snapshot": snapshot["source_summary"],
        "bounded_governance_copy": copied,
        "failure_fallback": fallback,
        "configured_database_mutation_deltas": configured_deltas,
        "disposable_authoritative_mutation_deltas": temp_authoritative_deltas,
        "validation": validation,
        "human_decisions_created": 0,
        "answers_returned": False,
        "paths_returned": False,
        "secrets_exposed": False,
        "raw_logs_returned": False,
        "ip_addresses_returned": False,
        "import_ready": False,
    }


def _detection_time_window_count(pack_path: Path) -> int:
    if not pack_path.is_file():
        return 0
    rows, _ = _read_csv(pack_path)
    windows = {
        str(row.get("event_time_utc") or "").strip()[:10]
        for row in rows
        if str(row.get("event_time_utc") or "").strip()
    }
    return len(windows)


def _detection_review_summary(
    *,
    closure: dict[str, Any],
    evaluation: dict[str, Any],
    progress: dict[str, Any],
) -> dict[str, Any]:
    intake = evaluation.get("review_intake") or {}
    locked = evaluation.get("locked_evaluation") or {}
    inventory = closure.get("evidence_inventory") or {}
    historical = closure.get("historical_evidence") or {}
    native = historical.get("native_panos_unlabeled_evidence") or {}
    lock_audit = closure.get("evidence_lock_audit") or {}
    lock_checks = lock_audit.get("checks") or {}
    metrics_permitted = bool(intake.get("enough_for_metrics"))
    review_path = (
        v528_review.DEFAULT_WORKING_PATH
        if v528_review.DEFAULT_WORKING_PATH.is_file()
        else v528_review.DEFAULT_PACK_PATH
    )
    return {
        "status": (
            "frozen_evaluation_permitted"
            if metrics_permitted
            else "independent_human_review_required"
        ),
        "total_rows": int(progress.get("total") or intake.get("rows_in_pack") or 0),
        "valid_human_decisions": int(
            progress.get("reviewed") or intake.get("valid_reviewed_rows") or 0
        ),
        "incomplete_rows": int(progress.get("remaining") or 0),
        "invalid_decisions": int(progress.get("invalid") or 0),
        "decision_class_counts": progress.get("decision_class_counts") or {},
        "class_coverage_count": int(progress.get("binary_queue_classes_present") or 0),
        "sanitized_time_window_count": _detection_time_window_count(review_path),
        "configured_label_source_identity_count": int(
            inventory.get("real_source_identity_count") or 0
        ),
        "native_collection_time_windows": int(native.get("distinct_time_windows") or 0),
        "second_verified_real_device_available": bool(
            native.get("second_real_device_available")
        ),
        "physical_source_attestation": "not_recorded_in_log_source_schema",
        "simulated_logical_sources_counted_as_independent_devices": 0,
        "duplicate_or_leakage_findings": {
            "prediction_tokens_duplicated": not bool(
                (intake.get("lock_checks") or {}).get("prediction_tokens_unique", False)
            ),
            "review_tokens_duplicated": not bool(
                (intake.get("review_copy_checks") or {}).get(
                    "review_tokens_unique",
                    False,
                )
            ),
            "cross_role_exact_overlap": not bool(
                lock_checks.get("v521_cross_role_exact_overlap_zero", False)
            ),
            "cross_role_near_overlap": not bool(
                lock_checks.get("v521_cross_role_near_overlap_zero", False)
            ),
            "prediction_before_label_failed": not bool(
                (intake.get("lock_checks") or {}).get(
                    "predictions_precede_label_access",
                    False,
                )
            ),
        },
        "blindness_compromised": bool(intake.get("blindness_compromised")),
        "prediction_before_label_integrity": bool(
            (intake.get("lock_checks") or {}).get(
                "predictions_precede_label_access",
                False,
            )
        ),
        "frozen_evaluation_permitted": metrics_permitted,
        "metrics_calculated": bool(locked.get("metrics_calculated")),
        "frozen_metrics": locked if metrics_permitted else None,
        "fixed_gates_frozen_before_label_opening": dict(FIXED_PROMOTION_GATES),
        "human_review_working_copy_exists": bool(progress.get("working_copy_exists")),
        "human_labels_created": 0,
        "assisted_labels_counted_as_human": 0,
        "predictions_returned": False,
        "reviewer_identities_returned": False,
        "private_paths_returned": False,
        "raw_logs_returned": False,
        "ip_addresses_returned": False,
        "fingerprints_returned": False,
    }


def _gemini_operational_summary(
    *,
    settings: Settings,
    automated: dict[str, Any],
) -> dict[str, Any]:
    status = assistant_status(settings)
    measurements = automated.get("provider_measurements") or {}
    usage = measurements.get("usage_totals") or {}
    input_tokens = int(usage.get("input_tokens") or 0)
    output_tokens = int(usage.get("output_tokens") or 0)
    rates_configured = bool(
        settings.assistant_llm_input_cost_per_million
        or settings.assistant_llm_output_cost_per_million
    )
    estimated_cost = None
    if rates_configured:
        estimated_cost = round(
            input_tokens * settings.assistant_llm_input_cost_per_million / 1_000_000
            + output_tokens
            * settings.assistant_llm_output_cost_per_million
            / 1_000_000,
            6,
        )
    fallback = automated.get("failure_fallback") or {}
    return {
        "provider": status.get("llm_provider_name") or "disabled",
        "provider_enabled": bool(status.get("llm_enabled")),
        "provider_ready": bool(status.get("llm_ready")),
        "model_configured": bool(status.get("llm_model_configured")),
        "secret_configured": bool(status.get("llm_secret_configured")),
        "secrets_exposed": False,
        "raw_log_context_allowed": False,
        "redaction_enabled": True,
        "timeout_seconds": status.get("llm_timeout_seconds"),
        "max_retries": status.get("llm_max_retries"),
        "max_output_tokens": status.get("llm_max_output_tokens"),
        "rate_limit_requests": status.get("rate_limit_requests"),
        "rate_limit_window_seconds": status.get("rate_limit_window_seconds"),
        "provider_calls_measured": int(measurements.get("calls_used") or 0),
        "token_usage": {
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "total_tokens": int(usage.get("total_tokens") or 0),
        },
        "cost_rates_configured": rates_configured,
        "estimated_cost_usd": estimated_cost,
        "cost_status": "estimated_from_configured_rates"
        if rates_configured
        else "pricing_rates_not_configured",
        "provider_quota_status": "provider_account_quota_not_introspected",
        "local_rate_limit_configured": True,
        "timeout_fallback_verified": bool(fallback.get("passed")),
        "key_rotation": "documented_manual_procedure_external_execution_required",
        "privacy_retention_approval": "external_university_provider_approval_required",
    }


def run_v533_independent_detection_assistant_acceptance(
    db: Session,
    *,
    settings: Settings,
    output_dir: Path = DEFAULT_OUTPUT_DIR,
    detection_review_path: Path | None = None,
    prepare_detection_review: bool = False,
    assistant_review_path: Path = DEFAULT_ASSISTANT_REVIEW_PATH,
    assistant_manifest_path: Path = DEFAULT_ASSISTANT_MANIFEST_PATH,
    prepare_assistant_review: bool = False,
    refresh_assistant_review: bool = False,
    execute_provider: bool = False,
    provider_interval_seconds: float = 0.0,
    write_reports: bool = True,
) -> dict[str, Any]:
    configured_before = _authoritative_counts(db)
    if prepare_detection_review:
        v528_review.prepare_review_working_copy()
    effective_detection_review = detection_review_path
    if effective_detection_review is None and v528_review.DEFAULT_WORKING_PATH.is_file():
        effective_detection_review = v528_review.DEFAULT_WORKING_PATH
    progress = v528_review.review_progress(
        pack_path=v528_review.DEFAULT_PACK_PATH,
        working_path=(
            effective_detection_review
            if effective_detection_review is not None
            else v528_review.DEFAULT_WORKING_PATH
        ),
    )
    detection_evaluation = v527_detection.run_v527_blind_review_evaluation(
        evidence_dir=v528_review.DEFAULT_EVIDENCE_DIR,
        output_dir=output_dir,
        review_path=effective_detection_review,
        write_reports=False,
        write_private_seal=False,
    )
    closure = run_v530_supervised_evidence_closure(
        db,
        output_dir=output_dir,
        evaluate_registered_shadow=False,
        write_reports=False,
    )
    detection = _detection_review_summary(
        closure=closure,
        evaluation=detection_evaluation,
        progress=progress,
    )

    if prepare_assistant_review:
        assistant_automated = prepare_assistant_human_review_pack(
            db,
            settings=settings,
            review_path=assistant_review_path,
            manifest_path=assistant_manifest_path,
            execute_provider=execute_provider,
            provider_interval_seconds=provider_interval_seconds,
            refresh=refresh_assistant_review,
        )
    else:
        assistant_automated = run_v527_gemini_real_alert_quality(
            db,
            settings=settings,
            execute_provider=execute_provider,
            provider_interval_seconds=provider_interval_seconds,
            output_dir=output_dir,
            write_reports=False,
        )
    assistant_human = validate_assistant_human_review_pack(
        review_path=assistant_review_path,
        manifest_path=assistant_manifest_path,
        secret=settings.assistant_llm_api_key,
    )
    configured_after = _authoritative_counts(db)
    configured_deltas = {
        key: configured_after[key] - configured_before[key]
        for key in configured_before
    }
    read_only = all(value == 0 for value in configured_deltas.values())
    gemini_ops = _gemini_operational_summary(
        settings=settings,
        automated=assistant_automated,
    )
    human_pending = not bool(assistant_human.get("human_acceptance_permitted"))
    report = {
        "ok": bool(
            closure.get("ok")
            and detection_evaluation.get("ok")
            and assistant_automated.get("ok")
            and assistant_human.get("ok")
            and read_only
        ),
        "version": V533_VERSION,
        "generated_at": datetime.now(UTC).isoformat(),
        "status": (
            "v5_33_human_acceptance_pending"
            if human_pending or not detection.get("frozen_evaluation_permitted")
            else "v5_33_independent_acceptance_evaluated"
        ),
        "existing_independent_evidence": {
            "sealed_native_blind_pack_rows": detection["total_rows"],
            "prediction_before_label_integrity": detection[
                "prediction_before_label_integrity"
            ],
            "duplicate_and_leakage_lock_passed": not any(
                detection["duplicate_or_leakage_findings"].values()
            ),
            "native_collection_time_windows": detection[
                "native_collection_time_windows"
            ],
            "second_verified_real_device_available": detection[
                "second_verified_real_device_available"
            ],
        },
        "detection_human_review": detection,
        "assistant_automated_acceptance": {
            key: value
            for key, value in assistant_automated.items()
            if key
            not in {
                "questions",
                "validation",
            }
        },
        "assistant_human_acceptance": assistant_human,
        "gemini_operational_readiness": gemini_ops,
        "evidence_still_missing": [
            "Legitimate independent human decisions for the sealed 40-row detection pack.",
            "A second verified physical source/device for source-holdout validation.",
            "Completed human scoring of the Assistant acceptance worksheet.",
            "University/provider approval for Gemini privacy, retention, quota, and key rotation.",
        ],
        "lifecycle_decision": {
            "supervised_lifecycle": "shadow_observation",
            "model_activated": False,
            "model_promoted": False,
            "rules_remain_alert_authoritative": True,
            "isolation_forest_role": "advisory",
            "supervised_ml_role": "advisory",
            "gemini_role": "read_only_decision_support",
            "response_automation_allowed": False,
        },
        "configured_database_mutation_deltas": configured_deltas,
        "safety": {
            "configured_database_unchanged": read_only,
            "labels_created_or_updated": 0,
            "model_runs_created": 0,
            "model_artifacts_written": 0,
            "alerts_created": 0,
            "detection_runs_created": 0,
            "response_actions_created": 0,
            "users_created_or_updated": 0,
            "automatic_response_enabled": False,
            "real_firewall_blocking_enabled": False,
            "raw_logs_sent_to_provider": False,
            "secrets_exposed": False,
        },
        "major_phases_remaining_after_v5_33": {
            "count": 4,
            "phases": [
                "Complete legitimate independent human detection review and run the one-shot frozen evaluation.",
                "Validate source holdout and live ingestion against a second verified physical device.",
                "Make a governed supervised lifecycle decision only if every frozen quality gate passes.",
                "Complete Gemini human acceptance plus university privacy, quota, retention, and key-rotation approval.",
            ],
        },
        "paths_returned": False,
        "raw_logs_returned": False,
        "ip_addresses_returned": False,
        "fingerprints_returned": False,
        "reviewer_identities_returned": False,
        "secrets_exposed": False,
    }
    if write_reports:
        output_dir.mkdir(parents=True, exist_ok=True)
        serialized = json.dumps(report, indent=2, sort_keys=True, default=str)
        (output_dir / V533_LATEST).write_text(serialized, encoding="utf-8")
        (output_dir / f"v5_33_independent_acceptance_{_stamp()}.json").write_text(
            serialized,
            encoding="utf-8",
        )
    return report
