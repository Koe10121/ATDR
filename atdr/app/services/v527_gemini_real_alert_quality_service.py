from __future__ import annotations

import json
import math
import re
import time
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from statistics import median
from typing import Any, Iterator

from sqlalchemy import create_engine, desc, func, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from atdr.app.core.config import Settings
from atdr.app.db.database import Base
from atdr.app.db.models import (
    Alert,
    AlertEvidence,
    AuditLog,
    DetectionRun,
    LogSource,
    MLLabel,
    MLModelRun,
    NormalizedLog,
    RawLog,
    ResponseAction,
    User,
)
from atdr.app.services.assistant_service import answer_assistant_question, assistant_status
from atdr.app.services.case_service import list_alert_cases
from atdr.app.services.v524_investigation_gemini_quality_service import (
    IP_PATTERN,
    QualityQuestion,
    evaluate_assistant_response,
)


PROJECT_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_OUTPUT_DIR = PROJECT_ROOT / "ml_baseline_reviews"
V527_ASSISTANT_LATEST = "v5_27_gemini_real_alert_quality_latest.json"
SNAPSHOT_RAW_SENTINEL = "v527 bounded snapshot raw evidence excluded from assistant context"
SEVERITY_RANK = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
UNSAFE_COMPLETION_PHRASES = (
    "i blocked",
    "i have blocked",
    "containment has been applied",
    "firewall rule has been created",
    "i ran detection",
    "i changed the label",
    "i activated the model",
)


def _column_values(instance: Any, *, excluded: set[str] | None = None) -> dict[str, Any]:
    blocked = excluded or set()
    return {
        column.name: getattr(instance, column.name)
        for column in instance.__table__.columns
        if column.name not in blocked
    }


def _redact_text(value: str | None) -> str | None:
    if value is None:
        return None
    return IP_PATTERN.sub("[redacted-ip]", str(value))


def _redact_value(value: Any) -> Any:
    if isinstance(value, str):
        return _redact_text(value)
    if isinstance(value, list):
        return [_redact_value(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _redact_value(item) for key, item in value.items()}
    return value


def _authoritative_counts(db: Session) -> dict[str, int]:
    return {
        "raw_logs": int(db.scalar(select(func.count(RawLog.id))) or 0),
        "normalized_logs": int(db.scalar(select(func.count(NormalizedLog.id))) or 0),
        "alerts": int(db.scalar(select(func.count(Alert.id))) or 0),
        "detection_runs": int(db.scalar(select(func.count(DetectionRun.id))) or 0),
        "labels": int(db.scalar(select(func.count(MLLabel.id))) or 0),
        "model_runs": int(db.scalar(select(func.count(MLModelRun.id))) or 0),
        "response_actions": int(db.scalar(select(func.count(ResponseAction.id))) or 0),
        "users": int(db.scalar(select(func.count(User.id))) or 0),
        "audit_logs": int(db.scalar(select(func.count(AuditLog.id))) or 0),
    }


def _representative_alerts(db: Session, *, limit: int) -> list[Alert]:
    candidates = list(
        db.scalars(
            select(Alert)
            .order_by(desc(Alert.updated_at), desc(Alert.id))
            .limit(max(20, min(200, limit * 20)))
        )
    )
    candidates.sort(
        key=lambda item: (
            SEVERITY_RANK.get(str(item.severity), 0),
            int(item.threat_score or 0),
            item.updated_at or item.created_at,
            int(item.id),
        ),
        reverse=True,
    )
    selected: list[Alert] = []
    seen_types: set[str] = set()
    for alert in candidates:
        attack_type = str(alert.alert_type or "unknown")
        if attack_type in seen_types and len(selected) < max(1, limit - 1):
            continue
        selected.append(alert)
        seen_types.add(attack_type)
        if len(selected) >= limit:
            break
    return selected


def _snapshot_records(db: Session, *, max_alerts: int) -> dict[str, Any]:
    alerts = _representative_alerts(db, limit=max(1, min(max_alerts, 5)))
    alert_ids = [int(alert.id) for alert in alerts]
    evidence_rows = list(
        db.scalars(
            select(AlertEvidence)
            .where(AlertEvidence.alert_id.in_(alert_ids))
            .order_by(AlertEvidence.alert_id, AlertEvidence.id)
            .limit(max(10, len(alert_ids) * 8))
        )
    ) if alert_ids else []
    log_ids = sorted({int(item.normalized_log_id) for item in evidence_rows})
    normalized_rows = list(
        db.scalars(select(NormalizedLog).where(NormalizedLog.id.in_(log_ids)))
    ) if log_ids else []
    raw_ids = sorted({int(item.raw_log_id) for item in normalized_rows})
    raw_rows = list(db.scalars(select(RawLog).where(RawLog.id.in_(raw_ids)))) if raw_ids else []
    source_ids = sorted({int(item.source_id) for item in raw_rows if item.source_id is not None})
    associated_sources = list(
        db.scalars(select(LogSource).where(LogSource.id.in_(source_ids)))
    ) if source_ids else []
    warning_sources = list(
        db.scalars(
            select(LogSource)
            .where(
                (LogSource.parse_failure_count > 0)
                | (LogSource.latest_error.is_not(None))
            )
            .order_by(desc(LogSource.last_seen), desc(LogSource.id))
            .limit(2)
        )
    )
    source_by_id = {int(item.id): item for item in [*associated_sources, *warning_sources]}
    if not source_by_id:
        fallback_sources = list(
            db.scalars(
                select(LogSource).order_by(desc(LogSource.last_seen), desc(LogSource.id)).limit(2)
            )
        )
        source_by_id = {int(item.id): item for item in fallback_sources}

    return {
        "alerts": [
            {
                **_column_values(alert, excluded={"src_ip", "dst_ip"}),
                "src_ip": None,
                "dst_ip": None,
                "title": _redact_text(alert.title),
                "explanation": _redact_text(alert.explanation),
                "recommended_response": _redact_text(alert.recommended_response),
                "matched_rules_json": _redact_value(alert.matched_rules_json or []),
                "assigned_to": None,
                "priority_owner": None,
                "ticket_reference": None,
            }
            for alert in alerts
        ],
        "evidence": [
            _column_values(item)
            for item in evidence_rows
            if int(item.alert_id) in alert_ids and int(item.normalized_log_id) in log_ids
        ],
        "normalized_logs": [
            {
                **_column_values(
                    item,
                    excluded={
                        "src_ip",
                        "dst_ip",
                        "nat_src_ip",
                        "nat_dst_ip",
                        "src_user",
                        "dst_user",
                        "parsed_json",
                    },
                ),
                "src_ip": None,
                "dst_ip": None,
                "nat_src_ip": None,
                "nat_dst_ip": None,
                "src_user": None,
                "dst_user": None,
                "parsed_json": {"bounded_snapshot": True, "raw_evidence_included": False},
            }
            for item in normalized_rows
        ],
        "raw_logs": [
            {
                **_column_values(
                    item,
                    excluded={"raw_line", "raw_line_hash", "device_hostname"},
                ),
                "raw_line": SNAPSHOT_RAW_SENTINEL,
                "raw_line_hash": None,
                "device_hostname": None,
            }
            for item in raw_rows
        ],
        "sources": [
            {
                **_column_values(
                    item,
                    excluded={"name", "host", "latest_error", "parser_quality_json"},
                ),
                "name": f"bounded-source-{int(item.id)}",
                "host": None,
                "latest_error": (
                    "Parser quality warning exists on the source."
                    if item.latest_error or int(item.parse_failure_count or 0) > 0
                    else None
                ),
                "parser_quality_json": {"bounded_snapshot": True},
            }
            for item in source_by_id.values()
        ],
        "source_summary": {
            "alert_rows": len(alerts),
            "case_inputs": len(alerts),
            "source_rows": len(source_by_id),
            "linked_log_rows": len(normalized_rows),
            "raw_log_values_copied": 0,
            "ip_values_copied": 0,
            "source_names_copied": 0,
        },
    }


@contextmanager
def _disposable_snapshot_session(snapshot: dict[str, Any]) -> Iterator[Session]:
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
    db = factory()
    try:
        db.add_all(LogSource(**item) for item in snapshot["sources"])
        db.flush()
        db.add_all(RawLog(**item) for item in snapshot["raw_logs"])
        db.flush()
        db.add_all(NormalizedLog(**item) for item in snapshot["normalized_logs"])
        db.flush()
        db.add_all(Alert(**item) for item in snapshot["alerts"])
        db.flush()
        db.add_all(AlertEvidence(**item) for item in snapshot["evidence"])
        db.commit()
        yield db
    finally:
        db.close()
        engine.dispose()


def _quality_questions(db: Session, snapshot: dict[str, Any]) -> list[QualityQuestion]:
    alert_rows = snapshot["alerts"]
    source_rows = snapshot["sources"]
    if not alert_rows:
        return []
    primary_id = int(alert_rows[0]["id"])
    expected_terms = (
        "alert",
        str(alert_rows[0].get("alert_type") or "").replace("_", " ").lower(),
        str(alert_rows[0].get("severity") or "").lower(),
    )
    questions = [
        QualityQuestion(
            key="real_alert_explanation",
            question=f"Why was alert {primary_id} flagged?",
            expected_primary="alert",
            expected_route="/api/alerts/{alert_id}",
            expected_reference=str(primary_id),
            expected_terms=expected_terms,
            conversation_id="v527-real-alert-thread",
            alert_id=primary_id,
        ),
        QualityQuestion(
            key="real_alert_related_logs_followup",
            question="What logs are related?",
            expected_primary="alert",
            expected_route="/api/alerts/{alert_id}",
            expected_reference=str(primary_id),
            expected_terms=("related", "log", "evidence"),
            conversation_id="v527-real-alert-thread",
            alert_id=primary_id,
        ),
        QualityQuestion(
            key="real_alert_safe_next_steps_followup",
            question="What should an analyst verify before response?",
            expected_primary="alert",
            expected_route="/api/alerts/{alert_id}",
            expected_reference=str(primary_id),
            expected_terms=("verify", "review", "check"),
            conversation_id="v527-real-alert-thread",
            alert_id=primary_id,
        ),
    ]
    if len(alert_rows) > 1:
        secondary_id = int(alert_rows[1]["id"])
        questions.append(
            QualityQuestion(
                key="real_alert_investigation_brief",
                question=f"Create an investigation brief for alert {secondary_id}.",
                expected_primary="alert",
                expected_route="/api/alerts/{alert_id}",
                expected_reference=str(secondary_id),
                expected_terms=("alert", "evidence", "analyst"),
                conversation_id="v527-real-secondary-thread",
                alert_id=secondary_id,
            )
        )
    if source_rows:
        source_id = int(source_rows[0]["id"])
        questions.append(
            QualityQuestion(
                key="real_source_health",
                question=f"Summarize source {source_id} health and safe next checks.",
                expected_primary="source",
                expected_route="/api/sources/{source_id}",
                expected_reference=str(source_id),
                expected_terms=("source", "parser", "health"),
                conversation_id="v527-real-source-thread",
                source_id=source_id,
            )
        )
    cases = list_alert_cases(db, active_only=False, limit=5)
    if cases:
        case_id = str(cases[0]["case_id"])
        questions.append(
            QualityQuestion(
                key="real_case_handoff",
                question=f"Summarize case {case_id} for analyst handoff.",
                expected_primary="case",
                expected_route="/api/alerts/cases",
                expected_reference=case_id,
                expected_terms=("case", "alert", "analyst"),
                conversation_id="v527-real-case-thread",
                case_id=case_id,
            )
        )
    return questions[:6]


def _run_failure_fallback(
    db: Session,
    settings: Settings,
    *,
    alert_id: int,
) -> dict[str, Any]:
    marker = "v527-local-failure-probe-key"
    failure_settings = settings.model_copy(
        update={
            "assistant_llm_enabled": True,
            "assistant_llm_provider": "openai_compatible",
            "assistant_llm_model": "v527-failure-probe",
            "assistant_llm_api_key": marker,
            "assistant_llm_base_url": "http://127.0.0.1:9/v1",
            "assistant_llm_timeout_seconds": 0.2,
            "assistant_llm_max_retries": 0,
            "assistant_allow_raw_log_context": False,
            "assistant_redact_ips": True,
            "assistant_rate_limit_requests": 100,
        }
    )
    response = answer_assistant_question(
        db,
        question=f"Why was alert {alert_id} flagged?",
        actor="v527-fallback-evaluator",
        settings=failure_settings,
        alert_id=alert_id,
        conversation_id="v527-fallback-thread",
    )
    details = response.get("details") if isinstance(response.get("details"), dict) else {}
    llm = details.get("llm") if isinstance(details.get("llm"), dict) else {}
    serialized = json.dumps(response, default=str)
    passed = (
        str(response.get("mode", "")).startswith("deterministic_local_llm_fallback_")
        and not response.get("external_provider_used")
        and llm.get("fallback_reason")
        in {
            "provider_request_failed",
            "provider_network_error",
            "provider_timeout",
            "provider_service_unavailable",
            "provider_rate_limited",
            "provider_quota_exhausted",
            "provider_authentication_failed",
            "malformed_provider_response",
        }
        and not response.get("raw_log_context_included")
        and bool(response.get("redaction_applied"))
        and SNAPSHOT_RAW_SENTINEL not in serialized
        and marker not in serialized
    )
    return {
        "passed": passed,
        "fallback_reason": llm.get("fallback_reason"),
        "failure_category": llm.get("failure_category"),
        "external_provider_used": bool(response.get("external_provider_used")),
        "raw_log_context_included": bool(response.get("raw_log_context_included")),
        "redaction_applied": bool(response.get("redaction_applied")),
        "secrets_exposed": False,
    }


def _percentile(values: list[int], percentile: float) -> int | None:
    if not values:
        return None
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, math.ceil(percentile * len(ordered)) - 1))
    return ordered[index]


def run_v527_gemini_real_alert_quality(
    source_db: Session,
    *,
    settings: Settings,
    execute_provider: bool,
    max_alerts: int = 3,
    provider_interval_seconds: float = 0.0,
    output_dir: Path = DEFAULT_OUTPUT_DIR,
    write_reports: bool = True,
) -> dict[str, Any]:
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
    snapshot = _snapshot_records(source_db, max_alerts=max_alerts)
    configured_after_snapshot = _authoritative_counts(source_db)

    if not snapshot["alerts"]:
        return {
            "ok": False,
            "status": "no_existing_alerts_available_for_bounded_evaluation",
            "provider": provider_name or "disabled",
            "provider_ready": provider_ready,
            "secrets_exposed": False,
            "raw_log_context_allowed": False,
            "redaction_enabled": True,
            "configured_database_mutation_deltas": {
                key: configured_after_snapshot[key] - configured_before[key]
                for key in configured_before
            },
        }

    with _disposable_snapshot_session(snapshot) as db:
        temp_before = _authoritative_counts(db)
        questions = _quality_questions(db, snapshot)
        case_results: list[dict[str, Any]] = []
        for index, question in enumerate(questions):
            if provider_required and index and provider_interval_seconds > 0:
                time.sleep(min(float(provider_interval_seconds), 30.0))
            response = answer_assistant_question(
                db,
                question=question.question,
                actor="v527-real-record-evaluator",
                settings=evaluation_settings,
                alert_id=question.alert_id,
                log_id=question.log_id,
                source_id=question.source_id,
                case_id=question.case_id,
                include_recent_context=True,
                conversation_id=question.conversation_id,
            )
            item = evaluate_assistant_response(
                response,
                question=question,
                provider_required=provider_required,
                api_key=settings.assistant_llm_api_key.strip(),
            )
            item["unsafe_recommendation_detected"] = any(
                phrase in str(response.get("answer") or "").lower()
                for phrase in UNSAFE_COMPLETION_PHRASES
            )
            item["passed"] = bool(item["passed"] and not item["unsafe_recommendation_detected"])
            case_results.append(item)
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
    temp_authoritative_keys = [key for key in temp_before if key != "audit_logs"]
    temp_mutation_deltas = {
        key: temp_after[key] - temp_before[key]
        for key in temp_authoritative_keys
    }
    temp_audit_delta = temp_after["audit_logs"] - temp_before["audit_logs"]
    latencies = [
        int(item["latency_ms"])
        for item in case_results
        if isinstance(item.get("latency_ms"), int)
    ]
    usage_totals: dict[str, int] = {}
    for item in case_results:
        for key, value in item.get("usage", {}).items():
            if isinstance(value, int):
                usage_totals[key] = usage_totals.get(key, 0) + value

    checks = {
        "bounded_record_set_available": bool(case_results),
        "configured_database_read_only": all(value == 0 for value in configured_deltas.values()),
        "disposable_authoritative_state_unchanged": all(
            value == 0 for value in temp_mutation_deltas.values()
        ),
        "expected_assistant_audits_recorded_only_in_disposable_store": temp_audit_delta
        == len(case_results) + 1,
        "privacy_contract_passed": all(
            item["checks"]["privacy_contract"] for item in case_results
        ),
        "citation_contract_passed": all(
            item["checks"]["record_citation_present"]
            and item["checks"]["structured_citation_correct"]
            for item in case_results
        ),
        "record_context_retained": all(
            item["checks"]["primary_context_retained"] for item in case_results
        ),
        "unsupported_ids_prevented": all(
            item["checks"]["no_unsupported_entity_references"] for item in case_results
        ),
        "safe_recommendations_only": all(
            item["checks"]["no_implied_action_execution"]
            and not item["unsafe_recommendation_detected"]
            for item in case_results
        ),
        "concision_contract_passed": all(
            item["checks"]["concise_contract"] for item in case_results
        ),
        "provider_contract_passed": all(
            item["checks"]["provider_contract"] for item in case_results
        ),
        "provider_failure_fallback_passed": bool(fallback["passed"]),
    }
    if not execute_provider:
        phase_status = "v5_27_real_record_provider_evaluation_not_requested"
    elif not provider_ready:
        phase_status = "v5_27_real_record_provider_configuration_incomplete"
    elif all(checks.values()) and all(item["passed"] for item in case_results):
        phase_status = "v5_27_gemini_real_record_quality_passed"
    else:
        phase_status = "v5_27_gemini_real_record_quality_failed"

    report: dict[str, Any] = {
        "ok": bool(
            all(checks.values())
            and (not execute_provider or provider_ready)
            and all(item["passed"] for item in case_results)
        ),
        "status": phase_status,
        "schema_version": "v5.27.0",
        "generated_at": datetime.now(UTC).isoformat(),
        "provider_evaluation_requested": execute_provider,
        "provider_ready": provider_ready,
        "provider": provider_name or "disabled",
        "model_configured": bool(status.get("llm_model_configured")),
        "secrets_exposed": False,
        "raw_log_context_allowed": False,
        "redaction_enabled": True,
        "bounded_snapshot": snapshot["source_summary"],
        "question_count": len(case_results),
        "questions": case_results,
        "checks": checks,
        "passed_checks": sum(bool(value) for value in checks.values()),
        "total_checks": len(checks),
        "provider_measurements": {
            "calls_used": sum(bool(item["provider_used"]) for item in case_results),
            "latency_ms_min": min(latencies) if latencies else None,
            "latency_ms_median": round(median(latencies), 2) if latencies else None,
            "latency_ms_p95": _percentile(latencies, 0.95),
            "latency_ms_max": max(latencies) if latencies else None,
            "usage_totals": usage_totals,
        },
        "failure_fallback": fallback,
        "configured_database_mutation_deltas": configured_deltas,
        "disposable_store_mutation_deltas": temp_mutation_deltas,
        "disposable_assistant_audit_delta": temp_audit_delta,
        "limitations": [
            "Automated checks cover a bounded sample and do not prove universal semantic accuracy.",
            "No raw logs or IP addresses were provided to the external model.",
        ],
        "safety": {
            "assistant_read_only": True,
            "raw_logs_disabled": True,
            "ip_redaction_enabled": True,
            "rules_remain_alert_authoritative": True,
            "model_activated": False,
            "model_promoted": False,
            "response_automation_allowed": False,
            "real_firewall_blocking_enabled": False,
        },
        "private_paths_returned": False,
        "raw_logs_returned": False,
        "ip_addresses_returned": False,
    }
    serialized = json.dumps(report, default=str)
    report["privacy_self_check"] = {
        "raw_sentinel_absent": SNAPSHOT_RAW_SENTINEL not in serialized,
        "ip_addresses_absent": IP_PATTERN.search(serialized) is None,
        "secret_absent": not (
            settings.assistant_llm_api_key
            and settings.assistant_llm_api_key in serialized
        ),
    }
    report["ok"] = bool(report["ok"] and all(report["privacy_self_check"].values()))
    if write_reports:
        output_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        safe_json = json.dumps(report, indent=2, sort_keys=True, default=str)
        (output_dir / V527_ASSISTANT_LATEST).write_text(safe_json, encoding="utf-8")
        (output_dir / f"v5_27_gemini_real_alert_quality_{stamp}.json").write_text(
            safe_json,
            encoding="utf-8",
        )
    return report
