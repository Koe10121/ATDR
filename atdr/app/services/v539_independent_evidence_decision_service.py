from __future__ import annotations

import hashlib
import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from atdr.app.core.config import Settings
from atdr.app.detection import v528_blind_review_helper as v528
from atdr.app.services import evidence_review_service as review_service
from atdr.app.services import v533_independent_acceptance_service as v533
from atdr.app.services.v524_investigation_gemini_quality_service import (
    _authoritative_counts,
)
from atdr.app.services.v536_independent_evidence_activation_service import (
    run_v536_independent_evidence_activation_decision,
)


V539_VERSION = "v5.39.0"
DEFAULT_OUTPUT_DIR = v528.DEFAULT_EVIDENCE_DIR
DEFAULT_STATE_PATH = DEFAULT_OUTPUT_DIR / "v5_39_frozen_evidence_state.json"
V539_LATEST = "v5_39_independent_evidence_decision_latest.json"
V539_EXECUTION_CONFIRMATION = "FROZEN_V539_EVALUATION"
EXPECTED_DETECTION_ROWS = 40
EXPECTED_ASSISTANT_ROWS = 8

_DETECTION_DECISION_FIELDS = (
    "review_token",
    "human_decision",
    "human_attack_type",
    "human_confidence",
    "human_notes",
    "human_reviewer",
    "human_reviewed_at",
    "human_must_confirm",
    "human_reviewed",
)
_ASSISTANT_DECISION_FIELDS = (
    "review_case_id",
    *v533.ASSISTANT_HUMAN_FIELDS,
)


class FrozenEvidenceDecisionError(review_service.EvidenceReviewError):
    pass


class FrozenEvidenceIntegrityError(review_service.EvidenceReviewIntegrityError):
    pass


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _stamp() -> str:
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")


def _digest(value: Any) -> str:
    serialized = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def _load_frozen_state(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise FrozenEvidenceIntegrityError(
            "frozen_state_invalid",
            "The frozen evaluation state failed integrity validation.",
        ) from exc
    if not isinstance(payload, dict) or payload.get("schema_version") != V539_VERSION:
        raise FrozenEvidenceIntegrityError(
            "frozen_state_invalid",
            "The frozen evaluation state failed integrity validation.",
        )
    return payload


def _claim_path(state_path: Path) -> Path:
    return state_path.with_name(f"{state_path.name}.claim")


def _create_evaluation_claim(state_path: Path) -> None:
    claim_path = _claim_path(state_path)
    claim_path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(
        {
            "schema_version": V539_VERSION,
            "attempt_count": 1,
            "claimed_at": _now(),
        },
        sort_keys=True,
    )
    try:
        descriptor = os.open(
            claim_path,
            os.O_CREAT | os.O_EXCL | os.O_WRONLY,
            0o600,
        )
    except FileExistsError as exc:
        raise FrozenEvidenceDecisionError(
            "frozen_evaluation_already_claimed",
            "The frozen evaluation was already claimed and cannot run again.",
        ) from exc
    except OSError as exc:
        raise FrozenEvidenceDecisionError(
            "frozen_evaluation_claim_failed",
            "The frozen evaluation could not claim its single execution attempt.",
        ) from exc
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    except OSError as exc:
        raise FrozenEvidenceDecisionError(
            "frozen_evaluation_claim_failed",
            "The frozen evaluation claim failed closed.",
        ) from exc


def _read_workspace_state(paths: review_service.EvidenceWorkspacePaths) -> dict[str, Any]:
    state = review_service._load_state(paths.state)
    if not all(isinstance(state.get(name), dict) for name in ("detection", "assistant")):
        raise FrozenEvidenceIntegrityError(
            "workspace_state_invalid",
            "The private review workspace state failed integrity validation.",
        )
    return state


def _reviewer_contract(
    rows: list[dict[str, str]],
    *,
    owner_username: str,
) -> bool:
    reviewers = {
        str(row.get("human_reviewer") or "").strip()
        for row in rows
        if review_service._boolean(row.get("human_reviewed"))
    }
    return bool(owner_username and reviewers == {owner_username})


def _collect_readiness(
    *,
    settings: Settings,
    paths: review_service.EvidenceWorkspacePaths,
) -> dict[str, Any]:
    state = _read_workspace_state(paths)
    detection_workspace = state["detection"]
    assistant_workspace = state["assistant"]

    if not paths.detection_pack.is_file() or not paths.detection_working.is_file():
        detection = {
            "available": False,
            "total": 0,
            "reviewed": 0,
            "remaining": EXPECTED_DETECTION_ROWS,
            "invalid": 0,
            "completed": False,
            "closed": False,
            "evaluation_ready": False,
            "owner_contract_valid": False,
        }
        detection_pack_digest = ""
        detection_decision_digest = ""
    else:
        detection_pack_digest = review_service._detection_pack_digest(
            paths.detection_pack
        )
        review_service._assert_digest(
            detection_workspace,
            detection_pack_digest,
            code="detection_pack_changed",
        )
        try:
            v528.validate_working_copy(
                pack_path=paths.detection_pack,
                working_path=paths.detection_working,
            )
            detection_progress = v528.review_progress(
                pack_path=paths.detection_pack,
                working_path=paths.detection_working,
            )
            detection_rows, _ = v528._read_rows(paths.detection_working)
        except (OSError, ValueError) as exc:
            raise FrozenEvidenceIntegrityError(
                "detection_review_invalid",
                "The detection review failed its sealed evidence contract.",
            ) from exc
        detection_total = int(detection_progress.get("total") or 0)
        detection_reviewed = int(detection_progress.get("reviewed") or 0)
        detection_invalid = int(detection_progress.get("invalid") or 0)
        detection_complete = bool(
            detection_total == EXPECTED_DETECTION_ROWS
            and detection_reviewed == detection_total
            and detection_invalid == 0
        )
        detection_owner_valid = _reviewer_contract(
            detection_rows,
            owner_username=str(detection_workspace.get("owner_username") or ""),
        )
        detection = {
            "available": True,
            "total": detection_total,
            "reviewed": detection_reviewed,
            "remaining": int(detection_progress.get("remaining") or 0),
            "invalid": detection_invalid,
            "completed": detection_complete,
            "closed": bool(
                detection_complete and detection_workspace.get("completed_at")
            ),
            "evaluation_ready": bool(
                detection_complete
                and detection_progress.get("enough_for_locked_evaluation")
            ),
            "owner_contract_valid": detection_owner_valid,
        }
        detection_decision_digest = _digest(
            [
                {
                    field: str(row.get(field) or "")
                    for field in _DETECTION_DECISION_FIELDS
                }
                for row in detection_rows
            ]
        )

    if not paths.assistant_review.is_file() or not paths.assistant_manifest.is_file():
        assistant = {
            "available": False,
            "total": 0,
            "reviewed": 0,
            "remaining": EXPECTED_ASSISTANT_ROWS,
            "invalid": 0,
            "completed": False,
            "closed": False,
            "evaluation_ready": False,
            "owner_contract_valid": False,
            "human_acceptance_passed": None,
        }
        assistant_pack_digest = ""
        assistant_decision_digest = ""
    else:
        assistant_pack_digest = review_service._assistant_pack_digest(
            paths,
            secret=settings.assistant_llm_api_key,
        )
        review_service._assert_digest(
            assistant_workspace,
            assistant_pack_digest,
            code="assistant_pack_changed",
        )
        try:
            assistant_validation = v533.validate_assistant_human_review_pack(
                review_path=paths.assistant_review,
                manifest_path=paths.assistant_manifest,
                secret=settings.assistant_llm_api_key,
            )
            assistant_rows, _ = v533._read_csv(paths.assistant_review)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            raise FrozenEvidenceIntegrityError(
                "assistant_review_invalid",
                "The Assistant review failed its protected acceptance contract.",
            ) from exc
        if not assistant_validation.get("ok"):
            raise FrozenEvidenceIntegrityError(
                "assistant_review_invalid",
                "The Assistant review failed its protected acceptance contract.",
            )
        assistant_total = int(assistant_validation.get("total_rows") or 0)
        assistant_reviewed = int(
            assistant_validation.get("valid_human_reviews") or 0
        )
        assistant_invalid = int(assistant_validation.get("invalid_rows") or 0)
        assistant_complete = bool(
            assistant_total == EXPECTED_ASSISTANT_ROWS
            and assistant_reviewed == assistant_total
            and assistant_invalid == 0
        )
        assistant_owner_valid = _reviewer_contract(
            assistant_rows,
            owner_username=str(assistant_workspace.get("owner_username") or ""),
        )
        assistant = {
            "available": True,
            "total": assistant_total,
            "reviewed": assistant_reviewed,
            "remaining": int(assistant_validation.get("incomplete_rows") or 0),
            "invalid": assistant_invalid,
            "completed": assistant_complete,
            "closed": bool(
                assistant_complete and assistant_workspace.get("completed_at")
            ),
            "evaluation_ready": bool(
                assistant_complete
                and assistant_validation.get("human_acceptance_permitted")
            ),
            "owner_contract_valid": assistant_owner_valid,
            "human_acceptance_passed": (
                bool(assistant_validation.get("human_acceptance_passed"))
                if assistant_validation.get("human_metrics_calculated")
                else None
            ),
        }
        assistant_decision_digest = _digest(
            [
                {
                    field: str(row.get(field) or "")
                    for field in _ASSISTANT_DECISION_FIELDS
                }
                for row in assistant_rows
            ]
        )

    reviews_complete = bool(detection["completed"] and assistant["completed"])
    reviews_closed = bool(detection["closed"] and assistant["closed"])
    owners_valid = bool(
        detection["owner_contract_valid"] and assistant["owner_contract_valid"]
    )
    freeze_ready = bool(
        reviews_complete
        and reviews_closed
        and owners_valid
        and detection["evaluation_ready"]
        and assistant["evaluation_ready"]
    )
    return {
        "detection": detection,
        "assistant": assistant,
        "reviews_complete": reviews_complete,
        "reviews_closed": reviews_closed,
        "owners_valid": owners_valid,
        "freeze_ready": freeze_ready,
        "private_contract": {
            "detection_pack_digest": detection_pack_digest,
            "detection_decision_digest": detection_decision_digest,
            "assistant_pack_digest": assistant_pack_digest,
            "assistant_decision_digest": assistant_decision_digest,
            "workspace_state_digest": _digest(
                {
                    "detection": detection_workspace,
                    "assistant": assistant_workspace,
                }
            ),
        },
    }


def _assert_frozen_contract(
    frozen: dict[str, Any],
    readiness: dict[str, Any],
) -> None:
    expected = frozen.get("private_contract")
    observed = readiness.get("private_contract")
    if not isinstance(expected, dict) or expected != observed:
        raise FrozenEvidenceIntegrityError(
            "frozen_evidence_changed",
            "The completed evidence changed after it was frozen.",
        )


def _public_status(
    *,
    readiness: dict[str, Any],
    frozen: dict[str, Any] | None,
    executed_now: bool = False,
) -> dict[str, Any]:
    evaluation = (frozen or {}).get("evaluation") or {}
    evaluation_status = str(evaluation.get("status") or "not_started")
    if frozen:
        _assert_frozen_contract(frozen, readiness)
        status = {
            "pending": "frozen_evaluation_pending",
            "in_progress": "frozen_evaluation_in_progress",
            "completed": "frozen_evaluation_complete",
            "failed_closed": "frozen_evaluation_failed_closed",
        }.get(evaluation_status, "frozen_evaluation_failed_closed")
    elif readiness["freeze_ready"]:
        status = "ready_to_freeze"
    elif readiness["reviews_complete"]:
        status = "review_complete_not_evaluable"
    else:
        status = "human_review_required"
    result = evaluation.get("result_summary") or {}
    activation = result.get("activation_decision") or {}
    return {
        "ok": status != "frozen_evaluation_failed_closed",
        "version": V539_VERSION,
        "status": status,
        "detection": readiness["detection"],
        "assistant": readiness["assistant"],
        "reviews_complete": readiness["reviews_complete"],
        "reviews_closed": readiness["reviews_closed"],
        "freeze_ready": readiness["freeze_ready"],
        "evidence_frozen": frozen is not None,
        "evaluation_attempted": int(evaluation.get("attempt_count") or 0) > 0,
        "evaluation_completed": evaluation_status == "completed",
        "evaluation_execution_count": int(evaluation.get("attempt_count") or 0),
        "executed_now": executed_now,
        "metrics_available": bool(result.get("metrics_available")),
        "blind_metrics": result.get("blind_metrics") or {},
        "assistant_metrics": result.get("assistant_metrics") or {},
        "activation_decision": {
            "lifecycle": activation.get("lifecycle") or "shadow_observation",
            "activate_candidate": bool(activation.get("activate_candidate")),
            "eligible_for_manual_activation_review": bool(
                activation.get("eligible_for_manual_activation_review")
            ),
            "production_promoted": False,
            "model_activated": False,
            "model_promoted": False,
            "response_automation_allowed": False,
            "rules_remain_alert_authoritative": True,
            "blockers": activation.get("blockers") or [],
        },
        "message": {
            "human_review_required": (
                "Complete and close all 40 detection decisions and eight "
                "Assistant assessments before the frozen evaluation."
            ),
            "review_complete_not_evaluable": (
                "The completed reviews do not yet satisfy the frozen evaluation contract."
            ),
            "ready_to_freeze": (
                "Both human reviews are closed and ready for the single governed evaluation."
            ),
            "frozen_evaluation_pending": (
                "Evidence is frozen. The single governed evaluation has not started."
            ),
            "frozen_evaluation_in_progress": (
                "The frozen evaluation was claimed and cannot be started again."
            ),
            "frozen_evaluation_complete": (
                "The single governed evaluation is complete. No model was activated."
            ),
            "frozen_evaluation_failed_closed": (
                "The single governed evaluation failed closed and cannot be retried automatically."
            ),
        }[status],
        "safety": {
            "predictions_exposed_before_completion": False,
            "digests_recorded_privately": frozen is not None,
            "digests_exposed": False,
            "reviewer_identities_exposed": False,
            "raw_logs_exposed": False,
            "ip_addresses_exposed": False,
            "private_paths_exposed": False,
            "external_provider_called": False,
            "labels_written": 0,
            "model_runs_written": 0,
            "detection_runs_written": 0,
            "alerts_written": 0,
            "response_actions_written": 0,
            "model_activated": False,
            "model_promoted": False,
            "automatic_response_enabled": False,
            "real_firewall_blocking_enabled": False,
            "secrets_exposed": False,
        },
    }


def get_v539_evaluation_status(
    *,
    settings: Settings,
    paths: review_service.EvidenceWorkspacePaths | None = None,
    state_path: Path | None = None,
) -> dict[str, Any]:
    resolved_paths = paths or review_service._workspace_paths()
    readiness = _collect_readiness(settings=settings, paths=resolved_paths)
    resolved_state = state_path or resolved_paths.evidence_dir / DEFAULT_STATE_PATH.name
    frozen = _load_frozen_state(resolved_state)
    if frozen is None and _claim_path(resolved_state).is_file():
        frozen = _frozen_state(readiness)
        frozen["evaluation"].update(
            {
                "status": "failed_closed",
                "attempt_count": 1,
                "completed_at": None,
            }
        )
    return _public_status(readiness=readiness, frozen=frozen)


def _frozen_state(readiness: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": V539_VERSION,
        "frozen_at": _now(),
        "private_contract": readiness["private_contract"],
        "review_contract": {
            "detection_rows": readiness["detection"]["total"],
            "assistant_rows": readiness["assistant"]["total"],
            "both_reviews_closed": readiness["reviews_closed"],
            "owner_contracts_valid": readiness["owners_valid"],
        },
        "evaluation": {
            "status": "pending",
            "attempt_count": 0,
            "started_at": None,
            "completed_at": None,
            "result_summary": None,
        },
    }


def _result_summary(report: dict[str, Any]) -> dict[str, Any]:
    activation = report.get("activation_decision") or {}
    blind = report.get("blind_layer_evaluation") or {}
    assistant = report.get("assistant_human_acceptance") or {}
    return {
        "metrics_available": bool(blind.get("metrics_calculated")),
        "blind_metrics": {
            "status": blind.get("status"),
            "rows": int(blind.get("rows") or 0),
            "layers": blind.get("layers") or {},
            "predictions_returned": False,
        },
        "assistant_metrics": {
            "status": assistant.get("status"),
            "valid_human_reviews": int(assistant.get("valid_human_reviews") or 0),
            "total_rows": int(assistant.get("total_rows") or 0),
            "human_metrics": assistant.get("human_metrics"),
            "human_acceptance_passed": bool(
                assistant.get("human_acceptance_passed")
            ),
            "answers_returned": False,
        },
        "activation_decision": {
            "lifecycle": activation.get("decision") or "shadow_observation",
            "activate_candidate": bool(
                activation.get("eligible_for_manual_activation_review")
            ),
            "eligible_for_manual_activation_review": bool(
                activation.get("eligible_for_manual_activation_review")
            ),
            "blockers": list(activation.get("blockers") or []),
            "production_promoted": False,
            "model_activated": False,
            "model_promoted": False,
            "response_automation_allowed": False,
            "rules_remain_alert_authoritative": True,
        },
    }


def render_v539_report(report: dict[str, Any]) -> str:
    activation = report.get("activation_decision") or {}
    detection = report.get("detection") or {}
    assistant = report.get("assistant") or {}
    lines = [
        "# v5.39 Independent Evidence And Frozen Activation Decision",
        "",
        f"- Status: `{report.get('status')}`",
        f"- Detection review: `{detection.get('reviewed', 0)}/{detection.get('total', 0)}`",
        f"- Assistant review: `{assistant.get('reviewed', 0)}/{assistant.get('total', 0)}`",
        f"- Evidence frozen: `{report.get('evidence_frozen')}`",
        f"- Evaluation execution count: `{report.get('evaluation_execution_count', 0)}`",
        f"- Metrics available: `{report.get('metrics_available')}`",
        f"- Lifecycle: `{activation.get('lifecycle')}`",
        f"- Activate candidate: `{activation.get('activate_candidate')}`",
        "- Model activated: `false`",
        "- Production promoted: `false`",
        "- Response automation allowed: `false`",
        "- Rules remain alert-authoritative: `true`",
        "",
        "## Remaining Blockers",
        "",
    ]
    blockers = activation.get("blockers") or []
    lines.extend(f"- `{item}`" for item in blockers)
    if not blockers:
        lines.append("- None in the frozen evaluator; separate activation approval is still required.")
    return "\n".join(lines) + "\n"


def run_v539_frozen_activation_decision(
    db: Session,
    *,
    settings: Settings,
    confirmation: str,
    paths: review_service.EvidenceWorkspacePaths | None = None,
    state_path: Path | None = None,
    output_dir: Path = DEFAULT_OUTPUT_DIR,
    write_reports: bool = True,
) -> dict[str, Any]:
    if confirmation != V539_EXECUTION_CONFIRMATION:
        raise FrozenEvidenceDecisionError(
            "explicit_confirmation_required",
            "The single frozen evaluation requires the exact confirmation value.",
            status_code=422,
        )
    resolved_paths = paths or review_service._workspace_paths()
    resolved_state = state_path or resolved_paths.evidence_dir / DEFAULT_STATE_PATH.name
    readiness = _collect_readiness(settings=settings, paths=resolved_paths)
    if not readiness["freeze_ready"]:
        raise FrozenEvidenceDecisionError(
            "frozen_evaluation_not_ready",
            "Complete and close both genuine human reviews before evaluation.",
        )

    frozen = _load_frozen_state(resolved_state)
    if frozen is None:
        frozen = _frozen_state(readiness)
    _assert_frozen_contract(frozen, readiness)
    evaluation = frozen["evaluation"]
    current_status = str(evaluation.get("status") or "")
    if current_status == "completed":
        return _public_status(readiness=readiness, frozen=frozen)
    if current_status != "pending" or int(evaluation.get("attempt_count") or 0):
        raise FrozenEvidenceDecisionError(
            "frozen_evaluation_already_claimed",
            "The frozen evaluation was already claimed and cannot run again.",
        )

    _create_evaluation_claim(resolved_state)
    try:
        evaluation.update(
            {
                "status": "in_progress",
                "attempt_count": 1,
                "started_at": _now(),
            }
        )
        review_service._atomic_write_json(resolved_state, frozen)
        before = _authoritative_counts(db)
        report = run_v536_independent_evidence_activation_decision(
            db,
            settings=settings,
            output_dir=output_dir,
            detection_review_path=resolved_paths.detection_working,
            assistant_review_path=resolved_paths.assistant_review,
            assistant_manifest_path=resolved_paths.assistant_manifest,
            execute_provider=False,
            provider_interval_seconds=0.0,
            write_reports=False,
        )
        after = _authoritative_counts(db)
        deltas = {name: after[name] - before[name] for name in before}
        current_readiness = _collect_readiness(
            settings=settings,
            paths=resolved_paths,
        )
        _assert_frozen_contract(frozen, current_readiness)
        safety = report.get("safety") or {}
        provider = report.get("assistant_automated_acceptance") or {}
        provider_calls = int(
            ((provider.get("provider_measurements") or {}).get("calls_used") or 0)
        )
        safe = bool(
            report.get("ok")
            and all(value == 0 for value in deltas.values())
            and provider_calls == 0
            and not safety.get("raw_logs_sent_to_provider")
            and not safety.get("model_activated")
            and not safety.get("model_promoted")
            and not safety.get("response_actions_created")
        )
        if not safe:
            raise FrozenEvidenceIntegrityError(
                "frozen_evaluation_safety_failed",
                "The frozen evaluation failed its read-only safety contract.",
            )
        evaluation.update(
            {
                "status": "completed",
                "completed_at": _now(),
                "result_summary": _result_summary(report),
                "authoritative_mutation_deltas": deltas,
                "external_provider_calls": 0,
            }
        )
        review_service._atomic_write_json(resolved_state, frozen)
        public = _public_status(
            readiness=current_readiness,
            frozen=frozen,
            executed_now=True,
        )
        if write_reports:
            output_dir.mkdir(parents=True, exist_ok=True)
            serialized = json.dumps(public, indent=2, sort_keys=True, default=str)
            (output_dir / V539_LATEST).write_text(serialized, encoding="utf-8")
            stamp = _stamp()
            (output_dir / f"v5_39_independent_evidence_decision_{stamp}.json").write_text(
                serialized,
                encoding="utf-8",
            )
            (output_dir / f"v5_39_independent_evidence_decision_{stamp}.md").write_text(
                render_v539_report(public),
                encoding="utf-8",
            )
        return public
    except Exception as exc:
        evaluation.update(
            {
                "status": "failed_closed",
                "completed_at": _now(),
                "error_code": (
                    exc.code
                    if isinstance(exc, review_service.EvidenceReviewError)
                    else "frozen_evaluation_failed"
                ),
                "result_summary": None,
            }
        )
        try:
            review_service._atomic_write_json(resolved_state, frozen)
        except OSError:
            pass
        if isinstance(exc, review_service.EvidenceReviewError):
            raise
        raise FrozenEvidenceDecisionError(
            "frozen_evaluation_failed",
            "The frozen evaluation failed closed and was not retried.",
        ) from exc
