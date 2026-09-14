from __future__ import annotations

from statistics import mean
from typing import Any, Iterable

from sqlalchemy.orm import Session

from atdr.app.core.config import get_settings
from atdr.app.db.models import NormalizedLog
from atdr.app.detection.v51_supervised_lifecycle import (
    V51_FEATURE_SET_VERSION,
    V51_MODEL_TYPE,
    V51_TARGET_MODE,
)


V558_RUNTIME_CONTRACT_VERSION = "v5.58-governed-hybrid-runtime-v1"

# This tracked aggregate decision is deliberately separate from private review
# evidence. A later governed phase may replace it only after a new candidate
# passes its predeclared gates.
CURRENT_SUPERVISED_GOVERNANCE_DECISION: dict[str, Any] = {
    "phase": "v5.49b",
    "decision": "no_candidate_selected",
    "candidate_qualified": False,
    "approved_model_version": None,
    "evaluation_consumed": True,
    "development_gates_passed": False,
    "candidate_frozen": False,
    "protected_evaluation_excluded_from_training": True,
    "reason_codes": [
        "fixed_evaluation_missing_suspicious_support",
        "calibration_confidence_gap_failed",
    ],
}


def _lifecycle_status(db: Session) -> dict[str, Any]:
    try:
        from atdr.app.detection.v51_supervised_lifecycle import (
            supervised_lifecycle_status,
        )

        return supervised_lifecycle_status(db, execute_shadow_runtime=False)
    except (OSError, ValueError, TypeError, KeyError, AttributeError, RuntimeError) as exc:
        return {
            "lifecycle_state": "inactive",
            "artifact": {"available": False, "checksum_valid": False},
            "status_error_type": exc.__class__.__name__,
            "production_promoted": False,
            "response_automation_allowed": False,
            "rule_detection_authoritative": True,
        }


def _metadata_checks(lifecycle: dict[str, Any]) -> dict[str, bool]:
    artifact = lifecycle.get("artifact") or {}
    return {
        "registered_model": lifecycle.get("model_run_id") is not None,
        "model_version": bool(lifecycle.get("model_version")),
        "model_type": lifecycle.get("model_type") == V51_MODEL_TYPE,
        "target_mode": lifecycle.get("target_mode") == V51_TARGET_MODE,
        "feature_set_version": (
            lifecycle.get("feature_set_version") == V51_FEATURE_SET_VERSION
        ),
        "calibration_method": bool(lifecycle.get("calibration_method")),
        "threshold": isinstance(lifecycle.get("threshold"), (int, float))
        and 0.0 < float(lifecycle["threshold"]) < 1.0,
        "artifact_available": bool(artifact.get("available")),
        "artifact_checksum_valid": bool(artifact.get("checksum_valid")),
        "training_provenance": bool(
            lifecycle.get("dataset_provenance_recorded")
            or lifecycle.get("dataset_fingerprint")
        ),
        "shadow_safety_passed": bool(lifecycle.get("shadow_safety_passed")),
        "strict_validation_passed": (
            lifecycle.get("validation_status") == "strict_gates_passed"
            and bool(lifecycle.get("decision_support_eligible"))
        ),
    }


def _decision_gate_checks(decision: dict[str, Any]) -> dict[str, bool]:
    return {
        "candidate_qualified": bool(decision.get("candidate_qualified")),
        "development_gates_passed": bool(decision.get("development_gates_passed")),
        "candidate_frozen": bool(decision.get("candidate_frozen")),
        "protected_evaluation_excluded_from_training": bool(
            decision.get("protected_evaluation_excluded_from_training")
        ),
    }


def supervised_runtime_status(
    db: Session,
    *,
    requested: bool = True,
    governance_decision: dict[str, Any] | None = None,
    lifecycle_status: dict[str, Any] | None = None,
) -> dict[str, Any]:
    settings = get_settings()
    decision = dict(governance_decision or CURRENT_SUPERVISED_GOVERNANCE_DECISION)
    lifecycle = lifecycle_status or _lifecycle_status(db)
    metadata = _metadata_checks(lifecycle)
    metadata_complete = all(metadata.values())
    decision_gates = _decision_gate_checks(decision)
    approved_version = decision.get("approved_model_version")
    model_version = lifecycle.get("model_version")

    state = "unavailable"
    reason_code = "supervised_not_requested"
    if requested:
        if not bool(decision.get("candidate_qualified")):
            state = "unqualified"
            reason_code = "latest_governance_decision_selected_no_candidate"
        elif not all(decision_gates.values()):
            state = "unqualified"
            reason_code = "latest_governance_decision_missing_runtime_gates"
        elif not approved_version or model_version != approved_version:
            state = "unqualified"
            reason_code = "registered_model_not_approved_by_latest_decision"
        elif lifecycle.get("lifecycle_state") not in {
            "shadow_observation",
            "decision_support",
        }:
            reason_code = "governed_lifecycle_inactive"
        elif not metadata_complete:
            reason_code = "registered_artifact_metadata_incomplete"
        elif not settings.governed_shadow_scoring_enabled:
            reason_code = "shadow_scoring_disabled_by_configuration"
        else:
            state = "active_shadow"
            reason_code = "governed_shadow_scoring_ready"

    return {
        "contract_version": V558_RUNTIME_CONTRACT_VERSION,
        "state": state,
        "reason_code": reason_code,
        "requested": requested,
        "scoring_allowed": state == "active_shadow",
        "configured": bool(settings.governed_shadow_scoring_enabled),
        "historical_lifecycle_state": lifecycle.get("lifecycle_state", "inactive"),
        "model_version": model_version if metadata.get("model_version") else None,
        "model_type": lifecycle.get("model_type") if metadata.get("model_type") else None,
        "target_mode": lifecycle.get("target_mode") if metadata.get("target_mode") else None,
        "feature_set_version": (
            lifecycle.get("feature_set_version")
            if metadata.get("feature_set_version")
            else None
        ),
        "calibration_method": (
            lifecycle.get("calibration_method")
            if metadata.get("calibration_method")
            else None
        ),
        "threshold": lifecycle.get("threshold") if metadata.get("threshold") else None,
        "metadata_complete": metadata_complete,
        "metadata_checks": metadata,
        "decision_gate_checks": decision_gates,
        "latest_governance": {
            "phase": decision.get("phase"),
            "decision": decision.get("decision"),
            "candidate_qualified": bool(decision.get("candidate_qualified")),
            "evaluation_consumed": bool(decision.get("evaluation_consumed")),
            "development_gates_passed": bool(
                decision.get("development_gates_passed")
            ),
            "candidate_frozen": bool(decision.get("candidate_frozen")),
            "protected_evaluation_excluded_from_training": bool(
                decision.get("protected_evaluation_excluded_from_training")
            ),
            "reason_codes": list(decision.get("reason_codes") or []),
        },
        "decision_support_only": True,
        "used_for_alert_creation": False,
        "used_for_severity": False,
        "used_for_suppression": False,
        "production_promoted": False,
        "response_automation_allowed": False,
        "secrets_exposed": False,
    }


def _score_summary(values: Iterable[float]) -> dict[str, float | None]:
    scores = [float(value) for value in values]
    return {
        "minimum": round(min(scores), 6) if scores else None,
        "mean": round(mean(scores), 6) if scores else None,
        "maximum": round(max(scores), 6) if scores else None,
    }


def score_supervised_runtime_batch(
    db: Session,
    logs: list[NormalizedLog],
    *,
    requested: bool,
) -> dict[str, Any]:
    status = supervised_runtime_status(db, requested=requested)
    status.update(
        {
            "rows_considered": len(logs),
            "rows_scored": 0,
            "rows_abstained": 0,
            "queue_count": 0,
            "queue_rate": 0.0,
            "score_summary": _score_summary([]),
            "confidence_summary": _score_summary([]),
        }
    )
    if not status["scoring_allowed"] or not logs:
        if status["scoring_allowed"] and not logs:
            status["state"] = "abstained"
            status["reason_code"] = "no_logs_in_detection_scope"
            status["scoring_allowed"] = False
        return status

    settings = get_settings()
    bounded_logs = logs[: min(len(logs), int(settings.governed_shadow_batch_size))]
    try:
        from atdr.app.detection.v51_supervised_lifecycle import (
            score_governed_supervised_logs,
        )

        result = score_governed_supervised_logs(db, bounded_logs)
    except (OSError, ValueError, TypeError, KeyError, AttributeError, RuntimeError) as exc:
        status.update(
            {
                "state": "unavailable",
                "reason_code": "governed_shadow_scoring_failed",
                "scoring_allowed": False,
                "error_type": exc.__class__.__name__,
            }
        )
        return status

    rows = list(result.get("rows") or [])
    scored = [row for row in rows if not row.get("abstained")]
    scores = [
        float(row["queue_probability"])
        for row in scored
        if row.get("queue_probability") is not None
    ]
    queue_count = sum(row.get("queue_decision") == "needs_review" for row in scored)
    if not result.get("ok"):
        status.update(
            {
                "state": "unavailable",
                "reason_code": str(result.get("status") or "governed_shadow_scoring_failed"),
                "scoring_allowed": False,
            }
        )
    status.update(
        {
            "rows_considered": len(bounded_logs),
            "rows_scored": len(scored),
            "rows_abstained": len(rows) - len(scored),
            "queue_count": queue_count,
            "queue_rate": round(queue_count / len(scored), 6) if scored else 0.0,
            "score_summary": _score_summary(scores),
            "confidence_summary": _score_summary(scores),
        }
    )
    return status


def anomaly_runtime_status(
    *,
    requested: bool,
    artifact_available: bool,
    rows_scored: int,
    anomaly_count: int,
    error_type: str | None = None,
    score_values: Iterable[float] = (),
) -> dict[str, Any]:
    if not requested:
        state = "unavailable"
        reason_code = "anomaly_scoring_not_requested"
    elif error_type:
        state = "unavailable"
        reason_code = "anomaly_scoring_failed"
    elif not artifact_available:
        state = "unavailable"
        reason_code = "anomaly_artifact_missing"
    elif rows_scored == 0:
        state = "abstained"
        reason_code = "no_logs_scored"
    else:
        state = "active_advisory"
        reason_code = "isolation_forest_scored"
    return {
        "state": state,
        "reason_code": reason_code,
        "requested": requested,
        "artifact_available": artifact_available,
        "rows_scored": int(rows_scored),
        "anomaly_count": int(anomaly_count),
        "score_summary": _score_summary(score_values),
        "error_type": error_type,
        "limitation_codes": [
            "advisory_only",
            "known_benign_noise_possible",
            "not_alert_authoritative",
        ],
        "decision_support_only": True,
        "used_for_alert_creation": False,
        "used_for_severity": False,
        "used_for_suppression": False,
    }


def detection_layer_contract(
    *,
    rules_evaluated: int,
    authoritative_rule_signals: int,
    anomaly: dict[str, Any],
    supervised: dict[str, Any],
    response_simulation: bool,
    matched_rule_ids: Iterable[str] = (),
    authoritative_matched_rule_ids: Iterable[str] = (),
    candidate_logs: int = 0,
    alerts_created: int = 0,
    alerts_updated: int = 0,
) -> dict[str, Any]:
    def bounded_rule_ids(values: Iterable[str], *, limit: int = 20) -> dict[str, Any]:
        unique = sorted({str(value) for value in values if value})
        return {
            "values": unique[:limit],
            "count": len(unique),
            "truncated": len(unique) > limit,
        }

    rule_ids = bounded_rule_ids(matched_rule_ids)
    authoritative_ids = bounded_rule_ids(authoritative_matched_rule_ids)
    supervised_layer = dict(supervised)
    score_summary = supervised_layer.get("score_summary") or _score_summary([])
    supervised_layer.setdefault("confidence_summary", score_summary)
    supervised_layer["abstention"] = {
        "occurred": bool(
            supervised_layer.get("state") == "abstained"
            or int(supervised_layer.get("rows_abstained") or 0) > 0
        ),
        "rows": int(supervised_layer.get("rows_abstained") or 0),
        "eligibility_refused": supervised_layer.get("state")
        in {"unqualified", "unavailable"},
        "reason_code": (
            supervised_layer.get("reason_code")
            if supervised_layer.get("state") != "active_shadow"
            or int(supervised_layer.get("rows_abstained") or 0) > 0
            else None
        ),
    }
    advisory_active = anomaly.get("state") == "active_advisory" or supervised.get("state") == "active_shadow"
    advisory_signal_count = int(anomaly.get("anomaly_count") or 0) + int(
        supervised_layer.get("queue_count") or 0
    )
    if alerts_created or alerts_updated:
        analyst_priority = "authoritative_alert_review"
    elif candidate_logs or authoritative_rule_signals:
        analyst_priority = "authoritative_rule_review"
    elif advisory_signal_count:
        analyst_priority = "advisory_signal_review"
    else:
        analyst_priority = "routine_monitoring"

    if candidate_logs or authoritative_rule_signals:
        evidence_strength = "authoritative_rule_evidence"
    elif advisory_signal_count:
        evidence_strength = "advisory_evidence_only"
    else:
        evidence_strength = "no_detection_evidence"

    missing_context: list[str] = []
    if anomaly.get("state") != "active_advisory":
        missing_context.append("IsolationForest advisory score is unavailable for this run scope.")
    if supervised_layer.get("state") != "active_shadow":
        missing_context.append("A qualified supervised shadow score is unavailable.")
    if not authoritative_rule_signals:
        missing_context.append("No authoritative rule match was observed in this run scope.")

    recommended_checks: list[str] = []
    if alerts_created or alerts_updated:
        recommended_checks.append("Review the affected alerts and their linked normalized evidence.")
    elif authoritative_rule_signals:
        recommended_checks.append("Review rule matches that did not produce a new alert in this run.")
    if int(anomaly.get("anomaly_count") or 0):
        recommended_checks.append("Compare anomaly signals with rule evidence and expected source behavior.")
    if supervised_layer.get("state") != "active_shadow":
        recommended_checks.append("Treat missing supervised evidence as unknown, not as a benign verdict.")
    recommended_checks.append("Keep any response simulated and analyst-approved.")

    return {
        "contract_version": V558_RUNTIME_CONTRACT_VERSION,
        "rules": {
            "state": "active_authoritative",
            "rows_evaluated": int(rules_evaluated),
            "authoritative_signals": int(authoritative_rule_signals),
            "verdict": (
                "authoritative_match"
                if authoritative_rule_signals
                else "no_authoritative_match"
            ),
            "matched_rule_ids": rule_ids["values"],
            "matched_rule_id_count": rule_ids["count"],
            "matched_rule_ids_truncated": rule_ids["truncated"],
            "authoritative_matched_rule_ids": authoritative_ids["values"],
            "authoritative_matched_rule_id_count": authoritative_ids["count"],
            "authoritative_matched_rule_ids_truncated": authoritative_ids["truncated"],
            "can_create_alerts": True,
        },
        "anomaly": anomaly,
        "supervised": supervised_layer,
        "hybrid": {
            "state": "active_advisory" if advisory_active else "abstained",
            "reason_code": (
                "advisory_signal_available"
                if advisory_active
                else "no_qualified_advisory_signal"
            ),
            "analyst_priority": analyst_priority,
            "advisory_signal_count": advisory_signal_count,
            "decision_support_only": True,
            "used_for_alert_creation": False,
            "used_for_severity": False,
            "used_for_suppression": False,
        },
        "response": {
            "state": "simulation_only" if response_simulation else "unsafe_configuration",
            "automatic_response_enabled": False,
            "real_firewall_blocking_enabled": False,
        },
        "analyst_summary": {
            "evidence_strength": evidence_strength,
            "missing_context": missing_context[:3],
            "recommended_checks": recommended_checks[:3],
            "bounded": True,
        },
        "rule_detection_authoritative": True,
        "model_only_alert_creation_allowed": False,
        "production_promoted": False,
        "response_automation_allowed": False,
    }


def current_detection_runtime_status(db: Session) -> dict[str, Any]:
    settings = get_settings()
    supervised = supervised_runtime_status(db, requested=True)
    anomaly_available = settings.resolved_model_path.exists()
    anomaly = {
        "state": "active_advisory" if anomaly_available else "unavailable",
        "reason_code": (
            "artifact_ready_for_normal_detection_jobs"
            if anomaly_available
            else "anomaly_artifact_missing"
        ),
        "artifact_available": anomaly_available,
        "invoked_by_normal_detection": True,
        "decision_support_only": True,
        "used_for_alert_creation": False,
        "used_for_severity": False,
        "used_for_suppression": False,
    }
    hybrid_active = anomaly_available or supervised["state"] == "active_shadow"
    return {
        "ok": True,
        "contract_version": V558_RUNTIME_CONTRACT_VERSION,
        "rules": {
            "state": "active_authoritative",
            "invoked_by_normal_detection": True,
            "can_create_alerts": True,
        },
        "anomaly": anomaly,
        "supervised": {
            **supervised,
            "runtime_checked_by_normal_detection": True,
            "invoked_by_normal_detection": supervised["state"] == "active_shadow",
        },
        "hybrid": {
            "state": "active_advisory" if hybrid_active else "abstained",
            "invoked_by_normal_detection": hybrid_active,
            "used_for_alert_creation": False,
            "decision_support_only": True,
        },
        "response": {
            "state": (
                "simulation_only"
                if settings.response_simulation
                else "unsafe_configuration"
            ),
            "automatic_response_enabled": False,
            "real_firewall_blocking_enabled": False,
        },
        "production_promoted": False,
        "response_automation_allowed": False,
        "secrets_exposed": False,
    }
