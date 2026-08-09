from __future__ import annotations

import json
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from atdr.app.core.config import PROJECT_ROOT
from atdr.app.db.models import (
    Alert,
    DetectionRun,
    MLLabel,
    MLModelRun,
    MLShadowObservation,
    ResponseAction,
)
from atdr.app.detection.supervised_detector import _artifact_hash
from atdr.app.detection.v51_supervised_lifecycle import (
    ACTIVE_OPERATIONS,
    SHADOW_TELEMETRY_OPERATION,
)
from atdr.app.detection.v520_schema_aware_abstention import (
    public_schema_abstention_policy,
)


DEFAULT_OUTPUT_DIR = PROJECT_ROOT / "ml_baseline_reviews"
V528_READINESS_LATEST = "v5_28_supervised_shadow_readiness_latest.json"
V528_VERSION = "v5.28.0"


def _stamp() -> str:
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")


def _database_state(db: Session) -> dict[str, int]:
    return {
        "labels": int(db.scalar(select(func.count(MLLabel.id))) or 0),
        "model_runs": int(db.scalar(select(func.count(MLModelRun.id))) or 0),
        "alerts": int(db.scalar(select(func.count(Alert.id))) or 0),
        "detection_runs": int(db.scalar(select(func.count(DetectionRun.id))) or 0),
        "response_actions": int(
            db.scalar(select(func.count(ResponseAction.id))) or 0
        ),
    }


def _latest_lifecycle(db: Session) -> MLModelRun | None:
    return db.scalar(
        select(MLModelRun)
        .where(MLModelRun.operation.in_(ACTIVE_OPERATIONS))
        .order_by(desc(MLModelRun.created_at), desc(MLModelRun.id))
        .limit(1)
    )


def _registered_model(db: Session, lifecycle: MLModelRun | None) -> MLModelRun | None:
    if lifecycle is None or lifecycle.operation == "disable_supervised_governed":
        return None
    metrics = lifecycle.metrics_json or {}
    model_run_id = metrics.get("model_run_id") or metrics.get(
        "restored_model_run_id"
    )
    try:
        return db.get(MLModelRun, int(model_run_id))
    except (TypeError, ValueError):
        return None


def _artifact_contract(model_run: MLModelRun | None) -> dict[str, Any]:
    if model_run is None:
        return {
            "available": False,
            "checksum_valid": False,
            "metadata_loaded": False,
            "metadata_status": "no_registered_shadow_artifact",
            "feature_schema": {},
            "calibration": {},
        }
    path = Path(model_run.model_path)
    before_state = (
        (path.stat().st_size, path.stat().st_mtime_ns) if path.is_file() else None
    )
    checksum = _artifact_hash(path) if path.is_file() else None
    checksum_valid = bool(checksum and checksum == model_run.artifact_sha256)
    artifact: dict[str, Any] = {}
    if checksum_valid:
        try:
            import joblib

            loaded = joblib.load(path)
            if isinstance(loaded, dict):
                artifact = loaded
        except (OSError, ValueError, TypeError, KeyError):
            artifact = {}
    after_state = (
        (path.stat().st_size, path.stat().st_mtime_ns) if path.is_file() else None
    )
    feature_schema = artifact.get("feature_schema") or {}
    numeric = list(feature_schema.get("numeric") or [])
    categorical = list(feature_schema.get("categorical") or [])
    excluded = list(feature_schema.get("excluded_leakage_features") or [])
    threshold = artifact.get("threshold")
    try:
        valid_threshold = 0.0 <= float(threshold) <= 1.0
    except (TypeError, ValueError):
        valid_threshold = False
    return {
        "available": path.is_file(),
        "checksum_valid": checksum_valid,
        "artifact_unchanged_during_audit": before_state == after_state,
        "metadata_loaded": bool(artifact),
        "metadata_status": "registered" if artifact else "unavailable_or_invalid",
        "schema_version_configured": bool(artifact.get("schema_version")),
        "model_version": artifact.get("model_version") or model_run.model_version,
        "model_type": artifact.get("model_type")
        or (model_run.metrics_json or {}).get("model_type"),
        "target_mode": artifact.get("target_mode")
        or (model_run.metrics_json or {}).get("target_mode"),
        "feature_schema": {
            "feature_set_version": artifact.get("feature_set_version"),
            "numeric_feature_count": len(numeric),
            "categorical_feature_count": len(categorical),
            "excluded_leakage_feature_count": len(excluded),
            "schema_present": bool(numeric or categorical),
        },
        "calibration": {
            "method": artifact.get("calibration_method")
            or (model_run.metrics_json or {}).get("calibration_method"),
            "method_configured": bool(
                artifact.get("calibration_method")
                or (model_run.metrics_json or {}).get("calibration_method")
            ),
            "threshold_configured": valid_threshold,
            "positive_class": artifact.get("positive_class"),
            "positive_class_contract_valid": artifact.get("positive_class")
            == "needs_review",
        },
        "private_path_returned": False,
        "artifact_hash_returned": False,
        "dataset_fingerprint_returned": False,
    }


def _latency_contract(model_run: MLModelRun | None) -> dict[str, Any]:
    metrics = (model_run.metrics_json or {}) if model_run else {}
    runtime = metrics.get("runtime_checks") or {}
    latency = runtime.get("latency_ms") or {}
    return {
        "registered_runtime_check_present": bool(runtime),
        "sample_rows": int(runtime.get("sample_rows") or 0),
        "p95_ms": latency.get("p95"),
        "gate_ms": runtime.get("latency_gate_ms"),
        "gate_passed": bool(runtime.get("latency_gate_passed")),
        "serialization_round_trip": bool(
            runtime.get("serialization_round_trip")
        ),
        "probabilities_bounded": bool(runtime.get("probabilities_bounded")),
    }


def _drift_contract(db: Session, model_run: MLModelRun | None) -> dict[str, Any]:
    latest = db.scalar(
        select(MLShadowObservation)
        .order_by(desc(MLShadowObservation.created_at), desc(MLShadowObservation.id))
        .limit(1)
    )
    observations = int(
        db.scalar(select(func.count(MLShadowObservation.id))) or 0
    )
    telemetry_run = db.scalar(
        select(MLModelRun)
        .where(MLModelRun.operation == SHADOW_TELEMETRY_OPERATION)
        .where(
            MLModelRun.model_version == model_run.model_version
            if model_run and model_run.model_version
            else True
        )
        .order_by(desc(MLModelRun.created_at), desc(MLModelRun.id))
        .limit(1)
    )
    telemetry = ((telemetry_run.metrics_json or {}).get("telemetry") or {}) if telemetry_run else {}
    return {
        "shadow_observation_count": observations,
        "latest_status": latest.status if latest else "not_observed",
        "latest_drift_state": latest.drift_status
        if latest
        else "Insufficient Evidence",
        "latest_rows_evaluated": int(latest.rows_evaluated) if latest else 0,
        "latest_queue_rate": float(latest.queue_rate) if latest else None,
        "durable_telemetry_available": bool(telemetry_run),
        "durable_inference_count": int(telemetry.get("inference_count") or 0),
        "durable_failure_count": int(telemetry.get("failure_count") or 0),
        "raw_logs_returned": False,
        "private_identifiers_returned": False,
    }


def _registry_contract(
    db: Session,
    lifecycle: MLModelRun | None,
    model_run: MLModelRun | None,
) -> dict[str, Any]:
    rows = list(
        db.scalars(
            select(MLModelRun).order_by(
                desc(MLModelRun.created_at),
                desc(MLModelRun.id),
            )
        )
    )
    return {
        "entries": len(rows),
        "operations": dict(sorted(Counter(row.operation for row in rows).items())),
        "statuses": dict(sorted(Counter(row.status for row in rows).items())),
        "lifecycle_entry_present": lifecycle is not None,
        "registered_artifact_entry_present": model_run is not None,
        "active_metadata_status": "registered"
        if model_run is not None
        else "metadata_unavailable",
        "production_promoted": False,
        "response_automation_allowed": False,
        "paths_returned": False,
        "hashes_returned": False,
    }


def post_review_decision_tree() -> list[dict[str, Any]]:
    return [
        {
            "condition": "fewer_than_20_legitimate_reviews_or_one_queue_class",
            "decision": "withhold_all_blind_metrics",
            "next_action": "continue_independent_human_review",
        },
        {
            "condition": "review_copy_or_integrity_contract_invalid",
            "decision": "fail_closed_without_metrics",
            "next_action": "repair_review_copy_only_and_preserve_sealed_pack",
        },
        {
            "condition": "locked_metrics_fail_fixed_quality_gates",
            "decision": "remain_shadow_observation",
            "next_action": "repair_on_development_evidence_then_create_a_new_blind_pack",
        },
        {
            "condition": "locked_metrics_pass_fixed_quality_gates",
            "decision": "remain_shadow_until_independent_evidence_and_governance_complete",
            "next_action": "require_second_source_or_new_blind_evidence_and_explicit_activation_review",
        },
        {
            "condition": "any_prediction_leakage_or_lock_mismatch",
            "decision": "invalidate_blind_pack",
            "next_action": "generate_a_new_untouched_pack_without_reusing_exposed_rows",
        },
    ]


def render_readiness_report(report: dict[str, Any]) -> str:
    artifact = report.get("artifact_contract") or {}
    calibration = artifact.get("calibration") or {}
    drift = report.get("drift") or {}
    lines = [
        "# v5.28 Supervised Shadow Readiness Audit",
        "",
        f"- Lifecycle: `{report.get('lifecycle_state')}`",
        f"- Review gate: `{report.get('review_gate')}`",
        f"- Registered artifact: `{artifact.get('available')}`",
        f"- Artifact checksum valid: `{artifact.get('checksum_valid')}`",
        f"- Calibration method configured: `{calibration.get('method_configured')}`",
        f"- Abstention fails closed: `{(report.get('abstention') or {}).get('fail_closed')}`",
        f"- Latest drift state: `{drift.get('latest_drift_state')}`",
        "- Model activated by audit: `false`",
        "- Rules remain alert-authoritative: `true`",
        "- Response automation enabled: `false`",
        "",
        "## Post-Review Decision Tree",
        "",
    ]
    lines.extend(
        f"- `{item['condition']}` -> `{item['decision']}`; {item['next_action']}."
        for item in report.get("post_review_decision_tree") or []
    )
    return "\n".join(lines) + "\n"


def run_v528_supervised_readiness_audit(
    db: Session,
    *,
    output_dir: Path = DEFAULT_OUTPUT_DIR,
    review_progress: dict[str, Any] | None = None,
    write_reports: bool = True,
) -> dict[str, Any]:
    before = _database_state(db)
    lifecycle = _latest_lifecycle(db)
    model_run = _registered_model(db, lifecycle)
    artifact = _artifact_contract(model_run)
    configured_state = (
        str((lifecycle.metrics_json or {}).get("lifecycle_state") or lifecycle.status)
        if lifecycle is not None
        else "inactive"
    )
    lifecycle_state = (
        configured_state
        if configured_state in {"shadow_observation", "decision_support"}
        and artifact.get("available")
        and artifact.get("checksum_valid")
        else "inactive"
    )
    progress = review_progress or {}
    report = {
        "ok": True,
        "status": "v5_28_shadow_readiness_audited_review_pending",
        "schema_version": V528_VERSION,
        "generated_at": datetime.now(UTC).isoformat(),
        "lifecycle_state": lifecycle_state,
        "configured_lifecycle_state": configured_state,
        "review_gate": (
            "ready_for_locked_post_review_evaluation"
            if progress.get("enough_for_locked_evaluation") is True
            else "human_review_pending"
        ),
        "reviewed_rows": int(progress.get("reviewed") or 0),
        "blind_metrics_calculated": False,
        "artifact_contract": artifact,
        "abstention": public_schema_abstention_policy(),
        "latency": _latency_contract(model_run),
        "drift": _drift_contract(db, model_run),
        "registry": _registry_contract(db, lifecycle, model_run),
        "post_review_decision_tree": post_review_decision_tree(),
        "safety": {
            "label_independent_checks_only": True,
            "locked_evidence_opened": False,
            "predictions_rerun": False,
            "candidate_selected": False,
            "model_retrained": False,
            "model_recalibrated": False,
            "model_activated": False,
            "model_promoted": False,
            "model_artifacts_written": 0,
            "labels_created_or_updated": 0,
            "response_actions_created": 0,
            "rules_remain_alert_authoritative": True,
            "automatic_response_enabled": False,
            "real_firewall_blocking_enabled": False,
        },
        "paths_returned": False,
        "hashes_returned": False,
        "private_identifiers_returned": False,
    }
    after = _database_state(db)
    report["safety"]["database_state_unchanged"] = before == after
    report["ok"] = bool(
        report["safety"]["database_state_unchanged"]
        and artifact.get("artifact_unchanged_during_audit", True)
    )
    if write_reports:
        output_dir.mkdir(parents=True, exist_ok=True)
        serialized = json.dumps(report, indent=2, sort_keys=True, default=str)
        (output_dir / V528_READINESS_LATEST).write_text(
            serialized,
            encoding="utf-8",
        )
        (output_dir / f"v5_28_supervised_shadow_readiness_{_stamp()}.json").write_text(
            serialized,
            encoding="utf-8",
        )
        (output_dir / f"v5_28_supervised_shadow_readiness_{_stamp()}.md").write_text(
            render_readiness_report(report),
            encoding="utf-8",
        )
    return report
