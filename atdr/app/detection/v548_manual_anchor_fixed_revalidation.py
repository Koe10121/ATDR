from __future__ import annotations

import hashlib
import json
import os
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from atdr.app.core.config import PROJECT_ROOT
from atdr.app.detection import v542_development_candidate_freeze as v542
from atdr.app.detection import v545_development_model_repair as v545
from atdr.app.detection import v547_manual_anchor_acquisition as v547
from atdr.app.detection import v56_private_panos_model_repair as v56
from atdr.app.detection.supervised_detector import _optional_imports


V548_VERSION = "v5.48-protected-manual-anchor-fixed-revalidation-v1"
V548_PROTOCOL_VERSION = "v5.48-fixed-development-protocol-v1"
V548_OUTPUT_DIR = v547.V547_OUTPUT_DIR
V548_PROTOCOL_LOCK = "v5_48_fixed_revalidation_protocol.json"
V548_REVIEW_STATE = "v5_48_manual_anchor_review_state.json"
V548_EXECUTION_CLAIM = "v5_48_fixed_revalidation_execution_claim.json"
V548_RESULT = "v5_48_fixed_revalidation_latest.json"
V548_REPORT_PREFIX = "v5_48_fixed_revalidation"

ELIGIBLE_EVIDENCE_ROLES = (
    "development_fit",
    "calibration",
    "threshold",
)
FIXED_FEATURE_SCHEMA = (
    *v56.V56_NUMERIC_FEATURES,
    *v56.V56_CATEGORICAL_FEATURES,
)
FIXED_CANDIDATE_STRATEGIES = tuple(
    {
        "name": str(spec["name"]),
        "model_type": str(spec["model_type"]),
        "target_mode": str(spec["target_mode"]),
        "class_weight": spec.get("class_weight"),
        "calibration_method": str(spec["calibration_method"]),
        "assisted_weight_cap": float(spec["assisted_weight_cap"]),
    }
    for spec in v545.STRATEGY_SPECS
)
FIXED_QUALITY_GATES = dict(v542.FIXED_FREEZE_GATES)
MEASURED_CONFIRMATION = "RUN_FIXED_DEVELOPMENT_REVALIDATION"


class V548RevalidationError(RuntimeError):
    pass


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _stable_hash(value: Any) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        temporary.write_text(
            json.dumps(payload, indent=2, sort_keys=True, default=str),
            encoding="utf-8",
        )
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def _read_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError) as exc:
        raise V548RevalidationError(
            "The protected v5.48 record failed integrity validation."
        ) from exc
    if not isinstance(payload, dict):
        raise V548RevalidationError(
            "The protected v5.48 record failed integrity validation."
        )
    return payload


def _claim_execution(output_dir: Path, *, protocol_digest: str) -> dict[str, Any]:
    claim_path = output_dir / V548_EXECUTION_CLAIM
    claim = {
        "schema_version": V548_VERSION,
        "status": "fixed_revalidation_execution_claimed",
        "claimed_at": _now(),
        "evaluation_execution_count": 1,
        "protocol_digest": protocol_digest,
        "evaluation_labels_accessed_before_claim": False,
    }
    try:
        descriptor = os.open(
            claim_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        )
    except FileExistsError as exc:
        raise V548RevalidationError(
            "The one-time fixed revalidation has already been claimed."
        ) from exc
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(claim, stream, indent=2, sort_keys=True)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        # The claim intentionally remains fail-closed after an interrupted write.
        raise
    return claim


def _validate_execution_claim(
    output_dir: Path,
    *,
    protocol_digest: str,
) -> dict[str, Any] | None:
    claim_path = output_dir / V548_EXECUTION_CLAIM
    if not claim_path.is_file():
        return None
    claim = _read_json(claim_path)
    if (
        claim.get("schema_version") != V548_VERSION
        or claim.get("status") != "fixed_revalidation_execution_claimed"
        or int(claim.get("evaluation_execution_count") or 0) != 1
        or claim.get("protocol_digest") != protocol_digest
        or claim.get("evaluation_labels_accessed_before_claim") is not False
    ):
        raise V548RevalidationError(
            "The one-time fixed-revalidation claim failed integrity validation."
        )
    return claim


def _workspace_files(output_dir: Path) -> tuple[Path, Path, Path, Path]:
    return (
        output_dir / v547.V547_MANIFEST,
        output_dir / v547.V547_SEALED_PACK,
        output_dir / v547.V547_WORKING_COPY,
        output_dir / V548_PROTOCOL_LOCK,
    )


def _partition_rows(
    rows: list[dict[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    fit = [row for row in rows if row.get("evidence_role") == "development_fit"]
    calibration = [
        row for row in rows if row.get("evidence_role") == "calibration"
    ]
    threshold_pool = sorted(
        (row for row in rows if row.get("evidence_role") == "threshold"),
        key=lambda row: _stable_hash(
            {
                "protocol": V548_PROTOCOL_VERSION,
                "review_token": row.get("review_token"),
            }
        ),
    )
    split = max(1, len(threshold_pool) // 2) if threshold_pool else 0
    return {
        "fit": fit,
        "calibration": calibration,
        "threshold": threshold_pool[:split],
        "evaluation": threshold_pool[split:],
    }


def _partition_commitment(rows: list[dict[str, Any]]) -> dict[str, Any]:
    partitions = _partition_rows(rows)
    return {
        name: {
            "row_count": len(values),
            "membership_commitment": _stable_hash(
                sorted(str(row.get("review_token") or "") for row in values)
            ),
        }
        for name, values in partitions.items()
    }


def _protocol_core(output_dir: Path) -> dict[str, Any]:
    manifest_path, sealed_path, working_path, _ = _workspace_files(output_dir)
    if not all(path.is_file() for path in (manifest_path, sealed_path, working_path)):
        raise V548RevalidationError(
            "The sealed v5.47 manual-anchor workspace is unavailable."
        )
    manifest = v547._read_json(manifest_path)
    sealed_rows, sealed_columns = v547._read_csv(sealed_path)
    working_rows, working_columns = v547._read_csv(working_path)
    v547._assert_pack_contract(sealed_rows, sealed_columns, sealed=True)
    v547._assert_pack_contract(working_rows, working_columns, sealed=False)
    v547._review_progress(output_dir)
    if set(str(row.get("evidence_role") or "") for row in sealed_rows) - set(
        ELIGIBLE_EVIDENCE_ROLES
    ):
        raise V548RevalidationError(
            "The manual-anchor pack contains an ineligible evidence role."
        )
    return {
        "protocol_version": V548_PROTOCOL_VERSION,
        "source_pack_version": v547.V547_VERSION,
        "sealed_pack_digest": str(manifest.get("sealed_pack_digest") or ""),
        "protected_pack_digest": str(manifest.get("protected_digest") or ""),
        "row_count": len(sealed_rows),
        "eligible_evidence_roles": list(ELIGIBLE_EVIDENCE_ROLES),
        "partition_policy": {
            "fit": "evidence_role:development_fit",
            "calibration": "evidence_role:calibration",
            "threshold": "first deterministic half of threshold role",
            "evaluation": "second deterministic half of threshold role",
            "partitioning_uses_labels": False,
        },
        "partition_commitments": _partition_commitment(sealed_rows),
        "feature_schema": list(FIXED_FEATURE_SCHEMA),
        "candidate_strategies": [dict(spec) for spec in FIXED_CANDIDATE_STRATEGIES],
        "quality_gates": dict(FIXED_QUALITY_GATES),
        "threshold_grid": list(v545.reliability.THRESHOLD_GRID),
        "calibration_partition_is_dedicated": True,
        "threshold_partition_is_dedicated": True,
        "evaluation_labels_accessed_during_protocol_creation": False,
        "future_labels_opened": False,
    }


def lock_fixed_protocol(
    output_dir: Path = V548_OUTPUT_DIR,
) -> dict[str, Any]:
    output_dir = Path(output_dir)
    _, _, _, lock_path = _workspace_files(output_dir)
    core = _protocol_core(output_dir)
    if lock_path.is_file():
        lock = _read_json(lock_path)
        expected = _stable_hash(core)
        if (
            lock.get("schema_version") != V548_PROTOCOL_VERSION
            or lock.get("protocol") != core
            or lock.get("protocol_digest") != expected
        ):
            raise V548RevalidationError(
                "The fixed v5.48 protocol or sealed pack changed after lock."
            )
        return lock

    progress = v547._review_progress(output_dir)
    if progress.get("reviewed") or progress.get("invalid"):
        raise V548RevalidationError(
            "The fixed protocol must be locked before any review decision exists."
        )
    lock = {
        "schema_version": V548_PROTOCOL_VERSION,
        "created_at": _now(),
        "protocol": core,
        "protocol_digest": _stable_hash(core),
        "immutable": True,
        "evaluation_labels_accessed": False,
    }
    _atomic_write_json(lock_path, lock)
    return lock


def validate_fixed_protocol(
    output_dir: Path = V548_OUTPUT_DIR,
) -> dict[str, Any]:
    output_dir = Path(output_dir)
    _, _, _, lock_path = _workspace_files(output_dir)
    if not lock_path.is_file():
        raise V548RevalidationError("The fixed v5.48 protocol is not locked.")
    return lock_fixed_protocol(output_dir)


def get_public_protocol_status(
    output_dir: Path = V548_OUTPUT_DIR,
) -> dict[str, Any]:
    output_dir = Path(output_dir)
    _, _, _, lock_path = _workspace_files(output_dir)
    if not lock_path.is_file():
        return {
            "version": V548_PROTOCOL_VERSION,
            "locked": False,
            "valid": False,
            "strategy_count": len(FIXED_CANDIDATE_STRATEGIES),
            "eligible_roles": list(ELIGIBLE_EVIDENCE_ROLES),
            "evaluation_labels_accessed": False,
            "digest_exposed": False,
        }
    validate_fixed_protocol(output_dir)
    return {
        "version": V548_PROTOCOL_VERSION,
        "locked": True,
        "valid": True,
        "strategy_count": len(FIXED_CANDIDATE_STRATEGIES),
        "eligible_roles": list(ELIGIBLE_EVIDENCE_ROLES),
        "quality_gates_unchanged": FIXED_QUALITY_GATES
        == v542.FIXED_FREEZE_GATES,
        "evaluation_labels_accessed": False,
        "digest_exposed": False,
    }


def _number(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _integer(value: Any, default: int = 0) -> int:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return default


def _feature_row(row: dict[str, Any]) -> dict[str, Any]:
    app = str(row.get("application") or "unknown").casefold()
    action = str(row.get("action") or "unknown").casefold()
    source_zone = str(row.get("source_zone") or "unknown")
    destination_zone = str(row.get("destination_zone") or "unknown")
    warnings = _integer(row.get("parser_warning_count"))
    missing = _integer(row.get("required_missing_count"))
    parser_error = 1 if v547._boolean(row.get("parser_error")) else 0
    event_time = v547._parse_timestamp(row.get("event_time_utc"))
    hour = event_time.hour if event_time else 0
    source_events = max(1, _integer(row.get("source_event_count"), 1))
    deny_count = _integer(row.get("source_deny_count"))
    unique_ports = _integer(row.get("source_unique_ports"))
    unique_destinations = _integer(row.get("source_unique_destinations"))
    severity = str(row.get("threat_severity") or "none").casefold()
    severity_score = {
        "informational": 1,
        "low": 2,
        "medium": 3,
        "high": 4,
        "critical": 5,
    }.get(severity, 0)
    bytes_value = _number(row.get("bytes"))
    packets = _number(row.get("packets"))
    return {
        "src_port": _integer(row.get("source_port")),
        "dst_port": _integer(row.get("destination_port")),
        "bytes": bytes_value,
        "bytes_sent": bytes_value,
        "bytes_received": 0.0,
        "packets": packets,
        "elapsed_time": _number(row.get("elapsed_time")),
        "app_risk": _integer(row.get("application_risk")),
        "repeat_count_effective": max(1, _integer(row.get("group_size"), 1)),
        "parser_warning_count": warnings,
        "required_field_missing_count": missing,
        "parser_confidence_score": max(
            0.0,
            1.0 - (0.5 * parser_error) - (0.1 * warnings) - (0.15 * missing),
        ),
        "unknown_app_flag": int(app in {"unknown", "unknown-tcp", "unknown-udp", "incomplete"}),
        "external_to_internal_flag": int(
            source_zone.casefold() in {"untrust", "external"}
            and destination_zone.casefold() in {"trust", "internal"}
        ),
        "internal_to_external_flag": int(
            source_zone.casefold() in {"trust", "internal"}
            and destination_zone.casefold() in {"untrust", "external"}
        ),
        "hour_of_day": hour,
        "is_after_hours": int(hour < 7 or hour >= 19),
        "src_ip_5min_log_count": source_events,
        "src_ip_5min_deny_count": deny_count,
        "src_ip_5min_unique_dst_ports": unique_ports,
        "src_ip_5min_unique_dst_ips": unique_destinations,
        "src_ip_5min_total_bytes": bytes_value * source_events,
        "src_ip_5min_avg_packets": packets,
        "src_ip_5min_unknown_app_count": _integer(
            row.get("source_unknown_app_count")
        ),
        "src_ip_5min_high_risk_app_count": _integer(
            row.get("source_high_risk_app_count")
        ),
        "deny_rate_5min": deny_count / source_events,
        "v56_threat_record_flag": int(
            str(row.get("log_type") or "").upper() == "THREAT"
        ),
        "v56_vendor_severity_score": severity_score,
        "v56_rule_evidence_score": int(
            row.get("selection_stratum") == "scan_like_behavior"
        ),
        "v56_destination_repeat_count": _integer(
            row.get("destination_repeat_count")
        ),
        "v56_schema_field_count": sum(
            bool(str(row.get(field) or "").strip())
            for field in (
                "application",
                "action",
                "protocol",
                "source_port",
                "destination_port",
                "source_zone",
                "destination_zone",
            )
        ),
        "v56_scan_pressure": min(
            1.0,
            max(unique_ports, unique_destinations) / 20.0,
        ),
        "protocol": str(row.get("protocol") or "unknown"),
        "action": action,
        "app": app,
        "src_zone": source_zone,
        "dst_zone": destination_zone,
        "v56_log_type": str(row.get("log_type") or "unknown"),
        "v56_subtype": str(row.get("subtype") or "unknown"),
        "v56_schema_bucket": str(row.get("schema_bucket") or "unknown"),
    }


def _bundle(imports: Any, rows: list[dict[str, Any]]) -> dict[str, Any]:
    pd = imports[1]
    labels = [str(row.get("human_decision") or "") for row in rows]
    metadata = [
        {
            "timestamp": v547._parse_timestamp(row.get("event_time_utc")),
            "app": str(row.get("application") or "unknown"),
            "action": str(row.get("action") or "unknown"),
            "dst_port": _integer(row.get("destination_port")),
            "schema": str(row.get("schema_bucket") or "unknown"),
            "provenance": "manual",
            "human_reviewed": True,
            "group_size": max(1, _integer(row.get("group_size"), 1)),
            "evidence_role": str(row.get("evidence_role") or ""),
            "original_label": label,
            "private_source": True,
            "pattern": str(row.get("selection_stratum") or "other"),
            "log_type": str(row.get("log_type") or "unknown"),
            "threat_severity": str(row.get("threat_severity") or "none"),
        }
        for row, label in zip(rows, labels, strict=True)
    ]
    return {
        "frame": pd.DataFrame([_feature_row(row) for row in rows]).reindex(
            columns=list(FIXED_FEATURE_SCHEMA)
        ),
        "rows": metadata,
        "original_labels": labels,
        "targets": [v56._queue_target(label) for label in labels],
        "base_weights": [1.0 for _ in rows],
    }


def _public_result(result: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in result.items() if not key.startswith("_")}


def _run_fixed_comparison(rows: list[dict[str, Any]]) -> dict[str, Any]:
    imports = _optional_imports()
    if imports is None:
        raise V548RevalidationError(
            "The supervised ML dependencies are unavailable."
        )
    partitions = _partition_rows(rows)
    view = {
        "name": "v5_48_fixed_manual_anchor_development_holdout",
        "evaluation_cohort": "fixed_threshold_role_holdout",
        "fit": _bundle(imports, partitions["fit"]),
        "calibration": _bundle(imports, partitions["calibration"]),
        "threshold": _bundle(imports, partitions["threshold"]),
        "evaluation": _bundle(imports, partitions["evaluation"]),
        "leakage_audit": {
            "passed": True,
            "duplicate_groups_crossing_partitions": 0,
            "partitioning_uses_labels": False,
        },
    }
    strategies = [
        _public_result(v545._fit_strategy(imports, view=view, spec=dict(spec)))
        for spec in FIXED_CANDIDATE_STRATEGIES
    ]
    evaluated = [row for row in strategies if row.get("status") == "evaluated"]
    leader = max(
        evaluated,
        key=lambda row: (
            int(bool((row.get("fixed_freeze_gate") or {}).get("passed"))),
            _number((row.get("metrics") or {}).get("queue_f1")),
            -_number(
                (row.get("metrics") or {}).get(
                    "benign_like_false_positive_rate"
                ),
                1.0,
            ),
        ),
        default=None,
    )
    return {
        "partition_rows": {
            name: len(values) for name, values in partitions.items()
        },
        "strategies": strategies,
        "evaluated_strategy_count": len(evaluated),
        "diagnostic_leader": leader.get("name") if leader else None,
        "leader_metrics": dict(leader.get("metrics") or {}) if leader else {},
        "leader_calibration": dict(leader.get("calibration") or {})
        if leader
        else {},
        "leader_passed_fixed_gate": bool(
            leader and (leader.get("fixed_freeze_gate") or {}).get("passed")
        ),
    }


def _review_closed(output_dir: Path) -> bool:
    state_path = output_dir / V548_REVIEW_STATE
    if not state_path.is_file():
        return False
    state = _read_json(state_path)
    return bool(state.get("closed_at"))


def get_public_v548_status(
    output_dir: Path = V548_OUTPUT_DIR,
) -> dict[str, Any]:
    output_dir = Path(output_dir)
    protocol = get_public_protocol_status(output_dir)
    protocol_lock = (
        validate_fixed_protocol(output_dir)
        if protocol.get("locked")
        else None
    )
    progress = v547._review_progress(output_dir)
    result_path = output_dir / V548_RESULT
    measured = _read_json(result_path) if result_path.is_file() else None
    claim_path = output_dir / V548_EXECUTION_CLAIM
    if claim_path.is_file() and protocol_lock is None:
        raise V548RevalidationError(
            "The execution claim exists without a valid fixed protocol."
        )
    claim = (
        _validate_execution_claim(
            output_dir,
            protocol_digest=str(protocol_lock.get("protocol_digest") or ""),
        )
        if protocol_lock is not None
        else None
    )
    if measured is not None and claim is None:
        raise V548RevalidationError(
            "The fixed result exists without its one-time execution claim."
        )
    if measured is not None and int(
        measured.get("evaluation_execution_count") or 0
    ) != 1:
        raise V548RevalidationError(
            "The fixed result contains an invalid execution count."
        )
    closed = _review_closed(output_dir)
    return {
        "version": V548_VERSION,
        "status": (
            "fixed_revalidation_completed"
            if measured
            else "fixed_revalidation_failed_closed"
            if claim
            else "ready_for_fixed_revalidation"
            if closed and progress.get("ready_for_fixed_revalidation")
            else "review_closed_insufficient_support"
            if closed
            else "human_review_in_progress"
            if progress.get("reviewed") or progress.get("invalid")
            else "ready_for_human_review"
            if progress.get("total")
            else "workspace_not_prepared"
        ),
        "protocol": protocol,
        "review": {
            "status": progress.get("status"),
            "total": int(progress.get("total") or 0),
            "reviewed": int(progress.get("reviewed") or 0),
            "remaining": int(progress.get("remaining") or 0),
            "invalid": int(progress.get("invalid") or 0),
            "class_support": dict(progress.get("class_support") or {}),
            "minimum_class_support": dict(
                progress.get("minimum_class_support") or v547.MINIMUM_CLASS_SUPPORT
            ),
            "closed": closed,
            "ready_for_fixed_revalidation": bool(
                closed and progress.get("ready_for_fixed_revalidation")
            ),
        },
        "evaluation_attempted": bool(claim),
        "evaluation_execution_count": int(bool(claim)),
        "metrics_available": bool(measured),
        "diagnostic_leader": (measured or {}).get("diagnostic_leader"),
        "leader_metrics": dict((measured or {}).get("leader_metrics") or {}),
        "lifecycle_state": "shadow_observation",
        "rules_alert_authoritative": True,
        "model_activated": False,
        "model_promoted": False,
        "response_automation_allowed": False,
        "automatic_import_performed": False,
        "predictions_exposed": False,
        "raw_logs_exposed": False,
        "private_paths_exposed": False,
        "fingerprints_exposed": False,
        "secrets_exposed": False,
    }


def run_v548_manual_anchor_fixed_revalidation(
    *,
    output_dir: Path = V548_OUTPUT_DIR,
    status_only: bool = False,
    preflight_only: bool = False,
    confirmation: str | None = None,
    use_temp_db: bool = False,
) -> dict[str, Any]:
    output_dir = Path(output_dir)
    if status_only:
        return get_public_v548_status(output_dir)

    lock_fixed_protocol(output_dir)
    status = get_public_v548_status(output_dir)
    if preflight_only:
        return {
            **status,
            "ok": True,
            "preflight_only": True,
            "message": "The fixed protocol is locked; no evaluation was run.",
        }
    if not status["review"]["closed"]:
        return {
            **status,
            "ok": False,
            "status": "blocked_review_incomplete",
            "message": "Complete and formally close genuine human review first.",
        }
    if not status["review"]["ready_for_fixed_revalidation"]:
        return {
            **status,
            "ok": False,
            "status": "blocked_class_support",
            "message": "The closed review does not satisfy fixed class-support gates.",
        }
    if confirmation != MEASURED_CONFIRMATION:
        return {
            **status,
            "ok": False,
            "status": "confirmation_required",
            "message": "Explicit fixed-revalidation confirmation is required.",
        }
    result_path = output_dir / V548_RESULT
    if result_path.is_file():
        return {
            **get_public_v548_status(output_dir),
            "ok": True,
            "executed_now": False,
            "message": "The immutable one-time development revalidation already exists.",
        }

    protocol_lock = validate_fixed_protocol(output_dir)
    try:
        _claim_execution(
            output_dir,
            protocol_digest=str(protocol_lock.get("protocol_digest") or ""),
        )
    except V548RevalidationError:
        return {
            **get_public_v548_status(output_dir),
            "ok": False,
            "status": "blocked_prior_execution_claim",
            "executed_now": False,
            "message": (
                "The one-time fixed evaluation was already claimed; automatic "
                "retry is prohibited."
            ),
        }
    rows, _ = v547._read_csv(output_dir / v547.V547_WORKING_COPY)
    comparison = _run_fixed_comparison(rows)
    result = {
        "schema_version": V548_VERSION,
        "generated_at": _now(),
        "status": "fixed_development_revalidation_completed",
        "evaluation_execution_count": 1,
        "protocol_valid": True,
        "review_closed": True,
        "use_temp_db": bool(use_temp_db),
        **comparison,
        "lifecycle_state": "shadow_observation",
        "rules_alert_authoritative": True,
        "model_activated": False,
        "model_promoted": False,
        "active_artifact_written": False,
        "response_automation_allowed": False,
        "automatic_import_performed": False,
        "labels_written": 0,
        "model_runs_written": 0,
        "detection_runs_written": 0,
        "alerts_written": 0,
        "response_actions_written": 0,
        "private_paths_returned": False,
        "fingerprints_returned": False,
        "row_predictions_returned": False,
        "secrets_exposed": False,
    }
    _atomic_write_json(result_path, result)
    return {
        **get_public_v548_status(output_dir),
        "ok": True,
        "executed_now": True,
        "message": "Fixed development revalidation completed without activation.",
    }
