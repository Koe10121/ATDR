from __future__ import annotations

import csv
import hashlib
import json
import re
import sqlite3
import tempfile
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from statistics import mean
from typing import Any, Iterable

from sqlalchemy.orm import Session

from atdr.app.core.config import get_settings
from atdr.app.detection import v398_independent_holdout_validation as frozen
from atdr.app.detection import v49_detection_ml_reliability as reliability
from atdr.app.detection import v52_shadow_reliability as v52
from atdr.app.detection import v54_temporal_evidence as v54
from atdr.app.detection import v55_development_model_repair as v55
from atdr.app.detection import v56_private_panos_model_repair as v56
from atdr.app.detection.supervised_detector import _optional_imports
from atdr.app.detection.v330_detection_ml_quality import OUTPUT_DIR


V57_VERSION = "v5.7-independent-shadow-revalidation-v1"
V57_MANIFEST_VERSION = "v5.7-independent-evidence-manifest-v1"
V57_LATEST = "v5_7_independent_shadow_revalidation_latest.json"
V57_CANDIDATE_FREEZE = "v5_7_frozen_candidate_manifest_latest.json"
V57_PREDICTION_FREEZE = "v5_7_prediction_freeze_latest.json"
V57_DEVELOPMENT_REFERENCE = "v5_7_development_reference_lock.json"
V57_EVIDENCE_LOCK_AUDIT = "v5_7_evidence_lock_audit_latest.json"
V57_GATES = {
    "queue_f1_min": 0.85,
    "benign_like_false_positive_rate_max": 0.05,
    "suspicious_recall_min": 0.80,
    "malicious_recall_min": 0.80,
    "expected_calibration_error_max": 0.10,
    "max_confidence_accuracy_gap_max": 0.15,
}
ALLOWED_SCHEMA_FAMILIES = {
    "native_panos_syslog",
    "compatible_panos_normalized",
}
ALLOWED_GROUND_TRUTH_PROVENANCE = {
    "human_reviewed",
    "advisor_approved_human_review",
    "provider_ground_truth",
}
ALLOWED_OVERLAP_AUDIT_METHODS = {
    "fingerprint_comparison_against_v53_v56",
    "cryptographic_fingerprint_and_duplicate_family_comparison",
}
VALID_DECISIONS = {
    "benign",
    "benign_unusual",
    "needs_context",
    "suspicious",
    "malicious",
}
PRIVATE_EVIDENCE_RESEARCH = (
    {
        "dataset": "PAN-OS traffic log field documentation",
        "publisher": "Palo Alto Networks",
        "official_url": (
            "https://docs.paloaltonetworks.com/ngfw/administration/"
            "monitoring/use-syslog-for-monitoring/"
            "syslog-field-descriptions/traffic-log-fields"
        ),
        "finding": "schema_reference_only",
        "version": "current vendor field reference",
        "schema": "native PAN-OS traffic log field contract",
        "license": "documentation reference; not a dataset license",
        "checksum": "not_applicable_no_corpus",
        "native_panos": True,
        "labeled_corpus": False,
        "limitation": "No downloadable independently labeled corpus.",
    },
    {
        "dataset": "CSE-CIC-IDS2018",
        "publisher": (
            "Canadian Institute for Cybersecurity, "
            "University of New Brunswick"
        ),
        "official_url": "https://www.unb.ca/cic/datasets/ids-2018.html",
        "finding": "already_opened_and_locked_flow_benchmark",
        "version": "2018",
        "schema": "CICFlowMeter bidirectional flow features",
        "license": "redistribution allowed with required citation and AWS link",
        "checksum": (
            "recorded in "
            "data/samples/benchmarks/cse_cic_ids2018_v49_manifest.json"
        ),
        "native_panos": False,
        "labeled_corpus": True,
        "limitation": (
            "Not PAN-OS schema and already opened as locked external evidence."
        ),
    },
    {
        "dataset": "UNSW-NB15",
        "publisher": "UNSW Canberra",
        "official_url": (
            "https://research.unsw.edu.au/projects/unsw-nb15-dataset"
        ),
        "finding": "labeled_flow_and_packet_evidence_not_panos",
        "version": "UNSW-NB15",
        "schema": "PCAP, Argus, Bro, and 49-feature CSV records",
        "license": (
            "free academic research use with citation; "
            "commercial use requires author agreement"
        ),
        "checksum": "not_acquired_in_v5_7",
        "native_panos": False,
        "labeled_corpus": True,
        "limitation": "Not native PAN-OS logs or source-device evidence.",
    },
    {
        "dataset": "Splunk Boss of the SOC v3",
        "publisher": "Splunk",
        "official_url": "https://github.com/splunk/botsv3",
        "finding": "security_dataset_without_native_panos_sourcetype",
        "version": "3",
        "schema": "pre-indexed multi-sourcetype Splunk security data",
        "license": "CC0-1.0",
        "checksum": "published MD5 d7ccca99a01cff070dff3c139cdc10eb",
        "native_panos": False,
        "labeled_corpus": False,
        "limitation": (
            "No native PAN-OS source and no row-level ground-truth contract "
            "for this evaluator."
        ),
    },
)


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _stable_hash(value: Any) -> str:
    payload = json.dumps(
        value,
        sort_keys=True,
        default=str,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _file_sha256(path: Path) -> str | None:
    if not path.exists() or not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_json(path: Path) -> dict[str, Any]:
    if not path.exists() or not path.is_file():
        return {}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def _truthy(value: Any) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "y"}


def _number(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _integer(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _safe_evidence_id(value: Any) -> str:
    token = re.sub(r"[^a-zA-Z0-9_-]+", "-", str(value or "")).strip("-")
    return token[:80] or "unassigned-evidence"


def _independent_contract_fingerprint(manifest: dict[str, Any]) -> str:
    return _stable_hash(
        {
            "manifest_version": manifest.get("manifest_version"),
            "evidence_id": manifest.get("evidence_id"),
            "schema_family": manifest.get("schema_family"),
            "collection_provenance": manifest.get(
                "collection_provenance"
            ),
            "license_or_owner_permission": manifest.get(
                "license_or_owner_permission"
            ),
            "files": manifest.get("files"),
            "independence": manifest.get("independence"),
            "prediction_before_label_protocol": manifest.get(
                "prediction_before_label_protocol"
            ),
        }
    )


def _resolve_output_file(output_dir: Path, name: Any) -> Path | None:
    text = str(name or "")
    if not text or Path(text).name != text:
        return None
    return output_dir / text


def _role_signature(protocol: dict[str, Any]) -> str | None:
    roles = protocol.get("roles") or {}
    if not roles:
        return None
    projection = {
        name: {
            "rows": value.get("rows"),
            "representative_families": value.get(
                "representative_families"
            ),
            "time_windows": value.get("time_windows"),
            "aggregate_fingerprint": value.get("aggregate_fingerprint"),
        }
        for name, value in sorted(roles.items())
    }
    return _stable_hash(projection)


def _code_contract_fingerprint() -> str:
    paths = (
        Path(__file__),
        Path(v56.__file__),
    )
    return _stable_hash(
        {
            path.name: _file_sha256(path)
            for path in paths
            if path.exists()
        }
    )


def _artifact_pipeline_details(pipeline: Any) -> dict[str, Any]:
    estimator = getattr(pipeline, "estimator", None)
    steps = [
        {"name": str(name), "type": type(value).__name__}
        for name, value in getattr(estimator, "steps", [])
    ]
    model_type = next(
        (
            row["type"]
            for row in steps
            if row["name"] == "model"
        ),
        type(estimator).__name__ if estimator is not None else None,
    )
    feature_names = [
        str(value) for value in getattr(pipeline, "feature_names_in_", [])
    ]
    return {
        "calibrator_type": type(pipeline).__name__,
        "calibration_method": getattr(pipeline, "method", None),
        "base_estimator_type": type(estimator).__name__
        if estimator is not None
        else None,
        "model_type": model_type,
        "preprocessing_steps": steps,
        "feature_count": len(feature_names),
        "feature_contract_fingerprint": _stable_hash(feature_names),
        "feature_names": feature_names,
        "classes": [
            str(value) for value in getattr(pipeline, "classes_", [])
        ],
    }


def audit_evidence_locks(
    *,
    output_dir: Path,
    current_lock_validation: dict[str, Any],
    v53_lock_path: Path = v54.V53_LOCK_PATH,
) -> dict[str, Any]:
    v53_lock = _safe_json(v53_lock_path)
    v54_manifest_path = (
        output_dir / "v5_4_development_evidence_manifest_latest.json"
    )
    v55_report_path = output_dir / v55.V55_LATEST
    v56_report_path = output_dir / v56.V56_LATEST
    v56_manifest_path = (
        output_dir / "v5_6_private_evidence_manifest_latest.json"
    )
    v56_report = _safe_json(v56_report_path)
    v56_manifest = _safe_json(v56_manifest_path)
    candidate_state = v56_report.get("diagnostic_candidate_artifact") or {}
    artifact_path = _resolve_output_file(
        output_dir,
        candidate_state.get("artifact_name"),
    )
    artifact_hash = _file_sha256(artifact_path) if artifact_path else None
    expected_artifact_hash = candidate_state.get("sha256")
    report_protocol = v56_report.get("chronological_protocol") or {}
    manifest_protocol = v56_manifest.get("chronological_protocol") or {}

    checks = {
        "v53_lock_present": bool(v53_lock),
        "v53_current_lock_matched": bool(
            current_lock_validation.get("passed")
        ),
        "v54_manifest_present": bool(_safe_json(v54_manifest_path)),
        "v55_report_present": bool(_safe_json(v55_report_path)),
        "v56_report_present": bool(v56_report),
        "v56_manifest_present": bool(v56_manifest),
        "v56_role_manifest_matched": (
            _role_signature(report_protocol)
            == _role_signature(manifest_protocol)
            and _role_signature(report_protocol) is not None
        ),
        "v56_duplicate_families_contained": bool(
            report_protocol.get("duplicate_families_contained")
        ),
        "v56_future_excluded_from_selection": not bool(
            (v56_report.get("untouched_future_validation") or {}).get(
                "used_for_candidate_selection"
            )
        ),
        "v56_candidate_frozen_before_future": bool(
            (v56_report.get("frozen_diagnostic_candidate") or {}).get(
                "frozen_before_future_label_access"
            )
        ),
        "v56_candidate_artifact_present": artifact_hash is not None,
        "v56_candidate_artifact_hash_matched": (
            artifact_hash is not None
            and artifact_hash == expected_artifact_hash
        ),
        "locked_external_not_selectable": not bool(
            (v53_lock.get("external_evidence") or {}).get(
                "passed_v49_gates"
            )
        ),
    }
    prior_roles = {
        "v53_fit": _integer(
            ((v53_lock.get("roles") or {}).get("fit") or {}).get("rows")
        ),
        "v53_calibration": _integer(
            ((v53_lock.get("roles") or {}).get("calibration") or {}).get(
                "rows"
            )
        ),
        "v53_threshold": _integer(
            ((v53_lock.get("roles") or {}).get("threshold") or {}).get(
                "rows"
            )
        ),
        "v53_temporal_final": _integer(
            ((v53_lock.get("roles") or {}).get("temporal_final") or {}).get(
                "rows"
            )
        ),
        "v56_development_fit": _integer(
            ((report_protocol.get("roles") or {}).get("development_fit") or {}).get(
                "rows"
            )
        ),
        "v56_calibration": _integer(
            ((report_protocol.get("roles") or {}).get("calibration") or {}).get(
                "rows"
            )
        ),
        "v56_threshold": _integer(
            ((report_protocol.get("roles") or {}).get("threshold") or {}).get(
                "rows"
            )
        ),
        "v56_opened_future": _integer(
            (
                (report_protocol.get("roles") or {}).get(
                    "untouched_future_validation"
                )
                or {}
            ).get("rows")
        ),
    }
    return {
        "status": "locked_and_matched"
        if all(checks.values())
        else "failed_closed_lock_mismatch",
        "passed": all(checks.values()),
        "checks": checks,
        "prior_role_rows": prior_roles,
        "previously_opened_evidence": [
            "v5.3 temporal final",
            "v5.3 rolling future",
            "v5.3 external benchmark",
            "v5.6 private future",
        ],
        "reusable_for_fresh_independent_validation": False,
        "fingerprints_recorded_locally": True,
        "fingerprints_exposed": False,
        "raw_logs_included": False,
        "private_identifiers_included": False,
        "_fingerprints": {
            "v53_lock": _file_sha256(v53_lock_path),
            "v53_roles": {
                name: value.get("fingerprint")
                for name, value in (v53_lock.get("roles") or {}).items()
            },
            "v53_rolling_future": [
                {
                    "role": value.get("role"),
                    "fingerprint": value.get("fingerprint"),
                }
                for value in v53_lock.get("rolling_future_roles") or []
            ],
            "v53_external": (
                (v53_lock.get("external_evidence") or {}).get(
                    "fingerprint"
                )
            ),
            "v54_manifest": _file_sha256(v54_manifest_path),
            "v55_report": _file_sha256(v55_report_path),
            "v56_report": _file_sha256(v56_report_path),
            "v56_manifest": _file_sha256(v56_manifest_path),
            "v56_role_signature": _role_signature(report_protocol),
            "v56_roles": {
                name: value.get("aggregate_fingerprint")
                for name, value in (
                    report_protocol.get("roles") or {}
                ).items()
            },
            "candidate_artifact": artifact_hash,
        },
        "_artifact_path": artifact_path,
        "_v56_report": v56_report,
    }


def _write_evidence_lock_audit(
    output_dir: Path,
    lock_audit: dict[str, Any],
) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    record = {
        "version": V57_VERSION,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "status": lock_audit.get("status"),
        "passed": bool(lock_audit.get("passed")),
        "checks": lock_audit.get("checks") or {},
        "prior_role_rows": lock_audit.get("prior_role_rows") or {},
        "fingerprints": lock_audit.get("_fingerprints") or {},
        "reusable_for_fresh_independent_validation": False,
        "private_paths_included": False,
        "raw_logs_included": False,
        "ip_addresses_included": False,
        "row_values_included": False,
        "secrets_exposed": False,
        "ignored_output": True,
    }
    (output_dir / V57_EVIDENCE_LOCK_AUDIT).write_text(
        json.dumps(record, indent=2),
        encoding="utf-8",
    )


def freeze_v56_candidate(
    imports: Any,
    *,
    output_dir: Path,
    lock_audit: dict[str, Any],
    development_sample_sha256: str | None,
    write_output: bool,
) -> dict[str, Any]:
    report = lock_audit.get("_v56_report") or {}
    artifact_path = lock_audit.get("_artifact_path")
    if not lock_audit.get("passed") or not isinstance(artifact_path, Path):
        return {
            "ok": False,
            "status": "failed_closed_candidate_lock_unavailable",
            "active_artifact_written": False,
        }
    artifact_before = v55._file_state(artifact_path)
    try:
        artifact = imports[0].load(artifact_path)
    except (OSError, ValueError, TypeError, KeyError, AttributeError) as exc:
        return {
            "ok": False,
            "status": "failed_closed_candidate_unreadable",
            "error_type": exc.__class__.__name__,
            "active_artifact_written": False,
        }
    pipeline = artifact.get("pipeline")
    if pipeline is None:
        return {
            "ok": False,
            "status": "failed_closed_candidate_pipeline_missing",
            "active_artifact_written": False,
        }
    details = _artifact_pipeline_details(pipeline)
    v56_candidate = report.get("frozen_diagnostic_candidate") or {}
    role_protocol = report.get("chronological_protocol") or {}
    training_manifest_fingerprint = _stable_hash(
        {
            "v56_candidate_freeze": v56_candidate.get(
                "freeze_fingerprint"
            ),
            "v56_role_signature": _role_signature(role_protocol),
            "label_policy": artifact.get("label_policy"),
            "feature_contract": details["feature_contract_fingerprint"],
        }
    )
    existing_reference = _safe_json(
        output_dir / V57_DEVELOPMENT_REFERENCE
    )
    reference_hash = (
        development_sample_sha256
        or existing_reference.get("development_sample_sha256")
    )
    manifest = {
        "manifest_version": V57_VERSION,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "candidate_name": artifact.get("candidate_name"),
        "candidate_version": artifact.get("version"),
        "candidate_freeze_fingerprint": v56_candidate.get(
            "freeze_fingerprint"
        ),
        "artifact_name": artifact_path.name,
        "artifact_sha256": artifact_before.get("sha256"),
        "artifact_size_bytes": artifact_before.get("size_bytes"),
        "threshold": artifact.get("threshold"),
        "label_policy": artifact.get("label_policy"),
        "training_manifest_fingerprint": training_manifest_fingerprint,
        "code_contract_fingerprint": _code_contract_fingerprint(),
        "pipeline": details,
        "post_prediction_decision_policy": "calibrated_threshold_only",
        "post_prediction_guard_used": False,
        "actual_threats_suppressed_by_post_prediction_guard": 0,
        "frozen_before_independent_label_access": True,
        "active": False,
        "production_promoted": False,
        "response_automation_allowed": False,
        "rules_alert_authoritative": True,
        "development_sample_sha256": reference_hash,
        "private_path_included": False,
        "raw_logs_included": False,
        "row_fingerprints_included": False,
        "ignored_output": True,
    }
    if write_output:
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / V57_CANDIDATE_FREEZE).write_text(
            json.dumps(manifest, indent=2),
            encoding="utf-8",
        )
        if reference_hash:
            (output_dir / V57_DEVELOPMENT_REFERENCE).write_text(
                json.dumps(
                    {
                        "version": V57_VERSION,
                        "development_sample_sha256": reference_hash,
                        "source_role": "reused_v56_development_evidence",
                        "eligible_as_independent_evidence": False,
                        "private_path_included": False,
                        "raw_logs_included": False,
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )
    artifact_after = v55._file_state(artifact_path)
    return {
        "ok": artifact_before == artifact_after,
        "status": "frozen_diagnostic_candidate_ready",
        "candidate_name": manifest["candidate_name"],
        "model_type": details["model_type"],
        "calibration_method": details["calibration_method"],
        "threshold": manifest["threshold"],
        "feature_count": details["feature_count"],
        "feature_contract_recorded": True,
        "preprocessing_recorded": True,
        "training_manifest_recorded": True,
        "artifact_hash_recorded": True,
        "artifact_unchanged": artifact_before == artifact_after,
        "post_prediction_decision_policy": (
            manifest["post_prediction_decision_policy"]
        ),
        "post_prediction_guard_used": False,
        "actual_threats_suppressed_by_post_prediction_guard": 0,
        "active": False,
        "production_promoted": False,
        "response_automation_allowed": False,
        "eligible_for_activation": False,
        "private_path_included": False,
        "raw_logs_included": False,
        "_pipeline": pipeline,
        "_artifact": artifact,
        "_manifest": manifest,
    }


def qualify_independent_evidence(
    manifest: dict[str, Any],
    *,
    profile: dict[str, Any],
    sample_sha256: str | None,
    development_sample_sha256: str | None,
    matches_v56_role_signature: bool,
    label_reveal_mode: bool = False,
    minimum_rows: int = 100,
) -> dict[str, Any]:
    independence = manifest.get("independence") or {}
    labels = manifest.get("labels") or {}
    approval = manifest.get("advisor_signoff") or {}
    expected_sha = str(
        (manifest.get("files") or {}).get("sample_sha256") or ""
    ).strip()
    checks = {
        "manifest_version_supported": manifest.get("manifest_version")
        == V57_MANIFEST_VERSION,
        "evidence_id_present": bool(manifest.get("evidence_id")),
        "manifest_workflow_status_valid": manifest.get("status")
        == (
            "ready_for_label_reveal"
            if label_reveal_mode
            else "ready_for_predictions"
        ),
        "native_panos_compatible_schema": manifest.get("schema_family")
        in ALLOWED_SCHEMA_FAMILIES,
        "minimum_parsed_rows_observed": _integer(
            profile.get("parser_successes")
        )
        >= max(1, int(minimum_rows)),
        "chronological_profile_observed": bool(
            profile.get("chronological_profile_ok")
        ),
        "minimum_observed_time_windows": _integer(
            profile.get("observed_distinct_time_windows")
        )
        >= 2,
        "at_least_two_real_devices": _integer(
            independence.get("real_device_count")
        )
        >= 2,
        "at_least_two_independent_time_windows": _integer(
            independence.get("independent_time_window_count")
        )
        >= 2,
        "not_same_v56_file": bool(
            sample_sha256
            and development_sample_sha256
            and sample_sha256 != development_sample_sha256
        ),
        "not_same_v56_role_signature": not matches_v56_role_signature,
        "configured_database_overlap_zero": _integer(
            profile.get("configured_database_overlap_rows")
        )
        == 0,
        "declared_prior_overlap_zero": _integer(
            independence.get("prior_evidence_overlap_rows"),
            -1,
        )
        == 0,
        "declared_duplicate_leakage_zero": _integer(
            independence.get("cross_role_duplicate_groups"),
            -1,
        )
        == 0,
        "prior_evidence_overlap_audit_completed": bool(
            independence.get("overlap_audit_completed")
        ),
        "prior_evidence_overlap_audit_method_approved": (
            independence.get("overlap_audit_method")
            in ALLOWED_OVERLAP_AUDIT_METHODS
        ),
        "sample_checksum_declared_and_matched": bool(
            expected_sha
            and sample_sha256
            and expected_sha == sample_sha256
        ),
        "label_workflow_state_valid": (
            labels.get("status") == "complete_and_sealed"
            if label_reveal_mode
            else labels.get("status") in {"sealed", "not_collected"}
        ),
        "labels_unavailable_to_prediction_runner": not bool(
            labels.get("available_to_prediction_runner")
        ),
        "prediction_before_label_protocol_declared": bool(
            manifest.get("prediction_before_label_protocol")
        ),
        "collection_provenance_declared": bool(
            manifest.get("collection_provenance")
        ),
        "license_or_owner_permission_declared": bool(
            manifest.get("license_or_owner_permission")
        ),
        "advisor_protocol_acknowledged": bool(
            approval.get("protocol_acknowledged")
        ),
    }
    blockers = [
        key.replace("_", " ")
        for key, passed in checks.items()
        if not passed
    ]
    return {
        "status": "qualified_for_prediction_freeze"
        if all(checks.values())
        else "independent_evidence_required",
        "eligible_for_predictions": all(checks.values()),
        "eligible_for_label_reveal": False,
        "checks": checks,
        "blockers": blockers,
        "evidence_id": _safe_evidence_id(manifest.get("evidence_id")),
        "source_device_count": _integer(
            independence.get("real_device_count")
        ),
        "independent_time_window_count": _integer(
            independence.get("independent_time_window_count")
        ),
        "raw_logs_included": False,
        "private_identifiers_included": False,
        "file_fingerprints_exposed": False,
    }


def _prepare_independent_index(
    connection: sqlite3.Connection,
    *,
    sample_path: Path,
    database_url: str,
    chunk_size: int,
) -> tuple[dict[str, Any], dict[str, Any], str | None]:
    profile = v56.stream_private_file_to_disposable_index(
        sample_path,
        connection,
        database_url=database_url,
        chunk_size=chunk_size,
    )
    if not profile.get("ok"):
        return profile, {}, None
    protocol = v56.predeclare_chronological_roles(connection)
    return profile, protocol, _role_signature(protocol)


def _activate_independent_evaluation_role(
    connection: sqlite3.Connection,
) -> dict[str, Any]:
    connection.execute(
        "UPDATE events SET role_rank=0 "
        "WHERE quarantine_reason IS NULL"
    )
    connection.commit()
    aggregates = v56.build_disposable_behavior_aggregates(connection)
    eligible = _integer(
        connection.execute(
            "SELECT COUNT(*) FROM events WHERE role_rank=0"
        ).fetchone()[0]
    )
    quarantined = _integer(
        connection.execute(
            "SELECT COUNT(*) FROM events WHERE role_rank=4"
        ).fetchone()[0]
    )
    return {
        **aggregates,
        "eligible_rows": eligible,
        "quarantined_rows": quarantined,
    }


def _select_prediction_rows(
    connection: sqlite3.Connection,
    *,
    max_rows: int,
) -> list[dict[str, Any]]:
    rows = [
        v56._row_mapping(values)
        for values in connection.execute(v56.REPRESENTATIVE_QUERY)
        if _integer(values[3]) == 0
    ]
    rows.sort(
        key=lambda row: _stable_hash(
            {
                "protocol": V57_VERSION,
                "family": row.get("propagation_hash"),
            }
        )
    )
    return rows[: max(50, int(max_rows))]


def _source_tokens(
    connection: sqlite3.Connection,
    row_ids: list[int],
) -> dict[int, str]:
    output: dict[int, str] = {}
    for offset in range(0, len(row_ids), 500):
        batch = row_ids[offset : offset + 500]
        placeholders = ",".join("?" for _ in batch)
        query = (
            "SELECT id, source_token FROM events WHERE id IN ("
            f"{placeholders})"
        )
        for row_id, token in connection.execute(query, batch):
            output[int(row_id)] = str(token)
    return output


def _prediction_bundle(
    imports: Any,
    connection: sqlite3.Connection,
    *,
    max_rows: int,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    pd = imports[1]
    rows = _select_prediction_rows(connection, max_rows=max_rows)
    source_tokens = _source_tokens(
        connection,
        [_integer(row.get("id")) for row in rows],
    )
    feature_rows: list[dict[str, Any]] = []
    safe_rows: list[dict[str, Any]] = []
    for row in rows:
        rule_codes, rule_score = v56._rule_evidence(row)
        row["rule_score"] = rule_score
        feature_rows.append(v56._private_feature_row(row))
        row_id = _integer(row.get("id"))
        safe_rows.append(
            {
                "row_id": row_id,
                "source_group": _stable_hash(
                    {
                        "namespace": "v57-source-group",
                        "value": source_tokens.get(row_id, "missing"),
                    }
                )[:16],
                "time_window_group": _stable_hash(
                    {
                        "namespace": "v57-time-window",
                        "value": row.get("minute_bucket"),
                    }
                )[:16],
                "log_type": str(row.get("log_type") or "missing"),
                "subtype": str(row.get("subtype") or "missing"),
                "app": str(row.get("app") or "unknown"),
                "action": str(row.get("action") or "unknown"),
                "protocol": str(row.get("protocol") or "unknown"),
                "src_port": row.get("src_port"),
                "dst_port": row.get("dst_port"),
                "direction": (
                    "external_to_internal"
                    if _integer(row.get("external_to_internal_flag"))
                    else "internal_to_external"
                    if _integer(row.get("internal_to_external_flag"))
                    else "other"
                ),
                "schema_bucket": str(
                    row.get("schema_bucket") or "unrecognized"
                ),
                "rule_codes": rule_codes,
                "rule_evidence_score": rule_score,
                "source_event_count": _integer(
                    row.get("source_event_count")
                ),
                "source_unique_destinations": _integer(
                    row.get("source_unique_destinations")
                ),
                "source_unique_ports": _integer(
                    row.get("source_unique_ports")
                ),
                "source_deny_count": _integer(
                    row.get("source_deny_count")
                ),
                "group_size": _integer(row.get("group_size"), 1),
            }
        )
    frame = pd.DataFrame(
        feature_rows,
        columns=[*v56.V56_NUMERIC_FEATURES, *v56.V56_CATEGORICAL_FEATURES],
    )
    return {
        "frame": frame,
        "rows": safe_rows,
    }, rows


def _write_prediction_freeze(
    imports: Any,
    *,
    output_dir: Path,
    evidence_manifest: dict[str, Any],
    evidence_manifest_path: Path,
    sample_sha256: str,
    candidate: dict[str, Any],
    bundle: dict[str, Any],
) -> dict[str, Any]:
    existing = _safe_json(output_dir / V57_PREDICTION_FREEZE)
    expected_contract = _independent_contract_fingerprint(
        evidence_manifest
    )
    if existing:
        prediction_path = _resolve_output_file(
            output_dir,
            existing.get("predictions_file_name"),
        )
        same_freeze = all(
            (
                existing.get("evidence_id")
                == _safe_evidence_id(evidence_manifest.get("evidence_id")),
                existing.get("candidate_artifact_sha256")
                == candidate["_manifest"].get("artifact_sha256"),
                existing.get("evidence_sample_sha256") == sample_sha256,
                existing.get("evidence_contract_fingerprint")
                == expected_contract,
                bool(
                    prediction_path
                    and prediction_path.exists()
                    and _file_sha256(prediction_path)
                    == existing.get("predictions_sha256")
                ),
            )
        )
        if existing.get("labels_revealed"):
            return {
                "status": "failed_closed_labels_already_revealed",
                "predictions_frozen_before_labels": True,
                "labels_revealed": True,
                "active_model_artifact_written": False,
                "paths_returned": False,
                "raw_logs_included": False,
                "private_identifiers_included": False,
            }
        if same_freeze:
            return {
                "status": "predictions_already_frozen",
                "evidence_id": existing.get("evidence_id"),
                "evaluation_rows": existing.get("evaluation_rows"),
                "predictions_frozen_before_labels": True,
                "labels_revealed": False,
                "review_pack_created": True,
                "review_pack_is_import_ready": False,
                "review_pack_predictions_hidden": True,
                "active_model_artifact_written": False,
                "paths_returned": False,
                "raw_logs_included": False,
                "private_identifiers_included": False,
            }
        return {
            "status": "failed_closed_existing_prediction_freeze_mismatch",
            "predictions_frozen_before_labels": True,
            "labels_revealed": bool(existing.get("labels_revealed")),
            "active_model_artifact_written": False,
            "paths_returned": False,
            "raw_logs_included": False,
            "private_identifiers_included": False,
        }

    pipeline = candidate["_pipeline"]
    artifact = candidate["_artifact"]
    threshold = _number(artifact.get("threshold"), 0.5)
    scores = reliability._queue_scores(
        pipeline,
        bundle["frame"],
        list(range(len(bundle["rows"]))),
        {"needs_review"},
    )
    evidence_id = _safe_evidence_id(evidence_manifest.get("evidence_id"))
    salt = _stable_hash(
        {
            "evidence": sample_sha256,
            "candidate": candidate["_manifest"].get("artifact_sha256"),
            "version": V57_VERSION,
        }
    )
    predictions = []
    review_rows = []
    for row, score in zip(bundle["rows"], scores, strict=True):
        review_token = _stable_hash(
            {
                "salt": salt,
                "row_id": row["row_id"],
                "source_group": row["source_group"],
                "time_window_group": row["time_window_group"],
            }
        )
        prediction = (
            "needs_review" if float(score) >= threshold else "non_threat"
        )
        public_row = {
            key: value for key, value in row.items() if key != "row_id"
        }
        predictions.append(
            {
                "review_token": review_token,
                "prediction": prediction,
                "threat_score": round(float(score), 8),
                **public_row,
            }
        )
        review_rows.append(
            {
                "review_token": review_token,
                **public_row,
                "human_decision": "",
                "attack_type": "",
                "label_provenance": "",
                "human_confirmed": "false",
                "reviewer_id": "",
                "reviewed_at": "",
                "review_notes": "",
            }
        )

    prediction_path = output_dir / f"v5_7_predictions_{evidence_id}.jsonl"
    review_path = output_dir / f"v5_7_blind_review_pack_{evidence_id}.csv"
    with prediction_path.open("w", encoding="utf-8", newline="\n") as stream:
        for row in predictions:
            stream.write(json.dumps(row, sort_keys=True) + "\n")
    fieldnames = list(review_rows[0]) if review_rows else []
    with review_path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(review_rows)

    prediction_sha = _file_sha256(prediction_path)
    review_sha = _file_sha256(review_path)
    freeze = {
        "manifest_version": V57_VERSION,
        "evidence_id": evidence_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "candidate_name": candidate.get("candidate_name"),
        "candidate_artifact_sha256": candidate["_manifest"].get(
            "artifact_sha256"
        ),
        "candidate_threshold": threshold,
        "evidence_sample_sha256": sample_sha256,
        "evidence_manifest_sha256": _file_sha256(evidence_manifest_path),
        "evidence_contract_fingerprint": expected_contract,
        "predictions_file_name": prediction_path.name,
        "predictions_sha256": prediction_sha,
        "review_pack_file_name": review_path.name,
        "review_pack_initial_sha256": review_sha,
        "review_token_set_sha256": _stable_hash(
            sorted(row["review_token"] for row in predictions)
        ),
        "evaluation_rows": len(predictions),
        "labels_revealed": False,
        "predictions_frozen_before_labels": True,
        "prediction_file_contains_raw_logs": False,
        "prediction_file_contains_ip_addresses": False,
        "review_pack_contains_predictions": False,
        "active_model_artifact_written": False,
        "ignored_output": True,
    }
    (output_dir / V57_PREDICTION_FREEZE).write_text(
        json.dumps(freeze, indent=2),
        encoding="utf-8",
    )
    return {
        "status": "predictions_frozen_labels_sealed",
        "evidence_id": evidence_id,
        "evaluation_rows": len(predictions),
        "predictions_frozen_before_labels": True,
        "labels_revealed": False,
        "review_pack_created": bool(review_rows),
        "review_pack_is_import_ready": False,
        "review_pack_predictions_hidden": True,
        "active_model_artifact_written": False,
        "paths_returned": False,
        "raw_logs_included": False,
        "private_identifiers_included": False,
    }


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows = []
    with path.open("r", encoding="utf-8") as stream:
        for line in stream:
            value = json.loads(line)
            if isinstance(value, dict):
                rows.append(value)
    return rows


def _label_file_path(
    evidence_manifest: dict[str, Any],
    evidence_manifest_path: Path,
) -> Path | None:
    value = str(
        (evidence_manifest.get("labels") or {}).get("file") or ""
    ).strip()
    if not value:
        return None
    path = Path(value)
    if not path.is_absolute():
        path = evidence_manifest_path.parent / path
    return path


def _qualify_label_reveal(
    evidence_manifest: dict[str, Any],
    *,
    freeze: dict[str, Any],
    predictions_path: Path | None,
    label_path: Path | None,
    sample_sha256: str,
    candidate_sha256: str | None,
) -> dict[str, Any]:
    labels = evidence_manifest.get("labels") or {}
    approval = evidence_manifest.get("advisor_signoff") or {}
    checks = {
        "prediction_freeze_present": bool(freeze),
        "predictions_frozen_before_labels": bool(
            freeze.get("predictions_frozen_before_labels")
        ),
        "labels_not_previously_revealed": not bool(
            freeze.get("labels_revealed")
        ),
        "evidence_id_matched": _safe_evidence_id(
            evidence_manifest.get("evidence_id")
        )
        == freeze.get("evidence_id"),
        "sample_fingerprint_matched": sample_sha256
        == freeze.get("evidence_sample_sha256"),
        "candidate_artifact_matched": candidate_sha256
        == freeze.get("candidate_artifact_sha256"),
        "evidence_contract_matched": (
            _independent_contract_fingerprint(evidence_manifest)
            == freeze.get("evidence_contract_fingerprint")
        ),
        "prediction_file_present": bool(
            predictions_path and predictions_path.exists()
        ),
        "prediction_file_hash_matched": bool(
            predictions_path
            and _file_sha256(predictions_path)
            == freeze.get("predictions_sha256")
        ),
        "label_file_present": bool(label_path and label_path.exists()),
        "labels_complete_and_sealed": labels.get("status")
        == "complete_and_sealed",
        "ground_truth_provenance_allowed": labels.get("provenance")
        in ALLOWED_GROUND_TRUTH_PROVENANCE,
        "ground_truth_confirmed": bool(labels.get("ground_truth_confirmed")),
        "advisor_signoff_approved": bool(approval.get("approved")),
    }
    return {
        "passed": all(checks.values()),
        "status": "label_reveal_allowed"
        if all(checks.values())
        else "failed_closed_label_reveal_not_authorized",
        "checks": checks,
        "blockers": [
            key.replace("_", " ")
            for key, passed in checks.items()
            if not passed
        ],
    }


def _load_confirmed_labels(
    path: Path,
    *,
    expected_tokens: set[str],
) -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    labels: dict[str, dict[str, Any]] = {}
    invalid = Counter()
    with path.open("r", encoding="utf-8-sig", newline="") as stream:
        for row in csv.DictReader(stream):
            token = str(row.get("review_token") or "").strip()
            decision = str(row.get("human_decision") or "").strip().lower()
            provenance = str(
                row.get("label_provenance") or ""
            ).strip().lower()
            if token not in expected_tokens:
                invalid["unknown_token"] += 1
                continue
            if decision not in VALID_DECISIONS:
                invalid["invalid_decision"] += 1
                continue
            if provenance not in ALLOWED_GROUND_TRUTH_PROVENANCE:
                invalid["invalid_provenance"] += 1
                continue
            if not _truthy(row.get("human_confirmed")):
                invalid["not_confirmed"] += 1
                continue
            if not str(row.get("reviewer_id") or "").strip():
                invalid["reviewer_missing"] += 1
                continue
            labels[token] = {
                "decision": decision,
                "attack_type": str(
                    row.get("attack_type") or "unknown"
                ).strip(),
                "provenance": provenance,
            }
    missing = len(expected_tokens - set(labels))
    return labels, {
        "valid_labels": len(labels),
        "expected_labels": len(expected_tokens),
        "missing_labels": missing,
        "invalid_rows": dict(invalid),
        "complete": missing == 0 and not invalid,
        "ai_generated_labels_marked_human_reviewed": False,
    }


def _safe_error_patterns(
    predictions: list[dict[str, Any]],
    labels: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    fields = ("app", "action", "dst_port", "schema_bucket", "log_type")
    counters = {
        "false_positives": {field: Counter() for field in fields},
        "false_negatives": {field: Counter() for field in fields},
    }
    for row in predictions:
        label = labels[row["review_token"]]["decision"]
        actual = label in {"suspicious", "malicious"}
        predicted = row["prediction"] == "needs_review"
        category = (
            "false_positives"
            if predicted and not actual
            else "false_negatives"
            if actual and not predicted
            else None
        )
        if not category:
            continue
        for field in fields:
            counters[category][field][str(row.get(field) or "unknown")] += 1
    return {
        category: {
            field: [
                {"value": value, "count": count}
                for value, count in values.most_common(8)
            ]
            for field, values in groups.items()
        }
        for category, groups in counters.items()
    }


def _group_stability(
    predictions: list[dict[str, Any]],
    labels: dict[str, dict[str, Any]],
    *,
    group_field: str,
) -> dict[str, Any]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in predictions:
        grouped[str(row.get(group_field) or "unknown")].append(row)
    metrics = []
    for rows in grouped.values():
        comparable = [
            row
            for row in rows
            if labels[row["review_token"]]["decision"] != "needs_context"
        ]
        if not comparable:
            continue
        y_true = [
            "needs_review"
            if labels[row["review_token"]]["decision"]
            in {"suspicious", "malicious"}
            else "non_threat"
            for row in comparable
        ]
        values = frozen._binary_metrics(
            y_true,
            [str(row["prediction"]) for row in comparable],
        )
        metrics.append(values)
    if not metrics:
        return {"groups": 0, "status": "insufficient_evidence"}
    return {
        "groups": len(metrics),
        "status": "evaluated",
        "queue_f1_range": {
            "minimum": min(_number(row.get("queue_f1")) for row in metrics),
            "maximum": max(_number(row.get("queue_f1")) for row in metrics),
        },
        "benign_fpr_range": {
            "minimum": min(
                _number(row.get("benign_like_false_positive_rate"))
                for row in metrics
            ),
            "maximum": max(
                _number(row.get("benign_like_false_positive_rate"))
                for row in metrics
            ),
        },
        "group_identifiers_included": False,
    }


def _distribution(rows: Iterable[dict[str, Any]], field: str) -> dict[str, float]:
    counter = Counter(str(row.get(field) or "unknown") for row in rows)
    total = max(1, sum(counter.values()))
    return {key: value / total for key, value in counter.items()}


def _baseline_distribution(
    v56_report: dict[str, Any],
    *,
    role: str,
    field: str,
) -> dict[str, float]:
    role_rows = (
        ((v56_report.get("drift_profile") or {}).get("role_distributions") or {}).get(
            role
        )
        or {}
    )
    values = role_rows.get(field) or []
    total = max(1, sum(_integer(row.get("count")) for row in values))
    return {
        str(row.get("value") or "unknown"): _integer(row.get("count"))
        / total
        for row in values
    }


def _drift_summary(
    predictions: list[dict[str, Any]],
    v56_report: dict[str, Any],
) -> dict[str, Any]:
    fields = {
        "application": "app",
        "action": "action",
        "schema": "schema_bucket",
        "log_type": "log_type",
    }
    distances = {}
    for baseline_field, row_field in fields.items():
        baseline = _baseline_distribution(
            v56_report,
            role="development_fit",
            field=baseline_field,
        )
        current = _distribution(predictions, row_field)
        distances[baseline_field] = round(
            v54.total_variation_distance(baseline, current),
            6,
        )
    maximum = max(distances.values(), default=1.0)
    return {
        "status": "OOD Warning"
        if maximum >= 0.50
        else "Drift Warning"
        if maximum >= 0.25
        else "Stable",
        "total_variation": distances,
        "raw_logs_included": False,
        "private_identifiers_included": False,
    }


def _evaluate_isolation_forest(
    imports: Any,
    *,
    bundle: dict[str, Any],
    y_true: list[str],
    comparable_positions: list[int],
) -> dict[str, Any]:
    path = get_settings().resolved_model_path
    before = v55._file_state(path)
    if not before.get("exists"):
        return {
            "status": "active_artifact_unavailable",
            "advisory_only": True,
            "active_artifact_written": False,
        }
    frame = bundle["frame"].iloc[comparable_positions]
    try:
        model = imports[0].load(path)
        raw_predictions = model.predict(frame)
        scores = [float(value) for value in model.decision_function(frame)]
    except (OSError, ValueError, TypeError, KeyError, AttributeError) as exc:
        return {
            "status": "active_artifact_incompatible",
            "error_type": exc.__class__.__name__,
            "artifact_unchanged": before == v55._file_state(path),
            "advisory_only": True,
            "active_artifact_written": False,
        }
    predictions = [
        "needs_review" if int(value) == -1 else "non_threat"
        for value in raw_predictions
    ]
    metrics = frozen._binary_metrics(y_true, predictions)
    after = v55._file_state(path)
    return {
        "status": "evaluated_independently",
        "metrics": metrics,
        "score_distribution": {
            "minimum": round(min(scores), 6) if scores else None,
            "maximum": round(max(scores), 6) if scores else None,
            "mean": round(mean(scores), 6) if scores else None,
        },
        "artifact_unchanged": before == after,
        "advisory_only": True,
        "active_artifact_written": False,
    }


def _readiness(
    *,
    lock_audit: dict[str, Any],
    candidate: dict[str, Any],
    qualification: dict[str, Any],
    validation: dict[str, Any] | None,
    safety: dict[str, Any],
) -> dict[str, Any]:
    metrics = (validation or {}).get("metrics") or {}
    calibration = (validation or {}).get("calibration") or {}
    checks = {
        "evidence_locks_matched": bool(lock_audit.get("passed")),
        "independent_source_time_evidence": bool(
            qualification.get("eligible_for_predictions")
        ),
        "blind_validation_completed": bool(
            validation and validation.get("status") == "evaluated_blind_once"
        ),
        "queue_f1": _number(metrics.get("queue_f1"))
        >= V57_GATES["queue_f1_min"],
        "benign_like_false_positive_rate": _number(
            metrics.get("benign_like_false_positive_rate"),
            1.0,
        )
        <= V57_GATES["benign_like_false_positive_rate_max"],
        "suspicious_recall": metrics.get("suspicious_recall") is not None
        and _number(metrics.get("suspicious_recall"))
        >= V57_GATES["suspicious_recall_min"],
        "malicious_recall": metrics.get("malicious_recall") is not None
        and _number(metrics.get("malicious_recall"))
        >= V57_GATES["malicious_recall_min"],
        "expected_calibration_error": _number(
            calibration.get("expected_calibration_error"),
            1.0,
        )
        <= V57_GATES["expected_calibration_error_max"],
        "max_confidence_accuracy_gap": _number(
            calibration.get("max_confidence_accuracy_gap"),
            1.0,
        )
        <= V57_GATES["max_confidence_accuracy_gap_max"],
        "no_evidence_leakage": bool(
            qualification.get("eligible_for_predictions")
        ),
        "no_post_prediction_guard_threat_suppression": (
            candidate.get("post_prediction_guard_used") is False
            and _integer(
                candidate.get(
                    "actual_threats_suppressed_by_post_prediction_guard"
                ),
                -1,
            )
            == 0
        ),
        "configured_database_unchanged": bool(
            safety.get("database_counts_unchanged")
        ),
        "model_artifacts_unchanged": bool(
            safety.get("model_artifacts_unchanged")
        ),
        "no_response_actions": _integer(
            safety.get("response_actions_created")
        )
        == 0,
    }
    passed = all(checks.values())
    return {
        "decision": "eligible_for_manual_decision_support_review"
        if passed
        else "shadow_observation",
        "lifecycle_state": "shadow_observation",
        "checks": checks,
        "gates": V57_GATES,
        "blockers": [
            key.replace("_", " ")
            for key, value in checks.items()
            if not value
        ],
        "all_fixed_gates_passed": passed,
        "automatic_activation_allowed": False,
        "production_promoted": False,
        "response_automation_allowed": False,
        "rules_alert_authoritative": True,
    }


def _evaluate_revealed_labels(
    imports: Any,
    *,
    output_dir: Path,
    evidence_manifest: dict[str, Any],
    evidence_manifest_path: Path,
    sample_sha256: str,
    candidate: dict[str, Any],
    bundle: dict[str, Any],
    lock_audit: dict[str, Any],
) -> dict[str, Any]:
    freeze = _safe_json(output_dir / V57_PREDICTION_FREEZE)
    prediction_path = _resolve_output_file(
        output_dir,
        freeze.get("predictions_file_name"),
    )
    label_path = _label_file_path(
        evidence_manifest,
        evidence_manifest_path,
    )
    reveal = _qualify_label_reveal(
        evidence_manifest,
        freeze=freeze,
        predictions_path=prediction_path,
        label_path=label_path,
        sample_sha256=sample_sha256,
        candidate_sha256=candidate["_manifest"].get("artifact_sha256"),
    )
    if not reveal.get("passed") or prediction_path is None or label_path is None:
        return {
            "status": reveal.get("status"),
            "label_reveal": reveal,
            "labels_used_for_tuning": False,
            "active_artifact_written": False,
        }
    predictions = _read_jsonl(prediction_path)
    expected_tokens = {
        str(row.get("review_token") or "") for row in predictions
    }
    labels, label_validation = _load_confirmed_labels(
        label_path,
        expected_tokens=expected_tokens,
    )
    if not label_validation.get("complete"):
        return {
            "status": "failed_closed_incomplete_ground_truth",
            "label_reveal": reveal,
            "label_validation": label_validation,
            "labels_used_for_tuning": False,
            "active_artifact_written": False,
        }
    comparable_positions = [
        index
        for index, row in enumerate(predictions)
        if labels[row["review_token"]]["decision"] != "needs_context"
    ]
    comparable = [predictions[index] for index in comparable_positions]
    y_true = [
        "needs_review"
        if labels[row["review_token"]]["decision"]
        in {"suspicious", "malicious"}
        else "non_threat"
        for row in comparable
    ]
    predicted = [str(row["prediction"]) for row in comparable]
    scores = [_number(row.get("threat_score")) for row in comparable]
    metrics = frozen._binary_metrics(y_true, predicted)
    original_rows = [
        {
            "original_label": labels[row["review_token"]]["decision"],
        }
        for row in comparable
    ]
    metrics.update(
        frozen._diagnostic_original_recall(
            original_rows,
            list(range(len(original_rows))),
            predicted,
        )
    )
    calibration = frozen._calibration_report(y_true, scores)
    drift = _drift_summary(predictions, lock_audit.get("_v56_report") or {})
    isolation = _evaluate_isolation_forest(
        imports,
        bundle=bundle,
        y_true=y_true,
        comparable_positions=comparable_positions,
    )
    freeze.update(
        {
            "labels_revealed": True,
            "labels_revealed_at": datetime.now(timezone.utc).isoformat(),
            "label_file_sha256": _file_sha256(label_path),
            "blind_evaluation_completed": True,
            "labels_used_for_tuning": False,
        }
    )
    (output_dir / V57_PREDICTION_FREEZE).write_text(
        json.dumps(freeze, indent=2),
        encoding="utf-8",
    )
    return {
        "status": "evaluated_blind_once",
        "rows": len(comparable),
        "needs_context_rows_excluded": len(predictions) - len(comparable),
        "metrics": metrics,
        "calibration": calibration,
        "false_positive_false_negative_patterns": _safe_error_patterns(
            predictions,
            labels,
        ),
        "source_stability": _group_stability(
            predictions,
            labels,
            group_field="source_group",
        ),
        "temporal_stability": _group_stability(
            predictions,
            labels,
            group_field="time_window_group",
        ),
        "parser_schema_drift": drift,
        "isolation_forest": isolation,
        "label_reveal": reveal,
        "label_validation": label_validation,
        "labels_used_for_tuning": False,
        "evaluated_once_after_prediction_freeze": True,
        "active_artifact_written": False,
        "post_prediction_guard": {
            "used": False,
            "decision_policy": "calibrated_threshold_only",
            "actual_threats_suppressed": 0,
        },
        "raw_logs_included": False,
        "private_identifiers_included": False,
    }


def _public_lock_audit(value: dict[str, Any]) -> dict[str, Any]:
    return {key: item for key, item in value.items() if not key.startswith("_")}


def _public_candidate(value: dict[str, Any]) -> dict[str, Any]:
    return {key: item for key, item in value.items() if not key.startswith("_")}


def _render_report(result: dict[str, Any]) -> str:
    audit = result.get("evidence_lock_audit") or {}
    qualification = result.get("independent_evidence") or {}
    candidate = result.get("frozen_candidate") or {}
    validation = result.get("blind_validation") or {}
    readiness = result.get("readiness") or {}
    lines = [
        "# v5.7 Independent Evidence Readiness and Blind Shadow Revalidation",
        "",
        "## Evidence Boundary",
        "",
        f"- Lock audit: `{audit.get('status')}`",
        "- v5.3 final/rolling/external evidence is previously opened and locked.",
        "- v5.6 private evidence is development evidence, not a fresh holdout.",
        f"- Independent evidence: `{qualification.get('status')}`",
        "- Raw logs, IP addresses, private paths, and row fingerprints included: `false`",
        "",
        "## Frozen Candidate",
        "",
        f"- Candidate: `{candidate.get('candidate_name')}`",
        f"- Model: `{candidate.get('model_type')}`",
        f"- Calibration: `{candidate.get('calibration_method')}`",
        f"- Threshold: `{candidate.get('threshold')}`",
        "- Activated: `false`",
        "- Production promoted: `false`",
        "",
        "## Blind Validation",
        "",
        f"- Status: `{validation.get('status', 'not_run')}`",
        "- Predictions must be frozen before label reveal.",
        "- Labels used for tuning: `false`",
        "",
        "## Lifecycle",
        "",
        f"- State: `{readiness.get('lifecycle_state')}`",
        f"- Decision: `{readiness.get('decision')}`",
        "- Rules alert-authoritative: `true`",
        "- Response automation enabled: `false`",
        "- Real firewall blocking enabled: `false`",
        "",
        "## Blockers",
        "",
    ]
    lines.extend(f"- {item}" for item in readiness.get("blockers") or [])
    return "\n".join(lines) + "\n"


def run_v57_independent_shadow_revalidation(
    db: Session,
    *,
    sample_path: str | Path,
    evidence_manifest_path: str | Path | None = None,
    output_dir: str | Path = OUTPUT_DIR,
    min_samples: int = 100,
    chunk_size: int = 2000,
    max_prediction_rows: int = 1200,
    preflight_only: bool = False,
    predictions_only: bool = False,
    reveal_labels: bool = False,
    write_output: bool = True,
) -> dict[str, Any]:
    started = time.perf_counter()
    if predictions_only and reveal_labels:
        return {
            "ok": False,
            "status": "failed_closed_conflicting_modes",
            "lifecycle_state": "shadow_observation",
        }
    output = Path(output_dir)
    sample = Path(sample_path)
    manifest_path = (
        Path(evidence_manifest_path)
        if evidence_manifest_path is not None
        else None
    )
    evidence_manifest = _safe_json(manifest_path) if manifest_path else {}
    imports = _optional_imports()
    if imports is None:
        return {
            "ok": False,
            "status": "dependencies_unavailable",
            "lifecycle_state": "shadow_observation",
        }
    counts_before = frozen._database_counts(db)
    artifacts_before = v55._model_artifact_states()

    dataset = v52._prepare_dataset(db, min_samples=min_samples)
    if not dataset.get("ok"):
        return {
            "ok": False,
            "status": dataset.get("status", "failed_closed"),
            "message": dataset.get("message"),
            "lifecycle_state": "shadow_observation",
        }
    current_lock = v54.build_evidence_lock(dataset, output_dir=output)
    current_lock_validation = v54.validate_evidence_lock(
        current_lock,
        lock_path=v54.V53_LOCK_PATH,
    )
    lock_audit = audit_evidence_locks(
        output_dir=output,
        current_lock_validation=current_lock_validation,
    )
    if write_output:
        _write_evidence_lock_audit(output, lock_audit)
    sample_sha256 = _file_sha256(sample)
    development_reference = _safe_json(
        output / V57_DEVELOPMENT_REFERENCE
    )
    development_sha = development_reference.get(
        "development_sample_sha256"
    )
    if not evidence_manifest:
        development_sha = sample_sha256
    candidate = freeze_v56_candidate(
        imports,
        output_dir=output,
        lock_audit=lock_audit,
        development_sample_sha256=development_sha,
        write_output=write_output,
    )
    if not lock_audit.get("passed") or not candidate.get("ok"):
        return {
            "ok": False,
            "status": "failed_closed_lock_or_candidate_mismatch",
            "version": V57_VERSION,
            "lifecycle_state": "shadow_observation",
            "evidence_lock_audit": _public_lock_audit(lock_audit),
            "frozen_candidate": _public_candidate(candidate),
        }

    with tempfile.TemporaryDirectory(prefix="atdr-v57-") as directory:
        connection = sqlite3.connect(
            Path(directory) / "independent-shadow.sqlite3"
        )
        try:
            profile, protocol, signature = _prepare_independent_index(
                connection,
                sample_path=sample,
                database_url=get_settings().database_url,
                chunk_size=chunk_size,
            )
            previous_signature = (
                (lock_audit.get("_fingerprints") or {}).get(
                    "v56_role_signature"
                )
            )
            qualification = qualify_independent_evidence(
                evidence_manifest,
                profile={
                    **profile,
                    "chronological_profile_ok": protocol.get("ok"),
                    "observed_distinct_time_windows": protocol.get(
                        "distinct_time_windows"
                    ),
                },
                sample_sha256=sample_sha256,
                development_sample_sha256=development_sha,
                matches_v56_role_signature=bool(
                    signature
                    and previous_signature
                    and signature == previous_signature
                ),
                label_reveal_mode=reveal_labels,
                minimum_rows=min_samples,
            )
            bundle: dict[str, Any] = {
                "frame": imports[1].DataFrame(
                    columns=[
                        *v56.V56_NUMERIC_FEATURES,
                        *v56.V56_CATEGORICAL_FEATURES,
                    ]
                ),
                "rows": [],
            }
            prediction_freeze: dict[str, Any] = {
                "status": "not_run",
                "labels_revealed": False,
            }
            blind_validation: dict[str, Any] = {
                "status": "not_run_independent_evidence_required",
                "labels_used_for_tuning": False,
                "active_artifact_written": False,
            }
            if qualification.get("eligible_for_predictions"):
                independent_index = _activate_independent_evaluation_role(
                    connection
                )
                bundle, _ = _prediction_bundle(
                    imports,
                    connection,
                    max_rows=max_prediction_rows,
                )
                qualification["eligible_rows"] = independent_index.get(
                    "eligible_rows"
                )
                qualification["quarantined_rows"] = independent_index.get(
                    "quarantined_rows"
                )
                if predictions_only:
                    if manifest_path is None:
                        raise ValueError(
                            "Qualified predictions require a manifest path."
                        )
                    prediction_freeze = _write_prediction_freeze(
                        imports,
                        output_dir=output,
                        evidence_manifest=evidence_manifest,
                        evidence_manifest_path=manifest_path,
                        sample_sha256=str(sample_sha256),
                        candidate=candidate,
                        bundle=bundle,
                    )
                    blind_validation = {
                        "status": "pending_label_reveal",
                        "labels_used_for_tuning": False,
                        "active_artifact_written": False,
                    }
                elif reveal_labels:
                    if manifest_path is None:
                        raise ValueError(
                            "Label reveal requires an evidence manifest path."
                        )
                    blind_validation = _evaluate_revealed_labels(
                        imports,
                        output_dir=output,
                        evidence_manifest=evidence_manifest,
                        evidence_manifest_path=manifest_path,
                        sample_sha256=str(sample_sha256),
                        candidate=candidate,
                        bundle=bundle,
                        lock_audit=lock_audit,
                    )
                elif not preflight_only:
                    blind_validation = {
                        "status": "ready_for_predictions_only_command",
                        "labels_used_for_tuning": False,
                        "active_artifact_written": False,
                    }
            elif reveal_labels:
                blind_validation = {
                    "status": "failed_closed_independent_evidence_not_qualified",
                    "labels_used_for_tuning": False,
                    "active_artifact_written": False,
                }
        finally:
            connection.close()

    counts_after = frozen._database_counts(db)
    artifacts_after = v55._model_artifact_states()
    safety = {
        "database_counts_unchanged": counts_before == counts_after,
        "model_artifacts_unchanged": artifacts_before == artifacts_after,
        "labels_created": counts_after["ml_labels"] - counts_before["ml_labels"],
        "model_runs_created": counts_after["ml_model_runs"]
        - counts_before["ml_model_runs"],
        "detection_runs_created": counts_after["detection_runs"]
        - counts_before["detection_runs"],
        "alerts_created": counts_after["alerts"] - counts_before["alerts"],
        "response_actions_created": counts_after["response_actions"]
        - counts_before["response_actions"],
        "configured_database_written": False,
        "active_model_artifact_written": False,
        "active_model_artifact_replaced": False,
        "model_activated": False,
        "model_promoted": False,
        "rules_alert_authoritative": True,
        "automatic_response_enabled": False,
        "real_firewall_blocking_enabled": False,
    }
    readiness = _readiness(
        lock_audit=lock_audit,
        candidate=candidate,
        qualification=qualification,
        validation=blind_validation,
        safety=safety,
    )
    status = (
        "blind_validation_complete"
        if blind_validation.get("status") == "evaluated_blind_once"
        else "predictions_frozen"
        if prediction_freeze.get("status")
        in {
            "predictions_frozen_labels_sealed",
            "predictions_already_frozen",
        }
        else "sample_preflight_failed"
        if not profile.get("ok")
        else "independent_evidence_required"
        if not qualification.get("eligible_for_predictions")
        else "ready_for_prediction_freeze"
    )
    result = {
        "ok": bool(
            lock_audit.get("passed")
            and candidate.get("ok")
            and profile.get("ok")
            and safety["database_counts_unchanged"]
            and safety["model_artifacts_unchanged"]
            and safety["labels_created"] == 0
            and safety["response_actions_created"] == 0
        ),
        "status": status,
        "version": V57_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "lifecycle_state": "shadow_observation",
        "evidence_lock_audit": _public_lock_audit(lock_audit),
        "frozen_candidate": _public_candidate(candidate),
        "sample_profile": {
            "status": profile.get("status"),
            "rows_processed": profile.get("rows_processed"),
            "parser_successes": profile.get("parser_successes"),
            "parser_failures": profile.get("parser_failures"),
            "configured_database_overlap_rows": profile.get(
                "configured_database_overlap_rows"
            ),
            "exact_duplicate_rows": profile.get("exact_duplicate_rows"),
            "near_duplicate_rows": profile.get("near_duplicate_rows"),
            "matches_reused_v56_evidence": bool(
                signature
                and previous_signature
                and signature == previous_signature
            ),
            "raw_logs_included": False,
            "private_identifiers_included": False,
            "file_fingerprint_exposed": False,
        },
        "independent_evidence": qualification,
        "evidence_research": {
            "sources_reviewed": list(PRIVATE_EVIDENCE_RESEARCH),
            "fresh_native_panos_labeled_corpus_found": False,
            "conclusion": "independent_evidence_required",
        },
        "prediction_freeze": prediction_freeze,
        "blind_validation": blind_validation,
        "isolation_forest": (
            blind_validation.get("isolation_forest")
            if blind_validation.get("status") == "evaluated_blind_once"
            else {
                "status": "pending_independent_labels",
                "v5_6_development_baseline_only": True,
                "advisory_only": True,
            }
        ),
        "readiness": readiness,
        "safety": safety,
        "acquisition_package": {
            "required": not qualification.get("eligible_for_predictions"),
            "manifest_template": (
                "data/samples/benchmarks/"
                "v57_independent_evidence_manifest.template.json"
            ),
            "instructions": (
                "docs/detection/"
                "V5_7_INDEPENDENT_EVIDENCE_ACQUISITION.md"
            ),
            "ai_suggestions_are_ground_truth": False,
        },
        "privacy": {
            "private_path_returned": False,
            "raw_logs_returned": False,
            "ip_addresses_returned": False,
            "row_fingerprints_returned": False,
            "secrets_exposed": False,
        },
        "runtime_seconds": round(time.perf_counter() - started, 4),
    }
    if write_output:
        output.mkdir(parents=True, exist_ok=True)
        stamp = _stamp()
        report_path = output / f"v5_7_independent_shadow_{stamp}.md"
        latest_path = output / V57_LATEST
        report_path.write_text(_render_report(result), encoding="utf-8")
        latest_path.write_text(
            json.dumps(result, indent=2, default=str),
            encoding="utf-8",
        )
        result["reports"] = {
            "markdown_file_name": report_path.name,
            "latest_json_file_name": latest_path.name,
            "ignored_output": True,
            "private_paths_returned": False,
        }
    return result
