from __future__ import annotations

import csv
import hashlib
import heapq
import json
import math
import time
from collections import Counter, defaultdict, deque
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable

from sqlalchemy.orm import Session

from atdr.app.core.config import PROJECT_ROOT
from atdr.app.detection import v398_independent_holdout_validation as frozen
from atdr.app.detection import v55_development_model_repair as v55
from atdr.app.detection import v56_private_panos_model_repair as v56
from atdr.app.detection import v57_independent_shadow_revalidation as v57
from atdr.app.detection.supervised_detector import _optional_imports
from atdr.app.detection.v330_detection_ml_quality import OUTPUT_DIR


V519_VERSION = "v5.19-independent-labeled-blind-validation-v1"
V519_MANIFEST_VERSION = "atdr-v5.19-ctu13-evidence-manifest-v1"
V519_LATEST = "v5_19_independent_labeled_validation_latest.json"
V519_STATE = "v5_19_blind_evaluation_state.json"
V519_REPORT_PREFIX = "v5_19_independent_labeled_validation"
DEFAULT_ROWS_PER_SCENARIO = 5_000
DEFAULT_SAMPLE_SEED = 519
MAX_NEAR_DUPLICATES_PER_FAMILY = 3

DATASET = {
    "dataset_id": "ctu-13-bidirectional-netflow",
    "title": "CTU-13",
    "publisher": "Stratosphere Laboratory, Czech Technical University",
    "version": "CTU-13 scenarios 5, 7, 11, and 12",
    "official_page": "https://www.stratosphereips.org/datasets-ctu13",
    "license": "CC-BY; research use requires the publisher citation",
    "citation": (
        "Sebastian Garcia, Martin Grill, Jan Stiborek, and Alejandro "
        "Zunino, An empirical comparison of botnet detection methods, 2014."
    ),
    "schema_family": "ctu13_bidirectional_argus_netflow",
    "ground_truth": "publisher_manual_flow_labels",
    "native_panos": False,
    "independent_of_atdr_development": True,
}

SOURCE_FILES: tuple[dict[str, str], ...] = (
    {
        "logical_name": "scenario-05.binetflow",
        "scenario_id": "ctu13-scenario-05",
        "provider_scenario": "5",
        "behavior_family": "virut_botnet",
        "official_url": (
            "https://mcfp.felk.cvut.cz/publicDatasets/"
            "CTU-Malware-Capture-Botnet-46/"
            "detailed-bidirectional-flow-labels/"
            "capture20110815-2.binetflow"
        ),
    },
    {
        "logical_name": "scenario-07.binetflow",
        "scenario_id": "ctu13-scenario-07",
        "provider_scenario": "7",
        "behavior_family": "sogou_botnet",
        "official_url": (
            "https://mcfp.felk.cvut.cz/publicDatasets/"
            "CTU-Malware-Capture-Botnet-48/"
            "detailed-bidirectional-flow-labels/"
            "capture20110816-2.binetflow"
        ),
    },
    {
        "logical_name": "scenario-11.binetflow",
        "scenario_id": "ctu13-scenario-11",
        "provider_scenario": "11",
        "behavior_family": "rbot_icmp_dos",
        "official_url": (
            "https://mcfp.felk.cvut.cz/publicDatasets/"
            "CTU-Malware-Capture-Botnet-52/"
            "detailed-bidirectional-flow-labels/"
            "capture20110818-2.binetflow"
        ),
    },
    {
        "logical_name": "scenario-12.binetflow",
        "scenario_id": "ctu13-scenario-12",
        "provider_scenario": "12",
        "behavior_family": "nsis_p2p_udp_scan",
        "official_url": (
            "https://mcfp.felk.cvut.cz/publicDatasets/"
            "CTU-Malware-Capture-Botnet-53/"
            "detailed-bidirectional-flow-labels/"
            "capture20110819.binetflow"
        ),
    },
)

REQUIRED_COLUMNS = (
    "StartTime",
    "Dur",
    "Proto",
    "SrcAddr",
    "Sport",
    "Dir",
    "DstAddr",
    "Dport",
    "State",
    "sTos",
    "dTos",
    "TotPkts",
    "TotBytes",
    "SrcBytes",
    "Label",
)

DIRECT_FEATURES = (
    "src_port",
    "dst_port",
    "bytes",
    "bytes_sent",
    "bytes_received",
    "packets",
    "elapsed_time",
    "protocol",
    "hour_of_day",
    "is_after_hours",
)
DERIVED_FEATURES = (
    "repeat_count_effective",
    "parser_warning_count",
    "required_field_missing_count",
    "parser_confidence_score",
    "src_ip_5min_log_count",
    "src_ip_5min_unique_dst_ports",
    "src_ip_5min_unique_dst_ips",
    "src_ip_5min_total_bytes",
    "src_ip_5min_avg_packets",
    "v56_rule_evidence_score",
    "v56_destination_repeat_count",
    "v56_schema_field_count",
    "v56_scan_pressure",
)
UNAVAILABLE_FEATURES = tuple(
    sorted(
        set(v56.V56_NUMERIC_FEATURES + v56.V56_CATEGORICAL_FEATURES)
        - set(DIRECT_FEATURES)
        - set(DERIVED_FEATURES)
    )
)

GATES = {
    "queue_f1_min": 0.85,
    "threat_recall_min": 0.80,
    "benign_like_false_positive_rate_max": 0.05,
    "expected_calibration_error_max": 0.10,
    "max_confidence_accuracy_gap_max": 0.15,
    "minimum_comparable_rows": 1_000,
    "minimum_scenarios": 4,
    "minimum_rows_per_class": 100,
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


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


def _file_sha256(path: Path) -> str:
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


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n",
        encoding="utf-8",
    )


def _number(value: Any, default: float = 0.0) -> float:
    try:
        result = float(str(value).strip())
    except (TypeError, ValueError):
        return default
    return result if math.isfinite(result) else default


def _integer(value: Any, default: int = 0) -> int:
    try:
        text = str(value).strip()
        if not text:
            return default
        return int(float(text))
    except (TypeError, ValueError):
        return default


def _optional_integer(value: Any) -> int | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return int(text, 0) if text.lower().startswith("0x") else int(float(text))
    except (TypeError, ValueError):
        return None


def _parse_timestamp(value: Any) -> datetime | None:
    text = str(value or "").strip()
    patterns = (
        "%Y/%m/%d %H:%M:%S.%f",
        "%Y/%m/%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
    )
    for pattern in patterns:
        try:
            return datetime.strptime(text, pattern).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _magnitude_bucket(value: Any) -> int:
    numeric = abs(_number(value))
    return 0 if numeric < 1 else int(math.log10(numeric)) + 1


def _path_is_ignored_output(path: Path) -> bool:
    resolved = path.resolve()
    roots = (
        (PROJECT_ROOT / ".tmp").resolve(),
        (PROJECT_ROOT / "ml_baseline_reviews").resolve(),
        (PROJECT_ROOT / "demo_exports").resolve(),
    )
    return any(resolved == root or resolved.is_relative_to(root) for root in roots)


def _file_spec(logical_name: str) -> dict[str, str]:
    for value in SOURCE_FILES:
        if value["logical_name"] == logical_name:
            return dict(value)
    raise ValueError("Unsupported CTU-13 provider file.")


def _manifest_contract() -> dict[str, Any]:
    return {
        "version": V519_VERSION,
        "dataset_id": DATASET["dataset_id"],
        "provider_scenarios": [
            value["provider_scenario"] for value in SOURCE_FILES
        ],
        "selection_policy": (
            "four_smallest_official_bidirectional_flow_scenarios_by_file_size"
        ),
        "sample_seed": DEFAULT_SAMPLE_SEED,
        "maximum_near_duplicates_per_family": (
            MAX_NEAR_DUPLICATES_PER_FAMILY
        ),
        "label_mapping": {
            "from-botnet-prefix": "threat_positive",
            "from-normal-prefix": "benign_like",
            "background": "ambiguous_excluded",
            "to-botnet-prefix": "ambiguous_excluded",
            "to-normal-prefix": "ambiguous_excluded",
            "all_other_values": "unsupported_excluded",
        },
        "taxonomy_policy": (
            "binary_provider_ground_truth_only_no_atdr_suspicious_or_malicious_inference"
        ),
        "prediction_policy": "frozen_v56_calibrated_threshold_only",
        "post_prediction_guard": "disabled",
        "metrics": (
            "binary_precision_recall_f1_fpr_confusion_queue_calibration_"
            "scenario_stability"
        ),
        "gates": GATES,
        "rule_baseline": (
            "volume_rules_only_when_required_provider_fields_are_present"
        ),
        "labels_used_for_sampling": False,
        "labels_used_for_prediction": False,
        "labels_used_for_tuning": False,
    }


def _public_manifest(value: dict[str, Any]) -> dict[str, Any]:
    return {
        "status": value.get("status"),
        "dataset_id": value.get("dataset_id"),
        "publisher": value.get("publisher"),
        "version": value.get("dataset_version"),
        "schema_family": value.get("schema_family"),
        "ground_truth": value.get("ground_truth"),
        "file_count": len(value.get("files") or []),
        "identity_verified": bool(value.get("identity_verified")),
        "manifest_immutable": True,
        "manifest_hash_recorded_privately": bool(value),
        "fingerprints_exposed": False,
        "paths_exposed": False,
        "raw_rows_exposed": False,
        "ip_addresses_exposed": False,
    }


def create_or_verify_evidence_manifest(
    dataset_dir: Path,
    manifest_path: Path,
) -> dict[str, Any]:
    if not _path_is_ignored_output(dataset_dir):
        return {
            "ok": False,
            "status": "failed_closed_dataset_path_must_be_ignored",
        }
    if not _path_is_ignored_output(manifest_path):
        return {
            "ok": False,
            "status": "failed_closed_manifest_path_must_be_ignored",
        }
    files: list[dict[str, Any]] = []
    for spec in SOURCE_FILES:
        path = dataset_dir / spec["logical_name"]
        if not path.exists() or not path.is_file():
            return {
                "ok": False,
                "status": "failed_closed_provider_file_missing",
                "missing_file": spec["logical_name"],
            }
        files.append(
            {
                "logical_name": spec["logical_name"],
                "scenario_id": spec["scenario_id"],
                "provider_scenario": spec["provider_scenario"],
                "behavior_family": spec["behavior_family"],
                "official_url": spec["official_url"],
                "size_bytes": path.stat().st_size,
                "sha256": _file_sha256(path),
            }
        )
    contract = _manifest_contract()
    identity = {
        "manifest_version": V519_MANIFEST_VERSION,
        "dataset_id": DATASET["dataset_id"],
        "publisher": DATASET["publisher"],
        "dataset_version": DATASET["version"],
        "official_page": DATASET["official_page"],
        "license": DATASET["license"],
        "citation": DATASET["citation"],
        "schema_family": DATASET["schema_family"],
        "ground_truth": DATASET["ground_truth"],
        "files": files,
        "contract": contract,
        "independence": {
            "not_used_for_atdr_fit": True,
            "not_used_for_atdr_calibration": True,
            "not_used_for_atdr_threshold_selection": True,
            "not_previously_opened_in_atdr": True,
            "private_panos_development_file": False,
            "prior_cse_cic_ids2018_benchmark": False,
        },
    }
    identity_hash = _stable_hash(identity)
    expected = {
        **identity,
        "created_at": _utc_now(),
        "status": "ready_for_one_shot_blind_execution",
        "identity_verified": True,
        "identity_sha256": identity_hash,
        "labels_opened": False,
        "private_paths_included": False,
        "raw_rows_included": False,
        "ip_addresses_included": False,
        "ignored_output": True,
    }
    existing = _safe_json(manifest_path)
    if existing:
        existing_identity = {
            key: existing.get(key) for key in identity
        }
        valid = all(
            (
                existing.get("manifest_version") == V519_MANIFEST_VERSION,
                existing.get("identity_sha256") == identity_hash,
                _stable_hash(existing_identity) == identity_hash,
                existing.get("labels_opened") is False,
            )
        )
        return {
            "ok": valid,
            "status": (
                "manifest_identity_verified"
                if valid
                else "failed_closed_manifest_identity_mismatch"
            ),
            "manifest": existing if valid else {},
        }
    _write_json(manifest_path, expected)
    return {
        "ok": True,
        "status": "manifest_created_and_identity_verified",
        "manifest": expected,
    }


def audit_prior_evidence_and_load_candidate(
    *, output_dir: Path = OUTPUT_DIR
) -> dict[str, Any]:
    imports = _optional_imports()
    if imports is None:
        return {"ok": False, "status": "dependencies_unavailable"}
    lock_path = output_dir / v57.V57_EVIDENCE_LOCK_AUDIT
    freeze_path = output_dir / v57.V57_CANDIDATE_FREEZE
    v56_report_path = output_dir / v56.V56_LATEST
    lock = _safe_json(lock_path)
    freeze = _safe_json(freeze_path)
    report = _safe_json(v56_report_path)
    artifact_name = str(
        (report.get("diagnostic_candidate_artifact") or {}).get(
            "artifact_name"
        )
        or freeze.get("artifact_name")
        or ""
    )
    artifact_path = (
        output_dir / artifact_name
        if artifact_name and Path(artifact_name).name == artifact_name
        else None
    )
    artifact_hash = (
        _file_sha256(artifact_path)
        if artifact_path and artifact_path.exists()
        else None
    )
    expected_report_hash = (
        (report.get("diagnostic_candidate_artifact") or {}).get("sha256")
    )
    checks = {
        "v57_lock_audit_present_and_passed": bool(
            lock and lock.get("passed")
        ),
        "v57_candidate_freeze_present": bool(freeze),
        "v56_report_present": bool(report),
        "candidate_frozen_before_label_access": bool(
            freeze.get("frozen_before_independent_label_access")
        ),
        "candidate_inactive": freeze.get("active") is False,
        "candidate_not_promoted": freeze.get("production_promoted") is False,
        "response_automation_disabled": (
            freeze.get("response_automation_allowed") is False
        ),
        "rules_alert_authoritative": bool(
            freeze.get("rules_alert_authoritative")
        ),
        "artifact_present": artifact_hash is not None,
        "artifact_matches_v56_report": bool(
            artifact_hash and artifact_hash == expected_report_hash
        ),
        "artifact_matches_v57_freeze": bool(
            artifact_hash and artifact_hash == freeze.get("artifact_sha256")
        ),
    }
    if not all(checks.values()) or artifact_path is None:
        return {
            "ok": False,
            "status": "failed_closed_prior_lock_or_candidate_mismatch",
            "checks": checks,
        }
    try:
        artifact = imports[0].load(artifact_path)
    except (OSError, ValueError, TypeError, KeyError, AttributeError) as exc:
        return {
            "ok": False,
            "status": "failed_closed_candidate_unreadable",
            "error_type": type(exc).__name__,
            "checks": checks,
        }
    pipeline = artifact.get("pipeline")
    feature_names = [
        str(value) for value in getattr(pipeline, "feature_names_in_", [])
    ]
    expected_features = [
        *v56.V56_NUMERIC_FEATURES,
        *v56.V56_CATEGORICAL_FEATURES,
    ]
    checks["feature_contract_matched"] = feature_names == expected_features
    checks["threshold_matched"] = _number(artifact.get("threshold"), -1.0) == _number(
        freeze.get("threshold"), -2.0
    )
    if pipeline is None or not all(checks.values()):
        return {
            "ok": False,
            "status": "failed_closed_candidate_contract_mismatch",
            "checks": checks,
        }
    details = v57._artifact_pipeline_details(pipeline)
    calibration_estimator = getattr(pipeline, "estimator", None)
    base_estimator = getattr(
        calibration_estimator,
        "estimator",
        calibration_estimator,
    )
    base_steps = [
        {"name": str(name), "type": type(value).__name__}
        for name, value in getattr(base_estimator, "steps", [])
    ]
    underlying_model_type = next(
        (
            row["type"]
            for row in base_steps
            if row["name"] == "model"
        ),
        details.get("model_type"),
    )
    return {
        "ok": True,
        "status": "frozen_candidate_verified",
        "checks": checks,
        "candidate_name": artifact.get("candidate_name"),
        "candidate_version": artifact.get("version"),
        "model_type": underlying_model_type,
        "calibration_method": details.get("calibration_method"),
        "threshold": _number(artifact.get("threshold"), 0.5),
        "feature_count": len(feature_names),
        "active": False,
        "production_promoted": False,
        "response_automation_allowed": False,
        "fingerprints_recorded_privately": True,
        "fingerprints_exposed": False,
        "_pipeline": pipeline,
        "_artifact_hash": artifact_hash,
    }


def _scenario_salt(manifest: dict[str, Any], scenario_id: str) -> str:
    return _stable_hash(
        {
            "manifest": manifest.get("identity_sha256"),
            "scenario": scenario_id,
            "namespace": V519_VERSION,
        }
    )


def _token(salt: str, namespace: str, value: Any) -> str:
    return hashlib.sha256(
        f"{salt}|{namespace}|{value or 'missing'}".encode("utf-8")
    ).hexdigest()


def _canonical_feature_hash(
    values: dict[str, str], *, salt: str
) -> str:
    payload = {
        key: (
            _token(salt, key, value)
            if key in {"SrcAddr", "DstAddr"}
            else str(value).strip()
        )
        for key, value in sorted(values.items())
    }
    return _stable_hash(payload)


def _sample_rank(
    *, file_hash: str, row_number: int, seed: int = DEFAULT_SAMPLE_SEED
) -> int:
    return int.from_bytes(
        hashlib.sha256(
            f"{seed}|{file_hash}|{row_number}".encode("utf-8")
        ).digest(),
        byteorder="big",
        signed=False,
    )


def _feature_record(
    values: dict[str, str],
    *,
    scenario_id: str,
    row_number: int,
    salt: str,
    source_window: deque[dict[str, Any]],
    window_preloaded: bool = False,
) -> dict[str, Any]:
    timestamp = _parse_timestamp(values.get("StartTime"))
    duration = max(0.0, _number(values.get("Dur")))
    packets = max(0, _integer(values.get("TotPkts")))
    total_bytes = max(0, _integer(values.get("TotBytes")))
    source_bytes = min(total_bytes, max(0, _integer(values.get("SrcBytes"))))
    destination_bytes = max(0, total_bytes - source_bytes)
    src_port = _optional_integer(values.get("Sport"))
    dst_port = _optional_integer(values.get("Dport"))
    protocol = str(values.get("Proto") or "unknown").strip().lower()
    source_token = _token(salt, "source", values.get("SrcAddr"))
    destination_token = _token(salt, "destination", values.get("DstAddr"))
    raw_destination = str(values.get("DstAddr") or "missing")
    current = {
        "timestamp": timestamp,
        "destination": raw_destination,
        "dst_port": dst_port,
        "bytes": total_bytes,
        "packets": packets,
    }
    if not window_preloaded:
        if timestamp:
            cutoff = timestamp - timedelta(minutes=5)
            while source_window and (
                source_window[0].get("timestamp") is not None
                and source_window[0]["timestamp"] < cutoff
            ):
                source_window.popleft()
        source_window.append(current)
    unique_destinations = len(
        {item["destination"] for item in source_window}
    )
    unique_ports = len(
        {
            item["dst_port"]
            for item in source_window
            if item.get("dst_port") is not None
        }
    )
    source_total_bytes = sum(_integer(item.get("bytes")) for item in source_window)
    average_packets = (
        sum(_integer(item.get("packets")) for item in source_window)
        / max(1, len(source_window))
    )
    destination_repeat = sum(
        1
        for item in source_window
        if item.get("destination") == raw_destination
        and item.get("dst_port") == dst_port
    )
    required_values = (
        timestamp,
        protocol if protocol != "unknown" else None,
        dst_port,
        packets,
        total_bytes,
    )
    missing_count = sum(value is None for value in required_values)
    volume_rule_score = int(total_bytes >= 10_000_000) + int(packets >= 50_000)
    row = {
        "event_time": timestamp.isoformat() if timestamp else None,
        "src_port": src_port,
        "dst_port": dst_port,
        "bytes": total_bytes,
        "bytes_sent": source_bytes,
        "bytes_received": destination_bytes,
        "packets": packets,
        "elapsed_time": duration,
        "app_risk": 0,
        "repeat_count": 1,
        "parser_error": int(missing_count >= 3),
        "parser_warning_count": int(missing_count > 0),
        "required_missing_count": missing_count,
        "unknown_app_flag": 0,
        "external_to_internal_flag": 0,
        "internal_to_external_flag": 0,
        "source_event_count": len(source_window),
        "source_deny_count": 0,
        "source_unique_ports": unique_ports,
        "source_unique_destinations": unique_destinations,
        "source_total_bytes": source_total_bytes,
        "source_average_packets": average_packets,
        "source_unknown_app_count": 0,
        "source_high_risk_app_count": 0,
        "rule_score": volume_rule_score,
        "destination_repeat_count": destination_repeat,
        "field_count": sum(
            bool(str(values.get(column) or "").strip())
            for column in REQUIRED_COLUMNS
            if column != "Label"
        ),
        "protocol": protocol,
        "action": "unavailable_provider_flow",
        "app": "unavailable_provider_flow",
        "src_zone": "unavailable_provider_flow",
        "dst_zone": "unavailable_provider_flow",
        "log_type": "FLOW",
        "subtype": "ctu13_bidirectional",
        "schema_bucket": "provider_flow_limited",
        "threat_severity": "unavailable",
    }
    feature_row = v56._private_feature_row(row)
    near_group = _stable_hash(
        {
            "scenario": scenario_id,
            "minute": (
                timestamp.replace(second=0, microsecond=0).isoformat()
                if timestamp
                else "missing"
            ),
            "source": source_token,
            "destination": destination_token,
            "protocol": protocol,
            "src_port": src_port,
            "dst_port": dst_port,
            "bytes_bucket": _magnitude_bucket(total_bytes),
            "packets_bucket": _magnitude_bucket(packets),
        }
    )
    return {
        "scenario_id": scenario_id,
        "row_number": row_number,
        "timestamp": timestamp,
        "source_group": source_token[:16],
        "time_window_group": _stable_hash(
            {
                "scenario": scenario_id,
                "hour": (
                    timestamp.replace(minute=0, second=0, microsecond=0).isoformat()
                    if timestamp
                    else "missing"
                ),
            }
        )[:16],
        "protocol": protocol,
        "dst_port": dst_port,
        "bytes_bucket": _magnitude_bucket(total_bytes),
        "packets_bucket": _magnitude_bucket(packets),
        "rule_prediction": (
            "needs_review" if volume_rule_score else "non_threat"
        ),
        "feature_row": feature_row,
        "near_group": near_group,
    }


def build_label_sealed_feature_sample(
    dataset_dir: Path,
    manifest: dict[str, Any],
    *,
    rows_per_scenario: int = DEFAULT_ROWS_PER_SCENARIO,
) -> dict[str, Any]:
    selected_rows: list[dict[str, Any]] = []
    file_summaries: list[dict[str, Any]] = []
    exact_seen: set[str] = set()
    near_counts: Counter[str] = Counter()
    exact_duplicates = 0
    near_duplicates_quarantined = 0
    malformed_rows = 0
    manifest_files = {
        value["logical_name"]: value for value in manifest.get("files") or []
    }
    for spec in SOURCE_FILES:
        path = dataset_dir / spec["logical_name"]
        file_identity = manifest_files.get(spec["logical_name"]) or {}
        file_hash = str(file_identity.get("sha256") or "")
        salt = _scenario_salt(manifest, spec["scenario_id"])
        source_windows: dict[str, deque[dict[str, Any]]] = defaultdict(deque)
        candidate_heap: list[tuple[int, int, int]] = []
        rows_seen = 0
        eligible_rows = 0

        # Pass one selects row numbers from file identity and row position only.
        # No feature value or provider label participates in sampling.
        with path.open("r", encoding="utf-8-sig", newline="") as stream:
            reader = csv.reader(stream)
            try:
                header = [value.strip() for value in next(reader)]
            except StopIteration:
                return {"ok": False, "status": "failed_closed_empty_provider_file"}
            if tuple(header) != REQUIRED_COLUMNS:
                return {
                    "ok": False,
                    "status": "failed_closed_provider_schema_mismatch",
                    "scenario_id": spec["scenario_id"],
                }
            label_index = header.index("Label")
            for row_number, row in enumerate(reader, start=1):
                rows_seen += 1
                if len(row) != len(header):
                    malformed_rows += 1
                    continue
                rank = _sample_rank(
                    file_hash=file_hash,
                    row_number=row_number,
                )
                candidate = (-rank, -row_number, row_number)
                candidate_limit = max(1, rows_per_scenario * 2)
                if len(candidate_heap) < candidate_limit:
                    heapq.heappush(candidate_heap, candidate)
                elif candidate > candidate_heap[0]:
                    heapq.heapreplace(candidate_heap, candidate)

        selected_numbers = {
            item[2]: -item[0] for item in candidate_heap
        }
        scenario_candidates: list[tuple[int, int, dict[str, Any]]] = []

        # Pass two computes rolling context for all rows, but performs expensive
        # fingerprinting and feature conversion only for selected candidates.
        with path.open("r", encoding="utf-8-sig", newline="") as stream:
            reader = csv.reader(stream)
            header = [value.strip() for value in next(reader)]
            label_index = header.index("Label")
            for row_number, row in enumerate(reader, start=1):
                if len(row) != len(header):
                    continue
                values = {
                    column: row[index]
                    for index, column in enumerate(header)
                    if index != label_index
                }
                timestamp = _parse_timestamp(values.get("StartTime"))
                source_key = str(values.get("SrcAddr") or "missing")
                source_window = source_windows[source_key]
                if timestamp:
                    cutoff = timestamp - timedelta(minutes=5)
                    while source_window and (
                        source_window[0].get("timestamp") is not None
                        and source_window[0]["timestamp"] < cutoff
                    ):
                        source_window.popleft()
                source_window.append(
                    {
                        "timestamp": timestamp,
                        "destination": str(values.get("DstAddr") or "missing"),
                        "dst_port": _optional_integer(values.get("Dport")),
                        "bytes": max(0, _integer(values.get("TotBytes"))),
                        "packets": max(0, _integer(values.get("TotPkts"))),
                    }
                )
                rank = selected_numbers.get(row_number)
                if rank is None:
                    continue
                exact_hash = _canonical_feature_hash(values, salt=salt)
                if exact_hash in exact_seen:
                    exact_duplicates += 1
                    continue
                exact_seen.add(exact_hash)
                record = _feature_record(
                    values,
                    scenario_id=spec["scenario_id"],
                    row_number=row_number,
                    salt=salt,
                    source_window=source_window,
                    window_preloaded=True,
                )
                near_group = str(record["near_group"])
                near_counts[near_group] += 1
                if near_counts[near_group] > MAX_NEAR_DUPLICATES_PER_FAMILY:
                    near_duplicates_quarantined += 1
                    continue
                record["exact_hash"] = exact_hash
                scenario_candidates.append((rank, row_number, record))
        scenario_candidates.sort(key=lambda item: (item[0], item[1]))
        selected = scenario_candidates[: max(1, rows_per_scenario)]
        eligible_rows = len(scenario_candidates)
        selected_rows.extend(item[2] for item in selected)
        file_summaries.append(
            {
                "scenario_id": spec["scenario_id"],
                "provider_rows": rows_seen,
                "label_sealed_eligible_rows": eligible_rows,
                "sampled_rows": len(selected),
                "sampling_consulted_labels": False,
            }
        )
    selected_rows.sort(
        key=lambda row: (str(row["scenario_id"]), _integer(row["row_number"]))
    )
    return {
        "ok": bool(selected_rows),
        "status": "label_sealed_feature_sample_ready",
        "rows": selected_rows,
        "sampled_rows": len(selected_rows),
        "files": file_summaries,
        "duplicate_audit": {
            "exact_duplicates_quarantined": exact_duplicates,
            "near_duplicates_quarantined": near_duplicates_quarantined,
            "malformed_rows_quarantined": malformed_rows,
            "duplicate_policy_label_independent": True,
        },
        "labels_accessed": False,
        "labels_used_for_sampling": False,
        "labels_used_for_features": False,
        "raw_rows_retained": False,
        "ip_addresses_retained": False,
    }


def _state_path(output_dir: Path) -> Path:
    return output_dir / V519_STATE


def freeze_predictions(
    imports: Any,
    *,
    output_dir: Path,
    manifest_path: Path,
    manifest: dict[str, Any],
    candidate: dict[str, Any],
    feature_sample: dict[str, Any],
) -> dict[str, Any]:
    state_path = _state_path(output_dir)
    existing = _safe_json(state_path)
    if existing:
        return {
            "ok": False,
            "status": (
                "failed_closed_blind_labels_already_revealed"
                if existing.get("labels_revealed")
                else "failed_closed_prediction_freeze_already_exists"
            ),
            "labels_revealed": bool(existing.get("labels_revealed")),
        }
    pd = imports[1]
    rows = feature_sample["rows"]
    frame = pd.DataFrame(
        [row["feature_row"] for row in rows],
        columns=[*v56.V56_NUMERIC_FEATURES, *v56.V56_CATEGORICAL_FEATURES],
    )
    pipeline = candidate["_pipeline"]
    classes = [str(value) for value in getattr(pipeline, "classes_", [])]
    if "needs_review" not in classes:
        return {
            "ok": False,
            "status": "failed_closed_candidate_positive_class_missing",
        }
    position = classes.index("needs_review")
    probabilities = pipeline.predict_proba(frame)
    threshold = _number(candidate.get("threshold"), 0.5)
    prediction_name = f"v5_19_frozen_predictions_{_stamp()}.jsonl"
    prediction_path = output_dir / prediction_name
    output_dir.mkdir(parents=True, exist_ok=True)
    frozen_at = _utc_now()
    prediction_rows: list[dict[str, Any]] = []
    private_salt = _stable_hash(
        {
            "manifest": manifest.get("identity_sha256"),
            "candidate": candidate.get("_artifact_hash"),
            "version": V519_VERSION,
        }
    )
    with prediction_path.open("w", encoding="utf-8", newline="\n") as stream:
        for row, probability in zip(rows, probabilities, strict=True):
            score = float(probability[position])
            review_token = _stable_hash(
                {
                    "salt": private_salt,
                    "scenario": row["scenario_id"],
                    "row": row["row_number"],
                    "exact": row["exact_hash"],
                }
            )
            record = {
                "review_token": review_token,
                "scenario_id": row["scenario_id"],
                "provider_row_number": row["row_number"],
                "prediction": (
                    "needs_review" if score >= threshold else "non_threat"
                ),
                "threat_score": round(score, 10),
                "rule_prediction": row["rule_prediction"],
                "source_group": row["source_group"],
                "time_window_group": row["time_window_group"],
                "protocol": row["protocol"],
                "dst_port": row["dst_port"],
                "bytes_bucket": row["bytes_bucket"],
                "packets_bucket": row["packets_bucket"],
            }
            stream.write(json.dumps(record, sort_keys=True) + "\n")
            prediction_rows.append(record)
    state = {
        "version": V519_VERSION,
        "created_at": frozen_at,
        "manifest_file_name": manifest_path.name,
        "manifest_sha256": _file_sha256(manifest_path),
        "candidate_artifact_sha256": candidate.get("_artifact_hash"),
        "prediction_file_name": prediction_name,
        "predictions_sha256": _file_sha256(prediction_path),
        "prediction_rows": len(prediction_rows),
        "predictions_frozen_before_labels": True,
        "labels_accessed_before_freeze": False,
        "labels_used_for_sampling": False,
        "labels_used_for_features": False,
        "labels_used_for_prediction": False,
        "labels_used_for_tuning": False,
        "labels_revealed": False,
        "evaluation_completed": False,
        "private_paths_included": False,
        "raw_rows_included": False,
        "ip_addresses_included": False,
        "ignored_output": True,
    }
    _write_json(state_path, state)
    return {
        "ok": True,
        "status": "predictions_frozen_labels_sealed",
        "rows": prediction_rows,
        "predictions_frozen_at": frozen_at,
        "labels_revealed": False,
        "fingerprints_recorded_privately": True,
        "fingerprints_exposed": False,
    }


def _provider_truth(label: Any, *, scenario_id: str) -> dict[str, str]:
    normalized = str(label or "").strip().lower()
    if normalized.startswith("flow="):
        normalized = normalized.removeprefix("flow=").strip()
    spec = next(
        value for value in SOURCE_FILES if value["scenario_id"] == scenario_id
    )
    if normalized.startswith("from-botnet"):
        return {
            "truth": "needs_review",
            "provider_class": "from_botnet",
            "attack_family": spec["behavior_family"],
            "eligibility": "comparable",
        }
    if normalized.startswith("from-normal"):
        return {
            "truth": "non_threat",
            "provider_class": "from_normal",
            "attack_family": "normal",
            "eligibility": "comparable",
        }
    if "background" in normalized:
        reason = "ambiguous_background"
    elif normalized.startswith("to-botnet"):
        reason = "ambiguous_to_botnet"
    elif normalized.startswith("to-normal"):
        reason = "ambiguous_to_normal"
    else:
        reason = "unsupported_provider_label"
    return {
        "truth": "abstain",
        "provider_class": reason,
        "attack_family": "ambiguous",
        "eligibility": "excluded",
    }


def _read_frozen_predictions(output_dir: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    state = _safe_json(_state_path(output_dir))
    name = str(state.get("prediction_file_name") or "")
    path = output_dir / name if Path(name).name == name else None
    if (
        not state
        or not state.get("labels_revealed")
        or path is None
        or not path.exists()
        or _file_sha256(path) != state.get("predictions_sha256")
    ):
        return [], state
    predictions: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as stream:
        for line in stream:
            value = json.loads(line)
            if isinstance(value, dict):
                predictions.append(value)
    return predictions, state


def _read_selected_provider_truth(
    dataset_dir: Path,
    predictions: list[dict[str, Any]],
) -> dict[str, dict[str, str]]:
    wanted: dict[str, dict[int, str]] = defaultdict(dict)
    for row in predictions:
        wanted[str(row["scenario_id"])][
            _integer(row["provider_row_number"])
        ] = str(row["review_token"])
    revealed: dict[str, dict[str, str]] = {}
    for spec in SOURCE_FILES:
        scenario_wanted = wanted.get(spec["scenario_id"]) or {}
        if not scenario_wanted:
            continue
        path = dataset_dir / spec["logical_name"]
        with path.open("r", encoding="utf-8-sig", newline="") as stream:
            reader = csv.DictReader(stream)
            if tuple(reader.fieldnames or ()) != REQUIRED_COLUMNS:
                raise ValueError("Provider schema changed after prediction freeze.")
            for row_number, row in enumerate(reader, start=1):
                review_token = scenario_wanted.get(row_number)
                if review_token:
                    revealed[review_token] = _provider_truth(
                        row.get("Label"),
                        scenario_id=spec["scenario_id"],
                    )
    return revealed


def run_v519_label_adapter_recovery(
    db: Session,
    *,
    dataset_path: Path,
    output_dir: Path = OUTPUT_DIR,
    write_output: bool = True,
) -> dict[str, Any]:
    """Recover a provider serialization mismatch without changing predictions.

    This is deliberately not called a fresh blind result. It may diagnose the
    frozen predictions after the label wrapper is normalized, but it cannot
    authorize activation or replace the first one-shot protocol record.
    """

    output_dir = Path(output_dir)
    dataset_dir = Path(dataset_path)
    state = _safe_json(_state_path(output_dir))
    if state.get("adapter_recovery_completed"):
        return {
            "ok": False,
            "status": "failed_closed_adapter_recovery_already_completed",
            "lifecycle_state": "shadow_observation",
            "fresh_blind_claim": False,
        }
    counts_before = frozen._database_counts(db)
    artifacts_before = v55._model_artifact_states()
    predictions, state = _read_frozen_predictions(output_dir)
    if not predictions:
        return {
            "ok": False,
            "status": "failed_closed_frozen_predictions_unavailable",
            "lifecycle_state": "shadow_observation",
        }
    try:
        labels = _read_selected_provider_truth(dataset_dir, predictions)
    except (OSError, ValueError, csv.Error) as exc:
        return {
            "ok": False,
            "status": "failed_closed_adapter_recovery_read_error",
            "error_type": type(exc).__name__,
            "lifecycle_state": "shadow_observation",
        }
    if len(labels) != len(predictions):
        return {
            "ok": False,
            "status": "failed_closed_adapter_recovery_incomplete",
            "expected_rows": len(predictions),
            "recovered_rows": len(labels),
            "lifecycle_state": "shadow_observation",
        }
    diagnostic = evaluate_blind_predictions(predictions, labels)
    diagnostic["status"] = "post_blind_label_adapter_recovery_diagnostic"
    diagnostic["fresh_blind_claim"] = False
    diagnostic["adapter_repair"] = {
        "problem": "provider_flow_equals_serialization_wrapper",
        "semantic_mapping_changed": False,
        "model_changed": False,
        "threshold_changed": False,
        "calibration_changed": False,
        "prediction_rows_changed": False,
        "labels_used_for_tuning": False,
    }
    counts_after = frozen._database_counts(db)
    artifacts_after = v55._model_artifact_states()
    safety = {
        "configured_database_unchanged": counts_before == counts_after,
        "model_artifacts_unchanged": artifacts_before == artifacts_after,
        "labels_created": counts_after["ml_labels"] - counts_before["ml_labels"],
        "model_runs_created": counts_after["ml_model_runs"]
        - counts_before["ml_model_runs"],
        "detection_runs_created": counts_after["detection_runs"]
        - counts_before["detection_runs"],
        "alerts_created": counts_after["alerts"] - counts_before["alerts"],
        "response_actions_created": counts_after["response_actions"]
        - counts_before["response_actions"],
        "active_model_artifact_written": False,
        "model_activated": False,
        "model_promoted": False,
        "automatic_response_enabled": False,
        "real_firewall_blocking_enabled": False,
    }
    initial = _safe_json(output_dir / V519_LATEST)
    result = {
        "ok": all(
            (
                safety["configured_database_unchanged"],
                safety["model_artifacts_unchanged"],
                safety["labels_created"] == 0,
                safety["model_runs_created"] == 0,
                safety["detection_runs_created"] == 0,
                safety["alerts_created"] == 0,
                safety["response_actions_created"] == 0,
            )
        ),
        "status": "label_adapter_recovery_diagnostic_complete",
        "version": V519_VERSION,
        "initial_one_shot_result": {
            "status": (initial.get("blind_validation") or {}).get("status"),
            "comparable_rows": (initial.get("blind_validation") or {}).get(
                "comparable_rows"
            ),
            "adapter_contract_failed": True,
            "preserved": True,
        },
        "post_blind_diagnostic": diagnostic,
        "readiness": {
            "decision": "shadow_observation",
            "lifecycle_state": "shadow_observation",
            "eligible_for_activation": False,
            "production_promoted": False,
            "response_automation_allowed": False,
            "rules_alert_authoritative": True,
            "fresh_blind_gate_passed": False,
            "binary_transfer_diagnostic_gate_passed": bool(
                (diagnostic.get("binary_transfer_gate") or {}).get("passed")
            ),
            "blockers": [
                "the first blind label adapter contract failed",
                "adapter-recovery metrics are diagnostic rather than fresh blind evidence",
                "native PAN-OS independent labeled evidence is unavailable",
                "schema transfer remains out-of-distribution",
            ],
        },
        "safety": safety,
        "predictions_frozen_before_label_access": True,
        "labels_used_for_tuning": False,
        "private_paths_returned": False,
        "raw_rows_returned": False,
        "ip_addresses_returned": False,
        "fingerprints_returned": False,
        "secrets_exposed": False,
    }
    state.update(
        {
            "adapter_recovery_completed": True,
            "adapter_recovery_completed_at": _utc_now(),
            "adapter_recovery_result_fingerprint": _stable_hash(diagnostic),
            "fresh_blind_claim": False,
            "labels_used_for_tuning": False,
        }
    )
    _write_json(_state_path(output_dir), state)
    if write_output:
        _write_json(output_dir / V519_LATEST, result)
        report_path = output_dir / f"{V519_REPORT_PREFIX}_adapter_recovery_{_stamp()}.md"
        report_path.write_text(
            _render_markdown(
                {
                    "status": result["status"],
                    "dataset": {
                        "dataset_id": DATASET["dataset_id"],
                        "ground_truth": DATASET["ground_truth"],
                    },
                    "blind_validation": diagnostic,
                    "readiness": result["readiness"],
                }
            ),
            encoding="utf-8",
        )
    return result


def reveal_provider_labels_once(
    dataset_dir: Path,
    *,
    output_dir: Path,
    prediction_freeze: dict[str, Any],
) -> dict[str, Any]:
    state_path = _state_path(output_dir)
    state = _safe_json(state_path)
    prediction_path = output_dir / str(state.get("prediction_file_name") or "")
    if not state or state.get("labels_revealed"):
        return {
            "ok": False,
            "status": "failed_closed_blind_labels_already_revealed",
        }
    if (
        not prediction_path.exists()
        or _file_sha256(prediction_path) != state.get("predictions_sha256")
    ):
        return {
            "ok": False,
            "status": "failed_closed_prediction_freeze_integrity_mismatch",
        }
    predictions = prediction_freeze["rows"]
    wanted: dict[str, dict[int, str]] = defaultdict(dict)
    for row in predictions:
        wanted[str(row["scenario_id"])][
            _integer(row["provider_row_number"])
        ] = str(row["review_token"])
    revealed: dict[str, dict[str, str]] = {}
    reveal_started = _utc_now()
    for spec in SOURCE_FILES:
        scenario_wanted = wanted.get(spec["scenario_id"]) or {}
        if not scenario_wanted:
            continue
        path = dataset_dir / spec["logical_name"]
        with path.open("r", encoding="utf-8-sig", newline="") as stream:
            reader = csv.DictReader(stream)
            if tuple(reader.fieldnames or ()) != REQUIRED_COLUMNS:
                return {
                    "ok": False,
                    "status": "failed_closed_provider_schema_changed",
                }
            for row_number, row in enumerate(reader, start=1):
                review_token = scenario_wanted.get(row_number)
                if not review_token:
                    continue
                revealed[review_token] = _provider_truth(
                    row.get("Label"),
                    scenario_id=spec["scenario_id"],
                )
    if len(revealed) != len(predictions):
        return {
            "ok": False,
            "status": "failed_closed_incomplete_provider_label_reveal",
            "expected_rows": len(predictions),
            "revealed_rows": len(revealed),
        }
    label_name = f"v5_19_revealed_labels_{_stamp()}.jsonl"
    label_path = output_dir / label_name
    with label_path.open("w", encoding="utf-8", newline="\n") as stream:
        for token in sorted(revealed):
            stream.write(
                json.dumps(
                    {"review_token": token, **revealed[token]},
                    sort_keys=True,
                )
                + "\n"
            )
    state.update(
        {
            "labels_revealed": True,
            "labels_revealed_at": _utc_now(),
            "label_file_name": label_name,
            "labels_sha256": _file_sha256(label_path),
            "prediction_frozen_before_label_read": (
                reveal_started > str(state.get("created_at") or "")
            ),
            "labels_used_for_tuning": False,
        }
    )
    _write_json(state_path, state)
    return {
        "ok": True,
        "status": "provider_labels_revealed_once",
        "labels": revealed,
        "prediction_frozen_before_label_read": True,
        "labels_used_for_tuning": False,
        "provider_labels_called_human_reviewed": False,
    }


def _metrics(y_true: list[str], predicted: list[str]) -> dict[str, Any]:
    result = frozen._binary_metrics(y_true, predicted)
    result["threat_positive_precision"] = result.get("queue_precision")
    result["threat_positive_recall"] = result.get("queue_recall")
    result["threat_positive_f1"] = result.get("queue_f1")
    result["suspicious_recall"] = None
    result["malicious_recall"] = None
    result["taxonomy_note"] = (
        "Provider ground truth supports binary from-botnet/from-normal "
        "evaluation only. ATDR suspicious and malicious labels were not inferred."
    )
    return result


def _group_metrics(
    predictions: list[dict[str, Any]],
    labels: dict[str, dict[str, str]],
    *,
    group_key: str,
) -> dict[str, Any]:
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in predictions:
        truth = labels[row["review_token"]]
        if truth["eligibility"] != "comparable":
            continue
        groups[str(row[group_key])].append(row)
    output: dict[str, Any] = {}
    for name, rows in sorted(groups.items()):
        y_true = [labels[row["review_token"]]["truth"] for row in rows]
        predicted = [str(row["prediction"]) for row in rows]
        output[name] = {
            "rows": len(rows),
            **_metrics(y_true, predicted),
        }
    return output


def _error_patterns(
    predictions: list[dict[str, Any]],
    labels: dict[str, dict[str, str]],
) -> dict[str, Any]:
    false_positives: Counter[tuple[str, str, str, str]] = Counter()
    false_negatives: Counter[tuple[str, str, str, str]] = Counter()
    for row in predictions:
        truth = labels[row["review_token"]]
        if truth["eligibility"] != "comparable":
            continue
        key = (
            str(row["scenario_id"]),
            str(row.get("protocol") or "unknown"),
            str(row.get("dst_port") or "missing"),
            f"bytes_bucket_{row.get('bytes_bucket')}",
        )
        if truth["truth"] == "non_threat" and row["prediction"] == "needs_review":
            false_positives[key] += 1
        if truth["truth"] == "needs_review" and row["prediction"] == "non_threat":
            false_negatives[key] += 1

    def render(values: Counter[tuple[str, str, str, str]]) -> list[dict[str, Any]]:
        return [
            {
                "scenario_id": key[0],
                "protocol": key[1],
                "destination_port": key[2],
                "bytes_bucket": key[3],
                "rows": count,
            }
            for key, count in values.most_common(10)
        ]

    return {
        "top_false_positive_patterns": render(false_positives),
        "top_false_negative_patterns": render(false_negatives),
        "raw_rows_included": False,
        "ip_addresses_included": False,
    }


def evaluate_blind_predictions(
    predictions: list[dict[str, Any]],
    labels: dict[str, dict[str, str]],
) -> dict[str, Any]:
    comparable = [
        row
        for row in predictions
        if labels[row["review_token"]]["eligibility"] == "comparable"
    ]
    y_true = [labels[row["review_token"]]["truth"] for row in comparable]
    predicted = [str(row["prediction"]) for row in comparable]
    scores = [_number(row.get("threat_score")) for row in comparable]
    rule_predicted = [str(row["rule_prediction"]) for row in comparable]
    metrics = _metrics(y_true, predicted)
    calibration = frozen._calibration_report(y_true, scores)
    scenario_metrics = _group_metrics(
        predictions,
        labels,
        group_key="scenario_id",
    )
    source_group_metrics = _group_metrics(
        predictions,
        labels,
        group_key="source_group",
    )
    class_support = Counter(y_true)
    ambiguous = Counter(
        labels[row["review_token"]]["provider_class"]
        for row in predictions
        if labels[row["review_token"]]["eligibility"] != "comparable"
    )
    binary_checks = {
        "minimum_comparable_rows": len(comparable)
        >= GATES["minimum_comparable_rows"],
        "minimum_scenarios": len(scenario_metrics) >= GATES["minimum_scenarios"],
        "minimum_benign_rows": class_support["non_threat"]
        >= GATES["minimum_rows_per_class"],
        "minimum_threat_rows": class_support["needs_review"]
        >= GATES["minimum_rows_per_class"],
        "queue_f1": _number(metrics.get("queue_f1"))
        >= GATES["queue_f1_min"],
        "threat_recall": _number(metrics.get("queue_recall"))
        >= GATES["threat_recall_min"],
        "benign_like_false_positive_rate": _number(
            metrics.get("benign_like_false_positive_rate"), 1.0
        )
        <= GATES["benign_like_false_positive_rate_max"],
        "expected_calibration_error": _number(
            calibration.get("expected_calibration_error"), 1.0
        )
        <= GATES["expected_calibration_error_max"],
        "max_confidence_accuracy_gap": _number(
            calibration.get("max_confidence_accuracy_gap"), 1.0
        )
        <= GATES["max_confidence_accuracy_gap_max"],
    }
    return {
        "status": "evaluated_blind_once",
        "attempted_rows": len(predictions),
        "comparable_rows": len(comparable),
        "excluded_ambiguous_rows": len(predictions) - len(comparable),
        "class_support": dict(sorted(class_support.items())),
        "excluded_reasons": dict(sorted(ambiguous.items())),
        "metrics": metrics,
        "calibration": calibration,
        "review_queue_rate": round(
            sum(value == "needs_review" for value in predicted)
            / max(1, len(predicted)),
            6,
        ),
        "abstention_rate": round(
            (len(predictions) - len(comparable)) / max(1, len(predictions)),
            6,
        ),
        "scenario_stability": scenario_metrics,
        "source_group_count": len(source_group_metrics),
        "source_group_metrics_exposed": False,
        "attack_family_support": dict(
            sorted(
                Counter(
                    labels[row["review_token"]]["attack_family"]
                    for row in comparable
                    if labels[row["review_token"]]["truth"] == "needs_review"
                ).items()
            )
        ),
        "partial_deterministic_rule_baseline": {
            "status": "partial_schema_only",
            "applicable_rules": ["high_bytes_outlier", "high_packets_outlier"],
            "unavailable_rule_families": [
                "action",
                "application_risk",
                "palo_alto_threat_record",
                "zone_direction",
            ],
            "metrics": _metrics(y_true, rule_predicted),
            "not_claimed_as_full_atdr_rule_validation": True,
        },
        "error_patterns": _error_patterns(predictions, labels),
        "schema_transfer": {
            "status": "ood_warning",
            "schema_family": DATASET["schema_family"],
            "native_panos": False,
            "direct_feature_count": len(DIRECT_FEATURES),
            "derived_feature_count": len(DERIVED_FEATURES),
            "unavailable_feature_count": len(UNAVAILABLE_FEATURES),
            "feature_contract_count": len(
                v56.V56_NUMERIC_FEATURES + v56.V56_CATEGORICAL_FEATURES
            ),
            "missing_fields_not_fabricated": True,
        },
        "binary_transfer_gate": {
            "passed": all(binary_checks.values()),
            "checks": binary_checks,
            "gates": GATES,
        },
        "labels_used_for_tuning": False,
        "suspicious_malicious_metrics_available": False,
        "raw_rows_included": False,
        "ip_addresses_included": False,
    }


def _public_candidate(candidate: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in candidate.items()
        if not key.startswith("_") and key != "checks"
    }


def _public_feature_sample(sample: dict[str, Any]) -> dict[str, Any]:
    return {
        "status": sample.get("status"),
        "sampled_rows": sample.get("sampled_rows"),
        "files": sample.get("files"),
        "duplicate_audit": sample.get("duplicate_audit"),
        "labels_accessed": False,
        "labels_used_for_sampling": False,
        "labels_used_for_features": False,
        "raw_rows_included": False,
        "ip_addresses_included": False,
    }


def _render_markdown(result: dict[str, Any]) -> str:
    validation = result.get("blind_validation") or {}
    metrics = validation.get("metrics") or {}
    readiness = result.get("readiness") or {}
    return "\n".join(
        [
            "# v5.19 Independent Labeled Detection/ML Evidence",
            "",
            f"- Status: `{result.get('status')}`",
            f"- Dataset: `{(result.get('dataset') or {}).get('dataset_id')}`",
            f"- Publisher ground truth: `{(result.get('dataset') or {}).get('ground_truth')}`",
            f"- Comparable rows: `{validation.get('comparable_rows')}`",
            f"- Excluded ambiguous rows: `{validation.get('excluded_ambiguous_rows')}`",
            f"- Threat-positive precision: `{metrics.get('threat_positive_precision')}`",
            f"- Threat-positive recall: `{metrics.get('threat_positive_recall')}`",
            f"- Threat-positive F1: `{metrics.get('threat_positive_f1')}`",
            f"- Benign-like FPR: `{metrics.get('benign_like_false_positive_rate')}`",
            f"- Calibration: `{(validation.get('calibration') or {}).get('status')}`",
            f"- Binary transfer gate: `{(validation.get('binary_transfer_gate') or {}).get('passed')}`",
            f"- Lifecycle: `{readiness.get('lifecycle_state')}`",
            "",
            "## Interpretation",
            "",
            "This is a one-shot binary schema-transfer evaluation against publisher-provided CTU-13 flow labels.",
            "It is not native PAN-OS validation and does not support invented suspicious/malicious class claims.",
            "The result cannot activate or promote the supervised candidate.",
            "Deterministic ATDR rules remain alert-authoritative and response automation remains disabled.",
            "",
        ]
    )


def run_v519_independent_labeled_validation(
    db: Session,
    *,
    dataset_path: Path,
    manifest_path: Path,
    preflight_only: bool = False,
    execute: bool = False,
    confirm: bool = False,
    rows_per_scenario: int = DEFAULT_ROWS_PER_SCENARIO,
    output_dir: Path = OUTPUT_DIR,
    write_output: bool = True,
) -> dict[str, Any]:
    started = time.perf_counter()
    if execute and not confirm:
        return {
            "ok": False,
            "status": "failed_closed_execute_requires_confirm",
            "lifecycle_state": "shadow_observation",
        }
    if preflight_only and execute:
        return {
            "ok": False,
            "status": "failed_closed_conflicting_modes",
            "lifecycle_state": "shadow_observation",
        }
    output_dir = Path(output_dir)
    dataset_dir = Path(dataset_path)
    manifest_file = Path(manifest_path)
    counts_before = frozen._database_counts(db)
    artifacts_before = v55._model_artifact_states()
    manifest_result = create_or_verify_evidence_manifest(
        dataset_dir,
        manifest_file,
    )
    candidate = audit_prior_evidence_and_load_candidate(output_dir=output_dir)
    if not manifest_result.get("ok") or not candidate.get("ok"):
        return {
            "ok": False,
            "status": (
                manifest_result.get("status")
                if not manifest_result.get("ok")
                else candidate.get("status")
            ),
            "version": V519_VERSION,
            "lifecycle_state": "shadow_observation",
            "dataset": _public_manifest(manifest_result.get("manifest") or {}),
            "frozen_candidate": _public_candidate(candidate),
        }
    manifest = manifest_result["manifest"]
    protocol_state = _safe_json(_state_path(output_dir))
    if preflight_only and protocol_state.get("labels_revealed"):
        counts_after = frozen._database_counts(db)
        artifacts_after = v55._model_artifact_states()
        public_manifest = _public_manifest(manifest)
        public_manifest["status"] = "blind_validation_locked_complete"
        return {
            "ok": counts_before == counts_after and artifacts_before == artifacts_after,
            "status": "blind_validation_locked_complete",
            "version": V519_VERSION,
            "dataset": public_manifest,
            "frozen_contract": {
                "candidate": _public_candidate(candidate),
                "taxonomy": "binary_provider_ground_truth_only",
                "labels_used_for_tuning": False,
            },
            "protocol": {
                "labels_revealed_once": True,
                "one_shot_execution_available": False,
                "adapter_recovery_completed": bool(
                    protocol_state.get("adapter_recovery_completed")
                ),
                "fresh_blind_claim": False,
            },
            "readiness": {
                "decision": "shadow_observation",
                "eligible_for_activation": False,
                "production_promoted": False,
                "response_automation_allowed": False,
                "rules_alert_authoritative": True,
            },
            "safety": {
                "configured_database_unchanged": counts_before == counts_after,
                "model_artifacts_unchanged": artifacts_before == artifacts_after,
                "model_activated": False,
                "model_promoted": False,
                "automatic_response_enabled": False,
                "real_firewall_blocking_enabled": False,
            },
            "private_paths_returned": False,
            "raw_rows_returned": False,
            "ip_addresses_returned": False,
            "fingerprints_returned": False,
            "secrets_exposed": False,
        }
    feature_sample = build_label_sealed_feature_sample(
        dataset_dir,
        manifest,
        rows_per_scenario=rows_per_scenario,
    )
    if not feature_sample.get("ok"):
        return {
            "ok": False,
            "status": feature_sample.get("status"),
            "version": V519_VERSION,
            "lifecycle_state": "shadow_observation",
        }
    blind_validation: dict[str, Any] = {
        "status": "not_run_preflight_only",
        "labels_used_for_tuning": False,
    }
    prediction_summary: dict[str, Any] = {
        "status": "not_run_preflight_only",
        "labels_revealed": False,
    }
    if execute:
        imports = _optional_imports()
        if imports is None:
            return {
                "ok": False,
                "status": "dependencies_unavailable",
                "lifecycle_state": "shadow_observation",
            }
        prediction_freeze = freeze_predictions(
            imports,
            output_dir=output_dir,
            manifest_path=manifest_file,
            manifest=manifest,
            candidate=candidate,
            feature_sample=feature_sample,
        )
        if not prediction_freeze.get("ok"):
            return {
                "ok": False,
                "status": prediction_freeze.get("status"),
                "version": V519_VERSION,
                "lifecycle_state": "shadow_observation",
                "prediction_freeze": {
                    key: value
                    for key, value in prediction_freeze.items()
                    if key != "rows"
                },
            }
        reveal = reveal_provider_labels_once(
            dataset_dir,
            output_dir=output_dir,
            prediction_freeze=prediction_freeze,
        )
        if not reveal.get("ok"):
            return {
                "ok": False,
                "status": reveal.get("status"),
                "version": V519_VERSION,
                "lifecycle_state": "shadow_observation",
            }
        blind_validation = evaluate_blind_predictions(
            prediction_freeze["rows"],
            reveal["labels"],
        )
        state = _safe_json(_state_path(output_dir))
        state.update(
            {
                "evaluation_completed": True,
                "evaluation_completed_at": _utc_now(),
                "result_fingerprint": _stable_hash(blind_validation),
                "labels_used_for_tuning": False,
                "post_reveal_candidate_changes": False,
            }
        )
        _write_json(_state_path(output_dir), state)
        prediction_summary = {
            "status": prediction_freeze.get("status"),
            "rows": len(prediction_freeze["rows"]),
            "predictions_frozen_before_labels": True,
            "labels_revealed_once": True,
            "labels_used_for_tuning": False,
            "fingerprints_recorded_privately": True,
            "fingerprints_exposed": False,
        }
    counts_after = frozen._database_counts(db)
    artifacts_after = v55._model_artifact_states()
    safety = {
        "configured_database_unchanged": counts_before == counts_after,
        "model_artifacts_unchanged": artifacts_before == artifacts_after,
        "labels_created": counts_after["ml_labels"] - counts_before["ml_labels"],
        "model_runs_created": counts_after["ml_model_runs"]
        - counts_before["ml_model_runs"],
        "detection_runs_created": counts_after["detection_runs"]
        - counts_before["detection_runs"],
        "alerts_created": counts_after["alerts"] - counts_before["alerts"],
        "response_actions_created": counts_after["response_actions"]
        - counts_before["response_actions"],
        "active_model_artifact_written": False,
        "model_activated": False,
        "model_promoted": False,
        "rules_alert_authoritative": True,
        "automatic_response_enabled": False,
        "real_firewall_blocking_enabled": False,
    }
    binary_gate = (blind_validation.get("binary_transfer_gate") or {}).get(
        "passed"
    )
    blockers = [
        "native PAN-OS independent labeled evidence is still unavailable",
        "a second real source device is still unavailable",
        "provider taxonomy supports binary transfer metrics only",
        "schema transfer remains out-of-distribution",
    ]
    if execute and not binary_gate:
        blockers.insert(0, "fixed binary transfer gates did not all pass")
    readiness = {
        "decision": "shadow_observation",
        "lifecycle_state": "shadow_observation",
        "binary_transfer_gate_passed": bool(binary_gate),
        "eligible_for_activation": False,
        "model_activated": False,
        "production_promoted": False,
        "response_automation_allowed": False,
        "rules_alert_authoritative": True,
        "blockers": blockers,
    }
    status = (
        "blind_validation_complete"
        if execute
        else "preflight_ready_for_one_shot_execution"
    )
    result = {
        "ok": all(
            (
                manifest_result.get("ok"),
                candidate.get("ok"),
                feature_sample.get("ok"),
                safety["configured_database_unchanged"],
                safety["model_artifacts_unchanged"],
                safety["labels_created"] == 0,
                safety["model_runs_created"] == 0,
                safety["response_actions_created"] == 0,
            )
        ),
        "status": status,
        "version": V519_VERSION,
        "generated_at": _utc_now(),
        "dataset": _public_manifest(manifest),
        "frozen_contract": {
            "candidate": _public_candidate(candidate),
            "taxonomy": "binary_provider_ground_truth_only",
            "threshold_frozen": True,
            "calibration_frozen": True,
            "post_prediction_guard_used": False,
            "labels_used_for_sampling": False,
            "labels_used_for_prediction": False,
            "labels_used_for_tuning": False,
            "contract_fingerprint_recorded_privately": True,
            "fingerprint_exposed": False,
        },
        "feature_sample": _public_feature_sample(feature_sample),
        "prediction_freeze": prediction_summary,
        "blind_validation": blind_validation,
        "readiness": readiness,
        "safety": safety,
        "elapsed_seconds": round(time.perf_counter() - started, 4),
        "private_paths_returned": False,
        "raw_rows_returned": False,
        "ip_addresses_returned": False,
        "fingerprints_returned": False,
        "secrets_exposed": False,
    }
    if write_output:
        output_dir.mkdir(parents=True, exist_ok=True)
        _write_json(output_dir / V519_LATEST, result)
        report_path = output_dir / f"{V519_REPORT_PREFIX}_{_stamp()}.md"
        report_path.write_text(_render_markdown(result), encoding="utf-8")
    return result
