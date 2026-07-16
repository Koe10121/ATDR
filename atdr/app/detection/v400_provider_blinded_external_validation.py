from __future__ import annotations

import csv
import hashlib
import heapq
import json
import math
import random
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Iterable

from sqlalchemy.orm import Session

from atdr.app.core.config import PROJECT_ROOT
from atdr.app.detection import v398_independent_holdout_validation as v398
from atdr.app.detection import v399_multisource_frozen_revalidation as v399


V400_VERSION = "v4.0"
V400_LATEST = "v4_0_external_validation_latest.json"
V400_OUTPUT_DIR = PROJECT_ROOT / "ml_baseline_reviews"
V400_EVIDENCE_DIR = PROJECT_ROOT / ".tmp" / "external_evidence" / "cse_cic_ids2018"
DEFAULT_ROWS_PER_FILE = 2_000
DEFAULT_SAMPLE_SEED = 400
MAPPING_VERSION = "cse_cic_ids2018_to_atdr_flow_v1"
MANIFEST_SCHEMA = "atdr_v400_external_evidence_manifest_v1"

DATASET = {
    "dataset_id": "cse-cic-ids2018",
    "title": "CSE-CIC-IDS2018 on AWS",
    "publisher": "Canadian Institute for Cybersecurity, University of New Brunswick",
    "version": "2018 processed traffic data for ML algorithms",
    "official_page": "https://www.unb.ca/cic/datasets/ids-2018.html",
    "official_aws_page": "https://registry.opendata.aws/cse-cic-ids2018/",
    "license_summary": (
        "Official dataset page permits redistribution, republication, and mirroring; "
        "use must cite the dataset and official AWS page."
    ),
    "citation": (
        "Iman Sharafaldin, Arash Habibi Lashkari, and Ali A. Ghorbani, "
        "Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization, 2018."
    ),
    "human_reviewed": False,
    "import_ready": False,
}

SOURCE_FILES: tuple[dict[str, Any], ...] = (
    {
        "file_name": "Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv",
        "provider_day": "2018-02-14",
        "public_url": (
            "https://s3.ca-central-1.amazonaws.com/cse-cic-ids2018/"
            "Processed%20Traffic%20Data%20for%20ML%20Algorithms/"
            "Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv"
        ),
        "expected_bytes": 358_223_333,
        "sha256": "acff8bc61376ee031d80878ee6099e0b1a87a1bd711d8068298421418c9f8147",
        "s3_etag": "46c0f45f8e6fe1edf1f08487448c102f-22",
        "s3_last_modified": "2018-10-11T16:09:44Z",
        "official_scenario": "FTP and SSH brute-force day",
    },
    {
        "file_name": "Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv",
        "provider_day": "2018-03-01",
        "public_url": (
            "https://s3.ca-central-1.amazonaws.com/cse-cic-ids2018/"
            "Processed%20Traffic%20Data%20for%20ML%20Algorithms/"
            "Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv"
        ),
        "expected_bytes": 107_842_858,
        "sha256": "b0534c5d7d8b41e03df71c6966c995d116a8ed28e61f377c8b14cdf5d28f4edf",
        "s3_etag": "5889e4b7e0a421070747a2441a2772d7-7",
        "s3_last_modified": "2018-10-11T16:08:38Z",
        "official_scenario": "Infiltration day",
    },
)

PROVIDER_LABEL_MAPPING = {
    "benign": {"atdr_label": "benign", "queue_target": "non_threat", "attack_type": "normal"},
    "ftp-bruteforce": {
        "atdr_label": "suspicious",
        "queue_target": "needs_review",
        "attack_type": "brute_force",
    },
    "ssh-bruteforce": {
        "atdr_label": "suspicious",
        "queue_target": "needs_review",
        "attack_type": "brute_force",
    },
    "infilteration": {
        "atdr_label": "malicious",
        "queue_target": "needs_review",
        "attack_type": "infiltration",
    },
    "infiltration": {
        "atdr_label": "malicious",
        "queue_target": "needs_review",
        "attack_type": "infiltration",
    },
}

DIRECT_FIELD_MAPPING = {
    "Timestamp": "generated_time",
    "Dst Port": "dst_port",
    "Protocol": "protocol",
    "TotLen Fwd Pkts": "bytes_sent",
    "TotLen Bwd Pkts": "bytes_received",
    "Tot Fwd Pkts + Tot Bwd Pkts": "packets",
    "Flow Duration / 1_000_000": "elapsed_time_seconds",
}

UNAVAILABLE_ATDR_FIELDS = (
    "src_ip",
    "dst_ip",
    "src_port",
    "action",
    "app",
    "src_zone",
    "dst_zone",
    "app_risk",
    "app_category",
    "app_characteristic",
)

RULE_APPLICABILITY = {
    "high_bytes_outlier": "applicable_with_frozen_internal_byte_threshold",
    "high_packets_outlier": "applicable_with_frozen_internal_packet_threshold",
    "deny_drop_action": "unavailable_missing_action",
    "paloalto_threat_log": "unavailable_missing_palo_alto_log_type",
    "app_risk_4": "unavailable_missing_app_risk",
    "app_risk_5": "unavailable_missing_app_risk",
    "suspicious_app_characteristic": "unavailable_missing_app_characteristic",
    "outside_to_inside": "unavailable_missing_zones",
    "repeated_source_ip": "unavailable_missing_source_ip",
    "multiple_denied_connections": "unavailable_missing_source_ip_and_action",
    "brute_force_like_attempts": "unavailable_missing_source_ip_and_action",
    "possible_port_scan": "unavailable_missing_source_ip",
    "beaconing_like_outbound": "unavailable_missing_source_and_destination_ip",
    "connection_flood_suspicion": "unavailable_missing_source_and_destination_ip",
    "unusual_destination_port": "unavailable_missing_zones",
    "high_outbound_bytes": "unavailable_missing_zones",
    "unknown_or_incomplete_app": "unavailable_missing_app_not_equivalent_to_unknown_app",
    "ml_anomaly_detected": "excluded_from_deterministic_rule_baseline",
}

ENRICHMENT_NUMERIC = (
    "v337_web_like_allow_flag",
    "v337_utility_like_allow_flag",
    "v337_low_signal_allow_flag",
    "v337_web_low_signal_flag",
    "v337_web_scan_context_flag",
    "v337_utility_low_signal_flag",
    "v337_incomplete_scan_context_flag",
    "v337_unknown_scan_context_flag",
    "v337_rule_backed_allow_flag",
    "v337_anomaly_signal_flag",
    "v337_repeated_service_flag",
    "v337_source_diversity_pressure",
    "v337_behavior_evidence_strength",
    "v337_benign_web_likelihood_score",
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _stable_hash(payload: Any) -> str:
    encoded = json.dumps(payload, sort_keys=True, default=str, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")


def _write_self_hashed_manifest(path: Path, payload: dict[str, Any]) -> str:
    manifest = dict(payload)
    manifest["manifest_hash_algorithm"] = "sha256_canonical_json_without_manifest_hash"
    manifest["manifest_hash"] = _stable_hash(manifest)
    _write_json(path, manifest)
    return str(manifest["manifest_hash"])


def _normal_header(value: str) -> str:
    return value.lstrip("\ufeff").strip()


def _safe_float(value: Any) -> float | None:
    try:
        numeric = float(str(value).strip())
    except (TypeError, ValueError):
        return None
    return numeric if math.isfinite(numeric) else None


def _safe_int(value: Any) -> int | None:
    numeric = _safe_float(value)
    return None if numeric is None else int(numeric)


def _parse_timestamp(value: str) -> datetime | None:
    text = value.strip()
    for pattern in ("%d/%m/%Y %H:%M:%S", "%d/%m/%Y %H:%M", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(text, pattern).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _protocol_name(value: Any) -> str:
    code = _safe_int(value)
    if code == 6:
        return "tcp"
    if code == 17:
        return "udp"
    return f"ip_protocol_{code}" if code is not None else "unavailable"


def _source_file(path: Path) -> dict[str, Any] | None:
    return next((dict(item) for item in SOURCE_FILES if item["file_name"] == path.name), None)


def verify_provider_files(evidence_dir: Path) -> dict[str, Any]:
    files: list[dict[str, Any]] = []
    for spec in SOURCE_FILES:
        path = evidence_dir / str(spec["file_name"])
        if not path.exists():
            return {
                "ok": False,
                "status": "acquisition_required",
                "message": f"Missing official provider file: {path.name}",
            }
        size = path.stat().st_size
        sha256 = _file_sha256(path)
        if size != int(spec["expected_bytes"]) or sha256 != spec["sha256"]:
            return {
                "ok": False,
                "status": "failed_closed",
                "message": f"Provider file identity mismatch: {path.name}",
                "file_name": path.name,
                "expected_bytes": spec["expected_bytes"],
                "actual_bytes": size,
                "expected_sha256": spec["sha256"],
                "actual_sha256": sha256,
            }
        files.append(
            {
                key: value
                for key, value in spec.items()
                if key not in {"public_url"}
            }
            | {
                "public_url": spec["public_url"],
                "verified_bytes": size,
                "verified_sha256": sha256,
                "download_verified_at": _utc_now(),
            }
        )
    return {"ok": True, "status": "verified", "files": files}


def _sample_rank(*, seed: int, file_sha256: str, row_number: int) -> int:
    token = f"{seed}|{file_sha256}|{row_number}".encode()
    return int.from_bytes(hashlib.sha256(token).digest(), byteorder="big", signed=False)


def build_feature_only_sample(
    evidence_dir: Path,
    *,
    rows_per_file: int,
    seed: int,
    stamp: str,
) -> dict[str, Any]:
    """Sample provider rows without retaining or consulting the label column."""

    feature_path = evidence_dir / f"v4_0_feature_only_sample_{stamp}.csv"
    file_summaries: list[dict[str, Any]] = []
    selected_rows: list[dict[str, Any]] = []
    feature_header: list[str] | None = None

    for spec in SOURCE_FILES:
        path = evidence_dir / str(spec["file_name"])
        heap: list[tuple[int, int, int, list[str]]] = []
        original_rows = 0
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            reader = csv.reader(handle)
            raw_header = next(reader)
            header = [_normal_header(value) for value in raw_header]
            if "Label" not in header:
                raise ValueError(f"Provider label column is missing from {path.name}.")
            label_index = header.index("Label")
            provider_features = [value for index, value in enumerate(header) if index != label_index]
            if feature_header is None:
                feature_header = provider_features
            elif feature_header != provider_features:
                raise ValueError("Provider files do not share one feature schema.")

            for row_number, row in enumerate(reader, start=1):
                original_rows += 1
                if len(row) != len(header):
                    continue
                rank = _sample_rank(seed=seed, file_sha256=str(spec["sha256"]), row_number=row_number)
                feature_values = [value for index, value in enumerate(row) if index != label_index]
                candidate = (-rank, -row_number, row_number, feature_values)
                if len(heap) < rows_per_file:
                    heapq.heappush(heap, candidate)
                elif candidate > heap[0]:
                    heapq.heapreplace(heap, candidate)

        selected = sorted(heap, key=lambda item: item[2])
        selected_indices = [item[2] for item in selected]
        for _negative_rank, _negative_row, row_number, values in selected:
            selected_rows.append(
                {
                    "evidence_id": f"{spec['provider_day']}:{row_number}",
                    "provider_file": spec["file_name"],
                    "provider_day": spec["provider_day"],
                    "provider_row_number": row_number,
                    "values": values,
                }
            )
        file_summaries.append(
            {
                "file_name": spec["file_name"],
                "provider_day": spec["provider_day"],
                "original_row_count": original_rows,
                "sampled_row_count": len(selected),
                "selected_row_numbers_hash": _stable_hash(selected_indices),
                "sampling_consulted_label_values": False,
            }
        )

    if feature_header is None:
        raise ValueError("No provider feature header was available.")
    with feature_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["evidence_id", "provider_file", "provider_day", "provider_row_number", *feature_header])
        for item in sorted(selected_rows, key=lambda row: str(row["evidence_id"])):
            writer.writerow(
                [
                    item["evidence_id"],
                    item["provider_file"],
                    item["provider_day"],
                    item["provider_row_number"],
                    *item["values"],
                ]
            )

    return {
        "feature_path": feature_path,
        "feature_sha256": _file_sha256(feature_path),
        "sampled_rows": len(selected_rows),
        "feature_columns": feature_header,
        "files": file_summaries,
        "sampling": {
            "seed": seed,
            "method": "minimum_sha256_rank_of_seed_file_checksum_and_provider_row_number",
            "rows_per_file": rows_per_file,
            "label_independent": True,
            "label_column_retained": False,
            "label_values_consulted": False,
        },
    }


def _canonical_feature_payload(provider: dict[str, str]) -> dict[str, Any]:
    return {key: provider.get(key) for key in sorted(provider)}


def _magnitude_bucket(value: Any) -> int:
    numeric = abs(_safe_float(value) or 0.0)
    return 0 if numeric < 1 else int(math.log10(numeric)) + 1


def _feature_record(row: dict[str, str]) -> dict[str, Any]:
    sent = _safe_int(row.get("TotLen Fwd Pkts"))
    received = _safe_int(row.get("TotLen Bwd Pkts"))
    forward_packets = _safe_int(row.get("Tot Fwd Pkts"))
    backward_packets = _safe_int(row.get("Tot Bwd Pkts"))
    duration_microseconds = _safe_float(row.get("Flow Duration"))
    timestamp = _parse_timestamp(str(row.get("Timestamp") or ""))
    return {
        "evidence_id": row["evidence_id"],
        "provider_file": row["provider_file"],
        "provider_day": row["provider_day"],
        "provider_row_number": int(row["provider_row_number"]),
        "timestamp": timestamp,
        "src_ip": None,
        "dst_ip": None,
        "src_port": None,
        "dst_port": _safe_int(row.get("Dst Port")),
        "protocol": _protocol_name(row.get("Protocol")),
        "action": None,
        "app": None,
        "bytes_sent": sent,
        "bytes_received": received,
        "bytes": (sent + received) if sent is not None and received is not None else None,
        "packets": (
            forward_packets + backward_packets
            if forward_packets is not None and backward_packets is not None
            else None
        ),
        "elapsed_time": duration_microseconds / 1_000_000 if duration_microseconds is not None else None,
        "src_zone": None,
        "dst_zone": None,
        "app_risk": None,
        "provider_feature_payload": _canonical_feature_payload(
            {
                key: value
                for key, value in row.items()
                if key not in {"evidence_id", "provider_file", "provider_day", "provider_row_number"}
            }
        ),
    }


def _log_namespace(record: dict[str, Any]) -> SimpleNamespace:
    return SimpleNamespace(
        id=None,
        raw_log=None,
        generated_time=record["timestamp"],
        receive_time=record["timestamp"],
        start_time=record["timestamp"],
        log_type="FLOW",
        subtype="provider_flow",
        src_ip=None,
        dst_ip=None,
        src_port=None,
        dst_port=record["dst_port"],
        protocol=record["protocol"],
        action=None,
        app=None,
        bytes=record["bytes"],
        bytes_sent=record["bytes_sent"],
        bytes_received=record["bytes_received"],
        packets=record["packets"],
        elapsed_time=record["elapsed_time"],
        src_zone=None,
        dst_zone=None,
        app_risk=None,
        app_category=None,
        app_characteristic=None,
        session_end_reason=None,
        action_source=None,
        is_anomaly=False,
    )


def build_external_feature_dataset(
    feature_path: Path,
    *,
    internal_dataset: dict[str, Any],
    frozen_rule_thresholds: dict[str, float],
) -> dict[str, Any]:
    imports = v398._optional_imports()
    if imports is None:
        return {"ok": False, "status": "skipped", "message": "Supervised ML dependencies are unavailable."}
    pd = imports[1]
    records: list[dict[str, Any]] = []
    provider_rows: list[dict[str, str]] = []
    with feature_path.open("r", encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            provider_rows.append(dict(row))
            records.append(_feature_record(dict(row)))

    numeric_features = list(internal_dataset["feature_meta"]["numeric_features"])
    categorical_features = list(internal_dataset["feature_meta"]["categorical_features"])
    frame_rows: list[dict[str, Any]] = []
    logs: list[SimpleNamespace] = []
    rule_scores: list[float] = []
    rows: list[dict[str, Any]] = []
    used_columns = [*numeric_features, *categorical_features]

    for index, record in enumerate(records):
        frame_row: dict[str, Any] = {column: math.nan for column in numeric_features}
        frame_row.update({column: "unavailable" for column in categorical_features})
        timestamp = record["timestamp"]
        frame_row.update(
            {
                "src_port": math.nan,
                "dst_port": record["dst_port"],
                "bytes": record["bytes"],
                "bytes_sent": record["bytes_sent"],
                "bytes_received": record["bytes_received"],
                "packets": record["packets"],
                "elapsed_time": record["elapsed_time"],
                "app_risk": math.nan,
                "protocol": record["protocol"],
                "action": "unavailable",
                "app": "unavailable",
                "src_zone": "unavailable",
                "dst_zone": "unavailable",
                "hour_of_day": timestamp.hour if timestamp else math.nan,
                "is_after_hours": int(timestamp.hour < 7 or timestamp.hour >= 18) if timestamp else math.nan,
                "v337_traffic_family": "external_flow_fields_limited",
            }
        )
        bytes_score = 20 if (record["bytes"] or 0) > frozen_rule_thresholds["byte_outlier_threshold"] else 0
        packets_score = 20 if (record["packets"] or 0) > frozen_rule_thresholds["packet_outlier_threshold"] else 0
        rule_score = min(100, bytes_score + packets_score) / 100.0
        frame_row["v398_local_rule_score"] = rule_score * 100.0
        for column in ENRICHMENT_NUMERIC:
            frame_row[column] = math.nan
        frame_rows.append(frame_row)
        logs.append(_log_namespace(record))
        rule_scores.append(rule_score)

    frame = pd.DataFrame(frame_rows)
    for index, record in enumerate(records):
        provider_payload = record.pop("provider_feature_payload")
        log = logs[index]
        exact_fingerprint = _stable_hash(provider_payload)
        near_fingerprint = v398._near_fingerprint(log)
        feature_fingerprint = v398._feature_fingerprint(frame, index, used_columns)
        rows.append(
            {
                "index": index,
                "evidence_id": record["evidence_id"],
                "provider_file": record["provider_file"],
                "provider_day": record["provider_day"],
                "provider_row_number": record["provider_row_number"],
                "source_name": f"cse-cic-ids2018:{record['provider_day']}",
                "source_type": "external_provider_flow_file",
                "timestamp": record["timestamp"],
                "protocol": record["protocol"],
                "dst_port": record["dst_port"],
                "app": "unavailable",
                "action": "unavailable",
                "exact_fingerprint": exact_fingerprint,
                "near_fingerprint": near_fingerprint,
                "feature_fingerprint": feature_fingerprint,
                "human_reviewed": False,
                "import_ready": False,
                "label_source": "provider_ground_truth_not_yet_revealed",
            }
        )

    return {
        "ok": True,
        "records": records,
        "provider_rows": provider_rows,
        "logs": logs,
        "frame": frame,
        "rows": rows,
        "rule_scores": rule_scores,
        "feature_meta": {
            "numeric_features": numeric_features,
            "categorical_features": categorical_features,
            "direct_field_mapping": DIRECT_FIELD_MAPPING,
            "unavailable_atdr_fields": list(UNAVAILABLE_ATDR_FIELDS),
            "missing_numeric_policy": "frozen_internal_pipeline_imputation",
            "missing_categorical_sentinel": "unavailable",
            "source_identity_policy": "provider_file_day_not_network_source_ip",
        },
    }


def _synthetic_reference_dataset(internal_dataset: dict[str, Any]) -> dict[str, Any]:
    records = v399.build_evidence_records(
        base_time=v399._base_time(internal_dataset),
        seed=399,
        rows_per_source=v399.DEFAULT_ROWS_PER_SOURCE,
    )
    return v399._external_feature_dataset(records)


def audit_external_overlap(
    internal_dataset: dict[str, Any],
    synthetic_dataset: dict[str, Any],
    external_dataset: dict[str, Any],
) -> dict[str, Any]:
    fields = ("exact_fingerprint", "near_fingerprint", "feature_fingerprint")
    references = {
        "internal_reviewed": {
            field: {str(row[field]) for row in internal_dataset["rows"]}
            for field in fields
        },
        "v399_synthetic": {
            field: {str(row[field]) for row in synthetic_dataset["rows"]}
            for field in fields
        },
    }
    accepted: list[int] = []
    quarantined: list[int] = []
    reason_by_index: dict[int, list[str]] = {}
    seen_exact: set[str] = set()
    for index, row in enumerate(external_dataset["rows"]):
        reasons: list[str] = []
        for reference_name, tokens in references.items():
            for field in fields:
                if str(row[field]) in tokens[field]:
                    reasons.append(f"{reference_name}_{field}_overlap")
        exact = str(row["exact_fingerprint"])
        if exact in seen_exact:
            reasons.append("external_duplicate_exact_fingerprint")
        seen_exact.add(exact)
        if reasons:
            quarantined.append(index)
            reason_by_index[index] = reasons
        else:
            accepted.append(index)

    accepted_rows = [external_dataset["rows"][index] for index in accepted]
    remaining = {
        reference_name: {
            field: sum(1 for row in accepted_rows if str(row[field]) in tokens[field])
            for field in fields
        }
        for reference_name, tokens in references.items()
    }
    return {
        "passed": bool(accepted) and all(
            value == 0
            for reference in remaining.values()
            for value in reference.values()
        ),
        "attempted_rows": len(external_dataset["rows"]),
        "accepted_rows": len(accepted),
        "quarantined_rows": len(quarantined),
        "accepted_indices": accepted,
        "quarantined_indices": quarantined,
        "quarantine_reason_counts": dict(
            sorted(Counter(reason for reasons in reason_by_index.values() for reason in reasons).items())
        ),
        "remaining_overlap_after_quarantine": remaining,
        "reference_row_counts": {
            "internal_reviewed": len(internal_dataset["rows"]),
            "v399_synthetic": len(synthetic_dataset["rows"]),
        },
    }


def _frozen_rule_thresholds(internal_dataset: dict[str, Any], freeze: dict[str, Any]) -> dict[str, float]:
    from atdr.app.detection.rules import build_detection_context

    fit_logs = [internal_dataset["logs"][index] for index in freeze["partition"]["fit_idx"]]
    context = build_detection_context(fit_logs)
    return {
        "byte_outlier_threshold": float(context.byte_outlier_threshold),
        "packet_outlier_threshold": float(context.packet_outlier_threshold),
        "selected_from": "internal_fit_partition_features_only",
        "external_labels_used": False,
    }


def _score_external(model: Any, frame: Any, indices: list[int]) -> list[float]:
    return v399._score_external(model, frame, indices)


def freeze_predictions(
    external_dataset: dict[str, Any],
    candidates: dict[str, Any],
    accepted_indices: list[int],
    *,
    evidence_dir: Path,
    stamp: str,
) -> dict[str, Any]:
    frame = external_dataset["frame"]
    primary_scores = _score_external(candidates["primary"]["model"], frame, accepted_indices)
    logistic_scores = _score_external(candidates["logistic"]["model"], frame, accepted_indices)
    anomaly_scores = candidates["anomaly"]["score_external"](frame, accepted_indices)
    rule_scores = [external_dataset["rule_scores"][index] for index in accepted_indices]
    hybrid_scores = [
        (0.55 * rule_score) + (0.20 * anomaly_score) + (0.20 * supervised_score)
        for rule_score, anomaly_score, supervised_score in zip(
            rule_scores,
            anomaly_scores,
            primary_scores,
            strict=True,
        )
    ]
    majority_scores = [
        1.0 if candidates["majority_class"] == "needs_review" else 0.0
        for _index in accepted_indices
    ]
    thresholds = {
        "supervised": candidates["primary"]["threshold_selection"],
        "logistic": candidates["logistic"]["threshold_selection"],
        "anomaly": candidates["anomaly"]["threshold_selection"],
        "rules": v398._fixed_threshold(v398.RULE_QUEUE_THRESHOLD, policy="existing_fixed_rule_queue_threshold"),
        "hybrid": candidates["hybrid_threshold"],
        "majority": v398._fixed_threshold(0.5, policy="internal_fit_majority_class_only"),
    }
    score_sets = {
        "supervised": primary_scores,
        "logistic": logistic_scores,
        "anomaly": anomaly_scores,
        "rules": rule_scores,
        "hybrid": hybrid_scores,
        "majority": majority_scores,
    }
    prediction_path = evidence_dir / f"v4_0_frozen_predictions_{stamp}.jsonl"
    prediction_records: list[dict[str, Any]] = []
    with prediction_path.open("w", encoding="utf-8", newline="\n") as handle:
        for position, index in enumerate(accepted_indices):
            row = external_dataset["rows"][index]
            strategies = {}
            for name, scores in score_sets.items():
                threshold = float(thresholds[name].get("selected_threshold", 0.5))
                score = float(scores[position])
                strategies[name] = {
                    "score": round(score, 12),
                    "prediction": "needs_review" if score >= threshold else "non_threat",
                    "threshold": threshold,
                }
            record = {
                "evidence_id": row["evidence_id"],
                "provider_file": row["provider_file"],
                "provider_row_number": row["provider_row_number"],
                "strategies": strategies,
            }
            prediction_records.append(record)
            handle.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")

    frozen_at = _utc_now()
    return {
        "prediction_path": prediction_path,
        "prediction_sha256": _file_sha256(prediction_path),
        "prediction_row_count": len(prediction_records),
        "prediction_frozen_at": frozen_at,
        "predictions": prediction_records,
        "score_sets": score_sets,
        "thresholds": thresholds,
        "external_labels_loaded_before_prediction_freeze": False,
        "external_rows_used_for_fit": 0,
        "external_rows_used_for_calibration": 0,
        "external_rows_used_for_threshold_selection": 0,
    }


def reveal_labels_after_prediction_freeze(
    evidence_dir: Path,
    *,
    selected_rows: dict[str, set[int]],
    prediction_freeze: dict[str, Any],
    stamp: str,
) -> dict[str, Any]:
    prediction_path = Path(prediction_freeze["prediction_path"])
    if not prediction_path.exists():
        raise RuntimeError("Prediction artifact must exist before provider labels are revealed.")
    if _file_sha256(prediction_path) != prediction_freeze["prediction_sha256"]:
        raise RuntimeError("Prediction artifact hash changed before provider labels were revealed.")
    label_read_started_at = _utc_now()
    labels: dict[str, dict[str, Any]] = {}
    label_path = evidence_dir / f"v4_0_revealed_provider_labels_{stamp}.csv"
    with label_path.open("w", encoding="utf-8", newline="") as output:
        writer = csv.DictWriter(
            output,
            fieldnames=[
                "evidence_id",
                "provider_file",
                "provider_row_number",
                "provider_label",
                "atdr_label",
                "queue_target",
                "attack_type",
                "label_provenance",
                "human_reviewed",
                "import_ready",
            ],
        )
        writer.writeheader()
        for spec in SOURCE_FILES:
            selected = selected_rows.get(str(spec["file_name"]), set())
            if not selected:
                continue
            path = evidence_dir / str(spec["file_name"])
            with path.open("r", encoding="utf-8-sig", newline="") as handle:
                reader = csv.DictReader(handle)
                if reader.fieldnames is None:
                    raise ValueError(f"Provider header unavailable: {path.name}")
                field_map = {_normal_header(name): name for name in reader.fieldnames}
                label_field = field_map.get("Label")
                if label_field is None:
                    raise ValueError(f"Provider label column unavailable: {path.name}")
                for row_number, row in enumerate(reader, start=1):
                    if row_number not in selected:
                        continue
                    provider_label = str(row[label_field]).strip()
                    mapping = PROVIDER_LABEL_MAPPING.get(provider_label.lower())
                    mapped = mapping or {
                        "atdr_label": "unsupported_provider_label",
                        "queue_target": "unsupported",
                        "attack_type": "unsupported",
                    }
                    evidence_id = f"{spec['provider_day']}:{row_number}"
                    item = {
                        "evidence_id": evidence_id,
                        "provider_file": spec["file_name"],
                        "provider_row_number": row_number,
                        "provider_label": provider_label,
                        **mapped,
                        "label_provenance": "provider_ground_truth_cse_cic_ids2018",
                        "human_reviewed": False,
                        "import_ready": False,
                    }
                    labels[evidence_id] = item
                    writer.writerow(item)

    label_read_completed_at = _utc_now()
    return {
        "label_path": label_path,
        "label_sha256": _file_sha256(label_path),
        "labels": labels,
        "label_row_count": len(labels),
        "label_read_started_at": label_read_started_at,
        "label_read_completed_at": label_read_completed_at,
        "prediction_frozen_before_label_read": label_read_started_at > prediction_freeze["prediction_frozen_at"],
        "class_distribution": dict(sorted(Counter(item["atdr_label"] for item in labels.values()).items())),
        "provider_label_distribution": dict(
            sorted(Counter(item["provider_label"] for item in labels.values()).items())
        ),
        "unsupported_provider_label_count": sum(
            1 for item in labels.values() if item["queue_target"] == "unsupported"
        ),
    }


def _selected_rows_by_file(external_dataset: dict[str, Any], indices: Iterable[int]) -> dict[str, set[int]]:
    result: dict[str, set[int]] = defaultdict(set)
    for index in indices:
        row = external_dataset["rows"][index]
        result[str(row["provider_file"])].add(int(row["provider_row_number"]))
    return dict(result)


def attach_revealed_labels(
    external_dataset: dict[str, Any],
    label_reveal: dict[str, Any],
    accepted_indices: list[int],
) -> dict[str, Any]:
    labels = label_reveal["labels"]
    scored_indices: list[int] = []
    unsupported_indices: list[int] = []
    targets = ["unsupported" for _row in external_dataset["rows"]]
    original_labels = ["unsupported" for _row in external_dataset["rows"]]
    for index in accepted_indices:
        row = external_dataset["rows"][index]
        label = labels.get(str(row["evidence_id"]))
        if label is None or label["queue_target"] == "unsupported":
            unsupported_indices.append(index)
            continue
        row.update(
            {
                "original_label": label["atdr_label"],
                "safe_queue_target": label["queue_target"],
                "original_queue_target": label["queue_target"],
                "provider_label": label["provider_label"],
                "expected_attack_type": label["attack_type"],
                "label_source": label["label_provenance"],
            }
        )
        targets[index] = str(label["queue_target"])
        original_labels[index] = str(label["atdr_label"])
        scored_indices.append(index)
    external_dataset["targets"] = targets
    external_dataset["original_labels"] = original_labels
    return {
        "scored_indices": scored_indices,
        "unsupported_indices": unsupported_indices,
        "scored_rows": len(scored_indices),
        "unsupported_rows": len(unsupported_indices),
    }


def build_external_splits(external_dataset: dict[str, Any], scored_indices: list[int]) -> dict[str, list[int]]:
    rows = external_dataset["rows"]
    ordered = sorted(
        scored_indices,
        key=lambda index: (
            rows[index].get("timestamp") or datetime.min.replace(tzinfo=timezone.utc),
            str(rows[index]["evidence_id"]),
        ),
    )
    midpoint = max(1, len(ordered) // 2)
    splits: dict[str, list[int]] = {
        "all_external": sorted(scored_indices),
        "temporal_early": sorted(ordered[:midpoint]),
        "temporal_late": sorted(ordered[midpoint:]),
    }
    for spec in SOURCE_FILES:
        name = f"provider_day_{str(spec['provider_day']).replace('-', '_')}"
        splits[name] = sorted(
            index
            for index in scored_indices
            if rows[index]["provider_file"] == spec["file_name"]
        )
    for seed in (7, 17, 42):
        sample = list(scored_indices)
        random.Random(seed).shuffle(sample)
        splits[f"random_seed_{seed}"] = sorted(sample[: max(1, round(len(sample) * 0.75))])
    return splits


def _evaluate_frozen_strategy(
    external_dataset: dict[str, Any],
    indices: list[int],
    *,
    name: str,
    scores_by_index: dict[int, float],
    threshold: dict[str, Any],
    seed: int,
    details: dict[str, Any],
) -> dict[str, Any]:
    scores = [scores_by_index[index] for index in indices]
    result = v398._evaluate_scores(
        external_dataset,
        {"final_test_idx": indices},
        name=name,
        scores=scores,
        threshold_selection=threshold,
        seed=seed,
        details=details,
    )
    result["metrics"].update(
        {
            "threat_positive_precision": result["metrics"]["queue_precision"],
            "threat_positive_recall": result["metrics"]["queue_recall"],
            "threat_positive_f1": result["metrics"]["queue_f1"],
        }
    )
    result.pop("_scores", None)
    result.pop("_predictions", None)
    return result


def _error_dimensions(
    external_dataset: dict[str, Any],
    indices: list[int],
    *,
    scores_by_index: dict[int, float],
    threshold: float,
) -> dict[str, Any]:
    grouped: dict[str, Counter[str]] = {
        "provider_file": Counter(),
        "provider_label": Counter(),
        "protocol": Counter(),
        "destination_port": Counter(),
    }
    for index in indices:
        row = external_dataset["rows"][index]
        truth = external_dataset["targets"][index]
        prediction = "needs_review" if scores_by_index[index] >= threshold else "non_threat"
        if prediction == truth:
            continue
        kind = "false_positive" if truth == "non_threat" else "false_negative"
        grouped["provider_file"][f"{kind}:{row['provider_file']}"] += 1
        grouped["provider_label"][f"{kind}:{row.get('provider_label', 'unknown')}"] += 1
        grouped["protocol"][f"{kind}:{row.get('protocol', 'unavailable')}"] += 1
        grouped["destination_port"][f"{kind}:{row.get('dst_port', 'unavailable')}"] += 1
    return {name: counts.most_common(20) for name, counts in grouped.items()}


def evaluate_external_predictions(
    external_dataset: dict[str, Any],
    prediction_freeze: dict[str, Any],
    scored_indices: list[int],
) -> dict[str, Any]:
    index_by_evidence_id = {
        str(row["evidence_id"]): index
        for index, row in enumerate(external_dataset["rows"])
    }
    accepted_indices = [
        index_by_evidence_id[str(prediction["evidence_id"])]
        for prediction in prediction_freeze["predictions"]
    ]
    score_maps = {
        name: {index: float(scores[position]) for position, index in enumerate(accepted_indices)}
        for name, scores in prediction_freeze["score_sets"].items()
    }
    definitions = {
        "supervised": (v399.PRIMARY_CANDIDATE, {"training_evidence": "internal_reviewed_only"}),
        "logistic": ("balanced_logistic_regression_baseline", {"training_evidence": "internal_reviewed_only"}),
        "anomaly": ("isolation_forest_baseline", {"fit_evidence": "internal_features_only"}),
        "rules": (
            "deterministic_rules_partial_field_baseline",
            {"rule_applicability": RULE_APPLICABILITY, "unsupported_rules_fabricated": False},
        ),
        "hybrid": (
            "hybrid_rule_anomaly_supervised_decision_support",
            {"rule_component": "partial_field_applicability_only"},
        ),
        "majority": ("internal_fit_majority_baseline", {"training_evidence": "internal_fit_targets_only"}),
    }
    split_results: list[dict[str, Any]] = []
    splits = build_external_splits(external_dataset, scored_indices)
    for split_position, (split_name, indices) in enumerate(splits.items()):
        strategies = []
        for name, (display_name, details) in definitions.items():
            strategies.append(
                _evaluate_frozen_strategy(
                    external_dataset,
                    indices,
                    name=display_name,
                    scores_by_index=score_maps[name],
                    threshold=prediction_freeze["thresholds"][name],
                    seed=400 + split_position,
                    details=details
                    | {
                        "external_rows_used_for_fit": 0,
                        "external_rows_used_for_calibration": 0,
                        "external_rows_used_for_threshold_selection": 0,
                    },
                )
            )
        primary_threshold = float(prediction_freeze["thresholds"]["supervised"]["selected_threshold"])
        split_results.append(
            {
                "split_mode": split_name,
                "status": "evaluated",
                "final_rows": len(indices),
                "target_distribution": dict(
                    sorted(Counter(external_dataset["targets"][index] for index in indices).items())
                ),
                "provider_label_distribution": dict(
                    sorted(Counter(external_dataset["rows"][index]["provider_label"] for index in indices).items())
                ),
                "strategies": strategies,
                "primary_error_dimensions": _error_dimensions(
                    external_dataset,
                    indices,
                    scores_by_index=score_maps["supervised"],
                    threshold=primary_threshold,
                ),
                "external_fit_rows": 0,
                "external_calibration_rows": 0,
                "external_threshold_rows": 0,
            }
        )

    primary_rows = [
        (
            split["split_mode"],
            next(strategy for strategy in split["strategies"] if strategy["name"] == v399.PRIMARY_CANDIDATE),
        )
        for split in split_results
    ]
    metric_names = (
        "threat_positive_precision",
        "threat_positive_recall",
        "threat_positive_f1",
        "benign_like_false_positive_rate",
        "suspicious_recall",
        "malicious_recall",
        "macro_f1",
        "weighted_f1",
    )
    stability: dict[str, Any] = {}
    for metric in metric_names:
        values = [
            float(item["metrics"][metric])
            for _split_name, item in primary_rows
            if item["metrics"].get(metric) is not None
        ]
        stability[metric] = {
            "minimum": min(values) if values else None,
            "maximum": max(values) if values else None,
            "range": max(values) - min(values) if values else None,
        }
    worst_split_name, worst = min(
        primary_rows,
        key=lambda item: float(item[1]["metrics"].get("threat_positive_f1") or 0.0),
    )
    return {
        "split_results": split_results,
        "stability": stability,
        "worst_primary": {
            "split_mode": worst_split_name,
            "strategy": worst["name"],
            "metrics": worst["metrics"],
            "calibration": worst["calibration"],
        },
    }


def _render_report(result: dict[str, Any]) -> str:
    all_split = next(split for split in result["evaluation"]["split_results"] if split["split_mode"] == "all_external")
    lines = [
        "# v4.0 Provider-Blinded External Evidence And Frozen Validation",
        "",
        f"Generated: `{result['generated_at']}`",
        "",
        "## Dataset And Protocol",
        "",
        f"- Dataset: `{DATASET['title']}` from `{DATASET['publisher']}`.",
        f"- Official page: {DATASET['official_page']}",
        f"- Sampled/scored rows: `{result['evidence_manifest']['sampled_rows']}` / `{result['label_integrity']['scored_rows']}`.",
        f"- Prediction frozen before label read: `{str(result['protocol']['prediction_frozen_before_label_read']).lower()}`.",
        "- External rows used for fit/calibration/threshold selection: `0/0/0`.",
        "- Provider labels are not ATDR human review and are not import-ready.",
        "",
        "## Field And Rule Applicability",
        "",
        f"- Direct mappings: `{', '.join(DIRECT_FIELD_MAPPING)}`.",
        f"- Unavailable ATDR fields: `{', '.join(UNAVAILABLE_ATDR_FIELDS)}`.",
        "- Only frozen internal byte/packet outlier rules are applicable; all other rule families are unavailable.",
        "",
        "## All-External Results",
        "",
        "| Strategy | Precision | Recall | F1 | Benign FPR | Suspicious recall | Malicious recall | Brier | ECE |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for strategy in all_split["strategies"]:
        metrics = strategy["metrics"]
        calibration = strategy["calibration"]
        lines.append(
            "| {name} | {precision:.4f} | {recall:.4f} | {f1:.4f} | {fpr:.4f} | {suspicious} | "
            "{malicious} | {brier:.4f} | {ece:.4f} |".format(
                name=strategy["name"],
                precision=float(metrics["threat_positive_precision"]),
                recall=float(metrics["threat_positive_recall"]),
                f1=float(metrics["threat_positive_f1"]),
                fpr=float(metrics["benign_like_false_positive_rate"]),
                suspicious=(
                    f"{float(metrics['suspicious_recall']):.4f}"
                    if metrics.get("suspicious_recall") is not None
                    else "unavailable"
                ),
                malicious=(
                    f"{float(metrics['malicious_recall']):.4f}"
                    if metrics.get("malicious_recall") is not None
                    else "unavailable"
                ),
                brier=float(calibration["brier_score"]),
                ece=float(calibration["expected_calibration_error"]),
            )
        )
    lines.extend(
        [
            "",
            "## Readiness",
            "",
            f"Decision: `{result['readiness']['decision']}`.",
            "",
            "No model was activated or promoted, no artifact was written, no operational labels were imported, "
            "and no response or firewall action was created.",
            "",
        ]
    )
    return "\n".join(lines)


def _public_result(result: dict[str, Any]) -> dict[str, Any]:
    return json.loads(json.dumps(result, default=str))


def run_v400_provider_blinded_external_validation(
    db: Session,
    *,
    evidence_dir: Path = V400_EVIDENCE_DIR,
    output_dir: Path = V400_OUTPUT_DIR,
    rows_per_file: int = DEFAULT_ROWS_PER_FILE,
    seed: int = DEFAULT_SAMPLE_SEED,
    write_output: bool = True,
) -> dict[str, Any]:
    started = time.perf_counter()
    before_counts = v398._database_counts(db)
    before_artifact = v398._artifact_state()
    verification = verify_provider_files(evidence_dir)
    if not verification.get("ok"):
        return {
            "ok": False,
            "status": verification.get("status", "failed_closed"),
            "message": verification.get("message"),
            "readiness": {"decision": "candidate_only"},
        }

    internal_dataset = v398._build_dataset(db, min_samples=100)
    if not internal_dataset.get("ok"):
        return {
            "ok": False,
            "status": internal_dataset.get("status", "failed_closed"),
            "message": internal_dataset.get("message"),
            "readiness": {"decision": "candidate_only"},
        }
    v398.assign_leakage_groups(internal_dataset["rows"])
    freeze = v399._internal_freeze(internal_dataset)
    if not freeze.get("ok"):
        return {
            "ok": False,
            "status": "failed_closed",
            "message": freeze.get("message"),
            "readiness": {"decision": "candidate_only"},
        }

    stamp = _stamp()
    sample = build_feature_only_sample(
        evidence_dir,
        rows_per_file=rows_per_file,
        seed=seed,
        stamp=stamp,
    )
    prelabel_manifest_path = evidence_dir / f"v4_0_prelabel_manifest_{stamp}.json"
    prelabel_manifest_hash = _write_self_hashed_manifest(
        prelabel_manifest_path,
        {
            "schema": MANIFEST_SCHEMA,
            "phase": "features_frozen_labels_not_loaded",
            "created_at": _utc_now(),
            "dataset": DATASET,
            "provider_files": verification["files"],
            "sampling": sample["sampling"],
            "files": sample["files"],
            "sampled_rows": sample["sampled_rows"],
            "feature_sample_sha256": sample["feature_sha256"],
            "mapping_version": MAPPING_VERSION,
            "label_values_loaded": False,
            "class_distribution": "pending_prediction_freeze",
            "human_reviewed": False,
            "import_ready": False,
        },
    )

    rule_thresholds = _frozen_rule_thresholds(internal_dataset, freeze)
    external_dataset = build_external_feature_dataset(
        sample["feature_path"],
        internal_dataset=internal_dataset,
        frozen_rule_thresholds=rule_thresholds,
    )
    if not external_dataset.get("ok"):
        return {
            "ok": False,
            "status": external_dataset.get("status", "failed_closed"),
            "message": external_dataset.get("message"),
            "readiness": {"decision": "candidate_only"},
        }

    synthetic_dataset = _synthetic_reference_dataset(internal_dataset)
    try:
        overlap = audit_external_overlap(internal_dataset, synthetic_dataset, external_dataset)
        if not overlap["passed"]:
            return {
                "ok": False,
                "status": "failed_closed",
                "message": "External feature evidence failed overlap quarantine.",
                "overlap": {key: value for key, value in overlap.items() if not key.endswith("_indices")},
                "readiness": {"decision": "candidate_only"},
            }

        candidates = v399._fit_frozen_candidates(internal_dataset, freeze)
        prediction_freeze = freeze_predictions(
            external_dataset,
            candidates,
            overlap["accepted_indices"],
            evidence_dir=evidence_dir,
            stamp=stamp,
        )
        labels = reveal_labels_after_prediction_freeze(
            evidence_dir,
            selected_rows=_selected_rows_by_file(external_dataset, overlap["accepted_indices"]),
            prediction_freeze=prediction_freeze,
            stamp=stamp,
        )
        attachment = attach_revealed_labels(external_dataset, labels, overlap["accepted_indices"])
        if not attachment["scored_indices"]:
            return {
                "ok": False,
                "status": "failed_closed",
                "message": "No supported provider labels remained for scoring.",
                "readiness": {"decision": "candidate_only"},
            }
        evaluation = evaluate_external_predictions(
            external_dataset,
            prediction_freeze,
            attachment["scored_indices"],
        )

        final_manifest_path = evidence_dir / f"v4_0_external_evidence_manifest_{stamp}.json"
        final_manifest_hash = _write_self_hashed_manifest(
            final_manifest_path,
            {
                "schema": MANIFEST_SCHEMA,
                "phase": "labels_revealed_after_prediction_freeze",
                "created_at": _utc_now(),
                "dataset": DATASET,
                "provider_files": verification["files"],
                "sampling": sample["sampling"],
                "files": sample["files"],
                "sampled_rows": sample["sampled_rows"],
                "accepted_rows": overlap["accepted_rows"],
                "quarantined_rows": overlap["quarantined_rows"],
                "scored_rows": attachment["scored_rows"],
                "class_distribution": labels["class_distribution"],
                "provider_label_distribution": labels["provider_label_distribution"],
                "time_information": {
                    "provider_days": sorted({row["provider_day"] for row in external_dataset["rows"]}),
                    "timestamp_values_available": sum(1 for row in external_dataset["rows"] if row["timestamp"]),
                },
                "source_information": {
                    "identity": "provider file/day",
                    "network_source_ip_available": False,
                    "source_count": len({row["source_name"] for row in external_dataset["rows"]}),
                },
                "mapping_version": MAPPING_VERSION,
                "direct_field_mapping": DIRECT_FIELD_MAPPING,
                "unavailable_atdr_fields": list(UNAVAILABLE_ATDR_FIELDS),
                "rule_applicability": RULE_APPLICABILITY,
                "prelabel_manifest_sha256": prelabel_manifest_hash,
                "feature_sample_sha256": sample["feature_sha256"],
                "prediction_sha256": prediction_freeze["prediction_sha256"],
                "label_sha256": labels["label_sha256"],
                "prediction_frozen_at": prediction_freeze["prediction_frozen_at"],
                "label_read_started_at": labels["label_read_started_at"],
                "prediction_frozen_before_label_read": labels["prediction_frozen_before_label_read"],
                "label_provenance": "provider_ground_truth_cse_cic_ids2018",
                "human_reviewed": False,
                "import_ready": False,
            },
        )

        after_counts = v398._database_counts(db)
        after_artifact = v398._artifact_state()
        public_overlap = {key: value for key, value in overlap.items() if not key.endswith("_indices")}
        result: dict[str, Any] = {
            "ok": True,
            "status": "completed",
            "version": V400_VERSION,
            "generated_at": _utc_now(),
            "runtime_seconds": round(time.perf_counter() - started, 4),
            "dataset": DATASET,
            "evidence_manifest": {
                "schema": MANIFEST_SCHEMA,
                "sampled_rows": sample["sampled_rows"],
                "accepted_rows": overlap["accepted_rows"],
                "scored_rows": attachment["scored_rows"],
                "mapping_version": MAPPING_VERSION,
                "prelabel_manifest_hash": prelabel_manifest_hash,
                "final_manifest_hash": final_manifest_hash,
            },
            "protocol": {
                "feature_mapping_completed_without_provider_labels": True,
                "prediction_frozen_before_label_read": labels["prediction_frozen_before_label_read"],
                "prediction_sha256": prediction_freeze["prediction_sha256"],
                "external_rows_used_for_fit": 0,
                "external_rows_used_for_calibration": 0,
                "external_rows_used_for_threshold_selection": 0,
                "thresholds_frozen_on_internal_evidence": True,
                "external_final_labels_used_for_tuning": False,
            },
            "frozen_internal_protocol": {
                "split_mode": freeze["split_mode"],
                "partition_hash": freeze["partition_hash"],
                "partition_sizes": freeze["partition_sizes"],
                "rule_outlier_thresholds": rule_thresholds,
                "primary_threshold": candidates["primary"]["threshold_selection"],
                "logistic_threshold": candidates["logistic"]["threshold_selection"],
                "anomaly_threshold": candidates["anomaly"]["threshold_selection"],
                "hybrid_threshold": candidates["hybrid_threshold"],
            },
            "feature_adapter": external_dataset["feature_meta"] | {"rule_applicability": RULE_APPLICABILITY},
            "overlap_and_quarantine": public_overlap,
            "label_integrity": {
                "provider_ground_truth_rows": labels["label_row_count"],
                "scored_rows": attachment["scored_rows"],
                "unsupported_rows": attachment["unsupported_rows"],
                "class_distribution": labels["class_distribution"],
                "provider_label_distribution": labels["provider_label_distribution"],
                "human_reviewed_rows": 0,
                "labels_imported_to_operational_database": 0,
                "import_ready": False,
            },
            "evaluation": evaluation,
            "readiness": {
                "decision": "candidate_only",
                "production_promoted": False,
                "model_activated": False,
                "model_artifact_written": False,
                "response_automation_allowed": False,
                "real_firewall_blocking_enabled": False,
                "reason": (
                    "External provider evidence is diagnostic and field-limited; independent operational and "
                    "real-device validation remain required regardless of benchmark metrics."
                ),
            },
            "safety": {
                "database_counts_before": before_counts,
                "database_counts_after": after_counts,
                "database_counts_unchanged": before_counts == after_counts,
                "active_artifact_before": before_artifact,
                "active_artifact_after": after_artifact,
                "active_artifact_unchanged": before_artifact == after_artifact,
                "session_new_objects": len(db.new),
                "session_dirty_objects": len(db.dirty),
                "session_deleted_objects": len(db.deleted),
                "labels_written": False,
                "model_activated": False,
                "model_artifact_written": False,
                "response_actions_created": 0,
                "configured_database_migrated": False,
            },
        }
        if write_output:
            output_dir.mkdir(parents=True, exist_ok=True)
            latest_path = output_dir / V400_LATEST
            report_path = output_dir / f"v4_0_provider_blinded_external_validation_{stamp}.md"
            _write_json(latest_path, _public_result(result))
            report_path.write_text(_render_report(result), encoding="utf-8")
            result["reports"] = {
                "latest": latest_path.name,
                "validation_report": report_path.name,
                "generated_outputs_ignored": True,
            }
        return _public_result(result)
    finally:
        v399._close_external_dataset(synthetic_dataset)
