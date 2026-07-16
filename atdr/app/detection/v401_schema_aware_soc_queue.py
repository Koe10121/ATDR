from __future__ import annotations

import csv
import hashlib
import heapq
import json
import math
import random
import time
import warnings
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from sqlalchemy.orm import Session

from atdr.app.core.config import PROJECT_ROOT
from atdr.app.detection import v398_independent_holdout_validation as v398
from atdr.app.detection import v400_provider_blinded_external_validation as v400
from atdr.app.detection.schema_contracts import (
    COMMON_CATEGORICAL_FEATURES,
    COMMON_NUMERIC_FEATURES,
    get_schema_contract,
    normalize_common_features,
    public_schema_contracts,
    validate_schema_row,
)


V401_VERSION = "v4.1"
V401_OUTPUT_DIR = PROJECT_ROOT / "ml_baseline_reviews"
V401_DEVELOPMENT_DIR = PROJECT_ROOT / ".tmp" / "development_corpus" / "cse_cic_ids2018_v41"
V401_LATEST = "v4_1_schema_aware_soc_queue_latest.json"
DEFAULT_ROWS_PER_PROVIDER_LABEL = 3_000
DEFAULT_SEED = 401
DEVELOPMENT_MANIFEST_SCHEMA = "atdr_v401_development_evidence_manifest_v1"
MODEL_COMPARISON_SCHEMA = "atdr_v401_schema_aware_model_comparison_v1"

DEVELOPMENT_SOURCE_FILES: tuple[dict[str, Any], ...] = (
    {
        "file_name": "Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv",
        "provider_day": "2018-02-15",
        "scenario": "DoS GoldenEye and Slowloris",
        "public_url": (
            "https://cse-cic-ids2018.s3.ca-central-1.amazonaws.com/"
            "Processed%20Traffic%20Data%20for%20ML%20Algorithms/"
            "Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv"
        ),
        "expected_bytes": 375_945_899,
        "sha256": "fa2947a8256d81ee9103ae16139d62d0e17aa23e696ee80d9e76fb51c01c9c4b",
        "s3_etag": "eb1dc2ec76efe09c8995f28bfa4c8656-23",
        "s3_last_modified": "2018-10-11T16:08:48Z",
    },
    {
        "file_name": "Thursday-22-02-2018_TrafficForML_CICFlowMeter.csv",
        "provider_day": "2018-02-22",
        "scenario": "Web brute force, XSS, and SQL injection",
        "public_url": (
            "https://cse-cic-ids2018.s3.ca-central-1.amazonaws.com/"
            "Processed%20Traffic%20Data%20for%20ML%20Algorithms/"
            "Thursday-22-02-2018_TrafficForML_CICFlowMeter.csv"
        ),
        "expected_bytes": 382_636_202,
        "sha256": "da33c927018274f9d49b145baa00e4ce0526c25b3b890b34c489e247b5e24544",
        "s3_etag": "2bfbfdc038eb59f60bb725d9f3ede5d7-23",
        "s3_last_modified": "2018-10-11T16:09:20Z",
    },
    {
        "file_name": "Friday-02-03-2018_TrafficForML_CICFlowMeter.csv",
        "provider_day": "2018-03-02",
        "scenario": "Bot activity",
        "public_url": (
            "https://cse-cic-ids2018.s3.ca-central-1.amazonaws.com/"
            "Processed%20Traffic%20Data%20for%20ML%20Algorithms/"
            "Friday-02-03-2018_TrafficForML_CICFlowMeter.csv"
        ),
        "expected_bytes": 352_368_373,
        "sha256": "d96f38e7496aba83475031e6fb8c6fdf1abf6aa1b71325a917798f3c7de93de1",
        "s3_etag": "2cef2d9c87fc74df84d7424f6949f1b3-22",
        "s3_last_modified": "2018-10-11T16:02:49Z",
    },
)

DEVELOPMENT_DATASET = {
    "dataset_id": "cse-cic-ids2018-v401-development-days",
    "title": "CSE-CIC-IDS2018 development-only days for ATDR v4.1",
    "publisher": "Canadian Institute for Cybersecurity, University of New Brunswick",
    "official_page": "https://www.unb.ca/cic/datasets/ids-2018.html",
    "official_aws_page": "https://registry.opendata.aws/cse-cic-ids2018/",
    "license_summary": (
        "Official terms permit redistribution, republication, and mirroring with citation to the dataset "
        "and a link to the official AWS page."
    ),
    "role": "development_only_not_final_external_evidence",
    "human_reviewed": False,
    "import_ready": False,
}

RESERVED_FUTURE_BENCHMARK = {
    "dataset_id": "unsw-nb15-official-testing-partition",
    "publisher": "UNSW Canberra at ADFA",
    "official_page": "https://research.unsw.edu.au/projects/unsw-nb15-dataset",
    "reserved_file": "UNSW_NB15_testing-set.csv",
    "expected_rows_from_official_page": 82_332,
    "usage_terms": (
        "Official page grants free academic research use in perpetuity with required citation; "
        "commercial use requires author agreement."
    ),
    "status": "reserved_not_downloaded_not_inspected",
    "allowed_v401_roles": [],
    "human_reviewed": False,
    "import_ready": False,
}

LOCKED_V400_FILES: dict[str, str] = {
    "Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv": (
        "acff8bc61376ee031d80878ee6099e0b1a87a1bd711d8068298421418c9f8147"
    ),
    "Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv": (
        "b0534c5d7d8b41e03df71c6966c995d116a8ed28e61f377c8b14cdf5d28f4edf"
    ),
    "v4_0_prelabel_manifest_20260714T042536Z.json": (
        "230edb8402bbc84f3de4d951758711c460e0a3c5fdf012f5c8eebe27ab7c2721"
    ),
    "v4_0_feature_only_sample_20260714T042536Z.csv": (
        "6c5174c9a588bc81d1a0a58664cc6196c0f0b01dd696c9a3cb3a41c7a5717841"
    ),
    "v4_0_frozen_predictions_20260714T042536Z.jsonl": (
        "84d7a0bc9a85e9cd7094f8f9289f63e349185be7e4f3409ce3a398beb99ec2bf"
    ),
    "v4_0_revealed_provider_labels_20260714T042536Z.csv": (
        "00f0282044c786bbe30f8c379ac89680b7c82ee12413439849407ba02b0238cc"
    ),
    "v4_0_external_evidence_manifest_20260714T042536Z.json": (
        "1c67c7d86f246917fed6e601dade9e31595a5822a24609cf9eb759f6129b720e"
    ),
}

DEVELOPMENT_ROLES = (
    "feature_engineering",
    "fit",
    "calibration",
    "threshold_selection",
    "candidate_selection",
)

PROVIDER_LABEL_MAPPING = {
    "benign": {"atdr_label": "benign", "queue_target": "non_threat", "severity_target": "benign"},
    "dos attacks-goldeneye": {
        "atdr_label": "malicious",
        "queue_target": "needs_review",
        "severity_target": "malicious",
    },
    "dos attacks-slowloris": {
        "atdr_label": "malicious",
        "queue_target": "needs_review",
        "severity_target": "malicious",
    },
    "brute force -web": {
        "atdr_label": "suspicious",
        "queue_target": "needs_review",
        "severity_target": "suspicious",
    },
    "brute force -xss": {
        "atdr_label": "malicious",
        "queue_target": "needs_review",
        "severity_target": "malicious",
    },
    "sql injection": {
        "atdr_label": "malicious",
        "queue_target": "needs_review",
        "severity_target": "malicious",
    },
    "bot": {"atdr_label": "malicious", "queue_target": "needs_review", "severity_target": "malicious"},
}

FLOW_METADATA_COLUMNS = {"Timestamp", "Label"}
FLOW_CATEGORICAL_FEATURES = ("schema_id", "protocol_family")
SPLIT_MODES = ("time_holdout", "source_group_holdout", "random_seed_7", "random_seed_17", "random_seed_42")
ROLE_NAMES = ("fit_idx", "calibration_idx", "threshold_idx", "final_test_idx")


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


def _write_self_hashed_json(path: Path, payload: dict[str, Any]) -> str:
    document = dict(payload)
    document["manifest_hash_algorithm"] = "sha256_canonical_json_without_manifest_hash"
    document["manifest_hash"] = _stable_hash(document)
    _write_json(path, document)
    return str(document["manifest_hash"])


def _normal_header(value: str) -> str:
    return value.lstrip("\ufeff").strip()


def _safe_float(value: Any) -> float:
    try:
        result = float(str(value).strip())
    except (TypeError, ValueError):
        return math.nan
    return result if math.isfinite(result) else math.nan


def _safe_int(value: Any) -> int | None:
    numeric = _safe_float(value)
    return None if not math.isfinite(numeric) else int(numeric)


def _parse_timestamp(value: Any) -> datetime | None:
    text = str(value or "").strip()
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
    if code == 1:
        return "icmp"
    return f"ip_protocol_{code}" if code is not None else "unavailable"


def _slug(value: str) -> str:
    return "".join(character.lower() if character.isalnum() else "_" for character in value).strip("_")


def verify_v400_evidence_lock(evidence_dir: Path = v400.V400_EVIDENCE_DIR) -> dict[str, Any]:
    verified: list[dict[str, Any]] = []
    missing: list[str] = []
    mismatched: list[dict[str, str]] = []
    for file_name, expected_hash in LOCKED_V400_FILES.items():
        path = evidence_dir / file_name
        if not path.exists():
            missing.append(file_name)
            continue
        actual_hash = _file_sha256(path)
        if actual_hash != expected_hash:
            mismatched.append(
                {"file_name": file_name, "expected_sha256": expected_hash, "actual_sha256": actual_hash}
            )
        else:
            verified.append({"file_name": file_name, "sha256": actual_hash, "locked": True})
    return {
        "ok": not missing and not mismatched,
        "status": "locked_and_verified" if not missing and not mismatched else "failed_closed",
        "lock_version": "v4_0_final_evidence_lock_20260714T042536Z",
        "verified": verified,
        "missing": missing,
        "mismatched": mismatched,
        "development_roles_denied": list(DEVELOPMENT_ROLES),
        "content_read_for_development": False,
    }


def enforce_development_role_boundary(paths: Sequence[Path]) -> dict[str, Any]:
    locked_root = v400.V400_EVIDENCE_DIR.resolve()
    locked_hashes = set(LOCKED_V400_FILES.values())
    inspected: list[dict[str, Any]] = []
    violations: list[dict[str, Any]] = []
    for path in paths:
        resolved = path.resolve()
        actual_hash = _file_sha256(path) if path.exists() and path.is_file() else None
        reasons: list[str] = []
        if resolved == locked_root or locked_root in resolved.parents:
            reasons.append("path_inside_locked_v400_evidence_root")
        if path.name in LOCKED_V400_FILES or path.name.startswith("v4_0_"):
            reasons.append("locked_v400_file_name")
        if actual_hash in locked_hashes:
            reasons.append("locked_v400_file_hash")
        if path.name.casefold() == str(RESERVED_FUTURE_BENCHMARK["reserved_file"]).casefold():
            reasons.append("reserved_future_benchmark")
        row = {"file_name": path.name, "sha256": actual_hash, "development_roles": list(DEVELOPMENT_ROLES)}
        if reasons:
            violations.append(row | {"reasons": reasons})
        else:
            inspected.append(row | {"authorized": True})
    if violations:
        detail = "; ".join(f"{item['file_name']}: {','.join(item['reasons'])}" for item in violations)
        raise RuntimeError(f"Development evidence boundary rejected locked/reserved input: {detail}")
    return {
        "passed": True,
        "inspected": inspected,
        "roles_authorized": list(DEVELOPMENT_ROLES),
        "locked_v400_rows_used": 0,
        "locked_v400_labels_used": 0,
        "reserved_benchmark_rows_used": 0,
    }


def verify_development_files(development_dir: Path) -> dict[str, Any]:
    paths = [development_dir / str(spec["file_name"]) for spec in DEVELOPMENT_SOURCE_FILES]
    boundary = enforce_development_role_boundary(paths)
    files: list[dict[str, Any]] = []
    for spec, path in zip(DEVELOPMENT_SOURCE_FILES, paths, strict=True):
        if not path.exists():
            return {
                "ok": False,
                "status": "acquisition_required",
                "message": f"Missing development-only provider file: {path.name}",
            }
        size = path.stat().st_size
        actual_hash = _file_sha256(path)
        if size != int(spec["expected_bytes"]) or actual_hash != spec["sha256"]:
            return {
                "ok": False,
                "status": "failed_closed",
                "message": f"Development provider file identity mismatch: {path.name}",
                "file_name": path.name,
                "expected_bytes": spec["expected_bytes"],
                "actual_bytes": size,
                "expected_sha256": spec["sha256"],
                "actual_sha256": actual_hash,
            }
        files.append(dict(spec) | {"verified_bytes": size, "verified_sha256": actual_hash})
    return {"ok": True, "status": "verified_development_only", "files": files, "role_boundary": boundary}


def _sample_rank(*, seed: int, file_hash: str, label: str, row_number: int) -> int:
    token = f"{seed}|{file_hash}|{label.casefold()}|{row_number}".encode()
    return int.from_bytes(hashlib.sha256(token).digest(), byteorder="big", signed=False)


def build_development_sample(
    development_dir: Path,
    *,
    rows_per_provider_label: int,
    seed: int,
    stamp: str,
) -> dict[str, Any]:
    if rows_per_provider_label < 10:
        raise ValueError("rows_per_provider_label must be at least 10")
    selected_rows: list[dict[str, Any]] = []
    source_summaries: list[dict[str, Any]] = []
    common_header: list[str] | None = None

    for spec in DEVELOPMENT_SOURCE_FILES:
        path = development_dir / str(spec["file_name"])
        heaps: dict[str, list[tuple[int, int, int, list[str]]]] = defaultdict(list)
        provider_distribution: Counter[str] = Counter()
        original_rows = malformed_rows = unsupported_rows = 0
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            reader = csv.reader(handle)
            header = [_normal_header(item) for item in next(reader)]
            if "Label" not in header or "Timestamp" not in header:
                raise ValueError(f"Required provider columns are absent from {path.name}")
            if common_header is None:
                common_header = header
            elif header != common_header:
                raise ValueError("Development provider files do not share one verified feature schema")
            label_index = header.index("Label")
            for row_number, row in enumerate(reader, start=1):
                original_rows += 1
                if len(row) != len(header):
                    malformed_rows += 1
                    continue
                provider_label = str(row[label_index]).strip()
                mapping = PROVIDER_LABEL_MAPPING.get(provider_label.casefold())
                provider_distribution[provider_label] += 1
                if mapping is None:
                    unsupported_rows += 1
                    continue
                rank = _sample_rank(
                    seed=seed,
                    file_hash=str(spec["sha256"]),
                    label=provider_label,
                    row_number=row_number,
                )
                candidate = (-rank, -row_number, row_number, row)
                heap = heaps[provider_label]
                if len(heap) < rows_per_provider_label:
                    heapq.heappush(heap, candidate)
                elif candidate > heap[0]:
                    heapq.heapreplace(heap, candidate)

        sampled_distribution: Counter[str] = Counter()
        selected_numbers: dict[str, list[int]] = {}
        for provider_label, heap in sorted(heaps.items()):
            selected = sorted(heap, key=lambda item: item[2])
            selected_numbers[provider_label] = [item[2] for item in selected]
            mapping = PROVIDER_LABEL_MAPPING[provider_label.casefold()]
            for _rank, _negative_row, row_number, values in selected:
                selected_rows.append(
                    {
                        "evidence_id": f"{spec['provider_day']}:{row_number}",
                        "provider_file": spec["file_name"],
                        "provider_day": spec["provider_day"],
                        "provider_row_number": row_number,
                        "provider_label": provider_label,
                        "atdr_label": mapping["atdr_label"],
                        "queue_target": mapping["queue_target"],
                        "severity_target": mapping["severity_target"],
                        "human_reviewed": False,
                        "import_ready": False,
                        "values": values,
                    }
                )
                sampled_distribution[provider_label] += 1
        source_summaries.append(
            {
                "file_name": spec["file_name"],
                "provider_day": spec["provider_day"],
                "original_row_count": original_rows,
                "malformed_row_count": malformed_rows,
                "unsupported_label_rows": unsupported_rows,
                "provider_label_distribution": dict(sorted(provider_distribution.items())),
                "sampled_label_distribution": dict(sorted(sampled_distribution.items())),
                "selected_row_numbers_hash": _stable_hash(selected_numbers),
            }
        )

    if common_header is None:
        raise ValueError("No development feature schema was available")
    feature_columns = [column for column in common_header if column != "Label"]
    label_index = common_header.index("Label")
    sample_path = development_dir / f"v4_1_development_sample_{stamp}.csv"
    with sample_path.open("w", encoding="utf-8", newline="") as handle:
        fieldnames = [
            "evidence_id",
            "provider_file",
            "provider_day",
            "provider_row_number",
            "provider_label",
            "atdr_label",
            "queue_target",
            "severity_target",
            "human_reviewed",
            "import_ready",
            *feature_columns,
        ]
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for item in sorted(selected_rows, key=lambda row: str(row["evidence_id"])):
            provider_values = {
                column: item["values"][index]
                for index, column in enumerate(common_header)
                if index != label_index
            }
            writer.writerow({key: item[key] for key in fieldnames if key in item} | provider_values)

    return {
        "sample_path": sample_path,
        "sample_sha256": _file_sha256(sample_path),
        "rows": selected_rows,
        "sampled_rows": len(selected_rows),
        "provider_header": common_header,
        "provider_feature_columns": feature_columns,
        "provider_header_hash": _stable_hash(common_header),
        "source_summaries": source_summaries,
        "sampling": {
            "seed": seed,
            "method": "minimum_sha256_rank_per_provider_file_and_provider_label",
            "rows_per_provider_label": rows_per_provider_label,
            "label_aware_development_sampling": True,
            "final_benchmark_sampling": False,
            "v400_locked_labels_consulted": False,
        },
        "class_distribution": dict(sorted(Counter(item["atdr_label"] for item in selected_rows).items())),
        "queue_distribution": dict(sorted(Counter(item["queue_target"] for item in selected_rows).items())),
        "provider_label_distribution": dict(
            sorted(Counter(item["provider_label"] for item in selected_rows).items())
        ),
    }


def _provider_common_values(row: Mapping[str, Any]) -> dict[str, Any]:
    sent = _safe_float(row.get("TotLen Fwd Pkts"))
    received = _safe_float(row.get("TotLen Bwd Pkts"))
    forward_packets = _safe_float(row.get("Tot Fwd Pkts"))
    backward_packets = _safe_float(row.get("Tot Bwd Pkts"))
    duration_microseconds = _safe_float(row.get("Flow Duration"))
    return {
        "timestamp": _parse_timestamp(row.get("Timestamp")),
        "dst_port": _safe_int(row.get("Dst Port")),
        "protocol": _protocol_name(row.get("Protocol")),
        "bytes_sent": sent if math.isfinite(sent) else None,
        "bytes_received": received if math.isfinite(received) else None,
        "packets": (
            forward_packets + backward_packets
            if math.isfinite(forward_packets) and math.isfinite(backward_packets)
            else None
        ),
        "duration_seconds": duration_microseconds / 1_000_000 if math.isfinite(duration_microseconds) else None,
    }


def _provider_exact_fingerprint(row: Mapping[str, Any], feature_columns: Sequence[str]) -> str:
    payload = {
        column: str(row.get(column) or "").strip()
        for column in feature_columns
        if column != "Timestamp"
    }
    return _stable_hash(payload)


def _provider_near_fingerprint(values: Mapping[str, Any], provider_day: str) -> str:
    def bucket(value: Any) -> int:
        numeric = abs(_safe_float(value))
        if not math.isfinite(numeric) or numeric < 1:
            return 0
        return int(math.log10(numeric)) + 1

    return _stable_hash(
        {
            "provider_day": provider_day,
            "protocol": values.get("protocol"),
            "dst_port": values.get("dst_port"),
            "bytes_sent_bucket": bucket(values.get("bytes_sent")),
            "bytes_received_bucket": bucket(values.get("bytes_received")),
            "packets_bucket": bucket(values.get("packets")),
            "duration_bucket": bucket(values.get("duration_seconds")),
        }
    )


def build_flow_development_dataset(sample_path: Path) -> dict[str, Any]:
    imports = v398._optional_imports()
    if imports is None:
        return {"ok": False, "status": "skipped", "message": "Supervised ML dependencies are unavailable"}
    pd = imports[1]
    metadata = {
        "evidence_id",
        "provider_file",
        "provider_day",
        "provider_row_number",
        "provider_label",
        "atdr_label",
        "queue_target",
        "severity_target",
        "human_reviewed",
        "import_ready",
    }
    raw_rows: list[dict[str, str]] = []
    with sample_path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        fieldnames = list(reader.fieldnames or [])
        provider_features = [column for column in fieldnames if column not in metadata]
        numeric_features = [column for column in provider_features if column != "Timestamp"]
        for row in reader:
            raw_rows.append(dict(row))
    if not raw_rows or not numeric_features:
        return {"ok": False, "status": "failed_closed", "message": "Development sample has no usable flow rows"}

    missing_features = [f"missing__{_slug(column)}" for column in numeric_features]
    flow_rows: list[dict[str, Any]] = []
    common_rows: list[dict[str, Any]] = []
    rows: list[dict[str, Any]] = []
    targets: list[str] = []
    severity_targets: list[str] = []
    exact_seen: set[str] = set()
    duplicate_rows: list[dict[str, Any]] = []
    schema_violations: list[dict[str, Any]] = []

    for raw in raw_rows:
        common_values = _provider_common_values(raw)
        validation = validate_schema_row("provider_flow", common_values)
        if not validation["valid"]:
            schema_violations.append({"evidence_id": raw["evidence_id"], **validation})
            continue
        exact = _provider_exact_fingerprint(raw, provider_features)
        if exact in exact_seen:
            duplicate_rows.append({"evidence_id": raw["evidence_id"], "exact_fingerprint": exact})
            continue
        exact_seen.add(exact)
        flow_row = {column: _safe_float(raw.get(column)) for column in numeric_features}
        flow_row.update(
            {
                f"missing__{_slug(column)}": int(not math.isfinite(flow_row[column]))
                for column in numeric_features
            }
        )
        flow_row.update(
            {
                "schema_id": "provider_flow",
                "protocol_family": str(common_values["protocol"]),
            }
        )
        common_row = normalize_common_features("provider_flow", common_values)
        index = len(rows)
        timestamp = common_values["timestamp"]
        near = _provider_near_fingerprint(common_values, raw["provider_day"])
        rows.append(
            {
                "index": index,
                "log_id": raw["evidence_id"],
                "evidence_id": raw["evidence_id"],
                "provider_file": raw["provider_file"],
                "provider_day": raw["provider_day"],
                "provider_row_number": int(raw["provider_row_number"]),
                "source_name": f"cse-cic-ids2018-dev:{raw['provider_day']}",
                "source_type": "external_provider_flow_development",
                "schema_id": "provider_flow",
                "timestamp": timestamp,
                "provider_label": raw["provider_label"],
                "original_label": raw["atdr_label"],
                "safe_queue_target": raw["queue_target"],
                "severity_target": raw["severity_target"],
                "human_reviewed": False,
                "import_ready": False,
                "label_source": "provider_ground_truth_development_only",
                "protocol": common_values["protocol"],
                "dst_port": common_values["dst_port"],
                "app": "unavailable",
                "action": "unavailable",
                "exact_fingerprint": exact,
                "near_fingerprint": near,
                "feature_fingerprint": exact,
            }
        )
        flow_rows.append(flow_row)
        common_rows.append(common_row)
        targets.append(raw["queue_target"])
        severity_targets.append(raw["severity_target"])

    leakage_group_summary = v398.assign_leakage_groups(rows) if rows else {}

    return {
        "ok": bool(rows) and not schema_violations,
        "status": "ready" if rows and not schema_violations else "failed_closed",
        "imports": imports,
        "frame": pd.DataFrame(flow_rows),
        "common_frame": pd.DataFrame(common_rows),
        "rows": rows,
        "targets": targets,
        "severity_targets": severity_targets,
        "feature_meta": {
            "numeric_features": [*numeric_features, *missing_features],
            "categorical_features": list(FLOW_CATEGORICAL_FEATURES),
            "provider_numeric_features": numeric_features,
            "missingness_indicator_count": len(missing_features),
            "schema_contract": get_schema_contract("provider_flow").as_dict(),
            "unavailable_fields_not_invented": True,
        },
        "input_rows": len(raw_rows),
        "accepted_rows": len(rows),
        "duplicate_rows_quarantined": len(duplicate_rows),
        "duplicate_examples": duplicate_rows[:10],
        "schema_violations": schema_violations[:20],
        "leakage_group_summary": leakage_group_summary,
        "label_integrity": {
            "provider_ground_truth": True,
            "human_reviewed_rows": 0,
            "import_ready_rows": 0,
            "operational_database_imported_rows": 0,
            "v400_locked_labels_used": 0,
        },
    }


def build_firewall_common_frame(internal_dataset: dict[str, Any]) -> Any:
    pd = internal_dataset["imports"][1]
    common_rows: list[dict[str, Any]] = []
    for log in internal_dataset["logs"]:
        common_rows.append(
            normalize_common_features(
                "palo_alto",
                {
                    "timestamp": v398._timestamp(log),
                    "src_ip": getattr(log, "src_ip", None),
                    "dst_ip": getattr(log, "dst_ip", None),
                    "src_port": getattr(log, "src_port", None),
                    "dst_port": getattr(log, "dst_port", None),
                    "protocol": getattr(log, "protocol", None),
                    "action": getattr(log, "action", None),
                    "app": getattr(log, "app", None),
                    "bytes_sent": getattr(log, "bytes_sent", None),
                    "bytes_received": getattr(log, "bytes_received", None),
                    "packets": getattr(log, "packets", None),
                    "duration_seconds": getattr(log, "elapsed_time", None),
                    "src_zone": getattr(log, "src_zone", None),
                    "dst_zone": getattr(log, "dst_zone", None),
                    "app_risk": getattr(log, "app_risk", None),
                    "behavior_windows": True,
                },
            )
        )
    return pd.DataFrame(common_rows)


def _split_counts(total: int, proportions: Sequence[float]) -> list[int]:
    boundaries: list[int] = []
    consumed = 0
    for proportion in proportions[:-1]:
        consumed += round(total * proportion)
        boundaries.append(min(total, consumed))
    return boundaries


def _assign_stratified_roles(
    rows: list[dict[str, Any]],
    indices: Sequence[int],
    *,
    seed: int,
    chronological: bool,
    proportions: Sequence[float] = (0.55, 0.15, 0.15, 0.15),
) -> dict[str, list[int]]:
    roles = {name: [] for name in ROLE_NAMES}
    grouped: dict[str, list[int]] = defaultdict(list)
    for index in indices:
        grouped[str(rows[index]["severity_target"])].append(index)
    rng = random.Random(seed)
    for label, members in sorted(grouped.items()):
        if chronological:
            members = sorted(
                members,
                key=lambda index: (
                    rows[index].get("timestamp") or datetime.min.replace(tzinfo=timezone.utc),
                    rows[index]["evidence_id"],
                ),
            )
        else:
            members = sorted(members, key=lambda index: str(rows[index]["leakage_group"]))
            rng.shuffle(members)
        boundaries = _split_counts(len(members), proportions)
        chunks = (
            members[: boundaries[0]],
            members[boundaries[0] : boundaries[1]],
            members[boundaries[1] : boundaries[2]],
            members[boundaries[2] :],
        )
        for role, chunk in zip(ROLE_NAMES, chunks, strict=True):
            roles[role].extend(chunk)
    return {role: sorted(values) for role, values in roles.items()}


def audit_development_partition(rows: list[dict[str, Any]], partition: dict[str, list[int]]) -> dict[str, Any]:
    role_sets = {role: set(partition.get(role, [])) for role in ROLE_NAMES}
    pairwise_overlap: dict[str, int] = {}
    group_overlap: dict[str, int] = {}
    for position, left in enumerate(ROLE_NAMES):
        for right in ROLE_NAMES[position + 1 :]:
            name = f"{left}_vs_{right}"
            pairwise_overlap[name] = len(role_sets[left] & role_sets[right])
            left_groups = {str(rows[index]["leakage_group"]) for index in role_sets[left]}
            right_groups = {str(rows[index]["leakage_group"]) for index in role_sets[right]}
            group_overlap[name] = len(left_groups & right_groups)
    distributions = {
        role: {
            "queue": dict(sorted(Counter(rows[index]["safe_queue_target"] for index in indices).items())),
            "severity": dict(sorted(Counter(rows[index]["severity_target"] for index in indices).items())),
            "sources": dict(sorted(Counter(rows[index]["provider_file"] for index in indices).items())),
        }
        for role, indices in role_sets.items()
    }
    required_diversity = all(
        len(distributions[role]["queue"]) == 2
        for role in ROLE_NAMES
    )
    passed = (
        all(role_sets[role] for role in ROLE_NAMES)
        and not any(pairwise_overlap.values())
        and not any(group_overlap.values())
        and required_diversity
    )
    return {
        "passed": passed,
        "partition_sizes": {role: len(values) for role, values in role_sets.items()},
        "pairwise_row_overlap": pairwise_overlap,
        "pairwise_group_overlap": group_overlap,
        "target_distributions": distributions,
        "required_queue_class_diversity": required_diversity,
    }


def build_development_partition(
    dataset: dict[str, Any],
    *,
    split_mode: str,
) -> dict[str, Any]:
    if split_mode not in SPLIT_MODES:
        raise ValueError(f"Unknown v4.1 development split: {split_mode}")
    rows = dataset["rows"]
    mapped_mode = {
        "time_holdout": "temporal_holdout",
        "source_group_holdout": "source_holdout",
    }.get(split_mode, split_mode)
    frozen = v398.build_frozen_partition(
        rows,
        split_mode=mapped_mode,
        final_test_size=0.15,
        calibration_size=0.15,
        threshold_size=0.15,
    )
    roles = {role: list(frozen.get(role) or []) for role in ROLE_NAMES}
    audit = audit_development_partition(rows, roles)
    detailed_audit = v398.audit_partition_leakage(rows, frozen)
    ready = frozen.get("status") == "partitioned" and audit["passed"] and detailed_audit.get("passed")
    return {
        "status": "ready" if ready else "failed_closed",
        "split_mode": split_mode,
        "mapped_split_mode": mapped_mode,
        **roles,
        "quarantined_idx": list(frozen.get("quarantined_idx") or []),
        "partition_id": frozen.get("partition_id"),
        "partition_method": frozen.get("partition_method"),
        "audit": audit,
        "detailed_leakage_audit": detailed_audit,
        "provider_labels_used_for": ["development_fit", "development_calibration", "development_threshold", "development_test"],
        "v400_final_labels_used": False,
    }


def _build_model_pipeline(
    *,
    model_type: str,
    numeric_features: Sequence[str],
    categorical_features: Sequence[str],
    random_state: int,
) -> Any:
    from sklearn.compose import ColumnTransformer
    from sklearn.ensemble import ExtraTreesClassifier
    from sklearn.impute import SimpleImputer
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import OneHotEncoder, StandardScaler

    numeric_steps: list[tuple[str, Any]] = [("imputer", SimpleImputer(strategy="median", keep_empty_features=True))]
    if model_type == "logistic_regression":
        numeric_steps.append(("scaler", StandardScaler()))
    preprocess = ColumnTransformer(
        transformers=[
            ("numeric", Pipeline(numeric_steps), list(numeric_features)),
            (
                "categorical",
                Pipeline(
                    [
                        ("imputer", SimpleImputer(strategy="constant", fill_value="unavailable")),
                        ("onehot", OneHotEncoder(handle_unknown="ignore")),
                    ]
                ),
                list(categorical_features),
            ),
        ]
    )
    if model_type == "extra_trees":
        classifier: Any = ExtraTreesClassifier(
            n_estimators=240,
            min_samples_leaf=2,
            class_weight="balanced_subsample",
            random_state=random_state,
            n_jobs=-1,
        )
    elif model_type == "logistic_regression":
        classifier = LogisticRegression(
            max_iter=1_500,
            class_weight="balanced",
            random_state=random_state,
        )
    else:
        raise ValueError(f"Unsupported v4.1 model type: {model_type}")
    return Pipeline([("preprocess", preprocess), ("model", classifier)])


def _classes(model: Any) -> list[str]:
    classes = getattr(model, "classes_", None)
    if classes is None and hasattr(model, "named_steps"):
        classes = getattr(model.named_steps.get("model"), "classes_", None)
    return [] if classes is None else [str(value) for value in classes]


def _calibrate_prefit(model: Any, frame: Any, indices: Sequence[int], targets: Sequence[str]) -> Any:
    from sklearn.calibration import CalibratedClassifierCV

    calibration_targets = [targets[index] for index in indices]
    if len(set(calibration_targets)) < 2:
        raise ValueError("Dedicated calibration role must contain at least two classes")
    try:
        # scikit-learn 1.6's FrozenEstimator path still invokes
        # cross_val_predict for multiclass string labels. The explicit prefit
        # branch keeps the dedicated calibration role separate and is stable
        # for the version pinned by ATDR.
        calibrated = CalibratedClassifierCV(model, method="sigmoid", cv="prefit")
        with warnings.catch_warnings():
            warnings.filterwarnings("ignore", message="The `cv='prefit'` option is deprecated")
            calibrated.fit(frame.iloc[list(indices)], calibration_targets)
    except (TypeError, ValueError):  # pragma: no cover - future sklearn compatibility
        from sklearn.frozen import FrozenEstimator

        calibrated = CalibratedClassifierCV(FrozenEstimator(model), method="sigmoid")
        calibrated.fit(frame.iloc[list(indices)], calibration_targets)
    return calibrated


def _queue_scores(model: Any, frame: Any, indices: Sequence[int]) -> list[float]:
    classes = _classes(model)
    if "needs_review" not in classes:
        return [0.0 for _index in indices]
    position = classes.index("needs_review")
    probabilities = model.predict_proba(frame.iloc[list(indices)])
    return [float(row[position]) for row in probabilities]


def _severity_queue_scores(model: Any, frame: Any, indices: Sequence[int]) -> tuple[list[float], list[str]]:
    classes = _classes(model)
    probabilities = model.predict_proba(frame.iloc[list(indices)])
    benign_position = classes.index("benign") if "benign" in classes else None
    scores = [1.0 - float(row[benign_position]) if benign_position is not None else 1.0 for row in probabilities]
    predictions = [classes[max(range(len(row)), key=lambda index: float(row[index]))] for row in probabilities]
    return scores, predictions


def _evaluate_candidate(
    dataset: dict[str, Any],
    partition: dict[str, Any],
    *,
    name: str,
    scores: list[float],
    threshold_selection: dict[str, Any],
    seed: int,
    details: dict[str, Any] | None = None,
    severity_predictions: list[str] | None = None,
) -> dict[str, Any]:
    indices = list(partition["final_test_idx"])
    truth = [dataset["targets"][index] for index in indices]
    threshold = float(threshold_selection.get("selected_threshold", 0.5))
    predictions = ["needs_review" if score >= threshold else "non_threat" for score in scores]
    metrics = v398._binary_metrics(truth, predictions)
    metrics.update(v398._diagnostic_original_recall(dataset["rows"], indices, predictions))
    if severity_predictions is not None:
        exact: dict[str, Any] = {}
        for label in ("suspicious", "malicious"):
            positions = [
                position
                for position, index in enumerate(indices)
                if dataset["rows"][index]["original_label"] == label
            ]
            exact[label] = {
                "support": len(positions),
                "exact_recall": (
                    round(sum(1 for position in positions if severity_predictions[position] == label) / len(positions), 4)
                    if positions
                    else None
                ),
            }
        metrics["exact_severity_recall"] = exact
    return {
        "name": name,
        "status": "evaluated",
        "threshold_selection": threshold_selection,
        "metrics": metrics,
        "calibration": v398._calibration_report(truth, scores),
        "bootstrap_95_percent": v398._bootstrap_intervals(truth, predictions, seed=seed),
        "error_patterns": v398._error_patterns(dataset["rows"], indices, truth, predictions),
        "details": details or {},
        "_scores": scores,
        "_predictions": predictions,
    }


def _fit_binary_model(
    dataset: dict[str, Any],
    partition: dict[str, Any],
    *,
    model_type: str,
    calibrate: bool,
    random_state: int,
) -> dict[str, Any]:
    frame = dataset["frame"]
    targets = dataset["targets"]
    pipeline = _build_model_pipeline(
        model_type=model_type,
        numeric_features=dataset["feature_meta"]["numeric_features"],
        categorical_features=dataset["feature_meta"]["categorical_features"],
        random_state=random_state,
    )
    fit_idx = list(partition["fit_idx"])
    started = time.perf_counter()
    pipeline.fit(frame.iloc[fit_idx], [targets[index] for index in fit_idx])
    model = (
        _calibrate_prefit(pipeline, frame, partition["calibration_idx"], targets)
        if calibrate
        else pipeline
    )
    threshold_scores = _queue_scores(model, frame, partition["threshold_idx"])
    threshold = v398.select_threshold(
        [targets[index] for index in partition["threshold_idx"]],
        threshold_scores,
    )
    return {
        "model": model,
        "threshold_selection": threshold,
        "threshold_scores": threshold_scores,
        "final_scores": _queue_scores(model, frame, partition["final_test_idx"]),
        "model_type": model_type,
        "calibration_method": "sigmoid_dedicated_role" if calibrate else "uncalibrated",
        "training_seconds": round(time.perf_counter() - started, 4),
        "active_artifact_written": False,
    }


def _fit_three_class_model(
    dataset: dict[str, Any],
    partition: dict[str, Any],
    *,
    random_state: int,
) -> dict[str, Any]:
    frame = dataset["frame"]
    severity_targets = dataset["severity_targets"]
    pipeline = _build_model_pipeline(
        model_type="extra_trees",
        numeric_features=dataset["feature_meta"]["numeric_features"],
        categorical_features=dataset["feature_meta"]["categorical_features"],
        random_state=random_state,
    )
    fit_idx = list(partition["fit_idx"])
    started = time.perf_counter()
    pipeline.fit(frame.iloc[fit_idx], [severity_targets[index] for index in fit_idx])
    model = _calibrate_prefit(pipeline, frame, partition["calibration_idx"], severity_targets)
    threshold_scores, _threshold_severity = _severity_queue_scores(model, frame, partition["threshold_idx"])
    threshold = v398.select_threshold(
        [dataset["targets"][index] for index in partition["threshold_idx"]],
        threshold_scores,
    )
    final_scores, severity_predictions = _severity_queue_scores(model, frame, partition["final_test_idx"])
    return {
        "model": model,
        "threshold_selection": threshold,
        "final_scores": final_scores,
        "severity_predictions": severity_predictions,
        "calibration_method": "sigmoid_multiclass_dedicated_role",
        "training_seconds": round(time.perf_counter() - started, 4),
        "active_artifact_written": False,
    }


def _fit_anomaly_model(dataset: dict[str, Any], partition: dict[str, Any], *, random_state: int) -> dict[str, Any]:
    from sklearn.ensemble import IsolationForest
    from sklearn.impute import SimpleImputer
    from sklearn.pipeline import Pipeline

    numeric = list(dataset["feature_meta"]["numeric_features"])
    frame = dataset["frame"]
    targets = dataset["targets"]
    benign_fit = [index for index in partition["fit_idx"] if targets[index] == "non_threat"]
    fit_indices = benign_fit or list(partition["fit_idx"])
    model = Pipeline(
        [
            ("imputer", SimpleImputer(strategy="median", keep_empty_features=True)),
            ("model", IsolationForest(n_estimators=160, contamination="auto", random_state=random_state, n_jobs=-1)),
        ]
    )
    model.fit(frame.iloc[fit_indices][numeric])
    calibration_raw = [
        -float(value)
        for value in model.decision_function(frame.iloc[list(partition["calibration_idx"])][numeric])
    ]
    reference = sorted(calibration_raw)

    def percentile(indices: Sequence[int]) -> list[float]:
        raw = [-float(value) for value in model.decision_function(frame.iloc[list(indices)][numeric])]
        if not reference:
            return [0.5 for _value in raw]
        return [sum(1 for item in reference if item <= value) / len(reference) for value in raw]

    threshold_scores = percentile(partition["threshold_idx"])
    threshold = v398.select_threshold(
        [targets[index] for index in partition["threshold_idx"]],
        threshold_scores,
    )
    return {
        "model": model,
        "threshold_selection": threshold,
        "threshold_scores": threshold_scores,
        "final_scores": percentile(partition["final_test_idx"]),
        "fit_policy": "benign_development_fit_rows_only",
        "scaling": "empirical_percentile_from_dedicated_calibration_role",
        "active_artifact_written": False,
    }


def _flow_rule_scores(
    dataset: dict[str, Any],
    fit_indices: Sequence[int],
    score_indices: Sequence[int],
) -> tuple[list[float], dict[str, Any]]:
    frame = dataset["common_frame"]
    fit = frame.iloc[list(fit_indices)]
    byte_threshold = float(fit["total_bytes"].quantile(0.995))
    packet_threshold = float(fit["packets"].quantile(0.995))
    scores: list[float] = []
    for _index, row in frame.iloc[list(score_indices)].iterrows():
        score = 0.0
        if math.isfinite(float(row["total_bytes"])) and float(row["total_bytes"]) > byte_threshold:
            score += 0.5
        if math.isfinite(float(row["packets"])) and float(row["packets"]) > packet_threshold:
            score += 0.5
        scores.append(score)
    contract = get_schema_contract("provider_flow")
    applicable = {
        name: status
        for name, status in contract.rule_applicability.items()
        if status.startswith("applicable")
    }
    unavailable = {
        name: status
        for name, status in contract.rule_applicability.items()
        if not status.startswith("applicable")
    }
    return scores, {
        "byte_threshold": byte_threshold,
        "packet_threshold": packet_threshold,
        "threshold_source": "development_fit_features_only",
        "applicable_rules": applicable,
        "unavailable_rules": unavailable,
        "unavailable_rules_scored_as_negative": False,
    }


def evaluate_flow_split(dataset: dict[str, Any], *, split_mode: str) -> dict[str, Any]:
    partition = build_development_partition(dataset, split_mode=split_mode)
    if partition["status"] != "ready":
        return {"split_mode": split_mode, "status": "failed_closed", "partition": partition, "strategies": []}
    seed = DEFAULT_SEED if split_mode in {"time_holdout", "source_group_holdout"} else int(split_mode.rsplit("_", 1)[-1])
    raw_extra_trees = _fit_binary_model(
        dataset,
        partition,
        model_type="extra_trees",
        calibrate=False,
        random_state=seed,
    )
    calibrated_extra_trees = _fit_binary_model(
        dataset,
        partition,
        model_type="extra_trees",
        calibrate=True,
        random_state=seed,
    )
    calibrated_logistic = _fit_binary_model(
        dataset,
        partition,
        model_type="logistic_regression",
        calibrate=True,
        random_state=seed,
    )
    three_class = _fit_three_class_model(dataset, partition, random_state=seed)
    anomaly = _fit_anomaly_model(dataset, partition, random_state=seed)
    threshold_rule_scores, rule_meta = _flow_rule_scores(
        dataset,
        partition["fit_idx"],
        partition["threshold_idx"],
    )
    final_rule_scores, _final_rule_meta = _flow_rule_scores(
        dataset,
        partition["fit_idx"],
        partition["final_test_idx"],
    )
    rule_threshold = v398.select_threshold(
        [dataset["targets"][index] for index in partition["threshold_idx"]],
        threshold_rule_scores,
    )
    threshold_hybrid_scores = [
        (0.70 * supervised) + (0.20 * anomaly_score) + (0.10 * rule_score)
        for supervised, anomaly_score, rule_score in zip(
            calibrated_extra_trees["threshold_scores"],
            anomaly["threshold_scores"],
            threshold_rule_scores,
            strict=True,
        )
    ]
    hybrid_threshold = v398.select_threshold(
        [dataset["targets"][index] for index in partition["threshold_idx"]],
        threshold_hybrid_scores,
    )
    final_hybrid_scores = [
        (0.70 * supervised) + (0.20 * anomaly_score) + (0.10 * rule_score)
        for supervised, anomaly_score, rule_score in zip(
            calibrated_extra_trees["final_scores"],
            anomaly["final_scores"],
            final_rule_scores,
            strict=True,
        )
    ]
    strategies = [
        _evaluate_candidate(
            dataset,
            partition,
            name="provider_flow_extra_trees_raw",
            scores=raw_extra_trees["final_scores"],
            threshold_selection=raw_extra_trees["threshold_selection"],
            seed=seed,
            details={"calibration": raw_extra_trees["calibration_method"]},
        ),
        _evaluate_candidate(
            dataset,
            partition,
            name="provider_flow_calibrated_extra_trees",
            scores=calibrated_extra_trees["final_scores"],
            threshold_selection=calibrated_extra_trees["threshold_selection"],
            seed=seed,
            details={"calibration": calibrated_extra_trees["calibration_method"]},
        ),
        _evaluate_candidate(
            dataset,
            partition,
            name="provider_flow_calibrated_logistic",
            scores=calibrated_logistic["final_scores"],
            threshold_selection=calibrated_logistic["threshold_selection"],
            seed=seed,
            details={"calibration": calibrated_logistic["calibration_method"]},
        ),
        _evaluate_candidate(
            dataset,
            partition,
            name="provider_flow_three_class_soc_queue",
            scores=three_class["final_scores"],
            threshold_selection=three_class["threshold_selection"],
            seed=seed,
            details={"calibration": three_class["calibration_method"]},
            severity_predictions=three_class["severity_predictions"],
        ),
        _evaluate_candidate(
            dataset,
            partition,
            name="provider_flow_isolation_forest",
            scores=anomaly["final_scores"],
            threshold_selection=anomaly["threshold_selection"],
            seed=seed,
            details={"fit_policy": anomaly["fit_policy"]},
        ),
        _evaluate_candidate(
            dataset,
            partition,
            name="provider_flow_applicable_rules",
            scores=final_rule_scores,
            threshold_selection=rule_threshold,
            seed=seed,
            details=rule_meta,
        ),
        _evaluate_candidate(
            dataset,
            partition,
            name="provider_flow_rule_anomaly_supervised_hybrid",
            scores=final_hybrid_scores,
            threshold_selection=hybrid_threshold,
            seed=seed,
            details={
                "weights": {"supervised": 0.70, "anomaly": 0.20, "applicable_rules": 0.10},
                "unavailable_rules_scored_as_negative": False,
            },
        ),
    ]
    return {
        "split_mode": split_mode,
        "status": "evaluated",
        "partition": partition,
        "strategies": strategies,
        "v400_locked_rows_used": 0,
        "active_artifact_written": False,
    }


def _internal_split_mode(split_mode: str) -> str:
    if split_mode == "time_holdout":
        return "temporal_holdout"
    if split_mode == "source_group_holdout":
        return "source_holdout"
    return split_mode


def _internal_partition(internal_dataset: dict[str, Any], split_mode: str) -> dict[str, Any]:
    # v3.98 assigns these groups in its public runner rather than its dataset
    # builder. v4.1 reuses the builder directly, so establish the same
    # in-memory-only leakage boundary before creating any split.
    if any("leakage_group" not in row for row in internal_dataset["rows"]):
        v398.assign_leakage_groups(internal_dataset["rows"])
    internal_mode = _internal_split_mode(split_mode)
    partition = v398.build_frozen_partition(internal_dataset["rows"], split_mode=internal_mode)
    leakage = v398.audit_partition_leakage(internal_dataset["rows"], partition)
    if partition.get("status") == "failed" or not leakage.get("passed"):
        return {
            "status": "failed_closed",
            "split_mode": internal_mode,
            "partition": partition,
            "leakage_audit": leakage,
        }
    return {
        "status": "ready",
        "split_mode": internal_mode,
        "partition": partition,
        "leakage_audit": leakage,
    }


def evaluate_firewall_split(internal_dataset: dict[str, Any], *, split_mode: str) -> dict[str, Any]:
    prepared = _internal_partition(internal_dataset, split_mode)
    if prepared["status"] != "ready":
        return {
            "split_mode": split_mode,
            "internal_split_mode": prepared["split_mode"],
            "status": "failed_closed",
            "leakage_audit": prepared["leakage_audit"],
            "strategies": [],
        }
    seed = DEFAULT_SEED if split_mode in {"time_holdout", "source_group_holdout"} else int(split_mode.rsplit("_", 1)[-1])
    partition = prepared["partition"]
    candidate = v398._fit_supervised_candidate(
        internal_dataset,
        partition,
        model_type="extra_trees",
        calibrate=True,
    )
    result = v398._evaluate_scores(
        internal_dataset,
        partition,
        name="firewall_specific_calibrated_extra_trees",
        scores=candidate["final_scores"],
        threshold_selection=candidate["threshold_selection"],
        seed=seed,
        details={
            "schema_id": "palo_alto",
            "calibration": candidate["calibration_method"],
            "active_artifact_written": False,
        },
    )
    return {
        "split_mode": split_mode,
        "internal_split_mode": prepared["split_mode"],
        "status": "evaluated",
        "partition": partition,
        "leakage_audit": prepared["leakage_audit"],
        "strategies": [result],
        "active_artifact_written": False,
    }


def build_pooled_common_dataset(internal_dataset: dict[str, Any], flow_dataset: dict[str, Any]) -> dict[str, Any]:
    pd = internal_dataset["imports"][1]
    firewall_frame = build_firewall_common_frame(internal_dataset)
    flow_frame = flow_dataset["common_frame"].copy()
    frame = pd.concat([firewall_frame, flow_frame], ignore_index=True)
    rows: list[dict[str, Any]] = []
    targets: list[str] = []
    severity_targets: list[str] = []
    for index, row in enumerate(internal_dataset["rows"]):
        original = str(row["original_label"])
        severity = original if original in {"suspicious", "malicious"} else "benign"
        rows.append(
            dict(row)
            | {
                "index": index,
                "schema_id": "palo_alto",
                "severity_target": severity,
                "provider_file": "internal_firewall_reviewed",
            }
        )
        targets.append(str(internal_dataset["targets"][index]))
        severity_targets.append(severity)
    offset = len(rows)
    for flow_index, row in enumerate(flow_dataset["rows"]):
        rows.append(dict(row) | {"index": offset + flow_index})
        targets.append(str(flow_dataset["targets"][flow_index]))
        severity_targets.append(str(flow_dataset["severity_targets"][flow_index]))
    return {
        "ok": True,
        "imports": internal_dataset["imports"],
        "frame": frame,
        "rows": rows,
        "targets": targets,
        "severity_targets": severity_targets,
        "feature_meta": {
            "numeric_features": list(COMMON_NUMERIC_FEATURES),
            "categorical_features": list(COMMON_CATEGORICAL_FEATURES),
            "schema_contracts": public_schema_contracts(),
        },
        "firewall_rows": len(internal_dataset["rows"]),
        "flow_rows": len(flow_dataset["rows"]),
        "flow_offset": offset,
    }


def _pooled_partition(
    pooled: dict[str, Any],
    internal_dataset: dict[str, Any],
    flow_dataset: dict[str, Any],
    *,
    split_mode: str,
) -> dict[str, Any]:
    internal = _internal_partition(internal_dataset, split_mode)
    flow = build_development_partition(flow_dataset, split_mode=split_mode)
    if internal["status"] != "ready" or flow["status"] != "ready":
        return {
            "status": "failed_closed",
            "split_mode": split_mode,
            "internal_status": internal["status"],
            "flow_status": flow["status"],
        }
    offset = int(pooled["flow_offset"])
    combined = {
        role: sorted(
            [*internal["partition"][role], *[offset + index for index in flow[role]]]
        )
        for role in ROLE_NAMES
    }
    role_sets = {role: set(values) for role, values in combined.items()}
    overlap = sum(
        len(role_sets[left] & role_sets[right])
        for position, left in enumerate(ROLE_NAMES)
        for right in ROLE_NAMES[position + 1 :]
    )
    return {
        "status": "ready" if not overlap else "failed_closed",
        "split_mode": split_mode,
        **combined,
        "row_overlap_count": overlap,
        "internal_split_mode": internal["split_mode"],
        "v400_final_rows_used": 0,
    }


def evaluate_pooled_schema_split(
    pooled: dict[str, Any],
    internal_dataset: dict[str, Any],
    flow_dataset: dict[str, Any],
    *,
    split_mode: str,
) -> dict[str, Any]:
    partition = _pooled_partition(
        pooled,
        internal_dataset,
        flow_dataset,
        split_mode=split_mode,
    )
    if partition["status"] != "ready":
        return {"split_mode": split_mode, "status": "failed_closed", "partition": partition, "strategies": []}
    seed = int(split_mode.rsplit("_", 1)[-1]) if split_mode.startswith("random_seed_") else DEFAULT_SEED
    candidate = _fit_binary_model(
        pooled,
        partition,
        model_type="extra_trees",
        calibrate=True,
        random_state=seed,
    )
    result = _evaluate_candidate(
        pooled,
        partition,
        name="pooled_schema_aware_calibrated_extra_trees",
        scores=candidate["final_scores"],
        threshold_selection=candidate["threshold_selection"],
        seed=seed,
        details={
            "schemas_trained": ["palo_alto", "provider_flow"],
            "schema_availability_indicators": True,
            "calibration": candidate["calibration_method"],
        },
    )
    return {
        "split_mode": split_mode,
        "status": "evaluated",
        "partition": partition,
        "strategies": [result],
        "active_artifact_written": False,
    }


def evaluate_schema_holdout(
    pooled: dict[str, Any],
    internal_dataset: dict[str, Any],
    flow_dataset: dict[str, Any],
    *,
    heldout_schema: str,
) -> dict[str, Any]:
    if heldout_schema not in {"provider_flow", "palo_alto"}:
        raise ValueError(f"Unsupported schema holdout: {heldout_schema}")
    internal = _internal_partition(internal_dataset, "random_seed_42")
    flow = build_development_partition(flow_dataset, split_mode="random_seed_42")
    if internal["status"] != "ready" or flow["status"] != "ready":
        return {"split_mode": f"schema_holdout_{heldout_schema}", "status": "failed_closed", "strategies": []}
    offset = int(pooled["flow_offset"])
    if heldout_schema == "provider_flow":
        partition = {
            "fit_idx": list(internal["partition"]["fit_idx"]),
            "calibration_idx": list(internal["partition"]["calibration_idx"]),
            "threshold_idx": list(internal["partition"]["threshold_idx"]),
            "final_test_idx": list(range(offset, len(pooled["rows"]))),
        }
        trained_schema = "palo_alto"
    else:
        partition = {
            "fit_idx": [offset + index for index in flow["fit_idx"]],
            "calibration_idx": [offset + index for index in flow["calibration_idx"]],
            "threshold_idx": [offset + index for index in flow["threshold_idx"]],
            "final_test_idx": list(range(offset)),
        }
        trained_schema = "provider_flow"
    candidate = _fit_binary_model(
        pooled,
        partition,
        model_type="extra_trees",
        calibrate=True,
        random_state=401,
    )
    result = _evaluate_candidate(
        pooled,
        partition,
        name=f"schema_heldout_{heldout_schema}_common_feature_extra_trees",
        scores=candidate["final_scores"],
        threshold_selection=candidate["threshold_selection"],
        seed=401,
        details={
            "trained_schema": trained_schema,
            "heldout_schema": heldout_schema,
            "heldout_schema_rows_used_for_fit_calibration_threshold": 0,
            "purpose": "domain_transfer_diagnostic_not_candidate_selection",
        },
    )
    return {
        "split_mode": f"schema_holdout_{heldout_schema}",
        "status": "evaluated",
        "partition_sizes": {role: len(indices) for role, indices in partition.items()},
        "strategies": [result],
        "active_artifact_written": False,
    }


def _find_strategy(split: dict[str, Any], name: str) -> dict[str, Any] | None:
    return next((item for item in split.get("strategies", []) if item.get("name") == name), None)


def combine_schema_routed_result(
    internal_dataset: dict[str, Any],
    flow_dataset: dict[str, Any],
    firewall_split: dict[str, Any],
    flow_split: dict[str, Any],
    *,
    split_mode: str,
) -> dict[str, Any]:
    firewall = _find_strategy(firewall_split, "firewall_specific_calibrated_extra_trees")
    flow = _find_strategy(flow_split, "provider_flow_calibrated_extra_trees")
    if firewall is None or flow is None:
        return {"split_mode": split_mode, "status": "failed_closed", "strategies": []}
    firewall_indices = list(firewall_split["partition"]["final_test_idx"])
    flow_indices = list(flow_split["partition"]["final_test_idx"])
    truth = [internal_dataset["targets"][index] for index in firewall_indices] + [
        flow_dataset["targets"][index] for index in flow_indices
    ]
    predictions = [*firewall["_predictions"], *flow["_predictions"]]
    scores = [*firewall["_scores"], *flow["_scores"]]
    combined_rows = [internal_dataset["rows"][index] for index in firewall_indices] + [
        flow_dataset["rows"][index] for index in flow_indices
    ]
    metrics = v398._binary_metrics(truth, predictions)
    diagnostic_rows = [
        dict(row) | {"original_label": str(row["original_label"])}
        for row in combined_rows
    ]
    metrics.update(v398._diagnostic_original_recall(diagnostic_rows, list(range(len(diagnostic_rows))), predictions))
    result = {
        "name": "schema_routed_firewall_plus_flow_ensemble",
        "status": "evaluated",
        "threshold_selection": {
            "status": "branch_specific",
            "firewall": firewall["threshold_selection"],
            "provider_flow": flow["threshold_selection"],
            "used_v400_final_labels": False,
        },
        "metrics": metrics,
        "calibration": v398._calibration_report(truth, scores),
        "bootstrap_95_percent": v398._bootstrap_intervals(truth, predictions, seed=401),
        "details": {
            "router": "explicit_schema_id",
            "fallback_policy": "unknown_schema_requires_review_no_model_guess",
            "firewall_rows": len(firewall_indices),
            "provider_flow_rows": len(flow_indices),
            "active_artifact_written": False,
        },
        "_scores": scores,
        "_predictions": predictions,
    }
    return {
        "split_mode": split_mode,
        "status": "evaluated",
        "strategies": [result],
        "active_artifact_written": False,
    }


def _public_strategy(strategy: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in strategy.items() if not key.startswith("_")}


def _public_split(split: dict[str, Any]) -> dict[str, Any]:
    return {
        key: ([_public_strategy(item) for item in value] if key == "strategies" else value)
        for key, value in split.items()
        if not key.startswith("_")
    }


def build_strategy_comparison(split_results: Sequence[dict[str, Any]]) -> dict[str, Any]:
    names = sorted(
        {
            str(strategy["name"])
            for split in split_results
            for strategy in split.get("strategies", [])
            if strategy.get("status") == "evaluated"
        }
    )
    comparison: dict[str, Any] = {}
    metrics_to_range = (
        "queue_precision",
        "queue_recall",
        "queue_f1",
        "benign_like_false_positive_rate",
        "suspicious_recall",
        "malicious_recall",
        "macro_f1",
        "weighted_f1",
        "review_queue_rate",
    )
    for name in names:
        rows: list[dict[str, Any]] = []
        for split in split_results:
            for strategy in split.get("strategies", []):
                if strategy.get("name") == name and strategy.get("status") == "evaluated":
                    rows.append(
                        {
                            "split_mode": split["split_mode"],
                            **strategy["metrics"],
                            "calibration": strategy["calibration"],
                        }
                    )
        ranges: dict[str, Any] = {}
        for metric in metrics_to_range:
            values = [float(row[metric]) for row in rows if row.get(metric) is not None]
            ranges[metric] = {
                "min": round(min(values), 4) if values else None,
                "max": round(max(values), 4) if values else None,
            }
        comparison[name] = {
            "evaluated_splits": len(rows),
            "metric_ranges": ranges,
            "calibration_passed_splits": sum(1 for row in rows if row["calibration"].get("passed")),
            "split_metrics": rows,
        }
    return comparison


def select_diagnostic_candidates(comparison: dict[str, Any]) -> dict[str, Any]:
    def rank(item: tuple[str, dict[str, Any]]) -> tuple[float, float, float, int]:
        _name, value = item
        ranges = value["metric_ranges"]
        worst_f1 = float((ranges["queue_f1"] or {}).get("min") or 0.0)
        worst_recall = float((ranges["queue_recall"] or {}).get("min") or 0.0)
        worst_fpr = float((ranges["benign_like_false_positive_rate"] or {}).get("max") or 1.0)
        return (
            round(worst_f1 - (0.50 * worst_fpr), 6),
            worst_f1,
            worst_recall,
            int(value["calibration_passed_splits"]),
        )

    eligible = [(name, value) for name, value in comparison.items() if int(value["evaluated_splits"]) >= 3]
    cross_schema = [item for item in eligible if item[0].startswith(("schema_routed_", "pooled_schema_aware_"))]
    best_overall = max(eligible, key=rank) if eligible else None
    best_cross = max(cross_schema, key=rank) if cross_schema else None

    def public(item: tuple[str, dict[str, Any]] | None) -> dict[str, Any] | None:
        if item is None:
            return None
        name, value = item
        return {
            "name": name,
            "selection_score": rank(item)[0],
            "evaluated_splits": value["evaluated_splits"],
            "metric_ranges": value["metric_ranges"],
            "calibration_passed_splits": value["calibration_passed_splits"],
            "selection_scope": "development_only_not_activation",
        }

    return {
        "best_overall_development_diagnostic": public(best_overall),
        "best_cross_schema_diagnostic": public(best_cross),
        "selection_used_v400_final_labels": False,
        "activation_allowed": False,
    }


def _worst_split_for_candidate(
    split_results: Sequence[dict[str, Any]],
    candidate_name: str | None,
) -> dict[str, Any] | None:
    if not candidate_name:
        return None
    rows: list[dict[str, Any]] = []
    for split in split_results:
        for strategy in split.get("strategies", []):
            if strategy.get("name") == candidate_name and strategy.get("status") == "evaluated":
                rows.append(
                    {
                        "split_mode": split["split_mode"],
                        "metrics": strategy["metrics"],
                        "calibration": strategy["calibration"],
                    }
                )
    if not rows:
        return None
    return min(
        rows,
        key=lambda row: (
            float(row["metrics"]["queue_f1"]),
            -float(row["metrics"]["benign_like_false_positive_rate"]),
        ),
    )


def _render_report(result: dict[str, Any]) -> str:
    best_overall = result["diagnostic_selection"].get("best_overall_development_diagnostic") or {}
    best_cross = result["diagnostic_selection"].get("best_cross_schema_diagnostic") or {}
    lines = [
        "# v4.1 Schema-Aware SOC Queue Model Redesign",
        "",
        f"Generated: {result['generated_at']}",
        "",
        "This is development-only diagnostic evidence. It does not replace the locked v4.0 final benchmark and does not authorize model activation or response automation.",
        "",
        "## Evidence Boundary",
        "",
        f"- v4.0 evidence lock: `{result['v400_evidence_lock']['status']}`.",
        f"- Locked v4.0 rows/labels used: `0/0`.",
        f"- Development files verified: `{len(result['development_evidence']['files'])}`.",
        f"- Development sample rows accepted: `{result['development_sample']['accepted_rows']}`.",
        f"- Exact duplicate development flows quarantined: `{result['development_sample']['duplicate_rows_quarantined']}`.",
        f"- Future untouched benchmark: `{result['reserved_future_benchmark']['dataset_id']}` (`{result['reserved_future_benchmark']['status']}`).",
        "",
        "## Schema Contracts",
        "",
        "- Explicit contracts: `palo_alto`, `generic_syslog`, `provider_flow`, `raw_fallback`.",
        "- Provider-flow unavailable firewall fields are represented by availability indicators, not invented values.",
        "- Unsupported rule families remain unavailable and are not scored as benign evidence.",
        "",
        "## Diagnostic Selection",
        "",
        f"- Best overall development diagnostic: `{best_overall.get('name')}`.",
        f"- Best cross-schema diagnostic: `{best_cross.get('name')}`.",
        f"- Worst cross-schema split: `{(result.get('worst_cross_schema_split') or {}).get('split_mode')}`.",
        "",
        "## Stability Ranges",
        "",
        "| Strategy | Splits | F1 min-max | FPR min-max | Recall min-max | Calibration passed |",
        "| --- | ---: | --- | --- | --- | ---: |",
    ]
    for name, comparison in sorted(result["strategy_comparison"].items()):
        ranges = comparison["metric_ranges"]
        lines.append(
            "| {name} | {splits} | {f1min}-{f1max} | {fprmin}-{fprmax} | {rmin}-{rmax} | {cal} |".format(
                name=name,
                splits=comparison["evaluated_splits"],
                f1min=ranges["queue_f1"]["min"],
                f1max=ranges["queue_f1"]["max"],
                fprmin=ranges["benign_like_false_positive_rate"]["min"],
                fprmax=ranges["benign_like_false_positive_rate"]["max"],
                rmin=ranges["queue_recall"]["min"],
                rmax=ranges["queue_recall"]["max"],
                cal=comparison["calibration_passed_splits"],
            )
        )
    lines.extend(
        [
            "",
            "## Readiness",
            "",
            "Decision: `candidate_only`.",
            "",
            "- No model was activated or promoted.",
            "- No active model artifact was written.",
            "- No operational labels, detections, or response actions were created.",
            "- Automatic response and real firewall blocking remain disabled.",
            "- A later one-time final validation requires the reserved untouched provider benchmark and explicit approval.",
            "",
        ]
    )
    return "\n".join(lines)


def run_v401_schema_aware_soc_queue(
    db: Session,
    *,
    development_dir: Path = V401_DEVELOPMENT_DIR,
    output_dir: Path = V401_OUTPUT_DIR,
    rows_per_provider_label: int = DEFAULT_ROWS_PER_PROVIDER_LABEL,
    seed: int = DEFAULT_SEED,
    min_samples: int = 100,
    write_output: bool = True,
) -> dict[str, Any]:
    started = time.perf_counter()
    generated_at = _utc_now()
    stamp = _stamp()
    before_counts = v398._database_counts(db)
    before_artifact = v398._artifact_state()
    before_session = {
        "new": len(db.new),
        "dirty": len(db.dirty),
        "deleted": len(db.deleted),
    }
    v400_lock_before = verify_v400_evidence_lock()
    if not v400_lock_before["ok"]:
        return {
            "ok": False,
            "status": "failed_closed",
            "message": "Locked v4.0 evidence identity is missing or changed",
            "v400_evidence_lock": v400_lock_before,
            "readiness": {"decision": "candidate_only"},
        }
    development_verification = verify_development_files(development_dir)
    if not development_verification["ok"]:
        return {
            "ok": False,
            "status": development_verification["status"],
            "message": development_verification["message"],
            "development_evidence": development_verification,
            "readiness": {"decision": "candidate_only"},
        }
    internal_dataset = v398._build_dataset(db, min_samples=min_samples)
    if not internal_dataset.get("ok"):
        return {
            "ok": False,
            "status": internal_dataset.get("status", "failed_closed"),
            "message": internal_dataset.get("message", "Internal reviewed dataset is unavailable"),
            "readiness": {"decision": "candidate_only"},
        }
    internal_leakage_group_summary = v398.assign_leakage_groups(internal_dataset["rows"])
    sample = build_development_sample(
        development_dir,
        rows_per_provider_label=rows_per_provider_label,
        seed=seed,
        stamp=stamp,
    )
    manifest_path = development_dir / f"v4_1_development_manifest_{stamp}.json"
    manifest_hash = _write_self_hashed_json(
        manifest_path,
        {
            "schema": DEVELOPMENT_MANIFEST_SCHEMA,
            "created_at": _utc_now(),
            "dataset": DEVELOPMENT_DATASET,
            "source_files": development_verification["files"],
            "sample_path_name": Path(sample["sample_path"]).name,
            "sample_sha256": sample["sample_sha256"],
            "sampled_rows": sample["sampled_rows"],
            "class_distribution": sample["class_distribution"],
            "queue_distribution": sample["queue_distribution"],
            "provider_label_distribution": sample["provider_label_distribution"],
            "sampling": sample["sampling"],
            "schema_contract_version": public_schema_contracts()["contract_version"],
            "development_only": True,
            "human_reviewed": False,
            "import_ready": False,
            "v400_locked_rows_used": 0,
            "v400_locked_labels_used": 0,
            "reserved_future_benchmark": RESERVED_FUTURE_BENCHMARK,
        },
    )
    flow_dataset = build_flow_development_dataset(Path(sample["sample_path"]))
    if not flow_dataset.get("ok"):
        return {
            "ok": False,
            "status": "failed_closed",
            "message": "Development flow adapter failed schema or duplicate checks",
            "flow_dataset": flow_dataset,
            "readiness": {"decision": "candidate_only"},
        }

    flow_splits = [evaluate_flow_split(flow_dataset, split_mode=mode) for mode in SPLIT_MODES]
    firewall_splits = [evaluate_firewall_split(internal_dataset, split_mode=mode) for mode in SPLIT_MODES]
    pooled = build_pooled_common_dataset(internal_dataset, flow_dataset)
    pooled_splits = [
        evaluate_pooled_schema_split(
            pooled,
            internal_dataset,
            flow_dataset,
            split_mode=mode,
        )
        for mode in ("random_seed_7", "random_seed_17", "random_seed_42")
    ]
    routed_splits = [
        combine_schema_routed_result(
            internal_dataset,
            flow_dataset,
            next(split for split in firewall_splits if split["split_mode"] == mode),
            next(split for split in flow_splits if split["split_mode"] == mode),
            split_mode=mode,
        )
        for mode in ("random_seed_7", "random_seed_17", "random_seed_42")
    ]
    schema_holdouts = [
        evaluate_schema_holdout(
            pooled,
            internal_dataset,
            flow_dataset,
            heldout_schema=schema,
        )
        for schema in ("provider_flow", "palo_alto")
    ]
    all_splits = [*flow_splits, *firewall_splits, *pooled_splits, *routed_splits, *schema_holdouts]
    comparison = build_strategy_comparison(all_splits)
    selection = select_diagnostic_candidates(comparison)
    best_cross_name = ((selection.get("best_cross_schema_diagnostic") or {}).get("name"))

    after_counts = v398._database_counts(db)
    after_artifact = v398._artifact_state()
    after_session = {
        "new": len(db.new),
        "dirty": len(db.dirty),
        "deleted": len(db.deleted),
    }
    v400_lock_after = verify_v400_evidence_lock()
    safety = {
        "database_counts_before": before_counts,
        "database_counts_after": after_counts,
        "database_counts_unchanged": before_counts == after_counts,
        "active_artifact_before": before_artifact,
        "active_artifact_after": after_artifact,
        "active_artifact_unchanged": before_artifact == after_artifact,
        "session_before": before_session,
        "session_after": after_session,
        "session_unchanged": before_session == after_session == {"new": 0, "dirty": 0, "deleted": 0},
        "v400_lock_unchanged": v400_lock_before == v400_lock_after,
        "labels_written": False,
        "model_runs_created": 0,
        "model_artifact_written": False,
        "detection_runs_created": 0,
        "response_actions_created": 0,
        "automatic_response_enabled": False,
        "real_firewall_blocking_enabled": False,
    }
    state_safe = all(
        (
            safety["database_counts_unchanged"],
            safety["active_artifact_unchanged"],
            safety["session_unchanged"],
            safety["v400_lock_unchanged"],
        )
    )
    result: dict[str, Any] = {
        "ok": state_safe,
        "status": "completed_candidate_only" if state_safe else "failed_closed_state_changed",
        "version": V401_VERSION,
        "generated_at": generated_at,
        "runtime_seconds": round(time.perf_counter() - started, 4),
        "v400_evidence_lock": v400_lock_after,
        "development_evidence": {
            "dataset": DEVELOPMENT_DATASET,
            "files": development_verification["files"],
            "role_boundary": development_verification["role_boundary"],
            "manifest_path": str(manifest_path),
            "manifest_hash": manifest_hash,
            "development_only": True,
            "v400_locked_rows_used": 0,
            "v400_locked_labels_used": 0,
        },
        "development_sample": {
            "attempted_sample_rows": sample["sampled_rows"],
            "accepted_rows": flow_dataset["accepted_rows"],
            "duplicate_rows_quarantined": flow_dataset["duplicate_rows_quarantined"],
            "schema_violation_rows": len(flow_dataset["schema_violations"]),
            "class_distribution": dict(
                sorted(Counter(row["original_label"] for row in flow_dataset["rows"]).items())
            ),
            "queue_distribution": dict(sorted(Counter(flow_dataset["targets"]).items())),
            "provider_label_distribution": dict(
                sorted(Counter(row["provider_label"] for row in flow_dataset["rows"]).items())
            ),
            "sample_sha256": sample["sample_sha256"],
            "label_integrity": flow_dataset["label_integrity"],
        },
        "internal_firewall_leakage_group_summary": internal_leakage_group_summary,
        "schema_contracts": public_schema_contracts(),
        "feature_design": {
            "flow_numeric_feature_count": len(flow_dataset["feature_meta"]["numeric_features"]),
            "flow_missingness_indicator_count": flow_dataset["feature_meta"]["missingness_indicator_count"],
            "common_numeric_features": list(COMMON_NUMERIC_FEATURES),
            "common_categorical_features": list(COMMON_CATEGORICAL_FEATURES),
            "unavailable_fields_not_invented": True,
            "unsupported_rules_scored_as_negative": False,
        },
        "evaluation": {
            "flow_splits": [_public_split(split) for split in flow_splits],
            "firewall_splits": [_public_split(split) for split in firewall_splits],
            "pooled_schema_splits": [_public_split(split) for split in pooled_splits],
            "schema_routed_splits": [_public_split(split) for split in routed_splits],
            "schema_holdout_splits": [_public_split(split) for split in schema_holdouts],
        },
        "strategy_comparison": comparison,
        "diagnostic_selection": selection,
        "worst_cross_schema_split": _worst_split_for_candidate(all_splits, best_cross_name),
        "reserved_future_benchmark": RESERVED_FUTURE_BENCHMARK,
        "readiness": {
            "decision": "candidate_only",
            "development_quality_may_not_promote_model": True,
            "production_promoted": False,
            "model_activated": False,
            "model_artifact_written": False,
            "response_automation_allowed": False,
            "real_firewall_blocking_enabled": False,
            "next_final_gate": "one_time_reserved_untouched_provider_benchmark_after_separate_approval",
        },
        "safety": safety,
    }
    reports: dict[str, str] = {}
    if write_output:
        output_dir.mkdir(parents=True, exist_ok=True)
        report_path = output_dir / f"v4_1_schema_aware_soc_queue_{stamp}.md"
        comparison_path = output_dir / f"v4_1_model_comparison_{stamp}.json"
        latest_path = output_dir / V401_LATEST
        report_path.write_text(_render_report(result), encoding="utf-8")
        _write_json(comparison_path, result)
        _write_json(latest_path, result)
        reports = {
            "report": str(report_path),
            "model_comparison": str(comparison_path),
            "latest": str(latest_path),
        }
    result["reports"] = reports
    result["runtime_seconds"] = round(time.perf_counter() - started, 4)
    return result
