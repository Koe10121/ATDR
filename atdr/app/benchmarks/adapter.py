import csv
import hashlib
import json
import random
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any


DEFAULT_FIELD_MAPPING = {
    "timestamp": "timestamp",
    "source_name": "source_name",
    "scenario": "scenario",
    "src_ip": "src_ip",
    "dst_ip": "dst_ip",
    "src_port": "src_port",
    "dst_port": "dst_port",
    "protocol": "protocol",
    "action": "action",
    "app": "app",
    "bytes": "bytes",
    "packets": "packets",
    "label": "label",
    "attack_type": "attack_type",
}

DEFAULT_LABEL_MAPPING = {
    "0": "benign",
    "1": "threat",
    "allow": "benign",
    "allowed": "benign",
    "benign": "benign",
    "normal": "benign",
    "clean": "benign",
    "attack": "threat",
    "malicious": "malicious",
    "suspicious": "suspicious",
    "threat": "threat",
}

DEFAULT_ATTACK_TYPE_MAPPING = {
    "normal": "normal",
    "benign": "normal",
    "portscan": "port_scan",
    "port_scan": "port_scan",
    "scan": "port_scan",
    "bruteforce": "brute_force",
    "brute_force": "brute_force",
    "dos": "dos_ddos",
    "ddos": "dos_ddos",
    "c2": "malware_c2",
    "malware_c2": "malware_c2",
    "exfiltration": "data_exfiltration_suspicion",
}

SNAPSHOT_SCHEMA = "atdr_benchmark_snapshot_v1"
PRIVATE_RAW_FIELDS = {
    "payload",
    "raw",
    "raw_payload",
    "message",
    "event.original",
    "http_request_body",
    "request_body",
    "response_body",
}


@dataclass(frozen=True, slots=True)
class BenchmarkRecord:
    row_number: int
    raw: dict[str, str]
    normalized: dict[str, Any]
    label: str
    attack_type: str


def load_mapping_config(path: Path | None) -> dict[str, Any]:
    if path is None:
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def load_benchmark_config(mapping_path: Path | None = None, label_path: Path | None = None) -> dict[str, Any]:
    """Load optional field and label mapping configs without requiring one combined file."""
    mapping_config = load_mapping_config(mapping_path)
    label_config = load_mapping_config(label_path)
    merged = {
        "fields": {**(mapping_config.get("fields") or {}), **(label_config.get("fields") or {})},
        "labels": {**(mapping_config.get("labels") or {}), **(label_config.get("labels") or {})},
        "attack_types": {**(mapping_config.get("attack_types") or {}), **(label_config.get("attack_types") or {})},
        "required_fields": list(
            dict.fromkeys(
                [
                    *(mapping_config.get("required_fields") or []),
                    *(label_config.get("required_fields") or []),
                ]
            )
        ),
    }
    for key, value in mapping_config.items():
        if key not in merged:
            merged[key] = value
    for key, value in label_config.items():
        if key not in merged:
            merged[key] = value
    return merged


def _value(row: dict[str, str], mapping: dict[str, str], field: str) -> str | None:
    source_field = mapping.get(field)
    if not source_field:
        return None
    value = row.get(source_field)
    if value is None:
        return None
    stripped = str(value).strip()
    return stripped or None


def _int_value(row: dict[str, str], mapping: dict[str, str], field: str) -> int | None:
    raw = _value(row, mapping, field)
    if raw is None:
        return None
    try:
        return int(float(raw))
    except ValueError:
        return None


def _timestamp_value(row: dict[str, str], mapping: dict[str, str]) -> datetime | None:
    raw = _value(row, mapping, "timestamp")
    if raw is None:
        return None
    for candidate in (raw, raw.replace("Z", "+00:00")):
        try:
            return datetime.fromisoformat(candidate)
        except ValueError:
            continue
    return None


def _timestamp_from_snapshot(value: Any) -> datetime | None:
    if value in (None, ""):
        return None
    if isinstance(value, datetime):
        return value
    raw = str(value)
    for candidate in (raw, raw.replace("Z", "+00:00")):
        try:
            return datetime.fromisoformat(candidate)
        except ValueError:
            continue
    return None


def _mapped_label(value: str | None, mapping: dict[str, str]) -> str:
    if value is None:
        return "unknown"
    return mapping.get(value.strip().lower(), value.strip().lower() or "unknown")


def _mapped_attack_type(value: str | None, mapping: dict[str, str], label: str) -> str:
    if value is None:
        return "normal" if label == "benign" else "unknown_anomaly"
    return mapping.get(value.strip().lower(), value.strip().lower() or "unknown_anomaly")


def load_benchmark_csv(
    csv_path: Path,
    *,
    mapping_config: dict[str, Any] | None = None,
    limit: int | None = None,
) -> tuple[list[BenchmarkRecord], dict[str, Any]]:
    config = mapping_config or {}
    field_mapping = {**DEFAULT_FIELD_MAPPING, **(config.get("fields") or {})}
    label_mapping = {**DEFAULT_LABEL_MAPPING, **{str(k).lower(): str(v) for k, v in (config.get("labels") or {}).items()}}
    attack_mapping = {
        **DEFAULT_ATTACK_TYPE_MAPPING,
        **{str(k).lower(): str(v) for k, v in (config.get("attack_types") or {}).items()},
    }

    records: list[BenchmarkRecord] = []
    errors: list[dict[str, Any]] = []
    with csv_path.open("r", encoding="utf-8-sig", errors="replace", newline="") as handle:
        reader = csv.DictReader(handle)
        for row_number, row in enumerate(reader, start=2):
            if limit is not None and len(records) >= limit:
                break
            label = _mapped_label(_value(row, field_mapping, "label"), label_mapping)
            attack_type = _mapped_attack_type(_value(row, field_mapping, "attack_type"), attack_mapping, label)
            normalized = {
                "timestamp": _timestamp_value(row, field_mapping),
                "source_name": _value(row, field_mapping, "source_name"),
                "scenario": _value(row, field_mapping, "scenario"),
                "src_ip": _value(row, field_mapping, "src_ip"),
                "dst_ip": _value(row, field_mapping, "dst_ip"),
                "src_port": _int_value(row, field_mapping, "src_port"),
                "dst_port": _int_value(row, field_mapping, "dst_port"),
                "protocol": _value(row, field_mapping, "protocol"),
                "action": _value(row, field_mapping, "action"),
                "app": _value(row, field_mapping, "app"),
                "bytes": _int_value(row, field_mapping, "bytes"),
                "packets": _int_value(row, field_mapping, "packets"),
            }
            if not normalized["src_ip"] or not normalized["dst_ip"]:
                errors.append({"row_number": row_number, "error": "missing src_ip or dst_ip"})
            records.append(
                BenchmarkRecord(
                    row_number=row_number,
                    raw={str(k): "" if v is None else str(v) for k, v in row.items()},
                    normalized=normalized,
                    label=label,
                    attack_type=attack_type,
                )
            )
    summary = {
        "csv_name": csv_path.name,
        "total_rows": len(records),
        "field_mapping": field_mapping,
        "label_mapping": label_mapping,
        "attack_type_mapping": attack_mapping,
        "mapping_errors": errors[:25],
    }
    return records, summary


def _json_normalized(record: BenchmarkRecord) -> dict[str, Any]:
    normalized = dict(record.normalized)
    timestamp = normalized.get("timestamp")
    if isinstance(timestamp, datetime):
        normalized["timestamp"] = timestamp.isoformat()
    return normalized


def record_to_snapshot_row(record: BenchmarkRecord, *, include_raw: bool = False) -> dict[str, Any]:
    row = {
        "row_number": record.row_number,
        "normalized": _json_normalized(record),
        "label": record.label,
        "attack_type": record.attack_type,
    }
    if include_raw:
        row["raw"] = {
            key: value
            for key, value in record.raw.items()
            if key.strip().lower() not in PRIVATE_RAW_FIELDS
        }
    return row


def snapshot_row_to_record(row: dict[str, Any]) -> BenchmarkRecord:
    normalized = dict(row.get("normalized") or {})
    normalized["timestamp"] = _timestamp_from_snapshot(normalized.get("timestamp"))
    return BenchmarkRecord(
        row_number=int(row.get("row_number") or 0),
        raw={str(k): "" if v is None else str(v) for k, v in (row.get("raw") or {}).items()},
        normalized=normalized,
        label=str(row.get("label") or "unknown"),
        attack_type=str(row.get("attack_type") or "unknown_anomaly"),
    )


def select_benchmark_records(
    records: list[BenchmarkRecord],
    *,
    limit: int | None = None,
    sample_strategy: str = "random",
) -> list[BenchmarkRecord]:
    if limit is None or limit >= len(records):
        return list(records)
    if limit <= 0:
        return []
    strategy = sample_strategy.lower()
    if strategy == "time":
        return sorted(records, key=lambda item: (item.normalized.get("timestamp") is None, item.normalized.get("timestamp") or datetime.max))[
            :limit
        ]
    if strategy == "balanced":
        buckets: dict[str, list[BenchmarkRecord]] = {}
        for record in records:
            buckets.setdefault(record.label, []).append(record)
        selected: list[BenchmarkRecord] = []
        labels = sorted(buckets)
        cursor = 0
        while len(selected) < limit and any(buckets.values()):
            label = labels[cursor % len(labels)]
            if buckets[label]:
                selected.append(buckets[label].pop(0))
            cursor += 1
        return selected[:limit]
    rng = random.Random(42)
    shuffled = list(records)
    rng.shuffle(shuffled)
    return shuffled[:limit]


def _counter(values: list[str]) -> dict[str, int]:
    result: dict[str, int] = {}
    for value in values:
        result[value] = result.get(value, 0) + 1
    return dict(sorted(result.items()))


def benchmark_dataset_profile(records: list[BenchmarkRecord], *, required_fields: list[str] | None = None) -> dict[str, Any]:
    required = required_fields or ["timestamp", "src_ip", "dst_ip", "action", "app", "label", "attack_type"]
    total = len(records)
    missing_rates = {}
    for field in required:
        if field == "label":
            missing = sum(1 for record in records if not record.label or record.label == "unknown")
        elif field == "attack_type":
            missing = sum(1 for record in records if not record.attack_type or record.attack_type == "unknown_anomaly")
        else:
            missing = sum(1 for record in records if record.normalized.get(field) in (None, ""))
        missing_rates[field] = {
            "missing": missing,
            "rate": round(missing / total, 4) if total else 0.0,
        }
    timestamps = [
        value
        for value in (record.normalized.get("timestamp") for record in records)
        if isinstance(value, datetime)
    ]
    label_distribution = _counter([record.label for record in records])
    attack_distribution = _counter([record.attack_type for record in records])
    source_distribution = _counter(
        [
            str(record.normalized.get("source_name") or "unspecified")
            for record in records
        ]
    )
    scenario_distribution = _counter(
        [
            str(record.normalized.get("scenario") or "unspecified")
            for record in records
        ]
    )
    max_label = max(label_distribution.values(), default=0)
    min_label = min(label_distribution.values(), default=0)
    return {
        "total_rows": total,
        "missing_field_rates": missing_rates,
        "label_distribution": label_distribution,
        "attack_type_distribution": attack_distribution,
        "source_distribution": source_distribution,
        "source_count": len(source_distribution),
        "scenario_distribution": scenario_distribution,
        "scenario_count": len(scenario_distribution),
        "time_range": {
            "start": min(timestamps).isoformat() if timestamps else None,
            "end": max(timestamps).isoformat() if timestamps else None,
            "timestamps_available": len(timestamps),
        },
        "class_imbalance": {
            "max_class_count": max_label,
            "min_class_count": min_label,
            "imbalance_ratio": round(max_label / min_label, 4) if min_label else None,
            "warning": "Class imbalance is high; prefer balanced sampling or per-class metrics."
            if min_label and max_label / min_label >= 5
            else None,
        },
    }


def write_benchmark_snapshot(
    records: list[BenchmarkRecord],
    *,
    input_name: str,
    mapping_summary: dict[str, Any],
    output_dir: Path,
    sample_strategy: str,
    requested_limit: int | None,
    include_raw: bool = False,
) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    profile = benchmark_dataset_profile(records, required_fields=mapping_summary.get("required_fields"))
    digest = hashlib.sha256()
    for record in records:
        digest.update(json.dumps(record_to_snapshot_row(record, include_raw=False), sort_keys=True, default=str).encode("utf-8"))
    snapshot_id = digest.hexdigest()[:16]
    stem = f"benchmark_snapshot_{snapshot_id}"
    snapshot_path = output_dir / f"{stem}.json"
    payload = {
        "snapshot_schema": SNAPSHOT_SCHEMA,
        "snapshot_id": snapshot_id,
        "created_at": datetime.utcnow().isoformat() + "Z",
        "input_name": input_name,
        "requested_limit": requested_limit,
        "sample_strategy": sample_strategy,
        "private_raw_payloads_excluded": not include_raw,
        "mapping_summary": mapping_summary,
        "profile": profile,
        "records": [record_to_snapshot_row(record, include_raw=include_raw) for record in records],
        "safety": {
            "benchmark_data_not_for_commit": True,
            "production_readiness_claim": False,
            "automatic_response_enabled": False,
        },
    }
    snapshot_path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    payload["snapshot_path"] = str(snapshot_path)
    return payload


def load_prepared_benchmark_snapshot(snapshot_path: Path, *, limit: int | None = None) -> tuple[list[BenchmarkRecord], dict[str, Any]]:
    payload = json.loads(snapshot_path.read_text(encoding="utf-8"))
    if payload.get("snapshot_schema") != SNAPSHOT_SCHEMA:
        raise ValueError(f"Unsupported benchmark snapshot schema: {payload.get('snapshot_schema')}")
    rows = payload.get("records") or []
    if limit is not None:
        rows = rows[:limit]
    records = [snapshot_row_to_record(row) for row in rows]
    summary = {
        "csv_name": payload.get("input_name") or snapshot_path.name,
        "snapshot_id": payload.get("snapshot_id"),
        "snapshot_path_name": snapshot_path.name,
        "prepared_snapshot": True,
        "profile": payload.get("profile") or {},
        "mapping_errors": (payload.get("mapping_summary") or {}).get("mapping_errors", []),
    }
    return records, summary
