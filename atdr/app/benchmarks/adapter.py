import csv
import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any


DEFAULT_FIELD_MAPPING = {
    "timestamp": "timestamp",
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
    "malicious": "threat",
    "suspicious": "threat",
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
