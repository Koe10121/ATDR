from __future__ import annotations

import csv
from collections import Counter
from dataclasses import dataclass
from io import StringIO
from pathlib import Path
from typing import Any


LABEL_MAP = {
    "normal": "benign",
    "benign": "benign",
    "benign_unusual": "benign_unusual",
    "suspicious": "suspicious",
    "attack": "suspicious",
    "scan": "suspicious",
    "port_scan": "suspicious",
    "malicious": "malicious",
    "malware": "malicious",
    "needs_context": "needs_context",
    "unknown": "needs_context",
}

ATTACK_TYPE_MAP = {
    "normal": "normal",
    "benign": "normal",
    "scan": "port_scan",
    "port_scan": "port_scan",
    "bruteforce": "brute_force",
    "brute_force": "brute_force",
    "dos": "dos_ddos",
    "ddos": "dos_ddos",
    "malware": "malware_c2",
    "c2": "malware_c2",
    "policy": "policy_violation",
    "exfil": "data_exfiltration_suspicion",
    "unknown": "unknown_anomaly",
}

BENCHMARK_FEATURE_FIELDS = [
    "src_port",
    "dst_port",
    "bytes",
    "bytes_sent",
    "bytes_received",
    "packets",
    "elapsed_time",
    "app_risk",
    "protocol",
    "action",
    "app",
    "src_zone",
    "dst_zone",
]


@dataclass(frozen=True)
class BenchmarkDatasetSpec:
    dataset_name: str
    source_type: str
    label_column: str = "label"
    attack_type_column: str = "attack_type"


def _normalize_key(value: Any) -> str:
    return str(value or "").strip().lower().replace("-", "_").replace(" ", "_")


def _map_label(value: Any) -> str:
    key = _normalize_key(value)
    return LABEL_MAP.get(key, "needs_context")


def _map_attack_type(value: Any, label: str) -> str:
    key = _normalize_key(value)
    if label == "benign":
        return "normal"
    return ATTACK_TYPE_MAP.get(key, "unknown_anomaly")


def load_benchmark_csv(csv_content: str, spec: BenchmarkDatasetSpec) -> list[dict[str, Any]]:
    reader = csv.DictReader(StringIO(csv_content))
    rows: list[dict[str, Any]] = []
    for index, row in enumerate(reader, start=1):
        label = _map_label(row.get(spec.label_column))
        attack_type = _map_attack_type(row.get(spec.attack_type_column) or row.get(spec.label_column), label)
        normalized = {
            "benchmark_row_id": index,
            "dataset_name": spec.dataset_name,
            "source_type": spec.source_type,
            "label": label,
            "attack_type": attack_type,
        }
        for field in BENCHMARK_FEATURE_FIELDS:
            normalized[field] = row.get(field)
        rows.append(normalized)
    return rows


def split_benchmark_rows(rows: list[dict[str, Any]], *, test_size: float = 0.3) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    if len(rows) < 2:
        return rows, []
    test_count = max(1, min(len(rows) - 1, round(len(rows) * test_size)))
    return rows[:-test_count], rows[-test_count:]


def benchmark_dataset_report(csv_content: str, spec: BenchmarkDatasetSpec, *, test_size: float = 0.3) -> dict[str, Any]:
    rows = load_benchmark_csv(csv_content, spec)
    train_rows, test_rows = split_benchmark_rows(rows, test_size=test_size)
    labels = Counter(row["label"] for row in rows)
    attack_types = Counter(row["attack_type"] for row in rows)
    warnings = [
        "Benchmark data is isolated from real firewall labels by default.",
        "Benchmark metrics must not be presented as real deployment accuracy.",
    ]
    if len(labels) < 2:
        warnings.append("Benchmark dataset has fewer than two mapped classes.")
    return {
        "dataset_name": spec.dataset_name,
        "source_type": spec.source_type,
        "rows": len(rows),
        "train_rows": len(train_rows),
        "test_rows": len(test_rows),
        "label_distribution": dict(sorted(labels.items())),
        "attack_type_distribution": dict(sorted(attack_types.items())),
        "feature_columns": BENCHMARK_FEATURE_FIELDS,
        "writes_to_real_labels": False,
        "warnings": warnings,
    }


def render_benchmark_report(report: dict[str, Any]) -> str:
    labels = "\n".join(f"- {label}: {count}" for label, count in (report.get("label_distribution") or {}).items())
    attack_types = "\n".join(f"- {label}: {count}" for label, count in (report.get("attack_type_distribution") or {}).items())
    warnings = "\n".join(f"- {warning}" for warning in report.get("warnings", []))
    return f"""# ATDR Benchmark Dataset Adapter Report

## Dataset

- Dataset name: {report.get("dataset_name")}
- Source type: {report.get("source_type")}
- Rows: {report.get("rows", 0)}
- Train rows: {report.get("train_rows", 0)}
- Test rows: {report.get("test_rows", 0)}
- Writes to real ATDR labels: {report.get("writes_to_real_labels", False)}

## Label Distribution

{labels or "- No labels"}

## Attack Type Distribution

{attack_types or "- No attack types"}

## Warnings

{warnings}

## Use

This adapter is for testing model architecture and feature-pipeline assumptions against public/benchmark datasets. It does not mix benchmark rows with real firewall labels unless a future, explicit, reviewed import workflow is created.
"""


def write_benchmark_report(
    csv_path: str | Path,
    *,
    dataset_name: str,
    source_type: str = "benchmark_csv",
    output_path: str | Path = "ml_baseline_reviews/benchmark_dataset_report.md",
    test_size: float = 0.3,
) -> dict[str, Any]:
    content = Path(csv_path).read_text(encoding="utf-8-sig")
    report = benchmark_dataset_report(
        content,
        BenchmarkDatasetSpec(dataset_name=dataset_name, source_type=source_type),
        test_size=test_size,
    )
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_benchmark_report(report), encoding="utf-8")
    return {**report, "status": "exported", "path": str(path)}
