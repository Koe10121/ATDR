import csv
import io
import json
import math
from collections import Counter
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from atdr.app.benchmarks.adapter import BenchmarkRecord
from atdr.app.core.config import PROJECT_ROOT


BENCHMARK_REVIEW_SCHEMA = "atdr_benchmark_review_v1"
DEFAULT_REVIEW_ARTIFACT_DIR = PROJECT_ROOT / "demo_exports" / "benchmarks"
VALID_REVIEW_DECISIONS = {
    "benign",
    "benign_unusual",
    "suspicious",
    "malicious",
    "needs_context",
}
VALID_ATTACK_TYPES = {
    "normal",
    "port_scan",
    "brute_force",
    "dos_ddos",
    "malware_c2",
    "policy_violation",
    "data_exfiltration_suspicion",
    "unknown",
    "unknown_anomaly",
}


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _clean(value: Any) -> str:
    return "" if value is None else str(value).strip()


def _row_id(value: Any) -> int:
    raw = _clean(value)
    if not raw:
        raise ValueError("missing_benchmark_row_id")
    try:
        parsed = int(float(raw))
    except ValueError as exc:
        raise ValueError("invalid_benchmark_row_id") from exc
    if parsed <= 0:
        raise ValueError("invalid_benchmark_row_id")
    return parsed


def _confidence(value: Any) -> tuple[float | None, float | None, int | None]:
    raw = _clean(value)
    if not raw:
        return None, None, None
    try:
        parsed = float(raw)
    except ValueError as exc:
        raise ValueError("invalid_human_review_confidence") from exc
    if not math.isfinite(parsed) or parsed < 0 or parsed > 5:
        raise ValueError("invalid_human_review_confidence")
    scale = 1 if parsed <= 1 else 5
    normalized = parsed if scale == 1 else parsed / 5
    return parsed, round(normalized, 4), scale


def is_benchmark_review_csv(csv_text: str) -> bool:
    reader = csv.DictReader(io.StringIO(csv_text))
    fields = {str(value or "").strip() for value in (reader.fieldnames or [])}
    return "benchmark_row_id" in fields and not ({"label_id", "log_id"} & fields)


def parse_benchmark_review_csv(
    csv_text: str,
    *,
    benchmark_kind: str,
    input_name: str,
    reviewer: str | None = None,
) -> dict[str, Any]:
    reader = csv.DictReader(io.StringIO(csv_text))
    fields = {str(value or "").strip() for value in (reader.fieldnames or [])}
    missing_columns = sorted(
        {"benchmark_row_id", "human_review_decision"} - fields
    )
    if missing_columns:
        return {
            "ok": False,
            "status": "failed",
            "benchmark_kind": benchmark_kind,
            "input_name": Path(input_name).name,
            "imported": 0,
            "skipped": 0,
            "failed": 1,
            "errors": [
                {
                    "row_number": 1,
                    "reason": "missing_required_columns",
                    "columns": missing_columns,
                }
            ],
            "reviews": [],
            "decision_distribution": {},
            "attack_type_distribution": {},
        }

    reviews: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    skipped = 0
    seen_ids: set[int] = set()
    for csv_row_number, row in enumerate(reader, start=2):
        decision = _clean(row.get("human_review_decision")).lower()
        if not decision:
            skipped += 1
            continue
        try:
            benchmark_row_id = _row_id(row.get("benchmark_row_id"))
            if benchmark_row_id in seen_ids:
                raise ValueError("duplicate_benchmark_row_id")
            if decision not in VALID_REVIEW_DECISIONS:
                raise ValueError("invalid_human_review_decision")
            attack_type = _clean(row.get("human_review_attack_type")).lower()
            if attack_type and attack_type not in VALID_ATTACK_TYPES:
                raise ValueError("invalid_human_review_attack_type")
            confidence, normalized_confidence, confidence_scale = _confidence(
                row.get("human_review_confidence")
            )
        except ValueError as exc:
            errors.append(
                {
                    "row_number": csv_row_number,
                    "benchmark_row_id": _clean(row.get("benchmark_row_id")),
                    "reason": str(exc),
                }
            )
            continue

        seen_ids.add(benchmark_row_id)
        reviews.append(
            {
                "benchmark_row_id": benchmark_row_id,
                "human_review_decision": decision,
                "human_review_attack_type": attack_type or None,
                "human_review_confidence": confidence,
                "normalized_confidence": normalized_confidence,
                "confidence_scale": confidence_scale,
                "human_review_note": _clean(row.get("human_review_note")) or None,
                "reviewer": reviewer,
                "source": _clean(row.get("source")) or None,
                "scenario_family": _clean(row.get("scenario_family")) or None,
                "current_label": _clean(row.get("current_label")) or None,
                "expected_label": _clean(row.get("expected_label")) or None,
                "model_prediction": _clean(row.get("model_prediction")) or None,
                "reason_selected": _clean(row.get("reason_selected")) or None,
                "evidence_summary": _clean(row.get("evidence_summary")) or None,
            }
        )

    imported = len(reviews)
    failed = len(errors)
    return {
        "ok": imported > 0 and failed == 0,
        "status": (
            "completed"
            if imported > 0 and failed == 0
            else "completed_with_errors"
            if imported > 0
            else "failed"
        ),
        "benchmark_kind": benchmark_kind,
        "input_name": Path(input_name).name,
        "imported": imported,
        "skipped": skipped,
        "failed": failed,
        "errors": errors,
        "reviews": reviews,
        "decision_distribution": dict(
            sorted(
                Counter(
                    review["human_review_decision"] for review in reviews
                ).items()
            )
        ),
        "attack_type_distribution": dict(
            sorted(
                Counter(
                    review["human_review_attack_type"]
                    for review in reviews
                    if review["human_review_attack_type"]
                ).items()
            )
        ),
    }


def write_benchmark_review_artifact(
    parsed: dict[str, Any],
    *,
    output_dir: Path = DEFAULT_REVIEW_ARTIFACT_DIR,
) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    benchmark_kind = str(parsed.get("benchmark_kind") or "benchmark")
    artifact_path = (
        output_dir
        / f"reviewed_{benchmark_kind}_labels_{_stamp()}.json"
    )
    payload = {
        "schema": BENCHMARK_REVIEW_SCHEMA,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "benchmark_kind": benchmark_kind,
        "input_name": parsed.get("input_name"),
        "imported": parsed.get("imported", 0),
        "skipped": parsed.get("skipped", 0),
        "failed": parsed.get("failed", 0),
        "decision_distribution": parsed.get("decision_distribution") or {},
        "attack_type_distribution": (
            parsed.get("attack_type_distribution") or {}
        ),
        "reviews": parsed.get("reviews") or [],
        "safety": {
            "stored_outside_ml_labels": True,
            "model_activated": False,
            "response_automation_allowed": False,
            "production_readiness_claim": False,
        },
    }
    artifact_path.write_text(
        json.dumps(payload, indent=2, default=str),
        encoding="utf-8",
    )
    return {**parsed, "artifact_path": str(artifact_path)}


def import_benchmark_review_csv_text(
    csv_text: str,
    *,
    benchmark_kind: str,
    input_name: str,
    reviewer: str | None = None,
    output_dir: Path = DEFAULT_REVIEW_ARTIFACT_DIR,
) -> dict[str, Any]:
    parsed = parse_benchmark_review_csv(
        csv_text,
        benchmark_kind=benchmark_kind,
        input_name=input_name,
        reviewer=reviewer,
    )
    if not parsed.get("reviews"):
        return {**parsed, "artifact_path": None}
    return write_benchmark_review_artifact(parsed, output_dir=output_dir)


def import_benchmark_review_csv(
    input_csv: Path,
    *,
    benchmark_kind: str,
    reviewer: str | None = None,
    output_dir: Path = DEFAULT_REVIEW_ARTIFACT_DIR,
) -> dict[str, Any]:
    return import_benchmark_review_csv_text(
        input_csv.read_text(encoding="utf-8-sig", errors="replace"),
        benchmark_kind=benchmark_kind,
        input_name=input_csv.name,
        reviewer=reviewer,
        output_dir=output_dir,
    )


def apply_benchmark_reviews(
    records: list[BenchmarkRecord],
    reviews: list[dict[str, Any]],
) -> tuple[list[BenchmarkRecord], dict[str, Any], dict[int, dict[str, Any]]]:
    review_by_id = {
        int(review["benchmark_row_id"]): review for review in reviews
    }
    record_ids = {record.row_number for record in records}
    applied_ids: list[int] = []
    reviewed_records: list[BenchmarkRecord] = []
    for record in records:
        review = review_by_id.get(record.row_number)
        if review is None:
            reviewed_records.append(record)
            continue
        applied_ids.append(record.row_number)
        reviewed_records.append(
            replace(
                record,
                label=str(review["human_review_decision"]),
                attack_type=str(
                    review.get("human_review_attack_type")
                    or record.attack_type
                ),
            )
        )
    unmatched_ids = sorted(set(review_by_id) - record_ids)
    applied_reviews = {
        row_id: review_by_id[row_id] for row_id in applied_ids
    }
    return (
        reviewed_records,
        {
            "review_count": len(reviews),
            "applied_count": len(applied_ids),
            "unmatched_count": len(unmatched_ids),
            "unmatched_benchmark_row_ids": unmatched_ids[:50],
            "decision_distribution": dict(
                sorted(
                    Counter(
                        review_by_id[row_id]["human_review_decision"]
                        for row_id in applied_ids
                    ).items()
                )
            ),
        },
        applied_reviews,
    )
