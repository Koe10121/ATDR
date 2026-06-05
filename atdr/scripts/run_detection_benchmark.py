import argparse
import json
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import select

from atdr.app.benchmarks.adapter import BenchmarkRecord, load_benchmark_csv, load_mapping_config
from atdr.app.core.config import PROJECT_ROOT
from atdr.app.db.database import SessionLocal, init_db
from atdr.app.db.models import AlertEvidence, NormalizedLog, RawLog, ResponseAction
from atdr.app.services.alert_service import list_alerts
from atdr.app.services.detection_service import run_detection
from atdr.app.services.source_service import get_or_create_source
from atdr.scripts.detection_reliability_common import RELIABILITY_OUTPUT_DIR, json_default, write_report_files
from atdr.scripts.run_source_scenario import _temp_session_factory


def _is_threat(record: BenchmarkRecord) -> bool:
    label = record.label.lower()
    attack_type = record.attack_type.lower()
    return label in {"threat", "attack", "malicious", "suspicious"} or attack_type not in {"normal", "benign", "unknown"}


def _safe_div(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 4) if denominator else 0.0


def _f1(precision: float, recall: float) -> float:
    return round((2 * precision * recall) / (precision + recall), 4) if precision + recall else 0.0


def _insert_records(db, records: list[BenchmarkRecord], *, source_name: str) -> tuple[list[int], int]:
    source = get_or_create_source(db, name=source_name, source_type="benchmark", parser_profile="benchmark_csv")
    db.flush()
    normalized_ids: list[int] = []
    now = datetime.now(timezone.utc)
    for record in records:
        raw = RawLog(source_id=source.id, raw_line=json.dumps(record.raw, ensure_ascii=True), imported_at=now)
        db.add(raw)
        db.flush()
        timestamp = record.normalized.get("timestamp")
        log = NormalizedLog(
            raw_log_id=raw.id,
            receive_time=timestamp,
            generated_time=timestamp,
            src_ip=record.normalized.get("src_ip"),
            dst_ip=record.normalized.get("dst_ip"),
            src_port=record.normalized.get("src_port"),
            dst_port=record.normalized.get("dst_port"),
            protocol=record.normalized.get("protocol"),
            action=record.normalized.get("action"),
            app=record.normalized.get("app"),
            bytes=record.normalized.get("bytes"),
            packets=record.normalized.get("packets"),
            src_zone="outside",
            dst_zone="inside",
            parsed_json={
                "benchmark": True,
                "row_number": record.row_number,
                "label": record.label,
                "attack_type": record.attack_type,
            },
        )
        db.add(log)
        db.flush()
        normalized_ids.append(log.id)
    source.logs_received_count += len(records)
    source.parse_success_count += len(records)
    source.last_seen = now
    source.last_log_received_at = now
    db.commit()
    return normalized_ids, int(source.id)


def _linked_alert_ids_by_log(db, normalized_ids: list[int]) -> dict[int, set[int]]:
    rows = list(db.scalars(select(AlertEvidence).where(AlertEvidence.normalized_log_id.in_(normalized_ids))))
    linked: dict[int, set[int]] = defaultdict(set)
    for row in rows:
        linked[row.normalized_log_id].add(row.alert_id)
    return linked


def _metrics(records: list[BenchmarkRecord], normalized_ids: list[int], linked: dict[int, set[int]]) -> dict[str, Any]:
    tp = fp = fn = tn = 0
    per_attack: dict[str, Counter[str]] = defaultdict(Counter)
    false_positives: list[dict[str, Any]] = []
    false_negatives: list[dict[str, Any]] = []
    for record, log_id in zip(records, normalized_ids, strict=False):
        expected_threat = _is_threat(record)
        detected = bool(linked.get(log_id))
        if expected_threat and detected:
            tp += 1
            per_attack[record.attack_type]["tp"] += 1
        elif expected_threat and not detected:
            fn += 1
            per_attack[record.attack_type]["fn"] += 1
            false_negatives.append({"row_number": record.row_number, "attack_type": record.attack_type, "src_ip": record.normalized.get("src_ip")})
        elif not expected_threat and detected:
            fp += 1
            per_attack["normal"]["fp"] += 1
            false_positives.append({"row_number": record.row_number, "label": record.label, "src_ip": record.normalized.get("src_ip")})
        else:
            tn += 1
            per_attack["normal"]["tn"] += 1
    precision = _safe_div(tp, tp + fp)
    recall = _safe_div(tp, tp + fn)
    return {
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "true_negatives": tn,
        "precision": precision,
        "recall": recall,
        "f1": _f1(precision, recall),
        "per_attack_metrics": {
            attack: {
                "support": counts["tp"] + counts["fn"],
                "detected": counts["tp"],
                "missed": counts["fn"],
                "false_positives": counts["fp"],
                "recall": _safe_div(counts["tp"], counts["tp"] + counts["fn"]),
            }
            for attack, counts in sorted(per_attack.items())
        },
        "false_positive_examples": false_positives[:25],
        "false_negative_examples": false_negatives[:25],
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# ATDR Detection Benchmark Report",
        "",
        f"- Generated at: {report['generated_at']}",
        f"- Dataset: {report['dataset']['csv_name']}",
        f"- Database mode: {'temporary SQLite' if report['use_temp_db'] else 'current local database'}",
        "- Production readiness claim: none",
        "",
        "## Metrics",
        "",
        f"- Rows mapped: {report['rows_mapped']} / {report['total_rows']}",
        f"- Precision: {report['metrics']['precision']}",
        f"- Recall: {report['metrics']['recall']}",
        f"- F1: {report['metrics']['f1']}",
        f"- False positives: {report['metrics']['false_positives']}",
        f"- False negatives: {report['metrics']['false_negatives']}",
        f"- Alert volume: {report['alert_volume']}",
        f"- Runtime seconds: {report['runtime_seconds']}",
        "",
        "## Limitations",
        "",
        "- Generic CSV field mapping cannot prove real deployment quality by itself.",
        "- External/public benchmark metrics must not be mixed with local firewall-log metrics by default.",
        "- ML and detection output remain SOC decision support.",
    ]
    return "\n".join(lines)


def run_detection_benchmark(
    *,
    csv_path: Path,
    mapping_config_path: Path | None = None,
    limit: int | None = None,
    use_temp_db: bool = True,
    use_ml: bool = False,
    write_output: bool = True,
    output_dir: Path = RELIABILITY_OUTPUT_DIR,
) -> dict[str, Any]:
    started = time.perf_counter()
    records, dataset_summary = load_benchmark_csv(csv_path, mapping_config=load_mapping_config(mapping_config_path), limit=limit)
    temp_engine = None
    if use_temp_db:
        temp_engine, SessionFactory = _temp_session_factory()
    else:
        init_db()
        SessionFactory = SessionLocal
    try:
        with SessionFactory() as db:
            response_actions_before = int(db.query(ResponseAction).count())
            source_name = f"benchmark-{csv_path.stem}"
            normalized_ids, source_id = _insert_records(db, records, source_name=source_name)
            detection_result = run_detection(
                db,
                limit=max(100, len(records) * 3),
                use_ml=use_ml,
                actor="detection_benchmark",
                source_id=source_id,
                source_name=source_name,
                source_type="benchmark",
            )
            linked = _linked_alert_ids_by_log(db, normalized_ids)
            alerts = list_alerts(db, source_id=source_id, limit=200)
            metrics = _metrics(records, normalized_ids, linked)
            response_actions_after = int(db.query(ResponseAction).count())
    finally:
        if temp_engine is not None:
            temp_engine.dispose()

    label_distribution = Counter(record.label for record in records)
    attack_distribution = Counter(record.attack_type for record in records)
    report = {
        "ok": True,
        "generated_at": datetime.now(timezone.utc),
        "validation_scope": "generic external/public-style benchmark adapter",
        "use_temp_db": use_temp_db,
        "use_ml": use_ml,
        "dataset": dataset_summary,
        "total_rows": len(records),
        "rows_mapped": len(records) - len(dataset_summary.get("mapping_errors", [])),
        "label_distribution": dict(sorted(label_distribution.items())),
        "attack_type_distribution": dict(sorted(attack_distribution.items())),
        "detection_result": detection_result,
        "metrics": metrics,
        "alert_volume": len(alerts),
        "runtime_seconds": round(time.perf_counter() - started, 4),
        "safety": {
            "automatic_response_enabled": False,
            "real_firewall_blocking_enabled": False,
            "response_actions_created": response_actions_after - response_actions_before,
            "production_readiness_claim": False,
        },
        "limitations": [
            "No public dataset is bundled with ATDR.",
            "Benchmark metrics are separate from local firewall-log metrics.",
            "Generic mapping quality depends on the provided field and label mapping config.",
        ],
    }
    if write_output:
        report["paths"] = write_report_files(
            report,
            output_dir=output_dir,
            stem_prefix="detection_benchmark",
            markdown=render_markdown(report),
        )
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description="Run a generic mapped CSV detection benchmark.")
    parser.add_argument("--csv-path", required=True)
    parser.add_argument("--mapping-config", default=None)
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--use-temp-db", action="store_true", default=True)
    parser.add_argument("--write-to-current-db", action="store_true")
    parser.add_argument("--use-ml", action="store_true")
    parser.add_argument("--no-report", action="store_true")
    parser.add_argument("--output-dir", default=None)
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()
    report = run_detection_benchmark(
        csv_path=Path(args.csv_path),
        mapping_config_path=Path(args.mapping_config) if args.mapping_config else None,
        limit=args.limit,
        use_temp_db=not args.write_to_current_db,
        use_ml=args.use_ml,
        write_output=not args.no_report,
        output_dir=Path(args.output_dir) if args.output_dir else RELIABILITY_OUTPUT_DIR,
    )
    print(json.dumps(report, default=json_default, indent=2 if args.pretty else None))
    raise SystemExit(0 if report["ok"] else 1)


if __name__ == "__main__":
    main()
