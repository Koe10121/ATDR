import argparse
import json
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import select

from atdr.app.benchmarks.adapter import (
    BenchmarkRecord,
    load_benchmark_csv,
    load_mapping_config,
    load_prepared_benchmark_snapshot,
)
from atdr.app.benchmarks.readiness import readiness_gate_v2
from atdr.app.core.config import PROJECT_ROOT
from atdr.app.db.database import SessionLocal, init_db
from atdr.app.db.models import AlertEvidence, NormalizedLog, RawLog, ResponseAction
from atdr.app.detection.ml_detector import apply_model_to_db
from atdr.app.detection.supervised_detector import POSITIVE_LABELS, predict_supervised_log
from atdr.app.services.alert_service import list_alerts
from atdr.app.services.detection_service import run_detection
from atdr.app.services.source_service import get_or_create_source
from atdr.scripts.detection_reliability_common import json_default, write_report_files
from atdr.scripts.run_source_scenario import _temp_session_factory


BENCHMARK_OUTPUT_DIR = PROJECT_ROOT / "demo_exports" / "benchmarks"
DETECTION_MODES = ("rules_only", "anomaly_only", "supervised_only", "hybrid")


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


def _class_metrics(confusion: dict[str, dict[str, int]], labels: list[str]) -> dict[str, Any]:
    rows: dict[str, Any] = {}
    for label in labels:
        tp = confusion[label][label]
        fp = sum(confusion[actual][label] for actual in labels if actual != label)
        fn = sum(confusion[label][predicted] for predicted in labels if predicted != label)
        precision = _safe_div(tp, tp + fp)
        recall = _safe_div(tp, tp + fn)
        rows[label] = {
            "precision": precision,
            "recall": recall,
            "f1": _f1(precision, recall),
            "support": sum(confusion[label].values()),
        }
    return rows


def _metrics(records: list[BenchmarkRecord], normalized_ids: list[int], predicted_threat_by_log: dict[int, bool]) -> dict[str, Any]:
    tp = fp = fn = tn = 0
    per_attack: dict[str, Counter[str]] = defaultdict(Counter)
    false_positives: list[dict[str, Any]] = []
    false_negatives: list[dict[str, Any]] = []
    labels = ["benign", "threat"]
    confusion: dict[str, dict[str, int]] = {actual: {predicted: 0 for predicted in labels} for actual in labels}
    for record, log_id in zip(records, normalized_ids, strict=False):
        expected_threat = _is_threat(record)
        detected = bool(predicted_threat_by_log.get(log_id))
        actual_label = "threat" if expected_threat else "benign"
        predicted_label = "threat" if detected else "benign"
        confusion[actual_label][predicted_label] += 1
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
    per_class = _class_metrics(confusion, labels)
    macro_f1 = round(sum(item["f1"] for item in per_class.values()) / len(per_class), 4) if per_class else 0.0
    total = len(records)
    weighted_f1 = (
        round(sum(item["f1"] * item["support"] for item in per_class.values()) / total, 4)
        if total
        else 0.0
    )
    return {
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "true_negatives": tn,
        "precision": precision,
        "recall": recall,
        "f1": _f1(precision, recall),
        "threat_positive_precision": precision,
        "threat_positive_recall": recall,
        "threat_positive_f1": _f1(precision, recall),
        "macro_f1": macro_f1,
        "weighted_f1": weighted_f1,
        "per_class_metrics": per_class,
        "confusion_matrix": {
            "labels": labels,
            "matrix": [[confusion[actual][predicted] for predicted in labels] for actual in labels],
        },
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


def _records_from_inputs(
    *,
    csv_path: Path | None,
    prepared_snapshot: Path | None,
    mapping_config_path: Path | None,
    limit: int | None,
) -> tuple[list[BenchmarkRecord], dict[str, Any]]:
    if prepared_snapshot is not None:
        return load_prepared_benchmark_snapshot(prepared_snapshot, limit=limit)
    if csv_path is None:
        raise ValueError("Either csv_path or prepared_snapshot is required.")
    return load_benchmark_csv(csv_path, mapping_config=load_mapping_config(mapping_config_path), limit=limit)


def _diagnostic_predictions(db, normalized_ids: list[int], *, mode: str) -> tuple[dict[int, bool], dict[str, Any]]:
    if mode == "anomaly_only":
        result = apply_model_to_db(db, limit=None)
        logs = {log.id: log for log in db.scalars(select(NormalizedLog).where(NormalizedLog.id.in_(normalized_ids)))}
        return {log_id: bool(logs[log_id].is_anomaly) for log_id in normalized_ids if log_id in logs}, {
            "scored_logs": len(result),
            "diagnostic_alerts_created": 0,
            "mode_note": "Anomaly-only benchmark uses IsolationForest diagnostic flags and does not create persistent alerts.",
        }
    if mode == "supervised_only":
        predictions: dict[int, bool] = {}
        available = 0
        for log_id in normalized_ids:
            prediction = predict_supervised_log(db, log_id)
            predicted_label = prediction.get("predicted_label")
            malicious_probability = float(prediction.get("malicious_probability") or 0.0)
            if predicted_label:
                available += 1
            predictions[log_id] = bool(predicted_label in POSITIVE_LABELS or malicious_probability >= 0.5)
        return predictions, {
            "predictions_available": available,
            "diagnostic_alerts_created": 0,
            "mode_note": "Supervised-only benchmark uses model predictions as decision support and does not create persistent alerts.",
        }
    raise ValueError(f"Unsupported diagnostic mode: {mode}")


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# ATDR Detection Benchmark Report",
        "",
        f"- Generated at: {report['generated_at']}",
        f"- Dataset: {report['dataset']['csv_name']}",
        f"- Detection mode: {report['detection_mode']}",
        f"- Database mode: {'temporary SQLite' if report['use_temp_db'] else 'current local database'}",
        "- Production readiness claim: none",
        "",
        "## Metrics",
        "",
        f"- Rows mapped: {report['rows_mapped']} / {report['total_rows']}",
        f"- Precision: {report['metrics']['precision']}",
        f"- Recall: {report['metrics']['recall']}",
        f"- F1: {report['metrics']['f1']}",
        f"- Macro F1: {report['metrics']['macro_f1']}",
        f"- Weighted F1: {report['metrics']['weighted_f1']}",
        f"- False positives: {report['metrics']['false_positives']}",
        f"- False negatives: {report['metrics']['false_negatives']}",
        f"- Alert volume: {report['alert_volume']}",
        f"- Runtime seconds: {report['runtime_seconds']}",
        f"- Readiness decision: {(report.get('readiness_gate_v2') or {}).get('decision')}",
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
    csv_path: Path | None = None,
    prepared_snapshot: Path | None = None,
    mapping_config_path: Path | None = None,
    limit: int | None = None,
    detection_mode: str = "hybrid",
    use_temp_db: bool = True,
    use_ml: bool = False,
    write_output: bool = True,
    output_dir: Path = BENCHMARK_OUTPUT_DIR,
) -> dict[str, Any]:
    if detection_mode not in DETECTION_MODES:
        raise ValueError(f"detection_mode must be one of {DETECTION_MODES}")
    started = time.perf_counter()
    records, dataset_summary = _records_from_inputs(
        csv_path=csv_path,
        prepared_snapshot=prepared_snapshot,
        mapping_config_path=mapping_config_path,
        limit=limit,
    )
    temp_engine = None
    if use_temp_db:
        temp_engine, SessionFactory = _temp_session_factory()
    else:
        init_db()
        SessionFactory = SessionLocal
    try:
        with SessionFactory() as db:
            response_actions_before = int(db.query(ResponseAction).count())
            source_stem = (prepared_snapshot or csv_path or Path("benchmark")).stem
            source_name = f"benchmark-{source_stem}"
            normalized_ids, source_id = _insert_records(db, records, source_name=source_name)
            detection_result: dict[str, Any]
            alerts = []
            if detection_mode in {"rules_only", "hybrid"}:
                detection_result = run_detection(
                    db,
                    limit=max(100, len(records) * 3),
                    use_ml=detection_mode == "hybrid" or use_ml,
                    actor="detection_benchmark",
                    source_id=source_id,
                    source_name=source_name,
                    source_type="benchmark",
                )
                linked = _linked_alert_ids_by_log(db, normalized_ids)
                predicted = {log_id: bool(linked.get(log_id)) for log_id in normalized_ids}
                alerts = list_alerts(db, source_id=source_id, limit=500)
            else:
                predicted, detection_result = _diagnostic_predictions(db, normalized_ids, mode=detection_mode)
            metrics = _metrics(records, normalized_ids, predicted)
            response_actions_after = int(db.query(ResponseAction).count())
    finally:
        if temp_engine is not None:
            temp_engine.dispose()

    label_distribution = Counter(record.label for record in records)
    attack_distribution = Counter(record.attack_type for record in records)
    readiness = readiness_gate_v2(
        label_count=len(records),
        label_distribution=dict(label_distribution),
        metrics=metrics,
        benchmark_metrics=metrics,
        response_automation_allowed=False,
    )
    report = {
        "ok": True,
        "generated_at": datetime.now(timezone.utc),
        "validation_scope": "generic external/public-style benchmark adapter",
        "use_temp_db": use_temp_db,
        "use_ml": detection_mode == "hybrid" or use_ml,
        "detection_mode": detection_mode,
        "dataset": dataset_summary,
        "total_rows": len(records),
        "rows_mapped": len(records) - len(dataset_summary.get("mapping_errors", [])),
        "label_distribution": dict(sorted(label_distribution.items())),
        "attack_type_distribution": dict(sorted(attack_distribution.items())),
        "detection_result": detection_result,
        "metrics": metrics,
        "readiness_gate_v2": readiness,
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
            stem_prefix="benchmark_evaluation",
            markdown=render_markdown(report),
        )
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description="Run a generic mapped CSV detection benchmark.")
    parser.add_argument("--csv-path", default=None)
    parser.add_argument("--prepared-snapshot", default=None)
    parser.add_argument("--mapping-config", default=None)
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--detection-mode", choices=DETECTION_MODES, default="hybrid")
    parser.add_argument("--use-temp-db", action="store_true", default=True)
    parser.add_argument("--write-to-current-db", action="store_true")
    parser.add_argument("--use-ml", action="store_true")
    parser.add_argument("--no-report", action="store_true")
    parser.add_argument("--output-dir", default=None)
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()
    report = run_detection_benchmark(
        csv_path=Path(args.csv_path) if args.csv_path else None,
        prepared_snapshot=Path(args.prepared_snapshot) if args.prepared_snapshot else None,
        mapping_config_path=Path(args.mapping_config) if args.mapping_config else None,
        limit=args.limit,
        detection_mode=args.detection_mode,
        use_temp_db=not args.write_to_current_db,
        use_ml=args.use_ml,
        write_output=not args.no_report,
        output_dir=Path(args.output_dir) if args.output_dir else BENCHMARK_OUTPUT_DIR,
    )
    print(json.dumps(report, default=json_default, indent=2 if args.pretty else None))
    raise SystemExit(0 if report["ok"] else 1)


if __name__ == "__main__":
    main()
