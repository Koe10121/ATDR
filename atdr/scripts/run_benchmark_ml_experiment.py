import argparse
import json
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import select

from atdr.app.benchmarks.adapter import BenchmarkRecord, load_prepared_benchmark_snapshot
from atdr.app.benchmarks.readiness import readiness_gate_v2
from atdr.app.core.config import PROJECT_ROOT
from atdr.app.db.models import NormalizedLog
from atdr.app.ml.features import build_feature_rows
from atdr.app.detection.supervised_detector import _build_pipeline, _optional_imports
from atdr.scripts.detection_reliability_common import json_default, write_report_files
from atdr.scripts.run_detection_benchmark import _insert_records
from atdr.scripts.run_source_scenario import _temp_session_factory


DEFAULT_OUTPUT_DIR = PROJECT_ROOT / "ml_baseline_reviews" / "benchmark_ml_experiments"
MODEL_TYPES = ("random_forest", "extra_trees", "logistic_regression", "hist_gradient_boosting")
MALICIOUS_LIKE_ATTACKS = {
    "brute_force",
    "dos_ddos",
    "malware_c2",
    "data_exfiltration_suspicion",
}


def _is_threat(record: BenchmarkRecord) -> bool:
    explicit = record.label.lower()
    if explicit in {
        "benign",
        "benign_like",
        "benign_unusual",
        "normal",
        "needs_context",
    }:
        return False
    return explicit in {"threat", "attack", "malicious", "suspicious"} or record.attack_type not in {
        "normal",
        "benign",
        "unknown",
    }


def _triage_label(record: BenchmarkRecord) -> str:
    explicit = record.label.lower()
    if explicit in {"suspicious", "malicious"}:
        return explicit
    if explicit in {
        "benign",
        "benign_like",
        "benign_unusual",
        "normal",
        "needs_context",
    }:
        return "benign_like"
    if not _is_threat(record):
        return "benign_like"
    if record.attack_type in MALICIOUS_LIKE_ATTACKS:
        return "malicious"
    return "suspicious"


def _binary_label(record: BenchmarkRecord) -> str:
    return "threat_positive" if _is_threat(record) else "benign_like"


def _timestamp_sort_key(record: BenchmarkRecord) -> datetime:
    value = record.normalized.get("timestamp")
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            value = None
    if not isinstance(value, datetime):
        return datetime.max.replace(tzinfo=timezone.utc)
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _split_indices(records: list[BenchmarkRecord], labels: list[str], *, split: str, test_size: float, train_test_split) -> tuple[list[int], list[int], list[str]]:
    warnings: list[str] = []
    if split == "time" and any(record.normalized.get("timestamp") for record in records):
        ordered = sorted(
            range(len(records)),
            key=lambda idx: _timestamp_sort_key(records[idx]),
        )
        cutoff = max(1, min(len(ordered) - 1, int(len(ordered) * (1 - test_size))))
        return ordered[:cutoff], ordered[cutoff:], warnings
    if split == "time":
        warnings.append("Timestamps are missing or unreliable; falling back to random split.")
    stratify = labels if min(Counter(labels).values(), default=0) >= 2 else None
    train_idx, test_idx = train_test_split(
        list(range(len(records))),
        test_size=test_size,
        random_state=42,
        stratify=stratify,
    )
    return list(train_idx), list(test_idx), warnings


def _metrics(y_true: list[str], y_pred: list[str], labels_order: list[str], *, accuracy_score, confusion_matrix, precision_recall_fscore_support) -> dict[str, Any]:
    weighted = precision_recall_fscore_support(y_true, y_pred, labels=labels_order, average="weighted", zero_division=0)
    macro = precision_recall_fscore_support(y_true, y_pred, labels=labels_order, average="macro", zero_division=0)
    per_class = precision_recall_fscore_support(y_true, y_pred, labels=labels_order, average=None, zero_division=0)
    if "threat_positive" in labels_order:
        threat_labels = {"threat_positive"}
    else:
        threat_labels = {"suspicious", "malicious"}
    tp = fp = fn = tn = 0
    for actual, predicted in zip(y_true, y_pred, strict=False):
        actual_threat = actual in threat_labels
        predicted_threat = predicted in threat_labels
        if actual_threat and predicted_threat:
            tp += 1
        elif not actual_threat and predicted_threat:
            fp += 1
        elif actual_threat and not predicted_threat:
            fn += 1
        else:
            tn += 1
    precision = round(tp / (tp + fp), 4) if tp + fp else 0.0
    recall = round(tp / (tp + fn), 4) if tp + fn else 0.0
    threat_f1 = round((2 * precision * recall) / (precision + recall), 4) if precision + recall else 0.0
    benign_support = sum(1 for value in y_true if value == "benign_like")
    benign_fp = sum(1 for actual, predicted in zip(y_true, y_pred, strict=False) if actual == "benign_like" and predicted in threat_labels)
    return {
        "accuracy": round(float(accuracy_score(y_true, y_pred)), 4),
        "macro_f1": round(float(macro[2]), 4),
        "weighted_f1": round(float(weighted[2]), 4),
        "threat_positive_precision": precision,
        "threat_positive_recall": recall,
        "threat_positive_f1": threat_f1,
        "benign_false_positive_rate": round(benign_fp / benign_support, 4) if benign_support else 0.0,
        "per_class": {
            label: {
                "precision": round(float(per_class[0][index]), 4),
                "recall": round(float(per_class[1][index]), 4),
                "f1": round(float(per_class[2][index]), 4),
                "support": int(per_class[3][index]),
            }
            for index, label in enumerate(labels_order)
        },
        "confusion_matrix": confusion_matrix(y_true, y_pred, labels=labels_order).tolist(),
        "labels": labels_order,
        "false_positives": fp,
        "false_negatives": fn,
        "true_positives": tp,
        "true_negatives": tn,
    }


def _confidence_buckets(y_true: list[str], y_pred: list[str], probabilities: Any) -> list[dict[str, Any]]:
    if probabilities is None or len(probabilities) == 0:
        return []
    buckets = [
        ("0.00-0.50", 0.0, 0.5),
        ("0.50-0.70", 0.5, 0.7),
        ("0.70-0.85", 0.7, 0.85),
        ("0.85-1.00", 0.85, 1.01),
    ]
    rows = []
    confidences = [float(max(row)) for row in probabilities]
    for name, low, high in buckets:
        indexes = [idx for idx, confidence in enumerate(confidences) if low <= confidence < high]
        correct = sum(1 for idx in indexes if y_true[idx] == y_pred[idx])
        rows.append(
            {
                "bucket": name,
                "count": len(indexes),
                "accuracy": round(correct / len(indexes), 4) if indexes else None,
                "average_confidence": (
                    round(sum(confidences[idx] for idx in indexes) / len(indexes), 4)
                    if indexes
                    else None
                ),
            }
        )
    return rows


def _evaluate_hierarchical_candidate(
    *,
    imports,
    frame,
    records: list[BenchmarkRecord],
    triage_labels: list[str],
    split: str,
    test_size: float,
) -> dict[str, Any]:
    (
        _joblib,
        _pd,
        _ColumnTransformer,
        _RandomForestClassifier,
        _SimpleImputer,
        accuracy_score,
        confusion_matrix,
        precision_recall_fscore_support,
        train_test_split,
        _Pipeline,
        _OneHotEncoder,
    ) = imports
    train_idx, test_idx, split_warnings = _split_indices(
        records,
        triage_labels,
        split=split,
        test_size=test_size,
        train_test_split=train_test_split,
    )
    binary_labels = [
        "threat_positive" if label in {"suspicious", "malicious"} else "benign_like"
        for label in triage_labels
    ]
    stage1 = _build_pipeline(imports, model_type="extra_trees", class_weight="balanced")
    stage1.fit(frame.iloc[train_idx], [binary_labels[idx] for idx in train_idx])
    threat_train_idx = [
        idx for idx in train_idx if triage_labels[idx] in {"suspicious", "malicious"}
    ]
    if len({triage_labels[idx] for idx in threat_train_idx}) < 2:
        return {
            "model_type": "hierarchical_extra_trees",
            "status": "skipped",
            "message": "Stage 2 training split lacks suspicious/malicious coverage.",
            "split_warnings": split_warnings,
        }
    stage2 = _build_pipeline(imports, model_type="extra_trees", class_weight="balanced")
    stage2.fit(
        frame.iloc[threat_train_idx],
        [triage_labels[idx] for idx in threat_train_idx],
    )
    stage1_predictions = list(stage1.predict(frame.iloc[test_idx]))
    threat_positions = [
        position
        for position, prediction in enumerate(stage1_predictions)
        if prediction == "threat_positive"
    ]
    predictions = ["benign_like"] * len(test_idx)
    if threat_positions:
        stage2_predictions = list(
            stage2.predict(frame.iloc[[test_idx[position] for position in threat_positions]])
        )
        for position, prediction in zip(
            threat_positions, stage2_predictions, strict=False
        ):
            predictions[position] = prediction
    y_test = [triage_labels[idx] for idx in test_idx]
    labels_order = ["benign_like", "malicious", "suspicious"]
    return {
        "model_type": "hierarchical_extra_trees",
        "status": "evaluated",
        "training_rows": len(train_idx),
        "stage2_training_rows": len(threat_train_idx),
        "test_rows": len(test_idx),
        "split_strategy": split,
        "split_warnings": split_warnings,
        "metrics": _metrics(
            y_test,
            predictions,
            labels_order,
            accuracy_score=accuracy_score,
            confusion_matrix=confusion_matrix,
            precision_recall_fscore_support=precision_recall_fscore_support,
        ),
        "confidence_buckets": [],
        "model_artifact_written": False,
        "model_activated": False,
    }


def _evaluate_candidate(
    *,
    imports,
    frame,
    records: list[BenchmarkRecord],
    labels: list[str],
    model_type: str,
    split: str,
    test_size: float,
) -> dict[str, Any]:
    (
        _joblib,
        _pd,
        _ColumnTransformer,
        _RandomForestClassifier,
        _SimpleImputer,
        accuracy_score,
        confusion_matrix,
        precision_recall_fscore_support,
        train_test_split,
        _Pipeline,
        _OneHotEncoder,
    ) = imports
    train_idx, test_idx, split_warnings = _split_indices(records, labels, split=split, test_size=test_size, train_test_split=train_test_split)
    y_train = [labels[idx] for idx in train_idx]
    y_test = [labels[idx] for idx in test_idx]
    if len(set(y_train)) < 2:
        return {
            "model_type": model_type,
            "status": "skipped",
            "message": "Training split contains fewer than two classes.",
            "split_warnings": split_warnings,
        }
    pipeline = _build_pipeline(imports, model_type=model_type, class_weight="balanced")
    pipeline.fit(frame.iloc[train_idx], y_train)
    predictions = list(pipeline.predict(frame.iloc[test_idx]))
    probabilities = pipeline.predict_proba(frame.iloc[test_idx]) if hasattr(pipeline, "predict_proba") else None
    labels_order = sorted(set(labels))
    metrics = _metrics(
        y_test,
        predictions,
        labels_order,
        accuracy_score=accuracy_score,
        confusion_matrix=confusion_matrix,
        precision_recall_fscore_support=precision_recall_fscore_support,
    )
    return {
        "model_type": model_type,
        "status": "evaluated",
        "training_rows": len(train_idx),
        "test_rows": len(test_idx),
        "split_strategy": split,
        "split_warnings": split_warnings,
        "metrics": metrics,
        "confidence_buckets": _confidence_buckets(y_test, predictions, probabilities),
        "model_artifact_written": False,
        "model_activated": False,
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# ATDR Benchmark ML Experiment",
        "",
        f"- Generated at: {report['generated_at']}",
        f"- Snapshot ID: {report['snapshot_id']}",
        f"- Rows: {report['row_count']}",
        f"- Split: {report['split_strategy']}",
        "- Model activation: false",
        "- Production readiness claim: none",
        "",
        "## Candidate Results",
        "",
        "| Candidate | Status | Threat F1 | Macro F1 | Weighted F1 |",
        "| --- | --- | ---: | ---: | ---: |",
    ]
    for item in report["candidates"]:
        metrics = item.get("metrics") or {}
        lines.append(
            f"| {item['candidate_name']} | {item['status']} | {metrics.get('threat_positive_f1', '-')} | "
            f"{metrics.get('macro_f1', '-')} | {metrics.get('weighted_f1', '-')} |"
        )
    readiness = report["readiness_gate_v2"]
    lines.extend(
        [
            "",
            "## Readiness Gate v2",
            "",
            f"- Decision: {readiness['decision']}",
            f"- Production status: {readiness['production_status']}",
            f"- Response automation allowed: {readiness['response_automation_allowed']}",
            "",
            "## Limitations",
            "",
            "- Benchmark experiment metrics are separate from local firewall-log metrics.",
            "- No model artifact is activated by this script.",
            "- ML remains SOC decision support.",
        ]
    )
    return "\n".join(lines)


def run_benchmark_ml_experiment(
    *,
    snapshot_path: Path,
    split: str = "random",
    test_size: float = 0.3,
    limit: int | None = None,
    output_dir: Path = DEFAULT_OUTPUT_DIR,
    write_output: bool = True,
) -> dict[str, Any]:
    imports = _optional_imports()
    if imports is None:
        return {"ok": False, "status": "skipped", "message": "Supervised ML dependencies are unavailable."}
    _joblib, pd, *_ = imports
    started = time.perf_counter()
    records, snapshot_summary = load_prepared_benchmark_snapshot(snapshot_path, limit=limit)
    engine, SessionFactory = _temp_session_factory()
    try:
        with SessionFactory() as db:
            normalized_ids, _source_id = _insert_records(db, records, source_name=f"benchmark-ml-{snapshot_path.stem}")
            logs = list(db.scalars(select(NormalizedLog).where(NormalizedLog.id.in_(normalized_ids)).order_by(NormalizedLog.id)))
            frame = pd.DataFrame(build_feature_rows(db, logs))
    finally:
        engine.dispose()

    triage_labels = [_triage_label(record) for record in records]
    binary_labels = [_binary_label(record) for record in records]
    candidates: list[dict[str, Any]] = []
    for model_type in MODEL_TYPES:
        result = _evaluate_candidate(
            imports=imports,
            frame=frame,
            records=records,
            labels=triage_labels,
            model_type=model_type,
            split=split,
            test_size=test_size,
        )
        result["candidate_name"] = f"{model_type}_three_class_soc_triage"
        result["label_space"] = "benign_like/suspicious/malicious"
        candidates.append(result)
    binary = _evaluate_candidate(
        imports=imports,
        frame=frame,
        records=records,
        labels=binary_labels,
        model_type="random_forest",
        split=split,
        test_size=test_size,
    )
    binary["candidate_name"] = "random_forest_binary_threat_positive"
    binary["label_space"] = "benign_like/threat_positive"
    candidates.append(binary)
    hierarchical = _evaluate_hierarchical_candidate(
        imports=imports,
        frame=frame,
        records=records,
        triage_labels=triage_labels,
        split=split,
        test_size=test_size,
    )
    hierarchical["candidate_name"] = "hierarchical_two_stage_extra_trees"
    hierarchical["label_space"] = (
        "stage1 benign_like/threat_positive; stage2 suspicious/malicious"
    )
    candidates.append(hierarchical)

    evaluated = [item for item in candidates if item.get("status") == "evaluated"]
    best = max(evaluated, key=lambda item: (item["metrics"].get("threat_positive_f1", 0), item["metrics"].get("macro_f1", 0)), default=None)
    readiness = readiness_gate_v2(
        label_count=len(records),
        label_distribution=dict(Counter(binary_labels)),
        metrics=(best or {}).get("metrics") or {},
        benchmark_metrics=(best or {}).get("metrics") or {},
        response_automation_allowed=False,
    )
    report = {
        "ok": True,
        "generated_at": datetime.now(timezone.utc),
        "validation_scope": "benchmark-prepared ML candidate experiment",
        "snapshot_id": snapshot_summary.get("snapshot_id"),
        "snapshot_name": snapshot_path.name,
        "row_count": len(records),
        "split_strategy": split,
        "test_size": test_size,
        "triage_label_distribution": dict(sorted(Counter(triage_labels).items())),
        "binary_label_distribution": dict(sorted(Counter(binary_labels).items())),
        "candidates": candidates,
        "best_candidate": best,
        "readiness_gate_v2": readiness,
        "runtime_seconds": round(time.perf_counter() - started, 4),
        "safety": {
            "model_artifact_written": False,
            "model_activated": False,
            "automatic_response_enabled": False,
            "real_firewall_blocking_enabled": False,
            "production_readiness_claim": False,
        },
    }
    if write_output:
        report["paths"] = write_report_files(
            report,
            output_dir=output_dir,
            stem_prefix="benchmark_ml_experiment",
            markdown=render_markdown(report),
        )
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description="Run safe supervised ML experiments on a prepared benchmark snapshot.")
    parser.add_argument("--prepared-snapshot", required=True)
    parser.add_argument("--split", choices=["random", "time"], default="random")
    parser.add_argument("--test-size", type=float, default=0.3)
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--output-dir", default=None)
    parser.add_argument("--no-report", action="store_true")
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()
    report = run_benchmark_ml_experiment(
        snapshot_path=Path(args.prepared_snapshot),
        split=args.split,
        test_size=args.test_size,
        limit=args.limit,
        output_dir=Path(args.output_dir) if args.output_dir else DEFAULT_OUTPUT_DIR,
        write_output=not args.no_report,
    )
    print(json.dumps(report, default=json_default, indent=2 if args.pretty else None))
    raise SystemExit(0 if report["ok"] else 1)


if __name__ == "__main__":
    main()
