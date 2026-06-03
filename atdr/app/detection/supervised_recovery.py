import csv
import json
import time
from collections import Counter
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path
from typing import Any

from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from atdr.app.db.models import MLLabel, MLModelRun
from atdr.app.detection.boundary_analysis import build_boundary_analysis, render_boundary_report
from atdr.app.detection.model_comparison import compare_supervised_models
from atdr.app.detection.supervised_detector import (
    TRAINABLE_LABELS,
    _build_pipeline,
    _latest_labels,
    _metrics_from_predictions,
    _optional_imports,
    _sample_weights,
    _split_class_warnings,
    _split_indices,
    threshold_decision,
    train_supervised_classifier,
)
from atdr.app.detection.supervised_workflow import export_supervised_dataset_snapshot
from atdr.app.detection.suspicious_recall_analysis import (
    build_suspicious_recall_error_report,
    render_suspicious_recall_error_report,
)
from atdr.app.ml.features import CATEGORICAL_FEATURES, FEATURE_COLUMNS, NUMERIC_FEATURES, build_feature_rows, feature_set_metadata
from atdr.app.services.active_learning_service import (
    build_active_learning_review_sample,
    write_benign_needs_context_final_gap_sample,
    write_final_small_label_gap_sample,
)
from atdr.app.services.class_temporal_coverage_service import build_class_temporal_coverage


RECOVERY_DIR = Path("ml_baseline_reviews/supervised_recovery")
DATASET_AUDIT_PATH = Path("ml_baseline_reviews/current_supervised_dataset_audit.md")
CURRENT_ERROR_ANALYSIS_PATH = Path("ml_baseline_reviews/current_supervised_error_analysis.md")
RECOVERY_REVIEW_SAMPLE_PATH = Path("ml_baseline_reviews/supervised_recovery_review_sample.csv")
BINARY_EXPERIMENT_PATH = Path("ml_baseline_reviews/supervised_binary_threat_positive_experiment.md")
STAGE1_THRESHOLD_TUNING_PATH = Path("ml_baseline_reviews/stage1_threshold_tuning_report.md")
TWO_STAGE_EXPERIMENT_PATH = Path("ml_baseline_reviews/supervised_two_stage_experiment.md")
LABEL_TARGET_PLAN_PATH = Path("ml_baseline_reviews/supervised_label_target_plan.md")
EVALUATION_SPLIT_DIAGNOSTICS_PATH = Path("ml_baseline_reviews/evaluation_split_diagnostics.md")
BENIGN_CLASS_DEBUG_REPORT_PATH = Path("ml_baseline_reviews/benign_class_debug_report.md")
BENIGN_RECOVERY_EXPERIMENT_PATH = Path("ml_baseline_reviews/benign_recovery_experiment.md")
SOC_TRIAGE_MODEL_STRATEGY_REPORT_PATH = Path("ml_baseline_reviews/soc_triage_model_strategy_report.md")
SOC_TRIAGE_FINAL_RECOMMENDATION_PATH = Path("ml_baseline_reviews/soc_triage_final_recommendation.md")

LABEL_TARGETS = {
    "benign": 300,
    "benign_unusual": 300,
    "suspicious": 300,
    "malicious": 150,
    "needs_context": 50,
}

RECOVERY_REVIEW_FIELDNAMES = [
    "label_id",
    "log_id",
    "timestamp",
    "split",
    "current_label",
    "current_attack_type",
    "reviewed_status",
    "label_source",
    "model_prediction",
    "confidence",
    "rule_evidence",
    "anomaly_evidence",
    "hybrid_risk",
    "reason_selected",
    "evidence_summary",
    "human_review_decision",
    "human_review_attack_type",
    "human_review_confidence",
    "human_review_note",
]


def _safe_timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")


def _supervised_labels(db: Session) -> list[MLLabel]:
    return [label for label in _latest_labels(db) if label.log is not None and label.label in TRAINABLE_LABELS]


def _log_timestamp(label: MLLabel) -> datetime | None:
    log = label.log
    if log is None:
        return None
    return log.generated_time or log.receive_time or log.start_time


def _distribution(labels: list[MLLabel], *, indexes: list[int] | None = None, reviewed: bool | None = None) -> dict[str, int]:
    selected = [labels[index] for index in indexes] if indexes is not None else labels
    values = [
        label.label
        for label in selected
        if reviewed is None or bool(getattr(label, "reviewed", True)) is reviewed
    ]
    return {value: values.count(value) for value in sorted(set(values))}


def _label_source_distribution(labels: list[MLLabel]) -> dict[str, int]:
    values = [str(getattr(label, "label_source", "manual") or "manual") for label in labels]
    return {value: values.count(value) for value in sorted(set(values))}


def _top_log_values(labels: list[MLLabel], attr: str, *, limit: int = 10) -> list[dict[str, Any]]:
    values = []
    for label in labels:
        log = label.log
        value = getattr(log, attr, None) if log is not None else None
        values.append("missing" if value in {None, ""} else str(value))
    return [{"value": value, "count": count} for value, count in Counter(values).most_common(limit)]


def _source_breakdown(labels: list[MLLabel]) -> dict[str, Any]:
    names: Counter[str] = Counter()
    types: Counter[str] = Counter()
    parser_profiles: Counter[str] = Counter()
    for label in labels:
        raw = getattr(label.log, "raw_log", None) if label.log is not None else None
        source = getattr(raw, "source", None)
        names[source.name if source else "unknown_source"] += 1
        types[source.source_type if source else "unknown"] += 1
        parser_profiles[source.parser_profile if source else "unknown"] += 1
    return {
        "source_names": [{"value": value, "count": count} for value, count in names.most_common(10)],
        "source_types": [{"value": value, "count": count} for value, count in types.most_common(10)],
        "parser_profiles": [{"value": value, "count": count} for value, count in parser_profiles.most_common(10)],
    }


def _overlap_patterns(labels: list[MLLabel], *, limit: int = 12) -> dict[str, Any]:
    pattern_counts: Counter[tuple[str, str, str, str, str]] = Counter()
    shared: dict[tuple[str, str, str, str], set[str]] = {}
    for label in labels:
        if label.label not in {"suspicious", "malicious"} or label.log is None:
            continue
        log = label.log
        pattern = (
            str(log.action or "missing"),
            str(log.app or "missing"),
            str(log.dst_port or "missing"),
            str(log.protocol or "missing"),
        )
        pattern_counts[(label.label, *pattern)] += 1
        shared.setdefault(pattern, set()).add(label.label)
    shared_patterns = [
        {"action": key[0], "app": key[1], "dst_port": key[2], "protocol": key[3], "labels": sorted(values)}
        for key, values in shared.items()
        if {"suspicious", "malicious"}.issubset(values)
    ]
    return {
        "top_suspicious_malicious_patterns": [
            {
                "label": key[0],
                "action": key[1],
                "app": key[2],
                "dst_port": key[3],
                "protocol": key[4],
                "count": count,
            }
            for key, count in pattern_counts.most_common(limit)
        ],
        "shared_boundary_patterns": shared_patterns[:limit],
    }


def _render_dataset_audit(result: dict[str, Any]) -> str:
    def lines(rows: list[dict[str, Any]]) -> str:
        return "\n".join(f"- {row.get('value')}: {row.get('count')}" for row in rows) or "- none"

    missing = result.get("missing_feature_summary") or {}
    missing_lines = "\n".join(f"- {key}: {value}" for key, value in sorted(missing.items()) if value) or "- none"
    overlap = result.get("suspicious_malicious_overlap_patterns") or {}
    top_patterns = "\n".join(
        f"- {row['label']}: action={row['action']}, app={row['app']}, dst_port={row['dst_port']}, protocol={row['protocol']} ({row['count']})"
        for row in overlap.get("top_suspicious_malicious_patterns", [])
    )
    shared_patterns = "\n".join(
        f"- action={row['action']}, app={row['app']}, dst_port={row['dst_port']}, protocol={row['protocol']} labels={','.join(row['labels'])}"
        for row in overlap.get("shared_boundary_patterns", [])
    )
    return f"""# Current Supervised Dataset Audit

Generated: {result.get("generated_at")}

This audit is for lab supervised-ML recovery. It excludes raw private payloads and does not claim production accuracy.

## Row Counts

- Total supervised rows: {result.get("total_supervised_rows")}
- Training rows: {result.get("training_rows")}
- Test rows: {result.get("test_rows")}
- Reviewed labels: {result.get("reviewed_label_count")}
- Weak labels: {result.get("weak_label_count")}
- Split: {result.get("split")}

## Label Distribution

- Overall: {result.get("label_distribution")}
- Train: {result.get("train_label_distribution")}
- Test: {result.get("test_label_distribution")}
- Reviewed train: {result.get("reviewed_train_label_distribution")}
- Reviewed test: {result.get("reviewed_test_label_distribution")}
- Weak train: {result.get("weak_train_label_distribution")}
- Weak test: {result.get("weak_test_label_distribution")}

## Label Source Distribution

{result.get("label_source_distribution")}

## Source / Parser Breakdown

### Source Names
{lines((result.get("source_breakdown") or {}).get("source_names", []))}

### Source Types
{lines((result.get("source_breakdown") or {}).get("source_types", []))}

### Parser Profiles
{lines((result.get("source_breakdown") or {}).get("parser_profiles", []))}

## Top Field Values

### Apps
{lines(result.get("top_apps", []))}

### Actions
{lines(result.get("top_actions", []))}

### Destination Ports
{lines(result.get("top_dst_ports", []))}

### Protocols
{lines(result.get("top_protocols", []))}

## Missing Feature Summary

{missing_lines}

## Suspicious / Malicious Overlap

### Top Patterns
{top_patterns or "- none"}

### Shared Boundary Patterns
{shared_patterns or "- none"}

## Class Temporal Coverage

```json
{json.dumps(result.get("class_temporal_coverage", {}), indent=2, default=str)}
```

## Warnings

{chr(10).join(f"- {warning}" for warning in result.get("warnings", []))}
"""


def build_current_supervised_dataset_audit(
    db: Session,
    *,
    output_path: str | Path = DATASET_AUDIT_PATH,
    split: str = "time",
    test_size: float = 0.3,
) -> dict[str, Any]:
    imports = _optional_imports()
    if imports is None:
        return {"ok": False, "status": "skipped", "message": "Supervised ML dependencies are unavailable."}
    pd = imports[1]
    train_test_split = imports[8]
    labels = _supervised_labels(db)
    logs = [label.log for label in labels]
    y = [label.label for label in labels]
    feature_rows = build_feature_rows(db, logs) if logs else []
    frame = pd.DataFrame(feature_rows)
    missing_summary = {column: int(frame[column].isna().sum()) if column in frame else len(labels) for column in FEATURE_COLUMNS}
    train_idx, test_idx, y_train, y_test, split_warnings = _split_indices(
        logs=logs,
        y=y,
        split=split,
        test_size=test_size,
        train_test_split=train_test_split,
    )
    split_warnings = [*split_warnings, *_split_class_warnings(y_train, y_test)]
    result = {
        "ok": True,
        "status": "exported",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "report_path": str(output_path),
        "split": split,
        "test_size": test_size,
        "total_supervised_rows": len(labels),
        "training_rows": len(train_idx),
        "test_rows": len(test_idx),
        "reviewed_label_count": sum(1 for label in labels if label.reviewed),
        "weak_label_count": sum(1 for label in labels if not label.reviewed),
        "label_distribution": _distribution(labels),
        "train_label_distribution": _distribution(labels, indexes=train_idx),
        "test_label_distribution": _distribution(labels, indexes=test_idx),
        "reviewed_train_label_distribution": _distribution(labels, indexes=train_idx, reviewed=True),
        "reviewed_test_label_distribution": _distribution(labels, indexes=test_idx, reviewed=True),
        "weak_train_label_distribution": _distribution(labels, indexes=train_idx, reviewed=False),
        "weak_test_label_distribution": _distribution(labels, indexes=test_idx, reviewed=False),
        "label_source_distribution": _label_source_distribution(labels),
        "source_breakdown": _source_breakdown(labels),
        "class_temporal_coverage": build_class_temporal_coverage(db, test_size=test_size),
        "missing_feature_summary": missing_summary,
        "feature_set_metadata": feature_set_metadata(row_count=len(labels), missing_value_summary=missing_summary),
        "top_apps": _top_log_values(labels, "app"),
        "top_actions": _top_log_values(labels, "action"),
        "top_dst_ports": _top_log_values(labels, "dst_port"),
        "top_protocols": _top_log_values(labels, "protocol"),
        "suspicious_malicious_overlap_patterns": _overlap_patterns(labels),
        "warnings": [
            "Metrics based on this dataset must be presented as lab/recovery evidence only.",
            "Weak assisted labels may bias supervised learning until reviewed coverage improves.",
            *split_warnings,
        ],
        "production_promoted": False,
        "response_automation_allowed": False,
    }
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_render_dataset_audit(result), encoding="utf-8")
    _write_json(path.with_suffix(".json"), result)
    return result


def _binary_metrics(y_true: list[str], predictions: list[str]) -> dict[str, Any]:
    tp = fp = fn = tn = 0
    for actual, predicted in zip(y_true, predictions, strict=False):
        actual_positive = actual == "threat_positive"
        predicted_positive = predicted == "threat_positive"
        if actual_positive and predicted_positive:
            tp += 1
        elif not actual_positive and predicted_positive:
            fp += 1
        elif actual_positive and not predicted_positive:
            fn += 1
        else:
            tn += 1
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "false_negatives": fn,
        "false_positives": fp,
        "true_positives": tp,
        "true_negatives": tn,
    }


def _evaluate_5class_subset(
    db: Session,
    labels: list[MLLabel],
    *,
    split: str,
    test_size: float,
    min_samples: int,
    reviewed_weight: float,
    weak_weight: float,
    model_type: str = "random_forest",
) -> dict[str, Any]:
    imports = _optional_imports()
    if imports is None:
        return {"status": "skipped", "reason": "Supervised ML dependencies are unavailable."}
    if len(labels) < min_samples or len({label.label for label in labels}) < 2:
        return {"status": "skipped", "rows": len(labels), "reason": "not enough rows or classes"}
    pd = imports[1]
    train_test_split = imports[8]
    logs = [label.log for label in labels]
    y = [label.label for label in labels]
    frame = pd.DataFrame(build_feature_rows(db, logs))
    train_idx, test_idx, y_train, y_test, split_warnings = _split_indices(
        logs=logs,
        y=y,
        split=split,
        test_size=test_size,
        train_test_split=train_test_split,
    )
    pipeline = _build_pipeline(imports, model_type=model_type, class_weight="balanced")
    all_weights, weight_summary = _sample_weights(labels, reviewed_weight=reviewed_weight, weak_weight=weak_weight)
    pipeline.fit(frame.iloc[train_idx], y_train, model__sample_weight=[all_weights[index] for index in train_idx])
    classes = [str(label) for label in getattr(pipeline.named_steps["model"], "classes_", [])]
    probabilities = pipeline.predict_proba(frame.iloc[test_idx]) if hasattr(pipeline, "predict_proba") else []
    predictions = (
        [
            threshold_decision({label: float(prob) for label, prob in zip(classes, row, strict=False)}, profile="balanced")
            for row in probabilities
        ]
        if len(probabilities)
        else list(pipeline.predict(frame.iloc[test_idx]))
    )
    accuracy_score = imports[5]
    confusion_matrix = imports[6]
    precision_recall_fscore_support = imports[7]
    return {
        "status": "evaluated",
        "rows": len(labels),
        "training_rows": len(train_idx),
        "test_rows": len(test_idx),
        "split_warnings": [*split_warnings, *_split_class_warnings(y_train, y_test)],
        "sample_weighting": weight_summary,
        "metrics": _metrics_from_predictions(
            accuracy_score=accuracy_score,
            confusion_matrix=confusion_matrix,
            precision_recall_fscore_support=precision_recall_fscore_support,
            y_true=y_test,
            predictions=predictions,
            labels_order=sorted(set(y)),
        ),
    }


def evaluate_weak_label_impact(
    db: Session,
    *,
    split: str = "time",
    test_size: float = 0.3,
    min_samples: int = 6,
) -> dict[str, Any]:
    labels = _supervised_labels(db)
    reviewed_labels = [label for label in labels if label.reviewed]
    weak_labels = [label for label in labels if not label.reviewed]
    diagnostics = {
        "mixed_default": _evaluate_5class_subset(
            db,
            labels,
            split=split,
            test_size=test_size,
            min_samples=min_samples,
            reviewed_weight=3.0,
            weak_weight=0.55,
        ),
        "reviewed_only": _evaluate_5class_subset(
            db,
            reviewed_labels,
            split=split,
            test_size=test_size,
            min_samples=min_samples,
            reviewed_weight=3.0,
            weak_weight=0.55,
        ),
        "weak_only_diagnostic": _evaluate_5class_subset(
            db,
            weak_labels,
            split=split,
            test_size=test_size,
            min_samples=min_samples,
            reviewed_weight=3.0,
            weak_weight=0.55,
        ),
        "reviewed_heavy": _evaluate_5class_subset(
            db,
            labels,
            split=split,
            test_size=test_size,
            min_samples=min_samples,
            reviewed_weight=5.0,
            weak_weight=0.2,
        ),
        "weak_downweighted": _evaluate_5class_subset(
            db,
            labels,
            split=split,
            test_size=test_size,
            min_samples=min_samples,
            reviewed_weight=3.0,
            weak_weight=0.1,
        ),
    }
    mixed_f1 = float(((diagnostics["mixed_default"].get("metrics") or {}).get("weighted_average") or {}).get("f1") or 0)
    reviewed_f1 = float(((diagnostics["reviewed_only"].get("metrics") or {}).get("weighted_average") or {}).get("f1") or 0)
    conclusion = (
        "Reviewed-only evaluation is stronger than mixed evaluation; weak labels likely need more review/downweighting."
        if reviewed_f1 > mixed_f1 + 0.05
        else "No clear evidence that weak labels alone explain the current performance drop."
    )
    return {
        "status": "completed",
        "reviewed_rows": len(reviewed_labels),
        "weak_rows": len(weak_labels),
        "diagnostics": diagnostics,
        "conclusion": conclusion,
        "production_promoted": False,
        "response_automation_allowed": False,
    }


def run_binary_threat_positive_experiment(
    db: Session,
    *,
    output_path: str | Path = BINARY_EXPERIMENT_PATH,
    split: str = "time",
    test_size: float = 0.3,
    min_samples: int = 6,
) -> dict[str, Any]:
    imports = _optional_imports()
    if imports is None:
        return {"ok": False, "status": "skipped", "message": "Supervised ML dependencies are unavailable."}
    pd = imports[1]
    train_test_split = imports[8]
    labels = _supervised_labels(db)
    if len(labels) < min_samples:
        return {"ok": False, "status": "skipped", "message": "Not enough labels for binary experiment."}
    logs = [label.log for label in labels]
    y = ["threat_positive" if label.label in {"suspicious", "malicious"} else "non_threat" for label in labels]
    if len(set(y)) < 2:
        return {"ok": False, "status": "skipped", "message": "Need both threat and non-threat labels."}
    frame = pd.DataFrame(build_feature_rows(db, logs))
    train_idx, test_idx, y_train, y_test, split_warnings = _split_indices(
        logs=logs,
        y=y,
        split=split,
        test_size=test_size,
        train_test_split=train_test_split,
    )
    all_weights, weight_summary = _sample_weights(labels)
    models = []
    for model_type in ["random_forest", "extra_trees", "logistic_regression", "hist_gradient_boosting"]:
        pipeline = _build_pipeline(imports, model_type=model_type, class_weight="balanced")
        started = time.perf_counter()
        pipeline.fit(frame.iloc[train_idx], y_train, model__sample_weight=[all_weights[index] for index in train_idx])
        training_seconds = time.perf_counter() - started
        classes = [str(label) for label in getattr(pipeline.named_steps["model"], "classes_", [])]
        probabilities = pipeline.predict_proba(frame.iloc[test_idx]) if hasattr(pipeline, "predict_proba") else []
        if len(probabilities) and "threat_positive" in classes:
            threat_index = classes.index("threat_positive")
            predictions = ["threat_positive" if float(row[threat_index]) >= 0.5 else "non_threat" for row in probabilities]
        else:
            predictions = [str(value) for value in pipeline.predict(frame.iloc[test_idx])]
        models.append(
            {
                "model_type": model_type,
                "training_time_seconds": round(training_seconds, 4),
                "metrics": _binary_metrics(y_test, predictions),
            }
        )
    best = max(models, key=lambda item: float((item.get("metrics") or {}).get("f1") or 0))
    result = {
        "ok": True,
        "status": "completed",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "split": split,
        "training_rows": len(train_idx),
        "test_rows": len(test_idx),
        "sample_weighting": weight_summary,
        "models": models,
        "best_model": best.get("model_type"),
        "decision": "candidate_experimental",
        "split_warnings": split_warnings,
        "production_promoted": False,
        "response_automation_allowed": False,
    }
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    rows = "\n".join(
        f"| {model['model_type']} | {model['metrics']['precision']} | {model['metrics']['recall']} | {model['metrics']['f1']} | {model['metrics']['false_negatives']} | {model['metrics']['false_positives']} |"
        for model in models
    )
    path.write_text(
        f"""# Binary Threat-Positive Experiment

Generated: {result['generated_at']}

This candidate is experimental only. It groups suspicious and malicious as `threat_positive`; it does not replace exact-class validation.

| Model | Precision | Recall | F1 | False Negatives | False Positives |
| --- | --- | --- | --- | --- | --- |
{rows}

Best model: {result['best_model']}

Decision: candidate_experimental

Response automation allowed: false
""",
        encoding="utf-8",
    )
    _write_json(path.with_suffix(".json"), result)
    result["report_path"] = str(path)
    return result


STAGE1_THRESHOLD_PROFILES = {
    "conservative": 0.7,
    "balanced": 0.5,
    "recall_high": 0.35,
    "recall_max_review_queue": 0.2,
}


def run_stage1_threshold_tuning(
    db: Session,
    *,
    output_path: str | Path = STAGE1_THRESHOLD_TUNING_PATH,
    split: str = "time",
    test_size: float = 0.3,
    min_samples: int = 6,
    model_type: str = "random_forest",
) -> dict[str, Any]:
    imports = _optional_imports()
    if imports is None:
        return {"ok": False, "status": "skipped", "message": "Supervised ML dependencies are unavailable."}
    pd = imports[1]
    train_test_split = imports[8]
    labels = _supervised_labels(db)
    if len(labels) < min_samples:
        return {"ok": False, "status": "skipped", "message": "Not enough labels for Stage 1 threshold tuning."}
    logs = [label.log for label in labels]
    y = ["threat_positive" if label.label in {"suspicious", "malicious"} else "non_threat" for label in labels]
    if len(set(y)) < 2:
        return {"ok": False, "status": "skipped", "message": "Need both threat-positive and non-threat labels."}
    frame = pd.DataFrame(build_feature_rows(db, logs))
    train_idx, test_idx, y_train, y_test, split_warnings = _split_indices(
        logs=logs,
        y=y,
        split=split,
        test_size=test_size,
        train_test_split=train_test_split,
    )
    pipeline = _build_pipeline(imports, model_type=model_type, class_weight="balanced")
    all_weights, weight_summary = _sample_weights(labels)
    pipeline.fit(frame.iloc[train_idx], y_train, model__sample_weight=[all_weights[index] for index in train_idx])
    classes = [str(label) for label in getattr(pipeline.named_steps["model"], "classes_", [])]
    probabilities = pipeline.predict_proba(frame.iloc[test_idx]) if hasattr(pipeline, "predict_proba") else []
    profile_results = []
    if len(probabilities) and "threat_positive" in classes:
        threat_index = classes.index("threat_positive")
        threat_scores = [float(row[threat_index]) for row in probabilities]
        for profile, threshold in STAGE1_THRESHOLD_PROFILES.items():
            predictions = ["threat_positive" if score >= threshold else "non_threat" for score in threat_scores]
            metrics = _binary_metrics(y_test, predictions)
            profile_results.append(
                {
                        "profile": profile,
                        "threshold": threshold,
                        "metrics": metrics,
                        "estimated_review_queue_size": metrics["true_positives"] + metrics["false_positives"],
                    }
                )
    else:
        predictions = [str(value) for value in pipeline.predict(frame.iloc[test_idx])]
        metrics = _binary_metrics(y_test, predictions)
        profile_results.append(
            {
                "profile": "model_default",
                "threshold": None,
                "metrics": metrics,
                "estimated_review_queue_size": metrics["true_positives"] + metrics["false_positives"],
            }
        )
    best_recall = max(profile_results, key=lambda item: (float(item["metrics"].get("recall") or 0), float(item["metrics"].get("f1") or 0)))
    result = {
        "ok": True,
        "status": "completed",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "split": split,
        "model_type": model_type,
        "training_rows": len(train_idx),
        "test_rows": len(test_idx),
        "sample_weighting": weight_summary,
        "profiles": profile_results,
        "best_recall_profile": best_recall["profile"],
        "decision": "candidate_experimental",
        "split_warnings": split_warnings,
        "production_promoted": False,
        "response_automation_allowed": False,
        "interpretation": [
            "Stage 1 threshold tuning is diagnostic only; it does not activate or promote any model.",
            "Recall-heavy profiles catch more threat-positive rows but increase analyst review queue size.",
            "Response actions remain analyst-approved and simulated.",
        ],
    }
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    rows = "\n".join(
        "| {profile} | {threshold} | {precision} | {recall} | {f1} | {fp} | {fn} | {queue} |".format(
            profile=item["profile"],
            threshold=item["threshold"],
            precision=item["metrics"]["precision"],
            recall=item["metrics"]["recall"],
            f1=item["metrics"]["f1"],
            fp=item["metrics"]["false_positives"],
            fn=item["metrics"]["false_negatives"],
            queue=item["estimated_review_queue_size"],
        )
        for item in profile_results
    )
    path.write_text(
        f"""# Stage 1 Threat-Positive Threshold Tuning

Generated: {result['generated_at']}

This report tunes the experimental binary Stage 1 threat-positive classifier. It does not activate a model, does not promote a model, and does not allow automatic response.

| Profile | Threshold | Precision | Recall | F1 | False Positives | False Negatives | Estimated Review Queue |
| --- | --- | --- | --- | --- | --- | --- | --- |
{rows}

Best recall profile: {result['best_recall_profile']}

Decision: candidate_experimental

Production promoted: false

Response automation allowed: false
""",
        encoding="utf-8",
    )
    _write_json(path.with_suffix(".json"), result)
    result["report_path"] = str(path)
    return result


def _label_pattern(label: MLLabel) -> tuple[str, str, str, str]:
    log = label.log
    if log is None:
        return ("missing", "missing", "missing", "missing")
    return (
        str(log.action or "missing"),
        str(log.app or "missing"),
        str(log.dst_port or "missing"),
        str(log.protocol or "missing"),
    )


def _pattern_rows(labels: list[MLLabel], *, limit: int = 12) -> list[dict[str, Any]]:
    counter = Counter(_label_pattern(label) for label in labels)
    return [
        {"action": key[0], "app": key[1], "dst_port": key[2], "protocol": key[3], "count": count}
        for key, count in counter.most_common(limit)
    ]


def _shared_patterns(labels: list[MLLabel], labels_to_compare: set[str], *, limit: int = 12) -> list[dict[str, Any]]:
    patterns: dict[tuple[str, str, str, str], Counter[str]] = {}
    for label in labels:
        if label.label not in labels_to_compare:
            continue
        patterns.setdefault(_label_pattern(label), Counter())[label.label] += 1
    rows = []
    for pattern, counts in patterns.items():
        if len(counts) < 2:
            continue
        rows.append(
            {
                "action": pattern[0],
                "app": pattern[1],
                "dst_port": pattern[2],
                "protocol": pattern[3],
                "labels": dict(counts),
                "total": sum(counts.values()),
            }
        )
    rows.sort(key=lambda row: int(row["total"]), reverse=True)
    return rows[:limit]


def _average_weight_by_label(labels: list[MLLabel], weights: list[float]) -> dict[str, float]:
    grouped: dict[str, list[float]] = {}
    for label, weight in zip(labels, weights, strict=False):
        grouped.setdefault(label.label, []).append(float(weight))
    return {label: round(sum(values) / len(values), 4) for label, values in sorted(grouped.items()) if values}


def _custom_sample_weights(labels: list[MLLabel], strategy: str) -> tuple[list[float] | None, dict[str, Any]]:
    if strategy == "balanced_only":
        return None, {"enabled": False, "strategy": strategy, "reason": "class_weight balanced only; no custom sample weights"}
    if strategy == "none":
        return None, {"enabled": False, "strategy": strategy, "reason": "no custom sample weights"}
    if strategy == "current":
        weights, summary = _sample_weights(labels)
        summary["strategy"] = strategy
        return weights, summary
    weights: list[float] = []
    for label in labels:
        reviewed = bool(getattr(label, "reviewed", True))
        source = str(getattr(label, "label_source", "manual") or "manual")
        weight = 2.0 if reviewed else 0.7
        if source.startswith("assisted") and not reviewed:
            weight *= 0.8
        if strategy == "lighter_threat":
            if label.label == "malicious":
                weight *= 1.7 if reviewed else 1.1
            elif label.label == "suspicious":
                weight *= 1.25 if reviewed else 1.0
            elif label.label == "benign":
                weight *= 1.4
        elif strategy == "benign_boost":
            if label.label == "benign":
                weight *= 3.0 if reviewed else 1.8
            elif label.label == "benign_unusual":
                weight *= 1.4
            elif label.label == "malicious":
                weight *= 1.8 if reviewed else 1.1
            elif label.label == "suspicious":
                weight *= 1.35 if reviewed else 1.0
            elif label.label == "needs_context":
                weight *= 1.6
        weights.append(round(min(weight, 20.0), 4))
    return weights, {
        "enabled": True,
        "strategy": strategy,
        "min_weight": round(min(weights), 4) if weights else 0,
        "max_weight": round(max(weights), 4) if weights else 0,
        "average_weight": round(sum(weights) / len(weights), 4) if weights else 0,
        "average_weight_by_label": _average_weight_by_label(labels, weights),
    }


def _map_recovery_target(label: str, target_mode: str) -> str:
    if target_mode == "binary":
        return "threat_positive" if label in {"suspicious", "malicious"} else "benign_like"
    if target_mode == "three_class":
        return label if label in {"suspicious", "malicious"} else "benign_like"
    return label


def _prepare_recovery_data(db: Session, labels: list[MLLabel], imports) -> dict[str, Any]:
    pd = imports[1]
    logs = [label.log for label in labels]
    return {"logs": logs, "frame": pd.DataFrame(build_feature_rows(db, logs))}


def _evaluate_recovery_variant(
    db: Session,
    labels: list[MLLabel],
    *,
    name: str,
    model_type: str,
    target_mode: str = "flat",
    class_weight: str | None = "balanced",
    sample_weight_strategy: str = "current",
    split: str = "time",
    test_size: float = 0.3,
    min_samples: int = 6,
    prepared: dict[str, Any] | None = None,
) -> dict[str, Any]:
    imports = _optional_imports()
    if imports is None:
        return {"name": name, "status": "skipped", "reason": "Supervised ML dependencies are unavailable."}
    if len(labels) < min_samples:
        return {"name": name, "status": "skipped", "rows": len(labels), "reason": "not enough labels"}
    pd = imports[1]
    accuracy_score = imports[5]
    confusion_matrix = imports[6]
    precision_recall_fscore_support = imports[7]
    train_test_split = imports[8]
    logs = (prepared or {}).get("logs") or [label.log for label in labels]
    y = [_map_recovery_target(label.label, target_mode) for label in labels]
    if len(set(y)) < 2:
        return {"name": name, "status": "skipped", "rows": len(labels), "reason": "not enough mapped classes"}
    frame = (prepared or {}).get("frame")
    if frame is None:
        frame = pd.DataFrame(build_feature_rows(db, logs))
    train_idx, test_idx, y_train, y_test, split_warnings = _split_indices(
        logs=logs,
        y=y,
        split=split,
        test_size=test_size,
        train_test_split=train_test_split,
    )
    pipeline = _build_pipeline(imports, model_type=model_type, class_weight=class_weight)
    weights, weight_summary = _custom_sample_weights(labels, sample_weight_strategy)
    fit_kwargs = {}
    if weights is not None:
        fit_kwargs["model__sample_weight"] = [weights[index] for index in train_idx]
    started = time.perf_counter()
    pipeline.fit(frame.iloc[train_idx], y_train, **fit_kwargs)
    training_seconds = time.perf_counter() - started
    classes = [str(label) for label in getattr(pipeline.named_steps["model"], "classes_", [])]
    probabilities = pipeline.predict_proba(frame.iloc[test_idx]) if hasattr(pipeline, "predict_proba") else []
    if target_mode == "flat" and len(probabilities):
        predictions = [
            threshold_decision({label: float(prob) for label, prob in zip(classes, row, strict=False)}, profile="balanced")
            for row in probabilities
        ]
    else:
        predictions = [str(value) for value in pipeline.predict(frame.iloc[test_idx])]
    labels_order = sorted(set([*y_train, *y_test, *predictions]))
    metrics = _metrics_from_predictions(
        accuracy_score=accuracy_score,
        confusion_matrix=confusion_matrix,
        precision_recall_fscore_support=precision_recall_fscore_support,
        y_true=y_test,
        predictions=predictions,
        labels_order=labels_order,
    )
    binary_metrics = None
    if target_mode == "binary":
        binary_metrics = _binary_metrics(y_test, predictions)
    summary = _recovery_metric_summary(metrics, binary_metrics=binary_metrics)
    return {
        "name": name,
        "status": "evaluated",
        "target_mode": target_mode,
        "model_type": model_type,
        "class_weight": class_weight or "none",
        "sample_weight_strategy": sample_weight_strategy,
        "training_rows": len(train_idx),
        "test_rows": len(test_idx),
        "classes": classes,
        "training_seconds": round(training_seconds, 4),
        "sample_weighting": weight_summary,
        "metrics": metrics,
        "binary_metrics": binary_metrics,
        "summary": summary,
        "split_warnings": [*split_warnings, *_split_class_warnings(y_train, y_test)],
        "production_promoted": False,
        "response_automation_allowed": False,
    }


def _recovery_metric_summary(metrics: dict[str, Any], *, binary_metrics: dict[str, Any] | None = None) -> dict[str, Any]:
    per_class = metrics.get("per_class") or {}
    threat_positive = metrics.get("threat_positive") or {}
    binary = binary_metrics or {}
    return {
        "weighted_f1": (metrics.get("weighted_average") or {}).get("f1", metrics.get("f1")),
        "macro_f1": (metrics.get("macro_average") or {}).get("f1"),
        "benign_precision": (per_class.get("benign") or {}).get("precision"),
        "benign_recall": (per_class.get("benign") or {}).get("recall"),
        "benign_like_precision": (per_class.get("benign_like") or {}).get("precision"),
        "benign_like_recall": (per_class.get("benign_like") or {}).get("recall"),
        "suspicious_recall": (per_class.get("suspicious") or {}).get("recall"),
        "malicious_recall": (per_class.get("malicious") or {}).get("recall"),
        "threat_positive_precision": binary.get("precision", threat_positive.get("precision")),
        "threat_positive_recall": binary.get("recall", threat_positive.get("recall")),
        "threat_positive_f1": binary.get("f1", threat_positive.get("f1")),
        "false_positives": binary.get("false_positives", threat_positive.get("false_positives")),
        "false_negatives": binary.get("false_negatives", threat_positive.get("false_negatives")),
        "review_queue_size_estimate": (binary.get("true_positives", 0) + binary.get("false_positives", 0)) if binary else None,
        "cost_sensitive_total": (metrics.get("cost_sensitive") or {}).get("total_cost"),
    }


def build_benign_class_debug_report(
    db: Session,
    *,
    split: str = "time",
    test_size: float = 0.3,
    min_samples: int = 6,
    model_type: str = "extra_trees",
) -> dict[str, Any]:
    imports = _optional_imports()
    if imports is None:
        return {"ok": False, "status": "skipped", "message": "Supervised ML dependencies are unavailable."}
    labels = _supervised_labels(db)
    if len(labels) < min_samples:
        return {"ok": False, "status": "skipped", "message": "Not enough labels for benign debug report."}
    pd = imports[1]
    train_test_split = imports[8]
    logs = [label.log for label in labels]
    y = [label.label for label in labels]
    frame = pd.DataFrame(build_feature_rows(db, logs))
    train_idx, test_idx, y_train, y_test, split_warnings = _split_indices(
        logs=logs,
        y=y,
        split=split,
        test_size=test_size,
        train_test_split=train_test_split,
    )
    pipeline = _build_pipeline(imports, model_type=model_type, class_weight="balanced")
    weights, weight_summary = _sample_weights(labels)
    pipeline.fit(frame.iloc[train_idx], y_train, model__sample_weight=[weights[index] for index in train_idx])
    classes = [str(label) for label in getattr(pipeline.named_steps["model"], "classes_", [])]
    probabilities = pipeline.predict_proba(frame.iloc[test_idx]) if hasattr(pipeline, "predict_proba") else []
    class_probability_rows = [
        {label: float(prob) for label, prob in zip(classes, row, strict=False)}
        for row in probabilities
    ]
    predictions = [
        threshold_decision(row, profile="balanced")
        for row in class_probability_rows
    ] if class_probability_rows else [str(value) for value in pipeline.predict(frame.iloc[test_idx])]
    benign_test_positions = [pos for pos, actual in enumerate(y_test) if actual == "benign"]
    true_benign_prediction_distribution = Counter(predictions[pos] for pos in benign_test_positions)
    benign_false_positive_labels = [
        labels[test_idx[pos]]
        for pos in benign_test_positions
        if predictions[pos] != "benign"
    ]
    avg_true_benign_probs: dict[str, float] = {}
    if benign_test_positions and class_probability_rows:
        for class_name in classes:
            avg_true_benign_probs[class_name] = round(
                sum(float(class_probability_rows[pos].get(class_name, 0)) for pos in benign_test_positions) / len(benign_test_positions),
                4,
            )
    mapping_checks = {
        "benign_in_model_classes": "benign" in classes,
        "model_classes": classes,
        "benign_probability_column_index": classes.index("benign") if "benign" in classes else None,
        "threshold_can_output_benign": threshold_decision(
            {"benign": 0.72, "benign_unusual": 0.1, "suspicious": 0.05, "malicious": 0.02, "needs_context": 0.11},
            profile="balanced",
        )
        == "benign",
        "threshold_can_output_benign_unusual": threshold_decision(
            {"benign": 0.2, "benign_unusual": 0.55, "suspicious": 0.05, "malicious": 0.02, "needs_context": 0.18},
            profile="balanced",
        )
        == "benign_unusual",
    }
    reviewed_train_benign = sum(1 for index in train_idx if labels[index].label == "benign" and labels[index].reviewed)
    reviewed_test_benign = sum(1 for index in test_idx if labels[index].label == "benign" and labels[index].reviewed)
    weak_train_benign = sum(1 for index in train_idx if labels[index].label == "benign" and not labels[index].reviewed)
    weak_test_benign = sum(1 for index in test_idx if labels[index].label == "benign" and not labels[index].reviewed)
    possible_causes = []
    if not mapping_checks["benign_in_model_classes"] or not mapping_checks["threshold_can_output_benign"]:
        possible_causes.append("Possible label mapping or threshold bug: benign cannot be selected reliably.")
    if reviewed_train_benign < max(50, int(len(benign_test_positions) * 0.25)):
        possible_causes.append(
            "Reviewed benign training support is small relative to benign test support; the time split may be asking the model to generalize from too few trusted benign examples."
        )
    if true_benign_prediction_distribution.get("suspicious", 0) or true_benign_prediction_distribution.get("malicious", 0):
        possible_causes.append("Some true benign rows cross threat thresholds or share features with threat-like rows.")
    if true_benign_prediction_distribution.get("benign_unusual", 0):
        possible_causes.append("Benign and benign_unusual appear feature-overlapped; exact five-class separation may be too granular for current labels.")
    if not possible_causes:
        possible_causes.append("No single code-path bug was found; continue targeted benign/needs_context review and calibration.")
    result = {
        "ok": True,
        "status": "built",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "split": split,
        "model_type": model_type,
        "total_supervised_rows": len(labels),
        "training_rows": len(train_idx),
        "test_rows": len(test_idx),
        "benign_train_support": int(Counter(y_train).get("benign", 0)),
        "benign_test_support": int(Counter(y_test).get("benign", 0)),
        "reviewed_benign_train_support": reviewed_train_benign,
        "reviewed_benign_test_support": reviewed_test_benign,
        "weak_benign_train_support": weak_train_benign,
        "weak_benign_test_support": weak_test_benign,
        "prediction_distribution": dict(Counter(predictions)),
        "true_benign_prediction_distribution": dict(true_benign_prediction_distribution),
        "average_true_benign_probabilities": avg_true_benign_probs,
        "top_benign_patterns": _pattern_rows([label for label in labels if label.label == "benign"]),
        "top_benign_false_positive_patterns": _pattern_rows(benign_false_positive_labels),
        "benign_benign_unusual_overlap": _shared_patterns(labels, {"benign", "benign_unusual"}),
        "benign_suspicious_overlap": _shared_patterns(labels, {"benign", "suspicious"}),
        "benign_time_ranges": {
            "train": _timestamp_range(labels, [index for index in train_idx if labels[index].label == "benign"]),
            "test": _timestamp_range(labels, [index for index in test_idx if labels[index].label == "benign"]),
        },
        "mapping_checks": mapping_checks,
        "sample_weighting": {**weight_summary, "average_weight_by_label": _average_weight_by_label(labels, weights)},
        "split_warnings": [*split_warnings, *_split_class_warnings(y_train, y_test)],
        "possible_causes": possible_causes,
        "production_promoted": False,
        "response_automation_allowed": False,
    }
    return result


def render_benign_class_debug_report(report: dict[str, Any]) -> str:
    def table(rows: list[dict[str, Any]]) -> str:
        if not rows:
            return "- none"
        return _markdown_table(
            ["Action", "App", "Dst Port", "Protocol", "Count"],
            [[row["action"], row["app"], row["dst_port"], row["protocol"], row["count"]] for row in rows],
        )

    def overlap(rows: list[dict[str, Any]]) -> str:
        if not rows:
            return "- none"
        return _markdown_table(
            ["Action", "App", "Dst Port", "Protocol", "Labels", "Total"],
            [[row["action"], row["app"], row["dst_port"], row["protocol"], row["labels"], row["total"]] for row in rows],
        )

    causes = "\n".join(f"- {item}" for item in report.get("possible_causes", [])) or "- none"
    return f"""# Benign Class Debug Report

Generated: {report.get("generated_at")}

This report explains why benign recall is weak in the current lab supervised model. It does not activate or promote any model.

## Benign Support

- Benign train support: {report.get("benign_train_support")}
- Benign test support: {report.get("benign_test_support")}
- Reviewed benign train support: {report.get("reviewed_benign_train_support")}
- Reviewed benign test support: {report.get("reviewed_benign_test_support")}
- Weak benign train support: {report.get("weak_benign_train_support")}
- Weak benign test support: {report.get("weak_benign_test_support")}

## Prediction Distribution

- Overall predictions: {report.get("prediction_distribution")}
- True benign predicted as: {report.get("true_benign_prediction_distribution")}
- Average probabilities for true benign rows: {report.get("average_true_benign_probabilities")}

## Mapping And Threshold Checks

```json
{json.dumps(report.get("mapping_checks", {}), indent=2, default=str)}
```

## Weighting Snapshot

```json
{json.dumps(report.get("sample_weighting", {}), indent=2, default=str)}
```

## Common Benign Patterns

{table(report.get("top_benign_patterns", []))}

## Common Benign False-Positive Patterns

{table(report.get("top_benign_false_positive_patterns", []))}

## Benign / Benign Unusual Overlap

{overlap(report.get("benign_benign_unusual_overlap", []))}

## Benign / Suspicious Overlap

{overlap(report.get("benign_suspicious_overlap", []))}

## Time Window Check

```json
{json.dumps(report.get("benign_time_ranges", {}), indent=2, default=str)}
```

## Likely Cause

{causes}

## Safety

- Production promoted: false
- Response automation allowed: false
"""


def write_benign_class_debug_report(
    db: Session,
    *,
    output_path: str | Path = BENIGN_CLASS_DEBUG_REPORT_PATH,
    split: str = "time",
    test_size: float = 0.3,
    min_samples: int = 6,
    model_type: str = "extra_trees",
) -> dict[str, Any]:
    report = build_benign_class_debug_report(db, split=split, test_size=test_size, min_samples=min_samples, model_type=model_type)
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_benign_class_debug_report(report), encoding="utf-8")
    _write_json(path.with_suffix(".json"), report)
    report["report_path"] = str(path)
    return report


def run_benign_recovery_experiment(
    db: Session,
    *,
    output_path: str | Path = BENIGN_RECOVERY_EXPERIMENT_PATH,
    split: str = "time",
    test_size: float = 0.3,
    min_samples: int = 6,
) -> dict[str, Any]:
    imports = _optional_imports()
    if imports is None:
        return {"ok": False, "status": "skipped", "message": "Supervised ML dependencies are unavailable."}
    labels = _supervised_labels(db)
    reviewed_labels = [label for label in labels if label.reviewed]
    prepared_all = _prepare_recovery_data(db, labels, imports) if labels else {}
    prepared_reviewed = _prepare_recovery_data(db, reviewed_labels, imports) if reviewed_labels else {}
    variants = [
        ("extra_trees_current", "extra_trees", "flat", "balanced", "current", labels),
        ("extra_trees_lighter_threat", "extra_trees", "flat", "balanced", "lighter_threat", labels),
        ("extra_trees_benign_boost", "extra_trees", "flat", "balanced", "benign_boost", labels),
        ("random_forest_benign_boost", "random_forest", "flat", "balanced", "benign_boost", labels),
        ("logistic_regression_calibrated", "logistic_regression", "flat", "balanced", "lighter_threat", labels),
        ("balanced_class_weight_only", "extra_trees", "flat", "balanced", "balanced_only", labels),
        ("no_custom_sample_weighting", "extra_trees", "flat", None, "none", labels),
        ("reviewed_only_diagnostic", "extra_trees", "flat", "balanced", "benign_boost", reviewed_labels),
        ("binary_benign_like_vs_threat", "extra_trees", "binary", "balanced", "benign_boost", labels),
        ("three_class_soc_triage", "extra_trees", "three_class", "balanced", "benign_boost", labels),
    ]
    results = [
        _evaluate_recovery_variant(
            db,
            variant_labels,
            name=name,
            model_type=model_type,
            target_mode=target_mode,
            class_weight=class_weight,
            sample_weight_strategy=sample_weight_strategy,
            split=split,
            test_size=test_size,
            min_samples=min_samples,
            prepared=prepared_reviewed if name == "reviewed_only_diagnostic" else prepared_all,
        )
        for name, model_type, target_mode, class_weight, sample_weight_strategy, variant_labels in variants
    ]
    evaluated = [item for item in results if item.get("status") == "evaluated"]
    best_for_benign = max(evaluated, key=lambda item: float((item.get("summary") or {}).get("benign_recall") or 0), default=None)
    best_for_triage = max(evaluated, key=lambda item: float((item.get("summary") or {}).get("threat_positive_f1") or 0), default=None)
    result = {
        "ok": True,
        "status": "completed",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "split": split,
        "total_supervised_rows": len(labels),
        "variants": results,
        "best_for_benign_recall": best_for_benign["name"] if best_for_benign else None,
        "best_for_soc_triage": best_for_triage["name"] if best_for_triage else None,
        "decision": "diagnostic_only",
        "interpretation": [
            "This experiment compares benign calibration strategies only; it does not replace or activate the current candidate model.",
            "If flat five-class benign recall stays weak, SOC triage should favor benign-like vs threat-positive review queues before exact-class claims.",
            "Response automation remains disabled.",
        ],
        "production_promoted": False,
        "response_automation_allowed": False,
    }
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    rows = "\n".join(
        "| {name} | {mode} | {weighted} | {macro} | {benign} | {benign_like} | {suspicious} | {malicious} | {threat_f1} | {cost} |".format(
            name=item.get("name"),
            mode=item.get("target_mode"),
            weighted=(item.get("summary") or {}).get("weighted_f1"),
            macro=(item.get("summary") or {}).get("macro_f1"),
            benign=(item.get("summary") or {}).get("benign_recall"),
            benign_like=(item.get("summary") or {}).get("benign_like_recall"),
            suspicious=(item.get("summary") or {}).get("suspicious_recall"),
            malicious=(item.get("summary") or {}).get("malicious_recall"),
            threat_f1=(item.get("summary") or {}).get("threat_positive_f1"),
            cost=(item.get("summary") or {}).get("cost_sensitive_total"),
        )
        for item in results
    )
    path.write_text(
        f"""# Benign Recovery Experiment

Generated: {result['generated_at']}

This diagnostic compares weighting and SOC-triage alternatives. No model is activated or promoted.

| Variant | Target Mode | Weighted F1 | Macro F1 | Benign Recall | Benign-Like Recall | Suspicious Recall | Malicious Recall | Threat+ F1 | Cost |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
{rows}

Best for benign recall: {result['best_for_benign_recall']}

Best for SOC triage: {result['best_for_soc_triage']}

Decision: diagnostic_only

Production promoted: false

Response automation allowed: false
""",
        encoding="utf-8",
    )
    _write_json(path.with_suffix(".json"), result)
    result["report_path"] = str(path)
    return result


def write_soc_triage_model_strategy_report(
    db: Session,
    *,
    output_path: str | Path = SOC_TRIAGE_MODEL_STRATEGY_REPORT_PATH,
    split: str = "time",
    test_size: float = 0.3,
    min_samples: int = 6,
) -> dict[str, Any]:
    imports = _optional_imports()
    if imports is None:
        return {"ok": False, "status": "skipped", "message": "Supervised ML dependencies are unavailable."}
    labels = _supervised_labels(db)
    prepared = _prepare_recovery_data(db, labels, imports) if labels else {}
    flat = _evaluate_recovery_variant(
        db,
        labels,
        name="flat_5_class",
        model_type="extra_trees",
        target_mode="flat",
        class_weight="balanced",
        sample_weight_strategy="current",
        split=split,
        test_size=test_size,
        min_samples=min_samples,
        prepared=prepared,
    )
    binary = _evaluate_recovery_variant(
        db,
        labels,
        name="binary_threat_positive",
        model_type="extra_trees",
        target_mode="binary",
        class_weight="balanced",
        sample_weight_strategy="benign_boost",
        split=split,
        test_size=test_size,
        min_samples=min_samples,
        prepared=prepared,
    )
    three_class = _evaluate_recovery_variant(
        db,
        labels,
        name="three_class_soc_triage",
        model_type="extra_trees",
        target_mode="three_class",
        class_weight="balanced",
        sample_weight_strategy="benign_boost",
        split=split,
        test_size=test_size,
        min_samples=min_samples,
        prepared=prepared,
    )
    hierarchical = build_boundary_analysis(db, split=split, test_size=test_size, min_samples=min_samples)
    result = {
        "ok": True,
        "status": "completed",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "split": split,
        "strategies": {
            "flat_5_class": flat,
            "binary_threat_positive": binary,
            "three_class_soc_triage": three_class,
            "hierarchical_two_stage": hierarchical.get("hierarchical_candidate", {}),
        },
        "recommendation": [
            "Use flat five-class output only as analyst decision support until benign and needs_context validation improve.",
            "Use binary or three-class SOC triage as the safer review-queue framing because it separates benign-like from threat-positive before exact labels.",
            "Hierarchical Stage 2 remains promising for suspicious vs malicious, but Stage 1 must be reliable first.",
            "No strategy is production-promoted; response actions remain analyst-approved and simulated.",
        ],
        "production_promoted": False,
        "response_automation_allowed": False,
    }
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    rows = "\n".join(
        "| {name} | {mode} | {benign} | {benign_like} | {suspicious} | {malicious} | {threat_f1} | {weighted} |".format(
            name=item.get("name"),
            mode=item.get("target_mode"),
            benign=(item.get("summary") or {}).get("benign_recall"),
            benign_like=(item.get("summary") or {}).get("benign_like_recall"),
            suspicious=(item.get("summary") or {}).get("suspicious_recall"),
            malicious=(item.get("summary") or {}).get("malicious_recall"),
            threat_f1=(item.get("summary") or {}).get("threat_positive_f1"),
            weighted=(item.get("summary") or {}).get("weighted_f1"),
        )
        for item in [flat, binary, three_class]
    )
    path.write_text(
        f"""# SOC Triage Model Strategy Report

Generated: {result['generated_at']}

This report compares model strategies for analyst review queues. It does not claim production accuracy.

| Strategy | Mode | Benign Recall | Benign-Like Recall | Suspicious Recall | Malicious Recall | Threat+ F1 | Weighted F1 |
| --- | --- | --- | --- | --- | --- | --- | --- |
{rows}

## Hierarchical Candidate

```json
{json.dumps(result['strategies']['hierarchical_two_stage'], indent=2, default=str)}
```

## Recommendation

{chr(10).join(f"- {item}" for item in result['recommendation'])}

## Safety

- Production promoted: false
- Response automation allowed: false
""",
        encoding="utf-8",
    )
    _write_json(path.with_suffix(".json"), result)
    result["report_path"] = str(path)
    return result


def _label_target_rows(reviewed_distribution: dict[str, int]) -> list[dict[str, Any]]:
    rows = []
    for label, target in LABEL_TARGETS.items():
        reviewed = int(reviewed_distribution.get(label, 0))
        rows.append(
            {
                "label": label,
                "reviewed": reviewed,
                "target": target,
                "gap": max(0, target - reviewed),
                "status": "met" if reviewed >= target else "gap",
            }
        )
    return rows


def _strategy_summary_row(strategy: dict[str, Any]) -> dict[str, Any]:
    summary = strategy.get("summary") or {}
    return {
        "name": strategy.get("name", "unknown"),
        "mode": strategy.get("target_mode", "unknown"),
        "status": strategy.get("status", "unknown"),
        "weighted_f1": summary.get("weighted_f1"),
        "macro_f1": summary.get("macro_f1"),
        "benign_recall": summary.get("benign_recall"),
        "benign_like_recall": summary.get("benign_like_recall"),
        "suspicious_recall": summary.get("suspicious_recall"),
        "malicious_recall": summary.get("malicious_recall"),
        "threat_positive_precision": summary.get("threat_positive_precision"),
        "threat_positive_recall": summary.get("threat_positive_recall"),
        "threat_positive_f1": summary.get("threat_positive_f1"),
        "false_positives": summary.get("false_positives"),
        "false_negatives": summary.get("false_negatives"),
        "review_queue_size_estimate": summary.get("review_queue_size_estimate"),
    }


def build_soc_triage_final_recommendation(
    db: Session,
    *,
    split: str = "time",
    test_size: float = 0.3,
    min_samples: int = 6,
) -> dict[str, Any]:
    imports = _optional_imports()
    if imports is None:
        return {"ok": False, "status": "skipped", "message": "Supervised ML dependencies are unavailable."}
    labels = _supervised_labels(db)
    reviewed_distribution = _distribution(labels, reviewed=True)
    weak_distribution = _distribution(labels, reviewed=False)
    label_distribution = _distribution(labels)
    strategy_report = write_soc_triage_model_strategy_report(
        db,
        output_path=SOC_TRIAGE_MODEL_STRATEGY_REPORT_PATH,
        split=split,
        test_size=test_size,
        min_samples=min_samples,
    )
    stage1_profiles = run_stage1_threshold_tuning(
        db,
        output_path=STAGE1_THRESHOLD_TUNING_PATH,
        split=split,
        test_size=test_size,
        min_samples=min_samples,
    )
    strategies = strategy_report.get("strategies") or {}
    strategy_rows = [
        _strategy_summary_row(strategies.get("flat_5_class") or {}),
        _strategy_summary_row(strategies.get("binary_threat_positive") or {}),
        _strategy_summary_row(strategies.get("three_class_soc_triage") or {}),
    ]
    hierarchical = strategies.get("hierarchical_two_stage") or {}
    stage1 = ((hierarchical.get("stage1") or {}).get("metrics") or {}) if isinstance(hierarchical, dict) else {}
    stage2 = ((hierarchical.get("stage2") or {}).get("metrics") or {}) if isinstance(hierarchical, dict) else {}
    result = {
        "ok": True,
        "status": "completed",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "split": split,
        "test_size": test_size,
        "total_supervised_rows": len(labels),
        "reviewed_label_count": sum(1 for label in labels if label.reviewed),
        "weak_label_count": sum(1 for label in labels if not label.reviewed),
        "label_distribution": label_distribution,
        "reviewed_label_distribution": reviewed_distribution,
        "weak_label_distribution": weak_distribution,
        "label_target_status": _label_target_rows(reviewed_distribution),
        "strategy_comparison": strategy_rows,
        "hierarchical_summary": {
            "decision": (hierarchical.get("overall_combined_decision_quality") or {}).get("decision", "candidate_experimental")
            if isinstance(hierarchical, dict)
            else "candidate_experimental",
            "stage1_threat_positive_f1": stage1.get("threat_positive", {}).get("f1") if isinstance(stage1, dict) else None,
            "stage2_macro_f1": stage2.get("macro_average", {}).get("f1") if isinstance(stage2, dict) else None,
        },
        "stage1_review_profiles": [
            {
                "profile": item.get("profile"),
                "threshold": item.get("threshold"),
                "precision": (item.get("metrics") or {}).get("precision"),
                "recall": (item.get("metrics") or {}).get("recall"),
                "f1": (item.get("metrics") or {}).get("f1"),
                "false_positives": (item.get("metrics") or {}).get("false_positives"),
                "false_negatives": (item.get("metrics") or {}).get("false_negatives"),
                "estimated_review_queue_size": item.get("estimated_review_queue_size"),
            }
            for item in stage1_profiles.get("profiles", [])
            if item.get("profile") in {"conservative", "balanced", "recall_high"}
        ],
        "recommended_dashboard_strategy": {
            "mode": "SOC triage decision support",
            "primary_signal": "threat_positive review priority",
            "secondary_signal": "exact flat five-class label shown as assistive context only",
            "recommended_default_profile": "balanced",
            "allowed_profiles": ["conservative", "balanced", "recall_high"],
            "do_not_auto_activate": True,
        },
        "recommendation": [
            "Use supervised ML as SOC triage decision support, not as an automatic final authority.",
            "Prioritize threat-positive review queues because suspicious + malicious grouping is more useful than exact five-class production claims.",
            "Keep flat five-class predictions visible as evidence and review priority context, but do not promote them for production decisions.",
            "Benign and needs_context exact classification remain weak; they need more reviewed labels and cleaner boundary examples.",
            "Keep response automation disabled; simulated response still requires analyst approval and evidence.",
        ],
        "production_promoted": False,
        "response_automation_allowed": False,
        "decision": "candidate_only",
    }
    return result


def render_soc_triage_final_recommendation(report: dict[str, Any]) -> str:
    target_rows = "\n".join(
        "| {label} | {reviewed} | {target} | {gap} | {status} |".format(**row)
        for row in report.get("label_target_status", [])
    )
    strategy_rows = "\n".join(
        "| {name} | {mode} | {weighted_f1} | {macro_f1} | {benign_recall} | {benign_like_recall} | {suspicious_recall} | {malicious_recall} | {threat_positive_f1} |".format(
            **row
        )
        for row in report.get("strategy_comparison", [])
    )
    profile_rows = "\n".join(
        "| {profile} | {threshold} | {precision} | {recall} | {f1} | {false_positives} | {false_negatives} | {estimated_review_queue_size} |".format(
            **row
        )
        for row in report.get("stage1_review_profiles", [])
    )
    return f"""# SOC Triage Final Recommendation

Generated: {report.get('generated_at')}

## Dataset Summary

- Total supervised rows: {report.get('total_supervised_rows')}
- Reviewed labels: {report.get('reviewed_label_count')}
- Weak labels: {report.get('weak_label_count')}
- Split: {report.get('split')}
- Production promoted: false
- Response automation allowed: false

## Label Target Status

| Label | Reviewed | Target | Gap | Status |
| --- | --- | --- | --- | --- |
{target_rows}

## Strategy Comparison

| Strategy | Mode | Weighted F1 | Macro F1 | Benign Recall | Benign-Like Recall | Suspicious Recall | Malicious Recall | Threat+ F1 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
{strategy_rows}

## Stage 1 SOC Review Profiles

These profiles are diagnostic only and do not activate automatic decisions.

| Profile | Threshold | Precision | Recall | F1 | False Positives | False Negatives | Estimated Review Queue |
| --- | --- | --- | --- | --- | --- | --- | --- |
{profile_rows}

## Final Recommendation

Recommended AI mode: SOC triage decision support.

Use threat-positive triage to prioritize analyst review. Keep exact five-class supervised predictions visible as assistive evidence only, because benign and needs_context exact classification remain weak and the flat model is not production-promoted.

Recommended dashboard strategy:

- Primary signal: threat-positive review priority.
- Secondary signal: exact predicted label as review context, not ground truth.
- Default review profile: balanced.
- Conservative profile: smaller queue and fewer false positives.
- Recall-high profile: larger queue and fewer threat-positive misses.

## Why The Flat Five-Class Model Is Not Promoted

- Benign recall remains weak.
- needs_context support remains below target.
- benign, benign_unusual, suspicious, and needs_context overlap in common firewall patterns.
- Current metrics are lab validation metrics, not production accuracy.
- Response automation must remain disabled.

## Safe Presentation Wording

> ATDR uses supervised ML as SOC triage decision support. Threat-positive triage is useful for analyst review, but the flat five-class model is not production-promoted. Benign and needs_context exact classification remain weak, and all response actions remain simulated and analyst-approved.

## Safety

- Production promoted: false
- Response automation allowed: false
- Real firewall blocking: not implemented
"""


def write_soc_triage_final_recommendation(
    db: Session,
    *,
    output_path: str | Path = SOC_TRIAGE_FINAL_RECOMMENDATION_PATH,
    split: str = "time",
    test_size: float = 0.3,
    min_samples: int = 6,
) -> dict[str, Any]:
    report = build_soc_triage_final_recommendation(db, split=split, test_size=test_size, min_samples=min_samples)
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_soc_triage_final_recommendation(report), encoding="utf-8")
    _write_json(path.with_suffix(".json"), report)
    report["report_path"] = str(path)
    return report


def run_two_stage_recovery_experiment(
    db: Session,
    *,
    output_path: str | Path = TWO_STAGE_EXPERIMENT_PATH,
    split: str = "time",
    test_size: float = 0.3,
    min_samples: int = 6,
) -> dict[str, Any]:
    report = build_boundary_analysis(db, split=split, test_size=test_size, min_samples=min_samples)
    report["decision"] = "candidate_experimental"
    report["production_promoted"] = False
    report["response_automation_allowed"] = False
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_boundary_report(report), encoding="utf-8")
    _write_json(path.with_suffix(".json"), report)
    report["report_path"] = str(path)
    return report


def write_current_supervised_error_analysis(
    db: Session,
    *,
    output_path: str | Path = CURRENT_ERROR_ANALYSIS_PATH,
    split: str = "time",
    test_size: float = 0.3,
    min_samples: int = 6,
) -> dict[str, Any]:
    recall_report = build_suspicious_recall_error_report(db, split=split, test_size=test_size, min_samples=min_samples)
    boundary_report = build_boundary_analysis(db, split=split, test_size=test_size, min_samples=min_samples)
    text = [
        "# Current Supervised Error Analysis",
        "",
        "This report is for recovery planning. It does not activate a model or authorize response actions.",
        "",
        "## Suspicious Recall Errors",
        "",
        render_suspicious_recall_error_report(recall_report),
        "",
        "## Suspicious / Malicious Boundary",
        "",
        render_boundary_report(boundary_report),
        "",
        "## Active-Learning Recommendation",
        "",
        "- Review threat-positive rows predicted as benign-like.",
        "- Review suspicious/malicious boundary rows with the same app/action/port pattern.",
        "- Prioritize reviewed labels in the training window for weak classes.",
    ]
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(text), encoding="utf-8")
    result = {
        "ok": True,
        "status": "exported",
        "report_path": str(path),
        "suspicious_recall_report": recall_report,
        "boundary_report": boundary_report,
        "production_promoted": False,
        "response_automation_allowed": False,
    }
    _write_json(path.with_suffix(".json"), result)
    return result


def export_supervised_recovery_review_sample(
    db: Session,
    *,
    output_path: str | Path = RECOVERY_REVIEW_SAMPLE_PATH,
    limit: int = 150,
) -> dict[str, Any]:
    rows = build_active_learning_review_sample(
        db,
        limit=max(limit, 150),
        focus="malicious,suspicious,needs_context",
        strategy="supervised_recovery",
    )[:limit]
    output = StringIO()
    writer = csv.DictWriter(output, fieldnames=RECOVERY_REVIEW_FIELDNAMES)
    writer.writeheader()
    for row in rows:
        timestamp = row.get("generated_time")
        if hasattr(timestamp, "isoformat"):
            timestamp = timestamp.isoformat()
        writer.writerow(
            {
                "label_id": row.get("label_id", ""),
                "log_id": row.get("log_id", ""),
                "timestamp": timestamp or "",
                "split": row.get("time_window", ""),
                "current_label": row.get("current_label", ""),
                "current_attack_type": row.get("current_attack_type", ""),
                "reviewed_status": row.get("reviewed", ""),
                "label_source": row.get("label_source", ""),
                "model_prediction": row.get("model_prediction", ""),
                "confidence": row.get("confidence", ""),
                "rule_evidence": f"rule_score={row.get('rule_score', 0)}",
                "anomaly_evidence": f"is_anomaly={row.get('is_anomaly')}; anomaly_score={row.get('anomaly_score', '')}",
                "hybrid_risk": row.get("hybrid_risk_score", 0),
                "reason_selected": row.get("reason_selected_for_review", ""),
                "evidence_summary": row.get("top_evidence", ""),
                "human_review_decision": "",
                "human_review_attack_type": row.get("current_attack_type") or "unknown_anomaly",
                "human_review_confidence": row.get("label_confidence", 3),
                "human_review_note": "",
            }
        )
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    text = output.getvalue()
    path.write_text(text, encoding="utf-8")
    return {
        "ok": True,
        "status": "exported",
        "path": str(path),
        "rows": max(0, len(text.splitlines()) - 1),
        "production_promoted": False,
        "response_automation_allowed": False,
    }


def rebuild_clean_registered_baseline(
    db: Session,
    *,
    split: str = "time",
    test_size: float = 0.3,
    min_samples: int = 6,
    actor: str = "supervised_recovery",
    output_root: str | Path = RECOVERY_DIR,
) -> dict[str, Any]:
    output_dir = Path(output_root)
    output_dir.mkdir(parents=True, exist_ok=True)
    snapshot = export_supervised_dataset_snapshot(db, output_root=output_dir / "snapshots", split=split, test_size=test_size)
    model_types = ["random_forest", "extra_trees", "logistic_regression", "hist_gradient_boosting"]
    candidates = []
    for model_type in model_types:
        command = (
            f"python -m atdr.scripts.train_supervised_model --split {split} --test-size {test_size} "
            f"--min-samples {min_samples} --model {model_type} --class-weight balanced --threshold-profile balanced --save-candidate "
            f"--dataset-snapshot-id {snapshot['snapshot_id']}"
        )
        result = train_supervised_classifier(
            db,
            actor=actor,
            split=split,
            test_size=test_size,
            min_samples=min_samples,
            model_type=model_type,
            class_weight="balanced",
            threshold_profile="balanced",
            save_candidate=True,
            dataset_snapshot_id=snapshot["snapshot_id"],
            training_command=command,
        )
        run = db.scalar(
            select(MLModelRun)
            .where(MLModelRun.model_path == result.get("model_path"))
            .order_by(desc(MLModelRun.created_at), desc(MLModelRun.id))
        )
        candidates.append(
            {
                "model_id": run.id if run else None,
                "model_type": model_type,
                "status": result.get("status"),
                "model_path": result.get("model_path"),
                "artifact_hash": result.get("artifact_sha256"),
                "dataset_snapshot_id": snapshot["snapshot_id"],
                "feature_set_version": (result.get("feature_set_metadata") or {}).get("feature_set_version"),
                "feature_hash": (result.get("feature_set_metadata") or {}).get("feature_code_hash"),
                "metrics": result.get("metrics", {}),
                "readiness_decision": (result.get("promotion_gate") or {}).get("decision", "candidate_only"),
                "production_promoted": False,
                "response_automation_allowed": False,
            }
        )
    best = max(candidates, key=lambda item: float((item.get("metrics") or {}).get("f1") or 0), default=None)
    result = {
        "ok": True,
        "status": "completed",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "dataset_snapshot_id": snapshot["snapshot_id"],
        "snapshot_path": snapshot["metadata_path"],
        "candidates": candidates,
        "best_candidate": best,
        "decision": "candidate_only",
        "production_promoted": False,
        "response_automation_allowed": False,
        "message": "Clean registered baseline candidates were saved without activating or promoting any model.",
    }
    report_path = output_dir / f"registered_baseline-{_safe_timestamp()}.json"
    _write_json(report_path, result)
    result["report_path"] = str(report_path)
    return result


def _markdown_table(headers: list[str], rows: list[list[Any]]) -> str:
    header_line = "| " + " | ".join(headers) + " |"
    divider = "| " + " | ".join("---" for _ in headers) + " |"
    row_lines = ["| " + " | ".join(str(value) for value in row) + " |" for row in rows]
    return "\n".join([header_line, divider, *row_lines])


def build_supervised_label_target_plan(
    db: Session,
    *,
    split: str = "time",
    test_size: float = 0.3,
    targets: dict[str, int] | None = None,
) -> dict[str, Any]:
    labels = _supervised_labels(db)
    targets = targets or LABEL_TARGETS
    reviewed_counts = Counter(label.label for label in labels if bool(getattr(label, "reviewed", True)))
    weak_counts = Counter(label.label for label in labels if not bool(getattr(label, "reviewed", True)))
    train_distribution: dict[str, int] = {}
    test_distribution: dict[str, int] = {}
    reviewed_train_distribution: dict[str, int] = {}
    reviewed_test_distribution: dict[str, int] = {}
    split_warnings: list[str] = []
    imports = _optional_imports()
    if imports is not None and labels:
        train_test_split = imports[8]
        logs = [label.log for label in labels]
        y = [label.label for label in labels]
        train_idx, test_idx, _y_train, _y_test, split_warnings = _split_indices(
            logs=logs,
            y=y,
            split=split,
            test_size=test_size,
            train_test_split=train_test_split,
        )
        train_distribution = _distribution(labels, indexes=train_idx)
        test_distribution = _distribution(labels, indexes=test_idx)
        reviewed_train_distribution = _distribution(labels, indexes=train_idx, reviewed=True)
        reviewed_test_distribution = _distribution(labels, indexes=test_idx, reviewed=True)
    class_rows: list[dict[str, Any]] = []
    for label in sorted(targets):
        current = int(reviewed_counts.get(label, 0))
        target = int(targets[label])
        class_rows.append(
            {
                "label": label,
                "target": target,
                "reviewed": current,
                "gap": max(0, target - current),
                "weak": int(weak_counts.get(label, 0)),
                "train": int(train_distribution.get(label, 0)),
                "test": int(test_distribution.get(label, 0)),
                "reviewed_train": int(reviewed_train_distribution.get(label, 0)),
                "reviewed_test": int(reviewed_test_distribution.get(label, 0)),
            }
        )
    rows_by_label = {row["label"]: row for row in class_rows}
    focus_labels = [
        label
        for label in ["benign", "needs_context", "suspicious"]
        if rows_by_label.get(label, {}).get("gap", 0) > 0
    ]
    focus = sorted(class_rows, key=lambda row: (row["gap"], row["target"]), reverse=True)
    recommendations = []
    if focus_labels:
        recommendations.append(
            "Next review focus: "
            + ", ".join(focus_labels)
            + ". Avoid another malicious-heavy batch unless a row has strong independent evidence."
        )
    recommendations.append(
        "Review Stage 1 threat-positive false negatives: suspicious/malicious rows predicted benign-like or assigned low threat-positive score."
    )
    for row in focus:
        if row["gap"] > 0:
            recommendations.append(f"Prioritize {row['label']} review: {row['gap']} more reviewed labels to reach target {row['target']}.")
    malicious_row = rows_by_label.get("malicious")
    if malicious_row and malicious_row["gap"] == 0:
        recommendations.append("Malicious reviewed target is met; do not prioritize malicious unless strong evidence appears.")
    suspicious_row = rows_by_label.get("suspicious")
    if suspicious_row and suspicious_row["gap"] == 0:
        recommendations.append("Suspicious reviewed target is met; continue only focused boundary cleanup.")
    if any(row["reviewed_train"] < 20 for row in class_rows if row["label"] in {"suspicious", "malicious"}):
        recommendations.append("Increase reviewed suspicious/malicious examples in the training window before promotion.")
    recommendations.extend(
        [
            "Use the full log pool for anomaly/source behavior and active-learning selection.",
            "Use reviewed labels, not random raw logs, for supervised training and validation.",
            "Keep weak labels as bootstrap data only; they can hurt exact-class metrics.",
        ]
    )
    return {
        "ok": True,
        "status": "built",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "split": split,
        "test_size": test_size,
        "targets": targets,
        "total_supervised_rows": len(labels),
        "reviewed_total": sum(reviewed_counts.values()),
        "weak_total": sum(weak_counts.values()),
        "class_rows": class_rows,
        "split_warnings": split_warnings,
        "recommendations": recommendations,
        "production_promoted": False,
        "response_automation_allowed": False,
    }


def render_supervised_label_target_plan(plan: dict[str, Any]) -> str:
    rows = [
        [
            row["label"],
            row["reviewed"],
            row["target"],
            row["gap"],
            row["weak"],
            row["train"],
            row["test"],
            row["reviewed_train"],
            row["reviewed_test"],
        ]
        for row in plan.get("class_rows", [])
    ]
    table = _markdown_table(
        [
            "Class",
            "Reviewed",
            "Target",
            "Gap",
            "Weak",
            "Train",
            "Test",
            "Reviewed Train",
            "Reviewed Test",
        ],
        rows,
    )
    warnings = "\n".join(f"- {warning}" for warning in plan.get("split_warnings", [])) or "- none"
    recommendations = "\n".join(f"- {item}" for item in plan.get("recommendations", [])) or "- none"
    return f"""# Supervised Label Target Plan

Generated: {plan.get("generated_at")}

This plan is for ATDR lab supervised-ML recovery. It does not promote a model and does not allow automatic response.

## Current Counts

- Total supervised rows: {plan.get("total_supervised_rows")}
- Reviewed labels: {plan.get("reviewed_total")}
- Weak/unreviewed labels: {plan.get("weak_total")}
- Split: {plan.get("split")}

## Target Coverage

{table}

## Recommended Next Review Focus

{recommendations}

## How to Use the Large Log Pool

- All available logs are useful for baseline statistics, IsolationForest anomaly scoring, source behavior, drift checks, and active-learning selection.
- Reviewed labels are required for supervised model training and validation.
- Weak labels help bootstrap the workflow, but they can bias metrics and hurt exact suspicious/malicious separation.
- Active learning should choose high-value rows for review instead of randomly labeling thousands of logs.

## Split Warnings

{warnings}

## Safety

- Production promoted: false
- Response automation allowed: false
"""


def write_supervised_label_target_plan(
    db: Session,
    *,
    output_path: str | Path = LABEL_TARGET_PLAN_PATH,
    split: str = "time",
    test_size: float = 0.3,
) -> dict[str, Any]:
    plan = build_supervised_label_target_plan(db, split=split, test_size=test_size)
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_supervised_label_target_plan(plan), encoding="utf-8")
    _write_json(path.with_suffix(".json"), plan)
    plan["report_path"] = str(path)
    return plan


def _timestamp_range(labels: list[MLLabel], indexes: list[int]) -> dict[str, str | None]:
    values = [_log_timestamp(labels[index]) for index in indexes]
    timestamps = [value for value in values if value is not None]
    if not timestamps:
        return {"earliest": None, "latest": None}
    return {"earliest": min(timestamps).isoformat(), "latest": max(timestamps).isoformat()}


def _split_support_summary(
    labels: list[MLLabel],
    train_idx: list[int],
    test_idx: list[int],
    y_train: list[str],
    y_test: list[str],
) -> dict[str, Any]:
    all_labels = sorted(set([*y_train, *y_test]))
    rows = []
    for label in all_labels:
        class_train_idx = [index for index in train_idx if labels[index].label == label]
        class_test_idx = [index for index in test_idx if labels[index].label == label]
        rows.append(
            {
                "label": label,
                "train": len(class_train_idx),
                "test": len(class_test_idx),
                "train_time_range": _timestamp_range(labels, class_train_idx),
                "test_time_range": _timestamp_range(labels, class_test_idx),
            }
        )
    return {
        "training_rows": len(train_idx),
        "test_rows": len(test_idx),
        "class_rows": rows,
        "label_distribution_train": dict(Counter(y_train)),
        "label_distribution_test": dict(Counter(y_test)),
    }


def _time_split_explanation(labels: list[MLLabel], split_summary: dict[str, Any]) -> list[str]:
    messages = []
    class_rows = split_summary.get("class_rows", [])
    first_test_values = []
    for row in class_rows:
        test_range = row.get("test_time_range") or {}
        if test_range.get("earliest"):
            first_test_values.append(test_range["earliest"])
    first_test = min(first_test_values) if first_test_values else None
    for row in class_rows:
        label = row["label"]
        train = int(row["train"])
        test = int(row["test"])
        train_range = row.get("train_time_range") or {}
        test_range = row.get("test_time_range") or {}
        if test == 0:
            messages.append(
                f"{label} has 0 test rows because its labeled timestamps are earlier than the holdout window"
                + (f" starting around {first_test}." if first_test else ".")
            )
        if train == 0:
            messages.append(
                f"{label} has 0 training rows because its labeled timestamps are concentrated in the holdout window"
                + (f" ({test_range.get('earliest')} to {test_range.get('latest')})." if test_range.get("earliest") else ".")
            )
        if label in {"malicious", "benign"} and train and test:
            total = train + test
            test_ratio = test / total if total else 0
            if test_ratio >= 0.7:
                messages.append(f"{label} is concentrated in the test window ({test} of {total} rows), so recall may be unstable.")
            if test_ratio <= 0.05:
                messages.append(f"{label} is concentrated in the training window ({train} of {total} rows), so holdout metrics may miss it.")
        if train_range.get("latest") and test_range.get("earliest") and train_range["latest"] == test_range["earliest"]:
            messages.append(f"{label} sits on a tight timestamp boundary; small label changes can move support between train and test.")
    if labels:
        timestamps = [_log_timestamp(label) for label in labels]
        timestamps = [timestamp for timestamp in timestamps if timestamp is not None]
        if timestamps and (max(timestamps) - min(timestamps)).total_seconds() < 3600:
            messages.append("All reviewed-label timestamps are tightly clustered; temporal validation may be noisy until labels cover more time.")
    return list(dict.fromkeys(messages))


def build_evaluation_split_diagnostics(
    db: Session,
    *,
    test_size: float = 0.3,
    min_samples: int = 6,
) -> dict[str, Any]:
    imports = _optional_imports()
    if imports is None:
        return {"ok": False, "status": "skipped", "message": "Supervised ML dependencies are unavailable."}
    train_test_split = imports[8]
    labels = _supervised_labels(db)
    logs = [label.log for label in labels]
    y = [label.label for label in labels]
    split_summaries: dict[str, Any] = {}
    comparisons: dict[str, Any] = {}
    for split in ["time", "grouped_stratified"]:
        train_idx, test_idx, y_train, y_test, split_warnings = _split_indices(
            logs=logs,
            y=y,
            split=split,
            test_size=test_size,
            train_test_split=train_test_split,
        )
        summary = _split_support_summary(labels, train_idx, test_idx, y_train, y_test)
        summary["warnings"] = [*split_warnings, *_split_class_warnings(y_train, y_test)]
        split_summaries[split] = summary
        comparisons[split] = _evaluate_5class_subset(
            db,
            labels,
            split=split,
            test_size=test_size,
            min_samples=min_samples,
            reviewed_weight=3.0,
            weak_weight=0.55,
            model_type="random_forest",
        )
    time_summary = split_summaries.get("time") or {}
    result = {
        "ok": True,
        "status": "built",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "test_size": test_size,
        "total_supervised_rows": len(labels),
        "time_split": time_summary,
        "grouped_stratified_split": split_summaries.get("grouped_stratified", {}),
        "comparison": comparisons,
        "time_split_explanation": _time_split_explanation(labels, time_summary),
        "interpretation": [
            "Time split remains the primary deployment-style validation.",
            "Grouped/stratified split is diagnostic only and may overestimate deployment performance.",
            "Large differences between split metrics indicate temporal drift, label timing bias, or unstable reviewed coverage.",
        ],
        "production_promoted": False,
        "response_automation_allowed": False,
    }
    return result


def _metric_summary(evaluation: dict[str, Any], label: str) -> dict[str, Any]:
    metrics = evaluation.get("metrics") or {}
    per_class = metrics.get("per_class") or {}
    return {
        "weighted_f1": (metrics.get("weighted_average") or {}).get("f1", metrics.get("f1")),
        "macro_f1": (metrics.get("macro_average") or {}).get("f1"),
        "suspicious_recall": (per_class.get("suspicious") or {}).get("recall"),
        "malicious_recall": (per_class.get("malicious") or {}).get("recall"),
        "threat_positive_f1": (metrics.get("threat_positive") or {}).get("f1"),
        "benign_test_support": (per_class.get("benign") or {}).get("support"),
        "malicious_test_support": (per_class.get("malicious") or {}).get("support"),
        "label": label,
    }


def render_evaluation_split_diagnostics(report: dict[str, Any]) -> str:
    time_eval = _metric_summary((report.get("comparison") or {}).get("time") or {}, "time")
    grouped_eval = _metric_summary((report.get("comparison") or {}).get("grouped_stratified") or {}, "grouped_stratified")
    comparison_table = _markdown_table(
        ["Split", "Weighted F1", "Macro F1", "Suspicious Recall", "Malicious Recall", "Threat+ F1", "Benign Test", "Malicious Test"],
        [
            [
                time_eval["label"],
                time_eval["weighted_f1"],
                time_eval["macro_f1"],
                time_eval["suspicious_recall"],
                time_eval["malicious_recall"],
                time_eval["threat_positive_f1"],
                time_eval["benign_test_support"],
                time_eval["malicious_test_support"],
            ],
            [
                grouped_eval["label"],
                grouped_eval["weighted_f1"],
                grouped_eval["macro_f1"],
                grouped_eval["suspicious_recall"],
                grouped_eval["malicious_recall"],
                grouped_eval["threat_positive_f1"],
                grouped_eval["benign_test_support"],
                grouped_eval["malicious_test_support"],
            ],
        ],
    )
    time_rows = _markdown_table(
        ["Class", "Train", "Test", "Train Time Range", "Test Time Range"],
        [
            [
                row["label"],
                row["train"],
                row["test"],
                f"{(row.get('train_time_range') or {}).get('earliest')} to {(row.get('train_time_range') or {}).get('latest')}",
                f"{(row.get('test_time_range') or {}).get('earliest')} to {(row.get('test_time_range') or {}).get('latest')}",
            ]
            for row in (report.get("time_split") or {}).get("class_rows", [])
        ],
    )
    grouped_rows = _markdown_table(
        ["Class", "Train", "Test"],
        [
            [row["label"], row["train"], row["test"]]
            for row in (report.get("grouped_stratified_split") or {}).get("class_rows", [])
        ],
    )
    explanations = "\n".join(f"- {item}" for item in report.get("time_split_explanation", [])) or "- none"
    interpretation = "\n".join(f"- {item}" for item in report.get("interpretation", [])) or "- none"
    return f"""# Evaluation Split Diagnostics

Generated: {report.get("generated_at")}

This report explains supervised evaluation reliability. It does not activate or promote any model.

## Split Metric Comparison

{comparison_table}

Grouped/stratified split is diagnostic only and may overestimate deployment performance.

## Time Split Class Support

{time_rows}

## Grouped/Stratified Diagnostic Class Support

{grouped_rows}

## Why the Time Split May Be Unstable

{explanations}

## Interpretation

{interpretation}

## Safety

- Production promoted: false
- Response automation allowed: false
"""


def write_evaluation_split_diagnostics(
    db: Session,
    *,
    output_path: str | Path = EVALUATION_SPLIT_DIAGNOSTICS_PATH,
    test_size: float = 0.3,
    min_samples: int = 6,
) -> dict[str, Any]:
    report = build_evaluation_split_diagnostics(db, test_size=test_size, min_samples=min_samples)
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_evaluation_split_diagnostics(report), encoding="utf-8")
    _write_json(path.with_suffix(".json"), report)
    report["report_path"] = str(path)
    return report


def _write_recovery_progress(
    status_path: str | Path | None,
    *,
    step: str,
    status: str,
    completed_steps: list[str],
    started_at: str,
    extra: dict[str, Any] | None = None,
) -> None:
    if status_path is None:
        return
    payload = {
        "status": status,
        "current_step": step,
        "completed_steps": completed_steps,
        "started_at": started_at,
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "production_promoted": False,
        "response_automation_allowed": False,
    }
    if extra:
        payload.update(extra)
    _write_json(Path(status_path), payload)


def run_supervised_recovery_phase(
    db: Session,
    *,
    split: str = "time",
    test_size: float = 0.3,
    min_samples: int = 6,
    review_limit: int = 150,
    status_path: str | Path | None = RECOVERY_DIR / "latest_status.json",
    progress_callback: Any | None = None,
) -> dict[str, Any]:
    started_at = datetime.now(timezone.utc).isoformat()
    completed_steps: list[str] = []

    def run_step(name: str, callback):
        _write_recovery_progress(status_path, step=name, status="running", completed_steps=completed_steps, started_at=started_at)
        if progress_callback is not None:
            progress_callback(name, "running")
        value = callback()
        completed_steps.append(name)
        _write_recovery_progress(status_path, step=name, status="completed", completed_steps=completed_steps, started_at=started_at)
        if progress_callback is not None:
            progress_callback(name, "completed")
        return value

    audit = run_step("dataset_audit", lambda: build_current_supervised_dataset_audit(db, split=split, test_size=test_size))
    weak_label_impact = run_step(
        "weak_label_impact",
        lambda: evaluate_weak_label_impact(db, split=split, test_size=test_size, min_samples=min_samples),
    )
    baseline = run_step(
        "registered_baseline",
        lambda: rebuild_clean_registered_baseline(db, split=split, test_size=test_size, min_samples=min_samples),
    )
    binary = run_step(
        "binary_threat_positive_experiment",
        lambda: run_binary_threat_positive_experiment(db, split=split, test_size=test_size, min_samples=min_samples),
    )
    stage1_threshold_tuning = run_step(
        "stage1_threshold_tuning",
        lambda: run_stage1_threshold_tuning(db, split=split, test_size=test_size, min_samples=min_samples),
    )
    two_stage = run_step(
        "two_stage_experiment",
        lambda: run_two_stage_recovery_experiment(db, split=split, test_size=test_size, min_samples=min_samples),
    )
    errors = run_step(
        "error_analysis",
        lambda: write_current_supervised_error_analysis(db, split=split, test_size=test_size, min_samples=min_samples),
    )
    benign_debug = run_step(
        "benign_class_debug",
        lambda: write_benign_class_debug_report(db, split=split, test_size=test_size, min_samples=min_samples),
    )
    benign_experiment = run_step(
        "benign_recovery_experiment",
        lambda: run_benign_recovery_experiment(db, split=split, test_size=test_size, min_samples=min_samples),
    )
    soc_strategy = run_step(
        "soc_triage_model_strategy",
        lambda: write_soc_triage_model_strategy_report(db, split=split, test_size=test_size, min_samples=min_samples),
    )
    review_sample = run_step("recovery_review_sample", lambda: export_supervised_recovery_review_sample(db, limit=review_limit))
    benign_gap_sample = run_step(
        "benign_needs_context_final_gap_sample",
        lambda: write_benign_needs_context_final_gap_sample(db, limit=100),
    )
    final_soc_recommendation = run_step(
        "soc_triage_final_recommendation",
        lambda: write_soc_triage_final_recommendation(db, split=split, test_size=test_size, min_samples=min_samples),
    )
    final_small_gap_sample = run_step(
        "final_small_label_gap_sample",
        lambda: write_final_small_label_gap_sample(db, limit=64),
    )
    label_target_plan = run_step(
        "label_target_plan",
        lambda: write_supervised_label_target_plan(db, split=split, test_size=test_size),
    )
    result = {
        "ok": True,
        "status": "completed",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "dataset_audit": audit,
        "weak_label_impact": weak_label_impact,
        "registered_baseline": baseline,
        "binary_threat_positive_experiment": binary,
        "stage1_threshold_tuning": stage1_threshold_tuning,
        "two_stage_experiment": two_stage,
        "error_analysis": errors,
        "benign_class_debug": benign_debug,
        "benign_recovery_experiment": benign_experiment,
        "soc_triage_model_strategy": soc_strategy,
        "recovery_review_sample": review_sample,
        "benign_needs_context_final_gap_sample": benign_gap_sample,
        "soc_triage_final_recommendation": final_soc_recommendation,
        "final_small_label_gap_sample": final_small_gap_sample,
        "label_target_plan": label_target_plan,
        "final_model_status": "candidate_only",
        "production_promoted": False,
        "response_automation_allowed": False,
    }
    path = RECOVERY_DIR / f"supervised_recovery_phase-{_safe_timestamp()}.json"
    _write_json(path, result)
    result["report_path"] = str(path)
    _write_recovery_progress(
        status_path,
        step="complete",
        status="completed",
        completed_steps=completed_steps,
        started_at=started_at,
        extra={"report_path": str(path)},
    )
    return result
