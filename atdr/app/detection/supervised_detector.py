import hashlib
import math
import time
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any

from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from atdr.app.core.config import get_settings
from atdr.app.db.models import AuditLog, MLLabel, MLModelRun, NormalizedLog
from atdr.app.detection.cost_sensitive import cost_sensitive_report
from atdr.app.detection.hybrid_scoring import hybrid_risk_score
from atdr.app.ml.features import (
    CATEGORICAL_FEATURES,
    FEATURE_COLUMNS,
    FEATURE_SET_VERSION,
    NUMERIC_FEATURES,
    build_feature_rows,
    build_log_features,
    feature_set_metadata,
)
from atdr.app.services.class_temporal_coverage_service import (
    MALICIOUS_TRAINING_MINIMUM,
    build_class_temporal_coverage,
)


MODEL_NAME = "supervised_random_forest"
SUPPORTED_SUPERVISED_MODELS = {"random_forest", "hist_gradient_boosting", "logistic_regression", "extra_trees"}
TRAINABLE_LABELS = {"benign", "benign_unusual", "suspicious", "malicious", "needs_context"}
POSITIVE_LABELS = {"suspicious", "malicious"}
REVIEWED_LABEL_TARGET = 300
MIN_CLASS_SUPPORT = 5
IMPORTANT_CLASSES = ("suspicious", "malicious")
THRESHOLD_PROFILES = {
    "conservative": {"malicious": 0.65, "suspicious": 0.65, "needs_context": 0.55},
    "balanced": {"malicious": 0.35, "suspicious": 0.45, "needs_context": 0.5},
    "aggressive": {"malicious": 0.25, "suspicious": 0.32, "needs_context": 0.4},
    "suspicious_recall": {"malicious": 0.52, "suspicious": 0.30, "needs_context": 0.45},
    "malicious_recall": {"malicious": 0.24, "suspicious": 0.48, "needs_context": 0.45},
    "threat_positive": {"malicious": 0.32, "suspicious": 0.30, "needs_context": 0.5},
}
THRESHOLD_PROFILE_ORDER = [
    "conservative",
    "balanced",
    "aggressive",
    "suspicious_recall",
    "malicious_recall",
    "threat_positive",
]


def _optional_imports():
    try:
        import joblib
        import pandas as pd
        from sklearn.compose import ColumnTransformer
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.impute import SimpleImputer
        from sklearn.metrics import accuracy_score, confusion_matrix, precision_recall_fscore_support
        from sklearn.model_selection import train_test_split
        from sklearn.pipeline import Pipeline
        from sklearn.preprocessing import OneHotEncoder
    except ImportError:
        return None
    return (
        joblib,
        pd,
        ColumnTransformer,
        RandomForestClassifier,
        SimpleImputer,
        accuracy_score,
        confusion_matrix,
        precision_recall_fscore_support,
        train_test_split,
        Pipeline,
        OneHotEncoder,
    )


def supervised_model_path(path: str | Path | None = None) -> Path:
    if path is not None:
        model_path = Path(path)
        return model_path if model_path.is_absolute() else Path(get_settings().resolved_model_path).parent / model_path
    settings = get_settings()
    return settings.resolved_supervised_model_path


def _artifact_hash(path: Path) -> str | None:
    if not path.exists():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


@lru_cache(maxsize=4)
def _load_supervised_artifact(path_string: str, modified_ns: int) -> dict[str, Any] | None:
    _ = modified_ns
    imports = _optional_imports()
    if imports is None:
        return None
    joblib = imports[0]
    return joblib.load(Path(path_string))


def _report_path_for_model(path: Path) -> Path:
    return path.with_suffix(".report.md")


def _render_supervised_report(result: dict) -> str:
    metrics = result.get("metrics") or {}
    evaluation = result.get("evaluation") or {}
    promotion_gate = result.get("promotion_gate") or {}
    labels = metrics.get("labels") or sorted((result.get("label_distribution") or {}).keys())
    matrix = metrics.get("confusion_matrix") or []
    matrix_lines = ["| Actual \\ Predicted | " + " | ".join(str(label) for label in labels) + " |"]
    matrix_lines.append("| --- | " + " | ".join("---" for _ in labels) + " |")
    for label, row in zip(labels, matrix, strict=False):
        matrix_lines.append("| " + str(label) + " | " + " | ".join(str(value) for value in row) + " |")
    feature_lines = "\n".join(f"- `{column}`" for column in result.get("feature_columns", []))
    distribution_lines = "\n".join(f"- {label}: {count}" for label, count in (result.get("label_distribution") or {}).items())
    source_lines = "\n".join(f"- {source}: {count}" for source, count in (result.get("label_source_distribution") or {}).items())
    reviewed_lines = "\n".join(f"- {label}: {count}" for label, count in (result.get("reviewed_label_distribution") or {}).items())
    weak_lines = "\n".join(f"- {label}: {count}" for label, count in (result.get("weak_label_distribution") or {}).items())
    warning_lines = "\n".join(f"- {warning}" for warning in (result.get("validation_warnings") or []))
    diagnostics = result.get("training_dataset_diagnostics") or {}
    eval_lines = []
    for key in ["mixed_label_evaluation", "weak_label_evaluation", "reviewed_label_evaluation"]:
        item = evaluation.get(key) or {}
        item_metrics = item.get("metrics") or {}
        eval_lines.append(
            "- {name}: status={status}, rows={rows}, F1={f1}, quality={quality}".format(
                name=item.get("name", key),
                status=item.get("status", "not_available"),
                rows=item.get("rows", 0),
                f1=item_metrics.get("f1", "not_available"),
                quality=item.get("label_quality", "unknown"),
            )
        )
    feature_generation = result.get("feature_generation") or {}
    cost = metrics.get("cost_sensitive") or {}
    threat_positive = metrics.get("threat_positive") or {}
    direct_metrics = result.get("direct_model_metrics") or {}
    sample_weighting = result.get("sample_weighting") or {}
    readiness = result.get("model_readiness_checklist") or {}
    readiness_lines = "\n".join(
        "- [{mark}] {name}: {detail} (target: {target})".format(
            mark="x" if item.get("passed") else " ",
            name=item.get("name", "readiness item"),
            detail=item.get("detail", ""),
            target=item.get("target") or "not_specified",
        )
        for item in readiness.get("items", [])
    )
    return f"""# ATDR Supervised AI Model Evaluation

## Model

- Model name: {result.get("model_name", MODEL_NAME)}
- Model type: {result.get("model_type", "random_forest")}
- Model version: {result.get("model_version", "not_trained")}
- Status: {result.get("status", "unknown")}
- Model path: {result.get("model_path", "")}
- Artifact SHA-256: {result.get("artifact_sha256") or "not_available"}
- Split strategy: {result.get("split_strategy", "random")}
- Label quality: {result.get("label_quality", "unknown")}
- Threshold profile: {result.get("threshold_profile", "balanced")}
- Feature set version: {(result.get("feature_set_metadata") or {}).get("feature_set_version", FEATURE_SET_VERSION)}
- Feature code hash: {(result.get("feature_set_metadata") or {}).get("feature_code_hash", "not_available")}
- Dataset snapshot ID: {result.get("dataset_snapshot_id") or "not_linked"}
- Production promoted: false
- Response automation allowed: false

## Dataset

- Training rows: {result.get("training_rows", 0)}
- Test rows: {result.get("test_rows", 0)}
- Total label rows: {diagnostics.get("total_label_rows", "not_available")}
- Latest trainable rows: {diagnostics.get("trainable_latest_rows", "not_available")}
- Excluded label-history rows: {diagnostics.get("excluded_from_training", "not_available")}
- Superseded label rows: {diagnostics.get("superseded_label_rows", "not_available")}
- Missing timestamp latest rows: {diagnostics.get("missing_timestamp_latest_rows", "not_available")}
- Feature-excluded rows: {diagnostics.get("feature_excluded_rows", "not_available")}

{diagnostics.get("explanation", "")}

## Label Distribution

{distribution_lines or "- No labels available"}

## Label Provenance

{source_lines or "- No label-source distribution available"}

- Reviewed label rows: {result.get("reviewed_label_count", "not_available")}
- Unreviewed assisted label rows: {result.get("unreviewed_assisted_label_count", "not_available")}

### Reviewed Label Distribution

{reviewed_lines or "- No reviewed labels available"}

### Weak Label Distribution

{weak_lines or "- No unreviewed assisted labels available"}

## Metrics

- Accuracy: {metrics.get("accuracy", "not_available")}
- Precision: {metrics.get("precision", "not_available")}
- Recall: {metrics.get("recall", "not_available")}
- F1: {metrics.get("f1", "not_available")}
- Macro F1: {(metrics.get("macro_average") or {}).get("f1", "not_available")}
- Weighted F1: {(metrics.get("weighted_average") or {}).get("f1", "not_available")}
- Threat-positive precision: {threat_positive.get("precision", "not_available")}
- Threat-positive recall: {threat_positive.get("recall", "not_available")}
- Threat-positive F1: {threat_positive.get("f1", "not_available")}

Direct model F1 before threshold policy: {direct_metrics.get("f1", "not_available")}

## Cost-Sensitive Triage Report

- Total cost: {cost.get("total_cost", "not_available")}
- Average cost: {cost.get("average_cost", "not_available")}
- High-cost errors: {cost.get("high_cost_errors", "not_available")}
- Threat false negatives: {cost.get("threat_false_negatives", "not_available")}
- Benign predicted malicious: {cost.get("benign_predicted_malicious", "not_available")}

## Sample Weighting

- Enabled: {sample_weighting.get("enabled", False)}
- Average weight: {sample_weighting.get("average_weight", "not_available")}
- Max weight: {sample_weighting.get("max_weight", "not_available")}

## Reviewed / Weak / Mixed Evaluation

{chr(10).join(eval_lines) if eval_lines else "- No evaluation subsets available"}

## Validation Warnings

{warning_lines or "- No validation warnings"}

## Model Promotion Gate

- Decision: {promotion_gate.get("decision", "candidate_only")}
- Analyst review eligible: {promotion_gate.get("analyst_review_eligible", False)}
- Production promoted: {promotion_gate.get("production_promoted", False)}
- Response automation allowed: {promotion_gate.get("response_automation_allowed", False)}

## Model Readiness Checklist

- Status: {readiness.get("status", "candidate_only")}
- Passed: {readiness.get("passed", 0)} / {readiness.get("total", 0)}

{readiness_lines or "- No readiness checklist available."}

## Feature Generation Performance

- Rows processed: {feature_generation.get("rows_processed", "not_available")}
- Duration seconds: {feature_generation.get("duration_seconds", "not_available")}
- Rows per second: {feature_generation.get("rows_per_second", "not_available")}
- Warning: {feature_generation.get("warning") or "none"}

## Confusion Matrix

{chr(10).join(matrix_lines) if matrix else "No confusion matrix available."}

## Feature Columns

{feature_lines or "- No feature columns available"}

## Limitations

- This model is decision support only. Rule evidence and analyst review remain authoritative.
- Metrics are only meaningful when labels are representative of the small office environment being monitored.
- Weak-label and mixed-label metrics are development indicators, not production accuracy.
- The model can miss novel activity and can overfit small or synthetic label sets.
- Response actions must remain simulated or analyst-approved until firewall integration is formally authorized and tested.
"""


def _write_supervised_report(path: Path, result: dict) -> Path:
    report_path = _report_path_for_model(path)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(_render_supervised_report(result), encoding="utf-8")
    return report_path


def _latest_labels(db: Session) -> list[MLLabel]:
    labels = list(
        db.scalars(
            select(MLLabel)
            .join(MLLabel.log)
            .where(MLLabel.label.in_(TRAINABLE_LABELS))
            .order_by(MLLabel.log_id, desc(MLLabel.created_at), desc(MLLabel.id))
        )
    )
    latest: dict[int, MLLabel] = {}
    for label in labels:
        latest.setdefault(label.log_id, label)
    return list(latest.values())


def training_dataset_diagnostics(db: Session) -> dict[str, Any]:
    total_label_rows = int(db.scalar(select(func.count(MLLabel.id))) or 0)
    labels_with_logs = list(db.scalars(select(MLLabel).join(MLLabel.log).where(MLLabel.label.in_(TRAINABLE_LABELS))))
    latest_labels = _latest_labels(db)
    latest_ids = {label.id for label in latest_labels}
    superseded_trainable = [label for label in labels_with_logs if label.id not in latest_ids]
    missing_log_rows = int(
        db.scalar(select(func.count(MLLabel.id)).outerjoin(MLLabel.log).where(NormalizedLog.id.is_(None))) or 0
    )
    non_trainable_rows = int(db.scalar(select(func.count(MLLabel.id)).where(MLLabel.label.notin_(TRAINABLE_LABELS))) or 0)
    missing_timestamp = sum(1 for label in latest_labels if label.log and _log_timestamp(label.log) is None)
    feature_excluded = 0
    feature_errors: list[dict[str, Any]] = []
    for label in latest_labels:
        try:
            if label.log is not None:
                build_log_features(db, label.log)
        except Exception as exc:  # pragma: no cover - defensive diagnostic path
            feature_excluded += 1
            feature_errors.append({"log_id": label.log_id, "error": str(exc)[:200]})
    trainable_latest_rows = len(latest_labels)
    excluded_from_training = total_label_rows - trainable_latest_rows
    return {
        "total_label_rows": total_label_rows,
        "trainable_latest_rows": trainable_latest_rows,
        "excluded_from_training": excluded_from_training,
        "superseded_label_rows": len(superseded_trainable),
        "missing_log_rows": missing_log_rows,
        "non_trainable_label_rows": non_trainable_rows,
        "missing_timestamp_latest_rows": missing_timestamp,
        "feature_excluded_rows": feature_excluded,
        "feature_error_examples": feature_errors[:10],
        "explanation": (
            "Training uses one latest trainable label per normalized log. Extra label rows are retained as review history "
            "but are excluded from train/test so older decisions do not double-count the same log."
        ),
    }


def _label_distribution(labels: list[str]) -> dict[str, int]:
    return {label: labels.count(label) for label in sorted(set(labels))}


def _label_source_distribution(labels: list[MLLabel]) -> dict[str, int]:
    sources = [getattr(label, "label_source", "manual") for label in labels]
    return {source: sources.count(source) for source in sorted(set(sources))}


def _reviewed_distribution(labels: list[MLLabel]) -> dict[str, int]:
    reviewed = [label.label for label in labels if getattr(label, "reviewed", True)]
    return _label_distribution(reviewed)


def _weak_distribution(labels: list[MLLabel]) -> dict[str, int]:
    weak = [
        label.label
        for label in labels
        if not getattr(label, "reviewed", True) and str(getattr(label, "label_source", "")).startswith("assisted")
    ]
    return _label_distribution(weak)


def _label_quality(labels: list[MLLabel]) -> str:
    if not labels:
        return "unlabeled"
    reviewed = sum(1 for label in labels if getattr(label, "reviewed", True))
    weak = sum(
        1
        for label in labels
        if not getattr(label, "reviewed", True) and str(getattr(label, "label_source", "")).startswith("assisted")
    )
    if reviewed == len(labels):
        return "reviewed-label"
    if reviewed and weak:
        return "mixed-label"
    if weak:
        return "weak-label"
    return "manual-label"


def _class_support_warnings(
    label_distribution: dict[str, int],
    reviewed_distribution: dict[str, int],
    weak_distribution: dict[str, int],
) -> list[str]:
    warnings: list[str] = []
    reviewed_total = sum(reviewed_distribution.values())
    weak_total = sum(weak_distribution.values())
    total = sum(label_distribution.values())
    if reviewed_total < REVIEWED_LABEL_TARGET:
        warnings.append("Reviewed-label sample is too small for reliable model validation.")
    for label in IMPORTANT_CLASSES:
        if int(label_distribution.get(label, 0)) < MIN_CLASS_SUPPORT:
            warnings.append(f"{label} class has very low support.")
        if reviewed_total and int(reviewed_distribution.get(label, 0)) < MIN_CLASS_SUPPORT:
            warnings.append(f"reviewed {label} class has very low support.")
    if total and weak_total / total >= 0.5:
        warnings.append("Metrics are mostly weak-label based.")
    warnings.append("Do not claim production accuracy from this evaluation.")
    return list(dict.fromkeys(warnings))


def _log_timestamp(log: NormalizedLog) -> datetime | None:
    return log.generated_time or log.receive_time or log.start_time


def _metrics_from_predictions(
    *,
    accuracy_score,
    confusion_matrix,
    precision_recall_fscore_support,
    y_true: list[str],
    predictions: list[str],
    labels_order: list[str],
) -> dict[str, Any]:
    weighted = precision_recall_fscore_support(y_true, predictions, labels=labels_order, average="weighted", zero_division=0)
    macro = precision_recall_fscore_support(y_true, predictions, labels=labels_order, average="macro", zero_division=0)
    per_class = precision_recall_fscore_support(y_true, predictions, labels=labels_order, average=None, zero_division=0)
    threat_positive = _threat_positive_metrics(y_true, predictions)
    return {
        "accuracy": round(float(accuracy_score(y_true, predictions)), 4),
        "precision": round(float(weighted[0]), 4),
        "recall": round(float(weighted[1]), 4),
        "f1": round(float(weighted[2]), 4),
        "macro_average": {
            "precision": round(float(macro[0]), 4),
            "recall": round(float(macro[1]), 4),
            "f1": round(float(macro[2]), 4),
        },
        "weighted_average": {
            "precision": round(float(weighted[0]), 4),
            "recall": round(float(weighted[1]), 4),
            "f1": round(float(weighted[2]), 4),
        },
        "per_class": {
            label: {
                "precision": round(float(per_class[0][index]), 4),
                "recall": round(float(per_class[1][index]), 4),
                "f1": round(float(per_class[2][index]), 4),
                "support": int(per_class[3][index]),
            }
            for index, label in enumerate(labels_order)
        },
        "threat_positive": threat_positive,
        "cost_sensitive": cost_sensitive_report(y_true, predictions),
        "confusion_matrix": confusion_matrix(y_true, predictions, labels=labels_order).tolist(),
        "labels": labels_order,
    }


def _threat_positive_metrics(y_true: list[str], predictions: list[str]) -> dict[str, Any]:
    threat_labels = {"suspicious", "malicious"}
    true_positive = 0
    false_positive = 0
    false_negative = 0
    true_negative = 0
    for actual, predicted in zip(y_true, predictions, strict=False):
        actual_threat = actual in threat_labels
        predicted_threat = predicted in threat_labels
        if actual_threat and predicted_threat:
            true_positive += 1
        elif not actual_threat and predicted_threat:
            false_positive += 1
        elif actual_threat and not predicted_threat:
            false_negative += 1
        else:
            true_negative += 1
    precision = true_positive / (true_positive + false_positive) if true_positive + false_positive else 0.0
    recall = true_positive / (true_positive + false_negative) if true_positive + false_negative else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if precision + recall else 0.0
    return {
        "positive_labels": sorted(threat_labels),
        "precision": round(float(precision), 4),
        "recall": round(float(recall), 4),
        "f1": round(float(f1), 4),
        "support": true_positive + false_negative,
        "true_positive": true_positive,
        "false_positive": false_positive,
        "false_negative": false_negative,
        "true_negative": true_negative,
        "interpretation": "Combined suspicious+malicious metric for SOC triage only; it does not replace per-class validation.",
    }


def _subset_evaluation(
    *,
    name: str,
    quality: str,
    labels: list[MLLabel],
    y_true: list[str],
    predictions: list[str],
    labels_order: list[str],
    accuracy_score,
    confusion_matrix,
    precision_recall_fscore_support,
) -> dict[str, Any]:
    if not y_true:
        return {
            "name": name,
            "label_quality": quality,
            "status": "skipped",
            "rows": 0,
            "metrics": {},
            "warnings": [f"{name} has no rows in the test split."],
        }
    distribution = _label_distribution(y_true)
    warnings = _class_support_warnings(distribution, _reviewed_distribution(labels), _weak_distribution(labels))
    if len(set(y_true)) < 2:
        return {
            "name": name,
            "label_quality": quality,
            "status": "skipped",
            "rows": len(y_true),
            "label_distribution": distribution,
            "metrics": {},
            "warnings": [f"{name} has fewer than two classes in the test split.", *warnings],
        }
    return {
        "name": name,
        "label_quality": quality,
        "status": "computed",
        "rows": len(y_true),
        "label_distribution": distribution,
        "metrics": _metrics_from_predictions(
            accuracy_score=accuracy_score,
            confusion_matrix=confusion_matrix,
            precision_recall_fscore_support=precision_recall_fscore_support,
            y_true=y_true,
            predictions=predictions,
            labels_order=labels_order,
        ),
        "warnings": warnings,
        "reliable": not warnings or warnings == ["Do not claim production accuracy from this evaluation."],
    }


def _build_evaluations(
    *,
    test_labels: list[MLLabel],
    y_test: list[str],
    predictions: list[str],
    labels_order: list[str],
    accuracy_score,
    confusion_matrix,
    precision_recall_fscore_support,
) -> dict[str, Any]:
    weak_indices = [
        index
        for index, label in enumerate(test_labels)
        if not getattr(label, "reviewed", True) and str(getattr(label, "label_source", "")).startswith("assisted")
    ]
    reviewed_indices = [index for index, label in enumerate(test_labels) if getattr(label, "reviewed", True)]
    return {
        "mixed_label_evaluation": _subset_evaluation(
            name="mixed-label evaluation",
            quality="mixed-label",
            labels=test_labels,
            y_true=y_test,
            predictions=predictions,
            labels_order=labels_order,
            accuracy_score=accuracy_score,
            confusion_matrix=confusion_matrix,
            precision_recall_fscore_support=precision_recall_fscore_support,
        ),
        "weak_label_evaluation": _subset_evaluation(
            name="weak-label evaluation",
            quality="weak-label",
            labels=[test_labels[index] for index in weak_indices],
            y_true=[y_test[index] for index in weak_indices],
            predictions=[predictions[index] for index in weak_indices],
            labels_order=labels_order,
            accuracy_score=accuracy_score,
            confusion_matrix=confusion_matrix,
            precision_recall_fscore_support=precision_recall_fscore_support,
        ),
        "reviewed_label_evaluation": _subset_evaluation(
            name="reviewed-label-only evaluation",
            quality="reviewed-label",
            labels=[test_labels[index] for index in reviewed_indices],
            y_true=[y_test[index] for index in reviewed_indices],
            predictions=[predictions[index] for index in reviewed_indices],
            labels_order=labels_order,
            accuracy_score=accuracy_score,
            confusion_matrix=confusion_matrix,
            precision_recall_fscore_support=precision_recall_fscore_support,
        ),
    }


def _split_indices(
    *,
    logs: list[NormalizedLog],
    y: list[str],
    split: str,
    test_size: float,
    train_test_split,
) -> tuple[list[int], list[int], list[str], list[str], list[str]]:
    indices = list(range(len(y)))
    warnings: list[str] = []
    if split == "time":
        timestamped = [(index, _log_timestamp(log)) for index, log in enumerate(logs)]
        missing = sum(1 for _index, timestamp in timestamped if timestamp is None)
        if missing:
            warnings.append(f"{missing} labeled rows are missing timestamps; log id ordering was used as a fallback.")
        ordered = sorted(timestamped, key=lambda item: (item[1] is None, item[1] or datetime.min.replace(tzinfo=timezone.utc), logs[item[0]].id))
        ordered_indices = [index for index, _timestamp in ordered]
        test_count = max(1, math.ceil(len(indices) * test_size))
        test_count = min(test_count, len(indices) - 1)
        train_idx = ordered_indices[:-test_count]
        test_idx = ordered_indices[-test_count:]
        return train_idx, test_idx, [y[index] for index in train_idx], [y[index] for index in test_idx], warnings
    if split == "grouped_stratified":
        warnings.append("Grouped/stratified split is diagnostic only and may overestimate deployment performance.")
        test_count = max(1, math.ceil(len(indices) * test_size))
        test_count = min(test_count, len(indices) - 1)
        target_by_label = {
            label: max(1, min(y.count(label) - 1, round(y.count(label) * test_size)))
            for label in sorted(set(y))
            if y.count(label) > 1
        }
        groups: dict[tuple[str, str, str, str, str], list[int]] = {}
        for index, log in enumerate(logs):
            key = (
                str(log.src_ip or "missing_src"),
                str(log.dst_ip or "missing_dst"),
                str(log.dst_port or "missing_port"),
                str(log.app or "missing_app"),
                str(log.action or "missing_action"),
            )
            groups.setdefault(key, []).append(index)
        group_rows = [
            {
                "key": key,
                "indices": group_indices,
                "counts": _label_distribution([y[index] for index in group_indices]),
                "size": len(group_indices),
            }
            for key, group_indices in groups.items()
        ]
        group_rows.sort(key=lambda item: (item["size"], "|".join(item["key"])))
        test_idx_set: set[int] = set()
        test_counts: dict[str, int] = {label: 0 for label in target_by_label}
        used_groups: set[tuple[str, str, str, str, str]] = set()
        for label, _target in sorted(target_by_label.items(), key=lambda item: y.count(item[0])):
            for group in group_rows:
                if group["key"] in used_groups:
                    continue
                if not group["counts"].get(label):
                    continue
                if len(test_idx_set) + group["size"] > test_count + max(2, math.ceil(test_count * 0.1)):
                    continue
                test_idx_set.update(group["indices"])
                used_groups.add(group["key"])
                for group_label, count in group["counts"].items():
                    if group_label in test_counts:
                        test_counts[group_label] += int(count)
                if test_counts.get(label, 0) >= target_by_label[label]:
                    break
        for group in group_rows:
            if len(test_idx_set) >= test_count:
                break
            if group["key"] in used_groups:
                continue
            if len(test_idx_set) + group["size"] > test_count + max(2, math.ceil(test_count * 0.1)):
                continue
            test_idx_set.update(group["indices"])
            used_groups.add(group["key"])
        if not test_idx_set or len(test_idx_set) >= len(indices):
            warnings.append("Grouped/stratified split fell back to random stratified split because groups were too coarse.")
        else:
            test_idx = sorted(test_idx_set)
            train_idx = [index for index in indices if index not in test_idx_set]
            return train_idx, test_idx, [y[index] for index in train_idx], [y[index] for index in test_idx], warnings
    distribution = _label_distribution(y)
    estimated_test_rows = max(1, math.ceil(len(y) * test_size))
    stratify = y if min(distribution.values()) >= 2 and estimated_test_rows >= len(distribution) else None
    train_idx, test_idx, y_train, y_test = train_test_split(
        indices,
        y,
        test_size=test_size,
        random_state=42,
        stratify=stratify,
    )
    return list(train_idx), list(test_idx), list(y_train), list(y_test), warnings


def _split_class_warnings(y_train: list[str], y_test: list[str]) -> list[str]:
    warnings: list[str] = []
    train_classes = set(y_train)
    test_classes = set(y_test)
    for label in sorted(test_classes - train_classes):
        warnings.append(f"{label} appears in the test split but not in the training split; class recall is not learnable in this run.")
    for label in IMPORTANT_CLASSES:
        if y_train.count(label) < MIN_CLASS_SUPPORT:
            warnings.append(f"training split has very low {label} support.")
        if y_test.count(label) < MIN_CLASS_SUPPORT:
            warnings.append(f"test split has very low {label} support.")
    return list(dict.fromkeys(warnings))


def _promotion_gate_for_training(
    *,
    label_distribution: dict[str, int],
    reviewed_distribution: dict[str, int],
    weak_distribution: dict[str, int],
    metrics: dict[str, Any],
    split: str,
    reviewed_count: int,
    temporal_coverage: dict[str, Any],
) -> dict[str, Any]:
    warnings = _class_support_warnings(label_distribution, reviewed_distribution, weak_distribution)
    per_class = metrics.get("per_class") or {}
    threat_positive = metrics.get("threat_positive") or {}
    macro_f1 = float((metrics.get("macro_average") or {}).get("f1") or 0)
    suspicious_recall = float((per_class.get("suspicious") or {}).get("recall") or 0)
    malicious_recall = float((per_class.get("malicious") or {}).get("recall") or 0)
    malicious_train_count = int(temporal_coverage.get("malicious_train_count") or 0)
    threat_positive_f1 = float(threat_positive.get("f1") or 0)
    for label in IMPORTANT_CLASSES:
        if label in label_distribution and float((per_class.get(label) or {}).get("recall", 0)) == 0:
            warnings.append(f"{label} recall is zero in this test split.")
    analyst_review_eligible = (
        reviewed_count >= REVIEWED_LABEL_TARGET
        and malicious_train_count >= MALICIOUS_TRAINING_MINIMUM
        and malicious_recall > 0
        and suspicious_recall >= 0.7
        and threat_positive_f1 >= 0.85
        and macro_f1 >= 0.6
    )
    production_promoted = False
    if suspicious_recall < 0.8:
        warnings.append("Suspicious recall remains below the 0.8 production-promotion target.")
    return {
        "eligible_for_promotion": False,
        "production_promoted": production_promoted,
        "analyst_review_eligible": bool(analyst_review_eligible),
        "decision": "eligible_for_analyst_review" if analyst_review_eligible else "candidate_only",
        "split": split,
        "warnings": list(dict.fromkeys(warnings)),
        "response_automation_allowed": False,
        "message": (
            "Model is eligible for analyst review, not production promotion."
            if analyst_review_eligible
            else "Model remains candidate-only until reviewed-label validation is stronger."
        )
        + " Response actions remain analyst-approved.",
    }


def _readiness_item(name: str, passed: bool, detail: str, *, target: str | None = None) -> dict[str, Any]:
    return {"name": name, "passed": bool(passed), "detail": detail, "target": target}


def _model_readiness_checklist(
    *,
    metrics: dict[str, Any],
    reviewed_count: int,
    temporal_coverage: dict[str, Any],
) -> dict[str, Any]:
    per_class = metrics.get("per_class") or {}
    suspicious = per_class.get("suspicious") or {}
    malicious = per_class.get("malicious") or {}
    macro_f1 = float((metrics.get("macro_average") or {}).get("f1") or 0)
    malicious_train_count = int(temporal_coverage.get("malicious_train_count") or 0)
    malicious_recall = float(malicious.get("recall") or 0)
    suspicious_recall = float(suspicious.get("recall") or 0)
    checklist = [
        _readiness_item(
            "Malicious exists in training window",
            malicious_train_count >= MALICIOUS_TRAINING_MINIMUM,
            f"malicious_train_count={temporal_coverage.get('malicious_train_count', 0)}",
            target=f">= {MALICIOUS_TRAINING_MINIMUM}",
        ),
        _readiness_item(
            "Malicious exists in test window",
            int(temporal_coverage.get("malicious_test_count") or 0) > 0,
            f"malicious_test_count={temporal_coverage.get('malicious_test_count', 0)}",
            target="> 0",
        ),
        _readiness_item(
            "Suspicious recall remains strong",
            suspicious_recall >= 0.8,
            f"suspicious_recall={suspicious.get('recall', 0)}",
            target=">= 0.8",
        ),
        _readiness_item(
            "Malicious recall above zero",
            malicious_recall > 0,
            f"malicious_recall={malicious.get('recall', 0)}",
            target="> 0",
        ),
        _readiness_item(
            "Reviewed-label support is large enough",
            reviewed_count >= REVIEWED_LABEL_TARGET,
            f"reviewed_label_count={reviewed_count}",
            target=f">= {REVIEWED_LABEL_TARGET}",
        ),
        _readiness_item(
            "Macro F1 has not collapsed",
            macro_f1 >= 0.5,
            f"macro_f1={round(macro_f1, 4)}",
            target=">= 0.5",
        ),
        _readiness_item(
            "Automatic response remains disabled",
            True,
            "Model output is decision support only; containment still requires analyst approval.",
            target="required",
        ),
    ]
    passed = sum(1 for item in checklist if item["passed"])
    improved = malicious_train_count > 0 and malicious_recall > 0 and reviewed_count >= REVIEWED_LABEL_TARGET and macro_f1 >= 0.5
    status = "candidate_improved" if improved else "candidate_only"
    if passed == len(checklist):
        status = "candidate_improved"
    return {
        "status": status,
        "passed": passed,
        "total": len(checklist),
        "items": checklist,
        "message": "Model remains decision support only; promotion requires stable reviewed-label validation and analyst-approved response.",
    }


def _sample_weights(
    labels: list[MLLabel],
    *,
    reviewed_weight: float = 3.0,
    weak_weight: float = 0.55,
) -> tuple[list[float], dict[str, Any]]:
    weights: list[float] = []
    for label in labels:
        weight = 1.0
        source = str(getattr(label, "label_source", "manual") or "manual")
        reviewed = bool(getattr(label, "reviewed", True))
        if source.startswith("assisted") and not reviewed:
            weight *= weak_weight
        if reviewed:
            weight *= reviewed_weight
        if label.label == "malicious":
            weight *= 4.0 if reviewed else 2.0
        elif label.label == "suspicious":
            weight *= 2.0 if reviewed else 1.35
        elif label.label == "needs_context":
            weight *= 1.8
        if label.confidence >= 4:
            weight *= 1.2
        elif label.confidence <= 2:
            weight *= 0.8
        weights.append(round(min(weight, 20.0), 4))
    return weights, {
        "enabled": True,
        "reviewed_multiplier": reviewed_weight,
        "unreviewed_assisted_multiplier": weak_weight,
        "reviewed_malicious_multiplier": 4.0,
        "reviewed_suspicious_multiplier": 2.0,
        "needs_context_multiplier": 1.8,
        "min_weight": round(min(weights), 4) if weights else 0,
        "max_weight": round(max(weights), 4) if weights else 0,
        "average_weight": round(sum(weights) / len(weights), 4) if weights else 0,
    }


def threshold_decision(class_probs: dict[str, float], *, profile: str = "balanced") -> str:
    thresholds = THRESHOLD_PROFILES.get(profile, THRESHOLD_PROFILES["balanced"])
    malicious_probability = float(class_probs.get("malicious", 0.0))
    suspicious_probability = float(class_probs.get("suspicious", 0.0)) + malicious_probability
    needs_context_probability = float(class_probs.get("needs_context", 0.0))
    if malicious_probability >= thresholds["malicious"]:
        return "malicious"
    if suspicious_probability >= thresholds["suspicious"]:
        return "suspicious"
    if needs_context_probability >= thresholds["needs_context"]:
        return "needs_context"
    if class_probs:
        return max(class_probs.items(), key=lambda item: float(item[1]))[0]
    return "needs_context"


def _model_for_type(model_type: str, RandomForestClassifier, *, class_weight: str | None = "balanced"):
    if model_type == "random_forest":
        return RandomForestClassifier(n_estimators=150, random_state=42, class_weight=class_weight)
    if model_type == "extra_trees":
        from sklearn.ensemble import ExtraTreesClassifier

        return ExtraTreesClassifier(n_estimators=180, random_state=42, class_weight=class_weight)
    if model_type == "hist_gradient_boosting":
        from sklearn.ensemble import HistGradientBoostingClassifier

        return HistGradientBoostingClassifier(random_state=42)
    if model_type == "logistic_regression":
        from sklearn.linear_model import LogisticRegression

        return LogisticRegression(max_iter=1000, solver="liblinear", class_weight=class_weight)
    raise ValueError(f"Unsupported supervised model type: {model_type}")


def _build_pipeline(imports, *, model_type: str = "random_forest", class_weight: str | None = "balanced"):
    _, _, ColumnTransformer, RandomForestClassifier, SimpleImputer, *_rest, Pipeline, OneHotEncoder = imports
    preprocessor = ColumnTransformer(
        transformers=[
            ("numeric", SimpleImputer(strategy="median"), NUMERIC_FEATURES),
            (
                "categorical",
                Pipeline(
                    steps=[
                        ("imputer", SimpleImputer(strategy="most_frequent")),
                        ("onehot", OneHotEncoder(handle_unknown="ignore")),
                    ]
                ),
                CATEGORICAL_FEATURES,
            ),
        ]
    )
    return Pipeline(
        steps=[
            ("preprocess", preprocessor),
            ("model", _model_for_type(model_type, RandomForestClassifier, class_weight=class_weight)),
        ]
    )


def _feature_importances(pipeline, limit: int = 10) -> list[dict[str, Any]]:
    model = pipeline.named_steps.get("model")
    preprocessor = pipeline.named_steps.get("preprocess")
    if model is None or preprocessor is None or not hasattr(model, "feature_importances_"):
        return []
    try:
        names = preprocessor.get_feature_names_out()
    except Exception:
        names = FEATURE_COLUMNS
    pairs = sorted(zip(names, model.feature_importances_, strict=False), key=lambda item: float(item[1]), reverse=True)
    return [{"feature": str(name), "importance": round(float(value), 6)} for name, value in pairs[:limit]]


def train_supervised_classifier(
    db: Session,
    *,
    actor: str = "cli",
    model_path: str | Path | None = None,
    test_size: float = 0.3,
    min_samples: int = 6,
    split: str = "random",
    model_type: str = "random_forest",
    class_weight: str | None = "balanced",
    reviewed_weight: float = 3.0,
    weak_weight: float = 0.55,
    threshold_profile: str = "balanced",
    save_candidate: bool = False,
    dataset_snapshot_id: str | None = None,
    training_command: str | None = None,
) -> dict:
    imports = _optional_imports()
    if imports is None:
        return {"trained": False, "status": "skipped", "message": "Supervised ML dependencies are unavailable."}
    (
        joblib,
        pd,
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

    if split not in {"random", "time", "grouped_stratified"}:
        return {"trained": False, "status": "failed", "message": "split must be 'random', 'time', or 'grouped_stratified'."}
    if model_type not in SUPPORTED_SUPERVISED_MODELS:
        return {
            "trained": False,
            "status": "failed",
            "message": f"model_type must be one of {sorted(SUPPORTED_SUPERVISED_MODELS)}.",
        }
    if threshold_profile not in THRESHOLD_PROFILES:
        return {
            "trained": False,
            "status": "failed",
            "message": f"threshold_profile must be one of {sorted(THRESHOLD_PROFILES)}.",
        }
    labels = [label for label in _latest_labels(db) if label.log is not None]
    logs = [label.log for label in labels]
    y = [label.label for label in labels]
    source_distribution = _label_source_distribution(labels)
    reviewed_count = sum(1 for label in labels if getattr(label, "reviewed", True))
    reviewed_distribution = _reviewed_distribution(labels)
    weak_distribution = _weak_distribution(labels)
    unreviewed_assisted_count = sum(
        1 for label in labels if not getattr(label, "reviewed", True) and getattr(label, "label_source", "").startswith("assisted")
    )
    if len(logs) < min_samples or len(set(y)) < 2:
        result = {
            "trained": False,
            "status": "skipped",
            "message": "Need at least two label classes and enough reviewed rows to train supervised model.",
            "training_rows": len(logs),
            "label_distribution": _label_distribution(y),
            "label_source_distribution": source_distribution,
            "reviewed_label_count": reviewed_count,
            "reviewed_label_distribution": reviewed_distribution,
            "weak_label_distribution": weak_distribution,
            "unreviewed_assisted_label_count": unreviewed_assisted_count,
            "validation_warnings": _class_support_warnings(_label_distribution(y), reviewed_distribution, weak_distribution),
        }
        _record_run(db, result, actor=actor, model_path=supervised_model_path(model_path))
        return result

    feature_start = time.perf_counter()
    X = pd.DataFrame(build_feature_rows(db, logs))
    feature_duration = time.perf_counter() - feature_start
    feature_generation = {
        "rows_processed": len(logs),
        "duration_seconds": round(feature_duration, 4),
        "rows_per_second": round(len(logs) / feature_duration, 2) if feature_duration > 0 else len(logs),
        "warning": "Feature generation is slow on this dataset; consider batching/caching before larger lab deployment."
        if feature_duration > 0 and len(logs) / feature_duration < 25
        else None,
    }
    distribution = _label_distribution(y)
    train_idx, test_idx, y_train, y_test, split_warnings = _split_indices(
        logs=logs,
        y=y,
        split=split,
        test_size=test_size,
        train_test_split=train_test_split,
    )
    split_warnings = [*split_warnings, *_split_class_warnings(y_train, y_test)]
    X_train = X.iloc[train_idx]
    X_test = X.iloc[test_idx]
    test_labels = [labels[index] for index in test_idx]
    pipeline = _build_pipeline(imports, model_type=model_type, class_weight=class_weight)
    all_weights, weighting_summary = _sample_weights(labels, reviewed_weight=reviewed_weight, weak_weight=weak_weight)
    train_weights = [all_weights[index] for index in train_idx]
    pipeline.fit(X_train, y_train, model__sample_weight=train_weights)
    direct_predictions = list(pipeline.predict(X_test))
    class_labels = [str(label) for label in getattr(pipeline.named_steps["model"], "classes_", [])]
    probabilities = pipeline.predict_proba(X_test) if hasattr(pipeline, "predict_proba") else []
    predictions = (
        [
            threshold_decision({label: float(prob) for label, prob in zip(class_labels, row, strict=False)}, profile=threshold_profile)
            for row in probabilities
        ]
        if len(probabilities)
        else direct_predictions
    )
    labels_order = sorted(set(y))
    metrics = _metrics_from_predictions(
        accuracy_score=accuracy_score,
        confusion_matrix=confusion_matrix,
        precision_recall_fscore_support=precision_recall_fscore_support,
        y_true=y_test,
        predictions=predictions,
        labels_order=labels_order,
    )
    evaluations = _build_evaluations(
        test_labels=test_labels,
        y_test=y_test,
        predictions=predictions,
        labels_order=labels_order,
        accuracy_score=accuracy_score,
        confusion_matrix=confusion_matrix,
        precision_recall_fscore_support=precision_recall_fscore_support,
    )
    if save_candidate and model_path is None:
        candidate_id = f"{model_type}-{split}-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
        path = supervised_model_path().parent / "supervised_candidates" / f"{candidate_id}.joblib"
    else:
        path = supervised_model_path(model_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    artifact = {
        "pipeline": pipeline,
        "feature_columns": FEATURE_COLUMNS,
        "label_classes": labels_order,
        "positive_labels": sorted(POSITIVE_LABELS),
        "threshold_profiles": THRESHOLD_PROFILES,
        "threshold_profile": threshold_profile,
        "sample_weighting": weighting_summary,
        "model_type": model_type,
        "feature_set_metadata": feature_set_metadata(row_count=len(logs), missing_value_summary=X.isna().sum().to_dict()),
        "dataset_snapshot_id": dataset_snapshot_id,
        "trained_at": datetime.now(timezone.utc).isoformat(),
    }
    joblib.dump(artifact, path)
    result = {
        "trained": True,
        "status": "trained",
        "model_name": MODEL_NAME,
        "model_type": model_type,
        "model_path": str(path),
        "model_version": f"{model_type}-{split}-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}",
        "training_rows": len(X_train),
        "test_rows": len(X_test),
        "metrics": metrics,
        "direct_model_metrics": _metrics_from_predictions(
            accuracy_score=accuracy_score,
            confusion_matrix=confusion_matrix,
            precision_recall_fscore_support=precision_recall_fscore_support,
            y_true=y_test,
            predictions=direct_predictions,
            labels_order=labels_order,
        ),
        "evaluation": evaluations,
        "split_strategy": split,
        "split_warnings": split_warnings,
        "label_quality": _label_quality(labels),
        "label_distribution": _label_distribution(y),
        "label_source_distribution": source_distribution,
        "reviewed_label_distribution": reviewed_distribution,
        "weak_label_distribution": weak_distribution,
        "reviewed_label_count": reviewed_count,
        "unreviewed_assisted_label_count": unreviewed_assisted_count,
        "feature_columns": FEATURE_COLUMNS,
        "feature_set_metadata": artifact["feature_set_metadata"],
        "dataset_snapshot_id": dataset_snapshot_id,
        "sample_weighting": weighting_summary,
        "threshold_profile": threshold_profile,
        "save_candidate": save_candidate,
        "production_promoted": False,
        "response_automation_allowed": False,
        "training_command": training_command,
        "feature_generation": feature_generation,
        "training_dataset_diagnostics": training_dataset_diagnostics(db),
        "top_features": _feature_importances(pipeline),
        "artifact_sha256": _artifact_hash(path),
        "message": f"Trained supervised classifier on {len(X_train)} rows and tested on {len(X_test)} rows.",
    }
    result["class_temporal_coverage"] = build_class_temporal_coverage(db, test_size=test_size)
    result["model_readiness_checklist"] = _model_readiness_checklist(
        metrics=metrics,
        reviewed_count=reviewed_count,
        temporal_coverage=result["class_temporal_coverage"],
    )
    result["validation_warnings"] = _class_support_warnings(distribution, reviewed_distribution, weak_distribution) + split_warnings
    result["promotion_gate"] = _promotion_gate_for_training(
        label_distribution=distribution,
        reviewed_distribution=reviewed_distribution,
        weak_distribution=weak_distribution,
        metrics=metrics,
        split=split,
        reviewed_count=reviewed_count,
        temporal_coverage=result["class_temporal_coverage"],
    )
    result["promotion_gate"]["warnings"] = list(dict.fromkeys([*result["promotion_gate"].get("warnings", []), *split_warnings]))
    if split_warnings:
        result["promotion_gate"]["decision"] = "candidate_only"
        result["promotion_gate"]["eligible_for_promotion"] = False
        result["promotion_gate"]["production_promoted"] = False
        result["promotion_gate"]["analyst_review_eligible"] = False
    report_path = _write_supervised_report(path, result)
    result["report_path"] = str(report_path)
    _record_run(db, result, actor=actor, model_path=path)
    return result


def _record_run(db: Session, result: dict, *, actor: str, model_path: Path) -> None:
    run = MLModelRun(
        model_name=result.get("model_name", MODEL_NAME),
        model_version=result.get("model_version"),
        operation="train_supervised",
        status=result.get("status", "skipped"),
        actor=actor,
        model_path=str(model_path),
        artifact_sha256=result.get("artifact_sha256"),
        artifact_size_bytes=model_path.stat().st_size if model_path.exists() else None,
        training_log_count=result.get("training_rows"),
        feature_columns_json=result.get("feature_columns", FEATURE_COLUMNS),
        metrics_json={
            "metrics": result.get("metrics", {}),
            "model_type": result.get("model_type", "random_forest"),
            "feature_set_metadata": result.get("feature_set_metadata", {}),
            "dataset_snapshot_id": result.get("dataset_snapshot_id"),
            "training_command": result.get("training_command"),
            "save_candidate": result.get("save_candidate", False),
            "production_promoted": False,
            "response_automation_allowed": False,
            "direct_model_metrics": result.get("direct_model_metrics", {}),
            "evaluation": result.get("evaluation", {}),
            "label_distribution": result.get("label_distribution", {}),
            "test_rows": result.get("test_rows", 0),
            "top_features": result.get("top_features", []),
            "report_path": result.get("report_path"),
            "label_source_distribution": result.get("label_source_distribution", {}),
            "reviewed_label_distribution": result.get("reviewed_label_distribution", {}),
            "weak_label_distribution": result.get("weak_label_distribution", {}),
            "reviewed_label_count": result.get("reviewed_label_count"),
            "unreviewed_assisted_label_count": result.get("unreviewed_assisted_label_count"),
            "validation_warnings": result.get("validation_warnings", []),
            "promotion_gate": result.get("promotion_gate", {}),
            "model_readiness_checklist": result.get("model_readiness_checklist", {}),
            "class_temporal_coverage": result.get("class_temporal_coverage", {}),
            "split_strategy": result.get("split_strategy", "random"),
            "split_warnings": result.get("split_warnings", []),
            "label_quality": result.get("label_quality", "unknown"),
            "feature_generation": result.get("feature_generation", {}),
            "sample_weighting": result.get("sample_weighting", {}),
            "training_dataset_diagnostics": result.get("training_dataset_diagnostics", {}),
            "threshold_profile": result.get("threshold_profile", "balanced"),
        },
        message=result.get("message", ""),
    )
    db.add(run)
    db.add(
        AuditLog(
            actor=actor,
            action="train_supervised_model",
            target_type="ml_model",
            target_value=str(model_path),
            details={"status": run.status, "training_rows": run.training_log_count, "metrics": result.get("metrics", {})},
        )
    )
    db.commit()


def supervised_model_report(db: Session) -> dict:
    path = supervised_model_path()
    latest = db.scalar(
        select(MLModelRun)
        .where(MLModelRun.model_name == MODEL_NAME, MLModelRun.operation == "train_supervised")
        .order_by(desc(MLModelRun.created_at), desc(MLModelRun.id))
        .limit(1)
    )
    label_rows = db.execute(select(MLLabel.label, func.count()).group_by(MLLabel.label)).all()
    source_rows = db.execute(select(MLLabel.label_source, func.count()).group_by(MLLabel.label_source)).all()
    reviewed_rows = db.execute(select(MLLabel.label, func.count()).where(MLLabel.reviewed.is_(True)).group_by(MLLabel.label)).all()
    weak_rows = db.execute(
        select(MLLabel.label, func.count())
        .where(MLLabel.reviewed.is_(False), MLLabel.label_source.like("assisted%"))
        .group_by(MLLabel.label)
    ).all()
    reviewed_count = int(db.scalar(select(func.count(MLLabel.id)).where(MLLabel.reviewed.is_(True))) or 0)
    unreviewed_assisted_count = int(
        db.scalar(select(func.count(MLLabel.id)).where(MLLabel.reviewed.is_(False), MLLabel.label_source.like("assisted%"))) or 0
    )
    label_distribution = {str(label): int(count) for label, count in label_rows}
    reviewed_distribution = {str(label): int(count) for label, count in reviewed_rows}
    weak_distribution = {str(label): int(count) for label, count in weak_rows}
    temporal_coverage = build_class_temporal_coverage(db)
    latest_report = _run_to_report(latest) if latest else None
    latest_metrics = (latest_report or {}).get("metrics") or {}
    try:
        from atdr.app.detection.v51_supervised_lifecycle import supervised_lifecycle_status

        lifecycle = supervised_lifecycle_status(db)
    except Exception:
        lifecycle = {
            "lifecycle_state": "inactive",
            "production_promoted": False,
            "response_automation_allowed": False,
            "rule_detection_authoritative": True,
        }
    return {
        "model_name": MODEL_NAME,
        "model_path": str(path),
        "artifact_exists": path.exists(),
        "artifact_sha256": _artifact_hash(path),
        "latest_run": latest_report,
        "label_count": int(db.scalar(select(func.count(MLLabel.id))) or 0),
        "label_distribution": label_distribution,
        "label_source_distribution": {str(source): int(count) for source, count in source_rows},
        "reviewed_label_distribution": reviewed_distribution,
        "weak_label_distribution": weak_distribution,
        "reviewed_label_count": reviewed_count,
        "reviewed_label_target": REVIEWED_LABEL_TARGET,
        "unreviewed_assisted_label_count": unreviewed_assisted_count,
        "validation_warnings": _class_support_warnings(label_distribution, reviewed_distribution, weak_distribution),
        "class_temporal_coverage": temporal_coverage,
        "model_readiness_checklist": (latest_report or {}).get("model_readiness_checklist")
        or _model_readiness_checklist(metrics=latest_metrics, reviewed_count=reviewed_count, temporal_coverage=temporal_coverage),
        "soc_triage_mode": {
            "recommended_ai_mode": "SOC triage decision support",
            "primary_signal": "threat_positive review priority",
            "flat_5_class_status": "not_production_promoted",
            "response_automation_allowed": False,
            "production_promoted": False,
            "limitations": [
                "Threat-positive triage is useful for analyst review.",
                "Flat five-class exact classification is not production-promoted.",
                "Benign and needs_context exact classification remain weak.",
                "Response actions remain simulated and analyst-approved.",
            ],
            "review_profiles": _soc_review_profiles_from_metrics(latest_metrics),
        },
        "decision_support_only": True,
        "governed_lifecycle": lifecycle,
    }


def _soc_review_profiles_from_metrics(metrics: dict[str, Any]) -> list[dict[str, Any]]:
    threat = metrics.get("threat_positive") or {}
    true_positives = threat.get("true_positives")
    false_positives = threat.get("false_positives")
    estimated_queue = None
    if true_positives is not None and false_positives is not None:
        estimated_queue = int(true_positives or 0) + int(false_positives or 0)
    return [
        {
            "profile": "conservative",
            "precision": None,
            "recall": None,
            "false_positives": None,
            "false_negatives": None,
            "estimated_review_queue_size": None,
            "guidance": "Fewer false positives and smaller review queue; run the final SOC report for measured profile metrics.",
            "auto_activation_allowed": False,
        },
        {
            "profile": "balanced",
            "precision": threat.get("precision"),
            "recall": threat.get("recall"),
            "f1": threat.get("f1"),
            "false_positives": false_positives,
            "false_negatives": threat.get("false_negatives"),
            "estimated_review_queue_size": estimated_queue,
            "guidance": "Default dashboard framing from the latest supervised run.",
            "auto_activation_allowed": False,
        },
        {
            "profile": "recall_high",
            "precision": None,
            "recall": None,
            "false_positives": None,
            "false_negatives": None,
            "estimated_review_queue_size": None,
            "guidance": "Catches more threat-positive rows but increases analyst review queue; diagnostic only.",
            "auto_activation_allowed": False,
        },
    ]


def _run_to_report(run: MLModelRun) -> dict:
    metrics = run.metrics_json or {}
    return {
        "id": run.id,
        "model_version": run.model_version,
        "status": run.status,
        "actor": run.actor,
        "training_rows": run.training_log_count,
        "test_rows": metrics.get("test_rows", 0),
        "metrics": metrics.get("metrics", {}),
        "model_type": metrics.get("model_type", "random_forest"),
        "feature_set_metadata": metrics.get("feature_set_metadata", {}),
        "dataset_snapshot_id": metrics.get("dataset_snapshot_id"),
        "training_command": metrics.get("training_command"),
        "save_candidate": metrics.get("save_candidate", False),
        "production_promoted": metrics.get("production_promoted", False),
        "response_automation_allowed": metrics.get("response_automation_allowed", False),
        "direct_model_metrics": metrics.get("direct_model_metrics", {}),
        "evaluation": metrics.get("evaluation", {}),
        "label_distribution": metrics.get("label_distribution", {}),
        "label_source_distribution": metrics.get("label_source_distribution", {}),
        "reviewed_label_distribution": metrics.get("reviewed_label_distribution", {}),
        "weak_label_distribution": metrics.get("weak_label_distribution", {}),
        "reviewed_label_count": metrics.get("reviewed_label_count"),
        "unreviewed_assisted_label_count": metrics.get("unreviewed_assisted_label_count"),
        "validation_warnings": metrics.get("validation_warnings", []),
        "promotion_gate": metrics.get("promotion_gate", {}),
        "model_readiness_checklist": metrics.get("model_readiness_checklist", {}),
        "class_temporal_coverage": metrics.get("class_temporal_coverage", {}),
        "split_strategy": metrics.get("split_strategy", "random"),
        "split_warnings": metrics.get("split_warnings", []),
        "label_quality": metrics.get("label_quality", "unknown"),
        "feature_generation": metrics.get("feature_generation", {}),
        "training_dataset_diagnostics": metrics.get("training_dataset_diagnostics", {}),
        "sample_weighting": metrics.get("sample_weighting", {}),
        "threshold_profile": metrics.get("threshold_profile", "balanced"),
        "target_mode": metrics.get("target_mode"),
        "calibration_method": metrics.get("calibration_method"),
        "threshold": metrics.get("threshold"),
        "strict_gates": metrics.get("strict_gates", {}),
        "shadow_safety_passed": metrics.get("shadow_safety_passed", False),
        "runtime_checks": metrics.get("runtime_checks", {}),
        "selected_strategy_summary": metrics.get("selected_strategy_summary", {}),
        "external_benchmark": metrics.get("external_benchmark", {}),
        "lifecycle_state": metrics.get("lifecycle_state", "inactive"),
        "top_features": metrics.get("top_features", []),
        "report_path": metrics.get("report_path"),
        "created_at": run.created_at,
        "message": run.message,
    }


def supervised_report_markdown(db: Session) -> str:
    latest = db.scalar(
        select(MLModelRun)
        .where(MLModelRun.model_name == MODEL_NAME, MLModelRun.operation == "train_supervised")
        .order_by(desc(MLModelRun.created_at), desc(MLModelRun.id))
        .limit(1)
    )
    if latest is None:
        return _render_supervised_report(
            {
                "status": "not_trained",
                "model_name": MODEL_NAME,
                "model_path": str(supervised_model_path()),
                "label_distribution": {},
                "feature_columns": FEATURE_COLUMNS,
                "message": "No supervised training run has been recorded yet.",
            }
        )
    metrics_json = latest.metrics_json or {}
    report_path = metrics_json.get("report_path")
    if report_path and Path(report_path).exists():
        return Path(report_path).read_text(encoding="utf-8")
    result = {
        "model_name": latest.model_name,
        "model_version": latest.model_version,
        "status": latest.status,
        "model_path": latest.model_path,
        "artifact_sha256": latest.artifact_sha256,
        "training_rows": latest.training_log_count,
        "test_rows": metrics_json.get("test_rows", 0),
        "metrics": metrics_json.get("metrics", {}),
        "model_type": metrics_json.get("model_type", "random_forest"),
        "feature_set_metadata": metrics_json.get("feature_set_metadata", {}),
        "dataset_snapshot_id": metrics_json.get("dataset_snapshot_id"),
        "training_command": metrics_json.get("training_command"),
        "direct_model_metrics": metrics_json.get("direct_model_metrics", {}),
        "label_distribution": metrics_json.get("label_distribution", {}),
        "label_source_distribution": metrics_json.get("label_source_distribution", {}),
        "reviewed_label_distribution": metrics_json.get("reviewed_label_distribution", {}),
        "weak_label_distribution": metrics_json.get("weak_label_distribution", {}),
        "reviewed_label_count": metrics_json.get("reviewed_label_count"),
        "unreviewed_assisted_label_count": metrics_json.get("unreviewed_assisted_label_count"),
        "validation_warnings": metrics_json.get("validation_warnings", []),
        "promotion_gate": metrics_json.get("promotion_gate", {}),
        "split_strategy": metrics_json.get("split_strategy", "random"),
        "label_quality": metrics_json.get("label_quality", "unknown"),
        "feature_generation": metrics_json.get("feature_generation", {}),
        "training_dataset_diagnostics": metrics_json.get("training_dataset_diagnostics", {}),
        "sample_weighting": metrics_json.get("sample_weighting", {}),
        "threshold_profile": metrics_json.get("threshold_profile", "balanced"),
        "feature_columns": latest.feature_columns_json or FEATURE_COLUMNS,
        "message": latest.message,
    }
    return _render_supervised_report(result)


def predict_supervised_log(db: Session, log_id: int, *, rule_score: int = 0, asset_context_weight: int = 0) -> dict:
    imports = _optional_imports()
    if imports is None:
        return {"predicted_label": None, "malicious_probability": 0.0, "confidence": 0.0, "top_contributing_features": []}
    _joblib, pd, *_ = imports
    log = db.get(NormalizedLog, log_id)
    if log is None:
        return {"predicted_label": None, "malicious_probability": 0.0, "confidence": 0.0, "top_contributing_features": []}
    try:
        from atdr.app.detection.v51_supervised_lifecycle import (
            score_governed_supervised_log,
            supervised_lifecycle_status,
        )

        lifecycle = supervised_lifecycle_status(db)
        if lifecycle.get("lifecycle_state") in {"shadow_observation", "decision_support"}:
            return score_governed_supervised_log(db, log)
    except Exception:
        # Governed inference is assistive. Legacy/rule behavior remains available
        # when the lifecycle service itself is unavailable.
        pass
    path = supervised_model_path()
    if not path.exists():
        return {"predicted_label": None, "malicious_probability": 0.0, "confidence": 0.0, "top_contributing_features": []}
    artifact = _load_supervised_artifact(str(path.resolve()), path.stat().st_mtime_ns)
    if artifact is None:
        return {"predicted_label": None, "malicious_probability": 0.0, "confidence": 0.0, "top_contributing_features": []}
    pipeline = artifact["pipeline"]
    frame = pd.DataFrame([build_log_features(db, log)])
    direct_predicted = str(pipeline.predict(frame)[0])
    classes = list(getattr(pipeline.named_steps["model"], "classes_", []))
    probabilities = pipeline.predict_proba(frame)[0] if hasattr(pipeline, "predict_proba") else []
    class_probs = {str(label): float(prob) for label, prob in zip(classes, probabilities, strict=False)}
    predicted = threshold_decision(class_probs, profile=str(artifact.get("threshold_profile", "balanced"))) if class_probs else direct_predicted
    malicious_probability = round(sum(class_probs.get(label, 0.0) for label in POSITIVE_LABELS), 4)
    confidence = round(max(class_probs.values()) if class_probs else 0.0, 4)
    hybrid = hybrid_risk_score(
        rule_score=rule_score,
        isolation_anomaly_score=log.anomaly_score,
        isolation_is_anomaly=log.is_anomaly,
        supervised_malicious_probability=malicious_probability,
        asset_context_weight=asset_context_weight,
    )
    return {
        "predicted_label": predicted,
        "direct_predicted_label": direct_predicted,
        "malicious_probability": malicious_probability,
        "confidence": confidence,
        "top_contributing_features": _feature_importances(pipeline),
        "class_probabilities": class_probs,
        "threshold_profile": str(artifact.get("threshold_profile", "balanced")),
        "hybrid_risk": hybrid,
        "decision_support_only": True,
    }
