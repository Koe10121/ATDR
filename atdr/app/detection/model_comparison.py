import math
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from atdr.app.db.models import MLLabel, NormalizedLog
from atdr.app.detection.cost_sensitive import cost_sensitive_report
from atdr.app.detection.hybrid_scoring import hybrid_risk_score
from atdr.app.detection.rules import build_detection_context, evaluate_rules
from atdr.app.detection.supervised_detector import (
    MIN_CLASS_SUPPORT,
    REVIEWED_LABEL_TARGET,
    TRAINABLE_LABELS,
    _label_distribution,
    _label_source_distribution,
    _latest_labels,
    _sample_weights,
)
from atdr.app.ml.features import CATEGORICAL_FEATURES, FEATURE_COLUMNS, NUMERIC_FEATURES, build_feature_rows


DEFAULT_REPORT_PATH = Path("ml_baseline_reviews/model_comparison_report.md")
POSITIVE_LABELS = {"suspicious", "malicious"}


def _optional_imports():
    try:
        import pandas as pd
        from sklearn.compose import ColumnTransformer
        from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
        from sklearn.impute import SimpleImputer
        from sklearn.linear_model import LogisticRegression
        from sklearn.metrics import accuracy_score, confusion_matrix, precision_recall_fscore_support
        from sklearn.model_selection import train_test_split
        from sklearn.pipeline import Pipeline
        from sklearn.preprocessing import OneHotEncoder
    except ImportError:
        return None
    return (
        pd,
        ColumnTransformer,
        HistGradientBoostingClassifier,
        RandomForestClassifier,
        SimpleImputer,
        LogisticRegression,
        accuracy_score,
        confusion_matrix,
        precision_recall_fscore_support,
        train_test_split,
        Pipeline,
        OneHotEncoder,
    )


def _one_hot_encoder(OneHotEncoder):
    try:
        return OneHotEncoder(handle_unknown="ignore", sparse_output=False)
    except TypeError:
        return OneHotEncoder(handle_unknown="ignore", sparse=False)


def _build_pipeline(imports, model):
    ColumnTransformer = imports[1]
    SimpleImputer = imports[4]
    Pipeline = imports[10]
    OneHotEncoder = imports[11]
    preprocessor = ColumnTransformer(
        transformers=[
            ("numeric", SimpleImputer(strategy="median"), NUMERIC_FEATURES),
            (
                "categorical",
                Pipeline(
                    steps=[
                        ("imputer", SimpleImputer(strategy="most_frequent")),
                        ("onehot", _one_hot_encoder(OneHotEncoder)),
                    ]
                ),
                CATEGORICAL_FEATURES,
            ),
        ]
    )
    return Pipeline(steps=[("preprocess", preprocessor), ("model", model)])


def _label_quality(labels: list[MLLabel]) -> str:
    reviewed = sum(1 for label in labels if getattr(label, "reviewed", True))
    assisted = sum(1 for label in labels if getattr(label, "label_source", "").startswith("assisted"))
    if labels and reviewed == len(labels):
        return "reviewed-label"
    if assisted and reviewed:
        return "mixed weak-label plus reviewed-sample"
    if assisted:
        return "weak-label"
    return "manual-label"


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


def _support_warnings(label_distribution: dict[str, int], reviewed_distribution: dict[str, int], weak_distribution: dict[str, int]) -> list[str]:
    warnings: list[str] = []
    reviewed_total = sum(reviewed_distribution.values())
    total = sum(label_distribution.values())
    weak_total = sum(weak_distribution.values())
    if reviewed_total < REVIEWED_LABEL_TARGET:
        warnings.append("Reviewed-label sample is too small for reliable model validation.")
    for label in ["suspicious", "malicious"]:
        if int(label_distribution.get(label, 0)) < MIN_CLASS_SUPPORT:
            warnings.append(f"{label} class has very low support.")
        if reviewed_total and int(reviewed_distribution.get(label, 0)) < MIN_CLASS_SUPPORT:
            warnings.append(f"reviewed {label} class has very low support.")
    if total and weak_total / total >= 0.5:
        warnings.append("Metrics are mostly weak-label based.")
    warnings.append("Do not claim production accuracy from this evaluation.")
    return list(dict.fromkeys(warnings))


def _false_positive_rate(y_true: list[str], y_pred: list[str]) -> float:
    fp = tn = 0
    for actual, predicted in zip(y_true, y_pred, strict=False):
        actual_positive = actual in POSITIVE_LABELS
        predicted_positive = predicted in POSITIVE_LABELS
        if predicted_positive and not actual_positive:
            fp += 1
        elif not predicted_positive and not actual_positive:
            tn += 1
    return round(fp / (fp + tn), 4) if fp + tn else 0.0


def _metrics(imports, y_test: list[str], predictions: list[str], labels_order: list[str]) -> dict[str, Any]:
    accuracy_score = imports[6]
    confusion_matrix = imports[7]
    precision_recall_fscore_support = imports[8]
    weighted = precision_recall_fscore_support(y_test, predictions, labels=labels_order, average="weighted", zero_division=0)
    macro = precision_recall_fscore_support(y_test, predictions, labels=labels_order, average="macro", zero_division=0)
    per_class = precision_recall_fscore_support(y_test, predictions, labels=labels_order, average=None, zero_division=0)
    return {
        "accuracy": round(float(accuracy_score(y_test, predictions)), 4),
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
        "cost_sensitive": cost_sensitive_report(y_test, predictions),
        "false_positive_rate": _false_positive_rate(y_test, predictions),
        "confusion_matrix": confusion_matrix(y_test, predictions, labels=labels_order).tolist(),
        "labels": labels_order,
    }


def _model_by_name(results: list[dict[str, Any]], name: str) -> dict[str, Any] | None:
    return next((item for item in results if item.get("name") == name), None)


def _recall_for(model: dict[str, Any] | None, label: str) -> float:
    if not model:
        return 0.0
    return float(((model.get("metrics") or {}).get("per_class") or {}).get(label, {}).get("recall", 0.0))


def _promotion_gate(
    *,
    results: list[dict[str, Any]],
    best: dict[str, Any],
    label_distribution: dict[str, int],
    reviewed_distribution: dict[str, int],
    weak_distribution: dict[str, int],
) -> dict[str, Any]:
    baseline = _model_by_name(results, "random_forest")
    baseline_metrics = (baseline or {}).get("metrics") or {}
    best_metrics = best.get("metrics") or {}
    baseline_f1 = float(baseline_metrics.get("f1") or 0)
    best_f1 = float(best_metrics.get("f1") or 0)
    baseline_macro = float((baseline_metrics.get("macro_average") or {}).get("f1") or 0)
    best_macro = float((best_metrics.get("macro_average") or {}).get("f1") or 0)
    reasons: list[str] = []
    warnings = _support_warnings(label_distribution, reviewed_distribution, weak_distribution)
    if best_f1 < baseline_f1 + 0.01 and best_macro < baseline_macro + 0.01:
        reasons.append("Candidate does not meaningfully improve weighted or macro F1 over the current Random Forest baseline.")
    for label in ["suspicious", "malicious"]:
        if int(label_distribution.get(label, 0)) >= MIN_CLASS_SUPPORT and _recall_for(best, label) < _recall_for(baseline, label):
            reasons.append(f"{label} recall is worse than the active Random Forest baseline.")
        if int(label_distribution.get(label, 0)) and _recall_for(best, label) == 0:
            reasons.append(f"{label} recall collapsed to zero.")
    if any("too small" in warning or "very low support" in warning or "weak-label" in warning for warning in warnings):
        reasons.append("Validation evidence is not strong enough for promotion.")
    analyst_review_eligible = not reasons
    return {
        "eligible_for_promotion": False,
        "production_promoted": False,
        "analyst_review_eligible": analyst_review_eligible,
        "decision": "eligible_for_analyst_review" if analyst_review_eligible else "candidate_only",
        "candidate_model": best.get("name"),
        "baseline_model": "random_forest",
        "weighted_f1_delta": round(best_f1 - baseline_f1, 4),
        "macro_f1_delta": round(best_macro - baseline_macro, 4),
        "warnings": warnings,
        "reasons": reasons,
        "response_automation_allowed": False,
        "message": "Comparison can identify analyst-review candidates, but it never production-promotes a model automatically.",
    }


def _hybrid_predictions(db: Session, logs: list[NormalizedLog]) -> list[str]:
    context = build_detection_context(logs)
    predictions: list[str] = []
    for log in logs:
        rule_score = sum(rule.score for rule in evaluate_rules(log, context))
        hybrid = hybrid_risk_score(
            rule_score=rule_score,
            isolation_anomaly_score=log.anomaly_score,
            isolation_is_anomaly=log.is_anomaly,
            supervised_malicious_probability=0,
        )
        score = int(hybrid["final_risk_score"])
        if score >= 80:
            predictions.append("malicious")
        elif score >= 40:
            predictions.append("suspicious")
        elif score >= 20:
            predictions.append("benign_unusual")
        else:
            predictions.append("benign")
    return predictions


def _render_report(result: dict[str, Any]) -> str:
    rows = []
    for model in result.get("models", []):
        metrics = model.get("metrics", {})
        rows.append(
            "| {name} | {accuracy} | {precision} | {recall} | {f1} | {fpr} |".format(
                name=model.get("name"),
                accuracy=metrics.get("accuracy"),
                precision=metrics.get("precision"),
                recall=metrics.get("recall"),
                f1=metrics.get("f1"),
                fpr=metrics.get("false_positive_rate"),
            )
        )
    label_distribution = "\n".join(f"- {label}: {count}" for label, count in result.get("label_distribution", {}).items())
    source_distribution = "\n".join(f"- {source}: {count}" for source, count in result.get("label_source_distribution", {}).items())
    reviewed_distribution = "\n".join(f"- {label}: {count}" for label, count in result.get("reviewed_label_distribution", {}).items())
    weak_distribution = "\n".join(f"- {label}: {count}" for label, count in result.get("weak_label_distribution", {}).items())
    gate = result.get("promotion_gate") or {}
    warning_lines = "\n".join(f"- {warning}" for warning in gate.get("warnings", []))
    reason_lines = "\n".join(f"- {reason}" for reason in gate.get("reasons", []))
    feature_generation = result.get("feature_generation") or {}
    return f"""# ATDR Supervised Model Comparison

Generated: {result.get("generated_at")}

## Label Quality

- Dataset type: {result.get("label_quality")}
- Training rows: {result.get("training_rows")}
- Test rows: {result.get("test_rows")}
- Decision support only: true

These metrics are lab/development indicators only. They are not production accuracy because the dataset can contain weak assisted labels and only a reviewed sample.

## Label Distribution

{label_distribution or "- No labels available"}

## Label Source Distribution

{source_distribution or "- No label source data available"}

## Reviewed Label Distribution

{reviewed_distribution or "- No reviewed label data available"}

## Weak Label Distribution

{weak_distribution or "- No weak label data available"}

## Leaderboard

| Model | Accuracy | Precision | Recall | F1 | False Positive Rate |
| --- | --- | --- | --- | --- | --- |
{chr(10).join(rows) if rows else "| No model | - | - | - | - | - |"}

Best candidate by weighted F1: **{result.get("best_model") or "not_available"}**.

## Promotion Gate

- Decision: {gate.get("decision", "candidate_only")}
- Analyst review eligible: {gate.get("analyst_review_eligible", False)}
- Production promoted: {gate.get("production_promoted", False)}
- Candidate model: {gate.get("candidate_model", result.get("best_model") or "not_available")}
- Weighted F1 delta vs Random Forest: {gate.get("weighted_f1_delta", "not_available")}
- Macro F1 delta vs Random Forest: {gate.get("macro_f1_delta", "not_available")}
- Response automation allowed: {gate.get("response_automation_allowed", False)}

### Warnings

{warning_lines or "- No warnings"}

### Promotion Blockers

{reason_lines or "- No blockers"}

## Feature Generation Performance

- Rows processed: {feature_generation.get("rows_processed", "not_available")}
- Duration seconds: {feature_generation.get("duration_seconds", "not_available")}
- Rows per second: {feature_generation.get("rows_per_second", "not_available")}
- Warning: {feature_generation.get("warning") or "none"}

## Sanity And Safety

- The current production model artifact is not overwritten by this comparison.
- A candidate should only replace the active classifier after improving F1 and passing analyst sanity review.
- Response actions remain analyst-approved and simulated unless explicitly authorized later.
"""


def compare_supervised_models(
    db: Session,
    *,
    output_path: str | Path = DEFAULT_REPORT_PATH,
    test_size: float = 0.3,
    min_samples: int = 6,
) -> dict[str, Any]:
    imports = _optional_imports()
    if imports is None:
        return {"ok": False, "status": "skipped", "message": "Supervised ML dependencies are unavailable."}
    (
        pd,
        _ColumnTransformer,
        HistGradientBoostingClassifier,
        RandomForestClassifier,
        _SimpleImputer,
        LogisticRegression,
        _accuracy_score,
        _confusion_matrix,
        _precision_recall_fscore_support,
        train_test_split,
        _Pipeline,
        _OneHotEncoder,
    ) = imports
    labels = [label for label in _latest_labels(db) if label.log is not None and label.label in TRAINABLE_LABELS]
    logs = [label.log for label in labels]
    y = [label.label for label in labels]
    if len(logs) < min_samples or len(set(y)) < 2:
        result = {
            "ok": False,
            "status": "skipped",
            "message": "Need at least two label classes and enough rows for model comparison.",
            "label_distribution": _label_distribution(y),
        }
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        Path(output_path).write_text(_render_report(result), encoding="utf-8")
        return result

    feature_start = time.perf_counter()
    frame = pd.DataFrame(build_feature_rows(db, logs))
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
    reviewed_distribution = _reviewed_distribution(labels)
    weak_distribution = _weak_distribution(labels)
    estimated_test_rows = max(1, math.ceil(len(y) * test_size))
    stratify = y if min(distribution.values()) >= 2 and estimated_test_rows >= len(distribution) else None
    X_train, X_test, y_train, y_test, train_labels, logs_test = train_test_split(
        frame,
        y,
        labels,
        test_size=test_size,
        random_state=42,
        stratify=stratify,
    )
    _weights, weight_summary = _sample_weights(train_labels)
    labels_order = sorted(set(y))
    candidates = [
        ("random_forest", RandomForestClassifier(n_estimators=150, random_state=42, class_weight="balanced")),
        ("logistic_regression", LogisticRegression(max_iter=1000, solver="liblinear", class_weight="balanced")),
        ("hist_gradient_boosting", HistGradientBoostingClassifier(random_state=42)),
    ]
    results: list[dict[str, Any]] = []
    for name, model in candidates:
        pipeline = _build_pipeline(imports, model)
        pipeline.fit(X_train, y_train, model__sample_weight=_weights)
        predictions = list(pipeline.predict(X_test))
        results.append({"name": name, "metrics": _metrics(imports, y_test, predictions, labels_order)})

    hybrid_predictions = _hybrid_predictions(db, [label.log for label in logs_test if label.log is not None])
    results.append({"name": "hybrid_score_baseline", "metrics": _metrics(imports, y_test, hybrid_predictions, labels_order)})
    best = max(results, key=lambda item: float(item["metrics"].get("f1", 0)))
    promotion_gate = _promotion_gate(
        results=results,
        best=best,
        label_distribution=distribution,
        reviewed_distribution=reviewed_distribution,
        weak_distribution=weak_distribution,
    )
    result = {
        "ok": True,
        "status": "completed",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "label_quality": _label_quality(labels),
        "training_rows": len(X_train),
        "test_rows": len(X_test),
        "label_distribution": distribution,
        "label_source_distribution": _label_source_distribution(labels),
        "reviewed_label_distribution": reviewed_distribution,
        "weak_label_distribution": weak_distribution,
        "feature_columns": FEATURE_COLUMNS,
        "feature_generation": feature_generation,
        "sample_weighting": weight_summary,
        "models": results,
        "best_model": best["name"],
        "promotion_gate": promotion_gate,
        "report_path": str(output_path),
        "message": "Model comparison completed without overwriting the active supervised model.",
    }
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_render_report(result), encoding="utf-8")
    return result
