from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from atdr.app.detection.supervised_detector import (
    _build_pipeline,
    _latest_labels,
    _metrics_from_predictions,
    _optional_imports,
    _sample_weights,
    _split_indices,
    threshold_decision,
)
from atdr.app.ml.features import build_feature_rows


DEFAULT_BOUNDARY_REPORT_PATH = Path("ml_baseline_reviews/suspicious_malicious_boundary_report.md")


def _common_values(labels, predictions: list[str], actual_value: str, predicted_value: str) -> dict[str, list[dict[str, Any]]]:
    matching = [
        label.log
        for label, actual, predicted in zip(labels, [label.label for label in labels], predictions, strict=False)
        if actual == actual_value and predicted == predicted_value and label.log is not None
    ]
    return {
        "ports": [{"value": value, "count": count} for value, count in Counter(log.dst_port for log in matching).most_common(8)],
        "apps": [{"value": value or "unknown", "count": count} for value, count in Counter(log.app or "unknown" for log in matching).most_common(8)],
        "actions": [{"value": value or "unknown", "count": count} for value, count in Counter(log.action or "unknown" for log in matching).most_common(8)],
    }


def _binary_metrics(y_true: list[str], predictions: list[str]) -> dict[str, Any]:
    true_positive = sum(1 for actual, predicted in zip(y_true, predictions, strict=False) if actual == "threat_positive" and predicted == "threat_positive")
    false_positive = sum(1 for actual, predicted in zip(y_true, predictions, strict=False) if actual != "threat_positive" and predicted == "threat_positive")
    false_negative = sum(1 for actual, predicted in zip(y_true, predictions, strict=False) if actual == "threat_positive" and predicted != "threat_positive")
    true_negative = sum(1 for actual, predicted in zip(y_true, predictions, strict=False) if actual != "threat_positive" and predicted != "threat_positive")
    precision = true_positive / (true_positive + false_positive) if true_positive + false_positive else 0.0
    recall = true_positive / (true_positive + false_negative) if true_positive + false_negative else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if precision + recall else 0.0
    return {
        "precision": round(float(precision), 4),
        "recall": round(float(recall), 4),
        "f1": round(float(f1), 4),
        "support": true_positive + false_negative,
        "true_positive": true_positive,
        "false_positive": false_positive,
        "false_negative": false_negative,
        "true_negative": true_negative,
    }


def build_boundary_analysis(db: Session, *, split: str = "time", test_size: float = 0.3, min_samples: int = 6) -> dict[str, Any]:
    imports = _optional_imports()
    if imports is None:
        return {"ok": False, "status": "skipped", "message": "Supervised ML dependencies are unavailable."}
    (
        _joblib,
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
    labels = [label for label in _latest_labels(db) if label.log is not None]
    if len(labels) < min_samples:
        return {"ok": False, "status": "skipped", "message": "Not enough labels for boundary analysis."}
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
    pipeline = _build_pipeline(imports)
    all_weights, weight_summary = _sample_weights(labels)
    pipeline.fit(frame.iloc[train_idx], y_train, model__sample_weight=[all_weights[index] for index in train_idx])
    classes = [str(label) for label in getattr(pipeline.named_steps["model"], "classes_", [])]
    probabilities = pipeline.predict_proba(frame.iloc[test_idx]) if hasattr(pipeline, "predict_proba") else []
    flat_predictions = [
        threshold_decision({label: float(prob) for label, prob in zip(classes, row, strict=False)}, profile="balanced")
        for row in probabilities
    ]
    labels_order = sorted(set(y))
    flat_metrics = _metrics_from_predictions(
        accuracy_score=accuracy_score,
        confusion_matrix=confusion_matrix,
        precision_recall_fscore_support=precision_recall_fscore_support,
        y_true=y_test,
        predictions=flat_predictions,
        labels_order=labels_order,
    )
    test_labels = [labels[index] for index in test_idx]
    boundary_counts = {
        "suspicious_predicted_malicious": sum(1 for actual, predicted in zip(y_test, flat_predictions, strict=False) if actual == "suspicious" and predicted == "malicious"),
        "malicious_predicted_suspicious": sum(1 for actual, predicted in zip(y_test, flat_predictions, strict=False) if actual == "malicious" and predicted == "suspicious"),
        "suspicious_predicted_benign_like": sum(
            1 for actual, predicted in zip(y_test, flat_predictions, strict=False) if actual == "suspicious" and predicted in {"benign", "benign_unusual"}
        ),
        "malicious_predicted_benign_like": sum(
            1 for actual, predicted in zip(y_test, flat_predictions, strict=False) if actual == "malicious" and predicted in {"benign", "benign_unusual"}
        ),
    }
    common_patterns = {
        "suspicious_predicted_malicious": _common_values(test_labels, flat_predictions, "suspicious", "malicious"),
        "malicious_predicted_suspicious": _common_values(test_labels, flat_predictions, "malicious", "suspicious"),
        "suspicious_predicted_benign_unusual": _common_values(test_labels, flat_predictions, "suspicious", "benign_unusual"),
    }

    stage1_y_train = ["threat_positive" if label in {"suspicious", "malicious"} else "non_threat" for label in y_train]
    stage1_y_test = ["threat_positive" if label in {"suspicious", "malicious"} else "non_threat" for label in y_test]
    stage1 = _build_pipeline(imports)
    stage1.fit(frame.iloc[train_idx], stage1_y_train, model__sample_weight=[all_weights[index] for index in train_idx])
    stage1_predictions = [str(value) for value in stage1.predict(frame.iloc[test_idx])]
    stage1_metrics = _binary_metrics(stage1_y_test, stage1_predictions)

    threat_train_idx = [index for index in train_idx if y[index] in {"suspicious", "malicious"}]
    threat_test_positions = [position for position, index in enumerate(test_idx) if y[index] in {"suspicious", "malicious"}]
    stage2_metrics: dict[str, Any]
    if len(threat_train_idx) >= min_samples and len({y[index] for index in threat_train_idx}) >= 2 and threat_test_positions:
        stage2 = _build_pipeline(imports)
        stage2_y_train = [y[index] for index in threat_train_idx]
        stage2.fit(frame.iloc[threat_train_idx], stage2_y_train, model__sample_weight=[all_weights[index] for index in threat_train_idx])
        threat_test_idx = [test_idx[position] for position in threat_test_positions]
        stage2_predictions = [str(value) for value in stage2.predict(frame.iloc[threat_test_idx])]
        stage2_y_test = [y[index] for index in threat_test_idx]
        stage2_metrics = _metrics_from_predictions(
            accuracy_score=accuracy_score,
            confusion_matrix=confusion_matrix,
            precision_recall_fscore_support=precision_recall_fscore_support,
            y_true=stage2_y_test,
            predictions=stage2_predictions,
            labels_order=["malicious", "suspicious"],
        )
    else:
        stage2_metrics = {
            "status": "skipped",
            "message": "Not enough suspicious/malicious support for stage 2 boundary evaluation.",
        }

    warnings = [
        "Hierarchical evaluation is a candidate analysis only; it does not replace the current supervised model.",
        "Metrics are still based on limited reviewed labels and weak-label history.",
        "Response actions remain analyst-approved only.",
    ]
    if y_train.count("malicious") < 20:
        warnings.append("Malicious training-window support remains below the minimum target of 20.")
    stage1_recall = float(stage1_metrics.get("recall") or 0)
    stage2_weighted_f1 = float((stage2_metrics.get("weighted_average") or {}).get("f1") or 0)
    stage2_suspicious_recall = float(((stage2_metrics.get("per_class") or {}).get("suspicious") or {}).get("recall") or 0)
    stage2_malicious_recall = float(((stage2_metrics.get("per_class") or {}).get("malicious") or {}).get("recall") or 0)
    overall_quality = {
        "stage1_blocker": stage1_recall < 0.8,
        "stage2_promising": stage2_weighted_f1 >= 0.7 or (stage2_suspicious_recall >= 0.8 and stage2_malicious_recall >= 0.5),
        "stage1_false_negatives": stage1_metrics.get("false_negative", 0),
        "stage1_false_positives": stage1_metrics.get("false_positive", 0),
        "decision": "candidate_experimental",
        "message": (
            "Stage 2 suspicious/malicious separation is promising, but Stage 1 threat-positive recall is not ready."
            if stage1_recall < 0.8 and (stage2_weighted_f1 >= 0.7 or stage2_suspicious_recall >= 0.8)
            else "Hierarchical candidate remains experimental until both stages validate reliably."
        ),
    }
    return {
        "ok": True,
        "status": "completed",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "split": split,
        "training_rows": len(train_idx),
        "test_rows": len(test_idx),
        "split_warnings": split_warnings,
        "sample_weighting": weight_summary,
        "flat_model": {
            "metrics": flat_metrics,
            "boundary_counts": boundary_counts,
            "common_patterns": common_patterns,
        },
        "hierarchical_candidate": {
            "stage1_threat_positive": stage1_metrics,
            "stage2_suspicious_malicious": stage2_metrics,
            "overall_combined_decision_quality": overall_quality,
        },
        "warnings": warnings,
        "decision_support_only": True,
    }


def render_boundary_report(report: dict[str, Any]) -> str:
    flat = report.get("flat_model") or {}
    flat_metrics = flat.get("metrics") or {}
    per_class = flat_metrics.get("per_class") or {}
    boundary = flat.get("boundary_counts") or {}
    threat = flat_metrics.get("threat_positive") or {}
    hierarchical = report.get("hierarchical_candidate") or {}
    stage1 = hierarchical.get("stage1_threat_positive") or {}
    stage2 = hierarchical.get("stage2_suspicious_malicious") or {}
    overall = hierarchical.get("overall_combined_decision_quality") or {}
    stage2_per_class = stage2.get("per_class") or {}
    warnings = "\n".join(f"- {warning}" for warning in report.get("warnings", []))
    patterns = flat.get("common_patterns") or {}
    pattern_lines = []
    for name, groups in patterns.items():
        pattern_lines.append(f"### {name}")
        for group_name, rows in (groups or {}).items():
            values = ", ".join(f"{row.get('value')} ({row.get('count')})" for row in rows[:5]) or "none"
            pattern_lines.append(f"- {group_name}: {values}")
    return f"""# Suspicious / Malicious Boundary Report

Generated: {report.get("generated_at")}

This report diagnoses whether the supervised model is confusing suspicious and malicious traffic. It is decision support only.

## Flat 5-Class Model

- Weighted F1: {(flat_metrics.get("weighted_average") or {}).get("f1", "n/a")}
- Macro F1: {(flat_metrics.get("macro_average") or {}).get("f1", "n/a")}
- Suspicious recall: {(per_class.get("suspicious") or {}).get("recall", "n/a")}
- Malicious recall: {(per_class.get("malicious") or {}).get("recall", "n/a")}
- Threat-positive precision: {threat.get("precision", "n/a")}
- Threat-positive recall: {threat.get("recall", "n/a")}
- Threat-positive F1: {threat.get("f1", "n/a")}

## Boundary Counts

- Suspicious predicted malicious: {boundary.get("suspicious_predicted_malicious", 0)}
- Malicious predicted suspicious: {boundary.get("malicious_predicted_suspicious", 0)}
- Suspicious predicted benign-like: {boundary.get("suspicious_predicted_benign_like", 0)}
- Malicious predicted benign-like: {boundary.get("malicious_predicted_benign_like", 0)}

## Common Boundary Patterns

{chr(10).join(pattern_lines) if pattern_lines else "- No boundary pattern rows available"}

## Hierarchical Candidate

This candidate is evaluated in two separate stages. Stage 1 decides whether a row is threat-positive at all. Stage 2 only separates suspicious from malicious after Stage 1 has already selected a row.

### Stage 1 Quality: Threat-Positive vs Non-Threat

- Precision: {stage1.get("precision", "n/a")}
- Recall: {stage1.get("recall", "n/a")}
- F1: {stage1.get("f1", "n/a")}
- False positives: {stage1.get("false_positive", "n/a")}
- False negatives: {stage1.get("false_negative", "n/a")}

### Stage 2 Quality: Suspicious vs Malicious

- Weighted F1: {(stage2.get("weighted_average") or {}).get("f1", "n/a")}
- Macro F1: {(stage2.get("macro_average") or {}).get("f1", "n/a")}
- Suspicious recall: {(stage2_per_class.get("suspicious") or {}).get("recall", "n/a")}
- Malicious recall: {(stage2_per_class.get("malicious") or {}).get("recall", "n/a")}

### Overall Combined Decision Quality

- Stage 1 blocker: {overall.get("stage1_blocker", "n/a")}
- Stage 2 promising: {overall.get("stage2_promising", "n/a")}
- Decision: {overall.get("decision", "candidate_experimental")}
- Interpretation: {overall.get("message", "Hierarchical candidate remains experimental.")}

## Warnings

{warnings or "- No warnings"}
"""


def write_boundary_report(
    db: Session,
    *,
    output_path: str | Path = DEFAULT_BOUNDARY_REPORT_PATH,
    split: str = "time",
    test_size: float = 0.3,
    min_samples: int = 6,
) -> dict[str, Any]:
    report = build_boundary_analysis(db, split=split, test_size=test_size, min_samples=min_samples)
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_boundary_report(report), encoding="utf-8")
    return {**report, "report_path": str(path)}
