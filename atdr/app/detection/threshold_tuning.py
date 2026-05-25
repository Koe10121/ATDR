from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from atdr.app.detection.supervised_detector import (
    THRESHOLD_PROFILES,
    THRESHOLD_PROFILE_ORDER,
    _build_pipeline,
    _latest_labels,
    _metrics_from_predictions,
    _optional_imports,
    _sample_weights,
    _split_class_warnings,
    _split_indices,
    threshold_decision,
)
from atdr.app.ml.features import FEATURE_COLUMNS, build_feature_rows


DEFAULT_THRESHOLD_REPORT_PATH = Path("ml_baseline_reviews/threshold_tuning_report.md")


def _render_report(result: dict[str, Any]) -> str:
    rows = []
    for mode in result.get("modes", []):
        metrics = mode.get("metrics", {})
        cost = metrics.get("cost_sensitive") or {}
        rows.append(
            "| {mode} | {accuracy} | {macro_f1} | {weighted_f1} | {malicious_recall} | {suspicious_recall} | {threat_positive_f1} | {cost} | {threat_fn} |".format(
                mode=mode.get("mode"),
                accuracy=metrics.get("accuracy"),
                macro_f1=(metrics.get("macro_average") or {}).get("f1"),
                weighted_f1=(metrics.get("weighted_average") or {}).get("f1"),
                malicious_recall=((metrics.get("per_class") or {}).get("malicious") or {}).get("recall", "n/a"),
                suspicious_recall=((metrics.get("per_class") or {}).get("suspicious") or {}).get("recall", "n/a"),
                threat_positive_f1=(metrics.get("threat_positive") or {}).get("f1", "n/a"),
                cost=cost.get("total_cost"),
                threat_fn=cost.get("threat_false_negatives"),
            )
        )
    return f"""# ATDR Threshold Tuning Report

Generated: {result.get("generated_at")}

This report tunes decision thresholds for supervised ML triage. It does not authorize automatic response actions.

Mode definitions:

- Conservative: fewer false positives, more missed borderline threats.
- Balanced: default SOC triage balance.
- Aggressive: catches more possible threats, creates more false positives.
- Suspicious recall: lowers suspicious threshold while keeping malicious threshold higher to recover suspicious rows.
- Malicious recall: lowers malicious threshold to catch more malicious rows, usually with more boundary confusion.
- Threat positive: optimizes suspicious+malicious triage grouping rather than exact class separation.

| Mode | Accuracy | Macro F1 | Weighted F1 | Malicious Recall | Suspicious Recall | Threat-Positive F1 | Total Cost | Threat False Negatives |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
{chr(10).join(rows) if rows else "| none | - | - | - | - | - | - | - | - |"}

## Safety

- Metrics are development indicators only while labels are mostly weak or limited.
- Response actions remain analyst-approved only.
"""


def tune_model_thresholds(
    db: Session,
    *,
    split: str = "time",
    test_size: float = 0.3,
    min_samples: int = 6,
    output_path: str | Path = DEFAULT_THRESHOLD_REPORT_PATH,
) -> dict[str, Any]:
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
    logs = [label.log for label in labels]
    y = [label.label for label in labels]
    if len(logs) < min_samples or len(set(y)) < 2:
        return {
            "ok": False,
            "status": "skipped",
            "message": "Need at least two label classes and enough rows for threshold tuning.",
        }
    frame = pd.DataFrame(build_feature_rows(db, logs))
    train_idx, test_idx, y_train, y_test, split_warnings = _split_indices(
        logs=logs,
        y=y,
        split=split,
        test_size=test_size,
        train_test_split=train_test_split,
    )
    split_warnings = [*split_warnings, *_split_class_warnings(y_train, y_test)]
    pipeline = _build_pipeline(imports)
    all_weights, weight_summary = _sample_weights(labels)
    pipeline.fit(frame.iloc[train_idx], y_train, model__sample_weight=[all_weights[index] for index in train_idx])
    class_labels = [str(label) for label in getattr(pipeline.named_steps["model"], "classes_", [])]
    probabilities = pipeline.predict_proba(frame.iloc[test_idx]) if hasattr(pipeline, "predict_proba") else []
    labels_order = sorted(set(y))
    modes = []
    for mode in THRESHOLD_PROFILE_ORDER:
        predictions = [
            threshold_decision({label: float(prob) for label, prob in zip(class_labels, row, strict=False)}, profile=mode)
            for row in probabilities
        ]
        modes.append(
            {
                "mode": mode,
                "thresholds": THRESHOLD_PROFILES[mode],
                "metrics": _metrics_from_predictions(
                    accuracy_score=accuracy_score,
                    confusion_matrix=confusion_matrix,
                    precision_recall_fscore_support=precision_recall_fscore_support,
                    y_true=y_test,
                    predictions=predictions,
                    labels_order=labels_order,
                ),
            }
        )
    result = {
        "ok": True,
        "status": "completed",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "split": split,
        "training_rows": len(train_idx),
        "test_rows": len(test_idx),
        "split_warnings": split_warnings,
        "sample_weighting": weight_summary,
        "modes": modes,
        "report_path": str(output_path),
        "decision_support_only": True,
    }
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_render_report(result), encoding="utf-8")
    return result
