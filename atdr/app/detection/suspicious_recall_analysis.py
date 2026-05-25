from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from atdr.app.detection.boundary_analysis import build_boundary_analysis
from atdr.app.detection.supervised_detector import (
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
from atdr.app.ml.features import build_feature_rows, build_log_features


DEFAULT_SUSPICIOUS_RECALL_REPORT_PATH = Path("ml_baseline_reviews/suspicious_recall_error_report.md")
BENIGN_LIKE_LABELS = {"benign", "benign_unusual"}


def _is_reviewed(label) -> bool:
    return bool(getattr(label, "reviewed", True))


def _label_source_bucket(label) -> str:
    if _is_reviewed(label):
        return "reviewed"
    source = str(getattr(label, "label_source", "") or "")
    return "weak_assisted" if source.startswith("assisted") else "unreviewed"


def _common_values(rows: list[tuple[Any, str]]) -> dict[str, list[dict[str, Any]]]:
    logs = [label.log for label, _predicted in rows if label.log is not None]
    return {
        "apps": [
            {"value": value or "unknown", "count": count}
            for value, count in Counter(log.app or "unknown" for log in logs).most_common(8)
        ],
        "actions": [
            {"value": value or "unknown", "count": count}
            for value, count in Counter(log.action or "unknown" for log in logs).most_common(8)
        ],
        "destination_ports": [
            {"value": value if value is not None else "missing", "count": count}
            for value, count in Counter(log.dst_port for log in logs).most_common(8)
        ],
        "source_ips": [
            {"value": value or "missing", "count": count}
            for value, count in Counter(log.src_ip or "missing" for log in logs).most_common(8)
        ],
    }


def _behavior_summary(db: Session, label, predicted: str) -> dict[str, Any]:
    log = label.log
    if log is None:
        return {"label_id": label.id, "log_id": label.log_id, "predicted": predicted}
    try:
        features = build_log_features(db, log)
    except Exception:
        features = {}
    return {
        "label_id": label.id,
        "log_id": log.id,
        "generated_time": log.generated_time.isoformat() if getattr(log.generated_time, "isoformat", None) else None,
        "src_ip": log.src_ip,
        "dst_ip": log.dst_ip,
        "app": log.app,
        "action": log.action,
        "dst_port": log.dst_port,
        "reviewed": _is_reviewed(label),
        "label_source": getattr(label, "label_source", None),
        "predicted": predicted,
        "scanning_like_behavior_score": features.get("scanning_like_behavior_score"),
        "src_ip_15min_unique_dst_ports": features.get("src_ip_15min_unique_dst_ports"),
        "src_ip_15min_deny_ratio": features.get("src_ip_15min_deny_ratio"),
        "src_ip_1h_total_bytes": features.get("src_ip_1h_total_bytes"),
        "unknown_app_flag": features.get("unknown_app_flag"),
        "external_to_internal_flag": features.get("external_to_internal_flag"),
    }


def _profile_metrics(
    *,
    class_labels: list[str],
    probabilities,
    y_test: list[str],
    labels_order: list[str],
    accuracy_score,
    confusion_matrix,
    precision_recall_fscore_support,
    profile: str,
) -> tuple[list[str], dict[str, Any]]:
    predictions = [
        threshold_decision({label: float(prob) for label, prob in zip(class_labels, row, strict=False)}, profile=profile)
        for row in probabilities
    ]
    metrics = _metrics_from_predictions(
        accuracy_score=accuracy_score,
        confusion_matrix=confusion_matrix,
        precision_recall_fscore_support=precision_recall_fscore_support,
        y_true=y_test,
        predictions=predictions,
        labels_order=labels_order,
    )
    return predictions, metrics


def _subset_metrics(
    *,
    test_labels,
    y_test: list[str],
    predictions: list[str],
    labels_order: list[str],
    accuracy_score,
    confusion_matrix,
    precision_recall_fscore_support,
    reviewed_only: bool,
) -> dict[str, Any]:
    positions = [index for index, label in enumerate(test_labels) if _is_reviewed(label) is reviewed_only]
    if not positions:
        return {"status": "skipped", "rows": 0, "metrics": {}}
    subset_y = [y_test[index] for index in positions]
    subset_predictions = [predictions[index] for index in positions]
    if len(set(subset_y)) < 2:
        return {"status": "skipped", "rows": len(positions), "metrics": {}, "message": "fewer than two classes"}
    return {
        "status": "computed",
        "rows": len(positions),
        "metrics": _metrics_from_predictions(
            accuracy_score=accuracy_score,
            confusion_matrix=confusion_matrix,
            precision_recall_fscore_support=precision_recall_fscore_support,
            y_true=subset_y,
            predictions=subset_predictions,
            labels_order=labels_order,
        ),
    }


def build_suspicious_recall_error_report(
    db: Session,
    *,
    split: str = "time",
    test_size: float = 0.3,
    min_samples: int = 6,
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
        return {"ok": False, "status": "skipped", "message": "Not enough labels for suspicious recall analysis."}

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
    test_labels = [labels[index] for index in test_idx]
    profiles: list[dict[str, Any]] = []
    predictions_by_profile: dict[str, list[str]] = {}
    for profile in THRESHOLD_PROFILE_ORDER:
        predictions, metrics = _profile_metrics(
            class_labels=class_labels,
            probabilities=probabilities,
            y_test=y_test,
            labels_order=labels_order,
            accuracy_score=accuracy_score,
            confusion_matrix=confusion_matrix,
            precision_recall_fscore_support=precision_recall_fscore_support,
            profile=profile,
        )
        predictions_by_profile[profile] = predictions
        per_class = metrics.get("per_class") or {}
        profiles.append(
            {
                "profile": profile,
                "metrics": metrics,
                "summary": {
                    "suspicious_recall": (per_class.get("suspicious") or {}).get("recall", 0),
                    "malicious_recall": (per_class.get("malicious") or {}).get("recall", 0),
                    "threat_positive_f1": (metrics.get("threat_positive") or {}).get("f1", 0),
                    "macro_f1": (metrics.get("macro_average") or {}).get("f1", 0),
                    "weighted_f1": (metrics.get("weighted_average") or {}).get("f1", 0),
                    "cost": (metrics.get("cost_sensitive") or {}).get("total_cost", 0),
                },
                "reviewed_only": _subset_metrics(
                    test_labels=test_labels,
                    y_test=y_test,
                    predictions=predictions,
                    labels_order=labels_order,
                    accuracy_score=accuracy_score,
                    confusion_matrix=confusion_matrix,
                    precision_recall_fscore_support=precision_recall_fscore_support,
                    reviewed_only=True,
                ),
                "weak_only": _subset_metrics(
                    test_labels=test_labels,
                    y_test=y_test,
                    predictions=predictions,
                    labels_order=labels_order,
                    accuracy_score=accuracy_score,
                    confusion_matrix=confusion_matrix,
                    precision_recall_fscore_support=precision_recall_fscore_support,
                    reviewed_only=False,
                ),
            }
        )

    balanced_predictions = predictions_by_profile.get("balanced", [])
    suspicious_rows = [
        (label, predicted)
        for label, actual, predicted in zip(test_labels, y_test, balanced_predictions, strict=False)
        if actual == "suspicious"
    ]
    error_rows = [(label, predicted) for label, predicted in suspicious_rows if predicted != "suspicious"]
    by_prediction = Counter(predicted for _label, predicted in error_rows)
    by_source = Counter(_label_source_bucket(label) for label, _predicted in error_rows)
    exact_995_rows = [
        (label, predicted)
        for label, predicted in error_rows
        if label.log is not None
        and (label.log.app or "").lower() == "incomplete"
        and (label.log.action or "").lower() == "allow"
        and label.log.dst_port == 995
    ]
    error_examples = [_behavior_summary(db, label, predicted) for label, predicted in error_rows[:20]]
    profile_lookup = {item["profile"]: item["summary"] for item in profiles}
    balanced = profile_lookup.get("balanced", {})
    warnings = [
        "Suspicious recall remains a candidate-model blocker if it is below 0.8.",
        "Threat-positive metrics are useful for SOC triage but do not replace suspicious/malicious per-class validation.",
        "Metrics remain mixed-label development indicators, not production accuracy.",
        "Response actions remain analyst-approved only.",
    ]
    if float(balanced.get("suspicious_recall") or 0) < 0.8:
        warnings.append("Current main blocker: suspicious recall is below the 0.8 target.")
    return {
        "ok": True,
        "status": "completed",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "split": split,
        "training_rows": len(train_idx),
        "test_rows": len(test_idx),
        "split_warnings": split_warnings,
        "sample_weighting": weight_summary,
        "suspicious_support": len(suspicious_rows),
        "suspicious_error_count": len(error_rows),
        "suspicious_error_counts": {
            "predicted_malicious": int(by_prediction.get("malicious", 0)),
            "predicted_benign_unusual": int(by_prediction.get("benign_unusual", 0)),
            "predicted_needs_context": int(by_prediction.get("needs_context", 0)),
            "predicted_benign": int(by_prediction.get("benign", 0)),
        },
        "suspicious_error_source_distribution": dict(by_source),
        "incomplete_allow_995_error_count": len(exact_995_rows),
        "common_error_patterns": {
            "all_suspicious_errors": _common_values(error_rows),
            "suspicious_predicted_malicious": _common_values(
                [(label, predicted) for label, predicted in error_rows if predicted == "malicious"]
            ),
            "suspicious_predicted_benign_like": _common_values(
                [(label, predicted) for label, predicted in error_rows if predicted in BENIGN_LIKE_LABELS]
            ),
        },
        "error_examples": error_examples,
        "threshold_profiles": profiles,
        "hierarchical_candidate": build_boundary_analysis(db, split=split, test_size=test_size, min_samples=min_samples),
        "warnings": warnings,
        "decision_support_only": True,
    }


def render_suspicious_recall_error_report(report: dict[str, Any]) -> str:
    profile_lines = []
    for profile in report.get("threshold_profiles", []):
        summary = profile.get("summary") or {}
        profile_lines.append(
            "| {profile} | {suspicious} | {malicious} | {threat} | {macro} | {weighted} | {cost} |".format(
                profile=profile.get("profile"),
                suspicious=summary.get("suspicious_recall"),
                malicious=summary.get("malicious_recall"),
                threat=summary.get("threat_positive_f1"),
                macro=summary.get("macro_f1"),
                weighted=summary.get("weighted_f1"),
                cost=summary.get("cost"),
            )
        )
    patterns = report.get("common_error_patterns") or {}
    pattern_lines = []
    for name, groups in patterns.items():
        pattern_lines.append(f"### {name}")
        for group_name, rows in (groups or {}).items():
            values = ", ".join(f"{row.get('value')} ({row.get('count')})" for row in rows[:6]) or "none"
            pattern_lines.append(f"- {group_name}: {values}")
    hierarchical = report.get("hierarchical_candidate") or {}
    hierarchical_candidate = hierarchical.get("hierarchical_candidate") or {}
    stage1 = hierarchical_candidate.get("stage1_threat_positive") or {}
    stage2 = hierarchical_candidate.get("stage2_suspicious_malicious") or {}
    stage2_per_class = stage2.get("per_class") or {}
    warnings = "\n".join(f"- {warning}" for warning in report.get("warnings", []))
    errors = report.get("suspicious_error_counts") or {}
    sources = report.get("suspicious_error_source_distribution") or {}
    source_lines = "\n".join(f"- {source}: {count}" for source, count in sources.items())
    return f"""# Suspicious Recall Error Report

Generated: {report.get("generated_at")}

This report diagnoses why current suspicious rows are not being predicted as suspicious. It is decision support only.

## Suspicious Recall Error Summary

- Split: {report.get("split")}
- Training rows: {report.get("training_rows")}
- Test rows: {report.get("test_rows")}
- Suspicious support in test split: {report.get("suspicious_support")}
- Suspicious exact-class errors: {report.get("suspicious_error_count")}
- Suspicious predicted malicious: {errors.get("predicted_malicious", 0)}
- Suspicious predicted benign_unusual: {errors.get("predicted_benign_unusual", 0)}
- Suspicious predicted needs_context: {errors.get("predicted_needs_context", 0)}
- Suspicious predicted benign: {errors.get("predicted_benign", 0)}
- app=incomplete/action=allow/port=995 suspicious errors: {report.get("incomplete_allow_995_error_count", 0)}

## Error Source Distribution

{source_lines or "- No suspicious errors"}

## Threshold / Profile Comparison

| Profile | Suspicious Recall | Malicious Recall | Threat-Positive F1 | Macro F1 | Weighted F1 | Cost |
| --- | --- | --- | --- | --- | --- | --- |
{chr(10).join(profile_lines) if profile_lines else "| none | - | - | - | - | - | - |"}

## Common Error Patterns

{chr(10).join(pattern_lines) if pattern_lines else "- No suspicious error patterns available"}

## Hierarchical Candidate Snapshot

Stage 1 threat-positive:

- Precision: {stage1.get("precision", "n/a")}
- Recall: {stage1.get("recall", "n/a")}
- F1: {stage1.get("f1", "n/a")}

Stage 2 suspicious vs malicious:

- Weighted F1: {(stage2.get("weighted_average") or {}).get("f1", "n/a")}
- Macro F1: {(stage2.get("macro_average") or {}).get("f1", "n/a")}
- Suspicious recall: {(stage2_per_class.get("suspicious") or {}).get("recall", "n/a")}
- Malicious recall: {(stage2_per_class.get("malicious") or {}).get("recall", "n/a")}

## Warnings

{warnings or "- No warnings"}
"""


def write_suspicious_recall_error_report(
    db: Session,
    *,
    output_path: str | Path = DEFAULT_SUSPICIOUS_RECALL_REPORT_PATH,
    split: str = "time",
    test_size: float = 0.3,
    min_samples: int = 6,
) -> dict[str, Any]:
    report = build_suspicious_recall_error_report(db, split=split, test_size=test_size, min_samples=min_samples)
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_suspicious_recall_error_report(report), encoding="utf-8")
    return {**report, "report_path": str(path)}
