import json
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from atdr.app.db.models import MLLabel, MLModelRun, ResponseAction
from atdr.app.detection.v330_detection_ml_quality import OUTPUT_DIR, _source_name
from atdr.app.detection.v331_noise_reduction import (
    _build_pipeline_for_columns,
    _calibration_report,
    _metric_bundle,
    _noise_reduced_weights,
    _probability_rows,
    _profile_summary,
)
from atdr.app.detection.v332_guard_validation import _load_base_dataset, _prepared_for_split, _safe_float, _stability_summary
from atdr.app.detection.v335_split_stability_repair import V335_SPLITS
from atdr.app.detection.v337_evidence_feature_enrichment import enrich_v337_features
from atdr.app.detection.v341_label_semantics_audit import _evidence_bucket
from atdr.app.detection.v342_label_policy_reframing import FPR_BUDGET, SOC_TARGETS, SOC_THREAT_TARGETS, behavior_aware_soc_target
from atdr.app.detection.v343_hybrid_soc_queue import _evidence_snapshot, evidence_first_queue_decision
from atdr.app.detection.supervised_detector import training_dataset_diagnostics


V344_LATEST = "v3_44_two_stage_soc_queue_latest.json"
REVIEW_TARGETS = {"unusual_needs_review", *SOC_THREAT_TARGETS}
QUEUE_LABELS = ["non_threat", "needs_review"]
SEVERITY_LABELS = ["unusual_needs_review", "evidence_backed_suspicious", "malicious_high_confidence"]


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _pattern(log: Any) -> str:
    return f"app={getattr(log, 'app', None) or '-'}|action={getattr(log, 'action', None) or '-'}|port={getattr(log, 'dst_port', None) or '-'}"


def _target_values(prepared: dict[str, Any], frame: Any) -> list[str]:
    return [behavior_aware_soc_target(label, frame.iloc[index]) for index, label in enumerate(prepared["y"])]


def _queue_target(target: str) -> str:
    return "needs_review" if target in REVIEW_TARGETS else "non_threat"


def _queue_metrics(y_true: list[str], predictions: list[str]) -> dict[str, Any]:
    tp = fp = fn = tn = 0
    for actual, predicted in zip(y_true, predictions, strict=False):
        actual_review = actual == "needs_review"
        predicted_review = predicted == "needs_review"
        if actual_review and predicted_review:
            tp += 1
        elif not actual_review and predicted_review:
            fp += 1
        elif actual_review and not predicted_review:
            fn += 1
        else:
            tn += 1
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "queue_precision": round(precision, 4),
        "queue_recall": round(recall, 4),
        "queue_f1": round(f1, 4),
        "queue_false_positive_rate": round(fp / (fp + tn), 4) if fp + tn else 0.0,
        "queue_true_positive": tp,
        "queue_false_positive": fp,
        "queue_false_negative": fn,
        "queue_true_negative": tn,
        "queue_size_estimate": tp + fp,
    }


def _class_list(model: Any) -> list[str]:
    if hasattr(model, "named_steps"):
        return list(model.named_steps["model"].classes_)
    return list(model.classes_)


def _split_train_calibration_indices(prepared: dict[str, Any], queue_values: list[str]) -> dict[str, Any]:
    train_idx = list(prepared["train_idx"])
    train_targets = [queue_values[index] for index in train_idx]
    train_test_split = prepared["imports"][8]
    distribution = Counter(train_targets)
    stratify = train_targets if len(distribution) >= 2 and min(distribution.values()) >= 2 else None
    fit_idx, calibration_idx = train_test_split(
        train_idx,
        test_size=0.25,
        random_state=344,
        stratify=stratify,
    )
    return {
        "fit_idx": list(fit_idx),
        "calibration_idx": list(calibration_idx),
        "fit_rows": len(fit_idx),
        "calibration_rows": len(calibration_idx),
        "calibration_strategy": "stratified_train_internal" if stratify is not None else "train_internal_unstratified",
        "used_test_for_threshold_selection": False,
    }


def _fit_classifier(
    prepared: dict[str, Any],
    augmented: dict[str, Any],
    *,
    indices: list[int],
    targets: list[str],
    model_type: str,
    weight_strategy: str = "strong_benign",
    class_weight: str | None = None,
) -> tuple[Any | None, list[str], dict[str, Any]]:
    y_train = [targets[index] for index in indices]
    if len(indices) < 3 or len(set(y_train)) < 2:
        return None, [], {"status": "skipped", "reason": "not enough class diversity"}
    model = _build_pipeline_for_columns(
        prepared["imports"],
        model_type=model_type,
        class_weight=class_weight,
        numeric_features=augmented["numeric_features"],
        categorical_features=augmented["categorical_features"],
    )
    weights, weight_summary = _noise_reduced_weights(prepared["labels"], weight_strategy)
    fit_kwargs = {}
    if weights is not None and model_type != "logistic_regression":
        fit_kwargs["model__sample_weight"] = [weights[index] for index in indices]
    model.fit(augmented["frame"].iloc[indices], y_train, **fit_kwargs)
    return model, _class_list(model), {"status": "fit", "sample_weighting": weight_summary}


def _prob_rows(model: Any | None, classes: list[str], frame: Any, indices: list[int]) -> list[dict[str, float]]:
    if model is None or not classes:
        return [{} for _ in indices]
    return _probability_rows(model.predict_proba(frame.iloc[indices]), classes)


def _severity_decision(row: Any, probabilities: dict[str, float], thresholds: dict[str, float]) -> str:
    snapshot = _evidence_snapshot(row)
    malicious = _safe_float(probabilities.get("malicious_high_confidence"))
    suspicious = _safe_float(probabilities.get("evidence_backed_suspicious"))
    unusual = _safe_float(probabilities.get("unusual_needs_review"))
    if malicious >= thresholds["malicious"] and snapshot["evidence_strength"] >= 4.0:
        return "malicious_high_confidence"
    if suspicious + malicious >= thresholds["threat"] and snapshot["evidence_strength"] >= 2.5 and not snapshot["low_signal"]:
        return "evidence_backed_suspicious"
    if max(malicious, suspicious, unusual) == 0:
        evidence = evidence_first_queue_decision(row)
        return evidence if evidence != "non_threat" else "unusual_needs_review"
    return "unusual_needs_review"


def _queue_from_stage(
    row: Any,
    queue_probabilities: dict[str, float],
    *,
    strategy: str,
    threshold: float,
) -> str:
    evidence_queue = evidence_first_queue_decision(row) != "non_threat"
    queue_score = _safe_float(queue_probabilities.get("needs_review"))
    snapshot = _evidence_snapshot(row)
    if strategy == "deterministic_queue_ml_severity":
        return "needs_review" if evidence_queue else "non_threat"
    if strategy == "ml_queue_ml_severity":
        return "needs_review" if queue_score >= threshold else "non_threat"
    if strategy == "hybrid_queue_ml_severity":
        if evidence_queue:
            return "needs_review"
        if queue_score >= threshold and not snapshot["low_signal"] and snapshot["evidence_strength"] >= 2.0:
            return "needs_review"
        return "non_threat"
    raise ValueError(f"Unknown v3.44 strategy: {strategy}")  # pragma: no cover


def _final_predictions(
    frame: Any,
    indices: list[int],
    *,
    queue_rows: list[dict[str, float]],
    severity_rows: list[dict[str, float]],
    strategy: str,
    thresholds: dict[str, float],
) -> tuple[list[str], list[str]]:
    queue_predictions: list[str] = []
    final_predictions: list[str] = []
    for position, index in enumerate(indices):
        row = frame.iloc[index]
        queue_prediction = _queue_from_stage(
            row,
            queue_rows[position],
            strategy=strategy,
            threshold=thresholds["queue"],
        )
        queue_predictions.append(queue_prediction)
        if queue_prediction != "needs_review":
            final_predictions.append("non_threat")
        else:
            final_predictions.append(_severity_decision(row, severity_rows[position], thresholds))
    return queue_predictions, final_predictions


def _threshold_grid(strategy: str) -> list[dict[str, float]]:
    queue_values = [0.45] if strategy == "deterministic_queue_ml_severity" else [round(value / 100, 2) for value in range(35, 86, 10)]
    return [
        {
            "queue": queue,
            "threat": round(threat / 100, 2),
            "malicious": malicious,
        }
        for queue in queue_values
        for threat in range(35, 86, 10)
        for malicious in [0.45, 0.6, 0.75]
    ]


def _summary(metrics: dict[str, Any], *, queue_metrics: dict[str, Any]) -> dict[str, Any]:
    summary = _profile_summary(metrics)
    per_class = metrics.get("per_class") or {}
    summary["suspicious_recall"] = (per_class.get("evidence_backed_suspicious") or {}).get("recall")
    summary["malicious_recall"] = (per_class.get("malicious_high_confidence") or {}).get("recall")
    summary["unusual_needs_review_recall"] = (per_class.get("unusual_needs_review") or {}).get("recall")
    summary.update(queue_metrics)
    return summary


def _metrics_for_predictions(prepared: dict[str, Any], y_true: list[str], predictions: list[str]) -> dict[str, Any]:
    return _metric_bundle(
        prepared,
        y_true=y_true,
        predictions=predictions,
        labels_order=list(SOC_TARGETS),
        threat_labels=set(SOC_THREAT_TARGETS),
    )


def _threshold_score(summary: dict[str, Any]) -> tuple[Any, ...]:
    queue_recall = _safe_float(summary.get("queue_recall"))
    queue_fpr = _safe_float(summary.get("queue_false_positive_rate"), 1.0)
    threat_f1 = _safe_float(summary.get("threat_positive_f1"))
    fpr = _safe_float(summary.get("benign_like_false_positive_rate"), 1.0)
    suspicious = _safe_float(summary.get("suspicious_recall"))
    malicious = _safe_float(summary.get("malicious_recall"))
    return (
        1 if fpr <= FPR_BUDGET else 0,
        1 if queue_recall >= 0.8 else 0,
        threat_f1 - 0.35 * fpr - 0.10 * queue_fpr,
        queue_recall,
        suspicious,
        malicious,
        -fpr,
        -queue_fpr,
    )


def _select_thresholds(
    prepared: dict[str, Any],
    frame: Any,
    *,
    strategy: str,
    calibration_idx: list[int],
    y_calibration: list[str],
    queue_calibration: list[str],
    queue_rows: list[dict[str, float]],
    severity_rows: list[dict[str, float]],
) -> dict[str, Any]:
    candidates = []
    for thresholds in _threshold_grid(strategy):
        queue_predictions, final_predictions = _final_predictions(
            frame,
            calibration_idx,
            queue_rows=queue_rows,
            severity_rows=severity_rows,
            strategy=strategy,
            thresholds=thresholds,
        )
        q_metrics = _queue_metrics(queue_calibration, queue_predictions)
        metrics = _metrics_for_predictions(prepared, y_calibration, final_predictions)
        summary = _summary(metrics, queue_metrics=q_metrics)
        candidates.append(
            {
                "thresholds": thresholds,
                "summary": summary,
                "within_fpr_budget": _safe_float(summary.get("benign_like_false_positive_rate"), 1.0) <= FPR_BUDGET,
            }
        )
    selected = max(candidates, key=lambda item: _threshold_score(item["summary"]))
    return {
        "selected_thresholds": selected["thresholds"],
        "selected_on": "train_internal_calibration",
        "used_test_for_threshold_selection": False,
        "selection_fpr_budget": FPR_BUDGET,
        "candidate_count": len(candidates),
        "within_fpr_budget_candidates": sum(1 for item in candidates if item["within_fpr_budget"]),
        "calibration_summary": selected["summary"],
    }


def _fit_two_stage_strategy(
    prepared: dict[str, Any],
    augmented: dict[str, Any],
    *,
    strategy: str,
    model_type: str,
) -> dict[str, Any]:
    frame = augmented["frame"]
    target_values = _target_values(prepared, frame)
    queue_values = [_queue_target(target) for target in target_values]
    split = _split_train_calibration_indices(prepared, queue_values)
    fit_idx = split["fit_idx"]
    calibration_idx = split["calibration_idx"]
    stage_b_fit_idx = [index for index in fit_idx if target_values[index] in REVIEW_TARGETS]
    started = time.perf_counter()
    stage_a_model, stage_a_classes, stage_a_meta = _fit_classifier(
        prepared,
        augmented,
        indices=fit_idx,
        targets=queue_values,
        model_type=model_type,
        weight_strategy="strong_benign",
        class_weight="balanced" if model_type == "logistic_regression" else None,
    )
    stage_b_model, stage_b_classes, stage_b_meta = _fit_classifier(
        prepared,
        augmented,
        indices=stage_b_fit_idx,
        targets=target_values,
        model_type=model_type,
        weight_strategy="strong_benign",
        class_weight="balanced" if model_type == "logistic_regression" else None,
    )
    training_seconds = round(time.perf_counter() - started, 4)
    if strategy != "deterministic_queue_ml_severity" and stage_a_model is None:
        return {"name": f"{strategy}_{model_type}", "status": "skipped", "message": "Stage A model unavailable."}
    if stage_b_model is None:
        return {"name": f"{strategy}_{model_type}", "status": "skipped", "message": "Stage B model unavailable."}
    queue_calibration_rows = _prob_rows(stage_a_model, stage_a_classes, frame, calibration_idx)
    severity_calibration_rows = _prob_rows(stage_b_model, stage_b_classes, frame, calibration_idx)
    y_calibration = [target_values[index] for index in calibration_idx]
    queue_calibration = [queue_values[index] for index in calibration_idx]
    threshold_selection = _select_thresholds(
        prepared,
        frame,
        strategy=strategy,
        calibration_idx=calibration_idx,
        y_calibration=y_calibration,
        queue_calibration=queue_calibration,
        queue_rows=queue_calibration_rows,
        severity_rows=severity_calibration_rows,
    )
    test_idx = list(prepared["test_idx"])
    y_test = [target_values[index] for index in test_idx]
    queue_test = [queue_values[index] for index in test_idx]
    queue_test_rows = _prob_rows(stage_a_model, stage_a_classes, frame, test_idx)
    severity_test_rows = _prob_rows(stage_b_model, stage_b_classes, frame, test_idx)
    queue_predictions, predictions = _final_predictions(
        frame,
        test_idx,
        queue_rows=queue_test_rows,
        severity_rows=severity_test_rows,
        strategy=strategy,
        thresholds=threshold_selection["selected_thresholds"],
    )
    q_metrics = _queue_metrics(queue_test, queue_predictions)
    metrics = _metrics_for_predictions(prepared, y_test, predictions)
    calibration = (
        {"status": "not_applicable", "passed": False, "reason": "Deterministic queue admission."}
        if strategy == "deterministic_queue_ml_severity"
        else _calibration_report(queue_test, stage_a_model.predict_proba(frame.iloc[test_idx]), stage_a_classes, threat_labels={"needs_review"})
    )
    return {
        "name": f"{strategy}_{model_type}",
        "status": "evaluated",
        "target_mode": "two_stage_behavior_aware_soc_queue",
        "model_type": model_type,
        "stage_a": stage_a_meta,
        "stage_b": stage_b_meta,
        "training_seconds": training_seconds,
        "threshold_selection": {
            **split,
            **threshold_selection,
            "stage_b_fit_rows": len(stage_b_fit_idx),
        },
        "summary": _summary(metrics, queue_metrics=q_metrics),
        "metrics": metrics,
        "queue_metrics": q_metrics,
        "calibration": calibration,
        "_predictions": predictions,
        "_queue_predictions": queue_predictions,
        "_y_test": y_test,
        "_queue_test": queue_test,
    }


def _false_positive_patterns(
    prepared: dict[str, Any],
    augmented: dict[str, Any],
    *,
    predictions: list[str],
    y_true: list[str],
) -> dict[str, Any]:
    frame = augmented["frame"]
    rows = []
    for position, (actual, predicted) in enumerate(zip(y_true, predictions, strict=False)):
        if actual in SOC_THREAT_TARGETS or predicted not in SOC_THREAT_TARGETS:
            continue
        index = prepared["test_idx"][position]
        log = prepared["test_logs"][position]
        row = frame.iloc[index]
        rows.append(
            {
                "pattern": _pattern(log),
                "family": str(row.get("v337_traffic_family") or "unknown"),
                "source_name": _source_name(log),
                "evidence_bucket": _evidence_bucket(row),
            }
        )
    return {
        "false_positive_count": len(rows),
        "top_patterns": Counter(row["pattern"] for row in rows).most_common(12),
        "top_traffic_families": Counter(row["family"] for row in rows).most_common(10),
        "top_evidence_buckets": Counter(row["evidence_bucket"] for row in rows).most_common(10),
        "top_sources": Counter(row["source_name"] for row in rows).most_common(10),
    }


def _strategy_rows(prepared: dict[str, Any], augmented: dict[str, Any], strategies: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for strategy in strategies:
        if strategy.get("status") != "evaluated":
            rows.append({key: strategy.get(key) for key in ["name", "status", "message", "target_mode"]})
            continue
        rows.append(
            {
                "name": strategy["name"],
                "status": strategy["status"],
                "target_mode": strategy.get("target_mode"),
                "model_type": strategy.get("model_type"),
                "summary": strategy["summary"],
                "queue_metrics": strategy.get("queue_metrics") or {},
                "calibration": strategy.get("calibration") or {},
                "threshold_selection": strategy.get("threshold_selection") or {},
                "false_positive_patterns": _false_positive_patterns(
                    prepared,
                    augmented,
                    predictions=strategy.get("_predictions") or [],
                    y_true=strategy.get("_y_test") or [],
                ),
            }
        )
    return rows


def _with_custom_metric_ranges(stability: dict[str, Any], strategy_splits: list[dict[str, Any]]) -> dict[str, Any]:
    ranges = dict(stability.get("metric_ranges") or {})
    for metric in [
        "queue_precision",
        "queue_recall",
        "queue_f1",
        "queue_false_positive_rate",
        "unusual_needs_review_recall",
    ]:
        values = [
            _safe_float((row.get("summary") or {}).get(metric))
            for row in strategy_splits
            if (row.get("summary") or {}).get(metric) is not None
        ]
        if values:
            ranges[metric] = {
                "min": round(min(values), 4),
                "max": round(max(values), 4),
                "span": round(max(values) - min(values), 4),
            }
    stability["metric_ranges"] = ranges
    return stability


def _aggregate_by_strategy(split_results: list[dict[str, Any]]) -> dict[str, Any]:
    names = sorted(
        {
            row["name"]
            for split in split_results
            for row in split.get("strategies", [])
            if row.get("status") == "evaluated"
        }
    )
    comparison: dict[str, Any] = {}
    for name in names:
        strategy_splits = []
        calibrations = []
        threshold_rows = []
        fp_patterns = Counter()
        fp_buckets = Counter()
        for split in split_results:
            for row in split.get("strategies", []):
                if row.get("name") != name or row.get("status") != "evaluated":
                    continue
                strategy_splits.append(
                    {
                        "split_mode": split["split_mode"],
                        "status": "evaluated",
                        "training_rows": split["training_rows"],
                        "test_rows": split["test_rows"],
                        "summary": row["summary"],
                    }
                )
                calibrations.append(row.get("calibration") or {})
                threshold_rows.append(row.get("threshold_selection") or {})
                for pattern, count in (row.get("false_positive_patterns") or {}).get("top_patterns") or []:
                    fp_patterns[str(pattern)] += int(count)
                for bucket, count in (row.get("false_positive_patterns") or {}).get("top_evidence_buckets") or []:
                    fp_buckets[str(bucket)] += int(count)
        stability = _with_custom_metric_ranges(_stability_summary(strategy_splits), strategy_splits)
        best_calibration = max(
            calibrations,
            key=lambda item: (
                1 if item.get("passed") else 0,
                -_safe_float(item.get("expected_calibration_error"), 1),
                -_safe_float(item.get("max_confidence_accuracy_gap"), 1),
            ),
            default={},
        )
        comparison[name] = {
            "stability": stability,
            "best_calibration": best_calibration,
            "threshold_selection": {
                "used_test_for_threshold_selection": any(
                    bool(row.get("used_test_for_threshold_selection")) for row in threshold_rows
                ),
                "selected_on": sorted({str(row.get("selected_on")) for row in threshold_rows if row.get("selected_on")}),
                "top_selected_thresholds": Counter(
                    json.dumps(row.get("selected_thresholds") or {}, sort_keys=True)
                    for row in threshold_rows
                    if row.get("selected_thresholds")
                ).most_common(5),
                "within_fpr_budget_candidates": sum(int(row.get("within_fpr_budget_candidates") or 0) for row in threshold_rows),
            },
            "top_false_positive_patterns": fp_patterns.most_common(12),
            "top_false_positive_evidence_buckets": fp_buckets.most_common(10),
        }
    return comparison


def _range_value(item: dict[str, Any], metric: str, kind: str, default: float = 0.0) -> float:
    ranges = (item.get("stability") or {}).get("metric_ranges") or {}
    return _safe_float((ranges.get(metric) or {}).get(kind), default)


def _select_best(comparison: dict[str, Any]) -> str | None:
    if not comparison:
        return None

    def score(name: str) -> tuple[Any, ...]:
        item = comparison[name]
        max_fpr = _range_value(item, "benign_like_false_positive_rate", "max", 1.0)
        max_queue_fpr = _range_value(item, "queue_false_positive_rate", "max", 1.0)
        min_queue_f1 = _range_value(item, "queue_f1", "min")
        min_queue_recall = _range_value(item, "queue_recall", "min")
        min_threat_f1 = _range_value(item, "threat_positive_f1", "min")
        min_suspicious = _range_value(item, "suspicious_recall", "min")
        min_malicious = _range_value(item, "malicious_recall", "min")
        calibration = item.get("best_calibration") or {}
        return (
            int((item.get("stability") or {}).get("passing_splits") or 0),
            1 if max_fpr <= FPR_BUDGET else 0,
            min_queue_f1 - 0.20 * max_queue_fpr,
            min_queue_recall,
            min_threat_f1,
            min_suspicious,
            min_malicious,
            1 if calibration.get("passed") or calibration.get("status") == "not_applicable" else 0,
            -max_fpr,
        )

    return max(comparison, key=score)


def _readiness(item: dict[str, Any]) -> dict[str, Any]:
    stability = item.get("stability") or {}
    calibration = item.get("best_calibration") or {}
    threshold_selection = item.get("threshold_selection") or {}
    checks = [
        {
            "name": "threshold selection avoids test leakage",
            "passed": not bool(threshold_selection.get("used_test_for_threshold_selection")),
            "value": threshold_selection.get("selected_on"),
            "target": "train-internal only",
        },
        {
            "name": "independent split stability acceptable",
            "passed": bool(stability.get("passed")),
            "value": f"{stability.get('passing_splits')}/{stability.get('evaluated_splits')}",
            "target": "all evaluated splits pass gates",
        },
        {
            "name": "queue recall stable",
            "passed": _range_value(item, "queue_recall", "min") >= 0.8,
            "value": _range_value(item, "queue_recall", "min"),
            "target": ">= 0.8 across splits",
        },
        {
            "name": "queue false-positive rate controlled",
            "passed": _range_value(item, "queue_false_positive_rate", "max", 1.0) <= 0.35,
            "value": _range_value(item, "queue_false_positive_rate", "max", 1.0),
            "target": "<= 0.35 across splits",
        },
        {
            "name": "threat-positive false-positive rate controlled",
            "passed": _range_value(item, "benign_like_false_positive_rate", "max", 1.0) <= FPR_BUDGET,
            "value": _range_value(item, "benign_like_false_positive_rate", "max", 1.0),
            "target": f"<= {FPR_BUDGET} across splits",
        },
        {
            "name": "threat-positive F1 stable",
            "passed": _range_value(item, "threat_positive_f1", "min") >= 0.85,
            "value": _range_value(item, "threat_positive_f1", "min"),
            "target": ">= 0.85 across splits",
        },
        {
            "name": "confidence calibration acceptable",
            "passed": bool(calibration.get("passed")) or calibration.get("status") == "not_applicable",
            "value": calibration.get("status"),
            "target": "passed or deterministic not_applicable",
        },
        {"name": "no labels written", "passed": True, "value": True, "target": "required"},
        {"name": "model activation disabled", "passed": True, "value": False, "target": "required"},
        {"name": "response automation disabled", "passed": True, "value": False, "target": "required"},
    ]
    return {
        "decision": "candidate_only",
        "passed": sum(1 for row in checks if row["passed"]),
        "total": len(checks),
        "production_promoted": False,
        "model_activated": False,
        "model_artifact_written": False,
        "response_automation_allowed": False,
        "blockers": [row["name"] for row in checks if not row["passed"]],
        "checks": checks,
    }


def _render_report(result: dict[str, Any]) -> str:
    rows = []
    for name, item in result.get("strategy_comparison", {}).items():
        ranges = item.get("stability", {}).get("metric_ranges", {})
        rows.append(
            "| {name} | {passed} | {qf1_min}-{qf1_max} | {qfpr_min}-{qfpr_max} | {tf1_min}-{tf1_max} | {fpr_min}-{fpr_max} | {cal} |".format(
                name=name,
                passed=f"{item.get('stability', {}).get('passing_splits')}/{item.get('stability', {}).get('evaluated_splits')}",
                qf1_min=(ranges.get("queue_f1") or {}).get("min"),
                qf1_max=(ranges.get("queue_f1") or {}).get("max"),
                qfpr_min=(ranges.get("queue_false_positive_rate") or {}).get("min"),
                qfpr_max=(ranges.get("queue_false_positive_rate") or {}).get("max"),
                tf1_min=(ranges.get("threat_positive_f1") or {}).get("min"),
                tf1_max=(ranges.get("threat_positive_f1") or {}).get("max"),
                fpr_min=(ranges.get("benign_like_false_positive_rate") or {}).get("min"),
                fpr_max=(ranges.get("benign_like_false_positive_rate") or {}).get("max"),
                cal=item.get("best_calibration", {}).get("status"),
            )
        )
    return f"""# v3.44 Two-Stage SOC Queue Admission And Severity Separation

Generated: {result.get("generated_at")}

This report is diagnostic only. It separates SOC queue admission from severity classification. No labels were written, no model was activated, no artifact was written, and response automation stayed disabled.

## Best Diagnostic Candidate

- Candidate: {result.get("best_strategy")}
- Readiness: {result.get("readiness", {}).get("decision")}
- Checks passed: {result.get("readiness", {}).get("passed")} / {result.get("readiness", {}).get("total")}
- Blockers: {result.get("readiness", {}).get("blockers")}

## Strategy Comparison

| Strategy | Passing Splits | Queue F1 Range | Queue FPR Range | Threat F1 Range | Threat FPR Range | Calibration |
| --- | ---: | --- | --- | --- | --- | --- |
{chr(10).join(rows)}

## Safety

```json
{json.dumps(result.get("safety"), indent=2, default=str)}
```
"""


def run_v344_two_stage_soc_queue(
    db: Session,
    *,
    test_size: float = 0.3,
    min_samples: int = 6,
    output_dir: str | Path = OUTPUT_DIR,
) -> dict[str, Any]:
    before_labels = int(db.scalar(select(func.count(MLLabel.id))) or 0)
    before_runs = int(db.scalar(select(func.count(MLModelRun.id))) or 0)
    before_responses = int(db.scalar(select(func.count(ResponseAction.id))) or 0)
    base = _load_base_dataset(db, min_samples=min_samples)
    if not base.get("ok"):
        return base

    started = time.perf_counter()
    split_results = []
    strategy_specs = [
        ("deterministic_queue_ml_severity", "extra_trees"),
        ("ml_queue_ml_severity", "extra_trees"),
        ("hybrid_queue_ml_severity", "extra_trees"),
        ("ml_queue_ml_severity", "logistic_regression"),
        ("hybrid_queue_ml_severity", "logistic_regression"),
    ]
    for split_mode in V335_SPLITS:
        prepared = _prepared_for_split(base, split_mode=split_mode, test_size=test_size)
        frame, meta = enrich_v337_features(prepared)
        augmented = {"frame": frame, **meta}
        strategies = [
            _fit_two_stage_strategy(prepared, augmented, strategy=strategy, model_type=model_type)
            for strategy, model_type in strategy_specs
        ]
        split_results.append(
            {
                "split_mode": split_mode,
                "status": "evaluated",
                "training_rows": len(prepared["train_idx"]),
                "test_rows": len(prepared["test_idx"]),
                "split_warnings": prepared.get("split_warnings") or [],
                "strategies": _strategy_rows(prepared, augmented, strategies),
            }
        )
    comparison = _aggregate_by_strategy(split_results)
    best_strategy = _select_best(comparison)
    best_item = comparison[best_strategy] if best_strategy else {}
    readiness = _readiness(best_item) if best_item else {
        "decision": "candidate_only",
        "passed": 0,
        "total": 0,
        "production_promoted": False,
        "model_activated": False,
        "model_artifact_written": False,
        "response_automation_allowed": False,
        "blockers": ["no evaluated v3.44 strategy"],
        "checks": [],
    }
    after_labels = int(db.scalar(select(func.count(MLLabel.id))) or 0)
    after_runs = int(db.scalar(select(func.count(MLModelRun.id))) or 0)
    after_responses = int(db.scalar(select(func.count(ResponseAction.id))) or 0)

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    stamp = _stamp()
    report_path = output_path / f"v3_44_two_stage_soc_queue_{stamp}.md"
    latest_path = output_path / V344_LATEST
    result = {
        "ok": True,
        "status": "completed",
        "phase": "v3.44",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "runtime_seconds": round(time.perf_counter() - started, 4),
        "feature_generation_seconds": base.get("feature_generation_seconds"),
        "target_mode": "two_stage_behavior_aware_soc_queue",
        "split_results": split_results,
        "strategy_comparison": comparison,
        "best_strategy": best_strategy,
        "readiness": readiness,
        "training_dataset": training_dataset_diagnostics(db),
        "safety": {
            "production_promoted": False,
            "model_activated": False,
            "model_artifact_written": False,
            "response_automation_allowed": False,
            "real_firewall_blocking_enabled": False,
            "labels_written": False,
            "ml_labels_before": before_labels,
            "ml_labels_after": after_labels,
            "ml_model_runs_before": before_runs,
            "ml_model_runs_after": after_runs,
            "response_actions_before": before_responses,
            "response_actions_after": after_responses,
        },
        "report_path": str(report_path),
        "latest_summary_path": str(latest_path),
    }
    report_path.write_text(_render_report(result), encoding="utf-8")
    latest_path.write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")
    return result
