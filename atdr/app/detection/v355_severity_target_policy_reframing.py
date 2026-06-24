import json
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from atdr.app.db.models import MLLabel, MLModelRun, ResponseAction
from atdr.app.detection.supervised_detector import training_dataset_diagnostics
from atdr.app.detection.v330_detection_ml_quality import OUTPUT_DIR
from atdr.app.detection.v331_noise_reduction import _calibration_report, _metric_bundle, _profile_summary
from atdr.app.detection.v332_guard_validation import _load_base_dataset, _prepared_for_split, _safe_float
from atdr.app.detection.v335_split_stability_repair import V335_SPLITS
from atdr.app.detection.v344_two_stage_soc_queue import _fit_classifier, _prob_rows, _queue_metrics, _split_train_calibration_indices
from atdr.app.detection.v348_repaired_queue_target_model import _predict_queue, _select_threshold, queue_targets_for_mode
from atdr.app.detection.v349_repaired_queue_severity_model import FPR_BUDGET, _error_patterns
from atdr.app.detection.v352_repaired_interface_severity_model import interface_severity_targets
from atdr.app.detection.v353_severity_feature_repair import enrich_v353_severity_features


V355_LATEST = "v3_55_severity_target_policy_reframing_latest.json"
SEVERITY_MODEL_TYPES = ["extra_trees", "logistic_regression"]

POLICIES: dict[str, dict[str, Any]] = {
    "current_three_severity": {
        "description": "Current downstream target: unusual review, suspicious evidence, and high-confidence malicious.",
        "mapping": {
            "unusual_needs_review": "unusual_needs_review",
            "evidence_backed_suspicious": "evidence_backed_suspicious",
            "malicious_high_confidence": "malicious_high_confidence",
        },
        "labels_order": ["non_threat", "unusual_needs_review", "evidence_backed_suspicious", "malicious_high_confidence"],
        "positive_labels": {"evidence_backed_suspicious", "malicious_high_confidence"},
        "critical_recalls": ["evidence_backed_suspicious", "malicious_high_confidence"],
    },
    "review_needed_vs_malicious": {
        "description": "Collapse unusual and suspicious into review_needed; keep malicious as the only high-confidence severity class.",
        "mapping": {
            "unusual_needs_review": "review_needed",
            "evidence_backed_suspicious": "review_needed",
            "malicious_high_confidence": "malicious_high_confidence",
        },
        "labels_order": ["non_threat", "review_needed", "malicious_high_confidence"],
        "positive_labels": {"malicious_high_confidence"},
        "critical_recalls": ["review_needed", "malicious_high_confidence"],
    },
    "unusual_vs_threat_evidence": {
        "description": "Collapse suspicious and malicious into threat_evidence; keep unusual review separate.",
        "mapping": {
            "unusual_needs_review": "unusual_needs_review",
            "evidence_backed_suspicious": "threat_evidence",
            "malicious_high_confidence": "threat_evidence",
        },
        "labels_order": ["non_threat", "unusual_needs_review", "threat_evidence"],
        "positive_labels": {"threat_evidence"},
        "critical_recalls": ["unusual_needs_review", "threat_evidence"],
    },
    "binary_review_queue": {
        "description": "Only model whether a row enters the SOC review queue.",
        "mapping": {
            "unusual_needs_review": "needs_review",
            "evidence_backed_suspicious": "needs_review",
            "malicious_high_confidence": "needs_review",
        },
        "labels_order": ["non_threat", "needs_review"],
        "positive_labels": {"needs_review"},
        "critical_recalls": ["needs_review"],
        "queue_only": True,
    },
}


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _policy_targets(
    prepared: dict[str, Any],
    frame: Any,
    *,
    policy_name: str,
) -> tuple[list[str], list[str], dict[str, Any]]:
    policy = POLICIES[policy_name]
    queue_values, queue_meta = queue_targets_for_mode(prepared, frame, target_mode="repaired_queue_target")
    severity_targets, interface_meta = interface_severity_targets(prepared, frame, variant="map_non_threat_to_unusual")
    targets: list[str] = []
    changed = Counter()
    for index, queue_value in enumerate(queue_values):
        if queue_value != "needs_review":
            targets.append("non_threat")
            continue
        severity = str(severity_targets[index] or "unusual_needs_review")
        mapped = str(policy["mapping"].get(severity, "review_needed"))
        if mapped != severity:
            changed[f"{severity}->{mapped}"] += 1
        targets.append(mapped)
    meta = {
        "policy_name": policy_name,
        "description": policy["description"],
        "mapping": policy["mapping"],
        "target_distribution": dict(Counter(targets)),
        "changed_review_rows": sum(changed.values()),
        "change_counts": dict(changed),
        "queue": queue_meta,
        "interface": interface_meta,
    }
    return targets, queue_values, meta


def _argmax_predictions(probability_rows: list[dict[str, float]], *, fallback: str) -> list[str]:
    predictions = []
    for row in probability_rows:
        if not row:
            predictions.append(fallback)
        else:
            predictions.append(max(row.items(), key=lambda item: item[1])[0])
    return predictions


def _policy_metrics(
    prepared: dict[str, Any],
    *,
    policy_name: str,
    y_true: list[str],
    predictions: list[str],
) -> dict[str, Any]:
    policy = POLICIES[policy_name]
    return _metric_bundle(
        prepared,
        y_true=y_true,
        predictions=predictions,
        labels_order=list(policy["labels_order"]),
        threat_labels=set(policy["positive_labels"]),
    )


def _summary_for_policy(metrics: dict[str, Any], queue_metrics: dict[str, Any], *, policy_name: str) -> dict[str, Any]:
    summary = _profile_summary(metrics)
    policy = POLICIES[policy_name]
    per_class = metrics.get("per_class") or {}
    summary["policy_positive_precision"] = summary.get("threat_positive_precision")
    summary["policy_positive_recall"] = summary.get("threat_positive_recall")
    summary["policy_positive_f1"] = summary.get("threat_positive_f1")
    for label in policy["labels_order"]:
        summary[f"{label}_recall"] = (per_class.get(label) or {}).get("recall")
        summary[f"{label}_f1"] = (per_class.get(label) or {}).get("f1")
    critical = [
        _safe_float(summary.get(f"{label}_recall"), default=float("nan"))
        for label in policy["critical_recalls"]
    ]
    critical = [value for value in critical if value == value]
    summary["critical_recall_min"] = round(min(critical), 4) if critical else None
    summary.update(queue_metrics)
    return summary


def _final_predictions_for_policy(
    *,
    policy_name: str,
    queue_predictions: list[str],
    severity_probability_rows: list[dict[str, float]],
) -> list[str]:
    if POLICIES[policy_name].get("queue_only"):
        return ["needs_review" if value == "needs_review" else "non_threat" for value in queue_predictions]
    severity_predictions = _argmax_predictions(
        severity_probability_rows,
        fallback=str(POLICIES[policy_name]["labels_order"][1]),
    )
    predictions = []
    for queue_prediction, severity_prediction in zip(queue_predictions, severity_predictions, strict=False):
        predictions.append(severity_prediction if queue_prediction == "needs_review" else "non_threat")
    return predictions


def _fit_policy_strategy(
    prepared: dict[str, Any],
    augmented: dict[str, Any],
    *,
    policy_name: str,
    model_type: str,
) -> dict[str, Any]:
    frame = augmented["frame"]
    target_values, queue_values, policy_meta = _policy_targets(prepared, frame, policy_name=policy_name)
    split = _split_train_calibration_indices(prepared, queue_values)
    fit_idx = split["fit_idx"]
    calibration_idx = split["calibration_idx"]
    name = f"{policy_name}_{model_type}"
    started = time.perf_counter()
    queue_model, queue_classes, queue_meta = _fit_classifier(
        prepared,
        augmented,
        indices=fit_idx,
        targets=queue_values,
        model_type="extra_trees",
        weight_strategy="strong_benign",
    )
    if queue_model is None:
        return {"name": name, "status": "skipped", "message": "Queue model unavailable.", "policy_name": policy_name}
    queue_calibration_rows = _prob_rows(queue_model, queue_classes, frame, calibration_idx)
    queue_thresholds = _select_threshold([queue_values[index] for index in calibration_idx], queue_calibration_rows)
    queue_calibration_predictions = _predict_queue(queue_calibration_rows, threshold=queue_thresholds["selected_threshold"])

    severity_model = None
    severity_classes: list[str] = []
    severity_meta: dict[str, Any] = {"status": "queue_only"}
    if not POLICIES[policy_name].get("queue_only"):
        severity_fit_idx = [index for index in fit_idx if queue_values[index] == "needs_review"]
        severity_model, severity_classes, severity_meta = _fit_classifier(
            prepared,
            augmented,
            indices=severity_fit_idx,
            targets=target_values,
            model_type=model_type,
            weight_strategy="strong_benign",
            class_weight="balanced" if model_type == "logistic_regression" else None,
        )
        if severity_model is None:
            return {
                "name": name,
                "status": "skipped",
                "message": "Severity policy model unavailable.",
                "policy_name": policy_name,
                "policy": policy_meta,
            }
    training_seconds = round(time.perf_counter() - started, 4)

    calibration_severity_rows = (
        _prob_rows(severity_model, severity_classes, frame, calibration_idx)
        if severity_model is not None
        else [{} for _ in calibration_idx]
    )
    calibration_predictions = _final_predictions_for_policy(
        policy_name=policy_name,
        queue_predictions=queue_calibration_predictions,
        severity_probability_rows=calibration_severity_rows,
    )
    calibration_metrics = _policy_metrics(
        prepared,
        policy_name=policy_name,
        y_true=[target_values[index] for index in calibration_idx],
        predictions=calibration_predictions,
    )
    queue_calibration_metrics = _queue_metrics([queue_values[index] for index in calibration_idx], queue_calibration_predictions)
    calibration_summary = _summary_for_policy(calibration_metrics, queue_calibration_metrics, policy_name=policy_name)

    test_idx = list(prepared["test_idx"])
    y_test = [target_values[index] for index in test_idx]
    queue_test = [queue_values[index] for index in test_idx]
    queue_test_rows = _prob_rows(queue_model, queue_classes, frame, test_idx)
    queue_predictions = _predict_queue(queue_test_rows, threshold=queue_thresholds["selected_threshold"])
    severity_test_rows = (
        _prob_rows(severity_model, severity_classes, frame, test_idx)
        if severity_model is not None
        else [{} for _ in test_idx]
    )
    predictions = _final_predictions_for_policy(
        policy_name=policy_name,
        queue_predictions=queue_predictions,
        severity_probability_rows=severity_test_rows,
    )
    q_metrics = _queue_metrics(queue_test, queue_predictions)
    metrics = _policy_metrics(prepared, policy_name=policy_name, y_true=y_test, predictions=predictions)
    if severity_model is None:
        probabilities = queue_model.predict_proba(frame.iloc[test_idx])
        classes = queue_classes
        calibration_threat = {"needs_review"}
    else:
        review_test_idx = [index for index in test_idx if queue_values[index] == "needs_review"]
        probabilities = severity_model.predict_proba(frame.iloc[review_test_idx])
        classes = severity_classes
        y_test = [target_values[index] for index in review_test_idx]
        calibration_threat = set(POLICIES[policy_name]["positive_labels"])
    calibration = _calibration_report(
        y_test,
        probabilities,
        classes,
        threat_labels=calibration_threat,
    )
    return {
        "name": name,
        "status": "evaluated",
        "target_mode": "v3_55_policy_reframing",
        "policy_name": policy_name,
        "policy": policy_meta,
        "queue_model_type": "extra_trees",
        "severity_model_type": "queue_only" if POLICIES[policy_name].get("queue_only") else model_type,
        "queue_model": queue_meta,
        "severity_model": severity_meta,
        "training_seconds": training_seconds,
        "threshold_selection": {
            "fit_rows": len(fit_idx),
            "calibration_rows": len(calibration_idx),
            "selected_on": "train_internal_calibration",
            "used_test_for_threshold_selection": False,
            "queue_threshold": queue_thresholds["selected_threshold"],
            "queue_threshold_selected_on": queue_thresholds["selected_on"],
            "calibration_summary": calibration_summary,
        },
        "summary": _summary_for_policy(metrics, q_metrics, policy_name=policy_name),
        "metrics": metrics,
        "queue_metrics": q_metrics,
        "calibration": calibration,
        "_predictions": predictions,
        "_y_test": [target_values[index] for index in test_idx],
        "_queue_predictions": queue_predictions,
        "_queue_test": queue_test,
    }


def _strategy_rows(prepared: dict[str, Any], augmented: dict[str, Any], strategies: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for strategy in strategies:
        if strategy.get("status") != "evaluated":
            rows.append({key: strategy.get(key) for key in ["name", "status", "message", "target_mode", "policy_name"]})
            continue
        rows.append(
            {
                "name": strategy["name"],
                "status": strategy["status"],
                "target_mode": strategy.get("target_mode"),
                "policy_name": strategy.get("policy_name"),
                "policy": strategy.get("policy") or {},
                "queue_model_type": strategy.get("queue_model_type"),
                "severity_model_type": strategy.get("severity_model_type"),
                "summary": strategy["summary"],
                "queue_metrics": strategy.get("queue_metrics") or {},
                "calibration": strategy.get("calibration") or {},
                "threshold_selection": strategy.get("threshold_selection") or {},
                "error_patterns": _error_patterns(
                    prepared,
                    augmented["frame"],
                    predictions=strategy.get("_predictions") or [],
                    y_true=strategy.get("_y_test") or [],
                ),
            }
        )
    return rows


def _range(metric_ranges: dict[str, Any], metric: str, kind: str, default: float = 0.0) -> float:
    return _safe_float((metric_ranges.get(metric) or {}).get(kind), default)


def _metric_ranges(strategy_splits: list[dict[str, Any]]) -> dict[str, Any]:
    keys = [
        "threat_positive_precision",
        "threat_positive_recall",
        "threat_positive_f1",
        "benign_like_false_positive_rate",
        "policy_positive_f1",
        "policy_positive_recall",
        "critical_recall_min",
        "macro_f1",
        "weighted_f1",
        "queue_precision",
        "queue_recall",
        "queue_f1",
        "queue_false_positive_rate",
        "unusual_needs_review_recall",
        "evidence_backed_suspicious_recall",
        "malicious_high_confidence_recall",
        "review_needed_recall",
        "threat_evidence_recall",
        "needs_review_recall",
    ]
    ranges: dict[str, Any] = {}
    for key in keys:
        values = [
            _safe_float((row.get("summary") or {}).get(key), default=float("nan"))
            for row in strategy_splits
            if (row.get("summary") or {}).get(key) is not None
        ]
        values = [value for value in values if value == value]
        if values:
            ranges[key] = {"min": round(min(values), 4), "max": round(max(values), 4), "span": round(max(values) - min(values), 4)}
    return ranges


def _split_passes(policy_name: str, summary: dict[str, Any]) -> tuple[bool, list[str]]:
    failures = []
    if _safe_float(summary.get("queue_f1")) < 0.95:
        failures.append("queue F1")
    if _safe_float(summary.get("benign_like_false_positive_rate"), 1.0) > FPR_BUDGET:
        failures.append("positive FPR")
    if _safe_float(summary.get("policy_positive_f1")) < 0.85:
        failures.append("policy positive F1")
    if _safe_float(summary.get("critical_recall_min")) < 0.75:
        failures.append("critical recall")
    if policy_name == "current_three_severity":
        if _safe_float(summary.get("evidence_backed_suspicious_recall")) < 0.8:
            failures.append("suspicious recall")
        if _safe_float(summary.get("malicious_high_confidence_recall")) < 0.5:
            failures.append("malicious recall")
    return not failures, failures


def _aggregate_by_strategy(split_results: list[dict[str, Any]]) -> dict[str, Any]:
    names = sorted(
        {
            row["name"]
            for split in split_results
            for row in split.get("strategies", [])
            if row.get("status") == "evaluated"
        }
    )
    comparison = {}
    for name in names:
        strategy_splits = []
        calibrations = []
        threshold_rows = []
        fp_patterns = Counter()
        severity_confusions = Counter()
        policy_name = ""
        for split in split_results:
            for row in split.get("strategies", []):
                if row.get("name") != name or row.get("status") != "evaluated":
                    continue
                policy_name = row.get("policy_name") or policy_name
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
                for pattern, count in (row.get("error_patterns") or {}).get("top_false_positive_patterns") or []:
                    fp_patterns[str(pattern)] += int(count)
                for confusion, count in (row.get("error_patterns") or {}).get("top_severity_confusions") or []:
                    severity_confusions[str(confusion)] += int(count)
        ranges = _metric_ranges(strategy_splits)
        pass_count = 0
        blockers = []
        for split in strategy_splits:
            passed, failures = _split_passes(policy_name, split.get("summary") or {})
            if passed:
                pass_count += 1
            else:
                blockers.append(f"{split['split_mode']}: {', '.join(failures)}")
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
            "policy_name": policy_name,
            "policy": POLICIES.get(policy_name, {}),
            "stability": {
                "evaluated_splits": len(strategy_splits),
                "passing_splits": pass_count,
                "passed": bool(strategy_splits) and pass_count == len(strategy_splits),
                "metric_ranges": ranges,
                "blockers": blockers,
            },
            "best_calibration": best_calibration,
            "threshold_selection": {
                "used_test_for_threshold_selection": any(
                    bool(row.get("used_test_for_threshold_selection")) for row in threshold_rows
                ),
                "selected_on": sorted({str(row.get("selected_on")) for row in threshold_rows if row.get("selected_on")}),
                "top_queue_thresholds": Counter(
                    str(row.get("queue_threshold")) for row in threshold_rows if row.get("queue_threshold") is not None
                ).most_common(5),
            },
            "top_false_positive_patterns": fp_patterns.most_common(12),
            "top_policy_confusions": severity_confusions.most_common(12),
        }
    return comparison


def _select_best(comparison: dict[str, Any]) -> str | None:
    if not comparison:
        return None

    def score(name: str) -> tuple[Any, ...]:
        item = comparison[name]
        ranges = (item.get("stability") or {}).get("metric_ranges") or {}
        max_fpr = _range(ranges, "benign_like_false_positive_rate", "max", 1.0)
        min_positive_f1 = _range(ranges, "policy_positive_f1", "min")
        min_critical_recall = _range(ranges, "critical_recall_min", "min")
        min_queue_f1 = _range(ranges, "queue_f1", "min")
        min_macro = _range(ranges, "macro_f1", "min")
        calibration = item.get("best_calibration") or {}
        return (
            int((item.get("stability") or {}).get("passing_splits") or 0),
            1 if max_fpr <= FPR_BUDGET else 0,
            1 if min_positive_f1 >= 0.85 else 0,
            1 if min_critical_recall >= 0.75 else 0,
            min_positive_f1 + 0.25 * min_critical_recall + 0.15 * min_queue_f1 + 0.10 * min_macro - 0.45 * max_fpr,
            1 if calibration.get("passed") else 0,
            -max_fpr,
        )

    return max(comparison, key=score)


def _readiness(item: dict[str, Any] | None) -> dict[str, Any]:
    if not item:
        return {
            "decision": "diagnostic_only",
            "passed": 0,
            "total": 0,
            "production_promoted": False,
            "model_activated": False,
            "model_artifact_written": False,
            "response_automation_allowed": False,
            "blockers": ["no evaluated v3.55 strategy"],
            "checks": [],
        }
    stability = item.get("stability") or {}
    ranges = stability.get("metric_ranges") or {}
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
            "name": "independent policy stability acceptable",
            "passed": bool(stability.get("passed")),
            "value": f"{stability.get('passing_splits')}/{stability.get('evaluated_splits')}",
            "target": "all evaluated splits pass policy gates",
        },
        {
            "name": "queue admission remains stable",
            "passed": _range(ranges, "queue_f1", "min") >= 0.95,
            "value": _range(ranges, "queue_f1", "min"),
            "target": "queue F1 >= 0.95 across splits",
        },
        {
            "name": "policy positive F1 stable",
            "passed": _range(ranges, "policy_positive_f1", "min") >= 0.85,
            "value": _range(ranges, "policy_positive_f1", "min"),
            "target": ">= 0.85 across splits",
        },
        {
            "name": "positive false-positive rate controlled",
            "passed": _range(ranges, "benign_like_false_positive_rate", "max", 1.0) <= FPR_BUDGET,
            "value": _range(ranges, "benign_like_false_positive_rate", "max", 1.0),
            "target": f"<= {FPR_BUDGET} across splits",
        },
        {
            "name": "critical recall stable",
            "passed": _range(ranges, "critical_recall_min", "min") >= 0.75,
            "value": _range(ranges, "critical_recall_min", "min"),
            "target": ">= 0.75 across policy critical classes",
        },
        {
            "name": "confidence calibration acceptable",
            "passed": bool(calibration.get("passed")),
            "value": calibration.get("status"),
            "target": "passed",
        },
        {"name": "no labels written", "passed": True, "value": True, "target": "required"},
        {"name": "model activation disabled", "passed": True, "value": False, "target": "required"},
        {"name": "response automation disabled", "passed": True, "value": False, "target": "required"},
    ]
    blockers = [row["name"] for row in checks if not row["passed"]]
    return {
        "decision": "candidate_only",
        "passed": sum(1 for row in checks if row["passed"]),
        "total": len(checks),
        "production_promoted": False,
        "model_activated": False,
        "model_artifact_written": False,
        "response_automation_allowed": False,
        "blockers": blockers,
        "checks": checks,
    }


def _render_report(result: dict[str, Any]) -> str:
    rows = []
    for name, item in result.get("strategy_comparison", {}).items():
        ranges = (item.get("stability") or {}).get("metric_ranges") or {}
        rows.append(
            "| {name} | {policy} | {passed} | {pf1} | {fpr} | {crit} | {queue} | {macro} | {cal} |".format(
                name=name,
                policy=item.get("policy_name"),
                passed=f"{(item.get('stability') or {}).get('passing_splits')}/{(item.get('stability') or {}).get('evaluated_splits')}",
                pf1=(ranges.get("policy_positive_f1") or {}).get("min"),
                fpr=(ranges.get("benign_like_false_positive_rate") or {}).get("max"),
                crit=(ranges.get("critical_recall_min") or {}).get("min"),
                queue=(ranges.get("queue_f1") or {}).get("min"),
                macro=(ranges.get("macro_f1") or {}).get("min"),
                cal=(item.get("best_calibration") or {}).get("status"),
            )
        )
    return f"""# v3.55 Severity Target Policy Reframing

Generated: {result.get("generated_at")}

This report is diagnostic only. It evaluates simpler downstream severity target policies after v3.54 showed the current three-class target is semantically ambiguous. No labels were written, no model was activated, no model artifact was written, and response automation stayed disabled.

## Best Diagnostic Candidate

- Candidate: `{result.get("best_strategy")}`
- Readiness: `{result.get("readiness", {}).get("decision")}`
- Checks passed: {result.get("readiness", {}).get("passed")} / {result.get("readiness", {}).get("total")}
- Blockers: {result.get("readiness", {}).get("blockers")}

## Strategy Comparison

| Strategy | Policy | Passing Splits | Positive F1 Min | Positive FPR Max | Critical Recall Min | Queue F1 Min | Macro F1 Min | Calibration |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
{chr(10).join(rows)}

## Policy Definitions

```json
{json.dumps(result.get("policies"), indent=2, default=str)}
```

## Safety

```json
{json.dumps(result.get("safety"), indent=2, default=str)}
```
"""


def run_v355_severity_target_policy_reframing(
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
    for split_mode in V335_SPLITS:
        prepared = _prepared_for_split(base, split_mode=split_mode, test_size=test_size)
        frame, meta = enrich_v353_severity_features(prepared)
        augmented = {"frame": frame, **meta}
        strategies = []
        for policy_name, policy in POLICIES.items():
            model_types = ["queue_only"] if policy.get("queue_only") else SEVERITY_MODEL_TYPES
            for model_type in model_types:
                strategies.append(_fit_policy_strategy(prepared, augmented, policy_name=policy_name, model_type=model_type))
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
    readiness = _readiness(comparison.get(best_strategy) if best_strategy else None)
    after_labels = int(db.scalar(select(func.count(MLLabel.id))) or 0)
    after_runs = int(db.scalar(select(func.count(MLModelRun.id))) or 0)
    after_responses = int(db.scalar(select(func.count(ResponseAction.id))) or 0)

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    stamp = _stamp()
    report_path = output_path / f"v3_55_severity_target_policy_reframing_{stamp}.md"
    latest_path = output_path / V355_LATEST
    result = {
        "ok": True,
        "status": "completed",
        "phase": "v3.55",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "runtime_seconds": round(time.perf_counter() - started, 4),
        "feature_generation_seconds": base.get("feature_generation_seconds"),
        "policies": POLICIES,
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
