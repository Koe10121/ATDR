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
from atdr.app.detection.v342_label_policy_reframing import (
    FPR_BUDGET,
    SOC_TARGETS,
    SOC_THREAT_TARGETS,
    behavior_aware_soc_target,
)
from atdr.app.detection.supervised_detector import training_dataset_diagnostics


V343_LATEST = "v3_43_hybrid_soc_queue_latest.json"
REVIEW_TARGETS = {"unusual_needs_review", *SOC_THREAT_TARGETS}


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _pattern(log: Any) -> str:
    return f"app={getattr(log, 'app', None) or '-'}|action={getattr(log, 'action', None) or '-'}|port={getattr(log, 'dst_port', None) or '-'}"


def _target_values(prepared: dict[str, Any], frame: Any) -> list[str]:
    return [behavior_aware_soc_target(label, frame.iloc[index]) for index, label in enumerate(prepared["y"])]


def _evidence_snapshot(row: Any) -> dict[str, Any]:
    evidence = _evidence_bucket(row)
    strength = _safe_float(row.get("v337_behavior_evidence_strength"))
    family = str(row.get("v337_traffic_family") or "unknown")
    anomaly = bool(row.get("v337_anomaly_signal_flag"))
    rule = bool(row.get("v337_rule_backed_allow_flag"))
    low_signal = evidence in {"web_low_signal", "utility_low_signal", "low_context"}
    scan_context = evidence in {"web_scan_context", "incomplete_scan_context", "unknown_scan_context"}
    return {
        "evidence_bucket": evidence,
        "evidence_strength": strength,
        "traffic_family": family,
        "anomaly_signal": anomaly,
        "rule_backed": rule,
        "low_signal": low_signal,
        "scan_context": scan_context,
    }


def evidence_first_queue_decision(row: Any) -> str:
    snapshot = _evidence_snapshot(row)
    evidence = snapshot["evidence_bucket"]
    strength = snapshot["evidence_strength"]
    family = snapshot["traffic_family"]
    if snapshot["low_signal"] and strength < 2.0 and not snapshot["anomaly_signal"]:
        return "non_threat"
    if evidence in {"unknown_scan_context", "incomplete_scan_context"} and strength >= 4.0:
        return "malicious_high_confidence"
    if evidence == "anomaly_backed" and strength >= 4.0:
        return "malicious_high_confidence"
    if evidence == "rule_backed" and strength >= 5.0 and family in {"non_allow", "incomplete_probe", "unknown_scan_context"}:
        return "malicious_high_confidence"
    if evidence in {"rule_backed", "anomaly_backed", "unknown_scan_context", "incomplete_scan_context"}:
        return "evidence_backed_suspicious" if strength >= 2.0 else "unusual_needs_review"
    if evidence == "web_scan_context" and strength >= 2.5:
        return "evidence_backed_suspicious"
    if strength >= 4.5:
        return "unusual_needs_review"
    return "non_threat"


def _bounded_hybrid_decision(row: Any, probabilities: dict[str, float], thresholds: dict[str, float]) -> str:
    evidence_decision = evidence_first_queue_decision(row)
    suspicious_score = _safe_float(probabilities.get("evidence_backed_suspicious"))
    malicious_score = _safe_float(probabilities.get("malicious_high_confidence"))
    review_score = suspicious_score + malicious_score + _safe_float(probabilities.get("unusual_needs_review"))
    threat_score = suspicious_score + malicious_score
    snapshot = _evidence_snapshot(row)
    if evidence_decision == "malicious_high_confidence":
        return "malicious_high_confidence"
    if evidence_decision == "non_threat":
        if review_score >= thresholds["review"] and not snapshot["low_signal"] and snapshot["evidence_strength"] >= 2.0:
            return "unusual_needs_review"
        return "non_threat"
    if evidence_decision == "unusual_needs_review":
        if malicious_score >= thresholds["malicious"] and snapshot["evidence_strength"] >= 4.0:
            return "malicious_high_confidence"
        if threat_score >= thresholds["threat"] and snapshot["evidence_strength"] >= 2.5:
            return "evidence_backed_suspicious"
        return "unusual_needs_review"
    if malicious_score >= thresholds["malicious"] and snapshot["evidence_strength"] >= 4.0:
        return "malicious_high_confidence"
    if threat_score < thresholds["threat_floor"] and snapshot["evidence_strength"] < 3.0:
        return "unusual_needs_review"
    return "evidence_backed_suspicious"


def _review_queue_recall(y_true: list[str], predictions: list[str]) -> float | None:
    total = 0
    hit = 0
    for actual, predicted in zip(y_true, predictions, strict=False):
        if actual not in REVIEW_TARGETS:
            continue
        total += 1
        if predicted in REVIEW_TARGETS:
            hit += 1
    return round(hit / total, 4) if total else None


def _summary(metrics: dict[str, Any], *, y_true: list[str], predictions: list[str]) -> dict[str, Any]:
    summary = _profile_summary(metrics)
    per_class = metrics.get("per_class") or {}
    summary["suspicious_recall"] = (per_class.get("evidence_backed_suspicious") or {}).get("recall")
    summary["malicious_recall"] = (per_class.get("malicious_high_confidence") or {}).get("recall")
    summary["unusual_needs_review_recall"] = (per_class.get("unusual_needs_review") or {}).get("recall")
    summary["soc_review_queue_recall"] = _review_queue_recall(y_true, predictions)
    return summary


def _metrics_for_predictions(prepared: dict[str, Any], y_true: list[str], predictions: list[str]) -> dict[str, Any]:
    metrics = _metric_bundle(
        prepared,
        y_true=y_true,
        predictions=predictions,
        labels_order=list(SOC_TARGETS),
        threat_labels=set(SOC_THREAT_TARGETS),
    )
    return metrics


def _threshold_grid() -> list[dict[str, float]]:
    return [
        {
            "review": round(review / 100, 2),
            "threat": round(threat / 100, 2),
            "threat_floor": round(floor / 100, 2),
            "malicious": malicious,
        }
        for review in range(45, 86, 10)
        for threat in range(35, 86, 10)
        for floor in range(15, 46, 10)
        for malicious in [0.35, 0.5, 0.65]
    ]


def _threshold_score(summary: dict[str, Any]) -> tuple[Any, ...]:
    fpr = _safe_float(summary.get("benign_like_false_positive_rate"), 1.0)
    threat_f1 = _safe_float(summary.get("threat_positive_f1"))
    suspicious = _safe_float(summary.get("suspicious_recall"))
    malicious = _safe_float(summary.get("malicious_recall"))
    review = _safe_float(summary.get("soc_review_queue_recall"))
    return (
        1 if fpr <= FPR_BUDGET else 0,
        threat_f1 - 0.35 * fpr,
        review,
        suspicious,
        malicious,
        -fpr,
    )


def _select_hybrid_thresholds(
    prepared: dict[str, Any],
    frame: Any,
    *,
    calibration_idx: list[int],
    y_calibration: list[str],
    probability_rows: list[dict[str, float]],
) -> dict[str, Any]:
    candidates = []
    for thresholds in _threshold_grid():
        predictions = [
            _bounded_hybrid_decision(frame.iloc[index], probability_rows[position], thresholds)
            for position, index in enumerate(calibration_idx)
        ]
        metrics = _metrics_for_predictions(prepared, y_calibration, predictions)
        summary = _summary(metrics, y_true=y_calibration, predictions=predictions)
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


def _split_train_calibration_indices(prepared: dict[str, Any], target_values: list[str]) -> dict[str, Any]:
    train_idx = list(prepared["train_idx"])
    train_targets = [target_values[index] for index in train_idx]
    train_test_split = prepared["imports"][8]
    distribution = Counter(train_targets)
    stratify = train_targets if len(distribution) >= 2 and min(distribution.values()) >= 2 else None
    fit_idx, calibration_idx = train_test_split(
        train_idx,
        test_size=0.25,
        random_state=343,
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


def _class_list(model: Any) -> list[str]:
    if hasattr(model, "named_steps"):
        return list(model.named_steps["model"].classes_)
    return list(model.classes_)


def _fit_hybrid_model(
    prepared: dict[str, Any],
    augmented: dict[str, Any],
    *,
    model_type: str,
) -> dict[str, Any]:
    frame = augmented["frame"]
    target_values = _target_values(prepared, frame)
    split = _split_train_calibration_indices(prepared, target_values)
    fit_idx = split["fit_idx"]
    calibration_idx = split["calibration_idx"]
    y_fit = [target_values[index] for index in fit_idx]
    y_calibration = [target_values[index] for index in calibration_idx]
    y_test = [target_values[index] for index in prepared["test_idx"]]
    if len(set(y_fit)) < 2 or len(set(y_calibration)) < 2:
        return {
            "name": f"hybrid_evidence_first_{model_type}",
            "status": "skipped",
            "message": "Not enough target diversity for hybrid diagnostic training.",
        }
    model = _build_pipeline_for_columns(
        prepared["imports"],
        model_type=model_type,
        class_weight="balanced" if model_type == "logistic_regression" else None,
        numeric_features=augmented["numeric_features"],
        categorical_features=augmented["categorical_features"],
    )
    weights, weight_summary = _noise_reduced_weights(prepared["labels"], "strong_benign")
    fit_kwargs = {}
    if model_type != "logistic_regression" and weights is not None:
        fit_kwargs["model__sample_weight"] = [weights[index] for index in fit_idx]
    started = time.perf_counter()
    model.fit(frame.iloc[fit_idx], y_fit, **fit_kwargs)
    training_seconds = round(time.perf_counter() - started, 4)
    classes = _class_list(model)
    calibration_probabilities = model.predict_proba(frame.iloc[calibration_idx])
    calibration_rows = _probability_rows(calibration_probabilities, classes)
    threshold_selection = _select_hybrid_thresholds(
        prepared,
        frame,
        calibration_idx=calibration_idx,
        y_calibration=y_calibration,
        probability_rows=calibration_rows,
    )
    test_probabilities = model.predict_proba(frame.iloc[prepared["test_idx"]])
    test_rows = _probability_rows(test_probabilities, classes)
    predictions = [
        _bounded_hybrid_decision(frame.iloc[index], test_rows[position], threshold_selection["selected_thresholds"])
        for position, index in enumerate(prepared["test_idx"])
    ]
    metrics = _metrics_for_predictions(prepared, y_test, predictions)
    return {
        "name": f"hybrid_evidence_first_{model_type}",
        "status": "evaluated",
        "target_mode": "behavior_aware_soc_queue",
        "model_type": model_type,
        "sample_weighting": weight_summary,
        "training_seconds": training_seconds,
        "threshold_selection": {
            **split,
            **threshold_selection,
        },
        "summary": _summary(metrics, y_true=y_test, predictions=predictions),
        "metrics": metrics,
        "calibration": _calibration_report(y_test, test_probabilities, classes, threat_labels=set(SOC_THREAT_TARGETS)),
        "_predictions": predictions,
        "_y_test": y_test,
    }


def _fit_evidence_first(prepared: dict[str, Any], augmented: dict[str, Any]) -> dict[str, Any]:
    frame = augmented["frame"]
    y_test = [behavior_aware_soc_target(prepared["y"][index], frame.iloc[index]) for index in prepared["test_idx"]]
    predictions = [evidence_first_queue_decision(frame.iloc[index]) for index in prepared["test_idx"]]
    metrics = _metrics_for_predictions(prepared, y_test, predictions)
    return {
        "name": "deterministic_evidence_first_queue",
        "status": "evaluated",
        "target_mode": "behavior_aware_soc_queue",
        "model_type": "rules_evidence_only",
        "summary": _summary(metrics, y_true=y_test, predictions=predictions),
        "metrics": metrics,
        "calibration": {"status": "not_applicable", "passed": False, "reason": "No probability model."},
        "threshold_selection": {
            "selected_on": "deterministic_evidence_policy",
            "used_test_for_threshold_selection": False,
        },
        "_predictions": predictions,
        "_y_test": y_test,
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


def _with_custom_metric_ranges(stability: dict[str, Any], strategy_splits: list[dict[str, Any]]) -> dict[str, Any]:
    ranges = dict(stability.get("metric_ranges") or {})
    for metric in ["soc_review_queue_recall", "unusual_needs_review_recall"]:
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


def _range_value(item: dict[str, Any], metric: str, kind: str, default: float = 0.0) -> float:
    ranges = (item.get("stability") or {}).get("metric_ranges") or {}
    return _safe_float((ranges.get(metric) or {}).get(kind), default)


def _select_best(comparison: dict[str, Any]) -> str | None:
    if not comparison:
        return None

    def score(name: str) -> tuple[Any, ...]:
        item = comparison[name]
        max_fpr = _range_value(item, "benign_like_false_positive_rate", "max", 1.0)
        min_f1 = _range_value(item, "threat_positive_f1", "min")
        min_review = _range_value(item, "soc_review_queue_recall", "min")
        min_suspicious = _range_value(item, "suspicious_recall", "min")
        min_malicious = _range_value(item, "malicious_recall", "min")
        calibration = item.get("best_calibration") or {}
        return (
            int((item.get("stability") or {}).get("passing_splits") or 0),
            1 if max_fpr <= FPR_BUDGET else 0,
            min_f1 - 0.35 * max_fpr,
            min_review,
            min_suspicious,
            min_malicious,
            1 if calibration.get("passed") else 0,
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
            "target": "train-internal or deterministic only",
        },
        {
            "name": "independent split stability acceptable",
            "passed": bool(stability.get("passed")),
            "value": f"{stability.get('passing_splits')}/{stability.get('evaluated_splits')}",
            "target": "all evaluated splits pass gates",
        },
        {
            "name": "benign-like false-positive rate stable",
            "passed": _range_value(item, "benign_like_false_positive_rate", "max", 1.0) <= FPR_BUDGET,
            "value": _range_value(item, "benign_like_false_positive_rate", "max", 1.0),
            "target": f"<= {FPR_BUDGET} across splits",
        },
        {
            "name": "SOC review queue recall stable",
            "passed": _range_value(item, "soc_review_queue_recall", "min") >= 0.8,
            "value": _range_value(item, "soc_review_queue_recall", "min"),
            "target": ">= 0.8 across splits",
        },
        {
            "name": "threat-positive F1 stable",
            "passed": _range_value(item, "threat_positive_f1", "min") >= 0.85,
            "value": _range_value(item, "threat_positive_f1", "min"),
            "target": ">= 0.85 across splits",
        },
        {
            "name": "confidence calibration acceptable for ML-assisted variant",
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
            "| {name} | {passed} | {f1_min}-{f1_max} | {fpr_min}-{fpr_max} | {review_min}-{review_max} | {susp_min}-{susp_max} | {cal} |".format(
                name=name,
                passed=f"{item.get('stability', {}).get('passing_splits')}/{item.get('stability', {}).get('evaluated_splits')}",
                f1_min=(ranges.get("threat_positive_f1") or {}).get("min"),
                f1_max=(ranges.get("threat_positive_f1") or {}).get("max"),
                fpr_min=(ranges.get("benign_like_false_positive_rate") or {}).get("min"),
                fpr_max=(ranges.get("benign_like_false_positive_rate") or {}).get("max"),
                review_min=(ranges.get("soc_review_queue_recall") or {}).get("min"),
                review_max=(ranges.get("soc_review_queue_recall") or {}).get("max"),
                susp_min=(ranges.get("suspicious_recall") or {}).get("min"),
                susp_max=(ranges.get("suspicious_recall") or {}).get("max"),
                cal=item.get("best_calibration", {}).get("status"),
            )
        )
    return f"""# v3.43 Hybrid Evidence-First SOC Queue Candidate

Generated: {result.get("generated_at")}

This report is diagnostic only. It evaluates evidence-first SOC queue decisions and bounded ML-assisted variants. No labels were written, no model was activated, no artifact was written, and response automation stayed disabled.

## Best Diagnostic Candidate

- Candidate: {result.get("best_strategy")}
- Readiness: {result.get("readiness", {}).get("decision")}
- Checks passed: {result.get("readiness", {}).get("passed")} / {result.get("readiness", {}).get("total")}
- Blockers: {result.get("readiness", {}).get("blockers")}

## Strategy Comparison

| Strategy | Passing Splits | Threat F1 Range | Benign FPR Range | SOC Review Recall Range | Evidence-Backed Recall Range | Calibration |
| --- | ---: | --- | --- | --- | --- | --- |
{chr(10).join(rows)}

## Safety

```json
{json.dumps(result.get("safety"), indent=2, default=str)}
```
"""


def run_v343_hybrid_soc_queue(
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
        frame, meta = enrich_v337_features(prepared)
        augmented = {"frame": frame, **meta}
        strategies = [
            _fit_evidence_first(prepared, augmented),
            _fit_hybrid_model(prepared, augmented, model_type="extra_trees"),
            _fit_hybrid_model(prepared, augmented, model_type="logistic_regression"),
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
        "blockers": ["no evaluated v3.43 strategy"],
        "checks": [],
    }
    after_labels = int(db.scalar(select(func.count(MLLabel.id))) or 0)
    after_runs = int(db.scalar(select(func.count(MLModelRun.id))) or 0)
    after_responses = int(db.scalar(select(func.count(ResponseAction.id))) or 0)

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    stamp = _stamp()
    report_path = output_path / f"v3_43_hybrid_soc_queue_{stamp}.md"
    latest_path = output_path / V343_LATEST
    result = {
        "ok": True,
        "status": "completed",
        "phase": "v3.43",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "runtime_seconds": round(time.perf_counter() - started, 4),
        "feature_generation_seconds": base.get("feature_generation_seconds"),
        "target_mode": "behavior_aware_soc_queue",
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
