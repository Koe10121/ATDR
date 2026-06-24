import json
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from atdr.app.db.models import MLLabel, MLModelRun, ResponseAction
from atdr.app.detection.v330_detection_ml_quality import BENIGN_LIKE_LABELS, OUTPUT_DIR, THREAT_LABELS, _source_name
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
from atdr.app.detection.v341_label_semantics_audit import _evidence_bucket, classify_semantic_issue
from atdr.app.detection.supervised_detector import training_dataset_diagnostics


V342_LATEST = "v3_42_label_policy_reframing_latest.json"
FPR_BUDGET = 0.15
SOC_TARGETS = [
    "non_threat",
    "unusual_needs_review",
    "evidence_backed_suspicious",
    "malicious_high_confidence",
]
SOC_THREAT_TARGETS = {"evidence_backed_suspicious", "malicious_high_confidence"}
SOC_REVIEW_TARGETS = {"unusual_needs_review", *SOC_THREAT_TARGETS}


LABEL_POLICY = {
    "benign": "Routine allowed traffic with no meaningful rule, anomaly, scan, diversity, deny/drop/reset, or high-risk service evidence.",
    "benign_unusual": "Allowed or utility traffic that is uncommon or noisy but lacks enough corroborating evidence for suspicious.",
    "needs_context": "Ambiguous traffic where evidence is incomplete, parser context is limited, or a human needs more logs before a verdict.",
    "suspicious": "Evidence-backed probing, scanning, repeated failures, unknown-app pressure, anomaly/rule agreement, or risky behavior that needs SOC review.",
    "malicious": "High-confidence malicious behavior with strong multi-signal evidence such as C2/exfiltration, repeated external attacks, or clear denied high-risk service attempts.",
}


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _pattern(log: Any) -> str:
    return f"app={getattr(log, 'app', None) or '-'}|action={getattr(log, 'action', None) or '-'}|port={getattr(log, 'dst_port', None) or '-'}"


def _current_binary_target(label: str, _row: Any | None = None) -> str:
    return "threat_positive" if label in THREAT_LABELS else "benign_like"


def _current_three_class_target(label: str, _row: Any | None = None) -> str:
    return label if label in THREAT_LABELS else "benign_like"


def _current_flat_target(label: str, _row: Any | None = None) -> str:
    return label


def _strong_malicious_context(label: str, row: Any) -> bool:
    evidence = _evidence_bucket(row)
    strength = _safe_float(row.get("v337_behavior_evidence_strength"))
    family = str(row.get("v337_traffic_family") or "")
    anomaly = bool(row.get("v337_anomaly_signal_flag"))
    return label == "malicious" and (
        evidence in {"rule_backed", "anomaly_backed", "incomplete_scan_context", "unknown_scan_context"}
        or strength >= 4.0
        or family in {"unknown_scan_context", "incomplete_probe", "non_allow"}
        or anomaly
    )


def soc_policy_target(label: str, row: Any) -> str:
    issue = classify_semantic_issue(label, row)
    evidence = issue["evidence_bucket"]
    strength = _safe_float(issue.get("evidence_strength"))
    if _strong_malicious_context(label, row):
        return "malicious_high_confidence"
    if label == "suspicious" and evidence in {
        "rule_backed",
        "anomaly_backed",
        "web_scan_context",
        "incomplete_scan_context",
        "unknown_scan_context",
        "evidence_strength_only",
    }:
        return "evidence_backed_suspicious"
    if label in THREAT_LABELS:
        return "unusual_needs_review"
    if label == "needs_context":
        return "unusual_needs_review"
    if label in BENIGN_LIKE_LABELS and evidence in {
        "rule_backed",
        "anomaly_backed",
        "web_scan_context",
        "incomplete_scan_context",
        "unknown_scan_context",
    }:
        return "unusual_needs_review"
    if strength >= 4.5:
        return "unusual_needs_review"
    return "non_threat"


def behavior_aware_soc_target(label: str, row: Any) -> str:
    evidence = _evidence_bucket(row)
    strength = _safe_float(row.get("v337_behavior_evidence_strength"))
    family = str(row.get("v337_traffic_family") or "")
    low_signal = evidence in {"web_low_signal", "utility_low_signal", "low_context"}
    if _strong_malicious_context(label, row):
        return "malicious_high_confidence"
    if low_signal and label in THREAT_LABELS:
        return "unusual_needs_review"
    if evidence in {"incomplete_scan_context", "unknown_scan_context"} and strength >= 2.0:
        return "evidence_backed_suspicious"
    if evidence == "rule_backed" and strength >= 3.0 and label in THREAT_LABELS:
        return "evidence_backed_suspicious"
    if evidence == "web_scan_context" and strength >= 2.5 and label in THREAT_LABELS:
        return "evidence_backed_suspicious"
    if label == "needs_context" or family in {"unknown_scan_context", "incomplete_probe"}:
        return "unusual_needs_review"
    if label in BENIGN_LIKE_LABELS and evidence in {"rule_backed", "anomaly_backed"} and strength >= 4.5:
        return "unusual_needs_review"
    if label in THREAT_LABELS:
        return "unusual_needs_review"
    return "non_threat"


def _target_values(prepared: dict[str, Any], frame: Any, mode: str) -> list[str]:
    values: list[str] = []
    for index, label in enumerate(prepared["y"]):
        row = frame.iloc[index]
        if mode == "current_flat":
            values.append(_current_flat_target(label, row))
        elif mode == "current_binary":
            values.append(_current_binary_target(label, row))
        elif mode == "current_three_class":
            values.append(_current_three_class_target(label, row))
        elif mode == "soc_policy_queue":
            values.append(soc_policy_target(label, row))
        elif mode == "behavior_aware_queue":
            values.append(behavior_aware_soc_target(label, row))
        else:  # pragma: no cover - defensive guard
            raise ValueError(f"Unknown target mode: {mode}")
    return values


def _labels_order(mode: str, y_values: list[str]) -> tuple[list[str], set[str]]:
    if mode == "current_binary":
        return ["benign_like", "threat_positive"], {"threat_positive"}
    if mode == "current_three_class":
        return ["benign_like", "malicious", "suspicious"], set(THREAT_LABELS)
    if mode in {"soc_policy_queue", "behavior_aware_queue"}:
        return list(SOC_TARGETS), set(SOC_THREAT_TARGETS)
    return sorted(set(y_values)), set(THREAT_LABELS)


def _split_train_calibration_indices(prepared: dict[str, Any], target_values: list[str]) -> dict[str, Any]:
    train_idx = list(prepared["train_idx"])
    train_targets = [target_values[index] for index in train_idx]
    train_test_split = prepared["imports"][8]
    distribution = Counter(train_targets)
    stratify = train_targets if len(distribution) >= 2 and min(distribution.values()) >= 2 else None
    fit_idx, calibration_idx = train_test_split(
        train_idx,
        test_size=0.25,
        random_state=342,
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


def _threshold_grid(mode: str) -> list[float]:
    if mode == "current_binary":
        return [round(value / 100, 2) for value in range(25, 91, 5)]
    return [round(value / 100, 2) for value in range(30, 91, 5)]


def _decision(probabilities: dict[str, float], threshold: float, *, labels_order: list[str], threat_labels: set[str]) -> str:
    threat_score = sum(_safe_float(probabilities.get(label)) for label in threat_labels)
    non_threat_labels = [label for label in labels_order if label not in threat_labels]
    if threat_score >= threshold:
        candidates = {label: _safe_float(probabilities.get(label)) for label in threat_labels}
        return max(candidates.items(), key=lambda item: item[1])[0]
    candidates = {label: _safe_float(probabilities.get(label)) for label in non_threat_labels}
    return max(candidates.items(), key=lambda item: item[1])[0] if candidates else labels_order[0]


def _predict_with_thresholds(
    probability_rows: list[dict[str, float]],
    threshold: float,
    *,
    labels_order: list[str],
    threat_labels: set[str],
) -> list[str]:
    return [
        _decision(row, threshold, labels_order=labels_order, threat_labels=threat_labels)
        for row in probability_rows
    ]


def _summary(
    metrics: dict[str, Any],
    *,
    mode: str,
    y_true: list[str] | None = None,
    predictions: list[str] | None = None,
) -> dict[str, Any]:
    summary = _profile_summary(metrics)
    per_class = metrics.get("per_class") or {}
    if mode in {"soc_policy_queue", "behavior_aware_queue"}:
        summary["suspicious_recall"] = (per_class.get("evidence_backed_suspicious") or {}).get("recall")
        summary["malicious_recall"] = (per_class.get("malicious_high_confidence") or {}).get("recall")
        summary["unusual_needs_review_recall"] = (per_class.get("unusual_needs_review") or {}).get("recall")
        summary["soc_review_queue_recall"] = _review_queue_recall(y_true or [], predictions or [])
    return summary


def _review_queue_recall(y_true: list[str], predictions: list[str]) -> float | None:
    if not y_true or not predictions:
        return None
    total = 0
    hit = 0
    for actual, predicted in zip(y_true, predictions, strict=False):
        if actual not in SOC_REVIEW_TARGETS:
            continue
        total += 1
        if predicted in SOC_REVIEW_TARGETS:
            hit += 1
    return round(hit / total, 4) if total else None


def _threshold_score(summary: dict[str, Any], *, fpr_budget: float) -> tuple[Any, ...]:
    fpr = _safe_float(summary.get("benign_like_false_positive_rate"), 1.0)
    threat_f1 = _safe_float(summary.get("threat_positive_f1"))
    suspicious = _safe_float(summary.get("suspicious_recall"))
    malicious = _safe_float(summary.get("malicious_recall"))
    return (
        1 if fpr <= fpr_budget else 0,
        threat_f1 - 0.35 * fpr,
        suspicious,
        malicious,
        -fpr,
    )


def _select_threshold(
    prepared: dict[str, Any],
    *,
    y_true: list[str],
    probability_rows: list[dict[str, float]],
    labels_order: list[str],
    threat_labels: set[str],
    mode: str,
    fpr_budget: float,
) -> dict[str, Any]:
    candidates = []
    for threshold in _threshold_grid(mode):
        predictions = _predict_with_thresholds(
            probability_rows,
            threshold,
            labels_order=labels_order,
            threat_labels=threat_labels,
        )
        metrics = _metric_bundle(
            prepared,
            y_true=y_true,
            predictions=predictions,
            labels_order=labels_order,
            threat_labels=threat_labels,
        )
        summary = _summary(metrics, mode=mode, y_true=y_true, predictions=predictions)
        candidates.append(
            {
                "threshold": threshold,
                "summary": summary,
                "within_fpr_budget": _safe_float(summary.get("benign_like_false_positive_rate"), 1.0) <= fpr_budget,
            }
        )
    selected = max(candidates, key=lambda item: _threshold_score(item["summary"], fpr_budget=fpr_budget))
    return {
        "selected_threshold": selected["threshold"],
        "selection_fpr_budget": fpr_budget,
        "calibration_summary": selected["summary"],
        "candidate_count": len(candidates),
        "within_fpr_budget_candidates": sum(1 for item in candidates if item["within_fpr_budget"]),
        "selected_on": "train_internal_calibration",
        "used_test_for_threshold_selection": False,
    }


def _target_mapping_summary(prepared: dict[str, Any], frame: Any, mode: str) -> dict[str, Any]:
    original_to_target = Counter()
    target_counts = Counter()
    issue_to_target = Counter()
    conflicts = Counter()
    targets = _target_values(prepared, frame, mode)
    for index, label in enumerate(prepared["y"]):
        row = frame.iloc[index]
        target = targets[index]
        issue = classify_semantic_issue(label, row)["issue"]
        log = prepared["logs"][index]
        original_to_target[f"{label}->{target}"] += 1
        target_counts[target] += 1
        issue_to_target[f"{issue}->{target}"] += 1
        conflicts[f"{_pattern(log)}|{_evidence_bucket(row)}|{target}"] += 1
    return {
        "mode": mode,
        "target_counts": dict(target_counts),
        "original_to_target": original_to_target.most_common(20),
        "semantic_issue_to_target": issue_to_target.most_common(20),
        "top_target_patterns": conflicts.most_common(20),
    }


def _fit_target_mapping(
    prepared: dict[str, Any],
    augmented: dict[str, Any],
    *,
    mode: str,
    model_type: str = "extra_trees",
    weight_strategy: str = "strong_benign",
    fpr_budget: float = FPR_BUDGET,
) -> dict[str, Any]:
    frame = augmented["frame"]
    target_values = _target_values(prepared, frame, mode)
    split = _split_train_calibration_indices(prepared, target_values)
    fit_idx = split["fit_idx"]
    calibration_idx = split["calibration_idx"]
    y_fit = [target_values[index] for index in fit_idx]
    y_calibration = [target_values[index] for index in calibration_idx]
    y_test = [target_values[index] for index in prepared["test_idx"]]
    if len(set(y_fit)) < 2 or len(set(y_calibration)) < 2 or len(set(y_test)) < 2:
        return {
            "name": f"{mode}_{model_type}",
            "status": "skipped",
            "target_mode": mode,
            "message": "Not enough target diversity for diagnostic training.",
            "mapping_summary": _target_mapping_summary(prepared, frame, mode),
        }
    labels_order, threat_labels = _labels_order(mode, target_values)
    model = _build_pipeline_for_columns(
        prepared["imports"],
        model_type=model_type,
        class_weight="balanced" if model_type == "logistic_regression" else None,
        numeric_features=augmented["numeric_features"],
        categorical_features=augmented["categorical_features"],
    )
    weights, weight_summary = _noise_reduced_weights(prepared["labels"], weight_strategy)
    fit_kwargs = {}
    if weights is not None and model_type != "logistic_regression":
        fit_kwargs["model__sample_weight"] = [weights[index] for index in fit_idx]
    started = time.perf_counter()
    model.fit(frame.iloc[fit_idx], y_fit, **fit_kwargs)
    training_seconds = round(time.perf_counter() - started, 4)
    calibration_probabilities = model.predict_proba(frame.iloc[calibration_idx])
    classes = list(model.named_steps["model"].classes_) if hasattr(model, "named_steps") else list(model.classes_)
    calibration_rows = _probability_rows(calibration_probabilities, classes)
    threshold_selection = _select_threshold(
        prepared,
        y_true=y_calibration,
        probability_rows=calibration_rows,
        labels_order=labels_order,
        threat_labels=threat_labels,
        mode=mode,
        fpr_budget=fpr_budget,
    )
    test_probabilities = model.predict_proba(frame.iloc[prepared["test_idx"]])
    test_rows = _probability_rows(test_probabilities, classes)
    predictions = _predict_with_thresholds(
        test_rows,
        threshold_selection["selected_threshold"],
        labels_order=labels_order,
        threat_labels=threat_labels,
    )
    metrics = _metric_bundle(
        prepared,
        y_true=y_test,
        predictions=predictions,
        labels_order=labels_order,
        threat_labels=threat_labels,
    )
    return {
        "name": f"{mode}_{model_type}",
        "status": "evaluated",
        "target_mode": mode,
        "model_type": model_type,
        "sample_weighting": weight_summary,
        "training_seconds": training_seconds,
        "threshold_selection": {
            **split,
            **threshold_selection,
        },
        "summary": _summary(metrics, mode=mode, y_true=y_test, predictions=predictions),
        "metrics": metrics,
        "calibration": _calibration_report(y_test, test_probabilities, classes, threat_labels=threat_labels),
        "mapping_summary": _target_mapping_summary(prepared, frame, mode),
        "_predictions": predictions,
        "_y_test": y_test,
    }


def _candidate_modes() -> list[dict[str, Any]]:
    return [
        {"mode": "current_flat", "model_type": "extra_trees", "weight_strategy": "strong_benign"},
        {"mode": "current_binary", "model_type": "extra_trees", "weight_strategy": "strong_benign"},
        {"mode": "current_three_class", "model_type": "extra_trees", "weight_strategy": "strong_benign"},
        {"mode": "soc_policy_queue", "model_type": "extra_trees", "weight_strategy": "strong_benign"},
        {"mode": "behavior_aware_queue", "model_type": "extra_trees", "weight_strategy": "strong_benign"},
        {"mode": "soc_policy_queue", "model_type": "logistic_regression", "weight_strategy": "none"},
        {"mode": "behavior_aware_queue", "model_type": "logistic_regression", "weight_strategy": "none"},
    ]


def _false_positive_patterns(
    prepared: dict[str, Any],
    augmented: dict[str, Any],
    *,
    predictions: list[str],
    y_true: list[str],
    threat_labels: set[str],
) -> dict[str, Any]:
    frame = augmented["frame"]
    rows = []
    for position, (actual, predicted) in enumerate(zip(y_true, predictions, strict=False)):
        if actual in threat_labels or predicted not in threat_labels:
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


def _split_strategy_rows(prepared: dict[str, Any], augmented: dict[str, Any], strategies: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for strategy in strategies:
        if strategy.get("status") != "evaluated":
            rows.append(
                {
                    "name": strategy.get("name"),
                    "status": strategy.get("status"),
                    "target_mode": strategy.get("target_mode"),
                    "message": strategy.get("message"),
                    "mapping_summary": strategy.get("mapping_summary") or {},
                }
            )
            continue
        labels_order, threat_labels = _labels_order(strategy["target_mode"], strategy["_y_test"])
        rows.append(
            {
                "name": strategy["name"],
                "status": strategy["status"],
                "target_mode": strategy["target_mode"],
                "model_type": strategy["model_type"],
                "summary": strategy["summary"],
                "calibration": strategy.get("calibration") or {},
                "threshold_selection": strategy.get("threshold_selection") or {},
                "mapping_summary": strategy.get("mapping_summary") or {},
                "false_positive_patterns": _false_positive_patterns(
                    prepared,
                    augmented,
                    predictions=strategy.get("_predictions") or [],
                    y_true=strategy.get("_y_test") or [],
                    threat_labels=threat_labels,
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
        strategy_splits: list[dict[str, Any]] = []
        calibrations = []
        threshold_rows = []
        fp_patterns = Counter()
        fp_buckets = Counter()
        target_modes = set()
        mapping_counts = Counter()
        for split in split_results:
            for row in split.get("strategies", []):
                if row.get("name") != name or row.get("status") != "evaluated":
                    continue
                target_modes.add(str(row.get("target_mode") or "unknown"))
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
                for target, count in (row.get("mapping_summary") or {}).get("target_counts", {}).items():
                    mapping_counts[str(target)] += int(count)
        stability = _stability_summary(strategy_splits)
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
            "target_modes": sorted(target_modes),
            "stability": stability,
            "best_calibration": best_calibration,
            "threshold_selection": {
                "used_test_for_threshold_selection": any(
                    bool(row.get("used_test_for_threshold_selection")) for row in threshold_rows
                ),
                "selected_on": sorted({str(row.get("selected_on")) for row in threshold_rows if row.get("selected_on")}),
                "top_selected_thresholds": Counter(
                    str(row.get("selected_threshold")) for row in threshold_rows if row.get("selected_threshold") is not None
                ).most_common(5),
                "within_fpr_budget_candidates": sum(int(row.get("within_fpr_budget_candidates") or 0) for row in threshold_rows),
            },
            "aggregate_target_counts": dict(mapping_counts),
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
        min_f1 = _range_value(item, "threat_positive_f1", "min")
        min_suspicious = _range_value(item, "suspicious_recall", "min")
        min_malicious = _range_value(item, "malicious_recall", "min")
        calibration = item.get("best_calibration") or {}
        return (
            int((item.get("stability") or {}).get("passing_splits") or 0),
            1 if max_fpr <= FPR_BUDGET else 0,
            min_f1 - 0.35 * max_fpr,
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
            "target": "train_internal_calibration only",
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
            "name": "threat-positive F1 stable",
            "passed": _range_value(item, "threat_positive_f1", "min") >= 0.85,
            "value": _range_value(item, "threat_positive_f1", "min"),
            "target": ">= 0.85 across splits",
        },
        {
            "name": "suspicious/evidence-backed recall stable",
            "passed": _range_value(item, "suspicious_recall", "min") >= 0.75,
            "value": _range_value(item, "suspicious_recall", "min"),
            "target": ">= 0.75 across splits",
        },
        {
            "name": "malicious/high-confidence recall acceptable",
            "passed": _range_value(item, "malicious_recall", "min") >= 0.5,
            "value": _range_value(item, "malicious_recall", "min"),
            "target": ">= 0.5 across splits",
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
            "| {name} | {passed} | {f1_min}-{f1_max} | {fpr_min}-{fpr_max} | {susp_min}-{susp_max} | {mal_min}-{mal_max} | {cal} |".format(
                name=name,
                passed=f"{item.get('stability', {}).get('passing_splits')}/{item.get('stability', {}).get('evaluated_splits')}",
                f1_min=(ranges.get("threat_positive_f1") or {}).get("min"),
                f1_max=(ranges.get("threat_positive_f1") or {}).get("max"),
                fpr_min=(ranges.get("benign_like_false_positive_rate") or {}).get("min"),
                fpr_max=(ranges.get("benign_like_false_positive_rate") or {}).get("max"),
                susp_min=(ranges.get("suspicious_recall") or {}).get("min"),
                susp_max=(ranges.get("suspicious_recall") or {}).get("max"),
                mal_min=(ranges.get("malicious_recall") or {}).get("min"),
                mal_max=(ranges.get("malicious_recall") or {}).get("max"),
                cal=item.get("best_calibration", {}).get("status"),
            )
        )
    return f"""# v3.42 Label Policy and SOC Target Reframing

Generated: {result.get("generated_at")}

This report is diagnostic only. It defines explicit ATDR label policy semantics and evaluates alternative SOC target mappings without writing labels, activating models, writing active artifacts, or enabling response automation.

## Label Policy

```json
{json.dumps(LABEL_POLICY, indent=2, default=str)}
```

## Best Diagnostic Candidate

- Candidate: {result.get("best_strategy")}
- Readiness: {result.get("readiness", {}).get("decision")}
- Checks passed: {result.get("readiness", {}).get("passed")} / {result.get("readiness", {}).get("total")}
- Blockers: {result.get("readiness", {}).get("blockers")}

## Strategy Comparison

| Strategy | Passing Splits | Threat F1 Range | Benign FPR Range | Suspicious/Evidence Recall Range | Malicious/High Confidence Recall Range | Calibration |
| --- | ---: | --- | --- | --- | --- | --- |
{chr(10).join(rows)}

## Safety

```json
{json.dumps(result.get("safety"), indent=2, default=str)}
```
"""


def run_v342_label_policy_reframing(
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
    split_results: list[dict[str, Any]] = []
    for split_mode in V335_SPLITS:
        prepared = _prepared_for_split(base, split_mode=split_mode, test_size=test_size)
        frame, meta = enrich_v337_features(prepared)
        augmented = {"frame": frame, **meta}
        strategies = [
            _fit_target_mapping(
                prepared,
                augmented,
                mode=spec["mode"],
                model_type=spec["model_type"],
                weight_strategy=spec["weight_strategy"],
            )
            for spec in _candidate_modes()
        ]
        split_results.append(
            {
                "split_mode": split_mode,
                "status": "evaluated",
                "training_rows": len(prepared["train_idx"]),
                "test_rows": len(prepared["test_idx"]),
                "split_warnings": prepared.get("split_warnings") or [],
                "strategies": _split_strategy_rows(prepared, augmented, strategies),
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
        "blockers": ["no evaluated v3.42 strategy"],
        "checks": [],
    }
    after_labels = int(db.scalar(select(func.count(MLLabel.id))) or 0)
    after_runs = int(db.scalar(select(func.count(MLModelRun.id))) or 0)
    after_responses = int(db.scalar(select(func.count(ResponseAction.id))) or 0)

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    stamp = _stamp()
    report_path = output_path / f"v3_42_label_policy_reframing_{stamp}.md"
    latest_path = output_path / V342_LATEST
    result: dict[str, Any] = {
        "ok": True,
        "status": "completed",
        "phase": "v3.42",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "runtime_seconds": round(time.perf_counter() - started, 4),
        "feature_generation_seconds": base.get("feature_generation_seconds"),
        "label_policy": LABEL_POLICY,
        "soc_targets": {
            "targets": SOC_TARGETS,
            "threat_positive_targets": sorted(SOC_THREAT_TARGETS),
            "review_queue_targets": sorted(SOC_REVIEW_TARGETS),
        },
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
