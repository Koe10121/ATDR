import json
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from atdr.app.db.models import MLModelRun, ResponseAction
from atdr.app.detection.v330_detection_ml_quality import BENIGN_LIKE_LABELS, OUTPUT_DIR, THREAT_LABELS, _source_name
from atdr.app.detection.v331_noise_reduction import _metric_bundle, _profile_summary
from atdr.app.detection.v332_guard_validation import _load_base_dataset, _prepared_for_split, _safe_float, _stability_summary
from atdr.app.detection.v335_split_stability_repair import V335_SPLITS
from atdr.app.detection.v337_evidence_feature_enrichment import enrich_v337_features
from atdr.app.detection.v338_calibrated_threshold_search import (
    FPR_BUDGET,
    _candidate_specs,
    _fit_candidate,
    _labels_order,
    _predictions_for_thresholds,
)
from atdr.app.detection.supervised_detector import training_dataset_diagnostics


V339_LATEST = "v3_39_suspicious_recall_recovery_latest.json"


RECALL_POLICIES: dict[str, dict[str, Any]] = {
    "none": {
        "enabled": False,
        "description": "No pattern-specific recall recovery.",
    },
    "scan_context_conservative": {
        "enabled": True,
        "min_evidence_strength": 3.0,
        "min_threat_score": 0.16,
        "min_suspicious_score": 0.08,
        "allow_rule_backed": True,
        "allow_anomaly": True,
        "allow_scan_context": True,
        "allow_incomplete_unknown_context": True,
        "allow_repeated_service": True,
        "max_benign_web_likelihood": 0.5,
        "description": "Raise only rows with strong evidence, scan context, or rule/anomaly support.",
    },
    "scan_context_balanced": {
        "enabled": True,
        "min_evidence_strength": 2.0,
        "min_threat_score": 0.12,
        "min_suspicious_score": 0.06,
        "allow_rule_backed": True,
        "allow_anomaly": True,
        "allow_scan_context": True,
        "allow_incomplete_unknown_context": True,
        "allow_repeated_service": True,
        "max_benign_web_likelihood": 1.0,
        "description": "Balanced recall recovery for scan-like, incomplete, unknown, rule, or anomaly context.",
    },
    "unknown_incomplete_focus": {
        "enabled": True,
        "min_evidence_strength": 1.5,
        "min_threat_score": 0.10,
        "min_suspicious_score": 0.05,
        "allow_rule_backed": True,
        "allow_anomaly": True,
        "allow_scan_context": False,
        "allow_incomplete_unknown_context": True,
        "allow_repeated_service": False,
        "max_benign_web_likelihood": 0.5,
        "description": "Prefer suspicious recovery for incomplete or unknown app contexts only.",
    },
}


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _selected_policies() -> list[str]:
    return list(RECALL_POLICIES)


def _row_context(row: Any, log: Any, probability_row: dict[str, float]) -> dict[str, Any]:
    family = str(row.get("v337_traffic_family") or "unknown")
    suspicious_score = _safe_float(probability_row.get("suspicious"))
    malicious_score = _safe_float(probability_row.get("malicious"))
    threat_positive = _safe_float(probability_row.get("threat_positive"), suspicious_score + malicious_score)
    if threat_positive == 0:
        threat_positive = suspicious_score + malicious_score
    return {
        "family": family,
        "app": str(getattr(log, "app", "") or "").lower(),
        "action": str(getattr(log, "action", "") or "").lower(),
        "dst_port": getattr(log, "dst_port", None),
        "suspicious_score": suspicious_score,
        "malicious_score": malicious_score,
        "threat_score": threat_positive,
        "web_low_signal": bool(row.get("v337_web_low_signal_flag")),
        "utility_low_signal": bool(row.get("v337_utility_low_signal_flag")),
        "web_scan_context": bool(row.get("v337_web_scan_context_flag")),
        "incomplete_scan_context": bool(row.get("v337_incomplete_scan_context_flag")),
        "unknown_scan_context": bool(row.get("v337_unknown_scan_context_flag")),
        "rule_backed_allow": bool(row.get("v337_rule_backed_allow_flag")),
        "anomaly_signal": bool(row.get("v337_anomaly_signal_flag")),
        "repeated_service": bool(row.get("v337_repeated_service_flag")),
        "evidence_strength": _safe_float(row.get("v337_behavior_evidence_strength")),
        "source_diversity_pressure": _safe_float(row.get("v337_source_diversity_pressure")),
        "benign_web_likelihood": _safe_float(row.get("v337_benign_web_likelihood_score")),
    }


def _has_recovery_evidence(context: dict[str, Any], policy: dict[str, Any]) -> bool:
    if policy.get("allow_rule_backed") and context["rule_backed_allow"]:
        return True
    if policy.get("allow_anomaly") and context["anomaly_signal"]:
        return True
    if policy.get("allow_scan_context") and context["web_scan_context"]:
        return True
    if policy.get("allow_incomplete_unknown_context") and (
        context["incomplete_scan_context"] or context["unknown_scan_context"]
    ):
        return True
    if policy.get("allow_repeated_service") and context["repeated_service"] and context["source_diversity_pressure"] >= 4:
        return True
    return False


def _should_raise_to_suspicious(context: dict[str, Any], policy_name: str) -> bool:
    policy = RECALL_POLICIES[policy_name]
    if not policy.get("enabled"):
        return False
    if context["web_low_signal"] or context["utility_low_signal"]:
        if not (
            context["rule_backed_allow"]
            or context["anomaly_signal"]
            or context["web_scan_context"]
            or context["incomplete_scan_context"]
            or context["unknown_scan_context"]
        ):
            return False
    if context["benign_web_likelihood"] > float(policy["max_benign_web_likelihood"]):
        return False
    if context["evidence_strength"] < float(policy["min_evidence_strength"]):
        return False
    if not _has_recovery_evidence(context, policy):
        return False
    return (
        context["threat_score"] >= float(policy["min_threat_score"])
        or context["suspicious_score"] >= float(policy["min_suspicious_score"])
        or context["rule_backed_allow"]
        or context["anomaly_signal"]
    )


def apply_pattern_specific_suspicious_recall_floor(
    prepared: dict[str, Any],
    augmented: dict[str, Any],
    predictions: list[str],
    probability_rows: list[dict[str, float]],
    *,
    absolute_indices: list[int] | None = None,
    logs: list[Any] | None = None,
    policy_name: str = "scan_context_balanced",
) -> list[str]:
    if policy_name not in RECALL_POLICIES:
        raise ValueError(f"Unknown v3.39 recall policy: {policy_name}")
    frame = augmented["frame"]
    indices = absolute_indices if absolute_indices is not None else list(prepared["test_idx"])
    selected_logs = logs if logs is not None else list(prepared["test_logs"])
    repaired: list[str] = []
    for position, prediction in enumerate(predictions):
        if prediction in THREAT_LABELS or prediction == "threat_positive":
            repaired.append(prediction)
            continue
        row = frame.iloc[indices[position]]
        context = _row_context(row, selected_logs[position], probability_rows[position])
        repaired.append("suspicious" if _should_raise_to_suspicious(context, policy_name) else prediction)
    return repaired


def _policy_score(summary: dict[str, Any], *, fpr_budget: float) -> tuple[Any, ...]:
    fpr = _safe_float(summary.get("benign_like_false_positive_rate"), 1.0)
    threat_f1 = _safe_float(summary.get("threat_positive_f1"))
    threat_recall = _safe_float(summary.get("threat_positive_recall"))
    suspicious = _safe_float(summary.get("suspicious_recall"))
    malicious = _safe_float(summary.get("malicious_recall"))
    return (
        1 if fpr <= fpr_budget else 0,
        suspicious,
        threat_f1 - 0.35 * fpr,
        malicious,
        threat_recall,
        -fpr,
    )


def _evaluate_predictions(
    prepared: dict[str, Any],
    *,
    y_true: list[str],
    predictions: list[str],
    target_mode: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    labels_order, threat_labels = _labels_order(target_mode, y_true)
    metrics = _metric_bundle(
        prepared,
        y_true=y_true,
        predictions=predictions,
        labels_order=labels_order,
        threat_labels=threat_labels,
    )
    return metrics, _profile_summary(metrics)


def _select_policy_on_calibration(
    prepared: dict[str, Any],
    augmented: dict[str, Any],
    strategy: dict[str, Any],
) -> dict[str, Any]:
    target_mode = str(strategy.get("target_mode") or "flat")
    y_calibration = list(strategy.get("_y_calibration") or [])
    calibration_rows = list(strategy.get("_calibration_probability_rows") or [])
    calibration_idx = list(strategy.get("_calibration_idx") or [])
    if not y_calibration or not calibration_rows or not calibration_idx:
        return {
            "selected_policy": "none",
            "selected_on": "unavailable",
            "used_test_for_policy_selection": False,
            "candidate_count": 0,
            "policy_candidates": [],
        }
    thresholds = (strategy.get("threshold_selection") or {}).get("selected_thresholds") or {}
    base_predictions = _predictions_for_thresholds(calibration_rows, thresholds, target_mode=target_mode)
    calibration_logs = [prepared["logs"][index] for index in calibration_idx]
    candidates = []
    for policy_name in _selected_policies():
        predictions = apply_pattern_specific_suspicious_recall_floor(
            prepared,
            augmented,
            base_predictions,
            calibration_rows,
            absolute_indices=calibration_idx,
            logs=calibration_logs,
            policy_name=policy_name,
        )
        metrics, summary = _evaluate_predictions(
            prepared,
            y_true=y_calibration,
            predictions=predictions,
            target_mode=target_mode,
        )
        candidates.append(
            {
                "policy": policy_name,
                "summary": summary,
                "metrics": metrics,
                "raised_to_suspicious": sum(
                    1 for before, after in zip(base_predictions, predictions, strict=False) if before != after
                ),
                "within_fpr_budget": _safe_float(summary.get("benign_like_false_positive_rate"), 1.0) <= FPR_BUDGET,
            }
        )
    selected = max(candidates, key=lambda item: _policy_score(item["summary"], fpr_budget=FPR_BUDGET))
    return {
        "selected_policy": selected["policy"],
        "selected_on": "train_internal_calibration",
        "used_test_for_policy_selection": False,
        "candidate_count": len(candidates),
        "within_fpr_budget_candidates": sum(1 for item in candidates if item["within_fpr_budget"]),
        "calibration_summary": selected["summary"],
        "raised_to_suspicious_on_calibration": selected["raised_to_suspicious"],
        "policy_candidates": [
            {
                "policy": item["policy"],
                "summary": item["summary"],
                "raised_to_suspicious": item["raised_to_suspicious"],
                "within_fpr_budget": item["within_fpr_budget"],
            }
            for item in candidates
        ],
    }


def _pattern_rows(
    prepared: dict[str, Any],
    augmented: dict[str, Any],
    *,
    predictions: list[str],
    y_true: list[str],
    target_mode: str,
) -> dict[str, Any]:
    frame = augmented["frame"]
    labels_order, threat_labels = _labels_order(target_mode, y_true)
    del labels_order
    suspicious_misses: list[dict[str, Any]] = []
    false_positives: list[dict[str, Any]] = []
    for position, (actual, predicted) in enumerate(zip(y_true, predictions, strict=False)):
        index = prepared["test_idx"][position]
        log = prepared["test_logs"][position]
        row = frame.iloc[index]
        item = {
            "pattern": f"app={log.app or '-'}|action={log.action or '-'}|port={log.dst_port or '-'}",
            "family": str(row.get("v337_traffic_family") or "unknown"),
            "source_name": _source_name(log),
            "predicted": predicted,
            "actual": actual,
        }
        if actual == "suspicious" and predicted != "suspicious":
            suspicious_misses.append(item)
        if actual in BENIGN_LIKE_LABELS or actual == "benign_like":
            if predicted in threat_labels:
                false_positives.append(item)
    return {
        "suspicious_miss_count": len(suspicious_misses),
        "suspicious_miss_top_patterns": Counter(row["pattern"] for row in suspicious_misses).most_common(12),
        "suspicious_miss_top_families": Counter(row["family"] for row in suspicious_misses).most_common(10),
        "suspicious_miss_predicted_as": dict(Counter(str(row["predicted"]) for row in suspicious_misses)),
        "false_positive_count": len(false_positives),
        "false_positive_top_patterns": Counter(row["pattern"] for row in false_positives).most_common(12),
        "false_positive_top_families": Counter(row["family"] for row in false_positives).most_common(10),
        "false_positive_top_sources": Counter(row["source_name"] for row in false_positives).most_common(10),
    }


def _strategy_rows(prepared: dict[str, Any], augmented: dict[str, Any], strategies: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for strategy in strategies:
        if strategy.get("status") != "evaluated":
            rows.append({key: strategy.get(key) for key in ["name", "status", "message", "target_mode"]})
            continue
        target_mode = str(strategy.get("target_mode") or "flat")
        if target_mode == "binary":
            continue
        y_test = list(strategy.get("_y_test") or prepared["y_test"])
        base_predictions = list(strategy.get("_predictions") or [])
        probability_rows = list(strategy.get("_test_probability_rows") or [])
        if not base_predictions or not probability_rows:
            continue
        policy_selection = _select_policy_on_calibration(prepared, augmented, strategy)
        selected_policy = policy_selection["selected_policy"]
        base_metrics, base_summary = _evaluate_predictions(
            prepared,
            y_true=y_test,
            predictions=base_predictions,
            target_mode=target_mode,
        )
        rows.append(
            {
                "name": f"{strategy['name']}_baseline",
                "base_strategy": strategy["name"],
                "status": "evaluated",
                "eligible_for_selection": True,
                "selected_by_calibration": selected_policy == "none",
                "target_mode": target_mode,
                "model_type": strategy.get("model_type"),
                "policy": "none",
                "policy_selected_on": "baseline",
                "used_test_for_policy_selection": False,
                "summary": base_summary,
                "metrics": base_metrics,
                "calibration": strategy.get("calibration") or {},
                "threshold_selection": strategy.get("threshold_selection") or {},
                "pattern_summary": _pattern_rows(
                    prepared,
                    augmented,
                    predictions=base_predictions,
                    y_true=y_test,
                    target_mode=target_mode,
                ),
                "raised_to_suspicious": 0,
            }
        )
        for policy_name in [name for name in _selected_policies() if name != "none"]:
            policy_predictions = apply_pattern_specific_suspicious_recall_floor(
                prepared,
                augmented,
                base_predictions,
                probability_rows,
                policy_name=policy_name,
            )
            policy_metrics, policy_summary = _evaluate_predictions(
                prepared,
                y_true=y_test,
                predictions=policy_predictions,
                target_mode=target_mode,
            )
            selected_by_calibration = policy_name == selected_policy
            suffix = "selected" if selected_by_calibration else "exploratory"
            rows.append(
                {
                    "name": f"{strategy['name']}_{policy_name}_{suffix}",
                    "base_strategy": strategy["name"],
                    "status": "evaluated",
                    "eligible_for_selection": selected_by_calibration,
                    "selected_by_calibration": selected_by_calibration,
                    "target_mode": target_mode,
                    "model_type": strategy.get("model_type"),
                    "policy": policy_name,
                    "policy_selected_on": policy_selection["selected_on"] if selected_by_calibration else "test_diagnostic_only",
                    "used_test_for_policy_selection": False,
                    "policy_selection": policy_selection if selected_by_calibration else {
                        "selected_policy": policy_name,
                        "selected_on": "test_diagnostic_only",
                        "used_test_for_policy_selection": False,
                        "note": "Exploratory what-if row; not eligible for best-candidate selection.",
                    },
                    "summary": policy_summary,
                    "metrics": policy_metrics,
                    "calibration": strategy.get("calibration") or {},
                    "threshold_selection": strategy.get("threshold_selection") or {},
                    "pattern_summary": _pattern_rows(
                        prepared,
                        augmented,
                        predictions=policy_predictions,
                        y_true=y_test,
                        target_mode=target_mode,
                    ),
                    "raised_to_suspicious": sum(
                        1
                        for before, after in zip(base_predictions, policy_predictions, strict=False)
                        if before != after
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
        suspicious_misses = Counter()
        false_positives = Counter()
        false_positive_families = Counter()
        policies = Counter()
        threshold_rows: list[dict[str, Any]] = []
        policy_rows: list[dict[str, Any]] = []
        raised_total = 0
        target_modes = set()
        eligible_for_selection = False
        selected_by_calibration = False
        for split in split_results:
            for row in split.get("strategies", []):
                if row.get("name") != name or row.get("status") != "evaluated":
                    continue
                eligible_for_selection = eligible_for_selection or bool(row.get("eligible_for_selection"))
                selected_by_calibration = selected_by_calibration or bool(row.get("selected_by_calibration"))
                target_modes.add(str(row.get("target_mode") or "unknown"))
                raised_total += int(row.get("raised_to_suspicious") or 0)
                policies[str(row.get("policy") or "none")] += 1
                threshold_rows.append(row.get("threshold_selection") or {})
                policy_rows.append(row.get("policy_selection") or {})
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
                pattern_summary = row.get("pattern_summary") or {}
                for pattern, count in pattern_summary.get("suspicious_miss_top_patterns") or []:
                    suspicious_misses[str(pattern)] += int(count)
                for pattern, count in pattern_summary.get("false_positive_top_patterns") or []:
                    false_positives[str(pattern)] += int(count)
                for family, count in pattern_summary.get("false_positive_top_families") or []:
                    false_positive_families[str(family)] += int(count)
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
            "eligible_for_selection": eligible_for_selection,
            "selected_by_calibration": selected_by_calibration,
            "stability": stability,
            "best_calibration": best_calibration,
            "policy_counts": dict(policies),
            "raised_to_suspicious_total": raised_total,
            "threshold_selection": {
                "used_test_for_threshold_selection": any(
                    bool(row.get("used_test_for_threshold_selection")) for row in threshold_rows
                ),
                "selected_on": sorted({str(row.get("selected_on")) for row in threshold_rows if row.get("selected_on")}),
            },
            "policy_selection": {
                "used_test_for_policy_selection": any(
                    bool(row.get("used_test_for_policy_selection")) for row in policy_rows
                ),
                "selected_on": sorted({str(row.get("selected_on")) for row in policy_rows if row.get("selected_on")}),
            },
            "top_suspicious_miss_patterns": suspicious_misses.most_common(12),
            "top_false_positive_patterns": false_positives.most_common(12),
            "top_false_positive_families": false_positive_families.most_common(10),
        }
    return comparison


def _range_value(item: dict[str, Any], metric: str, kind: str, default: float = 0.0) -> float:
    ranges = (item.get("stability") or {}).get("metric_ranges") or {}
    return _safe_float((ranges.get(metric) or {}).get(kind), default)


def _select_best(comparison: dict[str, Any]) -> str | None:
    if not comparison:
        return None
    selectable = {name: item for name, item in comparison.items() if item.get("eligible_for_selection")}
    if not selectable:
        selectable = comparison

    def score(name: str) -> tuple[Any, ...]:
        item = selectable[name]
        max_fpr = _range_value(item, "benign_like_false_positive_rate", "max", 1.0)
        min_f1 = _range_value(item, "threat_positive_f1", "min")
        min_suspicious = _range_value(item, "suspicious_recall", "min")
        min_malicious = _range_value(item, "malicious_recall", "min")
        calibration = item.get("best_calibration") or {}
        leakage_free = not (
            (item.get("threshold_selection") or {}).get("used_test_for_threshold_selection")
            or (item.get("policy_selection") or {}).get("used_test_for_policy_selection")
        )
        return (
            int((item.get("stability") or {}).get("passing_splits") or 0),
            1 if leakage_free else 0,
            1 if max_fpr <= FPR_BUDGET else 0,
            min_suspicious,
            min_f1 - 0.35 * max_fpr,
            min_malicious,
            1 if calibration.get("passed") else 0,
            -max_fpr,
        )

    return max(selectable, key=score)


def _readiness(item: dict[str, Any]) -> dict[str, Any]:
    stability = item.get("stability") or {}
    calibration = item.get("best_calibration") or {}
    threshold_selection = item.get("threshold_selection") or {}
    policy_selection = item.get("policy_selection") or {}
    leakage_free = not (
        bool(threshold_selection.get("used_test_for_threshold_selection"))
        or bool(policy_selection.get("used_test_for_policy_selection"))
    )
    checks = [
        {
            "name": "threshold and policy selection avoid test leakage",
            "passed": leakage_free,
            "value": {
                "threshold_selected_on": threshold_selection.get("selected_on"),
                "policy_selected_on": policy_selection.get("selected_on"),
            },
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
            "name": "suspicious recall stable",
            "passed": _range_value(item, "suspicious_recall", "min") >= 0.8,
            "value": _range_value(item, "suspicious_recall", "min"),
            "target": ">= 0.8 across splits",
        },
        {
            "name": "malicious recall acceptable",
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
            "| {name} | {eligible} | {policies} | {raised} | {passed} | {f1_min}-{f1_max} | {fpr_min}-{fpr_max} | {susp_min}-{susp_max} | {mal_min}-{mal_max} | {cal} |".format(
                name=name,
                eligible="yes" if item.get("eligible_for_selection") else "no",
                policies=item.get("policy_counts"),
                raised=item.get("raised_to_suspicious_total"),
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
    return f"""# v3.39 Pattern-Specific Suspicious Recall Recovery

Generated: {result.get("generated_at")}

This phase is diagnostic only. Pattern recall policies are selected on train-internal calibration rows, then evaluated on held-out splits. No labels were written, no model was activated, no artifact was written, and response automation stayed disabled.

## Best Diagnostic Candidate

- Candidate: {result.get("best_strategy")}
- Readiness: {result.get("readiness", {}).get("decision")}
- Checks passed: {result.get("readiness", {}).get("passed")} / {result.get("readiness", {}).get("total")}
- Blockers: {result.get("readiness", {}).get("blockers")}

## Strategy Comparison

| Strategy | Eligible | Policy Counts | Raised To Suspicious | Passing Splits | Threat F1 Range | Benign FPR Range | Suspicious Recall Range | Malicious Recall Range | Calibration |
| --- | --- | --- | ---: | ---: | --- | --- | --- | --- | --- |
{chr(10).join(rows)}

## Residual Pattern Notes

```json
{json.dumps(result.get("residual_pattern_notes"), indent=2, default=str)}
```

## Safety

```json
{json.dumps(result.get("safety"), indent=2, default=str)}
```
"""


def _residual_pattern_notes(comparison: dict[str, Any], best_strategy: str | None) -> dict[str, Any]:
    if not best_strategy or best_strategy not in comparison:
        return {"summary": "No evaluated v3.39 strategy was available."}
    item = comparison[best_strategy]
    return {
        "best_strategy": best_strategy,
        "top_suspicious_miss_patterns": item.get("top_suspicious_miss_patterns") or [],
        "top_false_positive_patterns": item.get("top_false_positive_patterns") or [],
        "top_false_positive_families": item.get("top_false_positive_families") or [],
        "interpretation": (
            "If suspicious recall is still below target, the remaining misses likely need better training support, "
            "more robust evidence features, or a model architecture change rather than broader post-prediction overrides."
        ),
    }


def run_v339_suspicious_recall_recovery(
    db: Session,
    *,
    test_size: float = 0.3,
    min_samples: int = 6,
    output_dir: str | Path = OUTPUT_DIR,
) -> dict[str, Any]:
    before_runs = int(db.scalar(select(func.count(MLModelRun.id))) or 0)
    before_responses = int(db.scalar(select(func.count(ResponseAction.id))) or 0)
    base = _load_base_dataset(db, min_samples=min_samples)
    if not base.get("ok"):
        return base

    started = time.perf_counter()
    split_results: list[dict[str, Any]] = []
    specs = [spec for spec in _candidate_specs() if spec["target_mode"] != "binary"]
    for split_mode in V335_SPLITS:
        prepared = _prepared_for_split(base, split_mode=split_mode, test_size=test_size)
        frame, meta = enrich_v337_features(prepared)
        augmented = {"frame": frame, **meta}
        strategies = [_fit_candidate(prepared, augmented, spec) for spec in specs]
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
        "blockers": ["no evaluated v3.39 strategy"],
        "checks": [],
    }
    after_runs = int(db.scalar(select(func.count(MLModelRun.id))) or 0)
    after_responses = int(db.scalar(select(func.count(ResponseAction.id))) or 0)

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    stamp = _stamp()
    report_path = output_path / f"v3_39_suspicious_recall_recovery_{stamp}.md"
    latest_path = output_path / V339_LATEST
    result: dict[str, Any] = {
        "ok": True,
        "status": "completed",
        "phase": "v3.39",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "runtime_seconds": round(time.perf_counter() - started, 4),
        "feature_generation_seconds": base.get("feature_generation_seconds"),
        "fpr_budget": FPR_BUDGET,
        "splits": V335_SPLITS,
        "recall_policies": RECALL_POLICIES,
        "strategy_comparison": comparison,
        "best_strategy": best_strategy,
        "readiness": readiness,
        "training_dataset": training_dataset_diagnostics(db),
        "residual_pattern_notes": _residual_pattern_notes(comparison, best_strategy),
        "split_results": split_results,
        "safety": {
            "production_promoted": False,
            "model_activated": False,
            "model_artifact_written": False,
            "response_automation_allowed": False,
            "real_firewall_blocking_enabled": False,
            "labels_written": False,
            "ml_model_runs_before": before_runs,
            "ml_model_runs_after": after_runs,
            "response_actions_before": before_responses,
            "response_actions_after": after_responses,
        },
        "report_path": str(report_path),
        "latest_summary_path": str(latest_path),
    }
    report_path.write_text(_render_report(result), encoding="utf-8")
    latest_path.write_text(
        json.dumps({key: value for key, value in result.items() if key != "split_results"}, indent=2, default=str),
        encoding="utf-8",
    )
    return result
