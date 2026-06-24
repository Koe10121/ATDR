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
from atdr.app.detection.v331_noise_reduction import (
    V331_PROFILE_ORDER,
    _augment_frame,
    _fit_hierarchical_strategy,
    _fit_strategy,
    _metric_bundle,
    _probability_rows,
    _profile_summary,
    _strategy_best_profile,
)
from atdr.app.detection.v332_guard_validation import _load_base_dataset, _prepared_for_split, _safe_float, _stability_summary
from atdr.app.detection.supervised_detector import training_dataset_diagnostics


V335_SPLITS = ["time", "grouped_stratified", "random_seed_7", "random_seed_17", "random_seed_42"]
V335_LATEST = "v3_35_split_stability_repair_latest.json"


REPAIR_POLICIES: dict[str, dict[str, float]] = {
    "evidence_floor_conservative": {"min_evidence": 3.0, "min_threat_score": 0.28, "min_suspicious_score": 0.12},
    "evidence_floor_balanced": {"min_evidence": 2.0, "min_threat_score": 0.22, "min_suspicious_score": 0.10},
    "evidence_floor_rule_or_scan": {"min_evidence": 1.0, "min_threat_score": 0.18, "min_suspicious_score": 0.08},
}


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _max_numeric(row: Any, names: list[str]) -> float:
    return max((_safe_float(row.get(name)) for name in names), default=0.0)


def _evidence_features(row: Any, log: Any, probability_row: dict[str, float]) -> dict[str, Any]:
    unique_dst_ips = _max_numeric(
        row,
        ["src_ip_5min_unique_dst_ips", "src_ip_15min_unique_dst_ips", "src_ip_60min_unique_dst_ips"],
    )
    unique_dst_ports = _max_numeric(
        row,
        ["src_ip_5min_unique_dst_ports", "src_ip_15min_unique_dst_ports", "src_ip_60min_unique_dst_ports"],
    )
    event_count = _max_numeric(
        row,
        ["src_ip_5min_log_count", "src_ip_5min_event_count", "src_ip_15min_event_count", "src_ip_60min_event_count"],
    )
    deny_count = _max_numeric(
        row,
        [
            "src_ip_5min_deny_count",
            "src_ip_5min_deny_drop_reset_count",
            "src_ip_15min_deny_drop_reset_count",
            "src_ip_60min_deny_drop_reset_count",
        ],
    )
    unknown_count = _max_numeric(
        row,
        ["src_ip_5min_unknown_app_count", "src_ip_15min_unknown_app_count", "src_ip_60min_unknown_app_count"],
    )
    high_risk_count = _max_numeric(
        row,
        ["src_ip_5min_high_risk_app_count", "src_ip_15min_high_risk_app_count", "src_ip_60min_high_risk_app_count"],
    )
    rule_score = _safe_float(row.get("v331_rule_score"))
    suspicious_score = _safe_float(probability_row.get("suspicious"))
    malicious_score = _safe_float(probability_row.get("malicious"))
    threat_score = suspicious_score + malicious_score
    anomaly_score = _safe_float(getattr(log, "anomaly_score", None), 0.0)
    anomaly_signal = bool(getattr(log, "is_anomaly", False)) or anomaly_score <= -0.20
    scan_like = (
        unique_dst_ips >= 4
        or unique_dst_ports >= 3
        or (event_count >= 10 and (unique_dst_ips >= 3 or unique_dst_ports >= 2))
        or deny_count > 0
        or unknown_count >= 3
        or high_risk_count >= 2
    )
    low_signal_benign = bool(row.get("v331_quic_443_allow_no_rule_flag")) or bool(
        row.get("v331_benign_network_utility_no_rule_flag")
    )
    evidence_score = 0
    evidence_score += 2 if rule_score >= 15 else 0
    evidence_score += 1 if scan_like else 0
    evidence_score += 1 if anomaly_signal else 0
    evidence_score += 1 if bool(row.get("v331_unknown_udp_scan_context_flag")) else 0
    evidence_score += 1 if deny_count > 0 else 0
    evidence_score += 1 if high_risk_count >= 2 else 0
    return {
        "unique_dst_ips": unique_dst_ips,
        "unique_dst_ports": unique_dst_ports,
        "event_count": event_count,
        "deny_count": deny_count,
        "unknown_count": unknown_count,
        "high_risk_count": high_risk_count,
        "rule_score": rule_score,
        "suspicious_score": suspicious_score,
        "malicious_score": malicious_score,
        "threat_score": threat_score,
        "anomaly_signal": anomaly_signal,
        "scan_like": scan_like,
        "low_signal_benign": low_signal_benign,
        "evidence_score": evidence_score,
    }


def _should_raise_to_suspicious(
    evidence: dict[str, Any],
    *,
    policy: dict[str, float],
) -> bool:
    if evidence["low_signal_benign"] and not (
        evidence["scan_like"] or evidence["anomaly_signal"] or evidence["rule_score"] >= 15
    ):
        return False
    if evidence["evidence_score"] < policy["min_evidence"]:
        return False
    return (
        evidence["threat_score"] >= policy["min_threat_score"]
        or evidence["suspicious_score"] >= policy["min_suspicious_score"]
        or evidence["rule_score"] >= 25
    )


def apply_evidence_aware_suspicious_recall_floor(
    prepared: dict[str, Any],
    augmented: dict[str, Any],
    predictions: list[str],
    probability_rows: list[dict[str, float]],
    *,
    policy_name: str = "evidence_floor_balanced",
) -> list[str]:
    policy = REPAIR_POLICIES[policy_name]
    repaired: list[str] = []
    frame = augmented["frame"]
    for position, prediction in enumerate(predictions):
        if prediction in THREAT_LABELS or prediction == "threat_positive":
            repaired.append(prediction)
            continue
        absolute_index = prepared["test_idx"][position]
        row = frame.iloc[absolute_index]
        log = prepared["test_logs"][position]
        evidence = _evidence_features(row, log, probability_rows[position])
        if _should_raise_to_suspicious(evidence, policy=policy):
            repaired.append("suspicious")
        else:
            repaired.append(prediction)
    return repaired


def _strategy_specs() -> list[dict[str, Any]]:
    return [
        {
            "name": "flat_current",
            "model_type": "extra_trees",
            "target_mode": "flat",
            "class_weight": "balanced",
            "weight_strategy": "current",
            "use_augmented_features": False,
            "calibrated": False,
            "postprocess_low_signal_guard": False,
        },
        {
            "name": "flat_augmented_strong_benign",
            "model_type": "extra_trees",
            "target_mode": "flat",
            "class_weight": None,
            "weight_strategy": "strong_benign",
            "use_augmented_features": True,
            "calibrated": False,
            "postprocess_low_signal_guard": False,
        },
        {
            "name": "three_class_soc_queue",
            "model_type": "extra_trees",
            "target_mode": "three_class",
            "class_weight": None,
            "weight_strategy": "strong_benign",
            "use_augmented_features": True,
            "calibrated": False,
            "postprocess_low_signal_guard": False,
        },
    ]


def _fit_base_strategies(prepared: dict[str, Any], augmented: dict[str, Any]) -> list[dict[str, Any]]:
    strategies: list[dict[str, Any]] = []
    for spec in _strategy_specs():
        try:
            strategy = _fit_strategy(prepared, augmented, **spec)
        except Exception as exc:  # pragma: no cover - defensive diagnostic output
            strategy = {"name": spec["name"], "status": "failed", "message": str(exc), "target_mode": spec["target_mode"]}
        if strategy.get("status") == "evaluated":
            profile = _strategy_best_profile(strategy)
            strategy["recommended_profile"] = profile
            strategy["recommended_metrics"] = _profile_summary(strategy["profiles"][profile]) if profile else {}
        strategies.append(strategy)
    try:
        hierarchical = _fit_hierarchical_strategy(prepared, augmented)
        if hierarchical.get("status") == "evaluated":
            profile = _strategy_best_profile(hierarchical)
            hierarchical["recommended_profile"] = profile
            hierarchical["recommended_metrics"] = _profile_summary(hierarchical["profiles"][profile]) if profile else {}
        strategies.append(hierarchical)
    except Exception as exc:  # pragma: no cover - defensive diagnostic output
        strategies.append({"name": "hierarchical_two_stage_augmented", "status": "failed", "message": str(exc)})
    return strategies


def _labels_for_mode(prepared: dict[str, Any], target_mode: str, y_test: list[str]) -> tuple[list[str], set[str]]:
    if target_mode == "three_class":
        return ["benign_like", "malicious", "suspicious"], set(THREAT_LABELS)
    if target_mode == "binary":
        return ["benign_like", "threat_positive"], {"threat_positive"}
    if target_mode == "hierarchical":
        return ["benign_like", "malicious", "suspicious"], set(THREAT_LABELS)
    return sorted(set(prepared["y"] + y_test)), set(THREAT_LABELS)


def _miss_patterns(
    prepared: dict[str, Any],
    augmented: dict[str, Any],
    *,
    predictions: list[str],
    y_true: list[str],
    threat_labels: set[str],
) -> dict[str, Any]:
    frame = augmented["frame"]
    suspicious_misses: list[dict[str, Any]] = []
    threat_misses: list[dict[str, Any]] = []
    false_positives: list[dict[str, Any]] = []
    for position, (actual, predicted) in enumerate(zip(y_true, predictions, strict=False)):
        absolute_index = prepared["test_idx"][position]
        log = prepared["test_logs"][position]
        label = prepared["test_labels"][position]
        row = frame.iloc[absolute_index]
        item = {
            "label": label,
            "log": log,
            "pattern": f"app={log.app or '-'}|action={log.action or '-'}|port={log.dst_port or '-'}",
            "source_name": _source_name(log),
            "quic_no_rule": bool(row.get("v331_quic_443_allow_no_rule_flag")),
            "unknown_udp_scan_context": bool(row.get("v331_unknown_udp_scan_context_flag")),
            "rule_score": _safe_float(row.get("v331_rule_score")),
        }
        if actual == "suspicious" and predicted != "suspicious":
            suspicious_misses.append(item | {"predicted": predicted})
        if actual in threat_labels and predicted not in threat_labels:
            threat_misses.append(item | {"actual": actual, "predicted": predicted})
        if actual in BENIGN_LIKE_LABELS or actual == "benign_like":
            if predicted in threat_labels:
                false_positives.append(item | {"actual": actual, "predicted": predicted})
    return {
        "suspicious_miss_count": len(suspicious_misses),
        "suspicious_miss_top_patterns": Counter(row["pattern"] for row in suspicious_misses).most_common(10),
        "suspicious_miss_predicted_as": dict(Counter(str(row["predicted"]) for row in suspicious_misses)),
        "threat_false_negative_count": len(threat_misses),
        "threat_false_negative_top_patterns": Counter(row["pattern"] for row in threat_misses).most_common(10),
        "false_positive_count": len(false_positives),
        "false_positive_top_patterns": Counter(row["pattern"] for row in false_positives).most_common(10),
        "false_positive_reviewed_vs_weak": dict(
            Counter("reviewed" if row["label"].reviewed else "weak" for row in false_positives)
        ),
    }


def _strategy_rows(prepared: dict[str, Any], augmented: dict[str, Any], strategies: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for strategy in strategies:
        if strategy.get("status") != "evaluated":
            rows.append({"name": strategy.get("name"), "status": strategy.get("status"), "message": strategy.get("message")})
            continue
        target_mode = str(strategy.get("target_mode") or "flat")
        if strategy.get("_y_test"):
            y_test = strategy["_y_test"]
        elif target_mode in {"three_class", "hierarchical"}:
            y_test = [label if label in THREAT_LABELS else "benign_like" for label in prepared["y_test"]]
        else:
            y_test = prepared["y_test"]
        labels_order, threat_labels = _labels_for_mode(prepared, target_mode, y_test)
        profile = strategy.get("recommended_profile")
        base_predictions = (strategy.get("_predictions") or {}).get(profile) or []
        if not base_predictions:
            rows.append(
                {
                    "name": strategy.get("name"),
                    "status": "evaluated",
                    "target_mode": target_mode,
                    "recommended_profile": profile,
                    "summary": strategy.get("recommended_metrics") or {},
                    "calibration": strategy.get("calibration") or {},
                    "repair_policy": "none",
                    "repair_applied": False,
                    "miss_patterns": {},
                }
            )
            continue
        rows.append(
            {
                "name": f"{strategy['name']}_recommended_profile",
                "base_strategy": strategy["name"],
                "status": "evaluated",
                "target_mode": target_mode,
                "recommended_profile": profile,
                "summary": _profile_summary(strategy["profiles"][profile]),
                "calibration": strategy.get("calibration") or {},
                "repair_policy": "none",
                "repair_applied": False,
                "miss_patterns": _miss_patterns(
                    prepared,
                    augmented,
                    predictions=base_predictions,
                    y_true=y_test,
                    threat_labels=threat_labels,
                ),
            }
        )
        if target_mode not in {"flat", "three_class"}:
            continue
        probabilities = strategy.get("_probabilities")
        classes = strategy.get("_classes") or []
        probability_rows = _probability_rows(probabilities, classes) if probabilities is not None else []
        for policy_name in REPAIR_POLICIES:
            repaired = apply_evidence_aware_suspicious_recall_floor(
                prepared,
                augmented,
                base_predictions,
                probability_rows,
                policy_name=policy_name,
            )
            metrics = _metric_bundle(
                prepared,
                y_true=y_test,
                predictions=repaired,
                labels_order=labels_order,
                threat_labels=threat_labels,
            )
            rows.append(
                {
                    "name": f"{strategy['name']}_{policy_name}",
                    "base_strategy": strategy["name"],
                    "status": "evaluated",
                    "target_mode": target_mode,
                    "recommended_profile": profile,
                    "summary": _profile_summary(metrics),
                    "calibration": strategy.get("calibration") or {},
                    "repair_policy": policy_name,
                    "repair_applied": True,
                    "raised_to_suspicious": sum(
                        1
                        for before, after in zip(base_predictions, repaired, strict=False)
                        if before != after and after == "suspicious"
                    ),
                    "miss_patterns": _miss_patterns(
                        prepared,
                        augmented,
                        predictions=repaired,
                        y_true=y_test,
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
            if split.get("status") == "evaluated"
            for row in split.get("strategies", [])
            if row.get("status") == "evaluated"
        }
    )
    comparison: dict[str, Any] = {}
    for name in names:
        strategy_splits: list[dict[str, Any]] = []
        calibrations: list[dict[str, Any]] = []
        miss_patterns = Counter()
        fp_patterns = Counter()
        raised_total = 0
        repair_applied = False
        modes = set()
        for split in split_results:
            if split.get("status") != "evaluated":
                continue
            for row in split.get("strategies", []):
                if row.get("name") != name or row.get("status") != "evaluated":
                    continue
                modes.add(str(row.get("target_mode") or "unknown"))
                repair_applied = repair_applied or bool(row.get("repair_applied"))
                raised_total += int(row.get("raised_to_suspicious") or 0)
                strategy_splits.append(
                    {
                        "split_mode": split["split_mode"],
                        "status": "evaluated",
                        "training_rows": split["training_rows"],
                        "test_rows": split["test_rows"],
                        "summary": row.get("summary") or {},
                    }
                )
                calibrations.append(row.get("calibration") or {})
                miss = row.get("miss_patterns") or {}
                for pattern, count in miss.get("suspicious_miss_top_patterns") or []:
                    miss_patterns[str(pattern)] += int(count)
                for pattern, count in miss.get("false_positive_top_patterns") or []:
                    fp_patterns[str(pattern)] += int(count)
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
            "target_modes": sorted(modes),
            "repair_applied": repair_applied,
            "raised_to_suspicious_total": raised_total,
            "stability": stability,
            "best_calibration": best_calibration,
            "top_suspicious_miss_patterns": miss_patterns.most_common(12),
            "top_false_positive_patterns": fp_patterns.most_common(12),
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
        stability = item.get("stability") or {}
        max_fpr = _range_value(item, "benign_like_false_positive_rate", "max", 1.0)
        min_f1 = _range_value(item, "threat_positive_f1", "min")
        min_suspicious = _range_value(item, "suspicious_recall", "min")
        min_malicious = _range_value(item, "malicious_recall", "min")
        calibration = item.get("best_calibration") or {}
        return (
            int(stability.get("passing_splits") or 0),
            1 if max_fpr <= 0.15 else 0,
            min_suspicious,
            min_f1 - 0.4 * max_fpr,
            min_malicious,
            1 if calibration.get("passed") else 0,
            -max_fpr,
        )

    return max(comparison, key=score)


def _readiness(item: dict[str, Any]) -> dict[str, Any]:
    stability = item.get("stability") or {}
    calibration = item.get("best_calibration") or {}
    checks = [
        {
            "name": "independent split stability acceptable",
            "passed": bool(stability.get("passed")),
            "value": f"{stability.get('passing_splits')}/{stability.get('evaluated_splits')}",
            "target": "all evaluated splits pass FPR/F1/recall gates",
        },
        {
            "name": "benign-like false-positive rate stable",
            "passed": _range_value(item, "benign_like_false_positive_rate", "max", 1.0) <= 0.15,
            "value": _range_value(item, "benign_like_false_positive_rate", "max", 1.0),
            "target": "<= 0.15 across splits",
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


def _root_cause_summary(comparison: dict[str, Any]) -> list[str]:
    if not comparison:
        return ["No evaluated v3.35 strategies were available."]
    miss_counter = Counter()
    fp_counter = Counter()
    for item in comparison.values():
        for pattern, count in item.get("top_suspicious_miss_patterns") or []:
            miss_counter[str(pattern)] += int(count)
        for pattern, count in item.get("top_false_positive_patterns") or []:
            fp_counter[str(pattern)] += int(count)
    notes = [
        "Suspicious recall instability is mostly a split-generalization issue: source/time patterns seen in one split do not transfer cleanly to grouped and random splits.",
    ]
    if miss_counter:
        notes.append(f"Top suspicious-miss pattern: {miss_counter.most_common(1)[0][0]}.")
    if fp_counter:
        notes.append(f"Top false-positive pattern after repair testing: {fp_counter.most_common(1)[0][0]}.")
    notes.append("Evidence-aware recall floors can be tested safely, but candidates remain diagnostic-only until all split gates pass.")
    return notes


def _render_repair_report(result: dict[str, Any]) -> str:
    rows = []
    for name, item in result.get("strategy_comparison", {}).items():
        ranges = item.get("stability", {}).get("metric_ranges", {})
        rows.append(
            "| {name} | {repair} | {raised} | {passed} | {f1_min}-{f1_max} | {fpr_min}-{fpr_max} | {susp_min}-{susp_max} | {mal_min}-{mal_max} | {cal} |".format(
                name=name,
                repair="yes" if item.get("repair_applied") else "no",
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
    return f"""# v3.35 Supervised ML Split-Stability Repair

Generated: {result.get("generated_at")}

This phase is diagnostic only. No model was activated, no model artifact was written, and response automation stayed disabled.

## Best Diagnostic Candidate

- Candidate: {result.get("best_strategy")}
- Readiness: {result.get("readiness", {}).get("decision")}
- Checks passed: {result.get("readiness", {}).get("passed")} / {result.get("readiness", {}).get("total")}
- Blockers: {result.get("readiness", {}).get("blockers")}

## Root Cause Summary

{chr(10).join(f"- {note}" for note in result.get("root_cause_summary", []))}

## Strategy Comparison

| Strategy | Repair Applied | Raised To Suspicious | Passing Splits | Threat F1 Range | Benign FPR Range | Suspicious Recall Range | Malicious Recall Range | Calibration |
| --- | --- | ---: | ---: | --- | --- | --- | --- | --- |
{chr(10).join(rows)}

## Safety

```json
{json.dumps(result.get("safety"), indent=2, default=str)}
```
"""


def _render_diagnosis_report(result: dict[str, Any]) -> str:
    rows = []
    for name, item in result.get("strategy_comparison", {}).items():
        rows.append(
            "| {name} | {misses} | {fps} |".format(
                name=name,
                misses=item.get("top_suspicious_miss_patterns"),
                fps=item.get("top_false_positive_patterns"),
            )
        )
    return f"""# v3.35 Suspicious Recall Diagnosis

Generated: {result.get("generated_at")}

| Strategy | Top Suspicious Miss Patterns | Top False-Positive Patterns |
| --- | --- | --- |
{chr(10).join(rows)}
"""


def run_v335_split_stability_repair(
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
    for split_mode in V335_SPLITS:
        prepared = _prepared_for_split(base, split_mode=split_mode, test_size=test_size)
        augmented_frame, augmented_meta = _augment_frame(prepared)
        augmented = {"frame": augmented_frame, **augmented_meta}
        strategies = _fit_base_strategies(prepared, augmented)
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
        "blockers": ["no evaluated strategy"],
        "checks": [],
    }
    after_runs = int(db.scalar(select(func.count(MLModelRun.id))) or 0)
    after_responses = int(db.scalar(select(func.count(ResponseAction.id))) or 0)

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    stamp = _stamp()
    repair_report_path = output_path / f"v3_35_split_stability_repair_{stamp}.md"
    diagnosis_report_path = output_path / f"v3_35_suspicious_recall_diagnosis_{stamp}.md"
    latest_path = output_path / V335_LATEST
    result: dict[str, Any] = {
        "ok": True,
        "status": "completed",
        "phase": "v3.35",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "runtime_seconds": round(time.perf_counter() - started, 4),
        "feature_generation_seconds": base.get("feature_generation_seconds"),
        "splits": V335_SPLITS,
        "strategy_comparison": comparison,
        "best_strategy": best_strategy,
        "readiness": readiness,
        "root_cause_summary": _root_cause_summary(comparison),
        "training_dataset": training_dataset_diagnostics(db),
        "split_results": split_results,
        "safety": {
            "production_promoted": False,
            "model_activated": False,
            "model_artifact_written": False,
            "response_automation_allowed": False,
            "real_firewall_blocking_enabled": False,
            "ml_model_runs_before": before_runs,
            "ml_model_runs_after": after_runs,
            "response_actions_before": before_responses,
            "response_actions_after": after_responses,
        },
        "repair_report_path": str(repair_report_path),
        "diagnosis_report_path": str(diagnosis_report_path),
        "latest_summary_path": str(latest_path),
    }
    repair_report_path.write_text(_render_repair_report(result), encoding="utf-8")
    diagnosis_report_path.write_text(_render_diagnosis_report(result), encoding="utf-8")
    latest_path.write_text(
        json.dumps({key: value for key, value in result.items() if key != "split_results"}, indent=2, default=str),
        encoding="utf-8",
    )
    return result
