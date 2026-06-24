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
    _augment_frame,
    _calibration_report,
    _fit_hierarchical_strategy,
    _fit_strategy,
    _profile_summary,
    _strategy_best_profile,
)
from atdr.app.detection.v332_guard_validation import _load_base_dataset, _prepared_for_split, _safe_float, _stability_summary
from atdr.app.detection.v335_split_stability_repair import V335_SPLITS, _max_numeric
from atdr.app.detection.supervised_detector import training_dataset_diagnostics


V337_LATEST = "v3_37_evidence_feature_enrichment_latest.json"
WEB_LIKE_APPS = {
    "ssl",
    "quic-base",
    "web-browsing",
    "gquic",
    "facebook-base",
    "gmail-base",
    "youtube-base",
    "naver-line",
    "tiktok-base",
    "apple-maps",
    "icloud-base",
    "wechat-base",
}
UTILITY_APPS = {"ping", "icmp", "dns-base", "ntp-base", "stun"}


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _lower(value: str | None) -> str:
    return (value or "").strip().lower()


def _event_count(row: Any) -> float:
    return _max_numeric(
        row,
        [
            "src_ip_5min_log_count",
            "src_ip_5min_event_count",
            "src_ip_15min_event_count",
            "src_ip_60min_event_count",
        ],
    )


def _unique_dst_ips(row: Any) -> float:
    return _max_numeric(
        row,
        ["src_ip_5min_unique_dst_ips", "src_ip_15min_unique_dst_ips", "src_ip_60min_unique_dst_ips"],
    )


def _unique_dst_ports(row: Any) -> float:
    return _max_numeric(
        row,
        ["src_ip_5min_unique_dst_ports", "src_ip_15min_unique_dst_ports", "src_ip_60min_unique_dst_ports"],
    )


def _deny_count(row: Any) -> float:
    return _max_numeric(
        row,
        [
            "src_ip_5min_deny_count",
            "src_ip_5min_deny_drop_reset_count",
            "src_ip_15min_deny_drop_reset_count",
            "src_ip_60min_deny_drop_reset_count",
        ],
    )


def _unknown_count(row: Any) -> float:
    return _max_numeric(
        row,
        ["src_ip_5min_unknown_app_count", "src_ip_15min_unknown_app_count", "src_ip_60min_unknown_app_count"],
    )


def _high_risk_count(row: Any) -> float:
    return _max_numeric(
        row,
        ["src_ip_5min_high_risk_app_count", "src_ip_15min_high_risk_app_count", "src_ip_60min_high_risk_app_count"],
    )


def _traffic_family(log: Any, *, has_rule: bool, scan_context: bool, low_signal: bool) -> str:
    app = _lower(getattr(log, "app", None))
    action = _lower(getattr(log, "action", None))
    port = getattr(log, "dst_port", None)
    if action != "allow":
        return "non_allow"
    if app == "incomplete":
        return "incomplete_probe" if scan_context or has_rule else "incomplete_low_context"
    if app.startswith("unknown"):
        return "unknown_scan_context" if scan_context or has_rule else "unknown_low_context"
    if app in WEB_LIKE_APPS or port in {80, 443}:
        if has_rule:
            return "web_rule_backed"
        if scan_context:
            return "web_scan_context"
        return "web_low_signal" if low_signal else "web_general"
    if app in UTILITY_APPS or port in {53, 123, 3478}:
        if has_rule or scan_context:
            return "utility_evidence_context"
        return "utility_low_signal"
    return "other_allow"


def _enrichment_values(row: Any, log: Any, *, rule_codes: set[str]) -> dict[str, Any]:
    app = _lower(getattr(log, "app", None))
    action = _lower(getattr(log, "action", None))
    port = getattr(log, "dst_port", None)
    unique_ips = _unique_dst_ips(row)
    unique_ports = _unique_dst_ports(row)
    events = _event_count(row)
    deny = _deny_count(row)
    unknown = _unknown_count(row)
    high_risk = _high_risk_count(row)
    repeated = _safe_float(row.get("repeated_connection_attempts"))
    rule_score = _safe_float(row.get("v331_rule_score"))
    anomaly_score = _safe_float(getattr(log, "anomaly_score", None), 0.0)
    anomaly_signal = bool(getattr(log, "is_anomaly", False)) or anomaly_score <= -0.20
    has_rule = bool(rule_codes)
    web_like = action == "allow" and (app in WEB_LIKE_APPS or port in {80, 443})
    utility_like = action == "allow" and (app in UTILITY_APPS or port in {53, 123, 3478})
    scan_context = (
        unique_ips >= 4
        or unique_ports >= 3
        or (events >= 10 and (unique_ips >= 3 or unique_ports >= 2))
        or deny > 0
        or unknown >= 3
        or high_risk >= 2
    )
    repeated_service = repeated >= 5 or events >= 8
    low_signal = not has_rule and not anomaly_signal and not scan_context and high_risk < 2 and deny == 0
    evidence_strength = 0.0
    evidence_strength += min(rule_score / 10, 4.0)
    evidence_strength += 1.5 if anomaly_signal else 0.0
    evidence_strength += min(unique_ips / 4, 3.0)
    evidence_strength += min(unique_ports / 3, 3.0)
    evidence_strength += min(deny, 3.0)
    evidence_strength += min(unknown / 2, 3.0)
    evidence_strength += min(high_risk, 3.0)
    benign_web_score = 0.0
    benign_web_score += 2.0 if web_like and low_signal else 0.0
    benign_web_score += 1.0 if utility_like and low_signal else 0.0
    benign_web_score += 1.0 if action == "allow" and port in {80, 443} and events <= 3 else 0.0
    benign_web_score -= 1.5 if scan_context else 0.0
    benign_web_score -= 2.0 if has_rule else 0.0
    return {
        "v337_web_like_allow_flag": int(web_like),
        "v337_utility_like_allow_flag": int(utility_like),
        "v337_low_signal_allow_flag": int(action == "allow" and low_signal),
        "v337_web_low_signal_flag": int(web_like and low_signal),
        "v337_web_scan_context_flag": int(web_like and scan_context),
        "v337_utility_low_signal_flag": int(utility_like and low_signal),
        "v337_incomplete_scan_context_flag": int(app == "incomplete" and scan_context),
        "v337_unknown_scan_context_flag": int(app.startswith("unknown") and scan_context),
        "v337_rule_backed_allow_flag": int(action == "allow" and has_rule),
        "v337_anomaly_signal_flag": int(anomaly_signal),
        "v337_repeated_service_flag": int(repeated_service),
        "v337_source_diversity_pressure": round(unique_ips + unique_ports, 4),
        "v337_behavior_evidence_strength": round(evidence_strength, 4),
        "v337_benign_web_likelihood_score": round(benign_web_score, 4),
        "v337_traffic_family": _traffic_family(log, has_rule=has_rule, scan_context=scan_context, low_signal=low_signal),
    }


def enrich_v337_features(prepared: dict[str, Any]) -> tuple[Any, dict[str, Any]]:
    frame, meta = _augment_frame(prepared)
    enriched_rows = [
        _enrichment_values(frame.iloc[position], log, rule_codes=meta["rule_code_rows"][position])
        for position, log in enumerate(prepared["logs"])
    ]
    experimental_features = [
        "v337_web_like_allow_flag",
        "v337_utility_like_allow_flag",
        "v337_low_signal_allow_flag",
        "v337_web_low_signal_flag",
        "v337_web_scan_context_flag",
        "v337_utility_low_signal_flag",
        "v337_incomplete_scan_context_flag",
        "v337_unknown_scan_context_flag",
        "v337_rule_backed_allow_flag",
        "v337_anomaly_signal_flag",
        "v337_repeated_service_flag",
        "v337_source_diversity_pressure",
        "v337_behavior_evidence_strength",
        "v337_benign_web_likelihood_score",
    ]
    for feature in experimental_features:
        frame[feature] = [row[feature] for row in enriched_rows]
    frame["v337_traffic_family"] = [row["v337_traffic_family"] for row in enriched_rows]
    return frame, {
        **meta,
        "numeric_features": [*meta["numeric_features"], *experimental_features],
        "categorical_features": [*meta["categorical_features"], "v337_traffic_family"],
        "experimental_features": [*meta["experimental_features"], *experimental_features, "v337_traffic_family"],
    }


def _strategy_specs() -> list[dict[str, Any]]:
    return [
        {
            "name": "flat_v337_enriched_strong_benign",
            "model_type": "extra_trees",
            "target_mode": "flat",
            "class_weight": None,
            "weight_strategy": "strong_benign",
            "use_augmented_features": True,
            "calibrated": False,
            "postprocess_low_signal_guard": False,
        },
        {
            "name": "flat_v337_enriched_lower_threat",
            "model_type": "extra_trees",
            "target_mode": "flat",
            "class_weight": None,
            "weight_strategy": "lower_threat",
            "use_augmented_features": True,
            "calibrated": False,
            "postprocess_low_signal_guard": False,
        },
        {
            "name": "three_class_v337_soc_queue",
            "model_type": "extra_trees",
            "target_mode": "three_class",
            "class_weight": None,
            "weight_strategy": "strong_benign",
            "use_augmented_features": True,
            "calibrated": False,
            "postprocess_low_signal_guard": False,
        },
        {
            "name": "binary_v337_threat_positive",
            "model_type": "extra_trees",
            "target_mode": "binary",
            "class_weight": None,
            "weight_strategy": "strong_benign",
            "use_augmented_features": True,
            "calibrated": False,
            "postprocess_low_signal_guard": False,
        },
        {
            "name": "calibrated_v337_logistic_flat",
            "model_type": "logistic_regression",
            "target_mode": "flat",
            "class_weight": "balanced",
            "weight_strategy": "none",
            "use_augmented_features": True,
            "calibrated": True,
            "postprocess_low_signal_guard": False,
        },
    ]


def _fit_strategies(prepared: dict[str, Any], augmented: dict[str, Any]) -> list[dict[str, Any]]:
    strategies: list[dict[str, Any]] = []
    for spec in _strategy_specs():
        try:
            strategy = _fit_strategy(prepared, augmented, **spec)
        except Exception as exc:  # pragma: no cover - diagnostic defensive path
            strategy = {"name": spec["name"], "status": "failed", "message": str(exc), "target_mode": spec["target_mode"]}
        if strategy.get("status") == "evaluated":
            profile = _strategy_best_profile(strategy)
            strategy["recommended_profile"] = profile
            strategy["recommended_metrics"] = _profile_summary(strategy["profiles"][profile]) if profile else {}
        strategies.append(strategy)
    try:
        hierarchical = _fit_hierarchical_strategy(prepared, augmented)
        hierarchical["name"] = "hierarchical_v337_two_stage"
        if hierarchical.get("status") == "evaluated":
            profile = _strategy_best_profile(hierarchical)
            hierarchical["recommended_profile"] = profile
            hierarchical["recommended_metrics"] = _profile_summary(hierarchical["profiles"][profile]) if profile else {}
        strategies.append(hierarchical)
    except Exception as exc:  # pragma: no cover - diagnostic defensive path
        strategies.append({"name": "hierarchical_v337_two_stage", "status": "failed", "message": str(exc)})
    return strategies


def _threat_labels_for_mode(target_mode: str) -> set[str]:
    if target_mode == "binary":
        return {"threat_positive"}
    return set(THREAT_LABELS)


def _false_positive_patterns(
    prepared: dict[str, Any],
    augmented: dict[str, Any],
    *,
    predictions: list[str],
    y_true: list[str],
    threat_labels: set[str],
) -> dict[str, Any]:
    frame = augmented["frame"]
    rows: list[dict[str, Any]] = []
    for position, (actual, predicted) in enumerate(zip(y_true, predictions, strict=False)):
        if actual in threat_labels or predicted not in threat_labels:
            continue
        index = prepared["test_idx"][position]
        log = prepared["test_logs"][position]
        row = frame.iloc[index]
        rows.append(
            {
                "pattern": f"app={log.app or '-'}|action={log.action or '-'}|port={log.dst_port or '-'}",
                "source_name": _source_name(log),
                "family": str(row.get("v337_traffic_family") or "unknown"),
                "web_low_signal": bool(row.get("v337_web_low_signal_flag")),
                "web_scan_context": bool(row.get("v337_web_scan_context_flag")),
                "evidence_strength": _safe_float(row.get("v337_behavior_evidence_strength")),
            }
        )
    return {
        "false_positive_count": len(rows),
        "top_patterns": Counter(row["pattern"] for row in rows).most_common(12),
        "top_sources": Counter(row["source_name"] for row in rows).most_common(10),
        "top_traffic_families": Counter(row["family"] for row in rows).most_common(10),
        "web_low_signal_false_positives": sum(1 for row in rows if row["web_low_signal"]),
        "web_scan_context_false_positives": sum(1 for row in rows if row["web_scan_context"]),
    }


def _suspicious_miss_patterns(
    prepared: dict[str, Any],
    augmented: dict[str, Any],
    *,
    predictions: list[str],
    y_true: list[str],
) -> dict[str, Any]:
    frame = augmented["frame"]
    rows: list[dict[str, Any]] = []
    for position, (actual, predicted) in enumerate(zip(y_true, predictions, strict=False)):
        if actual != "suspicious" or predicted == "suspicious":
            continue
        index = prepared["test_idx"][position]
        log = prepared["test_logs"][position]
        row = frame.iloc[index]
        rows.append(
            {
                "predicted": predicted,
                "pattern": f"app={log.app or '-'}|action={log.action or '-'}|port={log.dst_port or '-'}",
                "family": str(row.get("v337_traffic_family") or "unknown"),
                "evidence_strength": _safe_float(row.get("v337_behavior_evidence_strength")),
            }
        )
    return {
        "suspicious_miss_count": len(rows),
        "top_patterns": Counter(row["pattern"] for row in rows).most_common(12),
        "predicted_as": dict(Counter(str(row["predicted"]) for row in rows)),
        "top_traffic_families": Counter(row["family"] for row in rows).most_common(10),
    }


def _split_strategy_rows(prepared: dict[str, Any], augmented: dict[str, Any], strategies: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for strategy in strategies:
        profile = strategy.get("recommended_profile")
        metrics = (strategy.get("profiles") or {}).get(profile) if profile else None
        summary = _profile_summary(metrics) if metrics else {}
        predictions = (strategy.get("_predictions") or {}).get(profile) or []
        target_mode = str(strategy.get("target_mode") or "flat")
        y_true = strategy.get("_y_test") or prepared["y_test"]
        threat_labels = _threat_labels_for_mode(target_mode)
        rows.append(
            {
                "name": strategy.get("name"),
                "status": strategy.get("status"),
                "target_mode": target_mode,
                "model_type": strategy.get("model_type"),
                "recommended_profile": profile,
                "summary": summary,
                "calibration": strategy.get("calibration") or {},
                "limited_exact_class_output": target_mode == "binary",
                "false_positive_patterns": _false_positive_patterns(
                    prepared,
                    augmented,
                    predictions=predictions,
                    y_true=y_true,
                    threat_labels=threat_labels,
                )
                if predictions
                else {},
                "suspicious_miss_patterns": _suspicious_miss_patterns(
                    prepared,
                    augmented,
                    predictions=predictions,
                    y_true=y_true,
                )
                if predictions and target_mode != "binary"
                else {},
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
        calibrations: list[dict[str, Any]] = []
        fp_patterns = Counter()
        suspicious_misses = Counter()
        traffic_families = Counter()
        limited_exact = False
        modes = set()
        for split in split_results:
            for row in split.get("strategies", []):
                if row.get("name") != name or row.get("status") != "evaluated":
                    continue
                modes.add(str(row.get("target_mode") or "unknown"))
                limited_exact = limited_exact or bool(row.get("limited_exact_class_output"))
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
                for pattern, count in (row.get("false_positive_patterns") or {}).get("top_patterns") or []:
                    fp_patterns[str(pattern)] += int(count)
                for pattern, count in (row.get("suspicious_miss_patterns") or {}).get("top_patterns") or []:
                    suspicious_misses[str(pattern)] += int(count)
                for family, count in (row.get("false_positive_patterns") or {}).get("top_traffic_families") or []:
                    traffic_families[str(family)] += int(count)
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
            "limited_exact_class_output": limited_exact,
            "stability": stability,
            "best_calibration": best_calibration,
            "top_false_positive_patterns": fp_patterns.most_common(12),
            "top_false_positive_traffic_families": traffic_families.most_common(10),
            "top_suspicious_miss_patterns": suspicious_misses.most_common(12),
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
            0 if item.get("limited_exact_class_output") else 1,
            1 if max_fpr <= 0.15 else 0,
            min_f1 - 0.4 * max_fpr,
            min_suspicious,
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
            "target": "all evaluated splits pass gates",
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
        {
            "name": "candidate keeps exact suspicious/malicious outputs",
            "passed": not bool(item.get("limited_exact_class_output")),
            "value": bool(item.get("limited_exact_class_output")),
            "target": "false",
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


def _feature_family_summary(prepared: dict[str, Any], augmented: dict[str, Any]) -> dict[str, Any]:
    frame = augmented["frame"]
    labels = prepared["y"]
    family_counts: dict[str, Counter[str]] = {}
    for index, label in enumerate(labels):
        family = str(frame.iloc[index].get("v337_traffic_family") or "unknown")
        family_counts.setdefault(family, Counter())[label] += 1
    rows = []
    for family, counts in family_counts.items():
        benign = sum(counts[label] for label in BENIGN_LIKE_LABELS)
        threat = sum(counts[label] for label in THREAT_LABELS)
        rows.append(
            {
                "traffic_family": family,
                "total": sum(counts.values()),
                "benign_like": benign,
                "threat": threat,
                "label_counts": dict(counts),
                "threat_ratio": round(threat / sum(counts.values()), 4) if sum(counts.values()) else 0,
            }
        )
    rows.sort(key=lambda row: row["total"], reverse=True)
    return {
        "traffic_families": rows,
        "experimental_features": augmented["experimental_features"],
    }


def _render_report(result: dict[str, Any]) -> str:
    rows = []
    for name, item in result.get("strategy_comparison", {}).items():
        ranges = item.get("stability", {}).get("metric_ranges", {})
        rows.append(
            "| {name} | {modes} | {passed} | {f1_min}-{f1_max} | {fpr_min}-{fpr_max} | {susp_min}-{susp_max} | {mal_min}-{mal_max} | {cal} |".format(
                name=name,
                modes=", ".join(item.get("target_modes") or []),
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
    return f"""# v3.37 Evidence Feature Enrichment

Generated: {result.get("generated_at")}

This phase is diagnostic only. No model was activated, no active artifact was written, and response automation stayed disabled.

## Best Diagnostic Candidate

- Candidate: {result.get("best_strategy")}
- Readiness: {result.get("readiness", {}).get("decision")}
- Checks passed: {result.get("readiness", {}).get("passed")} / {result.get("readiness", {}).get("total")}
- Blockers: {result.get("readiness", {}).get("blockers")}

## Strategy Comparison

| Strategy | Output Mode | Passing Splits | Threat F1 Range | Benign FPR Range | Suspicious Recall Range | Malicious Recall Range | Calibration |
| --- | --- | ---: | --- | --- | --- | --- | --- |
{chr(10).join(rows)}

## Feature Family Summary

```json
{json.dumps((result.get("feature_family_summary") or {}).get("traffic_families", [])[:12], indent=2, default=str)}
```

## Safety

```json
{json.dumps(result.get("safety"), indent=2, default=str)}
```
"""


def run_v337_evidence_feature_enrichment(
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
    feature_family_summary: dict[str, Any] = {}
    for split_mode in V335_SPLITS:
        prepared = _prepared_for_split(base, split_mode=split_mode, test_size=test_size)
        frame, meta = enrich_v337_features(prepared)
        augmented = {"frame": frame, **meta}
        if not feature_family_summary:
            feature_family_summary = _feature_family_summary(prepared, augmented)
        strategies = _fit_strategies(prepared, augmented)
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
        "blockers": ["no evaluated v3.37 strategy"],
        "checks": [],
    }
    after_runs = int(db.scalar(select(func.count(MLModelRun.id))) or 0)
    after_responses = int(db.scalar(select(func.count(ResponseAction.id))) or 0)

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    stamp = _stamp()
    report_path = output_path / f"v3_37_evidence_feature_enrichment_{stamp}.md"
    latest_path = output_path / V337_LATEST
    result: dict[str, Any] = {
        "ok": True,
        "status": "completed",
        "phase": "v3.37",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "runtime_seconds": round(time.perf_counter() - started, 4),
        "feature_generation_seconds": base.get("feature_generation_seconds"),
        "splits": V335_SPLITS,
        "strategy_comparison": comparison,
        "best_strategy": best_strategy,
        "readiness": readiness,
        "feature_family_summary": feature_family_summary,
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
        "report_path": str(report_path),
        "latest_summary_path": str(latest_path),
    }
    report_path.write_text(_render_report(result), encoding="utf-8")
    latest_path.write_text(
        json.dumps({key: value for key, value in result.items() if key != "split_results"}, indent=2, default=str),
        encoding="utf-8",
    )
    return result
