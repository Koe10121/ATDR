import json
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from atdr.app.db.models import MLModelRun, ResponseAction
from atdr.app.detection.v330_detection_ml_quality import OUTPUT_DIR, THREAT_LABELS, _source_name
from atdr.app.detection.v331_noise_reduction import (
    V331_PROFILE_ORDER,
    _augment_frame,
    _calibration_report,
    _fit_hierarchical_strategy,
    _fit_strategy,
    _profile_summary,
    _strategy_best_profile,
)
from atdr.app.detection.v332_guard_validation import (
    _load_base_dataset,
    _prepared_for_split,
    _safe_float,
    _stability_summary,
)
from atdr.app.detection.supervised_detector import training_dataset_diagnostics


V334_SPLITS = ["time", "grouped_stratified", "random_seed_7", "random_seed_17", "random_seed_42"]
V334_LATEST = "v3_34_model_comparison_latest.json"


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _strategy_specs() -> list[dict[str, Any]]:
    return [
        {
            "name": "flat_5class_extra_trees_current_features_current_weights",
            "model_type": "extra_trees",
            "target_mode": "flat",
            "class_weight": "balanced",
            "weight_strategy": "current",
            "use_augmented_features": False,
            "calibrated": False,
            "postprocess_low_signal_guard": False,
            "guard_baseline": False,
        },
        {
            "name": "flat_5class_extra_trees_v331_guard_baseline",
            "model_type": "extra_trees",
            "target_mode": "flat",
            "class_weight": "balanced",
            "weight_strategy": "current",
            "use_augmented_features": False,
            "calibrated": False,
            "postprocess_low_signal_guard": True,
            "guard_baseline": True,
        },
        {
            "name": "flat_5class_extra_trees_augmented_lower_threat",
            "model_type": "extra_trees",
            "target_mode": "flat",
            "class_weight": None,
            "weight_strategy": "lower_threat",
            "use_augmented_features": True,
            "calibrated": False,
            "postprocess_low_signal_guard": False,
            "guard_baseline": False,
        },
        {
            "name": "flat_5class_extra_trees_augmented_strong_benign",
            "model_type": "extra_trees",
            "target_mode": "flat",
            "class_weight": None,
            "weight_strategy": "strong_benign",
            "use_augmented_features": True,
            "calibrated": False,
            "postprocess_low_signal_guard": False,
            "guard_baseline": False,
        },
        {
            "name": "binary_threat_positive_extra_trees",
            "model_type": "extra_trees",
            "target_mode": "binary",
            "class_weight": None,
            "weight_strategy": "strong_benign",
            "use_augmented_features": True,
            "calibrated": False,
            "postprocess_low_signal_guard": False,
            "guard_baseline": False,
        },
        {
            "name": "three_class_soc_queue_extra_trees",
            "model_type": "extra_trees",
            "target_mode": "three_class",
            "class_weight": None,
            "weight_strategy": "strong_benign",
            "use_augmented_features": True,
            "calibrated": False,
            "postprocess_low_signal_guard": False,
            "guard_baseline": False,
        },
        {
            "name": "calibrated_extra_trees_sigmoid_flat",
            "model_type": "extra_trees",
            "target_mode": "flat",
            "class_weight": "balanced",
            "weight_strategy": "current",
            "use_augmented_features": True,
            "calibrated": True,
            "postprocess_low_signal_guard": False,
            "guard_baseline": False,
        },
        {
            "name": "calibrated_logistic_regression_flat",
            "model_type": "logistic_regression",
            "target_mode": "flat",
            "class_weight": "balanced",
            "weight_strategy": "none",
            "use_augmented_features": True,
            "calibrated": True,
            "postprocess_low_signal_guard": False,
            "guard_baseline": False,
        },
    ]


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
    rows: list[dict[str, Any]] = []
    frame = augmented["frame"]
    test_idx = prepared["test_idx"]
    for position, (actual, predicted) in enumerate(zip(y_true, predictions, strict=False)):
        actual_threat = actual in threat_labels
        predicted_threat = predicted in threat_labels
        if actual_threat or not predicted_threat:
            continue
        absolute_index = test_idx[position]
        log = prepared["test_logs"][position]
        label = prepared["test_labels"][position]
        row = frame.iloc[absolute_index]
        rows.append(
            {
                "label": label,
                "log": log,
                "pattern": f"app={log.app or '-'}|action={log.action or '-'}|port={log.dst_port or '-'}",
                "source_name": _source_name(log),
                "quic_no_rule": bool(row.get("v331_quic_443_allow_no_rule_flag")),
                "quic_with_rule": bool(row.get("v331_quic_443_allow_with_rule_flag")),
                "incomplete_allow_80": bool(row.get("v331_incomplete_allow_80_flag")),
                "unknown_udp_scan_context": bool(row.get("v331_unknown_udp_scan_context_flag")),
                "app_risk_only": bool(row.get("v331_app_risk_only_flag")),
                "network_utility_no_rule": bool(row.get("v331_benign_network_utility_no_rule_flag")),
            }
        )
    return {
        "false_positive_count": len(rows),
        "top_patterns": Counter(row["pattern"] for row in rows).most_common(12),
        "top_sources": Counter(row["source_name"] for row in rows).most_common(10),
        "top_apps": Counter(str(row["log"].app or "-") for row in rows).most_common(10),
        "top_ports": Counter(str(row["log"].dst_port or "-") for row in rows).most_common(10),
        "quic_443_no_rule_false_positives": sum(1 for row in rows if row["quic_no_rule"]),
        "quic_443_with_rule_false_positives": sum(1 for row in rows if row["quic_with_rule"]),
        "incomplete_allow_80_false_positives": sum(1 for row in rows if row["incomplete_allow_80"]),
        "unknown_udp_scan_context_false_positives": sum(1 for row in rows if row["unknown_udp_scan_context"]),
        "app_risk_only_false_positives": sum(1 for row in rows if row["app_risk_only"]),
        "network_utility_no_rule_false_positives": sum(1 for row in rows if row["network_utility_no_rule"]),
        "reviewed_vs_weak": dict(Counter("reviewed" if row["label"].reviewed else "weak" for row in rows)),
        "label_sources": dict(Counter(str(row["label"].label_source or "unknown") for row in rows)),
    }


def _attach_recommended_profile(strategy: dict[str, Any]) -> dict[str, Any]:
    if strategy.get("status") != "evaluated" or not strategy.get("profiles"):
        return strategy
    profile = _strategy_best_profile(strategy)
    strategy["recommended_profile"] = profile
    strategy["recommended_metrics"] = _profile_summary(strategy["profiles"][profile]) if profile else {}
    return strategy


def _fit_strategies_for_split(prepared: dict[str, Any], augmented: dict[str, Any]) -> list[dict[str, Any]]:
    strategies: list[dict[str, Any]] = []
    for spec in _strategy_specs():
        try:
            strategy = _fit_strategy(prepared, augmented, **{key: value for key, value in spec.items() if key != "guard_baseline"})
            strategy["guard_baseline"] = bool(spec.get("guard_baseline"))
        except Exception as exc:  # pragma: no cover - defensive diagnostic output
            strategy = {"name": spec["name"], "status": "failed", "message": str(exc), "guard_baseline": bool(spec.get("guard_baseline"))}
        strategies.append(_attach_recommended_profile(strategy))
    try:
        strategies.append(_attach_recommended_profile(_fit_hierarchical_strategy(prepared, augmented)))
    except Exception as exc:  # pragma: no cover - defensive diagnostic output
        strategies.append({"name": "hierarchical_two_stage_augmented", "status": "failed", "message": str(exc)})
    return strategies


def _strip_strategy(strategy: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in strategy.items() if not key.startswith("_")}


def _split_strategy_rows(split: dict[str, Any], strategies: list[dict[str, Any]], augmented: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for strategy in strategies:
        profile = strategy.get("recommended_profile")
        metrics = (strategy.get("profiles") or {}).get(profile) if profile else None
        summary = _profile_summary(metrics) if metrics else {}
        target_mode = str(strategy.get("target_mode") or "")
        predictions = (strategy.get("_predictions") or {}).get(profile) or []
        y_test = strategy.get("_y_test") or split["prepared"]["y_test"]
        threat_labels = _threat_labels_for_mode(target_mode)
        patterns = (
            _false_positive_patterns(
                split["prepared"],
                augmented,
                predictions=predictions,
                y_true=y_test,
                threat_labels=threat_labels,
            )
            if predictions
            else {}
        )
        rows.append(
            {
                "name": strategy.get("name"),
                "status": strategy.get("status"),
                "target_mode": target_mode,
                "model_type": strategy.get("model_type"),
                "recommended_profile": profile,
                "summary": summary,
                "calibration": strategy.get("calibration") or {},
                "guard_baseline": bool(strategy.get("guard_baseline") or strategy.get("postprocess_low_signal_guard")),
                "false_positive_patterns": patterns,
                "limited_exact_class_output": target_mode == "binary",
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
        patterns = Counter()
        modes = set()
        guard_baseline = False
        limited_exact = False
        for split in split_results:
            if split.get("status") != "evaluated":
                continue
            for row in split.get("strategies", []):
                if row.get("name") != name or row.get("status") != "evaluated":
                    continue
                modes.add(str(row.get("target_mode") or "unknown"))
                guard_baseline = guard_baseline or bool(row.get("guard_baseline"))
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
                    patterns[str(pattern)] += int(count)
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
            "guard_baseline": guard_baseline,
            "limited_exact_class_output": limited_exact,
            "stability": stability,
            "best_calibration": best_calibration,
            "top_false_positive_patterns": patterns.most_common(12),
        }
    return comparison


def _range_value(item: dict[str, Any], metric: str, kind: str, default: float = 0.0) -> float:
    ranges = (item.get("stability") or {}).get("metric_ranges") or {}
    return _safe_float((ranges.get(metric) or {}).get(kind), default)


def _select_best(comparison: dict[str, Any], *, allow_guard: bool) -> str | None:
    candidates = [
        name
        for name, item in comparison.items()
        if allow_guard or not item.get("guard_baseline")
    ]
    if not candidates:
        return None

    def score(name: str) -> tuple[Any, ...]:
        item = comparison[name]
        stability = item.get("stability") or {}
        max_fpr = _range_value(item, "benign_like_false_positive_rate", "max", 1.0)
        min_f1 = _range_value(item, "threat_positive_f1", "min")
        min_recall = _range_value(item, "threat_positive_recall", "min")
        min_suspicious = _range_value(item, "suspicious_recall", "min")
        min_malicious = _range_value(item, "malicious_recall", "min")
        calibration = item.get("best_calibration") or {}
        return (
            int(stability.get("passing_splits") or 0),
            0 if item.get("limited_exact_class_output") else 1,
            0 if item.get("guard_baseline") else 1,
            1 if max_fpr <= 0.15 else 0,
            min_f1 - 0.45 * max_fpr,
            min_recall,
            min_suspicious,
            min_malicious,
            1 if calibration.get("passed") else 0,
            -max_fpr,
        )

    return max(candidates, key=score)


def _readiness(best_item: dict[str, Any]) -> dict[str, Any]:
    stability = best_item.get("stability") or {}
    calibration = best_item.get("best_calibration") or {}
    checks = [
        {
            "name": "independent split stability acceptable",
            "passed": bool(stability.get("passed")),
            "value": f"{stability.get('passing_splits')}/{stability.get('evaluated_splits')}",
            "target": "all evaluated splits pass FPR/F1/recall gates",
        },
        {
            "name": "benign-like false-positive rate stable",
            "passed": _range_value(best_item, "benign_like_false_positive_rate", "max", 1.0) <= 0.15,
            "value": _range_value(best_item, "benign_like_false_positive_rate", "max", 1.0),
            "target": "<= 0.15 across splits",
        },
        {
            "name": "threat-positive F1 stable",
            "passed": _range_value(best_item, "threat_positive_f1", "min") >= 0.85,
            "value": _range_value(best_item, "threat_positive_f1", "min"),
            "target": ">= 0.85 across splits",
        },
        {
            "name": "suspicious recall stable",
            "passed": _range_value(best_item, "suspicious_recall", "min") >= 0.8,
            "value": _range_value(best_item, "suspicious_recall", "min"),
            "target": ">= 0.8 across splits",
        },
        {
            "name": "malicious recall acceptable",
            "passed": _range_value(best_item, "malicious_recall", "min") >= 0.5,
            "value": _range_value(best_item, "malicious_recall", "min"),
            "target": ">= 0.5 across splits",
        },
        {
            "name": "confidence calibration acceptable",
            "passed": bool(calibration.get("passed")),
            "value": calibration.get("status"),
            "target": "passed",
        },
        {
            "name": "candidate does not depend on hard low-signal guard",
            "passed": not bool(best_item.get("guard_baseline")),
            "value": bool(best_item.get("guard_baseline")),
            "target": "false",
        },
        {
            "name": "candidate keeps exact suspicious/malicious outputs",
            "passed": not bool(best_item.get("limited_exact_class_output")),
            "value": bool(best_item.get("limited_exact_class_output")),
            "target": "false",
        },
        {"name": "model activation disabled", "passed": True, "value": False, "target": "required"},
        {"name": "response automation disabled", "passed": True, "value": False, "target": "required"},
    ]
    return {
        "decision": "candidate_only",
        "passed": sum(1 for item in checks if item["passed"]),
        "total": len(checks),
        "production_promoted": False,
        "model_activated": False,
        "model_artifact_written": False,
        "response_automation_allowed": False,
        "blockers": [item["name"] for item in checks if not item["passed"]],
        "checks": checks,
    }


def _render_model_report(result: dict[str, Any]) -> str:
    rows = []
    for name, item in result.get("model_comparison", {}).items():
        ranges = item.get("stability", {}).get("metric_ranges", {})
        rows.append(
            "| {name} | {modes} | {guard} | {passed} | {f1_min}-{f1_max} | {fpr_min}-{fpr_max} | {susp_min}-{susp_max} | {mal_min}-{mal_max} | {cal} |".format(
                name=name,
                modes=", ".join(item.get("target_modes") or []),
                guard="yes" if item.get("guard_baseline") else "no",
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
    return f"""# v3.34 SOC Queue Model Redesign

Generated: {result.get("generated_at")}

This report is diagnostic only. No model was activated, no active artifact was written, and response automation stayed disabled.

## Best Diagnostic Strategies

- Recommended diagnostic strategy: {result.get("best_strategy")}
- Best overall score, including old guard baseline: {result.get("best_overall_strategy")}
- Best non-guard strategy: {result.get("best_non_guard_strategy")}
- Readiness: {result.get("readiness", {}).get("decision")}
- Checks passed: {result.get("readiness", {}).get("passed")} / {result.get("readiness", {}).get("total")}
- Blockers: {result.get("readiness", {}).get("blockers")}

## Model Comparison

| Strategy | Output Mode | Guard Baseline | Passing Splits | Threat F1 Range | Benign FPR Range | Suspicious Recall Range | Malicious Recall Range | Calibration |
| --- | --- | --- | ---: | --- | --- | --- | --- | --- |
{chr(10).join(rows)}

## Interpretation

- The old v3.31 low-signal guard is retained only as a diagnostic baseline.
- Non-guard candidates are preferred when their split stability and calibration are competitive.
- Binary threat-positive models are useful for SOC queue triage, but they do not solve exact suspicious/malicious separation by themselves.

## Safety

```json
{json.dumps(result.get("safety"), indent=2, default=str)}
```
"""


def _render_split_report(result: dict[str, Any]) -> str:
    rows = []
    for split in result.get("split_results", []):
        for strategy in split.get("strategies", []):
            summary = strategy.get("summary") or {}
            rows.append(
                "| {split} | {name} | {profile} | {precision} | {recall} | {f1} | {fpr} | {suspicious} | {malicious} | {macro} | {weighted} | {fp} | {fn} | {queue} |".format(
                    split=split.get("split_mode"),
                    name=strategy.get("name"),
                    profile=strategy.get("recommended_profile"),
                    precision=summary.get("threat_positive_precision"),
                    recall=summary.get("threat_positive_recall"),
                    f1=summary.get("threat_positive_f1"),
                    fpr=summary.get("benign_like_false_positive_rate"),
                    suspicious=summary.get("suspicious_recall"),
                    malicious=summary.get("malicious_recall"),
                    macro=summary.get("macro_f1"),
                    weighted=summary.get("weighted_f1"),
                    fp=summary.get("false_positives"),
                    fn=summary.get("false_negatives"),
                    queue=summary.get("review_queue_size_estimate"),
                )
            )
    return f"""# v3.34 Split Stability

Generated: {result.get("generated_at")}

| Split | Strategy | Profile | Threat Precision | Threat Recall | Threat F1 | Benign FPR | Suspicious Recall | Malicious Recall | Macro F1 | Weighted F1 | FP | FN | Queue |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
{chr(10).join(rows)}
"""


def run_v334_soc_queue_model_redesign(
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
    for split_mode in V334_SPLITS:
        prepared = _prepared_for_split(base, split_mode=split_mode, test_size=test_size)
        augmented_frame, augmented_meta = _augment_frame(prepared)
        augmented = {"frame": augmented_frame, **augmented_meta}
        strategies = _fit_strategies_for_split(prepared, augmented)
        split_results.append(
            {
                "split_mode": split_mode,
                "status": "evaluated",
                "training_rows": len(prepared["train_idx"]),
                "test_rows": len(prepared["test_idx"]),
                "split_warnings": prepared.get("split_warnings") or [],
                "strategies": _split_strategy_rows(
                    {"prepared": prepared},
                    strategies,
                    augmented,
                ),
            }
        )

    comparison = _aggregate_by_strategy(split_results)
    best_overall_strategy = _select_best(comparison, allow_guard=True)
    best_non_guard = _select_best(comparison, allow_guard=False)
    recommended_strategy = best_non_guard or best_overall_strategy
    best_item = comparison[recommended_strategy] if recommended_strategy else {}
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
    report_path = output_path / f"v3_34_soc_queue_model_redesign_{stamp}.md"
    stability_path = output_path / f"v3_34_split_stability_{stamp}.md"
    latest_path = output_path / V334_LATEST
    result: dict[str, Any] = {
        "ok": True,
        "status": "completed",
        "phase": "v3.34",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "runtime_seconds": round(time.perf_counter() - started, 4),
        "feature_generation_seconds": base.get("feature_generation_seconds"),
        "splits": V334_SPLITS,
        "model_comparison": comparison,
        "best_strategy": recommended_strategy,
        "best_overall_strategy": best_overall_strategy,
        "best_non_guard_strategy": best_non_guard,
        "readiness": readiness,
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
        "stability_report_path": str(stability_path),
        "latest_summary_path": str(latest_path),
    }
    report_path.write_text(_render_model_report(result), encoding="utf-8")
    stability_path.write_text(_render_split_report(result), encoding="utf-8")
    latest_path.write_text(
        json.dumps(
            {
                key: value
                for key, value in result.items()
                if key not in {"split_results"}
            },
            indent=2,
            default=str,
        ),
        encoding="utf-8",
    )
    return result
