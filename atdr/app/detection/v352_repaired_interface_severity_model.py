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
from atdr.app.detection.v331_noise_reduction import _calibration_report
from atdr.app.detection.v332_guard_validation import _load_base_dataset, _prepared_for_split, _safe_float, _stability_summary
from atdr.app.detection.v335_split_stability_repair import V335_SPLITS
from atdr.app.detection.v337_evidence_feature_enrichment import enrich_v337_features
from atdr.app.detection.v342_label_policy_reframing import FPR_BUDGET, SOC_TARGETS, SOC_THREAT_TARGETS, behavior_aware_soc_target
from atdr.app.detection.v344_two_stage_soc_queue import _fit_classifier, _prob_rows, _queue_metrics, _split_train_calibration_indices
from atdr.app.detection.v348_repaired_queue_target_model import _predict_queue, _select_threshold, queue_targets_for_mode
from atdr.app.detection.v349_repaired_queue_severity_model import (
    SEVERITY_DECISION_MODES,
    SEVERITY_MODEL_TYPES,
    _error_patterns,
    _final_predictions,
    _metrics_for_predictions,
    _range_value,
    _select_severity_thresholds,
    _summary,
    _with_custom_metric_ranges,
)
from atdr.app.detection.v351_queue_severity_interface import repair_interface_target


V352_LATEST = "v3_52_repaired_interface_severity_model_latest.json"
INTERFACE_VARIANTS = ["baseline_current_interface", "map_non_threat_to_unusual"]


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _base_soc_targets(prepared: dict[str, Any], frame: Any) -> list[str]:
    return [behavior_aware_soc_target(label, frame.iloc[index]) for index, label in enumerate(prepared["y"])]


def _interface_row(frame: Any, index: int) -> dict[str, Any]:
    row = frame.iloc[index]
    evidence_bucket = str(row.get("v341_evidence_bucket") or row.get("v337_evidence_bucket") or "unknown")
    return {
        "evidence_strength": _safe_float(row.get("v337_behavior_evidence_strength")),
        "rule_backed": bool(row.get("v337_rule_backed_allow_flag")),
        "anomaly_signal": bool(row.get("v337_anomaly_signal_flag")),
        "scan_context": evidence_bucket in {"web_scan_context", "incomplete_scan_context", "unknown_scan_context"},
        "evidence_bucket": evidence_bucket,
    }


def interface_severity_targets(
    prepared: dict[str, Any],
    frame: Any,
    *,
    variant: str,
) -> tuple[list[str | None], dict[str, Any]]:
    base_targets = _base_soc_targets(prepared, frame)
    queue_values, queue_meta = queue_targets_for_mode(prepared, frame, target_mode="repaired_queue_target")
    targets: list[str | None] = []
    changed = 0
    removed = 0
    non_threat_mismatch = 0
    for index, base_target in enumerate(base_targets):
        if queue_values[index] != "needs_review":
            targets.append(base_target)
            continue
        repaired = repair_interface_target(base_target, _interface_row(frame, index), variant=variant)
        if repaired is None:
            removed += 1
        elif repaired != base_target:
            changed += 1
        if repaired == "non_threat":
            non_threat_mismatch += 1
        targets.append(repaired)
    return targets, {
        "interface_variant": variant,
        "queue_target_mode": queue_meta.get("target_mode"),
        "queue_repair": queue_meta,
        "changed_review_rows": changed,
        "removed_review_rows": removed,
        "retained_review_rows": sum(1 for value, queue in zip(targets, queue_values, strict=False) if queue == "needs_review" and value),
        "non_threat_mismatch_rows": non_threat_mismatch,
        "target_distribution": dict(Counter(str(value) for value in targets if value is not None)),
    }


def _true_targets_for_test(
    indices: list[int],
    *,
    queue_values: list[str],
    severity_targets: list[str | None],
) -> list[str]:
    y_true = []
    for index in indices:
        if queue_values[index] != "needs_review":
            y_true.append("non_threat")
            continue
        y_true.append(severity_targets[index] or "non_threat")
    return y_true


def _fit_strategy(
    prepared: dict[str, Any],
    augmented: dict[str, Any],
    *,
    interface_variant: str,
    severity_model_type: str,
    decision_mode: str,
) -> dict[str, Any]:
    frame = augmented["frame"]
    severity_targets, interface_meta = interface_severity_targets(prepared, frame, variant=interface_variant)
    queue_values, _queue_meta = queue_targets_for_mode(prepared, frame, target_mode="repaired_queue_target")
    split = _split_train_calibration_indices(prepared, queue_values)
    fit_idx = split["fit_idx"]
    calibration_idx = split["calibration_idx"]
    severity_fit_idx = [
        index
        for index in fit_idx
        if queue_values[index] == "needs_review" and severity_targets[index] is not None
    ]
    name = f"{interface_variant}_extra_trees_severity_{severity_model_type}_{decision_mode}"
    started = time.perf_counter()
    queue_model, queue_classes, queue_meta = _fit_classifier(
        prepared,
        augmented,
        indices=fit_idx,
        targets=queue_values,
        model_type="extra_trees",
        weight_strategy="strong_benign",
    )
    severity_model, severity_classes, severity_meta = _fit_classifier(
        prepared,
        augmented,
        indices=severity_fit_idx,
        targets=[target or "non_threat" for target in severity_targets],
        model_type=severity_model_type,
        weight_strategy="strong_benign",
        class_weight="balanced" if severity_model_type == "logistic_regression" else None,
    )
    training_seconds = round(time.perf_counter() - started, 4)
    if queue_model is None:
        return {"name": name, "status": "skipped", "message": "Queue model unavailable."}
    if severity_model is None:
        return {"name": name, "status": "skipped", "message": "Severity model unavailable."}

    queue_calibration_rows = _prob_rows(queue_model, queue_classes, frame, calibration_idx)
    queue_thresholds = _select_threshold([queue_values[index] for index in calibration_idx], queue_calibration_rows)
    queue_calibration_predictions = _predict_queue(
        queue_calibration_rows,
        threshold=queue_thresholds["selected_threshold"],
    )
    severity_calibration_rows = _prob_rows(severity_model, severity_classes, frame, calibration_idx)
    y_calibration = _true_targets_for_test(
        calibration_idx,
        queue_values=queue_values,
        severity_targets=severity_targets,
    )
    threshold_selection = _select_severity_thresholds(
        prepared,
        frame,
        calibration_idx=calibration_idx,
        y_calibration=y_calibration,
        queue_calibration=[queue_values[index] for index in calibration_idx],
        queue_predictions=queue_calibration_predictions,
        severity_rows=severity_calibration_rows,
        mode=decision_mode,
    )

    test_idx = list(prepared["test_idx"])
    y_test = _true_targets_for_test(test_idx, queue_values=queue_values, severity_targets=severity_targets)
    queue_test = [queue_values[index] for index in test_idx]
    queue_test_rows = _prob_rows(queue_model, queue_classes, frame, test_idx)
    queue_predictions = _predict_queue(queue_test_rows, threshold=queue_thresholds["selected_threshold"])
    severity_test_rows = _prob_rows(severity_model, severity_classes, frame, test_idx)
    predictions = _final_predictions(
        frame,
        test_idx,
        queue_predictions=queue_predictions,
        severity_rows=severity_test_rows,
        thresholds=threshold_selection["selected_thresholds"],
        mode=decision_mode,
    )
    queue_summary = _queue_metrics(queue_test, queue_predictions)
    metrics = _metrics_for_predictions(prepared, y_test, predictions)
    calibration = _calibration_report(
        y_test,
        severity_model.predict_proba(frame.iloc[test_idx]),
        severity_classes,
        threat_labels=set(SOC_THREAT_TARGETS),
    )
    return {
        "name": name,
        "status": "evaluated",
        "target_mode": "v3_51_interface_severity",
        "interface_variant": interface_variant,
        "queue_model_type": "extra_trees",
        "severity_model_type": severity_model_type,
        "decision_mode": decision_mode,
        "queue_model": queue_meta,
        "severity_model": severity_meta,
        "training_seconds": training_seconds,
        "interface_repair": interface_meta,
        "threshold_selection": {
            "fit_rows": len(fit_idx),
            "calibration_rows": len(calibration_idx),
            "severity_fit_rows": len(severity_fit_idx),
            "queue_threshold": queue_thresholds["selected_threshold"],
            "queue_threshold_selected_on": queue_thresholds["selected_on"],
            **threshold_selection,
        },
        "summary": _summary(metrics, queue_summary),
        "metrics": metrics,
        "queue_metrics": queue_summary,
        "calibration": calibration,
        "_predictions": predictions,
        "_y_test": y_test,
        "_queue_predictions": queue_predictions,
        "_queue_test": queue_test,
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
                "interface_variant": strategy.get("interface_variant"),
                "queue_model_type": strategy.get("queue_model_type"),
                "severity_model_type": strategy.get("severity_model_type"),
                "decision_mode": strategy.get("decision_mode"),
                "summary": strategy["summary"],
                "queue_metrics": strategy.get("queue_metrics") or {},
                "calibration": strategy.get("calibration") or {},
                "threshold_selection": strategy.get("threshold_selection") or {},
                "interface_repair": strategy.get("interface_repair") or {},
                "error_patterns": _error_patterns(
                    prepared,
                    augmented["frame"],
                    predictions=strategy.get("_predictions") or [],
                    y_true=strategy.get("_y_test") or [],
                ),
            }
        )
    return rows


def _aggregate_by_strategy(split_results: list[dict[str, Any]]) -> dict[str, Any]:
    comparison: dict[str, Any] = {}
    names = sorted(
        {
            row["name"]
            for split in split_results
            for row in split.get("strategies", [])
            if row.get("status") == "evaluated"
        }
    )
    for name in names:
        strategy_splits = []
        calibrations = []
        threshold_rows = []
        interface_rows = []
        fp_patterns = Counter()
        severity_confusions = Counter()
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
                interface_rows.append(row.get("interface_repair") or {})
                for pattern, count in (row.get("error_patterns") or {}).get("top_false_positive_patterns") or []:
                    fp_patterns[str(pattern)] += int(count)
                for confusion, count in (row.get("error_patterns") or {}).get("top_severity_confusions") or []:
                    severity_confusions[str(confusion)] += int(count)
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
            "interface_repair": {
                "variants": sorted({str(row.get("interface_variant")) for row in interface_rows if row.get("interface_variant")}),
                "max_non_threat_mismatch_rows": max(
                    (int(row.get("non_threat_mismatch_rows") or 0) for row in interface_rows),
                    default=0,
                ),
                "max_removed_review_rows": max((int(row.get("removed_review_rows") or 0) for row in interface_rows), default=0),
            },
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
            },
            "top_false_positive_patterns": fp_patterns.most_common(12),
            "top_severity_confusions": severity_confusions.most_common(12),
        }
    return comparison


def _select_best(comparison: dict[str, Any]) -> str | None:
    if not comparison:
        return None

    def score(name: str) -> tuple[Any, ...]:
        item = comparison[name]
        max_fpr = _range_value(item, "benign_like_false_positive_rate", "max", 1.0)
        min_threat_f1 = _range_value(item, "threat_positive_f1", "min")
        min_suspicious = _range_value(item, "suspicious_recall", "min")
        min_malicious = _range_value(item, "malicious_recall", "min")
        min_queue_f1 = _range_value(item, "queue_f1", "min")
        interface = item.get("interface_repair") or {}
        calibration = item.get("best_calibration") or {}
        return (
            int((item.get("stability") or {}).get("passing_splits") or 0),
            1 if int(interface.get("max_non_threat_mismatch_rows") or 0) == 0 else 0,
            1 if max_fpr <= FPR_BUDGET else 0,
            1 if min_suspicious >= 0.8 else 0,
            1 if min_malicious >= 0.5 else 0,
            min_threat_f1 + 0.20 * min_suspicious + 0.25 * min_malicious + 0.05 * min_queue_f1 - 0.45 * max_fpr,
            1 if calibration.get("passed") else 0,
            -max_fpr,
        )

    return max(comparison, key=score)


def _readiness(item: dict[str, Any]) -> dict[str, Any]:
    stability = item.get("stability") or {}
    calibration = item.get("best_calibration") or {}
    threshold_selection = item.get("threshold_selection") or {}
    interface = item.get("interface_repair") or {}
    checks = [
        {
            "name": "threshold selection avoids test leakage",
            "passed": not bool(threshold_selection.get("used_test_for_threshold_selection")),
            "value": threshold_selection.get("selected_on"),
            "target": "train-internal only",
        },
        {
            "name": "interface removes queued non-threat mismatch",
            "passed": int(interface.get("max_non_threat_mismatch_rows") or 0) == 0,
            "value": interface.get("max_non_threat_mismatch_rows"),
            "target": "0 across splits",
        },
        {
            "name": "independent severity stability acceptable",
            "passed": bool(stability.get("passed")),
            "value": f"{stability.get('passing_splits')}/{stability.get('evaluated_splits')}",
            "target": "all evaluated splits pass gates",
        },
        {
            "name": "queue admission remains stable",
            "passed": _range_value(item, "queue_f1", "min") >= 0.95,
            "value": _range_value(item, "queue_f1", "min"),
            "target": "queue F1 >= 0.95 across splits",
        },
        {
            "name": "threat-positive F1 stable",
            "passed": _range_value(item, "threat_positive_f1", "min") >= 0.85,
            "value": _range_value(item, "threat_positive_f1", "min"),
            "target": ">= 0.85 across splits",
        },
        {
            "name": "benign-like false-positive rate controlled",
            "passed": _range_value(item, "benign_like_false_positive_rate", "max", 1.0) <= FPR_BUDGET,
            "value": _range_value(item, "benign_like_false_positive_rate", "max", 1.0),
            "target": f"<= {FPR_BUDGET} across splits",
        },
        {
            "name": "suspicious recall stable",
            "passed": _range_value(item, "suspicious_recall", "min") >= 0.8,
            "value": _range_value(item, "suspicious_recall", "min"),
            "target": ">= 0.8 across splits",
        },
        {
            "name": "malicious recall stable",
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
        interface = item.get("interface_repair") or {}
        rows.append(
            "| {name} | {variants} | {mismatch} | {passed} | {tf1_min} | {fpr_max} | {srec_min} | {mrec_min} | {cal} |".format(
                name=name,
                variants=", ".join(interface.get("variants") or []),
                mismatch=interface.get("max_non_threat_mismatch_rows"),
                passed=f"{item.get('stability', {}).get('passing_splits')}/{item.get('stability', {}).get('evaluated_splits')}",
                tf1_min=(ranges.get("threat_positive_f1") or {}).get("min"),
                fpr_max=(ranges.get("benign_like_false_positive_rate") or {}).get("max"),
                srec_min=(ranges.get("suspicious_recall") or {}).get("min"),
                mrec_min=(ranges.get("malicious_recall") or {}).get("min"),
                cal=item.get("best_calibration", {}).get("status"),
            )
        )
    return f"""# v3.52 Repaired Interface Severity Model Revalidation

Generated: {result.get("generated_at")}

This report is diagnostic only. It tests downstream severity modeling using the v3.51 repaired queue/severity interface and compares it with the baseline interface. No labels were written, no model was activated, no model artifact was written, and response automation stayed disabled.

## Best Diagnostic Candidate

- Candidate: {result.get("best_strategy")}
- Readiness: {result.get("readiness", {}).get("decision")}
- Checks passed: {result.get("readiness", {}).get("passed")} / {result.get("readiness", {}).get("total")}
- Blockers: {result.get("readiness", {}).get("blockers")}

## Strategy Comparison

| Strategy | Interface | Max Mismatch | Passing Splits | Threat F1 Min | FPR Max | Suspicious Recall Min | Malicious Recall Min | Calibration |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
{chr(10).join(rows)}

## Safety

```json
{json.dumps(result.get("safety"), indent=2, default=str)}
```
"""


def run_v352_repaired_interface_severity_model(
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
            _fit_strategy(
                prepared,
                augmented,
                interface_variant=variant,
                severity_model_type=model_type,
                decision_mode=decision_mode,
            )
            for variant in INTERFACE_VARIANTS
            for model_type in SEVERITY_MODEL_TYPES
            for decision_mode in SEVERITY_DECISION_MODES
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
    readiness = _readiness(comparison[best_strategy]) if best_strategy else {
        "decision": "candidate_only",
        "passed": 0,
        "total": 0,
        "production_promoted": False,
        "model_activated": False,
        "model_artifact_written": False,
        "response_automation_allowed": False,
        "blockers": ["no evaluated v3.52 strategy"],
        "checks": [],
    }
    after_labels = int(db.scalar(select(func.count(MLLabel.id))) or 0)
    after_runs = int(db.scalar(select(func.count(MLModelRun.id))) or 0)
    after_responses = int(db.scalar(select(func.count(ResponseAction.id))) or 0)

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    stamp = _stamp()
    report_path = output_path / f"v3_52_repaired_interface_severity_model_{stamp}.md"
    latest_path = output_path / V352_LATEST
    result = {
        "ok": True,
        "status": "completed",
        "phase": "v3.52",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "runtime_seconds": round(time.perf_counter() - started, 4),
        "feature_generation_seconds": base.get("feature_generation_seconds"),
        "interface_variants": INTERFACE_VARIANTS,
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
