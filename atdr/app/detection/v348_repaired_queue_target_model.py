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
from atdr.app.detection.v330_detection_ml_quality import OUTPUT_DIR, _source_name
from atdr.app.detection.v331_noise_reduction import _calibration_report
from atdr.app.detection.v332_guard_validation import _load_base_dataset, _prepared_for_split, _safe_float
from atdr.app.detection.v335_split_stability_repair import V335_SPLITS
from atdr.app.detection.v337_evidence_feature_enrichment import enrich_v337_features
from atdr.app.detection.v341_label_semantics_audit import _evidence_bucket
from atdr.app.detection.v342_label_policy_reframing import behavior_aware_soc_target
from atdr.app.detection.v344_two_stage_soc_queue import (
    _fit_classifier,
    _prob_rows,
    _queue_metrics,
    _queue_target,
    _split_train_calibration_indices,
)
from atdr.app.detection.v346_queue_target_separability import _distribution
from atdr.app.detection.v347_queue_target_repair_proposal import propose_queue_target


V348_LATEST = "v3_48_repaired_queue_target_model_latest.json"
QUEUE_THRESHOLDS = [0.25, 0.35, 0.45, 0.55, 0.65, 0.75, 0.85, 0.95]
TARGET_MODES = ["original_queue_target", "repaired_queue_target"]
MODEL_TYPES = ["extra_trees", "logistic_regression"]


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _pattern(log: Any) -> str:
    return f"app={getattr(log, 'app', None) or '-'}|action={getattr(log, 'action', None) or '-'}|port={getattr(log, 'dst_port', None) or '-'}"


def _soc_targets(prepared: dict[str, Any], frame: Any) -> list[str]:
    return [behavior_aware_soc_target(label, frame.iloc[index]) for index, label in enumerate(prepared["y"])]


def queue_targets_for_mode(
    prepared: dict[str, Any],
    frame: Any,
    *,
    target_mode: str,
) -> tuple[list[str], dict[str, Any]]:
    soc_targets = _soc_targets(prepared, frame)
    original = [_queue_target(target) for target in soc_targets]
    if target_mode == "original_queue_target":
        return original, {"target_mode": target_mode, "repair_reasons": [], "changed_rows": 0}
    if target_mode != "repaired_queue_target":
        raise ValueError(f"Unknown v3.48 target mode: {target_mode}")  # pragma: no cover

    repaired: list[str] = []
    reasons: list[str] = []
    changed = 0
    for index, current in enumerate(original):
        proposed, reason = propose_queue_target(current, frame.iloc[index])
        repaired.append(proposed)
        reasons.append(reason)
        changed += int(proposed != current)
    return repaired, {
        "target_mode": target_mode,
        "changed_rows": changed,
        "changed_share": round(changed / len(original), 4) if original else 0.0,
        "repair_reasons": Counter(reasons).most_common(12),
    }


def _probability_for_label(probabilities: dict[str, float], label: str) -> float:
    return _safe_float(probabilities.get(label))


def _predict_queue(probability_rows: list[dict[str, float]], *, threshold: float) -> list[str]:
    predictions: list[str] = []
    for row in probability_rows:
        score = _probability_for_label(row, "needs_review")
        predictions.append("needs_review" if score >= threshold else "non_threat")
    return predictions


def _select_threshold(queue_true: list[str], probability_rows: list[dict[str, float]]) -> dict[str, Any]:
    candidates = []
    for threshold in QUEUE_THRESHOLDS:
        predictions = _predict_queue(probability_rows, threshold=threshold)
        metrics = _queue_metrics(queue_true, predictions)
        score = (
            int(_safe_float(metrics.get("queue_false_positive_rate"), 1.0) <= 0.35),
            int(_safe_float(metrics.get("queue_recall")) >= 0.8),
            _safe_float(metrics.get("queue_f1"))
            + 0.15 * _safe_float(metrics.get("queue_recall"))
            - 0.30 * _safe_float(metrics.get("queue_false_positive_rate"), 1.0),
            _safe_float(metrics.get("queue_precision")),
            -_safe_float(metrics.get("queue_false_positive_rate"), 1.0),
        )
        candidates.append({"threshold": threshold, "summary": metrics, "score": score})
    selected = max(candidates, key=lambda item: item["score"])
    return {
        "selected_threshold": selected["threshold"],
        "selected_on": "train_internal_calibration",
        "used_test_for_threshold_selection": False,
        "candidate_count": len(candidates),
        "within_queue_fpr_budget_candidates": sum(
            1 for item in candidates if _safe_float(item["summary"].get("queue_false_positive_rate"), 1.0) <= 0.35
        ),
        "within_queue_recall_budget_candidates": sum(
            1 for item in candidates if _safe_float(item["summary"].get("queue_recall")) >= 0.8
        ),
        "calibration_summary": selected["summary"],
    }


def _queue_false_positive_patterns(
    prepared: dict[str, Any],
    frame: Any,
    *,
    queue_true: list[str],
    predictions: list[str],
) -> dict[str, Any]:
    rows = []
    for position, (actual, predicted) in enumerate(zip(queue_true, predictions, strict=False)):
        if actual != "non_threat" or predicted != "needs_review":
            continue
        index = prepared["test_idx"][position]
        log = prepared["test_logs"][position]
        frame_row = frame.iloc[index]
        rows.append(
            {
                "pattern": _pattern(log),
                "traffic_family": str(frame_row.get("v337_traffic_family") or "unknown"),
                "evidence_bucket": _evidence_bucket(frame_row),
                "source_name": _source_name(log),
            }
        )
    return {
        "queue_false_positive_count": len(rows),
        "top_patterns": Counter(row["pattern"] for row in rows).most_common(12),
        "top_traffic_families": Counter(row["traffic_family"] for row in rows).most_common(10),
        "top_evidence_buckets": Counter(row["evidence_bucket"] for row in rows).most_common(10),
        "top_sources": Counter(row["source_name"] for row in rows).most_common(10),
    }


def _fit_queue_strategy(
    prepared: dict[str, Any],
    augmented: dict[str, Any],
    *,
    target_mode: str,
    model_type: str,
) -> dict[str, Any]:
    frame = augmented["frame"]
    queue_values, target_meta = queue_targets_for_mode(prepared, frame, target_mode=target_mode)
    split = _split_train_calibration_indices(prepared, queue_values)
    fit_idx = split["fit_idx"]
    calibration_idx = split["calibration_idx"]
    started = time.perf_counter()
    model, classes, model_meta = _fit_classifier(
        prepared,
        augmented,
        indices=fit_idx,
        targets=queue_values,
        model_type=model_type,
        weight_strategy="strong_benign",
        class_weight="balanced" if model_type == "logistic_regression" else None,
    )
    training_seconds = round(time.perf_counter() - started, 4)
    name = f"{target_mode}_{model_type}"
    if model is None:
        return {"name": name, "status": "skipped", "message": "Queue model unavailable.", "target_mode": target_mode}

    calibration_rows = _prob_rows(model, classes, frame, calibration_idx)
    y_calibration = [queue_values[index] for index in calibration_idx]
    threshold_selection = _select_threshold(y_calibration, calibration_rows)
    test_idx = list(prepared["test_idx"])
    y_test = [queue_values[index] for index in test_idx]
    test_rows = _prob_rows(model, classes, frame, test_idx)
    predictions = _predict_queue(test_rows, threshold=threshold_selection["selected_threshold"])
    queue_summary = _queue_metrics(y_test, predictions)
    calibration = _calibration_report(
        y_test,
        model.predict_proba(frame.iloc[test_idx]),
        classes,
        threat_labels={"needs_review"},
    )
    return {
        "name": name,
        "status": "evaluated",
        "target_mode": target_mode,
        "model_type": model_type,
        "model": model_meta,
        "training_seconds": training_seconds,
        "target_distribution": _distribution(queue_values),
        "target_repair": target_meta,
        "threshold_selection": {**split, **threshold_selection},
        "summary": queue_summary,
        "calibration": calibration,
        "false_positive_patterns": _queue_false_positive_patterns(
            prepared,
            frame,
            queue_true=y_test,
            predictions=predictions,
        ),
    }


def _strategy_rows(strategies: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for strategy in strategies:
        if strategy.get("status") != "evaluated":
            rows.append({key: strategy.get(key) for key in ["name", "status", "message", "target_mode"]})
            continue
        rows.append(
            {
                "name": strategy["name"],
                "status": strategy["status"],
                "target_mode": strategy["target_mode"],
                "model_type": strategy["model_type"],
                "target_distribution": strategy["target_distribution"],
                "target_repair": strategy["target_repair"],
                "summary": strategy["summary"],
                "calibration": strategy["calibration"],
                "threshold_selection": strategy["threshold_selection"],
                "false_positive_patterns": strategy["false_positive_patterns"],
            }
        )
    return rows


def _metric_ranges(strategy_splits: list[dict[str, Any]]) -> dict[str, Any]:
    ranges: dict[str, Any] = {}
    for metric in [
        "queue_precision",
        "queue_recall",
        "queue_f1",
        "queue_false_positive_rate",
        "queue_size_estimate",
    ]:
        values = [
            _safe_float((row.get("summary") or {}).get(metric), default=float("nan"))
            for row in strategy_splits
            if (row.get("summary") or {}).get(metric) is not None
        ]
        values = [value for value in values if value == value]
        if not values:
            ranges[metric] = {"min": None, "max": None, "span": None}
            continue
        ranges[metric] = {
            "min": round(min(values), 4),
            "max": round(max(values), 4),
            "span": round(max(values) - min(values), 4),
        }
    return ranges


def _queue_stability_summary(strategy_splits: list[dict[str, Any]]) -> dict[str, Any]:
    evaluated = [row for row in strategy_splits if row.get("status") == "evaluated"]
    pass_count = 0
    blockers: list[str] = []
    for row in evaluated:
        summary = row.get("summary") or {}
        checks = {
            "queue FPR": _safe_float(summary.get("queue_false_positive_rate"), 1.0) <= 0.35,
            "queue recall": _safe_float(summary.get("queue_recall")) >= 0.8,
            "queue F1": _safe_float(summary.get("queue_f1")) >= 0.75,
        }
        if all(checks.values()):
            pass_count += 1
        else:
            failed = ", ".join(name for name, passed in checks.items() if not passed)
            blockers.append(f"{row.get('split_mode')}: {failed}")
    return {
        "evaluated_splits": len(evaluated),
        "passing_splits": pass_count,
        "passed": bool(evaluated) and pass_count == len(evaluated),
        "metric_ranges": _metric_ranges(evaluated),
        "blockers": blockers,
    }


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
        target_repairs = []
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
                target_repairs.append(row.get("target_repair") or {})
                for pattern, count in (row.get("false_positive_patterns") or {}).get("top_patterns") or []:
                    fp_patterns[str(pattern)] += int(count)
                for bucket, count in (row.get("false_positive_patterns") or {}).get("top_evidence_buckets") or []:
                    fp_buckets[str(bucket)] += int(count)
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
            "stability": _queue_stability_summary(strategy_splits),
            "best_calibration": best_calibration,
            "threshold_selection": {
                "used_test_for_threshold_selection": any(
                    bool(row.get("used_test_for_threshold_selection")) for row in threshold_rows
                ),
                "selected_on": sorted({str(row.get("selected_on")) for row in threshold_rows if row.get("selected_on")}),
                "top_selected_thresholds": Counter(
                    str(row.get("selected_threshold")) for row in threshold_rows if row.get("selected_threshold") is not None
                ).most_common(5),
                "within_queue_fpr_budget_candidates": sum(
                    int(row.get("within_queue_fpr_budget_candidates") or 0) for row in threshold_rows
                ),
                "within_queue_recall_budget_candidates": sum(
                    int(row.get("within_queue_recall_budget_candidates") or 0) for row in threshold_rows
                ),
            },
            "target_repair_summary": {
                "changed_rows_by_split": [row.get("changed_rows", 0) for row in target_repairs],
                "changed_share_by_split": [row.get("changed_share", 0.0) for row in target_repairs],
            },
            "top_queue_false_positive_patterns": fp_patterns.most_common(12),
            "top_queue_false_positive_evidence_buckets": fp_buckets.most_common(10),
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
        max_fpr = _range_value(item, "queue_false_positive_rate", "max", 1.0)
        min_recall = _range_value(item, "queue_recall", "min")
        min_f1 = _range_value(item, "queue_f1", "min")
        calibration = item.get("best_calibration") or {}
        repaired_bonus = 0.03 if name.startswith("repaired_queue_target") else 0.0
        return (
            int((item.get("stability") or {}).get("passing_splits") or 0),
            1 if max_fpr <= 0.35 else 0,
            1 if min_recall >= 0.8 else 0,
            min_f1 + 0.15 * min_recall - 0.30 * max_fpr + repaired_bonus,
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
            "target": "train-internal only",
        },
        {
            "name": "independent queue stability acceptable",
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
            "name": "queue F1 stable",
            "passed": _range_value(item, "queue_f1", "min") >= 0.75,
            "value": _range_value(item, "queue_f1", "min"),
            "target": ">= 0.75 across splits",
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
            "| {name} | {passed} | {qf1_min}-{qf1_max} | {qrec_min}-{qrec_max} | {qfpr_min}-{qfpr_max} | {cal} |".format(
                name=name,
                passed=f"{item.get('stability', {}).get('passing_splits')}/{item.get('stability', {}).get('evaluated_splits')}",
                qf1_min=(ranges.get("queue_f1") or {}).get("min"),
                qf1_max=(ranges.get("queue_f1") or {}).get("max"),
                qrec_min=(ranges.get("queue_recall") or {}).get("min"),
                qrec_max=(ranges.get("queue_recall") or {}).get("max"),
                qfpr_min=(ranges.get("queue_false_positive_rate") or {}).get("min"),
                qfpr_max=(ranges.get("queue_false_positive_rate") or {}).get("max"),
                cal=item.get("best_calibration", {}).get("status"),
            )
        )
    return f"""# v3.48 Repaired Queue Target Model Evaluation

Generated: {result.get("generated_at")}

This report is diagnostic only. It compares original and v3.47-repaired queue targets as supervised queue-model targets. No labels were written, no model was activated, no artifact was written, and response automation stayed disabled.

## Best Diagnostic Candidate

- Candidate: {result.get("best_strategy")}
- Readiness: {result.get("readiness", {}).get("decision")}
- Checks passed: {result.get("readiness", {}).get("passed")} / {result.get("readiness", {}).get("total")}
- Blockers: {result.get("readiness", {}).get("blockers")}

## Strategy Comparison

| Strategy | Passing Splits | Queue F1 Range | Queue Recall Range | Queue FPR Range | Calibration |
| --- | ---: | --- | --- | --- | --- |
{chr(10).join(rows)}

## Safety

```json
{json.dumps(result.get("safety"), indent=2, default=str)}
```
"""


def run_v348_repaired_queue_target_model(
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
            _fit_queue_strategy(prepared, augmented, target_mode=target_mode, model_type=model_type)
            for target_mode in TARGET_MODES
            for model_type in MODEL_TYPES
        ]
        split_results.append(
            {
                "split_mode": split_mode,
                "status": "evaluated",
                "training_rows": len(prepared["train_idx"]),
                "test_rows": len(prepared["test_idx"]),
                "split_warnings": prepared.get("split_warnings") or [],
                "strategies": _strategy_rows(strategies),
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
        "blockers": ["no evaluated v3.48 strategy"],
        "checks": [],
    }
    after_labels = int(db.scalar(select(func.count(MLLabel.id))) or 0)
    after_runs = int(db.scalar(select(func.count(MLModelRun.id))) or 0)
    after_responses = int(db.scalar(select(func.count(ResponseAction.id))) or 0)

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    stamp = _stamp()
    report_path = output_path / f"v3_48_repaired_queue_target_model_{stamp}.md"
    latest_path = output_path / V348_LATEST
    result = {
        "ok": True,
        "status": "completed",
        "phase": "v3.48",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "runtime_seconds": round(time.perf_counter() - started, 4),
        "feature_generation_seconds": base.get("feature_generation_seconds"),
        "target_mode": "repaired_queue_target_model_evaluation",
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
