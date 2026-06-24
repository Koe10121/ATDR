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
from atdr.app.detection.v331_noise_reduction import _calibration_report, _metric_bundle, _profile_summary
from atdr.app.detection.v332_guard_validation import _load_base_dataset, _prepared_for_split, _safe_float, _stability_summary
from atdr.app.detection.v335_split_stability_repair import V335_SPLITS
from atdr.app.detection.v337_evidence_feature_enrichment import enrich_v337_features
from atdr.app.detection.v341_label_semantics_audit import _evidence_bucket
from atdr.app.detection.v342_label_policy_reframing import FPR_BUDGET, SOC_TARGETS, SOC_THREAT_TARGETS, behavior_aware_soc_target
from atdr.app.detection.v343_hybrid_soc_queue import _evidence_snapshot
from atdr.app.detection.v344_two_stage_soc_queue import _fit_classifier, _prob_rows, _queue_metrics, _split_train_calibration_indices
from atdr.app.detection.v348_repaired_queue_target_model import _predict_queue, _select_threshold, queue_targets_for_mode


V349_LATEST = "v3_49_repaired_queue_severity_model_latest.json"
SEVERITY_MODEL_TYPES = ["extra_trees", "logistic_regression"]
SEVERITY_DECISION_MODES = ["probability_only", "evidence_guarded"]
THREAT_THRESHOLDS = [0.25, 0.35, 0.45, 0.55, 0.65, 0.75]
MALICIOUS_THRESHOLDS = [0.35, 0.50, 0.65, 0.80]


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _pattern(log: Any) -> str:
    return f"app={getattr(log, 'app', None) or '-'}|action={getattr(log, 'action', None) or '-'}|port={getattr(log, 'dst_port', None) or '-'}"


def _soc_targets(prepared: dict[str, Any], frame: Any) -> list[str]:
    return [behavior_aware_soc_target(label, frame.iloc[index]) for index, label in enumerate(prepared["y"])]


def _summary(metrics: dict[str, Any], queue_metrics: dict[str, Any]) -> dict[str, Any]:
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


def severity_decision(row: Any, probabilities: dict[str, float], thresholds: dict[str, float], *, mode: str) -> str:
    malicious = _safe_float(probabilities.get("malicious_high_confidence"))
    suspicious = _safe_float(probabilities.get("evidence_backed_suspicious"))
    unusual = _safe_float(probabilities.get("unusual_needs_review"))
    threat_score = malicious + suspicious
    if mode == "evidence_guarded":
        evidence = _evidence_snapshot(row)
        if malicious >= thresholds["malicious"] and evidence["evidence_strength"] >= 4.0:
            return "malicious_high_confidence"
        if (
            threat_score >= thresholds["threat"]
            and evidence["evidence_strength"] >= 2.0
            and not evidence["low_signal"]
        ):
            return "evidence_backed_suspicious"
        return "unusual_needs_review"
    if malicious >= thresholds["malicious"] and malicious >= suspicious:
        return "malicious_high_confidence"
    if threat_score >= thresholds["threat"]:
        return "evidence_backed_suspicious"
    if max(malicious, suspicious, unusual) == 0:
        return "unusual_needs_review"
    return "unusual_needs_review"


def _final_predictions(
    frame: Any,
    indices: list[int],
    *,
    queue_predictions: list[str],
    severity_rows: list[dict[str, float]],
    thresholds: dict[str, float],
    mode: str,
) -> list[str]:
    predictions: list[str] = []
    for position, index in enumerate(indices):
        if queue_predictions[position] != "needs_review":
            predictions.append("non_threat")
            continue
        predictions.append(severity_decision(frame.iloc[index], severity_rows[position], thresholds, mode=mode))
    return predictions


def _threshold_score(summary: dict[str, Any]) -> tuple[Any, ...]:
    fpr = _safe_float(summary.get("benign_like_false_positive_rate"), 1.0)
    threat_f1 = _safe_float(summary.get("threat_positive_f1"))
    suspicious = _safe_float(summary.get("suspicious_recall"))
    malicious = _safe_float(summary.get("malicious_recall"))
    unusual = _safe_float(summary.get("unusual_needs_review_recall"))
    return (
        1 if fpr <= FPR_BUDGET else 0,
        1 if threat_f1 >= 0.85 else 0,
        1 if suspicious >= 0.8 else 0,
        1 if malicious >= 0.5 else 0,
        threat_f1 + 0.20 * suspicious + 0.25 * malicious + 0.05 * unusual - 0.45 * fpr,
        malicious,
        suspicious,
        -fpr,
    )


def _select_severity_thresholds(
    prepared: dict[str, Any],
    frame: Any,
    *,
    calibration_idx: list[int],
    y_calibration: list[str],
    queue_calibration: list[str],
    queue_predictions: list[str],
    severity_rows: list[dict[str, float]],
    mode: str,
) -> dict[str, Any]:
    candidates = []
    for threat in THREAT_THRESHOLDS:
        for malicious in MALICIOUS_THRESHOLDS:
            thresholds = {"threat": threat, "malicious": malicious}
            predictions = _final_predictions(
                frame,
                calibration_idx,
                queue_predictions=queue_predictions,
                severity_rows=severity_rows,
                thresholds=thresholds,
                mode=mode,
            )
            q_metrics = _queue_metrics(queue_calibration, queue_predictions)
            metrics = _metrics_for_predictions(prepared, y_calibration, predictions)
            summary = _summary(metrics, q_metrics)
            candidates.append({"thresholds": thresholds, "summary": summary})
    selected = max(candidates, key=lambda item: _threshold_score(item["summary"]))
    return {
        "selected_thresholds": selected["thresholds"],
        "selected_on": "train_internal_calibration",
        "used_test_for_threshold_selection": False,
        "candidate_count": len(candidates),
        "within_fpr_budget_candidates": sum(
            1 for item in candidates if _safe_float(item["summary"].get("benign_like_false_positive_rate"), 1.0) <= FPR_BUDGET
        ),
        "within_suspicious_recall_candidates": sum(
            1 for item in candidates if _safe_float(item["summary"].get("suspicious_recall")) >= 0.8
        ),
        "within_malicious_recall_candidates": sum(
            1 for item in candidates if _safe_float(item["summary"].get("malicious_recall")) >= 0.5
        ),
        "calibration_summary": selected["summary"],
    }


def _fit_repaired_queue_severity_strategy(
    prepared: dict[str, Any],
    augmented: dict[str, Any],
    *,
    severity_model_type: str,
    decision_mode: str,
) -> dict[str, Any]:
    frame = augmented["frame"]
    soc_targets = _soc_targets(prepared, frame)
    queue_values, target_meta = queue_targets_for_mode(prepared, frame, target_mode="repaired_queue_target")
    split = _split_train_calibration_indices(prepared, queue_values)
    fit_idx = split["fit_idx"]
    calibration_idx = split["calibration_idx"]
    severity_fit_idx = [index for index in fit_idx if queue_values[index] == "needs_review"]
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
        targets=soc_targets,
        model_type=severity_model_type,
        weight_strategy="strong_benign",
        class_weight="balanced" if severity_model_type == "logistic_regression" else None,
    )
    training_seconds = round(time.perf_counter() - started, 4)
    name = f"repaired_queue_extra_trees_severity_{severity_model_type}_{decision_mode}"
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
    threshold_selection = _select_severity_thresholds(
        prepared,
        frame,
        calibration_idx=calibration_idx,
        y_calibration=[soc_targets[index] for index in calibration_idx],
        queue_calibration=[queue_values[index] for index in calibration_idx],
        queue_predictions=queue_calibration_predictions,
        severity_rows=severity_calibration_rows,
        mode=decision_mode,
    )

    test_idx = list(prepared["test_idx"])
    y_test = [soc_targets[index] for index in test_idx]
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
    q_metrics = _queue_metrics(queue_test, queue_predictions)
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
        "target_mode": "repaired_queue_downstream_severity",
        "queue_model_type": "extra_trees",
        "severity_model_type": severity_model_type,
        "decision_mode": decision_mode,
        "queue_model": queue_meta,
        "severity_model": severity_meta,
        "training_seconds": training_seconds,
        "target_repair": target_meta,
        "threshold_selection": {
            "fit_rows": len(fit_idx),
            "calibration_rows": len(calibration_idx),
            "severity_fit_rows": len(severity_fit_idx),
            "queue_threshold": queue_thresholds["selected_threshold"],
            "queue_threshold_selected_on": queue_thresholds["selected_on"],
            **threshold_selection,
        },
        "summary": _summary(metrics, q_metrics),
        "metrics": metrics,
        "queue_metrics": q_metrics,
        "calibration": calibration,
        "_predictions": predictions,
        "_y_test": y_test,
        "_queue_predictions": queue_predictions,
        "_queue_test": queue_test,
    }


def _error_patterns(
    prepared: dict[str, Any],
    frame: Any,
    *,
    predictions: list[str],
    y_true: list[str],
) -> dict[str, Any]:
    false_positive_rows = []
    severity_error_rows = []
    for position, (actual, predicted) in enumerate(zip(y_true, predictions, strict=False)):
        if actual == predicted:
            continue
        index = prepared["test_idx"][position]
        log = prepared["test_logs"][position]
        row = frame.iloc[index]
        item = {
            "actual": actual,
            "predicted": predicted,
            "pattern": _pattern(log),
            "traffic_family": str(row.get("v337_traffic_family") or "unknown"),
            "evidence_bucket": _evidence_bucket(row),
            "source_name": _source_name(log),
        }
        if actual not in SOC_THREAT_TARGETS and predicted in SOC_THREAT_TARGETS:
            false_positive_rows.append(item)
        if actual in {"unusual_needs_review", *SOC_THREAT_TARGETS} and predicted in {"unusual_needs_review", *SOC_THREAT_TARGETS}:
            severity_error_rows.append(item)
    return {
        "false_positive_count": len(false_positive_rows),
        "top_false_positive_patterns": Counter(row["pattern"] for row in false_positive_rows).most_common(12),
        "top_false_positive_evidence_buckets": Counter(row["evidence_bucket"] for row in false_positive_rows).most_common(10),
        "severity_error_count": len(severity_error_rows),
        "top_severity_confusions": Counter(
            f"{row['actual']} -> {row['predicted']}" for row in severity_error_rows
        ).most_common(12),
        "top_severity_error_patterns": Counter(row["pattern"] for row in severity_error_rows).most_common(12),
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
                "queue_model_type": strategy.get("queue_model_type"),
                "severity_model_type": strategy.get("severity_model_type"),
                "decision_mode": strategy.get("decision_mode"),
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
            _safe_float((row.get("summary") or {}).get(metric), default=float("nan"))
            for row in strategy_splits
            if (row.get("summary") or {}).get(metric) is not None
        ]
        values = [value for value in values if value == value]
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


def _range_value(item: dict[str, Any], metric: str, kind: str, default: float = 0.0) -> float:
    ranges = (item.get("stability") or {}).get("metric_ranges") or {}
    return _safe_float((ranges.get(metric) or {}).get(kind), default)


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
        calibration = item.get("best_calibration") or {}
        return (
            int((item.get("stability") or {}).get("passing_splits") or 0),
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
    checks = [
        {
            "name": "threshold selection avoids test leakage",
            "passed": not bool(threshold_selection.get("used_test_for_threshold_selection")),
            "value": threshold_selection.get("selected_on"),
            "target": "train-internal only",
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
        rows.append(
            "| {name} | {passed} | {tf1_min} | {fpr_max} | {srec_min} | {mrec_min} | {qf1_min} | {cal} |".format(
                name=name,
                passed=f"{item.get('stability', {}).get('passing_splits')}/{item.get('stability', {}).get('evaluated_splits')}",
                tf1_min=(ranges.get("threat_positive_f1") or {}).get("min"),
                fpr_max=(ranges.get("benign_like_false_positive_rate") or {}).get("max"),
                srec_min=(ranges.get("suspicious_recall") or {}).get("min"),
                mrec_min=(ranges.get("malicious_recall") or {}).get("min"),
                qf1_min=(ranges.get("queue_f1") or {}).get("min"),
                cal=item.get("best_calibration", {}).get("status"),
            )
        )
    return f"""# v3.49 Repaired Queue Severity Classification

Generated: {result.get("generated_at")}

This report is diagnostic only. It tests downstream severity classification for rows admitted by the repaired v3.48 queue. No labels were written, no model was activated, no artifact was written, and response automation stayed disabled.

## Best Diagnostic Candidate

- Candidate: {result.get("best_strategy")}
- Readiness: {result.get("readiness", {}).get("decision")}
- Checks passed: {result.get("readiness", {}).get("passed")} / {result.get("readiness", {}).get("total")}
- Blockers: {result.get("readiness", {}).get("blockers")}

## Strategy Comparison

| Strategy | Passing Splits | Threat F1 Min | FPR Max | Suspicious Recall Min | Malicious Recall Min | Queue F1 Min | Calibration |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
{chr(10).join(rows)}

## Safety

```json
{json.dumps(result.get("safety"), indent=2, default=str)}
```
"""


def run_v349_repaired_queue_severity_model(
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
            _fit_repaired_queue_severity_strategy(
                prepared,
                augmented,
                severity_model_type=model_type,
                decision_mode=decision_mode,
            )
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
    best_item = comparison[best_strategy] if best_strategy else {}
    readiness = _readiness(best_item) if best_item else {
        "decision": "candidate_only",
        "passed": 0,
        "total": 0,
        "production_promoted": False,
        "model_activated": False,
        "model_artifact_written": False,
        "response_automation_allowed": False,
        "blockers": ["no evaluated v3.49 strategy"],
        "checks": [],
    }
    after_labels = int(db.scalar(select(func.count(MLLabel.id))) or 0)
    after_runs = int(db.scalar(select(func.count(MLModelRun.id))) or 0)
    after_responses = int(db.scalar(select(func.count(ResponseAction.id))) or 0)

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    stamp = _stamp()
    report_path = output_path / f"v3_49_repaired_queue_severity_model_{stamp}.md"
    latest_path = output_path / V349_LATEST
    result = {
        "ok": True,
        "status": "completed",
        "phase": "v3.49",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "runtime_seconds": round(time.perf_counter() - started, 4),
        "feature_generation_seconds": base.get("feature_generation_seconds"),
        "target_mode": "repaired_queue_downstream_severity",
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
