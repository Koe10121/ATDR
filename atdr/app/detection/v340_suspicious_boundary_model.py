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
    _build_pipeline_for_columns,
    _calibration_report,
    _classes,
    _metric_bundle,
    _noise_reduced_weights,
    _probability_rows,
    _profile_summary,
)
from atdr.app.detection.v332_guard_validation import _load_base_dataset, _prepared_for_split, _safe_float, _stability_summary
from atdr.app.detection.v335_split_stability_repair import V335_SPLITS
from atdr.app.detection.v337_evidence_feature_enrichment import enrich_v337_features
from atdr.app.detection.v338_calibrated_threshold_search import (
    FPR_BUDGET,
    _candidate_specs,
    _fit_candidate,
    _labels_order,
)
from atdr.app.detection.supervised_detector import training_dataset_diagnostics


V340_LATEST = "v3_40_suspicious_boundary_model_latest.json"
BOUNDARY_LABELS = ["benign_like", "suspicious"]


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _boundary_specs() -> list[dict[str, Any]]:
    return [
        {
            "name": "boundary_extra_trees_benign_protected",
            "model_type": "extra_trees",
            "class_weight": None,
            "weight_strategy": "strong_benign",
            "evidence_gate": True,
        },
        {
            "name": "boundary_extra_trees_balanced",
            "model_type": "extra_trees",
            "class_weight": "balanced",
            "weight_strategy": "none",
            "evidence_gate": True,
        },
        {
            "name": "boundary_logistic_balanced",
            "model_type": "logistic_regression",
            "class_weight": "balanced",
            "weight_strategy": "none",
            "evidence_gate": True,
        },
        {
            "name": "boundary_extra_trees_ungated_diagnostic",
            "model_type": "extra_trees",
            "class_weight": "balanced",
            "weight_strategy": "none",
            "evidence_gate": False,
            "eligible_for_selection": False,
        },
    ]


def _boundary_target(label: str) -> str | None:
    if label == "suspicious":
        return "suspicious"
    if label in BENIGN_LIKE_LABELS:
        return "benign_like"
    return None


def _boundary_split(prepared: dict[str, Any]) -> dict[str, Any]:
    train_test_split = prepared["imports"][8]
    eligible_idx = [index for index in prepared["train_idx"] if _boundary_target(prepared["y"][index]) is not None]
    eligible_targets = [_boundary_target(prepared["y"][index]) for index in eligible_idx]
    distribution = Counter(eligible_targets)
    if len(distribution) < 2 or min(distribution.values()) < 2:
        return {
            "status": "skipped",
            "message": "Not enough suspicious/benign-like train support for boundary calibration.",
            "used_test_for_boundary_selection": False,
        }
    stratify = eligible_targets if min(distribution.values()) >= 2 else None
    fit_idx, calibration_idx = train_test_split(
        eligible_idx,
        test_size=0.25,
        random_state=340,
        stratify=stratify,
    )
    return {
        "status": "ready",
        "fit_idx": list(fit_idx),
        "calibration_idx": list(calibration_idx),
        "fit_rows": len(fit_idx),
        "calibration_rows": len(calibration_idx),
        "fit_distribution": dict(Counter(_boundary_target(prepared["y"][index]) for index in fit_idx)),
        "calibration_distribution": dict(Counter(_boundary_target(prepared["y"][index]) for index in calibration_idx)),
        "selected_on": "train_internal_boundary_calibration",
        "used_test_for_boundary_selection": False,
    }


def _is_low_signal_without_evidence(row: Any) -> bool:
    low_signal = bool(row.get("v337_web_low_signal_flag")) or bool(row.get("v337_utility_low_signal_flag"))
    if not low_signal:
        return False
    return not (
        bool(row.get("v337_rule_backed_allow_flag"))
        or bool(row.get("v337_anomaly_signal_flag"))
        or bool(row.get("v337_web_scan_context_flag"))
        or bool(row.get("v337_incomplete_scan_context_flag"))
        or bool(row.get("v337_unknown_scan_context_flag"))
        or (_safe_float(row.get("v337_source_diversity_pressure")) >= 4 and bool(row.get("v337_repeated_service_flag")))
    )


def _has_boundary_evidence(row: Any) -> bool:
    return (
        bool(row.get("v337_rule_backed_allow_flag"))
        or bool(row.get("v337_anomaly_signal_flag"))
        or bool(row.get("v337_web_scan_context_flag"))
        or bool(row.get("v337_incomplete_scan_context_flag"))
        or bool(row.get("v337_unknown_scan_context_flag"))
        or (_safe_float(row.get("v337_behavior_evidence_strength")) >= 2.5 and _safe_float(row.get("v337_benign_web_likelihood_score")) <= 1.0)
        or (_safe_float(row.get("v337_source_diversity_pressure")) >= 5 and bool(row.get("v337_repeated_service_flag")))
    )


def apply_suspicious_boundary_overlay(
    augmented: dict[str, Any],
    base_predictions: list[str],
    boundary_probability_rows: list[dict[str, float]],
    indices: list[int],
    *,
    threshold: float,
    evidence_gate: bool = True,
) -> list[str]:
    frame = augmented["frame"]
    repaired: list[str] = []
    for position, prediction in enumerate(base_predictions):
        if prediction in THREAT_LABELS or prediction == "threat_positive":
            repaired.append(prediction)
            continue
        row = frame.iloc[indices[position]]
        suspicious_score = _safe_float(boundary_probability_rows[position].get("suspicious"))
        if suspicious_score < threshold:
            repaired.append(prediction)
            continue
        if _is_low_signal_without_evidence(row):
            repaired.append(prediction)
            continue
        if evidence_gate and not _has_boundary_evidence(row):
            repaired.append(prediction)
            continue
        repaired.append("suspicious")
    return repaired


def _probability_rows_for_indices(model: Any, frame: Any, indices: list[int]) -> tuple[list[dict[str, float]], Any, list[str]]:
    probabilities = model.predict_proba(frame.iloc[indices])
    classes = _classes(model)
    return _probability_rows(probabilities, classes), probabilities, classes


def _select_boundary_threshold(
    prepared: dict[str, Any],
    augmented: dict[str, Any],
    *,
    calibration_idx: list[int],
    probability_rows: list[dict[str, float]],
    evidence_gate: bool,
) -> dict[str, Any]:
    y_true = [_boundary_target(prepared["y"][index]) or "benign_like" for index in calibration_idx]
    candidates = []
    for threshold in [round(value / 100, 2) for value in range(10, 91, 5)]:
        predictions = apply_suspicious_boundary_overlay(
            augmented,
            ["benign_like"] * len(calibration_idx),
            probability_rows,
            calibration_idx,
            threshold=threshold,
            evidence_gate=evidence_gate,
        )
        metrics = _metric_bundle(
            prepared,
            y_true=y_true,
            predictions=predictions,
            labels_order=BOUNDARY_LABELS,
            threat_labels={"suspicious"},
        )
        summary = _profile_summary(metrics)
        candidates.append(
            {
                "threshold": threshold,
                "summary": summary,
                "metrics": metrics,
                "within_fpr_budget": _safe_float(summary.get("benign_like_false_positive_rate"), 1.0) <= FPR_BUDGET,
            }
        )

    def score(item: dict[str, Any]) -> tuple[Any, ...]:
        summary = item["summary"]
        fpr = _safe_float(summary.get("benign_like_false_positive_rate"), 1.0)
        suspicious = _safe_float(summary.get("suspicious_recall"))
        threat_f1 = _safe_float(summary.get("threat_positive_f1"))
        return (
            1 if fpr <= FPR_BUDGET else 0,
            suspicious,
            threat_f1 - 0.35 * fpr,
            -fpr,
            item["threshold"],
        )

    selected = max(candidates, key=score)
    return {
        "selected_threshold": selected["threshold"],
        "selected_on": "train_internal_boundary_calibration",
        "used_test_for_boundary_selection": False,
        "candidate_count": len(candidates),
        "within_fpr_budget_candidates": sum(1 for item in candidates if item["within_fpr_budget"]),
        "calibration_summary": selected["summary"],
        "threshold_candidates": [
            {
                "threshold": item["threshold"],
                "summary": item["summary"],
                "within_fpr_budget": item["within_fpr_budget"],
            }
            for item in candidates
        ],
    }


def _fit_boundary_candidate(
    prepared: dict[str, Any],
    augmented: dict[str, Any],
    spec: dict[str, Any],
) -> dict[str, Any]:
    frame = augmented["frame"]
    split = _boundary_split(prepared)
    if split.get("status") != "ready":
        return {
            "name": spec["name"],
            "status": "skipped",
            "message": split.get("message"),
            "used_test_for_boundary_selection": False,
        }
    fit_idx = split["fit_idx"]
    calibration_idx = split["calibration_idx"]
    y_fit = [_boundary_target(prepared["y"][index]) or "benign_like" for index in fit_idx]
    model = _build_pipeline_for_columns(
        prepared["imports"],
        model_type=spec["model_type"],
        class_weight=spec["class_weight"],
        numeric_features=augmented["numeric_features"],
        categorical_features=augmented["categorical_features"],
    )
    weights, weight_summary = _noise_reduced_weights(prepared["labels"], spec["weight_strategy"])
    fit_kwargs = {}
    if weights is not None:
        fit_kwargs["model__sample_weight"] = [weights[index] for index in fit_idx]
    started = time.perf_counter()
    model.fit(frame.iloc[fit_idx], y_fit, **fit_kwargs)
    training_seconds = round(time.perf_counter() - started, 4)
    calibration_rows, calibration_probabilities, calibration_classes = _probability_rows_for_indices(
        model,
        frame,
        calibration_idx,
    )
    selection = _select_boundary_threshold(
        prepared,
        augmented,
        calibration_idx=calibration_idx,
        probability_rows=calibration_rows,
        evidence_gate=bool(spec.get("evidence_gate", True)),
    )
    test_rows, test_probabilities, test_classes = _probability_rows_for_indices(model, frame, list(prepared["test_idx"]))
    return {
        "name": spec["name"],
        "status": "evaluated",
        "model_type": spec["model_type"],
        "class_weight": spec["class_weight"],
        "sample_weighting": weight_summary,
        "evidence_gate": bool(spec.get("evidence_gate", True)),
        "eligible_for_selection": bool(spec.get("eligible_for_selection", True)),
        "training_seconds": training_seconds,
        "boundary_selection": {**split, **selection},
        "calibration": _calibration_report(
            [_boundary_target(prepared["y"][index]) or "benign_like" for index in calibration_idx],
            calibration_probabilities,
            calibration_classes,
            threat_labels={"suspicious"},
        ),
        "_test_probability_rows": test_rows,
        "_test_probabilities": test_probabilities,
        "_test_classes": test_classes,
    }


def _evaluate_predictions(
    prepared: dict[str, Any],
    *,
    y_true: list[str],
    predictions: list[str],
    target_mode: str = "three_class",
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


def _pattern_summary(
    prepared: dict[str, Any],
    augmented: dict[str, Any],
    *,
    predictions: list[str],
    y_true: list[str],
) -> dict[str, Any]:
    frame = augmented["frame"]
    suspicious_misses = []
    false_positives = []
    raised_rows = []
    for position, (actual, predicted) in enumerate(zip(y_true, predictions, strict=False)):
        index = prepared["test_idx"][position]
        log = prepared["test_logs"][position]
        row = frame.iloc[index]
        item = {
            "pattern": f"app={log.app or '-'}|action={log.action or '-'}|port={log.dst_port or '-'}",
            "family": str(row.get("v337_traffic_family") or "unknown"),
            "source_name": _source_name(log),
            "actual": actual,
            "predicted": predicted,
        }
        if actual == "suspicious" and predicted != "suspicious":
            suspicious_misses.append(item)
        if actual == "benign_like" and predicted in THREAT_LABELS:
            false_positives.append(item)
        if predicted == "suspicious":
            raised_rows.append(item)
    return {
        "suspicious_miss_count": len(suspicious_misses),
        "suspicious_miss_top_patterns": Counter(row["pattern"] for row in suspicious_misses).most_common(12),
        "suspicious_miss_top_families": Counter(row["family"] for row in suspicious_misses).most_common(10),
        "false_positive_count": len(false_positives),
        "false_positive_top_patterns": Counter(row["pattern"] for row in false_positives).most_common(12),
        "false_positive_top_families": Counter(row["family"] for row in false_positives).most_common(10),
        "raised_suspicious_top_patterns": Counter(row["pattern"] for row in raised_rows).most_common(12),
    }


def _split_strategy_rows(
    prepared: dict[str, Any],
    augmented: dict[str, Any],
    baseline: dict[str, Any],
    boundary_candidates: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if baseline.get("status") != "evaluated":
        return [{"name": "v3_38_baseline", "status": baseline.get("status"), "message": baseline.get("message")}]
    y_test = list(baseline.get("_y_test") or [])
    base_predictions = list(baseline.get("_predictions") or [])
    base_metrics, base_summary = _evaluate_predictions(prepared, y_true=y_test, predictions=base_predictions)
    rows.append(
        {
            "name": "v3_38_soc_queue_low_noise_baseline",
            "status": "evaluated",
            "eligible_for_selection": True,
            "target_mode": "three_class",
            "summary": base_summary,
            "metrics": base_metrics,
            "calibration": baseline.get("calibration") or {},
            "boundary_selection": {"selected_on": "baseline", "used_test_for_boundary_selection": False},
            "raised_to_suspicious": 0,
            "pattern_summary": _pattern_summary(prepared, augmented, predictions=base_predictions, y_true=y_test),
        }
    )
    for candidate in boundary_candidates:
        if candidate.get("status") != "evaluated":
            rows.append(
                {
                    "name": candidate.get("name"),
                    "status": candidate.get("status"),
                    "message": candidate.get("message"),
                    "eligible_for_selection": False,
                }
            )
            continue
        threshold = float((candidate.get("boundary_selection") or {}).get("selected_threshold") or 1.0)
        predictions = apply_suspicious_boundary_overlay(
            augmented,
            base_predictions,
            candidate["_test_probability_rows"],
            list(prepared["test_idx"]),
            threshold=threshold,
            evidence_gate=bool(candidate.get("evidence_gate", True)),
        )
        metrics, summary = _evaluate_predictions(prepared, y_true=y_test, predictions=predictions)
        rows.append(
            {
                "name": f"v3_40_{candidate['name']}_overlay",
                "base_strategy": candidate["name"],
                "status": "evaluated",
                "eligible_for_selection": bool(candidate.get("eligible_for_selection", True)),
                "target_mode": "three_class",
                "model_type": candidate.get("model_type"),
                "evidence_gate": bool(candidate.get("evidence_gate", True)),
                "summary": summary,
                "metrics": metrics,
                "calibration": candidate.get("calibration") or {},
                "boundary_selection": candidate.get("boundary_selection") or {},
                "raised_to_suspicious": sum(
                    1 for before, after in zip(base_predictions, predictions, strict=False) if before != after
                ),
                "pattern_summary": _pattern_summary(prepared, augmented, predictions=predictions, y_true=y_test),
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
        boundary_rows = []
        suspicious_misses = Counter()
        false_positives = Counter()
        false_positive_families = Counter()
        raised_total = 0
        eligible = False
        for split in split_results:
            for row in split.get("strategies", []):
                if row.get("name") != name or row.get("status") != "evaluated":
                    continue
                eligible = eligible or bool(row.get("eligible_for_selection"))
                raised_total += int(row.get("raised_to_suspicious") or 0)
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
                boundary_rows.append(row.get("boundary_selection") or {})
                pattern = row.get("pattern_summary") or {}
                for value, count in pattern.get("suspicious_miss_top_patterns") or []:
                    suspicious_misses[str(value)] += int(count)
                for value, count in pattern.get("false_positive_top_patterns") or []:
                    false_positives[str(value)] += int(count)
                for value, count in pattern.get("false_positive_top_families") or []:
                    false_positive_families[str(value)] += int(count)
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
            "eligible_for_selection": eligible,
            "stability": stability,
            "best_calibration": best_calibration,
            "raised_to_suspicious_total": raised_total,
            "boundary_selection": {
                "used_test_for_boundary_selection": any(
                    bool(row.get("used_test_for_boundary_selection")) for row in boundary_rows
                ),
                "selected_on": sorted({str(row.get("selected_on")) for row in boundary_rows if row.get("selected_on")}),
                "top_selected_thresholds": Counter(
                    str(row.get("selected_threshold")) for row in boundary_rows if row.get("selected_threshold") is not None
                ).most_common(8),
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
    selectable = {name: item for name, item in comparison.items() if item.get("eligible_for_selection")}
    if not selectable:
        return None

    def score(name: str) -> tuple[Any, ...]:
        item = selectable[name]
        max_fpr = _range_value(item, "benign_like_false_positive_rate", "max", 1.0)
        min_suspicious = _range_value(item, "suspicious_recall", "min")
        min_f1 = _range_value(item, "threat_positive_f1", "min")
        min_malicious = _range_value(item, "malicious_recall", "min")
        calibration = item.get("best_calibration") or {}
        leakage_free = not bool((item.get("boundary_selection") or {}).get("used_test_for_boundary_selection"))
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
    boundary_selection = item.get("boundary_selection") or {}
    checks = [
        {
            "name": "boundary threshold selection avoids test leakage",
            "passed": not bool(boundary_selection.get("used_test_for_boundary_selection")),
            "value": boundary_selection.get("selected_on"),
            "target": "train_internal_boundary_calibration only",
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
            "| {name} | {eligible} | {raised} | {passed} | {f1_min}-{f1_max} | {fpr_min}-{fpr_max} | {susp_min}-{susp_max} | {mal_min}-{mal_max} | {cal} |".format(
                name=name,
                eligible="yes" if item.get("eligible_for_selection") else "no",
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
    return f"""# v3.40 Suspicious Boundary Model Redesign

Generated: {result.get("generated_at")}

This phase is diagnostic only. Suspicious-vs-benign-like boundary models are selected on train-internal calibration rows and evaluated on held-out splits. No labels were written, no model was activated, no artifact was written, and response automation stayed disabled.

## Best Diagnostic Candidate

- Candidate: {result.get("best_strategy")}
- Readiness: {result.get("readiness", {}).get("decision")}
- Checks passed: {result.get("readiness", {}).get("passed")} / {result.get("readiness", {}).get("total")}
- Blockers: {result.get("readiness", {}).get("blockers")}

## Strategy Comparison

| Strategy | Eligible | Raised To Suspicious | Passing Splits | Threat F1 Range | Benign FPR Range | Suspicious Recall Range | Malicious Recall Range | Calibration |
| --- | --- | ---: | ---: | --- | --- | --- | --- | --- |
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
        return {"summary": "No evaluated v3.40 strategy was available."}
    item = comparison[best_strategy]
    return {
        "best_strategy": best_strategy,
        "top_suspicious_miss_patterns": item.get("top_suspicious_miss_patterns") or [],
        "top_false_positive_patterns": item.get("top_false_positive_patterns") or [],
        "top_false_positive_families": item.get("top_false_positive_families") or [],
        "interpretation": (
            "If the boundary overlay does not improve split-stable suspicious recall, the remaining gap is likely "
            "label semantics and source-generalization rather than a simple thresholding problem."
        ),
    }


def run_v340_suspicious_boundary_model(
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
    baseline_spec = next(spec for spec in _candidate_specs() if spec["name"] == "three_class_v337_soc_queue_threshold_search_low_noise")
    for split_mode in V335_SPLITS:
        prepared = _prepared_for_split(base, split_mode=split_mode, test_size=test_size)
        frame, meta = enrich_v337_features(prepared)
        augmented = {"frame": frame, **meta}
        baseline = _fit_candidate(prepared, augmented, baseline_spec)
        boundary_candidates = [_fit_boundary_candidate(prepared, augmented, spec) for spec in _boundary_specs()]
        split_results.append(
            {
                "split_mode": split_mode,
                "status": "evaluated",
                "training_rows": len(prepared["train_idx"]),
                "test_rows": len(prepared["test_idx"]),
                "split_warnings": prepared.get("split_warnings") or [],
                "strategies": _split_strategy_rows(prepared, augmented, baseline, boundary_candidates),
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
        "blockers": ["no evaluated v3.40 strategy"],
        "checks": [],
    }
    after_runs = int(db.scalar(select(func.count(MLModelRun.id))) or 0)
    after_responses = int(db.scalar(select(func.count(ResponseAction.id))) or 0)

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    stamp = _stamp()
    report_path = output_path / f"v3_40_suspicious_boundary_model_{stamp}.md"
    latest_path = output_path / V340_LATEST
    result: dict[str, Any] = {
        "ok": True,
        "status": "completed",
        "phase": "v3.40",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "runtime_seconds": round(time.perf_counter() - started, 4),
        "feature_generation_seconds": base.get("feature_generation_seconds"),
        "fpr_budget": FPR_BUDGET,
        "splits": V335_SPLITS,
        "boundary_specs": _boundary_specs(),
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
