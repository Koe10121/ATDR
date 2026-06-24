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
from atdr.app.detection.supervised_detector import training_dataset_diagnostics


V338_LATEST = "v3_38_calibrated_threshold_search_latest.json"
FPR_BUDGET = 0.15


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _map_labels(labels: list[str], target_mode: str) -> list[str]:
    if target_mode == "binary":
        return ["threat_positive" if label in THREAT_LABELS else "benign_like" for label in labels]
    if target_mode in {"three_class", "hierarchical"}:
        return [label if label in THREAT_LABELS else "benign_like" for label in labels]
    return labels


def _labels_order(target_mode: str, y_values: list[str]) -> tuple[list[str], set[str]]:
    if target_mode == "binary":
        return ["benign_like", "threat_positive"], {"threat_positive"}
    if target_mode in {"three_class", "hierarchical"}:
        return ["benign_like", "malicious", "suspicious"], set(THREAT_LABELS)
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
        random_state=338,
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


def _candidate_specs() -> list[dict[str, Any]]:
    return [
        {
            "name": "flat_v337_extra_trees_strong_benign_threshold_search_standard",
            "model_type": "extra_trees",
            "target_mode": "flat",
            "class_weight": None,
            "weight_strategy": "strong_benign",
            "selection_fpr_budget": 0.15,
        },
        {
            "name": "flat_v337_extra_trees_strong_benign_threshold_search_low_noise",
            "model_type": "extra_trees",
            "target_mode": "flat",
            "class_weight": None,
            "weight_strategy": "strong_benign",
            "selection_fpr_budget": 0.05,
        },
        {
            "name": "flat_v337_extra_trees_lower_threat_threshold_search_standard",
            "model_type": "extra_trees",
            "target_mode": "flat",
            "class_weight": None,
            "weight_strategy": "lower_threat",
            "selection_fpr_budget": 0.15,
        },
        {
            "name": "flat_v337_extra_trees_lower_threat_threshold_search_low_noise",
            "model_type": "extra_trees",
            "target_mode": "flat",
            "class_weight": None,
            "weight_strategy": "lower_threat",
            "selection_fpr_budget": 0.05,
        },
        {
            "name": "three_class_v337_soc_queue_threshold_search_standard",
            "model_type": "extra_trees",
            "target_mode": "three_class",
            "class_weight": None,
            "weight_strategy": "strong_benign",
            "selection_fpr_budget": 0.15,
        },
        {
            "name": "three_class_v337_soc_queue_threshold_search_low_noise",
            "model_type": "extra_trees",
            "target_mode": "three_class",
            "class_weight": None,
            "weight_strategy": "strong_benign",
            "selection_fpr_budget": 0.05,
        },
        {
            "name": "binary_v337_threat_positive_threshold_search_standard",
            "model_type": "extra_trees",
            "target_mode": "binary",
            "class_weight": None,
            "weight_strategy": "strong_benign",
            "selection_fpr_budget": 0.15,
        },
        {
            "name": "binary_v337_threat_positive_threshold_search_low_noise",
            "model_type": "extra_trees",
            "target_mode": "binary",
            "class_weight": None,
            "weight_strategy": "strong_benign",
            "selection_fpr_budget": 0.05,
        },
        {
            "name": "flat_v337_logistic_threshold_search_standard",
            "model_type": "logistic_regression",
            "target_mode": "flat",
            "class_weight": "balanced",
            "weight_strategy": "none",
            "selection_fpr_budget": 0.15,
        },
        {
            "name": "flat_v337_logistic_threshold_search_low_noise",
            "model_type": "logistic_regression",
            "target_mode": "flat",
            "class_weight": "balanced",
            "weight_strategy": "none",
            "selection_fpr_budget": 0.05,
        },
        {
            "name": "hierarchical_v337_threshold_search_standard",
            "model_type": "extra_trees_two_stage",
            "target_mode": "hierarchical",
            "class_weight": "mixed",
            "weight_strategy": "strong_benign",
            "selection_fpr_budget": 0.15,
        },
        {
            "name": "hierarchical_v337_threshold_search_low_noise",
            "model_type": "extra_trees_two_stage",
            "target_mode": "hierarchical",
            "class_weight": "mixed",
            "weight_strategy": "strong_benign",
            "selection_fpr_budget": 0.05,
        },
    ]


def _threshold_grid(target_mode: str) -> list[dict[str, float]]:
    if target_mode == "binary":
        return [{"threat_positive": round(value / 100, 2)} for value in range(30, 91, 5)]
    if target_mode in {"three_class", "hierarchical"}:
        return [
            {"threat_positive": round(threat / 100, 2), "malicious": malicious}
            for threat in range(30, 91, 5)
            for malicious in [0.28, 0.35, 0.45, 0.60]
        ]
    return [
        {
            "threat_positive": round(threat / 100, 2),
            "malicious": malicious,
            "needs_context": needs_context,
        }
        for threat in range(30, 91, 5)
        for malicious in [0.28, 0.35, 0.45, 0.60]
        for needs_context in [0.45, 0.55]
    ]


def _decision(probabilities: dict[str, float], thresholds: dict[str, float], *, target_mode: str) -> str:
    if target_mode == "binary":
        return (
            "threat_positive"
            if _safe_float(probabilities.get("threat_positive")) >= thresholds["threat_positive"]
            else "benign_like"
        )
    malicious = _safe_float(probabilities.get("malicious"))
    suspicious = _safe_float(probabilities.get("suspicious"))
    threat = malicious + suspicious
    if malicious >= thresholds.get("malicious", 0.45):
        return "malicious"
    if threat >= thresholds["threat_positive"]:
        return "malicious" if malicious > suspicious else "suspicious"
    if target_mode in {"three_class", "hierarchical"}:
        return "benign_like"
    needs_context = _safe_float(probabilities.get("needs_context"))
    if needs_context >= thresholds.get("needs_context", 0.55):
        return "needs_context"
    fallback = {
        "benign": _safe_float(probabilities.get("benign")),
        "benign_unusual": _safe_float(probabilities.get("benign_unusual")),
        "needs_context": needs_context,
    }
    return max(fallback.items(), key=lambda item: item[1])[0]


def _predictions_for_thresholds(
    probability_rows: list[dict[str, float]],
    thresholds: dict[str, float],
    *,
    target_mode: str,
) -> list[str]:
    return [_decision(row, thresholds, target_mode=target_mode) for row in probability_rows]


def _threshold_score(summary: dict[str, Any], *, limited_exact: bool, fpr_budget: float) -> tuple[Any, ...]:
    fpr = _safe_float(summary.get("benign_like_false_positive_rate"), 1.0)
    threat_f1 = _safe_float(summary.get("threat_positive_f1"))
    threat_recall = _safe_float(summary.get("threat_positive_recall"))
    suspicious = _safe_float(summary.get("suspicious_recall"), threat_recall)
    malicious = _safe_float(summary.get("malicious_recall"), threat_recall)
    return (
        1 if fpr <= fpr_budget else 0,
        0 if limited_exact else 1,
        threat_f1 - 0.35 * fpr,
        suspicious,
        malicious,
        threat_recall,
        -fpr,
    )


def _select_thresholds(
    prepared: dict[str, Any],
    *,
    y_true: list[str],
    probability_rows: list[dict[str, float]],
    target_mode: str,
    fpr_budget: float,
) -> dict[str, Any]:
    labels_order, threat_labels = _labels_order(target_mode, y_true)
    candidates: list[dict[str, Any]] = []
    for thresholds in _threshold_grid(target_mode):
        predictions = _predictions_for_thresholds(probability_rows, thresholds, target_mode=target_mode)
        metrics = _metric_bundle(
            prepared,
            y_true=y_true,
            predictions=predictions,
            labels_order=labels_order,
            threat_labels=threat_labels,
        )
        summary = _profile_summary(metrics)
        candidates.append(
            {
                "thresholds": thresholds,
                "summary": summary,
                "metrics": metrics,
                "within_fpr_budget": _safe_float(summary.get("benign_like_false_positive_rate"), 1.0) <= fpr_budget,
            }
        )
    limited_exact = target_mode == "binary"
    selected = max(
        candidates,
        key=lambda item: _threshold_score(item["summary"], limited_exact=limited_exact, fpr_budget=fpr_budget),
    )
    return {
        "selected_thresholds": selected["thresholds"],
        "selection_fpr_budget": fpr_budget,
        "calibration_summary": selected["summary"],
        "candidate_count": len(candidates),
        "within_fpr_budget_candidates": sum(1 for item in candidates if item["within_fpr_budget"]),
    }


def _probability_rows_for_model(model: Any, frame: Any, indices: list[int]) -> tuple[list[dict[str, float]], list[str], Any]:
    probabilities = model.predict_proba(frame.iloc[indices])
    classes = _classes(model)
    return _probability_rows(probabilities, classes), classes, probabilities


def _fit_single_stage_candidate(
    prepared: dict[str, Any],
    augmented: dict[str, Any],
    spec: dict[str, Any],
) -> dict[str, Any]:
    frame = augmented["frame"]
    target_values = _map_labels(prepared["y"], spec["target_mode"])
    split = _split_train_calibration_indices(prepared, target_values)
    fit_idx = split["fit_idx"]
    calibration_idx = split["calibration_idx"]
    y_fit = [target_values[index] for index in fit_idx]
    y_calibration = [target_values[index] for index in calibration_idx]
    y_test = [target_values[index] for index in prepared["test_idx"]]
    if len(set(y_fit)) < 2 or len(set(y_calibration)) < 2:
        return {
            "name": spec["name"],
            "status": "skipped",
            "message": "Not enough train-internal class diversity for threshold selection.",
            "target_mode": spec["target_mode"],
        }
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
    calibration_rows, classes, calibration_probabilities = _probability_rows_for_model(model, frame, calibration_idx)
    selection = _select_thresholds(
        prepared,
        y_true=y_calibration,
        probability_rows=calibration_rows,
        target_mode=spec["target_mode"],
        fpr_budget=float(spec.get("selection_fpr_budget", FPR_BUDGET)),
    )
    test_rows, test_classes, test_probabilities = _probability_rows_for_model(model, frame, prepared["test_idx"])
    labels_order, threat_labels = _labels_order(spec["target_mode"], y_test)
    test_predictions = _predictions_for_thresholds(
        test_rows,
        selection["selected_thresholds"],
        target_mode=spec["target_mode"],
    )
    test_metrics = _metric_bundle(
        prepared,
        y_true=y_test,
        predictions=test_predictions,
        labels_order=labels_order,
        threat_labels=threat_labels,
    )
    return {
        "name": spec["name"],
        "status": "evaluated",
        "target_mode": spec["target_mode"],
        "model_type": spec["model_type"],
        "sample_weighting": weight_summary,
        "training_seconds": training_seconds,
        "threshold_selection": {
            **split,
            **selection,
            "selected_on": "train_internal_calibration",
        },
        "summary": _profile_summary(test_metrics),
        "metrics": test_metrics,
        "calibration": _calibration_report(y_test, test_probabilities, test_classes, threat_labels=threat_labels),
        "calibration_selection_diagnostics": _calibration_report(
            y_calibration,
            calibration_probabilities,
            classes,
            threat_labels=threat_labels,
        ),
        "limited_exact_class_output": spec["target_mode"] == "binary",
        "_predictions": test_predictions,
        "_y_test": y_test,
        "_test_probability_rows": test_rows,
        "_calibration_probability_rows": calibration_rows,
        "_y_calibration": y_calibration,
        "_calibration_idx": calibration_idx,
        "_test_idx": list(prepared["test_idx"]),
    }


def _fit_hierarchical_candidate(
    prepared: dict[str, Any],
    augmented: dict[str, Any],
    spec: dict[str, Any],
) -> dict[str, Any]:
    frame = augmented["frame"]
    y_flat = prepared["y"]
    stage1_values = _map_labels(y_flat, "binary")
    split = _split_train_calibration_indices(prepared, stage1_values)
    fit_idx = split["fit_idx"]
    calibration_idx = split["calibration_idx"]
    y_fit_stage1 = [stage1_values[index] for index in fit_idx]
    if len(set(y_fit_stage1)) < 2:
        return {"name": spec["name"], "status": "skipped", "message": "Not enough stage-1 class diversity."}
    weights, weight_summary = _noise_reduced_weights(prepared["labels"], spec["weight_strategy"])
    stage1 = _build_pipeline_for_columns(
        prepared["imports"],
        model_type="extra_trees",
        class_weight=None,
        numeric_features=augmented["numeric_features"],
        categorical_features=augmented["categorical_features"],
    )
    started = time.perf_counter()
    stage1.fit(frame.iloc[fit_idx], y_fit_stage1, model__sample_weight=[weights[index] for index in fit_idx])
    stage2_fit_idx = [index for index in fit_idx if y_flat[index] in THREAT_LABELS]
    if len(stage2_fit_idx) < 3 or len({y_flat[index] for index in stage2_fit_idx}) < 2:
        return {"name": spec["name"], "status": "skipped", "message": "Not enough stage-2 threat class diversity."}
    stage2 = _build_pipeline_for_columns(
        prepared["imports"],
        model_type="extra_trees",
        class_weight="balanced",
        numeric_features=augmented["numeric_features"],
        categorical_features=augmented["categorical_features"],
    )
    stage2.fit(
        frame.iloc[stage2_fit_idx],
        [y_flat[index] for index in stage2_fit_idx],
        model__sample_weight=[weights[index] for index in stage2_fit_idx],
    )
    training_seconds = round(time.perf_counter() - started, 4)

    def hierarchical_probability_rows(indices: list[int]) -> tuple[list[dict[str, float]], Any, list[str]]:
        stage1_probs = stage1.predict_proba(frame.iloc[indices])
        stage1_classes = _classes(stage1)
        stage2_probs = stage2.predict_proba(frame.iloc[indices])
        stage2_classes = _classes(stage2)
        rows: list[dict[str, float]] = []
        for first, second in zip(stage1_probs, stage2_probs, strict=False):
            first_row = {label: float(value) for label, value in zip(stage1_classes, first, strict=False)}
            second_row = {label: float(value) for label, value in zip(stage2_classes, second, strict=False)}
            threat = _safe_float(first_row.get("threat_positive"))
            suspicious = threat * _safe_float(second_row.get("suspicious"))
            malicious = threat * _safe_float(second_row.get("malicious"))
            rows.append(
                {
                    "benign_like": _safe_float(first_row.get("benign_like")),
                    "suspicious": suspicious,
                    "malicious": malicious,
                }
            )
        return rows, stage1_probs, stage1_classes

    y_calibration = _map_labels([y_flat[index] for index in calibration_idx], "hierarchical")
    y_test = _map_labels([y_flat[index] for index in prepared["test_idx"]], "hierarchical")
    calibration_rows, calibration_probabilities, calibration_classes = hierarchical_probability_rows(calibration_idx)
    selection = _select_thresholds(
        prepared,
        y_true=y_calibration,
        probability_rows=calibration_rows,
        target_mode="hierarchical",
        fpr_budget=float(spec.get("selection_fpr_budget", FPR_BUDGET)),
    )
    test_rows, test_probabilities, test_classes = hierarchical_probability_rows(prepared["test_idx"])
    labels_order, threat_labels = _labels_order("hierarchical", y_test)
    test_predictions = _predictions_for_thresholds(
        test_rows,
        selection["selected_thresholds"],
        target_mode="hierarchical",
    )
    test_metrics = _metric_bundle(
        prepared,
        y_true=y_test,
        predictions=test_predictions,
        labels_order=labels_order,
        threat_labels=threat_labels,
    )
    return {
        "name": spec["name"],
        "status": "evaluated",
        "target_mode": "hierarchical",
        "model_type": spec["model_type"],
        "sample_weighting": weight_summary,
        "training_seconds": training_seconds,
        "threshold_selection": {
            **split,
            **selection,
            "selected_on": "train_internal_calibration",
        },
        "summary": _profile_summary(test_metrics),
        "metrics": test_metrics,
        "calibration": _calibration_report(
            _map_labels([y_flat[index] for index in prepared["test_idx"]], "binary"),
            test_probabilities,
            test_classes,
            threat_labels={"threat_positive"},
        ),
        "calibration_selection_diagnostics": _calibration_report(
            _map_labels([y_flat[index] for index in calibration_idx], "binary"),
            calibration_probabilities,
            calibration_classes,
            threat_labels={"threat_positive"},
        ),
        "limited_exact_class_output": False,
        "_predictions": test_predictions,
        "_y_test": y_test,
        "_test_probability_rows": test_rows,
        "_calibration_probability_rows": calibration_rows,
        "_y_calibration": y_calibration,
        "_calibration_idx": calibration_idx,
        "_test_idx": list(prepared["test_idx"]),
    }


def _fit_candidate(prepared: dict[str, Any], augmented: dict[str, Any], spec: dict[str, Any]) -> dict[str, Any]:
    if spec["target_mode"] == "hierarchical":
        return _fit_hierarchical_candidate(prepared, augmented, spec)
    return _fit_single_stage_candidate(prepared, augmented, spec)


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
                "pattern": f"app={log.app or '-'}|action={log.action or '-'}|port={log.dst_port or '-'}",
                "family": str(row.get("v337_traffic_family") or "unknown"),
                "source_name": _source_name(log),
            }
        )
    return {
        "false_positive_count": len(rows),
        "top_patterns": Counter(row["pattern"] for row in rows).most_common(12),
        "top_traffic_families": Counter(row["family"] for row in rows).most_common(10),
        "top_sources": Counter(row["source_name"] for row in rows).most_common(10),
    }


def _suspicious_miss_patterns(
    prepared: dict[str, Any],
    augmented: dict[str, Any],
    *,
    predictions: list[str],
    y_true: list[str],
) -> dict[str, Any]:
    frame = augmented["frame"]
    rows = []
    for position, (actual, predicted) in enumerate(zip(y_true, predictions, strict=False)):
        if actual != "suspicious" or predicted == "suspicious":
            continue
        index = prepared["test_idx"][position]
        log = prepared["test_logs"][position]
        row = frame.iloc[index]
        rows.append(
            {
                "pattern": f"app={log.app or '-'}|action={log.action or '-'}|port={log.dst_port or '-'}",
                "family": str(row.get("v337_traffic_family") or "unknown"),
                "predicted": predicted,
            }
        )
    return {
        "suspicious_miss_count": len(rows),
        "top_patterns": Counter(row["pattern"] for row in rows).most_common(12),
        "top_traffic_families": Counter(row["family"] for row in rows).most_common(10),
        "predicted_as": dict(Counter(row["predicted"] for row in rows)),
    }


def _split_strategy_rows(prepared: dict[str, Any], augmented: dict[str, Any], strategies: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for strategy in strategies:
        if strategy.get("status") != "evaluated":
            rows.append({key: strategy.get(key) for key in ["name", "status", "message", "target_mode"]})
            continue
        target_mode = str(strategy.get("target_mode") or "flat")
        y_test = strategy.get("_y_test") or prepared["y_test"]
        labels_order, threat_labels = _labels_order(target_mode, y_test)
        predictions = strategy.get("_predictions") or []
        rows.append(
            {
                "name": strategy["name"],
                "status": strategy["status"],
                "target_mode": target_mode,
                "model_type": strategy.get("model_type"),
                "summary": strategy["summary"],
                "calibration": strategy.get("calibration") or {},
                "threshold_selection": strategy.get("threshold_selection") or {},
                "limited_exact_class_output": bool(strategy.get("limited_exact_class_output")),
                "labels_order": labels_order,
                "false_positive_patterns": _false_positive_patterns(
                    prepared,
                    augmented,
                    predictions=predictions,
                    y_true=y_test,
                    threat_labels=threat_labels,
                ),
                "suspicious_miss_patterns": _suspicious_miss_patterns(
                    prepared,
                    augmented,
                    predictions=predictions,
                    y_true=y_test,
                )
                if target_mode != "binary"
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
        calibrations = []
        selection_calibrations = []
        fp_patterns = Counter()
        miss_patterns = Counter()
        families = Counter()
        limited_exact = False
        threshold_rows: list[dict[str, Any]] = []
        for split in split_results:
            for row in split.get("strategies", []):
                if row.get("name") != name or row.get("status") != "evaluated":
                    continue
                limited_exact = limited_exact or bool(row.get("limited_exact_class_output"))
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
                selection_calibrations.append((row.get("threshold_selection") or {}).get("calibration_summary") or {})
                for pattern, count in (row.get("false_positive_patterns") or {}).get("top_patterns") or []:
                    fp_patterns[str(pattern)] += int(count)
                for pattern, count in (row.get("suspicious_miss_patterns") or {}).get("top_patterns") or []:
                    miss_patterns[str(pattern)] += int(count)
                for family, count in (row.get("false_positive_patterns") or {}).get("top_traffic_families") or []:
                    families[str(family)] += int(count)
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
            "limited_exact_class_output": limited_exact,
            "stability": stability,
            "best_calibration": best_calibration,
            "threshold_selection": {
                "used_test_for_threshold_selection": any(
                    bool(row.get("used_test_for_threshold_selection")) for row in threshold_rows
                ),
                "selected_on": sorted({str(row.get("selected_on")) for row in threshold_rows if row.get("selected_on")}),
                "average_calibration_rows": round(
                    sum(int(row.get("calibration_rows") or 0) for row in threshold_rows) / len(threshold_rows),
                    2,
                )
                if threshold_rows
                else 0,
                "within_fpr_budget_candidates": sum(int(row.get("within_fpr_budget_candidates") or 0) for row in threshold_rows),
                "top_selected_thresholds": Counter(
                    json.dumps(row.get("selected_thresholds") or {}, sort_keys=True) for row in threshold_rows
                ).most_common(5),
                "selection_calibration_summary": {
                    "min_threat_f1": min(
                        (_safe_float(row.get("threat_positive_f1")) for row in selection_calibrations),
                        default=0,
                    ),
                    "max_fpr": max(
                        (_safe_float(row.get("benign_like_false_positive_rate")) for row in selection_calibrations),
                        default=0,
                    ),
                },
            },
            "top_false_positive_patterns": fp_patterns.most_common(12),
            "top_false_positive_traffic_families": families.most_common(10),
            "top_suspicious_miss_patterns": miss_patterns.most_common(12),
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
            0 if (item.get("threshold_selection") or {}).get("used_test_for_threshold_selection") else 1,
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


def _render_report(result: dict[str, Any]) -> str:
    rows = []
    for name, item in result.get("strategy_comparison", {}).items():
        ranges = item.get("stability", {}).get("metric_ranges", {})
        rows.append(
            "| {name} | {limited} | {passed} | {f1_min}-{f1_max} | {fpr_min}-{fpr_max} | {susp_min}-{susp_max} | {mal_min}-{mal_max} | {cal} |".format(
                name=name,
                limited="yes" if item.get("limited_exact_class_output") else "no",
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
    return f"""# v3.38 Calibrated SOC Queue Threshold Search

Generated: {result.get("generated_at")}

This report is diagnostic only. Thresholds are selected on a train-internal calibration slice and evaluated on held-out test splits. No model was activated, no artifact was written, and response automation stayed disabled.

## Best Diagnostic Candidate

- Candidate: {result.get("best_strategy")}
- Readiness: {result.get("readiness", {}).get("decision")}
- Checks passed: {result.get("readiness", {}).get("passed")} / {result.get("readiness", {}).get("total")}
- Blockers: {result.get("readiness", {}).get("blockers")}

## Strategy Comparison

| Strategy | Limited Exact Classes | Passing Splits | Threat F1 Range | Benign FPR Range | Suspicious Recall Range | Malicious Recall Range | Calibration |
| --- | --- | ---: | --- | --- | --- | --- | --- |
{chr(10).join(rows)}

## Safety

```json
{json.dumps(result.get("safety"), indent=2, default=str)}
```
"""


def run_v338_calibrated_threshold_search(
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
        frame, meta = enrich_v337_features(prepared)
        augmented = {"frame": frame, **meta}
        strategies = [_fit_candidate(prepared, augmented, spec) for spec in _candidate_specs()]
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
        "blockers": ["no evaluated v3.38 strategy"],
        "checks": [],
    }
    after_runs = int(db.scalar(select(func.count(MLModelRun.id))) or 0)
    after_responses = int(db.scalar(select(func.count(ResponseAction.id))) or 0)

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    stamp = _stamp()
    report_path = output_path / f"v3_38_calibrated_threshold_search_{stamp}.md"
    latest_path = output_path / V338_LATEST
    result: dict[str, Any] = {
        "ok": True,
        "status": "completed",
        "phase": "v3.38",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "runtime_seconds": round(time.perf_counter() - started, 4),
        "feature_generation_seconds": base.get("feature_generation_seconds"),
        "fpr_budget": FPR_BUDGET,
        "splits": V335_SPLITS,
        "strategy_comparison": comparison,
        "best_strategy": best_strategy,
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
        "latest_summary_path": str(latest_path),
    }
    report_path.write_text(_render_report(result), encoding="utf-8")
    latest_path.write_text(
        json.dumps({key: value for key, value in result.items() if key != "split_results"}, indent=2, default=str),
        encoding="utf-8",
    )
    return result
