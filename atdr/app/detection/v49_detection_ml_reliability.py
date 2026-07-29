from __future__ import annotations

import json
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from atdr.app.detection import v398_independent_holdout_validation as frozen
from atdr.app.detection.v330_detection_ml_quality import OUTPUT_DIR
from atdr.app.detection.v331_noise_reduction import (
    _build_pipeline_for_columns,
    _classes,
    _noise_reduced_weights,
)


V49_VERSION = "v4.9-reliability-lock-v1"
V49_LATEST = "v4_9_model_comparison_latest.json"
V49_SPLITS = (
    "temporal_holdout",
    "network_zone_holdout",
    "random_seed_7",
    "random_seed_17",
    "random_seed_42",
)
PREDECLARED_CANDIDATE = "calibrated_binary_extra_trees_strong_benign"
STRICT_GATES = {
    "benign_like_false_positive_rate_max": 0.10,
    "threat_positive_f1_min": 0.85,
    "suspicious_recall_min": 0.80,
    "malicious_recall_min": 0.80,
    "expected_calibration_error_max": 0.10,
    "max_confidence_accuracy_gap_max": 0.15,
}
THRESHOLD_GRID = tuple(round(value / 100, 2) for value in range(5, 96, 5))


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _queue_targets(original_labels: list[str]) -> list[str]:
    return [
        "needs_review" if label in {"needs_context", "suspicious", "malicious"} else "non_threat"
        for label in original_labels
    ]


def _three_class_targets(original_labels: list[str]) -> list[str]:
    mapping = {
        "benign": "benign_like",
        "benign_unusual": "benign_like",
        "needs_context": "suspicious",
        "suspicious": "suspicious",
        "malicious": "malicious",
    }
    return [mapping[label] for label in original_labels]


def _queue_scores(model: Any, frame: Any, indices: list[int], positive_classes: set[str]) -> list[float]:
    classes = _classes(model)
    positions = [position for position, label in enumerate(classes) if label in positive_classes]
    if not positions:
        return [0.0 for _ in indices]
    probabilities = model.predict_proba(frame.iloc[indices])
    return [min(1.0, sum(float(row[position]) for position in positions)) for row in probabilities]


def _fit_frozen_calibrator(
    base_model: Any,
    frame: Any,
    calibration_idx: list[int],
    targets: list[str],
    *,
    method: str = "sigmoid",
) -> tuple[Any, str]:
    y_calibration = [targets[index] for index in calibration_idx]
    if len(set(y_calibration)) < 2:
        return base_model, "skipped_calibration_partition_has_one_class"
    model_classes = set(_classes(base_model))
    calibration_classes = set(y_calibration)
    if model_classes and calibration_classes != model_classes:
        return (
            base_model,
            "skipped_calibration_partition_missing_model_class",
        )
    class_support = Counter(y_calibration)
    if method == "isotonic" and (len(y_calibration) < 100 or min(class_support.values()) < 20):
        return base_model, "skipped_isotonic_insufficient_calibration_support"
    try:
        from sklearn.calibration import CalibratedClassifierCV

        try:
            from sklearn.frozen import FrozenEstimator

            model = CalibratedClassifierCV(FrozenEstimator(base_model), method=method)
        except ImportError:  # pragma: no cover - older supported sklearn
            model = CalibratedClassifierCV(base_model, method=method, cv="prefit")
        model.fit(frame.iloc[calibration_idx], y_calibration)
    except (ValueError, TypeError, IndexError) as exc:
        return base_model, f"skipped_calibration:{type(exc).__name__}"
    return model, f"{method}_on_dedicated_calibration_partition"


def select_v49_threshold(y_true: list[str], scores: list[float]) -> dict[str, Any]:
    """Select a queue threshold without consulting final-test labels."""

    if not y_true or len(y_true) != len(scores):
        return {
            "status": "failed",
            "selected_threshold": 0.5,
            "selected_on": "threshold_selection_partition_only",
            "threshold_rows": len(y_true),
            "used_final_test_labels": False,
            "gate_feasible_on_threshold_partition": False,
        }
    candidates: list[dict[str, Any]] = []
    for threshold in THRESHOLD_GRID:
        predictions = ["needs_review" if score >= threshold else "non_threat" for score in scores]
        metrics = frozen._binary_metrics(y_true, predictions)
        recall = float(metrics["queue_recall"])
        fpr = float(metrics["benign_like_false_positive_rate"])
        f1 = float(metrics["queue_f1"])
        feasible = recall >= STRICT_GATES["suspicious_recall_min"] and fpr <= STRICT_GATES[
            "benign_like_false_positive_rate_max"
        ]
        selection_score = f1 + (0.15 * recall) - (0.60 * fpr)
        candidates.append(
            {
                "threshold": threshold,
                "feasible": feasible,
                "selection_score": round(selection_score, 6),
                "metrics": metrics,
            }
        )
    feasible_candidates = [item for item in candidates if item["feasible"]]
    pool = feasible_candidates or candidates
    selected = max(
        pool,
        key=lambda item: (
            float(item["selection_score"]),
            float(item["metrics"]["queue_f1"]),
            -float(item["metrics"]["benign_like_false_positive_rate"]),
            item["threshold"],
        ),
    )
    return {
        "status": "selected",
        "selected_threshold": selected["threshold"],
        "selected_on": "threshold_selection_partition_only",
        "threshold_rows": len(y_true),
        "used_final_test_labels": False,
        "gate_feasible_on_threshold_partition": bool(feasible_candidates),
        "selected_metrics": selected["metrics"],
        "candidate_count": len(candidates),
    }


def _classification_diagnostics(y_true: list[str], predictions: list[str]) -> dict[str, Any]:
    from sklearn.metrics import confusion_matrix, f1_score

    labels = sorted(set(y_true) | set(predictions))
    return {
        "labels": labels,
        "confusion_matrix": confusion_matrix(y_true, predictions, labels=labels).tolist(),
        "macro_f1": round(float(f1_score(y_true, predictions, labels=labels, average="macro", zero_division=0)), 4),
        "weighted_f1": round(
            float(f1_score(y_true, predictions, labels=labels, average="weighted", zero_division=0)), 4
        ),
    }


def _fit_candidate(
    dataset: dict[str, Any],
    partition: dict[str, Any],
    *,
    model_type: str,
    targets: list[str],
    positive_classes: set[str],
    class_weight: str | None,
    weight_strategy: str,
    calibrate: bool,
    calibration_method: str = "sigmoid",
) -> dict[str, Any]:
    fit_idx = partition["fit_idx"]
    calibration_idx = partition["calibration_idx"]
    threshold_idx = partition["threshold_idx"]
    final_idx = partition["final_test_idx"]
    y_fit = [targets[index] for index in fit_idx]
    if len(set(y_fit)) < 2:
        return {"status": "skipped", "message": "Fit partition contains fewer than two target classes."}

    pipeline = _build_pipeline_for_columns(
        dataset["imports"],
        model_type=model_type,
        class_weight=class_weight,
        numeric_features=dataset["feature_meta"]["numeric_features"],
        categorical_features=dataset["feature_meta"]["categorical_features"],
    )
    weights, weighting = _noise_reduced_weights(dataset["labels"], weight_strategy)
    fit_kwargs: dict[str, Any] = {}
    if weights is not None:
        fit_kwargs["model__sample_weight"] = [weights[index] for index in fit_idx]
    started = time.perf_counter()
    pipeline.fit(dataset["frame"].iloc[fit_idx], y_fit, **fit_kwargs)
    model: Any = pipeline
    requested_calibration_method = calibration_method
    applied_calibration_method = "none"
    if calibrate:
        model, applied_calibration_method = _fit_frozen_calibrator(
            pipeline,
            dataset["frame"],
            calibration_idx,
            targets,
            method=requested_calibration_method,
        )

    threshold_scores = _queue_scores(model, dataset["frame"], threshold_idx, positive_classes)
    final_scores = _queue_scores(model, dataset["frame"], final_idx, positive_classes)
    threshold_selection = select_v49_threshold(
        [dataset["targets"][index] for index in threshold_idx],
        threshold_scores,
    )
    direct_predictions = [str(value) for value in model.predict(dataset["frame"].iloc[final_idx])]
    return {
        "status": "evaluated",
        "model": model,
        "threshold_scores": threshold_scores,
        "final_scores": final_scores,
        "threshold_selection": threshold_selection,
        "direct_predictions": direct_predictions,
        "training_seconds": round(time.perf_counter() - started, 4),
        "calibration_method": applied_calibration_method,
        "sample_weighting": weighting,
    }


def _strict_calibration(calibration: dict[str, Any]) -> dict[str, Any]:
    result = dict(calibration)
    result["legacy_gate_passed"] = bool(result.get("passed"))
    ece = float(result.get("expected_calibration_error", 1.0))
    gap = float(result.get("max_confidence_accuracy_gap", 1.0))
    result["passed"] = bool(
        ece <= STRICT_GATES["expected_calibration_error_max"]
        and gap <= STRICT_GATES["max_confidence_accuracy_gap_max"]
    )
    result["status"] = "passed" if result["passed"] else "weak"
    result["targets"] = {
        "expected_calibration_error": f"<= {STRICT_GATES['expected_calibration_error_max']}",
        "max_confidence_accuracy_gap": f"<= {STRICT_GATES['max_confidence_accuracy_gap_max']}",
    }
    return result


def _group_diagnostics(
    dataset: dict[str, Any],
    partition: dict[str, Any],
    predictions: list[str],
) -> dict[str, Any]:
    indices = partition["final_test_idx"]
    targets = [dataset["targets"][index] for index in indices]
    source_groups: dict[str, list[int]] = defaultdict(list)
    attack_groups: dict[str, list[int]] = defaultdict(list)
    for local_index, absolute_index in enumerate(indices):
        row = dataset["rows"][absolute_index]
        source_groups[str(row.get("source_name") or "unassigned")].append(local_index)
        if targets[local_index] == "needs_review":
            attack_groups[str(row.get("attack_type") or "unknown")].append(local_index)

    per_source: dict[str, Any] = {}
    for source, positions in sorted(source_groups.items()):
        per_source[source] = frozen._binary_metrics(
            [targets[position] for position in positions],
            [predictions[position] for position in positions],
        )
    per_attack = {
        attack_type: {
            "support": len(positions),
            "recall": round(
                sum(1 for position in positions if predictions[position] == "needs_review") / len(positions), 4
            ),
        }
        for attack_type, positions in sorted(attack_groups.items())
        if positions
    }
    return {"per_source": per_source, "per_attack": per_attack}


def _evaluate(
    dataset: dict[str, Any],
    partition: dict[str, Any],
    *,
    name: str,
    scores: list[float],
    threshold_selection: dict[str, Any],
    seed: int,
    details: dict[str, Any],
) -> dict[str, Any]:
    result = frozen._evaluate_scores(
        dataset,
        partition,
        name=name,
        scores=scores,
        threshold_selection=threshold_selection,
        seed=seed,
        details={
            **details,
            "fit_partition_only": True,
            "calibration_partition_only": True,
            "threshold_partition_only": True,
            "final_labels_used_for_tuning": False,
            "active_artifact_written": False,
        },
    )
    result["calibration"] = _strict_calibration(result["calibration"])
    result["confusion_matrix"] = {
        "true_positive": result["metrics"]["true_positive"],
        "false_positive": result["metrics"]["false_positive"],
        "true_negative": result["metrics"]["true_negative"],
        "false_negative": result["metrics"]["false_negative"],
    }
    result["group_diagnostics"] = _group_diagnostics(dataset, partition, result["_predictions"])
    return result


def _fit_hierarchical(dataset: dict[str, Any], partition: dict[str, Any]) -> dict[str, Any]:
    stage_one = _fit_candidate(
        dataset,
        partition,
        model_type="extra_trees",
        targets=dataset["targets"],
        positive_classes={"needs_review"},
        class_weight=None,
        weight_strategy="strong_benign",
        calibrate=True,
    )
    if stage_one.get("status") != "evaluated":
        return stage_one

    fit_idx = [
        index
        for index in partition["fit_idx"]
        if dataset["original_labels"][index] in {"suspicious", "malicious"}
    ]
    severity_targets = [dataset["original_labels"][index] for index in fit_idx]
    if len(set(severity_targets)) < 2:
        stage_one["severity_status"] = "skipped_insufficient_suspicious_malicious_fit_support"
        return stage_one
    stage_two = _build_pipeline_for_columns(
        dataset["imports"],
        model_type="extra_trees",
        class_weight="balanced",
        numeric_features=dataset["feature_meta"]["numeric_features"],
        categorical_features=dataset["feature_meta"]["categorical_features"],
    )
    stage_two.fit(dataset["frame"].iloc[fit_idx], severity_targets)
    final_idx = partition["final_test_idx"]
    severity_predictions = [str(value) for value in stage_two.predict(dataset["frame"].iloc[final_idx])]
    mapped_truth = _three_class_targets([dataset["original_labels"][index] for index in final_idx])
    threshold = float(stage_one["threshold_selection"]["selected_threshold"])
    combined = [
        severity if score >= threshold else "benign_like"
        for score, severity in zip(stage_one["final_scores"], severity_predictions, strict=True)
    ]
    stage_one["severity_status"] = "evaluated"
    stage_one["classification_diagnostics"] = _classification_diagnostics(mapped_truth, combined)
    return stage_one


def _public_strategy(strategy: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in strategy.items() if not key.startswith("_") and key != "model"}


def _run_split(dataset: dict[str, Any], *, split_mode: str) -> dict[str, Any]:
    partition = frozen.build_frozen_partition(dataset["rows"], split_mode=split_mode)
    leakage = frozen.audit_partition_leakage(dataset["rows"], partition)
    if not leakage.get("passed"):
        return {
            "split_mode": split_mode,
            "status": "failed_closed",
            "partition": partition,
            "leakage_audit": leakage,
            "strategies": [],
        }

    seed = (
        490
        if split_mode == "temporal_holdout"
        else 498
        if split_mode == "source_holdout"
        else 499
        if split_mode == "network_zone_holdout"
        else int(split_mode.rsplit("_", 1)[-1])
    )
    final_idx = partition["final_test_idx"]
    threshold_idx = partition["threshold_idx"]
    strategies: list[dict[str, Any]] = []
    fitted_candidates: dict[str, dict[str, Any]] = {}

    specs = [
        {
            "name": "binary_extra_trees_balanced",
            "model_type": "extra_trees",
            "targets": dataset["targets"],
            "positive_classes": {"needs_review"},
            "class_weight": "balanced",
            "weight_strategy": "none",
            "calibrate": False,
        },
        {
            "name": "binary_extra_trees_lower_threat_weight",
            "model_type": "extra_trees",
            "targets": dataset["targets"],
            "positive_classes": {"needs_review"},
            "class_weight": None,
            "weight_strategy": "lower_threat",
            "calibrate": False,
        },
        {
            "name": "binary_extra_trees_strong_benign",
            "model_type": "extra_trees",
            "targets": dataset["targets"],
            "positive_classes": {"needs_review"},
            "class_weight": None,
            "weight_strategy": "strong_benign",
            "calibrate": False,
        },
        {
            "name": PREDECLARED_CANDIDATE,
            "model_type": "extra_trees",
            "targets": dataset["targets"],
            "positive_classes": {"needs_review"},
            "class_weight": None,
            "weight_strategy": "strong_benign",
            "calibrate": True,
        },
        {
            "name": "calibrated_binary_logistic_regression",
            "model_type": "logistic_regression",
            "targets": dataset["targets"],
            "positive_classes": {"needs_review"},
            "class_weight": "balanced",
            "weight_strategy": "none",
            "calibrate": True,
        },
        {
            "name": "flat_5class_extra_trees",
            "model_type": "extra_trees",
            "targets": dataset["original_labels"],
            "positive_classes": {"needs_context", "suspicious", "malicious"},
            "class_weight": "balanced",
            "weight_strategy": "none",
            "calibrate": False,
        },
        {
            "name": "three_class_soc_queue_extra_trees",
            "model_type": "extra_trees",
            "targets": _three_class_targets(dataset["original_labels"]),
            "positive_classes": {"suspicious", "malicious"},
            "class_weight": "balanced",
            "weight_strategy": "strong_benign",
            "calibrate": False,
        },
    ]
    for position, spec in enumerate(specs):
        fitted = _fit_candidate(
            dataset,
            partition,
            model_type=spec["model_type"],
            targets=spec["targets"],
            positive_classes=spec["positive_classes"],
            class_weight=spec["class_weight"],
            weight_strategy=spec["weight_strategy"],
            calibrate=spec["calibrate"],
        )
        if fitted.get("status") != "evaluated":
            strategies.append({"name": spec["name"], **fitted})
            continue
        fitted_candidates[spec["name"]] = fitted
        evaluated = _evaluate(
            dataset,
            partition,
            name=spec["name"],
            scores=fitted["final_scores"],
            threshold_selection=fitted["threshold_selection"],
            seed=seed + position,
            details={
                "model_type": spec["model_type"],
                "target_mode": (
                    "flat_5class"
                    if spec["name"].startswith("flat_5class")
                    else "three_class_soc_queue"
                    if spec["name"].startswith("three_class")
                    else "binary_soc_queue"
                ),
                "calibration_method": fitted["calibration_method"],
                "sample_weighting": fitted["sample_weighting"],
                "training_seconds": fitted["training_seconds"],
            },
        )
        if spec["name"].startswith("flat_5class"):
            evaluated["classification_diagnostics"] = _classification_diagnostics(
                [dataset["original_labels"][index] for index in final_idx],
                fitted["direct_predictions"],
            )
        elif spec["name"].startswith("three_class"):
            evaluated["classification_diagnostics"] = _classification_diagnostics(
                [_three_class_targets(dataset["original_labels"])[index] for index in final_idx],
                fitted["direct_predictions"],
            )
        strategies.append(evaluated)

    hierarchical = _fit_hierarchical(dataset, partition)
    if hierarchical.get("status") == "evaluated":
        hierarchy_result = _evaluate(
            dataset,
            partition,
            name="hierarchical_two_stage_extra_trees",
            scores=hierarchical["final_scores"],
            threshold_selection=hierarchical["threshold_selection"],
            seed=seed + 20,
            details={
                "model_type": "extra_trees_two_stage",
                "target_mode": "hierarchical_soc_queue_then_severity",
                "calibration_method": hierarchical["calibration_method"],
                "severity_status": hierarchical.get("severity_status"),
                "sample_weighting": hierarchical["sample_weighting"],
            },
        )
        if hierarchical.get("classification_diagnostics"):
            hierarchy_result["classification_diagnostics"] = hierarchical["classification_diagnostics"]
        strategies.append(hierarchy_result)
    else:
        strategies.append({"name": "hierarchical_two_stage_extra_trees", **hierarchical})

    rule_final = frozen._rule_scores(dataset["logs"], final_idx)
    rule_result = _evaluate(
        dataset,
        partition,
        name="deterministic_rules_baseline",
        scores=rule_final,
        threshold_selection=frozen._fixed_threshold(
            frozen.RULE_QUEUE_THRESHOLD,
            policy="versioned_rule_pack_minimum_score",
        ),
        seed=seed + 30,
        details={"ml_anomaly_rule_excluded": True, "catalog_version": "atdr_rule_catalog_v4.9.0"},
    )
    strategies.append(rule_result)

    anomaly = frozen._fit_anomaly_candidate(dataset, partition)
    anomaly_threshold = select_v49_threshold(
        [dataset["targets"][index] for index in threshold_idx],
        anomaly["threshold_scores"],
    )
    anomaly_result = _evaluate(
        dataset,
        partition,
        name="isolation_forest_baseline",
        scores=anomaly["final_scores"],
        threshold_selection=anomaly_threshold,
        seed=seed + 31,
        details={"scaling": anomaly["scaling"], "model_artifact_written": False},
    )
    strategies.append(anomaly_result)

    primary = next((item for item in strategies if item.get("name") == PREDECLARED_CANDIDATE), None)
    primary_fitted = fitted_candidates.get(PREDECLARED_CANDIDATE)
    if primary and primary.get("status") == "evaluated" and primary_fitted:
        rule_threshold = frozen._rule_scores(dataset["logs"], threshold_idx)
        hybrid_threshold_scores = [
            (0.55 * rule_score) + (0.20 * anomaly_score) + (0.25 * supervised_score)
            for rule_score, anomaly_score, supervised_score in zip(
                rule_threshold,
                anomaly["threshold_scores"],
                primary_fitted["threshold_scores"],
                strict=True,
            )
        ]
        hybrid_final_scores = [
            (0.55 * rule_score) + (0.20 * anomaly_score) + (0.25 * supervised_score)
            for rule_score, anomaly_score, supervised_score in zip(
                rule_final,
                anomaly["final_scores"],
                primary_fitted["final_scores"],
                strict=True,
            )
        ]
        strategies.append(
            _evaluate(
                dataset,
                partition,
                name="hybrid_rule_anomaly_supervised_decision_support",
                scores=hybrid_final_scores,
                threshold_selection=select_v49_threshold(
                    [dataset["targets"][index] for index in threshold_idx],
                    hybrid_threshold_scores,
                ),
                seed=seed + 32,
                details={
                    "weights": {"rule": 0.55, "isolation_forest": 0.20, "supervised": 0.25},
                    "decision_support_only": True,
                },
            )
        )

    return {
        "split_mode": split_mode,
        "status": "evaluated",
        "partition": {
            key: value
            for key, value in partition.items()
            if key not in {"fit_idx", "calibration_idx", "threshold_idx", "final_test_idx", "quarantined_idx"}
        },
        "partition_sizes": leakage["partition_sizes"],
        "partition_target_distributions": leakage["target_distributions"],
        "leakage_audit": leakage,
        "strategies": strategies,
    }


def _strategy_comparison(split_results: list[dict[str, Any]]) -> dict[str, Any]:
    comparison = frozen._strategy_comparison(split_results)
    for summary in comparison.values():
        rows = summary.get("split_metrics") or []
        split_gate_results = []
        for row in rows:
            calibration = row.get("calibration") or {}
            checks = {
                "threat_f1": float(row.get("queue_f1") or 0) >= STRICT_GATES["threat_positive_f1_min"],
                "fpr": float(row.get("benign_like_false_positive_rate") or 0)
                <= STRICT_GATES["benign_like_false_positive_rate_max"],
                "suspicious_recall": row.get("suspicious_recall") is not None
                and float(row["suspicious_recall"]) >= STRICT_GATES["suspicious_recall_min"],
                "malicious_recall": row.get("malicious_recall") is not None
                and float(row["malicious_recall"]) >= STRICT_GATES["malicious_recall_min"],
                "calibration": bool(calibration.get("passed")),
            }
            split_gate_results.append(
                {"split_mode": row["split_mode"], "passed": all(checks.values()), "checks": checks}
            )
        summary["strict_split_gates"] = split_gate_results
        summary["strict_passing_splits"] = sum(1 for item in split_gate_results if item["passed"])
        summary["strict_required_splits"] = len(V49_SPLITS)
    return comparison


def _best_diagnostic_strategy(comparison: dict[str, Any]) -> dict[str, Any] | None:
    candidates = []
    for name, summary in comparison.items():
        if name in {"majority_class_baseline"}:
            continue
        ranges = summary.get("metric_ranges") or {}

        def minimum(metric: str, default: float = 0.0) -> float:
            value = (ranges.get(metric) or {}).get("min")
            return float(default if value is None else value)

        def maximum(metric: str, default: float = 1.0) -> float:
            value = (ranges.get(metric) or {}).get("max")
            return float(default if value is None else value)

        candidates.append(
            (
                name,
                int(summary.get("strict_passing_splits") or 0),
                minimum("queue_f1"),
                -maximum("benign_like_false_positive_rate"),
                minimum("suspicious_recall"),
                minimum("malicious_recall"),
                int(summary.get("calibration_passed_splits") or 0),
            )
        )
    if not candidates:
        return None
    selected = max(candidates, key=lambda item: item[1:])
    return {
        "name": selected[0],
        "selection_role": "post_evaluation_diagnostic_only",
        "eligible_for_activation": False,
        "summary": comparison[selected[0]],
    }


def _locked_external_evidence(output_dir: Path) -> dict[str, Any]:
    path = output_dir / "v4_0_external_validation_latest.json"
    if not path.exists():
        return {
            "available": False,
            "status": "not_available_in_local_ignored_outputs",
            "used_for_tuning": False,
            "passed_v49_gates": False,
        }
    data = json.loads(path.read_text(encoding="utf-8"))
    stability = ((data.get("evaluation") or {}).get("stability") or {})
    worst = ((data.get("evaluation") or {}).get("worst_primary") or {})
    worst_metrics = worst.get("metrics") or {}
    calibration = worst.get("calibration") or {}
    passed = bool(
        float((stability.get("benign_like_false_positive_rate") or {}).get("maximum", 1))
        <= STRICT_GATES["benign_like_false_positive_rate_max"]
        and float((stability.get("threat_positive_f1") or {}).get("minimum", 0))
        >= STRICT_GATES["threat_positive_f1_min"]
        and float((stability.get("malicious_recall") or {}).get("minimum", 0))
        >= STRICT_GATES["malicious_recall_min"]
        and float(calibration.get("expected_calibration_error", 1))
        <= STRICT_GATES["expected_calibration_error_max"]
        and float(calibration.get("max_confidence_accuracy_gap", 1))
        <= STRICT_GATES["max_confidence_accuracy_gap_max"]
    )
    return {
        "available": True,
        "source_report": path.name,
        "dataset": data.get("dataset") or {},
        "protocol": data.get("protocol") or {},
        "aggregate_stability": stability,
        "worst_primary_metrics": worst_metrics,
        "worst_primary_calibration": calibration,
        "used_for_fit": False,
        "used_for_calibration": False,
        "used_for_threshold_selection": False,
        "used_for_tuning": False,
        "passed_v49_gates": passed,
    }


def _readiness(
    split_results: list[dict[str, Any]],
    comparison: dict[str, Any],
    external: dict[str, Any],
) -> dict[str, Any]:
    primary = comparison.get(PREDECLARED_CANDIDATE) or {}
    checks = [
        {
            "name": "all required internal splits evaluated",
            "passed": sum(1 for split in split_results if split.get("status") == "evaluated") == len(V49_SPLITS),
            "value": sum(1 for split in split_results if split.get("status") == "evaluated"),
            "target": len(V49_SPLITS),
        },
        {
            "name": "all leakage audits passed",
            "passed": all(bool((split.get("leakage_audit") or {}).get("passed")) for split in split_results),
            "value": sum(1 for split in split_results if bool((split.get("leakage_audit") or {}).get("passed"))),
            "target": len(V49_SPLITS),
        },
        {
            "name": "predeclared candidate passes every strict split gate",
            "passed": int(primary.get("strict_passing_splits") or 0) == len(V49_SPLITS),
            "value": int(primary.get("strict_passing_splits") or 0),
            "target": len(V49_SPLITS),
        },
        {
            "name": "locked external benchmark passes strict gates",
            "passed": bool(external.get("passed_v49_gates")),
            "value": bool(external.get("passed_v49_gates")),
            "target": True,
        },
        {
            "name": "final labels excluded from fit calibration and threshold selection",
            "passed": all(
                not bool((strategy.get("threshold_selection") or {}).get("used_final_test_labels"))
                for split in split_results
                for strategy in split.get("strategies") or []
            ),
            "value": False,
            "target": False,
        },
    ]
    return {
        "decision": "candidate_only",
        "checks_passed": sum(1 for check in checks if check["passed"]),
        "checks_total": len(checks),
        "checks": checks,
        "blockers": [check["name"] for check in checks if not check["passed"]],
        "production_promoted": False,
        "model_activated": False,
        "model_artifact_written": False,
        "response_automation_allowed": False,
        "real_firewall_blocking_enabled": False,
    }


def _render_model_report(result: dict[str, Any]) -> str:
    lines = [
        "# v4.9 Detection and ML Reliability Evaluation",
        "",
        f"Generated: `{result['generated_at']}`",
        "",
        "## Claim Boundary",
        "",
        "This is a read-only decision-support evaluation. It did not activate or promote a model and did not create response actions.",
        "",
        "## Dataset",
        "",
        f"- Reviewed latest labels: `{result['dataset']['rows']}`",
        f"- Weak/unreviewed latest labels excluded: `{result['dataset']['label_provenance'].get('weak_or_unreviewed_latest_rows_excluded')}`",
        f"- Duplicate normalized-log identities: `{result['dataset']['label_provenance'].get('duplicate_normalized_log_ids_in_evaluation')}`",
        "",
        "## Strategy Stability",
        "",
        "| Strategy | Splits | Strict passes | Worst F1 | Worst FPR | Calibration passes |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for name, summary in sorted(result["strategy_comparison"].items()):
        ranges = summary.get("metric_ranges") or {}
        lines.append(
            "| {name} | {splits} | {strict} | {f1} | {fpr} | {cal} |".format(
                name=name,
                splits=summary.get("evaluated_splits"),
                strict=summary.get("strict_passing_splits"),
                f1=(ranges.get("queue_f1") or {}).get("min"),
                fpr=(ranges.get("benign_like_false_positive_rate") or {}).get("max"),
                cal=summary.get("calibration_passed_splits"),
            )
        )
    lines.extend(
        [
            "",
            "## Decision",
            "",
            f"- Readiness: `{result['readiness']['decision']}`",
            f"- Best diagnostic strategy: `{(result.get('best_diagnostic_strategy') or {}).get('name')}`",
            f"- External strict gate passed: `{result['external_benchmark'].get('passed_v49_gates')}`",
            "- Production promoted: `false`",
            "- Model activated: `false`",
            "- Automatic response: `false`",
            "",
            "## Remaining Boundaries",
            "",
            "- Diagnostic strategy ranking observes final-test results and therefore cannot authorize activation.",
            "- Firewall-flow evidence can indicate behavior; it cannot prove endpoint compromise or attacker intent.",
            "- External flow datasets do not provide native Palo Alto application metadata and must remain schema-aware evidence.",
        ]
    )
    return "\n".join(lines) + "\n"


def _render_split_report(result: dict[str, Any]) -> str:
    lines = [
        "# v4.9 Split Stability and Leakage Audit",
        "",
        f"Protocol: `{result['protocol']['version']}`",
        "",
    ]
    for split in result["splits"]:
        lines.extend(
            [
                f"## {split['split_mode']}",
                "",
                f"- Status: `{split['status']}`",
                f"- Leakage audit: `{(split.get('leakage_audit') or {}).get('status')}`",
                f"- Partition sizes: `{split.get('partition_sizes')}`",
                "",
            ]
        )
    lines.extend(
        [
            "## Protocol Guarantees",
            "",
            "- Duplicate and near-duplicate groups stay inside one partition.",
            "- Fit, calibration, threshold selection, and final test have separate roles.",
            "- Final-test labels are never used for fitting, calibration, or threshold selection.",
            "- Active model artifacts and operational database rows remain unchanged.",
        ]
    )
    return "\n".join(lines) + "\n"


def run_v49_detection_ml_reliability(
    db: Session,
    *,
    output_dir: str | Path = OUTPUT_DIR,
    min_samples: int = 100,
    write_output: bool = True,
) -> dict[str, Any]:
    started = time.perf_counter()
    before_counts = frozen._database_counts(db)
    before_artifact = frozen._artifact_state()
    dataset = frozen._build_dataset(db, min_samples=min_samples)
    if not dataset.get("ok"):
        return {
            "ok": False,
            "status": dataset.get("status", "skipped"),
            "version": V49_VERSION,
            "message": dataset.get("message"),
            "readiness": {"decision": "candidate_only"},
            "safety": {
                "model_activated": False,
                "model_artifact_written": False,
                "response_automation_allowed": False,
            },
        }

    repaired_targets = list(dataset["targets"])
    original_targets = _queue_targets(dataset["original_labels"])
    dataset["repaired_targets_diagnostic_only"] = repaired_targets
    dataset["targets"] = original_targets
    for row, label in zip(dataset["rows"], dataset["labels"], strict=True):
        row["safe_queue_target"] = original_targets[row["index"]]
        row["attack_type"] = str(label.attack_type or "unknown")
    dataset["label_provenance"]["ground_truth_policy"] = (
        "latest_labels_with_reviewed_flag_only_preserving_original_label_source"
    )
    dataset["label_provenance"]["target_repair_used_as_ground_truth"] = False
    dataset["label_provenance"]["ai_assisted_labels_authored"] = 0
    dataset["label_provenance"]["ai_assisted_labels_marked_human_reviewed"] = 0

    leakage_groups = frozen.assign_leakage_groups(dataset["rows"])
    split_results = [_run_split(dataset, split_mode=split_mode) for split_mode in V49_SPLITS]
    comparison = _strategy_comparison(split_results)
    best = _best_diagnostic_strategy(comparison)
    output = Path(output_dir)
    external = _locked_external_evidence(output)
    readiness = _readiness(split_results, comparison, external)
    after_counts = frozen._database_counts(db)
    after_artifact = frozen._artifact_state()
    counts_unchanged = before_counts == after_counts
    artifact_unchanged = before_artifact == after_artifact
    all_splits_evaluated = all(split.get("status") == "evaluated" for split in split_results)

    public_splits = [
        {
            **{key: value for key, value in split.items() if key != "strategies"},
            "strategies": [_public_strategy(strategy) for strategy in split.get("strategies") or []],
        }
        for split in split_results
    ]
    result = {
        "ok": counts_unchanged and artifact_unchanged and all_splits_evaluated,
        "status": "completed" if counts_unchanged and artifact_unchanged and all_splits_evaluated else "failed_closed",
        "version": V49_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "protocol": {
            "version": V49_VERSION,
            "predeclared_candidate": PREDECLARED_CANDIDATE,
            "required_splits": list(V49_SPLITS),
            "roles": ["fit", "calibration", "threshold_selection", "final_test"],
            "reviewed_flag_required": True,
            "original_label_source_preserved": True,
            "target_repair_used_as_ground_truth": False,
            "thresholds_selected_without_final_test_labels": True,
            "diagnostic_ranking_may_not_activate_model": True,
            "strict_gates": STRICT_GATES,
            "true_source_holdout_available": False,
            "source_holdout_limitation": (
                "Evaluation labels currently represent one physical firewall; network-zone group holdout is used as a proxy."
            ),
        },
        "dataset": {
            "rows": len(dataset["rows"]),
            "feature_count": len(dataset["feature_meta"]["numeric_features"])
            + len(dataset["feature_meta"]["categorical_features"]),
            "feature_generation_seconds": dataset["feature_generation_seconds"],
            "feature_contract": dataset["feature_meta"],
            "label_provenance": dataset["label_provenance"],
            "original_queue_distribution": dict(Counter(original_targets)),
            "raw_logs_in_reports": False,
        },
        "leakage_group_summary": leakage_groups,
        "splits": public_splits,
        "strategy_comparison": comparison,
        "best_diagnostic_strategy": best,
        "external_benchmark": external,
        "readiness": readiness,
        "review_sample": {
            "generated": False,
            "import_ready": False,
            "reason": "v4.9 evaluates existing eligible label evidence and does not auto-author human labels.",
        },
        "safety": {
            "database_counts_before": before_counts,
            "database_counts_after": after_counts,
            "database_counts_unchanged": counts_unchanged,
            "active_artifact_before": before_artifact,
            "active_artifact_after": after_artifact,
            "active_artifact_unchanged": artifact_unchanged,
            "session_new_objects": len(db.new),
            "session_dirty_objects": len(db.dirty),
            "session_deleted_objects": len(db.deleted),
            "labels_written": False,
            "model_runs_created": 0,
            "model_activated": False,
            "model_artifact_written": False,
            "production_promoted": False,
            "response_actions_created": 0,
            "response_automation_allowed": False,
            "real_firewall_blocking_enabled": False,
        },
        "runtime_seconds": round(time.perf_counter() - started, 4),
    }

    if write_output:
        output.mkdir(parents=True, exist_ok=True)
        stamp = _stamp()
        model_path = output / f"v4_9_detection_ml_reliability_{stamp}.md"
        split_path = output / f"v4_9_split_stability_{stamp}.md"
        latest_path = output / V49_LATEST
        result["reports"] = {
            "model_comparison": str(model_path),
            "split_stability": str(split_path),
            "latest_json": str(latest_path),
        }
        model_path.write_text(_render_model_report(result), encoding="utf-8")
        split_path.write_text(_render_split_report(result), encoding="utf-8")
        latest_path.write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")
    return result
