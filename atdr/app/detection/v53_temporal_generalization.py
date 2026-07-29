from __future__ import annotations

import hashlib
import json
import math
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from statistics import mean
from typing import Any

from sqlalchemy.orm import Session

from atdr.app.detection import v398_independent_holdout_validation as frozen
from atdr.app.detection import v49_detection_ml_reliability as reliability
from atdr.app.detection import v52_shadow_reliability as v52
from atdr.app.detection.v330_detection_ml_quality import OUTPUT_DIR
from atdr.app.detection.v331_noise_reduction import _build_pipeline_for_columns, _classes


V53_VERSION = "v5.3-temporal-generalization-v1"
V53_LATEST = "v5_3_temporal_generalization_latest.json"
V53_REQUIRED_SPLITS = v52.V52_SPLITS
V53_ROLLING_WINDOWS = 3
V53_SELECTABLE_STRATEGIES = (
    "v5_2_leading_binary_extra_trees",
    "recency_weighted_extra_trees_sigmoid",
    "provenance_weighted_extra_trees_sigmoid",
    "time_balanced_extra_trees_sigmoid",
    "calibrated_logistic_regression_sigmoid",
    "calibrated_hist_gradient_boosting_sigmoid",
    "schema_aware_routed_extra_trees",
    "calibrated_abstention_review_queue",
)
OOD_POLICY = {
    "critical_missing_count": 2,
    "unseen_categorical_rate": 0.34,
    "numeric_outlier_rate": 0.20,
    "missingness_delta": 0.20,
    "confidence_margin": 0.05,
}
CRITICAL_SCHEMA_COLUMNS = ("protocol", "action", "app", "src_zone", "dst_zone", "dst_port")
LIMITED_SCHEMA_VALUES = {"", "-", "missing", "none", "null", "unavailable"}


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _stable_hash(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, default=str, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _safe_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def _dataset_fingerprint(dataset: dict[str, Any]) -> str:
    return _stable_hash(
        [
            {
                "label_id": row["label_id"],
                "log_id": row["log_id"],
                "original_label": row["original_label"],
                "label_source": row["label_source"],
                "exact_fingerprint": row["exact_fingerprint"],
                "feature_fingerprint": row["feature_fingerprint"],
                "timestamp": row.get("timestamp"),
            }
            for row in dataset["rows"]
        ]
    )


def _partition_snapshot(dataset: dict[str, Any], split_mode: str) -> dict[str, Any]:
    partition = frozen.build_frozen_partition(dataset["rows"], split_mode=split_mode)
    leakage = frozen.audit_partition_leakage(dataset["rows"], partition)
    return {
        "split_mode": split_mode,
        "status": partition.get("status"),
        "reason": partition.get("reason"),
        "partition_id": partition.get("partition_id"),
        "partition_method": partition.get("partition_method"),
        "partition_sizes": leakage.get("partition_sizes") or {},
        "target_distributions": leakage.get("target_distributions") or {},
        "leakage_passed": bool(leakage.get("passed")),
        "unacceptable_overlap_count": int(leakage.get("unacceptable_overlap_count") or 0),
    }


def freeze_v52_baseline(db: Session, dataset: dict[str, Any], *, output_dir: Path) -> dict[str, Any]:
    report = _safe_json(output_dir / v52.V52_LATEST)
    selected = report.get("selected_diagnostic_strategy") or {}
    readiness = report.get("readiness") or {}
    return {
        "dataset_fingerprint": _dataset_fingerprint(dataset),
        "reviewed_latest_rows": len(dataset["rows"]),
        "label_provenance": dataset["label_provenance"],
        "queue_target_distribution": dict(Counter(dataset["targets"])),
        "split_definitions": [
            _partition_snapshot(dataset, split_mode) for split_mode in V53_REQUIRED_SPLITS
        ],
        "v5_2_report_available": bool(report),
        "v5_2_generated_at": report.get("generated_at"),
        "v5_2_selected_strategy": selected.get("name"),
        "v5_2_candidate_selected": bool(selected.get("candidate_selected")),
        "v5_2_governance_outcome": selected.get("governance_outcome", "no_supervised_candidate_selected"),
        "v5_2_lifecycle_decision": readiness.get("decision", "shadow_observation"),
        "database_counts": frozen._database_counts(db),
        "artifact_state": frozen._artifact_state(),
        "response_action_count": frozen._database_counts(db)["response_actions"],
        "production_promoted": False,
        "response_automation_allowed": False,
    }


def _distribution(dataset: dict[str, Any], indices: list[int], field: str) -> dict[str, Any]:
    values = [
        str(dataset["rows"][index].get(field) if dataset["rows"][index].get(field) is not None else "missing")
        for index in indices
    ]
    counts = Counter(values)
    total = max(1, len(values))
    return {
        "rows": len(values),
        "ratios": {key: round(value / total, 6) for key, value in sorted(counts.items())},
        "top": [{"value": key, "count": value} for key, value in counts.most_common(10)],
    }


def _total_variation(left: dict[str, float], right: dict[str, float]) -> float:
    keys = set(left) | set(right)
    return round(0.5 * sum(abs(left.get(key, 0.0) - right.get(key, 0.0)) for key in keys), 6)


def _quantile(values: list[float], fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    position = max(0, min(len(ordered) - 1, round((len(ordered) - 1) * fraction)))
    return float(ordered[position])


def fit_ood_profile(dataset: dict[str, Any], fit_idx: list[int]) -> dict[str, Any]:
    frame = dataset["frame"]
    categorical = dataset["feature_meta"]["categorical_features"]
    numeric = dataset["feature_meta"]["numeric_features"]
    known_categories: dict[str, set[str]] = {}
    for column in categorical:
        known_categories[column] = {
            str(value).strip().lower()
            for value in frame.iloc[fit_idx][column].dropna().tolist()
        }
    numeric_bounds: dict[str, tuple[float, float]] = {}
    for column in numeric:
        values = [
            float(value)
            for value in frame.iloc[fit_idx][column].dropna().tolist()
            if isinstance(value, (int, float)) and math.isfinite(float(value))
        ]
        if len(values) < 5:
            continue
        lower_quartile = _quantile(values, 0.25)
        upper_quartile = _quantile(values, 0.75)
        spread = max(1e-9, upper_quartile - lower_quartile)
        lower = min(_quantile(values, 0.01), lower_quartile - (3.0 * spread))
        upper = max(_quantile(values, 0.99), upper_quartile + (3.0 * spread))
        numeric_bounds[column] = (lower, upper)
    expected_columns = [*numeric, *categorical]
    missing_rates = {
        column: float(frame.iloc[fit_idx][column].isna().mean()) for column in expected_columns
    }
    return {
        "fit_rows": len(fit_idx),
        "categorical_features": categorical,
        "numeric_features": numeric,
        "known_categories": known_categories,
        "numeric_bounds": numeric_bounds,
        "fit_missing_rate": round(mean(missing_rates.values()), 6) if missing_rates else 0.0,
        "thresholds": OOD_POLICY,
        "fit_labels_used": False,
        "final_test_labels_used": False,
    }


def score_ood_rows(
    dataset: dict[str, Any],
    profile: dict[str, Any],
    indices: list[int],
    scores: list[float],
    *,
    threshold: float,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    frame = dataset["frame"]
    categorical = profile["categorical_features"]
    numeric = profile["numeric_features"]
    expected = [*numeric, *categorical]
    rows: list[dict[str, Any]] = []
    reasons: Counter[str] = Counter()
    for absolute_index, score in zip(indices, scores, strict=True):
        item = frame.iloc[absolute_index]
        critical_missing = 0
        for column in CRITICAL_SCHEMA_COLUMNS:
            if column not in frame.columns:
                critical_missing += 1
                continue
            value = item.get(column)
            if value is None or (isinstance(value, float) and math.isnan(value)):
                critical_missing += 1
        unseen = 0
        present_categories = 0
        limited_schema = 0
        for column in categorical:
            value = item.get(column)
            if value is None or (isinstance(value, float) and math.isnan(value)):
                continue
            normalized = str(value).strip().lower()
            present_categories += 1
            if normalized not in profile["known_categories"].get(column, set()):
                unseen += 1
            if normalized in LIMITED_SCHEMA_VALUES:
                limited_schema += 1
        unseen_rate = unseen / max(1, present_categories)
        numeric_outliers = 0
        numeric_present = 0
        for column, bounds in profile["numeric_bounds"].items():
            value = item.get(column)
            if value is None or (isinstance(value, float) and math.isnan(value)):
                continue
            numeric_present += 1
            numeric_value = float(value)
            if numeric_value < bounds[0] or numeric_value > bounds[1]:
                numeric_outliers += 1
        outlier_rate = numeric_outliers / max(1, numeric_present)
        missing_count = sum(
            1
            for column in expected
            if item.get(column) is None
            or (isinstance(item.get(column), float) and math.isnan(item.get(column)))
        )
        missing_rate = missing_count / max(1, len(expected))
        missingness_delta = max(0.0, missing_rate - float(profile["fit_missing_rate"]))
        confidence_margin = abs(float(score) - threshold)
        row_reasons: list[str] = []
        if critical_missing >= OOD_POLICY["critical_missing_count"]:
            row_reasons.append("critical_schema_fields_missing")
        if unseen_rate >= OOD_POLICY["unseen_categorical_rate"]:
            row_reasons.append("unseen_category_rate_high")
        if outlier_rate >= OOD_POLICY["numeric_outlier_rate"]:
            row_reasons.append("numeric_feature_range_drift")
        if missingness_delta >= OOD_POLICY["missingness_delta"]:
            row_reasons.append("missingness_drift")
        ood = bool(row_reasons)
        confidence_unstable = confidence_margin <= OOD_POLICY["confidence_margin"]
        if confidence_unstable:
            row_reasons.append("confidence_near_decision_threshold")
        for reason in row_reasons:
            reasons[reason] += 1
        rows.append(
            {
                "ood": ood,
                "confidence_unstable": confidence_unstable,
                "abstain": ood or confidence_unstable,
                "decision": "insufficient_model_evidence" if ood or confidence_unstable else "model_decision_available",
                "reason_count": len(row_reasons),
                "reasons": row_reasons,
                "critical_missing_count": critical_missing,
                "limited_schema_value_count": limited_schema,
                "unseen_categorical_rate": round(unseen_rate, 6),
                "numeric_outlier_rate": round(outlier_rate, 6),
                "missing_feature_rate": round(missing_rate, 6),
                "missingness_delta": round(missingness_delta, 6),
                "confidence_margin": round(confidence_margin, 6),
            }
        )
    total = max(1, len(rows))
    ood_count = sum(1 for row in rows if row["ood"])
    unstable_count = sum(1 for row in rows if row["confidence_unstable"])
    abstained_count = sum(1 for row in rows if row["abstain"])
    return rows, {
        "rows": len(rows),
        "ood_rows": ood_count,
        "ood_rate": round(ood_count / total, 6),
        "confidence_unstable_rows": unstable_count,
        "confidence_instability_rate": round(unstable_count / total, 6),
        "abstained_rows": abstained_count,
        "abstention_rate": round(abstained_count / total, 6),
        "coverage_rate": round((len(rows) - abstained_count) / total, 6),
        "reason_counts": dict(reasons),
        "raw_logs_included": False,
        "private_identifiers_included": False,
    }


def _chronological_component_rows(rows: list[dict[str, Any]]) -> list[list[int]]:
    grouped: dict[str, list[int]] = defaultdict(list)
    for index, row in enumerate(rows):
        if row.get("timestamp") is not None:
            grouped[str(row["leakage_group"])].append(index)
    return sorted(
        grouped.values(),
        key=lambda members: (
            min(rows[index]["timestamp"] for index in members),
            max(rows[index]["timestamp"] for index in members),
            str(rows[members[0]]["leakage_group"]),
        ),
    )


def build_rolling_temporal_partitions(
    rows: list[dict[str, Any]],
    *,
    window_count: int = V53_ROLLING_WINDOWS,
) -> list[dict[str, Any]]:
    """Build fixed-origin, disjoint future windows without recycling test labels."""

    base = frozen.build_frozen_partition(rows, split_mode="temporal_holdout")
    if base.get("status") != "partitioned":
        return [
            {
                "status": "failed",
                "split_mode": f"rolling_temporal_{position + 1}",
                "reason": "canonical temporal origin is unavailable",
            }
            for position in range(window_count)
        ]
    final_set = set(base["final_test_idx"])
    components = [
        [index for index in component if index in final_set]
        for component in _chronological_component_rows(rows)
    ]
    components = [component for component in components if component]
    if len(components) < window_count:
        return [
            {
                "status": "failed",
                "split_mode": f"rolling_temporal_{position + 1}",
                "reason": "insufficient final-test leakage components for rolling windows",
            }
            for position in range(window_count)
        ]
    windows: list[list[list[int]]] = [[] for _ in range(window_count)]
    total_rows = sum(len(component) for component in components)
    target_rows = total_rows / window_count
    position = 0
    rows_in_window = 0
    for component in components:
        if position < window_count - 1 and rows_in_window >= target_rows:
            position += 1
            rows_in_window = 0
        windows[position].append(component)
        rows_in_window += len(component)

    output: list[dict[str, Any]] = []
    for window_position, components_in_window in enumerate(windows, start=1):
        partition = {
            "status": "partitioned",
            "split_mode": f"rolling_temporal_{window_position}",
            "fit_idx": list(base["fit_idx"]),
            "calibration_idx": list(base["calibration_idx"]),
            "threshold_idx": list(base["threshold_idx"]),
            "final_test_idx": sorted(
                index for component in components_in_window for index in component
            ),
            "quarantined_idx": list(base["quarantined_idx"]),
            "partition_method": "fixed_origin_disjoint_chronological_future_windows_no_test_reuse",
            "final_test_labels_used_for_training": False,
            "final_test_labels_used_for_calibration": False,
            "final_test_labels_used_for_threshold_selection": False,
        }
        partition["partition_id"] = _stable_hash(
            {
                "protocol": "v5.3-fixed-origin-rolling-temporal-v1",
                "split_mode": partition["split_mode"],
                "roles": {
                    key: [rows[index]["log_id"] for index in partition[key]]
                    for key in ("fit_idx", "calibration_idx", "threshold_idx", "final_test_idx")
                },
            }
        )
        output.append(partition)
    return output


def _normalize_weights(values: list[float]) -> list[float]:
    average = mean(values) if values else 1.0
    return [round(max(0.25, min(6.0, value / max(average, 1e-9))), 6) for value in values]


def _recency_weights(dataset: dict[str, Any], fit_idx: list[int]) -> tuple[list[float], dict[str, Any]]:
    timestamps = [dataset["rows"][index].get("timestamp") for index in fit_idx]
    valid = [value.timestamp() for value in timestamps if value is not None]
    lower = min(valid) if valid else 0.0
    upper = max(valid) if valid else 0.0
    span = max(1.0, upper - lower)
    weights = []
    for index in fit_idx:
        timestamp = dataset["rows"][index].get("timestamp")
        recency = ((timestamp.timestamp() - lower) / span) if timestamp is not None else 0.0
        weights.append(0.65 + (1.35 * recency))
    return _normalize_weights(weights), {
        "strategy": "recency_linear_fit_partition_only",
        "minimum": round(min(weights), 4) if weights else None,
        "maximum": round(max(weights), 4) if weights else None,
        "final_test_timestamps_used": False,
    }


def _provenance_weights(dataset: dict[str, Any], fit_idx: list[int]) -> tuple[list[float], dict[str, Any]]:
    multipliers = {
        "manual": 2.0,
        "reviewed_import": 1.5,
        "assisted_rule": 0.85,
        "assisted_hybrid": 0.80,
        "assisted_ml": 0.60,
    }
    class_multipliers = {
        "benign": 1.5,
        "benign_unusual": 1.25,
        "needs_context": 1.0,
        "suspicious": 1.0,
        "malicious": 1.15,
    }
    raw = []
    sources: Counter[str] = Counter()
    for index in fit_idx:
        row = dataset["rows"][index]
        source = str(row.get("label_source") or "unknown")
        sources[source] += 1
        source_weight = multipliers.get(source, 0.75 if source.startswith("assisted") else 1.0)
        raw.append(source_weight * class_multipliers.get(str(row["original_label"]), 1.0))
    return _normalize_weights(raw), {
        "strategy": "review_provenance_and_class_support_fit_partition_only",
        "label_source_distribution": dict(sources),
        "weak_or_unreviewed_labels_promoted": 0,
        "final_test_labels_used": False,
    }


def _time_balanced_weights(dataset: dict[str, Any], fit_idx: list[int]) -> tuple[list[float], dict[str, Any]]:
    timestamps = [dataset["rows"][index].get("timestamp") for index in fit_idx]
    valid = sorted(value.timestamp() for value in timestamps if value is not None)
    boundaries = [_quantile(valid, fraction) for fraction in (0.25, 0.50, 0.75)] if valid else []

    def bucket(index: int) -> int:
        timestamp = dataset["rows"][index].get("timestamp")
        if timestamp is None:
            return -1
        value = timestamp.timestamp()
        return sum(1 for boundary in boundaries if value >= boundary)

    support = Counter((bucket(index), dataset["targets"][index]) for index in fit_idx)
    raw = [1.0 / max(1, support[(bucket(index), dataset["targets"][index])]) for index in fit_idx]
    return _normalize_weights(raw), {
        "strategy": "inverse_time_bucket_target_support_fit_partition_only",
        "time_bucket_count": 4 if boundaries else 1,
        "time_target_support": {
            f"bucket_{time_bucket}:{target}": count
            for (time_bucket, target), count in sorted(support.items())
        },
        "final_test_labels_used": False,
    }


def _fit_weighted_candidate(
    dataset: dict[str, Any],
    partition: dict[str, Any],
    *,
    model_type: str,
    class_weight: str | None,
    weights: list[float] | None,
    weighting: dict[str, Any],
    calibration_method: str = "sigmoid",
) -> dict[str, Any]:
    fit_idx = partition["fit_idx"]
    calibration_idx = partition["calibration_idx"]
    threshold_idx = partition["threshold_idx"]
    final_idx = partition["final_test_idx"]
    y_fit = [dataset["targets"][index] for index in fit_idx]
    if len(set(y_fit)) < 2:
        return {"status": "failed_closed", "message": "Fit partition contains one queue class."}
    pipeline = _build_pipeline_for_columns(
        dataset["imports"],
        model_type=model_type,
        class_weight=class_weight,
        numeric_features=dataset["feature_meta"]["numeric_features"],
        categorical_features=dataset["feature_meta"]["categorical_features"],
    )
    fit_kwargs: dict[str, Any] = {}
    if weights is not None:
        fit_kwargs["model__sample_weight"] = weights
    started = time.perf_counter()
    pipeline.fit(dataset["frame"].iloc[fit_idx], y_fit, **fit_kwargs)
    model, applied_calibration = reliability._fit_frozen_calibrator(
        pipeline,
        dataset["frame"],
        calibration_idx,
        dataset["targets"],
        method=calibration_method,
    )
    threshold_scores = reliability._queue_scores(
        model,
        dataset["frame"],
        threshold_idx,
        {"needs_review"},
    )
    return {
        "status": "evaluated",
        "model": model,
        "threshold_scores": threshold_scores,
        "final_scores": reliability._queue_scores(
            model,
            dataset["frame"],
            final_idx,
            {"needs_review"},
        ),
        "threshold_selection": reliability.select_v49_threshold(
            [dataset["targets"][index] for index in threshold_idx],
            threshold_scores,
        ),
        "calibration_method": applied_calibration,
        "sample_weighting": weighting,
        "training_seconds": round(time.perf_counter() - started, 4),
    }


def _schema_limited(dataset: dict[str, Any], index: int) -> bool:
    row = dataset["frame"].iloc[index]
    missing = 0
    for column in CRITICAL_SCHEMA_COLUMNS:
        value = row.get(column)
        if value is None or (isinstance(value, float) and math.isnan(value)):
            missing += 1
    app = str(row.get("app") or "").strip().lower()
    return missing >= 2 or app in {"unknown", "unavailable", "incomplete", "unknown-tcp", "unknown-udp"}


def _fit_route_model(
    dataset: dict[str, Any],
    fit_idx: list[int],
    calibration_idx: list[int],
) -> tuple[Any | None, str]:
    if len(fit_idx) < 40 or len(set(dataset["targets"][index] for index in fit_idx)) < 2:
        return None, "fallback_global_insufficient_fit_support"
    pipeline = _build_pipeline_for_columns(
        dataset["imports"],
        model_type="extra_trees",
        class_weight="balanced",
        numeric_features=dataset["feature_meta"]["numeric_features"],
        categorical_features=dataset["feature_meta"]["categorical_features"],
    )
    pipeline.fit(
        dataset["frame"].iloc[fit_idx],
        [dataset["targets"][index] for index in fit_idx],
    )
    calibration_support = Counter(dataset["targets"][index] for index in calibration_idx)
    if (
        len(calibration_idx) < 20
        or len(calibration_support) < 2
        or min(calibration_support.values()) < 5
    ):
        return pipeline, "uncalibrated_route_insufficient_calibration_support"
    model, method = reliability._fit_frozen_calibrator(
        pipeline,
        dataset["frame"],
        calibration_idx,
        dataset["targets"],
        method="sigmoid",
    )
    return model, method


def _routed_scores(dataset: dict[str, Any], models: dict[str, Any], indices: list[int]) -> list[float]:
    scores = [0.0 for _ in indices]
    positions_by_route: dict[str, list[tuple[int, int]]] = defaultdict(list)
    for position, index in enumerate(indices):
        route = "limited" if _schema_limited(dataset, index) else "complete"
        if models.get(route) is None:
            route = "global"
        positions_by_route[route].append((position, index))
    for route, pairs in positions_by_route.items():
        model = models[route]
        absolute_indices = [index for _position, index in pairs]
        route_scores = reliability._queue_scores(
            model,
            dataset["frame"],
            absolute_indices,
            {"needs_review"},
        )
        for (position, _index), score in zip(pairs, route_scores, strict=True):
            scores[position] = score
    return scores


def _fit_schema_routed_candidate(dataset: dict[str, Any], partition: dict[str, Any]) -> dict[str, Any]:
    fit_idx = partition["fit_idx"]
    calibration_idx = partition["calibration_idx"]
    global_model, global_method = _fit_route_model(dataset, fit_idx, calibration_idx)
    if global_model is None:
        return {"status": "failed_closed", "message": "Global schema route could not be fitted."}
    models: dict[str, Any] = {"global": global_model}
    methods = {"global": global_method}
    supports: dict[str, Any] = {}
    for route, limited in (("complete", False), ("limited", True)):
        route_fit = [index for index in fit_idx if _schema_limited(dataset, index) is limited]
        route_calibration = [
            index for index in calibration_idx if _schema_limited(dataset, index) is limited
        ]
        model, method = _fit_route_model(dataset, route_fit, route_calibration)
        models[route] = model
        methods[route] = method
        supports[route] = {"fit_rows": len(route_fit), "calibration_rows": len(route_calibration)}
    threshold_scores = _routed_scores(dataset, models, partition["threshold_idx"])
    return {
        "status": "evaluated",
        "model": models,
        "threshold_scores": threshold_scores,
        "final_scores": _routed_scores(dataset, models, partition["final_test_idx"]),
        "threshold_selection": reliability.select_v49_threshold(
            [dataset["targets"][index] for index in partition["threshold_idx"]],
            threshold_scores,
        ),
        "calibration_method": methods,
        "sample_weighting": {"strategy": "schema_route_balanced_classes"},
        "route_support": supports,
        "training_seconds": None,
    }


def _v51_artifact_reference(db: Session, dataset: dict[str, Any]) -> dict[str, Any]:
    try:
        from atdr.app.detection import v51_supervised_lifecycle as lifecycle

        lifecycle_run = lifecycle._latest_lifecycle_run(db)
        model_run = lifecycle._resolve_lifecycle_model_run(db, lifecycle_run) if lifecycle_run else None
        if model_run is None:
            return {"available": False, "reason": "no governed model run"}
        path = Path(model_run.model_path)
        state = lifecycle._safe_artifact_state(model_run)
        if not state.get("available") or not state.get("checksum_valid"):
            return {"available": False, "reason": "governed artifact unavailable or checksum invalid"}
        artifact = lifecycle._load_governed_artifact(
            str(path.resolve()),
            path.stat().st_mtime_ns,
            str(model_run.artifact_sha256),
        )
        manifest = artifact.get("dataset_manifest") or {}
        current_log_ids = [int(row["log_id"]) for row in dataset["rows"]]
        compatible = bool(
            manifest.get("normalized_log_ids") == current_log_ids
            and int(manifest.get("reviewed_latest_rows") or 0) == len(current_log_ids)
        )
        return {
            "available": True,
            "compatible_dataset": compatible,
            "model": artifact["model"],
            "model_version": artifact.get("model_version"),
            "model_type": artifact.get("model_type"),
            "threshold": float(artifact.get("threshold", 0.5)),
            "calibration_method": artifact.get("calibration_method"),
            "artifact_name": path.name,
            "artifact_sha256": model_run.artifact_sha256,
            "production_promoted": False,
            "response_automation_allowed": False,
        }
    except (OSError, ValueError, KeyError, ImportError) as exc:
        return {
            "available": False,
            "reason": f"artifact reference failed closed: {exc.__class__.__name__}",
        }


def _evaluate_fitted(
    dataset: dict[str, Any],
    partition: dict[str, Any],
    fitted: dict[str, Any],
    *,
    name: str,
    seed: int,
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if fitted.get("status") != "evaluated":
        return {"name": name, **fitted}
    return reliability._evaluate(
        dataset,
        partition,
        name=name,
        scores=fitted["final_scores"],
        threshold_selection=fitted["threshold_selection"],
        seed=seed,
        details={
            "model_type": details.get("model_type") if details else None,
            "calibration_method": fitted.get("calibration_method"),
            "sample_weighting": fitted.get("sample_weighting") or {},
            "training_seconds": fitted.get("training_seconds"),
            "diagnostic_only": True,
            "active_artifact_written": False,
            "eligible_for_activation": False,
            **(details or {}),
        },
    )


def _evaluate_abstention_policy(
    dataset: dict[str, Any],
    partition: dict[str, Any],
    fitted: dict[str, Any],
    *,
    seed: int,
) -> dict[str, Any]:
    result = _evaluate_fitted(
        dataset,
        partition,
        fitted,
        name="calibrated_abstention_review_queue",
        seed=seed,
        details={
            "model_type": "extra_trees",
            "decision_contract": "OOD or unstable confidence becomes insufficient_model_evidence",
            "abstention_routes_to_analyst_review": True,
            "abstention_is_not_a_threat_prediction": True,
        },
    )
    if result.get("status") != "evaluated":
        return result
    threshold = float(fitted["threshold_selection"].get("selected_threshold", 0.5))
    profile = fit_ood_profile(dataset, partition["fit_idx"])
    row_states, summary = score_ood_rows(
        dataset,
        profile,
        partition["final_test_idx"],
        fitted["final_scores"],
        threshold=threshold,
    )
    model_metrics = result["metrics"]
    model_predictions = list(result["_predictions"])
    policy_predictions = [
        "needs_review" if state["abstain"] else prediction
        for state, prediction in zip(row_states, model_predictions, strict=True)
    ]
    final_idx = partition["final_test_idx"]
    y_true = [dataset["targets"][index] for index in final_idx]
    metrics = frozen._binary_metrics(y_true, policy_predictions)
    metrics.update(frozen._diagnostic_original_recall(dataset["rows"], final_idx, policy_predictions))
    abstained_targets = Counter(
        dataset["targets"][index]
        for index, state in zip(final_idx, row_states, strict=True)
        if state["abstain"]
    )
    summary.update(
        {
            "abstained_target_distribution_diagnostic_only": dict(abstained_targets),
            "queue_rate_after_abstention": metrics["review_queue_rate"],
            "model_queue_rate_before_abstention": model_metrics["review_queue_rate"],
            "final_test_labels_used_to_set_abstention": False,
            "abstention_counted_as_review_queue_for_strict_metrics": True,
        }
    )
    result["model_metrics_before_abstention"] = model_metrics
    result["metrics"] = metrics
    result["error_patterns"] = frozen._error_patterns(
        dataset["rows"],
        final_idx,
        y_true,
        policy_predictions,
    )
    result["bootstrap_95_percent"] = frozen._bootstrap_intervals(
        y_true,
        policy_predictions,
        seed=seed,
    )
    result["ood_and_abstention"] = summary
    result["_predictions"] = policy_predictions
    result["details"]["ood_profile"] = {
        "fit_rows": profile["fit_rows"],
        "fit_missing_rate": profile["fit_missing_rate"],
        "thresholds": profile["thresholds"],
        "fit_labels_used": False,
        "final_test_labels_used": False,
    }
    return result


def _artifact_baseline_strategy(
    dataset: dict[str, Any],
    partition: dict[str, Any],
    artifact: dict[str, Any],
    *,
    split_mode: str,
) -> dict[str, Any]:
    name = "v5_1_governed_artifact_operational_reference"
    if split_mode != "temporal_holdout":
        return {
            "name": name,
            "status": "excluded_from_split_gate",
            "reason": "The governed artifact was trained on the canonical temporal fit partition; other split views could overlap its training rows.",
            "eligible_for_selection": False,
        }
    if not artifact.get("available") or not artifact.get("compatible_dataset"):
        return {
            "name": name,
            "status": "failed_closed",
            "reason": artifact.get("reason") or "governed artifact dataset no longer matches",
            "eligible_for_selection": False,
        }
    scores = reliability._queue_scores(
        artifact["model"],
        dataset["frame"],
        partition["final_test_idx"],
        {"needs_review"},
    )
    result = reliability._evaluate(
        dataset,
        partition,
        name=name,
        scores=scores,
        threshold_selection={
            "status": "frozen_artifact_threshold",
            "selected_threshold": artifact["threshold"],
            "selected_on": "v5.1 dedicated threshold partition",
            "used_final_test_labels": False,
        },
        seed=510,
        details={
            "model_version": artifact.get("model_version"),
            "model_type": artifact.get("model_type"),
            "calibration_method": artifact.get("calibration_method"),
            "artifact_name": artifact.get("artifact_name"),
            "operational_reference_only": True,
            "eligible_for_selection": False,
            "active_artifact_written": False,
        },
    )
    result["eligible_for_selection"] = False
    return result


def _audit_partition(
    dataset: dict[str, Any],
    partition: dict[str, Any],
    *,
    temporal: bool,
) -> dict[str, Any]:
    candidate = dict(partition)
    if temporal:
        candidate["split_mode"] = "temporal_holdout"
    return frozen.audit_partition_leakage(dataset["rows"], candidate)


def _run_partition(
    dataset: dict[str, Any],
    partition: dict[str, Any],
    *,
    split_mode: str,
    seed: int,
    artifact: dict[str, Any],
    temporal: bool,
) -> dict[str, Any]:
    leakage = _audit_partition(dataset, partition, temporal=temporal)
    if not leakage.get("passed"):
        return {
            "split_mode": split_mode,
            "status": "failed_closed",
            "partition": {
                key: value
                for key, value in partition.items()
                if key not in {"fit_idx", "calibration_idx", "threshold_idx", "final_test_idx", "quarantined_idx"}
            },
            "partition_sizes": leakage.get("partition_sizes") or {},
            "partition_target_distributions": leakage.get("target_distributions") or {},
            "leakage_audit": leakage,
            "strategies": [],
        }

    strategies: list[dict[str, Any]] = []
    strategies.append(
        _artifact_baseline_strategy(dataset, partition, artifact, split_mode=split_mode)
    )

    leading = reliability._fit_candidate(
        dataset,
        partition,
        model_type="extra_trees",
        targets=dataset["targets"],
        positive_classes={"needs_review"},
        class_weight=None,
        weight_strategy="lower_threat",
        calibrate=False,
    )
    strategies.append(
        _evaluate_fitted(
            dataset,
            partition,
            leading,
            name="v5_2_leading_binary_extra_trees",
            seed=seed,
            details={"model_type": "extra_trees", "baseline_role": "v5.2 leading comparator"},
        )
    )

    recency_weights, recency_meta = _recency_weights(dataset, partition["fit_idx"])
    recency = _fit_weighted_candidate(
        dataset,
        partition,
        model_type="extra_trees",
        class_weight=None,
        weights=recency_weights,
        weighting=recency_meta,
    )
    strategies.append(
        _evaluate_fitted(
            dataset,
            partition,
            recency,
            name="recency_weighted_extra_trees_sigmoid",
            seed=seed + 1,
            details={"model_type": "extra_trees"},
        )
    )

    provenance_weights, provenance_meta = _provenance_weights(dataset, partition["fit_idx"])
    provenance = _fit_weighted_candidate(
        dataset,
        partition,
        model_type="extra_trees",
        class_weight=None,
        weights=provenance_weights,
        weighting=provenance_meta,
    )
    strategies.append(
        _evaluate_fitted(
            dataset,
            partition,
            provenance,
            name="provenance_weighted_extra_trees_sigmoid",
            seed=seed + 2,
            details={"model_type": "extra_trees"},
        )
    )

    time_weights, time_meta = _time_balanced_weights(dataset, partition["fit_idx"])
    time_balanced = _fit_weighted_candidate(
        dataset,
        partition,
        model_type="extra_trees",
        class_weight=None,
        weights=time_weights,
        weighting=time_meta,
    )
    strategies.append(
        _evaluate_fitted(
            dataset,
            partition,
            time_balanced,
            name="time_balanced_extra_trees_sigmoid",
            seed=seed + 3,
            details={"model_type": "extra_trees"},
        )
    )

    logistic = _fit_weighted_candidate(
        dataset,
        partition,
        model_type="logistic_regression",
        class_weight="balanced",
        weights=None,
        weighting={"strategy": "balanced_class_weight"},
    )
    strategies.append(
        _evaluate_fitted(
            dataset,
            partition,
            logistic,
            name="calibrated_logistic_regression_sigmoid",
            seed=seed + 4,
            details={"model_type": "logistic_regression"},
        )
    )

    hist_weights, hist_meta = _provenance_weights(dataset, partition["fit_idx"])
    hist = _fit_weighted_candidate(
        dataset,
        partition,
        model_type="hist_gradient_boosting",
        class_weight=None,
        weights=hist_weights,
        weighting=hist_meta,
    )
    strategies.append(
        _evaluate_fitted(
            dataset,
            partition,
            hist,
            name="calibrated_hist_gradient_boosting_sigmoid",
            seed=seed + 5,
            details={"model_type": "hist_gradient_boosting"},
        )
    )

    routed = _fit_schema_routed_candidate(dataset, partition)
    strategies.append(
        _evaluate_fitted(
            dataset,
            partition,
            routed,
            name="schema_aware_routed_extra_trees",
            seed=seed + 6,
            details={
                "model_type": "schema_routed_extra_trees",
                "route_support": routed.get("route_support") or {},
            },
        )
    )
    strategies.append(
        _evaluate_abstention_policy(dataset, partition, recency, seed=seed + 7)
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


def _run_required_split(
    dataset: dict[str, Any],
    split_mode: str,
    *,
    artifact: dict[str, Any],
) -> dict[str, Any]:
    partition = frozen.build_frozen_partition(dataset["rows"], split_mode=split_mode)
    seed = 530 if split_mode == "temporal_holdout" else 538 if split_mode == "source_holdout" else 539
    if split_mode.startswith("random_seed_"):
        seed = int(split_mode.rsplit("_", 1)[-1])
    return _run_partition(
        dataset,
        partition,
        split_mode=split_mode,
        seed=seed,
        artifact=artifact,
        temporal=split_mode == "temporal_holdout",
    )


def _run_rolling_splits(dataset: dict[str, Any], *, artifact: dict[str, Any]) -> list[dict[str, Any]]:
    results = []
    for position, partition in enumerate(build_rolling_temporal_partitions(dataset["rows"]), start=1):
        split_mode = str(partition["split_mode"])
        if partition.get("status") != "partitioned":
            results.append(
                {
                    "split_mode": split_mode,
                    "status": "failed_closed",
                    "partition": partition,
                    "leakage_audit": {"passed": False, "reason": partition.get("reason")},
                    "strategies": [],
                }
            )
            continue
        results.append(
            _run_partition(
                dataset,
                partition,
                split_mode=split_mode,
                seed=560 + position,
                artifact=artifact,
                temporal=True,
            )
        )
    return results


def _metric_range(rows: list[dict[str, Any]], key: str) -> dict[str, float | None]:
    values = [
        float((row.get("metrics") or {}).get(key))
        for row in rows
        if (row.get("metrics") or {}).get(key) is not None
    ]
    if not values:
        return {"min": None, "max": None, "mean": None, "range": None}
    return {
        "min": round(min(values), 4),
        "max": round(max(values), 4),
        "mean": round(mean(values), 4),
        "range": round(max(values) - min(values), 4),
    }


def _strict_checks(row: dict[str, Any] | None) -> dict[str, bool]:
    if not row:
        return {}
    metrics = row.get("metrics") or {}
    calibration = row.get("calibration") or {}
    return {
        "threat_f1": float(metrics.get("queue_f1") or 0.0)
        >= reliability.STRICT_GATES["threat_positive_f1_min"],
        "benign_like_fpr": float(metrics.get("benign_like_false_positive_rate") or 1.0)
        <= reliability.STRICT_GATES["benign_like_false_positive_rate_max"],
        "suspicious_recall": metrics.get("suspicious_recall") is not None
        and float(metrics["suspicious_recall"])
        >= reliability.STRICT_GATES["suspicious_recall_min"],
        "malicious_recall": metrics.get("malicious_recall") is not None
        and float(metrics["malicious_recall"])
        >= reliability.STRICT_GATES["malicious_recall_min"],
        "ece": float(calibration.get("expected_calibration_error") or 1.0)
        <= reliability.STRICT_GATES["expected_calibration_error_max"],
        "confidence_gap": float(calibration.get("max_confidence_accuracy_gap") or 1.0)
        <= reliability.STRICT_GATES["max_confidence_accuracy_gap_max"],
    }


def _strategy_comparison(
    split_results: list[dict[str, Any]],
    rolling_results: list[dict[str, Any]],
) -> dict[str, Any]:
    all_results = [*split_results, *rolling_results]
    required_views = [*V53_REQUIRED_SPLITS, *(f"rolling_temporal_{index}" for index in range(1, V53_ROLLING_WINDOWS + 1))]
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    view_status = {str(split["split_mode"]): str(split.get("status")) for split in all_results}
    for split in all_results:
        for strategy in split.get("strategies") or []:
            if strategy.get("status") == "evaluated" and strategy.get("name") in V53_SELECTABLE_STRATEGIES:
                grouped[str(strategy["name"])].append({"split_mode": split["split_mode"], **strategy})
    output: dict[str, Any] = {}
    metrics = (
        "queue_precision",
        "queue_recall",
        "queue_f1",
        "benign_like_false_positive_rate",
        "suspicious_recall",
        "malicious_recall",
        "macro_f1",
        "weighted_f1",
        "review_queue_rate",
    )
    for name, rows in grouped.items():
        strict_views = []
        for view in required_views:
            row = next((item for item in rows if item["split_mode"] == view), None)
            checks = _strict_checks(row)
            strict_views.append(
                {
                    "split_mode": view,
                    "evaluated": row is not None,
                    "passed": bool(row and all(checks.values())),
                    "checks": checks,
                }
            )
        f1_range = _metric_range(rows, "queue_f1")
        fpr_range = _metric_range(rows, "benign_like_false_positive_rate")
        suspicious_range = _metric_range(rows, "suspicious_recall")
        malicious_range = _metric_range(rows, "malicious_recall")
        material_collapse = bool(
            float(f1_range.get("range") or 0.0) > 0.20
            or float(fpr_range.get("range") or 0.0) > 0.10
            or float(suspicious_range.get("range") or 0.0) > 0.20
            or float(malicious_range.get("range") or 0.0) > 0.20
        )
        abstention_rows = [row.get("ood_and_abstention") or {} for row in rows if row.get("ood_and_abstention")]
        output[name] = {
            "evaluated_views": len(rows),
            "required_views": len(required_views),
            "view_status": view_status,
            "metric_ranges": {metric: _metric_range(rows, metric) for metric in metrics},
            "calibration_ranges": {
                "brier_score": _metric_range(
                    [{"metrics": row.get("calibration") or {}} for row in rows],
                    "brier_score",
                ),
                "expected_calibration_error": _metric_range(
                    [{"metrics": row.get("calibration") or {}} for row in rows],
                    "expected_calibration_error",
                ),
                "max_confidence_accuracy_gap": _metric_range(
                    [{"metrics": row.get("calibration") or {}} for row in rows],
                    "max_confidence_accuracy_gap",
                ),
            },
            "strict_view_gates": strict_views,
            "strict_passing_views": sum(1 for row in strict_views if row["passed"]),
            "aggregate_gate_checks_passed": sum(
                1 for row in strict_views for passed in row["checks"].values() if passed
            ),
            "aggregate_gate_checks_total": len(required_views) * 6,
            "material_split_collapse": material_collapse,
            "stability_gate_passed": not material_collapse,
            "abstention_ranges": {
                "ood_rate": _metric_range([{"metrics": row} for row in abstention_rows], "ood_rate"),
                "abstention_rate": _metric_range(
                    [{"metrics": row} for row in abstention_rows],
                    "abstention_rate",
                ),
                "coverage_rate": _metric_range(
                    [{"metrics": row} for row in abstention_rows],
                    "coverage_rate",
                ),
            },
            "split_metrics": [
                {
                    "split_mode": row["split_mode"],
                    **(row.get("metrics") or {}),
                    "calibration": row.get("calibration") or {},
                    "threshold": (row.get("threshold_selection") or {}).get("selected_threshold"),
                    "ood_and_abstention": row.get("ood_and_abstention") or {},
                    "details": row.get("details") or {},
                    "error_patterns": row.get("error_patterns") or {},
                }
                for row in rows
            ],
        }
    return output


def _select_diagnostic(comparison: dict[str, Any]) -> dict[str, Any] | None:
    candidates = []
    for name, summary in comparison.items():
        ranges = summary.get("metric_ranges") or {}

        def minimum(metric: str) -> float:
            value = (ranges.get(metric) or {}).get("min")
            return float(value) if value is not None else -1.0

        def maximum(metric: str) -> float:
            value = (ranges.get(metric) or {}).get("max")
            return float(value) if value is not None else 1.0

        candidates.append(
            (
                name,
                int(summary.get("strict_passing_views") or 0),
                int(summary.get("aggregate_gate_checks_passed") or 0),
                int(not bool(summary.get("material_split_collapse"))),
                minimum("queue_f1"),
                -maximum("benign_like_false_positive_rate"),
                minimum("suspicious_recall"),
                minimum("malicious_recall"),
            )
        )
    if not candidates:
        return None
    selected = max(candidates, key=lambda item: item[1:])
    summary = comparison[selected[0]]
    all_views_passed = int(summary.get("strict_passing_views") or 0) == int(summary.get("required_views") or 0)
    selected_candidate = bool(all_views_passed and summary.get("stability_gate_passed"))
    return {
        "name": selected[0],
        "selection_role": "internally_qualified_diagnostic_candidate" if selected_candidate else "leading_comparator_not_selected",
        "candidate_selected": selected_candidate,
        "governance_outcome": "internal_candidate_available" if selected_candidate else "no_supervised_candidate_selected",
        "eligible_for_activation": False,
        "selection_rationale": (
            "Ranked by predeclared strict-view coverage, aggregate gate coverage, stability, and worst-view metrics. "
            "Unavailable source evidence and failed views remain failures; abstention cannot hide review-queue false positives."
        ),
        "summary": summary,
    }


def _score_summary(scores: list[float]) -> dict[str, float | int | None]:
    if not scores:
        return {"rows": 0, "minimum": None, "median": None, "p95": None, "maximum": None}
    return {
        "rows": len(scores),
        "minimum": round(min(scores), 6),
        "median": round(_quantile(scores, 0.50), 6),
        "p95": round(_quantile(scores, 0.95), 6),
        "maximum": round(max(scores), 6),
    }


def _numeric_drift(dataset: dict[str, Any], fit_idx: list[int], final_idx: list[int]) -> list[dict[str, Any]]:
    frame = dataset["frame"]
    rows = []
    for column in dataset["feature_meta"]["numeric_features"]:
        fit_values = [float(value) for value in frame.iloc[fit_idx][column].dropna().tolist()]
        final_values = [float(value) for value in frame.iloc[final_idx][column].dropna().tolist()]
        if not fit_values or not final_values:
            continue
        fit_median = _quantile(fit_values, 0.50)
        final_median = _quantile(final_values, 0.50)
        fit_iqr = max(1e-9, _quantile(fit_values, 0.75) - _quantile(fit_values, 0.25))
        rows.append(
            {
                "feature": column,
                "fit_median": round(fit_median, 6),
                "final_median": round(final_median, 6),
                "robust_median_shift": round(abs(final_median - fit_median) / fit_iqr, 6),
            }
        )
    return sorted(rows, key=lambda row: row["robust_median_shift"], reverse=True)


def diagnose_temporal_failure(dataset: dict[str, Any]) -> dict[str, Any]:
    partition = frozen.build_frozen_partition(dataset["rows"], split_mode="temporal_holdout")
    leakage = frozen.audit_partition_leakage(dataset["rows"], partition)
    if not leakage.get("passed"):
        return {"available": False, "status": "failed_closed", "leakage_audit": leakage}
    fit_idx = partition["fit_idx"]
    threshold_idx = partition["threshold_idx"]
    final_idx = partition["final_test_idx"]
    fields = ("original_label", "safe_queue_target", "label_source", "app", "action", "dst_port", "network_zone_group")
    distributions = {}
    for field in fields:
        fit = _distribution(dataset, fit_idx, field)
        final = _distribution(dataset, final_idx, field)
        distributions[field] = {
            "total_variation_distance": _total_variation(fit["ratios"], final["ratios"]),
            "fit_top": fit["top"],
            "final_top": final["top"],
        }
    leading = reliability._fit_candidate(
        dataset,
        partition,
        model_type="extra_trees",
        targets=dataset["targets"],
        positive_classes={"needs_review"},
        class_weight=None,
        weight_strategy="lower_threat",
        calibrate=False,
    )
    if leading.get("status") != "evaluated":
        return {"available": False, "status": "model_failed_closed", "distributions": distributions}
    selected_threshold = float(leading["threshold_selection"].get("selected_threshold", 0.5))
    final_targets = [dataset["targets"][index] for index in final_idx]
    post_hoc = []
    for threshold in reliability.THRESHOLD_GRID:
        predictions = ["needs_review" if score >= threshold else "non_threat" for score in leading["final_scores"]]
        metrics = frozen._binary_metrics(final_targets, predictions)
        post_hoc.append({"threshold": threshold, "metrics": metrics})
    oracle = max(
        post_hoc,
        key=lambda row: (
            float(row["metrics"]["queue_f1"]) - 0.60 * float(row["metrics"]["benign_like_false_positive_rate"]),
            -float(row["metrics"]["benign_like_false_positive_rate"]),
        ),
    )
    profile = fit_ood_profile(dataset, fit_idx)
    _ood_rows, ood_summary = score_ood_rows(
        dataset,
        profile,
        final_idx,
        leading["final_scores"],
        threshold=selected_threshold,
    )
    categorical_unseen = {}
    for column in dataset["feature_meta"]["categorical_features"]:
        known = profile["known_categories"].get(column, set())
        final_values = [
            str(value).strip().lower()
            for value in dataset["frame"].iloc[final_idx][column].dropna().tolist()
        ]
        unseen = [value for value in final_values if value not in known]
        categorical_unseen[column] = {
            "final_rows_with_values": len(final_values),
            "unseen_rows": len(unseen),
            "unseen_rate": round(len(unseen) / max(1, len(final_values)), 6),
            "unseen_value_count": len(set(unseen)),
        }
    threshold_target_rate = sum(1 for index in threshold_idx if dataset["targets"][index] == "needs_review") / max(1, len(threshold_idx))
    final_target_rate = sum(1 for index in final_idx if dataset["targets"][index] == "needs_review") / max(1, len(final_idx))
    final_by_target: dict[str, list[float]] = defaultdict(list)
    for target, score in zip(final_targets, leading["final_scores"], strict=True):
        final_by_target[target].append(score)
    root_causes = []
    if distributions["original_label"]["total_variation_distance"] >= 0.25:
        root_causes.append("chronological label prevalence changed materially")
    if distributions["label_source"]["total_variation_distance"] >= 0.25:
        root_causes.append("label provenance is chronologically clustered")
    if distributions["app"]["total_variation_distance"] >= 0.25:
        root_causes.append("application mix changed materially between fit and final windows")
    if abs(threshold_target_rate - final_target_rate) >= 0.25:
        root_causes.append("threshold-selection and final windows have opposing queue prevalence")
    if ood_summary["ood_rate"] >= 0.10:
        root_causes.append("a material share of final rows is out of fit-distribution")
    return {
        "available": True,
        "status": "diagnosed",
        "partition_id": partition.get("partition_id"),
        "partition_sizes": leakage["partition_sizes"],
        "quarantined_near_duplicate_rows": leakage.get("quarantined_rows"),
        "zero_leakage": bool(leakage.get("passed")),
        "time_boundaries": partition.get("time_boundaries") or {},
        "distributions": distributions,
        "largest_numeric_feature_shifts": _numeric_drift(dataset, fit_idx, final_idx)[:15],
        "categorical_unseen": categorical_unseen,
        "missingness": {
            "fit_rate": profile["fit_missing_rate"],
            "final_rate": round(
                mean(
                    float(dataset["frame"].iloc[final_idx][column].isna().mean())
                    for column in [
                        *dataset["feature_meta"]["numeric_features"],
                        *dataset["feature_meta"]["categorical_features"],
                    ]
                ),
                6,
            ),
        },
        "threshold_behavior": {
            "selected_threshold": selected_threshold,
            "selected_on": "threshold partition only",
            "threshold_partition_queue_prevalence": round(threshold_target_rate, 6),
            "final_test_queue_prevalence": round(final_target_rate, 6),
            "threshold_scores": _score_summary(leading["threshold_scores"]),
            "final_scores": _score_summary(leading["final_scores"]),
            "final_scores_by_target": {
                target: _score_summary(scores) for target, scores in sorted(final_by_target.items())
            },
            "post_hoc_final_oracle_diagnostic_only": {
                "threshold": oracle["threshold"],
                "metrics": oracle["metrics"],
                "used_for_strategy_selection": False,
                "used_for_tuning": False,
            },
        },
        "ood": ood_summary,
        "root_causes": root_causes,
        "final_test_labels_used_for_tuning": False,
        "raw_logs_included": False,
        "private_identifiers_included": False,
    }


def _readiness(
    selected: dict[str, Any] | None,
    external: dict[str, Any],
    split_results: list[dict[str, Any]],
    rolling_results: list[dict[str, Any]],
    layered: dict[str, Any],
    safety: dict[str, Any],
) -> dict[str, Any]:
    checks = [
        {
            "name": "one supervised strategy passes every strict internal view",
            "passed": bool(selected and selected.get("candidate_selected")),
            "value": (selected or {}).get("name"),
            "target": "all required and rolling views",
            "failure_message": "No supervised strategy passes every strict internal and rolling-temporal view",
        },
        {
            "name": "every required split is evaluated without fabricated source evidence",
            "passed": all(split.get("status") == "evaluated" for split in split_results),
            "value": {
                str(split["split_mode"]): str(split.get("status")) for split in split_results
            },
            "target": "all evaluated",
            "failure_message": "At least one required split failed closed; no second real source was fabricated",
        },
        {
            "name": "rolling temporal windows are leakage-free and evaluated",
            "passed": all(
                split.get("status") == "evaluated"
                and bool((split.get("leakage_audit") or {}).get("passed"))
                for split in rolling_results
            ),
            "value": {
                str(split["split_mode"]): str(split.get("status")) for split in rolling_results
            },
            "target": f"{V53_ROLLING_WINDOWS}/{V53_ROLLING_WINDOWS}",
            "failure_message": "Rolling temporal validation did not fully evaluate leakage-free",
        },
        {
            "name": "locked external benchmark passes without tuning",
            "passed": bool(external.get("passed_v49_gates")),
            "value": bool(external.get("passed_v49_gates")),
            "target": True,
            "failure_message": "Locked external benchmark remains below strict gates",
        },
        {
            "name": "layered rules/anomaly/supervised/hybrid matrix stays exact",
            "passed": bool(
                layered.get("available")
                and int(layered.get("failed_count") or 0) == 0
                and int(layered.get("false_positive_count") or 0) == 0
                and int(layered.get("false_negative_count") or 0) == 0
            ),
            "value": layered,
            "target": "zero failures, FP, FN, and responses",
            "failure_message": "Layered detection validation is not clean",
        },
        {
            "name": "evaluation is read-only with zero response side effects",
            "passed": bool(
                safety.get("database_counts_unchanged")
                and safety.get("active_artifact_unchanged")
                and int(safety.get("response_actions_created") or 0) == 0
            ),
            "value": {
                "database_counts_unchanged": safety.get("database_counts_unchanged"),
                "active_artifact_unchanged": safety.get("active_artifact_unchanged"),
                "response_actions_created": safety.get("response_actions_created"),
            },
            "target": "all true and zero responses",
            "failure_message": "Read-only or response-safety invariant failed",
        },
    ]
    return {
        "decision": "shadow_observation",
        "diagnostic_candidate_available": bool(selected and selected.get("candidate_selected")),
        "checks_passed": sum(1 for check in checks if check["passed"]),
        "checks_total": len(checks),
        "checks": checks,
        "blockers": [check["failure_message"] for check in checks if not check["passed"]],
        "production_promoted": False,
        "model_activated": False,
        "model_artifact_written": False,
        "response_automation_allowed": False,
        "real_firewall_blocking_enabled": False,
    }


def _render_report(result: dict[str, Any]) -> str:
    selected = result.get("selected_diagnostic_strategy") or {}
    diagnosis = result.get("temporal_diagnosis") or {}
    lines = [
        "# v5.3 Temporal Generalization Repair And Independent Evidence Preparation",
        "",
        f"- Generated: `{result['generated_at']}`",
        f"- Reviewed latest labels: `{result['dataset']['reviewed_latest_rows']}`",
        f"- Dataset fingerprint: `{result['dataset']['fingerprint']}`",
        f"- Lifecycle: `{result['readiness']['decision']}`",
        "- Rules alert-authoritative: `true`",
        "- Model activated: `false`",
        "- Production promoted: `false`",
        "- Response automation: `false`",
        "",
        "## Temporal FPR Diagnosis",
        "",
    ]
    for cause in diagnosis.get("root_causes") or ["No root-cause conclusion available."]:
        lines.append(f"- {cause}")
    threshold = diagnosis.get("threshold_behavior") or {}
    lines.extend(
        [
            f"- Frozen threshold: `{threshold.get('selected_threshold')}`",
            f"- Threshold-window queue prevalence: `{threshold.get('threshold_partition_queue_prevalence')}`",
            f"- Final-window queue prevalence: `{threshold.get('final_test_queue_prevalence')}`",
            f"- Final OOD rate: `{(diagnosis.get('ood') or {}).get('ood_rate')}`",
            "- Post-hoc final labels were used for diagnosis only, never fitting, calibration, threshold selection, or ranking.",
            "",
            "## Strategy Stability",
            "",
            f"- Leading diagnostic comparator: `{selected.get('name')}`",
            f"- Candidate selected: `{selected.get('candidate_selected', False)}`",
            "",
            "| Strategy | Views | Strict Passes | Worst F1 | Worst FPR | Material Collapse |",
            "|---|---:|---:|---:|---:|---:|",
        ]
    )
    for name, summary in sorted(result.get("strategy_comparison", {}).items()):
        ranges = summary.get("metric_ranges") or {}
        lines.append(
            f"| {name} | {summary.get('evaluated_views')}/{summary.get('required_views')} | "
            f"{summary.get('strict_passing_views')} | {(ranges.get('queue_f1') or {}).get('min')} | "
            f"{(ranges.get('benign_like_false_positive_rate') or {}).get('max')} | "
            f"{summary.get('material_split_collapse')} |"
        )
    lines.extend(
        [
            "",
            "## OOD And Abstention Contract",
            "",
            "- OOD profiles are fitted on fit rows only.",
            "- Missing schema, unseen categories, robust feature-range drift, missingness drift, and unstable confidence are measured.",
            "- Abstention is `insufficient_model_evidence`; it is not a threat prediction.",
            "- Abstained rows still enter the analyst review queue for strict queue metrics, so abstention cannot hide false positives.",
            "",
            "## Evidence Limitations",
            "",
            "- Source holdout fails closed until at least two independent real devices exist.",
            "- Locked external row-level evidence is not reused for tuning.",
            "- Existing disposable private PAN-OS evidence is aggregate-only and remains outside Git.",
            "",
            "## Safety",
            "",
            "- No labels were authored or overwritten.",
            "- No model artifact was written, activated, or promoted.",
            "- No response action was created.",
            "- Generated evidence contains aggregates, not raw logs or private identifiers.",
        ]
    )
    return "\n".join(lines) + "\n"


def run_v53_temporal_generalization(
    db: Session,
    *,
    output_dir: str | Path = OUTPUT_DIR,
    min_samples: int = 100,
    write_output: bool = True,
) -> dict[str, Any]:
    started = time.perf_counter()
    output = Path(output_dir)
    before_counts = frozen._database_counts(db)
    before_artifact = frozen._artifact_state()
    dataset = v52._prepare_dataset(db, min_samples=min_samples)
    if not dataset.get("ok"):
        return {
            "ok": False,
            "status": dataset.get("status", "failed_closed"),
            "message": dataset.get("message"),
            "version": V53_VERSION,
            "readiness": {"decision": "shadow_observation"},
        }
    baseline = freeze_v52_baseline(db, dataset, output_dir=output)
    artifact = _v51_artifact_reference(db, dataset)
    temporal_diagnosis = diagnose_temporal_failure(dataset)
    split_results = [
        _run_required_split(dataset, split_mode, artifact=artifact)
        for split_mode in V53_REQUIRED_SPLITS
    ]
    rolling_results = _run_rolling_splits(dataset, artifact=artifact)
    comparison = _strategy_comparison(split_results, rolling_results)
    selected = _select_diagnostic(comparison)
    external = reliability._locked_external_evidence(output)
    external["v5_3_candidate_scoring"] = {
        "status": "failed_closed_row_level_locked_snapshot_not_available",
        "new_candidates_scored": False,
        "reason": (
            "Only the frozen aggregate benchmark report is present. Provider labels and row-level predictions remain locked; "
            "they were not used to tune v5.3."
        ),
        "used_for_fit": False,
        "used_for_calibration": False,
        "used_for_threshold_selection": False,
        "used_for_tuning": False,
    }
    _baseline_path, repaired_path = v52._layered_reports()
    layered = v52._layered_summary(v52._safe_json(repaired_path), repaired_path)
    controlled_path = v52._latest_json(v52.SCENARIO_REPORT_DIR, "detection_validation_*.json")
    controlled = v52._controlled_scenario_summary(v52._safe_json(controlled_path), controlled_path)
    private = v52._safe_private_summary()
    after_counts = frozen._database_counts(db)
    after_artifact = frozen._artifact_state()
    safety = {
        "database_counts_before": before_counts,
        "database_counts_after": after_counts,
        "database_counts_unchanged": before_counts == after_counts,
        "active_artifact_before": before_artifact,
        "active_artifact_after": after_artifact,
        "active_artifact_unchanged": before_artifact == after_artifact,
        "labels_written": False,
        "model_runs_created": after_counts["ml_model_runs"] - before_counts["ml_model_runs"],
        "model_activated": False,
        "model_artifact_written": False,
        "production_promoted": False,
        "response_actions_created": after_counts["response_actions"] - before_counts["response_actions"],
        "response_automation_allowed": False,
        "real_firewall_blocking_enabled": False,
    }
    readiness = _readiness(
        selected,
        external,
        split_results,
        rolling_results,
        layered,
        safety,
    )

    def public_split(split: dict[str, Any]) -> dict[str, Any]:
        return {
            **{key: value for key, value in split.items() if key != "strategies"},
            "strategies": [
                reliability._public_strategy(strategy) for strategy in split.get("strategies") or []
            ],
        }

    artifact_public = {
        key: value
        for key, value in artifact.items()
        if key != "model" and key not in {"artifact_sha256"}
    }
    result = {
        "ok": bool(
            safety["database_counts_unchanged"]
            and safety["active_artifact_unchanged"]
            and safety["response_actions_created"] == 0
        ),
        "status": "completed_read_only_evaluation",
        "version": V53_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "protocol": {
            "required_splits": list(V53_REQUIRED_SPLITS),
            "rolling_temporal_windows": V53_ROLLING_WINDOWS,
            "strict_gates": reliability.STRICT_GATES,
            "ood_policy": OOD_POLICY,
            "fit_calibration_threshold_final_roles_separated": True,
            "rolling_final_labels_reused_for_tuning": False,
            "final_test_used_for_tuning": False,
            "external_labels_used_for_tuning": False,
            "diagnostic_ranking_may_not_activate_model": True,
            "rules_alert_authoritative": True,
        },
        "baseline_freeze": baseline,
        "dataset": {
            "reviewed_latest_rows": len(dataset["rows"]),
            "fingerprint": _dataset_fingerprint(dataset),
            "feature_count": len(dataset["feature_meta"]["numeric_features"])
            + len(dataset["feature_meta"]["categorical_features"]),
            "feature_generation_seconds": dataset["feature_generation_seconds"],
            "label_provenance": dataset["label_provenance"],
            "queue_target_distribution": dict(Counter(dataset["targets"])),
            "leakage_groups": frozen.assign_leakage_groups(dataset["rows"]),
            "raw_logs_included": False,
        },
        "v5_1_artifact_reference": artifact_public,
        "temporal_diagnosis": temporal_diagnosis,
        "splits": [public_split(split) for split in split_results],
        "rolling_temporal": [public_split(split) for split in rolling_results],
        "strategy_comparison": comparison,
        "selected_diagnostic_strategy": selected,
        "external_benchmark": external,
        "controlled_scenario_evidence": controlled,
        "layered_validation": layered,
        "private_shadow_evidence": private,
        "readiness": readiness,
        "review_sample": {
            "generated": False,
            "import_ready": False,
            "reason": "v5.3 changes model diagnostics and abstention policy; it does not create or overwrite labels.",
        },
        "safety": safety,
        "runtime_seconds": round(time.perf_counter() - started, 4),
    }
    if write_output:
        output.mkdir(parents=True, exist_ok=True)
        stamp = _stamp()
        report_path = output / f"v5_3_temporal_generalization_{stamp}.md"
        latest_path = output / V53_LATEST
        result["reports"] = {
            "markdown": str(report_path),
            "latest_json": str(latest_path),
        }
        report_path.write_text(_render_report(result), encoding="utf-8")
        latest_path.write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")
    return result
