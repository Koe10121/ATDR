from __future__ import annotations

import hashlib
import json
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from statistics import mean
from typing import Any

from sqlalchemy.orm import Session

from atdr.app.core.config import get_settings
from atdr.app.detection import v398_independent_holdout_validation as frozen
from atdr.app.detection import v49_detection_ml_reliability as reliability
from atdr.app.detection import v52_shadow_reliability as v52
from atdr.app.detection import v54_temporal_evidence as v54
from atdr.app.detection.ml_detector import logs_to_records
from atdr.app.detection.v330_detection_ml_quality import OUTPUT_DIR
from atdr.app.detection.v331_noise_reduction import _build_pipeline_for_columns


V55_VERSION = "v5.5-development-model-repair-anomaly-audit-v1"
V55_LATEST = "v5_5_development_model_repair_latest.json"
NESTED_PREFIX_SHARES = (0.70, 0.85, 1.0)
BENIGN_CONTROL_SCENARIOS = (
    "normal_allowed_traffic",
    "normal_web_dns_quic_traffic",
    "benign_dns_web_traffic",
    "benign_incomplete_allow_noise",
    "benign_repeated_internal_service",
    "benign_high_volume_single_service",
    "normal_high_volume_but_allowed_traffic",
    "normal_repeated_same_service_traffic",
)
DEVELOPMENT_GATES = {
    "benign_like_false_positive_rate_max": 0.10,
    "queue_f1_min": 0.85,
    "suspicious_recall_min": 0.80,
    "malicious_recall_min": 0.80,
    "expected_calibration_error_max": 0.10,
    "max_confidence_accuracy_gap_max": 0.15,
}
CANDIDATE_SPECS = (
    {
        "name": "calibrated_extra_trees",
        "model_type": "extra_trees",
        "target_mode": "binary_soc_queue",
        "calibration_method": "sigmoid",
    },
    {
        "name": "calibrated_hist_gradient_boosting",
        "model_type": "hist_gradient_boosting",
        "target_mode": "binary_soc_queue",
        "calibration_method": "sigmoid",
    },
    {
        "name": "calibrated_logistic_regression",
        "model_type": "logistic_regression",
        "target_mode": "binary_soc_queue",
        "calibration_method": "sigmoid",
    },
    {
        "name": "three_class_soc_queue_extra_trees",
        "model_type": "extra_trees",
        "target_mode": "three_class_soc_queue",
        "calibration_method": "sigmoid",
    },
    {
        "name": "hierarchical_two_stage_extra_trees",
        "model_type": "extra_trees",
        "target_mode": "hierarchical_two_stage",
        "calibration_method": "sigmoid",
    },
)


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _stable_hash(value: Any) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        default=str,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _file_state(path: Path) -> dict[str, Any]:
    if not path.exists() or not path.is_file():
        return {
            "exists": False,
            "artifact_name": path.name,
            "size_bytes": None,
            "sha256": None,
            "path_returned": False,
        }
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return {
        "exists": True,
        "artifact_name": path.name,
        "size_bytes": int(path.stat().st_size),
        "sha256": digest.hexdigest(),
        "path_returned": False,
    }


def _model_artifact_states() -> dict[str, Any]:
    settings = get_settings()
    return {
        "supervised": _file_state(settings.resolved_supervised_model_path),
        "isolation_forest": _file_state(settings.resolved_model_path),
    }


def _three_class_targets(labels: list[str]) -> list[str]:
    mapping = {
        "benign": "benign_like",
        "benign_unusual": "benign_like",
        "needs_context": "suspicious",
        "suspicious": "suspicious",
        "malicious": "malicious",
    }
    return [mapping[label] for label in labels]


def build_development_dataset(
    dataset: dict[str, Any],
    canonical_partition: dict[str, Any],
) -> dict[str, Any]:
    development_indices = sorted(
        {
            int(index)
            for key in ("fit_idx", "calibration_idx", "threshold_idx")
            for index in canonical_partition.get(key, [])
        }
    )
    locked_indices = {
        int(index)
        for key in ("final_test_idx", "quarantined_idx")
        for index in canonical_partition.get(key, [])
    }
    if set(development_indices) & locked_indices:
        raise ValueError("Development evidence overlaps locked or quarantined evidence.")

    rows: list[dict[str, Any]] = []
    for new_index, original_index in enumerate(development_indices):
        row = dict(dataset["rows"][original_index])
        row["governed_index"] = original_index
        row["index"] = new_index
        row["evidence_role"] = "development"
        rows.append(row)
    result = {
        "ok": True,
        "imports": dataset["imports"],
        "labels": [dataset["labels"][index] for index in development_indices],
        "logs": [dataset["logs"][index] for index in development_indices],
        "frame": dataset["frame"].iloc[development_indices].reset_index(drop=True),
        "rows": rows,
        "targets": [dataset["targets"][index] for index in development_indices],
        "original_labels": [
            dataset["original_labels"][index] for index in development_indices
        ],
        "feature_meta": dataset["feature_meta"],
        "label_provenance": dataset.get("label_provenance") or {},
        "governed_indices": development_indices,
        "locked_indices_included": False,
        "locked_label_count": 0,
    }
    result["development_fingerprint"] = _stable_hash(
        [
            {
                "log_id": row.get("log_id"),
                "label_id": row.get("label_id"),
                "leakage_group": row.get("leakage_group"),
            }
            for row in rows
        ]
    )
    return result


def _group_order(rows: list[dict[str, Any]]) -> list[tuple[str, list[int]]]:
    groups: dict[str, list[int]] = defaultdict(list)
    for index, row in enumerate(rows):
        groups[str(row["leakage_group"])].append(index)
    ordered = sorted(
        groups.items(),
        key=lambda item: (
            max(
                rows[index].get("timestamp")
                or datetime.min.replace(tzinfo=timezone.utc)
                for index in item[1]
            ),
            item[0],
        ),
    )
    return [(name, sorted(indices)) for name, indices in ordered]


def _subset_dataset(dataset: dict[str, Any], indices: list[int]) -> dict[str, Any]:
    ordered = sorted(set(indices))
    rows = []
    for new_index, old_index in enumerate(ordered):
        row = dict(dataset["rows"][old_index])
        row["parent_development_index"] = old_index
        row["index"] = new_index
        rows.append(row)
    return {
        "ok": True,
        "imports": dataset["imports"],
        "labels": [dataset["labels"][index] for index in ordered],
        "logs": [dataset["logs"][index] for index in ordered],
        "frame": dataset["frame"].iloc[ordered].reset_index(drop=True),
        "rows": rows,
        "targets": [dataset["targets"][index] for index in ordered],
        "original_labels": [dataset["original_labels"][index] for index in ordered],
        "feature_meta": dataset["feature_meta"],
        "label_provenance": dataset.get("label_provenance") or {},
        "development_indices": ordered,
        "locked_indices_included": False,
    }


def build_nested_temporal_folds(
    development: dict[str, Any],
) -> list[dict[str, Any]]:
    groups = _group_order(development["rows"])
    if len(groups) < 8:
        return [
            {
                "fold": "nested_temporal_1",
                "status": "failed_closed",
                "reason": "fewer than eight development leakage groups",
            }
        ]
    total_rows = len(development["rows"])
    folds: list[dict[str, Any]] = []
    prior_rows = 0
    for position, prefix_share in enumerate(NESTED_PREFIX_SHARES, start=1):
        target_rows = max(8, round(total_rows * prefix_share))
        cumulative = 0
        cutoff = None
        for _group, members in groups:
            cumulative += len(members)
            cutoff = max(
                development["rows"][index].get("timestamp")
                or datetime.min.replace(tzinfo=timezone.utc)
                for index in members
            )
            if cumulative >= target_rows:
                break
        selected = [
            index
            for _group, members in groups
            if max(
                development["rows"][index].get("timestamp")
                or datetime.min.replace(tzinfo=timezone.utc)
                for index in members
            )
            <= cutoff
            for index in members
        ]
        selected = sorted(set(selected))
        if len(selected) <= prior_rows:
            continue
        prior_rows = len(selected)
        fold_dataset = _subset_dataset(development, selected)
        partition = _distinct_timestamp_partition(fold_dataset["rows"])
        leakage = frozen.audit_partition_leakage(
            fold_dataset["rows"],
            partition,
        )
        folds.append(
            {
                "fold": f"nested_temporal_{position}",
                "status": "partitioned"
                if leakage.get("passed")
                else "failed_closed",
                "prefix_share": prefix_share,
                "dataset": fold_dataset,
                "partition": partition,
                "leakage_audit": leakage,
                "locked_indices_included": False,
            }
        )
    return folds


def _distinct_timestamp_partition(rows: list[dict[str, Any]]) -> dict[str, Any]:
    timestamp_counts = Counter(
        row.get("timestamp") for row in rows if row.get("timestamp") is not None
    )
    timestamps = sorted(timestamp_counts)
    if len(timestamps) < 8:
        return {
            "status": "failed",
            "reason": "fewer than eight distinct development timestamps",
            "split_mode": "temporal_holdout",
        }

    total = sum(timestamp_counts.values())
    desired = (0.50, 0.65, 0.80)
    cut_positions: list[int] = []
    cumulative = 0
    target_position = 0
    for position, timestamp in enumerate(timestamps):
        cumulative += timestamp_counts[timestamp]
        if (
            target_position < len(desired)
            and cumulative >= total * desired[target_position]
        ):
            minimum_position = cut_positions[-1] + 1 if cut_positions else 1
            maximum_position = len(timestamps) - (3 - target_position)
            cut_positions.append(
                max(minimum_position, min(position + 1, maximum_position))
            )
            target_position += 1
    while len(cut_positions) < 3:
        minimum_position = cut_positions[-1] + 1 if cut_positions else 1
        cut_positions.append(min(minimum_position, len(timestamps) - (3 - len(cut_positions))))
    calibration_start, threshold_start, final_start = [
        timestamps[position] for position in cut_positions
    ]

    grouped: dict[str, list[int]] = defaultdict(list)
    for index, row in enumerate(rows):
        grouped[str(row["leakage_group"])].append(index)
    partition = {
        "fit_idx": [],
        "calibration_idx": [],
        "threshold_idx": [],
        "final_test_idx": [],
    }
    quarantined: list[int] = []
    for members in grouped.values():
        member_times = [rows[index].get("timestamp") for index in members]
        if any(value is None for value in member_times):
            quarantined.extend(members)
            continue
        minimum = min(member_times)
        maximum = max(member_times)
        if maximum < calibration_start:
            partition["fit_idx"].extend(members)
        elif minimum >= calibration_start and maximum < threshold_start:
            partition["calibration_idx"].extend(members)
        elif minimum >= threshold_start and maximum < final_start:
            partition["threshold_idx"].extend(members)
        elif minimum >= final_start:
            partition["final_test_idx"].extend(members)
        else:
            quarantined.extend(members)
    result = {
        "status": "partitioned",
        **{key: sorted(values) for key, values in partition.items()},
        "quarantined_idx": sorted(quarantined),
        "split_mode": "temporal_holdout",
        "partition_method": (
            "distinct_timestamp_chronological_leakage_groups_with_boundary_quarantine"
        ),
        "time_boundaries": {
            "calibration_start": calibration_start.isoformat(),
            "threshold_start": threshold_start.isoformat(),
            "final_start": final_start.isoformat(),
        },
        "final_test_labels_used_for_training": False,
        "final_test_labels_used_for_calibration": False,
        "final_test_labels_used_for_threshold_selection": False,
    }
    result["partition_id"] = _stable_hash(
        {
            "protocol": "v5.5-distinct-timestamp-nested-temporal-v1",
            "fit": [rows[index]["log_id"] for index in result["fit_idx"]],
            "calibration": [
                rows[index]["log_id"] for index in result["calibration_idx"]
            ],
            "threshold": [
                rows[index]["log_id"] for index in result["threshold_idx"]
            ],
            "final": [
                rows[index]["log_id"] for index in result["final_test_idx"]
            ],
        }
    )
    return result


def build_source_aware_development_view(
    development: dict[str, Any],
) -> dict[str, Any]:
    source_count = len(
        {
            str(row.get("source_name") or "unknown_source")
            for row in development["rows"]
        }
    )
    if source_count < 2:
        return {
            "fold": "development_source_holdout",
            "status": "failed_closed",
            "reason": "fewer than two development source identities",
            "source_identity_count": source_count,
            "locked_indices_included": False,
        }
    partition = frozen.build_frozen_partition(
        development["rows"],
        split_mode="source_holdout",
        final_test_size=0.20,
        calibration_size=0.15,
        threshold_size=0.15,
    )
    leakage = frozen.audit_partition_leakage(
        development["rows"],
        partition,
    )
    return {
        "fold": "development_source_holdout",
        "status": "partitioned" if leakage.get("passed") else "failed_closed",
        "source_identity_count": source_count,
        "dataset": development,
        "partition": partition,
        "leakage_audit": leakage,
        "locked_indices_included": False,
    }


def _provenance_balanced_weights(
    dataset: dict[str, Any],
    indices: list[int],
) -> tuple[list[float], dict[str, Any]]:
    provenance = [
        str(dataset["rows"][index].get("label_source") or "unknown")
        for index in indices
    ]
    counts = Counter(provenance)
    total = max(1, len(indices))
    group_count = max(1, len(counts))
    raw = [
        min(4.0, max(0.25, total / (group_count * counts[value])))
        for value in provenance
    ]
    average = mean(raw) if raw else 1.0
    weights = [min(4.0, max(0.25, value / average)) for value in raw]
    return weights, {
        "strategy": "inverse_provenance_frequency_clipped",
        "provenance_groups": len(counts),
        "distribution": dict(sorted(counts.items())),
        "minimum_weight": round(min(weights), 4) if weights else None,
        "maximum_weight": round(max(weights), 4) if weights else None,
        "mean_weight": round(mean(weights), 4) if weights else None,
    }


def _target_config(
    dataset: dict[str, Any],
    spec: dict[str, Any],
) -> tuple[list[str], set[str]]:
    if spec["target_mode"] == "three_class_soc_queue":
        return _three_class_targets(dataset["original_labels"]), {
            "suspicious",
            "malicious",
        }
    return list(dataset["targets"]), {"needs_review"}


def _fit_pipeline(
    dataset: dict[str, Any],
    partition: dict[str, Any],
    spec: dict[str, Any],
) -> dict[str, Any]:
    fit_idx = list(partition["fit_idx"])
    calibration_idx = list(partition["calibration_idx"])
    threshold_idx = list(partition["threshold_idx"])
    evaluation_idx = list(partition["final_test_idx"])
    targets, positive_classes = _target_config(dataset, spec)
    y_fit = [targets[index] for index in fit_idx]
    if len(set(y_fit)) < 2:
        return {
            "status": "failed_closed",
            "reason": "fit partition has fewer than two target classes",
        }

    pipeline = _build_pipeline_for_columns(
        dataset["imports"],
        model_type=str(spec["model_type"]),
        class_weight="balanced"
        if spec["model_type"] in {"extra_trees", "logistic_regression"}
        else None,
        numeric_features=dataset["feature_meta"]["numeric_features"],
        categorical_features=dataset["feature_meta"]["categorical_features"],
    )
    weights, weighting = _provenance_balanced_weights(dataset, fit_idx)
    started = time.perf_counter()
    pipeline.fit(
        dataset["frame"].iloc[fit_idx],
        y_fit,
        model__sample_weight=weights,
    )
    model, calibration_method = reliability._fit_frozen_calibrator(
        pipeline,
        dataset["frame"],
        calibration_idx,
        targets,
        method=str(spec["calibration_method"]),
    )
    threshold_scores = reliability._queue_scores(
        model,
        dataset["frame"],
        threshold_idx,
        positive_classes,
    )
    threshold_selection = reliability.select_v49_threshold(
        [dataset["targets"][index] for index in threshold_idx],
        threshold_scores,
    )
    evaluation_scores = reliability._queue_scores(
        model,
        dataset["frame"],
        evaluation_idx,
        positive_classes,
    )
    threshold = float(threshold_selection["selected_threshold"])
    predictions = [
        "needs_review" if score >= threshold else "non_threat"
        for score in evaluation_scores
    ]
    y_true = [dataset["targets"][index] for index in evaluation_idx]
    metrics = frozen._binary_metrics(y_true, predictions)
    metrics.update(
        frozen._diagnostic_original_recall(
            dataset["rows"],
            evaluation_idx,
            predictions,
        )
    )
    calibration = frozen._calibration_report(y_true, evaluation_scores)
    classification = None
    severity_model = None
    if spec["target_mode"] == "three_class_soc_queue":
        direct = [
            str(value)
            for value in model.predict(dataset["frame"].iloc[evaluation_idx])
        ]
        classification = reliability._classification_diagnostics(
            [
                _three_class_targets(dataset["original_labels"])[index]
                for index in evaluation_idx
            ],
            direct,
        )
    elif spec["target_mode"] == "hierarchical_two_stage":
        severity_fit = [
            index
            for index in fit_idx
            if dataset["original_labels"][index] in {"suspicious", "malicious"}
        ]
        severity_targets = [
            dataset["original_labels"][index] for index in severity_fit
        ]
        if len(set(severity_targets)) >= 2:
            severity_model = _build_pipeline_for_columns(
                dataset["imports"],
                model_type="extra_trees",
                class_weight="balanced",
                numeric_features=dataset["feature_meta"]["numeric_features"],
                categorical_features=dataset["feature_meta"]["categorical_features"],
            )
            severity_weights, _ = _provenance_balanced_weights(
                dataset,
                severity_fit,
            )
            severity_model.fit(
                dataset["frame"].iloc[severity_fit],
                severity_targets,
                model__sample_weight=severity_weights,
            )
            severity_predictions = [
                str(value)
                for value in severity_model.predict(
                    dataset["frame"].iloc[evaluation_idx]
                )
            ]
            combined = [
                severity if queue == "needs_review" else "benign_like"
                for queue, severity in zip(
                    predictions,
                    severity_predictions,
                    strict=True,
                )
            ]
            classification = reliability._classification_diagnostics(
                [
                    _three_class_targets(dataset["original_labels"])[index]
                    for index in evaluation_idx
                ],
                combined,
            )

    return {
        "status": "evaluated",
        "name": spec["name"],
        "target_mode": spec["target_mode"],
        "model_type": spec["model_type"],
        "metrics": metrics,
        "calibration": calibration,
        "threshold_selection": threshold_selection,
        "error_patterns": frozen._error_patterns(
            dataset["rows"],
            evaluation_idx,
            y_true,
            predictions,
        ),
        "classification_diagnostics": classification,
        "sample_weighting": weighting,
        "calibration_method": calibration_method,
        "fit_rows": len(fit_idx),
        "calibration_rows": len(calibration_idx),
        "threshold_rows": len(threshold_idx),
        "evaluation_rows": len(evaluation_idx),
        "training_seconds": round(time.perf_counter() - started, 4),
        "final_labels_used_for_fit": False,
        "final_labels_used_for_calibration": False,
        "final_labels_used_for_threshold_selection": False,
        "active_artifact_written": False,
        "_model": model,
        "_severity_model": severity_model,
    }


def _public_evaluation(result: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in result.items()
        if not key.startswith("_")
    }


def _gate_result(result: dict[str, Any]) -> dict[str, Any]:
    metrics = result.get("metrics") or {}
    calibration = result.get("calibration") or {}
    suspicious = metrics.get("suspicious_recall")
    malicious = metrics.get("malicious_recall")

    def number(mapping: dict[str, Any], key: str, default: float) -> float:
        value = mapping.get(key)
        return default if value is None else float(value)

    checks = {
        "queue_f1": number(metrics, "queue_f1", 0)
        >= DEVELOPMENT_GATES["queue_f1_min"],
        "benign_like_false_positive_rate": number(
            metrics,
            "benign_like_false_positive_rate",
            1,
        )
        <= DEVELOPMENT_GATES["benign_like_false_positive_rate_max"],
        "suspicious_recall": suspicious is not None
        and float(suspicious) >= DEVELOPMENT_GATES["suspicious_recall_min"],
        "malicious_recall": malicious is not None
        and float(malicious) >= DEVELOPMENT_GATES["malicious_recall_min"],
        "expected_calibration_error": number(
            calibration,
            "expected_calibration_error",
            1,
        )
        <= DEVELOPMENT_GATES["expected_calibration_error_max"],
        "max_confidence_accuracy_gap": number(
            calibration,
            "max_confidence_accuracy_gap",
            1,
        )
        <= DEVELOPMENT_GATES["max_confidence_accuracy_gap_max"],
    }
    return {
        "passed": all(checks.values()),
        "checks": checks,
        "gates": DEVELOPMENT_GATES,
    }


def run_development_comparison(
    development: dict[str, Any],
) -> dict[str, Any]:
    temporal_folds = build_nested_temporal_folds(development)
    source_view = build_source_aware_development_view(development)
    views = [*temporal_folds, source_view]
    public_views: list[dict[str, Any]] = []
    by_strategy: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for view in views:
        if view.get("status") != "partitioned":
            public_views.append(
                {
                    key: value
                    for key, value in view.items()
                    if key not in {"dataset", "partition"}
                }
            )
            continue
        evaluations = []
        for spec in CANDIDATE_SPECS:
            evaluated = _fit_pipeline(
                view["dataset"],
                view["partition"],
                spec,
            )
            public = _public_evaluation(evaluated)
            public["development_gate"] = _gate_result(public)
            evaluations.append(public)
            by_strategy[str(spec["name"])].append(
                {
                    "view": view["fold"],
                    **public,
                }
            )
        public_views.append(
            {
                "fold": view["fold"],
                "status": view["status"],
                "prefix_share": view.get("prefix_share"),
                "source_identity_count": view.get("source_identity_count"),
                "partition_sizes": (
                    view.get("leakage_audit") or {}
                ).get("partition_sizes"),
                "leakage_audit_passed": bool(
                    (view.get("leakage_audit") or {}).get("passed")
                ),
                "locked_indices_included": False,
                "strategies": evaluations,
            }
        )

    summaries: dict[str, Any] = {}
    required_temporal = {
        f"nested_temporal_{index}"
        for index in range(1, len(NESTED_PREFIX_SHARES) + 1)
    }
    for name, evaluations in by_strategy.items():
        temporal = [
            item for item in evaluations if item["view"] in required_temporal
        ]
        metrics = [item["metrics"] for item in temporal]
        calibration = [item["calibration"] for item in temporal]
        summaries[name] = {
            "evaluated_temporal_folds": len(temporal),
            "required_temporal_folds": len(required_temporal),
            "passing_temporal_folds": sum(
                1
                for item in temporal
                if (item.get("development_gate") or {}).get("passed")
            ),
            "all_temporal_folds_passed": bool(temporal)
            and len(temporal) == len(required_temporal)
            and all(
                (item.get("development_gate") or {}).get("passed")
                for item in temporal
            ),
            "metric_ranges": {
                field: {
                    "min": round(min(values), 4) if values else None,
                    "max": round(max(values), 4) if values else None,
                    "mean": round(mean(values), 4) if values else None,
                }
                for field in (
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
                if (
                    values := [
                        float(item[field])
                        for item in metrics
                        if item.get(field) is not None
                    ]
                )
            },
            "calibration_ranges": {
                field: {
                    "min": round(min(values), 4) if values else None,
                    "max": round(max(values), 4) if values else None,
                    "mean": round(mean(values), 4) if values else None,
                }
                for field in (
                    "brier_score",
                    "expected_calibration_error",
                    "max_confidence_accuracy_gap",
                )
                if (
                    values := [
                        float(item[field])
                        for item in calibration
                        if item.get(field) is not None
                    ]
                )
            },
            "source_aware_view": next(
                (
                    {
                        "status": "evaluated",
                        "metrics": item["metrics"],
                        "calibration": item["calibration"],
                        "development_gate": item["development_gate"],
                    }
                    for item in evaluations
                    if item["view"] == "development_source_holdout"
                ),
                {
                    "status": source_view.get("status"),
                    "reason": source_view.get("reason"),
                    "source_identity_count": source_view.get(
                        "source_identity_count"
                    ),
                },
            ),
        }
    return {
        "protocol": "development_only_nested_temporal_v1",
        "development_rows": len(development["rows"]),
        "development_fingerprint": development["development_fingerprint"],
        "locked_indices_included": False,
        "locked_labels_used_for_selection": False,
        "provenance_balanced_sampling": True,
        "views": public_views,
        "strategy_summaries": summaries,
    }


def select_diagnostic_leader(
    comparison: dict[str, Any],
) -> dict[str, Any] | None:
    ranked = []
    for name, summary in (comparison.get("strategy_summaries") or {}).items():
        ranges = summary.get("metric_ranges") or {}

        def minimum(field: str, default: float = 0.0) -> float:
            value = (ranges.get(field) or {}).get("min")
            return default if value is None else float(value)

        def maximum(field: str, default: float = 1.0) -> float:
            value = (ranges.get(field) or {}).get("max")
            return default if value is None else float(value)

        stability_score = (
            minimum("queue_f1")
            + (0.20 * minimum("suspicious_recall"))
            + (0.20 * minimum("malicious_recall"))
            - (0.80 * maximum("benign_like_false_positive_rate"))
            - (
                0.20
                * float(
                    (
                        (summary.get("calibration_ranges") or {}).get(
                            "expected_calibration_error"
                        )
                        or {}
                    ).get("max")
                    or 1.0
                )
            )
        )
        ranked.append(
            (
                name,
                int(summary.get("passing_temporal_folds") or 0),
                int(summary.get("evaluated_temporal_folds") or 0),
                round(stability_score, 6),
                -maximum("benign_like_false_positive_rate"),
                minimum("queue_f1"),
            )
        )
    if not ranked:
        return None
    selected = max(ranked, key=lambda item: item[1:])
    summary = comparison["strategy_summaries"][selected[0]]
    return {
        "name": selected[0],
        "selection_basis": "development_roles_only",
        "locked_labels_used": False,
        "passed_all_development_gates": bool(
            summary.get("all_temporal_folds_passed")
        ),
        "summary": summary,
    }


def freeze_diagnostic_candidate(
    leader: dict[str, Any],
    development: dict[str, Any],
    evidence_lock: dict[str, Any],
) -> dict[str, Any]:
    spec = next(
        item for item in CANDIDATE_SPECS if item["name"] == leader["name"]
    )
    payload = {
        "protocol": "v5.5-development-only-candidate-freeze-v1",
        "candidate": spec,
        "development_fingerprint": development["development_fingerprint"],
        "fit_fingerprint": (
            (evidence_lock.get("roles") or {}).get("fit") or {}
        ).get("fingerprint"),
        "calibration_fingerprint": (
            (evidence_lock.get("roles") or {}).get("calibration") or {}
        ).get("fingerprint"),
        "threshold_fingerprint": (
            (evidence_lock.get("roles") or {}).get("threshold") or {}
        ).get("fingerprint"),
        "development_summary": leader["summary"],
        "locked_final_labels_read": False,
        "active_artifact_written": False,
    }
    return {
        **payload,
        "freeze_fingerprint": _stable_hash(payload),
        "status": "frozen_diagnostic_leader",
        "eligible_for_activation": False,
        "frozen_before_locked_final": True,
    }


def evaluate_locked_final_once(
    dataset: dict[str, Any],
    canonical_partition: dict[str, Any],
    candidate_freeze: dict[str, Any],
) -> dict[str, Any]:
    if not candidate_freeze.get("frozen_before_locked_final"):
        raise ValueError("Candidate must be frozen before locked-final evaluation.")
    spec = next(
        item
        for item in CANDIDATE_SPECS
        if item["name"] == candidate_freeze["candidate"]["name"]
    )
    evaluated = _fit_pipeline(dataset, canonical_partition, spec)
    public = _public_evaluation(evaluated)
    public["development_gate"] = _gate_result(public)
    return {
        "status": public.get("status"),
        "protocol": "read_only_locked_temporal_regression_one_shot",
        "candidate_freeze_fingerprint": candidate_freeze["freeze_fingerprint"],
        "candidate_frozen_before_evaluation": True,
        "used_for_candidate_selection": False,
        "used_for_calibration": False,
        "used_for_threshold_selection": False,
        "tuning_feedback_allowed": False,
        "result": public,
    }


def _distribution_summary(
    dataset: dict[str, Any],
    indices: list[int],
    anomaly_flags: list[bool],
    scores: list[float],
    *,
    field: str,
    limit: int = 12,
) -> list[dict[str, Any]]:
    groups: dict[str, list[int]] = defaultdict(list)
    for position, index in enumerate(indices):
        if field == "schema":
            app = str(dataset["rows"][index].get("app") or "unknown").lower()
            value = (
                "limited"
                if app in {"", "unknown", "unknown-tcp", "unknown-udp", "incomplete"}
                else "structured"
            )
        elif field == "month":
            timestamp = dataset["rows"][index].get("timestamp")
            value = timestamp.strftime("%Y-%m") if timestamp else "missing"
        else:
            value = str(dataset["rows"][index].get(field) or "unknown")
        groups[value].append(position)
    rows = []
    for value, positions in groups.items():
        flags = [anomaly_flags[position] for position in positions]
        values = [scores[position] for position in positions]
        rows.append(
            {
                "value": value,
                "rows": len(positions),
                "anomalies": sum(flags),
                "anomaly_rate": round(sum(flags) / len(flags), 4),
                "score_min": round(min(values), 6),
                "score_median": round(
                    sorted(values)[len(values) // 2],
                    6,
                ),
                "score_max": round(max(values), 6),
            }
        )
    return sorted(
        rows,
        key=lambda item: (item["anomalies"], item["rows"]),
        reverse=True,
    )[:limit]


def audit_isolation_forest_development(
    development: dict[str, Any],
    *,
    include_controlled_scenarios: bool,
) -> dict[str, Any]:
    settings = get_settings()
    path = settings.resolved_model_path
    artifact_before = _file_state(path)
    if not path.exists():
        return {
            "status": "artifact_unavailable",
            "artifact": artifact_before,
            "development_rows": len(development["rows"]),
            "locked_rows_scored": 0,
            "configured_database_mutated": False,
        }
    imports = development.get("imports")
    if imports is None:
        return {
            "status": "dependencies_unavailable",
            "artifact": artifact_before,
            "development_rows": len(development["rows"]),
            "locked_rows_scored": 0,
            "configured_database_mutated": False,
        }
    joblib = imports[0]
    pd = imports[1]
    model = joblib.load(path)
    frame = pd.DataFrame(logs_to_records(development["logs"]))
    feature_frame = frame.drop(columns=["id"])
    predictions = model.predict(feature_frame)
    scores = [float(value) for value in model.decision_function(feature_frame)]
    flags = [int(value) == -1 for value in predictions]
    original_labels = development["original_labels"]
    benign_positions = [
        position
        for position, label in enumerate(original_labels)
        if label in {"benign", "benign_unusual"}
    ]
    threat_positions = [
        position
        for position, label in enumerate(original_labels)
        if label in {"suspicious", "malicious"}
    ]
    needs_context_positions = [
        position
        for position, label in enumerate(original_labels)
        if label == "needs_context"
    ]

    def rate(positions: list[int]) -> float | None:
        if not positions:
            return None
        return round(
            sum(1 for position in positions if flags[position]) / len(positions),
            4,
        )

    noise_patterns = {
        "quic_443": [],
        "incomplete_80": [],
        "ping_icmp": [],
        "unknown_udp_tcp": [],
    }
    for position, row in enumerate(development["rows"]):
        app = str(row.get("app") or "").lower()
        port = int(row.get("dst_port") or 0)
        if app == "quic-base" and port == 443:
            noise_patterns["quic_443"].append(position)
        if app == "incomplete" and port == 80:
            noise_patterns["incomplete_80"].append(position)
        if app in {"ping", "icmp"}:
            noise_patterns["ping_icmp"].append(position)
        if app in {"unknown", "unknown-udp", "unknown-tcp"}:
            noise_patterns["unknown_udp_tcp"].append(position)

    controlled = {
        "included": False,
        "status": "not_requested",
        "scenario_count": 0,
        "scored_logs": 0,
        "anomaly_signals": 0,
        "anomaly_rate": None,
        "false_positive_scenarios": 0,
        "response_actions_created": 0,
        "temporary_databases_only": True,
    }
    if include_controlled_scenarios:
        from atdr.scripts.run_layered_detection_validation import (
            run_layered_detection_validation,
        )

        scenario_report = run_layered_detection_validation(
            scenarios=list(BENIGN_CONTROL_SCENARIOS),
            variants=1,
            use_temp_db=True,
            write_output=False,
        )
        anomaly_rows = [
            row
            for row in scenario_report.get("results") or []
            if row.get("mode") == "anomaly_only"
        ]
        scored_logs = sum(
            int((row.get("diagnostics") or {}).get("scored_logs") or 0)
            for row in anomaly_rows
        )
        anomaly_signals = sum(
            int((row.get("diagnostics") or {}).get("anomaly_count") or 0)
            for row in anomaly_rows
        )
        controlled = {
            "included": True,
            "status": "evaluated",
            "scenario_count": len(anomaly_rows),
            "scored_logs": scored_logs,
            "anomaly_signals": anomaly_signals,
            "anomaly_rate": round(anomaly_signals / scored_logs, 4)
            if scored_logs
            else None,
            "false_positive_scenarios": sum(
                1 for row in anomaly_rows if row.get("false_positive")
            ),
            "scenario_results": [
                {
                    "scenario": row.get("scenario"),
                    "scored_logs": int(
                        (row.get("diagnostics") or {}).get("scored_logs") or 0
                    ),
                    "anomaly_signals": int(
                        (row.get("diagnostics") or {}).get("anomaly_count") or 0
                    ),
                    "false_positive": bool(row.get("false_positive")),
                    "passed": bool(row.get("passed")),
                }
                for row in anomaly_rows
            ],
            "response_actions_created": sum(
                int((row.get("safety") or {}).get("response_actions_created") or 0)
                for row in anomaly_rows
            ),
            "temporary_databases_only": True,
        }

    artifact_after = _file_state(path)
    return {
        "status": "evaluated",
        "artifact": artifact_before,
        "artifact_unchanged": artifact_before == artifact_after,
        "development_rows": len(flags),
        "anomaly_count": sum(flags),
        "anomaly_rate": round(sum(flags) / len(flags), 4) if flags else None,
        "benign_like_false_positive_rate_estimate": rate(benign_positions),
        "threat_detection_rate_estimate": rate(threat_positions),
        "needs_context_queue_rate_estimate": rate(needs_context_positions),
        "queue_size_estimate": sum(flags),
        "queue_rate_estimate": round(sum(flags) / len(flags), 4)
        if flags
        else None,
        "score_distribution_by_application": _distribution_summary(
            development,
            list(range(len(development["rows"]))),
            flags,
            scores,
            field="app",
        ),
        "score_distribution_by_schema": _distribution_summary(
            development,
            list(range(len(development["rows"]))),
            flags,
            scores,
            field="schema",
        ),
        "score_distribution_by_month": _distribution_summary(
            development,
            list(range(len(development["rows"]))),
            flags,
            scores,
            field="month",
        ),
        "noise_patterns": {
            name: {
                "rows": len(positions),
                "anomalies": sum(1 for position in positions if flags[position]),
                "anomaly_rate": rate(positions),
            }
            for name, positions in noise_patterns.items()
        },
        "benign_controlled_scenarios": controlled,
        "locked_rows_scored": 0,
        "configured_database_mutated": False,
        "persistent_alerts_created": 0,
        "labels_written": 0,
        "model_artifact_written": False,
        "response_actions_created": 0,
    }


def audit_isolation_forest_locked_final(
    dataset: dict[str, Any],
    canonical_partition: dict[str, Any],
    candidate_freeze: dict[str, Any],
) -> dict[str, Any]:
    if not candidate_freeze.get("frozen_before_locked_final"):
        raise ValueError("Candidate must be frozen before locked anomaly regression.")
    settings = get_settings()
    path = settings.resolved_model_path
    if not path.exists():
        return {
            "status": "artifact_unavailable",
            "candidate_frozen_before_evaluation": True,
            "used_for_selection": False,
        }
    imports = dataset["imports"]
    joblib = imports[0]
    pd = imports[1]
    final_idx = list(canonical_partition["final_test_idx"])
    model = joblib.load(path)
    frame = pd.DataFrame(
        logs_to_records([dataset["logs"][index] for index in final_idx])
    ).drop(columns=["id"])
    predictions = model.predict(frame)
    scores = [float(value) for value in model.decision_function(frame)]
    flags = [int(value) == -1 for value in predictions]
    original = [dataset["original_labels"][index] for index in final_idx]
    benign = [
        position
        for position, label in enumerate(original)
        if label in {"benign", "benign_unusual"}
    ]
    threats = [
        position
        for position, label in enumerate(original)
        if label in {"suspicious", "malicious"}
    ]

    def rate(positions: list[int]) -> float | None:
        if not positions:
            return None
        return round(
            sum(1 for position in positions if flags[position]) / len(positions),
            4,
        )

    return {
        "status": "evaluated",
        "protocol": "read_only_locked_temporal_anomaly_regression",
        "candidate_frozen_before_evaluation": True,
        "used_for_selection": False,
        "tuning_feedback_allowed": False,
        "rows": len(final_idx),
        "anomaly_count": sum(flags),
        "anomaly_rate": round(sum(flags) / len(flags), 4) if flags else None,
        "benign_like_false_positive_rate_estimate": rate(benign),
        "threat_detection_rate_estimate": rate(threats),
        "score_min": round(min(scores), 6) if scores else None,
        "score_max": round(max(scores), 6) if scores else None,
        "model_artifact_written": False,
        "configured_database_mutated": False,
    }


def _readiness(
    *,
    lock_validation: dict[str, Any],
    comparison: dict[str, Any],
    leader: dict[str, Any] | None,
    locked_final: dict[str, Any] | None,
    isolation_audit: dict[str, Any],
) -> dict[str, Any]:
    source_view = next(
        (
            view
            for view in comparison.get("views") or []
            if view.get("fold") == "development_source_holdout"
        ),
        {},
    )
    checks = [
        {
            "name": "v5.4 evidence lock matched",
            "passed": bool(lock_validation.get("passed")),
        },
        {
            "name": "development selection excluded locked labels",
            "passed": not bool(comparison.get("locked_labels_used_for_selection")),
        },
        {
            "name": "all nested temporal development gates passed",
            "passed": bool(leader and leader.get("passed_all_development_gates")),
        },
        {
            "name": "source-aware development validation available and passed",
            "passed": source_view.get("status") == "partitioned",
        },
        {
            "name": "independent real-device evidence available",
            "passed": False,
        },
        {
            "name": "locked external benchmark passed",
            "passed": False,
        },
        {
            "name": "IsolationForest benign-like FPR acceptable",
            "passed": (
                isolation_audit.get("benign_like_false_positive_rate_estimate")
                is not None
                and float(
                    isolation_audit[
                        "benign_like_false_positive_rate_estimate"
                    ]
                )
                <= DEVELOPMENT_GATES[
                    "benign_like_false_positive_rate_max"
                ]
            ),
        },
    ]
    blockers = [
        check["name"] for check in checks if not check["passed"]
    ]
    if locked_final:
        result = locked_final.get("result") or {}
        gate = result.get("development_gate") or {}
        if not gate.get("passed"):
            blockers.append(
                "Frozen diagnostic leader did not pass the locked temporal regression gates."
            )
    return {
        "decision": "shadow_observation",
        "checks_passed": sum(1 for check in checks if check["passed"]),
        "checks_total": len(checks),
        "checks": checks,
        "blockers": blockers,
        "diagnostic_leader_frozen": bool(leader),
        "candidate_selected": bool(
            leader and leader.get("passed_all_development_gates")
        ),
        "eligible_for_activation": False,
        "model_activated": False,
        "production_promoted": False,
        "response_automation_allowed": False,
        "rules_alert_authoritative": True,
    }


def _render_report(result: dict[str, Any]) -> str:
    leader = result.get("frozen_diagnostic_candidate") or {}
    locked = (
        (result.get("locked_final_regression") or {}).get("supervised") or {}
    )
    locked_metrics = (locked.get("result") or {}).get("metrics") or {}
    anomaly = result.get("isolation_forest_audit") or {}
    readiness = result.get("readiness") or {}
    lines = [
        "# v5.5 Development-Only Detection Model Repair and Anomaly Reliability Audit",
        "",
        f"Generated: {result.get('generated_at')}",
        "",
        "## Evidence Boundary",
        "",
        f"- Evidence lock: `{result.get('evidence_lock_validation', {}).get('status')}`",
        f"- Development rows: `{result.get('development_evidence', {}).get('rows')}`",
        f"- Locked rows used for model selection: `{result.get('development_evidence', {}).get('locked_labels_used_for_selection')}`",
        "- Final/rolling/external evidence was not used for fitting, calibration, threshold selection, or candidate ranking.",
        "",
        "## IsolationForest",
        "",
        f"- Development anomaly rate: `{anomaly.get('anomaly_rate')}`",
        f"- Benign-like false-positive estimate: `{anomaly.get('benign_like_false_positive_rate_estimate')}`",
        f"- Threat detection estimate: `{anomaly.get('threat_detection_rate_estimate')}`",
        f"- Controlled benign scenario anomaly rate: `{(anomaly.get('benign_controlled_scenarios') or {}).get('anomaly_rate')}`",
        "",
        "## Frozen Diagnostic Leader",
        "",
        f"- Strategy: `{leader.get('candidate', {}).get('name')}`",
        f"- Passed all development gates: `{leader.get('development_summary', {}).get('all_temporal_folds_passed')}`",
        f"- Freeze fingerprint: `{leader.get('freeze_fingerprint')}`",
        f"- Eligible for activation: `{leader.get('eligible_for_activation')}`",
        "",
        "## Locked Temporal Regression",
        "",
        f"- Queue precision: `{locked_metrics.get('queue_precision')}`",
        f"- Queue recall: `{locked_metrics.get('queue_recall')}`",
        f"- Queue F1: `{locked_metrics.get('queue_f1')}`",
        f"- Benign-like FPR: `{locked_metrics.get('benign_like_false_positive_rate')}`",
        f"- Suspicious recall: `{locked_metrics.get('suspicious_recall')}`",
        f"- Malicious recall: `{locked_metrics.get('malicious_recall')}`",
        "- This result was not fed back into selection or tuning.",
        "",
        "## Governance",
        "",
        f"- Lifecycle: `{readiness.get('decision')}`",
        f"- Checks: `{readiness.get('checks_passed')}/{readiness.get('checks_total')}`",
        "- Deterministic rules remain alert-authoritative.",
        "- No model was activated or promoted.",
        "- No active model artifact, label, detection run, or response action was written.",
        "- Automatic response and real firewall blocking remain disabled.",
        "",
        "## Remaining Blockers",
        "",
    ]
    lines.extend(
        f"- {blocker}" for blocker in readiness.get("blockers") or []
    )
    return "\n".join(lines) + "\n"


def run_v55_development_model_repair(
    db: Session,
    *,
    output_dir: str | Path = OUTPUT_DIR,
    min_samples: int = 100,
    lock_path: str | Path = v54.V53_LOCK_PATH,
    include_controlled_scenarios: bool = True,
    run_locked_final: bool = True,
    write_output: bool = True,
) -> dict[str, Any]:
    started = time.perf_counter()
    output = Path(output_dir)
    counts_before = frozen._database_counts(db)
    artifacts_before = _model_artifact_states()
    dataset = v52._prepare_dataset(db, min_samples=min_samples)
    if not dataset.get("ok"):
        return {
            "ok": False,
            "status": dataset.get("status", "failed_closed"),
            "message": dataset.get("message"),
            "version": V55_VERSION,
            "lifecycle_state": "shadow_observation",
        }
    canonical_partition = frozen.build_frozen_partition(
        dataset["rows"],
        split_mode="temporal_holdout",
    )
    leakage = frozen.audit_partition_leakage(
        dataset["rows"],
        canonical_partition,
    )
    if not leakage.get("passed"):
        return {
            "ok": False,
            "status": "failed_closed",
            "message": "Canonical temporal evidence failed leakage containment.",
            "version": V55_VERSION,
            "lifecycle_state": "shadow_observation",
        }
    evidence_lock = v54.build_evidence_lock(dataset, output_dir=output)
    lock_validation = v54.validate_evidence_lock(
        evidence_lock,
        lock_path=Path(lock_path),
    )
    if not lock_validation.get("passed"):
        return {
            "ok": False,
            "status": "failed_closed",
            "message": "v5.4 evidence lock mismatch; development evaluation refused.",
            "version": V55_VERSION,
            "lifecycle_state": "shadow_observation",
            "evidence_lock_validation": lock_validation,
        }

    development = build_development_dataset(dataset, canonical_partition)
    isolation_audit = audit_isolation_forest_development(
        development,
        include_controlled_scenarios=include_controlled_scenarios,
    )
    comparison = run_development_comparison(development)
    leader = select_diagnostic_leader(comparison)
    candidate_freeze = (
        freeze_diagnostic_candidate(leader, development, evidence_lock)
        if leader
        else None
    )
    locked_final: dict[str, Any] | None = None
    if candidate_freeze and run_locked_final:
        locked_final = {
            "supervised": evaluate_locked_final_once(
                dataset,
                canonical_partition,
                candidate_freeze,
            ),
            "isolation_forest": audit_isolation_forest_locked_final(
                dataset,
                canonical_partition,
                candidate_freeze,
            ),
        }

    counts_after = frozen._database_counts(db)
    artifacts_after = _model_artifact_states()
    safety = {
        "database_counts_before": counts_before,
        "database_counts_after": counts_after,
        "database_counts_unchanged": counts_before == counts_after,
        "model_artifacts_before": artifacts_before,
        "model_artifacts_after": artifacts_after,
        "model_artifacts_unchanged": artifacts_before == artifacts_after,
        "labels_created": counts_after["ml_labels"] - counts_before["ml_labels"],
        "model_runs_created": counts_after["ml_model_runs"]
        - counts_before["ml_model_runs"],
        "detection_runs_created": counts_after["detection_runs"]
        - counts_before["detection_runs"],
        "response_actions_created": counts_after["response_actions"]
        - counts_before["response_actions"],
        "active_model_artifact_written": False,
        "model_activated": False,
        "model_promoted": False,
        "ml_changed_authoritative_alerts": False,
        "rules_alert_authoritative": True,
        "automatic_response_enabled": False,
        "real_firewall_blocking_enabled": False,
    }
    readiness = _readiness(
        lock_validation=lock_validation,
        comparison=comparison,
        leader=leader,
        locked_final=(locked_final or {}).get("supervised"),
        isolation_audit=isolation_audit,
    )
    result = {
        "ok": bool(
            lock_validation.get("passed")
            and safety["database_counts_unchanged"]
            and safety["model_artifacts_unchanged"]
        ),
        "status": "evaluated",
        "version": V55_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "lifecycle_state": "shadow_observation",
        "evidence_lock_validation": lock_validation,
        "development_evidence": {
            "rows": len(development["rows"]),
            "fingerprint": development["development_fingerprint"],
            "roles": list(v54.DEVELOPMENT_ROLES),
            "locked_labels_used_for_selection": False,
            "locked_temporal_rows": len(canonical_partition["final_test_idx"]),
            "quarantined_rows": len(canonical_partition["quarantined_idx"]),
            "duplicate_group_isolation": bool(leakage.get("passed")),
            "provenance_balanced_sampling": True,
        },
        "isolation_forest_audit": isolation_audit,
        "development_model_comparison": comparison,
        "selected_development_leader": leader,
        "frozen_diagnostic_candidate": candidate_freeze,
        "locked_final_regression": locked_final,
        "readiness": readiness,
        "safety": safety,
        "runtime_seconds": round(time.perf_counter() - started, 4),
    }
    if write_output:
        output.mkdir(parents=True, exist_ok=True)
        stamp = _stamp()
        report_path = output / f"v5_5_development_model_repair_{stamp}.md"
        latest_path = output / V55_LATEST
        report_path.write_text(_render_report(result), encoding="utf-8")
        latest_path.write_text(
            json.dumps(result, indent=2, default=str),
            encoding="utf-8",
        )
        result["reports"] = {
            "markdown_file_name": report_path.name,
            "latest_json_file_name": latest_path.name,
            "ignored_output": True,
            "private_paths_returned": False,
            "raw_logs_returned": False,
        }
    return result
