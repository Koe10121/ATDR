from __future__ import annotations

import hashlib
import json
import os
import time
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path
from statistics import mean
from typing import Any, Iterable

from sqlalchemy.orm import Session

from atdr.app.core.config import PROJECT_ROOT
from atdr.app.detection import v398_independent_holdout_validation as frozen
from atdr.app.detection import v49_detection_ml_reliability as reliability
from atdr.app.detection import v540_development_supervised_repair as v540
from atdr.app.detection import v541_governed_blind_evidence as v541
from atdr.app.detection import v542_development_candidate_freeze as v542
from atdr.app.detection import v55_development_model_repair as v55
from atdr.app.detection.v331_noise_reduction import _build_pipeline_for_columns


V543_VERSION = "v5.43-development-temporal-stability-repair-v1"
V543_OUTPUT_DIR = (
    PROJECT_ROOT / "ml_baseline_reviews" / "v5_43_temporal_stability_repair"
)
V543_LATEST = "v5_43_temporal_stability_repair_latest.json"
V543_REPORT_PREFIX = "v5_43_development_temporal_stability_repair"
V543_FREEZE_MANIFEST = "v5_43_immutable_candidate_manifest.json"
V543_CANDIDATE_ARTIFACT = "v5_43_diagnostic_candidate.joblib"
V543_FREEZE_LOCK = "v5_43_candidate_freeze.lock"

FIXED_FREEZE_GATES = dict(v542.FIXED_FREEZE_GATES)

PREDECLARED_REPAIR_VARIANTS = (
    {
        "name": "hierarchical_two_stage_baseline",
        "weighting_mode": "v540_baseline",
        "feature_mode": "full",
    },
    {
        "name": "inverse_duplicate_cluster_weighting",
        "weighting_mode": "inverse_duplicate_cluster",
        "feature_mode": "full",
    },
    {
        "name": "temporal_provenance_balanced_weighting",
        "weighting_mode": "temporal_provenance_balanced",
        "feature_mode": "full",
    },
    {
        "name": "stronger_assisted_label_downweighting",
        "weighting_mode": "stronger_assisted_downweight",
        "feature_mode": "full",
    },
    {
        "name": "compact_stable_feature_hierarchical",
        "weighting_mode": "v540_baseline",
        "feature_mode": "compact_stable",
    },
)

COMPACT_NUMERIC_FEATURES = (
    "app_risk",
    "src_ip_5min_log_count",
    "src_ip_5min_deny_count",
    "src_ip_5min_unique_dst_ports",
    "src_ip_5min_unique_dst_ips",
    "src_ip_5min_high_risk_app_count",
    "deny_rate_5min",
    "src_ip_15min_event_count",
    "src_ip_15min_unique_dst_ports",
    "src_ip_15min_unique_dst_ips",
    "src_ip_15min_deny_drop_reset_count",
    "src_ip_15min_deny_ratio",
    "src_ip_15min_high_risk_app_count",
    "unknown_app_flag",
    "external_to_internal_flag",
    "internal_to_external_flag",
    "repeated_connection_attempts",
    "scanning_like_behavior_score",
    "repeat_count_effective",
    "parser_warning_count",
    "required_field_missing_count",
    "parser_confidence_score",
    "v398_local_rule_score",
    "v337_low_signal_allow_flag",
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
    *v540.V540_NUMERIC_FEATURES,
)
COMPACT_CATEGORICAL_FEATURES = (
    "protocol",
    "action",
    v540.V540_CATEGORICAL_FEATURE,
)

FORBIDDEN_FEATURE_NAMES = {
    "label",
    "label_id",
    "human_review_decision",
    "prediction",
    "predicted_label",
    "alert_id",
    "alert_type",
    "threat_score",
    "response_action",
}


class V543RepairError(RuntimeError):
    pass


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _stamp() -> str:
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")


def _stable_hash(value: Any) -> str:
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    os.replace(temporary, path)


def _read_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise V543RepairError("The private v5.43 state is unreadable.") from exc
    if not isinstance(payload, dict):
        raise V543RepairError("The private v5.43 state is invalid.")
    return payload


def _number(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _range(values: Iterable[float]) -> dict[str, float | None]:
    clean = [float(value) for value in values]
    return {
        "min": round(min(clean), 4) if clean else None,
        "max": round(max(clean), 4) if clean else None,
        "mean": round(mean(clean), 4) if clean else None,
    }


def _distribution(values: Iterable[Any]) -> dict[str, int]:
    return dict(sorted(Counter(str(value or "unknown") for value in values).items()))


def _total_variation(left: dict[str, int], right: dict[str, int]) -> float | None:
    left_total = sum(left.values())
    right_total = sum(right.values())
    if not left_total or not right_total:
        return None
    keys = set(left) | set(right)
    return round(
        0.5
        * sum(
            abs(
                (left.get(key, 0) / left_total)
                - (right.get(key, 0) / right_total)
            )
            for key in keys
        ),
        4,
    )


def _workspace_state(output_dir: Path) -> dict[str, Any]:
    return {
        name: v542._file_state(output_dir / name)
        for name in (
            v542.V542_LATEST,
            v542.V542_FREEZE_MANIFEST,
            v542.V542_CANDIDATE_ARTIFACT,
        )
    }


def _feature_contract(
    dataset: dict[str, Any],
    feature_mode: str,
) -> dict[str, Any]:
    available_numeric = list(dataset["feature_meta"]["numeric_features"])
    available_categorical = list(dataset["feature_meta"]["categorical_features"])
    if feature_mode == "full":
        numeric = available_numeric
        categorical = available_categorical
    elif feature_mode == "compact_stable":
        numeric = [name for name in COMPACT_NUMERIC_FEATURES if name in available_numeric]
        categorical = [
            name for name in COMPACT_CATEGORICAL_FEATURES if name in available_categorical
        ]
    else:
        raise V543RepairError("The predeclared feature contract is unsupported.")
    if not numeric or not categorical:
        raise V543RepairError("The predeclared feature contract is incomplete.")
    selected = set(numeric) | set(categorical)
    return {
        "mode": feature_mode,
        "numeric_features": numeric,
        "categorical_features": categorical,
        "feature_count": len(selected),
        "excluded_feature_count": len(
            (set(available_numeric) | set(available_categorical)) - selected
        ),
        "selection_predeclared": True,
        "evaluation_labels_used_for_selection": False,
        "blind_evidence_used_for_selection": False,
    }


def _normalize_weights(values: list[float]) -> list[float]:
    if not values:
        return []
    average = sum(values) / len(values)
    if average <= 0:
        return [1.0 for _ in values]
    normalized = [min(8.0, max(0.05, value / average)) for value in values]
    second_average = sum(normalized) / len(normalized)
    return [round(value / second_average, 6) for value in normalized]


def _class_balance(
    targets: list[str],
    indices: list[int],
) -> dict[str, float]:
    counts = Counter(targets[index] for index in indices)
    total = max(1, len(indices))
    classes = max(1, len(counts))
    return {
        target: total / (classes * max(1, count))
        for target, count in counts.items()
    }


def _temporal_cohorts(
    dataset: dict[str, Any],
    indices: list[int],
    *,
    cohort_count: int = 4,
) -> dict[int, str]:
    timestamps = sorted(
        {
            dataset["rows"][index].get("timestamp")
            for index in indices
            if dataset["rows"][index].get("timestamp") is not None
        }
    )
    if not timestamps:
        return {index: "unknown" for index in indices}
    rank = {value: position for position, value in enumerate(timestamps)}
    result: dict[int, str] = {}
    for index in indices:
        timestamp = dataset["rows"][index].get("timestamp")
        position = rank.get(timestamp, 0)
        cohort = min(cohort_count - 1, (position * cohort_count) // len(timestamps))
        result[index] = f"cohort_{cohort + 1}"
    return result


def build_variant_weights(
    dataset: dict[str, Any],
    indices: list[int],
    targets: list[str],
    weighting_mode: str,
) -> tuple[list[float], dict[str, Any]]:
    if weighting_mode == "v540_baseline":
        values, audit = v540._fit_weights(dataset, indices, targets)
        return values, {**audit, "mode": weighting_mode}

    class_weights = _class_balance(targets, indices)
    group_counts = Counter(
        str(dataset["rows"][index].get("leakage_group") or "missing")
        for index in indices
    )
    cohorts = _temporal_cohorts(dataset, indices)
    cohort_counts = Counter(cohorts[index] for index in indices)
    provenance_counts = Counter(
        str(dataset["rows"][index].get("label_source") or "unknown")
        for index in indices
    )
    assisted_multiplier = {
        "manual": 1.0,
        "reviewed_import": 1.0,
        "assisted_rule": 0.25,
        "assisted_ml": 0.15,
        "assisted_hybrid": 0.15,
    }
    values: list[float] = []
    for index in indices:
        row = dataset["rows"][index]
        target = targets[index]
        provenance = str(row.get("label_source") or "unknown")
        value = class_weights[target]
        if weighting_mode == "inverse_duplicate_cluster":
            group = str(row.get("leakage_group") or "missing")
            value /= max(1, group_counts[group])
        elif weighting_mode == "temporal_provenance_balanced":
            cohort = cohorts[index]
            value *= len(indices) / (
                max(1, len(cohort_counts)) * max(1, cohort_counts[cohort])
            )
            value *= len(indices) / (
                max(1, len(provenance_counts))
                * max(1, provenance_counts[provenance])
            )
            value *= assisted_multiplier.get(provenance, 0.10)
        elif weighting_mode == "stronger_assisted_downweight":
            value *= assisted_multiplier.get(provenance, 0.10)
        else:
            raise V543RepairError("The predeclared weighting contract is unsupported.")
        values.append(value)
    normalized = _normalize_weights(values)
    return normalized, {
        "mode": weighting_mode,
        "target_distribution": _distribution(targets[index] for index in indices),
        "provenance_distribution": _distribution(
            dataset["rows"][index].get("label_source") for index in indices
        ),
        "duplicate_group_count": len(group_counts),
        "multirow_duplicate_group_count": sum(
            1 for count in group_counts.values() if count > 1
        ),
        "temporal_cohort_distribution": dict(sorted(cohort_counts.items())),
        "minimum_weight": min(normalized, default=None),
        "maximum_weight": max(normalized, default=None),
        "mean_weight": round(mean(normalized), 4) if normalized else None,
        "assisted_provenance_downweighted": True,
        "labels_rewritten": False,
        "row_identifiers_returned": False,
    }


def _series_missing_rate(series: Any) -> float:
    return round(float(series.isna().mean()), 4) if len(series) else 0.0


def analyze_feature_ablation(
    dataset: dict[str, Any],
    partition: dict[str, Any],
) -> dict[str, Any]:
    import pandas as pd

    fit_idx = list(partition["fit_idx"])
    evaluation_idx = list(partition["final_test_idx"])
    frame = dataset["frame"]
    full = _feature_contract(dataset, "full")
    compact = _feature_contract(dataset, "compact_stable")
    numeric_drift: list[dict[str, Any]] = []
    for name in full["numeric_features"]:
        fit = pd.to_numeric(frame.iloc[fit_idx][name], errors="coerce")
        evaluation = pd.to_numeric(frame.iloc[evaluation_idx][name], errors="coerce")
        fit_clean = fit.dropna()
        evaluation_clean = evaluation.dropna()
        fit_missing = _series_missing_rate(fit)
        evaluation_missing = _series_missing_rate(evaluation)
        median_shift = None
        if not fit_clean.empty and not evaluation_clean.empty:
            q1 = float(fit_clean.quantile(0.25))
            q3 = float(fit_clean.quantile(0.75))
            scale = max(abs(q3 - q1), 1.0)
            median_shift = round(
                abs(float(evaluation_clean.median()) - float(fit_clean.median()))
                / scale,
                4,
            )
        numeric_drift.append(
            {
                "feature": name,
                "missing_rate_shift": round(
                    abs(evaluation_missing - fit_missing), 4
                ),
                "normalized_median_shift": median_shift,
            }
        )

    categorical_drift: list[dict[str, Any]] = []
    source_specific: list[str] = []
    for name in full["categorical_features"]:
        fit = frame.iloc[fit_idx][name].fillna("unknown").astype(str)
        evaluation = (
            frame.iloc[evaluation_idx][name].fillna("unknown").astype(str)
        )
        fit_counts = Counter(fit.tolist())
        evaluation_counts = Counter(evaluation.tolist())
        if len(fit_counts) <= 1:
            source_specific.append(name)
        categorical_drift.append(
            {
                "feature": name,
                "total_variation": _total_variation(fit_counts, evaluation_counts),
                "fit_unique_values": len(fit_counts),
                "evaluation_unseen_value_count": len(
                    set(evaluation_counts) - set(fit_counts)
                ),
            }
        )

    fit_numeric = frame.iloc[fit_idx][full["numeric_features"]].apply(
        pd.to_numeric,
        errors="coerce",
    )
    correlations = fit_numeric.corr(method="spearman").abs()
    redundant: list[dict[str, Any]] = []
    columns = list(correlations.columns)
    for left_position, left in enumerate(columns):
        for right in columns[left_position + 1 :]:
            value = correlations.at[left, right]
            if pd.notna(value) and float(value) >= 0.98:
                redundant.append(
                    {"left": left, "right": right, "absolute_correlation": round(float(value), 4)}
                )
    redundant.sort(key=lambda item: (-item["absolute_correlation"], item["left"], item["right"]))
    numeric_drift.sort(
        key=lambda item: (
            -_number(item["normalized_median_shift"]),
            -_number(item["missing_rate_shift"]),
            item["feature"],
        )
    )
    categorical_drift.sort(
        key=lambda item: (-_number(item["total_variation"]), item["feature"])
    )
    all_features = set(full["numeric_features"]) | set(full["categorical_features"])
    compact_features = set(compact["numeric_features"]) | set(
        compact["categorical_features"]
    )
    return {
        "protocol": "v5.43-feature-ablation-development-only-v1",
        "full_feature_count": len(all_features),
        "compact_feature_count": len(compact_features),
        "excluded_feature_count": len(all_features - compact_features),
        "compact_numeric_features": list(compact["numeric_features"]),
        "compact_categorical_features": list(compact["categorical_features"]),
        "top_numeric_distribution_shifts": numeric_drift[:20],
        "categorical_distribution_shifts": categorical_drift,
        "source_specific_or_constant_features": sorted(source_specific),
        "high_redundancy_pairs": redundant[:25],
        "potential_label_leakage_features": sorted(
            feature for feature in all_features if feature in FORBIDDEN_FEATURE_NAMES
        ),
        "selection_was_predeclared": True,
        "evaluation_labels_used_for_selection": False,
        "locked_or_blind_evidence_used": False,
        "raw_logs_included": False,
        "private_identifiers_included": False,
    }


def _fit_variant(
    dataset: dict[str, Any],
    partition: dict[str, Any],
    spec: dict[str, Any],
) -> dict[str, Any]:
    fit_idx = list(partition["fit_idx"])
    calibration_idx = list(partition["calibration_idx"])
    threshold_idx = list(partition["threshold_idx"])
    evaluation_idx = list(partition["final_test_idx"])
    targets = list(dataset["targets"])
    y_fit = [targets[index] for index in fit_idx]
    if len(set(y_fit)) < 2:
        return {
            "status": "failed_closed",
            "name": spec["name"],
            "reason": "fit partition has fewer than two target classes",
        }
    feature_contract = _feature_contract(dataset, str(spec["feature_mode"]))
    pipeline = _build_pipeline_for_columns(
        dataset["imports"],
        model_type="extra_trees",
        class_weight="balanced",
        numeric_features=feature_contract["numeric_features"],
        categorical_features=feature_contract["categorical_features"],
    )
    weights, weighting = build_variant_weights(
        dataset,
        fit_idx,
        targets,
        str(spec["weighting_mode"]),
    )
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
        method="sigmoid",
    )
    threshold_scores = reliability._queue_scores(
        model,
        dataset["frame"],
        threshold_idx,
        {"needs_review"},
    )
    threshold_selection = v540.select_fixed_threshold_profile(
        [targets[index] for index in threshold_idx],
        threshold_scores,
    )
    threshold = float(threshold_selection["selected_threshold"])
    scores = reliability._queue_scores(
        model,
        dataset["frame"],
        evaluation_idx,
        {"needs_review"},
    )
    predictions = [
        "needs_review" if score >= threshold else "non_threat" for score in scores
    ]
    y_true = [targets[index] for index in evaluation_idx]
    metrics = frozen._binary_metrics(y_true, predictions)
    metrics.update(
        frozen._diagnostic_original_recall(
            dataset["rows"],
            evaluation_idx,
            predictions,
        )
    )
    calibration = frozen._calibration_report(y_true, scores)

    threat_fit = [
        index
        for index in fit_idx
        if dataset["original_labels"][index] in {"suspicious", "malicious"}
    ]
    severity_status = "not_fitted"
    classification = None
    severity_targets = [dataset["original_labels"][index] for index in threat_fit]
    if len(set(severity_targets)) >= 2:
        severity = _build_pipeline_for_columns(
            dataset["imports"],
            model_type="extra_trees",
            class_weight="balanced",
            numeric_features=feature_contract["numeric_features"],
            categorical_features=feature_contract["categorical_features"],
        )
        severity_weights, _ = build_variant_weights(
            dataset,
            threat_fit,
            dataset["original_labels"],
            str(spec["weighting_mode"]),
        )
        severity.fit(
            dataset["frame"].iloc[threat_fit],
            severity_targets,
            model__sample_weight=severity_weights,
        )
        severity_predictions = [
            str(value)
            for value in severity.predict(dataset["frame"].iloc[evaluation_idx])
        ]
        combined = [
            severity_value if queue == "needs_review" else "benign_like"
            for queue, severity_value in zip(
                predictions,
                severity_predictions,
                strict=True,
            )
        ]
        classification = reliability._classification_diagnostics(
            [
                v55._three_class_targets(dataset["original_labels"])[index]
                for index in evaluation_idx
            ],
            combined,
        )
        severity_status = "fitted"

    result = {
        "status": "evaluated",
        "name": spec["name"],
        "model_type": "extra_trees",
        "target_mode": "hierarchical_two_stage",
        "requested_calibration_method": "sigmoid",
        "applied_calibration_method": calibration_method,
        "threshold_selection": threshold_selection,
        "metrics": metrics,
        "calibration": calibration,
        "classification_diagnostics": classification,
        "severity_stage_status": severity_status,
        "error_patterns": v540._safe_error_patterns(
            dataset,
            evaluation_idx,
            y_true,
            predictions,
        ),
        "sample_weighting": weighting,
        "feature_contract": {
            key: value
            for key, value in feature_contract.items()
            if key not in {"numeric_features", "categorical_features"}
        },
        "fit_rows": len(fit_idx),
        "calibration_rows": len(calibration_idx),
        "threshold_rows": len(threshold_idx),
        "evaluation_rows": len(evaluation_idx),
        "training_seconds": round(time.perf_counter() - started, 4),
        "post_prediction_guard_used": False,
        "protected_v539_rows_used": 0,
        "v541_blind_rows_used": 0,
        "locked_final_rows_used": 0,
        "active_artifact_written": False,
    }
    result["fixed_freeze_gate"] = v542._fixed_fold_gate(
        result,
        leakage_passed=True,
    )
    return result


def _metric_ranges(rows: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        field: _range(
            _number((row.get("metrics") or {}).get(field))
            for row in rows
            if (row.get("metrics") or {}).get(field) is not None
        )
        for field in v542.METRIC_FIELDS
    }


def _calibration_ranges(rows: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        field: _range(
            _number((row.get("calibration") or {}).get(field))
            for row in rows
            if (row.get("calibration") or {}).get(field) is not None
        )
        for field in v542.CALIBRATION_FIELDS
    }


def _ablation_summary(views: list[dict[str, Any]]) -> dict[str, Any]:
    audits = [view["feature_ablation"] for view in views if view.get("feature_ablation")]
    unstable = Counter(
        item["feature"]
        for audit in audits
        for item in audit.get("top_numeric_distribution_shifts", [])[:10]
    )
    categorical = Counter(
        item["feature"]
        for audit in audits
        for item in audit.get("categorical_distribution_shifts", [])
        if _number(item.get("total_variation")) >= 0.30
    )
    constants = Counter(
        feature
        for audit in audits
        for feature in audit.get("source_specific_or_constant_features", [])
    )
    return {
        "folds_audited": len(audits),
        "full_feature_count": audits[0]["full_feature_count"] if audits else 0,
        "compact_feature_count": audits[0]["compact_feature_count"] if audits else 0,
        "features_repeatedly_unstable": unstable.most_common(20),
        "categorical_features_with_material_drift": categorical.most_common(20),
        "source_specific_or_constant_features": constants.most_common(20),
        "potential_label_leakage_features": sorted(
            {
                feature
                for audit in audits
                for feature in audit.get("potential_label_leakage_features", [])
            }
        ),
        "evaluation_labels_used_for_selection": False,
        "blind_evidence_used": False,
        "raw_logs_included": False,
    }


def run_repair_comparison(dataset: dict[str, Any]) -> dict[str, Any]:
    folds = v55.build_nested_temporal_folds(dataset)
    views: list[dict[str, Any]] = []
    by_variant: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for fold in folds:
        if fold.get("status") != "partitioned":
            views.append(
                {
                    "fold": fold.get("fold"),
                    "status": "failed_closed",
                    "reason": fold.get("reason") or "development fold unavailable",
                }
            )
            continue
        leakage_passed = bool((fold.get("leakage_audit") or {}).get("passed"))
        if not leakage_passed:
            views.append(
                {
                    "fold": fold.get("fold"),
                    "status": "failed_closed",
                    "reason": "duplicate-group isolation failed",
                }
            )
            continue
        ablation = analyze_feature_ablation(fold["dataset"], fold["partition"])
        evaluations: list[dict[str, Any]] = []
        for spec in PREDECLARED_REPAIR_VARIANTS:
            try:
                result = _fit_variant(fold["dataset"], fold["partition"], spec)
            except Exception as exc:  # diagnostic variants must fail closed
                result = {
                    "status": "failed_closed",
                    "name": spec["name"],
                    "error_type": exc.__class__.__name__,
                    "message": "Repair variant evaluation failed closed.",
                    "active_artifact_written": False,
                    "fixed_freeze_gate": {
                        "passed": False,
                        "checks": {"strategy_evaluated": False},
                        "gates": FIXED_FREEZE_GATES,
                    },
                }
            evaluations.append(result)
            by_variant[str(spec["name"])].append({"fold": fold["fold"], **result})
        views.append(
            {
                "fold": fold["fold"],
                "status": "partitioned",
                "prefix_share": fold.get("prefix_share"),
                "leakage_audit_passed": True,
                "partition_sizes": (fold.get("leakage_audit") or {}).get(
                    "partition_sizes"
                ),
                "evidence_profile": v542._fold_evidence_profile(
                    fold["dataset"],
                    fold["partition"],
                ),
                "feature_ablation": ablation,
                "variants": evaluations,
            }
        )

    required_folds = len(v55.NESTED_PREFIX_SHARES)
    summaries: dict[str, Any] = {}
    for spec in PREDECLARED_REPAIR_VARIANTS:
        name = str(spec["name"])
        evaluated = [
            row for row in by_variant.get(name, []) if row.get("status") == "evaluated"
        ]
        queue_rates = [
            _number((row.get("metrics") or {}).get("review_queue_rate"))
            for row in evaluated
            if (row.get("metrics") or {}).get("review_queue_rate") is not None
        ]
        queue_spread = (
            round(max(queue_rates) - min(queue_rates), 4) if queue_rates else None
        )
        passing_folds = sum(
            1 for row in evaluated if (row.get("fixed_freeze_gate") or {}).get("passed")
        )
        complete = len(evaluated) == required_folds
        queue_stable = bool(
            queue_spread is not None
            and queue_spread <= FIXED_FREEZE_GATES["review_queue_rate_spread_max"]
        )
        summaries[name] = {
            "variant_contract": spec,
            "evaluated_folds": len(evaluated),
            "required_folds": required_folds,
            "passing_folds": passing_folds,
            "all_fold_gates_passed": complete and passing_folds == required_folds,
            "review_queue_rate_spread": queue_spread,
            "review_queue_rate_stability_passed": queue_stable,
            "eligible_for_diagnostic_freeze": bool(
                complete and passing_folds == required_folds and queue_stable
            ),
            "metric_ranges": _metric_ranges(evaluated),
            "calibration_ranges": _calibration_ranges(evaluated),
            "calibration_methods": sorted(
                {
                    str(row.get("applied_calibration_method") or "missing")
                    for row in evaluated
                }
            ),
            "threshold_profiles": [
                {
                    "fold": row.get("fold"),
                    "profile": (row.get("threshold_selection") or {}).get(
                        "selected_profile"
                    ),
                    "threshold": (row.get("threshold_selection") or {}).get(
                        "selected_threshold"
                    ),
                }
                for row in evaluated
            ],
            "protected_v539_rows_used": 0,
            "v541_blind_rows_used": 0,
            "locked_final_rows_used": 0,
        }
    return {
        "protocol": "v5.43-fixed-development-temporal-repair-v1",
        "variant_count": len(PREDECLARED_REPAIR_VARIANTS),
        "predeclared_variant_names": [
            item["name"] for item in PREDECLARED_REPAIR_VARIANTS
        ],
        "development_rows": len(dataset["rows"]),
        "required_folds": required_folds,
        "fixed_freeze_gates": FIXED_FREEZE_GATES,
        "views": views,
        "variant_summaries": summaries,
        "feature_ablation_summary": _ablation_summary(views),
        "duplicate_group_isolation_required": True,
        "locked_final_rows_used": 0,
        "v539_rows_used": 0,
        "v541_blind_rows_used": 0,
        "active_artifact_written": False,
    }


def select_best_repair(comparison: dict[str, Any]) -> dict[str, Any] | None:
    ranked: list[tuple[Any, ...]] = []
    for name, summary in (comparison.get("variant_summaries") or {}).items():
        metrics = summary.get("metric_ranges") or {}
        calibration = summary.get("calibration_ranges") or {}

        def minimum(field: str, default: float = 0.0) -> float:
            value = (metrics.get(field) or {}).get("min")
            return default if value is None else float(value)

        def maximum(field: str, default: float = 1.0) -> float:
            value = (metrics.get(field) or {}).get("max")
            return default if value is None else float(value)

        ece = (calibration.get("expected_calibration_error") or {}).get("max")
        gap = (calibration.get("max_confidence_accuracy_gap") or {}).get("max")
        score = (
            minimum("queue_f1")
            + (0.20 * minimum("queue_recall"))
            + (0.15 * minimum("suspicious_recall"))
            + (0.15 * minimum("malicious_recall"))
            - (0.70 * maximum("benign_like_false_positive_rate"))
            - (0.10 * float(ece if ece is not None else 1.0))
            - (0.10 * float(gap if gap is not None else 1.0))
        )
        ranked.append(
            (
                bool(summary.get("eligible_for_diagnostic_freeze")),
                int(summary.get("passing_folds") or 0),
                round(score, 6),
                minimum("queue_f1"),
                -maximum("benign_like_false_positive_rate"),
                name,
            )
        )
    if not ranked:
        return None
    selected = max(ranked)
    name = str(selected[-1])
    return {
        "name": name,
        "selection_basis": "development_roles_only_unchanged_v5_42_gates",
        "eligible_for_diagnostic_freeze": bool(selected[0]),
        "summary": comparison["variant_summaries"][name],
        "locked_final_used": False,
        "v539_used": False,
        "v541_blind_used": False,
        "eligible_for_activation": False,
    }


def build_v543_development_state(
    db: Session,
    *,
    min_samples: int = 100,
    state_path: Path = v540.V539_STATE_PATH,
    pack_path: Path = v540.DEFAULT_PACK_PATH,
    blind_output_dir: Path = v541.V541_OUTPUT_DIR,
    v542_output_dir: Path = v542.V542_OUTPUT_DIR,
) -> dict[str, Any]:
    state = v542.build_v542_development_state(
        db,
        min_samples=min_samples,
        state_path=state_path,
        pack_path=pack_path,
        blind_output_dir=blind_output_dir,
    )
    v542_manifest = v542._validate_freeze_manifest(v542_output_dir)
    v542_latest_path = v542_output_dir / v542.V542_LATEST
    v542_latest = _read_json(v542_latest_path) if v542_latest_path.is_file() else None
    checks = {
        **{
            f"v542_{key}": bool(value)
            for key, value in state["boundary_checks"].items()
        },
        "v542_fixed_gates_unchanged": FIXED_FREEZE_GATES
        == v542.FIXED_FREEZE_GATES,
        "v542_candidate_set_published": len(v542.PREDECLARED_STRATEGIES) == 5,
        "v542_report_schema_valid_if_present": v542_latest is None
        or (
            v542_latest.get("version") == v542.V542_VERSION
            and int(v542_latest.get("development_rows") or -1)
            == len(state["development"]["rows"])
            and v542_latest.get("fixed_freeze_gates") == v542.FIXED_FREEZE_GATES
        ),
        "v542_freeze_integrity_valid_if_present": v542_manifest is None
        or v542_manifest.get("status") == "diagnostic_candidate_frozen",
    }
    if not all(checks.values()):
        raise V543RepairError("The v5.39-v5.42 custody boundaries do not match.")
    return {
        **state,
        "v543_boundary_checks": checks,
        "v542_report_present": v542_latest is not None,
        "v542_candidate_frozen": v542_manifest is not None,
        "development_contract": v542._development_contract(state["development"]),
    }


def diagnose_repair(
    dataset: dict[str, Any],
    comparison: dict[str, Any],
    leader: dict[str, Any] | None,
) -> dict[str, Any]:
    compatibility = {
        "views": [
            {
                **{key: value for key, value in view.items() if key != "variants"},
                "strategies": view.get("variants") or [],
            }
            for view in comparison.get("views") or []
        ],
        "strategy_summaries": comparison.get("variant_summaries") or {},
    }
    diagnosis = v542.diagnose_instability(dataset, compatibility, leader)
    ablation = comparison.get("feature_ablation_summary") or {}
    root_causes = list(diagnosis.get("root_causes") or [])
    if ablation.get("features_repeatedly_unstable"):
        root_causes.append(
            "Multiple numeric features shift materially across development folds."
        )
    if ablation.get("categorical_features_with_material_drift"):
        root_causes.append(
            "Categorical application or context distributions shift across time."
        )
    if ablation.get("source_specific_or_constant_features"):
        root_causes.append(
            "Some categorical features are constant or source-specific in fit evidence."
        )
    if ablation.get("potential_label_leakage_features"):
        root_causes.append("Potential label-derived features were detected.")
    return {
        **diagnosis,
        "root_causes": list(dict.fromkeys(root_causes)),
        "feature_ablation": ablation,
    }


def _fit_frozen_artifact(
    dataset: dict[str, Any],
    comparison: dict[str, Any],
    leader: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    spec = next(
        item for item in PREDECLARED_REPAIR_VARIANTS if item["name"] == leader["name"]
    )
    folds = v55.build_nested_temporal_folds(dataset)
    available = [fold for fold in folds if fold.get("status") == "partitioned"]
    if len(available) != len(v55.NESTED_PREFIX_SHARES):
        raise V543RepairError("All fixed development folds are required before freezing.")
    fold = available[-1]
    partition = fold["partition"]
    fit_idx = list(partition["fit_idx"])
    calibration_idx = list(partition["calibration_idx"])
    threshold_idx = list(partition["threshold_idx"])
    targets = list(dataset["targets"])
    features = _feature_contract(dataset, str(spec["feature_mode"]))
    pipeline = _build_pipeline_for_columns(
        dataset["imports"],
        model_type="extra_trees",
        class_weight="balanced",
        numeric_features=features["numeric_features"],
        categorical_features=features["categorical_features"],
    )
    weights, weighting = build_variant_weights(
        dataset,
        fit_idx,
        targets,
        str(spec["weighting_mode"]),
    )
    pipeline.fit(
        dataset["frame"].iloc[fit_idx],
        [targets[index] for index in fit_idx],
        model__sample_weight=weights,
    )
    model, calibration_method = reliability._fit_frozen_calibrator(
        pipeline,
        dataset["frame"],
        calibration_idx,
        targets,
        method="sigmoid",
    )
    threshold_scores = reliability._queue_scores(
        model,
        dataset["frame"],
        threshold_idx,
        {"needs_review"},
    )
    threshold = v540.select_fixed_threshold_profile(
        [targets[index] for index in threshold_idx],
        threshold_scores,
    )
    threat_fit = [
        index
        for index in fit_idx
        if dataset["original_labels"][index] in {"suspicious", "malicious"}
    ]
    severity_targets = [dataset["original_labels"][index] for index in threat_fit]
    if len(set(severity_targets)) < 2:
        raise V543RepairError("The hierarchical severity stage lacks two fit classes.")
    severity = _build_pipeline_for_columns(
        dataset["imports"],
        model_type="extra_trees",
        class_weight="balanced",
        numeric_features=features["numeric_features"],
        categorical_features=features["categorical_features"],
    )
    severity_weights, _ = build_variant_weights(
        dataset,
        threat_fit,
        dataset["original_labels"],
        str(spec["weighting_mode"]),
    )
    severity.fit(
        dataset["frame"].iloc[threat_fit],
        severity_targets,
        model__sample_weight=severity_weights,
    )
    contract = {
        "schema_version": V543_VERSION,
        "status": "diagnostic_configuration_frozen",
        "variant": spec,
        "threshold_profile": threshold["selected_profile"],
        "threshold": threshold["selected_threshold"],
        "calibration_method": calibration_method,
        "feature_mode": features["mode"],
        "feature_count": features["feature_count"],
        "development_contract": v542._development_contract(dataset),
        "fixed_gate_summary": leader["summary"],
        "comparison_protocol": comparison.get("protocol"),
        "fit_rows": len(fit_idx),
        "calibration_rows": len(calibration_idx),
        "threshold_rows": len(threshold_idx),
        "evaluation_rows_used_for_fit": 0,
        "locked_final_rows_used": 0,
        "v539_rows_used": 0,
        "v541_blind_rows_used": 0,
        "eligible_for_activation": False,
        "rules_alert_authoritative": True,
    }
    artifact = {
        "schema_version": V543_VERSION,
        "model": model,
        "severity_model": severity,
        "threshold": float(threshold["selected_threshold"]),
        "positive_classes": ["needs_review"],
        "numeric_features": list(features["numeric_features"]),
        "categorical_features": list(features["categorical_features"]),
        "variant": spec,
        "sample_weighting": weighting,
        "decision_support_only": True,
        "active": False,
        "production_promoted": False,
        "response_automation_allowed": False,
    }
    return artifact, contract


def _validate_freeze_manifest(output_dir: Path) -> dict[str, Any] | None:
    manifest_path = output_dir / V543_FREEZE_MANIFEST
    artifact_path = output_dir / V543_CANDIDATE_ARTIFACT
    if manifest_path.is_file() != artifact_path.is_file():
        raise V543RepairError("The immutable v5.43 candidate freeze is incomplete.")
    if not manifest_path.is_file():
        return None
    manifest = _read_json(manifest_path)
    if (
        manifest.get("schema_version") != V543_VERSION
        or manifest.get("status") != "diagnostic_candidate_frozen"
        or manifest.get("artifact_sha256") != _file_sha256(artifact_path)
        or not manifest.get("candidate_contract_digest")
    ):
        raise V543RepairError("The immutable v5.43 freeze failed integrity validation.")
    return manifest


def seal_immutable_candidate(
    *,
    artifact: Any,
    candidate_contract: dict[str, Any],
    output_dir: Path = V543_OUTPUT_DIR,
) -> dict[str, Any]:
    if candidate_contract.get("status") != "diagnostic_configuration_frozen":
        raise V543RepairError("Only an eligible diagnostic configuration can be frozen.")
    contract_digest = _stable_hash(candidate_contract)
    existing = _validate_freeze_manifest(output_dir)
    if existing is not None:
        if existing.get("candidate_contract_digest") != contract_digest:
            raise V543RepairError("A different immutable v5.43 candidate is frozen.")
        return {
            "status": "diagnostic_candidate_frozen",
            "candidate_frozen": True,
            "reused_existing_freeze": True,
            "artifact_name": V543_CANDIDATE_ARTIFACT,
            "artifact_path_returned": False,
            "digests_returned": False,
            "active": False,
            "production_promoted": False,
        }
    output_dir.mkdir(parents=True, exist_ok=True)
    lock_path = output_dir / V543_FREEZE_LOCK
    try:
        lock_fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except FileExistsError as exc:
        raise V543RepairError("Another immutable v5.43 freeze is in progress.") from exc
    os.close(lock_fd)
    try:
        import joblib

        artifact_path = output_dir / V543_CANDIDATE_ARTIFACT
        temporary = artifact_path.with_name(f".{artifact_path.name}.{os.getpid()}.tmp")
        joblib.dump(artifact, temporary)
        os.replace(temporary, artifact_path)
        manifest = {
            "schema_version": V543_VERSION,
            "status": "diagnostic_candidate_frozen",
            "created_at": _now(),
            "artifact_name": V543_CANDIDATE_ARTIFACT,
            "artifact_sha256": _file_sha256(artifact_path),
            "candidate_contract_digest": contract_digest,
            "variant": candidate_contract.get("variant"),
            "active": False,
            "production_promoted": False,
            "response_automation_allowed": False,
            "rules_alert_authoritative": True,
        }
        _atomic_write_json(output_dir / V543_FREEZE_MANIFEST, manifest)
    finally:
        lock_path.unlink(missing_ok=True)
    return {
        "status": "diagnostic_candidate_frozen",
        "candidate_frozen": True,
        "reused_existing_freeze": False,
        "artifact_name": V543_CANDIDATE_ARTIFACT,
        "artifact_path_returned": False,
        "digests_returned": False,
        "active": False,
        "production_promoted": False,
    }


def _readiness(
    *,
    leader: dict[str, Any] | None,
    candidate_freeze: dict[str, Any] | None,
    diagnosis: dict[str, Any],
    blind_status: dict[str, Any],
    safety: dict[str, Any],
) -> dict[str, Any]:
    candidate_frozen = bool(candidate_freeze and candidate_freeze.get("candidate_frozen"))
    blockers = list(diagnosis.get("root_causes") or [])
    if leader is None:
        blockers.append("No predeclared repair produced comparable fold metrics.")
    elif not leader.get("eligible_for_diagnostic_freeze"):
        blockers.append("No repair passed every unchanged v5.42 gate.")
    if not candidate_frozen:
        blockers.append("No immutable v5.43 diagnostic candidate is frozen.")
    if blind_status.get("independent_source_count", 0) < blind_status.get(
        "required_source_count", 2
    ):
        blockers.append("Independent evidence still lacks two verified sources.")
    if blind_status.get("collection_window_count", 0) < blind_status.get(
        "required_window_count", 3
    ):
        blockers.append("Independent evidence still lacks three future windows.")
    if not blind_status.get("human_review_complete"):
        blockers.append("Prediction-blind human review is not complete.")
    remaining = [
        "freeze one stable development-only diagnostic candidate",
        "collect qualifying future evidence from two independent sources across three windows",
        "complete genuine prediction-blind human review",
        "run one frozen evaluation without tuning",
        "make a separate governance decision and complete shadow observation",
    ]
    if candidate_frozen:
        remaining = remaining[1:]
    return {
        "status": "Diagnostic Candidate Frozen" if candidate_frozen else "No Candidate Frozen",
        "candidate_frozen": candidate_frozen,
        "candidate_selected_for_activation": False,
        "lifecycle_state": "shadow_observation",
        "model_activated": False,
        "model_promoted": False,
        "production_promoted": False,
        "rules_alert_authoritative": True,
        "response_automation_allowed": False,
        "supervised_phases_remaining": len(remaining),
        "remaining_phases": remaining,
        "blockers": list(dict.fromkeys(blockers)),
        "safety_invariants_passed": all(
            bool(safety.get(key))
            for key in (
                "database_counts_unchanged",
                "active_model_artifacts_unchanged",
                "v539_state_unchanged",
                "v541_workspace_unchanged",
                "v542_workspace_unchanged",
            )
        ),
    }


def _render_report(result: dict[str, Any]) -> str:
    leader = result.get("best_repair_variant") or {}
    summary = leader.get("summary") or {}
    diagnosis = result.get("diagnosis") or {}
    readiness = result.get("readiness") or {}
    metrics = summary.get("metric_ranges") or {}
    calibration = summary.get("calibration_ranges") or {}
    lines = [
        "# v5.43 Development Temporal Stability Repair",
        "",
        f"- Status: {result.get('status')}",
        f"- Development rows: {result.get('development_rows')}",
        f"- Best repair: {leader.get('name') or 'none'}",
        f"- Passing folds: {summary.get('passing_folds', 0)}/{summary.get('required_folds', 3)}",
        f"- Candidate frozen: {readiness.get('candidate_frozen', False)}",
        f"- Lifecycle: {readiness.get('lifecycle_state', 'shadow_observation')}",
        "",
        "## Metric Ranges",
        "",
        f"- Queue F1: {metrics.get('queue_f1')}",
        f"- Benign-like FPR: {metrics.get('benign_like_false_positive_rate')}",
        f"- Suspicious recall: {metrics.get('suspicious_recall')}",
        f"- Malicious recall: {metrics.get('malicious_recall')}",
        f"- ECE: {calibration.get('expected_calibration_error')}",
        f"- Confidence gap: {calibration.get('max_confidence_accuracy_gap')}",
        "",
        "## Root Causes",
        "",
        *[f"- {item}" for item in diagnosis.get("root_causes") or []],
        "",
        "## Safety",
        "",
        "- No labels, alerts, detection runs, model runs, or response actions were created.",
        "- Rules remain alert-authoritative.",
        "- Model activation, promotion, automatic response, and real blocking remain disabled.",
    ]
    return "\n".join(lines) + "\n"


def run_v543_temporal_stability_repair(
    db: Session,
    *,
    min_samples: int = 100,
    preflight_only: bool = False,
    write_output: bool = True,
    output_dir: Path = V543_OUTPUT_DIR,
    state_path: Path = v540.V539_STATE_PATH,
    pack_path: Path = v540.DEFAULT_PACK_PATH,
    blind_output_dir: Path = v541.V541_OUTPUT_DIR,
    v542_output_dir: Path = v542.V542_OUTPUT_DIR,
) -> dict[str, Any]:
    started = time.perf_counter()
    counts_before = frozen._database_counts(db)
    active_artifacts_before = v55._model_artifact_states()
    v539_before = {
        "state": v542._file_state(state_path),
        "pack": v542._file_state(pack_path),
    }
    v541_before = v542._workspace_states(blind_output_dir)
    v542_before = _workspace_state(v542_output_dir)
    try:
        state = build_v543_development_state(
            db,
            min_samples=min_samples,
            state_path=state_path,
            pack_path=pack_path,
            blind_output_dir=blind_output_dir,
            v542_output_dir=v542_output_dir,
        )
    except (
        v540.V540EvidenceBoundaryError,
        v541.V541EvidenceError,
        v542.V542FreezeError,
        V543RepairError,
    ) as exc:
        return {
            "ok": False,
            "version": V543_VERSION,
            "status": "failed_closed",
            "message": str(exc),
            "lifecycle_state": "shadow_observation",
            "candidate_frozen": False,
            "model_activated": False,
            "response_automation_allowed": False,
        }

    comparison = None
    leader = None
    diagnosis: dict[str, Any] = {
        "status": "preflight_only",
        "root_causes": [],
        "raw_logs_included": False,
    }
    manifest = _validate_freeze_manifest(output_dir)
    freeze_public = (
        {
            "status": "diagnostic_candidate_frozen",
            "candidate_frozen": True,
            "reused_existing_freeze": True,
            "artifact_name": V543_CANDIDATE_ARTIFACT,
            "artifact_path_returned": False,
            "digests_returned": False,
            "active": False,
            "production_promoted": False,
        }
        if manifest
        else None
    )
    if not preflight_only:
        comparison = run_repair_comparison(state["development"])
        leader = select_best_repair(comparison)
        diagnosis = diagnose_repair(state["development"], comparison, leader)
        if leader and leader.get("eligible_for_diagnostic_freeze") and write_output:
            artifact, contract = _fit_frozen_artifact(
                state["development"], comparison, leader
            )
            freeze_public = seal_immutable_candidate(
                artifact=artifact,
                candidate_contract=contract,
                output_dir=output_dir,
            )

    counts_after = frozen._database_counts(db)
    active_artifacts_after = v55._model_artifact_states()
    v539_after = {
        "state": v542._file_state(state_path),
        "pack": v542._file_state(pack_path),
    }
    v541_after = v542._workspace_states(blind_output_dir)
    v542_after = _workspace_state(v542_output_dir)
    safety = {
        "database_counts_unchanged": counts_before == counts_after,
        "active_model_artifacts_unchanged": active_artifacts_before
        == active_artifacts_after,
        "v539_state_unchanged": v539_before == v539_after,
        "v541_workspace_unchanged": v541_before == v541_after,
        "v542_workspace_unchanged": v542_before == v542_after,
        "labels_created": counts_after["ml_labels"] - counts_before["ml_labels"],
        "model_runs_created": counts_after["ml_model_runs"]
        - counts_before["ml_model_runs"],
        "detection_runs_created": counts_after["detection_runs"]
        - counts_before["detection_runs"],
        "alerts_created": counts_after["alerts"] - counts_before["alerts"],
        "response_actions_created": counts_after["response_actions"]
        - counts_before["response_actions"],
        "v539_evaluator_called": False,
        "v541_predictions_revealed": False,
        "v541_prediction_seal_written": False,
        "active_model_artifact_written": False,
        "model_activated": False,
        "model_promoted": False,
        "rules_alert_authoritative": True,
        "automatic_response_enabled": False,
        "real_firewall_blocking_enabled": False,
    }
    readiness = _readiness(
        leader=leader,
        candidate_freeze=freeze_public,
        diagnosis=diagnosis,
        blind_status=state["blind_status"],
        safety=safety,
    )
    result = {
        "ok": bool(readiness["safety_invariants_passed"]),
        "version": V543_VERSION,
        "status": "preflight_completed"
        if preflight_only
        else "candidate_frozen"
        if readiness["candidate_frozen"]
        else "no_candidate_frozen",
        "generated_at": _now(),
        "lifecycle_state": "shadow_observation",
        "boundary_revalidation": {
            "checks": state["v543_boundary_checks"],
            "all_checks_passed": all(state["v543_boundary_checks"].values()),
            "v542_report_present": state["v542_report_present"],
            "v542_candidate_frozen": state["v542_candidate_frozen"],
            "digests_returned": False,
            "private_identifiers_returned": False,
        },
        "development_rows": len(state["development"]["rows"]),
        "variant_count": len(PREDECLARED_REPAIR_VARIANTS),
        "fixed_freeze_gates": FIXED_FREEZE_GATES,
        "development_comparison": comparison,
        "best_repair_variant": leader,
        "diagnosis": diagnosis,
        "candidate_freeze": freeze_public,
        "blind_evidence_status": state["blind_status"],
        "readiness": readiness,
        "safety": safety,
        "runtime_seconds": round(time.perf_counter() - started, 4),
        "locked_final_rows_used": 0,
        "v539_rows_used_for_modeling": 0,
        "v541_blind_rows_used_for_modeling": 0,
        "raw_logs_included": False,
        "private_identifiers_included": False,
        "fingerprints_returned": False,
        "secrets_exposed": False,
    }
    if write_output:
        output_dir.mkdir(parents=True, exist_ok=True)
        latest = output_dir / V543_LATEST
        report = output_dir / f"{V543_REPORT_PREFIX}_{_stamp()}.md"
        _atomic_write_json(latest, result)
        report.write_text(_render_report(result), encoding="utf-8")
        result["reports"] = {
            "latest_file_name": latest.name,
            "report_file_name": report.name,
            "ignored_output": True,
            "private_paths_returned": False,
        }
    return result


def get_public_temporal_stability_status(
    *,
    output_dir: Path = V543_OUTPUT_DIR,
) -> dict[str, Any]:
    manifest = _validate_freeze_manifest(output_dir)
    latest_path = output_dir / V543_LATEST
    if not latest_path.is_file():
        return {
            "version": V543_VERSION,
            "status": "Designed",
            "best_variant": None,
            "passing_folds": 0,
            "required_folds": len(v55.NESTED_PREFIX_SHARES),
            "candidate_frozen": manifest is not None,
            "calibration_status": "not_evaluated",
            "queue_stability_status": "not_evaluated",
            "feature_ablation_status": "not_evaluated",
            "supervised_phases_remaining": 4 if manifest else 5,
            "blockers": ["Run the v5.43 development repair evaluator."],
            "lifecycle_state": "shadow_observation",
            "rules_alert_authoritative": True,
            "model_activated": False,
            "model_promoted": False,
            "response_automation_allowed": False,
            "private_paths_exposed": False,
            "digests_exposed": False,
            "blind_predictions_exposed": False,
            "secrets_exposed": False,
        }
    latest = _read_json(latest_path)
    if latest.get("version") != V543_VERSION:
        raise V543RepairError("The v5.43 repair report has an unsupported schema.")
    readiness = latest.get("readiness") or {}
    leader = latest.get("best_repair_variant") or {}
    summary = leader.get("summary") or {}
    if bool(readiness.get("candidate_frozen")) != bool(manifest):
        raise V543RepairError("The v5.43 report and freeze state disagree.")
    calibration = summary.get("calibration_ranges") or {}
    ece = (calibration.get("expected_calibration_error") or {}).get("max")
    gap = (calibration.get("max_confidence_accuracy_gap") or {}).get("max")
    calibration_passed = bool(
        ece is not None
        and float(ece) <= FIXED_FREEZE_GATES["expected_calibration_error_max"]
        and gap is not None
        and float(gap) <= FIXED_FREEZE_GATES["max_confidence_accuracy_gap_max"]
    )
    ablation = ((latest.get("development_comparison") or {}).get("feature_ablation_summary") or {})
    return {
        "version": V543_VERSION,
        "status": readiness.get("status") or latest.get("status") or "Unknown",
        "best_variant": leader.get("name"),
        "passing_folds": int(summary.get("passing_folds") or 0),
        "required_folds": int(
            summary.get("required_folds") or len(v55.NESTED_PREFIX_SHARES)
        ),
        "candidate_frozen": bool(readiness.get("candidate_frozen")),
        "calibration_status": "passed" if calibration_passed else "weak",
        "queue_stability_status": "passed"
        if summary.get("review_queue_rate_stability_passed")
        else "unstable",
        "feature_ablation_status": "complete"
        if int(ablation.get("folds_audited") or 0) == len(v55.NESTED_PREFIX_SHARES)
        else "incomplete",
        "supervised_phases_remaining": int(
            readiness.get("supervised_phases_remaining") or 5
        ),
        "blockers": list(readiness.get("blockers") or [])[:12],
        "lifecycle_state": "shadow_observation",
        "rules_alert_authoritative": True,
        "model_activated": False,
        "model_promoted": False,
        "response_automation_allowed": False,
        "private_paths_exposed": False,
        "digests_exposed": False,
        "blind_predictions_exposed": False,
        "secrets_exposed": False,
    }
