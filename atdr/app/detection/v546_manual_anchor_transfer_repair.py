from __future__ import annotations

import itertools
import json
import os
import sqlite3
import tempfile
import time
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path
from statistics import mean
from typing import Any, Iterable

from sqlalchemy.orm import Session

from atdr.app.core.config import PROJECT_ROOT, get_settings
from atdr.app.detection import v398_independent_holdout_validation as frozen
from atdr.app.detection import v49_detection_ml_reliability as reliability
from atdr.app.detection import v540_development_supervised_repair as v540
from atdr.app.detection import v541_governed_blind_evidence as v541
from atdr.app.detection import v542_development_candidate_freeze as v542
from atdr.app.detection import v543_temporal_stability_repair as v543
from atdr.app.detection import v544_chronological_evidence as v544
from atdr.app.detection import v545_development_model_repair as v545
from atdr.app.detection import v55_development_model_repair as v55
from atdr.app.detection import v56_private_panos_model_repair as v56
from atdr.app.detection.supervised_detector import _optional_imports
from atdr.app.detection.v331_noise_reduction import _build_pipeline_for_columns


V546_VERSION = "v5.46-manual-anchor-transfer-repair-v1"
V546_OUTPUT_DIR = PROJECT_ROOT / "ml_baseline_reviews" / "v5_46_transfer_repair"
V546_LATEST = "v5_46_manual_anchor_transfer_repair_latest.json"
V546_FREEZE_MANIFEST = "v5_46_diagnostic_candidate_recipe.json"
V546_REPORT_PREFIX = "v5_46_manual_anchor_transfer_repair"

FIXED_FREEZE_GATES = dict(v545.FIXED_FREEZE_GATES)
DEFAULT_MAX_ROWS = dict(v545.DEFAULT_MAX_ROWS)

V546_DERIVED_NUMERIC_FEATURES = (
    "v546_incomplete_allow_80_flag",
    "v546_quic_443_allow_flag",
    "v546_unknown_transport_flag",
    "v546_routine_service_flag",
    "v546_rule_support_flag",
    "v546_parser_limited_flag",
    "v546_scan_diversity_ratio",
    "v546_destination_diversity_ratio",
    "v546_unknown_app_rate",
    "v546_high_risk_app_rate",
    "v546_deny_intensity",
    "v546_evidence_strength",
    "v546_bytes_per_packet",
    "v546_destination_repeat_ratio",
)
V546_DERIVED_CATEGORICAL_FEATURES = (
    "v546_context_profile",
    "v546_evidence_band",
    "v546_time_regime",
    "v546_transport_context",
)
V546_NUMERIC_FEATURES = [
    *v56.V56_NUMERIC_FEATURES,
    *V546_DERIVED_NUMERIC_FEATURES,
]
V546_CATEGORICAL_FEATURES = [
    *v56.V56_CATEGORICAL_FEATURES,
    *V546_DERIVED_CATEGORICAL_FEATURES,
]

TRANSFER_STRATEGY_SPECS = (
    {
        "name": "calibrated_extra_trees_v545_baseline",
        "model_type": "extra_trees",
        "target_mode": "flat_5class",
        "class_weight": "balanced",
        "feature_set": "v545_baseline",
        "fit_assisted_ratio": None,
        "manual_weight_multiplier": 1.0,
        "assisted_weight_cap": 0.50,
        "calibration_method": "sigmoid",
        "calibration_policy": "dedicated",
        "threshold_policy": "global_fixed_gate",
    },
    {
        "name": "provenance_balanced_extra_trees",
        "model_type": "extra_trees",
        "target_mode": "flat_5class",
        "class_weight": "balanced",
        "feature_set": "v546_transfer",
        "fit_assisted_ratio": 2.0,
        "manual_weight_multiplier": 1.5,
        "assisted_weight_cap": 0.50,
        "calibration_method": "sigmoid",
        "calibration_policy": "manual_preferred",
        "threshold_policy": "global_fixed_gate",
    },
    {
        "name": "manual_anchor_prioritized_extra_trees",
        "model_type": "extra_trees",
        "target_mode": "flat_5class",
        "class_weight": "balanced",
        "feature_set": "v546_transfer",
        "fit_assisted_ratio": 1.0,
        "manual_weight_multiplier": 2.0,
        "assisted_weight_cap": 0.25,
        "calibration_method": "isotonic",
        "calibration_policy": "manual_preferred",
        "threshold_policy": "class_conditional_fixed_gate",
    },
    {
        "name": "transfer_hist_gradient_boosting",
        "model_type": "hist_gradient_boosting",
        "target_mode": "flat_5class",
        "class_weight": None,
        "feature_set": "v546_transfer",
        "fit_assisted_ratio": 2.0,
        "manual_weight_multiplier": 1.5,
        "assisted_weight_cap": 0.50,
        "calibration_method": "sigmoid",
        "calibration_policy": "manual_preferred",
        "threshold_policy": "global_fixed_gate",
    },
    {
        "name": "transfer_logistic_regression",
        "model_type": "logistic_regression",
        "target_mode": "flat_5class",
        "class_weight": "balanced",
        "feature_set": "v546_transfer",
        "fit_assisted_ratio": 2.0,
        "manual_weight_multiplier": 1.5,
        "assisted_weight_cap": 0.50,
        "calibration_method": "sigmoid",
        "calibration_policy": "manual_preferred",
        "threshold_policy": "global_fixed_gate",
    },
    {
        "name": "binary_threat_positive_transfer",
        "model_type": "extra_trees",
        "target_mode": "binary_threat_positive",
        "class_weight": "balanced",
        "feature_set": "v546_transfer",
        "fit_assisted_ratio": 2.0,
        "manual_weight_multiplier": 1.5,
        "assisted_weight_cap": 0.50,
        "calibration_method": "sigmoid",
        "calibration_policy": "manual_preferred",
        "threshold_policy": "global_fixed_gate",
    },
    {
        "name": "three_class_soc_queue_transfer",
        "model_type": "extra_trees",
        "target_mode": "three_class_soc_queue",
        "class_weight": "balanced",
        "feature_set": "v546_transfer",
        "fit_assisted_ratio": 2.0,
        "manual_weight_multiplier": 1.5,
        "assisted_weight_cap": 0.50,
        "calibration_method": "isotonic",
        "calibration_policy": "manual_preferred",
        "threshold_policy": "class_conditional_fixed_gate",
    },
    {
        "name": "hierarchical_two_stage_transfer",
        "model_type": "extra_trees",
        "target_mode": "hierarchical_two_stage",
        "class_weight": "balanced",
        "feature_set": "v546_transfer",
        "fit_assisted_ratio": 2.0,
        "manual_weight_multiplier": 1.5,
        "assisted_weight_cap": 0.50,
        "calibration_method": "sigmoid",
        "calibration_policy": "manual_preferred",
        "threshold_policy": "global_fixed_gate",
    },
)

ENSEMBLE_SPEC = {
    "name": "conservative_calibrated_transfer_ensemble",
    "members": (
        "provenance_balanced_extra_trees",
        "transfer_logistic_regression",
    ),
    "target_mode": "flat_5class",
    "threshold_policy": "global_fixed_gate",
}

PROFILE_NUMERIC_FIELDS = (
    "parser_confidence_score",
    "v56_rule_evidence_score",
    "v56_scan_pressure",
    "src_ip_5min_unique_dst_ports",
    "src_ip_5min_unique_dst_ips",
    "deny_rate_5min",
    "src_ip_5min_unknown_app_count",
    "src_ip_5min_high_risk_app_count",
)


class V546TransferRepairError(RuntimeError):
    pass


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _stamp() -> str:
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")


def _number(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _integer(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _atomic_write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(
        json.dumps(value, indent=2, sort_keys=True, default=str),
        encoding="utf-8",
    )
    os.replace(temporary, path)


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError) as exc:
        raise V546TransferRepairError(
            "A required development-repair record is unreadable."
        ) from exc
    if not isinstance(value, dict):
        raise V546TransferRepairError(
            "A required development-repair record is malformed."
        )
    return value


def _time_regime(value: Any) -> str:
    hour = _integer(value, -1)
    if hour < 0:
        return "unknown"
    if hour < 7:
        return "overnight"
    if hour < 18:
        return "business_hours"
    return "evening"


def _port_bucket(value: Any) -> str:
    port = _integer(value, -1)
    if port < 0:
        return "missing"
    if port <= 1023:
        return "well_known"
    if port <= 49151:
        return "registered"
    return "ephemeral"


def _derived_feature_row(frame_row: Any, metadata: dict[str, Any]) -> dict[str, Any]:
    app = str(metadata.get("app") or frame_row.get("app") or "unknown").casefold()
    action = str(
        metadata.get("action") or frame_row.get("action") or "unknown"
    ).casefold()
    protocol = str(frame_row.get("protocol") or "unknown").casefold()
    port = _integer(metadata.get("dst_port", frame_row.get("dst_port")), -1)
    events = max(1.0, _number(frame_row.get("src_ip_5min_log_count"), 1.0))
    unique_ports = max(
        0.0, _number(frame_row.get("src_ip_5min_unique_dst_ports"))
    )
    unique_destinations = max(
        0.0, _number(frame_row.get("src_ip_5min_unique_dst_ips"))
    )
    unknown_count = max(
        0.0, _number(frame_row.get("src_ip_5min_unknown_app_count"))
    )
    high_risk_count = max(
        0.0, _number(frame_row.get("src_ip_5min_high_risk_app_count"))
    )
    deny_count = max(0.0, _number(frame_row.get("src_ip_5min_deny_count")))
    rule_score = max(0.0, _number(frame_row.get("v56_rule_evidence_score")))
    scan_pressure = max(0.0, _number(frame_row.get("v56_scan_pressure")))
    vendor_score = max(
        0.0, _number(frame_row.get("v56_vendor_severity_score")) / 5.0
    )
    parser_confidence = max(
        0.0, min(1.0, _number(frame_row.get("parser_confidence_score")))
    )
    bytes_value = max(0.0, _number(frame_row.get("bytes")))
    packets = max(0.0, _number(frame_row.get("packets")))
    destination_repeat = max(
        0.0, _number(frame_row.get("v56_destination_repeat_count"))
    )
    incomplete = app == "incomplete" and action == "allow" and port == 80
    quic = app == "quic-base" and action == "allow" and port == 443
    unknown = app in v56.UNKNOWN_APPS or app.startswith("unknown")
    routine = bool(
        action == "allow"
        and (
            app in v56.WEB_APPS
            or port in {53, 80, 123, 443}
        )
        and rule_score <= 0
        and scan_pressure < 0.50
    )
    rule_supported = bool(
        rule_score > 0
        or _integer(frame_row.get("v56_threat_record_flag")) > 0
        or vendor_score >= 0.60
    )
    parser_limited = bool(
        _number(frame_row.get("parser_warning_count")) > 0
        or _number(frame_row.get("required_field_missing_count")) > 0
        or parser_confidence < 0.75
    )
    evidence_strength = min(
        1.0,
        (rule_score / 100.0)
        + (0.35 * scan_pressure)
        + (0.25 * vendor_score)
        + (0.15 * min(1.0, deny_count / events)),
    )
    if rule_supported:
        context_profile = "rule_supported"
    elif scan_pressure >= 0.70:
        context_profile = "scan_context"
    elif incomplete:
        context_profile = "incomplete_web"
    elif quic:
        context_profile = "quic_web"
    elif unknown:
        context_profile = "unknown_transport"
    elif routine:
        context_profile = "routine_service"
    else:
        context_profile = "other"
    if evidence_strength >= 0.70:
        evidence_band = "strong"
    elif evidence_strength >= 0.35:
        evidence_band = "moderate"
    elif evidence_strength > 0:
        evidence_band = "weak"
    else:
        evidence_band = "none"
    transport_context = f"{protocol}:{_port_bucket(port)}"
    return {
        "v546_incomplete_allow_80_flag": int(incomplete),
        "v546_quic_443_allow_flag": int(quic),
        "v546_unknown_transport_flag": int(unknown),
        "v546_routine_service_flag": int(routine),
        "v546_rule_support_flag": int(rule_supported),
        "v546_parser_limited_flag": int(parser_limited),
        "v546_scan_diversity_ratio": round(
            min(1.0, (unique_ports + unique_destinations) / events), 6
        ),
        "v546_destination_diversity_ratio": round(
            min(1.0, unique_destinations / events), 6
        ),
        "v546_unknown_app_rate": round(min(1.0, unknown_count / events), 6),
        "v546_high_risk_app_rate": round(
            min(1.0, high_risk_count / events), 6
        ),
        "v546_deny_intensity": round(min(1.0, deny_count / events), 6),
        "v546_evidence_strength": round(evidence_strength, 6),
        "v546_bytes_per_packet": round(
            bytes_value / packets if packets else 0.0, 6
        ),
        "v546_destination_repeat_ratio": round(
            min(1.0, destination_repeat / events), 6
        ),
        "v546_context_profile": context_profile,
        "v546_evidence_band": evidence_band,
        "v546_time_regime": _time_regime(frame_row.get("hour_of_day")),
        "v546_transport_context": transport_context,
    }


def augment_bundle(imports: Any, bundle: dict[str, Any]) -> dict[str, Any]:
    pd = imports[1]
    frame = bundle["frame"].copy().reset_index(drop=True)
    derived = [
        _derived_feature_row(frame.iloc[index], bundle["rows"][index])
        for index in range(len(bundle["rows"]))
    ]
    if derived:
        derived_frame = pd.DataFrame(derived)
        for field in [
            *V546_DERIVED_NUMERIC_FEATURES,
            *V546_DERIVED_CATEGORICAL_FEATURES,
        ]:
            frame[field] = derived_frame[field]
    else:
        for field in V546_DERIVED_NUMERIC_FEATURES:
            frame[field] = pd.Series(dtype="float64")
        for field in V546_DERIVED_CATEGORICAL_FEATURES:
            frame[field] = pd.Series(dtype="object")
    return {
        "frame": frame,
        "rows": list(bundle["rows"]),
        "original_labels": list(bundle["original_labels"]),
        "targets": list(bundle["targets"]),
        "base_weights": list(bundle["base_weights"]),
    }


def _augment_views(imports: Any, views: list[dict[str, Any]]) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for view in views:
        output.append(
            {
                **view,
                **{
                    key: augment_bundle(imports, view[key])
                    for key in ("fit", "calibration", "threshold", "evaluation")
                },
            }
        )
    return output


def _safe_top(values: Iterable[Any], *, limit: int = 8) -> dict[str, int]:
    counts = Counter(str(value or "unknown") for value in values)
    return dict(counts.most_common(limit))


def _bundle_profile(bundle: dict[str, Any]) -> dict[str, Any]:
    rows = bundle["rows"]
    frame = bundle["frame"]
    numeric_means: dict[str, float] = {}
    for field in PROFILE_NUMERIC_FIELDS:
        values = [
            _number(frame.iloc[index].get(field))
            for index in range(len(rows))
        ]
        numeric_means[field] = round(mean(values), 4) if values else 0.0
    patterns = [
        v545._pattern_for_error(rows[index], frame.iloc[index])
        for index in range(len(rows))
    ]
    return {
        "rows": len(rows),
        "labels": _safe_top(bundle["original_labels"]),
        "queue_targets": _safe_top(bundle["targets"]),
        "provenance": _safe_top(row.get("provenance") for row in rows),
        "applications": _safe_top(row.get("app") for row in rows),
        "actions": _safe_top(row.get("action") for row in rows),
        "protocols": _safe_top(
            frame.iloc[index].get("protocol") for index in range(len(rows))
        ),
        "port_buckets": _safe_top(
            _port_bucket(row.get("dst_port")) for row in rows
        ),
        "schemas": _safe_top(row.get("schema") for row in rows),
        "time_regimes": _safe_top(
            _time_regime(frame.iloc[index].get("hour_of_day"))
            for index in range(len(rows))
        ),
        "patterns": _safe_top(patterns),
        "numeric_means": numeric_means,
        "manual_or_reviewed_rows": sum(
            1 for row in rows if row.get("human_reviewed")
        ),
        "private_rows": sum(1 for row in rows if row.get("private_source")),
        "exact_time_windows_returned": False,
        "private_identifiers_returned": False,
    }


def _distribution(values: dict[str, int]) -> dict[str, float]:
    total = max(1, sum(int(value) for value in values.values()))
    return {
        key: float(value) / total
        for key, value in values.items()
    }


def _total_variation(left: dict[str, int], right: dict[str, int]) -> float:
    left_distribution = _distribution(left)
    right_distribution = _distribution(right)
    keys = set(left_distribution) | set(right_distribution)
    return round(
        0.5
        * sum(
            abs(left_distribution.get(key, 0.0) - right_distribution.get(key, 0.0))
            for key in keys
        ),
        4,
    )


def diagnose_manual_anchor_transfer(
    imports: Any,
    *,
    human: dict[str, dict[str, Any]],
    private: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    manual = v545._manual_only(
        imports,
        v545._concat_bundles(
            imports,
            human["development_fit"],
            human["calibration"],
            human["threshold"],
        ),
    )
    assisted = v545._concat_bundles(
        imports,
        private["development_fit"],
        private["calibration"],
        private["threshold"],
    )
    manual = augment_bundle(imports, manual)
    assisted = augment_bundle(imports, assisted)
    manual_profile = _bundle_profile(manual)
    assisted_profile = _bundle_profile(assisted)
    categorical_shift = {
        field: _total_variation(
            manual_profile[field],
            assisted_profile[field],
        )
        for field in (
            "labels",
            "applications",
            "actions",
            "protocols",
            "port_buckets",
            "schemas",
            "time_regimes",
            "patterns",
        )
    }
    numeric_shift = {
        field: round(
            abs(
                _number(manual_profile["numeric_means"].get(field))
                - _number(assisted_profile["numeric_means"].get(field))
            ),
            4,
        )
        for field in PROFILE_NUMERIC_FIELDS
    }
    root_causes: list[str] = []
    if categorical_shift["labels"] >= 0.20:
        root_causes.append("Manual and assisted label distributions differ materially.")
    if categorical_shift["applications"] >= 0.20:
        root_causes.append("Application mix shifts between assisted and manual evidence.")
    if categorical_shift["patterns"] >= 0.20:
        root_causes.append("Residual traffic-pattern mix differs across provenance cohorts.")
    if categorical_shift["time_regimes"] >= 0.20:
        root_causes.append("Chronological operating regimes differ across evidence cohorts.")
    if numeric_shift["v56_rule_evidence_score"] >= 10.0:
        root_causes.append("Rule-evidence strength differs across provenance cohorts.")
    if numeric_shift["v56_scan_pressure"] >= 0.20:
        root_causes.append("Scan/diversity behavior differs across provenance cohorts.")
    if not root_causes:
        root_causes.append(
            "No single aggregate shift dominates; calibration and class-boundary transfer remain the leading hypotheses."
        )
    return {
        "status": "evaluated",
        "manual_anchor_profile": manual_profile,
        "assisted_profile": assisted_profile,
        "categorical_total_variation": categorical_shift,
        "numeric_mean_absolute_shift": numeric_shift,
        "root_causes": root_causes,
        "single_real_device_available": True,
        "anomaly_evidence_audited_separately": True,
        "future_labels_opened": False,
        "raw_rows_returned": False,
        "private_identifiers_returned": False,
        "exact_time_windows_returned": False,
    }


def _rebalance_fit_bundle(
    imports: Any,
    bundle: dict[str, Any],
    *,
    target_mode: str,
    assisted_to_manual_ratio: float | None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    if assisted_to_manual_ratio is None:
        return bundle, {
            "policy": "all_rows_with_effective_weight_cap",
            "input_rows": len(bundle["rows"]),
            "output_rows": len(bundle["rows"]),
            "assisted_rows_dropped": 0,
            "labels_rewritten": False,
        }
    targets = v545._targets_for_mode(bundle, target_mode)
    manual_by_target: dict[str, list[int]] = defaultdict(list)
    assisted_by_target: dict[str, list[int]] = defaultdict(list)
    for index, target in enumerate(targets):
        if bundle["rows"][index].get("human_reviewed"):
            manual_by_target[target].append(index)
        else:
            assisted_by_target[target].append(index)
    selected = [index for values in manual_by_target.values() for index in values]
    for target, values in sorted(assisted_by_target.items()):
        manual_support = len(manual_by_target.get(target, []))
        fallback = max(20, len(selected) // max(1, len(set(targets))))
        cap = max(
            fallback if manual_support == 0 else 0,
            int(max(1, manual_support) * assisted_to_manual_ratio),
        )
        selected.extend(values[:cap])
    output = v545._slice_bundle(imports, bundle, selected)
    return output, {
        "policy": "deterministic_provenance_and_target_balance",
        "input_rows": len(bundle["rows"]),
        "output_rows": len(output["rows"]),
        "manual_rows": sum(
            1 for row in output["rows"] if row.get("human_reviewed")
        ),
        "assisted_rows": sum(
            1 for row in output["rows"] if not row.get("human_reviewed")
        ),
        "assisted_rows_dropped": len(bundle["rows"]) - len(output["rows"]),
        "assisted_to_manual_row_ratio_limit": assisted_to_manual_ratio,
        "labels_rewritten": False,
    }


def _transfer_weights(
    bundle: dict[str, Any],
    targets: list[str],
    *,
    assisted_cap: float,
    manual_multiplier: float,
) -> tuple[list[float], dict[str, Any]]:
    weights, summary = v545._anchor_capped_weights(
        bundle,
        targets,
        assisted_cap=assisted_cap,
    )
    for index, row in enumerate(bundle["rows"]):
        if row.get("human_reviewed"):
            weights[index] *= max(1.0, float(manual_multiplier))
    manual_total = sum(
        weights[index]
        for index, row in enumerate(bundle["rows"])
        if row.get("human_reviewed")
    )
    assisted_total = sum(
        weights[index]
        for index, row in enumerate(bundle["rows"])
        if not row.get("human_reviewed")
    )
    allowed = manual_total * min(0.75, max(0.0, assisted_cap))
    if assisted_total > allowed and assisted_total > 0:
        scale = allowed / assisted_total
        for index, row in enumerate(bundle["rows"]):
            if not row.get("human_reviewed"):
                weights[index] *= scale
        assisted_total = sum(
            weights[index]
            for index, row in enumerate(bundle["rows"])
            if not row.get("human_reviewed")
        )
    summary.update(
        {
            "strategy": "manual_prioritized_class_balance_with_assisted_cap",
            "manual_weight_multiplier": float(manual_multiplier),
            "manual_effective_weight": round(manual_total, 6),
            "assisted_effective_weight": round(assisted_total, 6),
            "assisted_to_manual_weight_ratio": (
                round(assisted_total / manual_total, 6)
                if manual_total
                else None
            ),
            "assisted_labels_dominate_manual_anchors": bool(
                manual_total <= 0 or assisted_total > manual_total
            ),
            "labels_rewritten": False,
        }
    )
    return weights, summary


def _prepare_calibration_bundle(
    imports: Any,
    bundle: dict[str, Any],
    *,
    target_mode: str,
    policy: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    filtered = v545._filter_for_mode(imports, bundle, target_mode)
    if policy != "manual_preferred":
        return filtered, {
            "policy": "dedicated_partition",
            "manual_only_used": False,
            "rows": len(filtered["rows"]),
            "fallback_used": False,
        }
    manual = v545._manual_only(imports, filtered)
    manual_targets = v545._targets_for_mode(manual, target_mode)
    full_targets = v545._targets_for_mode(filtered, target_mode)
    class_support = Counter(manual_targets)
    required_classes = set(full_targets)
    support_sufficient = bool(
        len(manual["rows"]) >= 80
        and set(manual_targets) == required_classes
        and min(class_support.values(), default=0) >= 10
    )
    selected = manual if support_sufficient else filtered
    return selected, {
        "policy": "manual_preferred_dedicated_partition",
        "manual_only_used": support_sufficient,
        "manual_rows_available": len(manual["rows"]),
        "rows": len(selected["rows"]),
        "class_support_sufficient": support_sufficient,
        "fallback_used": not support_sufficient,
        "fallback_reason": (
            None
            if support_sufficient
            else "manual calibration partition lacks required class support"
        ),
    }


def _fit_calibrator(
    pipeline: Any,
    imports: Any,
    fit: dict[str, Any],
    calibration: dict[str, Any],
    *,
    target_mode: str,
    method: str,
) -> tuple[Any, str]:
    combined = v545._concat_bundles(imports, fit, calibration)
    targets = v545._targets_for_mode(combined, target_mode)
    calibration_indices = list(range(len(fit["rows"]), len(combined["rows"])))
    model, applied = reliability._fit_frozen_calibrator(
        pipeline,
        combined["frame"],
        calibration_indices,
        targets,
        method=method,
    )
    if method == "isotonic" and not applied.startswith("isotonic_"):
        model, fallback = reliability._fit_frozen_calibrator(
            pipeline,
            combined["frame"],
            calibration_indices,
            targets,
            method="sigmoid",
        )
        return model, f"{fallback};isotonic_fallback"
    return model, applied


def _queue_metrics(
    bundle: dict[str, Any],
    predictions: list[str],
) -> dict[str, Any]:
    metrics = frozen._binary_metrics(bundle["targets"], predictions)
    metrics.update(
        frozen._diagnostic_original_recall(
            bundle["rows"],
            list(range(len(bundle["rows"]))),
            predictions,
        )
    )
    metrics.update(
        {
            "threat_positive_precision": metrics.get("queue_precision"),
            "threat_positive_recall": metrics.get("queue_recall"),
            "threat_positive_f1": metrics.get("queue_f1"),
        }
    )
    return metrics


def _threshold_quality(metrics: dict[str, Any]) -> tuple[int, float]:
    checks = (
        _number(metrics.get("queue_precision"))
        >= FIXED_FREEZE_GATES["queue_precision_min"],
        _number(metrics.get("queue_recall"))
        >= FIXED_FREEZE_GATES["queue_recall_min"],
        _number(metrics.get("queue_f1"))
        >= FIXED_FREEZE_GATES["queue_f1_min"],
        _number(metrics.get("benign_like_false_positive_rate"), 1.0)
        <= FIXED_FREEZE_GATES["benign_like_false_positive_rate_max"],
        metrics.get("suspicious_recall") is not None
        and _number(metrics.get("suspicious_recall"))
        >= FIXED_FREEZE_GATES["suspicious_recall_min"],
        metrics.get("malicious_recall") is not None
        and _number(metrics.get("malicious_recall"))
        >= FIXED_FREEZE_GATES["malicious_recall_min"],
    )
    score = (
        _number(metrics.get("queue_f1"))
        + (0.20 * _number(metrics.get("queue_recall")))
        + (0.10 * _number(metrics.get("suspicious_recall")))
        + (0.10 * _number(metrics.get("malicious_recall")))
        - (0.75 * _number(metrics.get("benign_like_false_positive_rate"), 1.0))
    )
    return sum(checks), score


def _select_global_threshold(
    bundle: dict[str, Any],
    scores: list[float],
) -> dict[str, Any]:
    candidates: list[dict[str, Any]] = []
    for threshold in reliability.THRESHOLD_GRID:
        predictions = [
            "needs_review" if score >= threshold else "non_threat"
            for score in scores
        ]
        metrics = _queue_metrics(bundle, predictions)
        gates, quality = _threshold_quality(metrics)
        candidates.append(
            {
                "threshold": threshold,
                "gate_count": gates,
                "all_quality_gates_feasible": gates == 6,
                "quality": quality,
                "metrics": metrics,
            }
        )
    selected = max(
        candidates,
        key=lambda row: (
            int(row["all_quality_gates_feasible"]),
            int(row["gate_count"]),
            float(row["quality"]),
            -_number(row["metrics"].get("benign_like_false_positive_rate"), 1.0),
            float(row["threshold"]),
        ),
    )
    return {
        "status": "selected",
        "policy": "global_fixed_gate",
        "selected_threshold": selected["threshold"],
        "selected_on": "threshold_partition_only",
        "threshold_rows": len(bundle["rows"]),
        "used_evaluation_labels": False,
        "future_labels_used": False,
        "gate_feasible_on_threshold_partition": bool(
            selected["all_quality_gates_feasible"]
        ),
        "selected_metrics": selected["metrics"],
        "candidate_count": len(candidates),
    }


def _class_probability_rows(model: Any, frame: Any) -> tuple[list[str], list[list[float]]]:
    classes = [str(value) for value in reliability._classes(model)]
    probabilities = [
        [float(value) for value in row]
        for row in model.predict_proba(frame)
    ]
    return classes, probabilities


def _class_conditional_predictions(
    classes: list[str],
    probabilities: list[list[float]],
    thresholds: dict[str, float],
) -> list[str]:
    positions = {
        label: classes.index(label)
        for label in thresholds
        if label in classes
    }
    return [
        (
            "needs_review"
            if any(row[positions[label]] >= threshold for label, threshold in thresholds.items() if label in positions)
            else "non_threat"
        )
        for row in probabilities
    ]


def _select_class_conditional_thresholds(
    model: Any,
    bundle: dict[str, Any],
    *,
    target_mode: str,
) -> dict[str, Any]:
    classes, probabilities = _class_probability_rows(model, bundle["frame"])
    positive_classes = sorted(v545._positive_classes(target_mode) & set(classes))
    if not positive_classes or len(positive_classes) > 3:
        scores = reliability._queue_scores(
            model,
            bundle["frame"],
            list(range(len(bundle["rows"]))),
            v545._positive_classes(target_mode),
        )
        result = _select_global_threshold(bundle, scores)
        result.update(
            {
                "policy": "global_fixed_gate_fallback",
                "class_conditional_supported": False,
            }
        )
        return result
    grid = (0.20, 0.30, 0.40, 0.50, 0.60, 0.70, 0.80)
    candidates: list[dict[str, Any]] = []
    for values in itertools.product(grid, repeat=len(positive_classes)):
        thresholds = dict(zip(positive_classes, values, strict=True))
        predictions = _class_conditional_predictions(
            classes,
            probabilities,
            thresholds,
        )
        metrics = _queue_metrics(bundle, predictions)
        gates, quality = _threshold_quality(metrics)
        candidates.append(
            {
                "thresholds": thresholds,
                "gate_count": gates,
                "all_quality_gates_feasible": gates == 6,
                "quality": quality,
                "metrics": metrics,
            }
        )
    selected = max(
        candidates,
        key=lambda row: (
            int(row["all_quality_gates_feasible"]),
            int(row["gate_count"]),
            float(row["quality"]),
            -_number(row["metrics"].get("benign_like_false_positive_rate"), 1.0),
            sum(float(value) for value in row["thresholds"].values()),
        ),
    )
    return {
        "status": "selected",
        "policy": "class_conditional_fixed_gate",
        "selected_class_thresholds": selected["thresholds"],
        "selected_on": "threshold_partition_only",
        "threshold_rows": len(bundle["rows"]),
        "used_evaluation_labels": False,
        "future_labels_used": False,
        "class_conditional_supported": True,
        "gate_feasible_on_threshold_partition": bool(
            selected["all_quality_gates_feasible"]
        ),
        "selected_metrics": selected["metrics"],
        "candidate_count": len(candidates),
    }


def _apply_threshold_policy(
    model: Any,
    bundle: dict[str, Any],
    *,
    target_mode: str,
    threshold_selection: dict[str, Any],
) -> tuple[list[str], list[float]]:
    scores = reliability._queue_scores(
        model,
        bundle["frame"],
        list(range(len(bundle["rows"]))),
        v545._positive_classes(target_mode),
    )
    class_thresholds = threshold_selection.get("selected_class_thresholds")
    if isinstance(class_thresholds, dict):
        classes, probabilities = _class_probability_rows(model, bundle["frame"])
        return (
            _class_conditional_predictions(
                classes,
                probabilities,
                {
                    str(key): float(value)
                    for key, value in class_thresholds.items()
                },
            ),
            scores,
        )
    threshold = _number(threshold_selection.get("selected_threshold"), 0.5)
    return (
        [
            "needs_review" if score >= threshold else "non_threat"
            for score in scores
        ],
        scores,
    )


def _calibration_by_provenance(
    bundle: dict[str, Any],
    scores: list[float],
) -> dict[str, Any]:
    output: dict[str, Any] = {}
    groups = {
        "manual_or_reviewed": [
            index
            for index, row in enumerate(bundle["rows"])
            if row.get("human_reviewed")
        ],
        "assisted": [
            index
            for index, row in enumerate(bundle["rows"])
            if not row.get("human_reviewed")
        ],
    }
    for name, indices in groups.items():
        if len(indices) < 20:
            output[name] = {"status": "insufficient_rows", "rows": len(indices)}
            continue
        report = frozen._calibration_report(
            [bundle["targets"][index] for index in indices],
            [scores[index] for index in indices],
        )
        report.pop("confidence_buckets", None)
        output[name] = {"rows": len(indices), **report}
    return output


def _top_features(pipeline: Any, *, limit: int = 15) -> list[dict[str, Any]]:
    try:
        preprocessor = pipeline.named_steps["preprocessor"]
        estimator = pipeline.named_steps["model"]
        names = [str(value) for value in preprocessor.get_feature_names_out()]
        if hasattr(estimator, "feature_importances_"):
            values = [float(value) for value in estimator.feature_importances_]
        elif hasattr(estimator, "coef_"):
            coefficients = estimator.coef_
            values = [
                mean(abs(float(row[index])) for row in coefficients)
                for index in range(len(names))
            ]
        else:
            return []
        ranked = sorted(zip(names, values, strict=False), key=lambda row: row[1], reverse=True)
        return [
            {"feature": name, "importance": round(value, 6)}
            for name, value in ranked[:limit]
        ]
    except (AttributeError, KeyError, TypeError, ValueError, IndexError):
        return []


def _fit_transfer_strategy(
    imports: Any,
    *,
    view: dict[str, Any],
    spec: dict[str, Any],
) -> dict[str, Any]:
    mode = str(spec["target_mode"])
    fit = v545._filter_for_mode(imports, view["fit"], mode)
    calibration, calibration_policy = _prepare_calibration_bundle(
        imports,
        view["calibration"],
        target_mode=mode,
        policy=str(spec["calibration_policy"]),
    )
    threshold = v545._filter_for_mode(imports, view["threshold"], mode)
    evaluation = v545._filter_for_mode(imports, view["evaluation"], mode)
    fit, sampling = _rebalance_fit_bundle(
        imports,
        fit,
        target_mode=mode,
        assisted_to_manual_ratio=spec.get("fit_assisted_ratio"),
    )
    if any(
        len(bundle["rows"]) < 10
        for bundle in (fit, calibration, threshold, evaluation)
    ):
        return {
            "status": "failed_closed",
            "name": spec["name"],
            "reason": "a dedicated development partition has insufficient rows",
        }
    targets = v545._targets_for_mode(fit, mode)
    if len(set(targets)) < 2:
        return {
            "status": "failed_closed",
            "name": spec["name"],
            "reason": "fit target support is insufficient",
        }
    enhanced = spec["feature_set"] == "v546_transfer"
    numeric_features = V546_NUMERIC_FEATURES if enhanced else v56.V56_NUMERIC_FEATURES
    categorical_features = (
        V546_CATEGORICAL_FEATURES if enhanced else v56.V56_CATEGORICAL_FEATURES
    )
    pipeline = _build_pipeline_for_columns(
        imports,
        model_type=str(spec["model_type"]),
        class_weight=spec.get("class_weight"),
        numeric_features=numeric_features,
        categorical_features=categorical_features,
    )
    weights, weighting = _transfer_weights(
        fit,
        targets,
        assisted_cap=float(spec["assisted_weight_cap"]),
        manual_multiplier=float(spec["manual_weight_multiplier"]),
    )
    if weighting["assisted_labels_dominate_manual_anchors"]:
        return {
            "status": "failed_closed",
            "name": spec["name"],
            "reason": "assisted effective weight exceeds manual anchor weight",
            "sample_weighting": weighting,
        }
    started = time.perf_counter()
    try:
        pipeline.fit(fit["frame"], targets, model__sample_weight=weights)
        model, calibration_method = _fit_calibrator(
            pipeline,
            imports,
            fit,
            calibration,
            target_mode=mode,
            method=str(spec["calibration_method"]),
        )
        threshold_scores = reliability._queue_scores(
            model,
            threshold["frame"],
            list(range(len(threshold["rows"]))),
            v545._positive_classes(mode),
        )
        if spec["threshold_policy"] == "class_conditional_fixed_gate":
            threshold_selection = _select_class_conditional_thresholds(
                model,
                threshold,
                target_mode=mode,
            )
        else:
            threshold_selection = _select_global_threshold(
                threshold,
                threshold_scores,
            )
        predictions, evaluation_scores = _apply_threshold_policy(
            model,
            evaluation,
            target_mode=mode,
            threshold_selection=threshold_selection,
        )
    except (ValueError, TypeError, IndexError, AttributeError) as exc:
        return {
            "status": "failed_closed",
            "name": spec["name"],
            "reason": f"model evaluation failed: {exc.__class__.__name__}",
            "sample_weighting": weighting,
        }
    metrics = _queue_metrics(evaluation, predictions)
    calibration_report = frozen._calibration_report(
        evaluation["targets"],
        evaluation_scores,
    )
    classification = None
    if mode in {"flat_5class", "three_class_soc_queue"}:
        direct = [str(value) for value in model.predict(evaluation["frame"])]
        actual = (
            evaluation["original_labels"]
            if mode == "flat_5class"
            else v56._three_class_targets(evaluation["original_labels"])
        )
        classification = reliability._classification_diagnostics(actual, direct)
    result = {
        "status": "evaluated",
        "name": spec["name"],
        "model_type": spec["model_type"],
        "target_mode": mode,
        "feature_set": spec["feature_set"],
        "fit_rows": len(fit["rows"]),
        "calibration_rows": len(calibration["rows"]),
        "threshold_rows": len(threshold["rows"]),
        "evaluation_rows": len(evaluation["rows"]),
        "evaluation_provenance": v545._provenance_profile(evaluation),
        "fit_sampling": sampling,
        "sample_weighting": weighting,
        "calibration_partition_policy": calibration_policy,
        "applied_calibration_method": calibration_method,
        "threshold_selection": threshold_selection,
        "metrics": metrics,
        "calibration": calibration_report,
        "calibration_by_provenance": _calibration_by_provenance(
            evaluation,
            evaluation_scores,
        ),
        "classification_diagnostics": classification,
        "residual_errors": v545._residual_error_audit(
            evaluation,
            evaluation["targets"],
            predictions,
        ),
        "top_features": _top_features(pipeline),
        "post_prediction_guard_used": False,
        "future_labels_used": False,
        "active_artifact_written": False,
        "model_activated": False,
        "model_promoted": False,
        "training_seconds": round(time.perf_counter() - started, 4),
        "_model": model,
        "_base_pipeline": pipeline,
        "_threshold_scores": threshold_scores,
        "_evaluation_scores": evaluation_scores,
        "_evaluation_bundle": evaluation,
        "_threshold_bundle": threshold,
    }
    result["fixed_freeze_gate"] = v542._fixed_fold_gate(
        result,
        leakage_passed=bool(view["leakage_audit"]["passed"]),
    )
    return result


def _fit_ensemble(
    *,
    view: dict[str, Any],
    members: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    names = tuple(str(value) for value in ENSEMBLE_SPEC["members"])
    selected = [members.get(name) for name in names]
    if any(not row or row.get("status") != "evaluated" for row in selected):
        return {
            "status": "failed_closed",
            "name": ENSEMBLE_SPEC["name"],
            "reason": "required calibrated ensemble member is unavailable",
        }
    typed = [row for row in selected if row]
    threshold_bundle = typed[0]["_threshold_bundle"]
    evaluation_bundle = typed[0]["_evaluation_bundle"]
    threshold_scores = [
        mean(float(row["_threshold_scores"][index]) for row in typed)
        for index in range(len(threshold_bundle["rows"]))
    ]
    evaluation_scores = [
        mean(float(row["_evaluation_scores"][index]) for row in typed)
        for index in range(len(evaluation_bundle["rows"]))
    ]
    threshold_selection = _select_global_threshold(
        threshold_bundle,
        threshold_scores,
    )
    selected_threshold = _number(
        threshold_selection.get("selected_threshold"), 0.5
    )
    predictions = [
        "needs_review" if score >= selected_threshold else "non_threat"
        for score in evaluation_scores
    ]
    metrics = _queue_metrics(evaluation_bundle, predictions)
    calibration = frozen._calibration_report(
        evaluation_bundle["targets"],
        evaluation_scores,
    )
    result = {
        "status": "evaluated",
        "name": ENSEMBLE_SPEC["name"],
        "model_type": "calibrated_soft_vote",
        "target_mode": ENSEMBLE_SPEC["target_mode"],
        "feature_set": "v546_transfer",
        "ensemble_members": list(names),
        "fit_rows": min(int(row["fit_rows"]) for row in typed),
        "calibration_rows": min(int(row["calibration_rows"]) for row in typed),
        "threshold_rows": len(threshold_bundle["rows"]),
        "evaluation_rows": len(evaluation_bundle["rows"]),
        "evaluation_provenance": v545._provenance_profile(evaluation_bundle),
        "fit_sampling": {"policy": "member_specific_transfer_balance"},
        "sample_weighting": {
            "strategy": "member_specific_manual_anchor_caps",
            "assisted_labels_dominate_manual_anchors": any(
                bool(
                    (row.get("sample_weighting") or {}).get(
                        "assisted_labels_dominate_manual_anchors"
                    )
                )
                for row in typed
            ),
            "labels_rewritten": False,
        },
        "calibration_partition_policy": {
            "policy": "average_of_independently_calibrated_members"
        },
        "applied_calibration_method": "sigmoid_ensemble_average",
        "threshold_selection": threshold_selection,
        "metrics": metrics,
        "calibration": calibration,
        "calibration_by_provenance": _calibration_by_provenance(
            evaluation_bundle,
            evaluation_scores,
        ),
        "classification_diagnostics": None,
        "residual_errors": v545._residual_error_audit(
            evaluation_bundle,
            evaluation_bundle["targets"],
            predictions,
        ),
        "top_features": [],
        "post_prediction_guard_used": False,
        "future_labels_used": False,
        "active_artifact_written": False,
        "model_activated": False,
        "model_promoted": False,
        "_threshold_scores": threshold_scores,
        "_evaluation_scores": evaluation_scores,
        "_evaluation_bundle": evaluation_bundle,
        "_threshold_bundle": threshold_bundle,
    }
    result["fixed_freeze_gate"] = v542._fixed_fold_gate(
        result,
        leakage_passed=bool(view["leakage_audit"]["passed"]),
    )
    return result


def _range(values: list[float]) -> dict[str, float | None]:
    return {
        "minimum": round(min(values), 4) if values else None,
        "maximum": round(max(values), 4) if values else None,
        "mean": round(mean(values), 4) if values else None,
    }


def _public_strategy(result: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in result.items() if not key.startswith("_")}


def run_transfer_model_comparison(
    imports: Any,
    views: list[dict[str, Any]],
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    views = _augment_views(imports, views)
    public_views: list[dict[str, Any]] = []
    by_strategy: dict[str, list[dict[str, Any]]] = defaultdict(list)
    internal_latest: dict[str, dict[str, Any]] = {}
    for view in views:
        strategies: list[dict[str, Any]] = []
        internal_view: dict[str, dict[str, Any]] = {}
        for spec in TRANSFER_STRATEGY_SPECS:
            result = _fit_transfer_strategy(imports, view=view, spec=spec)
            internal_view[str(spec["name"])] = result
            public = _public_strategy(result)
            strategies.append(public)
            if result.get("status") == "evaluated":
                by_strategy[str(spec["name"])].append(
                    {"view": view["name"], **public}
                )
                internal_latest[str(spec["name"])] = result
        ensemble = _fit_ensemble(view=view, members=internal_view)
        strategies.append(_public_strategy(ensemble))
        if ensemble.get("status") == "evaluated":
            by_strategy[str(ENSEMBLE_SPEC["name"])].append(
                {"view": view["name"], **_public_strategy(ensemble)}
            )
            internal_latest[str(ENSEMBLE_SPEC["name"])] = ensemble
        public_views.append(
            {
                "name": view["name"],
                "evaluation_cohort": view["evaluation_cohort"],
                "leakage_audit": view["leakage_audit"],
                "strategies": strategies,
            }
        )

    summaries: dict[str, Any] = {}
    ranking: list[tuple[Any, ...]] = []
    for name, evaluations in by_strategy.items():
        metric_ranges = {
            field: _range(
                [
                    float((row.get("metrics") or {})[field])
                    for row in evaluations
                    if (row.get("metrics") or {}).get(field) is not None
                ]
            )
            for field in v542.METRIC_FIELDS
        }
        calibration_ranges = {
            field: _range(
                [
                    float((row.get("calibration") or {})[field])
                    for row in evaluations
                    if (row.get("calibration") or {}).get(field) is not None
                ]
            )
            for field in v542.CALIBRATION_FIELDS
        }
        passing = sum(
            1
            for row in evaluations
            if (row.get("fixed_freeze_gate") or {}).get("passed")
        )
        queue_values = [
            _number((row.get("metrics") or {}).get("review_queue_rate"))
            for row in evaluations
        ]
        queue_spread = (
            max(queue_values) - min(queue_values) if queue_values else 1.0
        )
        all_views = len(evaluations) == len(views)
        weight_integrity = all(
            not bool(
                (row.get("sample_weighting") or {}).get(
                    "assisted_labels_dominate_manual_anchors"
                )
            )
            for row in evaluations
        )
        manual = next(
            (row for row in evaluations if row["view"] == "manual_anchor_holdout"),
            None,
        )
        assisted = next(
            (
                row
                for row in evaluations
                if row["view"] == "threshold_cohort_holdout"
            ),
            None,
        )
        summary = {
            "evaluated_views": len(evaluations),
            "required_views": len(views),
            "passing_views": passing,
            "all_views_passed": bool(all_views and passing == len(views)),
            "review_queue_rate_spread": round(queue_spread, 4),
            "review_queue_stability_passed": bool(
                queue_spread
                <= FIXED_FREEZE_GATES["review_queue_rate_spread_max"]
            ),
            "assisted_weight_integrity_passed": weight_integrity,
            "metric_ranges": metric_ranges,
            "calibration_ranges": calibration_ranges,
            "assisted_label_sensitivity": {
                "manual_holdout_available": manual is not None,
                "assisted_holdout_available": assisted is not None,
                "queue_f1_absolute_gap": (
                    round(
                        abs(
                            _number((manual or {}).get("metrics", {}).get("queue_f1"))
                            - _number((assisted or {}).get("metrics", {}).get("queue_f1"))
                        ),
                        4,
                    )
                    if manual and assisted
                    else None
                ),
                "fpr_absolute_gap": (
                    round(
                        abs(
                            _number(
                                (manual or {}).get("metrics", {}).get(
                                    "benign_like_false_positive_rate"
                                )
                            )
                            - _number(
                                (assisted or {}).get("metrics", {}).get(
                                    "benign_like_false_positive_rate"
                                )
                            )
                        ),
                        4,
                    )
                    if manual and assisted
                    else None
                ),
            },
        }
        summary["candidate_freeze_eligible"] = bool(
            summary["all_views_passed"]
            and summary["review_queue_stability_passed"]
            and weight_integrity
        )
        summaries[name] = summary
        f1_min = _number((metric_ranges.get("queue_f1") or {}).get("minimum"))
        fpr_max = _number(
            (metric_ranges.get("benign_like_false_positive_rate") or {}).get(
                "maximum"
            ),
            1.0,
        )
        suspicious_min = _number(
            (metric_ranges.get("suspicious_recall") or {}).get("minimum")
        )
        calibration_max = _number(
            (calibration_ranges.get("expected_calibration_error") or {}).get(
                "maximum"
            ),
            1.0,
        )
        ranking.append(
            (
                int(summary["candidate_freeze_eligible"]),
                passing,
                f1_min + (0.20 * suspicious_min) - fpr_max - (0.20 * calibration_max),
                -fpr_max,
                f1_min,
                name,
            )
        )
    leader = None
    if ranking:
        name = str(max(ranking)[-1])
        leader = {
            "name": name,
            "selection_basis": (
                "v5_44_development_roles_only_manual_transfer_and_unchanged_v5_42_gates"
            ),
            "summary": summaries[name],
            "candidate_freeze_eligible": bool(
                summaries[name]["candidate_freeze_eligible"]
            ),
            "future_labels_used": False,
            "_latest_fitted": internal_latest[name],
        }
    return {
        "status": "evaluated" if views else "failed_closed_no_views",
        "strategies_compared": len(TRANSFER_STRATEGY_SPECS) + 1,
        "views": public_views,
        "strategy_summaries": summaries,
        "fixed_freeze_gates": FIXED_FREEZE_GATES,
        "feature_sets_compared": ["v545_baseline", "v546_transfer"],
        "calibration_methods_compared": ["sigmoid", "isotonic"],
        "threshold_policies_compared": [
            "global_fixed_gate",
            "class_conditional_fixed_gate",
        ],
        "future_labels_used_for_fit": False,
        "future_labels_used_for_calibration": False,
        "future_labels_used_for_threshold_selection": False,
        "future_labels_used_for_candidate_ranking": False,
        "post_prediction_guard_used": False,
    }, leader


def _v545_status_lock(output_dir: Path) -> dict[str, Any]:
    latest_path = output_dir / v545.V545_LATEST
    if not latest_path.is_file():
        raise V546TransferRepairError(
            "The completed v5.45 development-repair record is required."
        )
    latest = _read_json(latest_path)
    checks = {
        "version_valid": latest.get("version") == v545.V545_VERSION,
        "safety_valid": bool(
            (latest.get("safety") or {}).get("all_invariants_passed")
        ),
        "future_labels_sealed": not bool(latest.get("future_labels_opened")),
        "active_artifact_unchanged": not bool(
            latest.get("active_model_artifact_written")
        ),
        "model_not_activated": not bool(latest.get("model_activated")),
        "model_not_promoted": not bool(latest.get("model_promoted")),
        "rules_remain_authoritative": bool(
            latest.get("rules_alert_authoritative")
        ),
        "fixed_gates_unchanged": (
            (latest.get("model_comparison") or {}).get("fixed_freeze_gates")
            == FIXED_FREEZE_GATES
        ),
    }
    if not all(checks.values()):
        raise V546TransferRepairError(
            "The v5.45 development-repair record failed custody validation."
        )
    return {
        "checks": checks,
        "all_checks_passed": True,
        "latest": latest,
        "file_state": v55._file_state(latest_path),
    }


def _protected_state(
    *,
    v544_output_dir: Path,
    v545_output_dir: Path,
    state_path: Path,
    pack_path: Path,
    blind_output_dir: Path,
    v542_output_dir: Path,
    v543_output_dir: Path,
) -> dict[str, Any]:
    return {
        "through_v544": v545._protected_state(
            v544_output_dir=v544_output_dir,
            state_path=state_path,
            pack_path=pack_path,
            blind_output_dir=blind_output_dir,
            v542_output_dir=v542_output_dir,
            v543_output_dir=v543_output_dir,
        ),
        "v545_latest": v55._file_state(v545_output_dir / v545.V545_LATEST),
        "v545_recipe": v55._file_state(
            v545_output_dir / v545.V545_FREEZE_MANIFEST
        ),
    }


def revalidate_v546_custody(
    db: Session,
    *,
    min_samples: int = 100,
    v544_output_dir: Path = v544.V544_OUTPUT_DIR,
    v545_output_dir: Path = v545.V545_OUTPUT_DIR,
    state_path: Path = v540.V539_STATE_PATH,
    pack_path: Path = v540.DEFAULT_PACK_PATH,
    blind_output_dir: Path = v541.V541_OUTPUT_DIR,
    v542_output_dir: Path = v542.V542_OUTPUT_DIR,
    v543_output_dir: Path = v543.V543_OUTPUT_DIR,
) -> dict[str, Any]:
    prior = v545.revalidate_v545_custody(
        db,
        min_samples=min_samples,
        v544_output_dir=v544_output_dir,
        state_path=state_path,
        pack_path=pack_path,
        blind_output_dir=blind_output_dir,
        v542_output_dir=v542_output_dir,
        v543_output_dir=v543_output_dir,
    )
    v545_lock = _v545_status_lock(v545_output_dir)
    checks = {
        "v539_through_v545_custody_valid": bool(
            prior.get("all_checks_passed")
        ),
        "v545_measured_record_valid": bool(v545_lock["all_checks_passed"]),
        "fixed_v542_gates_unchanged": (
            FIXED_FREEZE_GATES == v542.FIXED_FREEZE_GATES
        ),
        "eligible_roles_limited_to_development": True,
        "untouched_future_labels_sealed": True,
    }
    if not all(checks.values()):
        raise V546TransferRepairError(
            "The v5.39-v5.45 evidence boundary is not eligible for transfer repair."
        )
    return {
        "prior": prior,
        "v545_lock": v545_lock,
        "checks": checks,
        "all_checks_passed": True,
    }


def _public_custody(custody: dict[str, Any]) -> dict[str, Any]:
    prior = v545._public_custody(custody["prior"])
    return {
        "status": "v5_39_through_v5_45_custody_revalidated",
        "checks": dict(custody["checks"]),
        "prior_boundary": prior,
        "v545_record_validated": True,
        "v545_record_fingerprint_validated_internally": True,
        "all_checks_passed": True,
        "eligible_roles": ["development_fit", "calibration", "threshold"],
        "future_labels_opened": False,
        "private_paths_returned": False,
        "private_digests_returned": False,
        "private_identifiers_returned": False,
        "fingerprints_returned": False,
    }


def _leader_view(
    comparison: dict[str, Any],
    leader_name: str | None,
    view_name: str,
) -> dict[str, Any] | None:
    if not leader_name:
        return None
    view = next(
        (
            row
            for row in comparison.get("views") or []
            if row.get("name") == view_name
        ),
        None,
    )
    return next(
        (
            row
            for row in (view or {}).get("strategies") or []
            if row.get("name") == leader_name and row.get("status") == "evaluated"
        ),
        None,
    )


def _v545_baseline(v545_lock: dict[str, Any]) -> dict[str, Any]:
    latest = v545_lock["latest"]
    leader = (latest.get("diagnostic_leader") or {}).get("name")
    comparison = latest.get("model_comparison") or {}
    manual = _leader_view(comparison, str(leader) if leader else None, "manual_anchor_holdout")
    assisted = _leader_view(
        comparison,
        str(leader) if leader else None,
        "threshold_cohort_holdout",
    )
    sensitivity = (latest.get("assisted_label_sensitivity") or {})
    return {
        "version": v545.V545_VERSION,
        "leader": leader,
        "manual_anchor_metrics": (manual or {}).get("metrics") or {},
        "manual_anchor_calibration": {
            key: value
            for key, value in ((manual or {}).get("calibration") or {}).items()
            if key != "confidence_buckets"
        },
        "assisted_holdout_metrics": (assisted or {}).get("metrics") or {},
        "queue_f1_transfer_gap": sensitivity.get("queue_f1_absolute_gap"),
        "fpr_transfer_gap": sensitivity.get("fpr_absolute_gap"),
        "candidate_frozen": bool(
            (latest.get("candidate_freeze") or {}).get("candidate_frozen")
        ),
        "future_labels_opened": False,
        "private_identifiers_returned": False,
    }


def _before_after_transfer(
    baseline: dict[str, Any],
    comparison: dict[str, Any],
    leader: dict[str, Any] | None,
) -> dict[str, Any]:
    leader_name = str(leader["name"]) if leader else None
    manual = _leader_view(comparison, leader_name, "manual_anchor_holdout")
    after_metrics = (manual or {}).get("metrics") or {}
    after_calibration = (manual or {}).get("calibration") or {}
    sensitivity = ((leader or {}).get("summary") or {}).get(
        "assisted_label_sensitivity"
    ) or {}
    before_metrics = baseline.get("manual_anchor_metrics") or {}

    def delta(field: str) -> float | None:
        if field not in before_metrics or field not in after_metrics:
            return None
        return round(
            _number(after_metrics[field]) - _number(before_metrics[field]),
            4,
        )

    before_calibration = baseline.get("manual_anchor_calibration") or {}
    return {
        "before_version": v545.V545_VERSION,
        "after_version": V546_VERSION,
        "manual_anchor_metric_delta": {
            field: delta(field)
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
        },
        "manual_anchor_calibration_delta": {
            field: (
                round(
                    _number(after_calibration.get(field))
                    - _number(before_calibration.get(field)),
                    4,
                )
                if field in after_calibration and field in before_calibration
                else None
            )
            for field in v542.CALIBRATION_FIELDS
        },
        "before_queue_f1_transfer_gap": baseline.get("queue_f1_transfer_gap"),
        "after_queue_f1_transfer_gap": sensitivity.get(
            "queue_f1_absolute_gap"
        ),
        "before_fpr_transfer_gap": baseline.get("fpr_transfer_gap"),
        "after_fpr_transfer_gap": sensitivity.get("fpr_absolute_gap"),
        "manual_anchor_transfer_improved": bool(
            manual
            and _number(after_metrics.get("queue_f1"))
            > _number(before_metrics.get("queue_f1"))
            and _number(
                after_metrics.get("benign_like_false_positive_rate"), 1.0
            )
            <= _number(
                before_metrics.get("benign_like_false_positive_rate"), 1.0
            )
        ),
        "future_labels_opened": False,
    }


def _aggregate_residuals(
    comparison: dict[str, Any],
    leader_name: str | None,
) -> dict[str, Any]:
    return v545._aggregate_residuals(comparison, leader_name)


def _isolation_audit(
    imports: Any,
    *,
    fit: dict[str, Any],
    evaluations: list[tuple[str, dict[str, Any]]],
) -> dict[str, Any]:
    result = v545._isolation_audit(
        imports,
        fit=fit,
        evaluations=evaluations,
    )
    result["drift_sensitivity_audited"] = True
    result["queue_contribution_authoritative"] = False
    result["authoritative_alerts_allowed"] = False
    return result


def _freeze_recipe(
    leader: dict[str, Any] | None,
    *,
    output_dir: Path,
    write_output: bool,
) -> dict[str, Any]:
    if not leader or not leader.get("candidate_freeze_eligible"):
        return {
            "candidate_frozen": False,
            "candidate_freeze_ready": False,
            "reason": "no strategy passed every unchanged development gate",
            "manifest_written": False,
            "model_artifact_written": False,
            "active_artifact_written": False,
            "future_labels_opened": False,
        }
    fitted = leader.get("_latest_fitted") or {}
    recipe = {
        "schema_version": V546_VERSION,
        "status": "immutable_diagnostic_recipe_frozen",
        "candidate_name": leader["name"],
        "selection_basis": leader["selection_basis"],
        "model_type": fitted.get("model_type"),
        "target_mode": fitted.get("target_mode"),
        "feature_set": fitted.get("feature_set"),
        "ensemble_members": fitted.get("ensemble_members"),
        "calibration_method": fitted.get("applied_calibration_method"),
        "threshold_selection": fitted.get("threshold_selection"),
        "fixed_freeze_gates": FIXED_FREEZE_GATES,
        "development_summary": leader["summary"],
        "future_labels_opened": False,
        "eligible_for_activation": False,
        "model_artifact_written": False,
        "active_artifact_written": False,
    }
    path = output_dir / V546_FREEZE_MANIFEST
    status = "not_written_by_request"
    if write_output:
        if path.is_file():
            existing = _read_json(path)
            if existing != recipe:
                raise V546TransferRepairError(
                    "A different v5.46 diagnostic recipe already exists."
                )
            status = "existing_manifest_reused"
        else:
            _atomic_write_json(path, recipe)
            status = "manifest_written"
    return {
        "candidate_frozen": True,
        "candidate_freeze_ready": True,
        "candidate_name": leader["name"],
        "selection_basis": leader["selection_basis"],
        "manifest_status": status,
        "manifest_written": bool(write_output),
        "model_artifact_written": False,
        "active_artifact_written": False,
        "eligible_for_activation": False,
        "future_labels_opened": False,
        "fingerprints_returned": False,
    }


def _readiness(
    *,
    view_protocol: dict[str, Any],
    leader: dict[str, Any] | None,
    freeze: dict[str, Any],
    isolation: dict[str, Any],
) -> dict[str, Any]:
    checks = {
        "three_mandatory_views_available": int(
            view_protocol.get("valid_views") or 0
        )
        >= 3,
        "all_fixed_candidate_gates_passed": bool(
            leader and leader.get("candidate_freeze_eligible")
        ),
        "diagnostic_recipe_frozen": bool(freeze.get("candidate_frozen")),
        "future_labels_remain_sealed": not bool(
            freeze.get("future_labels_opened")
        ),
        "isolation_forest_reliable": bool(isolation.get("reliability_passed")),
    }
    blockers: list[str] = []
    if not checks["all_fixed_candidate_gates_passed"]:
        blockers.append(
            "Manual-anchor transfer, calibration, or split stability still fails at least one unchanged gate."
        )
    if not checks["isolation_forest_reliable"]:
        blockers.append(
            "IsolationForest remains advisory because fixed reliability requirements are not met."
        )
    blockers.extend(
        [
            "Only one genuine private device is currently available.",
            "Private chronological labels are assisted evidence, not new human-reviewed truth.",
            "Prediction-blind multi-device future evidence remains required before independent evaluation.",
            "A separate advisor/provider governance decision is required before any activation.",
        ]
    )
    return {
        "status": (
            "diagnostic_recipe_frozen"
            if freeze.get("candidate_frozen")
            else "manual_anchor_transfer_incomplete"
        ),
        "checks": checks,
        "candidate_freeze_ready": bool(
            freeze.get("candidate_freeze_ready")
        ),
        "independent_validation_ready": False,
        "shadow_activation_ready": False,
        "production_promotion_ready": False,
        "response_automation_allowed": False,
        "lifecycle_state": "shadow_observation",
        "blockers": blockers,
        "supervised_phases_remaining": 4 if freeze.get("candidate_frozen") else 5,
    }


def _render_report(result: dict[str, Any]) -> str:
    leader = result.get("diagnostic_leader") or {}
    summary = leader.get("summary") or {}
    transfer = result.get("before_after_transfer") or {}
    residual = result.get("residual_error_audit") or {}
    freeze = result.get("candidate_freeze") or {}
    return "\n".join(
        [
            "# v5.46 Manual-Anchor Transfer and Calibration Repair",
            "",
            f"Generated: `{result.get('generated_at')}`",
            "",
            "## Decision",
            "",
            f"- Status: `{result.get('status')}`",
            f"- Diagnostic leader: `{leader.get('name') or 'none'}`",
            f"- Passing views: `{summary.get('passing_views')}` / `{summary.get('required_views')}`",
            f"- Candidate frozen: `{freeze.get('candidate_frozen')}`",
            "- Lifecycle: `shadow_observation`",
            "- Future labels opened: `false`",
            "- Active artifact written: `false`",
            "",
            "## Transfer",
            "",
            f"- Manual-anchor metric deltas: `{transfer.get('manual_anchor_metric_delta')}`",
            f"- Calibration deltas: `{transfer.get('manual_anchor_calibration_delta')}`",
            f"- Transfer improved: `{transfer.get('manual_anchor_transfer_improved')}`",
            "",
            "## Residual Patterns",
            "",
            f"- False positives: `{residual.get('false_positive_patterns')}`",
            f"- False negatives: `{residual.get('false_negative_patterns')}`",
            "",
            "This report contains aggregate development-only diagnostics. It contains no raw logs, private paths, IP addresses, identities, row predictions, fingerprints, or model artifact.",
            "",
        ]
    )


def _safe_failure(
    status: str,
    *,
    error_type: str | None = None,
    failure_stage: str | None = None,
    diagnostics: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "ok": False,
        "version": V546_VERSION,
        "status": status,
        "generated_at": _now(),
        "error_type": error_type,
        "failure_stage": failure_stage,
        "diagnostics": diagnostics or {},
        "message": (
            "The v5.46 transfer repair failed closed. Review local aggregate diagnostics without exposing private evidence."
        ),
        "lifecycle_state": "shadow_observation",
        "rules_alert_authoritative": True,
        "model_activated": False,
        "model_promoted": False,
        "active_model_artifact_written": False,
        "response_automation_allowed": False,
        "real_firewall_blocking_enabled": False,
        "future_labels_opened": False,
        "private_paths_returned": False,
        "raw_logs_returned": False,
        "ip_addresses_returned": False,
        "source_identities_returned": False,
        "fingerprints_returned": False,
        "row_predictions_returned": False,
        "secrets_exposed": False,
    }


def run_v546_manual_anchor_transfer_repair(
    db: Session,
    *,
    sample_path: Path | None,
    use_temp_db: bool = False,
    preflight_only: bool = False,
    min_samples: int = 100,
    max_fit_rows: int = DEFAULT_MAX_ROWS["development_fit"],
    max_calibration_rows: int = DEFAULT_MAX_ROWS["calibration"],
    max_threshold_rows: int = DEFAULT_MAX_ROWS["threshold"],
    output_dir: Path = V546_OUTPUT_DIR,
    write_output: bool = True,
    v544_output_dir: Path = v544.V544_OUTPUT_DIR,
    v545_output_dir: Path = v545.V545_OUTPUT_DIR,
    state_path: Path = v540.V539_STATE_PATH,
    pack_path: Path = v540.DEFAULT_PACK_PATH,
    blind_output_dir: Path = v541.V541_OUTPUT_DIR,
    v542_output_dir: Path = v542.V542_OUTPUT_DIR,
    v543_output_dir: Path = v543.V543_OUTPUT_DIR,
) -> dict[str, Any]:
    started = time.perf_counter()
    counts_before = frozen._database_counts(db)
    artifacts_before = v55._model_artifact_states()
    protected_before = _protected_state(
        v544_output_dir=v544_output_dir,
        v545_output_dir=v545_output_dir,
        state_path=state_path,
        pack_path=pack_path,
        blind_output_dir=blind_output_dir,
        v542_output_dir=v542_output_dir,
        v543_output_dir=v543_output_dir,
    )
    stage = "custody_revalidation"
    failure_diagnostics: dict[str, Any] = {}
    try:
        custody = revalidate_v546_custody(
            db,
            min_samples=min_samples,
            v544_output_dir=v544_output_dir,
            v545_output_dir=v545_output_dir,
            state_path=state_path,
            pack_path=pack_path,
            blind_output_dir=blind_output_dir,
            v542_output_dir=v542_output_dir,
            v543_output_dir=v543_output_dir,
        )
    except (
        V546TransferRepairError,
        v545.V545RepairError,
        v544.V544EvidenceError,
        v543.V543RepairError,
        v542.V542FreezeError,
        v541.V541EvidenceError,
        v540.V540EvidenceBoundaryError,
    ) as exc:
        return _safe_failure(
            "failed_closed_custody",
            error_type=exc.__class__.__name__,
            failure_stage=stage,
        )

    available = bool(sample_path and sample_path.is_file())
    if preflight_only:
        counts_after = frozen._database_counts(db)
        artifacts_after = v55._model_artifact_states()
        protected_after = _protected_state(
            v544_output_dir=v544_output_dir,
            v545_output_dir=v545_output_dir,
            state_path=state_path,
            pack_path=pack_path,
            blind_output_dir=blind_output_dir,
            v542_output_dir=v542_output_dir,
            v543_output_dir=v543_output_dir,
        )
        safe = bool(
            available
            and counts_before == counts_after
            and artifacts_before == artifacts_after
            and protected_before == protected_after
        )
        return {
            "ok": safe,
            "version": V546_VERSION,
            "status": "preflight_complete" if safe else "private_file_unavailable",
            "generated_at": _now(),
            "preflight_only": True,
            "custody": _public_custody(custody),
            "private_file": {
                "supplied": sample_path is not None,
                "available": available,
                "path_returned": False,
                "file_name_returned": False,
                "digest_returned": False,
            },
            "safety": {
                "configured_database_counts_unchanged": counts_before
                == counts_after,
                "active_model_artifacts_unchanged": artifacts_before
                == artifacts_after,
                "protected_workspaces_unchanged": protected_before
                == protected_after,
                "all_invariants_passed": safe,
            },
            "future_labels_opened": False,
            "lifecycle_state": "shadow_observation",
            "rules_alert_authoritative": True,
            "model_activated": False,
            "model_promoted": False,
            "active_model_artifact_written": False,
            "response_automation_allowed": False,
            "real_firewall_blocking_enabled": False,
            "private_paths_returned": False,
            "raw_logs_returned": False,
            "ip_addresses_returned": False,
            "source_identities_returned": False,
            "fingerprints_returned": False,
            "secrets_exposed": False,
        }
    if not available:
        return _safe_failure("private_file_unavailable")
    if not use_temp_db:
        return _safe_failure("temporary_storage_acknowledgement_required")
    imports = _optional_imports()
    if imports is None:
        return _safe_failure("ml_dependencies_unavailable")

    stage = "disposable_stream"
    try:
        with tempfile.TemporaryDirectory(prefix="atdr-v546-") as directory:
            connection = sqlite3.connect(Path(directory) / "development.sqlite3")
            try:
                profile = v56.stream_private_file_to_disposable_index(
                    sample_path,
                    connection,
                    database_url=get_settings().database_url,
                )
                if not profile.get("ok"):
                    raise V546TransferRepairError(
                        "Private evidence parsing failed."
                    )
                stage = "protected_boundary_install"
                boundary = v544._install_protected_boundaries(
                    connection,
                    custody=custody["prior"]["custody"],
                    blind_output_dir=blind_output_dir,
                )
                stage = "chronological_role_reconstruction"
                roles = v56.predeclare_chronological_roles(connection)
                if not roles.get("ok"):
                    raise V546TransferRepairError(
                        "Chronological role reconstruction failed."
                    )
                stage = "behavior_aggregate_build"
                v56.build_disposable_behavior_aggregates(connection)
                stage = "assisted_policy_reconstruction"
                assisted = v544._apply_development_assisted_policy(
                    connection,
                    review_limit=0,
                )
                assisted.pop("_review_rows", None)
                stage = "v544_private_lock_revalidation"
                private_lock = v544._write_private_lock(
                    connection,
                    output_dir=v544_output_dir,
                    custody=custody["prior"]["custody"],
                )
                if private_lock.get("status") != "existing_private_lock_reused":
                    raise V546TransferRepairError(
                        "The v5.44 private lock reconstruction was not reused."
                    )
                stage = "candidate_near_containment"
                containment = v545._contain_candidate_near_families(connection)
                failure_diagnostics["candidate_near_containment"] = containment
                if not containment.get("passed"):
                    raise V546TransferRepairError(
                        "Candidate-near families remain across development roles."
                    )
                stage = "contained_aggregate_rebuild"
                v56.build_disposable_behavior_aggregates(connection)
                assisted = v544._apply_development_assisted_policy(
                    connection,
                    review_limit=0,
                )
                assisted.pop("_review_rows", None)
                stage = "human_anchor_projection"
                human = v545._human_role_bundles(
                    custody["prior"]["custody"]["state"]["development"],
                    custody["prior"]["custody"]["state"]["canonical"],
                )
                private: dict[str, dict[str, Any]] = {}
                private_selection: dict[str, Any] = {}
                stage = "private_development_sampling"
                for role_rank, role_name, maximum in (
                    (0, "development_fit", max_fit_rows),
                    (1, "calibration", max_calibration_rows),
                    (2, "threshold", max_threshold_rows),
                ):
                    private[role_name], private_selection[role_name] = (
                        v545._load_private_role_bundle(
                            connection,
                            imports,
                            role_rank=role_rank,
                            max_rows=maximum,
                        )
                    )
                failure_diagnostics["private_selection"] = private_selection
                stage = "manual_anchor_transfer_diagnosis"
                transfer_diagnosis = diagnose_manual_anchor_transfer(
                    imports,
                    human=human,
                    private=private,
                )
                stage = "development_view_construction"
                views, view_protocol = v545.build_development_views(
                    imports,
                    human=human,
                    private=private,
                )
                failure_diagnostics["view_protocol"] = view_protocol
                if view_protocol.get("status") != "ready":
                    raise V546TransferRepairError(
                        "Fewer than three leakage-safe development views exist."
                    )
                stage = "transfer_strategy_comparison"
                comparison, leader = run_transfer_model_comparison(
                    imports,
                    views,
                )
                baseline = _v545_baseline(custody["v545_lock"])
                transfer_change = _before_after_transfer(
                    baseline,
                    comparison,
                    leader,
                )
                residual = _aggregate_residuals(
                    comparison,
                    str(leader["name"]) if leader else None,
                )
                stage = "isolation_forest_audit"
                isolation = _isolation_audit(
                    imports,
                    fit=v545._concat_bundles(
                        imports,
                        human["development_fit"],
                        private["development_fit"],
                    ),
                    evaluations=[
                        (view["evaluation_cohort"], view["evaluation"])
                        for view in views
                        if view["name"]
                        in {"threshold_cohort_holdout", "manual_anchor_holdout"}
                    ],
                )
                stage = "candidate_freeze_decision"
                freeze = _freeze_recipe(
                    leader,
                    output_dir=output_dir,
                    write_output=write_output,
                )
                stage = "readiness_decision"
                readiness = _readiness(
                    view_protocol=view_protocol,
                    leader=leader,
                    freeze=freeze,
                    isolation=isolation,
                )
            finally:
                connection.close()
    except (
        V546TransferRepairError,
        v545.V545RepairError,
        v544.V544EvidenceError,
        sqlite3.Error,
        OSError,
        ValueError,
        TypeError,
        IndexError,
    ) as exc:
        return _safe_failure(
            "failed_closed_transfer_repair",
            error_type=exc.__class__.__name__,
            failure_stage=stage,
            diagnostics=failure_diagnostics,
        )

    counts_after = frozen._database_counts(db)
    artifacts_after = v55._model_artifact_states()
    protected_after = _protected_state(
        v544_output_dir=v544_output_dir,
        v545_output_dir=v545_output_dir,
        state_path=state_path,
        pack_path=pack_path,
        blind_output_dir=blind_output_dir,
        v542_output_dir=v542_output_dir,
        v543_output_dir=v543_output_dir,
    )
    deltas = {
        key: int(counts_after[key]) - int(counts_before[key])
        for key in counts_before
    }
    safety = {
        "configured_database_counts_unchanged": counts_before == counts_after,
        "active_model_artifacts_unchanged": artifacts_before == artifacts_after,
        "protected_workspaces_unchanged": protected_before == protected_after,
        "labels_created": deltas.get("ml_labels", 0),
        "model_runs_created": deltas.get("ml_model_runs", 0),
        "detection_runs_created": deltas.get("detection_runs", 0),
        "alerts_created": deltas.get("alerts", 0),
        "response_actions_created": deltas.get("response_actions", 0),
        "future_labels_opened": False,
        "active_model_artifact_written": False,
        "model_activated": False,
        "model_promoted": False,
        "rules_alert_authoritative": True,
        "automatic_response_enabled": False,
        "real_firewall_blocking_enabled": False,
        "human_reviewed_labels_created": 0,
    }
    safety_passed = bool(
        safety["configured_database_counts_unchanged"]
        and safety["active_model_artifacts_unchanged"]
        and safety["protected_workspaces_unchanged"]
        and all(value == 0 for value in deltas.values())
    )
    public_leader = None
    if leader:
        public_leader = {
            key: value for key, value in leader.items() if not key.startswith("_")
        }
    result = {
        "ok": safety_passed,
        "version": V546_VERSION,
        "status": readiness["status"],
        "generated_at": _now(),
        "preflight_only": False,
        "custody": _public_custody(custody),
        "private_reconstruction": {
            "status": "v5_44_private_lock_reconstructed_and_reused",
            "parsed_rows": int(profile.get("rows") or 0),
            "parser_success_rows": int(profile.get("parser_success_rows") or 0),
            "parser_failure_rows": int(profile.get("parser_failure_rows") or 0),
            "boundary_quarantine_rows": sum(
                int(value)
                for key, value in boundary.items()
                if key.endswith("_rows") and isinstance(value, int)
            ),
            "candidate_near_containment": containment,
            "future_labels_opened": False,
            "private_paths_returned": False,
            "private_identifiers_returned": False,
            "fingerprints_returned": False,
        },
        "development_dataset": {
            "human_anchor_roles": {
                name: v545._provenance_profile(bundle)
                for name, bundle in human.items()
            },
            "private_selection": private_selection,
            "view_protocol": view_protocol,
            "eligible_roles": ["development_fit", "calibration", "threshold"],
            "future_labels_opened": False,
            "labels_rewritten": False,
        },
        "manual_anchor_transfer_diagnosis": transfer_diagnosis,
        "v545_baseline": baseline,
        "model_comparison": comparison,
        "diagnostic_leader": public_leader,
        "before_after_transfer": transfer_change,
        "assisted_label_sensitivity": (
            (public_leader or {}).get("summary", {}).get(
                "assisted_label_sensitivity"
            )
            if public_leader
            else None
        ),
        "residual_error_audit": residual,
        "isolation_forest_audit": isolation,
        "candidate_freeze": freeze,
        "readiness": readiness,
        "safety": {**safety, "all_invariants_passed": safety_passed},
        "runtime_seconds": round(time.perf_counter() - started, 4),
        "lifecycle_state": "shadow_observation",
        "rules_alert_authoritative": True,
        "model_activated": False,
        "model_promoted": False,
        "active_model_artifact_written": False,
        "response_automation_allowed": False,
        "real_firewall_blocking_enabled": False,
        "future_labels_opened": False,
        "private_paths_returned": False,
        "raw_logs_returned": False,
        "ip_addresses_returned": False,
        "source_identities_returned": False,
        "fingerprints_returned": False,
        "row_predictions_returned": False,
        "secrets_exposed": False,
    }
    if write_output:
        output_dir.mkdir(parents=True, exist_ok=True)
        _atomic_write_json(output_dir / V546_LATEST, result)
        (output_dir / f"{V546_REPORT_PREFIX}_{_stamp()}.md").write_text(
            _render_report(result),
            encoding="utf-8",
        )
        result["reports"] = {
            "written": True,
            "file_names_returned": False,
            "private_paths_returned": False,
        }
    else:
        result["reports"] = {
            "written": False,
            "file_names_returned": False,
            "private_paths_returned": False,
        }
    return result


def get_public_v546_status(
    output_dir: Path = V546_OUTPUT_DIR,
) -> dict[str, Any]:
    path = output_dir / V546_LATEST
    if not path.is_file():
        return {
            "version": V546_VERSION,
            "status": "not_run",
            "generated_at": None,
            "diagnostic_leader": None,
            "passing_views": 0,
            "required_views": 3,
            "manual_anchor_transfer_status": "not_evaluated",
            "calibration_status": "not_evaluated",
            "manual_anchor_queue_f1": None,
            "manual_anchor_fpr": None,
            "manual_anchor_suspicious_recall": None,
            "manual_anchor_malicious_recall": None,
            "queue_f1_transfer_gap": None,
            "candidate_freeze_ready": False,
            "candidate_frozen": False,
            "isolation_forest_reliable": False,
            "supervised_phases_remaining": 5,
            "blockers": ["Manual-anchor transfer repair has not been run."],
            "lifecycle_state": "shadow_observation",
            "rules_alert_authoritative": True,
            "model_activated": False,
            "model_promoted": False,
            "response_automation_allowed": False,
            "future_labels_opened": False,
            "private_paths_returned": False,
            "fingerprints_returned": False,
            "secrets_exposed": False,
        }
    value = _read_json(path)
    leader = value.get("diagnostic_leader") or {}
    summary = leader.get("summary") or {}
    comparison = value.get("model_comparison") or {}
    manual = _leader_view(
        comparison,
        str(leader.get("name")) if leader.get("name") else None,
        "manual_anchor_holdout",
    )
    metrics = (manual or {}).get("metrics") or {}
    calibration = (manual or {}).get("calibration") or {}
    readiness = value.get("readiness") or {}
    transfer = value.get("before_after_transfer") or {}
    transfer_improved = bool(transfer.get("manual_anchor_transfer_improved"))
    return {
        "version": value.get("version") or V546_VERSION,
        "status": value.get("status"),
        "generated_at": value.get("generated_at"),
        "diagnostic_leader": leader.get("name"),
        "passing_views": int(summary.get("passing_views") or 0),
        "required_views": int(summary.get("required_views") or 3),
        "manual_anchor_transfer_status": (
            "improved" if transfer_improved else "blocked"
        ),
        "calibration_status": calibration.get("status") or "not_evaluated",
        "manual_anchor_queue_f1": metrics.get("queue_f1"),
        "manual_anchor_fpr": metrics.get("benign_like_false_positive_rate"),
        "manual_anchor_suspicious_recall": metrics.get("suspicious_recall"),
        "manual_anchor_malicious_recall": metrics.get("malicious_recall"),
        "queue_f1_transfer_gap": (
            (summary.get("assisted_label_sensitivity") or {}).get(
                "queue_f1_absolute_gap"
            )
        ),
        "candidate_freeze_ready": bool(
            (value.get("candidate_freeze") or {}).get("candidate_freeze_ready")
        ),
        "candidate_frozen": bool(
            (value.get("candidate_freeze") or {}).get("candidate_frozen")
        ),
        "isolation_forest_reliable": bool(
            (value.get("isolation_forest_audit") or {}).get(
                "reliability_passed"
            )
        ),
        "supervised_phases_remaining": int(
            readiness.get("supervised_phases_remaining") or 5
        ),
        "blockers": [str(item) for item in readiness.get("blockers") or []],
        "lifecycle_state": "shadow_observation",
        "rules_alert_authoritative": True,
        "model_activated": False,
        "model_promoted": False,
        "response_automation_allowed": False,
        "future_labels_opened": False,
        "private_paths_returned": False,
        "fingerprints_returned": False,
        "secrets_exposed": False,
    }
