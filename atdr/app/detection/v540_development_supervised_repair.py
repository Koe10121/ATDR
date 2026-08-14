from __future__ import annotations

import csv
import hashlib
import json
import time
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path
from statistics import mean
from typing import Any

from sqlalchemy.orm import Session

from atdr.app.detection import v398_independent_holdout_validation as frozen
from atdr.app.detection import v49_detection_ml_reliability as reliability
from atdr.app.detection import v52_shadow_reliability as v52
from atdr.app.detection import v55_development_model_repair as v55
from atdr.app.detection import v56_private_panos_model_repair as v56
from atdr.app.detection.v330_detection_ml_quality import OUTPUT_DIR
from atdr.app.detection.v331_noise_reduction import _build_pipeline_for_columns
from atdr.app.detection.v528_blind_review_helper import DEFAULT_PACK_PATH
from atdr.app.services import evidence_review_service as review_service
from atdr.app.services.v539_independent_evidence_decision_service import (
    DEFAULT_STATE_PATH as V539_STATE_PATH,
    EXPECTED_DETECTION_ROWS,
    V539_VERSION,
)


V540_VERSION = "v5.40-development-supervised-repair-v1"
V540_LATEST = "v5_40_development_supervised_repair_latest.json"
V540_REPORT_PREFIX = "v5_40_development_supervised_repair"

DEVELOPMENT_GATES = {
    "queue_f1_min": 0.85,
    "benign_like_false_positive_rate_max": 0.10,
    "suspicious_recall_min": 0.80,
    "malicious_recall_min": 0.80,
    "expected_calibration_error_max": 0.10,
    "max_confidence_accuracy_gap_max": 0.15,
}

FIXED_THRESHOLD_PROFILES = (
    {"name": "balanced", "threshold": 0.50},
    {"name": "precision_focused", "threshold": 0.70},
    {"name": "low_noise_soc_queue", "threshold": 0.85},
    {"name": "high_precision", "threshold": 0.92},
)

STRATEGY_SPECS = (
    {
        "name": "calibrated_extra_trees",
        "model_type": "extra_trees",
        "target_mode": "binary_soc_queue",
        "calibration_method": "sigmoid",
        "class_weight": "balanced",
    },
    {
        "name": "calibrated_hist_gradient_boosting",
        "model_type": "hist_gradient_boosting",
        "target_mode": "binary_soc_queue",
        "calibration_method": "sigmoid",
        "class_weight": None,
    },
    {
        "name": "calibrated_logistic_regression",
        "model_type": "logistic_regression",
        "target_mode": "binary_soc_queue",
        "calibration_method": "sigmoid",
        "class_weight": "balanced",
    },
    {
        "name": "binary_threat_queue",
        "model_type": "extra_trees",
        "target_mode": "binary_soc_queue",
        "calibration_method": "isotonic",
        "class_weight": "balanced",
    },
    {
        "name": "three_class_soc_queue",
        "model_type": "extra_trees",
        "target_mode": "three_class_soc_queue",
        "calibration_method": "isotonic",
        "class_weight": "balanced",
    },
    {
        "name": "hierarchical_two_stage",
        "model_type": "extra_trees",
        "target_mode": "hierarchical_two_stage",
        "calibration_method": "sigmoid",
        "class_weight": "balanced",
    },
)

V540_NUMERIC_FEATURES = (
    "v540_quic_443_allow_flag",
    "v540_routine_encrypted_allow_flag",
    "v540_incomplete_80_allow_flag",
    "v540_unknown_udp_flag",
    "v540_unknown_tcp_flag",
    "v540_scan_diversity_pressure",
    "v540_scan_context_flag",
    "v540_local_rule_strength",
    "v540_anomaly_or_behavior_signal",
    "v540_application_risk_signal",
    "v540_missingness_pressure",
    "v540_low_signal_routine_flag",
)
V540_CATEGORICAL_FEATURE = "v540_evidence_family"


class V540EvidenceBoundaryError(RuntimeError):
    pass


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


def _lower(value: Any) -> str:
    return str(value or "").strip().lower()


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


def _private_file_state(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {"exists": False, "size_bytes": None, "sha256": None}
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return {
        "exists": True,
        "size_bytes": int(path.stat().st_size),
        "sha256": digest.hexdigest(),
    }


def _public_boundary(boundary: dict[str, Any]) -> dict[str, Any]:
    return {
        "status": boundary.get("status"),
        "schema_version": boundary.get("schema_version"),
        "evaluation_status": boundary.get("evaluation_status"),
        "evaluation_attempt_count": boundary.get("evaluation_attempt_count"),
        "protected_detection_rows": boundary.get("protected_detection_rows"),
        "protected_token_count": boundary.get("protected_token_count"),
        "pack_integrity_matched": bool(boundary.get("pack_integrity_matched")),
        "both_reviews_closed": bool(boundary.get("both_reviews_closed")),
        "owner_contracts_valid": bool(boundary.get("owner_contracts_valid")),
        "used_for_exclusion_only": True,
        "labels_read": False,
        "predictions_read": False,
        "errors_read": False,
        "tokens_returned": False,
        "digests_returned": False,
        "private_paths_returned": False,
    }


def load_v539_consumed_boundary(
    *,
    state_path: Path = V539_STATE_PATH,
    pack_path: Path = DEFAULT_PACK_PATH,
) -> dict[str, Any]:
    if not state_path.is_file() or not pack_path.is_file():
        raise V540EvidenceBoundaryError(
            "The consumed v5.39 state or sealed detection pack is unavailable."
        )
    try:
        state = json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise V540EvidenceBoundaryError(
            "The consumed v5.39 state failed integrity validation."
        ) from exc

    evaluation = state.get("evaluation") or {}
    review_contract = state.get("review_contract") or {}
    private_contract = state.get("private_contract") or {}
    contract_valid = bool(
        state.get("schema_version") == V539_VERSION
        and evaluation.get("status") == "completed"
        and int(evaluation.get("attempt_count") or 0) == 1
        and bool(review_contract.get("both_reviews_closed"))
        and bool(review_contract.get("owner_contracts_valid"))
        and int(review_contract.get("detection_rows") or 0)
        == EXPECTED_DETECTION_ROWS
    )
    if not contract_valid:
        raise V540EvidenceBoundaryError(
            "The consumed v5.39 evidence contract is incomplete or invalid."
        )

    current_pack_digest = review_service._detection_pack_digest(pack_path)
    expected_pack_digest = str(private_contract.get("detection_pack_digest") or "")
    if not expected_pack_digest or current_pack_digest != expected_pack_digest:
        raise V540EvidenceBoundaryError(
            "The consumed v5.39 detection pack no longer matches its frozen state."
        )

    tokens: list[str] = []
    try:
        with pack_path.open("r", encoding="utf-8", newline="") as stream:
            reader = csv.DictReader(stream)
            if "review_token" not in set(reader.fieldnames or []):
                raise V540EvidenceBoundaryError(
                    "The consumed v5.39 detection pack has no review-token boundary."
                )
            for row in reader:
                token = str(row.get("review_token") or "").strip()
                if token:
                    tokens.append(token)
    except OSError as exc:
        raise V540EvidenceBoundaryError(
            "The consumed v5.39 detection boundary could not be read."
        ) from exc

    if len(tokens) != EXPECTED_DETECTION_ROWS or len(set(tokens)) != len(tokens):
        raise V540EvidenceBoundaryError(
            "The consumed v5.39 detection boundary has an invalid row count."
        )
    return {
        "status": "consumed_boundary_locked",
        "schema_version": state.get("schema_version"),
        "evaluation_status": evaluation.get("status"),
        "evaluation_attempt_count": int(evaluation.get("attempt_count") or 0),
        "protected_detection_rows": int(
            review_contract.get("detection_rows") or 0
        ),
        "protected_token_count": len(tokens),
        "pack_integrity_matched": True,
        "both_reviews_closed": True,
        "owner_contracts_valid": True,
        "_protected_tokens": frozenset(tokens),
    }


def _v539_review_token_for_log(log: Any) -> str:
    timestamp = frozen._timestamp(log)
    minute = v56._minute_bucket(timestamp)
    normalized = {
        name: getattr(log, name, None)
        for name in (
            "log_type",
            "subtype",
            "app",
            "action",
            "protocol",
            "src_port",
            "dst_port",
            "src_zone",
            "dst_zone",
            "app_risk",
            "bytes",
            "packets",
        )
    }
    near = v56._near_fingerprint(normalized, minute=minute)
    propagation = v56._stable_hash(
        {
            "source": v56._safe_token("source", getattr(log, "src_ip", None)),
            "pattern": near,
        }
    )
    return hashlib.sha256(
        f"v5.21-review:{propagation}".encode("ascii")
    ).hexdigest()[:24]


def _slice_dataset(dataset: dict[str, Any], indices: list[int]) -> dict[str, Any]:
    ordered = sorted(set(int(index) for index in indices))
    rows: list[dict[str, Any]] = []
    for new_index, old_index in enumerate(ordered):
        row = dict(dataset["rows"][old_index])
        row["source_dataset_index"] = old_index
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
        "feature_meta": dict(dataset["feature_meta"]),
        "label_provenance": dict(dataset.get("label_provenance") or {}),
        "source_dataset_indices": ordered,
    }


def exclude_v539_consumed_evidence(
    dataset: dict[str, Any],
    boundary: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    if boundary.get("status") != "consumed_boundary_locked":
        raise V540EvidenceBoundaryError("v5.39 exclusion boundary is not locked.")
    protected_tokens = boundary.get("_protected_tokens")
    if not isinstance(protected_tokens, frozenset) or not protected_tokens:
        raise V540EvidenceBoundaryError("v5.39 exclusion tokens are unavailable.")

    matched: list[int] = []
    eligible: list[int] = []
    for index, log in enumerate(dataset["logs"]):
        if _v539_review_token_for_log(log) in protected_tokens:
            matched.append(index)
        else:
            eligible.append(index)
    filtered = _slice_dataset(dataset, eligible)
    frozen.assign_leakage_groups(filtered["rows"])
    return filtered, {
        "configured_reviewed_rows": len(dataset["rows"]),
        "protected_token_count": len(protected_tokens),
        "matched_and_excluded_rows": len(matched),
        "eligible_after_v539_exclusion": len(eligible),
        "protected_rows_used_for_fit": 0,
        "protected_rows_used_for_calibration": 0,
        "protected_rows_used_for_threshold_selection": 0,
        "protected_rows_used_for_model_selection": 0,
        "protected_labels_read": False,
        "protected_predictions_read": False,
        "protected_errors_read": False,
        "protected_identities_returned": False,
    }


def _v540_family(values: dict[str, Any]) -> str:
    if values["v540_scan_context_flag"]:
        return "scan_like_behavior"
    if values["v540_local_rule_strength"] >= 30:
        return "rule_backed_behavior"
    if values["v540_routine_encrypted_allow_flag"]:
        return "routine_encrypted_allow"
    if values["v540_incomplete_80_allow_flag"]:
        return "incomplete_80_allow"
    if values["v540_unknown_udp_flag"]:
        return "unknown_udp"
    if values["v540_unknown_tcp_flag"]:
        return "unknown_tcp"
    if values["v540_missingness_pressure"] >= 2:
        return "field_limited"
    if values["v540_application_risk_signal"] >= 4:
        return "application_risk"
    return "other_context"


def augment_v540_features(dataset: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    frame = dataset["frame"].copy()
    family_counts: Counter[str] = Counter()
    columns: dict[str, list[Any]] = {name: [] for name in V540_NUMERIC_FEATURES}
    families: list[str] = []
    for position, log in enumerate(dataset["logs"]):
        row = frame.iloc[position]
        app = _lower(getattr(log, "app", None))
        action = _lower(getattr(log, "action", None))
        protocol = _lower(getattr(log, "protocol", None))
        dst_port = getattr(log, "dst_port", None)
        local_rule = _number(row.get("v398_local_rule_score"))
        unique_ports = max(
            _number(row.get("src_ip_5min_unique_dst_ports")),
            _number(row.get("src_ip_15min_unique_dst_ports")),
        )
        unique_destinations = max(
            _number(row.get("src_ip_5min_unique_dst_ips")),
            _number(row.get("src_ip_15min_unique_dst_ips")),
        )
        scan_pressure = min(100.0, (unique_ports * 4.0) + (unique_destinations * 2.0))
        scan_context = bool(
            _number(row.get("scanning_like_behavior_score")) >= 30
            or unique_ports >= 8
            or unique_destinations >= 8
        )
        quic = bool(app == "quic-base" and action == "allow" and dst_port == 443)
        encrypted = bool(
            action == "allow"
            and dst_port == 443
            and app in {"quic-base", "ssl", "web-browsing"}
        )
        routine_encrypted = bool(
            encrypted and not scan_context and local_rule < 30
        )
        incomplete_80 = bool(
            app == "incomplete" and action == "allow" and dst_port == 80
        )
        unknown_udp = bool(app.startswith("unknown") and protocol == "udp")
        unknown_tcp = bool(app.startswith("unknown") and protocol == "tcp")
        anomaly_or_behavior = max(
            _number(row.get("v337_anomaly_signal_flag")),
            min(1.0, _number(row.get("scanning_like_behavior_score")) / 100.0),
        )
        application_risk = max(
            _number(getattr(log, "app_risk", None)),
            _number(row.get("src_ip_5min_high_risk_app_count")) > 0 and 4.0 or 0.0,
        )
        missingness = _number(row.get("required_field_missing_count")) + min(
            3.0,
            _number(row.get("parser_warning_count")),
        )
        values = {
            "v540_quic_443_allow_flag": int(quic),
            "v540_routine_encrypted_allow_flag": int(routine_encrypted),
            "v540_incomplete_80_allow_flag": int(incomplete_80),
            "v540_unknown_udp_flag": int(unknown_udp),
            "v540_unknown_tcp_flag": int(unknown_tcp),
            "v540_scan_diversity_pressure": round(scan_pressure, 4),
            "v540_scan_context_flag": int(scan_context),
            "v540_local_rule_strength": round(local_rule, 4),
            "v540_anomaly_or_behavior_signal": round(anomaly_or_behavior, 4),
            "v540_application_risk_signal": round(application_risk, 4),
            "v540_missingness_pressure": round(missingness, 4),
            "v540_low_signal_routine_flag": int(
                action == "allow"
                and not scan_context
                and local_rule < 30
                and application_risk < 4
            ),
        }
        family = _v540_family(values)
        for name, value in values.items():
            columns[name].append(value)
        families.append(family)
        family_counts[family] += 1

    for name, values in columns.items():
        frame[name] = values
    frame[V540_CATEGORICAL_FEATURE] = families
    numeric = list(
        dict.fromkeys(
            [*dataset["feature_meta"]["numeric_features"], *V540_NUMERIC_FEATURES]
        )
    )
    categorical = list(
        dict.fromkeys(
            [
                *dataset["feature_meta"]["categorical_features"],
                V540_CATEGORICAL_FEATURE,
            ]
        )
    )
    rows = [dict(row) for row in dataset["rows"]]
    fingerprints = frozen._feature_fingerprints(frame, [*numeric, *categorical])
    for index, row in enumerate(rows):
        row["feature_fingerprint"] = fingerprints[index]
        row["v540_evidence_family"] = families[index]
    duplicate_audit = frozen.assign_leakage_groups(rows)
    enriched = {
        **dataset,
        "frame": frame,
        "rows": rows,
        "feature_meta": {
            **dataset["feature_meta"],
            "numeric_features": numeric,
            "categorical_features": categorical,
            "v540_features": [*V540_NUMERIC_FEATURES, V540_CATEGORICAL_FEATURE],
            "post_prediction_guard_used": False,
            "causal_or_row_local_features_only": True,
        },
    }
    return enriched, {
        "feature_contract": V540_VERSION,
        "numeric_features_added": len(V540_NUMERIC_FEATURES),
        "categorical_features_added": 1,
        "family_distribution": dict(sorted(family_counts.items())),
        "duplicate_audit_after_feature_rebuild": duplicate_audit,
        "post_prediction_guard_used": False,
        "raw_logs_included": False,
        "private_identifiers_included": False,
    }


def audit_development_evidence(dataset: dict[str, Any]) -> dict[str, Any]:
    rows = dataset["rows"]
    frame = dataset["frame"]
    provenance = Counter(str(row.get("label_source") or "unknown") for row in rows)
    labels = Counter(str(row.get("original_label") or "unknown") for row in rows)
    targets = Counter(str(value) for value in dataset["targets"])
    groups = Counter(str(row.get("leakage_group") or "missing") for row in rows)
    sources = Counter(str(row.get("source_name") or "unknown") for row in rows)
    timestamps = sorted(
        row["timestamp"] for row in rows if row.get("timestamp") is not None
    )
    missingness = []
    for column in [
        *dataset["feature_meta"]["numeric_features"],
        *dataset["feature_meta"]["categorical_features"],
    ]:
        rate = float(frame[column].isna().mean()) if len(frame) else 0.0
        missingness.append({"feature": column, "missing_rate": round(rate, 4)})
    missingness.sort(key=lambda item: item["missing_rate"], reverse=True)
    assisted_rows = sum(
        count for source, count in provenance.items() if source != "manual"
    )
    majority = max(targets.values(), default=0)
    minority = min(targets.values(), default=0)
    problems: list[str] = []
    if len(sources) < 2:
        problems.append("Development evidence contains fewer than two source identities.")
    if assisted_rows:
        problems.append("Assisted provenance is present and must remain down-weighted.")
    if sum(count for count in groups.values() if count > 1):
        problems.append("Duplicate groups require fold-level isolation.")
    if minority and majority / minority >= 3:
        problems.append("Queue targets are materially imbalanced.")
    if sources and max(sources.values()) / max(1, len(rows)) >= 0.80:
        problems.append("Development evidence is concentrated in one source.")
    return {
        "rows": len(rows),
        "original_label_distribution": dict(sorted(labels.items())),
        "queue_target_distribution": dict(sorted(targets.items())),
        "label_provenance_distribution": dict(sorted(provenance.items())),
        "manual_rows": int(provenance.get("manual", 0)),
        "assisted_or_weak_rows": assisted_rows,
        "assisted_rows_marked_human_by_v540": 0,
        "source_identity_count": len(sources),
        "source_event_counts_ranked": [
            {"rank": rank, "rows": count}
            for rank, (_source, count) in enumerate(sources.most_common(10), start=1)
        ],
        "duplicate_group_count": len(groups),
        "multirow_duplicate_groups": sum(1 for count in groups.values() if count > 1),
        "rows_in_multirow_duplicate_groups": sum(
            count for count in groups.values() if count > 1
        ),
        "largest_duplicate_group_rows": max(groups.values(), default=0),
        "time_range": {
            "start": timestamps[0].isoformat() if timestamps else None,
            "end": timestamps[-1].isoformat() if timestamps else None,
            "distinct_timestamps": len(set(timestamps)),
        },
        "largest_feature_missingness": missingness[:15],
        "problems": problems,
        "raw_logs_included": False,
        "source_names_returned": False,
        "private_identifiers_included": False,
    }


def _targets_for_strategy(
    dataset: dict[str, Any],
    spec: dict[str, Any],
) -> tuple[list[str], set[str]]:
    if spec["target_mode"] == "three_class_soc_queue":
        return v55._three_class_targets(dataset["original_labels"]), {
            "suspicious",
            "malicious",
        }
    return list(dataset["targets"]), {"needs_review"}


def _fit_weights(
    dataset: dict[str, Any],
    indices: list[int],
    targets: list[str],
) -> tuple[list[float], dict[str, Any]]:
    provenance_multiplier = {
        "manual": 1.0,
        "reviewed_import": 1.0,
        "assisted_rule": 0.65,
        "assisted_ml": 0.50,
        "assisted_hybrid": 0.50,
    }
    target_counts = Counter(targets[index] for index in indices)
    provenance_counts = Counter(
        str(dataset["rows"][index].get("label_source") or "unknown")
        for index in indices
    )
    total = max(1, len(indices))
    class_count = max(1, len(target_counts))
    values: list[float] = []
    for index in indices:
        target = targets[index]
        source = str(dataset["rows"][index].get("label_source") or "unknown")
        class_balance = total / (class_count * max(1, target_counts[target]))
        source_balance = total / (
            max(1, len(provenance_counts)) * max(1, provenance_counts[source])
        )
        value = (
            class_balance
            * min(2.0, max(0.5, source_balance))
            * provenance_multiplier.get(source, 0.50)
        )
        values.append(round(min(6.0, max(0.20, value)), 6))
    return values, {
        "strategy": "class_balance_x_provenance_balance_x_assisted_downweight",
        "target_distribution": dict(sorted(target_counts.items())),
        "provenance_distribution": dict(sorted(provenance_counts.items())),
        "minimum_weight": min(values, default=None),
        "maximum_weight": max(values, default=None),
        "mean_weight": round(mean(values), 4) if values else None,
        "assisted_provenance_downweighted": True,
        "labels_rewritten": False,
    }


def _profile_gate(metrics: dict[str, Any]) -> bool:
    return bool(
        _number(metrics.get("queue_recall"))
        >= DEVELOPMENT_GATES["suspicious_recall_min"]
        and _number(metrics.get("benign_like_false_positive_rate"), 1.0)
        <= DEVELOPMENT_GATES["benign_like_false_positive_rate_max"]
    )


def select_fixed_threshold_profile(
    y_true: list[str],
    scores: list[float],
) -> dict[str, Any]:
    profiles: list[dict[str, Any]] = []
    for profile in FIXED_THRESHOLD_PROFILES:
        threshold = float(profile["threshold"])
        predictions = [
            "needs_review" if float(score) >= threshold else "non_threat"
            for score in scores
        ]
        metrics = frozen._binary_metrics(y_true, predictions)
        feasible = _profile_gate(metrics)
        selection_score = (
            _number(metrics.get("queue_f1"))
            + (0.15 * _number(metrics.get("queue_recall")))
            - (
                0.60
                * _number(metrics.get("benign_like_false_positive_rate"), 1.0)
            )
        )
        profiles.append(
            {
                **profile,
                "feasible": feasible,
                "selection_score": round(selection_score, 6),
                "metrics": metrics,
            }
        )
    feasible = [item for item in profiles if item["feasible"]]
    selected = max(
        feasible or profiles,
        key=lambda item: (
            item["selection_score"],
            _number(item["metrics"].get("queue_f1")),
            -_number(
                item["metrics"].get("benign_like_false_positive_rate"),
                1.0,
            ),
            item["threshold"],
        ),
    )
    return {
        "status": "selected",
        "selected_profile": selected["name"],
        "selected_threshold": selected["threshold"],
        "selected_on": "development_threshold_partition_only",
        "fixed_profiles_only": True,
        "used_v539_labels": False,
        "used_nested_evaluation_labels": False,
        "feasible_profile_available": bool(feasible),
        "profiles": profiles,
    }


def _safe_error_patterns(
    dataset: dict[str, Any],
    indices: list[int],
    y_true: list[str],
    predictions: list[str],
) -> dict[str, Any]:
    false_positives: list[dict[str, Any]] = []
    false_negatives: list[dict[str, Any]] = []
    for position, index in enumerate(indices):
        if y_true[position] == predictions[position]:
            continue
        row = dataset["rows"][index]
        item = {
            "family": str(row.get("v540_evidence_family") or "unknown"),
            "app": str(row.get("app") or "unknown"),
            "action": str(row.get("action") or "unknown"),
            "dst_port": str(row.get("dst_port") or "unknown"),
            "original_label": str(row.get("original_label") or "unknown"),
            "provenance": str(row.get("label_source") or "unknown"),
        }
        if y_true[position] == "non_threat":
            false_positives.append(item)
        else:
            false_negatives.append(item)

    def summarize(items: list[dict[str, Any]]) -> dict[str, Any]:
        return {
            "rows": len(items),
            "top_families": Counter(item["family"] for item in items).most_common(10),
            "top_apps": Counter(item["app"] for item in items).most_common(10),
            "top_actions": Counter(item["action"] for item in items).most_common(10),
            "top_ports": Counter(item["dst_port"] for item in items).most_common(10),
            "top_original_labels": Counter(
                item["original_label"] for item in items
            ).most_common(10),
            "top_provenance": Counter(
                item["provenance"] for item in items
            ).most_common(10),
        }

    return {
        "false_positives": summarize(false_positives),
        "false_negatives": summarize(false_negatives),
        "source_names_returned": False,
        "row_identifiers_returned": False,
        "raw_logs_included": False,
    }


def _development_gate(
    metrics: dict[str, Any],
    calibration: dict[str, Any],
    calibration_method: str,
) -> dict[str, Any]:
    checks = {
        "queue_f1": _number(metrics.get("queue_f1"))
        >= DEVELOPMENT_GATES["queue_f1_min"],
        "benign_like_false_positive_rate": _number(
            metrics.get("benign_like_false_positive_rate"),
            1.0,
        )
        <= DEVELOPMENT_GATES["benign_like_false_positive_rate_max"],
        "suspicious_recall": metrics.get("suspicious_recall") is not None
        and _number(metrics.get("suspicious_recall"))
        >= DEVELOPMENT_GATES["suspicious_recall_min"],
        "malicious_recall": metrics.get("malicious_recall") is not None
        and _number(metrics.get("malicious_recall"))
        >= DEVELOPMENT_GATES["malicious_recall_min"],
        "expected_calibration_error": _number(
            calibration.get("expected_calibration_error"),
            1.0,
        )
        <= DEVELOPMENT_GATES["expected_calibration_error_max"],
        "max_confidence_accuracy_gap": _number(
            calibration.get("max_confidence_accuracy_gap"),
            1.0,
        )
        <= DEVELOPMENT_GATES["max_confidence_accuracy_gap_max"],
        "calibration_applied": calibration_method.startswith(("sigmoid_", "isotonic_")),
    }
    return {
        "passed": all(checks.values()),
        "checks": checks,
        "gates": DEVELOPMENT_GATES,
    }


def _fit_strategy(
    dataset: dict[str, Any],
    partition: dict[str, Any],
    spec: dict[str, Any],
) -> dict[str, Any]:
    fit_idx = list(partition["fit_idx"])
    calibration_idx = list(partition["calibration_idx"])
    threshold_idx = list(partition["threshold_idx"])
    evaluation_idx = list(partition["final_test_idx"])
    targets, positive_classes = _targets_for_strategy(dataset, spec)
    y_fit = [targets[index] for index in fit_idx]
    if len(set(y_fit)) < 2:
        return {
            "status": "failed_closed",
            "reason": "fit partition has fewer than two target classes",
        }

    pipeline = _build_pipeline_for_columns(
        dataset["imports"],
        model_type=str(spec["model_type"]),
        class_weight=spec.get("class_weight"),
        numeric_features=dataset["feature_meta"]["numeric_features"],
        categorical_features=dataset["feature_meta"]["categorical_features"],
    )
    weights, weighting = _fit_weights(dataset, fit_idx, targets)
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
    threshold_selection = select_fixed_threshold_profile(
        [dataset["targets"][index] for index in threshold_idx],
        threshold_scores,
    )
    threshold = float(threshold_selection["selected_threshold"])
    scores = reliability._queue_scores(
        model,
        dataset["frame"],
        evaluation_idx,
        positive_classes,
    )
    predictions = [
        "needs_review" if score >= threshold else "non_threat" for score in scores
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
    calibration = frozen._calibration_report(y_true, scores)
    classification = None
    if spec["target_mode"] == "three_class_soc_queue":
        direct = [
            str(value)
            for value in model.predict(dataset["frame"].iloc[evaluation_idx])
        ]
        classification = reliability._classification_diagnostics(
            [
                v55._three_class_targets(dataset["original_labels"])[index]
                for index in evaluation_idx
            ],
            direct,
        )
    elif spec["target_mode"] == "hierarchical_two_stage":
        threat_fit = [
            index
            for index in fit_idx
            if dataset["original_labels"][index] in {"suspicious", "malicious"}
        ]
        severity_targets = [dataset["original_labels"][index] for index in threat_fit]
        if len(set(severity_targets)) >= 2:
            severity = _build_pipeline_for_columns(
                dataset["imports"],
                model_type="extra_trees",
                class_weight="balanced",
                numeric_features=dataset["feature_meta"]["numeric_features"],
                categorical_features=dataset["feature_meta"]["categorical_features"],
            )
            severity_weights, _ = _fit_weights(dataset, threat_fit, dataset["original_labels"])
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

    gate = _development_gate(metrics, calibration, calibration_method)
    return {
        "status": "evaluated",
        "name": spec["name"],
        "model_type": spec["model_type"],
        "target_mode": spec["target_mode"],
        "requested_calibration_method": spec["calibration_method"],
        "applied_calibration_method": calibration_method,
        "threshold_selection": threshold_selection,
        "metrics": metrics,
        "calibration": calibration,
        "classification_diagnostics": classification,
        "error_patterns": _safe_error_patterns(
            dataset,
            evaluation_idx,
            y_true,
            predictions,
        ),
        "sample_weighting": weighting,
        "development_gate": gate,
        "fit_rows": len(fit_idx),
        "calibration_rows": len(calibration_idx),
        "threshold_rows": len(threshold_idx),
        "evaluation_rows": len(evaluation_idx),
        "training_seconds": round(time.perf_counter() - started, 4),
        "protected_v539_rows_used": 0,
        "active_artifact_written": False,
        "post_prediction_guard_used": False,
    }


def _range(values: list[float]) -> dict[str, float | None]:
    return {
        "min": round(min(values), 4) if values else None,
        "max": round(max(values), 4) if values else None,
        "mean": round(mean(values), 4) if values else None,
    }


def run_development_comparison(dataset: dict[str, Any]) -> dict[str, Any]:
    folds = v55.build_nested_temporal_folds(dataset)
    views: list[dict[str, Any]] = []
    by_strategy: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for fold in folds:
        if fold.get("status") != "partitioned":
            views.append(
                {
                    "fold": fold.get("fold"),
                    "status": fold.get("status"),
                    "reason": fold.get("reason"),
                }
            )
            continue
        evaluations: list[dict[str, Any]] = []
        for spec in STRATEGY_SPECS:
            try:
                result = _fit_strategy(fold["dataset"], fold["partition"], spec)
            except Exception as exc:  # diagnostic failures must fail closed
                result = {
                    "status": "failed_closed",
                    "name": spec["name"],
                    "error_type": exc.__class__.__name__,
                    "message": "Diagnostic strategy evaluation failed closed.",
                    "active_artifact_written": False,
                    "protected_v539_rows_used": 0,
                }
            evaluations.append(result)
            by_strategy[str(spec["name"])].append(
                {"fold": fold["fold"], **result}
            )
        views.append(
            {
                "fold": fold["fold"],
                "status": fold["status"],
                "prefix_share": fold.get("prefix_share"),
                "leakage_audit_passed": bool(
                    (fold.get("leakage_audit") or {}).get("passed")
                ),
                "partition_sizes": (
                    fold.get("leakage_audit") or {}
                ).get("partition_sizes"),
                "strategies": evaluations,
            }
        )

    summaries: dict[str, Any] = {}
    metric_fields = (
        "queue_precision",
        "queue_recall",
        "queue_f1",
        "benign_like_false_positive_rate",
        "suspicious_recall",
        "malicious_recall",
        "macro_f1",
        "weighted_f1",
        "review_queue_rate",
        "false_positive",
        "false_negative",
    )
    calibration_fields = (
        "brier_score",
        "expected_calibration_error",
        "max_confidence_accuracy_gap",
    )
    for name, rows in by_strategy.items():
        evaluated = [row for row in rows if row.get("status") == "evaluated"]
        summaries[name] = {
            "evaluated_folds": len(evaluated),
            "required_folds": len(v55.NESTED_PREFIX_SHARES),
            "passing_folds": sum(
                1
                for row in evaluated
                if (row.get("development_gate") or {}).get("passed")
            ),
            "all_required_folds_passed": bool(evaluated)
            and len(evaluated) == len(v55.NESTED_PREFIX_SHARES)
            and all(
                (row.get("development_gate") or {}).get("passed")
                for row in evaluated
            ),
            "metric_ranges": {
                field: _range(
                    [
                        _number((row.get("metrics") or {}).get(field))
                        for row in evaluated
                        if (row.get("metrics") or {}).get(field) is not None
                    ]
                )
                for field in metric_fields
            },
            "calibration_ranges": {
                field: _range(
                    [
                        _number((row.get("calibration") or {}).get(field))
                        for row in evaluated
                        if (row.get("calibration") or {}).get(field) is not None
                    ]
                )
                for field in calibration_fields
            },
            "calibration_methods": sorted(
                {
                    str(row.get("applied_calibration_method") or "missing")
                    for row in evaluated
                }
            ),
            "protected_v539_rows_used": 0,
        }
    source_count = len(
        {str(row.get("source_name") or "unknown") for row in dataset["rows"]}
    )
    return {
        "protocol": "v5.40-development-only-nested-temporal-v1",
        "development_rows": len(dataset["rows"]),
        "strategy_count": len(STRATEGY_SPECS),
        "views": views,
        "strategy_summaries": summaries,
        "source_aware_validation": {
            "status": "insufficient_evidence"
            if source_count < 2
            else "available_for_future_extension",
            "source_identity_count": source_count,
            "source_names_returned": False,
        },
        "duplicate_group_isolation_required": True,
        "v539_evaluated": False,
        "v539_labels_used": False,
        "v539_predictions_used": False,
        "v539_errors_used": False,
        "active_artifact_written": False,
    }


def select_best_diagnostic_strategy(comparison: dict[str, Any]) -> dict[str, Any] | None:
    ranked: list[tuple[Any, ...]] = []
    for name, summary in (comparison.get("strategy_summaries") or {}).items():
        ranges = summary.get("metric_ranges") or {}
        calibration = summary.get("calibration_ranges") or {}

        def minimum(field: str, default: float = 0.0) -> float:
            value = (ranges.get(field) or {}).get("min")
            return default if value is None else float(value)

        def maximum(field: str, default: float = 1.0) -> float:
            value = (ranges.get(field) or {}).get("max")
            return default if value is None else float(value)

        calibration_max = (
            calibration.get("expected_calibration_error") or {}
        ).get("max")
        score = (
            minimum("queue_f1")
            + (0.20 * minimum("suspicious_recall"))
            + (0.20 * minimum("malicious_recall"))
            - (0.75 * maximum("benign_like_false_positive_rate"))
            - (0.15 * float(calibration_max if calibration_max is not None else 1.0))
        )
        ranked.append(
            (
                bool(summary.get("all_required_folds_passed")),
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
    summary = comparison["strategy_summaries"][name]
    return {
        "name": name,
        "selection_basis": "development_roles_only",
        "passed_all_development_gates": bool(
            summary.get("all_required_folds_passed")
        ),
        "summary": summary,
        "v539_used": False,
        "eligible_for_activation": False,
    }


def summarize_development_errors(
    comparison: dict[str, Any] | None,
    leader: dict[str, Any] | None,
) -> dict[str, Any]:
    if not comparison or not leader:
        return {
            "status": "not_evaluated",
            "folds_analyzed": 0,
            "row_identifiers_returned": False,
        }
    false_positive: dict[str, Counter[str]] = defaultdict(Counter)
    false_negative: dict[str, Counter[str]] = defaultdict(Counter)
    fp_rows = 0
    fn_rows = 0
    folds = 0

    def add(counter: Counter[str], values: list[Any]) -> None:
        for item in values:
            if isinstance(item, (list, tuple)) and len(item) == 2:
                counter[str(item[0])] += _integer(item[1])

    for view in comparison.get("views") or []:
        evaluation = next(
            (
                item
                for item in view.get("strategies") or []
                if item.get("name") == leader.get("name")
                and item.get("status") == "evaluated"
            ),
            None,
        )
        if not evaluation:
            continue
        patterns = evaluation.get("error_patterns") or {}
        fp = patterns.get("false_positives") or {}
        fn = patterns.get("false_negatives") or {}
        fp_rows += _integer(fp.get("rows"))
        fn_rows += _integer(fn.get("rows"))
        folds += 1
        for field in (
            "top_families",
            "top_apps",
            "top_actions",
            "top_ports",
            "top_original_labels",
            "top_provenance",
        ):
            add(false_positive[field], fp.get(field) or [])
            add(false_negative[field], fn.get(field) or [])

    def public(value: dict[str, Counter[str]]) -> dict[str, Any]:
        return {
            field: counter.most_common(10)
            for field, counter in sorted(value.items())
        }

    return {
        "status": "evaluated" if folds else "not_evaluated",
        "strategy": leader.get("name"),
        "folds_analyzed": folds,
        "false_positive_observations_across_folds": fp_rows,
        "false_negative_observations_across_folds": fn_rows,
        "false_positive_patterns": public(false_positive),
        "false_negative_patterns": public(false_negative),
        "nested_fold_rows_may_repeat_across_prefixes": True,
        "source_names_returned": False,
        "row_identifiers_returned": False,
        "raw_logs_included": False,
    }


def summarize_calibration(
    leader: dict[str, Any] | None,
) -> dict[str, Any]:
    if not leader:
        return {"status": "not_evaluated", "passed": False}
    summary = leader.get("summary") or {}
    ranges = summary.get("calibration_ranges") or {}
    ece_max = (ranges.get("expected_calibration_error") or {}).get("max")
    gap_max = (ranges.get("max_confidence_accuracy_gap") or {}).get("max")
    methods = summary.get("calibration_methods") or []
    passed = bool(
        ece_max is not None
        and float(ece_max) <= DEVELOPMENT_GATES["expected_calibration_error_max"]
        and gap_max is not None
        and float(gap_max)
        <= DEVELOPMENT_GATES["max_confidence_accuracy_gap_max"]
        and methods
        and all(str(value).startswith(("sigmoid_", "isotonic_")) for value in methods)
    )
    return {
        "status": "passed" if passed else "weak",
        "passed": passed,
        "methods": methods,
        "ranges": ranges,
        "fixed_threshold_profiles": [
            {"name": item["name"], "threshold": item["threshold"]}
            for item in FIXED_THRESHOLD_PROFILES
        ],
        "v539_used": False,
    }


def freeze_diagnostic_candidate_metadata(
    leader: dict[str, Any] | None,
    dataset: dict[str, Any],
) -> dict[str, Any] | None:
    if not leader or not leader.get("passed_all_development_gates"):
        return None
    spec = next(item for item in STRATEGY_SPECS if item["name"] == leader["name"])
    payload = {
        "protocol": "v5.40-development-diagnostic-freeze-v1",
        "strategy": spec,
        "feature_contract": dataset["feature_meta"].get("v540_features") or [],
        "development_contract": _stable_hash(
            [
                {
                    "log_id": row.get("log_id"),
                    "label_id": row.get("label_id"),
                    "leakage_group": row.get("leakage_group"),
                }
                for row in dataset["rows"]
            ]
        ),
        "development_summary": leader["summary"],
        "v539_used": False,
        "model_artifact_written": False,
        "eligible_for_activation": False,
    }
    return {
        "status": "diagnostic_configuration_frozen",
        "candidate": spec,
        "freeze_fingerprint": _stable_hash(payload),
        "model_artifact_written": False,
        "active_artifact_written": False,
        "v539_evaluated": False,
        "eligible_for_activation": False,
    }


def design_new_blind_evidence_protocol(dataset: dict[str, Any]) -> dict[str, Any]:
    timestamps = sorted(
        row["timestamp"] for row in dataset["rows"] if row.get("timestamp") is not None
    )
    cutoff = timestamps[-1].isoformat() if timestamps else None
    return {
        "protocol": "v5.40-new-disjoint-blind-evidence-v1",
        "status": "designed_not_collected",
        "collection_starts_strictly_after_development_cutoff": cutoff,
        "minimum_independent_source_identities": 2,
        "minimum_distinct_collection_windows": 3,
        "target_review_rows": 240,
        "minimum_class_support_after_human_review": {
            "benign_like": 100,
            "suspicious": 50,
            "malicious": 50,
        },
        "required_strata": [
            "routine_encrypted_443",
            "incomplete_80",
            "unknown_udp_tcp",
            "scan_like_diversity",
            "vendor_threat_records",
            "routine_allowed_traffic",
            "parser_limited_evidence",
        ],
        "exclusion_keys": [
            "exact_raw_fingerprint",
            "near_behavior_fingerprint",
            "feature_fingerprint",
            "v539_consumed_review_token",
            "development_time_boundary",
            "source_identity_boundary",
        ],
        "workflow": [
            "collect future evidence from at least two independent real sources",
            "seal custody and duplicate-family manifests before predictions",
            "freeze candidate configuration before opening blind evidence",
            "store predictions separately and keep them hidden from reviewers",
            "collect genuine human decisions without assisted labels",
            "reveal labels once and run one fixed aggregate evaluation",
        ],
        "predictions_in_pack": False,
        "automatic_labels_in_pack": False,
        "human_labels_created": 0,
        "import_ready": False,
        "v539_rows_reused": False,
        "development_rows_reused": False,
        "raw_logs_returned": False,
        "private_identifiers_returned": False,
    }


def _readiness(
    *,
    evidence_audit: dict[str, Any],
    leader: dict[str, Any] | None,
    candidate_freeze: dict[str, Any] | None,
    safety: dict[str, Any],
) -> dict[str, Any]:
    blockers = list(evidence_audit.get("problems") or [])
    if leader is None:
        blockers.append("No development strategy produced comparable fold metrics.")
    elif not leader.get("passed_all_development_gates"):
        blockers.append("No strategy passed every fixed development gate across all folds.")
    if candidate_freeze is None:
        blockers.append("No diagnostic candidate configuration was frozen.")
    blockers.extend(
        [
            "v5.39 is consumed final evidence and cannot be reused.",
            "A new disjoint multi-source blind pack has not been collected or reviewed.",
        ]
    )
    return {
        "decision": "shadow_observation",
        "candidate_configuration_frozen": candidate_freeze is not None,
        "candidate_selected_for_activation": False,
        "model_activated": False,
        "model_promoted": False,
        "production_promoted": False,
        "response_automation_allowed": False,
        "rules_alert_authoritative": True,
        "safety_invariants_passed": bool(
            safety.get("database_counts_unchanged")
            and safety.get("model_artifacts_unchanged")
            and safety.get("v539_private_state_unchanged")
        ),
        "blockers": list(dict.fromkeys(blockers)),
    }


def _render_report(result: dict[str, Any]) -> str:
    evidence = result.get("evidence") or {}
    audit = result.get("development_evidence_audit") or {}
    leader = result.get("best_diagnostic_strategy") or {}
    summary = leader.get("summary") or {}
    calibration = result.get("calibration_result") or {}
    errors = result.get("development_error_analysis") or {}
    lines = [
        "# v5.40 Development-Only Supervised Model Repair",
        "",
        f"Generated: {result.get('generated_at')}",
        "",
        "## Evidence Boundary",
        "",
        f"- Configured reviewed rows: `{evidence.get('configured_reviewed_rows')}`",
        f"- v5.39 matched and excluded rows: `{evidence.get('matched_and_excluded_rows')}`",
        f"- Canonical development rows: `{evidence.get('development_rows')}`",
        f"- Canonical excluded rows: `{evidence.get('canonical_excluded_rows')}`",
        "- v5.39 labels, predictions, and errors were not opened or used.",
        "",
        "## Development Quality",
        "",
        f"- Source identities: `{audit.get('source_identity_count')}`",
        f"- Rows in multirow duplicate groups: `{audit.get('rows_in_multirow_duplicate_groups')}`",
        f"- Assisted or weak provenance rows: `{audit.get('assisted_or_weak_rows')}`",
        "",
        "## Best Diagnostic Strategy",
        "",
        f"- Strategy: `{leader.get('name') or 'none'}`",
        f"- Passed all fixed development gates: `{bool(leader.get('passed_all_development_gates'))}`",
        f"- Metric ranges: `{json.dumps(summary.get('metric_ranges') or {}, sort_keys=True)}`",
        f"- Calibration ranges: `{json.dumps(summary.get('calibration_ranges') or {}, sort_keys=True)}`",
        f"- Calibration decision: `{calibration.get('status') or 'not_evaluated'}`",
        f"- False-positive observations across nested folds: `{errors.get('false_positive_observations_across_folds')}`",
        f"- False-negative observations across nested folds: `{errors.get('false_negative_observations_across_folds')}`",
        "",
        "## Lifecycle",
        "",
        "- Lifecycle remains `shadow_observation`.",
        "- Deterministic rules remain alert-authoritative.",
        "- No model was activated, promoted, or written as an active artifact.",
        "- Automatic response and real firewall blocking remain disabled.",
        "",
        "## Remaining Blockers",
        "",
    ]
    lines.extend(
        f"- {item}" for item in (result.get("readiness") or {}).get("blockers") or []
    )
    return "\n".join(lines) + "\n"


def run_v540_development_supervised_repair(
    db: Session,
    *,
    min_samples: int = 100,
    preflight_only: bool = False,
    write_output: bool = True,
    output_dir: str | Path = OUTPUT_DIR,
    state_path: Path = V539_STATE_PATH,
    pack_path: Path = DEFAULT_PACK_PATH,
) -> dict[str, Any]:
    started = time.perf_counter()
    output = Path(output_dir)
    counts_before = frozen._database_counts(db)
    artifacts_before = v55._model_artifact_states()
    state_before = _private_file_state(state_path)
    pack_before = _private_file_state(pack_path)

    try:
        boundary = load_v539_consumed_boundary(
            state_path=state_path,
            pack_path=pack_path,
        )
    except V540EvidenceBoundaryError as exc:
        return {
            "ok": False,
            "status": "failed_closed",
            "version": V540_VERSION,
            "message": str(exc),
            "lifecycle_state": "shadow_observation",
            "v539_evaluated": False,
        }

    dataset = v52._prepare_dataset(db, min_samples=min_samples)
    if not dataset.get("ok"):
        return {
            "ok": False,
            "status": dataset.get("status", "failed_closed"),
            "version": V540_VERSION,
            "message": dataset.get("message"),
            "lifecycle_state": "shadow_observation",
            "v539_boundary": _public_boundary(boundary),
            "v539_evaluated": False,
        }
    filtered, exclusion = exclude_v539_consumed_evidence(dataset, boundary)
    canonical = frozen.build_frozen_partition(
        filtered["rows"],
        split_mode="temporal_holdout",
    )
    leakage = frozen.audit_partition_leakage(filtered["rows"], canonical)
    if not leakage.get("passed"):
        return {
            "ok": False,
            "status": "failed_closed",
            "version": V540_VERSION,
            "message": "Development evidence failed duplicate-group isolation.",
            "lifecycle_state": "shadow_observation",
            "v539_boundary": _public_boundary(boundary),
            "v539_evaluated": False,
        }
    development = v55.build_development_dataset(filtered, canonical)
    development, feature_audit = augment_v540_features(development)
    evidence_audit = audit_development_evidence(development)
    blind_design = design_new_blind_evidence_protocol(development)

    comparison = None
    leader = None
    candidate_freeze = None
    if not preflight_only:
        comparison = run_development_comparison(development)
        leader = select_best_diagnostic_strategy(comparison)
        candidate_freeze = freeze_diagnostic_candidate_metadata(
            leader,
            development,
        )
    error_analysis = summarize_development_errors(comparison, leader)
    calibration_result = summarize_calibration(leader)

    counts_after = frozen._database_counts(db)
    artifacts_after = v55._model_artifact_states()
    state_after = _private_file_state(state_path)
    pack_after = _private_file_state(pack_path)
    safety = {
        "database_counts_before": counts_before,
        "database_counts_after": counts_after,
        "database_counts_unchanged": counts_before == counts_after,
        "model_artifacts_unchanged": artifacts_before == artifacts_after,
        "v539_private_state_unchanged": state_before == state_after,
        "v539_detection_pack_unchanged": pack_before == pack_after,
        "labels_created": counts_after["ml_labels"] - counts_before["ml_labels"],
        "model_runs_created": counts_after["ml_model_runs"]
        - counts_before["ml_model_runs"],
        "detection_runs_created": counts_after["detection_runs"]
        - counts_before["detection_runs"],
        "alerts_created": counts_after["alerts"] - counts_before["alerts"],
        "response_actions_created": counts_after["response_actions"]
        - counts_before["response_actions"],
        "active_model_artifact_written": False,
        "model_activated": False,
        "model_promoted": False,
        "rules_alert_authoritative": True,
        "automatic_response_enabled": False,
        "real_firewall_blocking_enabled": False,
        "v539_evaluator_called": False,
    }
    evidence = {
        **exclusion,
        "canonical_fit_rows": len(canonical.get("fit_idx") or []),
        "canonical_calibration_rows": len(canonical.get("calibration_idx") or []),
        "canonical_threshold_rows": len(canonical.get("threshold_idx") or []),
        "canonical_temporal_final_rows": len(canonical.get("final_test_idx") or []),
        "canonical_quarantined_rows": len(canonical.get("quarantined_idx") or []),
        "development_rows": len(development["rows"]),
        "canonical_excluded_rows": len(canonical.get("final_test_idx") or [])
        + len(canonical.get("quarantined_idx") or []),
        "duplicate_group_isolation_passed": bool(leakage.get("passed")),
        "source_identity_count": evidence_audit["source_identity_count"],
        "raw_logs_included": False,
        "private_identifiers_included": False,
    }
    readiness = _readiness(
        evidence_audit=evidence_audit,
        leader=leader,
        candidate_freeze=candidate_freeze,
        safety=safety,
    )
    result = {
        "ok": bool(
            safety["database_counts_unchanged"]
            and safety["model_artifacts_unchanged"]
            and safety["v539_private_state_unchanged"]
            and safety["v539_detection_pack_unchanged"]
        ),
        "status": "preflight_completed" if preflight_only else "evaluated",
        "version": V540_VERSION,
        "generated_at": datetime.now(UTC).isoformat(),
        "lifecycle_state": "shadow_observation",
        "v539_boundary": _public_boundary(boundary),
        "evidence": evidence,
        "development_evidence_audit": evidence_audit,
        "feature_audit": feature_audit,
        "development_model_comparison": comparison,
        "best_diagnostic_strategy": leader,
        "development_error_analysis": error_analysis,
        "calibration_result": calibration_result,
        "frozen_diagnostic_candidate": candidate_freeze,
        "new_blind_evidence_design": blind_design,
        "readiness": readiness,
        "safety": safety,
        "runtime_seconds": round(time.perf_counter() - started, 4),
        "v539_evaluated": False,
        "v539_results_used_for_modeling": False,
        "raw_logs_included": False,
        "private_identifiers_included": False,
        "secrets_exposed": False,
    }
    if write_output:
        output.mkdir(parents=True, exist_ok=True)
        report_path = output / f"{V540_REPORT_PREFIX}_{_stamp()}.md"
        latest_path = output / V540_LATEST
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
        }
    return result
