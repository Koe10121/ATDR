from __future__ import annotations

import copy
import hashlib
import json
import math
import threading
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from statistics import mean
from typing import Any, Iterable

from sqlalchemy import func, select
from sqlalchemy.orm import Session, joinedload

from atdr.app.core.config import get_settings
from atdr.app.db.models import (
    Alert,
    AlertEvidence,
    DetectionRun,
    MLLabel,
    MLModelRun,
    NormalizedLog,
    RawLog,
    ResponseAction,
)
from atdr.app.detection import v55_development_model_repair as v55
from atdr.app.detection import v56_private_panos_model_repair as v56
from atdr.app.detection import v57_independent_shadow_revalidation as v57
from atdr.app.detection.rules import build_detection_context, evaluate_rules
from atdr.app.detection.supervised_detector import _optional_imports
from atdr.app.detection.v520_schema_aware_abstention import (
    assess_log_schema_compatibility,
    public_schema_abstention_policy,
    summarize_schema_compatibility,
)
from atdr.app.ml.features import build_feature_rows


V58_VERSION = "v5.8-governed-shadow-runtime-v1"
EXPECTED_CANDIDATE_NAME = "calibrated_hist_gradient_boosting"
EXPECTED_MODEL_TYPE = "HistGradientBoostingClassifier"
EXPECTED_CALIBRATION_METHOD = "sigmoid"
EXPECTED_THRESHOLD = 0.3
EXPECTED_FEATURE_NAMES = (
    *v56.V56_NUMERIC_FEATURES,
    *v56.V56_CATEGORICAL_FEATURES,
)
ADVISORY_RULE_CODES = frozenset({"ml_anomaly_detected"})
SCORE_BUCKETS = (
    (0.0, 0.2, "0.00-0.19"),
    (0.2, 0.4, "0.20-0.39"),
    (0.4, 0.6, "0.40-0.59"),
    (0.6, 0.8, "0.60-0.79"),
    (0.8, math.inf, "0.80-1.00"),
)

_cache_lock = threading.Lock()
_shadow_cache: dict[str, tuple[float, dict[str, Any]]] = {}
_contract_cache: dict[str, dict[str, Any]] = {}


def clear_shadow_runtime_cache() -> None:
    with _cache_lock:
        _shadow_cache.clear()
        _contract_cache.clear()


def _stable_hash(value: Any) -> str:
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _event_time(log: NormalizedLog) -> datetime | None:
    return (
        log.generated_time
        or log.receive_time
        or log.high_res_timestamp
        or log.start_time
    )


def _utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


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


def _percentile(values: list[float], fraction: float) -> float | None:
    if not values:
        return None
    ordered = sorted(float(value) for value in values)
    position = (len(ordered) - 1) * fraction
    lower = int(position)
    upper = min(len(ordered) - 1, lower + 1)
    weight = position - lower
    return round(
        (ordered[lower] * (1.0 - weight)) + (ordered[upper] * weight),
        6,
    )


def _numeric_summary(values: Iterable[float]) -> dict[str, float | None]:
    materialized = [float(value) for value in values]
    return {
        "minimum": round(min(materialized), 6) if materialized else None,
        "mean": round(mean(materialized), 6) if materialized else None,
        "p50": _percentile(materialized, 0.50),
        "p95": _percentile(materialized, 0.95),
        "maximum": round(max(materialized), 6) if materialized else None,
    }


def _bucket_distribution(values: Iterable[float]) -> list[dict[str, Any]]:
    materialized = [min(1.0, max(0.0, float(value))) for value in values]
    total = len(materialized)
    rows: list[dict[str, Any]] = []
    for lower, upper, label in SCORE_BUCKETS:
        count = sum(
            1
            for value in materialized
            if value >= lower
            and (value < upper or (math.isinf(upper) and value <= 1.0))
        )
        rows.append(
            {
                "bucket": label,
                "count": count,
                "rate": round(count / total, 6) if total else 0.0,
            }
        )
    return rows


def _database_state(db: Session) -> dict[str, int]:
    models = (
        RawLog,
        NormalizedLog,
        Alert,
        AlertEvidence,
        MLLabel,
        MLModelRun,
        DetectionRun,
        ResponseAction,
    )
    return {
        model.__tablename__: int(
            db.scalar(select(func.count()).select_from(model)) or 0
        )
        for model in models
    }


def _public_contract(value: dict[str, Any]) -> dict[str, Any]:
    return {
        key: item
        for key, item in value.items()
        if not key.startswith("_")
    }


def _clone_contract(value: dict[str, Any]) -> dict[str, Any]:
    return {
        key: (
            item
            if key in {"_pipeline", "_artifact_path"}
            else copy.deepcopy(item)
        )
        for key, item in value.items()
    }


def inspect_frozen_candidate_contract(
    *,
    output_dir: Path = v57.OUTPUT_DIR,
) -> dict[str, Any]:
    manifest_path = output_dir / v57.V57_CANDIDATE_FREEZE
    manifest = v57._safe_json(manifest_path)
    artifact_name = str(manifest.get("artifact_name") or "")
    artifact_path = (
        output_dir / artifact_name
        if artifact_name and Path(artifact_name).name == artifact_name
        else None
    )
    artifact_hash = (
        v57._file_sha256(artifact_path)
        if artifact_path is not None
        else None
    )
    current_code_contract = v57._code_contract_fingerprint()
    cache_key = _stable_hash(
        {
            "manifest": manifest,
            "artifact_sha256": artifact_hash,
            "code_contract": current_code_contract,
        }
    )
    with _cache_lock:
        cached_contract = _contract_cache.get(cache_key)
    if cached_contract is not None:
        return _clone_contract(cached_contract)

    imports = _optional_imports()
    pipeline: Any | None = None
    artifact: dict[str, Any] = {}
    details: dict[str, Any] = {}
    error_type: str | None = None

    if (
        imports is not None
        and artifact_path is not None
        and artifact_path.exists()
        and artifact_hash == manifest.get("artifact_sha256")
    ):
        try:
            loaded = imports[0].load(artifact_path)
            if isinstance(loaded, dict):
                artifact = loaded
                pipeline = loaded.get("pipeline")
                if pipeline is not None:
                    details = v57._artifact_pipeline_details(pipeline)
        except (
            OSError,
            ValueError,
            TypeError,
            KeyError,
            AttributeError,
        ) as exc:
            error_type = exc.__class__.__name__

    pipeline_manifest = manifest.get("pipeline") or {}
    threshold = _number(manifest.get("threshold"), -1.0)
    checks = {
        "candidate_manifest_present": bool(manifest),
        "candidate_manifest_version_supported": (
            manifest.get("manifest_version") == v57.V57_VERSION
        ),
        "artifact_name_safe": artifact_path is not None,
        "artifact_present": bool(
            artifact_path is not None and artifact_path.exists()
        ),
        "artifact_hash_matched": bool(
            artifact_hash
            and artifact_hash == manifest.get("artifact_sha256")
        ),
        "code_contract_matched": bool(
            manifest.get("code_contract_fingerprint")
            and manifest.get("code_contract_fingerprint")
            == current_code_contract
        ),
        "pipeline_loaded": pipeline is not None,
        "candidate_name_matched": bool(
            artifact
            and artifact.get("candidate_name")
            == manifest.get("candidate_name")
        ),
        "candidate_name_expected": (
            manifest.get("candidate_name")
            == artifact.get("candidate_name")
            == EXPECTED_CANDIDATE_NAME
        ),
        "candidate_version_expected": (
            manifest.get("candidate_version")
            == artifact.get("version")
            == v56.V56_VERSION
        ),
        "model_type_matched": bool(
            details
            and details.get("model_type")
            == pipeline_manifest.get("model_type")
        ),
        "model_type_expected": (
            details.get("model_type") == EXPECTED_MODEL_TYPE
        ),
        "calibration_method_matched": bool(
            details
            and details.get("calibration_method")
            == pipeline_manifest.get("calibration_method")
        ),
        "calibration_method_expected": (
            details.get("calibration_method")
            == EXPECTED_CALIBRATION_METHOD
        ),
        "feature_count_matched": bool(
            details
            and details.get("feature_count")
            == pipeline_manifest.get("feature_count")
            == 40
        ),
        "feature_contract_matched": bool(
            details
            and details.get("feature_contract_fingerprint")
            == pipeline_manifest.get("feature_contract_fingerprint")
        ),
        "feature_contract_expected": (
            tuple(details.get("feature_names") or ())
            == EXPECTED_FEATURE_NAMES
        ),
        "queue_classes_supported": (
            set(details.get("classes") or [])
            == {"needs_review", "non_threat"}
        ),
        "threshold_matched": bool(
            0.0 <= threshold <= 1.0
            and _number(artifact.get("threshold"), -2.0) == threshold
        ),
        "threshold_expected": math.isclose(
            threshold,
            EXPECTED_THRESHOLD,
            rel_tol=0.0,
            abs_tol=1e-12,
        ),
        "threshold_only_policy": (
            manifest.get("post_prediction_decision_policy")
            == "calibrated_threshold_only"
        ),
        "post_prediction_guard_absent": (
            manifest.get("post_prediction_guard_used") is False
        ),
        "candidate_inactive": manifest.get("active") is False,
        "artifact_inactive": bool(artifact)
        and artifact.get("active") is False,
        "candidate_not_production_promoted": (
            manifest.get("production_promoted") is False
        ),
        "artifact_not_production_promoted": bool(artifact)
        and artifact.get("production_promoted") is False,
        "response_automation_disallowed": (
            manifest.get("response_automation_allowed") is False
        ),
        "artifact_response_automation_disallowed": bool(artifact)
        and artifact.get("response_automation_allowed") is False,
        "rules_alert_authoritative": bool(
            manifest.get("rules_alert_authoritative")
        ),
    }
    matched = all(checks.values())
    blockers = [
        key.replace("_", " ")
        for key, passed in checks.items()
        if not passed
    ]
    result = {
        "status": (
            "candidate_contract_matched"
            if matched
            else "candidate_contract_missing"
            if not manifest
            else "candidate_contract_mismatched"
        ),
        "matched": matched,
        "checks": checks,
        "blockers": blockers,
        "candidate_name": manifest.get("candidate_name"),
        "model_type": pipeline_manifest.get("model_type"),
        "calibration_method": pipeline_manifest.get(
            "calibration_method"
        ),
        "threshold": (
            threshold
            if 0.0 <= threshold <= 1.0
            else None
        ),
        "feature_count": pipeline_manifest.get("feature_count"),
        "post_prediction_guard_used": manifest.get(
            "post_prediction_guard_used"
        ),
        "active": manifest.get("active"),
        "production_promoted": manifest.get("production_promoted"),
        "response_automation_allowed": manifest.get(
            "response_automation_allowed"
        ),
        "rules_alert_authoritative": manifest.get(
            "rules_alert_authoritative"
        ),
        "fallback_model_used": False,
        "error_type": error_type,
        "artifact_path_returned": False,
        "artifact_hash_returned": False,
        "feature_names_returned": False,
        "raw_logs_included": False,
        "private_identifiers_included": False,
        "_pipeline": pipeline,
        "_artifact": artifact,
        "_manifest": manifest,
        "_artifact_path": artifact_path,
        "_artifact_state": (
            v55._file_state(artifact_path)
            if artifact_path is not None
            else {}
        ),
        "_feature_names": details.get("feature_names") or [],
        "_artifact_sha256": artifact_hash,
    }
    with _cache_lock:
        _contract_cache[cache_key] = _clone_contract(result)
        while len(_contract_cache) > 8:
            oldest_key = next(iter(_contract_cache))
            del _contract_cache[oldest_key]
    return result


def _v57_evidence_status(
    output_dir: Path = v57.OUTPUT_DIR,
) -> dict[str, Any]:
    report = v57._safe_json(output_dir / v57.V57_LATEST)
    evidence = report.get("independent_evidence") or {}
    validation = report.get("blind_validation") or {}
    return {
        "status": evidence.get(
            "status",
            "independent_evidence_required",
        ),
        "qualified": bool(evidence.get("eligible_for_predictions")),
        "source_device_count": evidence.get("source_device_count"),
        "independent_time_window_count": evidence.get(
            "independent_time_window_count"
        ),
        "blind_validation_status": validation.get(
            "status",
            "not_run_independent_evidence_required",
        ),
        "blind_metrics_available": (
            validation.get("status") == "evaluated_blind_once"
        ),
    }


def _base_status(
    *,
    enabled: bool,
    contract: dict[str, Any],
    status: str,
    output_dir: Path = v57.OUTPUT_DIR,
) -> dict[str, Any]:
    evidence = _v57_evidence_status(output_dir)
    return {
        "ok": True,
        "version": V58_VERSION,
        "status": status,
        "enabled": enabled,
        "lifecycle_state": "shadow_observation",
        "candidate_contract": _public_contract(contract),
        "candidate_contract_matched": bool(contract.get("matched")),
        "schema_aware_abstention": public_schema_abstention_policy(),
        "independent_evidence": evidence,
        "blind_metrics_available": bool(
            evidence.get("blind_metrics_available")
        ),
        "rules_alert_authoritative": True,
        "model_only_alert_creation_allowed": False,
        "supervised_alert_suppression_allowed": False,
        "isolation_forest_advisory_only": True,
        "model_activated": False,
        "production_promoted": False,
        "response_automation_allowed": False,
        "real_firewall_blocking_enabled": False,
        "fallback_model_used": False,
        "labels_accessed": False,
        "raw_logs_included": False,
        "ip_addresses_included": False,
        "private_paths_included": False,
        "row_fingerprints_included": False,
        "secrets_exposed": False,
    }


def _select_logs(
    db: Session,
    *,
    source_id: int | None,
    start_at: datetime | None,
    end_at: datetime | None,
    limit: int,
) -> list[NormalizedLog]:
    event_time = func.coalesce(
        NormalizedLog.generated_time,
        NormalizedLog.receive_time,
        NormalizedLog.high_res_timestamp,
        NormalizedLog.start_time,
    )
    statement = (
        select(NormalizedLog)
        .join(RawLog, NormalizedLog.raw_log_id == RawLog.id)
        .options(
            joinedload(NormalizedLog.raw_log).joinedload(RawLog.source)
        )
        .order_by(event_time.asc(), NormalizedLog.id.asc())
        .limit(limit)
    )
    if source_id is not None:
        statement = statement.where(RawLog.source_id == source_id)
    if start_at is not None:
        statement = statement.where(event_time >= start_at)
    if end_at is not None:
        statement = statement.where(event_time <= end_at)
    return list(db.scalars(statement).unique())


def _top_reference_distance(
    baseline_rows: list[dict[str, Any]],
    current: Counter[str],
    *,
    baseline_total: int,
) -> float | None:
    current_total = sum(current.values())
    if baseline_total <= 0 or current_total <= 0:
        return None
    baseline = {
        str(row.get("value") or "unknown"): _integer(row.get("count"))
        for row in baseline_rows
    }
    keys = set(baseline)
    baseline_other = max(0, baseline_total - sum(baseline.values()))
    current_other = sum(
        count
        for key, count in current.items()
        if key not in keys
    )
    distance = 0.5 * sum(
        abs(
            (baseline.get(key, 0) / baseline_total)
            - (current.get(key, 0) / current_total)
        )
        for key in keys
    )
    distance += 0.5 * abs(
        (baseline_other / baseline_total)
        - (current_other / current_total)
    )
    return round(distance, 6)


def _shadow_drift(
    logs: list[NormalizedLog],
    feature_rows: list[dict[str, Any]],
    *,
    output_dir: Path = v57.OUTPUT_DIR,
) -> dict[str, Any]:
    del feature_rows
    # Imported lazily to avoid the v58 -> v512 -> v511 -> v59 -> v58
    # module cycle while keeping the parser baseline logic centralized.
    from atdr.app.services import v512_parser_baseline_service as v512

    parser_profiles: set[str] = set()
    source_types: set[str] = set()
    for log in logs:
        raw_log = getattr(log, "raw_log", None)
        source = getattr(raw_log, "source", None)
        parsed = log.parsed_json if isinstance(log.parsed_json, dict) else {}
        parser_profiles.add(
            str(
                getattr(source, "parser_profile", None)
                or parsed.get("parser_profile")
                or "palo_alto"
            )
            .strip()
            .lower()
        )
        source_types.add(
            str(getattr(source, "source_type", None) or "unscoped")
            .strip()
            .lower()
        )

    parser_profile = (
        next(iter(parser_profiles))
        if len(parser_profiles) == 1
        else "mixed"
    )
    source_type = (
        next(iter(source_types)) if len(source_types) == 1 else "mixed"
    )
    catalog = v512.build_governed_parser_baseline_catalog(
        report_path=output_dir / v56.V56_LATEST,
    )
    result = v512.evaluate_parser_profile_baseline(
        logs,
        parser_profile=parser_profile,
        source_type=source_type,
        catalog=catalog,
    )
    quality = result.get("quality") or {}
    quality["parser_warning_per_row"] = quality.get(
        "parser_structural_warning_per_row",
        0.0,
    )
    quality["unknown_app_rate"] = quality.get(
        "unresolved_application_rate",
        0.0,
    )
    result["quality"] = quality
    result["baseline_available"] = bool(catalog.get("available"))
    result["application_category_count"] = len(
        {
            str(log.app or "unknown").strip().lower() or "unknown"
            for log in logs
        }
    )
    result["schema_category_count"] = len(
        v512.parser_quality_from_logs(logs)["schemas"]
    )
    result["parser_contract_version"] = (
        v512.PARSER_CONTRACT_VERSION
    )
    result["private_identifiers_included"] = False
    return result


def _group_stability(
    groups: dict[Any, list[tuple[float, bool]]],
) -> dict[str, Any]:
    rows = [
        {
            "rows": len(values),
            "queue_rate": (
                sum(int(queued) for _, queued in values) / len(values)
            ),
            "mean_score": mean(score for score, _ in values),
        }
        for values in groups.values()
        if values
    ]
    queue_rates = [row["queue_rate"] for row in rows]
    mean_scores = [row["mean_score"] for row in rows]
    row_counts = [int(row["rows"]) for row in rows]
    return {
        "group_count": len(rows),
        "minimum_rows": min(row_counts) if row_counts else 0,
        "maximum_rows": max(row_counts) if row_counts else 0,
        "queue_rate_minimum": (
            round(min(queue_rates), 6) if queue_rates else None
        ),
        "queue_rate_mean": (
            round(mean(queue_rates), 6) if queue_rates else None
        ),
        "queue_rate_maximum": (
            round(max(queue_rates), 6) if queue_rates else None
        ),
        "mean_score_minimum": (
            round(min(mean_scores), 6) if mean_scores else None
        ),
        "mean_score_maximum": (
            round(max(mean_scores), 6) if mean_scores else None
        ),
        "group_identifiers_included": False,
    }


def _aggregate_shadow_telemetry(
    db: Session,
    logs: list[NormalizedLog],
    *,
    pipeline: Any,
    threshold: float,
    feature_names: list[str],
    output_dir: Path = v57.OUTPUT_DIR,
) -> dict[str, Any]:
    imports = _optional_imports()
    if imports is None:
        raise RuntimeError("optional_dependencies_unavailable")
    pandas = imports[1]
    compatibility = [assess_log_schema_compatibility(log) for log in logs]
    compatibility_summary = summarize_schema_compatibility(compatibility)
    compatible_positions = [
        position
        for position, assessment in enumerate(compatibility)
        if assessment["scoring_allowed"]
    ]
    compatible_logs = [logs[position] for position in compatible_positions]
    base_features = build_feature_rows(db, logs)
    compatible_base_features = [base_features[position] for position in compatible_positions]
    model_rows = [
        v56._human_feature_row(row, log)
        for row, log in zip(compatible_base_features, compatible_logs, strict=True)
    ]
    frame = pandas.DataFrame(model_rows).reindex(columns=feature_names)
    classes = [str(value) for value in pipeline.classes_]
    positive_index = classes.index("needs_review")
    probabilities = pipeline.predict_proba(frame) if compatible_logs else []
    queue_scores = [float(row[positive_index]) for row in probabilities]
    queued = [score >= threshold for score in queue_scores]
    confidence = [max(score, 1.0 - score) for score in queue_scores]

    context = build_detection_context(logs)
    agreement = Counter()
    source_groups: dict[Any, list[tuple[float, bool]]] = defaultdict(list)
    time_groups: dict[Any, list[tuple[float, bool]]] = defaultdict(list)
    anomaly_scores: list[float] = []
    anomaly_count = 0
    timestamps: list[datetime] = []
    for log, score, shadow_queue in zip(
        compatible_logs,
        queue_scores,
        queued,
        strict=True,
    ):
        rule_matches = [
            match
            for match in evaluate_rules(log, context)
            if match.code not in ADVISORY_RULE_CODES
        ]
        rule_score = min(100, sum(match.score for match in rule_matches))
        rule_queue = rule_score >= get_settings().min_alert_score
        key = (
            "both_queue"
            if rule_queue and shadow_queue
            else "rule_only"
            if rule_queue
            else "shadow_only"
            if shadow_queue
            else "neither"
        )
        agreement[key] += 1
        raw_log = getattr(log, "raw_log", None)
        source_key = getattr(raw_log, "source_id", None)
        source_groups[source_key].append((score, shadow_queue))
        timestamp = _utc(_event_time(log))
        time_key = timestamp.date().isoformat() if timestamp else "missing"
        time_groups[time_key].append((score, shadow_queue))
        if timestamp is not None:
            timestamps.append(timestamp)
        if bool(log.is_anomaly):
            anomaly_count += 1
        if log.anomaly_score is not None:
            anomaly_scores.append(float(log.anomaly_score))

    total = len(compatible_logs)
    disagreement_count = (
        agreement["rule_only"] + agreement["shadow_only"]
    )
    ordered = timestamps == sorted(timestamps)
    return {
        "rows_checked": len(logs),
        "rows_evaluated": total,
        "schema_compatibility": compatibility_summary,
        "queue_count": sum(int(value) for value in queued),
        "queue_rate": (
            round(sum(int(value) for value in queued) / total, 6)
            if total
            else 0.0
        ),
        "threshold": threshold,
        "score_summary": _numeric_summary(queue_scores),
        "score_distribution": _bucket_distribution(queue_scores),
        "confidence_summary": _numeric_summary(confidence),
        "confidence_distribution": _bucket_distribution(confidence),
        "missing_feature_values": int(frame.isna().sum().sum()),
        "feature_values_checked": int(frame.shape[0] * frame.shape[1]),
        "drift": _shadow_drift(
            logs,
            base_features,
            output_dir=output_dir,
        ),
        "source_stability": _group_stability(source_groups),
        "time_window_stability": _group_stability(time_groups),
        "chronology": {
            "ordered": ordered,
            "timestamped_rows": len(timestamps),
            "time_window_count": len(time_groups),
            "source_scope_preserved": True,
            "source_identifiers_included": False,
            "timestamps_included": False,
        },
        "rule_shadow_agreement": {
            "both_queue": agreement["both_queue"],
            "rule_only": agreement["rule_only"],
            "shadow_only": agreement["shadow_only"],
            "neither": agreement["neither"],
            "disagreement_count": disagreement_count,
            "disagreement_rate": (
                round(disagreement_count / total, 6)
                if total
                else 0.0
            ),
            "rule_threshold": get_settings().min_alert_score,
            "rules_alert_authoritative": True,
        },
        "isolation_forest": {
            "advisory_only": True,
            "persisted_anomaly_count": anomaly_count,
            "persisted_anomaly_rate": (
                round(anomaly_count / total, 6)
                if total
                else 0.0
            ),
            "persisted_score_rows": len(anomaly_scores),
            "persisted_score_summary": _numeric_summary(anomaly_scores),
            "new_isolation_scoring_performed": False,
            "alert_authority": False,
        },
        "accuracy_metrics_calculated": False,
        "labels_accessed": False,
        "raw_logs_included": False,
        "ip_addresses_included": False,
        "private_paths_included": False,
        "row_fingerprints_included": False,
    }


def governed_shadow_runtime_status(
    db: Session,
    *,
    execute: bool = True,
    source_id: int | None = None,
    start_at: datetime | None = None,
    end_at: datetime | None = None,
    limit: int | None = None,
    output_dir: Path = v57.OUTPUT_DIR,
) -> dict[str, Any]:
    settings = get_settings()
    enabled = bool(settings.governed_shadow_scoring_enabled)
    contract = inspect_frozen_candidate_contract(output_dir=output_dir)
    if not execute:
        return _base_status(
            enabled=enabled,
            contract=contract,
            status=(
                "ready_for_bounded_shadow_scoring"
                if enabled and contract.get("matched")
                else "disabled_by_configuration"
                if not enabled
                else "failed_closed_candidate_contract_mismatch"
            ),
            output_dir=output_dir,
        )
    if not enabled:
        return _base_status(
            enabled=False,
            contract=contract,
            status="disabled_by_configuration",
            output_dir=output_dir,
        )
    if not contract.get("matched"):
        value = _base_status(
            enabled=True,
            contract=contract,
            status="failed_closed_candidate_contract_mismatch",
            output_dir=output_dir,
        )
        value["ok"] = False
        return value

    configured_batch = int(settings.governed_shadow_batch_size)
    maximum_batch = int(settings.governed_shadow_max_batch_size)
    requested_limit = configured_batch if limit is None else int(limit)
    if (
        configured_batch < 1
        or maximum_batch < 1
        or configured_batch > maximum_batch
        or requested_limit < 1
        or requested_limit > maximum_batch
    ):
        value = _base_status(
            enabled=True,
            contract=contract,
            status="failed_closed_invalid_batch_limit",
            output_dir=output_dir,
        )
        value["ok"] = False
        value["operational_controls"] = {
            "requested_limit": requested_limit,
            "configured_batch_size": configured_batch,
            "maximum_batch_size": maximum_batch,
            "timeout_seconds": float(
                settings.governed_shadow_timeout_seconds
            ),
        }
        return value
    if (
        start_at is not None
        and end_at is not None
        and start_at > end_at
    ):
        value = _base_status(
            enabled=True,
            contract=contract,
            status="failed_closed_invalid_time_range",
            output_dir=output_dir,
        )
        value["ok"] = False
        return value

    started = time.perf_counter()
    timeout = max(
        0.001,
        float(settings.governed_shadow_timeout_seconds),
    )
    state_before = _database_state(db)
    active_artifacts_before = v55._model_artifact_states()
    candidate_before = contract.get("_artifact_state") or {}
    result = _base_status(
        enabled=True,
        contract=contract,
        status="evaluating",
        output_dir=output_dir,
    )
    try:
        logs = _select_logs(
            db,
            source_id=source_id,
            start_at=start_at,
            end_at=end_at,
            limit=requested_limit,
        )
        if time.perf_counter() - started > timeout:
            raise TimeoutError("shadow_selection_timeout")
        if not logs:
            result["status"] = "no_normalized_logs_in_scope"
            result["telemetry"] = {
                "rows_evaluated": 0,
                "accuracy_metrics_calculated": False,
                "labels_accessed": False,
            }
        else:
            cache_key = _stable_hash(
                {
                    "artifact": contract.get("_artifact_sha256"),
                    "log_ids": [int(log.id) for log in logs],
                    "source_scoped": source_id is not None,
                    "start_at": start_at,
                    "end_at": end_at,
                    "limit": requested_limit,
                    "threshold": contract.get("threshold"),
                }
            )
            cached: dict[str, Any] | None = None
            now = time.monotonic()
            with _cache_lock:
                entry = _shadow_cache.get(cache_key)
                if (
                    entry
                    and now - entry[0]
                    <= max(
                        0,
                        int(settings.governed_shadow_cache_seconds),
                    )
                ):
                    cached = copy.deepcopy(entry[1])
            if cached is not None:
                telemetry = cached
                cache_hit = True
            else:
                telemetry = _aggregate_shadow_telemetry(
                    db,
                    logs,
                    pipeline=contract["_pipeline"],
                    threshold=float(contract["threshold"]),
                    feature_names=list(contract["_feature_names"]),
                    output_dir=output_dir,
                )
                if time.perf_counter() - started > timeout:
                    raise TimeoutError("shadow_scoring_timeout")
                with _cache_lock:
                    _shadow_cache[cache_key] = (
                        time.monotonic(),
                        copy.deepcopy(telemetry),
                    )
                    while len(_shadow_cache) > 16:
                        oldest = min(
                            _shadow_cache,
                            key=lambda key: _shadow_cache[key][0],
                        )
                        del _shadow_cache[oldest]
                cache_hit = False
            result["status"] = "evaluated_shadow_read_only"
            result["telemetry"] = telemetry
            result["idempotency"] = {
                "deterministic_scope": True,
                "cache_hit": cache_hit,
                "persistent_record_written": False,
                "evaluation_identifier_exposed": False,
            }
    except TimeoutError as exc:
        result["ok"] = False
        result["status"] = "failed_closed_timeout"
        result["error_type"] = exc.__class__.__name__
        result.pop("telemetry", None)
    except (
        OSError,
        ValueError,
        TypeError,
        KeyError,
        AttributeError,
        RuntimeError,
    ) as exc:
        result["ok"] = False
        result["status"] = "failed_closed_shadow_scoring_error"
        result["error_type"] = exc.__class__.__name__
        result.pop("telemetry", None)

    state_after = _database_state(db)
    active_artifacts_after = v55._model_artifact_states()
    artifact_path = contract.get("_artifact_path")
    candidate_after = (
        v55._file_state(artifact_path)
        if isinstance(artifact_path, Path)
        else {}
    )
    safety = {
        "configured_database_unchanged": state_before == state_after,
        "active_model_artifacts_unchanged": (
            active_artifacts_before == active_artifacts_after
        ),
        "frozen_candidate_artifact_unchanged": (
            candidate_before == candidate_after
        ),
        "raw_logs_created": (
            state_after["raw_logs"] - state_before["raw_logs"]
        ),
        "normalized_logs_created": (
            state_after["normalized_logs"]
            - state_before["normalized_logs"]
        ),
        "alerts_created": (
            state_after["alerts"] - state_before["alerts"]
        ),
        "alert_evidence_created": (
            state_after["alert_evidence"]
            - state_before["alert_evidence"]
        ),
        "labels_created": (
            state_after["ml_labels"] - state_before["ml_labels"]
        ),
        "model_runs_created": (
            state_after["ml_model_runs"]
            - state_before["ml_model_runs"]
        ),
        "detection_runs_created": (
            state_after["detection_runs"]
            - state_before["detection_runs"]
        ),
        "response_actions_created": (
            state_after["response_actions"]
            - state_before["response_actions"]
        ),
        "model_activated": False,
        "production_promoted": False,
        "response_automation_allowed": False,
        "rules_alert_authoritative": True,
    }
    mutation_free = bool(
        safety["configured_database_unchanged"]
        and safety["active_model_artifacts_unchanged"]
        and safety["frozen_candidate_artifact_unchanged"]
        and all(
            safety[key] == 0
            for key in (
                "raw_logs_created",
                "normalized_logs_created",
                "alerts_created",
                "alert_evidence_created",
                "labels_created",
                "model_runs_created",
                "detection_runs_created",
                "response_actions_created",
            )
        )
    )
    result["safety"] = safety
    result["operational_controls"] = {
        "requested_limit": requested_limit,
        "configured_batch_size": configured_batch,
        "maximum_batch_size": maximum_batch,
        "timeout_seconds": timeout,
        "source_filter_applied": source_id is not None,
        "time_filter_applied": (
            start_at is not None or end_at is not None
        ),
        "read_only": True,
    }
    result["runtime_seconds"] = round(time.perf_counter() - started, 6)
    if not mutation_free:
        result["ok"] = False
        result["status"] = "failed_closed_mutation_detected"
    return result


def governed_evidence_intake_preflight(
    db: Session,
    *,
    sample_path: str | Path,
    evidence_manifest_path: str | Path,
    min_samples: int = 100,
    chunk_size: int = 2000,
    output_dir: Path = v57.OUTPUT_DIR,
) -> dict[str, Any]:
    state_before = _database_state(db)
    active_artifacts_before = v55._model_artifact_states()
    try:
        base = v57.run_v57_independent_shadow_revalidation(
            db,
            sample_path=sample_path,
            evidence_manifest_path=evidence_manifest_path,
            output_dir=output_dir,
            min_samples=min_samples,
            chunk_size=chunk_size,
            preflight_only=True,
            write_output=False,
        )
        sample_sha = v57._file_sha256(Path(sample_path))
        prior_freeze = v57._safe_json(
            output_dir / v57.V57_PREDICTION_FREEZE
        )
        prior_sample_sha = (
            prior_freeze.get("sample_sha256")
            or prior_freeze.get("evidence_sample_sha256")
        )
        reused_v57_prediction_evidence = bool(
            sample_sha
            and prior_sample_sha
            and sample_sha == prior_sample_sha
        )
        qualification = base.get("independent_evidence") or {}
        checks = dict(qualification.get("checks") or {})
        checks["not_reused_v57_prediction_evidence"] = not (
            reused_v57_prediction_evidence
        )
        eligible = bool(
            qualification.get("eligible_for_predictions")
            and all(checks.values())
        )
        blockers = [
            key.replace("_", " ")
            for key, passed in checks.items()
            if not passed
        ]
        result = {
            "ok": bool(base.get("ok")),
            "version": V58_VERSION,
            "status": (
                "evidence_intake_ready_for_prediction_freeze"
                if eligible
                else "independent_evidence_required"
            ),
            "eligible_for_prediction_freeze": eligible,
            "checks": checks,
            "blockers": blockers,
            "sample_profile": {
                "status": (base.get("sample_profile") or {}).get(
                    "status"
                ),
                "rows_processed": (base.get("sample_profile") or {}).get(
                    "rows_processed"
                ),
                "parser_successes": (
                    base.get("sample_profile") or {}
                ).get("parser_successes"),
                "parser_failures": (
                    base.get("sample_profile") or {}
                ).get("parser_failures"),
                "configured_database_overlap_rows": (
                    base.get("sample_profile") or {}
                ).get("configured_database_overlap_rows"),
                "exact_duplicate_rows": (
                    base.get("sample_profile") or {}
                ).get("exact_duplicate_rows"),
                "near_duplicate_rows": (
                    base.get("sample_profile") or {}
                ).get("near_duplicate_rows"),
            },
            "source_device_count": qualification.get(
                "source_device_count"
            ),
            "independent_time_window_count": qualification.get(
                "independent_time_window_count"
            ),
            "reused_v5_3_v5_6_evidence_rejected": not bool(
                qualification.get("eligible_for_predictions")
            )
            if (
                (base.get("sample_profile") or {}).get(
                    "matches_reused_v56_evidence"
                )
            )
            else True,
            "reused_v5_7_prediction_evidence_rejected": not (
                reused_v57_prediction_evidence
            ),
            "blind_metrics_calculated": False,
            "labels_accessed": False,
            "predictions_written": False,
            "prediction_freeze_replaced": False,
            "lifecycle_state": "shadow_observation",
            "rules_alert_authoritative": True,
            "model_activated": False,
            "production_promoted": False,
            "response_automation_allowed": False,
            "raw_logs_included": False,
            "ip_addresses_included": False,
            "private_paths_included": False,
            "row_fingerprints_included": False,
            "file_hashes_exposed": False,
            "secrets_exposed": False,
        }
    except (
        OSError,
        ValueError,
        TypeError,
        KeyError,
        AttributeError,
        RuntimeError,
    ) as exc:
        result = {
            "ok": False,
            "version": V58_VERSION,
            "status": "failed_closed_evidence_preflight_error",
            "error_type": exc.__class__.__name__,
            "eligible_for_prediction_freeze": False,
            "blind_metrics_calculated": False,
            "labels_accessed": False,
            "model_activated": False,
            "response_automation_allowed": False,
            "private_paths_included": False,
            "secrets_exposed": False,
        }
    state_after = _database_state(db)
    active_artifacts_after = v55._model_artifact_states()
    result["safety"] = {
        "configured_database_unchanged": state_before == state_after,
        "active_model_artifacts_unchanged": (
            active_artifacts_before == active_artifacts_after
        ),
        "labels_created": (
            state_after["ml_labels"] - state_before["ml_labels"]
        ),
        "model_runs_created": (
            state_after["ml_model_runs"]
            - state_before["ml_model_runs"]
        ),
        "detection_runs_created": (
            state_after["detection_runs"]
            - state_before["detection_runs"]
        ),
        "alerts_created": (
            state_after["alerts"] - state_before["alerts"]
        ),
        "response_actions_created": (
            state_after["response_actions"]
            - state_before["response_actions"]
        ),
    }
    if not all(
        (
            result["safety"]["configured_database_unchanged"],
            result["safety"]["active_model_artifacts_unchanged"],
            result["safety"]["labels_created"] == 0,
            result["safety"]["model_runs_created"] == 0,
            result["safety"]["detection_runs_created"] == 0,
            result["safety"]["alerts_created"] == 0,
            result["safety"]["response_actions_created"] == 0,
        )
    ):
        result["ok"] = False
        result["status"] = "failed_closed_mutation_detected"
    return result
