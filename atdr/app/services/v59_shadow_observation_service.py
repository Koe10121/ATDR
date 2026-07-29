from __future__ import annotations

import hashlib
import json
from collections import Counter
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from pathlib import Path
from statistics import mean
from typing import Any

from sqlalchemy import delete, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from atdr.app.core.config import get_settings
from atdr.app.db.models import AuditLog, MLShadowObservation
from atdr.app.detection.v54_temporal_evidence import (
    inspect_private_temporal_regimes,
)
from atdr.app.services import v58_shadow_scoring_service as v58


V59_VERSION = "v5.9-longitudinal-shadow-observation-v1"
DRIFT_STATES = {
    "Stable",
    "Drift Warning",
    "OOD Warning",
    "Insufficient Evidence",
}


def _utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _iso(value: datetime | None) -> str | None:
    normalized = _utc(value)
    return normalized.isoformat() if normalized is not None else None


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


def _stable_hash(value: Any) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        default=str,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _contract_fingerprint(contract: dict[str, Any]) -> str:
    return _stable_hash(
        {
            "artifact": contract.get("_artifact_sha256"),
            "candidate_name": contract.get("candidate_name"),
            "candidate_version": contract.get("candidate_version"),
            "model_type": contract.get("model_type"),
            "calibration_method": contract.get("calibration_method"),
            "threshold": contract.get("threshold"),
            "feature_count": contract.get("feature_count"),
            "matched": bool(contract.get("matched")),
        }
    )


def _observed_window(logs: list[Any]) -> tuple[datetime | None, datetime | None]:
    timestamps = [
        _utc(v58._event_time(log))
        for log in logs
        if v58._event_time(log) is not None
    ]
    values = [value for value in timestamps if value is not None]
    return (
        min(values) if values else None,
        max(values) if values else None,
    )


def _observation_key(
    *,
    contract_fingerprint: str,
    candidate_name: str,
    candidate_version: str,
    source_id: int | None,
    window_start: datetime | None,
    window_end: datetime | None,
    requested_limit: int,
) -> str:
    return _stable_hash(
        {
            "contract_fingerprint": contract_fingerprint,
            "candidate_name": candidate_name,
            "candidate_version": candidate_version,
            "source_id": source_id,
            "window_start": _iso(window_start),
            "window_end": _iso(window_end),
            "requested_limit": requested_limit,
        }
    )


def _safe_numeric_summary(value: Any) -> dict[str, float | None]:
    source = value if isinstance(value, dict) else {}
    return {
        key: (
            None
            if source.get(key) is None
            else round(_number(source.get(key)), 6)
        )
        for key in ("minimum", "mean", "p50", "p95", "maximum")
    }


def _safe_distribution(value: Any) -> list[dict[str, Any]]:
    rows = value if isinstance(value, list) else []
    return [
        {
            "bucket": str(row.get("bucket") or "")[:32],
            "count": max(0, _integer(row.get("count"))),
            "rate": round(max(0.0, min(1.0, _number(row.get("rate")))), 6),
        }
        for row in rows[:20]
        if isinstance(row, dict)
    ]


def _safe_stability(value: Any) -> dict[str, Any]:
    source = value if isinstance(value, dict) else {}
    return {
        "group_count": max(0, _integer(source.get("group_count"))),
        "minimum_rows": max(0, _integer(source.get("minimum_rows"))),
        "maximum_rows": max(0, _integer(source.get("maximum_rows"))),
        "queue_rate_minimum": source.get("queue_rate_minimum"),
        "queue_rate_mean": source.get("queue_rate_mean"),
        "queue_rate_maximum": source.get("queue_rate_maximum"),
        "mean_score_minimum": source.get("mean_score_minimum"),
        "mean_score_maximum": source.get("mean_score_maximum"),
        "group_identifiers_included": False,
    }


def _safe_telemetry(value: Any) -> dict[str, Any]:
    source = value if isinstance(value, dict) else {}
    drift = source.get("drift") if isinstance(source.get("drift"), dict) else {}
    quality = drift.get("quality") if isinstance(drift.get("quality"), dict) else {}
    quality_delta = (
        drift.get("quality_absolute_delta")
        if isinstance(drift.get("quality_absolute_delta"), dict)
        else {}
    )
    agreement = (
        source.get("rule_shadow_agreement")
        if isinstance(source.get("rule_shadow_agreement"), dict)
        else {}
    )
    isolation = (
        source.get("isolation_forest")
        if isinstance(source.get("isolation_forest"), dict)
        else {}
    )
    drift_status = str(drift.get("status") or "Insufficient Evidence")
    if drift_status not in DRIFT_STATES:
        drift_status = "Insufficient Evidence"
    return {
        "rows_evaluated": max(0, _integer(source.get("rows_evaluated"))),
        "queue_count": max(0, _integer(source.get("queue_count"))),
        "queue_rate": round(
            max(0.0, min(1.0, _number(source.get("queue_rate")))),
            6,
        ),
        "score_summary": _safe_numeric_summary(source.get("score_summary")),
        "score_distribution": _safe_distribution(
            source.get("score_distribution")
        ),
        "confidence_summary": _safe_numeric_summary(
            source.get("confidence_summary")
        ),
        "confidence_distribution": _safe_distribution(
            source.get("confidence_distribution")
        ),
        "missing_feature_values": max(
            0,
            _integer(source.get("missing_feature_values")),
        ),
        "feature_values_checked": max(
            0,
            _integer(source.get("feature_values_checked")),
        ),
        "drift": {
            "status": drift_status,
            "rows_evaluated": max(
                0,
                _integer(drift.get("rows_evaluated")),
            ),
            "application_total_variation": drift.get(
                "application_total_variation"
            ),
            "schema_total_variation": drift.get(
                "schema_total_variation"
            ),
            "quality": {
                key: quality.get(key)
                for key in (
                    "parser_error_rate",
                    "parser_warning_per_row",
                    "parser_structural_warning_per_row",
                    "required_missing_per_row",
                    "unknown_app_rate",
                    "unresolved_application_rate",
                )
            },
            "quality_absolute_delta": {
                key: quality_delta.get(key)
                for key in (
                    "parser_error_rate",
                    "parser_warning_per_row",
                    "parser_structural_warning_per_row",
                    "required_missing_per_row",
                    "unknown_app_rate",
                    "unresolved_application_rate",
                )
            },
            "baseline_selection": {
                key: (drift.get("baseline_selection") or {}).get(key)
                for key in (
                    "status",
                    "scope",
                    "comparable",
                    "parser_profile",
                    "source_type",
                    "support_rows",
                )
            },
            "parser_contract_version": drift.get(
                "parser_contract_version"
            ),
            "compatibility_status_counts": dict(
                drift.get("compatibility_status_counts") or {}
            ),
            "application_resolution_counts": dict(
                drift.get("application_resolution_counts") or {}
            ),
            "root_cause_codes": [
                str(value)
                for value in drift.get("root_cause_codes") or []
            ],
            "application_category_count": max(
                0,
                _integer(drift.get("application_category_count")),
            ),
            "schema_category_count": max(
                0,
                _integer(drift.get("schema_category_count")),
            ),
            "raw_logs_included": False,
            "private_identifiers_included": False,
        },
        "source_stability": _safe_stability(
            source.get("source_stability")
        ),
        "time_window_stability": _safe_stability(
            source.get("time_window_stability")
        ),
        "rule_shadow_agreement": {
            "both_queue": max(0, _integer(agreement.get("both_queue"))),
            "rule_only": max(0, _integer(agreement.get("rule_only"))),
            "shadow_only": max(0, _integer(agreement.get("shadow_only"))),
            "neither": max(0, _integer(agreement.get("neither"))),
            "disagreement_count": max(
                0,
                _integer(agreement.get("disagreement_count")),
            ),
            "disagreement_rate": round(
                max(
                    0.0,
                    min(1.0, _number(agreement.get("disagreement_rate"))),
                ),
                6,
            ),
            "rules_alert_authoritative": True,
        },
        "isolation_forest": {
            "advisory_only": True,
            "persisted_anomaly_count": max(
                0,
                _integer(isolation.get("persisted_anomaly_count")),
            ),
            "persisted_anomaly_rate": round(
                max(
                    0.0,
                    min(
                        1.0,
                        _number(isolation.get("persisted_anomaly_rate")),
                    ),
                ),
                6,
            ),
            "persisted_score_rows": max(
                0,
                _integer(isolation.get("persisted_score_rows")),
            ),
            "persisted_score_summary": _safe_numeric_summary(
                isolation.get("persisted_score_summary")
            ),
            "new_isolation_scoring_performed": False,
            "alert_authority": False,
        },
        "accuracy_metrics_calculated": False,
        "labels_accessed": False,
        "raw_logs_included": False,
        "ip_addresses_included": False,
        "private_paths_included": False,
        "row_fingerprints_included": False,
        "secrets_exposed": False,
    }


def shadow_observation_to_dict(
    observation: MLShadowObservation,
    *,
    include_aggregate: bool = True,
) -> dict[str, Any]:
    value = {
        "observation_id": int(observation.id),
        "candidate_name": observation.candidate_name,
        "candidate_version": observation.candidate_version,
        "status": observation.status,
        "contract_matched": bool(observation.contract_matched),
        "window_start": observation.window_start,
        "window_end": observation.window_end,
        "observed_start": observation.observed_start,
        "observed_end": observation.observed_end,
        "requested_limit": int(observation.requested_limit),
        "rows_evaluated": int(observation.rows_evaluated),
        "queue_count": int(observation.queue_count),
        "queue_rate": float(observation.queue_rate),
        "score_mean": observation.score_mean,
        "score_p95": observation.score_p95,
        "confidence_mean": observation.confidence_mean,
        "confidence_p95": observation.confidence_p95,
        "drift_status": observation.drift_status,
        "application_total_variation": (
            observation.application_total_variation
        ),
        "schema_total_variation": observation.schema_total_variation,
        "disagreement_count": int(observation.disagreement_count),
        "disagreement_rate": float(observation.disagreement_rate),
        "isolation_anomaly_count": int(
            observation.isolation_anomaly_count
        ),
        "isolation_anomaly_rate": float(
            observation.isolation_anomaly_rate
        ),
        "runtime_seconds": observation.runtime_seconds,
        "failure_code": observation.failure_code,
        "created_at": observation.created_at,
        "accuracy_metrics_calculated": False,
        "labels_accessed": False,
        "raw_logs_included": False,
        "ip_addresses_included": False,
        "private_paths_included": False,
        "fingerprints_included": False,
        "source_identifiers_included": False,
        "secrets_exposed": False,
    }
    if include_aggregate:
        value["aggregate"] = dict(observation.aggregate_json or {})
    return value


def _disabled_result(status: str) -> dict[str, Any]:
    settings = get_settings()
    return {
        "ok": True,
        "version": V59_VERSION,
        "status": status,
        "observation_enabled": bool(
            settings.governed_shadow_observation_enabled
        ),
        "shadow_scoring_enabled": bool(
            settings.governed_shadow_scoring_enabled
        ),
        "observation_created": False,
        "lifecycle_state": "shadow_observation",
        "rules_alert_authoritative": True,
        "model_activated": False,
        "production_promoted": False,
        "response_automation_allowed": False,
        "real_firewall_blocking_enabled": False,
        "raw_logs_included": False,
        "private_paths_included": False,
        "fingerprints_included": False,
        "secrets_exposed": False,
    }


def record_governed_shadow_observation(
    db: Session,
    *,
    actor: str,
    source_id: int | None = None,
    start_at: datetime | None = None,
    end_at: datetime | None = None,
    limit: int | None = None,
    output_dir: Path = v58.v57.OUTPUT_DIR,
    should_stop: Callable[[], bool] | None = None,
) -> dict[str, Any]:
    settings = get_settings()
    if not settings.governed_shadow_observation_enabled:
        return _disabled_result("observation_disabled_by_configuration")
    if not settings.governed_shadow_scoring_enabled:
        return _disabled_result("shadow_scoring_disabled_by_configuration")

    effective_limit = int(
        settings.governed_shadow_batch_size
        if limit is None
        else limit
    )
    if (
        effective_limit < 1
        or effective_limit > int(settings.governed_shadow_max_batch_size)
    ):
        result = _disabled_result("failed_closed_invalid_batch_limit")
        result["ok"] = False
        return result
    if start_at is not None and end_at is not None and start_at > end_at:
        result = _disabled_result("failed_closed_invalid_time_range")
        result["ok"] = False
        return result
    if should_stop is not None and should_stop():
        return _disabled_result("cancelled_before_shadow_scoring")

    contract = v58.inspect_frozen_candidate_contract(
        output_dir=output_dir
    )
    candidate_name = str(
        contract.get("candidate_name")
        or "frozen_diagnostic_candidate"
    )
    candidate_version = str(
        contract.get("candidate_version")
        or v58.v56.V56_VERSION
    )
    fingerprint = _contract_fingerprint(contract)
    logs = v58._select_logs(
        db,
        source_id=source_id,
        start_at=start_at,
        end_at=end_at,
        limit=effective_limit,
    )
    observed_start, observed_end = _observed_window(logs)
    effective_start = _utc(start_at) or observed_start
    effective_end = _utc(end_at) or observed_end
    observation_key = _observation_key(
        contract_fingerprint=fingerprint,
        candidate_name=candidate_name,
        candidate_version=candidate_version,
        source_id=source_id,
        window_start=effective_start,
        window_end=effective_end,
        requested_limit=effective_limit,
    )
    existing = db.scalar(
        select(MLShadowObservation).where(
            MLShadowObservation.observation_key == observation_key
        )
    )
    if existing is not None:
        return {
            **_disabled_result("observation_already_recorded"),
            "observation_enabled": True,
            "shadow_scoring_enabled": True,
            "idempotent_reuse": True,
            "observation": shadow_observation_to_dict(existing),
        }

    authoritative_before = v58._database_state(db)
    runtime = v58.governed_shadow_runtime_status(
        db,
        execute=True,
        source_id=source_id,
        start_at=start_at,
        end_at=end_at,
        limit=effective_limit,
        output_dir=output_dir,
    )
    if should_stop is not None and should_stop():
        return {
            **_disabled_result("cancelled_before_observation_persist"),
            "observation_enabled": True,
            "shadow_scoring_enabled": True,
            "shadow_runtime_completed": bool(runtime.get("ok")),
        }

    telemetry = _safe_telemetry(runtime.get("telemetry"))
    runtime_safety = (
        runtime.get("safety")
        if isinstance(runtime.get("safety"), dict)
        else {}
    )
    runtime_authoritative_unchanged = (
        authoritative_before == v58._database_state(db)
    )
    telemetry["operational_contract"] = {
        "schema_version": "v5.10-operational-observation-v1",
        "evidence_role": "reused_development_operational_evidence_only",
        "independent_validation": False,
        "authoritative_state_unchanged": (
            runtime_authoritative_unchanged
        ),
        "authoritative_mutations": {
            "alerts": _integer(runtime_safety.get("alerts_created")),
            "alert_evidence": _integer(
                runtime_safety.get("alert_evidence_created")
            ),
            "labels": _integer(runtime_safety.get("labels_created")),
            "model_runs": _integer(
                runtime_safety.get("model_runs_created")
            ),
            "detection_runs": _integer(
                runtime_safety.get("detection_runs_created")
            ),
            "response_actions": _integer(
                runtime_safety.get("response_actions_created")
            ),
        },
        "private_data_exposed": False,
        "source_identifier_included": False,
        "locked_evidence_used_for_selection": False,
    }
    drift = telemetry["drift"]
    agreement = telemetry["rule_shadow_agreement"]
    isolation = telemetry["isolation_forest"]
    score_summary = telemetry["score_summary"]
    confidence_summary = telemetry["confidence_summary"]
    observation = MLShadowObservation(
        observation_key=observation_key,
        candidate_name=candidate_name,
        candidate_version=candidate_version,
        contract_fingerprint=fingerprint,
        status=str(runtime.get("status") or "failed_closed_unknown"),
        contract_matched=bool(runtime.get("candidate_contract_matched")),
        source_id=source_id,
        window_start=effective_start,
        window_end=effective_end,
        observed_start=observed_start,
        observed_end=observed_end,
        requested_limit=effective_limit,
        rows_evaluated=int(telemetry["rows_evaluated"]),
        queue_count=int(telemetry["queue_count"]),
        queue_rate=float(telemetry["queue_rate"]),
        score_mean=score_summary.get("mean"),
        score_p95=score_summary.get("p95"),
        confidence_mean=confidence_summary.get("mean"),
        confidence_p95=confidence_summary.get("p95"),
        missing_feature_values=int(
            telemetry["missing_feature_values"]
        ),
        feature_values_checked=int(
            telemetry["feature_values_checked"]
        ),
        drift_status=str(drift["status"]),
        application_total_variation=drift.get(
            "application_total_variation"
        ),
        schema_total_variation=drift.get(
            "schema_total_variation"
        ),
        rule_both_queue=int(agreement["both_queue"]),
        rule_only=int(agreement["rule_only"]),
        shadow_only=int(agreement["shadow_only"]),
        neither_queue=int(agreement["neither"]),
        disagreement_count=int(agreement["disagreement_count"]),
        disagreement_rate=float(agreement["disagreement_rate"]),
        isolation_anomaly_count=int(
            isolation["persisted_anomaly_count"]
        ),
        isolation_anomaly_rate=float(
            isolation["persisted_anomaly_rate"]
        ),
        runtime_seconds=runtime.get("runtime_seconds"),
        failure_code=(
            None
            if runtime.get("ok")
            else str(runtime.get("status") or "shadow_runtime_failed")[:64]
        ),
        aggregate_json=telemetry,
        created_by=actor.strip()[:128] or "shadow-observation",
    )
    db.add(observation)
    try:
        db.commit()
        db.refresh(observation)
        created = True
    except IntegrityError:
        db.rollback()
        observation = db.scalar(
            select(MLShadowObservation).where(
                MLShadowObservation.observation_key == observation_key
            )
        )
        if observation is None:
            raise
        created = False

    authoritative_after = v58._database_state(db)
    mutation_free = bool(
        authoritative_before == authoritative_after
        and runtime_safety.get(
            "active_model_artifacts_unchanged",
            True,
        )
        and runtime_safety.get(
            "frozen_candidate_artifact_unchanged",
            True,
        )
        and all(
            _integer(runtime_safety.get(key)) == 0
            for key in (
                "alerts_created",
                "alert_evidence_created",
                "labels_created",
                "model_runs_created",
                "detection_runs_created",
                "response_actions_created",
            )
        )
    )
    return {
        "ok": bool(runtime.get("ok")) and mutation_free,
        "version": V59_VERSION,
        "status": (
            "shadow_observation_recorded"
            if created
            else "observation_already_recorded"
        ),
        "observation_enabled": True,
        "shadow_scoring_enabled": True,
        "observation_created": created,
        "idempotent_reuse": not created,
        "observation": shadow_observation_to_dict(observation),
        "safety": {
            "authoritative_database_state_unchanged": (
                authoritative_before == authoritative_after
            ),
            "aggregate_observation_rows_created": int(created),
            "active_model_artifacts_unchanged": runtime_safety.get(
                "active_model_artifacts_unchanged",
                True,
            ),
            "frozen_candidate_artifact_unchanged": runtime_safety.get(
                "frozen_candidate_artifact_unchanged",
                True,
            ),
            "alerts_created": _integer(
                runtime_safety.get("alerts_created")
            ),
            "alert_evidence_created": _integer(
                runtime_safety.get("alert_evidence_created")
            ),
            "labels_created": _integer(
                runtime_safety.get("labels_created")
            ),
            "model_runs_created": _integer(
                runtime_safety.get("model_runs_created")
            ),
            "detection_runs_created": _integer(
                runtime_safety.get("detection_runs_created")
            ),
            "response_actions_created": _integer(
                runtime_safety.get("response_actions_created")
            ),
        },
        "lifecycle_state": "shadow_observation",
        "rules_alert_authoritative": True,
        "model_activated": False,
        "production_promoted": False,
        "response_automation_allowed": False,
        "real_firewall_blocking_enabled": False,
        "accuracy_metrics_calculated": False,
        "labels_accessed": False,
        "raw_logs_included": False,
        "private_paths_included": False,
        "fingerprints_included": False,
        "secrets_exposed": False,
    }


def list_shadow_observations(
    db: Session,
    *,
    source_id: int | None = None,
    since: datetime | None = None,
    drift_status: str | None = None,
    limit: int = 30,
) -> list[dict[str, Any]]:
    statement = select(MLShadowObservation)
    if source_id is not None:
        statement = statement.where(
            MLShadowObservation.source_id == source_id
        )
    if since is not None:
        statement = statement.where(
            MLShadowObservation.created_at >= since
        )
    if drift_status:
        statement = statement.where(
            MLShadowObservation.drift_status == drift_status
        )
    rows = list(
        db.scalars(
            statement.order_by(
                MLShadowObservation.created_at.desc(),
                MLShadowObservation.id.desc(),
            ).limit(max(1, min(int(limit), 365)))
        )
    )
    return [
        shadow_observation_to_dict(row, include_aggregate=False)
        for row in rows
    ]


def shadow_observation_summary(
    db: Session,
    *,
    source_id: int | None = None,
    since: datetime | None = None,
    limit: int | None = None,
) -> dict[str, Any]:
    settings = get_settings()
    effective_limit = (
        int(settings.governed_shadow_observation_trend_limit)
        if limit is None
        else max(1, min(int(limit), 365))
    )
    filters = []
    if source_id is not None:
        filters.append(
            MLShadowObservation.source_id == source_id
        )
    if since is not None:
        filters.append(
            MLShadowObservation.created_at >= since
        )
    total_count = int(
        db.scalar(
            select(func.count())
            .select_from(MLShadowObservation)
            .where(*filters)
        )
        or 0
    )
    statement = select(MLShadowObservation).where(*filters)
    rows = list(
        db.scalars(
            statement.order_by(
                MLShadowObservation.created_at.desc(),
                MLShadowObservation.id.desc(),
            ).limit(effective_limit)
        )
    )
    chronological = list(reversed(rows))
    drift_counts = Counter(row.drift_status for row in rows)
    status_counts = Counter(row.status for row in rows)
    queue_rates = [float(row.queue_rate) for row in rows]
    disagreement_rates = [
        float(row.disagreement_rate)
        for row in rows
    ]
    # The summary needs only the locked evidence status. Loading the frozen
    # model contract here made a read-only dashboard request pay model
    # deserialization cost even when no observation was executed.
    independent = v58._v57_evidence_status()
    return {
        "ok": True,
        "version": V59_VERSION,
        "status": (
            "longitudinal_observations_available"
            if rows
            else "no_longitudinal_observations"
        ),
        "observation_enabled": bool(
            settings.governed_shadow_observation_enabled
        ),
        "shadow_scoring_enabled": bool(
            settings.governed_shadow_scoring_enabled
        ),
        "observation_count": total_count,
        "trend_count": len(rows),
        "source_filter_applied": source_id is not None,
        "since_filter_applied": since is not None,
        "latest": (
            shadow_observation_to_dict(
                rows[0],
                include_aggregate=False,
            )
            if rows
            else None
        ),
        "trend": [
            shadow_observation_to_dict(
                row,
                include_aggregate=False,
            )
            for row in chronological
        ],
        "drift_status_counts": dict(sorted(drift_counts.items())),
        "runtime_status_counts": dict(sorted(status_counts.items())),
        "queue_rate": {
            "minimum": min(queue_rates) if queue_rates else None,
            "mean": round(mean(queue_rates), 6)
            if queue_rates
            else None,
            "maximum": max(queue_rates) if queue_rates else None,
        },
        "rule_disagreement_rate": {
            "minimum": min(disagreement_rates)
            if disagreement_rates
            else None,
            "mean": round(mean(disagreement_rates), 6)
            if disagreement_rates
            else None,
            "maximum": max(disagreement_rates)
            if disagreement_rates
            else None,
        },
        "independent_evidence": {
            "status": independent.get(
                "status",
                "independent_evidence_required",
            ),
            "qualified": bool(independent.get("qualified")),
            "source_device_count": independent.get(
                "source_device_count"
            ),
            "independent_time_window_count": independent.get(
                "independent_time_window_count"
            ),
            "blind_metrics_available": bool(
                independent.get("blind_metrics_available")
            ),
        },
        "retention": {
            "retention_days": int(
                settings.governed_shadow_observation_retention_days
            ),
            "automatic_cleanup_enabled": False,
            "append_only_between_explicit_retention_runs": True,
        },
        "lifecycle_state": "shadow_observation",
        "rules_alert_authoritative": True,
        "model_activated": False,
        "production_promoted": False,
        "response_automation_allowed": False,
        "real_firewall_blocking_enabled": False,
        "accuracy_metrics_calculated": False,
        "labels_accessed": False,
        "raw_logs_included": False,
        "private_paths_included": False,
        "fingerprints_included": False,
        "secrets_exposed": False,
    }


def preview_shadow_observation_retention(
    db: Session,
    *,
    older_than_days: int | None = None,
) -> dict[str, Any]:
    settings = get_settings()
    days = max(
        1,
        int(
            older_than_days
            or settings.governed_shadow_observation_retention_days
        ),
    )
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    candidate_count = int(
        db.scalar(
            select(func.count())
            .select_from(MLShadowObservation)
            .where(MLShadowObservation.created_at < cutoff)
        )
        or 0
    )
    return {
        "ok": True,
        "status": "retention_preview",
        "retention_days": days,
        "candidate_count": candidate_count,
        "cutoff": cutoff,
        "automatic_cleanup_enabled": False,
        "raw_evidence_affected": False,
        "labels_affected": False,
        "alerts_affected": False,
        "model_artifacts_affected": False,
        "response_actions_affected": False,
    }


def prune_shadow_observations(
    db: Session,
    *,
    actor: str,
    older_than_days: int | None = None,
    limit: int = 1000,
) -> dict[str, Any]:
    preview = preview_shadow_observation_retention(
        db,
        older_than_days=older_than_days,
    )
    ids = list(
        db.scalars(
            select(MLShadowObservation.id)
            .where(
                MLShadowObservation.created_at < preview["cutoff"]
            )
            .order_by(MLShadowObservation.created_at)
            .limit(max(1, min(int(limit), 10_000)))
        )
    )
    deleted_count = 0
    if ids:
        deleted_count = int(
            db.execute(
                delete(MLShadowObservation).where(
                    MLShadowObservation.id.in_(ids)
                )
            ).rowcount
            or 0
        )
        db.add(
            AuditLog(
                actor=actor.strip()[:128] or "shadow-retention",
                action="ml_shadow_observation_retention_applied",
                target_type="ml_shadow_observation",
                target_value="aggregate_only",
                details={
                    "retention_days": preview["retention_days"],
                    "deleted_aggregate_observations": deleted_count,
                    "raw_evidence_affected": False,
                    "labels_affected": False,
                    "model_artifacts_affected": False,
                    "response_actions_affected": False,
                },
            )
        )
        db.commit()
    return {
        "ok": True,
        "status": "retention_applied",
        "actor": actor.strip()[:128] or "shadow-retention",
        "retention_days": preview["retention_days"],
        "deleted_aggregate_observations": deleted_count,
        "remaining_candidates": max(
            0,
            int(preview["candidate_count"]) - deleted_count,
        ),
        "raw_evidence_affected": False,
        "labels_affected": False,
        "alerts_affected": False,
        "model_artifacts_affected": False,
        "response_actions_affected": False,
    }


def _top_distribution(rows: Any) -> dict[str, float]:
    values = rows if isinstance(rows, list) else []
    counts = {
        str(row.get("value") or "unknown"): max(
            0,
            _integer(row.get("count")),
        )
        for row in values
        if isinstance(row, dict)
    }
    total = sum(counts.values())
    if total <= 0:
        return {}
    return {
        key: value / total
        for key, value in counts.items()
    }


def _total_variation(
    left: dict[str, float],
    right: dict[str, float],
) -> float | None:
    if not left or not right:
        return None
    keys = set(left) | set(right)
    return round(
        0.5
        * sum(
            abs(left.get(key, 0.0) - right.get(key, 0.0))
            for key in keys
        ),
        6,
    )


def inspect_private_longitudinal_drift(
    sample_path: str | Path,
    *,
    max_lines: int | None = None,
) -> dict[str, Any]:
    private = inspect_private_temporal_regimes(
        Path(sample_path),
        current_database_url=None,
        max_lines=max_lines,
    )
    if not private.get("ok"):
        return {
            "ok": False,
            "version": V59_VERSION,
            "status": "private_evidence_unavailable",
            "path_returned": False,
            "raw_logs_returned": False,
            "ip_addresses_returned": False,
            "fingerprints_returned": False,
            "secrets_exposed": False,
        }
    source_windows = list(private.get("windows") or [])
    safe_windows: list[dict[str, Any]] = []
    baseline_apps: dict[str, float] = {}
    baseline_schema: dict[str, float] = {}
    maximum_shift = 0.0
    for index, window in enumerate(source_windows):
        applications = _top_distribution(window.get("applications"))
        schemas = _top_distribution(window.get("schema_variants"))
        if index == 0:
            baseline_apps = applications
            baseline_schema = schemas
        app_shift = _total_variation(baseline_apps, applications)
        schema_shift = _total_variation(baseline_schema, schemas)
        maximum_shift = max(
            maximum_shift,
            app_shift or 0.0,
            schema_shift or 0.0,
            _number(window.get("unknown_app_rate")),
            _number(window.get("parser_error_rate")),
            _number(window.get("core_missing_rate")),
        )
        safe_windows.append(
            {
                "window_id": str(
                    window.get("window_id")
                    or f"private-window-{index + 1:02d}"
                ),
                "rows": max(0, _integer(window.get("rows"))),
                "application_shift_from_first": app_shift,
                "schema_shift_from_first": schema_shift,
                "unknown_app_rate": window.get(
                    "unknown_app_rate"
                ),
                "parser_error_rate": window.get(
                    "parser_error_rate"
                ),
                "core_missing_rate": window.get(
                    "core_missing_rate"
                ),
            }
        )
    status = (
        "Insufficient Evidence"
        if len(safe_windows) < 2
        else "OOD Warning"
        if maximum_shift >= 0.50
        else "Drift Warning"
        if maximum_shift >= 0.25
        else "Stable"
    )
    preflight = (
        private.get("preflight")
        if isinstance(private.get("preflight"), dict)
        else {}
    )
    parser = (
        preflight.get("parser")
        if isinstance(preflight.get("parser"), dict)
        else {}
    )
    duplicates = (
        preflight.get("duplicates")
        if isinstance(preflight.get("duplicates"), dict)
        else {}
    )
    return {
        "ok": True,
        "version": V59_VERSION,
        "status": "private_development_shadow_drift_complete",
        "evidence_role": "reused_private_development_evidence_only",
        "independent_holdout": False,
        "rows_observed": max(
            0,
            _integer(private.get("rows_observed")),
        ),
        "timed_rows": max(0, _integer(private.get("timed_rows"))),
        "untimed_rows": max(
            0,
            _integer(private.get("untimed_rows")),
        ),
        "window_count": len(safe_windows),
        "drift_status": status,
        "maximum_aggregate_shift": round(maximum_shift, 6),
        "windows": safe_windows,
        "parser_error_count": max(
            0,
            _integer(parser.get("errors")),
        ),
        "exact_duplicate_rows": max(
            0,
            _integer(duplicates.get("exact_duplicate_rows")),
        ),
        "accuracy_metrics_calculated": False,
        "labels_accessed": False,
        "human_reviewed_labels_created": False,
        "configured_database_accessed": False,
        "configured_database_modified": False,
        "model_artifacts_modified": False,
        "path_returned": False,
        "raw_logs_returned": False,
        "ip_addresses_returned": False,
        "fingerprints_returned": False,
        "secrets_exposed": False,
    }
