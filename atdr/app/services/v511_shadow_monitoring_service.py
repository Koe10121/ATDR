from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from statistics import mean
from typing import Any

from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from atdr.app.core.config import get_settings
from atdr.app.db.database import Base
from atdr.app.db.models import (
    Alert,
    AuditLog,
    DetectionRun,
    IngestionRun,
    MLLabel,
    MLModelRun,
    MLShadowObservation,
    NormalizedLog,
    OperationJob,
    RawLog,
    ResponseAction,
    User,
)
from atdr.app.services import v59_shadow_observation_service as v59
from atdr.app.services.job_service import ACTIVE_JOB_STATUSES, enqueue_job


V511_VERSION = "v5.11-operational-drift-root-cause-v1"
DRIFT_STATES = {
    "Stable",
    "Drift Warning",
    "OOD Warning",
    "Insufficient Evidence",
}
DRIFT_PRIORITY = {
    "Stable": 0,
    "Insufficient Evidence": 1,
    "Drift Warning": 2,
    "OOD Warning": 3,
}
MONITORING_THRESHOLDS = {
    "minimum_rows": 50,
    "drift_total_variation": 0.25,
    "ood_total_variation": 0.50,
    "parser_limited_rate": 0.50,
    "queue_change": 0.35,
    "score_mean_change": 0.20,
    "disagreement_change": 0.35,
    "isolation_anomaly_change": 0.05,
    "source_volume_ratio": 0.25,
}
HYSTERESIS_POLICY = {
    "drift_escalation_observations": 2,
    "drift_recovery_stable_observations": 2,
    "ood_escalation_observations": 1,
    "ood_recovery_sufficient_observations": 3,
    "insufficient_evidence_clears_warning": False,
}


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


def _metric_range(values: list[float]) -> dict[str, float | None]:
    return {
        "minimum": round(min(values), 6) if values else None,
        "mean": round(mean(values), 6) if values else None,
        "maximum": round(max(values), 6) if values else None,
        "range": round(max(values) - min(values), 6) if values else None,
    }


def _quality_values(observation: MLShadowObservation) -> tuple[dict[str, float], dict[str, float]]:
    aggregate = observation.aggregate_json if isinstance(observation.aggregate_json, dict) else {}
    drift = aggregate.get("drift") if isinstance(aggregate.get("drift"), dict) else {}
    quality = drift.get("quality") if isinstance(drift.get("quality"), dict) else {}
    deltas = (
        drift.get("quality_absolute_delta")
        if isinstance(drift.get("quality_absolute_delta"), dict)
        else {}
    )
    keys = (
        "parser_error_rate",
        "parser_warning_per_row",
        "required_missing_per_row",
        "unknown_app_rate",
    )
    return (
        {key: max(0.0, _number(quality.get(key))) for key in keys},
        {key: max(0.0, _number(deltas.get(key))) for key in keys},
    )


def classify_operational_drift(
    *,
    rows_evaluated: int,
    application_total_variation: float | None,
    schema_total_variation: float | None,
    quality_absolute_delta: dict[str, float] | None = None,
    minimum_rows: int = MONITORING_THRESHOLDS["minimum_rows"],
) -> str:
    """Classify aggregate distribution evidence without using labels or accuracy."""

    if int(rows_evaluated) < max(1, int(minimum_rows)):
        return "Insufficient Evidence"
    values = [
        _number(application_total_variation),
        _number(schema_total_variation),
        *[
            _number(value)
            for value in (quality_absolute_delta or {}).values()
        ],
    ]
    maximum_shift = max(values, default=0.0)
    if maximum_shift >= MONITORING_THRESHOLDS["ood_total_variation"]:
        return "OOD Warning"
    if maximum_shift >= MONITORING_THRESHOLDS["drift_total_variation"]:
        return "Drift Warning"
    return "Stable"


def apply_drift_hysteresis(states: list[str]) -> list[str]:
    """Apply conservative alert-state hysteresis to chronological raw states."""

    effective: list[str] = []
    current: str | None = None
    drift_streak = 0
    stable_streak = 0
    ood_recovery_streak = 0
    for supplied in states:
        raw = supplied if supplied in DRIFT_STATES else "Insufficient Evidence"
        if raw == "Insufficient Evidence":
            effective.append(current or raw)
            continue
        if raw == "OOD Warning":
            current = raw
            drift_streak = 0
            stable_streak = 0
            ood_recovery_streak = 0
            effective.append(current)
            continue
        if current == "OOD Warning":
            ood_recovery_streak += 1
            if (
                ood_recovery_streak
                >= HYSTERESIS_POLICY["ood_recovery_sufficient_observations"]
            ):
                current = raw
                ood_recovery_streak = 0
                stable_streak = 0
                drift_streak = 0
            effective.append(current)
            continue
        ood_recovery_streak = 0
        if current is None or current == "Insufficient Evidence":
            current = raw
        elif raw == "Drift Warning":
            stable_streak = 0
            drift_streak += 1
            if (
                current != "Stable"
                or drift_streak
                >= HYSTERESIS_POLICY["drift_escalation_observations"]
            ):
                current = "Drift Warning"
        elif raw == "Stable":
            drift_streak = 0
            if current == "Drift Warning":
                stable_streak += 1
                if (
                    stable_streak
                    >= HYSTERESIS_POLICY[
                        "drift_recovery_stable_observations"
                    ]
                ):
                    current = "Stable"
                    stable_streak = 0
            else:
                current = "Stable"
                stable_streak = 0
        effective.append(current)
    return effective


def _scope_mapping(
    observations: list[MLShadowObservation],
) -> dict[int | None, str]:
    source_ids = sorted(
        {
            int(row.source_id)
            for row in observations
            if row.source_id is not None
        }
    )
    mapping: dict[int | None, str] = {
        source_id: f"source-scope-{index:02d}"
        for index, source_id in enumerate(source_ids, 1)
    }
    if any(row.source_id is None for row in observations):
        mapping[None] = "aggregate-scope"
    return mapping


def _root_causes(
    observation: MLShadowObservation,
    *,
    previous: MLShadowObservation | None,
    maximum_rows: int,
) -> list[str]:
    quality, deltas = _quality_values(observation)
    causes: list[str] = []
    rows = int(observation.rows_evaluated)
    app_shift = _number(observation.application_total_variation)
    schema_shift = _number(observation.schema_total_variation)
    if rows < MONITORING_THRESHOLDS["minimum_rows"]:
        causes.append("short_or_sparse_window")
    if app_shift >= MONITORING_THRESHOLDS["drift_total_variation"]:
        causes.append("application_distribution_shift")
    if schema_shift >= MONITORING_THRESHOLDS["drift_total_variation"]:
        causes.append("schema_or_missingness_shift")
    if max(
        quality.get("parser_warning_per_row", 0.0),
        quality.get("unknown_app_rate", 0.0),
    ) >= MONITORING_THRESHOLDS["parser_limited_rate"]:
        causes.append("parser_profile_limited_fields")
    if max(deltas.values(), default=0.0) >= MONITORING_THRESHOLDS["drift_total_variation"]:
        causes.append("parser_quality_shift")
    if maximum_rows > 0 and rows < max(
        MONITORING_THRESHOLDS["minimum_rows"],
        int(maximum_rows * MONITORING_THRESHOLDS["source_volume_ratio"]),
    ):
        causes.append("source_volume_imbalance")
    if previous is not None:
        if (
            abs(_number(observation.score_mean) - _number(previous.score_mean))
            >= MONITORING_THRESHOLDS["score_mean_change"]
            or abs(float(observation.queue_rate) - float(previous.queue_rate))
            >= MONITORING_THRESHOLDS["queue_change"]
        ):
            causes.append("candidate_score_distribution_shift")
        if (
            abs(
                float(observation.disagreement_rate)
                - float(previous.disagreement_rate)
            )
            >= MONITORING_THRESHOLDS["disagreement_change"]
        ):
            causes.append("rule_shadow_disagreement_shift")
        if (
            abs(
                float(observation.isolation_anomaly_rate)
                - float(previous.isolation_anomaly_rate)
            )
            >= MONITORING_THRESHOLDS["isolation_anomaly_change"]
        ):
            causes.append("isolation_forest_variation")
    return causes or ["no_material_aggregate_shift"]


def _quality_warning(
    *,
    raw_state: str,
    causes: list[str],
) -> str:
    if "short_or_sparse_window" in causes:
        return "Short or sparse window; not treated as accuracy evidence."
    if "parser_profile_limited_fields" in causes:
        return "Parser profile has limited fields or unknown applications."
    if "schema_or_missingness_shift" in causes:
        return "Structured-field distribution differs from the governed baseline."
    if "application_distribution_shift" in causes:
        return "Application mix differs from the governed baseline."
    if raw_state == "Stable":
        return "No material aggregate quality shift detected."
    return "Aggregate monitoring change requires analyst review."


def monitoring_cadence_status(
    db: Session,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    settings = get_settings()
    current_time = _utc(now) or datetime.now(timezone.utc)
    cadence = int(settings.governed_shadow_monitoring_cadence_minutes)
    active = db.scalar(
        select(OperationJob)
        .where(
            OperationJob.job_type == "shadow_monitoring_cycle",
            OperationJob.status.in_(ACTIVE_JOB_STATUSES),
        )
        .order_by(OperationJob.created_at.desc(), OperationJob.id.desc())
        .limit(1)
    )
    latest_completed = db.scalar(
        select(OperationJob)
        .where(
            OperationJob.job_type == "shadow_monitoring_cycle",
            OperationJob.status == "completed",
        )
        .order_by(OperationJob.finished_at.desc(), OperationJob.id.desc())
        .limit(1)
    )
    completed_at = (
        _utc(latest_completed.finished_at)
        if latest_completed is not None
        else None
    )
    next_due_at = (
        completed_at + timedelta(minutes=cadence)
        if completed_at is not None
        else None
    )
    enabled = bool(settings.governed_shadow_monitoring_enabled)
    dependencies_ready = bool(
        settings.governed_shadow_observation_enabled
        and settings.governed_shadow_scoring_enabled
    )
    return {
        "enabled": enabled,
        "dependencies_ready": dependencies_ready,
        "scheduler_mode": "external_due_check_only",
        "always_on_scheduler_enabled": False,
        "cadence_minutes": cadence,
        "active_job": active is not None,
        "latest_status": (
            str(active.status)
            if active is not None
            else str(latest_completed.status)
            if latest_completed is not None
            else "not_run"
        ),
        "last_completed_at": completed_at,
        "next_due_at": next_due_at,
        "due": bool(
            enabled
            and dependencies_ready
            and active is None
            and (next_due_at is None or current_time >= next_due_at)
        ),
        "bounded_source_count": int(
            settings.governed_shadow_monitoring_max_sources
        ),
        "bounded_windows_per_source": int(
            settings.governed_shadow_monitoring_max_windows_per_source
        ),
        "duplicate_suppression": True,
        "idempotent_retry": True,
        "cooperative_cancellation": True,
    }


def enqueue_monitoring_cycle_if_due(
    db: Session,
    *,
    actor: str,
    now: datetime | None = None,
) -> dict[str, Any]:
    settings = get_settings()
    current_time = _utc(now) or datetime.now(timezone.utc)
    cadence_status = monitoring_cadence_status(db, now=current_time)
    if not cadence_status["enabled"]:
        return {
            "ok": True,
            "status": "monitoring_disabled_by_configuration",
            "job_created": False,
            "idempotent_reuse": False,
            "cadence": cadence_status,
        }
    if not cadence_status["dependencies_ready"]:
        return {
            "ok": False,
            "status": "monitoring_dependencies_disabled",
            "job_created": False,
            "idempotent_reuse": False,
            "cadence": cadence_status,
        }
    if cadence_status["active_job"]:
        return {
            "ok": True,
            "status": "active_monitoring_cycle_exists",
            "job_created": False,
            "idempotent_reuse": True,
            "cadence": cadence_status,
        }
    if not cadence_status["due"]:
        return {
            "ok": True,
            "status": "monitoring_cycle_not_due",
            "job_created": False,
            "idempotent_reuse": False,
            "cadence": cadence_status,
        }

    cadence_minutes = int(
        settings.governed_shadow_monitoring_cadence_minutes
    )
    bucket_seconds = cadence_minutes * 60
    bucket_start = int(current_time.timestamp()) // bucket_seconds
    idempotency_key = f"v511-shadow-monitoring-{bucket_start}"
    payload = {
        "maximum_sources": int(
            settings.governed_shadow_monitoring_max_sources
        ),
        "maximum_windows_per_source": int(
            settings.governed_shadow_monitoring_max_windows_per_source
        ),
        "minimum_rows": int(settings.governed_shadow_monitoring_min_rows),
        "batch_limit": int(
            settings.governed_shadow_monitoring_batch_limit
        ),
    }
    job, reused = enqueue_job(
        db,
        job_type="shadow_monitoring_cycle",
        requested_by=actor.strip()[:128] or "shadow-monitor",
        payload=payload,
        details={
            "operation": "bounded_historical_shadow_monitoring",
            "source_identifiers_included": False,
        },
        idempotency_key=idempotency_key,
        max_attempts=2,
        progress_total=1,
    )
    return {
        "ok": True,
        "status": (
            "monitoring_cycle_reused"
            if reused
            else "monitoring_cycle_queued"
        ),
        "job_created": not reused,
        "idempotent_reuse": reused,
        "job_reference": int(job.id),
        "cadence": monitoring_cadence_status(db, now=current_time),
        "source_identifiers_included": False,
        "raw_logs_included": False,
        "secrets_exposed": False,
    }


def build_shadow_monitoring_diagnostics(
    db: Session,
    *,
    limit: int = 365,
) -> dict[str, Any]:
    observations = list(
        db.scalars(
            select(MLShadowObservation)
            .order_by(
                MLShadowObservation.created_at.desc(),
                MLShadowObservation.id.desc(),
            )
            .limit(max(1, min(int(limit), 1000)))
        )
    )
    observations.reverse()
    scope_map = _scope_mapping(observations)
    maximum_rows = max(
        (int(row.rows_evaluated) for row in observations),
        default=0,
    )
    grouped: dict[int | None, list[MLShadowObservation]] = defaultdict(list)
    for observation in observations:
        grouped[observation.source_id].append(observation)

    rows: list[dict[str, Any]] = []
    cause_counts: Counter[str] = Counter()
    for source_id, source_rows in sorted(
        grouped.items(),
        key=lambda item: (
            item[0] is None,
            int(item[0] or 0),
        ),
    ):
        source_rows.sort(
            key=lambda row: (
                _utc(row.window_start)
                or _utc(row.observed_start)
                or _utc(row.created_at)
                or datetime.min.replace(tzinfo=timezone.utc),
                int(row.id),
            )
        )
        raw_states: list[str] = []
        row_causes: list[list[str]] = []
        previous: MLShadowObservation | None = None
        for observation in source_rows:
            _, deltas = _quality_values(observation)
            raw_state = classify_operational_drift(
                rows_evaluated=int(observation.rows_evaluated),
                application_total_variation=(
                    observation.application_total_variation
                ),
                schema_total_variation=observation.schema_total_variation,
                quality_absolute_delta=deltas,
            )
            causes = _root_causes(
                observation,
                previous=previous,
                maximum_rows=maximum_rows,
            )
            raw_states.append(raw_state)
            row_causes.append(causes)
            cause_counts.update(causes)
            previous = observation
        effective_states = apply_drift_hysteresis(raw_states)
        for time_index, (
            observation,
            raw_state,
            effective_state,
            causes,
        ) in enumerate(
            zip(
                source_rows,
                raw_states,
                effective_states,
                row_causes,
                strict=True,
            ),
            1,
        ):
            quality, _ = _quality_values(observation)
            rows.append(
                {
                    "source_scope": scope_map[source_id],
                    "time_scope": f"time-scope-{time_index:02d}",
                    "observation_time": observation.created_at,
                    "rows_evaluated": int(observation.rows_evaluated),
                    "raw_drift_state": raw_state,
                    "drift_state": effective_state,
                    "queue_rate": round(float(observation.queue_rate), 6),
                    "disagreement_rate": round(
                        float(observation.disagreement_rate),
                        6,
                    ),
                    "isolation_anomaly_rate": round(
                        float(observation.isolation_anomaly_rate),
                        6,
                    ),
                    "score_mean": (
                        round(float(observation.score_mean), 6)
                        if observation.score_mean is not None
                        else None
                    ),
                    "score_p95": (
                        round(float(observation.score_p95), 6)
                        if observation.score_p95 is not None
                        else None
                    ),
                    "application_total_variation": (
                        round(
                            float(
                                observation.application_total_variation
                            ),
                            6,
                        )
                        if observation.application_total_variation
                        is not None
                        else None
                    ),
                    "schema_total_variation": (
                        round(
                            float(observation.schema_total_variation),
                            6,
                        )
                        if observation.schema_total_variation is not None
                        else None
                    ),
                    "unknown_app_rate": round(
                        quality.get("unknown_app_rate", 0.0),
                        6,
                    ),
                    "parser_warning_per_row": round(
                        quality.get("parser_warning_per_row", 0.0),
                        6,
                    ),
                    "runtime_seconds": (
                        round(float(observation.runtime_seconds), 6)
                        if observation.runtime_seconds is not None
                        else None
                    ),
                    "root_cause_codes": causes,
                    "quality_warning": _quality_warning(
                        raw_state=raw_state,
                        causes=causes,
                    ),
                    "accuracy_metrics_calculated": False,
                }
            )

    queue_rates = [float(row.queue_rate) for row in observations]
    disagreement_rates = [
        float(row.disagreement_rate) for row in observations
    ]
    anomaly_rates = [
        float(row.isolation_anomaly_rate) for row in observations
    ]
    effective_latest: dict[str, str] = {}
    for row in rows:
        effective_latest[row["source_scope"]] = row["drift_state"]
    current_state = max(
        effective_latest.values(),
        key=lambda value: DRIFT_PRIORITY.get(value, 1),
        default="Insufficient Evidence",
    )
    return {
        "ok": True,
        "version": V511_VERSION,
        "status": (
            "operational_diagnostics_available"
            if rows
            else "insufficient_operational_evidence"
        ),
        "observation_count": len(rows),
        "source_scope_count": len(grouped),
        "current_state": current_state,
        "rows": rows,
        "root_cause_counts": dict(sorted(cause_counts.items())),
        "operational_metrics": {
            "queue_rate": _metric_range(queue_rates),
            "rule_shadow_disagreement_rate": _metric_range(
                disagreement_rates
            ),
            "isolation_forest_anomaly_rate": _metric_range(anomaly_rates),
        },
        "thresholds": dict(MONITORING_THRESHOLDS),
        "hysteresis": dict(HYSTERESIS_POLICY),
        "cadence": monitoring_cadence_status(db),
        "accuracy_metrics_calculated": False,
        "lifecycle_state": "shadow_observation",
        "rules_alert_authoritative": True,
        "isolation_forest_advisory_only": True,
        "model_activated": False,
        "production_promoted": False,
        "response_automation_allowed": False,
        "real_firewall_blocking_enabled": False,
        "source_identifiers_included": False,
        "raw_logs_included": False,
        "ip_addresses_included": False,
        "private_paths_included": False,
        "fingerprints_included": False,
        "labels_accessed": False,
        "secrets_exposed": False,
    }


def _rehearsal_observation(
    *,
    key: str,
    created_at: datetime,
) -> MLShadowObservation:
    return MLShadowObservation(
        observation_key=key,
        candidate_name="disposable-candidate",
        candidate_version="disposable-v1",
        contract_fingerprint="f" * 64,
        status="evaluated_shadow_read_only",
        contract_matched=True,
        source_id=None,
        requested_limit=50,
        rows_evaluated=50,
        queue_count=5,
        queue_rate=0.1,
        missing_feature_values=0,
        feature_values_checked=2000,
        drift_status="Stable",
        rule_both_queue=1,
        rule_only=1,
        shadow_only=1,
        neither_queue=47,
        disagreement_count=2,
        disagreement_rate=0.04,
        isolation_anomaly_count=0,
        isolation_anomaly_rate=0.0,
        runtime_seconds=0.01,
        aggregate_json={
            "accuracy_metrics_calculated": False,
            "labels_accessed": False,
            "raw_logs_included": False,
        },
        created_by="retention-rehearsal",
        created_at=created_at,
    )


def rehearse_shadow_retention() -> dict[str, Any]:
    """Exercise aggregate retention in a disposable in-memory database only."""

    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    SessionLocal = sessionmaker(
        bind=engine,
        autoflush=False,
        autocommit=False,
        expire_on_commit=False,
    )
    now = datetime.now(timezone.utc)
    with SessionLocal() as db:
        user = User(
            username="retention-sentinel",
            role="analyst",
            password_hash="not-a-real-credential",
        )
        raw = RawLog(raw_line="synthetic-retention-sentinel")
        db.add_all([user, raw])
        db.flush()
        normalized = NormalizedLog(
            raw_log_id=int(raw.id),
            app="synthetic",
            action="allow",
            parsed_json={"synthetic": True},
        )
        alert = Alert(
            title="Synthetic retention sentinel",
            alert_type="retention_rehearsal",
            threat_score=1,
            severity="low",
            explanation="Synthetic disposable evidence.",
            recommended_response="No action.",
        )
        db.add_all([normalized, alert])
        db.flush()
        db.add_all(
            [
                MLLabel(
                    log_id=int(normalized.id),
                    label="needs_context",
                    attack_type="unknown",
                    confidence=1,
                    reviewer="retention-rehearsal",
                    label_source="weak",
                    reviewed=False,
                ),
                MLModelRun(
                    model_name="retention-sentinel",
                    operation="diagnostic",
                    status="not_activated",
                    actor="retention-rehearsal",
                    model_path="disposable-artifact",
                    message="Disposable retention sentinel.",
                ),
                IngestionRun(
                    source_type="disposable",
                    status="completed",
                ),
                DetectionRun(
                    detection_type="disposable",
                    status="completed",
                ),
                ResponseAction(
                    alert_id=int(alert.id),
                    action_type="simulate_only",
                    target_ip="192.0.2.1",
                    status="simulated",
                    result_message="Disposable retention sentinel.",
                    executed_by="retention-rehearsal",
                ),
                _rehearsal_observation(
                    key="a" * 64,
                    created_at=now - timedelta(days=120),
                ),
                _rehearsal_observation(
                    key="b" * 64,
                    created_at=now,
                ),
            ]
        )
        db.commit()

        preserved_models = (
            User,
            RawLog,
            NormalizedLog,
            Alert,
            MLLabel,
            MLModelRun,
            IngestionRun,
            DetectionRun,
            ResponseAction,
        )
        before = {
            model.__tablename__: int(
                db.scalar(select(func.count()).select_from(model)) or 0
            )
            for model in preserved_models
        }
        preview = v59.preview_shadow_observation_retention(
            db,
            older_than_days=90,
        )
        applied = v59.prune_shadow_observations(
            db,
            actor="retention-rehearsal",
            older_than_days=90,
        )
        after = {
            model.__tablename__: int(
                db.scalar(select(func.count()).select_from(model)) or 0
            )
            for model in preserved_models
        }
        remaining_observations = int(
            db.scalar(
                select(func.count()).select_from(MLShadowObservation)
            )
            or 0
        )
        audit_events = int(
            db.scalar(
                select(func.count())
                .select_from(AuditLog)
                .where(
                    AuditLog.action
                    == "ml_shadow_observation_retention_applied"
                )
            )
            or 0
        )
    engine.dispose()
    return {
        "ok": bool(
            preview["candidate_count"] == 1
            and applied["deleted_aggregate_observations"] == 1
            and remaining_observations == 1
            and before == after
            and audit_events == 1
        ),
        "status": "disposable_retention_rehearsal_completed",
        "preview_candidate_count": int(preview["candidate_count"]),
        "deleted_aggregate_observations": int(
            applied["deleted_aggregate_observations"]
        ),
        "remaining_aggregate_observations": remaining_observations,
        "preserved_entity_counts": after,
        "preservation_passed": before == after,
        "audit_event_created": audit_events == 1,
        "configured_database_accessed": False,
        "disposable_database": True,
        "raw_evidence_returned": False,
        "source_identifiers_included": False,
        "private_paths_included": False,
        "secrets_exposed": False,
    }
