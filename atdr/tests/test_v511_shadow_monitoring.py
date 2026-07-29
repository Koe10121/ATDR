from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from atdr.app.core.config import get_settings
from atdr.app.db.database import Base
from atdr.app.db.models import (
    Alert,
    DetectionRun,
    MLLabel,
    MLModelRun,
    MLShadowObservation,
    NormalizedLog,
    OperationJob,
    RawLog,
    ResponseAction,
)
from atdr.app.services import v59_shadow_observation_service as v59
from atdr.app.services import v510_detection_operations_service as v510
from atdr.app.services import v511_shadow_monitoring_service as v511
from atdr.app.services.job_dispatcher import (
    ADMIN_QUEUEABLE_JOB_TYPES,
    ANALYST_QUEUEABLE_JOB_TYPES,
    CooperativeShadowObservationCancelled,
    execute_operation_job,
    validate_job_submission,
)
from atdr.app.services.job_service import (
    AUTO_RETRY_SAFE_JOB_TYPES,
    COOPERATIVE_CANCELLABLE_JOB_TYPES,
)


def _session_factory():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    return sessionmaker(
        bind=engine,
        autoflush=False,
        autocommit=False,
    )


@pytest.fixture(autouse=True)
def _reset_settings():
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def _configure_monitoring(monkeypatch, *, enabled: bool = True) -> None:
    monkeypatch.setenv(
        "GOVERNED_SHADOW_MONITORING_ENABLED",
        str(enabled).lower(),
    )
    monkeypatch.setenv("GOVERNED_SHADOW_SCORING_ENABLED", "true")
    monkeypatch.setenv("GOVERNED_SHADOW_OBSERVATION_ENABLED", "true")
    monkeypatch.setenv("GOVERNED_SHADOW_MONITORING_CADENCE_MINUTES", "60")
    monkeypatch.setenv("GOVERNED_SHADOW_MONITORING_MAX_SOURCES", "4")
    monkeypatch.setenv(
        "GOVERNED_SHADOW_MONITORING_MAX_WINDOWS_PER_SOURCE",
        "3",
    )
    monkeypatch.setenv("GOVERNED_SHADOW_MONITORING_MIN_ROWS", "50")
    monkeypatch.setenv("GOVERNED_SHADOW_MONITORING_BATCH_LIMIT", "100")
    monkeypatch.setenv("GOVERNED_SHADOW_MAX_BATCH_SIZE", "100")
    get_settings.cache_clear()


def _authoritative_counts(db) -> dict[str, int]:
    models = (
        RawLog,
        NormalizedLog,
        Alert,
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


def _observation(
    *,
    key: str,
    source_id: int,
    created_at: datetime,
    rows: int = 100,
    app_shift: float = 0.1,
    schema_shift: float = 0.01,
    queue_rate: float = 0.2,
    disagreement_rate: float = 0.1,
    anomaly_rate: float = 0.0,
    score_mean: float = 0.2,
    warning_rate: float = 0.0,
    unknown_rate: float = 0.0,
) -> MLShadowObservation:
    drift_status = v511.classify_operational_drift(
        rows_evaluated=rows,
        application_total_variation=app_shift,
        schema_total_variation=schema_shift,
        quality_absolute_delta={
            "parser_warning_per_row": warning_rate,
            "unknown_app_rate": unknown_rate,
        },
    )
    return MLShadowObservation(
        observation_key=key,
        candidate_name="private-diagnostic-candidate",
        candidate_version="v5.11-test",
        contract_fingerprint="f" * 64,
        status="evaluated_shadow_read_only",
        contract_matched=True,
        source_id=source_id,
        window_start=created_at,
        window_end=created_at + timedelta(minutes=1),
        observed_start=created_at,
        observed_end=created_at + timedelta(minutes=1),
        requested_limit=rows,
        rows_evaluated=rows,
        queue_count=int(rows * queue_rate),
        queue_rate=queue_rate,
        score_mean=score_mean,
        score_p95=min(1.0, score_mean + 0.2),
        confidence_mean=0.7,
        confidence_p95=0.9,
        missing_feature_values=0,
        feature_values_checked=rows * 40,
        drift_status=drift_status,
        application_total_variation=app_shift,
        schema_total_variation=schema_shift,
        rule_both_queue=0,
        rule_only=0,
        shadow_only=int(rows * disagreement_rate),
        neither_queue=rows - int(rows * disagreement_rate),
        disagreement_count=int(rows * disagreement_rate),
        disagreement_rate=disagreement_rate,
        isolation_anomaly_count=int(rows * anomaly_rate),
        isolation_anomaly_rate=anomaly_rate,
        runtime_seconds=0.1,
        aggregate_json={
            "drift": {
                "status": drift_status,
                "quality": {
                    "parser_error_rate": 0.0,
                    "parser_warning_per_row": warning_rate,
                    "required_missing_per_row": 0.0,
                    "unknown_app_rate": unknown_rate,
                },
                "quality_absolute_delta": {
                    "parser_error_rate": 0.0,
                    "parser_warning_per_row": warning_rate,
                    "required_missing_per_row": 0.0,
                    "unknown_app_rate": unknown_rate,
                },
            },
            "operational_contract": {
                "authoritative_state_unchanged": True,
                "private_data_exposed": False,
            },
            "accuracy_metrics_calculated": False,
            "labels_accessed": False,
            "raw_logs_included": False,
        },
        created_by="admin",
        created_at=created_at,
    )


def test_drift_classification_and_hysteresis_are_conservative():
    assert (
        v511.classify_operational_drift(
            rows_evaluated=49,
            application_total_variation=0.9,
            schema_total_variation=0.9,
        )
        == "Insufficient Evidence"
    )
    assert (
        v511.classify_operational_drift(
            rows_evaluated=100,
            application_total_variation=0.25,
            schema_total_variation=0.01,
        )
        == "Drift Warning"
    )
    assert (
        v511.classify_operational_drift(
            rows_evaluated=100,
            application_total_variation=0.5,
            schema_total_variation=0.01,
        )
        == "OOD Warning"
    )
    states = v511.apply_drift_hysteresis(
        [
            "Stable",
            "Drift Warning",
            "Insufficient Evidence",
            "Drift Warning",
            "Stable",
            "Stable",
            "OOD Warning",
            "Stable",
            "Stable",
            "Stable",
        ]
    )
    assert states == [
        "Stable",
        "Stable",
        "Stable",
        "Drift Warning",
        "Drift Warning",
        "Stable",
        "OOD Warning",
        "OOD Warning",
        "OOD Warning",
        "Stable",
    ]


def test_diagnostics_are_aggregate_only_and_explain_variation_without_mutation():
    Session = _session_factory()
    with Session() as db:
        start = datetime(2026, 7, 1, tzinfo=timezone.utc)
        db.add_all(
            [
                _observation(
                    key="1" * 64,
                    source_id=77,
                    created_at=start,
                ),
                _observation(
                    key="2" * 64,
                    source_id=77,
                    created_at=start + timedelta(hours=1),
                    app_shift=0.62,
                    queue_rate=0.8,
                    disagreement_rate=0.55,
                    score_mean=0.8,
                    warning_rate=0.8,
                    unknown_rate=0.8,
                ),
                _observation(
                    key="3" * 64,
                    source_id=91,
                    created_at=start + timedelta(hours=2),
                    rows=20,
                    app_shift=0.9,
                    queue_rate=1.0,
                    warning_rate=1.0,
                    unknown_rate=1.0,
                ),
            ]
        )
        db.commit()
        before = _authoritative_counts(db)
        result = v511.build_shadow_monitoring_diagnostics(db)
        after = _authoritative_counts(db)

    assert before == after
    assert result["observation_count"] == 3
    assert result["source_scope_count"] == 2
    assert result["accuracy_metrics_calculated"] is False
    assert result["labels_accessed"] is False
    assert result["rules_alert_authoritative"] is True
    assert result["isolation_forest_advisory_only"] is True
    assert result["model_activated"] is False
    assert result["response_automation_allowed"] is False
    assert result["root_cause_counts"]["application_distribution_shift"] == 2
    assert result["root_cause_counts"]["short_or_sparse_window"] == 1
    assert result["root_cause_counts"]["parser_profile_limited_fields"] == 2
    assert all(row["source_scope"].startswith("source-scope-") for row in result["rows"])
    serialized = json.dumps(result, default=str)
    for forbidden in (
        "\"source_id\"",
        "private-diagnostic-candidate",
        "198.51.100.",
        "raw_line",
        "\"precision\"",
        "\"recall\"",
        "\"f1\"",
    ):
        assert forbidden not in serialized


def test_public_shadow_serializer_omits_internal_source_identifier():
    observation = _observation(
        key="4" * 64,
        source_id=12345,
        created_at=datetime(2026, 7, 1, tzinfo=timezone.utc),
    )
    observation.id = 1
    value = v59.shadow_observation_to_dict(observation)
    assert "source_id" not in value
    assert value["source_identifiers_included"] is False


def test_monitoring_cycle_is_disabled_by_default_and_admin_only(monkeypatch):
    _configure_monitoring(monkeypatch, enabled=False)
    assert "shadow_monitoring_cycle" in ADMIN_QUEUEABLE_JOB_TYPES
    assert "shadow_monitoring_cycle" not in ANALYST_QUEUEABLE_JOB_TYPES
    assert "shadow_monitoring_cycle" in AUTO_RETRY_SAFE_JOB_TYPES
    assert "shadow_monitoring_cycle" in COOPERATIVE_CANCELLABLE_JOB_TYPES
    with pytest.raises(ValueError, match="disabled by configuration"):
        validate_job_submission("shadow_monitoring_cycle", {})


def test_due_monitoring_cycle_is_idempotent_and_bounded(monkeypatch):
    _configure_monitoring(monkeypatch)
    payload = validate_job_submission(
        "shadow_monitoring_cycle",
        {
            "maximum_sources": 4,
            "maximum_windows_per_source": 3,
            "minimum_rows": 50,
            "batch_limit": 100,
        },
    )
    assert payload == {
        "maximum_sources": 4,
        "maximum_windows_per_source": 3,
        "minimum_rows": 50,
        "batch_limit": 100,
    }
    with pytest.raises(ValueError, match="maximum_sources"):
        validate_job_submission(
            "shadow_monitoring_cycle",
            {"maximum_sources": 5},
        )

    Session = _session_factory()
    now = datetime(2026, 7, 1, tzinfo=timezone.utc)
    with Session() as db:
        first = v511.enqueue_monitoring_cycle_if_due(
            db,
            actor="admin",
            now=now,
        )
        second = v511.enqueue_monitoring_cycle_if_due(
            db,
            actor="admin",
            now=now,
        )
        job_count = int(
            db.scalar(
                select(func.count())
                .select_from(OperationJob)
                .where(OperationJob.job_type == "shadow_monitoring_cycle")
            )
            or 0
        )

    assert first["status"] == "monitoring_cycle_queued"
    assert first["job_created"] is True
    assert second["status"] == "active_monitoring_cycle_exists"
    assert second["idempotent_reuse"] is True
    assert job_count == 1
    serialized = json.dumps(first, default=str)
    assert "\"source_id\"" not in serialized
    assert "change-this" not in serialized.lower()
    assert first["secrets_exposed"] is False


def test_monitoring_dispatch_is_mutation_free_and_honors_cancellation(
    monkeypatch,
):
    Session = _session_factory()
    with Session() as db:
        before = _authoritative_counts(db)
        monkeypatch.setattr(
            v510,
            "run_historical_shadow_observations",
            lambda *args, **kwargs: {
                "ok": True,
                "status": "historical_shadow_observations_completed",
                "planned_scope_count": 2,
                "observations_executed": 2,
                "successful_observation_count": 2,
                "created_observation_count": 0,
                "idempotent_reuse_count": 2,
                "operational_acceptance": {
                    "drift": {"current_state": "Stable"}
                },
                "accuracy_metrics_calculated": False,
                "model_activated": False,
                "response_automation_allowed": False,
            },
        )
        result = execute_operation_job(
            db,
            job_type="shadow_monitoring_cycle",
            payload={
                "maximum_sources": 2,
                "maximum_windows_per_source": 1,
                "minimum_rows": 50,
                "batch_limit": 100,
            },
            actor="admin",
            should_stop=lambda: False,
        )
        after = _authoritative_counts(db)
        assert before == after
        assert result["model_activated"] is False
        assert result["response_automation_allowed"] is False

        monkeypatch.setattr(
            v510,
            "run_historical_shadow_observations",
            lambda *args, **kwargs: {
                "ok": False,
                "status": "cancelled_without_partial_scope_persist",
            },
        )
        with pytest.raises(CooperativeShadowObservationCancelled):
            execute_operation_job(
                db,
                job_type="shadow_monitoring_cycle",
                payload={
                    "maximum_sources": 2,
                    "maximum_windows_per_source": 1,
                    "minimum_rows": 50,
                    "batch_limit": 100,
                },
                actor="admin",
                job_id=9,
                should_stop=lambda: True,
            )


def test_retention_rehearsal_uses_disposable_storage_and_preserves_entities():
    result = v511.rehearse_shadow_retention()
    assert result["ok"] is True
    assert result["configured_database_accessed"] is False
    assert result["disposable_database"] is True
    assert result["preview_candidate_count"] == 1
    assert result["deleted_aggregate_observations"] == 1
    assert result["remaining_aggregate_observations"] == 1
    assert result["preservation_passed"] is True
    assert result["audit_event_created"] is True
    assert all(
        count == 1
        for count in result["preserved_entity_counts"].values()
    )
    assert result["raw_evidence_returned"] is False
