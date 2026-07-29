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
    AlertEvidence,
    DetectionRun,
    LogSource,
    MLLabel,
    MLModelRun,
    MLShadowObservation,
    NormalizedLog,
    OperationJob,
    RawLog,
    ResponseAction,
)
from atdr.app.services import v59_shadow_observation_service as v59
from atdr.app.services.job_dispatcher import (
    ADMIN_QUEUEABLE_JOB_TYPES,
    ANALYST_QUEUEABLE_JOB_TYPES,
    execute_operation_job,
    validate_job_submission,
)
from atdr.app.services.job_service import (
    AUTO_RETRY_SAFE_JOB_TYPES,
    request_job_cancellation,
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


def _configure(monkeypatch, *, enabled: bool = True) -> None:
    monkeypatch.setenv("GOVERNED_SHADOW_SCORING_ENABLED", "true")
    monkeypatch.setenv(
        "GOVERNED_SHADOW_OBSERVATION_ENABLED",
        "true" if enabled else "false",
    )
    monkeypatch.setenv("GOVERNED_SHADOW_BATCH_SIZE", "20")
    monkeypatch.setenv("GOVERNED_SHADOW_MAX_BATCH_SIZE", "25")
    monkeypatch.setenv(
        "GOVERNED_SHADOW_OBSERVATION_RETENTION_DAYS",
        "90",
    )
    get_settings.cache_clear()


def _add_source_logs(db) -> tuple[int, int]:
    first = LogSource(
        name="v59-source-a",
        source_type="firewall",
        parser_profile="palo_alto",
    )
    second = LogSource(
        name="v59-source-b",
        source_type="firewall",
        parser_profile="palo_alto",
    )
    db.add_all([first, second])
    db.flush()
    for index, (source_id, hour) in enumerate(
        (
            (first.id, 0),
            (first.id, 1),
            (second.id, 2),
        )
    ):
        raw = RawLog(
            source_id=source_id,
            raw_line=(
                f"private 198.51.100.{index + 1} "
                f"to 10.0.0.{index + 1}"
            ),
            raw_line_hash=f"{index + 1:064x}",
        )
        db.add(raw)
        db.flush()
        db.add(
            NormalizedLog(
                raw_log_id=raw.id,
                generated_time=datetime(
                    2026,
                    7,
                    1,
                    hour,
                    tzinfo=timezone.utc,
                ),
                src_ip=f"198.51.100.{index + 1}",
                dst_ip=f"10.0.0.{index + 1}",
                src_port=41000 + index,
                dst_port=443,
                protocol="tcp",
                action="allow",
                app="ssl",
                src_zone="outside",
                dst_zone="inside",
                bytes=800,
                packets=8,
                app_risk=2,
                parsed_json={
                    "parser_profile": "palo_alto",
                    "parse_status": "parsed",
                    "field_count": 110,
                },
            )
        )
    db.commit()
    return int(first.id), int(second.id)


def _authoritative_counts(db) -> dict[str, int]:
    models = {
        "raw": RawLog,
        "normalized": NormalizedLog,
        "alerts": Alert,
        "evidence": AlertEvidence,
        "labels": MLLabel,
        "models": MLModelRun,
        "runs": DetectionRun,
        "responses": ResponseAction,
    }
    return {
        name: int(
            db.scalar(select(func.count()).select_from(model)) or 0
        )
        for name, model in models.items()
    }


def _runtime_result(*, rows: int = 1) -> dict:
    return {
        "ok": True,
        "status": "evaluated_shadow_read_only",
        "candidate_contract_matched": True,
        "runtime_seconds": 0.25,
        "telemetry": {
            "rows_evaluated": rows,
            "queue_count": rows,
            "queue_rate": 1.0,
            "score_summary": {
                "minimum": 0.7,
                "mean": 0.8,
                "p50": 0.8,
                "p95": 0.9,
                "maximum": 0.9,
            },
            "score_distribution": [
                {"bucket": "0.75-1.00", "count": rows, "rate": 1.0}
            ],
            "confidence_summary": {
                "minimum": 0.8,
                "mean": 0.85,
                "p50": 0.85,
                "p95": 0.9,
                "maximum": 0.9,
            },
            "confidence_distribution": [
                {"bucket": "0.75-1.00", "count": rows, "rate": 1.0}
            ],
            "missing_feature_values": 0,
            "feature_values_checked": rows * 40,
            "drift": {
                "status": "Drift Warning",
                "rows_evaluated": rows,
                "application_total_variation": 0.27,
                "schema_total_variation": 0.04,
                "quality": {
                    "parser_error_rate": 0.0,
                    "parser_warning_per_row": 0.0,
                    "required_missing_per_row": 0.0,
                    "unknown_app_rate": 0.0,
                },
                "quality_absolute_delta": {},
                "application_category_count": 1,
                "schema_category_count": 1,
            },
            "source_stability": {
                "group_count": 1,
                "minimum_rows": rows,
                "maximum_rows": rows,
            },
            "time_window_stability": {
                "group_count": 1,
                "minimum_rows": rows,
                "maximum_rows": rows,
            },
            "rule_shadow_agreement": {
                "both_queue": 0,
                "rule_only": 0,
                "shadow_only": rows,
                "neither": 0,
                "disagreement_count": rows,
                "disagreement_rate": 1.0,
            },
            "isolation_forest": {
                "persisted_anomaly_count": 0,
                "persisted_anomaly_rate": 0.0,
                "persisted_score_rows": 0,
                "persisted_score_summary": {},
            },
        },
        "safety": {
            "active_model_artifacts_unchanged": True,
            "frozen_candidate_artifact_unchanged": True,
            "alerts_created": 0,
            "alert_evidence_created": 0,
            "labels_created": 0,
            "model_runs_created": 0,
            "detection_runs_created": 0,
            "response_actions_created": 0,
        },
    }


def _stub_runtime(monkeypatch, *, rows: int = 1) -> list[dict]:
    calls: list[dict] = []
    monkeypatch.setattr(
        v59.v58,
        "inspect_frozen_candidate_contract",
        lambda **kwargs: {
            "matched": True,
            "candidate_name": "calibrated_hist_gradient_boosting",
            "candidate_version": "v5.6-frozen",
            "model_type": "HistGradientBoostingClassifier",
            "calibration_method": "sigmoid",
            "threshold": 0.3,
            "feature_count": 40,
            "_artifact_sha256": "a" * 64,
        },
    )

    def runtime(db, **kwargs):
        calls.append(dict(kwargs))
        return _runtime_result(rows=rows)

    monkeypatch.setattr(
        v59.v58,
        "governed_shadow_runtime_status",
        runtime,
    )
    return calls


def test_observation_disabled_by_default_and_no_write(monkeypatch):
    monkeypatch.delenv(
        "GOVERNED_SHADOW_OBSERVATION_ENABLED",
        raising=False,
    )
    get_settings.cache_clear()
    Session = _session_factory()
    with Session() as db:
        result = v59.record_governed_shadow_observation(
            db,
            actor="admin",
        )
        count = db.scalar(
            select(func.count()).select_from(MLShadowObservation)
        )

    assert result["status"] == "observation_disabled_by_configuration"
    assert result["observation_created"] is False
    assert result["rules_alert_authoritative"] is True
    assert result["model_activated"] is False
    assert result["response_automation_allowed"] is False
    assert count == 0


def test_observation_is_scoped_idempotent_private_and_mutation_free(
    monkeypatch,
):
    _configure(monkeypatch)
    calls = _stub_runtime(monkeypatch, rows=1)
    Session = _session_factory()
    with Session() as db:
        source_id, _ = _add_source_logs(db)
        before = _authoritative_counts(db)
        first = v59.record_governed_shadow_observation(
            db,
            actor="admin",
            source_id=source_id,
            start_at=datetime(2026, 7, 1, 1, tzinfo=timezone.utc),
            end_at=datetime(2026, 7, 1, 1, tzinfo=timezone.utc),
            limit=10,
        )
        second = v59.record_governed_shadow_observation(
            db,
            actor="admin",
            source_id=source_id,
            start_at=datetime(2026, 7, 1, 1, tzinfo=timezone.utc),
            end_at=datetime(2026, 7, 1, 1, tzinfo=timezone.utc),
            limit=10,
        )
        after = _authoritative_counts(db)
        observations = list(db.scalars(select(MLShadowObservation)))

    assert first["ok"] is True
    assert first["observation_created"] is True
    assert second["idempotent_reuse"] is True
    assert len(calls) == 1
    assert calls[0]["source_id"] == source_id
    assert calls[0]["limit"] == 10
    assert len(observations) == 1
    assert observations[0].source_id == source_id
    assert observations[0].rows_evaluated == 1
    assert observations[0].drift_status == "Drift Warning"
    operational = observations[0].aggregate_json[
        "operational_contract"
    ]
    assert operational["schema_version"] == (
        "v5.10-operational-observation-v1"
    )
    assert operational["evidence_role"] == (
        "reused_development_operational_evidence_only"
    )
    assert operational["independent_validation"] is False
    assert operational["authoritative_state_unchanged"] is True
    assert operational["private_data_exposed"] is False
    assert all(
        value == 0
        for value in operational["authoritative_mutations"].values()
    )
    assert before == after
    serialized = json.dumps(first, default=str)
    assert "198.51.100." not in serialized
    assert "10.0.0." not in serialized
    assert "private " not in serialized
    assert "a" * 64 not in serialized
    assert first["raw_logs_included"] is False
    assert first["private_paths_included"] is False
    assert first["fingerprints_included"] is False
    assert first["safety"]["alerts_created"] == 0
    assert first["safety"]["labels_created"] == 0
    assert first["safety"]["model_runs_created"] == 0
    assert first["safety"]["response_actions_created"] == 0


def test_summary_and_explicit_retention_touch_only_aggregate_rows(
    monkeypatch,
):
    _configure(monkeypatch)
    _stub_runtime(monkeypatch, rows=1)
    Session = _session_factory()
    with Session() as db:
        source_id, _ = _add_source_logs(db)
        before = _authoritative_counts(db)
        first = v59.record_governed_shadow_observation(
            db,
            actor="admin",
            source_id=source_id,
            limit=1,
        )
        old = db.get(
            MLShadowObservation,
            first["observation"]["observation_id"],
        )
        old.created_at = datetime.now(timezone.utc) - timedelta(days=120)
        db.commit()
        v59.record_governed_shadow_observation(
            db,
            actor="admin",
            source_id=source_id,
            limit=2,
        )
        summary = v59.shadow_observation_summary(db)
        preview = v59.preview_shadow_observation_retention(
            db,
            older_than_days=90,
        )
        applied = v59.prune_shadow_observations(
            db,
            actor="admin",
            older_than_days=90,
        )
        after = _authoritative_counts(db)
        remaining = db.scalar(
            select(func.count()).select_from(MLShadowObservation)
        )

    assert summary["observation_count"] == 2
    assert summary["retention"]["automatic_cleanup_enabled"] is False
    assert summary["rules_alert_authoritative"] is True
    assert summary["independent_evidence"]["qualified"] is False
    assert preview["candidate_count"] == 1
    assert applied["deleted_aggregate_observations"] == 1
    assert remaining == 1
    assert before == after
    assert applied["raw_evidence_affected"] is False
    assert applied["labels_affected"] is False
    assert applied["model_artifacts_affected"] is False
    assert applied["response_actions_affected"] is False


def test_private_drift_output_is_aggregate_only(monkeypatch):
    monkeypatch.setattr(
        v59,
        "inspect_private_temporal_regimes",
        lambda *args, **kwargs: {
            "ok": True,
            "rows_observed": 200,
            "timed_rows": 200,
            "untimed_rows": 0,
            "windows": [
                {
                    "window_id": "window-1",
                    "rows": 100,
                    "applications": [
                        {"value": "ssl", "count": 100}
                    ],
                    "schema_variants": [
                        {"value": "traffic:full", "count": 100}
                    ],
                    "unknown_app_rate": 0.0,
                    "parser_error_rate": 0.0,
                    "core_missing_rate": 0.0,
                    "raw_line": "198.51.100.8",
                },
                {
                    "window_id": "window-2",
                    "rows": 100,
                    "applications": [
                        {"value": "unknown", "count": 100}
                    ],
                    "schema_variants": [
                        {"value": "traffic:limited", "count": 100}
                    ],
                    "unknown_app_rate": 1.0,
                    "parser_error_rate": 0.0,
                    "core_missing_rate": 0.0,
                },
            ],
            "preflight": {
                "parser": {"errors": 0},
                "duplicates": {"exact_duplicate_rows": 0},
                "private_path": "C:/private/firewall.log",
            },
        },
    )

    result = v59.inspect_private_longitudinal_drift(
        "C:/private/firewall.log"
    )
    serialized = json.dumps(result)

    assert result["ok"] is True
    assert result["drift_status"] == "OOD Warning"
    assert result["configured_database_accessed"] is False
    assert result["accuracy_metrics_calculated"] is False
    assert result["labels_accessed"] is False
    assert result["human_reviewed_labels_created"] is False
    assert result["path_returned"] is False
    assert result["raw_logs_returned"] is False
    assert result["ip_addresses_returned"] is False
    assert "C:/private" not in serialized
    assert "198.51.100.8" not in serialized


def test_shadow_job_is_admin_only_bounded_retryable_and_cancelable(
    monkeypatch,
):
    _configure(monkeypatch)
    assert "shadow_observation" in ADMIN_QUEUEABLE_JOB_TYPES
    assert "shadow_observation" not in ANALYST_QUEUEABLE_JOB_TYPES
    assert "shadow_observation" in AUTO_RETRY_SAFE_JOB_TYPES

    payload = validate_job_submission(
        "shadow_observation",
        {
            "source_id": 7,
            "start_at": "2026-07-01T00:00:00Z",
            "end_at": "2026-07-01T01:00:00Z",
            "limit": 20,
        },
    )
    assert payload["source_id"] == 7
    assert payload["limit"] == 20
    assert payload["start_at"].endswith("+00:00")

    Session = _session_factory()
    with Session() as db:
        job = OperationJob(
            job_type="shadow_observation",
            status="running",
            requested_by="admin",
            payload_json=payload,
            details_json={},
            result_summary_json={},
            progress_current=0,
            progress_total=1,
            attempt_count=1,
            max_attempts=2,
        )
        db.add(job)
        db.commit()
        db.refresh(job)
        cancelled = request_job_cancellation(
            db,
            job,
            actor="admin",
        )

    assert cancelled.status == "cancel_requested"
    assert cancelled.cancellation_requested_by == "admin"


def test_shadow_job_submission_fails_closed_when_disabled(monkeypatch):
    _configure(monkeypatch, enabled=False)
    with pytest.raises(
        ValueError,
        match="disabled by configuration",
    ):
        validate_job_submission("shadow_observation", {"limit": 20})


def test_shadow_job_dispatch_records_only_aggregate_observation(
    monkeypatch,
):
    _configure(monkeypatch)
    _stub_runtime(monkeypatch, rows=1)
    Session = _session_factory()
    with Session() as db:
        source_id, _ = _add_source_logs(db)
        before = _authoritative_counts(db)
        result = execute_operation_job(
            db,
            job_type="shadow_observation",
            payload={"source_id": source_id, "limit": 1},
            actor="admin",
        )
        after = _authoritative_counts(db)
        observations = db.scalar(
            select(func.count()).select_from(MLShadowObservation)
        )

    assert result["ok"] is True
    assert result["observation_created"] is True
    assert observations == 1
    assert before == after
    assert result["rules_alert_authoritative"] is True
    assert result["model_activated"] is False
    assert result["production_promoted"] is False
    assert result["response_automation_allowed"] is False
