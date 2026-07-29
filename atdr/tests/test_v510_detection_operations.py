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
    RawLog,
    ResponseAction,
)
from atdr.app.services import ml_service
from atdr.app.services import v59_shadow_observation_service as v59
from atdr.app.services import v510_detection_operations_service as v510


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


def _configure(monkeypatch) -> None:
    monkeypatch.setenv("GOVERNED_SHADOW_SCORING_ENABLED", "true")
    monkeypatch.setenv("GOVERNED_SHADOW_OBSERVATION_ENABLED", "true")
    monkeypatch.setenv("GOVERNED_SHADOW_BATCH_SIZE", "20")
    monkeypatch.setenv("GOVERNED_SHADOW_MAX_BATCH_SIZE", "25")
    monkeypatch.setenv("GOVERNED_SHADOW_TIMEOUT_SECONDS", "30")
    monkeypatch.setattr(
        v510.v58,
        "inspect_frozen_candidate_contract",
        lambda: {"matched": True},
    )
    get_settings.cache_clear()


def _add_logs(
    db,
    *,
    source_name: str,
    count: int,
    start: datetime,
) -> int:
    source = LogSource(
        name=source_name,
        source_type="firewall",
        parser_profile="palo_alto",
    )
    db.add(source)
    db.flush()
    for index in range(count):
        raw = RawLog(
            source_id=source.id,
            raw_line=f"private-evidence-{source_name}-{index}",
            raw_line_hash=f"{source.id * 1000 + index:064x}",
        )
        db.add(raw)
        db.flush()
        db.add(
            NormalizedLog(
                raw_log_id=raw.id,
                generated_time=start + timedelta(seconds=index),
                src_ip=f"198.51.100.{(index % 200) + 1}",
                dst_ip=f"10.0.0.{(index % 200) + 1}",
                src_port=40000 + index,
                dst_port=443,
                protocol="tcp",
                action="allow",
                app="ssl",
                src_zone="outside",
                dst_zone="inside",
                bytes=800,
                packets=8,
                app_risk=2,
                is_anomaly=index % 20 == 0,
                anomaly_score=-0.1 if index % 20 == 0 else 0.2,
                parsed_json={
                    "parser_profile": "palo_alto",
                    "parse_status": "parsed",
                    "field_count": 110,
                },
            )
        )
    db.commit()
    return int(source.id)


def _authoritative_counts(db) -> dict[str, int]:
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


def _aggregate_contract(
    *,
    rows: int = 20,
    queue_rate: float = 0.2,
    disagreement_rate: float = 0.1,
    drift_status: str = "Stable",
) -> dict:
    return {
        "rows_evaluated": rows,
        "queue_count": int(rows * queue_rate),
        "queue_rate": queue_rate,
        "score_summary": {},
        "confidence_summary": {},
        "missing_feature_values": 0,
        "feature_values_checked": rows * 40,
        "drift": {
            "status": drift_status,
            "quality": {
                "parser_error_rate": 0.0,
                "parser_warning_per_row": 0.0,
                "required_missing_per_row": 0.0,
                "unknown_app_rate": 0.0,
            },
        },
        "rule_shadow_agreement": {
            "disagreement_rate": disagreement_rate,
        },
        "isolation_forest": {
            "persisted_anomaly_rate": 0.05,
        },
        "accuracy_metrics_calculated": False,
        "labels_accessed": False,
        "raw_logs_included": False,
        "ip_addresses_included": False,
        "private_paths_included": False,
        "row_fingerprints_included": False,
        "secrets_exposed": False,
        "operational_contract": {
            "schema_version": v510.OBSERVATION_SCHEMA_VERSION,
            "evidence_role": v510.DEVELOPMENT_EVIDENCE_ROLE,
            "independent_validation": False,
            "authoritative_state_unchanged": True,
            "authoritative_mutations": {
                "alerts": 0,
                "alert_evidence": 0,
                "labels": 0,
                "model_runs": 0,
                "detection_runs": 0,
                "response_actions": 0,
            },
            "private_data_exposed": False,
            "source_identifier_included": False,
            "locked_evidence_used_for_selection": False,
        },
    }


def _add_observation(
    db,
    *,
    key: str,
    source_id: int,
    start: datetime,
    aggregate: dict | None = None,
) -> MLShadowObservation:
    value = aggregate or _aggregate_contract()
    observation = MLShadowObservation(
        observation_key=key,
        candidate_name="governed-shadow-candidate",
        candidate_version="v5.6-frozen",
        contract_fingerprint="a" * 64,
        status="evaluated_shadow_read_only",
        contract_matched=True,
        source_id=source_id,
        window_start=start,
        window_end=start + timedelta(minutes=1),
        observed_start=start,
        observed_end=start + timedelta(minutes=1),
        requested_limit=20,
        rows_evaluated=20,
        queue_count=4,
        queue_rate=float(value["queue_rate"]),
        score_mean=0.4,
        score_p95=0.8,
        confidence_mean=0.7,
        confidence_p95=0.9,
        missing_feature_values=0,
        feature_values_checked=800,
        drift_status=str(value["drift"]["status"]),
        application_total_variation=0.1,
        schema_total_variation=0.05,
        rule_both_queue=2,
        rule_only=1,
        shadow_only=1,
        neither_queue=16,
        disagreement_count=2,
        disagreement_rate=float(
            value["rule_shadow_agreement"]["disagreement_rate"]
        ),
        isolation_anomaly_count=1,
        isolation_anomaly_rate=0.05,
        runtime_seconds=0.25,
        aggregate_json=value,
        created_by="admin",
    )
    db.add(observation)
    db.commit()
    db.refresh(observation)
    return observation


def test_historical_plan_is_bounded_nonoverlapping_and_development_only():
    Session = _session_factory()
    with Session() as db:
        _add_logs(
            db,
            source_name="source-private-a",
            count=120,
            start=datetime(2026, 7, 1, tzinfo=timezone.utc),
        )
        _add_logs(
            db,
            source_name="source-private-b",
            count=20,
            start=datetime(2026, 7, 2, tzinfo=timezone.utc),
        )
        plan = v510.governed_historical_observation_plan(
            db,
            minimum_rows=50,
            batch_limit=20,
        )

    assert plan["source_scope_count"] == 2
    assert plan["observation_scope_count"] == 3
    assert plan["sufficient_scope_count"] == 2
    assert plan["insufficient_scope_count"] == 1
    assert plan["independent_validation"] is False
    assert plan["evidence_role"] == (
        "reused_development_operational_evidence_only"
    )
    assert plan["scope_contract"]["non_overlapping_within_source"] is True
    assert plan["scope_contract"]["locked_final_evidence_used_for_selection"] is False
    for scope in plan["scopes"]:
        assert scope["requested_limit"] <= 20
        assert scope["independent_validation"] is False
        assert scope["source_identifier_included"] is False
    first, second = plan["scopes"][:2]
    assert first["window_end"] < second["window_start"]
    serialized = json.dumps(plan, default=str)
    assert "source-private" not in serialized
    assert "198.51.100." not in serialized
    assert "private-evidence" not in serialized


def test_operational_acceptance_uses_no_accuracy_metrics_or_identifiers():
    Session = _session_factory()
    with Session() as db:
        source_id = _add_logs(
            db,
            source_name="private-source",
            count=2,
            start=datetime(2026, 7, 1, tzinfo=timezone.utc),
        )
        _add_observation(
            db,
            key="1" * 64,
            source_id=source_id,
            start=datetime(2026, 7, 1, tzinfo=timezone.utc),
        )
        _add_observation(
            db,
            key="2" * 64,
            source_id=source_id,
            start=datetime(2026, 7, 1, 1, tzinfo=timezone.utc),
        )
        before = _authoritative_counts(db)
        result = v510.shadow_operational_acceptance_summary(db)
        after = _authoritative_counts(db)

    assert result["operational_acceptance_passed"] is True
    assert result["gates_passed"] == result["gates_total"]
    assert result["accuracy_metrics_calculated"] is False
    assert result["independent_validation"] is False
    assert result["rules_alert_authoritative"] is True
    assert result["isolation_forest_advisory_only"] is True
    assert result["model_activated"] is False
    assert result["response_automation_allowed"] is False
    assert before == after
    serialized = json.dumps(result, default=str)
    assert "private-source" not in serialized
    assert "198.51.100." not in serialized
    for forbidden in ("precision", "recall", "\"f1\"", "raw_line"):
        assert forbidden not in serialized.lower()


def test_historical_execution_is_idempotent_and_mutation_free(
    monkeypatch,
):
    _configure(monkeypatch)
    Session = _session_factory()
    with Session() as db:
        source_id = _add_logs(
            db,
            source_name="source-a",
            count=60,
            start=datetime(2026, 7, 1, tzinfo=timezone.utc),
        )
        before = _authoritative_counts(db)

        def record(
            db,
            *,
            source_id,
            start_at,
            end_at,
            limit,
            **_kwargs,
        ):
            key = f"{source_id:04d}{int(start_at.timestamp()):060d}"[-64:]
            existing = db.scalar(
                select(MLShadowObservation).where(
                    MLShadowObservation.observation_key == key
                )
            )
            if existing is None:
                existing = _add_observation(
                    db,
                    key=key,
                    source_id=source_id,
                    start=start_at,
                )
                created = True
            else:
                created = False
            return {
                "ok": True,
                "status": (
                    "shadow_observation_recorded"
                    if created
                    else "observation_already_recorded"
                ),
                "observation_created": created,
                "idempotent_reuse": not created,
                "observation": v59.shadow_observation_to_dict(existing),
            }

        monkeypatch.setattr(
            v510.v59,
            "record_governed_shadow_observation",
            record,
        )
        first = v510.run_historical_shadow_observations(
            db,
            actor="admin",
            maximum_sources=1,
            maximum_windows_per_source=1,
            batch_limit=20,
        )
        second = v510.run_historical_shadow_observations(
            db,
            actor="admin",
            maximum_sources=1,
            maximum_windows_per_source=1,
            batch_limit=20,
        )
        after = _authoritative_counts(db)
        observation_count = int(
            db.scalar(
                select(func.count()).select_from(MLShadowObservation)
            )
            or 0
        )

    assert first["created_observation_count"] == 1
    assert second["created_observation_count"] == 0
    assert second["idempotent_reuse_count"] == 1
    assert observation_count == 1
    assert before == after
    assert first["safety"]["alert_case_label_model_detection_response_mutations"] == 0


def test_cancellation_persists_no_partial_observation(monkeypatch):
    _configure(monkeypatch)
    Session = _session_factory()
    with Session() as db:
        _add_logs(
            db,
            source_name="source-a",
            count=60,
            start=datetime(2026, 7, 1, tzinfo=timezone.utc),
        )
        result = v510.run_historical_shadow_observations(
            db,
            actor="admin",
            should_stop=lambda: True,
        )
        observation_count = int(
            db.scalar(
                select(func.count()).select_from(MLShadowObservation)
            )
            or 0
        )

    assert result["status"] == "cancelled_without_partial_scope_persist"
    assert result["observations_executed"] == 0
    assert observation_count == 0


def test_contract_mismatch_fails_closed_without_observation(monkeypatch):
    _configure(monkeypatch)
    monkeypatch.setattr(
        v510.v58,
        "inspect_frozen_candidate_contract",
        lambda: {"matched": False},
    )
    Session = _session_factory()
    with Session() as db:
        _add_logs(
            db,
            source_name="source-a",
            count=60,
            start=datetime(2026, 7, 1, tzinfo=timezone.utc),
        )
        result = v510.run_historical_shadow_observations(
            db,
            actor="admin",
        )
        observation_count = int(
            db.scalar(
                select(func.count()).select_from(MLShadowObservation)
            )
            or 0
        )

    assert result["status"] == (
        "failed_closed_candidate_contract_mismatch"
    )
    assert result["observations_executed"] == 0
    assert result["candidate_contract_matched"] is False
    assert observation_count == 0


def test_cold_and_warm_ml_governance_responses_are_equivalent():
    Session = _session_factory()
    with Session() as db:
        _add_logs(
            db,
            source_name="source-a",
            count=12,
            start=datetime(2026, 7, 1, tzinfo=timezone.utc),
        )
        cold = ml_service.evaluation_report(db)
        warm = ml_service.evaluation_report(db)

    assert cold == warm
    assert cold["dataset_profile"]["total_logs"] == 12
    assert cold["model_status"]["total_logs"] == 12
