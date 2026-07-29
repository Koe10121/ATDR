from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from atdr.app.db.database import Base
from atdr.app.db.models import Alert, AuditLog, DetectionRun, MLLabel, MLModelRun, NormalizedLog, RawLog, ResponseAction
from atdr.app.detection import v51_supervised_lifecycle as lifecycle
from atdr.scripts import manage_supervised_lifecycle as lifecycle_cli


class _ConstantQueueModel:
    classes_ = np.asarray(["non_threat", "needs_review"])

    def predict_proba(self, frame):
        return np.asarray([[0.2, 0.8] for _ in range(len(frame))])


def _session_factory():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, autoflush=False, autocommit=False)


def _add_log(db, *, index: int = 1) -> NormalizedLog:
    raw = RawLog(
        raw_line=f"synthetic-v51-{index}",
        raw_line_hash=f"{index:064x}",
    )
    db.add(raw)
    db.flush()
    log = NormalizedLog(
        raw_log_id=raw.id,
        generated_time=datetime(2026, 1, 1, 0, 0, index),
        src_ip="198.51.100.10",
        dst_ip="10.0.0.10",
        src_port=40000 + index,
        dst_port=443,
        protocol="tcp",
        action="allow",
        app="ssl",
        src_zone="outside",
        dst_zone="inside",
        bytes=500,
        packets=5,
        app_risk=2,
        parsed_json={"parser_profile": "palo_alto"},
    )
    db.add(log)
    db.flush()
    return log


def _registered_candidate(db, path: Path, *, eligible: bool = False) -> MLModelRun:
    artifact = {
        "schema_version": lifecycle.V51_VERSION,
        "model_name": "supervised_random_forest",
        "model_version": "v5.1-test-model",
        "model_type": lifecycle.V51_MODEL_TYPE,
        "target_mode": lifecycle.V51_TARGET_MODE,
        "model": _ConstantQueueModel(),
        "positive_class": "needs_review",
        "threshold": 0.7,
        "feature_set_version": lifecycle.V51_FEATURE_SET_VERSION,
        "feature_schema": {"numeric": [], "categorical": [], "excluded_leakage_features": []},
        "calibration_method": "sigmoid_on_dedicated_calibration_partition",
        "production_promoted": False,
        "response_automation_allowed": False,
    }
    joblib.dump(artifact, path)
    checksum = lifecycle._artifact_hash(path)
    run = MLModelRun(
        model_name="supervised_random_forest",
        model_version="v5.1-test-model",
        operation="train_supervised",
        status="registered_candidate",
        actor="tester",
        model_path=str(path),
        artifact_sha256=checksum,
        artifact_size_bytes=path.stat().st_size,
        training_log_count=10,
        feature_columns_json=[],
        metrics_json={
            "model_type": lifecycle.V51_MODEL_TYPE,
            "target_mode": lifecycle.V51_TARGET_MODE,
            "feature_set_metadata": {"feature_set_version": lifecycle.V51_FEATURE_SET_VERSION},
            "dataset_snapshot_id": "dataset-test-fingerprint",
            "calibration_method": "sigmoid_on_dedicated_calibration_partition",
            "threshold": 0.7,
            "runtime_checks": {"serialization_round_trip": True, "checksum_verified": True},
            "shadow_safety_passed": True,
            "strict_gates": {"decision_support_eligible": eligible},
            "promotion_gate": {
                "decision": "candidate_only",
                "production_promoted": False,
                "response_automation_allowed": False,
            },
        },
        message="test governed candidate",
    )
    db.add(run)
    db.commit()
    return run


def test_governed_shadow_activation_keeps_legacy_artifact_untouched(tmp_path):
    Session = _session_factory()
    candidate_path = tmp_path / "candidate.joblib"
    legacy_path = tmp_path / "legacy.joblib"
    legacy_path.write_bytes(b"legacy-unknown-artifact")
    legacy_before = legacy_path.read_bytes()
    with Session() as db:
        candidate = _registered_candidate(db, candidate_path)
        result = lifecycle.activate_governed_supervised_model(
            db,
            model_id=candidate.id,
            lifecycle_state="shadow_observation",
            actor="tester",
        )
        status = lifecycle.supervised_lifecycle_status(db)

    assert result["ok"] is True
    assert result["lifecycle_state"] == "shadow_observation"
    assert status["lifecycle_state"] == "shadow_observation"
    assert status["model_version"] == "v5.1-test-model"
    assert status["production_promoted"] is False
    assert status["response_automation_allowed"] is False
    assert legacy_path.read_bytes() == legacy_before


def test_decision_support_activation_is_denied_when_strict_gates_fail(tmp_path):
    Session = _session_factory()
    with Session() as db:
        candidate = _registered_candidate(db, tmp_path / "candidate.joblib", eligible=False)
        result = lifecycle.activate_governed_supervised_model(
            db,
            model_id=candidate.id,
            lifecycle_state="decision_support",
            actor="tester",
        )

    assert result["ok"] is False
    assert result["status"] == "quality_gates_failed"
    assert result["required_state"] == "shadow_observation"
    assert result["production_promoted"] is False


def test_production_promotion_is_never_a_valid_lifecycle_activation(tmp_path):
    Session = _session_factory()
    with Session() as db:
        candidate = _registered_candidate(db, tmp_path / "candidate.joblib", eligible=True)
        result = lifecycle.activate_governed_supervised_model(
            db,
            model_id=candidate.id,
            lifecycle_state="production_promoted",
            actor="tester",
        )

    assert result["ok"] is False
    assert result["status"] == "rejected"
    assert result["production_promoted"] is False


def test_lifecycle_cli_accepts_explicit_read_only_status():
    args = lifecycle_cli._build_parser().parse_args(["--status", "--pretty"])

    assert args.status is True
    assert args.pretty is True
    assert args.activate_model_id is None
    assert args.disable is False
    assert args.rollback is False
    assert args.snapshot_telemetry is False


def test_lifecycle_cli_accepts_aggregate_telemetry_snapshot():
    args = lifecycle_cli._build_parser().parse_args(["--snapshot-telemetry", "--actor", "tester"])

    assert args.snapshot_telemetry is True
    assert args.actor == "tester"


def test_shadow_scoring_is_read_only_and_returns_evidence_provenance(tmp_path):
    Session = _session_factory()
    with Session() as db:
        log = _add_log(db)
        candidate = _registered_candidate(db, tmp_path / "candidate.joblib")
        lifecycle.activate_governed_supervised_model(
            db,
            model_id=candidate.id,
            lifecycle_state="shadow_observation",
            actor="tester",
        )
        before = {
            "alerts": int(db.scalar(select(func.count(Alert.id))) or 0),
            "detections": int(db.scalar(select(func.count(DetectionRun.id))) or 0),
            "responses": int(db.scalar(select(func.count(ResponseAction.id))) or 0),
            "labels": int(db.scalar(select(func.count(MLLabel.id))) or 0),
        }
        result = lifecycle.score_governed_supervised_log(db, log)
        after = {
            "alerts": int(db.scalar(select(func.count(Alert.id))) or 0),
            "detections": int(db.scalar(select(func.count(DetectionRun.id))) or 0),
            "responses": int(db.scalar(select(func.count(ResponseAction.id))) or 0),
            "labels": int(db.scalar(select(func.count(MLLabel.id))) or 0),
        }

    assert result["queue_decision"] == "needs_review"
    assert result["queue_probability"] == 0.8
    assert result["threshold"] == 0.7
    assert result["lifecycle_state"] == "shadow_observation"
    assert result["used_for_alert_creation"] is False
    assert result["used_for_severity"] is False
    assert result["used_for_suppression"] is False
    assert result["response_automation_allowed"] is False
    assert before == after


def test_shadow_model_failure_falls_back_without_side_effects(tmp_path, monkeypatch):
    Session = _session_factory()
    with Session() as db:
        log = _add_log(db)
        candidate = _registered_candidate(db, tmp_path / "candidate.joblib")
        lifecycle.activate_governed_supervised_model(
            db,
            model_id=candidate.id,
            lifecycle_state="shadow_observation",
            actor="tester",
        )
        monkeypatch.setattr(
            lifecycle,
            "_load_governed_artifact",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(ValueError("incompatible")),
        )
        response_count = int(db.scalar(select(func.count(ResponseAction.id))) or 0)
        result = lifecycle.score_governed_supervised_log(db, log)
        response_count_after = int(db.scalar(select(func.count(ResponseAction.id))) or 0)

    assert result["predicted_label"] is None
    assert result["model_failure_fallback"] is True
    assert result["rule_detection_continues"] is True
    assert response_count_after == response_count == 0


def test_disable_is_audited_and_preserves_evidence_and_labels(tmp_path):
    Session = _session_factory()
    with Session() as db:
        log = _add_log(db)
        db.add(
            MLLabel(
                log_id=log.id,
                label="benign",
                attack_type="normal",
                confidence=5,
                reviewer="tester",
                reviewed=True,
            )
        )
        db.commit()
        candidate = _registered_candidate(db, tmp_path / "candidate.joblib")
        lifecycle.activate_governed_supervised_model(
            db,
            model_id=candidate.id,
            lifecycle_state="shadow_observation",
            actor="tester",
        )
        labels_before = int(db.scalar(select(func.count(MLLabel.id))) or 0)
        result = lifecycle.disable_governed_supervised_model(db, actor="tester")
        labels_after = int(db.scalar(select(func.count(MLLabel.id))) or 0)
        audit = db.scalar(
            select(AuditLog).where(AuditLog.action == "disable_supervised_governed").order_by(AuditLog.id.desc())
        )

    assert result["lifecycle_state"] == "inactive"
    assert result["evidence_deleted"] is False
    assert result["labels_deleted"] is False
    assert labels_after == labels_before == 1
    assert audit is not None
    assert audit.details["response_automation_allowed"] is False


def test_shadow_telemetry_snapshot_is_durable_aggregate_only(tmp_path):
    Session = _session_factory()
    with Session() as db:
        log = _add_log(db)
        candidate = _registered_candidate(db, tmp_path / "candidate.joblib")
        lifecycle.activate_governed_supervised_model(
            db,
            model_id=candidate.id,
            lifecycle_state="shadow_observation",
            actor="tester",
        )
        lifecycle.score_governed_supervised_log(db, log)
        responses_before = int(db.scalar(select(func.count(ResponseAction.id))) or 0)
        labels_before = int(db.scalar(select(func.count(MLLabel.id))) or 0)
        runs_before = int(db.scalar(select(func.count(MLModelRun.id))) or 0)

        result = lifecycle.persist_supervised_telemetry_snapshot(db, actor="tester")
        status = lifecycle.supervised_lifecycle_status(db)
        telemetry_run = db.scalar(
            select(MLModelRun)
            .where(MLModelRun.operation == lifecycle.SHADOW_TELEMETRY_OPERATION)
            .order_by(MLModelRun.id.desc())
        )
        audit = db.scalar(
            select(AuditLog)
            .where(AuditLog.action == lifecycle.SHADOW_TELEMETRY_OPERATION)
            .order_by(AuditLog.id.desc())
        )

        assert int(db.scalar(select(func.count(MLModelRun.id))) or 0) == runs_before + 1
        assert int(db.scalar(select(func.count(ResponseAction.id))) or 0) == responses_before == 0
        assert int(db.scalar(select(func.count(MLLabel.id))) or 0) == labels_before == 0

    serialized = json.dumps(telemetry_run.metrics_json, sort_keys=True)
    assert result["ok"] is True
    assert result["snapshot"]["telemetry"]["inference_count"] >= 1
    assert status["durable_telemetry"]["available"] is True
    assert telemetry_run.model_path == "aggregate-only://supervised-shadow-telemetry"
    assert telemetry_run.metrics_json["privacy"]["aggregate_only"] is True
    assert "raw_line" not in serialized
    assert "198.51.100.10" not in serialized
    assert audit.details["aggregate_only"] is True
    assert audit.details["response_actions_created"] == 0
