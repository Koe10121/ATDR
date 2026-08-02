from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

import joblib
import numpy as np
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from atdr.app.db.database import Base
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
from atdr.app.detection import explanations
from atdr.app.detection import v51_supervised_lifecycle as lifecycle
from atdr.app.detection.v519_independent_labeled_validation import (
    V519_LATEST,
    V519_STATE,
    V519_VERSION,
)
from atdr.app.detection.v520_schema_aware_abstention import (
    assess_log_schema_compatibility,
    public_schema_abstention_policy,
    summarize_schema_compatibility,
)
from atdr.app.detection.v520_schema_aware_abstention_validation import (
    V520_LOCK_RECORD,
    run_v520_schema_aware_abstention_validation,
)
from atdr.app.services import ml_evidence_snapshot_service


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


def _add_log(db, *, index: int, profile: str | None = "palo_alto", app: str | None = "ssl") -> NormalizedLog:
    raw = RawLog(raw_line=f"synthetic-v520-{index}", raw_line_hash=f"{index:064x}")
    db.add(raw)
    db.flush()
    parsed_json = {"parse_status": "parsed"}
    if profile is not None:
        parsed_json["parser_profile"] = profile
    log = NormalizedLog(
        raw_log_id=raw.id,
        generated_time=datetime(2026, 8, 1, 0, 0, index),
        src_ip="198.51.100.10",
        dst_ip="10.0.0.10",
        src_port=41000 + index,
        dst_port=443,
        protocol="tcp",
        action="allow",
        app=app,
        src_zone="outside",
        dst_zone="inside",
        bytes=800,
        packets=8,
        app_risk=2,
        parsed_json=parsed_json,
    )
    db.add(log)
    db.flush()
    return log


def _register_candidate(db, path: Path) -> MLModelRun:
    artifact = {
        "schema_version": lifecycle.V51_VERSION,
        "model_name": "supervised_random_forest",
        "model_version": "v5.20-test-model",
        "model_type": lifecycle.V51_MODEL_TYPE,
        "target_mode": lifecycle.V51_TARGET_MODE,
        "model": _ConstantQueueModel(),
        "positive_class": "needs_review",
        "threshold": 0.7,
        "feature_set_version": lifecycle.V51_FEATURE_SET_VERSION,
        "feature_schema": {"numeric": [], "categorical": [], "excluded_leakage_features": []},
        "calibration_method": "sigmoid",
        "production_promoted": False,
        "response_automation_allowed": False,
    }
    joblib.dump(artifact, path)
    run = MLModelRun(
        model_name="supervised_random_forest",
        model_version="v5.20-test-model",
        operation="train_supervised",
        status="registered_candidate",
        actor="tester",
        model_path=str(path),
        artifact_sha256=lifecycle._artifact_hash(path),
        artifact_size_bytes=path.stat().st_size,
        training_log_count=10,
        feature_columns_json=[],
        metrics_json={
            "model_type": lifecycle.V51_MODEL_TYPE,
            "target_mode": lifecycle.V51_TARGET_MODE,
            "feature_set_metadata": {"feature_set_version": lifecycle.V51_FEATURE_SET_VERSION},
            "calibration_method": "sigmoid",
            "threshold": 0.7,
            "runtime_checks": {"serialization_round_trip": True, "checksum_verified": True},
            "shadow_safety_passed": True,
            "strict_gates": {"decision_support_eligible": False},
        },
        message="v5.20 test candidate",
    )
    db.add(run)
    db.commit()
    return run


def _authoritative_counts(db) -> dict[str, int]:
    models = {
        "alerts": Alert,
        "detections": DetectionRun,
        "labels": MLLabel,
        "models": MLModelRun,
        "responses": ResponseAction,
    }
    return {
        name: int(db.scalar(select(func.count()).select_from(model)) or 0)
        for name, model in models.items()
    }


def test_schema_compatibility_is_fail_closed_and_privacy_safe():
    Session = _session_factory()
    with Session() as db:
        compatible = assess_log_schema_compatibility(_add_log(db, index=1))
        legacy = assess_log_schema_compatibility(_add_log(db, index=2, profile=None))
        generic = assess_log_schema_compatibility(_add_log(db, index=3, profile="generic_syslog"))
        unknown = assess_log_schema_compatibility(_add_log(db, index=4, profile="mystery"))
        incomplete = assess_log_schema_compatibility(_add_log(db, index=5, app=None))

    assert compatible["status"] == "compatible"
    assert compatible["scoring_allowed"] is True
    assert legacy["scoring_allowed"] is True
    assert legacy["profile_inferred_from_legacy_default"] is True
    assert generic["status"] == "incompatible_schema"
    assert unknown["status"] == "unknown_schema"
    assert incomplete["status"] == "insufficient_evidence"
    assert incomplete["missing_required_features"] == ["app"]
    assert all(row["private_identifiers_included"] is False for row in [compatible, generic, unknown, incomplete])
    summary = summarize_schema_compatibility([compatible, generic, unknown, incomplete])
    assert summary["scoring_allowed_count"] == 1
    assert summary["abstained_count"] == 3
    assert summary["rules_remain_authoritative"] is True


def test_governed_batch_scores_only_compatible_rows_without_side_effects(tmp_path):
    Session = _session_factory()
    with Session() as db:
        compatible = _add_log(db, index=1)
        incompatible = _add_log(db, index=2, profile="provider_flow")
        candidate = _register_candidate(db, tmp_path / "candidate.joblib")
        lifecycle.activate_governed_supervised_model(
            db,
            model_id=candidate.id,
            lifecycle_state="shadow_observation",
            actor="tester",
        )
        before = _authoritative_counts(db)
        result = lifecycle.score_governed_supervised_logs(db, [compatible, incompatible])
        after = _authoritative_counts(db)

    assert result["ok"] is True
    assert result["status"] == "scored_with_schema_abstentions"
    assert result["schema_compatibility"]["scoring_allowed_count"] == 1
    assert result["schema_compatibility"]["abstained_count"] == 1
    assert result["rows"][0]["queue_probability"] == 0.8
    assert result["rows"][0]["abstained"] is False
    assert result["rows"][1]["queue_probability"] is None
    assert result["rows"][1]["queue_decision"] is None
    assert result["rows"][1]["abstained"] is True
    assert before == after


def test_alert_explanation_surfaces_schema_abstention(monkeypatch):
    Session = _session_factory()
    with Session() as db:
        log = _add_log(db, index=1, profile="raw_fallback", app=None)
        alert = Alert(
            title="Synthetic rule alert",
            alert_type="possible_port_scan",
            threat_score=80,
            severity="high",
            status="open",
            explanation="Rule evidence identified scanning behavior.",
            matched_rules_json=[
                {
                    "code": "possible_port_scan",
                    "title": "Possible port scan",
                    "explanation": "Source touched multiple ports.",
                }
            ],
            recommended_response="Review related logs.",
        )
        db.add(alert)
        db.flush()
        db.add(AlertEvidence(alert_id=alert.id, normalized_log_id=log.id))
        db.commit()
        monkeypatch.setattr(
            explanations,
            "predict_supervised_log",
            lambda *_args, **_kwargs: {
                "predicted_label": None,
                "abstained": True,
                "schema_compatibility": assess_log_schema_compatibility(log),
                "abstention_reason_codes": ["schema_profile_mismatch"],
                "missing_required_features": ["app"],
                "confidence_limitations": ["No supervised probability was produced."],
            },
        )
        result = explanations.build_alert_detection_summary(db, alert)

    assert result["ml_evidence"]["abstained"] is True
    assert result["ml_evidence"]["missing_required_features"] == ["app"]
    assert any("Supervised scoring abstained" in row for row in result["diagnostic_evidence"])
    assert "ML-required field: app" in result["missing_context"]
    assert result["alert_authority"]["layer"] == "deterministic_rules"


def test_ml_evidence_snapshot_exposes_policy_not_secrets(monkeypatch, tmp_path):
    monkeypatch.setattr(ml_evidence_snapshot_service, "CANONICAL_EVIDENCE_PATH", tmp_path / "missing.json")
    monkeypatch.setattr(
        ml_evidence_snapshot_service,
        "model_status",
        lambda _db: {"artifact_exists": False, "latest_training": {}, "latest_scoring": {}},
    )
    monkeypatch.setattr(
        ml_evidence_snapshot_service,
        "list_supervised_models",
        lambda _db, limit=25: {
            "models": [],
            "active_artifact_exists": False,
            "governed_lifecycle": {
                "telemetry": {
                    "schema_compatibility_checked": 4,
                    "schema_abstention_count": 3,
                    "schema_abstention_rate": 0.75,
                    "schema_abstention_reasons": {"schema_profile_mismatch": 3},
                }
            },
        },
    )
    snapshot = ml_evidence_snapshot_service.build_ml_evidence_snapshot(object())
    encoded = json.dumps(snapshot)

    assert snapshot["schema_aware_abstention"]["fail_closed"] is True
    assert snapshot["schema_aware_abstention"]["runtime"]["abstained_count"] == 3
    assert snapshot["schema_aware_abstention"]["incompatible_evidence_scored"] is False
    assert "api_key" not in encoded.lower()
    assert "client_secret" not in encoded.lower()


def test_v519_terminal_lock_is_read_only_and_keeps_fingerprints_private(tmp_path):
    state = {
        "version": V519_VERSION,
        "evaluation_completed": True,
        "adapter_recovery_completed": True,
        "labels_revealed": True,
        "predictions_frozen_before_labels": True,
        "post_reveal_candidate_changes": False,
        "labels_used_for_features": False,
        "labels_used_for_prediction": False,
        "labels_used_for_sampling": False,
        "labels_used_for_tuning": False,
    }
    (tmp_path / V519_STATE).write_text(json.dumps(state), encoding="utf-8")
    (tmp_path / V519_LATEST).write_text(
        json.dumps({"version": V519_VERSION, "status": "evaluated"}),
        encoding="utf-8",
    )
    before = {
        name: (tmp_path / name).read_bytes()
        for name in (V519_STATE, V519_LATEST)
    }
    result = run_v520_schema_aware_abstention_validation(output_dir=tmp_path)
    after = {
        name: (tmp_path / name).read_bytes()
        for name in (V519_STATE, V519_LATEST)
    }

    assert result["ok"] is True
    assert result["v519_terminal_lock"]["locked"] is True
    assert result["fingerprints_exposed"] is False
    assert result["labels_opened"] is False
    assert result["prediction_rows_opened"] is False
    assert before == after
    private_lock = json.loads((tmp_path / V520_LOCK_RECORD).read_text(encoding="utf-8"))
    assert private_lock["terminal_state"] is True
    assert all(row["sha256"] for row in private_lock["files"].values())


def test_public_policy_keeps_ml_and_response_authority_disabled():
    policy = public_schema_abstention_policy()

    assert policy["fail_closed"] is True
    assert policy["incompatible_evidence_scored"] is False
    assert policy["rules_remain_authoritative"] is True
    assert policy["production_promoted"] is False
    assert policy["response_automation_allowed"] is False
