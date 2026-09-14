from __future__ import annotations

from datetime import datetime
from pathlib import Path
from types import SimpleNamespace

from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from atdr.app.db.database import Base
from atdr.app.db.models import Alert, NormalizedLog, RawLog, ResponseAction
from atdr.app.detection import runtime_contract, supervised_detector
from atdr.app.detection import v51_supervised_lifecycle
from atdr.app.services import assistant_service, detection_service
from atdr.app.services import v58_shadow_scoring_service


def _session():
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, future=True)()


def _log(db) -> NormalizedLog:
    raw = RawLog(raw_line="synthetic v5.58 runtime evidence")
    db.add(raw)
    db.flush()
    log = NormalizedLog(
        raw_log_id=raw.id,
        generated_time=datetime(2026, 9, 5, 8, 0, 0),
        log_type="TRAFFIC",
        src_ip="198.51.100.10",
        dst_ip="10.0.0.10",
        src_port=44000,
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
    db.commit()
    return log


def _settings(tmp_path: Path, *, shadow_enabled: bool):
    anomaly_path = tmp_path / "isolation.joblib"
    anomaly_path.write_bytes(b"diagnostic artifact marker")
    return SimpleNamespace(
        governed_shadow_scoring_enabled=shadow_enabled,
        governed_shadow_batch_size=25,
        resolved_model_path=anomaly_path,
        response_simulation=True,
    )


def _complete_lifecycle() -> dict:
    return {
        "lifecycle_state": "shadow_observation",
        "model_run_id": 7,
        "model_version": "governed-test-v1",
        "model_type": "calibrated_extra_trees",
        "target_mode": "binary_soc_review_queue",
        "feature_set_version": "v5.1-causal-soc-queue-features-v1",
        "calibration_method": "sigmoid",
        "threshold": 0.4,
        "dataset_fingerprint": "synthetic-governed-test-dataset",
        "validation_status": "strict_gates_passed",
        "decision_support_eligible": True,
        "shadow_safety_passed": True,
        "artifact": {"available": True, "checksum_valid": True},
        "production_promoted": False,
        "response_automation_allowed": False,
        "rule_detection_authoritative": True,
    }


def test_latest_negative_decision_overrides_historical_shadow_state(tmp_path, monkeypatch):
    db = _session()
    monkeypatch.setattr(runtime_contract, "get_settings", lambda: _settings(tmp_path, shadow_enabled=True))
    monkeypatch.setattr(runtime_contract, "_lifecycle_status", lambda _db: _complete_lifecycle())

    status = runtime_contract.supervised_runtime_status(db)

    assert status["state"] == "unqualified"
    assert status["reason_code"] == "latest_governance_decision_selected_no_candidate"
    assert status["historical_lifecycle_state"] == "shadow_observation"
    assert status["scoring_allowed"] is False
    assert status["latest_governance"]["phase"] == "v5.49b"
    assert status["latest_governance"]["evaluation_consumed"] is True
    assert status["production_promoted"] is False
    assert status["response_automation_allowed"] is False
    assert "artifact_sha256" not in status


def test_active_shadow_requires_matching_qualified_decision_and_metadata(tmp_path, monkeypatch):
    db = _session()
    monkeypatch.setattr(runtime_contract, "get_settings", lambda: _settings(tmp_path, shadow_enabled=True))
    monkeypatch.setattr(runtime_contract, "_lifecycle_status", lambda _db: _complete_lifecycle())
    decision = {
        "phase": "future-governed-test",
        "decision": "candidate_selected",
        "candidate_qualified": True,
        "approved_model_version": "governed-test-v1",
        "evaluation_consumed": False,
        "development_gates_passed": True,
        "candidate_frozen": True,
        "protected_evaluation_excluded_from_training": True,
        "reason_codes": [],
    }

    status = runtime_contract.supervised_runtime_status(
        db,
        governance_decision=decision,
    )

    assert status["state"] == "active_shadow"
    assert status["scoring_allowed"] is True
    assert status["metadata_complete"] is True
    assert all(status["decision_gate_checks"].values())
    assert status["used_for_alert_creation"] is False


def test_missing_metadata_fails_closed_even_for_qualified_candidate(tmp_path, monkeypatch):
    db = _session()
    lifecycle = _complete_lifecycle()
    lifecycle["feature_set_version"] = None
    monkeypatch.setattr(runtime_contract, "get_settings", lambda: _settings(tmp_path, shadow_enabled=True))
    monkeypatch.setattr(runtime_contract, "_lifecycle_status", lambda _db: lifecycle)
    decision = {
        "phase": "future-governed-test",
        "decision": "candidate_selected",
        "candidate_qualified": True,
        "approved_model_version": "governed-test-v1",
        "development_gates_passed": True,
        "candidate_frozen": True,
        "protected_evaluation_excluded_from_training": True,
    }

    status = runtime_contract.supervised_runtime_status(
        db,
        governance_decision=decision,
    )

    assert status["state"] == "unavailable"
    assert status["reason_code"] == "registered_artifact_metadata_incomplete"
    assert status["scoring_allowed"] is False


def test_empty_supervised_scope_abstains_after_eligibility_passes(tmp_path, monkeypatch):
    db = _session()
    monkeypatch.setattr(runtime_contract, "get_settings", lambda: _settings(tmp_path, shadow_enabled=True))
    monkeypatch.setattr(
        runtime_contract,
        "supervised_runtime_status",
        lambda _db, requested=True: {
            "state": "active_shadow",
            "reason_code": "governed_shadow_scoring_ready",
            "scoring_allowed": True,
        },
    )

    status = runtime_contract.score_supervised_runtime_batch(db, [], requested=True)

    assert status["state"] == "abstained"
    assert status["reason_code"] == "no_logs_in_detection_scope"
    assert status["rows_scored"] == 0
    assert status["scoring_allowed"] is False


def test_anomaly_runtime_states_are_explicit():
    active = runtime_contract.anomaly_runtime_status(
        requested=True,
        artifact_available=True,
        rows_scored=2,
        anomaly_count=1,
    )
    abstained = runtime_contract.anomaly_runtime_status(
        requested=True,
        artifact_available=True,
        rows_scored=0,
        anomaly_count=0,
    )
    unavailable = runtime_contract.anomaly_runtime_status(
        requested=True,
        artifact_available=False,
        rows_scored=0,
        anomaly_count=0,
    )

    assert active["state"] == "active_advisory"
    assert abstained["state"] == "abstained"
    assert unavailable["state"] == "unavailable"
    assert active["used_for_alert_creation"] is False
    assert active["score_summary"] == {
        "minimum": None,
        "mean": None,
        "maximum": None,
    }
    assert "known_benign_noise_possible" in active["limitation_codes"]


def test_lifecycle_status_is_read_only_by_default(monkeypatch):
    db = _session()
    observed: list[bool] = []

    def shadow_status(_db, *, execute=True):
        observed.append(execute)
        return {"ok": True, "status": "inspection_only"}

    monkeypatch.setattr(
        v58_shadow_scoring_service,
        "governed_shadow_runtime_status",
        shadow_status,
    )

    status = v51_supervised_lifecycle.supervised_lifecycle_status(db)

    assert observed == [False]
    assert status["lifecycle_state"] == "inactive"


def test_legacy_supervised_artifact_is_not_used_implicitly(tmp_path, monkeypatch):
    db = _session()
    log = _log(db)
    legacy_path = tmp_path / "legacy.joblib"
    legacy_path.write_bytes(b"not a trusted model")
    monkeypatch.setattr(
        supervised_detector,
        "get_settings",
        lambda: SimpleNamespace(resolved_supervised_model_path=legacy_path),
    )
    monkeypatch.setattr(
        runtime_contract,
        "supervised_runtime_status",
        lambda _db, requested=True: {
            "state": "unqualified",
            "reason_code": "latest_governance_decision_selected_no_candidate",
            "scoring_allowed": False,
            "historical_lifecycle_state": "shadow_observation",
            "model_version": "historical-only",
            "feature_set_version": "historical-only",
            "calibration_method": "sigmoid",
        },
    )

    prediction = supervised_detector.predict_supervised_log(db, log.id)

    assert prediction["predicted_label"] is None
    assert prediction["runtime_state"] == "unqualified"
    assert prediction["used_for_alert_creation"] is False
    assert prediction["used_for_suppression"] is False


def test_normal_detection_reports_all_layers_and_ml_cannot_create_alert(tmp_path, monkeypatch):
    db = _session()
    log = _log(db)
    settings = SimpleNamespace(
        min_alert_score=30,
        resolved_model_path=tmp_path / "isolation.joblib",
        response_simulation=True,
    )
    settings.resolved_model_path.write_bytes(b"artifact marker")
    monkeypatch.setattr(detection_service, "get_settings", lambda: settings)

    def mark_advisory(_db, *, limit=None):
        log.is_anomaly = True
        log.anomaly_score = -0.2
        return {log.id: {"is_anomaly": True, "anomaly_score": -0.2}}

    monkeypatch.setattr(detection_service, "apply_model_to_db", mark_advisory)
    monkeypatch.setattr(
        detection_service,
        "score_supervised_runtime_batch",
        lambda _db, _logs, requested: {
            "state": "unqualified",
            "reason_code": "latest_governance_decision_selected_no_candidate",
            "scoring_allowed": False,
            "rows_considered": len(_logs),
            "rows_scored": 0,
            "rows_abstained": 0,
            "queue_count": 0,
            "queue_rate": 0.0,
            "decision_support_only": True,
            "used_for_alert_creation": False,
            "used_for_severity": False,
            "used_for_suppression": False,
        },
    )

    result = detection_service.run_detection(db, limit=10, use_ml=True, actor="v558-test")
    layers = result["detection_layers"]

    assert layers["rules"]["state"] == "active_authoritative"
    assert layers["anomaly"]["state"] == "active_advisory"
    assert layers["supervised"]["state"] == "unqualified"
    assert layers["hybrid"]["state"] == "active_advisory"
    assert layers["response"]["state"] == "simulation_only"
    assert layers["model_only_alert_creation_allowed"] is False
    assert layers["rules"]["verdict"] == "authoritative_match"
    assert "outside_to_inside" in layers["rules"]["authoritative_matched_rule_ids"]
    assert "ml_anomaly_detected" in layers["rules"]["matched_rule_ids"]
    assert layers["anomaly"]["score_summary"] == {
        "minimum": -0.2,
        "mean": -0.2,
        "maximum": -0.2,
    }
    assert layers["supervised"]["abstention"]["eligibility_refused"] is True
    assert layers["hybrid"]["analyst_priority"] == "authoritative_rule_review"
    assert layers["analyst_summary"]["evidence_strength"] == "authoritative_rule_evidence"
    assert 1 <= len(layers["analyst_summary"]["recommended_checks"]) <= 3
    assert layers["analyst_summary"]["bounded"] is True
    assert list(db.scalars(select(Alert))) == []
    assert list(db.scalars(select(ResponseAction))) == []


def test_advisory_model_failure_does_not_stop_rule_detection(tmp_path, monkeypatch):
    db = _session()
    _log(db)
    settings = SimpleNamespace(
        min_alert_score=30,
        resolved_model_path=tmp_path / "isolation.joblib",
        response_simulation=True,
    )
    settings.resolved_model_path.write_bytes(b"corrupt artifact")
    monkeypatch.setattr(detection_service, "get_settings", lambda: settings)
    monkeypatch.setattr(
        detection_service,
        "apply_model_to_db",
        lambda _db, *, limit=None: (_ for _ in ()).throw(ValueError("corrupt model")),
    )
    monkeypatch.setattr(
        detection_service,
        "score_supervised_runtime_batch",
        lambda _db, _logs, requested: {
            "state": "unqualified",
            "reason_code": "latest_governance_decision_selected_no_candidate",
            "scoring_allowed": False,
        },
    )

    result = detection_service.run_detection(db, limit=10, use_ml=True, actor="v558-test")

    assert result["evaluated"] == 1
    assert result["detection_layers"]["rules"]["state"] == "active_authoritative"
    assert result["detection_layers"]["anomaly"]["state"] == "unavailable"
    assert result["detection_layers"]["anomaly"]["error_type"] == "ValueError"
    assert list(db.scalars(select(ResponseAction))) == []


def test_assistant_reports_effective_runtime_not_historical_state(monkeypatch):
    db = _session()
    monkeypatch.setattr(
        assistant_service,
        "evaluation_report",
        lambda _db: {
            "anomaly_rate": 0.12,
            "scored_log_count": 100,
            "model_status": {"artifact_exists": True},
        },
    )
    monkeypatch.setattr(
        assistant_service,
        "supervised_model_report",
        lambda _db: {
            "label_count": 120,
            "decision_support_only": True,
            "governed_lifecycle": {"lifecycle_state": "shadow_observation"},
            "effective_runtime": {
                "state": "unqualified",
                "reason_code": "latest_governance_decision_selected_no_candidate",
            },
            "latest_run": {
                "status": "evaluated",
                "promotion_gate": {
                    "production_promoted": False,
                    "response_automation_allowed": False,
                },
            },
        },
    )

    result = assistant_service._answer_ml_question(db, redacted=True)

    assert "Supervised runtime is unqualified" in result.answer
    assert "historical lifecycle is shadow_observation" in result.answer
    assert "deterministic rules are alert-authoritative" in result.details[
        "answer_sections"
    ]["summary"][0]
    assert "api_key" not in str(result.details).lower()
