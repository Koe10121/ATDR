from __future__ import annotations

import json
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from atdr.app.db.database import Base
from atdr.app.db.models import NormalizedLog, RawLog
from atdr.app.detection import v5631_advisor_demo_reliability as reliability
from atdr.app.schemas.ml import MLStatusRead
from atdr.app.services import ml_service
from atdr.app.services import v561_anomaly_bootstrap_service as bootstrap
from atdr.scripts import run_v5631_advisor_demo_acceptance as advisor_acceptance


def _session() -> Session:
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    Base.metadata.create_all(engine)
    return Session(engine)


def _normalized(raw: RawLog, *, scored: bool, anomaly: bool) -> NormalizedLog:
    return NormalizedLog(
        raw_log=raw,
        log_type="TRAFFIC",
        action="allow",
        app="ssl",
        protocol="tcp",
        src_zone="trust",
        dst_zone="untrust",
        src_port=51000,
        dst_port=443,
        bytes=500,
        bytes_sent=300,
        bytes_received=200,
        packets=5,
        elapsed_time=1,
        app_risk=2,
        anomaly_score=-0.1 if scored else None,
        is_anomaly=anomaly,
        parsed_json={"parse_status": "parsed"},
    )


def test_anomaly_rate_uses_scored_population_and_reports_coverage():
    db = _session()
    try:
        for index in range(10):
            raw = RawLog(raw_line=f"safe synthetic row {index}")
            db.add(
                _normalized(
                    raw,
                    scored=index < 4,
                    anomaly=index < 2,
                )
            )
        db.commit()

        status = ml_service.model_status(db)
        profile = ml_service.dataset_profile(db)

        assert status["total_logs"] == 10
        assert status["scored_log_count"] == 4
        assert status["current_anomaly_logs"] == 2
        assert status["current_anomaly_rate"] == 50.0
        assert status["anomaly_rate_basis"] == "scored_logs"
        assert status["scoring_coverage_percent"] == 40.0
        assert status["stored_anomaly_prevalence_percent"] == 20.0
        assert profile["current_anomaly_rate"] == 50.0
        assert MLStatusRead.model_validate(status).anomaly_rate_basis == "scored_logs"
    finally:
        db.close()
        db.bind.dispose()


def test_reliability_manifest_requires_fixed_development_gates():
    root = Path(__file__).resolve().parents[2]
    inspection = bootstrap.inspect_anomaly_evidence(
        project_root=root,
        use_committed_synthetic_sample=True,
    )
    manifest = bootstrap._deterministic_manifest(
        inspection,
        contamination=0.02,
        acceptance={
            "anomaly_state": "active_advisory",
            "rows_scored": 41,
            "model_driven_alerts": 0,
            "model_driven_suppressions": 0,
            "labels_created": 0,
            "model_runs_created": 0,
            "detection_runs_created": 0,
            "response_actions_created": 0,
            "rules_alert_authoritative": True,
            "supervised_state": "unqualified",
            "response_state": "simulation_only",
        },
    )
    manifest["protocol_version"] = reliability.VERSION
    manifest["reliability"] = {
        "fixed_gates_passed": True,
        "development_only": True,
        "independent_accuracy_validated": False,
        "controlled_benign_anomaly_rate": 0.05,
        "controlled_suspicious_scenario_recall": 0.8,
        "controlled_malicious_scenario_recall": 1.0,
        "private_holdout_queue_rate": 0.02,
    }

    assert bootstrap.anomaly_manifest_is_valid(manifest) is True
    manifest["reliability"]["fixed_gates_passed"] = False
    assert bootstrap.anomaly_manifest_is_valid(manifest) is False


def test_private_evaluation_is_redacted_and_refuses_unqualified_install(
    tmp_path: Path,
):
    scenario = (
        Path(__file__).resolve().parents[2]
        / "data"
        / "samples"
        / "scenarios"
        / "normal_allowed_traffic.txt"
    )
    base = scenario.read_text(encoding="utf-8").splitlines()[0]
    prefix, _hostname, payload = base.split(maxsplit=2)
    private_path = tmp_path / "operator-private-firewall.log"
    private_path.write_text(
        "\n".join(f"{prefix} test-host-{index} {payload}" for index in range(200)),
        encoding="utf-8",
    )
    artifact = tmp_path / "models" / "isolation_forest.joblib"

    report = reliability.run_anomaly_reliability_evaluation(
        sample_path=private_path,
        limit=200,
        install_candidate=True,
        confirmation=reliability.INSTALL_CONFIRMATION,
        artifact_path=artifact,
        minimum_fit_rows=20,
    )

    assert report["selection"]["candidate_selected"] is False
    assert report["status"] == "candidate_installation_refused"
    assert report["installation"]["installed"] is False
    assert not artifact.exists()
    assert report["safety"]["model_driven_alerts"] == 0
    assert report["safety"]["model_driven_suppressions"] == 0
    assert report["safety"]["labels_created"] == 0
    assert report["safety"]["response_actions_created"] == 0
    encoded = json.dumps(report)
    assert str(private_path) not in encoded
    assert report["privacy"] == {
        "source_paths_exposed": False,
        "raw_logs_exposed": False,
        "network_addresses_exposed": False,
        "identities_exposed": False,
        "fingerprints_exposed": False,
        "secrets_exposed": False,
    }


def test_safe_reliability_error_hides_private_exception_details(tmp_path: Path):
    private_path = tmp_path / "private.log"
    report = reliability.safe_anomaly_reliability_error(
        RuntimeError(f"failed at {private_path}")
    )

    assert str(private_path) not in json.dumps(report)
    assert report["candidate_installed"] is False
    assert report["safety"]["supervised_model_activated"] is False
    assert report["safety"]["automatic_response_enabled"] is False


def test_advisor_acceptance_requires_temp_db_and_composes_safe_stages(monkeypatch):
    refused = advisor_acceptance.run_advisor_demo_acceptance(use_temp_db=False)
    assert refused["status"] == "explicit_temp_database_required"

    monkeypatch.setattr(
        advisor_acceptance,
        "run_v557_analyst_workflow_acceptance",
        lambda: {
            "ok": True,
            "database_mode": "temporary_in_memory_sqlite",
            "configured_database_accessed": False,
            "checks": {"passed": 24, "total": 24, "failed": []},
            "stages": {
                name: {"passed": True}
                for name in (
                    "ingestion",
                    "parsing_and_normalization",
                    "detection",
                    "explanation_and_related_evidence",
                    "case_investigation",
                    "simulated_response",
                    "audit_history",
                )
            },
        },
    )
    monkeypatch.setattr(
        advisor_acceptance,
        "evaluate_assistant_qa",
        lambda: {
            "ok": True,
            "quality_dimensions": {
                "zero_authoritative_side_effects": True,
            },
            "answer_quality_cases": 30,
            "answer_concision": {"all_word_budgets_passed": True},
            "conversation_sequence_results": [{"passed": True}],
        },
    )
    monkeypatch.setattr(
        advisor_acceptance,
        "_anomaly_stage",
        lambda: {"passed": True},
    )
    monkeypatch.setattr(
        advisor_acceptance,
        "build_provider_report",
        lambda *, execute: {
            "ok": True,
            "provider": "gemini",
            "llm_enabled": True,
            "provider_configured": True,
            "model_configured": True,
            "api_key_configured": True,
            "executed_provider_call": execute,
            "structured_output_valid": True,
            "raw_log_context_included": False,
            "redaction_enabled": True,
            "secrets_exposed": False,
        },
    )

    report = advisor_acceptance.run_advisor_demo_acceptance(
        use_temp_db=True,
        execute_provider_probe=True,
    )

    assert report["ok"] is True
    assert all(report["stages"].values())
    assert report["runtime_truth"]["rules"] == "active_authoritative"
    assert report["runtime_truth"]["supervised"] == "unqualified"
    assert report["runtime_truth"]["response"] == "simulation_only"
    assert report["provider"]["executed_provider_call"] is True
    assert report["provider"]["raw_log_context_included"] is False
    assert report["safety"]["current_database_accessed"] is False
    assert report["safety"]["model_activated_or_promoted"] is False
