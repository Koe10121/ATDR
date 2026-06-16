from pathlib import Path

from atdr.scripts.register_log_source import register_log_source
from atdr.scripts.run_source_scenario import _temp_session_factory
from atdr.scripts.run_v32_no_hardware_source_pilot import run_v32_no_hardware_source_pilot
from atdr.scripts.run_v32_syslog_source_simulator import run_v32_syslog_source_simulator


def test_v32_syslog_source_simulator_dry_run_is_non_mutating():
    result = run_v32_syslog_source_simulator(dry_run=True, count=30)

    assert result["ok"] is True
    assert result["dry_run"] is True
    assert result["hardware_required"] is False
    assert result["current_database_modified"] is False
    assert result["real_device_forwarding_validated"] is False
    assert result["production_ready"] is False


def test_v32_syslog_source_simulator_imports_safe_rows_in_temp_db():
    result = run_v32_syslog_source_simulator(use_temp_db=True, count=100)

    assert result["ok"] is True
    assert result["simulated_source_validated"] is True
    assert result["counts"]["raw_logs_imported"] == 100
    assert result["counts"]["normalized_logs_created"] == 100
    assert result["counts"]["parse_successes"] == 97
    assert result["counts"]["parse_failures"] == 3
    assert result["response_safety"]["automatic_response_actions_created"] == 0
    assert result["real_firewall_blocking_enabled"] is False


def test_v32_no_hardware_pilot_validates_source_pipeline_in_temp_db():
    result = run_v32_no_hardware_source_pilot(use_temp_db=True, count=100)

    assert result["ok"] is True
    assert result["status"] == "simulated_source_pilot_validated"
    assert result["simulated_source_validated"] is True
    assert result["real_device_forwarding_validated"] is False
    assert result["counts"]["parse_successes"] == 97
    assert result["counts"]["parse_failures"] == 3
    assert result["detection_result"]["source_name"] == "lab-firewall-sim-1"
    assert result["detection_result"]["top_attack_types"] == [{"name": "port_scan", "count": 1}]
    assert result["counts"]["after_detection"]["alerts"] >= 1
    assert result["case_summaries"]
    assert result["response_safety"]["automatic_response_actions_created"] == 0
    assert result["v30_validator"]["real_device_forwarding_validated"] is False
    assert result["production_ready"] is False


def test_register_log_source_helper_is_idempotent_for_v32(monkeypatch):
    engine, SessionFactory = _temp_session_factory()
    try:
        monkeypatch.setattr("atdr.scripts.register_log_source.init_db", lambda: None)
        monkeypatch.setattr("atdr.scripts.register_log_source.SessionLocal", SessionFactory)

        first = register_log_source(
            name="lab-firewall-sim-1",
            source_type="firewall",
            parser_profile="palo_alto",
            host="127.0.0.1",
            port=5514,
        )
        second = register_log_source(
            name="lab-firewall-sim-1",
            source_type="firewall",
            parser_profile="palo_alto",
            host="127.0.0.1",
            port=5514,
        )

        assert first["ok"] is True
        assert first["action"] == "created"
        assert second["ok"] is True
        assert second["action"] == "updated"
        assert second["source"]["name"] == "lab-firewall-sim-1"
        assert second["source"]["health"]["status"] == "idle"
    finally:
        engine.dispose()


def test_v32_docs_have_safe_commands_and_no_production_claim():
    doc = Path("docs/V3_2_NO_HARDWARE_SOURCE_PILOT.md")
    assert doc.exists()
    text = doc.read_text(encoding="utf-8")

    assert "run_v32_no_hardware_source_pilot" in text
    assert "run_v32_syslog_source_simulator" in text
    assert "real_device_forwarding_validated=false" in text
    assert "production_ready=false" in text
    assert "does not claim production readiness" in text.lower()

