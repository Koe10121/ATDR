from pathlib import Path

from atdr.scripts.register_log_source import register_log_source
from atdr.scripts.run_source_scenario import _temp_session_factory








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
    doc = Path("docs/archive/phases/V3_2_NO_HARDWARE_SOURCE_PILOT.md")
    assert doc.exists()
    text = doc.read_text(encoding="utf-8")

    assert "run_v32_no_hardware_source_pilot" in text
    assert "run_v32_syslog_source_simulator" in text
    assert "real_device_forwarding_validated=false" in text
    assert "production_ready=false" in text
    assert "does not claim production readiness" in text.lower()
