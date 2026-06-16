import json

from atdr.app.benchmarks.readiness import readiness_gate_v9_production_readiness_track
from atdr.app.core.config import Settings
from atdr.app.services.detection_service import run_detection
from atdr.app.services.log_service import import_log_file
from atdr.app.services.source_service import get_or_create_source
from atdr.scripts import production_readiness_doctor as doctor_module
from atdr.scripts import run_v30_real_source_pilot_validation as pilot_module
from atdr.scripts.production_readiness_doctor import run_production_readiness_doctor
from atdr.scripts.run_postgres_lab_validation import run_postgres_lab_validation
from atdr.scripts.run_source_scenario import SCENARIO_DIR, _temp_session_factory
from atdr.scripts.run_v30_real_source_pilot_validation import run_v30_real_source_pilot_validation


def test_readiness_v9_never_marks_production_ready():
    result = readiness_gate_v9_production_readiness_track(
        final_controlled_validation_passed=True,
        real_source_pilot_validated=True,
        postgres_lab_validated=True,
        production_doctor_blockers=[],
        observability_plan_exists=True,
        ml_monitoring_plan_exists=True,
        runbook_updated=True,
    )

    assert result["version"] == "v9"
    assert result["decision"] == "production_readiness_candidate"
    assert result["production_ready"] is False
    assert result["production_readiness_claim"] is False
    assert result["production_promoted"] is False
    assert result["response_automation_allowed"] is False
    assert result["real_firewall_blocking_enabled"] is False


def test_production_readiness_doctor_is_secret_safe(monkeypatch):
    monkeypatch.setattr(doctor_module, "_tracked_files", lambda: [])
    settings = Settings(
        JWT_SECRET_KEY="change-this-dev-secret",
        OIDC_CLIENT_SECRET="super-secret-value",
        DEMO_ADMIN_PASSWORD="admin123",
        DEMO_ANALYST_PASSWORD="analyst123",
    )

    result = run_production_readiness_doctor(settings=settings)
    rendered = json.dumps(result)

    assert result["production_ready"] is False
    assert result["response_automation_allowed"] is False
    assert "super-secret-value" not in rendered
    assert any("jwt" in item.lower() for item in result["warnings"])


def test_postgres_lab_validation_blocks_cleanly_on_sqlite():
    settings = Settings(DATABASE_URL="sqlite:///./atdr.db")

    result = run_postgres_lab_validation(settings=settings)

    assert result["ok"] is True
    assert result["status"] == "postgres_lab_validation_blocked_by_environment"
    assert result["postgres_lab_validated"] is False
    assert result["current_database_modified"] is False
    assert result["response_automation_allowed"] is False


def test_real_source_pilot_validation_reads_source_without_response(monkeypatch):
    engine, SessionFactory = _temp_session_factory()
    try:
        with SessionFactory() as db:
            source = get_or_create_source(
                db,
                name="v30-test-firewall",
                source_type="firewall",
                parser_profile="palo_alto",
            )
            db.flush()
            db.commit()
            db.refresh(source)
            import_log_file(
                db,
                SCENARIO_DIR / "port_scan_like_traffic.txt",
                actor="pytest",
                source_id=source.id,
                parser_profile="palo_alto",
            )
            run_detection(db, use_ml=False, source_id=source.id)

        monkeypatch.setattr(pilot_module, "SessionLocal", SessionFactory)
        result = run_v30_real_source_pilot_validation(
            source_name="v30-test-firewall",
            expected_min_logs=10,
        )

        assert result["ok"] is True
        assert result["real_source_pilot_validated"] is True
        assert result["counts"]["raw_logs"] == 10
        assert result["counts"]["normalized_logs"] == 10
        assert result["checks"][-2]["name"] == "no_automatic_response"
        assert result["response_automation_allowed"] is False
        assert result["real_firewall_blocking_enabled"] is False
    finally:
        engine.dispose()


def test_real_source_pilot_dry_run_writes_nothing():
    result = run_v30_real_source_pilot_validation(dry_run=True)

    assert result["ok"] is True
    assert result["status"] == "dry_run"
    assert result["current_database_modified"] is False
    assert result["real_source_pilot_validated"] is False
