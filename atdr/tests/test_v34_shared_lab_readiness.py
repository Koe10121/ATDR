import json
import sqlite3
from pathlib import Path

from atdr.app.core.config import PROJECT_ROOT, Settings
from atdr.scripts.config_doctor import run_config_doctor
from atdr.scripts.profile_dashboard_summary import profile_dashboard_summary
from atdr.scripts.run_backup_restore_drill import run_backup_restore_drill
from atdr.scripts.run_postgres_lab_validation import run_postgres_lab_validation
from atdr.scripts.run_v34_shared_lab_readiness import REAL_SOURCE_PILOT_CHECKLIST, run_v34_shared_lab_readiness


def _create_tiny_sqlite_db(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        path.unlink()
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT)")
        connection.execute("CREATE TABLE raw_logs (id INTEGER PRIMARY KEY, raw_line TEXT)")
        connection.execute("CREATE TABLE normalized_logs (id INTEGER PRIMARY KEY, raw_log_id INTEGER)")
        connection.execute("CREATE TABLE alerts (id INTEGER PRIMARY KEY, title TEXT)")
        connection.execute("INSERT INTO users (username) VALUES ('admin')")
        connection.execute("INSERT INTO raw_logs (raw_line) VALUES ('sample')")
        connection.execute("INSERT INTO normalized_logs (raw_log_id) VALUES (1)")
        connection.commit()


def test_backup_restore_drill_copies_sqlite_without_modifying_live_db():
    db_path = PROJECT_ROOT / ".tmp" / "pytest-v34-source.sqlite3"
    output_dir = PROJECT_ROOT / ".tmp" / "pytest-v34-backups"
    _create_tiny_sqlite_db(db_path)

    result = run_backup_restore_drill(
        settings=Settings(DATABASE_URL=f"sqlite:///{db_path}"),
        output_dir=output_dir,
        dry_run=False,
    )

    assert result["ok"] is True
    assert result["status"] == "sqlite_backup_restore_drill_passed"
    assert result["current_database_modified"] is False
    assert result["restore_check_performed"] is True
    assert result["row_counts"]["users"] == 1
    assert result["row_counts"]["raw_logs"] == 1
    assert Path(result["backup_path"]).exists()


def test_backup_restore_drill_dry_run_writes_no_backup():
    db_path = PROJECT_ROOT / ".tmp" / "pytest-v34-dry.sqlite3"
    _create_tiny_sqlite_db(db_path)

    result = run_backup_restore_drill(
        settings=Settings(DATABASE_URL=f"sqlite:///{db_path}"),
        output_dir=PROJECT_ROOT / ".tmp" / "pytest-v34-dry-backups",
        dry_run=True,
    )

    assert result["ok"] is True
    assert result["status"] == "dry_run"
    assert result["current_database_modified"] is False
    assert result["restore_check_performed"] is False


def test_config_doctor_warns_for_demo_passwords_and_keeps_oidc_secret_hidden():
    settings = Settings(
        JWT_SECRET_KEY="change-this-dev-secret",
        DEMO_ADMIN_PASSWORD="admin123",
        DEMO_ANALYST_PASSWORD="analyst123",
        OIDC_ENABLED=False,
        OIDC_CLIENT_SECRET="do-not-render-this-secret",
        OIDC_PROVIDER_NAME="School OIDC",
    )

    result = run_config_doctor(settings=settings)
    rendered = json.dumps(result)

    assert result["ok"] is True
    assert any(issue["code"] == "default-demo-password" for issue in result["issues"])
    assert any(issue["code"] == "oidc-partial-disabled" for issue in result["issues"])
    assert "do-not-render-this-secret" not in rendered


def test_postgres_validation_reports_sqlite_local_mode_and_backup_readiness():
    result = run_postgres_lab_validation(settings=Settings(DATABASE_URL="sqlite:///./atdr.db"))

    assert result["ok"] is True
    assert result["status"] == "postgres_lab_validation_blocked_by_environment"
    assert result["local_sqlite_mode"] is True
    assert result["backup_restore_validated"] is False
    assert any(item["name"] == "backup_restore_readiness" for item in result["checks"])
    assert result["response_automation_allowed"] is False


def test_dashboard_profile_is_read_only(monkeypatch):
    from atdr.scripts.run_source_scenario import _temp_session_factory

    engine, SessionFactory = _temp_session_factory()
    try:
        monkeypatch.setattr("atdr.scripts.profile_dashboard_summary.SessionLocal", SessionFactory)
        result = profile_dashboard_summary(include_full_summary=False)

        assert result["ok"] is True
        assert result["read_only"] is True
        assert "count_normalized_logs" in result["timings"]
        assert result["production_ready"] is False
    finally:
        engine.dispose()


def test_v34_report_is_conservative_and_checklist_driven(monkeypatch):
    monkeypatch.setattr(
        "atdr.scripts.run_v34_shared_lab_readiness.run_production_readiness_doctor",
        lambda settings: {
            "ok": True,
            "warnings": [],
            "blockers": [],
            "production_ready": False,
            "response_automation_allowed": False,
        },
    )
    monkeypatch.setattr(
        "atdr.scripts.run_v34_shared_lab_readiness.run_postgres_lab_validation",
        lambda settings, include_smoke=False, include_sample_ingest=False: {
            "ok": True,
            "status": "postgres_lab_validation_blocked_by_environment",
            "postgres_lab_validated": False,
        },
    )
    monkeypatch.setattr(
        "atdr.scripts.run_v34_shared_lab_readiness.run_backup_restore_drill",
        lambda settings, dry_run=True: {"ok": True, "status": "dry_run"},
    )
    monkeypatch.setattr(
        "atdr.scripts.run_v34_shared_lab_readiness.profile_dashboard_summary",
        lambda include_full_summary=True: {"ok": True, "warnings": [], "read_only": True},
    )
    monkeypatch.setattr(
        "atdr.scripts.run_v34_shared_lab_readiness.operations_readiness_report",
        lambda: {"ok": True, "warnings": [], "read_only": True},
    )
    monkeypatch.setattr(
        "atdr.scripts.run_v34_shared_lab_readiness.run_v35_real_source_pilot_check",
        lambda source_name=None, expected_min_logs=1, settings=None: {
            "ok": True,
            "status": "real_device_forwarding_not_validated",
            "source_pipeline_validated": False,
            "real_device_forwarding_validated": False,
        },
    )

    result = run_v34_shared_lab_readiness(include_backup_copy=False, include_full_profile=False)

    assert result["ok"] is True
    assert result["production_ready"] is False
    assert result["response_automation_allowed"] is False
    assert result["real_firewall_blocking_enabled"] is False
    assert result["current_database_modified"] is False
    assert REAL_SOURCE_PILOT_CHECKLIST == result["real_source_pilot_checklist"]
    assert any("real_source_pilot" in warning for warning in result["warnings"])
