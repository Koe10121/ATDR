import json
import sqlite3
from pathlib import Path

from atdr.app.core.config import PROJECT_ROOT, Settings
from atdr.scripts.config_doctor import run_config_doctor
from atdr.scripts.profile_dashboard_summary import profile_dashboard_summary
from atdr.scripts.run_backup_restore_drill import run_backup_restore_drill


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


