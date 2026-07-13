import json
import os
from pathlib import Path
import subprocess
import sys

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from atdr.app.core.config import PROJECT_ROOT, Settings
from atdr.app.db.database import Base
from atdr.app.db.engine import build_engine_kwargs, database_kind, inspect_database_runtime
from atdr.app.db.models import MLLabel, MLModelRun, ResponseAction, User
from atdr.app.services import persistence_service
from atdr.app.services.persistence_service import create_database_backup, restore_database_backup
from atdr.scripts.config_doctor import run_config_doctor
from atdr.scripts.validate_persistence_profile import validate_persistence_profile


def _sqlite_url(path: Path) -> str:
    return f"sqlite:///{path.as_posix()}"


def _create_source_database(path: Path) -> Settings:
    settings = Settings(DATABASE_URL=_sqlite_url(path))
    engine = create_engine(settings.database_url, **build_engine_kwargs(settings))
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        session.add(
            User(
                username="backup-analyst",
                email="backup@example.invalid",
                role="analyst",
                password_hash="not-a-real-password",
            )
        )
        session.commit()
    engine.dispose()
    return settings


def test_sqlite_remains_default_and_ignores_postgres_pool_options():
    settings = Settings(DATABASE_URL="sqlite:///./atdr.db", _env_file=None)
    kwargs = build_engine_kwargs(settings)

    assert settings.database_url == "sqlite:///./atdr.db"
    assert database_kind(settings.database_url) == "sqlite"
    assert kwargs["connect_args"]["check_same_thread"] is False
    assert kwargs["connect_args"]["timeout"] == 10.0
    assert "pool_size" not in kwargs
    assert "max_overflow" not in kwargs
    assert "pool_timeout" not in kwargs


def test_postgres_engine_options_are_dialect_specific_and_secret_free():
    secret = "database-password-that-must-not-leak"
    settings = Settings(
        DATABASE_URL=f"postgresql+psycopg2://atdr:{secret}@db.internal:5432/atdr",
        DB_POOL_SIZE=7,
        DB_MAX_OVERFLOW=4,
        DB_POOL_TIMEOUT_SECONDS=12,
        DB_CONNECT_TIMEOUT_SECONDS=8,
        DB_STATEMENT_TIMEOUT_MS=25000,
    )
    kwargs = build_engine_kwargs(settings)

    assert kwargs["pool_size"] == 7
    assert kwargs["max_overflow"] == 4
    assert kwargs["pool_timeout"] == 12.0
    assert kwargs["connect_args"]["connect_timeout"] == 8
    assert kwargs["connect_args"]["options"] == "-c statement_timeout=25000"
    assert secret not in json.dumps(kwargs)


def test_backup_dry_run_writes_nothing(tmp_path):
    source = tmp_path / "source.sqlite3"
    settings = _create_source_database(source)
    output = tmp_path / "backup-output"

    result = create_database_backup(settings=settings, output_dir=output, execute=False)

    assert result["ok"] is True
    assert result["status"] == "dry_run"
    assert result["source_database_modified"] is False
    assert not output.exists()


def test_sqlite_backup_restore_preserves_counts_and_integrity(tmp_path):
    source = tmp_path / "source.sqlite3"
    target = tmp_path / "restored.sqlite3"
    settings = _create_source_database(source)

    backup = create_database_backup(settings=settings, output_dir=tmp_path / "backups", execute=True)
    restore = restore_database_backup(
        settings=settings,
        backup_path=backup["backup_path"],
        manifest_path=backup["manifest_path"],
        target_database_url=_sqlite_url(target),
        execute=True,
        confirmed=True,
    )

    assert backup["ok"] is True
    assert backup["source_database_modified"] is False
    assert backup["sha256"]
    assert Path(backup["manifest_path"]).exists()
    assert restore["ok"] is True
    assert restore["status"] == "restore_validated"
    assert restore["integrity_ok"] is True
    assert restore["row_counts_match"] is True
    assert restore["migration_revision_match"] is True
    assert restore["current_database_modified"] is False

    engine = create_engine(_sqlite_url(target), future=True)
    try:
        with Session(engine) as session:
            assert session.scalar(select(User.username)) == "backup-analyst"
            assert session.scalar(select(ResponseAction.id)) is None
            assert session.scalar(select(MLModelRun.id)) is None
            assert session.scalar(select(MLLabel.id)) is None
    finally:
        engine.dispose()


def test_restore_refuses_active_database(tmp_path):
    source = tmp_path / "source.sqlite3"
    settings = _create_source_database(source)
    backup = create_database_backup(settings=settings, output_dir=tmp_path / "backups", execute=True)

    result = restore_database_backup(
        settings=settings,
        backup_path=backup["backup_path"],
        target_database_url=settings.database_url,
        execute=True,
        confirmed=True,
    )

    assert result["ok"] is False
    assert result["status"] == "active_database_target_refused"
    assert result["current_database_modified"] is False


def test_restore_rejects_invalid_checksum(tmp_path):
    source = tmp_path / "source.sqlite3"
    settings = _create_source_database(source)
    backup = create_database_backup(settings=settings, output_dir=tmp_path / "backups", execute=True)
    Path(backup["backup_path"]).write_bytes(b"tampered")

    result = restore_database_backup(
        settings=settings,
        backup_path=backup["backup_path"],
        target_database_url=_sqlite_url(tmp_path / "target.sqlite3"),
        execute=False,
    )

    assert result["ok"] is False
    assert result["status"] == "checksum_mismatch"
    assert result["target_database_modified"] is False


def test_backup_rejects_unignored_project_output(tmp_path, monkeypatch):
    source = tmp_path / "source.sqlite3"
    settings = _create_source_database(source)
    monkeypatch.setattr(persistence_service, "PROJECT_ROOT", tmp_path)

    with pytest.raises(ValueError, match="Backup output inside the repository"):
        create_database_backup(settings=settings, output_dir=tmp_path / "docs" / "backups", execute=False)


def test_postgres_backup_reports_missing_tool_without_exposing_connection(monkeypatch, tmp_path):
    secret = "postgres-secret-that-must-not-leak"
    settings = Settings(DATABASE_URL=f"postgresql+psycopg2://atdr:{secret}@db.internal:5432/atdr")
    monkeypatch.setattr(persistence_service.shutil, "which", lambda _name: None)

    result = create_database_backup(settings=settings, output_dir=tmp_path, execute=False)
    rendered = json.dumps(result)

    assert result["ok"] is True
    assert result["planned"]["pg_dump_available"] is False
    assert secret not in rendered
    assert "db.internal" not in rendered
    assert "postgresql+psycopg2" not in rendered


def test_config_and_runtime_diagnostics_hide_database_details(monkeypatch):
    secret = "postgres-secret-that-must-not-leak"
    settings = Settings(DATABASE_URL=f"postgresql+psycopg2://atdr:{secret}@postgres:5432/atdr")
    result = run_config_doctor(settings=settings)
    rendered = json.dumps(result)

    assert result["database"] == "postgresql"
    assert result["database_host_configured"] is True
    assert result["database_profile"]["connection_status"] == "not_checked"
    assert result["database_profile"]["secrets_exposed"] is False
    assert secret not in rendered
    assert "postgresql+psycopg2" not in rendered
    assert "@postgres" not in rendered

    runtime = inspect_database_runtime(settings, probe_connection=False)
    assert runtime["connection_status"] == "not_checked"
    assert runtime["secrets_exposed"] is False


def test_isolated_persistence_validator_does_not_modify_configured_database(tmp_path):
    current = tmp_path / "current.sqlite3"
    current.write_bytes(b"current-database-sentinel")
    settings = Settings(DATABASE_URL=_sqlite_url(current))
    before = current.read_bytes()
    result = validate_persistence_profile(settings=settings)

    assert result["ok"] is True
    assert result["sqlite_validation"]["ok"] is True
    assert result["postgres_runtime_validated"] is False
    assert result["current_database_unchanged"] is True
    assert result["current_database_modified"] is False
    assert result["response_automation_allowed"] is False
    assert result["model_activation_performed"] is False
    assert current.read_bytes() == before


def test_isolated_persistence_validator_refuses_the_configured_database_as_a_target(tmp_path):
    current = tmp_path / "current.sqlite3"
    settings = Settings(DATABASE_URL=_sqlite_url(current))

    from atdr.scripts import validate_persistence_profile as validation

    result = validation._validate_pair(
        source_url=settings.database_url,
        restore_url=_sqlite_url(tmp_path / "restored.sqlite3"),
        output_dir=tmp_path / "backups",
        protected_database_url=settings.database_url,
    )

    assert result["ok"] is False
    assert result["status"] == "configured_database_target_refused"
    assert result["current_database_modified"] is False


def test_ci_has_an_ephemeral_postgres_persistence_job_without_external_providers():
    workflow = (PROJECT_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")

    assert "postgres-persistence:" in workflow
    assert "postgres:16" in workflow
    assert "ATDR_PERSISTENCE_SOURCE_DATABASE_URL" in workflow
    assert "ATDR_PERSISTENCE_RESTORE_DATABASE_URL" in workflow
    assert "atdr_v389_control" in workflow
    assert "atdr/tests/test_api.py" in workflow
    assert "validate_persistence_profile" in workflow
    assert "ASSISTANT_LLM_ENABLED: \"false\"" in workflow
    assert "MFU_IAM_ENABLED: \"false\"" in workflow
    assert "RESPONSE_SIMULATION: \"true\"" in workflow


def test_migration_chain_generates_postgresql_sql_offline_without_a_database(tmp_path):
    env = os.environ.copy()
    env.update(
        {
            "DATABASE_URL": "postgresql+psycopg2://atdr_ci:ephemeral@127.0.0.1:5432/atdr_v389_migration",
            "AUTO_CREATE_TABLES": "false",
        }
    )
    output_path = tmp_path / "migration.sql"
    result = subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head", "--sql"],
        cwd=PROJECT_ROOT,
        capture_output=True,
        check=False,
        env=env,
        text=True,
        timeout=60,
    )
    output_path.write_text(result.stdout, encoding="utf-8")

    assert result.returncode == 0
    sql = output_path.read_text(encoding="utf-8")
    assert "ALTER TABLE ml_labels ADD COLUMN reviewed BOOLEAN DEFAULT true NOT NULL" in sql
    assert "CREATE TABLE ingestion_runs" in sql
    assert "CREATE TABLE detection_runs" in sql
    assert "CREATE TABLE operation_jobs" in sql
    assert "CREATE TABLE assistant_feedback" in sql
