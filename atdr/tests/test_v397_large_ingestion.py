from __future__ import annotations

from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import subprocess
import sys

from sqlalchemy import create_engine, event, func, inspect, select, text
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from atdr.app.core.config import get_settings
from atdr.app.core.log_fingerprint import raw_line_fingerprint
from atdr.app.db.database import Base
from atdr.app.db.models import OperationJob, RawLog
from atdr.app.services.metrics_service import render_prometheus_metrics
from atdr.app.services.resumable_ingestion_service import _chunk_duplicate_count
from atdr.scripts.validate_large_ingestion import validate_large_ingestion


PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _engine():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    Base.metadata.create_all(engine)
    return engine


def test_raw_log_fingerprint_is_stable_indexed_and_populated_for_direct_inserts():
    engine = _engine()
    with Session(engine) as db:
        raw = RawLog(raw_line="synthetic fingerprint evidence")
        db.add(raw)
        db.commit()
        db.refresh(raw)

        assert raw.raw_line_hash == raw_line_fingerprint(raw.raw_line)
        assert any(index.name == "ix_raw_logs_raw_line_hash" for index in RawLog.__table__.indexes)


def test_chunk_duplicate_count_is_exact_and_uses_bounded_queries():
    engine = _engine()
    statements: list[str] = []

    @event.listens_for(engine, "before_cursor_execute")
    def record_queries(_connection, _cursor, statement, _parameters, _context, _executemany):
        if statement.lstrip().upper().startswith("SELECT") and "raw_logs" in statement:
            statements.append(statement)

    with Session(engine) as db:
        db.add(RawLog(raw_line="already stored"))
        db.commit()
        rows = ["already stored", *[f"new line {index}" for index in range(400)], "new line 0"]

        assert _chunk_duplicate_count(db, rows) == 2
        assert len(statements) == 2


def test_fingerprint_migration_backfills_existing_raw_evidence(tmp_path):
    database_path = tmp_path / "pre-v397.sqlite3"
    env = os.environ.copy()
    env.update(
        {
            "DATABASE_URL": f"sqlite:///{database_path}",
            "RESPONSE_SIMULATION": "true",
            "JWT_SECRET_KEY": "v397-test-migration-secret-not-for-deployment",
        }
    )
    before = subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "a3b4c5d6e7f8"],
        cwd=PROJECT_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    assert before.returncode == 0, before.stderr
    engine = create_engine(f"sqlite:///{database_path}", future=True)
    try:
        with engine.begin() as connection:
            connection.execute(text("INSERT INTO raw_logs (raw_line) VALUES ('existing raw evidence')"))
    finally:
        engine.dispose()

    upgraded = subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        cwd=PROJECT_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    assert upgraded.returncode == 0, upgraded.stderr
    engine = create_engine(f"sqlite:///{database_path}", future=True)
    try:
        with engine.connect() as connection:
            fingerprint = connection.execute(text("SELECT raw_line_hash FROM raw_logs LIMIT 1")).scalar_one()
        inspector = inspect(engine)
        assert fingerprint == raw_line_fingerprint("existing raw evidence")
        assert any(index["name"] == "ix_raw_logs_raw_line_hash" for index in inspector.get_indexes("raw_logs"))
    finally:
        engine.dispose()


def test_fingerprint_migration_renders_postgresql_offline_backfill_sql():
    env = os.environ.copy()
    env.update(
        {
            "DATABASE_URL": "postgresql+psycopg2://atdr:unused@127.0.0.1:5432/atdr_offline",
            "RESPONSE_SIMULATION": "true",
            "JWT_SECRET_KEY": "v397-test-offline-secret-not-for-deployment",
        }
    )
    rendered = subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "a3b4c5d6e7f8:b4c5d6e7f8a9", "--sql"],
        cwd=PROJECT_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )

    assert rendered.returncode == 0, rendered.stderr
    assert "ALTER TABLE raw_logs ADD COLUMN raw_line_hash VARCHAR(64)" in rendered.stdout
    assert "sha256(convert_to(COALESCE(raw_line, ''), 'UTF8'))" in rendered.stdout
    assert "CREATE INDEX ix_raw_logs_raw_line_hash" in rendered.stdout


def test_ingestion_metrics_include_progress_checkpoint_and_stall_health(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "sqlite://")
    monkeypatch.setenv("RESPONSE_SIMULATION", "true")
    monkeypatch.setenv("OPERATION_STAGING_MIN_FREE_BYTES", "0")
    get_settings.cache_clear()
    engine = _engine()
    with Session(engine) as db:
        db.add(
            OperationJob(
                job_type="import_logs",
                status="running",
                requested_by="validator",
                progress_current=500,
                progress_total=1000,
                checkpoint_line=500,
                checkpoint_bytes=25000,
                checkpoint_at=datetime.now(timezone.utc) - timedelta(minutes=5),
                chunk_commits=1,
                max_attempts=1,
                attempt_count=1,
            )
        )
        db.commit()
        rendered = render_prometheus_metrics(db, heartbeat_seconds=15)
    get_settings.cache_clear()

    for metric in (
        "atdr_ingestion_active_jobs 1",
        "atdr_ingestion_committed_rows_total 500",
        "atdr_ingestion_checkpoint_age_seconds",
        "atdr_ingestion_stalled_jobs 1",
    ):
        assert metric in rendered
    for forbidden in ("raw_line=", "source_id=", "requested_by=", "file_path="):
        assert forbidden not in rendered


def test_large_ingestion_validator_refuses_configured_database_and_passes_in_isolation():
    refused = validate_large_ingestion(use_temp_db=False, lines=20)
    isolated = validate_large_ingestion(use_temp_db=True, lines=20)

    assert refused["status"] == "explicit_temp_database_required"
    assert refused["current_database_modified"] is False
    assert isolated["ok"] is True
    assert isolated["counts"]["raw_logs"] == 20
    assert isolated["counts"]["normalized_logs"] == 20
    assert isolated["ingestion"]["progress_monotonic"] is True
    assert isolated["ingestion"]["duplicate_rows_after_resume"] == 0
    assert isolated["safety_checks"]["changed_input_rejected"] is True
    assert isolated["safety_checks"]["cooperative_cancellation"]["ok"] is True
    assert isolated["current_database_unchanged"] is True
    assert isolated["response_automation_allowed"] is False
    assert isolated["model_activation_performed"] is False
