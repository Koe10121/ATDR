from __future__ import annotations

from datetime import datetime, timedelta, timezone
from io import BytesIO
import json
from pathlib import Path
from threading import Event

import pytest
from sqlalchemy import create_engine, func, select
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from atdr.app.core.config import Settings, get_settings, validate_runtime_settings
from atdr.app.db.database import Base
from atdr.app.db.models import OperationJob, RawLog, ResponseAction
from atdr.app.services.job_service import (
    LeaseOwnershipError,
    build_claim_statement,
    build_lease_recovery_statement,
    claim_next_job,
    complete_queued_job,
    enqueue_job,
    job_to_dict,
)
from atdr.app.services.operation_worker import run_worker_once
from atdr.app.services.staging_service import (
    StagedInputError,
    effective_staging_storage_id,
    stage_upload_for_job,
    staged_payload_fields,
    validate_staged_payload,
)
from atdr.scripts.validate_backup_worker_concurrency import validate_backup_worker_concurrency
from atdr.scripts.validate_postgres_multiworker import validate_postgres_multiworker
from atdr.scripts.validate_worker_deployment import validate_worker_deployment
from atdr.tests.test_parser import TRAFFIC_LINE


@pytest.fixture(autouse=True)
def _safe_worker_settings(monkeypatch, tmp_path):
    monkeypatch.setenv("OPERATION_STAGING_ROOT", str(tmp_path / "staging"))
    monkeypatch.setenv("OPERATION_STAGING_SHARED", "false")
    monkeypatch.setenv("OPERATION_STAGING_STORAGE_ID", "local")
    monkeypatch.setenv("INGESTION_CHUNK_SIZE", "2")
    monkeypatch.setenv("INGESTION_PROGRESS_UPDATE_INTERVAL", "2")
    monkeypatch.setenv("OPERATION_STAGING_MIN_FREE_BYTES", "0")
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def _engine():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    Base.metadata.create_all(engine)
    return engine


def _enqueue_staged_import(db: Session, staged) -> OperationJob:
    payload = {
        **staged_payload_fields(staged),
        "input_name": staged.safe_name,
        "input_bytes": staged.byte_count,
        "input_fingerprint": staged.fingerprint,
        "available_lines": staged.available_lines,
        "source_type": "file_import",
        "parser_profile": "palo_alto",
        "limit": staged.available_lines,
        "source_id": None,
    }
    return enqueue_job(
        db,
        job_type="import_logs",
        requested_by="admin",
        payload=payload,
        progress_total=staged.available_lines,
        input_size_bytes=staged.byte_count,
        input_fingerprint=staged.fingerprint,
        resume_expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        staging_storage_id=staged.storage_id,
    )[0]


def test_postgres_claim_and_recovery_sql_use_skip_locked():
    now = datetime.now(timezone.utc)
    claim_sql = str(
        build_claim_statement(now=now, staging_storage_id="shared-a", allow_legacy_staging=False)
        .compile(dialect=postgresql.dialect(), compile_kwargs={"literal_binds": True})
    ).upper()
    recovery_sql = str(
        build_lease_recovery_statement(now=now, limit=5).compile(
            dialect=postgresql.dialect(),
            compile_kwargs={"literal_binds": True},
        )
    ).upper()

    assert "FOR UPDATE SKIP LOCKED" in claim_sql
    assert "FOR UPDATE SKIP LOCKED" in recovery_sql
    assert "STAGING_STORAGE_ID" in claim_sql


def test_lease_token_fences_stale_worker_and_is_never_public():
    engine = _engine()
    with Session(engine) as db:
        queued, _ = enqueue_job(db, job_type="validation", requested_by="admin", payload={})
        claimed = claim_next_job(db, worker_id="worker-a", lease_seconds=60)
        assert claimed is not None and claimed.id == queued.id
        token = str(claimed.lease_token)
        assert token
        assert claimed.claim_generation == 1

        with pytest.raises(LeaseOwnershipError):
            complete_queued_job(
                db,
                job_id=claimed.id,
                worker_id="worker-a",
                lease_token="stale-token",
            )
        db.rollback()
        completed = complete_queued_job(
            db,
            job_id=claimed.id,
            worker_id="worker-a",
            lease_token=token,
        )
        rendered = json.dumps(job_to_dict(completed), default=str)

        assert completed.status == "completed"
        assert completed.lease_token is None
        assert token not in rendered
        assert "lease_token" not in rendered


def test_shared_storage_identity_mismatch_blocks_input(monkeypatch, tmp_path):
    shared_root = (tmp_path / "shared").resolve()
    monkeypatch.setenv("OPERATION_STAGING_ROOT", str(shared_root))
    monkeypatch.setenv("OPERATION_STAGING_SHARED", "true")
    monkeypatch.setenv("OPERATION_STAGING_STORAGE_ID", "shared-a")
    get_settings.cache_clear()
    staged = stage_upload_for_job(BytesIO(b"sample\n"), filename="sample.log")
    payload = {**staged_payload_fields(staged), "input_bytes": staged.byte_count, "input_fingerprint": staged.fingerprint}

    assert effective_staging_storage_id() == "shared-a"
    assert validate_staged_payload(payload)[0] == staged.path
    with pytest.raises(StagedInputError, match="different staging storage"):
        validate_staged_payload({**payload, "staging_storage_id": "shared-b"})
    with pytest.raises(StagedInputError, match="key is invalid"):
        validate_staged_payload({**payload, "staged_input_key": "../sample.log"})


def test_shared_worker_does_not_claim_legacy_local_import():
    engine = _engine()
    with Session(engine) as db:
        legacy, _ = enqueue_job(
            db,
            job_type="import_logs",
            requested_by="admin",
            payload={"staged_input": "C:/private/local-only.log"},
        )
        validation, _ = enqueue_job(db, job_type="validation", requested_by="admin", payload={})
        claimed = claim_next_job(
            db,
            worker_id="shared-worker",
            lease_seconds=60,
            staging_storage_id="shared-a",
            allow_legacy_staging=False,
        )

        assert claimed is not None and claimed.id == validation.id
        assert db.get(OperationJob, legacy.id).status == "queued"


def test_graceful_stop_releases_import_at_committed_checkpoint(monkeypatch):
    from atdr.app.services import resumable_ingestion_service

    content = "".join(f"{TRAFFIC_LINE}\n" for _ in range(5)).encode()
    staged = stage_upload_for_job(BytesIO(content), filename="graceful.log")
    engine = _engine()
    stop_event = Event()
    original = resumable_ingestion_service.run_resumable_import

    def stop_after_first(*args, **kwargs):
        def set_stop(chunk_commits, _job):
            if chunk_commits == 1:
                stop_event.set()

        return original(*args, **kwargs, after_chunk=set_stop)

    monkeypatch.setattr(resumable_ingestion_service, "run_resumable_import", stop_after_first)
    with Session(engine) as db:
        job = _enqueue_staged_import(db, staged)
        result = run_worker_once(db, worker_id="shutdown-worker", stop_event=stop_event)
        db.refresh(job)

        assert result["ok"] is True
        assert result["shutdown_requested"] is True
        assert job.status == "queued"
        assert job.progress_current == 2
        assert job.checkpoint_line == 2
        assert job.lease_owner is None and job.lease_token is None
        assert staged.path.exists()

        monkeypatch.setattr(resumable_ingestion_service, "run_resumable_import", original)
        resumed = run_worker_once(db, worker_id="replacement-worker")
        db.refresh(job)
        assert resumed["ok"] is True
        assert job.status == "completed"
        assert db.scalar(select(func.count(RawLog.id))) == 5
        assert db.scalar(select(func.count(ResponseAction.id))) == 0


def test_worker_profile_validation_and_dry_run_harnesses_are_safe(tmp_path):
    local = Settings(
        _env_file=None,
        DATABASE_URL="sqlite:///./test.db",
        OPERATION_WORKER_CONCURRENCY=1,
        OPERATION_STAGING_ROOT=str(tmp_path / "local"),
    )
    invalid_sqlite = local.model_copy(update={"operation_worker_concurrency": 2})
    deployment = validate_worker_deployment(settings=local)
    postgres_dry_run = validate_postgres_multiworker(settings=local)
    backup_dry_run = validate_backup_worker_concurrency(source_url="", restore_url="")

    assert deployment["ok"] is True
    assert deployment["normal_sqlite_workflow_preserved"] is True
    assert any("must be 1" in issue for issue in validate_runtime_settings(invalid_sqlite))
    assert postgres_dry_run["ok"] is True and postgres_dry_run["executed"] is False
    assert backup_dry_run["ok"] is True and backup_dry_run["executed"] is False
    assert postgres_dry_run["secrets_exposed"] is False
    assert backup_dry_run["secrets_exposed"] is False
