from __future__ import annotations

from datetime import datetime, timedelta, timezone
from io import BytesIO
import os
from pathlib import Path
from types import SimpleNamespace
from collections.abc import Generator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from atdr.app.core.config import get_settings
from atdr.app.db.database import Base, get_db
from atdr.app.db.models import DetectionRun, MLLabel, MLModelRun, OperationJob, RawLog, ResponseAction
from atdr.app.services.job_service import (
    QueueBackpressureError,
    enforce_import_queue_backpressure,
    enqueue_job,
    request_job_cancellation,
    resume_import_job,
)
from atdr.app.services.operation_worker import run_worker_once
from atdr.app.services.staged_input_retention_service import build_staged_cleanup_plan, public_cleanup_plan
from atdr.app.services.staging_service import StagingPressureError, stage_upload_for_job
from atdr.tests.test_parser import TRAFFIC_LINE
from atdr.app.main import app
from atdr.app.services.user_service import create_user


@pytest.fixture(autouse=True)
def _small_chunks(monkeypatch):
    monkeypatch.setenv("INGESTION_CHUNK_SIZE", "2")
    monkeypatch.setenv("INGESTION_PROGRESS_UPDATE_INTERVAL", "2")
    monkeypatch.setenv("OPERATION_WORKER_LEASE_SECONDS", "60")
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


def _client(engine) -> tuple[TestClient, sessionmaker[Session]]:
    factory = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
    with factory() as db:
        create_user(db, username="admin", password="admin123", role="admin", full_name="Admin")
        create_user(db, username="analyst", password="analyst123", role="analyst", full_name="Analyst")
        db.commit()

    def override_get_db() -> Generator[Session, None, None]:
        db = factory()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    return TestClient(app), factory


def _login(client: TestClient, username: str, password: str) -> dict[str, str]:
    response = client.post("/api/auth/login", json={"username": username, "password": password})
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def _stage(monkeypatch, tmp_path: Path, *, count: int = 5):
    from atdr.app.services import staged_input_retention_service, staging_service

    root = tmp_path / "staging"
    monkeypatch.setattr(staging_service, "STAGING_ROOT", root)
    monkeypatch.setattr(staged_input_retention_service, "STAGING_ROOT", root)
    content = "".join(f"{TRAFFIC_LINE}\n" for _ in range(count)).encode("utf-8")
    return stage_upload_for_job(
        BytesIO(content),
        filename="private-firewall.log",
        max_bytes=5_000_000,
        staging_max_total_bytes=10_000_000,
        staging_min_free_bytes=0,
    )


def _enqueue_import(db: Session, staged, *, actor: str = "admin") -> OperationJob:
    job, _ = enqueue_job(
        db,
        job_type="import_logs",
        requested_by=actor,
        payload={
            "staged_input": str(staged.path),
            "input_name": staged.safe_name,
            "input_bytes": staged.byte_count,
            "input_fingerprint": staged.fingerprint,
            "available_lines": staged.available_lines,
            "source_type": "file_import",
            "parser_profile": "palo_alto",
            "limit": staged.available_lines,
            "source_id": None,
        },
        details={"input_name": staged.safe_name, "available_lines": staged.available_lines},
        progress_total=staged.available_lines,
        input_size_bytes=staged.byte_count,
        input_fingerprint=staged.fingerprint,
        resume_expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    return job


def test_large_import_commits_multiple_chunks_and_updates_progress_lease_and_heartbeat(monkeypatch, tmp_path):
    staged = _stage(monkeypatch, tmp_path, count=5)
    engine = _engine()
    with Session(engine) as db:
        job = _enqueue_import(db, staged)
        result = run_worker_once(db, worker_id="v393-worker")
        persisted = db.get(OperationJob, job.id)

        assert result["ok"] is True
        assert persisted is not None
        assert persisted.status == "completed"
        assert persisted.progress_current == 5
        assert persisted.progress_total == 5
        assert persisted.checkpoint_line == 5
        assert persisted.checkpoint_bytes == staged.byte_count
        assert persisted.chunk_commits == 3
        assert persisted.checkpoint_at is not None
        assert db.scalar(select(func.count(RawLog.id))) == 5
        assert not staged.path.exists()


def test_forced_interruption_after_committed_chunk_resumes_without_duplicate_committed_rows(monkeypatch, tmp_path):
    from atdr.app.services import resumable_ingestion_service

    staged = _stage(monkeypatch, tmp_path, count=5)
    engine = _engine()
    original = resumable_ingestion_service.run_resumable_import

    def interrupted(*args, **kwargs):
        def stop_after_first(chunk_commits, _job):
            if chunk_commits == 1:
                raise RuntimeError("forced test interruption")

        return original(*args, **kwargs, after_chunk=stop_after_first)

    monkeypatch.setattr(resumable_ingestion_service, "run_resumable_import", interrupted)
    with Session(engine) as db:
        parent = _enqueue_import(db, staged)
        failed_result = run_worker_once(db, worker_id="v393-crash-worker")
        db.refresh(parent)
        assert failed_result["ok"] is False
        assert parent.status == "failed"
        assert parent.progress_current == 2
        assert parent.checkpoint_line == 2
        assert db.scalar(select(func.count(RawLog.id))) == 2
        assert staged.path.exists()

        resumed = resume_import_job(db, parent, requested_by="admin")
        assert resumed.checkpoint_line == 2
        monkeypatch.setattr(resumable_ingestion_service, "run_resumable_import", original)
        completed_result = run_worker_once(db, worker_id="v393-resume-worker")
        db.refresh(resumed)

        assert completed_result["ok"] is True
        assert resumed.status == "completed"
        assert resumed.progress_current == 5
        assert db.scalar(select(func.count(RawLog.id))) == 5
        assert db.scalar(select(func.count(ResponseAction.id))) == 0
        assert db.scalar(select(func.count(DetectionRun.id))) == 0
        assert db.scalar(select(func.count(MLLabel.id))) == 0
        assert db.scalar(select(func.count(MLModelRun.id))) == 0


def test_changed_or_missing_staged_input_blocks_resume(monkeypatch, tmp_path):
    staged = _stage(monkeypatch, tmp_path, count=2)
    engine = _engine()
    with Session(engine) as db:
        job = _enqueue_import(db, staged)
        job.status = "failed"
        db.commit()

        changed = bytearray(staged.path.read_bytes())
        changed[0] = ord("X") if changed[0] != ord("X") else ord("Y")
        staged.path.write_bytes(changed)
        with pytest.raises(ValueError, match="fingerprint changed|input changed"):
            resume_import_job(db, job, requested_by="admin")

        staged.path.unlink()
        with pytest.raises(ValueError, match="unavailable"):
            resume_import_job(db, job, requested_by="admin")


def test_running_import_cancels_only_after_committed_chunk_and_preserves_evidence(monkeypatch, tmp_path):
    from atdr.app.services import resumable_ingestion_service

    staged = _stage(monkeypatch, tmp_path, count=5)
    engine = _engine()
    original = resumable_ingestion_service.run_resumable_import

    def request_after_first(*args, **kwargs):
        db = args[0] if args else kwargs["db"]

        def request_cancel(chunk_commits, job):
            if chunk_commits == 1:
                request_job_cancellation(db, job, actor="admin")

        return original(*args, **kwargs, after_chunk=request_cancel)

    monkeypatch.setattr(resumable_ingestion_service, "run_resumable_import", request_after_first)
    with Session(engine) as db:
        job = _enqueue_import(db, staged)
        result = run_worker_once(db, worker_id="v393-cancel-worker")
        db.refresh(job)

        assert result["ok"] is True
        assert job.status == "cancelled"
        assert job.progress_current == 2
        assert job.cancellation_requested_at is not None
        assert db.scalar(select(func.count(RawLog.id))) == 2
        assert staged.path.exists()
        assert db.scalar(select(func.count(ResponseAction.id))) == 0


def test_queue_backpressure_limits_total_and_per_actor():
    engine = _engine()
    with Session(engine) as db:
        enqueue_job(db, job_type="import_logs", requested_by="admin", payload={})
        with pytest.raises(QueueBackpressureError, match="capacity"):
            enforce_import_queue_backpressure(
                db,
                requested_by="another-admin",
                max_queued_imports=1,
                max_queued_jobs_per_actor=5,
            )
        with pytest.raises(QueueBackpressureError, match="Your active"):
            enforce_import_queue_backpressure(
                db,
                requested_by="admin",
                max_queued_imports=5,
                max_queued_jobs_per_actor=1,
            )


def test_staging_low_space_refuses_without_leaving_partial_file(monkeypatch, tmp_path):
    from atdr.app.services import staging_service

    root = tmp_path / "staging"
    monkeypatch.setattr(staging_service, "STAGING_ROOT", root)
    monkeypatch.setattr(
        staging_service.shutil,
        "disk_usage",
        lambda _path: SimpleNamespace(total=100, used=99, free=1),
    )
    with pytest.raises(StagingPressureError):
        stage_upload_for_job(
            BytesIO(b"sample\n"),
            filename="sample.log",
            max_bytes=100,
            staging_max_total_bytes=1000,
            staging_min_free_bytes=10,
        )
    assert not list(root.glob("*"))


def test_staged_cleanup_is_dry_run_and_protects_active_or_resumable_inputs(monkeypatch, tmp_path):
    from atdr.app.services import staged_input_retention_service

    staged = _stage(monkeypatch, tmp_path, count=1)
    orphan = staged.path.parent / "orphan-old.log"
    orphan.write_text("orphan", encoding="utf-8")
    old = (datetime.now(timezone.utc) - timedelta(hours=3)).timestamp()
    os.utime(staged.path, (old, old))
    os.utime(orphan, (old, old))
    monkeypatch.setattr(staged_input_retention_service, "STAGING_ROOT", staged.path.parent)

    engine = _engine()
    with Session(engine) as db:
        _enqueue_import(db, staged)
        plan = build_staged_cleanup_plan(db, retention_hours=1)
        public = public_cleanup_plan(plan)

        assert public["dry_run"] is True
        assert public["candidate_count"] == 1
        assert public["protected_count"] == 1
        assert orphan.exists()
        assert staged.path.exists()
        assert "_path" not in str(public)
        assert public["raw_evidence_deleted"] == 0


def test_resume_is_admin_only_and_running_cancel_request_is_persisted(monkeypatch, tmp_path):
    staged = _stage(monkeypatch, tmp_path, count=3)
    engine = _engine()
    client, factory = _client(engine)
    try:
        with factory() as db:
            failed = _enqueue_import(db, staged)
            failed.status = "failed"
            db.commit()
            failed_id = failed.id

        analyst_headers = _login(client, "analyst", "analyst123")
        assert client.post(f"/api/jobs/{failed_id}/resume", headers=analyst_headers).status_code == 403

        admin_headers = _login(client, "admin", "admin123")
        resumed_response = client.post(f"/api/jobs/{failed_id}/resume", headers=admin_headers)
        assert resumed_response.status_code == 200
        resumed_payload = resumed_response.json()
        assert resumed_payload["status"] == "queued"
        assert resumed_payload["resume_of_job_id"] == failed_id
        assert "staged_input" not in str(resumed_payload)

        with factory() as db:
            resumed = db.get(OperationJob, resumed_payload["job_id"])
            assert resumed is not None
            resumed.status = "running"
            resumed.lease_owner = "worker"
            db.commit()

        requested = client.post(
            f"/api/jobs/{resumed_payload['job_id']}/request-cancel",
            headers=admin_headers,
        )
        assert requested.status_code == 200
        assert requested.json()["status"] == "cancel_requested"
        assert requested.json()["cancellation_requested"] is True
    finally:
        app.dependency_overrides.clear()
