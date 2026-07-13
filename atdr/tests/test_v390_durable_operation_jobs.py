from __future__ import annotations

from collections.abc import Generator
from datetime import datetime, timedelta, timezone
from io import BytesIO, StringIO

from fastapi.testclient import TestClient
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from atdr.app.db.database import Base, get_db
from atdr.app.db.models import AuditLog, DetectionRun, OperationJob, OperationWorkerHeartbeat, RawLog, ResponseAction
from atdr.app.main import app
from atdr.app.services.job_dispatcher import stage_upload_for_job
from atdr.app.services.job_service import (
    build_job_summary,
    enqueue_job,
    job_to_dict,
    record_worker_heartbeat,
    recover_expired_leases,
)
from atdr.app.services.log_service import import_log_stream
from atdr.app.services.operation_worker import run_worker_once
from atdr.app.services.user_service import create_user
from atdr.tests.test_parser import TRAFFIC_LINE


def _client_with_session() -> tuple[TestClient, sessionmaker[Session]]:
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    Base.metadata.create_all(engine)
    testing_session = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
    with testing_session() as db:
        create_user(db, username="admin", password="admin123", role="admin", full_name="Test Admin")
        create_user(db, username="analyst", password="analyst123", role="analyst", full_name="Test Analyst")
        db.commit()

    def override_get_db() -> Generator[Session, None, None]:
        db = testing_session()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    return TestClient(app), testing_session


def _login(client: TestClient, username: str, password: str) -> dict[str, str]:
    response = client.post("/api/auth/login", json={"username": username, "password": password})
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def test_enqueue_idempotency_hides_private_payload_and_records_audit():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool, future=True)
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        first, reused = enqueue_job(
            db,
            job_type="run_detection",
            requested_by="analyst",
            payload={"limit": 10, "staged_input": "C:/private/input.log"},
            details={"input_name": "input.log", "staged_input": "C:/private/input.log"},
            idempotency_key="v390-detection-0001",
        )
        second, reused_second = enqueue_job(
            db,
            job_type="run_detection",
            requested_by="analyst",
            payload={"limit": 10},
            idempotency_key="v390-detection-0001",
        )

        assert reused is False
        assert reused_second is True
        assert second.id == first.id
        response = job_to_dict(first)
        assert "payload_json" not in response
        assert "staged_input" not in response["details"]
        assert "private" not in str(response)
        assert db.scalar(select(func.count(AuditLog.id)).where(AuditLog.action == "operation_job_queued")) == 1


def test_worker_processes_staged_import_preserves_evidence_and_never_creates_response(tmp_path, monkeypatch):
    from atdr.app.services import staging_service

    runtime_root = tmp_path / "runtime"
    monkeypatch.setattr(staging_service, "STAGING_ROOT", runtime_root)
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool, future=True)
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        staged = stage_upload_for_job(
            BytesIO((TRAFFIC_LINE + "\n").encode("utf-8")),
            filename="C:/private/firewall-log.csv",
            max_bytes=1024 * 1024,
            staging_min_free_bytes=0,
        )
        job, _ = enqueue_job(
            db,
            job_type="import_logs",
            requested_by="admin",
            payload={
                "staged_input": str(staged.path),
                "input_name": staged.safe_name,
                "input_bytes": staged.byte_count,
                "input_fingerprint": staged.fingerprint,
                "available_lines": staged.available_lines,
                "source_type": "file_import",
                "parser_profile": "palo_alto",
                "limit": 1,
                "source_id": None,
            },
            details={"input_name": staged.safe_name, "input_bytes": staged.byte_count, "source_type": "file_import"},
            progress_total=staged.available_lines,
            input_size_bytes=staged.byte_count,
            input_fingerprint=staged.fingerprint,
            resume_expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )

        result = run_worker_once(db, worker_id="test-worker")
        persisted = db.get(OperationJob, job.id)
        assert result["ok"] is True
        assert result["processed"] is True
        assert persisted is not None
        assert persisted.status == "completed"
        assert persisted.related_ingestion_run_id is not None
        assert db.scalar(select(func.count(RawLog.id))) == 1
        assert db.scalar(select(func.count(ResponseAction.id))) == 0
        assert not staged.path.exists()
        assert "staged_input" not in job_to_dict(persisted)["details"]


def test_worker_runs_source_scoped_detection_without_model_or_response_activation():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool, future=True)
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        imported = import_log_stream(db, StringIO(TRAFFIC_LINE + "\n"), limit=1, actor="admin")
        job, _ = enqueue_job(
            db,
            job_type="run_detection",
            requested_by="analyst",
            payload={"limit": 1, "use_ml": False, "source_id": imported["source_id"]},
            details={"limit": 1, "use_ml": False, "source_id": imported["source_id"]},
        )
        result = run_worker_once(db, worker_id="test-worker")
        persisted = db.get(OperationJob, job.id)

        assert result["ok"] is True
        assert persisted is not None
        assert persisted.status == "completed"
        assert persisted.related_detection_run_id is not None
        assert db.scalar(select(func.count(DetectionRun.id))) == 1
        assert db.scalar(select(func.count(ResponseAction.id))) == 0
        assert "activate" not in " ".join(
            row.action for row in db.scalars(select(AuditLog).where(AuditLog.target_type == "operation_job"))
        )


def test_jobs_api_scopes_analyst_to_own_jobs_and_restricts_admin_operations():
    client, testing_session = _client_with_session()
    try:
        with testing_session() as db:
            enqueue_job(db, job_type="run_detection", requested_by="analyst", payload={"limit": 1, "use_ml": False})
            enqueue_job(db, job_type="run_detection", requested_by="admin", payload={"limit": 1, "use_ml": False})

        assert client.get("/api/jobs").status_code == 401
        analyst_headers = _login(client, "analyst", "analyst123")
        analyst_jobs = client.get("/api/jobs", headers=analyst_headers)
        assert analyst_jobs.status_code == 200
        assert {item["requested_by"] for item in analyst_jobs.json()} == {"analyst"}

        denied = client.post(
            "/api/jobs/submit",
            json={"job_type": "train_ml", "payload": {"operation": "anomaly_train"}},
            headers=analyst_headers,
        )
        assert denied.status_code == 403

        admin_headers = _login(client, "admin", "admin123")
        allowed = client.post(
            "/api/jobs/submit",
            json={"job_type": "export_report", "payload": {"top_alert_limit": 1, "audit_limit": 1}},
            headers=admin_headers,
        )
        assert allowed.status_code == 200
        assert allowed.json()["status"] == "queued"
        assert "payload_json" not in allowed.json()
    finally:
        app.dependency_overrides.clear()


def test_admin_can_enqueue_multipart_import_without_exposing_staged_path():
    client, testing_session = _client_with_session()
    try:
        admin_headers = _login(client, "admin", "admin123")
        analyst_headers = _login(client, "analyst", "analyst123")
        denied = client.post(
            "/api/jobs/import",
            files={"upload": ("queued.log", (TRAFFIC_LINE + "\n").encode("utf-8"), "text/plain")},
            headers=analyst_headers,
        )
        assert denied.status_code == 403

        queued = client.post(
            "/api/jobs/import",
            files={"upload": ("queued.log", (TRAFFIC_LINE + "\n").encode("utf-8"), "text/plain")},
            data={"limit": "1", "source_type": "file_import", "parser_profile": "palo_alto"},
            headers=admin_headers,
        )
        assert queued.status_code == 200
        payload = queued.json()
        assert payload["status"] == "queued"
        assert "staged_input" not in str(payload)

        with testing_session() as db:
            result = run_worker_once(db, worker_id="api-import-worker")
            assert result["ok"] is True
            assert db.scalar(select(func.count(RawLog.id))) == 1
    finally:
        app.dependency_overrides.clear()


def test_existing_detection_route_keeps_sync_default_and_supports_explicit_enqueue():
    client, testing_session = _client_with_session()
    try:
        analyst_headers = _login(client, "analyst", "analyst123")
        queued = client.post(
            "/api/detection/run?limit=1&use_ml=false&enqueue=true&idempotency_key=v390-detection-route",
            headers=analyst_headers,
        )
        assert queued.status_code == 200
        assert queued.json()["queued"] is True
        job_id = queued.json()["job_id"]

        with testing_session() as db:
            job = db.get(OperationJob, job_id)
            assert job is not None
            assert job.status == "queued"
            assert db.scalar(select(func.count(DetectionRun.id))) == 0
            run_worker_once(db, worker_id="detection-route-worker")
            db.refresh(job)
            assert job.status == "completed"
            assert db.scalar(select(func.count(DetectionRun.id))) == 1
    finally:
        app.dependency_overrides.clear()


def test_cancel_retry_and_lease_recovery_fail_closed_for_evidence_mutating_jobs():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool, future=True)
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        job, _ = enqueue_job(
            db,
            job_type="run_detection",
            requested_by="admin",
            payload={"limit": 1, "use_ml": False},
        )
        job.status = "running"
        job.attempt_count = 1
        job.max_attempts = 3
        job.lease_owner = "lost-worker"
        job.lease_expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        db.commit()
        record_worker_heartbeat(db, worker_id="lost-worker", status="running", current_job_id=job.id)

        recovered = recover_expired_leases(db, retry_delay_seconds=1)
        db.refresh(job)
        assert [item.id for item in recovered] == [job.id]
        assert job.status == "failed"
        assert "lease expired" in (job.error_summary or "").lower()
        heartbeat = db.get(OperationWorkerHeartbeat, "lost-worker")
        assert heartbeat is not None
        assert heartbeat.current_job_id is None
        assert db.scalar(select(func.count(ResponseAction.id))) == 0


def test_worker_summary_reports_heartbeat_without_exposing_worker_payload():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool, future=True)
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        result = run_worker_once(db, worker_id="summary-worker")
        summary = build_job_summary(
            db,
            stale_after_minutes=60,
            job_retention_days=30,
            run_history_retention_days=90,
            worker_enabled=False,
            worker_heartbeat_seconds=15,
        )
        assert result["processed"] is False
        assert summary["worker"]["status"] == "idle"
        assert summary["worker"]["worker_id"] == "summary-worker"
        assert "payload" not in str(summary)
