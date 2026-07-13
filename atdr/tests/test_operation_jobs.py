from collections.abc import Generator
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from atdr.app.db.database import Base, get_db
from atdr.app.db.models import AuditLog, OperationJob, RawLog
from atdr.app.main import app
from atdr.app.services.user_service import create_user
from atdr.scripts.maintenance_jobs import run_maintenance_jobs
from atdr.scripts.replay_logs import replay_logs
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


def _client() -> TestClient:
    client, _ = _client_with_session()
    return client


def _login(client: TestClient, username: str, password: str) -> dict[str, str]:
    response = client.post("/api/auth/login", json={"username": username, "password": password})
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def test_job_history_endpoints_are_authenticated_and_detection_creates_job():
    client = _client()
    try:
        assert client.get("/api/jobs").status_code == 401
        analyst_headers = _login(client, "analyst", "analyst123")

        detection = client.post("/api/detection/run?limit=1&use_ml=false", headers=analyst_headers)
        assert detection.status_code == 200
        assert detection.json()["job_id"] >= 1

        jobs = client.get("/api/jobs", headers=analyst_headers)
        assert jobs.status_code == 200
        payload = jobs.json()
        assert payload[0]["job_type"] == "run_detection"
        assert payload[0]["status"] == "completed"
        assert payload[0]["related_detection_run_id"] == detection.json()["detection_run_id"]

        completed_cancel = client.post(f"/api/jobs/{payload[0]['job_id']}/cancel", headers=analyst_headers)
        assert completed_cancel.status_code == 409
    finally:
        app.dependency_overrides.clear()


def test_demo_import_success_and_failure_are_recorded_as_jobs(tmp_path):
    sample = tmp_path / "sample.log"
    sample.write_text(TRAFFIC_LINE + "\n", encoding="utf-8")
    missing = tmp_path / "missing.log"

    client = _client()
    try:
        admin_headers = _login(client, "admin", "admin123")
        imported = client.post(
            "/api/demo/import-sample",
            json={"limit": 1, "sample_path": str(sample)},
            headers=admin_headers,
        )
        assert imported.status_code == 200
        assert imported.json()["job_id"] >= 1

        failed = client.post(
            "/api/demo/import-sample",
            json={"limit": 1, "sample_path": str(missing)},
            headers=admin_headers,
        )
        assert failed.status_code == 404

        jobs = client.get("/api/jobs", headers=admin_headers).json()
        assert jobs[0]["status"] == "failed"
        assert jobs[0]["job_type"] == "import_logs"
        assert jobs[1]["status"] == "completed"
        assert jobs[1]["related_ingestion_run_id"] == imported.json()["run_id"]
        assert jobs[1]["result_summary"]["raw_logs_imported"] == 1
    finally:
        app.dependency_overrides.clear()


def test_replay_dry_run_does_not_write_job_and_direct_replay_records_job(tmp_path):
    sample = tmp_path / "replay.log"
    sample.write_text(TRAFFIC_LINE + "\n", encoding="utf-8")
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    Base.metadata.create_all(engine)
    testing_session = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)

    with testing_session() as db:
        dry = replay_logs(db, sample_path=str(sample), send_to="direct", dry_run=True, limit=1, rate=0)
        assert dry["dry_run"] is True
        assert db.scalar(select(OperationJob)) is None

        direct = replay_logs(db, sample_path=str(sample), send_to="direct", dry_run=False, limit=1, rate=0)
        assert direct["job_id"] >= 1
        job = db.scalar(select(OperationJob).where(OperationJob.id == direct["job_id"]))
        assert job is not None
        assert job.job_type == "replay_logs"
        assert job.status == "completed"
        assert job.related_ingestion_run_id == direct["run_id"]


def test_jobs_summary_reports_stale_jobs_without_mutating():
    client, testing_session = _client_with_session()
    try:
        admin_headers = _login(client, "admin", "admin123")
        with testing_session() as db:
            old = datetime.now(timezone.utc) - timedelta(hours=3)
            db.add(
                OperationJob(
                    job_type="run_detection",
                    status="running",
                    requested_by="test",
                    started_at=old,
                    created_at=old,
                    updated_at=old,
                    progress_current=0,
                    progress_total=1,
                    result_summary_json={},
                    details_json={},
                )
            )
            db.commit()

        response = client.get("/api/jobs/summary", headers=admin_headers)
        assert response.status_code == 200
        payload = response.json()
        assert payload["active_count"] == 1
        assert payload["stale_count"] == 1
        assert payload["retention_policy"]["automatic_cleanup_enabled"] is False
        assert payload["retention_policy"]["raw_evidence_cleanup_enabled"] is False
    finally:
        app.dependency_overrides.clear()


def test_maintenance_dry_run_and_stale_marking_protect_evidence():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    Base.metadata.create_all(engine)
    testing_session = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
    old = datetime.now(timezone.utc) - timedelta(hours=3)

    with testing_session() as db:
        db.add(RawLog(raw_line=TRAFFIC_LINE))
        db.add(AuditLog(actor="test", action="seed", target_type="job", target_value="stale", details={}))
        job = OperationJob(
            job_type="run_detection",
            status="running",
            requested_by="test",
            started_at=old,
            created_at=old,
            updated_at=old,
            progress_current=0,
            progress_total=1,
            result_summary_json={},
            details_json={},
        )
        db.add(job)
        db.commit()
        job_id = job.id

        dry = run_maintenance_jobs(db, dry_run=True, mark_stale_jobs=True, stale_after_minutes=60, limit=10)
        assert dry["dry_run"] is True
        assert dry["mutated"] is False
        assert len(dry["stale_candidates"]) == 1
        assert db.get(OperationJob, job_id).status == "running"  # type: ignore[union-attr]

        applied = run_maintenance_jobs(db, dry_run=False, mark_stale_jobs=True, stale_after_minutes=60, limit=10)
        assert applied["mutated"] is True
        marked = db.get(OperationJob, job_id)
        assert marked is not None
        assert marked.status == "failed"
        assert "Marked stale" in (marked.error_summary or "")
        assert db.scalar(select(func.count(RawLog.id))) == 1
        assert db.scalar(select(func.count(AuditLog.id))) == 2
        assert db.scalar(select(AuditLog.action).where(AuditLog.action == "operation_job_marked_stale")) == "operation_job_marked_stale"


def test_maintenance_cleanup_only_deletes_old_terminal_operation_jobs():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    Base.metadata.create_all(engine)
    testing_session = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
    old = datetime.now(timezone.utc) - timedelta(days=45)
    recent = datetime.now(timezone.utc)

    with testing_session() as db:
        db.add(RawLog(raw_line=TRAFFIC_LINE))
        db.add(AuditLog(actor="test", action="seed", target_type="job", target_value="cleanup", details={}))
        jobs = [
            OperationJob(
                job_type="run_detection",
                status="completed",
                requested_by="test",
                started_at=old,
                finished_at=old,
                created_at=old,
                updated_at=old,
                progress_current=1,
                progress_total=1,
                result_summary_json={},
                details_json={},
            ),
            OperationJob(
                job_type="import_logs",
                status="failed",
                requested_by="test",
                started_at=old,
                finished_at=old,
                created_at=old,
                updated_at=old,
                progress_current=0,
                progress_total=1,
                result_summary_json={},
                details_json={},
            ),
            OperationJob(
                job_type="train_ml",
                status="completed",
                requested_by="test",
                started_at=recent,
                finished_at=recent,
                created_at=recent,
                updated_at=recent,
                progress_current=1,
                progress_total=1,
                result_summary_json={},
                details_json={},
            ),
            OperationJob(
                job_type="run_detection",
                status="running",
                requested_by="test",
                started_at=old,
                created_at=old,
                updated_at=old,
                progress_current=0,
                progress_total=1,
                result_summary_json={},
                details_json={},
            ),
        ]
        db.add_all(jobs)
        db.commit()

        dry = run_maintenance_jobs(db, dry_run=True, cleanup_completed_jobs=True, older_than_days=30, limit=10)
        assert len(dry["cleanup_candidates"]) == 2
        assert db.scalar(select(func.count(OperationJob.id))) == 4

        applied = run_maintenance_jobs(db, dry_run=False, cleanup_completed_jobs=True, older_than_days=30, limit=10)
        assert applied["deleted_operation_jobs"] == 2
        assert db.scalar(select(func.count(OperationJob.id))) == 2
        assert db.scalar(select(func.count(RawLog.id))) == 1
        assert db.scalar(select(func.count(AuditLog.id))) == 1
