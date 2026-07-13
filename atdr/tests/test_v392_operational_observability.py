from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import sys
from threading import Event

from fastapi.testclient import TestClient
import pytest
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from atdr.app.db.database import Base
from atdr.app.db.models import (
    AuditLog,
    DetectionRun,
    OperationJob,
    OperationWorkerHeartbeat,
    RawLog,
    ResponseAction,
)
from atdr.app.main import app
from atdr.app.services import observability_service, operation_worker
from atdr.app.services.audit_retention_service import (
    APPLY_CONFIRMATION,
    apply_audit_retention,
    build_audit_retention_report,
)
from atdr.app.services.job_service import build_job_summary, record_worker_heartbeat
from atdr.app.services.operation_worker import WorkerConcurrencyError, enforce_worker_concurrency, run_worker_loop
from atdr.tests.test_parser import TRAFFIC_LINE
from atdr.tests.test_v390_durable_operation_jobs import _client_with_session, _login
from atdr.scripts import audit_retention as audit_retention_script


def _memory_session() -> sessionmaker[Session]:
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)


def test_request_id_is_bounded_propagated_and_not_a_metric_dimension():
    client, _ = _client_with_session()
    try:
        accepted = client.get("/health/live", headers={"X-Request-ID": "ops-check-42"})
        assert accepted.status_code == 200
        assert accepted.headers["X-Request-ID"] == "ops-check-42"

        rejected = client.get("/health/live", headers={"X-Request-ID": "unsafe request id " + "x" * 200})
        generated = rejected.headers["X-Request-ID"]
        assert generated != "unsafe request id " + "x" * 200
        assert len(generated) == 36

        metrics = client.get("/metrics")
        assert metrics.status_code == 200
        assert "ops-check-42" not in metrics.text
        assert "request_id" not in metrics.text
        assert "/health/live" not in metrics.text
        assert "client_ip" not in metrics.text
    finally:
        app.dependency_overrides.clear()


def test_liveness_is_process_only_and_readiness_returns_clean_503(monkeypatch):
    client, _ = _client_with_session()
    try:
        live = client.get("/health/live")
        assert live.status_code == 200
        assert live.json()["status"] == "ok"

        monkeypatch.setattr(
            observability_service,
            "check_database_connection",
            lambda db: {
                "status": "error",
                "dialect": "postgresql",
                "detail": "OperationalError",
                "secrets_exposed": False,
            },
        )
        ready = client.get("/health/ready")
        assert ready.status_code == 503
        payload = ready.json()
        assert payload["status"] == "not_ready"
        assert payload["checks"]["database"]["status"] == "error"
        assert payload["secrets_exposed"] is False
        assert "password" not in ready.text.lower()
        assert "database_url" not in ready.text.lower()
    finally:
        app.dependency_overrides.clear()


def test_readiness_passes_only_with_database_migration_and_safe_config(monkeypatch):
    client, _ = _client_with_session()
    try:
        monkeypatch.setattr(observability_service, "validate_runtime_settings", lambda settings: [])
        monkeypatch.setattr(
            observability_service,
            "check_database_connection",
            lambda db: {
                "status": "ok",
                "dialect": "sqlite",
                "migration": {"status": "at_head", "revision": "current", "head_revision": "current"},
                "secrets_exposed": False,
            },
        )
        ready = client.get("/health/ready")
        assert ready.status_code == 200
        assert ready.json()["status"] == "ready"
    finally:
        app.dependency_overrides.clear()


def test_operational_warnings_cover_stale_worker_backlog_and_repeated_failures():
    testing_session = _memory_session()
    now = datetime.now(timezone.utc)
    with testing_session() as db:
        for index in range(2):
            db.add(OperationJob(job_type="run_detection", status="queued", requested_by=f"analyst-{index}"))
        for index in range(3):
            db.add(
                OperationJob(
                    job_type="export_report",
                    status="failed",
                    requested_by=f"admin-{index}",
                    finished_at=now,
                    updated_at=now,
                )
            )
        db.commit()
        heartbeat = record_worker_heartbeat(db, worker_id="stale-worker", status="running")
        heartbeat.last_seen_at = now - timedelta(minutes=5)
        db.commit()

        summary = build_job_summary(
            db,
            stale_after_minutes=60,
            job_retention_days=30,
            run_history_retention_days=90,
            worker_enabled=True,
            worker_heartbeat_seconds=15,
            queue_backlog_warning=2,
            job_failure_warning_count=3,
            job_failure_warning_window_minutes=60,
        )
        codes = {warning["code"] for warning in summary["warnings"]}
        assert {"worker_unavailable", "queue_backlog", "repeated_job_failures"} <= codes
        assert summary["health_status"] == "warning"


def test_sqlite_rejects_a_second_fresh_worker_and_graceful_stop_is_recorded(monkeypatch):
    testing_session = _memory_session()
    with testing_session() as db:
        record_worker_heartbeat(db, worker_id="worker-one", status="watching")
        with pytest.raises(WorkerConcurrencyError, match="SQLite permits one"):
            enforce_worker_concurrency(db, worker_id="worker-two", heartbeat_seconds=15)

    with testing_session() as db:
        existing = db.get(OperationWorkerHeartbeat, "worker-one")
        assert existing is not None
        existing.status = "stopped"
        db.commit()

    monkeypatch.setattr(operation_worker, "SessionLocal", testing_session)
    stop = Event()
    stop.set()
    assert run_worker_loop(worker_id="worker-two", max_jobs=1, stop_event=stop) == []
    with testing_session() as db:
        heartbeat = db.get(OperationWorkerHeartbeat, "worker-two")
        assert heartbeat is not None
        assert heartbeat.status == "stopped"
        assert heartbeat.current_job_id is None


def test_audit_retention_is_dry_run_by_default_and_preserves_security_evidence():
    testing_session = _memory_session()
    old = datetime.now(timezone.utc) - timedelta(days=400)
    with testing_session() as db:
        db.add(RawLog(raw_line=TRAFFIC_LINE))
        db.add_all(
            [
                AuditLog(actor="test", action="dashboard_viewed", target_type="page", target_value="overview", details={}, created_at=old),
                AuditLog(actor="test", action="response_action_denied", target_type="alert", target_value="1", details={}, created_at=old),
                AuditLog(actor="test", action="mfu_iam_login_failed", target_type="user", target_value="redacted", details={}, created_at=old),
            ]
        )
        db.commit()

        report = build_audit_retention_report(db, retention_days=365, minimum_days=90, batch_size=10)
        assert report["mode"] == "dry_run"
        assert report["eligible_event_count"] == 1
        assert report["protected_security_event_count"] == 2
        assert db.scalar(select(func.count(AuditLog.id))) == 3
        assert db.scalar(select(func.count(RawLog.id))) == 1

        with pytest.raises(ValueError, match="requires --confirm"):
            apply_audit_retention(
                db,
                retention_days=365,
                minimum_days=90,
                batch_size=10,
                confirmation="NO",
            )

        applied = apply_audit_retention(
            db,
            retention_days=365,
            minimum_days=90,
            batch_size=10,
            confirmation=APPLY_CONFIRMATION,
        )
        assert applied["deleted_count"] == 1
        actions = set(db.scalars(select(AuditLog.action)))
        assert "dashboard_viewed" not in actions
        assert {"response_action_denied", "mfu_iam_login_failed", "audit_retention_applied"} <= actions
        assert db.scalar(select(func.count(RawLog.id))) == 1


def test_audit_retention_cli_defaults_to_dry_run_on_temporary_database(monkeypatch, capsys):
    testing_session = _memory_session()
    old = datetime.now(timezone.utc) - timedelta(days=400)
    with testing_session() as db:
        db.add(AuditLog(actor="test", action="dashboard_viewed", target_type="page", target_value="overview", details={}, created_at=old))
        db.commit()

    monkeypatch.setattr(audit_retention_script, "SessionLocal", testing_session)
    monkeypatch.setattr(sys, "argv", ["audit_retention", "--pretty"])
    assert audit_retention_script.main() == 0
    output = json.loads(capsys.readouterr().out)
    assert output["mode"] == "dry_run"
    assert output["would_delete_count"] == 1
    with testing_session() as db:
        assert db.scalar(select(func.count(AuditLog.id))) == 1


def test_monitoring_endpoints_do_not_create_detection_or_response_side_effects():
    client, testing_session = _client_with_session()
    try:
        admin_headers = _login(client, "admin", "admin123")
        with testing_session() as db:
            before = {
                "detection": db.scalar(select(func.count(DetectionRun.id))),
                "response": db.scalar(select(func.count(ResponseAction.id))),
            }
        assert client.get("/health").status_code == 200
        assert client.get("/health/live").status_code == 200
        assert client.get("/metrics").status_code == 200
        assert client.get("/api/jobs/summary", headers=admin_headers).status_code == 200
        assert client.get("/api/operations/health", headers=admin_headers).status_code == 200
        with testing_session() as db:
            assert db.scalar(select(func.count(DetectionRun.id))) == before["detection"]
            assert db.scalar(select(func.count(ResponseAction.id))) == before["response"]
    finally:
        app.dependency_overrides.clear()


def test_detailed_operations_health_is_admin_only():
    client, _ = _client_with_session()
    try:
        analyst_headers = _login(client, "analyst", "analyst123")
        admin_headers = _login(client, "admin", "admin123")
        assert client.get("/api/operations/health").status_code == 401
        assert client.get("/api/operations/health", headers=analyst_headers).status_code == 403
        response = client.get("/api/operations/health", headers=admin_headers)
        assert response.status_code == 200
        assert response.json()["secrets_exposed"] is False
    finally:
        app.dependency_overrides.clear()
