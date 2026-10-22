"""What ATDR keeps only for a set time is deleted once that time has passed, by the worker, every hour.

The periods were settings with code to apply them, but only commands run by hand used it, so nothing was ever
deleted: audit entries past 365 days, finished jobs past 30 days, staged copies of imported files past 24 hours.
"""

from __future__ import annotations

import os
import threading
from datetime import datetime, timedelta, timezone

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from atdr.app.core.config import Settings
from atdr.app.db.database import Base
from atdr.app.db.models import AuditLog, OperationJob
from atdr.app.services import housekeeping_service, operation_worker, staged_input_retention_service, staging_service
from atdr.app.services.housekeeping_service import HOUSEKEEPING_LOOK_SECONDS, run_housekeeping

NOW = datetime.now(timezone.utc)


def _session() -> Session:
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool, future=True)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)()


def _audit(db: Session, action: str, days_ago: int) -> int:
    entry = AuditLog(actor="koe", action=action, target_type="alert", target_value="1", details={},
                     created_at=NOW - timedelta(days=days_ago))
    db.add(entry)
    db.flush()
    return entry.id


def _job(db: Session, status: str, days_ago: int, **fields) -> int:
    job = OperationJob(job_type="run_detection", status=status, requested_by="koe", payload_json={},
                       created_at=NOW - timedelta(days=days_ago), updated_at=NOW - timedelta(days=days_ago), **fields)
    db.add(job)
    db.flush()
    return job.id


def _staged(root, name: str, hours_ago: float):
    path = root / name
    path.write_text("staged firewall lines", encoding="utf-8")
    moment = (NOW - timedelta(hours=hours_ago)).timestamp()
    os.utime(path, (moment, moment))
    return path


def test_housekeeping_deletes_what_is_past_its_time_and_keeps_the_rest(monkeypatch, tmp_path):
    root = tmp_path / "staging"
    root.mkdir()
    monkeypatch.setattr(staging_service, "STAGING_ROOT", root)
    monkeypatch.setattr(staged_input_retention_service, "STAGING_ROOT", root)
    settings = Settings(_env_file=None, OPERATION_STAGING_ROOT="")
    db = _session()

    old_note = _audit(db, "alert_note_added", 400)
    old_sign_in = _audit(db, "login_success", 400)  # a security record: kept whatever its age
    recent_note = _audit(db, "alert_note_added", 10)
    old_job = _job(db, "completed", 40)
    repeated = _job(db, "failed", 40)
    _job(db, "completed", 2, original_job_id=repeated)  # still names the old failed job it repeats
    recent_job = _job(db, "completed", 5)
    stuck = _job(db, "running", 40)  # not finished: left alone
    db.commit()
    old_file = _staged(root, "abc-old-import.log", hours_ago=30)
    new_file = _staged(root, "def-new-import.log", hours_ago=2)

    done = run_housekeeping(db, settings=settings)

    assert done == {"audit_entries": 1, "jobs": 1, "staged_files": 1, "staged_bytes": len("staged firewall lines"), "evidence_logs": 0}
    kept_audit = set(db.scalars(select(AuditLog.id)))
    assert old_note not in kept_audit and {old_sign_in, recent_note} <= kept_audit
    kept_jobs = set(db.scalars(select(OperationJob.id)))
    assert old_job not in kept_jobs and {repeated, recent_job, stuck} <= kept_jobs
    assert not old_file.exists() and new_file.exists()
    actions = [entry.action for entry in db.scalars(select(AuditLog).where(AuditLog.actor == "housekeeping"))]
    assert sorted(actions) == ["audit_retention_applied", "housekeeping_applied"]

    # Nothing more is past its time: the next pass deletes nothing and writes no audit entry.
    assert run_housekeeping(db, settings=settings) == {"audit_entries": 0, "jobs": 0, "staged_files": 0, "staged_bytes": 0, "evidence_logs": 0}
    assert len(list(db.scalars(select(AuditLog).where(AuditLog.actor == "housekeeping")))) == 2


def test_the_worker_does_its_housekeeping_every_hour_and_a_failure_does_not_stop_it(monkeypatch):
    calls: list[str] = []

    class _Session:
        def __enter__(self):
            return object()

        def __exit__(self, *_exc):
            return False

    monkeypatch.setattr(operation_worker, "SessionLocal", _Session)
    monkeypatch.setattr(operation_worker, "get_settings", lambda: Settings(_env_file=None))
    monkeypatch.setattr(operation_worker, "run_housekeeping", lambda _db, **_kwargs: calls.append("pass") or {})
    before = operation_worker.time.monotonic()
    next_look = operation_worker._housekeeping_look(0.0)
    assert next_look >= before + HOUSEKEEPING_LOOK_SECONDS - 1 and calls == ["pass"]
    # Not time yet: nothing happens.
    assert operation_worker._housekeeping_look(next_look) == next_look and calls == ["pass"]

    def broken(_db, **_kwargs):
        calls.append("broken")
        raise RuntimeError("the database is locked")

    monkeypatch.setattr(operation_worker, "run_housekeeping", broken)
    assert operation_worker._housekeeping_look(0.0) >= before + HOUSEKEEPING_LOOK_SECONDS - 1
    assert calls == ["pass", "broken"]
    assert housekeeping_service.HOUSEKEEPING_LOOK_SECONDS == 3600


def test_the_worker_loop_does_its_housekeeping_when_nothing_is_queued(monkeypatch):
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool, future=True)
    Base.metadata.create_all(engine)
    monkeypatch.setattr(operation_worker, "SessionLocal", sessionmaker(bind=engine, future=True))
    monkeypatch.setattr(operation_worker, "get_settings", lambda: Settings(_env_file=None))
    monkeypatch.setattr(operation_worker, "_automatic_detection_look", lambda _worker, next_look: next_look)
    monkeypatch.setattr(operation_worker, "_retention_look", lambda next_look, _progress: next_look)
    monkeypatch.setattr(operation_worker, "_backup_look", lambda _worker, next_look: next_look)
    monkeypatch.setattr(operation_worker, "_notification_look", lambda *_args: None)
    stop = operation_worker.Event()
    looks: list[float] = []

    def look(next_look: float) -> float:
        looks.append(next_look)
        stop.set()
        return next_look

    monkeypatch.setattr(operation_worker, "_housekeeping_look", look)
    # A loop that never looks would run for ever: stop it, and fail on what was seen.
    give_up = threading.Timer(20.0, stop.set)
    give_up.start()
    try:
        operation_worker.run_worker_loop(worker_id="housekeeping-test-worker", poll_seconds=0.1, stop_event=stop)
    finally:
        give_up.cancel()
    assert looks == [0.0], "the first pass comes as soon as the worker has nothing queued"


def test_housekeeping_deletes_old_evidence_of_closed_alerts_and_says_so(monkeypatch):
    calls = []

    def evidence(db, *, settings):
        calls.append(settings.alert_evidence_retention_days)
        return {"enabled": True, "links": 3, "logs": 2, "alerts": 1}

    monkeypatch.setattr(housekeeping_service, "delete_closed_alert_evidence", evidence)
    db = _session()
    done = run_housekeeping(db, settings=Settings(_env_file=None, ALERT_EVIDENCE_RETENTION_DAYS=30))

    assert calls == [30] and done["evidence_logs"] == 2
    entry = db.scalar(select(AuditLog).where(AuditLog.action == "housekeeping_applied"))
    assert (entry.details["evidence_links_removed"], entry.details["evidence_logs_deleted"]) == (3, 2)
    assert entry.details["evidence_retention_days"] == 30
