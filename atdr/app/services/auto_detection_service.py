"""Check new logs by themselves, once their evidence is complete.

Detection used to run only when someone clicked "Check all unchecked logs". With ``AUTO_DETECTION_ENABLED`` the
background worker checks unchecked logs whenever it has no queued job, but only the logs whose evidence has arrived:

- The rules count per source and five-minute clock window, on two grids (the second shifted by half a window), and
  the beaconing rule also reads the window before and the window after a log's own. A log's evidence is therefore
  complete once the window after its own has closed, that is, once a log two windows later has been stored. Checked
  earlier, a group would be judged on part of its logs and the result would depend on when the check happened to run.
- When no log has been stored for ``AUTO_DETECTION_QUIET_SECONDS`` (an import has finished, a feed has gone quiet),
  nothing more is coming for the newest windows either, so every unchecked log is checked.

Each automatic check is recorded as a manual one is: an operation job, requested by ``auto_detection``, and a
detection run per batch. The button stays, and checks everything at once.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from atdr.app.core.config import Settings, get_settings
from atdr.app.db.models import NormalizedLog, OperationJob, OperationWorkerHeartbeat, RawLog
from atdr.app.detection.rules import CORRELATION_WINDOW, correlation_window_start
from atdr.app.services.detection_service import _event_time_expression, count_unchecked_logs, run_detection
from atdr.app.services.job_service import build_result_summary, complete_job, fail_job, start_job

AUTO_DETECTION_ACTOR = "auto_detection"
BATCH_LOGS = 5000
# One check gives way to the worker's queued jobs after this long; the rest follows on the next look.
MAX_SECONDS_PER_CHECK = 60.0
LIVE_WORKER_STATES = ("starting", "watching", "idle", "running", "paused")


@dataclass(frozen=True, slots=True)
class DueLogs:
    """Which unchecked logs can be checked now. ``before`` None with ``due`` means every unchecked log."""

    waiting: int
    due: bool
    before: datetime | None = None
    reason: str = "nothing_waiting"


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def _unchecked_before(db: Session, before: datetime | None) -> bool:
    statement = select(NormalizedLog.id).where(NormalizedLog.last_detection_run_id.is_(None))
    if before is not None:
        statement = statement.where(_event_time_expression() < before)
    return db.scalar(statement.limit(1)) is not None


def due_logs(db: Session, *, now: datetime, quiet_seconds: float) -> DueLogs:
    waiting = count_unchecked_logs(db)
    if not waiting:
        return DueLogs(0, False)
    newest_stored = db.scalar(select(func.max(RawLog.imported_at)))
    if newest_stored is None or (_utc(now) - _utc(newest_stored)).total_seconds() >= quiet_seconds:
        return DueLogs(waiting, True, None, "logs_stopped_arriving")
    newest_event = db.scalar(select(func.max(_event_time_expression())))
    if newest_event is None:
        # No stored log has a time, so none can be placed in a window; they wait for the quiet period.
        return DueLogs(waiting, False, None, "newest_window_still_open")
    # The newest log's window is still filling, and the window before it is still evidence for the one before that.
    before = correlation_window_start(newest_event) - CORRELATION_WINDOW
    if not _unchecked_before(db, before):
        return DueLogs(waiting, False, before, "newest_window_still_open")
    return DueLogs(waiting, True, before, "window_complete")


def _database_busy(error: BaseException) -> bool:
    """SQLite has one writer: a check that finds an import or a manual check writing waits for the next look."""

    return isinstance(error, OperationalError) and "locked" in str(error).lower()


def run_automatic_detection(
    db: Session,
    *,
    now: datetime | None = None,
    settings: Settings | None = None,
    between_batches: Callable[[], None] | None = None,
) -> dict[str, Any] | None:
    """Check every unchecked log whose evidence is complete. None when nothing was due or the database was busy.

    The result's ``more_due`` says that the time for one check ran out with complete windows still waiting.
    """

    settings = settings or get_settings()
    due = due_logs(db, now=now or datetime.now(timezone.utc), quiet_seconds=settings.auto_detection_quiet_seconds)
    if not due.due:
        return None
    totals = {"evaluated": 0, "created_alerts": 0, "deduplicated_alert_updates": 0, "suppressed_low_groups": 0, "suppressed_by_rules": 0}
    batches = 0
    last_run_id: int | None = None
    more_due = False
    job: OperationJob | None = None
    started = time.monotonic()
    began = datetime.now(timezone.utc)
    try:
        while True:
            result = run_detection(
                db, limit=BATCH_LOGS, use_ml=False, actor=AUTO_DETECTION_ACTOR, only_unchecked=True, event_time_end=due.before,
            )
            if job is None:
                # Recorded once the first batch is in: a check that found the database busy leaves no failed job behind.
                job = start_job(
                    db,
                    job_type="run_detection",
                    requested_by=AUTO_DETECTION_ACTOR,
                    details={
                        "mode": "unchecked",
                        "automatic": True,
                        "reason": due.reason,
                        "event_time_before": due.before.isoformat() if due.before else None,
                    },
                )
                # The job's own start would be the end of the first batch.
                job.started_at = began
            batches += 1
            last_run_id = result.get("detection_run_id") or last_run_id
            for key in totals:
                totals[key] += int(result.get(key) or 0)
            # Not "remaining_unchecked": that also counts the logs of windows still open.
            if not result.get("evaluated") or not _unchecked_before(db, due.before):
                break
            if between_batches is not None:
                between_batches()
            if time.monotonic() - started >= MAX_SECONDS_PER_CHECK:
                more_due = True
                break
    except Exception as error:
        db.rollback()
        if job is None and _database_busy(error):
            return None
        if job is None:
            job = start_job(db, job_type="run_detection", requested_by=AUTO_DETECTION_ACTOR, details={"mode": "unchecked", "automatic": True})
        fail_job(db, job, error)
        raise
    complete_job(
        db,
        job,
        result_summary={**build_result_summary("run_detection", totals), "batches": batches},
        related_detection_run_id=last_run_id,
    )
    return {**totals, "batches": batches, "reason": due.reason, "job_id": int(job.id), "more_due": more_due}


def automatic_detection_status(db: Session, *, settings: Settings | None = None, now: datetime | None = None) -> dict[str, Any]:
    """What the Data & Detection page says about automatic checks."""

    settings = settings or get_settings()
    now = _utc(now or datetime.now(timezone.utc))
    fresh_since = now - timedelta(seconds=max(1, int(settings.operation_worker_heartbeat_seconds)) * 3)
    worker_seen = db.scalar(
        select(func.max(OperationWorkerHeartbeat.last_seen_at)).where(OperationWorkerHeartbeat.status.in_(LIVE_WORKER_STATES))
    )
    last = db.scalar(
        select(OperationJob)
        .where(OperationJob.requested_by == AUTO_DETECTION_ACTOR, OperationJob.job_type == "run_detection")
        .where(OperationJob.status.in_(("completed", "failed")))
        .order_by(OperationJob.id.desc())
        .limit(1)
    )
    summary = (last.result_summary_json or {}) if last is not None else {}
    return {
        "enabled": bool(settings.auto_detection_enabled),
        "worker_running": worker_seen is not None and _utc(worker_seen) >= fresh_since,
        "quiet_seconds": int(settings.auto_detection_quiet_seconds),
        "window_minutes": int(CORRELATION_WINDOW.total_seconds() // 60),
        "last_check": None if last is None else {
            "status": last.status,
            "finished_at": _utc(last.finished_at).isoformat() if last.finished_at else None,
            "logs_checked": int(summary.get("logs_evaluated") or 0),
            "alerts_created": int(summary.get("alerts_created") or 0),
            "alerts_updated": int(summary.get("alerts_deduplicated") or 0),
        },
    }
