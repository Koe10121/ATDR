from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import os
import socket
from threading import Event
import time
from typing import Any
from collections.abc import Callable, Iterator

from sqlalchemy import select
from sqlalchemy.orm import Session

from atdr.app.core.config import get_settings
from atdr.app.db.database import SessionLocal
from atdr.app.db.models import OperationWorkerHeartbeat
from atdr.app.services.database_coordination_service import (
    acquire_worker_operation_lock,
    release_worker_operation_lock,
)
from atdr.app.services.job_dispatcher import (
    CooperativeShadowObservationCancelled,
    cleanup_staged_payload,
    execute_operation_job,
    related_run_ids,
)
from atdr.app.services.job_service import (
    LeaseOwnershipError,
    build_result_summary,
    claim_next_job,
    complete_cooperative_cancellation,
    complete_queued_job,
    fail_queued_job,
    job_to_dict,
    record_worker_heartbeat,
    recover_expired_leases,
)
from atdr.app.services.resumable_ingestion_service import (
    CooperativeImportCancelled,
    CooperativeWorkerShutdown,
    mark_resumable_ingestion_failed,
)
from atdr.app.services.staging_service import effective_staging_storage_id


_ACTIVE_WORKER_STATES = {"starting", "watching", "idle", "running"}


class WorkerConcurrencyError(RuntimeError):
    """Raised when a second fresh operation worker attempts to use SQLite."""


def default_worker_id() -> str:
    return f"{socket.gethostname()[:80]}-operation-worker-{os.getpid()}"


def enforce_worker_concurrency(
    db: Session,
    *,
    worker_id: str,
    heartbeat_seconds: int,
) -> None:
    """Keep SQLite single-worker while leaving PostgreSQL multi-worker capable."""

    if db.get_bind().dialect.name != "sqlite":
        return
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=max(1, int(heartbeat_seconds)) * 3)
    active_other = db.scalar(
        select(OperationWorkerHeartbeat)
        .where(OperationWorkerHeartbeat.worker_id != worker_id)
        .where(OperationWorkerHeartbeat.status.in_(_ACTIVE_WORKER_STATES))
        .where(OperationWorkerHeartbeat.last_seen_at >= cutoff)
        .limit(1)
    )
    if active_other is not None:
        raise WorkerConcurrencyError(
            "SQLite permits one ATDR operation worker. Stop the existing worker or wait for its heartbeat to become stale."
        )


def _record_worker_stopped(worker_id: str, *, reason: str) -> None:
    try:
        with SessionLocal() as db:
            record_worker_heartbeat(
                db,
                worker_id=worker_id,
                status="stopped",
                current_job_id=None,
                details={"shutdown": reason, "external_services": "disabled"},
            )
    except Exception:
        # Shutdown must never mask the worker's original result or exception.
        return


@contextmanager
def _worker_operation_lock_session(db: Session) -> Iterator[Session]:
    """Pin PostgreSQL advisory-lock ownership to one dedicated connection."""

    if db.get_bind().dialect.name != "postgresql":
        yield db
        return

    coordination_db = Session(bind=db.get_bind(), future=True)
    try:
        yield coordination_db
    finally:
        coordination_db.close()


def run_worker_once(
    db: Session,
    *,
    worker_id: str | None = None,
    stop_event: Event | None = None,
    after_chunk: Callable[[int, Any], None] | None = None,
) -> dict[str, Any]:
    """Process one job while honoring the PostgreSQL backup coordination lock."""

    active_worker_id = (worker_id or default_worker_id()).strip()[:128]
    with _worker_operation_lock_session(db) as coordination_db:
        if not acquire_worker_operation_lock(coordination_db):
            record_worker_heartbeat(
                db,
                worker_id=active_worker_id,
                status="paused",
                details={
                    "reason": "database_backup_in_progress",
                    "external_services": "disabled",
                },
            )
            return {
                "ok": True,
                "worker_id": active_worker_id,
                "processed": False,
                "status": "backup_coordination_pause",
                "job": None,
            }
        try:
            return _run_worker_once_locked(
                db,
                worker_id=active_worker_id,
                stop_event=stop_event,
                after_chunk=after_chunk,
            )
        finally:
            release_worker_operation_lock(coordination_db)


def _run_worker_once_locked(
    db: Session,
    *,
    worker_id: str,
    stop_event: Event | None,
    after_chunk: Callable[[int, Any], None] | None,
) -> dict[str, Any]:
    """Claim and process at most one durable operation job using the caller's DB session."""

    settings = get_settings()
    active_worker_id = worker_id
    recovered = recover_expired_leases(
        db,
        retry_delay_seconds=settings.operation_job_retry_delay_seconds,
    )
    record_worker_heartbeat(
        db,
        worker_id=active_worker_id,
        status="idle",
        details={"recovered_expired_jobs": len(recovered), "external_services": "disabled"},
    )
    job = claim_next_job(
        db,
        worker_id=active_worker_id,
        lease_seconds=settings.operation_worker_lease_seconds,
        staging_storage_id=effective_staging_storage_id(),
        allow_legacy_staging=not settings.operation_staging_shared,
    )
    if job is None:
        return {
            "ok": True,
            "worker_id": active_worker_id,
            "processed": False,
            "recovered_expired_jobs": len(recovered),
            "job": None,
        }

    job_id = int(job.id)
    lease_token = str(job.lease_token or "")
    if not lease_token:
        raise LeaseOwnershipError("Claimed operation job has no lease fencing token.")
    payload = dict(job.payload_json or {})
    record_worker_heartbeat(
        db,
        worker_id=active_worker_id,
        status="running",
        current_job_id=job_id,
        details={"job_type": job.job_type, "attempt_count": job.attempt_count},
    )
    try:
        result = execute_operation_job(
            db,
            job_type=job.job_type,
            payload=payload,
            actor=job.requested_by,
            job_id=job_id,
            worker_id=active_worker_id,
            lease_token=lease_token,
            should_stop=stop_event.is_set if stop_event is not None else None,
            after_chunk=after_chunk,
        )
        relation_ids = related_run_ids(result)
        completed = complete_queued_job(
            db,
            job_id=job_id,
            worker_id=active_worker_id,
            lease_token=lease_token,
            result_summary=build_result_summary(job.job_type, result),
            **relation_ids,
        )
        return {
            "ok": True,
            "worker_id": active_worker_id,
            "processed": True,
            "recovered_expired_jobs": len(recovered),
            "job": job_to_dict(completed),
        }
    except CooperativeImportCancelled:
        db.rollback()
        cancelled = db.get(type(job), job_id)
        if cancelled is None:
            raise ValueError("Cancelled operation job no longer exists.")
        return {
            "ok": True,
            "worker_id": active_worker_id,
            "processed": True,
            "recovered_expired_jobs": len(recovered),
            "job": job_to_dict(cancelled),
        }
    except CooperativeShadowObservationCancelled:
        db.rollback()
        pending = db.get(type(job), job_id)
        if pending is None:
            raise ValueError(
                "Cancelled shadow observation job no longer exists."
            )
        cancelled = complete_cooperative_cancellation(
            db,
            pending,
            worker_id=active_worker_id,
            lease_token=lease_token,
            details={
                "safe_boundary": "before_aggregate_observation_persist"
            },
        )
        db.commit()
        db.refresh(cancelled)
        return {
            "ok": True,
            "worker_id": active_worker_id,
            "processed": True,
            "recovered_expired_jobs": len(recovered),
            "job": job_to_dict(cancelled),
        }
    except CooperativeWorkerShutdown:
        db.rollback()
        released = db.get(type(job), job_id)
        if released is None:
            raise ValueError("Released operation job no longer exists.")
        return {
            "ok": True,
            "worker_id": active_worker_id,
            "processed": True,
            "shutdown_requested": True,
            "recovered_expired_jobs": len(recovered),
            "job": job_to_dict(released),
        }
    except LeaseOwnershipError:
        db.rollback()
        persisted = db.get(type(job), job_id)
        return {
            "ok": False,
            "worker_id": active_worker_id,
            "processed": True,
            "status": "lease_lost",
            "recovered_expired_jobs": len(recovered),
            "job": job_to_dict(persisted) if persisted is not None else None,
        }
    except Exception as exc:
        # Dispatch services may have left the session in a failed transaction.
        db.rollback()
        try:
            failed = fail_queued_job(
                db,
                job_id=job_id,
                worker_id=active_worker_id,
                lease_token=lease_token,
                error=exc,
                retry_delay_seconds=settings.operation_job_retry_delay_seconds,
            )
        except LeaseOwnershipError:
            db.rollback()
            persisted = db.get(type(job), job_id)
            return {
                "ok": False,
                "worker_id": active_worker_id,
                "processed": True,
                "status": "lease_lost",
                "recovered_expired_jobs": len(recovered),
                "job": job_to_dict(persisted) if persisted is not None else None,
            }
        if failed.job_type in {"import_logs", "replay_logs"}:
            mark_resumable_ingestion_failed(db, failed, error=exc)
        return {
            "ok": False,
            "worker_id": active_worker_id,
            "processed": True,
            "recovered_expired_jobs": len(recovered),
            "job": job_to_dict(failed),
        }
    finally:
        persisted = db.get(type(job), job_id)
        if persisted is not None and persisted.status == "completed":
            cleanup_staged_payload(payload)
        record_worker_heartbeat(
            db,
            worker_id=active_worker_id,
            status="idle",
            current_job_id=None,
            details={"external_services": "disabled"},
        )


def run_worker_cycle(*, worker_id: str | None = None) -> dict[str, Any]:
    settings = get_settings()
    active_worker_id = (worker_id or default_worker_id()).strip()[:128]
    with SessionLocal() as db:
        enforce_worker_concurrency(
            db,
            worker_id=active_worker_id,
            heartbeat_seconds=settings.operation_worker_heartbeat_seconds,
        )
        record_worker_heartbeat(
            db,
            worker_id=active_worker_id,
            status="starting",
            details={"mode": "once", "external_services": "disabled"},
        )
        try:
            return run_worker_once(db, worker_id=active_worker_id)
        finally:
            record_worker_heartbeat(
                db,
                worker_id=active_worker_id,
                status="stopped",
                current_job_id=None,
                details={"shutdown": "cycle_complete", "external_services": "disabled"},
            )


def run_worker_loop(
    *,
    worker_id: str | None = None,
    poll_seconds: float | None = None,
    max_jobs: int | None = None,
    stop_event: Event | None = None,
) -> list[dict[str, Any]]:
    settings = get_settings()
    active_worker_id = (worker_id or default_worker_id()).strip()[:128]
    delay = max(0.1, float(poll_seconds if poll_seconds is not None else settings.operation_worker_poll_seconds))
    processed: list[dict[str, Any]] = []
    with SessionLocal() as db:
        enforce_worker_concurrency(
            db,
            worker_id=active_worker_id,
            heartbeat_seconds=settings.operation_worker_heartbeat_seconds,
        )
        record_worker_heartbeat(
            db,
            worker_id=active_worker_id,
            status="watching",
            details={"mode": "watch", "external_services": "disabled"},
        )
    try:
        while max_jobs is None or len(processed) < max(1, int(max_jobs)):
            if stop_event is not None and stop_event.is_set():
                break
            with SessionLocal() as db:
                result = run_worker_once(db, worker_id=active_worker_id, stop_event=stop_event)
            if result.get("processed"):
                processed.append(result)
                continue
            if stop_event is not None:
                stop_event.wait(delay)
            else:
                time.sleep(delay)
        return processed
    finally:
        _record_worker_stopped(active_worker_id, reason="graceful_shutdown")
