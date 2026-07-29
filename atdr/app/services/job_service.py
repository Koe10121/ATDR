from __future__ import annotations

from datetime import datetime, timedelta, timezone
import re
from typing import Any
from uuid import uuid4

from sqlalchemy import desc, func, or_, select
from sqlalchemy.orm import Session

from atdr.app.db.models import AuditLog, IngestionRun, OperationJob, OperationWorkerHeartbeat
from atdr.app.services.operation_run_service import complete_ingestion_run
from atdr.app.services.staging_service import (
    StagedInputError,
    resume_window_open,
    staged_path,
    staging_pressure_state,
    validate_staged_payload,
)


JOB_TYPES = {
    "import_logs",
    "replay_logs",
    "run_detection",
    "train_ml",
    "apply_ml_scoring",
    "shadow_observation",
    "shadow_monitoring_cycle",
    "export_report",
    "validation",
}
JOB_STATUSES = {"queued", "retry_wait", "running", "cancel_requested", "completed", "failed", "cancelled"}
ACTIVE_JOB_STATUSES = {"queued", "retry_wait", "running", "cancel_requested"}
STALE_JOB_STATUSES = {"queued", "running", "cancel_requested"}
TERMINAL_JOB_STATUSES = {"completed", "failed", "cancelled"}
CANCELLABLE_JOB_STATUSES = {"queued", "retry_wait"}
RETRYABLE_JOB_STATUSES = {"failed", "cancelled"}
AUTO_RETRY_SAFE_JOB_TYPES = {
    "export_report",
    "shadow_observation",
    "shadow_monitoring_cycle",
}
COOPERATIVE_CANCELLABLE_JOB_TYPES = {
    "import_logs",
    "replay_logs",
    "shadow_observation",
    "shadow_monitoring_cycle",
}
MAX_SUMMARY_LENGTH = 500
MAX_DETAIL_ITEMS = 30
SENSITIVE_DETAIL_TOKENS = {
    "password",
    "secret",
    "token",
    "authorization",
    "api_key",
    "payload",
    "raw_line",
    "raw_log",
    "staged_input",
    "staged_input_key",
    "staging_storage_id",
    "lease_token",
    "file_path",
    "path",
    "content",
    "upload",
}
_PATH_FRAGMENT = re.compile(r"(?i)(?:[a-z]:)?(?:[\\/][^\s:'\"<>]+)+")


class QueueBackpressureError(RuntimeError):
    """Raised when bounded import queue limits are reached."""


class LeaseOwnershipError(RuntimeError):
    """Raised when a stale worker attempts to mutate a fenced operation job."""


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _cutoff(minutes: int) -> datetime:
    return _now() - timedelta(minutes=max(1, int(minutes)))


def _days_cutoff(days: int) -> datetime:
    return _now() - timedelta(days=max(1, int(days)))


def _assert_owned_lease(
    job: OperationJob,
    *,
    worker_id: str,
    lease_token: str,
    statuses: set[str] | None = None,
) -> None:
    allowed_statuses = statuses or {"running", "cancel_requested"}
    if (
        job.status not in allowed_statuses
        or job.lease_owner != worker_id
        or not lease_token
        or job.lease_token != lease_token
    ):
        raise LeaseOwnershipError("Operation job lease fencing rejected a stale worker update.")


def _safe_text(value: object, *, max_length: int = MAX_SUMMARY_LENGTH) -> str:
    text = _PATH_FRAGMENT.sub("[path]", str(value))
    if len(text) <= max_length:
        return text
    return f"{text[: max_length - 3]}..."


def _summary_value(result: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in result:
            return result[key]
    return None


def _is_sensitive_detail_key(key: object) -> bool:
    normalized = str(key).strip().lower()
    return any(token in normalized for token in SENSITIVE_DETAIL_TOKENS)


def _public_detail_value(value: Any, *, depth: int = 0) -> Any:
    if depth >= 3:
        return "[truncated]"
    if isinstance(value, dict):
        return {
            str(key): _public_detail_value(item, depth=depth + 1)
            for key, item in list(value.items())[:MAX_DETAIL_ITEMS]
            if not _is_sensitive_detail_key(key)
        }
    if isinstance(value, (list, tuple, set)):
        return [_public_detail_value(item, depth=depth + 1) for item in list(value)[:MAX_DETAIL_ITEMS]]
    if isinstance(value, str):
        # Do not render local paths or unexpectedly large diagnostic blobs through job history.
        if "\\" in value or "/" in value:
            return value.replace("\\", "/").rsplit("/", 1)[-1]
        return _safe_text(value, max_length=180)
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return _safe_text(value, max_length=180)


def public_job_details(details: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(details, dict):
        return {}
    return {
        str(key): _public_detail_value(value)
        for key, value in list(details.items())[:MAX_DETAIL_ITEMS]
        if not _is_sensitive_detail_key(key)
    }


def _append_job_audit(
    db: Session,
    *,
    actor: str,
    action: str,
    job: OperationJob,
    details: dict[str, Any] | None = None,
) -> None:
    db.add(
        AuditLog(
            actor=actor,
            action=action,
            target_type="operation_job",
            target_value=str(job.id or "pending"),
            details={
                "job_id": job.id,
                "job_type": job.job_type,
                "status": job.status,
                **public_job_details(details),
            },
        )
    )


def build_result_summary(job_type: str, result: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(result, dict):
        return {}
    if job_type in {"import_logs", "replay_logs"}:
        return {
            "requested_limit": result.get("requested_limit"),
            "limit": result.get("limit"),
            "available_lines": result.get("available_lines"),
            "lines_read": result.get("read"),
            "raw_logs_imported": _summary_value(result, "raw_logs_imported", "imported", "raw_logs_created"),
            "normalized_logs_created": _summary_value(result, "normalized_logs_created", "parsed", "parsed_successfully"),
            "parse_failures": _summary_value(result, "parse_failures", "failed"),
            "duplicate_raw_logs": result.get("duplicate_raw_logs"),
            "source": result.get("source_label") or result.get("source"),
            "alerts_created": result.get("alerts_created"),
            "alerts_deduplicated": result.get("alerts_deduplicated"),
            "parser_quality": public_job_details(
                result.get("parser_quality")
            ),
        }
    if job_type == "run_detection":
        return {
            "logs_evaluated": result.get("evaluated"),
            "candidate_logs": result.get("candidate_logs"),
            "alerts_created": result.get("created_alerts"),
            "alerts_deduplicated": result.get("deduplicated_alert_updates"),
            "alerts_suppressed": (result.get("suppressed_low_groups") or 0) + (result.get("suppressed_by_rules") or 0),
            "top_attack_types": result.get("top_attack_types"),
            "source_id": result.get("source_id"),
        }
    if job_type == "train_ml":
        metrics = result.get("metrics") if isinstance(result.get("metrics"), dict) else {}
        return {
            "status": result.get("status"),
            "trained": result.get("trained"),
            "model_type": result.get("model_type"),
            "training_rows": result.get("training_rows") or result.get("training_log_count"),
            "test_rows": result.get("test_rows"),
            "weighted_f1": metrics.get("weighted_f1"),
            "macro_f1": metrics.get("macro_f1"),
            "message": result.get("message"),
        }
    if job_type == "apply_ml_scoring":
        return {
            "scored": result.get("scored"),
            "anomalies": result.get("anomalies"),
            "anomaly_rate": result.get("anomaly_rate"),
        }
    if job_type == "shadow_observation":
        observation = (
            result.get("observation")
            if isinstance(result.get("observation"), dict)
            else {}
        )
        return {
            "status": result.get("status"),
            "observation_id": observation.get("observation_id"),
            "observation_created": result.get("observation_created"),
            "rows_evaluated": observation.get("rows_evaluated"),
            "queue_count": observation.get("queue_count"),
            "queue_rate": observation.get("queue_rate"),
            "drift_status": observation.get("drift_status"),
            "disagreement_count": observation.get("disagreement_count"),
            "rules_alert_authoritative": result.get(
                "rules_alert_authoritative"
            ),
            "model_activated": result.get("model_activated"),
            "response_automation_allowed": result.get(
                "response_automation_allowed"
            ),
        }
    if job_type == "shadow_monitoring_cycle":
        acceptance = (
            result.get("operational_acceptance")
            if isinstance(result.get("operational_acceptance"), dict)
            else {}
        )
        return {
            "status": result.get("status"),
            "planned_scope_count": result.get("planned_scope_count"),
            "observations_executed": result.get("observations_executed"),
            "successful_observation_count": result.get(
                "successful_observation_count"
            ),
            "created_observation_count": result.get(
                "created_observation_count"
            ),
            "idempotent_reuse_count": result.get(
                "idempotent_reuse_count"
            ),
            "current_drift_state": (
                (acceptance.get("drift") or {}).get("current_state")
                if isinstance(acceptance.get("drift"), dict)
                else None
            ),
            "accuracy_metrics_calculated": False,
            "rules_alert_authoritative": True,
            "model_activated": False,
            "response_automation_allowed": False,
        }
    if job_type == "export_report":
        files = result.get("files")
        return {
            "selected_alert_id": result.get("selected_alert_id"),
            "file_count": len(files) if isinstance(files, dict) else None,
            "counts": result.get("counts"),
            "export_name": _safe_text(result.get("export_dir", "").replace("\\", "/").rsplit("/", 1)[-1])
            if result.get("export_dir")
            else None,
        }
    return {key: result.get(key) for key in ["ok", "status", "message"] if key in result}


def start_job(
    db: Session,
    *,
    job_type: str,
    requested_by: str,
    progress_total: int = 1,
    details: dict[str, Any] | None = None,
) -> OperationJob:
    """Record an existing synchronous operation without changing its behavior."""

    if job_type not in JOB_TYPES:
        raise ValueError(f"Unsupported job type: {job_type}")
    job = OperationJob(
        job_type=job_type,
        status="running",
        requested_by=requested_by,
        started_at=_now(),
        progress_current=0,
        progress_total=max(0, int(progress_total)),
        attempt_count=1,
        max_attempts=1,
        result_summary_json={},
        details_json=public_job_details(details),
    )
    db.add(job)
    db.commit()
    db.refresh(job)
    return job


def enqueue_job(
    db: Session,
    *,
    job_type: str,
    requested_by: str,
    payload: dict[str, Any] | None = None,
    details: dict[str, Any] | None = None,
    idempotency_key: str | None = None,
    max_attempts: int = 1,
    progress_current: int = 0,
    progress_total: int = 1,
    input_size_bytes: int | None = None,
    input_fingerprint: str | None = None,
    resume_expires_at: datetime | None = None,
    resume_of_job_id: int | None = None,
    original_job_id: int | None = None,
    checkpoint_line: int = 0,
    checkpoint_bytes: int = 0,
    chunk_commits: int = 0,
    related_ingestion_run_id: int | None = None,
    staging_storage_id: str | None = None,
) -> tuple[OperationJob, bool]:
    """Persist a job for a separately launched worker. Payload is intentionally never API-visible."""

    if job_type not in JOB_TYPES:
        raise ValueError(f"Unsupported job type: {job_type}")
    normalized_key = (idempotency_key or "").strip() or None
    if normalized_key:
        existing = db.scalar(select(OperationJob).where(OperationJob.idempotency_key == normalized_key))
        if existing is not None:
            if existing.requested_by != requested_by:
                raise ValueError("Idempotency key is already in use by another user.")
            return existing, True

    safe_max_attempts = max(1, min(int(max_attempts), 3))
    job = OperationJob(
        job_type=job_type,
        status="queued",
        requested_by=requested_by,
        progress_current=max(0, int(progress_current)),
        progress_total=max(0, int(progress_total)),
        checkpoint_line=max(0, int(checkpoint_line)),
        checkpoint_bytes=max(0, int(checkpoint_bytes)),
        chunk_commits=max(0, int(chunk_commits)),
        input_size_bytes=input_size_bytes,
        input_fingerprint=(input_fingerprint or "").strip().lower() or None,
        resume_expires_at=resume_expires_at,
        resume_of_job_id=resume_of_job_id,
        original_job_id=original_job_id,
        related_ingestion_run_id=related_ingestion_run_id,
        staging_storage_id=(staging_storage_id or (payload or {}).get("staging_storage_id") or "").strip()[:128] or None,
        result_summary_json={},
        idempotency_key=normalized_key,
        payload_json=dict(payload or {}),
        max_attempts=safe_max_attempts,
        next_attempt_at=_now(),
        details_json=public_job_details({"queued_via": "operation_queue", **(details or {})}),
    )
    db.add(job)
    db.flush()
    _append_job_audit(
        db,
        actor=requested_by,
        action="operation_job_queued",
        job=job,
        details={"max_attempts": safe_max_attempts},
    )
    db.commit()
    db.refresh(job)
    return job, False


def enforce_import_queue_backpressure(
    db: Session,
    *,
    requested_by: str,
    max_queued_imports: int,
    max_queued_jobs_per_actor: int,
) -> None:
    active_statuses = {"queued", "retry_wait", "running", "cancel_requested"}
    import_types = {"import_logs", "replay_logs"}
    total = int(
        db.scalar(
            select(func.count(OperationJob.id)).where(
                OperationJob.job_type.in_(import_types),
                OperationJob.status.in_(active_statuses),
            )
        )
        or 0
    )
    actor_total = int(
        db.scalar(
            select(func.count(OperationJob.id)).where(
                OperationJob.job_type.in_(import_types),
                OperationJob.status.in_(active_statuses),
                OperationJob.requested_by == requested_by,
            )
        )
        or 0
    )
    if total >= max(1, int(max_queued_imports)):
        raise QueueBackpressureError("The import queue is at capacity. Wait for an active import to finish.")
    if actor_total >= max(1, int(max_queued_jobs_per_actor)):
        raise QueueBackpressureError("Your active import queue limit has been reached.")


def resume_eligibility(job: OperationJob) -> tuple[bool, str | None]:
    if job.job_type not in {"import_logs", "replay_logs"}:
        return False, "Only staged file-import jobs support resume."
    if job.status not in {"failed", "cancelled"}:
        return False, "Only failed or cancelled imports can resume."
    if not resume_window_open(job.resume_expires_at):
        return False, "The staged-input resume window expired."
    details = dict(job.details_json or {})
    if details.get("resume_child_job_id"):
        return False, "A resume job has already been created for this checkpoint."
    try:
        path = staged_path(dict(job.payload_json or {}))
    except StagedInputError as exc:
        return False, str(exc)
    expected_size = job.input_size_bytes
    if expected_size is not None and path.stat().st_size != expected_size:
        return False, "The staged input size changed; resume is blocked."
    if not job.input_fingerprint:
        return False, "The original input has no verified fingerprint."
    return True, None


def resume_import_job(db: Session, job: OperationJob, *, requested_by: str) -> OperationJob:
    eligible, reason = resume_eligibility(job)
    if not eligible:
        raise ValueError(reason or "This import is not eligible to resume.")
    payload = dict(job.payload_json or {})
    _, metadata = validate_staged_payload(payload)
    if metadata.fingerprint != job.input_fingerprint or metadata.byte_count != job.input_size_bytes:
        raise ValueError("The staged input changed; resume is blocked.")

    root_job_id = int(job.original_job_id or job.id)
    active_resume = db.scalar(
        select(OperationJob.id)
        .where(OperationJob.id != job.id)
        .where(or_(OperationJob.original_job_id == root_job_id, OperationJob.id == root_job_id))
        .where(OperationJob.status.in_(ACTIVE_JOB_STATUSES))
        .limit(1)
    )
    if active_resume is not None:
        raise ValueError("Another active import already owns this staged input.")

    resumed_payload = {
        **payload,
        "resume_from_line": job.checkpoint_line,
        "resume_from_bytes": job.checkpoint_bytes,
        "ingestion_run_id": job.related_ingestion_run_id,
    }
    resumed, _ = enqueue_job(
        db,
        job_type=job.job_type,
        requested_by=requested_by,
        payload=resumed_payload,
        details={
            **public_job_details(job.details_json),
            "resume_of_job_id": job.id,
            "original_job_id": root_job_id,
            "input_name": payload.get("input_name"),
        },
        idempotency_key=f"resume-{root_job_id}-{job.id}-{uuid4().hex}",
        max_attempts=1,
        progress_current=job.progress_current,
        progress_total=job.progress_total,
        input_size_bytes=job.input_size_bytes,
        input_fingerprint=job.input_fingerprint,
        resume_expires_at=job.resume_expires_at,
        resume_of_job_id=job.id,
        original_job_id=root_job_id,
        checkpoint_line=job.checkpoint_line,
        checkpoint_bytes=job.checkpoint_bytes,
        chunk_commits=job.chunk_commits,
        related_ingestion_run_id=job.related_ingestion_run_id,
        staging_storage_id=job.staging_storage_id,
    )
    parent_details = dict(job.details_json or {})
    parent_details["resume_child_job_id"] = resumed.id
    job.details_json = public_job_details(parent_details)
    _append_job_audit(
        db,
        actor=requested_by,
        action="operation_job_resumed",
        job=resumed,
        details={"resume_of_job_id": job.id, "original_job_id": root_job_id},
    )
    db.add(job)
    db.commit()
    db.refresh(resumed)
    return resumed


def renew_job_lease(
    db: Session,
    job: OperationJob,
    *,
    worker_id: str,
    lease_token: str,
    lease_seconds: int,
) -> None:
    _assert_owned_lease(job, worker_id=worker_id, lease_token=lease_token)
    job.lease_expires_at = _now() + timedelta(seconds=max(1, int(lease_seconds)))


def complete_cooperative_cancellation(
    db: Session,
    job: OperationJob,
    *,
    worker_id: str,
    lease_token: str,
    details: dict[str, Any] | None = None,
) -> OperationJob:
    _assert_owned_lease(job, worker_id=worker_id, lease_token=lease_token)
    if job.status != "cancel_requested":
        raise ValueError("Operation job has no cooperative cancellation request for this worker.")
    job.status = "cancelled"
    job.finished_at = _now()
    job.next_attempt_at = None
    job.lease_owner = None
    job.lease_token = None
    job.lease_expires_at = None
    _append_job_audit(
        db,
        actor=f"operation-worker:{worker_id}",
        action="operation_job_cancelled_at_chunk_boundary",
        job=job,
        details=details,
    )
    db.add(job)
    return job


def release_job_for_graceful_shutdown(
    db: Session,
    job: OperationJob,
    *,
    worker_id: str,
    lease_token: str,
) -> OperationJob:
    """Release a resumable import only after its latest chunk committed."""

    _assert_owned_lease(job, worker_id=worker_id, lease_token=lease_token, statuses={"running"})
    if job.job_type not in {"import_logs", "replay_logs"}:
        raise ValueError("Only resumable imports can be released during graceful shutdown.")
    job.status = "queued"
    job.next_attempt_at = _now()
    job.lease_owner = None
    job.lease_token = None
    job.lease_expires_at = None
    details = dict(job.details_json or {})
    details["graceful_release_at"] = _now().isoformat()
    details["resume_from_checkpoint"] = True
    job.details_json = public_job_details(details)
    _append_job_audit(
        db,
        actor=f"operation-worker:{worker_id}",
        action="operation_job_released_for_graceful_shutdown",
        job=job,
        details={"checkpoint_line": job.checkpoint_line, "chunk_commits": job.chunk_commits},
    )
    db.add(job)
    return job


def complete_job(
    db: Session,
    job: OperationJob,
    *,
    result_summary: dict[str, Any] | None = None,
    progress_current: int | None = None,
    progress_total: int | None = None,
    related_ingestion_run_id: int | None = None,
    related_detection_run_id: int | None = None,
    related_ml_model_run_id: int | None = None,
) -> OperationJob:
    job.status = "completed"
    job.finished_at = _now()
    job.next_attempt_at = None
    job.lease_owner = None
    job.lease_token = None
    job.lease_expires_at = None
    if progress_total is not None:
        job.progress_total = max(0, int(progress_total))
    job.progress_current = progress_current if progress_current is not None else job.progress_total
    job.result_summary_json = {key: value for key, value in (result_summary or {}).items() if value is not None}
    job.error_summary = None
    if related_ingestion_run_id is not None:
        job.related_ingestion_run_id = related_ingestion_run_id
    if related_detection_run_id is not None:
        job.related_detection_run_id = related_detection_run_id
    if related_ml_model_run_id is not None:
        job.related_ml_model_run_id = related_ml_model_run_id
    db.add(job)
    db.commit()
    db.refresh(job)
    return job


def complete_queued_job(
    db: Session,
    *,
    job_id: int,
    worker_id: str,
    lease_token: str,
    result_summary: dict[str, Any] | None = None,
    related_ingestion_run_id: int | None = None,
    related_detection_run_id: int | None = None,
    related_ml_model_run_id: int | None = None,
) -> OperationJob:
    job = db.get(OperationJob, job_id)
    if job is None:
        raise ValueError("Operation job no longer exists.")
    _assert_owned_lease(job, worker_id=worker_id, lease_token=lease_token, statuses={"running"})
    job.status = "completed"
    job.finished_at = _now()
    job.next_attempt_at = None
    job.lease_owner = None
    job.lease_token = None
    job.lease_expires_at = None
    job.progress_current = job.progress_total or 1
    job.result_summary_json = {key: value for key, value in (result_summary or {}).items() if value is not None}
    job.error_summary = None
    if related_ingestion_run_id is not None:
        job.related_ingestion_run_id = related_ingestion_run_id
    if related_detection_run_id is not None:
        job.related_detection_run_id = related_detection_run_id
    if related_ml_model_run_id is not None:
        job.related_ml_model_run_id = related_ml_model_run_id
    _append_job_audit(
        db,
        actor=f"operation-worker:{worker_id}",
        action="operation_job_completed",
        job=job,
        details={"attempt_count": job.attempt_count},
    )
    db.commit()
    db.refresh(job)
    return job


def fail_job(db: Session, job: OperationJob, error: BaseException | str) -> OperationJob:
    job_id = job.id
    db.rollback()
    failed_job = db.get(OperationJob, job_id)
    if failed_job is None:
        failed_job = job
        db.add(failed_job)
    failed_job.status = "failed"
    failed_job.finished_at = _now()
    failed_job.next_attempt_at = None
    failed_job.lease_owner = None
    failed_job.lease_token = None
    failed_job.lease_expires_at = None
    failed_job.error_summary = _safe_text(f"{error.__class__.__name__}: {error}" if isinstance(error, BaseException) else error)
    db.commit()
    db.refresh(failed_job)
    return failed_job


def fail_queued_job(
    db: Session,
    *,
    job_id: int,
    worker_id: str,
    lease_token: str,
    error: BaseException | str,
    retry_delay_seconds: int,
) -> OperationJob:
    """Finish a claimed job safely; only report exports are automatically retried."""

    job = db.get(OperationJob, job_id)
    if job is None:
        raise ValueError("Operation job no longer exists.")
    _assert_owned_lease(job, worker_id=worker_id, lease_token=lease_token)
    error_text = _safe_text(f"{error.__class__.__name__}: {error}" if isinstance(error, BaseException) else error)
    can_auto_retry = job.job_type in AUTO_RETRY_SAFE_JOB_TYPES and job.attempt_count < job.max_attempts
    job.lease_owner = None
    job.lease_token = None
    job.lease_expires_at = None
    job.error_summary = error_text
    if can_auto_retry:
        job.status = "retry_wait"
        job.next_attempt_at = _now() + timedelta(seconds=max(1, int(retry_delay_seconds)))
        action = "operation_job_retry_scheduled"
    else:
        job.status = "failed"
        job.finished_at = _now()
        job.next_attempt_at = None
        action = "operation_job_failed"
    _append_job_audit(
        db,
        actor=f"operation-worker:{worker_id}",
        action=action,
        job=job,
        details={"attempt_count": job.attempt_count, "error_type": error.__class__.__name__ if isinstance(error, BaseException) else "operation_error"},
    )
    db.commit()
    db.refresh(job)
    return job


def cancel_job(db: Session, job: OperationJob, *, actor: str | None = None) -> OperationJob:
    return request_job_cancellation(db, job, actor=actor)


def request_job_cancellation(db: Session, job: OperationJob, *, actor: str | None = None) -> OperationJob:
    request_actor = actor or job.requested_by
    if job.status in CANCELLABLE_JOB_STATUSES:
        job.status = "cancelled"
        job.finished_at = _now()
        job.next_attempt_at = None
        job.lease_owner = None
        job.lease_token = None
        job.lease_expires_at = None
        job.cancellation_requested_at = job.cancellation_requested_at or _now()
        job.cancellation_requested_by = request_actor
        action = "operation_job_cancelled"
        reason = "cancelled_before_worker_start"
    elif (
        job.status == "running"
        and job.job_type in COOPERATIVE_CANCELLABLE_JOB_TYPES
    ):
        job.status = "cancel_requested"
        job.cancellation_requested_at = _now()
        job.cancellation_requested_by = request_actor
        action = "operation_job_cancellation_requested"
        reason = "worker_will_stop_before_the_next_safe_persist_boundary"
    elif job.status == "cancel_requested":
        return job
    else:
        raise ValueError(
            "Only queued work or a running cooperatively cancellable "
            "operation can accept a cancellation request."
        )
    _append_job_audit(db, actor=request_actor, action=action, job=job, details={"reason": reason})
    db.add(job)
    db.commit()
    db.refresh(job)
    return job


def retry_job(db: Session, job: OperationJob, *, requested_by: str) -> OperationJob:
    if job.status not in RETRYABLE_JOB_STATUSES:
        raise ValueError("Only failed or cancelled jobs can be retried.")
    payload = dict(job.payload_json or {})
    if job.job_type in {"import_logs", "replay_logs"} and (
        payload.get("staged_input_key") or payload.get("staged_input")
    ):
        raise ValueError("This imported file was staged only for the original job and cannot be retried. Upload it again to preserve evidence safety.")
    details = {**public_job_details(job.details_json), "retry_of_job_id": job.id}
    retry, _ = enqueue_job(
        db,
        job_type=job.job_type,
        requested_by=requested_by,
        payload=payload,
        details=details,
        idempotency_key=f"retry-{job.id}-{uuid4().hex}",
        max_attempts=job.max_attempts,
    )
    return retry


def build_claim_statement(
    *,
    now: datetime,
    staging_storage_id: str | None = None,
    allow_legacy_staging: bool = True,
) -> Any:
    statement = (
        select(OperationJob)
        .where(OperationJob.status.in_({"queued", "retry_wait"}))
        .where(or_(OperationJob.next_attempt_at.is_(None), OperationJob.next_attempt_at <= now))
        .order_by(OperationJob.created_at.asc(), OperationJob.id.asc())
        .limit(1)
        .with_for_update(skip_locked=True)
    )
    if staging_storage_id:
        storage_conditions = [
            OperationJob.job_type.not_in({"import_logs", "replay_logs"}),
            OperationJob.staging_storage_id == staging_storage_id,
        ]
        if allow_legacy_staging:
            storage_conditions.append(OperationJob.staging_storage_id.is_(None))
        statement = statement.where(or_(*storage_conditions))
    return statement


def claim_next_job(
    db: Session,
    *,
    worker_id: str,
    lease_seconds: int,
    staging_storage_id: str | None = None,
    allow_legacy_staging: bool = True,
) -> OperationJob | None:
    now = _now()
    statement = build_claim_statement(
        now=now,
        staging_storage_id=staging_storage_id,
        allow_legacy_staging=allow_legacy_staging,
    )
    job = db.scalar(statement)
    if job is None:
        return None
    job.status = "running"
    job.started_at = job.started_at or now
    job.attempt_count += 1
    job.next_attempt_at = None
    job.lease_owner = worker_id
    job.lease_token = uuid4().hex
    job.claim_generation = int(job.claim_generation or 0) + 1
    job.lease_expires_at = now + timedelta(seconds=max(1, int(lease_seconds)))
    details = dict(job.details_json or {})
    details["last_worker"] = worker_id
    details["last_claimed_at"] = now.isoformat()
    job.details_json = public_job_details(details)
    _append_job_audit(
        db,
        actor=f"operation-worker:{worker_id}",
        action="operation_job_claimed",
        job=job,
        details={"attempt_count": job.attempt_count},
    )
    db.commit()
    db.refresh(job)
    return job


def build_lease_recovery_statement(
    *,
    now: datetime,
    limit: int = 25,
) -> Any:
    return (
        select(OperationJob)
        .where(OperationJob.status.in_({"running", "cancel_requested"}))
        .where(OperationJob.lease_expires_at.is_not(None))
        .where(OperationJob.lease_expires_at <= now)
        .order_by(OperationJob.lease_expires_at.asc(), OperationJob.id.asc())
        .limit(max(1, int(limit)))
        .with_for_update(skip_locked=True)
    )


def recover_expired_leases(
    db: Session,
    *,
    retry_delay_seconds: int,
    limit: int = 25,
) -> list[OperationJob]:
    """Recover only safe export work automatically; all evidence-mutating work fails closed."""

    now = _now()
    expired = list(db.scalars(build_lease_recovery_statement(now=now, limit=limit)))
    for job in expired:
        cancellation_pending = job.status == "cancel_requested"
        should_retry = (
            not cancellation_pending
            and job.job_type in AUTO_RETRY_SAFE_JOB_TYPES
            and job.attempt_count < job.max_attempts
        )
        job.lease_owner = None
        job.lease_token = None
        job.lease_expires_at = None
        job.error_summary = "Worker lease expired before completion."
        if cancellation_pending:
            job.status = "cancelled"
            job.finished_at = now
            job.next_attempt_at = None
            action = "operation_job_cancelled_after_lease_expiry"
        elif should_retry:
            job.status = "retry_wait"
            job.next_attempt_at = now + timedelta(seconds=max(1, int(retry_delay_seconds)))
            action = "operation_job_lease_retry_scheduled"
        else:
            job.status = "failed"
            job.finished_at = now
            job.next_attempt_at = None
            action = "operation_job_lease_expired"
        _append_job_audit(
            db,
            actor="operation-worker:lease-recovery",
            action=action,
            job=job,
            details={"attempt_count": job.attempt_count},
        )
        if job.related_ingestion_run_id:
            run = db.get(IngestionRun, job.related_ingestion_run_id)
            if run is not None and run.status == "running":
                complete_ingestion_run(
                    db,
                    run,
                    total_lines_received=run.total_lines_received,
                    raw_logs_created=run.raw_logs_created,
                    parsed_successfully=run.parsed_successfully,
                    parse_failures=run.parse_failures,
                    duplicate_raw_logs=run.duplicate_raw_logs,
                    status="cancelled" if cancellation_pending else "failed",
                    error_summary=None if cancellation_pending else "Worker lease expired before completion.",
                    details={
                        "operation_job_id": job.id,
                        "checkpoint_line": job.checkpoint_line,
                        "checkpoint_bytes": job.checkpoint_bytes,
                    },
                )
        for heartbeat in db.scalars(
            select(OperationWorkerHeartbeat).where(OperationWorkerHeartbeat.current_job_id == job.id)
        ):
            heartbeat.current_job_id = None
            heartbeat.status = "stale"
            heartbeat.details_json = public_job_details({"last_recovered_job_id": job.id})
    if expired:
        db.commit()
        for job in expired:
            db.refresh(job)
    return expired


def record_worker_heartbeat(
    db: Session,
    *,
    worker_id: str,
    status: str,
    current_job_id: int | None = None,
    details: dict[str, Any] | None = None,
    commit: bool = True,
) -> OperationWorkerHeartbeat:
    heartbeat = db.get(OperationWorkerHeartbeat, worker_id)
    now = _now()
    if heartbeat is None:
        heartbeat = OperationWorkerHeartbeat(
            worker_id=worker_id,
            status=status,
            started_at=now,
            last_seen_at=now,
            current_job_id=current_job_id,
            details_json=public_job_details(details),
        )
        db.add(heartbeat)
    else:
        heartbeat.status = status
        heartbeat.last_seen_at = now
        heartbeat.current_job_id = current_job_id
        heartbeat.details_json = public_job_details(details)
    if commit:
        db.commit()
        db.refresh(heartbeat)
    else:
        db.flush()
    return heartbeat


def list_jobs(
    db: Session,
    *,
    limit: int = 20,
    offset: int = 0,
    job_type: str | None = None,
    status: str | None = None,
    requested_by: str | None = None,
) -> list[OperationJob]:
    statement = select(OperationJob).order_by(desc(OperationJob.created_at), desc(OperationJob.id))
    if job_type:
        statement = statement.where(OperationJob.job_type == job_type)
    if status:
        statement = statement.where(OperationJob.status == status)
    if requested_by:
        statement = statement.where(OperationJob.requested_by == requested_by)
    return list(db.scalars(statement.limit(limit).offset(offset)))


def get_job(db: Session, job_id: int) -> OperationJob | None:
    return db.get(OperationJob, job_id)


def list_stale_jobs(
    db: Session,
    *,
    stale_after_minutes: int,
    limit: int = 50,
    requested_by: str | None = None,
) -> list[OperationJob]:
    cutoff = _cutoff(stale_after_minutes)
    stale_time = func.coalesce(OperationJob.updated_at, OperationJob.started_at, OperationJob.created_at)
    statement = (
        select(OperationJob)
        .where(OperationJob.status.in_(STALE_JOB_STATUSES))
        .where(stale_time <= cutoff)
        .order_by(OperationJob.created_at.asc(), OperationJob.id.asc())
        .limit(max(1, int(limit)))
    )
    if requested_by:
        statement = statement.where(OperationJob.requested_by == requested_by)
    return list(db.scalars(statement))


def list_cleanup_candidates(db: Session, *, older_than_days: int, limit: int = 100) -> list[OperationJob]:
    cutoff = _days_cutoff(older_than_days)
    statement = (
        select(OperationJob)
        .where(OperationJob.status.in_(TERMINAL_JOB_STATUSES))
        .where(OperationJob.created_at <= cutoff)
        .order_by(OperationJob.created_at.asc(), OperationJob.id.asc())
        .limit(max(1, int(limit)))
    )
    return list(db.scalars(statement))


def mark_jobs_stale(db: Session, jobs: list[OperationJob], *, actor: str, stale_after_minutes: int) -> list[OperationJob]:
    marked: list[OperationJob] = []
    timestamp = _now()
    for job in jobs:
        if job.status not in STALE_JOB_STATUSES:
            continue
        job.status = "failed"
        job.finished_at = timestamp
        job.next_attempt_at = None
        job.lease_owner = None
        job.lease_token = None
        job.lease_expires_at = None
        job.error_summary = (
            f"Marked stale by {actor}; job was active longer than {max(1, int(stale_after_minutes))} minutes. "
            "No underlying logs, alerts, labels, audit records, or evidence were deleted."
        )
        details = dict(job.details_json or {})
        details["stale_marked_by"] = actor
        details["stale_marked_at"] = timestamp.isoformat()
        details["stale_after_minutes"] = max(1, int(stale_after_minutes))
        job.details_json = public_job_details(details)
        _append_job_audit(db, actor=actor, action="operation_job_marked_stale", job=job)
        db.add(job)
        marked.append(job)
    db.commit()
    for job in marked:
        db.refresh(job)
    return marked


def cleanup_terminal_jobs(db: Session, jobs: list[OperationJob]) -> int:
    deleted = 0
    for job in jobs:
        if job.status not in TERMINAL_JOB_STATUSES:
            continue
        for heartbeat in db.scalars(
            select(OperationWorkerHeartbeat).where(OperationWorkerHeartbeat.current_job_id == job.id)
        ):
            heartbeat.current_job_id = None
            heartbeat.status = "stale"
            heartbeat.details_json = public_job_details({"last_cleaned_job_id": job.id})
        db.delete(job)
        deleted += 1
    db.commit()
    return deleted


def _count_jobs(db: Session, *, status: str, requested_by: str | None = None) -> int:
    statement = select(func.count(OperationJob.id)).where(OperationJob.status == status)
    if requested_by:
        statement = statement.where(OperationJob.requested_by == requested_by)
    return int(db.scalar(statement) or 0)


def _latest_job(db: Session, *, status: str, requested_by: str | None = None) -> OperationJob | None:
    statement = select(OperationJob).where(OperationJob.status == status)
    if requested_by:
        statement = statement.where(OperationJob.requested_by == requested_by)
    return db.scalar(statement.order_by(desc(OperationJob.updated_at), desc(OperationJob.id)).limit(1))


def _recent_failure_count(db: Session, *, minutes: int, requested_by: str | None = None) -> int:
    statement = select(func.count(OperationJob.id)).where(
        OperationJob.status == "failed",
        OperationJob.updated_at >= _cutoff(minutes),
    )
    if requested_by:
        statement = statement.where(OperationJob.requested_by == requested_by)
    return int(db.scalar(statement) or 0)


def _operational_warning(code: str, severity: str, message: str) -> dict[str, str]:
    return {"code": code, "severity": severity, "message": message}


def _worker_summary(db: Session, *, heartbeat_seconds: int) -> dict[str, Any]:
    heartbeat = db.scalar(
        select(OperationWorkerHeartbeat).order_by(desc(OperationWorkerHeartbeat.last_seen_at)).limit(1)
    )
    if heartbeat is None:
        return {"status": "not_seen", "worker_id": None, "last_seen_at": None, "current_job_id": None}
    last_seen = heartbeat.last_seen_at
    if last_seen.tzinfo is None:
        last_seen = last_seen.replace(tzinfo=timezone.utc)
    stale_after = _now() - timedelta(seconds=max(1, int(heartbeat_seconds)) * 3)
    state = "stale" if last_seen < stale_after else heartbeat.status
    return {
        "status": state,
        "worker_id": heartbeat.worker_id,
        "last_seen_at": heartbeat.last_seen_at,
        "current_job_id": heartbeat.current_job_id,
    }


def build_job_summary(
    db: Session,
    *,
    stale_after_minutes: int,
    job_retention_days: int,
    run_history_retention_days: int,
    worker_enabled: bool = False,
    worker_heartbeat_seconds: int = 15,
    queue_backlog_warning: int = 25,
    job_failure_warning_count: int = 3,
    job_failure_warning_window_minutes: int = 60,
    database_check: dict[str, Any] | None = None,
    runtime_issue_count: int = 0,
    response_simulation: bool = True,
    staging_max_total_bytes: int = 1_073_741_824,
    staging_min_free_bytes: int = 268_435_456,
    requested_by: str | None = None,
) -> dict[str, Any]:
    counts = {status: _count_jobs(db, status=status, requested_by=requested_by) for status in sorted(JOB_STATUSES)}
    stale_jobs = list_stale_jobs(
        db,
        stale_after_minutes=stale_after_minutes,
        limit=25,
        requested_by=requested_by,
    )
    latest_failed = _latest_job(db, status="failed", requested_by=requested_by)
    latest_successful = _latest_job(db, status="completed", requested_by=requested_by)
    worker = {"enabled": bool(worker_enabled), **_worker_summary(db, heartbeat_seconds=worker_heartbeat_seconds)}
    staging = staging_pressure_state(
        max_total_bytes=staging_max_total_bytes,
        min_free_bytes=staging_min_free_bytes,
    )
    queue_depth = counts.get("queued", 0) + counts.get("retry_wait", 0)
    recent_failures = _recent_failure_count(
        db,
        minutes=job_failure_warning_window_minutes,
        requested_by=requested_by,
    )
    warnings: list[dict[str, str]] = []
    if stale_jobs:
        warnings.append(
            _operational_warning(
                "stale_jobs",
                "warning",
                f"{len(stale_jobs)} operation job(s) exceeded the configured stale threshold.",
            )
        )
    if worker_enabled and worker["status"] in {"stale", "not_seen"}:
        warnings.append(
            _operational_warning(
                "worker_unavailable",
                "warning",
                "The operation worker is enabled but no fresh heartbeat is available.",
            )
        )
    if queue_depth >= max(1, int(queue_backlog_warning)):
        warnings.append(
            _operational_warning(
                "queue_backlog",
                "warning",
                f"Operation queue backlog reached {queue_depth} jobs.",
            )
        )
    if staging["state"] == "pressure":
        warnings.append(
            _operational_warning(
                "staging_pressure",
                "critical",
                "Import staging reached a configured storage safety boundary; new queued imports are paused.",
            )
        )
    if recent_failures >= max(1, int(job_failure_warning_count)):
        warnings.append(
            _operational_warning(
                "repeated_job_failures",
                "warning",
                f"{recent_failures} operation jobs failed in the recent monitoring window.",
            )
        )
    if database_check is not None:
        if database_check.get("status") != "ok":
            warnings.append(_operational_warning("database_unavailable", "critical", "Database readiness check failed."))
        elif (database_check.get("migration") or {}).get("status") != "at_head":
            warnings.append(
                _operational_warning("migration_drift", "warning", "Database migration revision is not at Alembic head.")
            )
    if runtime_issue_count:
        warnings.append(
            _operational_warning(
                "configuration_invalid",
                "critical",
                f"Runtime configuration has {runtime_issue_count} safety issue(s).",
            )
        )
    if not response_simulation:
        warnings.append(
            _operational_warning(
                "response_automation_unexpected",
                "critical",
                "Response simulation is unexpectedly disabled; automatic enforcement remains unsupported.",
            )
        )
    health_status = "critical" if any(item["severity"] == "critical" for item in warnings) else "warning" if warnings else "healthy"
    return {
        "counts": counts,
        "active_count": sum(counts.get(status, 0) for status in ACTIVE_JOB_STATUSES),
        "failed_count": counts.get("failed", 0),
        "stale_count": len(stale_jobs),
        "stale_job_ids": [job.id for job in stale_jobs],
        "latest_failed_job": job_to_dict(latest_failed) if latest_failed is not None else None,
        "latest_successful_job": job_to_dict(latest_successful) if latest_successful is not None else None,
        "queue": {
            "queued": counts.get("queued", 0),
            "retry_wait": counts.get("retry_wait", 0),
            "running": counts.get("running", 0),
            "cancel_requested": counts.get("cancel_requested", 0),
            "failed": counts.get("failed", 0),
            "backlog_warning_threshold": max(1, int(queue_backlog_warning)),
        },
        "worker": worker,
        "staging": staging,
        "health_status": health_status,
        "warnings": warnings,
        "warning_count": len(warnings),
        "recent_failure_count": recent_failures,
        "retention_policy": {
            "job_stale_after_minutes": max(1, int(stale_after_minutes)),
            "job_retention_days": max(1, int(job_retention_days)),
            "run_history_retention_days": max(1, int(run_history_retention_days)),
            "automatic_cleanup_enabled": False,
            "raw_evidence_cleanup_enabled": False,
        },
    }


def job_to_dict(job: OperationJob) -> dict[str, Any]:
    resumable, resume_reason = resume_eligibility(job)
    progress_total = max(0, int(job.progress_total or 0))
    progress_current = max(0, int(job.progress_current or 0))
    percentage = round(min(100.0, (progress_current / progress_total) * 100.0), 1) if progress_total else 0.0
    can_retry = job.status in RETRYABLE_JOB_STATUSES and job.job_type not in {"import_logs", "replay_logs"}
    can_request_cancel = job.status in CANCELLABLE_JOB_STATUSES or (
        job.status == "running"
        and job.job_type in COOPERATIVE_CANCELLABLE_JOB_TYPES
    )
    progress_status = {
        "queued": "waiting_for_worker",
        "retry_wait": "waiting_to_retry",
        "running": "processing_committed_chunks",
        "cancel_requested": "stopping_at_next_chunk_boundary",
        "completed": "completed",
        "failed": "interrupted",
        "cancelled": "cancelled_at_safe_boundary",
    }.get(job.status, job.status)
    details = public_job_details(job.details_json)
    return {
        "job_id": job.id,
        "job_type": job.job_type,
        "status": job.status,
        "requested_by": job.requested_by,
        "started_at": job.started_at,
        "finished_at": job.finished_at,
        "progress_current": progress_current,
        "progress_total": progress_total,
        "progress_percentage": percentage,
        "progress_status": progress_status,
        "checkpoint_line": job.checkpoint_line or 0,
        "checkpoint_bytes": job.checkpoint_bytes or 0,
        "checkpoint_at": job.checkpoint_at,
        "chunk_commits": job.chunk_commits or 0,
        "input_size_bytes": job.input_size_bytes,
        "cancellation_requested": job.status == "cancel_requested" or job.cancellation_requested_at is not None,
        "cancellation_requested_at": job.cancellation_requested_at,
        "resume_eligible": resumable,
        "resume_ineligible_reason": resume_reason,
        "resume_of_job_id": job.resume_of_job_id,
        "original_job_id": job.original_job_id or (job.id if job.job_type in {"import_logs", "replay_logs"} else None),
        "resume_expires_at": job.resume_expires_at,
        "latest_heartbeat_at": details.get("latest_heartbeat_at"),
        "result_summary": job.result_summary_json or {},
        "error_summary": job.error_summary,
        "related_ingestion_run_id": job.related_ingestion_run_id,
        "related_detection_run_id": job.related_detection_run_id,
        "related_ml_model_run_id": job.related_ml_model_run_id,
        "attempt_count": job.attempt_count or 0,
        "max_attempts": job.max_attempts or 1,
        "next_attempt_at": job.next_attempt_at,
        "lease_expires_at": job.lease_expires_at,
        "can_cancel": can_request_cancel,
        "can_request_cancel": can_request_cancel,
        "can_retry": can_retry,
        "can_resume": resumable,
        "details": details,
        "created_at": job.created_at,
        "updated_at": job.updated_at,
    }
