from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile
from sqlalchemy.orm import Session

from atdr.app.core.config import Settings, get_settings, validate_runtime_settings
from atdr.app.core.security import require_admin, require_analyst_or_admin
from atdr.app.db.database import check_database_connection, get_db
from atdr.app.db.models import User
from atdr.app.schemas.operations import OperationJobRead, OperationJobSubmit, OperationJobSummaryRead
from atdr.app.services.job_dispatcher import (
    ADMIN_QUEUEABLE_JOB_TYPES,
    ANALYST_QUEUEABLE_JOB_TYPES,
    cleanup_staged_payload,
    stage_upload_for_job,
    staged_payload_fields,
    validate_file_import_request,
    validate_job_submission,
)
from atdr.app.services.job_service import (
    QueueBackpressureError,
    build_job_summary,
    cancel_job,
    enqueue_job,
    enforce_import_queue_backpressure,
    get_job,
    job_to_dict,
    list_jobs,
    request_job_cancellation,
    resume_import_job,
    retry_job,
)
from atdr.app.services.staging_service import StagingPressureError


router = APIRouter(prefix="/api/jobs", tags=["jobs"])


def _job_scope(current_user: User, *, mine: bool) -> str | None:
    return current_user.username if current_user.role != "admin" or mine else None


def _require_job_access(job, current_user: User) -> None:
    if current_user.role != "admin" and job.requested_by != current_user.username:
        raise HTTPException(status_code=403, detail="You can access only your own operation jobs.")


def _require_queue_permission(job_type: str, current_user: User) -> None:
    if job_type in ANALYST_QUEUEABLE_JOB_TYPES:
        return
    if job_type in ADMIN_QUEUEABLE_JOB_TYPES and current_user.role == "admin":
        return
    if job_type in ADMIN_QUEUEABLE_JOB_TYPES:
        raise HTTPException(status_code=403, detail="Admin role required for this queued operation.")
    raise HTTPException(status_code=400, detail="This operation cannot be queued.")


@router.get("", response_model=list[OperationJobRead])
def api_list_jobs(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
    limit: int = Query(default=20, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    job_type: str | None = Query(default=None),
    status: str | None = Query(default=None),
    mine: bool = Query(default=False),
) -> list[dict]:
    return [
        job_to_dict(job)
        for job in list_jobs(
            db,
            limit=limit,
            offset=offset,
            job_type=job_type,
            status=status,
            requested_by=_job_scope(current_user, mine=mine),
        )
    ]


@router.get("/summary", response_model=OperationJobSummaryRead)
def api_jobs_summary(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
    settings: Settings = Depends(get_settings),
    mine: bool = Query(default=False),
) -> dict:
    return build_job_summary(
        db,
        stale_after_minutes=settings.job_stale_after_minutes,
        job_retention_days=settings.job_retention_days,
        run_history_retention_days=settings.run_history_retention_days,
        worker_enabled=settings.operation_worker_enabled,
        worker_heartbeat_seconds=settings.operation_worker_heartbeat_seconds,
        queue_backlog_warning=settings.operation_queue_backlog_warning,
        job_failure_warning_count=settings.operation_job_failure_warning_count,
        job_failure_warning_window_minutes=settings.operation_job_failure_warning_window_minutes,
        database_check=check_database_connection(db),
        runtime_issue_count=len(validate_runtime_settings(settings)),
        response_simulation=settings.response_simulation,
        staging_max_total_bytes=settings.operation_staging_max_total_bytes,
        staging_min_free_bytes=settings.operation_staging_min_free_bytes,
        requested_by=_job_scope(current_user, mine=mine),
    )


@router.post("/submit", response_model=OperationJobRead)
def api_submit_job(
    request: OperationJobSubmit,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
    settings: Settings = Depends(get_settings),
) -> dict:
    _require_queue_permission(request.job_type, current_user)
    try:
        payload = validate_job_submission(request.job_type, request.payload)
        job, reused = enqueue_job(
            db,
            job_type=request.job_type,
            requested_by=current_user.username,
            payload=payload,
            details={"operation": payload.get("operation"), "source_id": payload.get("source_id")},
            idempotency_key=request.idempotency_key,
            max_attempts=request.max_attempts or settings.operation_job_default_max_attempts,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    response = job_to_dict(job)
    response["details"] = {**response["details"], "idempotency_reused": reused}
    return response


@router.post("/import", response_model=OperationJobRead)
def api_enqueue_import(
    upload: UploadFile = File(...),
    job_type: str = Form(default="import_logs"),
    source_type: str | None = Form(default=None),
    parser_profile: str | None = Form(default=None),
    limit: int | None = Form(default=None),
    source_id: int | None = Form(default=None),
    idempotency_key: str | None = Form(default=None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
    settings: Settings = Depends(get_settings),
) -> dict:
    staged_payload: dict[str, object] | None = None
    try:
        enforce_import_queue_backpressure(
            db,
            requested_by=current_user.username,
            max_queued_imports=settings.operation_max_queued_imports,
            max_queued_jobs_per_actor=settings.operation_max_queued_jobs_per_actor,
        )
        request = validate_file_import_request(
            job_type=job_type,
            source_type=source_type,
            parser_profile=parser_profile,
            limit=limit,
            source_id=source_id,
        )
        staged = stage_upload_for_job(
            upload.file,
            filename=upload.filename,
            max_bytes=settings.operation_job_max_input_bytes,
            staging_max_total_bytes=settings.operation_staging_max_total_bytes,
            staging_min_free_bytes=settings.operation_staging_min_free_bytes,
        )
        staged_payload = {
            **request,
            **staged_payload_fields(staged),
            "input_name": staged.safe_name,
            "input_bytes": staged.byte_count,
            "input_fingerprint": staged.fingerprint,
            "available_lines": staged.available_lines,
        }
        total = min(staged.available_lines, int(request["limit"])) if request.get("limit") else staged.available_lines
        resume_expires_at = datetime.now(timezone.utc) + timedelta(hours=settings.operation_staging_retention_hours)
        job, reused = enqueue_job(
            db,
            job_type=job_type,
            requested_by=current_user.username,
            payload=staged_payload,
            details={
                "input_name": staged.safe_name,
                "input_bytes": staged.byte_count,
                "available_lines": staged.available_lines,
                "limit": request.get("limit"),
                "source_id": request.get("source_id"),
                "source_type": request.get("source_type"),
                "parser_profile": request.get("parser_profile"),
            },
            idempotency_key=idempotency_key,
            max_attempts=settings.operation_job_default_max_attempts,
            progress_total=total,
            input_size_bytes=staged.byte_count,
            input_fingerprint=staged.fingerprint,
            resume_expires_at=resume_expires_at,
            staging_storage_id=staged.storage_id,
        )
        if reused:
            cleanup_staged_payload(staged_payload)
        response = job_to_dict(job)
        response["details"] = {**response["details"], "idempotency_reused": reused}
        return response
    except QueueBackpressureError as exc:
        cleanup_staged_payload(staged_payload)
        raise HTTPException(status_code=429, detail=str(exc)) from exc
    except StagingPressureError as exc:
        cleanup_staged_payload(staged_payload)
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except ValueError as exc:
        cleanup_staged_payload(staged_payload)
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception:
        cleanup_staged_payload(staged_payload)
        raise


@router.get("/{job_id}", response_model=OperationJobRead)
def api_get_job(
    job_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
) -> dict:
    job = get_job(db, job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Operation job not found.")
    _require_job_access(job, current_user)
    return job_to_dict(job)


@router.post("/{job_id}/cancel", response_model=OperationJobRead)
def api_cancel_job(
    job_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
) -> dict:
    job = get_job(db, job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Operation job not found.")
    _require_job_access(job, current_user)
    try:
        return job_to_dict(cancel_job(db, job, actor=current_user.username))
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/{job_id}/request-cancel", response_model=OperationJobRead)
def api_request_job_cancellation(
    job_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
) -> dict:
    job = get_job(db, job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Operation job not found.")
    _require_job_access(job, current_user)
    try:
        return job_to_dict(request_job_cancellation(db, job, actor=current_user.username))
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/{job_id}/resume", response_model=OperationJobRead)
def api_resume_import_job(
    job_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
    settings: Settings = Depends(get_settings),
) -> dict:
    job = get_job(db, job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Operation job not found.")
    try:
        enforce_import_queue_backpressure(
            db,
            requested_by=current_user.username,
            max_queued_imports=settings.operation_max_queued_imports,
            max_queued_jobs_per_actor=settings.operation_max_queued_jobs_per_actor,
        )
        return job_to_dict(resume_import_job(db, job, requested_by=current_user.username))
    except QueueBackpressureError as exc:
        raise HTTPException(status_code=429, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/{job_id}/retry", response_model=OperationJobRead)
def api_retry_job(
    job_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
) -> dict:
    job = get_job(db, job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Operation job not found.")
    _require_job_access(job, current_user)
    _require_queue_permission(job.job_type, current_user)
    try:
        return job_to_dict(retry_job(db, job, requested_by=current_user.username))
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
