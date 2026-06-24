from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from atdr.app.core.config import Settings, get_settings
from atdr.app.core.security import require_analyst_or_admin
from atdr.app.db.database import get_db
from atdr.app.db.models import User
from atdr.app.schemas.operations import OperationJobRead, OperationJobSummaryRead
from atdr.app.services.job_service import build_job_summary, cancel_job, get_job, job_to_dict, list_jobs


router = APIRouter(prefix="/api/jobs", tags=["jobs"])


@router.get("", response_model=list[OperationJobRead])
def api_list_jobs(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
    limit: int = Query(default=20, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    job_type: str | None = Query(default=None),
    status: str | None = Query(default=None),
) -> list[dict]:
    return [job_to_dict(job) for job in list_jobs(db, limit=limit, offset=offset, job_type=job_type, status=status)]


@router.get("/summary", response_model=OperationJobSummaryRead)
def api_jobs_summary(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
    settings: Settings = Depends(get_settings),
) -> dict:
    return build_job_summary(
        db,
        stale_after_minutes=settings.job_stale_after_minutes,
        job_retention_days=settings.job_retention_days,
        run_history_retention_days=settings.run_history_retention_days,
    )


@router.get("/{job_id}", response_model=OperationJobRead)
def api_get_job(
    job_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
) -> dict:
    job = get_job(db, job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Operation job not found.")
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
    try:
        return job_to_dict(cancel_job(db, job))
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
