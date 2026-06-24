from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from atdr.app.core.security import require_analyst_or_admin
from atdr.app.db.database import get_db
from atdr.app.db.models import Alert, NormalizedLog, User
from atdr.app.schemas.operations import DetectionRunRead
from atdr.app.services.detection_service import run_detection
from atdr.app.services.job_service import build_result_summary, complete_job, fail_job, start_job
from atdr.app.services.operation_run_service import detection_run_to_dict, get_detection_run, list_detection_runs
from atdr.app.services.tuning_service import build_detection_tuning_report

router = APIRouter(prefix="/api/detection", tags=["detection"])


@router.post("/run")
def api_run_detection(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
    limit: int | None = Query(default=5000, ge=1, le=100000),
    use_ml: bool = True,
    source_id: int | None = Query(default=None, ge=1),
) -> dict:
    job = start_job(
        db,
        job_type="run_detection",
        requested_by=current_user.username,
        details={"limit": limit, "use_ml": use_ml, "source_id": source_id},
    )
    try:
        result = run_detection(db, limit=limit, use_ml=use_ml, actor=current_user.username, source_id=source_id)
        complete_job(
            db,
            job,
            result_summary=build_result_summary("run_detection", result),
            related_detection_run_id=result.get("detection_run_id"),
        )
        result["job_id"] = job.id
        return result
    except Exception as exc:
        fail_job(db, job, exc)
        raise


@router.get("/runs", response_model=list[DetectionRunRead])
def api_list_detection_runs(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
    limit: int = Query(default=20, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> list[dict]:
    return [detection_run_to_dict(run) for run in list_detection_runs(db, limit=limit, offset=offset)]


@router.get("/runs/{run_id}", response_model=DetectionRunRead)
def api_get_detection_run(
    run_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
) -> dict:
    run = get_detection_run(db, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Detection run not found.")
    return detection_run_to_dict(run)


@router.get("/summary")
def detection_summary(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
) -> dict:
    total_logs = int(db.scalar(select(func.count(NormalizedLog.id))) or 0)
    total_alerts = int(db.scalar(select(func.count(Alert.id))) or 0)
    open_alerts = int(db.scalar(select(func.count(Alert.id)).where(Alert.status == "open")) or 0)
    anomaly_count = int(db.scalar(select(func.count(NormalizedLog.id)).where(NormalizedLog.is_anomaly.is_(True))) or 0)
    return {
        "total_logs": total_logs,
        "total_alerts": total_alerts,
        "open_alerts": open_alerts,
        "ml_anomaly_logs": anomaly_count,
    }


@router.get("/tuning")
def detection_tuning_report(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
) -> dict:
    return build_detection_tuning_report(db)
