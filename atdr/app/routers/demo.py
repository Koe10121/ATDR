from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from atdr.app.core.security import require_admin
from atdr.app.db.database import get_db
from atdr.app.db.models import User
from atdr.app.schemas.demo import DemoDetectionRequest, DemoExportRequest, DemoLimitRequest, DemoResetRequest
from atdr.app.services.demo_service import (
    apply_demo_ml_scoring,
    export_demo_bundle,
    import_demo_sample_logs,
    reset_and_seed_demo,
    run_demo_detection,
    train_demo_ml_model,
)
from atdr.app.services.job_service import build_result_summary, complete_job, fail_job, start_job

router = APIRouter(prefix="/api/demo", tags=["demo"])


@router.post("/reset")
def reset_demo(
    request: DemoResetRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
) -> dict:
    try:
        return reset_and_seed_demo(
            db,
            sample_path=request.sample_path,
            limit=request.limit,
            use_ml=request.use_ml,
            actor=current_user.username,
        )
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=f"Sample log file not found: {exc.filename or request.sample_path}") from exc


@router.post("/import-sample")
def import_sample(
    request: DemoLimitRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
) -> dict:
    job = start_job(
        db,
        job_type="import_logs",
        requested_by=current_user.username,
        details={"limit": request.limit, "sample_path_configured": bool(request.sample_path)},
    )
    try:
        result = import_demo_sample_logs(db, sample_path=request.sample_path, limit=request.limit, actor=current_user.username)
        complete_job(
            db,
            job,
            result_summary=build_result_summary("import_logs", result),
            related_ingestion_run_id=result.get("run_id"),
        )
        result["job_id"] = job.id
        return result
    except FileNotFoundError as exc:
        fail_job(db, job, exc)
        raise HTTPException(status_code=404, detail=f"Sample log file not found: {exc.filename or request.sample_path}") from exc
    except Exception as exc:
        fail_job(db, job, exc)
        raise


@router.post("/run-detection")
def run_demo_detection_endpoint(
    request: DemoDetectionRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
) -> dict:
    job = start_job(
        db,
        job_type="run_detection",
        requested_by=current_user.username,
        details={"limit": request.limit, "use_ml": request.use_ml, "demo": True},
    )
    try:
        result = run_demo_detection(db, limit=request.limit, use_ml=request.use_ml, actor=current_user.username)
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


@router.post("/train-ml")
def train_ml(
    request: DemoLimitRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
) -> dict:
    job = start_job(
        db,
        job_type="train_ml",
        requested_by=current_user.username,
        details={"limit": request.limit, "demo": True},
    )
    try:
        result = train_demo_ml_model(db, limit=request.limit, actor=current_user.username)
        complete_job(
            db,
            job,
            result_summary=build_result_summary("train_ml", result),
            related_ml_model_run_id=result.get("run_id"),
        )
        result["job_id"] = job.id
        return result
    except Exception as exc:
        fail_job(db, job, exc)
        raise


@router.post("/apply-ml")
def apply_ml(
    request: DemoLimitRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
) -> dict:
    job = start_job(
        db,
        job_type="apply_ml_scoring",
        requested_by=current_user.username,
        details={"limit": request.limit, "demo": True},
    )
    try:
        result = apply_demo_ml_scoring(db, limit=request.limit, actor=current_user.username)
        complete_job(
            db,
            job,
            result_summary=build_result_summary("apply_ml_scoring", result),
            related_ml_model_run_id=result.get("run_id"),
        )
        result["job_id"] = job.id
        return result
    except Exception as exc:
        fail_job(db, job, exc)
        raise


@router.post("/export-bundle")
def export_bundle(
    request: DemoExportRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
) -> dict:
    job = start_job(
        db,
        job_type="export_report",
        requested_by=current_user.username,
        details={
            "alert_id": request.alert_id,
            "top_alert_limit": request.top_alert_limit,
            "audit_limit": request.audit_limit,
        },
    )
    try:
        result = export_demo_bundle(
            db,
            actor=current_user.username,
            alert_id=request.alert_id,
            output_dir=request.output_dir,
            top_alert_limit=request.top_alert_limit,
            audit_limit=request.audit_limit,
        )
        complete_job(db, job, result_summary=build_result_summary("export_report", result))
        result["job_id"] = job.id
        return result
    except Exception as exc:
        fail_job(db, job, exc)
        raise
