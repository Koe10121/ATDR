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
    try:
        return import_demo_sample_logs(db, sample_path=request.sample_path, limit=request.limit, actor=current_user.username)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=f"Sample log file not found: {exc.filename or request.sample_path}") from exc


@router.post("/run-detection")
def run_demo_detection_endpoint(
    request: DemoDetectionRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
) -> dict:
    return run_demo_detection(db, limit=request.limit, use_ml=request.use_ml, actor=current_user.username)


@router.post("/train-ml")
def train_ml(
    request: DemoLimitRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
) -> dict:
    return train_demo_ml_model(db, limit=request.limit, actor=current_user.username)


@router.post("/apply-ml")
def apply_ml(
    request: DemoLimitRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
) -> dict:
    return apply_demo_ml_scoring(db, limit=request.limit, actor=current_user.username)


@router.post("/export-bundle")
def export_bundle(
    request: DemoExportRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
) -> dict:
    return export_demo_bundle(
        db,
        actor=current_user.username,
        alert_id=request.alert_id,
        output_dir=request.output_dir,
        top_alert_limit=request.top_alert_limit,
        audit_limit=request.audit_limit,
    )
