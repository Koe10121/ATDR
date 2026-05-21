from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from atdr.app.core.security import require_admin, require_analyst_or_admin
from atdr.app.db.database import get_db
from atdr.app.db.models import User
from atdr.app.schemas.ml import MLDatasetProfileRead, MLEvaluationReportRead, MLModelRunRead, MLRunRequest, MLStatusRead
from atdr.app.services.ml_service import (
    apply_anomaly_scoring,
    dataset_profile,
    evaluation_report,
    list_model_runs,
    model_status,
    run_to_dict,
    train_anomaly_model,
)

router = APIRouter(prefix="/api/ml", tags=["ml"])


@router.get("/status", response_model=MLStatusRead)
def get_ml_status(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
) -> dict:
    return model_status(db)


@router.get("/runs", response_model=list[MLModelRunRead])
def get_ml_runs(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
    limit: int = Query(default=20, ge=1, le=100),
) -> list[dict]:
    return [run_to_dict(run) for run in list_model_runs(db, limit=limit)]


@router.get("/profile", response_model=MLDatasetProfileRead)
def get_ml_dataset_profile(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
    baseline_max_app_risk: int = Query(default=3, ge=1, le=5),
) -> dict:
    return dataset_profile(db, baseline_max_app_risk=baseline_max_app_risk)


@router.get("/report", response_model=MLEvaluationReportRead)
def get_ml_evaluation_report(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
) -> dict:
    return evaluation_report(db)


@router.post("/train")
def train_ml_model(
    request: MLRunRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
) -> dict:
    return train_anomaly_model(
        db,
        limit=request.limit,
        actor=current_user.username,
        baseline_only=request.baseline_only,
        max_app_risk=request.max_app_risk,
        exclude_unknown_apps=request.exclude_unknown_apps,
        exclude_existing_anomalies=request.exclude_existing_anomalies,
    )


@router.post("/score")
def score_logs_with_ml(
    request: MLRunRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
) -> dict:
    return apply_anomaly_scoring(db, limit=request.limit, actor=current_user.username)
