from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from atdr.app.core.security import require_analyst_or_admin
from atdr.app.db.database import get_db
from atdr.app.db.models import Alert, NormalizedLog, User
from atdr.app.services.detection_service import run_detection

router = APIRouter(prefix="/api/detection", tags=["detection"])


@router.post("/run")
def api_run_detection(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
    limit: int | None = Query(default=5000, ge=1, le=100000),
    use_ml: bool = True,
) -> dict:
    return run_detection(db, limit=limit, use_ml=use_ml, actor=current_user.username)


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
