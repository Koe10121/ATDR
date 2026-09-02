from fastapi import APIRouter, Depends
from fastapi.responses import Response
from sqlalchemy.orm import Session

from atdr.app.core.config import Settings, get_settings
from atdr.app.core.security import require_admin
from atdr.app.db.database import get_db
from atdr.app.db.models import User
from atdr.app.services.metrics_service import render_prometheus_metrics
from atdr.app.services.observability_service import build_operations_health
from atdr.app.schemas.operations import ReleaseReadinessRead
from atdr.app.services.v553_release_readiness_service import build_v553_release_readiness_report


router = APIRouter(tags=["operations"])


@router.get("/metrics", include_in_schema=False)
def metrics(
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> Response:
    content = render_prometheus_metrics(db, heartbeat_seconds=settings.operation_worker_heartbeat_seconds)
    return Response(content=content, media_type="text/plain; version=0.0.4")


@router.get("/api/operations/health")
def operations_health(
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    current_user: User = Depends(require_admin),
) -> dict:
    return build_operations_health(db, settings)


@router.get("/api/operations/release-readiness", response_model=ReleaseReadinessRead)
def release_readiness(
    settings: Settings = Depends(get_settings),
    current_user: User = Depends(require_admin),
) -> dict:
    return build_v553_release_readiness_report(settings)
