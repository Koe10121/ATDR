from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from atdr.app.core.security import require_analyst_or_admin
from atdr.app.db.database import get_db
from atdr.app.db.models import User
from atdr.app.services.dashboard_service import build_dashboard_summary

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


@router.get("/summary")
def dashboard_summary(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
) -> dict:
    return build_dashboard_summary(db)
