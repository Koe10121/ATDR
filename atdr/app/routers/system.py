from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from atdr.app.core.security import require_admin
from atdr.app.db.database import get_db
from atdr.app.db.models import User
from atdr.app.services.system_status_service import system_status

router = APIRouter(prefix="/api/system", tags=["system"])


@router.get("/status")
def get_system_status(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
) -> dict:
    """How ATDR looks after itself on this machine: its parts, its backups and the dashboard's build."""

    return system_status(db)
