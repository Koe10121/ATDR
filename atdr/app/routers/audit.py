from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from atdr.app.core.security import require_analyst_or_admin
from atdr.app.db.database import get_db
from atdr.app.db.models import AuditLog, User
from atdr.app.schemas.response import AuditLogRead

router = APIRouter(prefix="/api/audit", tags=["audit"])


@router.get("", response_model=list[AuditLogRead])
def list_audit_logs(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
    limit: int = 200,
    offset: int = 0,
):
    statement = select(AuditLog).order_by(AuditLog.created_at.desc(), AuditLog.id.desc()).limit(limit).offset(offset)
    return list(db.scalars(statement))
