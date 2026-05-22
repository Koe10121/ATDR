from fastapi import APIRouter, Depends, Response
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from atdr.app.core.security import require_analyst_or_admin
from atdr.app.db.database import get_db
from atdr.app.db.models import AuditLog, User
from atdr.app.parsers.paloalto_parser import parse_datetime
from atdr.app.schemas.response import AuditLogRead

router = APIRouter(prefix="/api/audit", tags=["audit"])


@router.get("", response_model=list[AuditLogRead])
def list_audit_logs(
    response: Response,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
    actor: str | None = None,
    action: str | None = None,
    target_type: str | None = None,
    target_value: str | None = None,
    created_from: str | None = None,
    created_to: str | None = None,
    limit: int = 200,
    offset: int = 0,
):
    statement = select(AuditLog).order_by(AuditLog.created_at.desc(), AuditLog.id.desc())
    if actor:
        statement = statement.where(AuditLog.actor.ilike(f"%{actor}%"))
    if action:
        statement = statement.where(AuditLog.action.ilike(f"%{action}%"))
    if target_type:
        statement = statement.where(AuditLog.target_type.ilike(f"%{target_type}%"))
    if target_value:
        statement = statement.where(AuditLog.target_value.ilike(f"%{target_value}%"))
    start = parse_datetime(created_from)
    end = parse_datetime(created_to)
    if start is not None:
        statement = statement.where(AuditLog.created_at >= start)
    if end is not None:
        statement = statement.where(AuditLog.created_at <= end)
    total = int(db.scalar(select(func.count()).select_from(statement.order_by(None).subquery())) or 0)
    response.headers["X-Total-Count"] = str(total)
    statement = statement.limit(limit).offset(offset)
    return list(db.scalars(statement))
