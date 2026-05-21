from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from atdr.app.core.security import require_admin, require_analyst_or_admin
from atdr.app.db.database import get_db
from atdr.app.db.models import User
from atdr.app.schemas.response import BlockedIPRead, BlockIPRequest, ResponseActionRead, UnblockIPRequest
from atdr.app.services.response_service import block_ip, list_blocked_ips, unblock_ip

router = APIRouter(prefix="/api/response", tags=["response"])


@router.post("/block-ip", response_model=ResponseActionRead)
def api_block_ip(
    request: BlockIPRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    return block_ip(
        db,
        target_ip=request.target_ip,
        reason=request.reason,
        alert_id=request.alert_id,
        actor=current_user.username,
    )


@router.post("/unblock-ip", response_model=ResponseActionRead)
def api_unblock_ip(
    request: UnblockIPRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    return unblock_ip(db, target_ip=request.target_ip, reason=request.reason, actor=current_user.username)


@router.get("/blocked-ips", response_model=list[BlockedIPRead])
def api_blocked_ips(
    db: Session = Depends(get_db),
    active_only: bool = True,
    current_user: User = Depends(require_analyst_or_admin),
):
    return list_blocked_ips(db, active_only=active_only)
