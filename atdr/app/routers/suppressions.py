from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from atdr.app.core.security import require_admin, require_analyst_or_admin
from atdr.app.db.database import get_db
from atdr.app.db.models import User
from atdr.app.schemas.suppressions import SuppressionCreateRequest, SuppressionRead, SuppressionReviewRequest
from atdr.app.services.suppression_service import (
    create_suppression,
    disable_suppression,
    list_suppressions,
    review_suppression,
)

router = APIRouter(prefix="/api/suppressions", tags=["suppressions"])


@router.get("", response_model=list[SuppressionRead])
def api_list_suppressions(
    db: Session = Depends(get_db),
    active_only: bool = False,
    current_user: User = Depends(require_analyst_or_admin),
):
    return list_suppressions(db, active_only=active_only)


@router.post("", response_model=SuppressionRead)
def api_create_suppression(
    request: SuppressionCreateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    return create_suppression(
        db,
        src_ip=request.src_ip,
        app=request.app,
        alert_type=request.alert_type,
        reason=request.reason,
        actor=current_user.username,
    )


@router.post("/{rule_id}/disable", response_model=SuppressionRead)
def api_disable_suppression(
    rule_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    rule = disable_suppression(db, rule_id, actor=current_user.username)
    if rule is None:
        raise HTTPException(status_code=404, detail="Suppression rule not found.")
    return rule


@router.post("/{rule_id}/review", response_model=SuppressionRead)
def api_review_suppression(
    rule_id: int,
    request: SuppressionReviewRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    try:
        rule = review_suppression(
            db,
            rule_id,
            review_status=request.normalized_status(),
            review_notes=request.review_notes,
            actor=current_user.username,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if rule is None:
        raise HTTPException(status_code=404, detail="Suppression rule not found.")
    return rule
