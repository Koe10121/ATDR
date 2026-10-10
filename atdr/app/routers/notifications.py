from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from atdr.app.core.security import get_current_user, require_admin
from atdr.app.db.database import get_db
from atdr.app.db.models import AuditLog, Notification, User
from atdr.app.services.notification_service import TEST, mark_seen, notifications_for, send_test

router = APIRouter(prefix="/api/notifications", tags=["notifications"])

# A second test straight after the first is a double click, not a second question.
TEST_AGAIN_AFTER = timedelta(seconds=10)


class SeenRequest(BaseModel):
    up_to: int = Field(ge=0)


class TestRequest(BaseModel):
    channel: str = Field(min_length=1, max_length=16)


@router.get("")
def get_notifications(
    limit: int = Query(default=30, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict:
    """What the bell shows: the newest notifications this user may see, and how many are unread."""

    return notifications_for(db, current_user, limit=limit)


@router.post("/seen")
def post_notifications_seen(
    body: SeenRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict:
    """The user has looked at the bell: everything up to this notification counts as read for them."""

    return {"seen_id": mark_seen(db, current_user, body.up_to)}


@router.post("/test")
def post_notification_test(
    body: TestRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
) -> dict:
    """Sends one test message through one channel now and says in words whether it went."""

    now = datetime.now(timezone.utc)
    last = db.scalar(select(func.max(Notification.created_at)).where(Notification.kind == TEST))
    if last is not None and now - (last if last.tzinfo else last.replace(tzinfo=timezone.utc)) < TEST_AGAIN_AFTER:
        return {"ok": False, "channel": body.channel, "words": "A test message went a moment ago. Wait ten seconds before the next one."}
    result = send_test(db, body.channel, actor=current_user.username, now=now)
    db.add(AuditLog(actor=current_user.username, action="notification_test", target_type="notification_channel",
                    target_value=body.channel, details={"ok": result["ok"], "words": result["words"]}))
    db.commit()
    return result
