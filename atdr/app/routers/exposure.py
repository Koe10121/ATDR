"""The MFU services that answer the internet, and whether each is meant to (exposure_service)."""

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from atdr.app.core.security import require_admin, require_analyst_or_admin
from atdr.app.db.database import get_db
from atdr.app.db.models import User
from atdr.app.services.exposure_service import list_internet_services, review_internet_service

router = APIRouter(prefix="/api/exposure", tags=["exposure"])


class ServiceReview(BaseModel):
    status: Literal["unreviewed", "expected", "not_expected"]
    note: str | None = Field(default=None, max_length=2000)


@router.get("/services")
def get_internet_services(
    status: Literal["unreviewed", "expected", "not_expected"] | None = Query(default=None),
    limit: int = Query(default=1000, ge=1, le=5000),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
) -> dict:
    return list_internet_services(db, status=status, limit=limit)


@router.patch("/services/{service_id}")
def patch_internet_service(
    service_id: int,
    body: ServiceReview,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
) -> dict:
    """Marks a service as meant to be public or not; detection uses the mark from its next check on."""

    reviewed = review_internet_service(db, service_id, status=body.status, note=body.note, actor=current_user.username)
    if reviewed is None:
        raise HTTPException(status_code=404, detail="No such service")
    return reviewed
