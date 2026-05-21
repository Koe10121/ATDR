from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from atdr.app.core.security import require_admin, require_analyst_or_admin
from atdr.app.db.database import get_db
from atdr.app.db.models import User
from atdr.app.schemas.watchlists import WatchlistCreateRequest, WatchlistRead
from atdr.app.services.watchlist_service import create_watchlist_item, disable_watchlist_item, list_watchlist_items

router = APIRouter(prefix="/api/watchlists", tags=["watchlists"])


@router.get("", response_model=list[WatchlistRead])
def api_list_watchlist_items(
    db: Session = Depends(get_db),
    active_only: bool = False,
    current_user: User = Depends(require_analyst_or_admin),
):
    return list_watchlist_items(db, active_only=active_only)


@router.post("", response_model=WatchlistRead)
def api_create_watchlist_item(
    request: WatchlistCreateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    try:
        return create_watchlist_item(
            db,
            indicator_type=request.indicator_type,
            indicator_value=request.indicator_value,
            description=request.description,
            severity_boost=request.severity_boost,
            actor=current_user.username,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/{item_id}/disable", response_model=WatchlistRead)
def api_disable_watchlist_item(
    item_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    item = disable_watchlist_item(db, item_id, actor=current_user.username)
    if item is None:
        raise HTTPException(status_code=404, detail="Watchlist item not found.")
    return item
