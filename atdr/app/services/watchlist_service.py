from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from atdr.app.db.models import AuditLog, NormalizedLog, WatchlistItem
from atdr.app.schemas.watchlists import ALLOWED_WATCHLIST_TYPES


def _normalized_value(indicator_type: str, value: str | None) -> str:
    if value is None:
        return ""
    if indicator_type in {"src_ip", "dst_ip", "app"}:
        return value.strip().lower()
    return value.strip()


def list_watchlist_items(db: Session, *, active_only: bool = False) -> list[WatchlistItem]:
    statement = select(WatchlistItem).order_by(WatchlistItem.created_at.desc(), WatchlistItem.id.desc())
    if active_only:
        statement = statement.where(WatchlistItem.active.is_(True))
    return list(db.scalars(statement))


def create_watchlist_item(
    db: Session,
    *,
    indicator_type: str,
    indicator_value: str,
    description: str,
    severity_boost: int,
    actor: str,
) -> WatchlistItem:
    normalized_type = indicator_type.strip().lower()
    if normalized_type not in ALLOWED_WATCHLIST_TYPES:
        raise ValueError(f"Unsupported watchlist indicator type: {indicator_type}")
    item = WatchlistItem(
        indicator_type=normalized_type,
        indicator_value=indicator_value.strip(),
        description=description.strip(),
        severity_boost=severity_boost,
        created_by=actor,
    )
    db.add(item)
    db.flush()
    db.add(
        AuditLog(
            actor=actor,
            action="watchlist_created",
            target_type="watchlist_item",
            target_value=str(item.id),
            details={
                "indicator_type": item.indicator_type,
                "indicator_value": item.indicator_value,
                "severity_boost": item.severity_boost,
            },
        )
    )
    db.commit()
    db.refresh(item)
    return item


def disable_watchlist_item(db: Session, item_id: int, *, actor: str) -> WatchlistItem | None:
    item = db.get(WatchlistItem, item_id)
    if item is None:
        return None
    item.active = False
    item.disabled_by = actor
    item.disabled_at = datetime.now(timezone.utc)
    db.add(
        AuditLog(
            actor=actor,
            action="watchlist_disabled",
            target_type="watchlist_item",
            target_value=str(item.id),
            details={"match_count": item.match_count, "indicator_value": item.indicator_value},
        )
    )
    db.commit()
    db.refresh(item)
    return item


def matching_watchlist_items(log: NormalizedLog, active_items: list[WatchlistItem]) -> list[WatchlistItem]:
    matches: list[WatchlistItem] = []
    log_values = {
        "src_ip": log.src_ip,
        "dst_ip": log.dst_ip,
        "app": log.app,
    }
    for item in active_items:
        expected = _normalized_value(item.indicator_type, item.indicator_value)
        observed = _normalized_value(item.indicator_type, log_values.get(item.indicator_type))
        if expected and expected == observed:
            matches.append(item)
    return matches


def record_watchlist_hits(items: list[WatchlistItem], *, count: int = 1) -> None:
    now = datetime.now(timezone.utc)
    for item in items:
        item.match_count += count
        item.last_matched_at = now
