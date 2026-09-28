import ipaddress
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import case, func, select
from sqlalchemy.orm import Session

from atdr.app.db.models import AuditLog, NormalizedLog, WatchlistItem
from atdr.app.schemas.watchlists import ALLOWED_WATCHLIST_TYPES


def _normalized_value(indicator_type: str, value: str | None) -> str:
    if value is None:
        return ""
    if indicator_type in {"src_ip", "dst_ip", "app", "src_country", "dst_country"}:
        return value.strip().lower()
    return value.strip()


def list_watchlist_items(db: Session, *, active_only: bool = False, manual_only: bool = False) -> list[WatchlistItem]:
    """Watchlist items, newest first. ``manual_only`` leaves out indicators imported from feeds."""

    statement = select(WatchlistItem).order_by(WatchlistItem.created_at.desc(), WatchlistItem.id.desc())
    if active_only:
        statement = statement.where(WatchlistItem.active.is_(True))
    if manual_only:
        statement = statement.where(WatchlistItem.source.is_(None))
    return list(db.scalars(statement))


def watchlist_feed_summary(db: Session) -> list[dict[str, Any]]:
    """One row per threat intelligence feed on the watchlist."""

    rows = db.execute(
        select(
            WatchlistItem.source,
            func.count(WatchlistItem.id),
            func.sum(case((WatchlistItem.active.is_(True), 1), else_=0)),
            func.max(WatchlistItem.created_at),
            func.sum(WatchlistItem.match_count),
            func.max(WatchlistItem.last_matched_at),
        )
        .where(WatchlistItem.source.is_not(None))
        .group_by(WatchlistItem.source)
        .order_by(WatchlistItem.source)
    ).all()
    def utc(value: datetime | None) -> datetime | None:
        # SQLite hands timestamps back without a zone; they are UTC, and saying so lets the browser show local time.
        return value.replace(tzinfo=timezone.utc) if value is not None and value.tzinfo is None else value

    return [
        {"source": source, "indicators": int(total), "active": int(active or 0), "last_added_at": utc(last_added),
         "matches": int(matches or 0), "last_matched_at": utc(last_matched)}
        for source, total, active, last_added, matches, last_matched in rows
    ]


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


class WatchlistIndex:
    """Active items keyed by (type, value), so a log costs one lookup per field.

    Threat intelligence feeds put thousands of addresses on the watchlist; comparing every log with
    every item would make detection thousands of times slower.
    """

    # Countries are parsed from PAN-OS logs and matched like the other fields.
    FIELDS = ("src_ip", "dst_ip", "app", "src_country", "dst_country")

    def __init__(self, items: list[WatchlistItem]) -> None:
        self._items: dict[tuple[str, str], list[WatchlistItem]] = defaultdict(list)
        for item in items:
            value = _normalized_value(item.indicator_type, item.indicator_value)
            if value:
                self._items[(item.indicator_type, value)].append(item)

    def __len__(self) -> int:
        return sum(len(items) for items in self._items.values())

    def matches(self, log: NormalizedLog) -> list[WatchlistItem]:
        found: list[WatchlistItem] = []
        for field in self.FIELDS:
            observed = _normalized_value(field, getattr(log, field, None))
            if observed:
                found.extend(self._items.get((field, observed), ()))
        return found


def matching_watchlist_items(log: NormalizedLog, active_items: list[WatchlistItem]) -> list[WatchlistItem]:
    return WatchlistIndex(active_items).matches(log)


def watchlist_attack_type(items: list[WatchlistItem], log: NormalizedLog) -> str | None:
    """What a watchlist hit says is happening, when the indicator's kind says it."""

    kinds = {item.indicator_type for item in items}
    # Threat-intel feeds list malware and C2 servers as destinations: reaching
    # one from inside is contact with known malicious infrastructure.
    if "dst_ip" in kinds and not _is_private_address(log.dst_ip):
        return "malware_c2"
    if kinds & {"app", "src_country", "dst_country"}:
        return "policy_violation"
    return None


def _is_private_address(value: str | None) -> bool:
    try:
        return ipaddress.ip_address(str(value)).is_private
    except ValueError:
        return False


def record_watchlist_hits(items: list[WatchlistItem], *, count: int = 1) -> None:
    now = datetime.now(timezone.utc)
    for item in items:
        item.match_count += count
        item.last_matched_at = now
