"""Logs from the live syslog feed are kept for SYSLOG_RETENTION_HOURS, summarised by hour, then deleted.

At MFU's firewall rate (about 600 lines a second) the feed brings about 2 million logs an hour, and the laptop running
ATDR has room for hours of them, not days. Imported files are datasets the team keeps on purpose and are never
touched. A log is deleted only after detection has checked it, and never when it is alert evidence or labelled.
Before an hour's logs go, each source address's traffic in that hour becomes one row of traffic_hourly_summaries;
an hour is deleted only once it is summarised, so a log stays 6 to 7 hours with the default setting.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import case, delete, exists, func, or_, select
from sqlalchemy.orm import Session

from atdr.app.core.config import get_settings
from atdr.app.db.models import AlertEvidence, AuditLog, LogSource, MLLabel, NormalizedLog, RawLog, TrafficHourlySummary
from atdr.app.services.detection_service import _event_time_expression

LIVE_SOURCE_TYPE = "syslog_udp"
HOUR = timedelta(hours=1)
DELETE_CHUNK = 2000
# One pass works for at most this long, then lets the worker's other work in; it carries on at once if more is due.
PASS_SECONDS = 20.0
# How often the worker looks when nothing is due.
RETENTION_EVERY_SECONDS = 300.0


@dataclass
class RetentionProgress:
    """Kept by the worker between passes: per source, every live log up to this raw log id is deleted or kept for good."""

    deleted_through_raw_id: dict[int, int] = field(default_factory=dict)


def _utc(moment: datetime) -> datetime:
    return moment if moment.tzinfo is not None else moment.replace(tzinfo=timezone.utc)


def _hour_floor(moment: datetime) -> datetime:
    return _utc(moment).replace(minute=0, second=0, microsecond=0)


def live_source_ids(db: Session) -> list[int]:
    return list(db.scalars(select(LogSource.id).where(LogSource.source_type == LIVE_SOURCE_TYPE).order_by(LogSource.id)))


def _denied():
    # A denied connection as the rules judge one (detection/rules.py): "deny" or "drop" anywhere, or a reset.
    action = func.lower(func.coalesce(NormalizedLog.action, ""))
    return case((or_(action.like("%deny%"), action.like("%drop%"), action.like("reset%")), 1), else_=0)


def summarise_hour(db: Session, source_id: int, hour_start: datetime) -> int:
    """One summary row per source address for the logs this source sent in the hour. Does not commit."""

    event = _event_time_expression()
    rows = db.execute(
        select(
            NormalizedLog.src_ip,
            func.count(NormalizedLog.id),
            func.sum(_denied()),
            func.sum(func.coalesce(NormalizedLog.bytes_sent, 0)),
            func.sum(func.coalesce(NormalizedLog.bytes_received, 0)),
            func.count(func.distinct(NormalizedLog.dst_ip)),
            func.count(func.distinct(NormalizedLog.dst_port)),
            func.min(event),
            func.max(event),
        )
        .join(RawLog, RawLog.id == NormalizedLog.raw_log_id)
        .where(RawLog.source_id == source_id, RawLog.imported_at >= hour_start, RawLog.imported_at < hour_start + HOUR)
        .group_by(NormalizedLog.src_ip)
    ).all()
    db.add_all(
        TrafficHourlySummary(
            hour_start=hour_start,
            source_id=source_id,
            src_ip=src_ip,
            connections=int(connections),
            denied=int(denied or 0),
            bytes_sent=int(sent or 0),
            bytes_received=int(received or 0),
            destinations=int(destinations or 0),
            destination_ports=int(ports or 0),
            first_seen=first,
            last_seen=last,
        )
        for src_ip, connections, denied, sent, received, destinations, ports, first, last in rows
    )
    return len(rows)


def _next_hour_to_summarise(db: Session, source_id: int) -> datetime | None:
    newest = db.scalar(select(func.max(TrafficHourlySummary.hour_start)).where(TrafficHourlySummary.source_id == source_id))
    if newest is not None:
        return _hour_floor(newest) + HOUR
    oldest = db.scalar(select(func.min(RawLog.imported_at)).where(RawLog.source_id == source_id))
    return _hour_floor(oldest) if oldest is not None else None


def _delete_chunk(db: Session, source_id: int, before: datetime, after_raw_id: int) -> tuple[int, int | None]:
    """Delete up to DELETE_CHUNK checked, unreferenced logs this source sent before `before`. Does not commit."""

    rows = db.execute(
        select(NormalizedLog.id, RawLog.id)
        .join(RawLog, RawLog.id == NormalizedLog.raw_log_id)
        .where(
            RawLog.source_id == source_id,
            RawLog.imported_at < before,
            RawLog.id > after_raw_id,
            NormalizedLog.last_detection_run_id.is_not(None),
            ~exists().where(AlertEvidence.normalized_log_id == NormalizedLog.id),
            ~exists().where(MLLabel.log_id == NormalizedLog.id),
        )
        .order_by(RawLog.id)
        .limit(DELETE_CHUNK)
    ).all()
    if not rows:
        return 0, None
    db.execute(delete(NormalizedLog).where(NormalizedLog.id.in_([row[0] for row in rows])))
    db.execute(delete(RawLog).where(RawLog.id.in_([row[1] for row in rows])))
    return len(rows), max(row[1] for row in rows)


def _prune_summaries(db: Session, source_ids: list[int], keep_days: int, now: datetime) -> int:
    if keep_days <= 0:
        return 0
    cutoff = now - timedelta(days=keep_days)
    pruned = 0
    for source_id in source_ids:
        newest = db.scalar(select(func.max(TrafficHourlySummary.hour_start)).where(TrafficHourlySummary.source_id == source_id))
        if newest is None:
            continue
        # The newest summarised hour stays: it says where summarising carries on.
        result = db.execute(
            delete(TrafficHourlySummary).where(
                TrafficHourlySummary.source_id == source_id,
                TrafficHourlySummary.hour_start < cutoff,
                TrafficHourlySummary.hour_start < newest,
            )
        )
        pruned += int(result.rowcount or 0)
    return pruned


def run_live_retention(
    db: Session,
    *,
    settings: Any = None,
    now: datetime | None = None,
    progress: RetentionProgress | None = None,
    budget_seconds: float = PASS_SECONDS,
) -> dict[str, Any]:
    """One pass: summarise the whole hours past the limit, then delete their checked, unreferenced live logs."""

    settings = settings or get_settings()
    hours = float(settings.syslog_retention_hours)
    if hours <= 0:
        return {"enabled": False, "more_due": False}
    now = _utc(now or datetime.now(timezone.utc))
    cutoff = now - timedelta(hours=hours)
    progress = progress if progress is not None else RetentionProgress()
    started = time.monotonic()
    sources = live_source_ids(db)
    summarised_hours = summary_rows = deleted = 0
    more_due = False
    for source_id in sources:
        hour = _next_hour_to_summarise(db, source_id)
        while hour is not None and hour + HOUR <= cutoff:
            if time.monotonic() - started >= budget_seconds:
                more_due = True
                break
            summary_rows += summarise_hour(db, source_id, hour)
            db.commit()
            summarised_hours += 1
            hour += HOUR
        if hour is None:
            continue
        # Every log this source sent before `hour` is in a summary now.
        while True:
            if time.monotonic() - started >= budget_seconds:
                more_due = True
                break
            count, last_raw_id = _delete_chunk(db, source_id, hour, progress.deleted_through_raw_id.get(source_id, 0))
            if not count:
                break
            db.commit()
            deleted += count
            progress.deleted_through_raw_id[source_id] = int(last_raw_id)
    pruned = _prune_summaries(db, sources, int(settings.syslog_summary_retention_days), now)
    summary = {
        "enabled": True,
        "keep_hours": hours,
        "cutoff": cutoff.isoformat(),
        "hours_summarised": summarised_hours,
        "summary_rows": summary_rows,
        "logs_deleted": deleted,
        "summaries_pruned": pruned,
        "more_due": more_due,
    }
    if summarised_hours or deleted or pruned:
        db.add(AuditLog(actor="live_log_retention", action="live_logs_retained", target_type="normalized_logs",
                        target_value=f"older than {hours:g} h", details=summary))
    db.commit()
    return summary
