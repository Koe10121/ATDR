"""Threat intelligence feeds on ATDR's watchlist.

ATDR's rules judge behaviour, but some attacks look like ordinary traffic and are known only because
someone has seen the server before. On 20 May an MFU device called a GHOSTENGINE C2 server every 14
seconds over plain HTTP; no behaviour rule could tell it from an app keep-alive without also firing on
dozens of harmless ones. Feeds of known-bad addresses cover that case.

A feed file is read offline: download it, then import it. Each address becomes a destination-IP
watchlist item tagged with the feed's name, so ATDR alerts when an MFU host contacts it. Importing a
newer file of the same feed replaces that feed's list: new addresses are added, addresses no longer
in the file are disabled (feeds retire servers that were cleaned up or reassigned), and returning
ones are switched back on. Manual watchlist items are never touched.

Supported files, recognised from their header:

- abuse.ch Feodo Tracker ``ipblocklist.csv`` (botnet C2 servers);
- abuse.ch ThreatFox CSV exports of ``ip:port`` indicators;
- a plain list, one IP address per line (``#`` starts a comment).

Private and reserved addresses are skipped: a feed must never put MFU's own hosts on the list.
"""

from __future__ import annotations

import csv
import ipaddress
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from atdr.app.db.models import AuditLog, NormalizedLog, WatchlistItem

HIGH_CONFIDENCE_BOOST = 60
DEFAULT_BOOST = 40
THREATFOX_HIGH_CONFIDENCE = 75
CHUNK = 500


@dataclass(frozen=True, slots=True)
class Indicator:
    ip: str
    description: str
    severity_boost: int


@dataclass(slots=True)
class ParsedFeed:
    format: str
    indicators: list[Indicator]
    rows: int
    skipped_invalid: int
    skipped_private: int


def _global_ip(value: str) -> tuple[str | None, str]:
    """(address, "") for a public address, else (None, why)."""

    try:
        address = ipaddress.ip_address(value.strip().strip('"'))
    except ValueError:
        return None, "invalid"
    return (str(address), "") if address.is_global else (None, "private")


def _rows(lines: list[str], header: str) -> list[dict[str, str]]:
    body = [line for line in lines if line.strip() and not line.lstrip().startswith("#")]
    return list(csv.DictReader([header, *body], skipinitialspace=True))


def parse_feed(text: str) -> ParsedFeed:
    lines = text.splitlines()
    header = next((line.lstrip("#").strip() for line in lines if '"first_seen_utc"' in line), None)
    grouped: dict[str, list[dict[str, str]]] = defaultdict(list)
    skipped = {"invalid": 0, "private": 0}
    rows = 0

    if header and '"dst_ip"' in header:
        kind = "feodo"
        records = [(row.get("dst_ip", ""), row) for row in _rows(lines, header)]
    elif header and '"ioc_value"' in header:
        kind = "threatfox"
        records = [((row.get("ioc_value") or "").rsplit(":", 1)[0], row) for row in _rows(lines, header)
                   if (row.get("ioc_type") or "").strip() == "ip:port"]
    else:
        kind = "plain"
        records = [(line.split("#", 1)[0].split()[0], {}) for line in lines
                   if line.split("#", 1)[0].strip()]
    for value, row in records:
        rows += 1
        ip, why = _global_ip(value)
        if ip is None:
            skipped[why] += 1
            continue
        grouped[ip].append(row)

    indicators = [_indicator(kind, ip, entries) for ip, entries in grouped.items()]
    return ParsedFeed(kind, indicators, rows, skipped["invalid"], skipped["private"])


def _indicator(kind: str, ip: str, entries: list[dict[str, str]]) -> Indicator:
    if kind == "feodo":
        entry = entries[-1]
        online = (entry.get("c2_status") or "").strip() == "online"
        text = (f"Feodo Tracker (abuse.ch): {entry.get('malware') or 'botnet'} C2 server, port {entry.get('dst_port')}, "
                f"{entry.get('c2_status') or 'status unknown'}, last online {entry.get('last_online') or 'unknown'}, "
                f"first seen {entry.get('first_seen_utc') or 'unknown'}.")
        return Indicator(ip, text, HIGH_CONFIDENCE_BOOST if online else DEFAULT_BOOST)
    if kind == "threatfox":
        malware = sorted({entry.get("malware_printable") or "unknown malware" for entry in entries})
        threats = sorted({entry.get("threat_type") or "unknown" for entry in entries})
        ports = sorted({(entry.get("ioc_value") or "").rsplit(":", 1)[-1] for entry in entries})
        confidence = max(int(entry.get("confidence_level") or 0) for entry in entries)
        first_seen = min(entry.get("first_seen_utc") or "" for entry in entries)
        text = (f"ThreatFox (abuse.ch): {', '.join(malware)} ({', '.join(threats)}), port(s) {', '.join(ports[:6])}, "
                f"confidence {confidence}, first seen {first_seen or 'unknown'}.")
        boost = HIGH_CONFIDENCE_BOOST if confidence >= THREATFOX_HIGH_CONFIDENCE else DEFAULT_BOOST
        return Indicator(ip, text, boost)
    return Indicator(ip, "Listed in an imported threat intelligence file.", DEFAULT_BOOST)


def import_feed(db: Session, *, source: str, feed: ParsedFeed, actor: str, apply: bool = False) -> dict[str, Any]:
    """Replace one feed's watchlist items with the addresses in ``feed``. Dry run unless ``apply``."""

    source = source.strip()
    if not source:
        raise ValueError("A feed needs a name.")
    existing = {item.indicator_value: item for item in db.scalars(select(WatchlistItem).where(WatchlistItem.source == source))}
    wanted = {indicator.ip: indicator for indicator in feed.indicators}
    added = [ip for ip in wanted if ip not in existing]
    reactivated = [ip for ip in wanted if ip in existing and not existing[ip].active]
    disabled = [ip for ip, item in existing.items() if ip not in wanted and item.active]
    summary = {
        "source": source, "format": feed.format, "rows": feed.rows, "indicators": len(wanted),
        "skipped_invalid": feed.skipped_invalid, "skipped_private": feed.skipped_private,
        "added": len(added), "reactivated": len(reactivated), "disabled": len(disabled),
        "unchanged": len(wanted) - len(added) - len(reactivated), "applied": apply,
    }
    if not apply:
        return summary

    now = datetime.now(timezone.utc)
    for ip, indicator in wanted.items():
        item = existing.get(ip)
        if item is None:
            db.add(WatchlistItem(indicator_type="dst_ip", indicator_value=ip, description=indicator.description[:2000],
                                 severity_boost=indicator.severity_boost, created_by=actor, source=source))
            continue
        item.description = indicator.description[:2000]
        item.severity_boost = indicator.severity_boost
        if not item.active:
            item.active, item.disabled_by, item.disabled_at = True, None, None
    for ip in disabled:
        item = existing[ip]
        item.active, item.disabled_by, item.disabled_at = False, actor, now
    db.add(AuditLog(actor=actor, action="watchlist_feed_imported", target_type="watchlist_feed", target_value=source,
                    details=summary))
    db.commit()
    return summary


def stored_log_matches(db: Session, ips: list[str]) -> dict[str, Any]:
    """How many stored logs contacted these addresses (read-only), and from how many sources."""

    logs, sources, matched = 0, set(), set()
    for start in range(0, len(ips), CHUNK):
        chunk = ips[start:start + CHUNK]
        for dst_ip, src_ip, count in db.execute(
            select(NormalizedLog.dst_ip, NormalizedLog.src_ip, func.count(NormalizedLog.id))
            .where(NormalizedLog.dst_ip.in_(chunk))
            .group_by(NormalizedLog.dst_ip, NormalizedLog.src_ip)
        ):
            logs += int(count)
            sources.add(src_ip)
            matched.add(dst_ip)
    return {"logs": logs, "sources": len(sources), "indicators_seen": len(matched)}
