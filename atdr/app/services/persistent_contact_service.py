"""Inside computers in constant contact with an outside address that almost nothing else uses.

On the BOTSv2 lab data four computers made 24,180 HTTPS connections to the attacker's command server over two
days, one every two to four seconds. The beaconing rule missed them: it looks at five-minute windows, wants
a gap of 5 to 300 seconds, and wants a second sign (an unusual port, an unnamed application, a firewall THREAT,
a risk-5 application) that plain HTTPS to port 443 never shows. What gave the server away was that it was the
second-busiest outside address in the data while only four inside computers ever used it: busy, lasting and
private to a handful of machines, where a real service is used by many.

That pattern needs half an hour of traffic to show. MFU's firewall export covers 21 minutes (ATDR's database holds
3 minutes 15 seconds of it), so this check was tried on BOTSv2 only, never on MFU's own traffic; its alerts are
Medium for that reason. It counts session ends: a firewall that logs only session starts is not covered.

A pair becomes a candidate when the batch being checked holds MIN_BATCH_CONNECTIONS of its connections, so a run
reads the stored logs only for pairs already busy in that batch.
"""

from __future__ import annotations

import ipaddress
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from types import SimpleNamespace
from typing import Any

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from atdr.app.db.models import NormalizedLog
from atdr.app.detection.rules import event_time, is_internal_to_external

LOOKBACK = timedelta(hours=1)
WINDOW = timedelta(minutes=5)
# About one connection every 25 seconds across a five-minute window.
MIN_BATCH_CONNECTIONS = 12
MIN_CONNECTIONS = 120
# Five-minute windows with contact in the hour looked back over: half an hour.
MIN_WINDOWS = 6
# Inside computers that used the address in that hour. BOTSv2's command server had four.
MAX_SOURCES = 5
# Name lookups, clocks and pings are steady by design: a DNS server forwarding to a public resolver is not this.
STEADY_BY_DESIGN_APPS = frozenset({"dns", "dns-base", "dns-over-tls", "ntp", "ping", "icmp", "traceroute", "snmp"})
STEADY_BY_DESIGN_PORTS = frozenset({53, 123, 853})
EVIDENCE_PER_CHECK = 20


@dataclass
class PersistentContact:
    destination: str
    # Inside address -> (connections, five-minute windows with contact) over the hour looked back over.
    sources: dict[str, tuple[int, int]]
    ports: list[int]
    apps: list[str]
    first_seen: datetime
    last_seen: datetime
    log_ids: list[int] = field(default_factory=list)

    @property
    def connections(self) -> int:
        return sum(connections for connections, _windows in self.sources.values())

    def as_logs(self) -> list[SimpleNamespace]:
        """One stand-in log per inside computer, for the suppression rules that judge every other alert by its logs."""

        return [SimpleNamespace(src_ip=source, dst_ip=self.destination, app=(self.apps or [None])[0]) for source in self.sources]


def _public(address: str | None) -> bool:
    try:
        return bool(address) and ipaddress.ip_address(str(address)).is_global
    except ValueError:
        return False


def _lower(value: Any) -> str:
    return str(value or "").strip().lower()


def is_candidate_log(log: Any) -> bool:
    """An inside computer's TCP or UDP connection to a public outside address, other than steady-by-design traffic."""

    return (
        _lower(log.protocol) in ("tcp", "udp")
        and is_internal_to_external(log)
        and _public(log.dst_ip)
        and bool(log.src_ip)
        and log.dst_port not in STEADY_BY_DESIGN_PORTS
        and _lower(log.app) not in STEADY_BY_DESIGN_APPS
    )


def _window(moment: datetime) -> datetime:
    return moment.replace(minute=moment.minute - moment.minute % 5, second=0, microsecond=0)


def persistent_contacts(db: Session, logs: list[Any]) -> list[PersistentContact]:
    busy = Counter((log.src_ip, log.dst_ip) for log in logs if is_candidate_log(log))
    destinations = sorted({destination for (_source, destination), count in busy.items() if count >= MIN_BATCH_CONNECTIONS})
    if not destinations:
        return []
    times = [moment for moment in (event_time(log) for log in logs) if moment is not None]
    end = _window(max(times)) + WINDOW
    start = end - LOOKBACK
    in_hour = (
        NormalizedLog.generated_time >= start,
        NormalizedLog.generated_time < end,
        NormalizedLog.log_type == "TRAFFIC",
        or_(NormalizedLog.subtype.is_(None), NormalizedLog.subtype != "start"),
    )
    found = []
    for destination in destinations:
        users = int(db.scalar(select(func.count(func.distinct(NormalizedLog.src_ip))).where(
            NormalizedLog.dst_ip == destination, *in_hour)) or 0)
        if users > MAX_SOURCES:
            continue
        rows = db.execute(
            select(NormalizedLog.id, NormalizedLog.src_ip, NormalizedLog.generated_time, NormalizedLog.dst_port,
                   NormalizedLog.app, NormalizedLog.protocol, NormalizedLog.src_zone, NormalizedLog.dst_zone, NormalizedLog.dst_ip)
            .where(NormalizedLog.dst_ip == destination, *in_hour)
            .order_by(NormalizedLog.generated_time.desc(), NormalizedLog.id.desc())
        ).all()
        connections: Counter[str] = Counter()
        windows: dict[str, set[datetime]] = defaultdict(set)
        for row in rows:
            if row.generated_time is None or not is_candidate_log(row):
                continue
            connections[row.src_ip] += 1
            windows[row.src_ip].add(_window(row.generated_time))
        sources = {
            source: (count, len(windows[source]))
            for source, count in connections.items()
            if count >= MIN_CONNECTIONS and len(windows[source]) >= MIN_WINDOWS
        }
        if not sources:
            continue
        theirs = [row for row in rows if row.src_ip in sources and row.generated_time is not None]
        found.append(PersistentContact(
            destination=destination,
            sources=dict(sorted(sources.items(), key=lambda item: -item[1][0])),
            ports=sorted({int(row.dst_port) for row in theirs if row.dst_port is not None}),
            apps=[app for app, _count in Counter(_lower(row.app) or "unknown" for row in theirs).most_common(3)],
            first_seen=min(row.generated_time for row in theirs),
            last_seen=max(row.generated_time for row in theirs),
            log_ids=[int(row.id) for row in theirs[:EVIDENCE_PER_CHECK]],
        ))
    return found
