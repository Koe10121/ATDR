"""Which MFU services answer people on the internet, and which of them should not.

Detection lists every MFU address and port that answers a connection from the internet (the internet_services
table): in three minutes of 20 May traffic, 136 of them, most of them DNS and web servers. An admin marks each one as
meant to be public ("expected") or not ("not_expected"). Detection then
- treats a connection to an expected service as use of it, not as an outsider trying an unusual port;
- raises an alert for a service that answers the internet although it was marked not to be public, for one that
  is a kind of service that should rarely be public (remote control, databases, file sharing, debugging), unless it
  is marked expected, and for a service that starts answering after ATDR has watched for a day.
alert_service.record_internet_exposure writes those alerts. A service is listed because it answered the internet, so
marking it not to be public raises its alert at once (review_internet_service), from the connections already seen.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from atdr.app.db.models import Alert, AuditLog, InternetService, NormalizedLog
from atdr.app.detection.attack_mapping import INTERNET_EXPOSURE_ALERT
from atdr.app.detection.rules import connection_answered, is_from_internet, is_ftp_data_connection
from atdr.app.services.alert_service import ALERT_DEDUP_ACTIVE_STATUSES, EXPOSURE_EVIDENCE_PER_CHECK, record_marked_exposure

STATUSES = ("unreviewed", "expected", "not_expected")
# A service first seen this long after ATDR began listing them is new: by then the ones always there are listed.
NEW_SERVICE_AFTER = timedelta(hours=24)
SAMPLE_SOURCES_KEPT = 10
APPS_KEPT = 5
# The firewall could not name the app: then the port says what the service probably is.
# How many stored logs answered_internet_logs reads at a time.
ANSWERED_LOGS_CHUNK = 5000
UNNAMED_APPS = frozenset({"", "incomplete", "insufficient-data", "not-applicable", "unknown-tcp", "unknown-udp", "unknown-p2p"})


@dataclass(frozen=True)
class RiskyService:
    """A kind of service that should rarely be reachable from the internet."""

    name: str
    severity: str
    why: str
    apps: tuple[str, ...] = ()
    ports: tuple[int, ...] = ()


RISKY_SERVICES: tuple[RiskyService, ...] = (
    RiskyService("remote desktop (RDP)", "High", "whoever reaches it can try passwords on a Windows desktop, one of the most attacked services",
                 apps=("ms-rdp",), ports=(3389,)),
    RiskyService("remote screen control (VNC)", "High", "whoever reaches it can try to take over the screen", apps=("vnc",),
                 ports=(5900, 5901, 5902, 5903)),
    RiskyService("Telnet", "High", "it sends passwords unencrypted", apps=("telnet",), ports=(23,)),
    RiskyService("Windows remote management", "High", "whoever reaches it can try to run commands on the machine",
                 apps=("ms-winrm", "winrm"), ports=(5985, 5986)),
    RiskyService("Windows file sharing", "High", "it is how ransomware and worms spread from machine to machine",
                 apps=("ms-ds-smb", "smb", "netbios-ss", "netbios-ns", "netbios-dg", "msrpc"), ports=(135, 137, 138, 139, 445)),
    RiskyService("Chrome remote debugging", "High", "whoever reaches it can control the browser and every site it is signed in to",
                 ports=(9222,)),
    RiskyService("Docker or Kubernetes control", "High", "whoever reaches it can start programs on the machine",
                 apps=("docker",), ports=(2375, 2376, 10250)),
    RiskyService("a database", "High", "databases are meant to be reached by their own applications, not the internet",
                 apps=("mysql", "postgres", "mssql-db", "ms-sql", "oracle", "redis", "mongodb", "elasticsearch", "memcache",
                       "cassandra", "couchdb"),
                 ports=(1433, 1521, 3306, 5432, 5984, 6379, 9042, 9200, 9300, 11211, 27017)),
    RiskyService("network file sharing (NFS)", "High", "it can hand out files to whoever asks", apps=("nfs", "portmapper"),
                 ports=(111, 2049)),
    RiskyService("SSH remote login", "Medium", "fine when it is meant to be public, but password guessing aims at it all day",
                 apps=("ssh",), ports=(22,)),
    RiskyService("FTP", "Medium", "it sends passwords unencrypted", apps=("ftp",), ports=(21,)),
    RiskyService("a directory or device management service (LDAP, SNMP)", "Medium", "it can tell an outsider about users and devices",
                 apps=("ldap", "snmp"), ports=(161, 389)),
)

# What the firewall's app names mean, for the list on the dashboard.
PLAIN_APPS = {"web-browsing": "a web site", "ssl": "an encrypted (TLS) service", "dns-base": "DNS", "dns": "DNS", "ntp": "time (NTP)",
              "smtp": "mail (SMTP)", "quic": "web (QUIC)", "stun": "video calls (STUN)", "openvpn": "VPN (OpenVPN)"}
# What usually answers on a port, for the list on the dashboard.
COMMON_SERVICES = {21: "FTP", 22: "SSH", 25: "mail (SMTP)", 53: "DNS", 80: "web (HTTP)", 110: "mail (POP3)", 123: "time (NTP)",
                   143: "mail (IMAP)", 443: "web (HTTPS)", 465: "mail (SMTPS)", 587: "mail (submission)", 993: "mail (IMAPS)",
                   995: "mail (POP3S)", 1194: "VPN (OpenVPN)", 3478: "video calls (STUN)", 8080: "web (alternative port)",
                   8443: "web (alternative HTTPS port)"}


def _lower(value: Any) -> str:
    return str(value or "").strip().lower()


def _app_matches(app: str, names: tuple[str, ...]) -> bool:
    return any(app == name or app.startswith(f"{name}-") for name in names)


def risk_of(apps: Iterable[str], port: int) -> RiskyService | None:
    """What kind of risky service this is: by the app the firewall named, or by the port when it named none."""

    named = [app for app in (_lower(app) for app in apps) if app not in UNNAMED_APPS and not app.startswith("unknown")]
    for service in RISKY_SERVICES:
        if any(_app_matches(app, service.apps) for app in named):
            return service
    if named:
        # The firewall saw something else there (a web site on 3389, say): the port is not what it is.
        return None
    return next((service for service in RISKY_SERVICES if port in service.ports), None)


def service_key(log: Any) -> tuple[str, int, str]:
    return (str(log.dst_ip), int(log.dst_port), _lower(log.protocol))


def is_exposure_log(log: Any) -> bool:
    """A connection from the internet to a port of an MFU address, which the MFU side answered."""

    return (
        _lower(log.protocol) in ("tcp", "udp")
        and log.dst_port is not None
        and bool(log.dst_ip)
        and is_from_internet(log)
        and connection_answered(getattr(log, "packets_received", None), log.session_end_reason)
        and not is_ftp_data_connection(log)
    )


def _utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def _event_time(log: Any) -> datetime | None:
    return _utc(log.generated_time or log.receive_time or getattr(log, "high_res_timestamp", None) or log.start_time)


def _app_names(service: InternetService) -> list[str]:
    return [str(item.get("app")) for item in service.apps or [] if isinstance(item, dict)]


@dataclass
class ExposureMap:
    """What detection needs of the list during one run: which services are meant to be public, and since when
    ATDR has been listing them."""

    expected: set[tuple[str, int, str]] = field(default_factory=set)
    started: datetime | None = None

    @classmethod
    def load(cls, db: Session) -> "ExposureMap":
        expected = {
            (address, int(port), protocol)
            for address, port, protocol in db.execute(
                select(InternetService.address, InternetService.port, InternetService.protocol).where(InternetService.status == "expected")
            )
        }
        return cls(expected=expected, started=_utc(db.scalar(select(func.min(InternetService.first_seen)))))

    def is_expected(self, log: Any) -> bool:
        return bool(self.expected) and log.dst_port is not None and bool(log.dst_ip) and service_key(log) in self.expected


@dataclass
class ExposureFinding:
    """A service that answered the internet and has to be told about, with this check's connections to it."""

    service: InternetService
    reason: str
    risk: RiskyService | None
    logs: list[Any]

    @property
    def severity(self) -> str:
        if self.reason == "not_expected":
            return "High"
        if self.reason == "risky" and self.risk is not None:
            return self.risk.severity
        return "Medium"


def note_internet_services(db: Session, logs: Iterable[Any]) -> dict[tuple[str, int, str], tuple[InternetService, list[Any]]]:
    """Adds the services these logs show answering the internet to the list, and counts their connections."""

    by_key: dict[tuple[str, int, str], list[Any]] = {}
    for log in logs:
        if is_exposure_log(log):
            by_key.setdefault(service_key(log), []).append(log)
    if not by_key:
        return {}
    addresses = sorted({key[0] for key in by_key})
    known: dict[tuple[str, int, str], InternetService] = {}
    for start in range(0, len(addresses), 500):
        for row in db.scalars(select(InternetService).where(InternetService.address.in_(addresses[start:start + 500]))):
            known[(row.address, int(row.port), row.protocol)] = row
    noted: dict[tuple[str, int, str], tuple[InternetService, list[Any]]] = {}
    for key, service_logs in by_key.items():
        row = known.get(key)
        if row is None:
            row = InternetService(address=key[0], port=key[1], protocol=key[2], apps=[], connections=0, sources=0,
                                  sample_sources=[], status="unreviewed")
            db.add(row)
        times = [moment for moment in (_event_time(log) for log in service_logs) if moment is not None]
        if times:
            first, last = min(times), max(times)
            row.first_seen = min(first, _utc(row.first_seen)) if row.first_seen else first
            row.last_seen = max(last, _utc(row.last_seen)) if row.last_seen else last
        row.connections = int(row.connections or 0) + len(service_logs)
        sources = {str(log.src_ip) for log in service_logs if log.src_ip}
        row.sources = max(int(row.sources or 0), len(sources))
        sample = list(row.sample_sources or [])
        row.sample_sources = [*sample, *sorted(sources - set(sample))][:SAMPLE_SOURCES_KEPT]
        apps = Counter({str(item["app"]): int(item.get("connections") or 0) for item in row.apps or [] if isinstance(item, dict)})
        apps.update(_lower(log.app) or "unknown" for log in service_logs)
        row.apps = [{"app": app, "connections": count} for app, count in sorted(apps.items(), key=lambda item: (-item[1], item[0]))[:APPS_KEPT]]
        noted[key] = (row, service_logs)
    db.flush()
    return noted


def exposure_findings(
    noted: dict[tuple[str, int, str], tuple[InternetService, list[Any]]],
    *,
    started: datetime | None,
) -> list[ExposureFinding]:
    """The services among these that have to be told about. `started` is when ATDR began listing services, before
    this check: none is new while nothing was listed."""

    findings = []
    for service, service_logs in noted.values():
        if service.status == "expected":
            continue
        risk = risk_of(_app_names(service), int(service.port))
        if service.status == "not_expected":
            reason = "not_expected"
        elif risk is not None:
            reason = "risky"
        elif started is not None and service.first_seen is not None and _utc(service.first_seen) >= started + NEW_SERVICE_AFTER:
            reason = "new"
        else:
            continue
        findings.append(ExposureFinding(service=service, reason=reason, risk=risk, logs=service_logs))
    # The most severe first, so that a new alert's number says which to look at first.
    return sorted(findings, key=lambda finding: (finding.severity != "High", finding.service.address, int(finding.service.port)))


def describe(service: InternetService) -> dict[str, Any]:
    """A service as the dashboard and the assistant show it."""

    apps = _app_names(service)
    risk = risk_of(apps, int(service.port))
    named = [app for app in apps if app not in UNNAMED_APPS and not app.startswith("unknown")]
    if risk is not None:
        what = risk.name
    elif int(service.port) in COMMON_SERVICES:
        what = COMMON_SERVICES[int(service.port)]
    elif named:
        what = PLAIN_APPS.get(named[0], named[0])
    else:
        what = "not named by the firewall"
    return {
        "id": service.id,
        "address": service.address,
        "port": int(service.port),
        "protocol": service.protocol,
        "what": what,
        "apps": service.apps or [],
        "connections": int(service.connections or 0),
        "sources": int(service.sources or 0),
        "sample_sources": service.sample_sources or [],
        "first_seen": _utc(service.first_seen),
        "last_seen": _utc(service.last_seen),
        "status": service.status,
        "note": service.note,
        "reviewed_by": service.reviewed_by,
        "reviewed_at": _utc(service.reviewed_at),
        "risk": {"name": risk.name, "severity": risk.severity, "why": risk.why} if risk else None,
    }


def _order(item: dict[str, Any]) -> tuple:
    # What needs a look first: risky ones nobody approved, then those marked not public, then the busiest.
    risky_open = item["risk"] is not None and item["status"] != "expected"
    return (
        0 if risky_open and item["risk"]["severity"] == "High" else 1 if risky_open else 2,
        0 if item["status"] == "not_expected" else 1 if item["status"] == "unreviewed" else 2,
        -item["sources"],
        -item["connections"],
        item["address"],
        item["port"],
    )


def list_internet_services(db: Session, *, status: str | None = None, limit: int = 1000) -> dict[str, Any]:
    rows = list(db.scalars(select(InternetService)))
    alerts = _open_alerts_by_service(db)
    items = sorted((describe(row) | {"alert": alerts.get(row.id)} for row in rows), key=_order)
    summary = {
        "services": len(items),
        "addresses": len({item["address"] for item in items}),
        "unreviewed": sum(1 for item in items if item["status"] == "unreviewed"),
        "expected": sum(1 for item in items if item["status"] == "expected"),
        "not_expected": sum(1 for item in items if item["status"] == "not_expected"),
        "risky_not_approved": sum(1 for item in items if item["risk"] is not None and item["status"] != "expected"),
        "listing_since": min((item["first_seen"] for item in items if item["first_seen"]), default=None),
    }
    shown = [item for item in items if status is None or item["status"] == status]
    return {"summary": summary, "services": shown[:limit], "total_shown": len(shown)}


def stored_connections(db: Session, service: InternetService, *, limit: int) -> list[NormalizedLog]:
    """The first of the stored connections from the internet that this service answered (ordinary logs are kept
    for hours only; the counts on the service are the whole story)."""

    rows = db.scalars(
        select(NormalizedLog)
        .where(NormalizedLog.dst_ip == service.address, NormalizedLog.dst_port == int(service.port), NormalizedLog.packets_received > 0)
        .order_by(NormalizedLog.id)
        .limit(limit * 10)
    )
    return [row for row in rows if is_exposure_log(row) and service_key(row) == (service.address, int(service.port), service.protocol)][:limit]


def _open_alerts_by_service(db: Session) -> dict[int, dict[str, Any]]:
    """Each service's open alert, by service id."""

    found: dict[int, dict[str, Any]] = {}
    for alert in db.scalars(select(Alert).where(Alert.alert_type == INTERNET_EXPOSURE_ALERT, Alert.status.in_(ALERT_DEDUP_ACTIVE_STATUSES))):
        service_id = next((rule.get("internet_service_id") for rule in alert.matched_rules_json or [] if rule.get("code") == "group_metadata"), None)
        if service_id is not None:
            found[int(service_id)] = {"id": alert.id, "severity": alert.severity, "status": alert.status}
    return found


def review_internet_service(db: Session, service_id: int, *, status: str, note: str | None, actor: str) -> dict[str, Any] | None:
    if status not in STATUSES:
        raise ValueError(f"status must be one of {', '.join(STATUSES)}")
    service = db.get(InternetService, service_id)
    if service is None:
        return None
    before = service.status
    service.status = status
    service.note = (note or "").strip()[:2000] or None
    service.reviewed_by = actor if status != "unreviewed" else None
    service.reviewed_at = datetime.now(timezone.utc) if status != "unreviewed" else None
    alerted = None
    if status == "not_expected":
        finding = ExposureFinding(service=service, reason="not_expected", risk=risk_of(_app_names(service), int(service.port)),
                                  logs=stored_connections(db, service, limit=EXPOSURE_EVIDENCE_PER_CHECK))
        alerted = record_marked_exposure(db, finding)
        db.flush()
    db.add(AuditLog(actor=actor, action="internet_service_reviewed", target_type="internet_service", target_value=str(service.id),
                    details={"address": service.address, "port": service.port, "protocol": service.protocol,
                             "status_before": before, "status": status, "note": service.note,
                             "alert_id": alerted[0].id if alerted else None, "alert_created": bool(alerted and alerted[1])}))
    db.commit()
    db.refresh(service)
    return describe(service) | {"alert": _open_alerts_by_service(db).get(service.id)}


def answered_internet_logs(db: Session, *, chunk: int | None = None) -> Iterable[list[NormalizedLog]]:
    """Every stored log that could show a service answering the internet, in chunks, oldest first."""

    chunk = chunk or ANSWERED_LOGS_CHUNK
    last_id = 0
    while True:
        rows = list(db.scalars(
            select(NormalizedLog)
            .where(NormalizedLog.id > last_id, NormalizedLog.packets_received > 0, NormalizedLog.dst_port.is_not(None))
            .order_by(NormalizedLog.id)
            .limit(chunk)
        ))
        if not rows:
            return
        last_id = int(rows[-1].id)
        yield [row for row in rows if is_exposure_log(row)]
