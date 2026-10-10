"""ATDR tells people what they need to know: new Critical alerts, a summary each day, and problems of its own.

Nobody was told anything: a Critical alert, a failed backup or a part that kept stopping were on a page that had
to be open. Now the background worker looks every 30 seconds and

- reports new alerts of the severity in ATDR_NOTIFY_ALERT_SEVERITY. A burst is one notification, and while
  alerts keep coming the next one waits ATDR_NOTIFY_ALERT_MINUTES_BETWEEN;
- writes one summary a day: the alerts since the last one, what is open, and what about ATDR needs attention;
- reports a problem of ATDR's own once it has lasted (a backup that failed, the live feed losing lines, a full
  disk) and reports when it is over. The watcher of ATDR's parts reports through atdr.scripts.notify, which
  does not need the worker;
- sends each notification through every channel that is set up (notification_channels) and tries again when
  a channel fails.

Every notification is kept for the dashboard's bell. Its words are the same in every channel and name no
address: the kind of attack, the severity, the alert's number and the time.
"""

from __future__ import annotations

import json
import shutil
import time
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, time as time_of_day, timedelta, timezone, tzinfo
from pathlib import Path
from typing import Any

from sqlalchemy import and_, delete, func, or_, select, update
from sqlalchemy.orm import Session

from atdr.app.core.config import Settings, get_settings
from atdr.app.core.redaction import IP_PATTERN
from atdr.app.db.models import (
    Alert,
    AuditLog,
    Notification,
    NotificationAlert,
    NotificationCondition,
    NotificationDelivery,
    NotificationSeen,
    NotificationState,
    User,
)
from atdr.app.detection.attack_mapping import ATTACK_LABELS, infer_attack_type_from_rules
from atdr.app.services.alert_service import ALERT_DEDUP_ACTIVE_STATUSES
from atdr.app.services.auto_detection_service import automatic_detection_status
from atdr.app.services.notification_channels import (
    CHANNEL_NAMES,
    CHANNELS,
    SENDERS,
    DeliveryError,
    Message,
    Sender,
    channel_problem,
    channels_on,
    describe_channels,
)
from atdr.app.services.persistence_service import _sqlite_path
from atdr.app.services.scheduled_backup_service import backup_status, failure_words, offsite_folders
from atdr.app.services.syslog_service import live_feed_status
from atdr.app.services.system_status_service import PARTS, RUNTIME, keeping_running_status

# Kinds of notification.
ALERTS, SUMMARY, PROBLEM, RESOLVED, STARTED, TEST = "alerts", "summary", "problem", "resolved", "started", "test"
# Who may see one: everyone signed in, or admins only (ATDR's own problems).
EVERYONE, ADMINS = "all", "admin"
# Who watches a problem, and so who may say that it is over.
WORKER, WATCHER = "worker", "watcher"
PENDING, SENDING, SENT, GAVE_UP = "pending", "sending", "sent", "failed"
ACTOR = "notifications"
NOTIFICATION_SENT, NOTIFICATION_FAILED = "notification_sent", "notification_failed"
STARTED_AT, SUMMARY_SINCE, FEED_LOST = "started_at", "summary_since", "feed_lost"
SYSTEM_PAGE, ALERTS_PAGE = "/data", "/alerts"

# How often the worker looks for something to tell, and how often for problems of ATDR's own.
LOOK_SECONDS = 30.0
PROBLEMS_EVERY_SECONDS = 300.0
# A burst is still arriving while its newest alert is younger than this; nobody waits longer than LONGEST_WAIT.
SETTLE = timedelta(seconds=60)
LONGEST_WAIT = timedelta(minutes=5)
# An alert this young is "new"; an older one has risen to the severity, or could not be reported sooner.
NEW_FOR = timedelta(hours=1)
LISTED_ALERTS = 10
# After a channel fails the next tries come after these minutes, then every hour, until the notification is a day
# old. A failure that only a changed setting can end (a refused sign-in) is not tried again at all.
RETRY_AFTER_MINUTES = (1, 5, 15, 60)
GIVE_UP_AFTER = timedelta(hours=24)
# A delivery claimed by a process that then died is taken up again after this.
CLAIM_EXPIRES = timedelta(minutes=5)
SEND_SECONDS_PER_LOOK = 45.0
KEEP_DAYS = 90
# The live feed counts as losing lines until it has lost none for this long.
LOSING_LINES_FOR = timedelta(minutes=30)
# A user who has never opened the bell is not shown months of notifications as unread.
UNREAD_WITHOUT_A_MARKER = timedelta(hours=24)
SEVERITIES = ("Critical", "High", "Medium", "Low")


@dataclass(frozen=True)
class Problem:
    """Something about ATDR itself that needs attention."""

    key: str
    title: str
    body: str
    # What is said when it is over.
    over: str
    # Urgent: sent out when it is told. Otherwise it is in the bell and in each daily summary.
    urgent: bool = True
    # It is told once it has lasted this long.
    grace: timedelta = timedelta(minutes=5)


def _utc(moment: datetime) -> datetime:
    """A time read from the database, which keeps UTC without saying so."""

    return moment if moment.tzinfo is not None else moment.replace(tzinfo=timezone.utc)


def _now(now: datetime | None) -> datetime:
    """The moment of a look, in UTC: SQLite stores a time's digits as they are, whatever its zone."""

    return _utc(now or datetime.now(timezone.utc)).astimezone(timezone.utc)


def _moment(text: Any) -> datetime | None:
    try:
        return _utc(datetime.fromisoformat(str(text).replace("Z", "+00:00"))) if text else None
    except ValueError:
        return None


def safe_text(text: str) -> str:
    """No address leaves in a notification, whatever a name or a label held."""

    return IP_PATTERN.sub("[address]", text)


def _when(moment: datetime, now: datetime, zone: tzinfo | None) -> str:
    local, today = moment.astimezone(zone), now.astimezone(zone)
    return f"{local:%H:%M}" if local.date() == today.date() else f"{local.day} {local:%b} {local:%H:%M}"


def _lasted(span: timedelta) -> str:
    """How long, to the nearest minute under an hour, the nearest hour under two days, and the nearest day after."""

    minutes = max(1, int(span.total_seconds() // 60))
    if minutes < 60:
        return _counted(minutes, "minute")
    hours = int(minutes / 60 + 0.5)
    return _counted(hours, "hour") if hours < 48 else _counted(int(hours / 24 + 0.5), "day")


def _counted(count: int, noun: str) -> str:
    return f"{count:,} {noun}{'' if count == 1 else 's'}"


def _state(db: Session, key: str) -> str | None:
    row = db.get(NotificationState, key)
    return row.value if row is not None else None


def _set_state(db: Session, key: str, value: str, now: datetime) -> None:
    row = db.get(NotificationState, key)
    if row is None:
        db.add(NotificationState(key=key, value=value, updated_at=now))
    else:
        row.value, row.updated_at = value, now


def _notify(
    db: Session,
    *,
    kind: str,
    level: str,
    title: str,
    body: str = "",
    link: str | None = None,
    audience: str = EVERYONE,
    details: dict[str, Any] | None = None,
    outward: bool,
    settings: Settings,
    now: datetime,
) -> Notification:
    """Writes a notification down for the bell and, when it is to go out, queues it for each channel that is on."""

    row = Notification(kind=kind, level=level, audience=audience, title=safe_text(title)[:255], body=safe_text(body),
                       link=link, details_json=details or {}, created_at=now)
    db.add(row)
    db.flush()
    if outward:
        for channel in channels_on(settings):
            db.add(NotificationDelivery(notification_id=row.id, channel=channel, status=PENDING, attempts=0, created_at=now))
    return row


# ---- Alerts ----


def watched_severities(settings: Settings) -> tuple[str, ...]:
    return ("Critical", "High") if settings.notify_alert_severity.strip().lower() == "high" else ("Critical",)


def _unreported(settings: Settings) -> Any:
    return and_(
        Alert.severity.in_(watched_severities(settings)),
        Alert.status.in_(ALERT_DEDUP_ACTIVE_STATUSES),
        Alert.id.not_in(select(NotificationAlert.alert_id)),
    )


def cover_alerts(db: Session, *, settings: Settings | None = None, now: datetime | None = None) -> int:
    """Marks every alert that would be reported as reported, without reporting it.

    For alerts that are not news: those on the list when reporting begins, and those a rebuild or a reset raises.
    """

    settings = settings or get_settings()
    now = _now(now)
    ids = list(db.scalars(select(Alert.id).where(_unreported(settings))))
    db.add_all(NotificationAlert(alert_id=alert_id, notification_id=None, created_at=now) for alert_id in ids)
    db.flush()
    return len(ids)


def _attack(alert: Alert) -> str:
    label = ATTACK_LABELS.get(infer_attack_type_from_rules(alert.matched_rules_json or []), "unclassified")
    return f"{label} (experimental)" if alert.alert_type == "mfu_behavior_model" else label


def _alert_words(alerts: list[Alert], *, now: datetime, zone: tzinfo | None) -> tuple[str, str]:
    new = "new " if all(now - _utc(alert.created_at) <= NEW_FOR for alert in alerts) else ""
    if len(alerts) == 1:
        alert = alerts[0]
        return (f"{new.capitalize()}{alert.severity} alert #{alert.id}: {_attack(alert)}",
                f"Raised {_when(_utc(alert.created_at), now, zone)}.")
    counts = Counter(alert.severity for alert in alerts)
    if len(counts) == 1:
        title = f"{len(alerts)} {new}{alerts[0].severity} alerts"
    else:
        title = f"{len(alerts)} {new}alerts: {', '.join(f'{counts[name]} {name}' for name in SEVERITIES if counts[name])}"
    lines = [f"#{alert.id} {alert.severity}: {_attack(alert)}, raised {_when(_utc(alert.created_at), now, zone)}"
             for alert in alerts[:LISTED_ALERTS]]
    if len(alerts) > LISTED_ALERTS:
        lines.append(f"and {len(alerts) - LISTED_ALERTS} more")
    return title, "\n".join(lines)


def raise_alert_notification(db: Session, *, settings: Settings, now: datetime, zone: tzinfo | None = None) -> Notification | None:
    """One notification for every alert not yet reported, once the burst has ended and the last one is old enough."""

    alerts = list(db.scalars(select(Alert).where(_unreported(settings)).order_by(Alert.id)))
    if not alerts:
        return None
    raised = [_utc(alert.created_at) for alert in alerts]
    # More may be coming: a detection run raises its alerts over seconds or minutes.
    if now - max(raised) < SETTLE and timedelta(0) <= now - min(raised) < LONGEST_WAIT:
        return None
    last = db.scalar(select(func.max(Notification.created_at)).where(Notification.kind == ALERTS))
    if last is not None and now - _utc(last) < timedelta(minutes=max(0, int(settings.notify_alert_minutes_between))):
        return None
    title, body = _alert_words(alerts, now=now, zone=zone)
    made = _notify(
        db, kind=ALERTS, level="critical", title=title, body=body, settings=settings, now=now, outward=True,
        link=f"{ALERTS_PAGE}?alert={alerts[0].id}" if len(alerts) == 1 else ALERTS_PAGE,
        details={"count": len(alerts),
                 "alerts": [{"id": alert.id, "severity": alert.severity, "attack": _attack(alert)} for alert in alerts[:LISTED_ALERTS]]},
    )
    db.add_all(NotificationAlert(alert_id=alert.id, notification_id=made.id, created_at=now) for alert in alerts)
    return made


def _summary_time(settings: Settings) -> time_of_day | None:
    text = settings.notify_summary_at.strip()
    if not text:
        return None
    try:
        return datetime.strptime(text, "%H:%M").time()
    except ValueError:
        return None


def _begin(db: Session, *, settings: Settings, now: datetime) -> Notification | None:
    """The first look: what is already on the list is not news."""

    if _state(db, STARTED_AT) is not None:
        return None
    covered = cover_alerts(db, settings=settings, now=now)
    _set_state(db, STARTED_AT, now.isoformat(), now)
    _set_state(db, SUMMARY_SINCE, now.isoformat(), now)
    names = " and ".join(reversed(watched_severities(settings)))
    said = [f"ATDR reports new {names} alerts here from now on, and problems of its own."]
    daily = _summary_time(settings)
    if daily is not None:
        said.append(f"A summary of everything else comes each day at {daily:%H:%M}.")
    if covered:
        said.append(f"The {_counted(covered, f'{names} alert')} already on the list {'is' if covered == 1 else 'are'} not reported again.")
    return _notify(db, kind=STARTED, level="info", title="Notifications are on", body=" ".join(said),
                   settings=settings, now=now, outward=False, details={"covered": covered})


# ---- The daily summary ----


def _summary_due(settings: Settings, *, since: datetime, now: datetime, zone: tzinfo | None) -> bool:
    daily = _summary_time(settings)
    if daily is None:
        return False
    local = now.astimezone(zone)
    today = local.replace(hour=daily.hour, minute=daily.minute, second=0, microsecond=0)
    # Today's time has come, and no summary has gone since it did.
    return local >= today and since.astimezone(zone) < today


def raise_summary(db: Session, *, settings: Settings, now: datetime, zone: tzinfo | None = None) -> Notification | None:
    since = _moment(_state(db, SUMMARY_SINCE))
    if since is None or not _summary_due(settings, since=since, now=now, zone=zone):
        return None
    new = dict(db.execute(select(Alert.severity, func.count()).where(Alert.created_at > since).group_by(Alert.severity)).all())
    total = sum(int(count) for count in new.values())
    by_severity = ", ".join(f"{int(new[name])} {name}" for name in SEVERITIES if new.get(name))
    open_now = dict(db.execute(
        select(Alert.severity, func.count()).where(Alert.status.in_(ALERT_DEDUP_ACTIVE_STATUSES)).group_by(Alert.severity)
    ).all())
    open_total, open_critical = sum(int(count) for count in open_now.values()), int(open_now.get("Critical") or 0)
    waiting = list(db.scalars(
        select(NotificationCondition).where(NotificationCondition.announced_at.is_not(None)).order_by(NotificationCondition.since)
    ))
    lines = [f"Since {_when(since, now, zone)}: " + (f"{_counted(total, 'new alert')} ({by_severity})." if total else "no new alerts.")]
    lines.append(f"Open now: {_counted(open_total, 'alert')}, {open_critical} of them Critical." if open_total else "Open now: no alerts.")
    if waiting:
        lines.append("Needs attention:")
        lines.extend(f"- {row.title}" for row in waiting)
    else:
        lines.append("Nothing about ATDR itself needs attention.")
    title = f"Daily summary: {_counted(total, 'new alert') if total else 'no new alerts'}"
    if waiting:
        title += f", {_counted(len(waiting), 'thing')} about ATDR need{'s' if len(waiting) == 1 else ''} attention"
    _set_state(db, SUMMARY_SINCE, now.isoformat(), now)
    return _notify(db, kind=SUMMARY, level="info", title=title, body="\n".join(lines), link=ALERTS_PAGE, settings=settings,
                   now=now, outward=True, details={"new": {name: int(new.get(name) or 0) for name in SEVERITIES},
                                                   "open": open_total, "open_critical": open_critical,
                                                   "needs_attention": [row.key for row in waiting]})


# ---- Problems of ATDR's own ----


def _free_gb(folder: Path) -> float:
    return shutil.disk_usage(folder).free / 1024**3


def _backup_problems(db: Session, settings: Settings, now: datetime, find_offsite: Callable[..., Any]) -> list[Problem]:
    status = backup_status(db, settings=settings, now=now, find_offsite=find_offsite)
    if not status["scheduled"]:
        return []
    found = []
    if status["last_failure"] is not None:
        found.append(Problem(
            "backup_failed", "ATDR could not back up its database",
            f"The last try failed: {failure_words(status['last_failure']['status'])}. ATDR tries again every hour.",
            over="ATDR backs its database up again.", grace=timedelta(0),
        ))
    offsite = status["offsite"]
    if offsite["wanted"] and offsite["last_failure"] is not None:
        found.append(Problem(
            "backup_copy_failed", "The backup could not be copied to the other disk",
            f"Copying to drive {offsite['last_failure']['drive']} failed: {failure_words(offsite['last_failure']['status'])}.",
            over="The backup is copied to the other disk again.", urgent=False,
        ))
    elif offsite["wanted"] and offsite["stale"]:
        connect = f"Connect a drive that has a folder named {offsite['folder_name']} at its top; ATDR copies the newest backup to it."
        if offsite["last_copy"] is None:
            title, body = "No copy of the backups is on another disk", f"Every backup is on the disk the database is on. {connect}"
        else:
            title = f"The copy of the backups on another disk is {int(offsite['last_copy']['age_days'])} days old"
            body = connect
        found.append(Problem("backup_copy_old", title, body, over="A copy of the newest backup is on another disk.", urgent=False))
    return found


def _feed_problems(db: Session, settings: Settings, now: datetime) -> list[Problem]:
    if not settings.syslog_enabled:
        return []
    feed = live_feed_status(db, settings=settings, now=now)
    if feed["state"] != "receiving":
        return [Problem(
            "feed_not_running", "The live log feed is not running",
            "ATDR is set to receive the firewall's logs, but its receiver is not running. Logs sent meanwhile are lost.",
            over="The live log feed is running again.", grace=timedelta(minutes=3),
        )]
    found = []
    if feed["disk_low"]:
        found.append(Problem(
            "feed_disk_full", "The live log feed stopped saving: the disk is almost full",
            f"The feed saves nothing while fewer than {feed['min_free_disk_gb']:g} GB are free. "
            f"{_counted(int(feed['dropped_disk_low']), 'line')} were lost so far.",
            over="The live log feed saves logs again.", grace=timedelta(0),
        ))
    # Lines lost: the count only grows, so what matters is when it last grew.
    try:
        lost = json.loads(_state(db, FEED_LOST) or "{}")
    except ValueError:
        lost = {}
    dropped = int(feed["dropped"])
    if lost.get("run") != feed["started_at"]:
        lost = {"run": feed["started_at"], "dropped": 0, "at": None}
    if dropped > int(lost.get("dropped") or 0):
        lost = {"run": feed["started_at"], "dropped": dropped, "at": now.isoformat()}
    _set_state(db, FEED_LOST, json.dumps(lost), now)
    grew = _moment(lost.get("at"))
    if grew is not None and now - grew < LOSING_LINES_FOR:
        found.append(Problem(
            "feed_losing_lines", "The live log feed is losing lines",
            f"{_counted(dropped, 'line')} could not be saved since the feed started: they arrive faster than ATDR saves them.",
            over="The live log feed no longer loses lines.", grace=timedelta(0),
        ))
    silent_after = int(settings.notify_feed_silent_minutes)
    received = _moment(feed["last_received_at"]) or _moment(feed["started_at"])
    if silent_after > 0 and received is not None and now - received >= timedelta(minutes=silent_after):
        found.append(Problem(
            "feed_silent", f"No log has arrived from the firewall for {silent_after} minutes",
            "The live log feed is running but receives nothing. Check that the firewall still sends its logs to this machine.",
            over="Logs arrive from the firewall again.", grace=timedelta(0),
        ))
    return found


def worker_problems(
    db: Session,
    *,
    settings: Settings,
    now: datetime,
    runtime: Path = RUNTIME,
    find_offsite: Callable[..., Any] = offsite_folders,
) -> list[Problem]:
    """What needs attention now, of the things the worker can see."""

    found = _backup_problems(db, settings, now, find_offsite) + _feed_problems(db, settings, now)
    database = _sqlite_path(settings.database_url)
    floor = float(settings.notify_disk_free_gb)
    if database is not None and floor > 0 and database.parent.is_dir():
        free = _free_gb(database.parent)
        if free < floor:
            found.append(Problem(
                "disk_low", "The disk ATDR's database is on is almost full",
                f"{free:.1f} GB are free. ATDR tells when fewer than {floor:g} GB are.",
                over="The disk ATDR's database is on has room again.", grace=timedelta(0),
            ))
    checks = automatic_detection_status(db, settings=settings, now=now)
    if checks["enabled"] and checks["last_check"] is not None and checks["last_check"]["status"] == "failed":
        found.append(Problem(
            "detection_failed", "ATDR's automatic check of new logs failed",
            "The last automatic check ended in an error, so new logs are not being checked. "
            "The job list on Data & Detection has the error.",
            over="ATDR checks new logs by itself again.", grace=timedelta(minutes=10),
        ))
    keep = keeping_running_status(now=now, runtime=runtime)
    if keep["meant_to_be"] == "running" and not keep["watching"]:
        found.append(Problem(
            "watcher_not_running", "Nothing is watching ATDR's parts",
            "A part that stops stays stopped until someone starts ATDR again. Run scripts\\autostart.cmd once on this machine.",
            over="ATDR's parts are watched again.", urgent=False, grace=timedelta(minutes=10),
        ))
    return found


def part_problem(name: str) -> Problem:
    """A part the watcher keeps having to start."""

    label = PARTS.get(name, (name, name))[1]
    words = label[4:] if label.startswith("the ") else label
    return Problem(
        f"part_keeps_stopping:{name}", f"ATDR's {words} keeps stopping",
        "ATDR started it three times in ten minutes and now tries once every five. Its log in .atdr_runtime\\logs says why it stops.",
        over=f"ATDR's {words} is running again.", grace=timedelta(0),
    )


NOT_STARTING = Problem(
    "atdr_not_starting", "ATDR could not be started",
    "The watcher found no part of ATDR running, tried to start it, and the start failed. "
    "Run scripts\\check_system.cmd on the machine to see why.",
    over="ATDR is running again.", grace=timedelta(0),
)


def track_problems(
    db: Session,
    problems: list[Problem],
    *,
    source: str,
    settings: Settings,
    now: datetime,
    zone: tzinfo | None = None,
    only: set[str] | None = None,
) -> list[Notification]:
    """Tells each problem once it has lasted its time, and each told problem once more when it is over.

    `problems` is everything this source sees now; a problem of its own that is not among them is over. With
    `only`, the source speaks about those keys alone and the rest are left as they are.
    """

    rows = {row.key: row for row in db.scalars(select(NotificationCondition).where(NotificationCondition.source == source))}
    if only is not None:
        rows = {key: row for key, row in rows.items() if key in only}
    made = []
    for problem in problems:
        row = rows.pop(problem.key, None)
        if row is None:
            row = NotificationCondition(key=problem.key, source=source, urgent=problem.urgent, since=now, last_seen_at=now,
                                        title="", body="", over="", details_json={})
            db.add(row)
        row.last_seen_at = now
        if row.announced_at is None:
            # Until it is told, its words follow what is seen: "no copy yet" can become "the copy is 8 days old".
            row.title, row.body, row.over, row.urgent = safe_text(problem.title)[:255], safe_text(problem.body), safe_text(problem.over)[:255], problem.urgent
            if now - _utc(row.since) >= problem.grace:
                row.announced_at = now
                made.append(_notify(db, kind=PROBLEM, level="warning" if row.urgent else "info", audience=ADMINS, title=row.title,
                                    body=row.body, link=SYSTEM_PAGE, details={"key": row.key}, outward=row.urgent,
                                    settings=settings, now=now))
    for row in rows.values():
        if row.announced_at is not None:
            began = _utc(row.since)
            made.append(_notify(db, kind=RESOLVED, level="info", audience=ADMINS, title=row.over,
                                body=f"It began {_when(began, now, zone)} and lasted {_lasted(now - began)}.", link=SYSTEM_PAGE,
                                details={"key": row.key}, outward=row.urgent, settings=settings, now=now))
        db.delete(row)
    return made


# ---- Sending ----


def _retry_at(attempts: int, now: datetime) -> datetime:
    return now + timedelta(minutes=RETRY_AFTER_MINUTES[min(attempts, len(RETRY_AFTER_MINUTES)) - 1])


def deliver_pending(
    db: Session,
    *,
    settings: Settings,
    now: datetime,
    senders: dict[str, Sender] | None = None,
    still_alive: Callable[[], None] | None = None,
    only: int | None = None,
) -> list[dict[str, Any]]:
    """Sends what is waiting. Each delivery is claimed first, so two processes never send the same one."""

    senders = SENDERS if senders is None else senders
    due = or_(
        and_(NotificationDelivery.status == PENDING,
             or_(NotificationDelivery.next_attempt_at.is_(None), NotificationDelivery.next_attempt_at <= now)),
        and_(NotificationDelivery.status == SENDING, NotificationDelivery.claimed_at <= now - CLAIM_EXPIRES),
    )
    query = select(NotificationDelivery.id).where(due).order_by(NotificationDelivery.id).limit(50)
    if only is not None:
        query = query.where(NotificationDelivery.notification_id == only)
    done = []
    started = time.monotonic()
    for delivery_id in list(db.scalars(query)):
        if time.monotonic() - started >= SEND_SECONDS_PER_LOOK:
            break
        claimed = db.execute(
            update(NotificationDelivery).where(NotificationDelivery.id == delivery_id, due)
            .values(status=SENDING, claimed_at=now, attempts=NotificationDelivery.attempts + 1)
            .execution_options(synchronize_session=False)
        )
        db.commit()
        if not claimed.rowcount:
            continue
        delivery = db.get(NotificationDelivery, delivery_id)
        db.refresh(delivery)
        notification = db.get(Notification, delivery.notification_id)
        if still_alive is not None:
            still_alive()
        error = None
        sender = senders.get(delivery.channel)
        if notification is None or sender is None or channel_problem(settings, delivery.channel) is not None:
            # The channel was switched off, or the notification deleted, since this was queued.
            db.delete(delivery)
            db.commit()
            continue
        note = None
        again = True
        try:
            note = sender(settings, Message(title=notification.title, body=notification.body, link=notification.link))
        except DeliveryError as failure:
            error, again = str(failure), failure.again
        except Exception as failure:  # a sender must never stop the worker; its class says enough
            error = f"sending failed ({failure.__class__.__name__})"
        if error is None:
            # A note is kept where an error would be: delivered, with something to say about it.
            delivery.status, delivery.sent_at, delivery.next_attempt_at = SENT, now, None
            delivery.error = safe_text(str(note))[:255] if note else None
            db.add(AuditLog(actor=ACTOR, action=NOTIFICATION_SENT, target_type="notification", target_value=str(notification.id),
                            details={"channel": delivery.channel, "kind": notification.kind, "title": notification.title},
                            created_at=now))
        elif not again or now - _utc(notification.created_at) >= GIVE_UP_AFTER:
            # Given up: a day of tries, or a refusal that only a changed setting can end.
            delivery.status, delivery.error = GAVE_UP, safe_text(error)[:255]
            db.add(AuditLog(actor=ACTOR, action=NOTIFICATION_FAILED, target_type="notification", target_value=str(notification.id),
                            details={"channel": delivery.channel, "kind": notification.kind, "error": delivery.error,
                                     "attempts": delivery.attempts}, created_at=now))
        else:
            delivery.status, delivery.error = PENDING, safe_text(error)[:255]
            delivery.next_attempt_at = _retry_at(delivery.attempts, now)
        db.commit()
        done.append({"notification_id": notification.id, "channel": delivery.channel, "ok": error is None, "error": error,
                     "note": delivery.error if error is None else None})
    return done


# ---- The look ----


def _prune(db: Session, now: datetime) -> None:
    old = select(Notification.id).where(Notification.created_at < now - timedelta(days=KEEP_DAYS))
    db.execute(delete(NotificationDelivery).where(NotificationDelivery.notification_id.in_(old)))
    db.execute(delete(Notification).where(Notification.created_at < now - timedelta(days=KEEP_DAYS)))


def notification_look(
    db: Session,
    *,
    settings: Settings | None = None,
    now: datetime | None = None,
    zone: tzinfo | None = None,
    senders: dict[str, Sender] | None = None,
    runtime: Path = RUNTIME,
    find_offsite: Callable[..., Any] = offsite_folders,
    problems: bool = True,
    still_alive: Callable[[], None] | None = None,
) -> dict[str, Any]:
    """What the worker does at each look: finds what is new, writes it down, and sends what is waiting."""

    settings = settings or get_settings()
    now = _now(now)
    if not settings.notify_enabled:
        return {"enabled": False, "made": [], "sent": []}
    made = [_begin(db, settings=settings, now=now)]
    db.commit()
    made.append(raise_alert_notification(db, settings=settings, now=now, zone=zone))
    if problems:
        found = worker_problems(db, settings=settings, now=now, runtime=runtime, find_offsite=find_offsite)
        made.extend(track_problems(db, found, source=WORKER, settings=settings, now=now, zone=zone))
        _prune(db, now)
    made.append(raise_summary(db, settings=settings, now=now, zone=zone))
    db.commit()
    sent = deliver_pending(db, settings=settings, now=now, senders=senders, still_alive=still_alive)
    return {"enabled": True, "made": [{"id": row.id, "kind": row.kind, "title": row.title} for row in made if row is not None], "sent": sent}


def report_problem(
    db: Session,
    problem: Problem,
    *,
    over: bool = False,
    source: str = WATCHER,
    settings: Settings | None = None,
    now: datetime | None = None,
    senders: dict[str, Sender] | None = None,
) -> dict[str, Any]:
    """One problem reported from outside the worker, or reported over, and sent at once: the worker may be what stopped."""

    settings = settings or get_settings()
    now = _now(now)
    if not settings.notify_enabled:
        return {"enabled": False, "made": [], "sent": []}
    made = track_problems(db, [] if over else [problem], source=source, settings=settings, now=now, only={problem.key})
    db.commit()
    sent = []
    for row in made:
        sent.extend(deliver_pending(db, settings=settings, now=now, senders=senders, only=row.id))
    return {"enabled": True, "made": [{"id": row.id, "kind": row.kind, "title": row.title} for row in made], "sent": sent}


def send_test(
    db: Session,
    channel: str,
    *,
    actor: str,
    settings: Settings | None = None,
    now: datetime | None = None,
    zone: tzinfo | None = None,
    senders: dict[str, Sender] | None = None,
) -> dict[str, Any]:
    """One test message through one channel, now, with what happened in words."""

    settings = settings or get_settings()
    now = _now(now)
    if channel not in CHANNELS:
        return {"ok": False, "channel": channel, "words": "ATDR has no such channel."}
    off = channel_problem(settings, channel)
    if off is not None:
        return {"ok": False, "channel": channel, "words": f"{CHANNEL_NAMES[channel]} is not set up: {off}."}
    row = Notification(kind=TEST, level="info", audience=ADMINS, title="Test message from ATDR",
                       body=f"{actor} asked for this test at {_when(now, now, zone)}. A real notification looks like this one.",
                       link=SYSTEM_PAGE, details_json={"channel": channel, "actor": actor}, created_at=now)
    db.add(row)
    db.flush()
    db.add(NotificationDelivery(notification_id=row.id, channel=channel, status=PENDING, attempts=0, created_at=now))
    db.commit()
    sent = deliver_pending(db, settings=settings, now=now, senders=senders, only=row.id)
    result = sent[0] if sent else {"ok": False, "error": "nothing was sent"}
    if not result["ok"]:
        # A test is not tried again later, and is not kept: the person who asked is told now.
        db.execute(delete(NotificationDelivery).where(NotificationDelivery.notification_id == row.id))
        db.execute(delete(Notification).where(Notification.id == row.id))
        db.commit()
        return {"ok": False, "channel": channel, "words": f"{CHANNEL_NAMES[channel]} failed: {result['error']}."}
    said = f"{CHANNEL_NAMES[channel]} sent, but {result['note']}." if result.get("note") else f"{CHANNEL_NAMES[channel]} sent."
    return {"ok": True, "channel": channel, "words": said}


# ---- The bell and the System panel ----


def _visible(user: User) -> Any:
    return Notification.audience.in_((EVERYONE, ADMINS) if user.role == "admin" else (EVERYONE,))


def _seen_id(db: Session, user: User, now: datetime) -> int:
    marker = db.get(NotificationSeen, user.id)
    if marker is not None:
        return int(marker.seen_id)
    older = db.scalar(select(func.max(Notification.id)).where(Notification.created_at < now - UNREAD_WITHOUT_A_MARKER))
    return int(older or 0)


def notifications_for(db: Session, user: User, *, limit: int = 30, now: datetime | None = None) -> dict[str, Any]:
    now = _now(now)
    seen = _seen_id(db, user, now)
    rows = list(db.scalars(select(Notification).where(_visible(user)).order_by(Notification.id.desc()).limit(max(1, min(int(limit), 100)))))
    unread = int(db.scalar(select(func.count()).select_from(Notification).where(_visible(user), Notification.id > seen)) or 0)
    return {
        "unread": unread,
        "newest_id": rows[0].id if rows else 0,
        "items": [{
            "id": row.id, "kind": row.kind, "level": row.level, "title": row.title, "body": row.body, "link": row.link,
            "created_at": _utc(row.created_at), "unread": row.id > seen,
            "alerts": [{"id": int(alert["id"]), "severity": str(alert["severity"]), "attack": str(alert["attack"])}
                       for alert in (row.details_json or {}).get("alerts") or []],
        } for row in rows],
    }


def mark_seen(db: Session, user: User, up_to: int, *, now: datetime | None = None) -> int:
    now = _now(now)
    newest = int(db.scalar(select(func.max(Notification.id))) or 0)
    up_to = max(0, min(int(up_to), newest))
    marker = db.get(NotificationSeen, user.id)
    if marker is None:
        db.add(NotificationSeen(user_id=user.id, seen_id=up_to, updated_at=now))
    elif up_to > marker.seen_id:
        marker.seen_id, marker.updated_at = up_to, now
    db.commit()
    return up_to


def notification_status(db: Session, *, settings: Settings | None = None, now: datetime | None = None) -> dict[str, Any]:
    """What the System panel shows about notifications."""

    settings = settings or get_settings()
    now = _now(now)
    channels = describe_channels(settings)
    for channel, described in channels.items():
        sent = db.scalar(select(func.max(NotificationDelivery.sent_at)).where(
            NotificationDelivery.channel == channel, NotificationDelivery.status == SENT))
        # What happened to the last message tried through the channel: a failure counts until a later one goes out.
        latest = db.scalar(
            select(NotificationDelivery).where(NotificationDelivery.channel == channel, NotificationDelivery.attempts > 0)
            .order_by(NotificationDelivery.claimed_at.desc(), NotificationDelivery.id.desc()).limit(1)
        )
        described["last_sent_at"] = _utc(sent) if sent is not None else None
        described["last_failure"] = None if latest is None or latest.error is None else {
            "at": _utc(latest.claimed_at), "words": latest.error, "gave_up": latest.status == GAVE_UP,
            # Delivered to some: the words say what was wrong with the rest.
            "delivered": latest.status == SENT,
        }
    daily = _summary_time(settings)
    waiting = list(db.scalars(
        select(NotificationCondition).where(NotificationCondition.announced_at.is_not(None)).order_by(NotificationCondition.since)
    ))
    return {
        "enabled": bool(settings.notify_enabled),
        "alert_severities": list(watched_severities(settings)),
        "minutes_between": max(0, int(settings.notify_alert_minutes_between)),
        "summary_at": f"{daily:%H:%M}" if daily is not None else None,
        "summary_setting_wrong": bool(settings.notify_summary_at.strip()) and daily is None,
        "started_at": _moment(_state(db, STARTED_AT)),
        "channels": channels,
        "needs_attention": [{"key": row.key, "title": row.title, "since": _utc(row.since), "urgent": bool(row.urgent)} for row in waiting],
    }
