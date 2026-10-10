"""ATDR tells people about new Critical alerts, sends a summary each day, and reports problems of its own.

Nobody was told anything: a Critical alert, a failed backup or a part that kept stopping were on a page that had
to be open.
"""

from __future__ import annotations

import json
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session, sessionmaker

from atdr.app.core.config import Settings
from atdr.app.db.database import Base
from atdr.app.db.models import (
    Alert,
    AuditLog,
    IngestionRun,
    Notification,
    NotificationAlert,
    NotificationCondition,
    NotificationDelivery,
    OperationJob,
    User,
)
from atdr.app.services import notification_service as notify
from atdr.app.services import operation_worker
from atdr.app.services.auto_detection_service import AUTO_DETECTION_ACTOR
from atdr.app.services.notification_channels import DeliveryError, Message
from atdr.app.services.notification_service import (
    Problem,
    cover_alerts,
    deliver_pending,
    mark_seen,
    notification_look,
    notification_status,
    notifications_for,
    part_problem,
    report_problem,
    send_test,
    track_problems,
)
from atdr.app.services.syslog_service import SOURCE_TYPE as SYSLOG

BANGKOK = timezone(timedelta(hours=7))
# Friday 9 October 2026, 10:00 in Bangkok.
START = datetime(2026, 10, 9, 3, 0, tzinfo=timezone.utc)
MINUTE, HOUR, DAY = timedelta(minutes=1), timedelta(hours=1), timedelta(days=1)
NO_DRIVE = lambda _settings: []  # noqa: E731
CHAT_ADDRESS = "https://chat.example.org/hook/secret-token"
C2 = [{"code": "paloalto_malware_threat", "attack_type": "malware_c2"}]
SCAN = [{"code": "possible_port_scan", "attack_type": "port_scan"}]


def _system(tmp_path: Path, **overrides) -> tuple[Settings, Session]:
    """A database, and settings with email and chat set up. Nothing here comes from the machine the tests run on."""

    database = tmp_path / "atdr.db"
    database.parent.mkdir(parents=True, exist_ok=True)
    engine = create_engine(f"sqlite:///{database.as_posix()}", future=True)
    Base.metadata.create_all(engine)
    settings = Settings(_env_file=None, **{
        "DATABASE_URL": f"sqlite:///{database.as_posix()}",
        "ATDR_NOTIFY_WINDOWS": False,
        "ATDR_NOTIFY_EMAIL_TO": "soc@example.org, lead@example.org",
        "SMTP_HOST": "mail.example.org",
        "SMTP_FROM_EMAIL": "atdr@example.org",
        "ATDR_NOTIFY_CHAT_WEBHOOK_URL": CHAT_ADDRESS,
        "ATDR_NOTIFY_SUMMARY_AT": "",
        "ATDR_NOTIFY_DISK_FREE_GB": 0,
        "ATDR_BACKUP_SCHEDULE_HOURS": 0,
        "AUTO_DETECTION_ENABLED": False,
        "SYSLOG_ENABLED": False,
        **overrides,
    })
    return settings, sessionmaker(bind=engine, future=True)()


def _with(settings: Settings, **overrides) -> Settings:
    return Settings(_env_file=None, **{**settings.model_dump(by_alias=True), **overrides})


class _Outbox:
    """Senders that keep what they were given instead of sending it."""

    def __init__(self, failing: dict[str, Exception] | None = None, notes: dict[str, str] | None = None) -> None:
        self.sent: list[tuple[str, Message]] = []
        self.failing = failing or {}
        self.notes = notes or {}

    def senders(self) -> dict:
        def sender(channel: str):
            def send(_settings: Settings, message: Message) -> str | None:
                if channel in self.failing:
                    raise self.failing[channel]
                self.sent.append((channel, message))
                return self.notes.get(channel)
            return send
        return {channel: sender(channel) for channel in ("windows", "email", "chat")}

    def titles(self, channel: str = "email") -> list[str]:
        return [message.title for sent_by, message in self.sent if sent_by == channel]


def _look(db: Session, settings: Settings, when: datetime, outbox: _Outbox | None = None, **kwargs) -> dict:
    return notification_look(db, settings=settings, now=when, zone=BANGKOK, senders=(outbox or _Outbox()).senders(),
                             runtime=kwargs.pop("runtime", Path("no-such-folder")), find_offsite=NO_DRIVE, **kwargs)


def _alert(db: Session, when: datetime, *, severity: str = "Critical", rules: list | None = None, status: str = "open",
           alert_type: str = "paloalto_malware_threat") -> Alert:
    alert = Alert(title="Critical: malware download from 10.20.30.40", alert_type=alert_type, src_ip="10.20.30.40", threat_score=95,
                  severity=severity, status=status, explanation="seen from 10.20.30.40", matched_rules_json=C2 if rules is None else rules,
                  recommended_response="look", created_at=when, updated_at=when)
    db.add(alert)
    db.commit()
    return alert


def _kinds(db: Session) -> list[str]:
    return list(db.scalars(select(Notification.kind).order_by(Notification.id)))


def _last(db: Session, kind: str | None = None) -> Notification:
    query = select(Notification).order_by(Notification.id.desc()).limit(1)
    return db.scalar(query.where(Notification.kind == kind) if kind else query)


def _audit(db: Session, action: str) -> list[AuditLog]:
    return list(db.scalars(select(AuditLog).where(AuditLog.action == action).order_by(AuditLog.id)))


def test_what_is_already_on_the_list_is_not_news(tmp_path):
    settings, db = _system(tmp_path, ATDR_NOTIFY_SUMMARY_AT="08:00")
    for severity in ("Critical", "Critical", "High"):
        _alert(db, START - DAY, severity=severity)
    outbox = _Outbox()

    first = _look(db, settings, START, outbox)
    assert [made["kind"] for made in first["made"]] == ["started"] and first["sent"] == []
    began = _last(db)
    assert (began.title, began.audience, began.level) == ("Notifications are on", "all", "info")
    assert began.body == ("ATDR reports new Critical alerts here from now on, and problems of its own. "
                          "A summary of everything else comes each day at 08:00. "
                          "The 2 Critical alerts already on the list are not reported again.")
    assert db.scalar(select(func.count()).select_from(NotificationDelivery)) == 0, "it goes to the bell only"
    assert sorted(db.scalars(select(NotificationAlert.alert_id))) == [1, 2]

    assert _look(db, settings, START + HOUR, outbox)["made"] == [] and outbox.sent == []
    assert _kinds(db) == ["started"], "said once"

    # One alert on the list reads "The 1 Critical alert ... is not reported again."; with none the sentence is left out.
    other, other_db = _system(tmp_path / "other")
    _look(other_db, other, START)
    assert _last(other_db).body == "ATDR reports new Critical alerts here from now on, and problems of its own."


def test_a_new_critical_alert_is_one_message_on_every_channel_that_is_set_up(tmp_path):
    settings, db = _system(tmp_path)
    outbox = _Outbox()
    _look(db, settings, START, outbox)
    alert = _alert(db, START + MINUTE)

    # More may be coming while it is under a minute old.
    assert _look(db, settings, START + MINUTE + timedelta(seconds=59), outbox)["made"] == []
    done = _look(db, settings, START + MINUTE * 2, outbox)
    assert done["made"] == [{"id": 2, "kind": "alerts", "title": "New Critical alert #1: malware / C2"}]
    assert [(sent["channel"], sent["ok"]) for sent in done["sent"]] == [("email", True), ("chat", True)]
    told = _last(db)
    assert (told.level, told.audience, told.body, told.link) == ("critical", "all", "Raised 10:01.", f"/alerts?alert={alert.id}")
    assert told.details_json == {"count": 1, "alerts": [{"id": 1, "severity": "Critical", "attack": "malware / C2"}]}
    assert outbox.sent == [(channel, Message(title="New Critical alert #1: malware / C2", body="Raised 10:01.", link="/alerts?alert=1"))
                           for channel in ("email", "chat")]
    assert [(entry.target_value, entry.details["channel"], entry.details["kind"]) for entry in _audit(db, "notification_sent")] == [
        ("2", "email", "alerts"), ("2", "chat", "alerts")]

    # Reported once.
    assert _look(db, settings, START + HOUR * 3, outbox)["made"] == [] and len(outbox.sent) == 2


def test_a_burst_is_one_message_and_nobody_waits_longer_than_five_minutes_for_it_to_end(tmp_path):
    settings, db = _system(tmp_path)
    outbox = _Outbox()
    _look(db, settings, START, outbox)
    for seconds in (0, 50, 100):
        _alert(db, START + timedelta(seconds=seconds), rules=SCAN if seconds == 50 else C2)

    assert _look(db, settings, START + timedelta(seconds=130), outbox)["made"] == [], "the newest is 30 seconds old"
    assert _look(db, settings, START + timedelta(seconds=160), outbox)["made"][0]["title"] == "3 new Critical alerts"
    assert _last(db).body == ("#1 Critical: malware / C2, raised 10:00\n#2 Critical: port scan, raised 10:00\n"
                              "#3 Critical: malware / C2, raised 10:01")
    assert _last(db).link == "/alerts" and outbox.titles() == ["3 new Critical alerts"]

    # Alerts that never stop arriving: the message goes once the oldest has waited five minutes.
    later = START + HOUR
    for seconds in range(0, 330, 30):
        _alert(db, later + timedelta(seconds=seconds))
        made = _look(db, settings, later + timedelta(seconds=seconds + 1), outbox)["made"]
        assert bool(made) is (seconds == 300), seconds
    assert outbox.titles()[-1] == "11 new Critical alerts"
    assert _last(db).body.splitlines()[-2:] == ["#13 Critical: malware / C2, raised 11:04", "and 1 more"], "ten are listed"
    assert _last(db).details_json["count"] == 11 and len(_last(db).details_json["alerts"]) == 10
    assert db.scalar(select(func.count()).select_from(NotificationAlert)) == 14, "all of them count as reported, listed or not"


def test_while_alerts_keep_coming_the_next_message_waits_half_an_hour(tmp_path):
    settings, db = _system(tmp_path)
    outbox = _Outbox()
    _look(db, settings, START, outbox)
    _alert(db, START)
    assert _look(db, settings, START + MINUTE, outbox)["made"]
    _alert(db, START + MINUTE * 5)
    _alert(db, START + MINUTE * 20, rules=SCAN)

    assert _look(db, settings, START + MINUTE * 30 + timedelta(seconds=59), outbox)["made"] == []
    assert _look(db, settings, START + MINUTE * 31, outbox)["made"][0]["title"] == "2 new Critical alerts"
    assert outbox.titles() == ["New Critical alert #1: malware / C2", "2 new Critical alerts"]

    # The time is a setting; 0 sends each burst as it ends.
    at_once = _with(settings, ATDR_NOTIFY_ALERT_MINUTES_BETWEEN=0)
    _alert(db, START + MINUTE * 32)
    assert _look(db, at_once, START + MINUTE * 33, outbox)["made"]


def test_only_the_severity_that_was_asked_for_is_reported_at_once(tmp_path):
    settings, db = _system(tmp_path)
    outbox = _Outbox()
    _look(db, settings, START, outbox)
    _alert(db, START, severity="High", rules=SCAN)
    _alert(db, START, severity="Medium")
    assert _look(db, settings, START + HOUR, outbox)["made"] == []

    both = _with(settings, ATDR_NOTIFY_ALERT_SEVERITY="high")
    _alert(db, START + HOUR * 2)
    told = _look(db, both, START + HOUR * 2 + MINUTE, outbox)["made"][0]
    assert told["title"] == "2 alerts: 1 Critical, 1 High", "the High alert is two hours old: not called new"
    assert _last(db).body == "#1 High: port scan, raised 10:00\n#3 Critical: malware / C2, raised 12:00"

    # The behaviour model's alerts are marked as what they are.
    _alert(db, START + HOUR * 4, alert_type="mfu_behavior_model", rules=SCAN)
    assert _look(db, both, START + HOUR * 4 + MINUTE, outbox)["made"][0]["title"] == "New Critical alert #4: port scan (experimental)"


def test_an_alert_that_rises_to_critical_is_reported_and_a_closed_one_is_not(tmp_path):
    settings, db = _system(tmp_path)
    outbox = _Outbox()
    _look(db, settings, START - DAY, outbox)
    rising = _alert(db, START - HOUR * 5, severity="High")
    closed = _alert(db, START)
    closed.status = "false_positive"
    db.commit()
    assert _look(db, settings, START + HOUR, outbox)["made"] == []

    # New evidence joined it and raised its score.
    rising.severity = "Critical"
    db.commit()
    told = _look(db, settings, START + HOUR * 2, outbox)["made"][0]
    assert told["title"] == "Critical alert #1: malware / C2" and _last(db).body == "Raised 05:00."
    for status in ("investigating", "contained", "needs_more_context"):
        _alert(db, START + HOUR * 3, status=status)
    told = _look(db, settings, START + HOUR * 4, outbox)["made"][0]
    assert told["title"] == "3 new Critical alerts", "still open, in any of its states; and new for an hour"
    _alert(db, START + HOUR * 5, status="resolved")
    assert _look(db, settings, START + HOUR * 6, outbox)["made"] == []


def test_no_address_is_in_a_notification_whatever_its_words_held(tmp_path):
    settings, db = _system(tmp_path)
    outbox = _Outbox()
    _look(db, settings, START, outbox)
    _alert(db, START)
    _look(db, settings, START + MINUTE, outbox)
    leaky = Problem("leaky", "Drive of 192.0.2.7 is full", "Seen from 2001:db8::1 and 10.20.30.40 at 10:05.", over="Fine again for 192.0.2.7.",
                    grace=timedelta(0))
    track_problems(db, [leaky], source="worker", settings=settings, now=START + MINUTE * 2, zone=BANGKOK)
    kept = db.get(NotificationCondition, "leaky")
    assert (kept.title, kept.body, kept.over) == ("Drive of [address] is full", "Seen from [address] and [address] at 10:05.",
                                                  "Fine again for [address]."), "what the System panel shows of it"
    track_problems(db, [], source="worker", settings=settings, now=START + MINUTE * 9, zone=BANGKOK)
    db.commit()
    deliver_pending(db, settings=settings, now=START + MINUTE * 9, senders=outbox.senders())

    everything = " ".join(f"{message.title} {message.body}" for _channel, message in outbox.sent)
    everything += " ".join(f"{row.title} {row.body} {json.dumps(row.details_json)}" for row in db.scalars(select(Notification)))
    assert "10.20.30.40" not in everything and "192.0.2.7" not in everything and "2001:db8" not in everything
    assert "Drive of [address] is full" in everything and "Seen from [address] and [address] at 10:05." in everything
    assert "Fine again for [address]." in everything
    # A time of day and an alert's number are not taken for addresses.
    assert notify.safe_text("#4163 Critical: malware / C2, raised 9 Oct 14:05") == "#4163 Critical: malware / C2, raised 9 Oct 14:05"

    # Whatever writes a notification down passes the same guard, and so does what is kept of a channel's failure.
    direct = notify._notify(db, kind="problem", level="warning", title="Host 198.51.100.4 answered", body="from 198.51.100.4",
                            outward=False, settings=settings, now=START + MINUTE * 10)
    assert (direct.title, direct.body) == ("Host [address] answered", "from [address]")
    failing = _Outbox(failing={"email": DeliveryError("the mail server at 198.51.100.25 could not be reached")})
    _alert(db, START + HOUR)
    _look(db, settings, START + HOUR + MINUTE, failing)
    assert db.scalar(select(NotificationDelivery.error).where(NotificationDelivery.error.is_not(None))) == (
        "the mail server at [address] could not be reached")


def test_the_summary_goes_once_a_day_at_its_time_and_says_what_is_new_and_open(tmp_path):
    settings, db = _system(tmp_path, ATDR_NOTIFY_SUMMARY_AT="08:00")
    outbox = _Outbox()
    _alert(db, START - DAY * 3, severity="High")
    assert [made["kind"] for made in _look(db, settings, START, outbox)["made"]] == ["started"], "begun at 10:00: not today's 08:00"
    for severity in ("Critical", "High", "Medium", "Medium", "Low"):
        _alert(db, START + HOUR, severity=severity)
    _alert(db, START + HOUR, status="resolved")
    _look(db, settings, START + HOUR * 2, outbox)

    morning = datetime(2026, 10, 10, 1, 0, tzinfo=timezone.utc)  # 08:00 on Saturday in Bangkok
    # A problem that has not lasted long enough to be told is not in the summary either.
    track_problems(db, [Problem("young", "Not yet told", "Too soon.", over="Gone.", grace=timedelta(hours=5))], source="watcher",
                   settings=settings, now=morning - MINUTE, zone=BANGKOK)
    db.commit()
    assert [made["kind"] for made in _look(db, settings, morning - MINUTE, outbox)["made"]] == []
    done = _look(db, settings, morning, outbox)
    assert done["made"] == [{"id": 3, "kind": "summary", "title": "Daily summary: 6 new alerts"}]
    summary = _last(db)
    assert summary.body == ("Since 9 Oct 10:00: 6 new alerts (2 Critical, 1 High, 2 Medium, 1 Low).\n"
                            "Open now: 6 alerts, 1 of them Critical.\n"
                            "Nothing about ATDR itself needs attention.")
    assert (summary.level, summary.audience, summary.link) == ("info", "all", "/alerts")
    assert summary.details_json == {"new": {"Critical": 2, "High": 1, "Medium": 2, "Low": 1}, "open": 6, "open_critical": 1,
                                    "needs_attention": []}
    assert outbox.titles("chat")[-1] == "Daily summary: 6 new alerts"
    assert _look(db, settings, morning + HOUR * 5, outbox)["made"] == [], "one a day"

    # A quiet day still gets its summary, with one alert it reads "1 new alert", and what needs attention is named.
    track_problems(db, [Problem("backup_copy_old", "No copy of the backups is on another disk", "Connect a drive.", over="Copied.",
                                urgent=False, grace=timedelta(0))], source="worker", settings=settings, now=morning + HOUR, zone=BANGKOK)
    db.commit()
    quiet = _look(db, settings, morning + DAY, outbox, problems=False)["made"][0]
    assert quiet["title"] == "Daily summary: no new alerts, 1 thing about ATDR needs attention"
    assert _last(db).body == ("Since 10 Oct 08:00: no new alerts.\nOpen now: 6 alerts, 1 of them Critical.\nNeeds attention:\n"
                              "- No copy of the backups is on another disk")
    _alert(db, morning + DAY + HOUR, severity="Low")
    # The laptop was off at 08:00 on the 12th: the summary goes when it is on again, and covers the whole time.
    late = _look(db, settings, morning + DAY * 2 + HOUR * 6, outbox, problems=False)["made"][0]
    assert late["title"] == "Daily summary: 1 new alert, 1 thing about ATDR needs attention"
    assert _last(db).body.splitlines()[0] == "Since 11 Oct 08:00: 1 new alert (1 Low)."
    assert _look(db, settings, morning + DAY * 2 + HOUR * 7, outbox, problems=False)["made"] == []


def test_no_summary_without_a_time_and_a_time_that_is_not_one_is_said_to_be_wrong(tmp_path):
    settings, db = _system(tmp_path)
    _look(db, settings, START)
    assert _look(db, settings, START + DAY * 3)["made"] == []
    assert notification_status(db, settings=settings, now=START)["summary_at"] is None
    assert notification_status(db, settings=settings, now=START)["summary_setting_wrong"] is False

    wrong = _with(settings, ATDR_NOTIFY_SUMMARY_AT="8 o'clock")
    assert _look(db, wrong, START + DAY * 4)["made"] == []
    assert notification_status(db, settings=wrong, now=START)["summary_setting_wrong"] is True
    evening = _with(settings, ATDR_NOTIFY_SUMMARY_AT="17:30")
    assert notification_status(db, settings=evening, now=START)["summary_at"] == "17:30"
    assert _look(db, evening, datetime(2026, 10, 13, 10, 29, tzinfo=timezone.utc))["made"] == [], "17:29 in Bangkok"
    assert _look(db, evening, datetime(2026, 10, 13, 10, 30, tzinfo=timezone.utc))["made"][0]["kind"] == "summary"


def _backups(**fields) -> dict:
    offsite = {"wanted": True, "folder_name": "ATDR-backups", "connected": [], "last_copy": {"age_days": 1.0}, "last_failure": None,
               "stale": False, **fields.pop("offsite", {})}
    return {"scheduled": True, "last_failure": None, "offsite": offsite, **fields}


def test_a_failed_backup_is_told_at_once_and_told_when_it_is_over(tmp_path, monkeypatch):
    settings, db = _system(tmp_path)
    outbox = _Outbox()
    state = {"backups": _backups()}
    monkeypatch.setattr(notify, "backup_status", lambda _db, **_kwargs: state["backups"])
    _look(db, settings, START, outbox)
    assert _kinds(db) == ["started"]

    state["backups"] = _backups(last_failure={"at": START, "status": "not_enough_free_space"})
    told = _look(db, settings, START + MINUTE * 5, outbox)["made"]
    assert told == [{"id": 2, "kind": "problem", "title": "ATDR could not back up its database"}]
    problem = _last(db)
    assert (problem.level, problem.audience, problem.link) == ("warning", "admin", "/data")
    assert problem.body == "The last try failed: there is not enough free space for it. ATDR tries again every hour."
    assert outbox.titles() == ["ATDR could not back up its database"] == outbox.titles("chat")
    assert _look(db, settings, START + MINUTE * 10, outbox)["made"] == [], "told once while it lasts"

    state["backups"] = _backups()
    over = _look(db, settings, START + HOUR * 2 + MINUTE * 5, outbox)["made"]
    assert over == [{"id": 3, "kind": "resolved", "title": "ATDR backs its database up again."}]
    assert _last(db).body == "It began 10:05 and lasted 2 hours."
    assert outbox.titles()[-1] == "ATDR backs its database up again." and db.scalar(select(func.count()).select_from(NotificationCondition)) == 0

    # No backups are scheduled: nothing about them is a problem.
    state["backups"] = {**_backups(last_failure={"at": START, "status": "backup_failed"}), "scheduled": False}
    assert _look(db, settings, START + HOUR * 3, outbox)["made"] == []


def test_a_copy_on_another_disk_that_is_missing_or_old_is_a_reminder_not_a_message(tmp_path, monkeypatch):
    settings, db = _system(tmp_path)
    outbox = _Outbox()
    state = {"backups": _backups(offsite={"last_copy": None, "stale": True})}
    monkeypatch.setattr(notify, "backup_status", lambda _db, **_kwargs: state["backups"])
    _look(db, settings, START, outbox)
    assert _look(db, settings, START + MINUTE * 4, outbox)["made"] == [], "not before it has lasted five minutes"
    told = _look(db, settings, START + MINUTE * 5, outbox)["made"]
    assert told == [{"id": 2, "kind": "problem", "title": "No copy of the backups is on another disk"}]
    reminder = _last(db)
    assert reminder.level == "info" and reminder.audience == "admin"
    assert reminder.body == ("Every backup is on the disk the database is on. Connect a drive that has a folder named ATDR-backups "
                             "at its top; ATDR copies the newest backup to it.")
    assert outbox.sent == [], "in the bell and in the daily summary, not sent out"

    # Copied, then eight days without the drive, then a copy that fails.
    state["backups"] = _backups()
    assert _look(db, settings, START + HOUR, outbox)["made"][0]["title"] == "A copy of the newest backup is on another disk."
    state["backups"] = _backups(offsite={"last_copy": {"age_days": 8.4}, "stale": True})
    _look(db, settings, START + DAY * 8, outbox)
    assert _look(db, settings, START + DAY * 8 + MINUTE * 5, outbox)["made"][0]["title"] == "The copy of the backups on another disk is 8 days old"
    state["backups"] = _backups(offsite={"last_failure": {"at": START, "status": "copy_failed", "drive": "E:"}, "stale": True})
    _look(db, settings, START + DAY * 9, outbox)
    made = [made["title"] for made in _look(db, settings, START + DAY * 9 + MINUTE * 5, outbox)["made"]]
    assert "The backup could not be copied to the other disk" in made
    assert _last(db, "problem").body == "Copying to drive E: failed: the copy could not be written."
    assert not [title for title in outbox.titles() if "copy" in title.lower() or "copied" in title.lower()]
    # A drive is not wanted: nothing is said about one.
    state["backups"] = _backups(offsite={"wanted": False, "stale": True, "last_copy": None})
    _look(db, settings, START + DAY * 10, outbox)
    assert db.scalar(select(func.count()).select_from(NotificationCondition)) == 0


def test_a_problem_that_ends_before_it_has_lasted_is_never_mentioned(tmp_path):
    settings, db = _system(tmp_path)
    runtime = tmp_path / ".atdr_runtime"
    runtime.mkdir()
    (runtime / "desired-state.json").write_text(json.dumps({"state": "running"}), encoding="utf-8")
    outbox = _Outbox()
    _look(db, settings, START, outbox, runtime=runtime)

    # Nothing is watching ATDR's parts: a reminder once it has been so for ten minutes.
    assert _look(db, settings, START + MINUTE * 9, outbox, runtime=runtime)["made"] == []
    assert db.scalar(select(NotificationCondition.key)) == "watcher_not_running"
    stamp = (START + MINUTE * 9).strftime("%Y-%m-%dT%H:%M:%S.0000000Z")
    (runtime / "watch-status.json").write_text(json.dumps({"watcher": {"checked_at": stamp, "interval_seconds": 30}, "parts": []}), encoding="utf-8")
    assert _look(db, settings, START + MINUTE * 10, outbox, runtime=runtime)["made"] == [], "the watcher is back"
    assert db.scalar(select(func.count()).select_from(NotificationCondition)) == 0 and _kinds(db) == ["started"]

    # Gone for ten minutes: said, in the bell only. A stop on purpose is not a problem.
    told = _look(db, settings, START + HOUR, outbox, runtime=runtime)["made"]
    assert told == []
    told = _look(db, settings, START + HOUR + MINUTE * 10, outbox, runtime=runtime)["made"]
    assert told == [{"id": 2, "kind": "problem", "title": "Nothing is watching ATDR's parts"}] and outbox.sent == []
    (runtime / "desired-state.json").write_text(json.dumps({"state": "stopped"}), encoding="utf-8")
    assert _look(db, settings, START + HOUR * 2, outbox, runtime=runtime)["made"][0]["title"] == "ATDR's parts are watched again."


def test_a_full_disk_and_a_failed_automatic_check_are_told(tmp_path, monkeypatch):
    settings, db = _system(tmp_path, ATDR_NOTIFY_DISK_FREE_GB=10, AUTO_DETECTION_ENABLED=True)
    outbox = _Outbox()
    free = {"gb": 10.0}
    monkeypatch.setattr(notify, "_free_gb", lambda _folder: free["gb"])
    _look(db, settings, START, outbox)
    assert _kinds(db) == ["started"], "ten of ten free is not below it"

    free["gb"] = 9.96
    assert _look(db, settings, START + MINUTE, outbox)["made"][0]["title"] == "The disk ATDR's database is on is almost full"
    assert _last(db).body == "10.0 GB are free. ATDR tells when fewer than 10 GB are."
    free["gb"] = 80.0
    assert _look(db, settings, START + MINUTE * 2, outbox)["made"][0]["title"] == "The disk ATDR's database is on has room again."
    free["gb"] = 1.0
    assert _look(db, _with(settings, ATDR_NOTIFY_DISK_FREE_GB=0), START + MINUTE * 3, outbox)["made"] == [], "0 switches it off"
    free["gb"] = 80.0

    db.add(OperationJob(job_type="run_detection", status="failed", requested_by=AUTO_DETECTION_ACTOR, details_json={},
                        started_at=START + HOUR, finished_at=START + HOUR))
    db.commit()
    assert _look(db, settings, START + HOUR + MINUTE * 9, outbox)["made"] == [], "one failed check is not yet a problem"
    assert _look(db, settings, START + HOUR + MINUTE * 19, outbox)["made"][0]["title"] == "ATDR's automatic check of new logs failed"
    db.add(OperationJob(job_type="run_detection", status="completed", requested_by=AUTO_DETECTION_ACTOR, details_json={},
                        started_at=START + HOUR * 2, finished_at=START + HOUR * 2))
    db.commit()
    assert _look(db, settings, START + HOUR * 2 + MINUTE, outbox)["made"][0]["title"] == "ATDR checks new logs by itself again."
    # Automatic checks switched off: a failed one from before is nobody's problem.
    db.add(OperationJob(job_type="run_detection", status="failed", requested_by=AUTO_DETECTION_ACTOR, details_json={},
                        started_at=START + HOUR * 3, finished_at=START + HOUR * 3))
    db.commit()
    switched_off = _with(settings, AUTO_DETECTION_ENABLED=False)
    _look(db, switched_off, START + HOUR * 3, outbox)
    assert _look(db, switched_off, START + HOUR * 4, outbox)["made"] == []


def _feed(db: Session, when: datetime, *, status: str = "running", reported: datetime | None = None, **details) -> IngestionRun:
    new_run = details.pop("new_run", False)
    run = db.scalar(select(IngestionRun).order_by(IngestionRun.id.desc()).limit(1))
    if run is None or new_run:
        run = IngestionRun(source_type=SYSLOG, status=status, started_at=when, total_lines_received=0, raw_logs_created=0)
        db.add(run)
    run.status = status
    run.details_json = {"reported_at": (reported or when).isoformat(), "dropped": 0, **details}
    db.commit()
    return run


def test_the_live_feed_says_when_it_stops_loses_lines_or_hears_nothing(tmp_path):
    settings, db = _system(tmp_path, SYSLOG_ENABLED=True, ATDR_NOTIFY_FEED_SILENT_MINUTES=10)
    outbox = _Outbox()
    _look(db, settings, START, outbox)
    assert _look(db, settings, START + MINUTE * 2, outbox)["made"] == [], "switched on and not yet started: two minutes are allowed"
    assert _look(db, settings, START + MINUTE * 3, outbox)["made"][0]["title"] == "The live log feed is not running"

    began = START + MINUTE * 4
    _feed(db, began, last_received_at=began.isoformat())
    assert _look(db, settings, began, outbox)["made"][0]["title"] == "The live log feed is running again."

    # Lines that could not be saved: told when the count grows, over when it has not grown for half an hour.
    _feed(db, began + MINUTE, last_received_at=(began + MINUTE).isoformat(), dropped=1200)
    told = _look(db, settings, began + MINUTE, outbox)["made"]
    assert told[0]["title"] == "The live log feed is losing lines"
    assert _last(db).body == "1,200 lines could not be saved since the feed started: they arrive faster than ATDR saves them."
    _feed(db, began + MINUTE * 20, last_received_at=(began + MINUTE * 20).isoformat(), dropped=1500)
    assert _look(db, settings, began + MINUTE * 20, outbox)["made"] == []
    _feed(db, began + MINUTE * 49, last_received_at=(began + MINUTE * 49).isoformat(), dropped=1500)
    assert _look(db, settings, began + MINUTE * 49, outbox)["made"] == [], "29 minutes since it last grew"
    _feed(db, began + MINUTE * 50, last_received_at=(began + MINUTE * 50).isoformat(), dropped=1500)
    assert _look(db, settings, began + MINUTE * 50, outbox)["made"][0]["title"] == "The live log feed no longer loses lines."

    # Running, and nothing arrives from the firewall.
    quiet = began + HOUR * 2
    _feed(db, quiet, last_received_at=(quiet - MINUTE * 9).isoformat(), dropped=1500)
    assert _look(db, settings, quiet, outbox)["made"] == []
    _feed(db, quiet + MINUTE, last_received_at=(quiet - MINUTE * 9).isoformat(), dropped=1500)
    assert _look(db, settings, quiet + MINUTE, outbox)["made"][0]["title"] == "No log has arrived from the firewall for 10 minutes"
    assert _look(db, _with(settings, ATDR_NOTIFY_FEED_SILENT_MINUTES=0), quiet + MINUTE * 2, outbox)["made"][0]["title"] == (
        "Logs arrive from the firewall again."), "0 switches that off"

    # The disk filled: the feed saves nothing.
    full = quiet + HOUR
    _feed(db, full, last_received_at=full.isoformat(), dropped=1500, disk_low=True, dropped_disk_low=40, free_disk_gb=9.0)
    assert _look(db, settings, full, outbox)["made"][0]["title"] == "The live log feed stopped saving: the disk is almost full"
    assert _last(db).body == "The feed saves nothing while fewer than 10 GB are free. 40 lines were lost so far."

    # A new run of the receiver starts its count again: an old total is not a new loss.
    again = full + HOUR
    _feed(db, again, last_received_at=again.isoformat(), dropped=0, new_run=True)
    made = [made["title"] for made in _look(db, settings, again, outbox)["made"]]
    assert made == ["The live log feed saves logs again."]
    # ...and a loss in the new run is one, although its count is far below the old run's.
    _feed(db, again + MINUTE, last_received_at=(again + MINUTE).isoformat(), dropped=10)
    assert [made["title"] for made in _look(db, settings, again + MINUTE, outbox)["made"]] == ["The live log feed is losing lines"]
    assert _last(db).body == "10 lines could not be saved since the feed started: they arrive faster than ATDR saves them."
    # With the feed switched off nothing about it is a problem any more.
    switched_off = _look(db, _with(settings, SYSLOG_ENABLED=False), again + MINUTE * 2, outbox)["made"]
    assert [made["title"] for made in switched_off] == ["The live log feed no longer loses lines."]
    assert _look(db, _with(settings, SYSLOG_ENABLED=False), again + MINUTE * 3, outbox)["made"] == []
    # Every one of these went out: they are urgent.
    assert outbox.titles() == [row.title for row in db.scalars(select(Notification).where(Notification.kind.in_(("problem", "resolved"))).order_by(Notification.id))]


def test_a_channel_that_fails_is_tried_again_and_given_up_after_a_day(tmp_path):
    settings, db = _system(tmp_path)
    outbox = _Outbox(failing={"email": DeliveryError("the mail server could not be reached (TimeoutError)")})
    _look(db, settings, START, outbox)
    _alert(db, START)
    first = _look(db, settings, START + MINUTE, outbox)["sent"]
    assert [(sent["channel"], sent["ok"], sent["error"]) for sent in first] == [
        ("email", False, "the mail server could not be reached (TimeoutError)"), ("chat", True, None)]
    assert outbox.titles("chat") == ["New Critical alert #1: malware / C2"], "one channel failing does not hold up another"
    email = db.scalar(select(NotificationDelivery).where(NotificationDelivery.channel == "email"))
    assert (email.status, email.attempts, email.error) == ("pending", 1, "the mail server could not be reached (TimeoutError)")

    # Tried again after 1, 5, 15 and 60 minutes, then every hour.
    tried = []
    when = START + MINUTE
    for _step in range(400):
        when += MINUTE
        if _look(db, settings, when, outbox, problems=False)["sent"]:
            tried.append(int((when - START).total_seconds() // 60) - 1)
        db.refresh(email)
        if email.status != "pending":
            break
    assert tried[:6] == [1, 6, 21, 81, 141, 201] and email.status == "pending"
    status = notification_status(db, settings=settings, now=when)["channels"]
    assert status["email"]["last_failure"]["words"] == "the mail server could not be reached (TimeoutError)"
    assert status["email"]["last_failure"]["gave_up"] is False and status["email"]["last_failure"]["delivered"] is False
    assert status["email"]["last_failure"]["at"] == START + MINUTE * (tried[-1] + 1), "when it was last tried"
    assert status["email"]["last_sent_at"] is None
    assert status["chat"]["last_failure"] is None and status["chat"]["last_sent_at"] == START + MINUTE

    # A day after the notification was made the next failure is the last, and is entered in the audit log.
    assert _look(db, settings, START + MINUTE + DAY, outbox, problems=False)["sent"][0]["ok"] is False
    db.refresh(email)
    assert email.status == "failed" and _look(db, settings, START + DAY * 2, outbox, problems=False)["sent"] == []
    gave_up = _audit(db, "notification_failed")
    assert [(entry.target_value, entry.details["channel"], entry.details["error"]) for entry in gave_up] == [
        ("2", "email", "the mail server could not be reached (TimeoutError)")]
    assert notification_status(db, settings=settings, now=START + DAY * 2)["channels"]["email"]["last_failure"]["gave_up"] is True

    # The mail server is back: the next notification goes out and the failure is no longer shown.
    outbox.failing.clear()
    _alert(db, START + DAY * 3)
    _look(db, settings, START + DAY * 3 + MINUTE, outbox)
    assert notification_status(db, settings=settings, now=START + DAY * 3 + HOUR)["channels"]["email"]["last_failure"] is None
    assert outbox.titles("email") == ["New Critical alert #2: malware / C2"]


def test_a_refusal_that_only_a_changed_setting_can_end_is_not_tried_again(tmp_path):
    # Each try would be one more refused sign-in on the mail account.
    settings, db = _system(tmp_path)
    outbox = _Outbox(failing={"email": DeliveryError("the mail server refused the account's name or password", again=False)})
    _look(db, settings, START, outbox)
    _alert(db, START)
    first = _look(db, settings, START + MINUTE, outbox)["sent"]
    assert [(sent["channel"], sent["ok"]) for sent in first] == [("email", False), ("chat", True)]
    email = db.scalar(select(NotificationDelivery).where(NotificationDelivery.channel == "email"))
    assert (email.status, email.attempts, email.next_attempt_at) == ("failed", 1, None)
    for minutes in (2, 7, 22, 82, 60 * 30):
        assert _look(db, settings, START + MINUTE * minutes, outbox, problems=False)["sent"] == [], minutes
    assert [(entry.details["channel"], entry.details["attempts"], entry.details["error"]) for entry in _audit(db, "notification_failed")] == [
        ("email", 1, "the mail server refused the account's name or password")]
    told = notification_status(db, settings=settings, now=START + HOUR)["channels"]["email"]["last_failure"]
    assert (told["gave_up"], told["delivered"], told["at"]) == (True, False, START + MINUTE)

    # The next notification is one more try: the setting may have been put right since.
    outbox.failing.clear()
    _alert(db, START + HOUR * 40)
    _look(db, settings, START + HOUR * 40 + MINUTE, outbox)
    assert outbox.titles("email") == ["New Critical alert #2: malware / C2"]
    assert notification_status(db, settings=settings, now=START + HOUR * 41)["channels"]["email"]["last_failure"] is None


def test_a_message_that_reached_only_some_addresses_is_not_sent_again(tmp_path):
    settings, db = _system(tmp_path)
    outbox = _Outbox(notes={"email": "the mail server refused 1 of the addresses the message was for, such as 192.0.2.9"})
    _look(db, settings, START, outbox)
    _alert(db, START)
    sent = _look(db, settings, START + MINUTE, outbox)["sent"]
    assert [(item["channel"], item["ok"], item["error"], item["note"]) for item in sent] == [
        ("email", True, None, "the mail server refused 1 of the addresses the message was for, such as [address]"), ("chat", True, None, None)]
    # Those who got it would get it again at every try.
    assert _look(db, settings, START + HOUR, outbox, problems=False)["sent"] == [] and len(outbox.titles("email")) == 1
    email_status = notification_status(db, settings=settings, now=START + HOUR)["channels"]["email"]
    assert email_status["last_failure"] == {"at": START + MINUTE, "gave_up": False, "delivered": True,
                                            "words": "the mail server refused 1 of the addresses the message was for, such as [address]"}
    assert email_status["last_sent_at"] == START + MINUTE
    done = send_test(db, "email", actor="koe", settings=settings, now=START + HOUR, senders=outbox.senders())
    assert done == {"ok": True, "channel": "email",
                    "words": "Email sent, but the mail server refused 1 of the addresses the message was for, such as [address]."}
    # The address is put right: the next message has nothing to say, and the note is no longer shown.
    outbox.notes.clear()
    _alert(db, START + HOUR * 2)
    _look(db, settings, START + HOUR * 2 + MINUTE, outbox)
    assert notification_status(db, settings=settings, now=START + HOUR * 3)["channels"]["email"]["last_failure"] is None


def test_two_processes_never_send_the_same_notification(tmp_path):
    settings, db = _system(tmp_path)
    outbox = _Outbox()
    _look(db, settings, START, outbox)
    _alert(db, START)
    notify.raise_alert_notification(db, settings=settings, now=START + MINUTE, zone=BANGKOK)
    db.commit()

    # Another process took the email a moment ago and has not finished.
    email = db.scalar(select(NotificationDelivery).where(NotificationDelivery.channel == "email"))
    email.status, email.claimed_at, email.attempts = "sending", START + MINUTE, 1
    db.commit()
    assert [sent["channel"] for sent in deliver_pending(db, settings=settings, now=START + MINUTE * 2, senders=outbox.senders())] == ["chat"]
    assert deliver_pending(db, settings=settings, now=START + MINUTE * 5, senders=outbox.senders()) == []
    # It died before it finished: after five minutes the email is taken up again.
    assert [sent["channel"] for sent in deliver_pending(db, settings=settings, now=START + MINUTE * 6, senders=outbox.senders())] == ["email"]
    assert [channel for channel, _message in outbox.sent] == ["chat", "email"]
    assert deliver_pending(db, settings=settings, now=START + HOUR, senders=outbox.senders()) == [], "sent once"

    # Between finding what is waiting and taking it, another process can take it: whoever comes second leaves it.
    _alert(db, START + HOUR * 2)
    notify.raise_alert_notification(db, settings=settings, now=START + HOUR * 2 + MINUTE, zone=BANGKOK)
    db.commit()
    senders = outbox.senders()

    def email_while_the_chat_message_is_taken(_settings: Settings, message: Message) -> None:
        db.execute(NotificationDelivery.__table__.update()
                   .where(NotificationDelivery.channel == "chat", NotificationDelivery.status == "pending")
                   .values(status="sending", claimed_at=START + HOUR * 2 + MINUTE))
        db.commit()
        outbox.sent.append(("email", message))

    senders["email"] = email_while_the_chat_message_is_taken
    taken = deliver_pending(db, settings=settings, now=START + HOUR * 2 + MINUTE, senders=senders)
    assert [sent["channel"] for sent in taken] == ["email"], "the chat message is the other process's to send"
    assert [channel for channel, _message in outbox.sent] == ["chat", "email", "email"]


def test_a_sender_that_breaks_does_not_stop_the_look_and_a_channel_switched_off_is_dropped(tmp_path):
    settings, db = _system(tmp_path)
    outbox = _Outbox(failing={"chat": RuntimeError(f"connection to {CHAT_ADDRESS} broke")})
    _look(db, settings, START, outbox)
    _alert(db, START)
    sent = _look(db, settings, START + MINUTE, outbox)["sent"]
    assert [(item["channel"], item["ok"], item["error"]) for item in sent] == [("email", True, None), ("chat", False, "sending failed (RuntimeError)")]
    assert "secret-token" not in json.dumps(notification_status(db, settings=settings, now=START + MINUTE), default=str)

    # The chat address was taken out of the settings: what was waiting for it is dropped, not kept failing.
    without_chat = _with(settings, ATDR_NOTIFY_CHAT_WEBHOOK_URL="")
    assert _look(db, without_chat, START + MINUTE * 3, outbox, problems=False)["sent"] == []
    assert [row.channel for row in db.scalars(select(NotificationDelivery))] == ["email"]
    _alert(db, START + HOUR)
    _look(db, without_chat, START + HOUR + MINUTE, outbox)
    assert [row.channel for row in db.scalars(select(NotificationDelivery).order_by(NotificationDelivery.id))] == ["email", "email"]


def test_the_watcher_reports_a_part_that_keeps_stopping_without_the_worker(tmp_path):
    settings, db = _system(tmp_path)
    outbox = _Outbox()
    worker = part_problem("atdr-worker")
    assert (worker.key, worker.title, worker.over) == ("part_keeps_stopping:atdr-worker", "ATDR's background worker keeps stopping",
                                                       "ATDR's background worker is running again.")
    assert part_problem("atdr-backend").title == "ATDR's API server keeps stopping"
    assert part_problem("a-part-from-a-later-version").title == "ATDR's a-part-from-a-later-version keeps stopping"

    told = report_problem(db, worker, settings=settings, now=START, senders=outbox.senders())
    assert told["made"] == [{"id": 1, "kind": "problem", "title": "ATDR's background worker keeps stopping"}]
    assert [(sent["channel"], sent["ok"]) for sent in told["sent"]] == [("email", True), ("chat", True)], "sent at once: no worker is needed"
    assert _last(db).body == ("ATDR started it three times in ten minutes and now tries once every five. "
                              "Its log in .atdr_runtime\\logs says why it stops.")
    assert report_problem(db, worker, settings=settings, now=START + MINUTE, senders=outbox.senders())["made"] == [], "told once"
    report_problem(db, notify.NOT_STARTING, settings=settings, now=START + MINUTE, senders=outbox.senders())

    # The worker's own look sees none of this and must not call it over.
    _look(db, settings, START + MINUTE * 2, outbox)
    _look(db, settings, START + HOUR, outbox)
    assert sorted(db.scalars(select(NotificationCondition.key))) == ["atdr_not_starting", "part_keeps_stopping:atdr-worker"]

    # The time in it is the machine's own; here that is said to be Bangkok's, wherever the tests run.
    over = report_problem(db, worker, over=True, settings=settings, now=START + HOUR * 3, zone=BANGKOK, senders=outbox.senders())
    assert over["made"] == [{"id": 4, "kind": "resolved", "title": "ATDR's background worker is running again."}]
    assert _last(db).body == "It began 10:00 and lasted 3 hours."
    assert list(db.scalars(select(NotificationCondition.key))) == ["atdr_not_starting"], "one problem said over, the other left"
    assert report_problem(db, worker, over=True, settings=settings, now=START + HOUR * 4, senders=outbox.senders())["made"] == []
    assert outbox.titles() == ["ATDR's background worker keeps stopping", "ATDR could not be started", "ATDR's background worker is running again."]

    off = report_problem(db, worker, settings=_with(settings, ATDR_NOTIFY_ENABLED=False), now=START + DAY, senders=outbox.senders())
    assert off == {"enabled": False, "made": [], "sent": []}


def test_the_notify_command_reports_and_says_how_it_went(tmp_path, monkeypatch, capsys):
    from atdr.scripts import notify as command

    _settings, db = _system(tmp_path)
    monkeypatch.setattr(command, "SessionLocal", sessionmaker(bind=db.get_bind(), future=True))

    def ran(*arguments: str) -> tuple[int, str]:
        code = command.main(list(arguments))
        return code, capsys.readouterr().out.strip()

    assert ran("--part", "atdr-worker") == (0, "told: ATDR's background worker keeps stopping")
    assert ran("--part", "atdr-worker") == (0, "nothing new to say")
    assert ran("--not-starting") == (0, "told: ATDR could not be started")
    assert ran("--part", "atdr-worker", "--over") == (0, "told: ATDR's background worker is running again.")
    assert sorted(db.scalars(select(NotificationCondition.key))) == ["atdr_not_starting"]
    assert ran("--not-starting", "--over") == (0, "told: ATDR is running again.")
    # No channel is set up where the tests run: the test message says what is missing, and that is a failure.
    assert ran("--test", "email") == (1, "Email is not set up: no address to send to (ATDR_NOTIFY_EMAIL_TO is empty).")

    # It is on record but a channel did not take it: the worker tries that again, and the caller is told.
    monkeypatch.setattr(command, "report_problem", lambda _db, problem, over=False: {
        "enabled": True, "made": [{"title": problem.title}],
        "sent": [{"channel": "chat", "ok": True, "error": None}, {"channel": "email", "ok": False, "error": "the mail server could not be reached (TimeoutError)"}]})
    assert ran("--part", "atdr-backend") == (1, "told: ATDR's API server keeps stopping\nemail: the mail server could not be reached (TimeoutError)")
    monkeypatch.setattr(command, "report_problem", lambda _db, _problem, over=False: {"enabled": False, "made": [], "sent": []})
    assert ran("--part", "atdr-backend") == (0, "notifications are switched off")

    # The database cannot be reached: nothing is on record, and the caller tries again later.
    def unreachable():
        raise OSError("unable to open database file")

    monkeypatch.setattr(command, "SessionLocal", unreachable)
    assert ran("--part", "atdr-worker") == (2, "could not be reported (OSError)")
    with pytest.raises(SystemExit):
        command.main(["--test", "chat", "--over"])
    with pytest.raises(SystemExit):
        command.main([])


def _user(db: Session, name: str, role: str) -> User:
    user = User(username=name, role=role, password_hash="x")
    db.add(user)
    db.commit()
    return user


def test_the_bell_counts_what_each_user_has_not_seen(tmp_path):
    settings, db = _system(tmp_path)
    admin, analyst = _user(db, "admin", "admin"), _user(db, "analyst", "analyst")
    _look(db, settings, START - DAY * 3)
    _alert(db, START)
    _look(db, settings, START + MINUTE)
    report_problem(db, part_problem("atdr-worker"), settings=settings, now=START + MINUTE * 2, senders=_Outbox().senders())
    now = START + MINUTE * 3

    for_admin = notifications_for(db, admin, now=now)
    assert [(item["id"], item["kind"], item["unread"]) for item in for_admin["items"]] == [(3, "problem", True), (2, "alerts", True), (1, "started", False)]
    assert (for_admin["unread"], for_admin["newest_id"]) == (2, 3), "never opened: only the last day's count as unread"
    assert for_admin["items"][1]["alerts"] == [{"id": 1, "severity": "Critical", "attack": "malware / C2"}]
    assert for_admin["items"][1]["created_at"] == START + MINUTE and for_admin["items"][1]["link"] == "/alerts?alert=1"

    # ATDR's own problems are for admins.
    for_analyst = notifications_for(db, analyst, now=now)
    assert [item["id"] for item in for_analyst["items"]] == [2, 1] and for_analyst["unread"] == 1

    assert mark_seen(db, admin, 2, now=now) == 2
    assert notifications_for(db, admin, now=now)["unread"] == 1
    assert [item["unread"] for item in notifications_for(db, admin, now=now)["items"]] == [True, False, False]
    assert notifications_for(db, analyst, now=now)["unread"] == 1, "each user has a marker of their own"
    # Never backwards, and never past the newest there is.
    assert mark_seen(db, admin, 1, now=now) == 1 and notifications_for(db, admin, now=now)["unread"] == 1
    assert mark_seen(db, admin, 9999, now=now) == 3 and notifications_for(db, admin, now=now)["unread"] == 0
    assert len(notifications_for(db, admin, limit=1, now=now)["items"]) == 1


def test_a_test_message_says_at_once_whether_it_went(tmp_path):
    settings, db = _system(tmp_path)
    outbox = _Outbox()
    done = send_test(db, "email", actor="koe", settings=settings, now=START, zone=BANGKOK, senders=outbox.senders())
    assert done == {"ok": True, "channel": "email", "words": "Email sent."}
    assert outbox.sent == [("email", Message(title="Test message from ATDR",
                                             body="koe asked for this test at 10:00. A real notification looks like this one.", link="/data"))]
    assert (_last(db).kind, _last(db).audience) == ("test", "admin")

    outbox.failing["chat"] = DeliveryError("the chat service answered 404")
    failed = send_test(db, "chat", actor="koe", settings=settings, now=START + MINUTE, senders=outbox.senders())
    assert failed == {"ok": False, "channel": "chat", "words": "Chat message failed: the chat service answered 404."}
    assert _kinds(db) == ["test"] and db.scalar(select(func.count()).select_from(NotificationDelivery)) == 1, "a failed test is not kept or retried"

    missing = send_test(db, "email", actor="koe", settings=_with(settings, SMTP_HOST=""), now=START, senders=outbox.senders())
    assert missing == {"ok": False, "channel": "email", "words": "Email is not set up: no mail server (SMTP_HOST is empty)."}
    assert send_test(db, "pager", actor="koe", settings=settings, now=START, senders=outbox.senders())["ok"] is False
    assert len(outbox.sent) == 1


def test_the_status_names_each_channel_and_never_the_chat_address(tmp_path):
    settings, db = _system(tmp_path)
    _look(db, settings, START)
    status = notification_status(db, settings=settings, now=START + MINUTE)
    assert (status["enabled"], status["alert_severities"], status["minutes_between"], status["summary_at"], status["started_at"]) == (
        True, ["Critical"], 30, None, START)
    assert status["channels"]["email"] == {"name": "Email", "on": True, "why_off": None, "to": 2, "server": "mail.example.org",
                                           "last_sent_at": None, "last_failure": None}
    assert status["channels"]["chat"] == {"name": "Chat message", "on": True, "why_off": None, "service": "chat.example.org",
                                          "last_sent_at": None, "last_failure": None}
    assert status["channels"]["windows"]["on"] is False and status["channels"]["windows"]["why_off"] == "switched off (ATDR_NOTIFY_WINDOWS=false)"
    assert "secret-token" not in json.dumps(status, default=str) and "hook" not in json.dumps(status, default=str)
    assert status["needs_attention"] == []

    report_problem(db, part_problem("atdr-syslog"), settings=settings, now=START + MINUTE, senders=_Outbox().senders())
    waiting = notification_status(db, settings=_with(settings, ATDR_NOTIFY_ALERT_SEVERITY="High", ATDR_NOTIFY_ALERT_MINUTES_BETWEEN=-5),
                                  now=START + MINUTE * 2)
    assert waiting["needs_attention"] == [{"key": "part_keeps_stopping:atdr-syslog", "title": "ATDR's live syslog receiver keeps stopping",
                                           "since": START + MINUTE, "urgent": True}]
    assert (waiting["alert_severities"], waiting["minutes_between"]) == (["Critical", "High"], 0)


def test_nothing_is_done_while_notifications_are_switched_off_and_old_ones_are_cleared_away(tmp_path):
    settings, db = _system(tmp_path)
    off = _with(settings, ATDR_NOTIFY_ENABLED=False)
    _alert(db, START)
    assert _look(db, off, START + HOUR) == {"enabled": False, "made": [], "sent": []}
    assert _kinds(db) == [] and db.scalar(select(func.count()).select_from(NotificationAlert)) == 0

    outbox = _Outbox()
    _look(db, settings, START + HOUR, outbox)
    _alert(db, START + HOUR * 2)
    _look(db, settings, START + HOUR * 3, outbox)
    assert _kinds(db) == ["started", "alerts"] and db.scalar(select(func.count()).select_from(NotificationDelivery)) == 2
    # Each is kept ninety days, with what was sent of it.
    _look(db, settings, START + HOUR + DAY * 90 - MINUTE, outbox)
    assert _kinds(db) == ["started", "alerts"]
    _look(db, settings, START + HOUR + DAY * 90 + MINUTE, outbox)
    assert _kinds(db) == ["alerts"] and db.scalar(select(func.count()).select_from(NotificationDelivery)) == 2
    _look(db, settings, START + HOUR * 3 + DAY * 90 + MINUTE, outbox)
    assert _kinds(db) == [] and db.scalar(select(func.count()).select_from(NotificationDelivery)) == 0
    # What was reported stays reported, and reporting does not begin again.
    assert _look(db, settings, START + DAY * 100, outbox)["made"] == []


def test_alerts_a_rebuild_or_a_reset_raises_can_be_marked_as_not_news(tmp_path):
    settings, db = _system(tmp_path)
    outbox = _Outbox()
    _look(db, settings, START, outbox)
    for severity in ("Critical", "Critical", "High"):
        _alert(db, START + MINUTE, severity=severity)
    assert cover_alerts(db, settings=settings, now=START + MINUTE) == 2
    db.commit()
    assert cover_alerts(db, settings=settings, now=START + MINUTE) == 0
    assert _look(db, settings, START + HOUR, outbox)["made"] == [] and outbox.sent == []
    _alert(db, START + HOUR * 2)
    assert _look(db, settings, START + HOUR * 2 + MINUTE, outbox)["made"][0]["title"] == "New Critical alert #4: malware / C2"


def test_the_worker_looks_every_half_minute_and_a_look_that_fails_never_stops_it(monkeypatch):
    calls: list[dict] = []

    class _Session:
        def __enter__(self):
            return object()

        def __exit__(self, *_exc):
            return False

    monkeypatch.setattr(operation_worker, "SessionLocal", _Session)
    monkeypatch.setattr(operation_worker, "get_settings", lambda: Settings(_env_file=None))
    monkeypatch.setattr(operation_worker, "record_worker_heartbeat", lambda *_args, **kwargs: calls.append({"heartbeat": kwargs["details"]}))

    def look(_db, **kwargs):
        kwargs["still_alive"]()
        kwargs["still_alive"]()
        calls.append({"problems": kwargs["problems"]})
        return {}

    monkeypatch.setattr(operation_worker, "notification_look", look)
    looks = operation_worker.NotificationLooks()
    before = operation_worker.time.monotonic()
    operation_worker._notification_look("worker-1", looks)
    assert calls == [{"heartbeat": {"notifications": True, "external_services": "notification channels"}}, {"problems": True}], (
        "one heartbeat, not one for every message sent")
    assert looks.next_look >= before + notify.LOOK_SECONDS - 1 and looks.next_problems >= before + notify.PROBLEMS_EVERY_SECONDS - 1
    assert (notify.LOOK_SECONDS, notify.PROBLEMS_EVERY_SECONDS) == (30.0, 300.0)

    operation_worker._notification_look("worker-1", looks)
    assert len(calls) == 2, "not time yet"
    looks.next_look = 0.0
    operation_worker._notification_look("worker-1", looks)
    assert calls[-1] == {"problems": False}, "ATDR's own problems are looked for every five minutes, not at every look"

    def broken(_db, **_kwargs):
        raise RuntimeError("the database is locked")

    monkeypatch.setattr(operation_worker, "notification_look", broken)
    looks.next_look = looks.next_problems = 0.0
    operation_worker._notification_look("worker-1", looks)
    assert looks.next_look > 0 and looks.next_problems == 0.0, "a look for problems that failed is made again at the next look"

    monkeypatch.setattr(operation_worker, "get_settings", lambda: Settings(_env_file=None, ATDR_NOTIFY_ENABLED=False))
    monkeypatch.setattr(operation_worker, "notification_look", lambda *_a, **_k: pytest.fail("notifications are switched off"))
    looks.next_look = 0.0
    operation_worker._notification_look("worker-1", looks)
    assert looks.next_look == 0.0


def test_the_worker_loop_looks_for_something_to_tell(monkeypatch, tmp_path):
    settings, db = _system(tmp_path)
    monkeypatch.setattr(operation_worker, "SessionLocal", sessionmaker(bind=db.get_bind(), future=True))
    monkeypatch.setattr(operation_worker, "get_settings", lambda: settings)
    stop = operation_worker.Event()
    seen: list[bool] = []
    real = operation_worker.notification_look

    def look(session, **kwargs):
        seen.append(kwargs["problems"])
        stop.set()
        return real(session, senders={}, runtime=Path("no-such-folder"), find_offsite=NO_DRIVE, **kwargs)

    monkeypatch.setattr(operation_worker, "notification_look", look)
    # A loop that never looks would run for ever: stop it, and fail on what was seen.
    give_up = threading.Timer(20.0, stop.set)
    give_up.start()
    try:
        operation_worker.run_worker_loop(worker_id="notify-test-worker", poll_seconds=0.1, stop_event=stop)
    finally:
        give_up.cancel()
    assert seen == [True] and _kinds(db) == ["started"]


def test_the_tests_never_send_anything_from_the_machine_they_run_on():
    # .env sets up the running system's channels; conftest.py clears them for every test.
    settings = Settings()
    assert (settings.notify_windows, settings.notify_email_to, settings.notify_chat_webhook_url) == (False, "", "")


def test_a_look_takes_its_moment_as_utc_whatever_zone_it_is_given_in(tmp_path):
    # SQLite keeps a time's digits as they are: 17:00 in Bangkok stored as 17:00 would be seven hours in the future.
    settings, db = _system(tmp_path)
    notification_look(db, settings=settings, now=START.astimezone(BANGKOK), zone=BANGKOK, senders=_Outbox().senders(),
                      runtime=Path("no-such-folder"), find_offsite=NO_DRIVE)
    assert _last(db).created_at.replace(tzinfo=timezone.utc) == START
    assert notification_status(db, settings=settings, now=START)["started_at"] == START


@pytest.mark.parametrize(("span", "words"), [
    (timedelta(seconds=20), "1 minute"), (timedelta(minutes=59, seconds=59), "59 minutes"), (timedelta(minutes=60), "1 hour"),
    (timedelta(minutes=89), "1 hour"), (timedelta(minutes=90), "2 hours"), (timedelta(hours=47), "47 hours"),
    (timedelta(hours=47, minutes=30), "2 days"), (timedelta(hours=60), "3 days"), (timedelta(days=30), "30 days"),
])
def test_how_long_a_problem_lasted_is_said_to_the_nearest_minute_hour_or_day(span, words):
    assert notify._lasted(span) == words
