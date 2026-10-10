"""The bell's routes, the test message, and what a reset and a rebuild do about notifications."""

from __future__ import annotations

from collections.abc import Generator
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from atdr.app.core.config import Settings
from atdr.app.db.database import Base, get_db
from atdr.app.db.models import Alert, AuditLog, Notification, NotificationAlert, NotificationDelivery, NotificationSeen, NotificationState
from atdr.app.main import app
from atdr.app.routers import notifications as routes
from atdr.app.services import demo_service
from atdr.app.services import notification_service as notify
from atdr.app.services.alert_rebuild_service import rebuild_alerts
from atdr.app.services.demo_service import clear_demo_data, reset_and_seed_demo
from atdr.app.services.notification_service import notification_look, part_problem, report_problem
from atdr.app.services.user_service import create_user
from atdr.tests.test_api import TRAFFIC_LINE
from atdr.tests.test_detection_grouping import _session

START = datetime(2026, 10, 9, 3, 0, tzinfo=timezone.utc)
MINUTE = timedelta(minutes=1)
QUIET = {"ATDR_NOTIFY_WINDOWS": False, "ATDR_NOTIFY_SUMMARY_AT": "", "ATDR_NOTIFY_DISK_FREE_GB": 0, "ATDR_BACKUP_SCHEDULE_HOURS": 0,
         "AUTO_DETECTION_ENABLED": False, "SYSLOG_ENABLED": False}


def _settings(**overrides) -> Settings:
    return Settings(_env_file=None, **{**QUIET, **overrides})


def _critical(db: Session, when: datetime) -> Alert:
    alert = Alert(title="Critical: watchlist match", alert_type="watchlist_match", threat_score=95, severity="Critical", status="open",
                  explanation="kept", matched_rules_json=[{"code": "watchlist_match", "attack_type": "malware_c2"}],
                  recommended_response="look", created_at=when, updated_at=when)
    db.add(alert)
    db.commit()
    return alert


def _look(db: Session, when: datetime, *, senders: dict | None = None, **overrides) -> dict:
    return notification_look(db, settings=_settings(**overrides), now=when, senders=senders or {}, runtime=Path("no-such-folder"),
                             find_offsite=lambda _settings: [])


def test_the_bell_is_for_whoever_is_signed_in_and_a_test_message_for_admins(monkeypatch):
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool, future=True)
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
    with factory() as db:
        create_user(db, username="admin", password="admin123", role="admin", full_name="Test Admin")
        create_user(db, username="analyst", password="analyst123", role="analyst", full_name="Test Analyst")
        _look(db, START)
        _critical(db, START)
        _look(db, START + MINUTE * 2)
        report_problem(db, part_problem("atdr-worker"), settings=_settings(), now=START + MINUTE * 3, senders={})
        # Old enough that none of it is "the last day's" for someone who has never opened the bell.
        db.execute(Notification.__table__.update().values(created_at=datetime.now(timezone.utc) - timedelta(minutes=5)))
        db.commit()

    def override_get_db() -> Generator[Session, None, None]:
        session = factory()
        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[get_db] = override_get_db
    try:
        client = TestClient(app)

        def headers(name: str, password: str) -> dict[str, str]:
            return {"Authorization": f"Bearer {client.post('/api/auth/login', json={'username': name, 'password': password}).json()['access_token']}"}

        assert client.get("/api/notifications").status_code == 401
        assert client.post("/api/notifications/seen", json={"up_to": 1}).status_code == 401
        assert client.post("/api/notifications/test", json={"channel": "email"}).status_code == 401

        analyst, admin = headers("analyst", "analyst123"), headers("admin", "admin123")
        seen_by_analyst = client.get("/api/notifications", headers=analyst).json()
        assert [(item["id"], item["kind"]) for item in seen_by_analyst["items"]] == [(2, "alerts"), (1, "started")]
        assert seen_by_analyst["unread"] == 2 and seen_by_analyst["newest_id"] == 2
        newest = seen_by_analyst["items"][0]
        assert datetime.fromisoformat(newest.pop("created_at").replace("Z", "+00:00")) > datetime.now(timezone.utc) - timedelta(minutes=6)
        assert newest == {
            "id": 2, "kind": "alerts", "level": "critical", "title": "New Critical alert #1: malware / C2",
            # The time is the machine's own.
            "body": f"Raised {START.astimezone():%H:%M}.", "link": "/alerts?alert=1", "unread": True,
            "alerts": [{"id": 1, "severity": "Critical", "attack": "malware / C2"}],
        }
        seen_by_admin = client.get("/api/notifications", headers=admin).json()
        assert [item["kind"] for item in seen_by_admin["items"]] == ["problem", "alerts", "started"] and seen_by_admin["unread"] == 3
        assert len(client.get("/api/notifications?limit=1", headers=admin).json()["items"]) == 1
        assert client.get("/api/notifications?limit=0", headers=admin).status_code == 422

        assert client.post("/api/notifications/seen", json={"up_to": 2}, headers=analyst).json() == {"seen_id": 2}
        assert client.get("/api/notifications", headers=analyst).json()["unread"] == 0
        assert client.get("/api/notifications", headers=admin).json()["unread"] == 3, "the admin has not looked"
        assert client.post("/api/notifications/seen", json={"up_to": -1}, headers=analyst).status_code == 422

        # A test message: admins only; it says in words what happened, and the audit log keeps who asked.
        assert client.post("/api/notifications/test", json={"channel": "email"}, headers=analyst).status_code == 403
        not_set_up = client.post("/api/notifications/test", json={"channel": "email"}, headers=admin)
        assert not_set_up.status_code == 200
        assert not_set_up.json() == {"ok": False, "channel": "email", "words": "Email is not set up: no address to send to (ATDR_NOTIFY_EMAIL_TO is empty)."}

        sent: list[str] = []
        real = notify.send_test
        ready = _settings(ATDR_NOTIFY_CHAT_WEBHOOK_URL="https://chat.example.org/hook/secret-token")
        monkeypatch.setattr(routes, "send_test", lambda db, channel, **kwargs: real(
            db, channel, settings=ready, senders={"chat": lambda _settings, message: sent.append(message.title)}, **kwargs))
        went = client.post("/api/notifications/test", json={"channel": "chat"}, headers=admin)
        assert went.json() == {"ok": True, "channel": "chat", "words": "Chat message sent."} and sent == ["Test message from ATDR"]
        # A double click is not a second message.
        again = client.post("/api/notifications/test", json={"channel": "chat"}, headers=admin)
        assert again.json()["ok"] is False and "a moment ago" in again.json()["words"] and len(sent) == 1
        with factory() as db:
            asked = list(db.scalars(select(AuditLog).where(AuditLog.action == "notification_test").order_by(AuditLog.id)))
            assert [(entry.actor, entry.target_value, entry.details["ok"]) for entry in asked] == [("admin", "email", False), ("admin", "chat", True)]
            assert all("secret-token" not in str(entry.details) for entry in asked)
        assert client.get("/api/notifications", headers=analyst).json()["unread"] == 0, "a test message is for admins"
    finally:
        app.dependency_overrides.clear()


def test_a_reset_takes_the_notifications_about_what_it_deletes_and_does_not_report_the_sample(tmp_path, monkeypatch):
    database = tmp_path / "C" / "atdr.db"
    database.parent.mkdir(parents=True)
    engine = create_engine(f"sqlite:///{database.as_posix()}", connect_args={"check_same_thread": False}, future=True)
    Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine, autoflush=False, future=True)()
    admin = create_user(db, username="admin", password="admin123", role="admin", full_name="Test Admin")
    chat = {"senders": {"chat": lambda _settings, _message: None}, "ATDR_NOTIFY_CHAT_WEBHOOK_URL": "https://chat.example.org/hook/x"}
    _look(db, START, **chat)
    _critical(db, START)
    _look(db, START + MINUTE * 2, **chat)
    report_problem(db, part_problem("atdr-worker"), settings=_settings(), now=START + MINUTE * 3, senders={})
    notify.mark_seen(db, admin, 3)
    assert db.scalar(select(func.count()).select_from(Notification)) == 3

    covered: list[int] = []
    real = demo_service.cover_alerts
    monkeypatch.setattr(demo_service, "cover_alerts", lambda session: covered.append(real(session, settings=_settings())))
    sample = tmp_path / "sample.log"
    sample.write_text(TRAFFIC_LINE + "\n", encoding="utf-8")
    result = reset_and_seed_demo(db, sample_path=sample, limit=10)

    assert (result["deleted"]["notifications"], result["deleted"]["notification_deliveries"], result["deleted"]["notification_alerts"]) == (3, 1, 1)
    assert len(covered) == 1, "the sample's alerts are marked as not news, after the detection run that raises them"
    # Who has read what, when reporting began, and ATDR's own problems are not about the deleted data.
    assert db.get(NotificationSeen, admin.id).seen_id == 3 and db.get(NotificationState, "started_at") is not None
    assert list(db.scalars(select(notify.NotificationCondition.key))) == ["part_keeps_stopping:atdr-worker"]
    # A number is never given out twice, so the reader's marker still means what it meant.
    report_problem(db, part_problem("atdr-backend"), settings=_settings(), now=START + MINUTE * 9, senders={})
    assert db.scalar(select(func.max(Notification.id))) == 4

    # By hand: an alert raised by the reset itself is covered, and so never reported.
    _critical(db, START + MINUTE * 10)
    assert real(db, settings=_settings()) == 1
    db.commit()
    assert _look(db, START + MINUTE * 30)["made"] == []
    assert clear_demo_data(db)["notification_alerts"] == 1


def test_a_rebuild_does_not_report_the_same_findings_again_under_their_new_numbers(monkeypatch):
    db = _session()
    _look(db, START)
    old = _critical(db, START)
    _look(db, START + MINUTE * 2)
    assert db.scalar(select(func.count()).select_from(NotificationAlert)) == 1

    def detect(session: Session) -> dict:
        # The same finding, raised again by the current rules under a new number.
        _critical(session, START + MINUTE * 10)
        return {"evaluated": 0, "created_alerts": 1}

    monkeypatch.setattr("atdr.app.services.alert_rebuild_service.cover_alerts", lambda session: notify.cover_alerts(session, settings=_settings()))
    summary = rebuild_alerts(db, actor="koe", reason="a change of grouping", detect=detect)
    assert summary["archived"] == 1 and summary["new_alerts"] == 1
    new = db.scalar(select(Alert))
    assert new.id != old.id and db.get(NotificationAlert, new.id).notification_id is None, "marked as reported, by no notification"
    assert _look(db, START + MINUTE * 30)["made"] == []
    assert [row.kind for row in db.scalars(select(Notification).order_by(Notification.id))] == ["started", "alerts"]
    assert db.scalar(select(func.count()).select_from(NotificationDelivery)) == 0
