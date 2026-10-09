"""An alert with thousands of evidence logs opens, changes and exports without loading them one by one.

One hour of internet scanning is one alert, and from a file import it keeps every scanning connection as
evidence: 5,547 logs on the first one. Opening it asked for its timeline and its report, which loaded every
evidence log (4.7 s) and worked out a behaviour window for each (141 s); a status change, a note, an assignment
or an escalation loaded them all again (4 to 8 s).
"""

from __future__ import annotations

from collections.abc import Generator

from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event, func, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from atdr.app.db.database import Base, get_db
from atdr.app.db.models import Alert, AlertEvidence, NormalizedLog
from atdr.app.main import app
from atdr.app.services.alert_service import (
    add_alert_note,
    alert_report,
    alert_timeline,
    assign_alert,
    escalate_alert,
    update_alert_status,
)
from atdr.app.services.user_service import create_user
from atdr.tests.test_detection_grouping import _add_scan_log, _session

EVIDENCE_TABLES = ("alert_evidence", "normalized_logs", "raw_logs")


def _alert_with_evidence(db: Session, logs: int, *, first_index: int = 0) -> Alert:
    for index in range(first_index, first_index + logs):
        _add_scan_log(db, index)
    db.flush()
    log_ids = list(db.scalars(select(NormalizedLog.id).order_by(NormalizedLog.id.desc()).limit(logs)))[::-1]
    alert = Alert(title="Medium: scan", alert_type="possible_horizontal_scan", threat_score=50, severity="Medium",
                  status="open", explanation="scan", matched_rules_json=[], recommended_response="look",
                  src_ip="203.0.113.10")
    db.add(alert)
    db.flush()
    db.add_all(AlertEvidence(alert_id=alert.id, normalized_log_id=log_id) for log_id in log_ids)
    db.commit()
    return alert


class _Statements:
    """The SQL a block of code sends."""

    def __init__(self, engine) -> None:
        self.engine = engine
        self.sent: list[str] = []

    def __enter__(self) -> list[str]:
        event.listen(self.engine, "before_cursor_execute", self._record)
        return self.sent

    def __exit__(self, *_exc) -> None:
        event.remove(self.engine, "before_cursor_execute", self._record)

    def _record(self, _connection, _cursor, statement, *_rest) -> None:
        self.sent.append(statement)


def _reads_evidence(statements: list[str]) -> list[str]:
    return [statement for statement in statements if any(table in statement for table in EVIDENCE_TABLES)]


def test_actions_on_an_alert_leave_its_evidence_logs_unread_and_in_place():
    db = _session()
    alert_id = _alert_with_evidence(db, 30).id
    create_user(db, username="koe", password="koe-password-1", role="analyst", full_name="Koe")
    actions = {
        "status": lambda: update_alert_status(db, alert_id, "investigating", actor="koe"),
        "note": lambda: add_alert_note(db, alert_id, author="koe", note="looked at the busiest scanner"),
        "assign": lambda: assign_alert(db, alert_id, assigned_to="koe", actor="koe"),
        "escalate": lambda: escalate_alert(db, alert_id, priority_owner="koe", escalation_reason="keeps coming back",
                                           ticket_reference="MFU-1", actor="koe"),
        "timeline": lambda: alert_timeline(db, alert_id),
    }
    for name, action in actions.items():
        db.expire_all()
        with _Statements(db.get_bind()) as sent:
            assert action() is not None
        assert sent and not _reads_evidence(sent), f"{name} read the alert's evidence logs"

    alert = db.get(Alert, alert_id)
    assert (alert.status, alert.assigned_to, alert.priority_owner, alert.ticket_reference) == ("investigating", "koe", "koe", "MFU-1")
    assert db.scalar(select(func.count(AlertEvidence.id)).where(AlertEvidence.alert_id == alert_id)) == 30
    assert [item["event_type"] for item in alert_timeline(db, alert_id)] == [
        "created", "alert_investigating", "alert_note_added", "alert_assigned", "alert_escalated",
    ]


def test_a_report_takes_the_same_number_of_queries_for_ten_evidence_logs_as_for_a_hundred_and_twenty():
    db = _session()
    small = _alert_with_evidence(db, 10).id
    large = _alert_with_evidence(db, 120, first_index=10).id
    sent = {}
    for alert_id in (small, large):
        db.expire_all()
        with _Statements(db.get_bind()) as statements:
            report = alert_report(db, alert_id, behavior_window_logs=0)
        sent[alert_id] = len(statements)
        linked = list(db.scalars(select(AlertEvidence.normalized_log_id).where(AlertEvidence.alert_id == alert_id)
                                 .order_by(AlertEvidence.id)))
        assert [log["id"] for log in report["evidence_logs"]] == linked, "every evidence log, oldest link first"
        assert report["evidence_count"] == len(linked) and report["evidence_logs_truncated"] is False
    assert sent[small] == sent[large]

    log = alert_report(db, large, behavior_window_logs=0)["evidence_logs"][0]
    assert (log["src_ip"], log["dst_ip"], log["dst_port"], log["action"], log["app"]) == ("203.0.113.10", "10.0.0.10", 10010, "allow", "unknown")
    assert log["raw_line_excerpt"] == "scan log 10" and log["generated_time"].isoformat() == "2026-05-20T13:36:15"


def test_a_report_works_out_behaviour_windows_for_its_first_logs_and_counts_every_log():
    db = _session()
    alert_id = _alert_with_evidence(db, 30).id
    newest = db.scalar(select(func.max(NormalizedLog.id)))
    db.get(NormalizedLog, newest).is_anomaly = True
    db.commit()

    report = alert_report(db, alert_id, behavior_window_logs=3)
    windows = [log["behavior_window"] for log in report["evidence_logs"]]
    assert len(windows) == 30
    assert [window["available"] for window in windows] == [True] * 3 + [False] * 27
    assert windows[2]["src_ip_5min_log_count"] == 3, "the third log's window holds the three logs up to it"
    assert "first 3 evidence logs" in windows[3]["reason"] and "error" not in windows[3]
    assert report["anomaly_evidence_count"] == 1

    preview = alert_report(db, alert_id, evidence_limit=5, behavior_window_logs=3)
    assert [log["id"] for log in preview["evidence_logs"]] == [log["id"] for log in report["evidence_logs"][:5]]
    assert preview["evidence_logs_truncated"] is True and preview["evidence_count"] == 30
    assert preview["anomaly_evidence_count"] == 1, "counted over every evidence log, not the five listed"
    assert "30 linked evidence logs" in preview["executive_summary"]


def _client_with_alert(logs: int) -> tuple[TestClient, object]:
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool, future=True)
    Base.metadata.create_all(engine)
    testing_session = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
    with testing_session() as db:
        create_user(db, username="analyst", password="analyst123", role="analyst", full_name="Test Analyst")
        _alert_with_evidence(db, logs)

    def override_get_db() -> Generator[Session, None, None]:
        db = testing_session()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    return TestClient(app), engine


def test_the_api_answers_for_a_large_alert_the_way_its_detail_does():
    client, engine = _client_with_alert(120)
    try:
        login = client.post("/api/auth/login", json={"username": "analyst", "password": "analyst123"})
        headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
        detail = client.get("/api/alerts/1", headers=headers).json()
        assert (detail["evidence_count"], len(detail["evidence_log_ids"]), detail["evidence_log_ids_truncated"]) == (120, 100, True)

        assigned = client.post("/api/alerts/1/assign/me", headers=headers)
        escalated = client.post("/api/alerts/1/escalate", headers=headers, json={
            "priority_owner": "analyst", "escalation_reason": "keeps coming back", "ticket_reference": "MFU-1"})
        for response in (assigned, escalated):
            assert response.status_code == 200
            body = response.json()
            assert body["assigned_to"] == "analyst"
            for key in ("evidence_count", "evidence_log_ids", "evidence_log_ids_truncated", "source_ids", "source_names"):
                assert body[key] == detail[key], key
        assert escalated.json()["ticket_reference"] == "MFU-1"

        with _Statements(engine) as for_preview:
            preview = client.get("/api/alerts/1/report?evidence_limit=25", headers=headers).json()
        assert (len(preview["evidence_logs"]), preview["evidence_count"], preview["evidence_logs_truncated"]) == (25, 120, True)
        assert all(log["behavior_window"]["available"] for log in preview["evidence_logs"])
        whole = client.get("/api/alerts/1/report", headers=headers).json()
        assert len(whole["evidence_logs"]) == 120 and whole["evidence_logs_truncated"] is False
        assert sum(1 for log in whole["evidence_logs"] if log["behavior_window"]["available"]) == 25

        # A download keeps every evidence log, whatever the page asked for. It shows no behaviour windows, so it
        # works out none for them: the preview's 25 take about fifteen queries each.
        with _Statements(engine) as for_download:
            csv_rows = client.get("/api/alerts/1/report?format=csv&evidence_limit=25", headers=headers).text.strip().splitlines()
        assert len(csv_rows) == 121
        assert len(for_download) * 5 < len(for_preview)
        html = client.get("/api/alerts/1/report?format=html&evidence_limit=25", headers=headers).text
        assert html.count("<td>203.0.113.10</td>") == 120
        assert client.get("/api/alerts/1/report?format=pdf", headers=headers).content.startswith(b"%PDF")
        assert client.get("/api/alerts/1/report?evidence_limit=0", headers=headers).status_code == 422
    finally:
        app.dependency_overrides.clear()
