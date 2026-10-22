"""An alert with thousands of evidence logs opens, changes, exports and is explained without loading them one by one.

One hour of internet scanning is one alert, and from a file import it keeps every scanning connection as
evidence: 5,547 logs on the first one. Opening it asked for its timeline and its report, which loaded every
evidence log (4.7 s) and worked out a behaviour window for each (141 s); a status change, a note, an assignment
or an escalation loaded them all again (4 to 8 s). Asked about it, the assistant loaded them all too, twice for
one look-up (11 s), and so did its answers on source health and the latest alerts while it was among them (5 s).
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Generator

from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event, func, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from atdr.app.core.config import get_settings
from atdr.app.db.database import Base, get_db
from atdr.app.db.models import Alert, AlertEvidence, LogSource, NormalizedLog, RawLog
from atdr.app.main import app
from atdr.app.services.alert_service import (
    add_alert_note,
    alert_report,
    alert_timeline,
    assign_alert,
    escalate_alert,
    update_alert_status,
)
from atdr.app.services.assistant_service import (
    _answer_alert_list_question,
    _answer_alert_question,
    _answer_attack_status,
    _answer_general_question,
    _answer_safe_next_steps,
    _answer_source_question,
)
from atdr.app.services.assistant_tools import build_assistant_tools
from atdr.app.services.user_service import create_user
from atdr.tests.test_detection_grouping import _add_scan_log, _session

EVIDENCE_TABLES = ("alert_evidence", "normalized_logs", "raw_logs")


def _alert_with_evidence(db: Session, logs: int, *, first_index: int = 0, newest_linked_first: bool = False) -> Alert:
    for index in range(first_index, first_index + logs):
        _add_scan_log(db, index)
    db.flush()
    log_ids = list(db.scalars(select(NormalizedLog.id).order_by(NormalizedLog.id.desc()).limit(logs)))
    if not newest_linked_first:
        log_ids.reverse()
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


class _Built:
    """How many alerts, evidence links, logs and raw logs a block of code builds from the database."""

    MODELS = (Alert, AlertEvidence, NormalizedLog, RawLog)

    def __enter__(self) -> Counter:
        self.built: Counter[str] = Counter()
        for model in self.MODELS:
            event.listen(model, "load", self._count)
        return self.built

    def __exit__(self, *_exc) -> None:
        for model in self.MODELS:
            event.remove(model, "load", self._count)

    def _count(self, target, _context) -> None:
        self.built[type(target).__name__] += 1


def _from_source(db: Session, name: str, *, alert_id: int | None = None, latest_error: str | None = None) -> None:
    """Every raw log, or only the given alert's, came in through the named source."""

    source = LogSource(name=name, source_type="syslog", parser_profile="palo_alto", latest_error=latest_error)
    db.add(source)
    db.flush()
    raws = select(RawLog)
    if alert_id is not None:
        raws = raws.join(NormalizedLog, NormalizedLog.raw_log_id == RawLog.id).join(
            AlertEvidence, AlertEvidence.normalized_log_id == NormalizedLog.id).where(AlertEvidence.alert_id == alert_id)
    for raw in db.scalars(raws):
        raw.source_id = source.id
    db.commit()


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


def test_the_assistant_explains_a_large_alert_from_its_first_logs_and_counts_every_one():
    db = _session()
    small = _alert_with_evidence(db, 40).id
    # Linked newest first, so the oldest links are not simply the lowest log numbers.
    large = _alert_with_evidence(db, 120, first_index=40, newest_linked_first=True).id
    _from_source(db, "mfu-firewall")
    _from_source(db, "lab-replay", alert_id=small, latest_error="12 lines did not parse")
    oldest_log = db.scalar(select(NormalizedLog).where(NormalizedLog.id == 41))
    oldest_log.parsed_json = {"parser_warnings": ["field 42 missing"]}
    db.commit()

    built, answers = {}, {}
    for alert_id in (small, large):
        db.expunge_all()
        with _Built() as counted:
            answers[alert_id] = _answer_alert_question(db, f"Explain alert {alert_id}", alert_id=alert_id, redacted=False)
        built[alert_id] = dict(counted)
    assert built[large] == built[small], "a few logs are read one by one, never all of them"

    answer, record = answers[large].answer, answers[large].details["alert"]
    linked = list(db.scalars(select(AlertEvidence.normalized_log_id).where(AlertEvidence.alert_id == large)
                             .order_by(AlertEvidence.id)))
    assert linked[0] == 160, "newest linked first"
    assert record["evidence_count"] == 120 and "Evidence logs: 120;" in answer
    assert [row["id"] for row in record["related_logs"]] == linked[:8], "the oldest links first, as on the alert page"
    assert f"Related log IDs: {', '.join(str(log_id) for log_id in linked[:12])}\n" in answer
    assert [row["name"] for row in record["source_rows"]] == ["mfu-firewall"]
    assert [row["name"] for row in answers[small].details["alert"]["source_rows"]] == ["lab-replay"]
    source_caveat = "Linked source has parser/data-quality errors that can increase noise."
    assert source_caveat in answers[small].details["alert"]["false_positive_notes"]
    assert source_caveat not in record["false_positive_notes"]
    assert record["parser_notes"] == ["field 42 missing"], "a note on the last linked log still counts"
    assert answers[small].details["alert"]["parser_notes"] == []


def test_the_assistant_looks_up_a_large_alert_and_its_playbook_without_building_its_evidence():
    db = _session()
    alert_id = _alert_with_evidence(db, 120).id
    tools = {tool.name: tool for tool in build_assistant_tools(db, settings=get_settings())}
    texts = {}
    for name in ("get_alert", "get_alert_playbook"):
        db.expunge_all()
        with _Built() as built:
            texts[name] = tools[name].run({"alert_id": alert_id}).text
        assert not built["AlertEvidence"], f"{name} built the alert's evidence links"
        assert built["NormalizedLog"] < 120, f"{name} built every evidence log"
    assert "120 evidence logs, 120 related logs" in texts["get_alert"]


def test_answers_that_name_alerts_build_none_of_their_evidence():
    db = _session()
    alert = _alert_with_evidence(db, 120)
    alert.severity, alert.threat_score = "Critical", 90
    db.commit()
    alert_id = alert.id
    _from_source(db, "mfu-firewall")
    answers = {
        "source health": lambda: _answer_source_question(db, source_id=None, limit=5, redacted=False),
        "open alerts": lambda: _answer_alert_list_question(db, question="Show open alerts", redacted=False),
        "attack status": lambda: _answer_attack_status(db, redacted=False),
        "general": lambda: _answer_general_question(db, question="Tell me a story", limit=5, redacted=False,
                                                    settings=get_settings()),
        "next steps": lambda: _answer_safe_next_steps(db, "What next?", alert_id=alert_id, redacted=False),
        "next steps, no alert named": lambda: _answer_safe_next_steps(db, "What next?", alert_id=None, redacted=False),
        "latest critical alert": lambda: _answer_alert_question(db, "Explain the latest critical alert", alert_id=None,
                                                                redacted=False),
    }
    for name, answer in answers.items():
        db.expunge_all()
        with _Built() as built:
            answer()
        assert built["Alert"] and not built["AlertEvidence"], f"{name} built the alert's evidence links"


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


def test_the_alert_list_leaves_out_the_scanning_alerts_scanner_list_that_its_detail_shows():
    # The hourly scanning alert keeps up to 2,000 scanners; the list showed none of them but sent them all.
    client, engine = _client_with_alert(5)
    scanners = {f"198.51.100.{n}": {"connections": 40 - n, "targets": 20, "ports": [22, 80]} for n in range(1, 31)}
    with Session(engine) as db:
        alert = db.get(Alert, 1)
        alert.alert_type = "internet_scanning"
        alert.src_ip = None
        alert.matched_rules_json = [
            {"code": "internet_scanning", "title": "Internet scanning", "score": 50, "explanation": "30 scanners"},
            {"code": "group_metadata", "scanner_count": 30, "connections": 765, "scanners": scanners},
        ]
        db.commit()
    try:
        login = client.post("/api/auth/login", json={"username": "analyst", "password": "analyst123"})
        headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
        row = client.get("/api/alerts", headers=headers).json()[0]
        detail = client.get("/api/alerts/1", headers=headers).json()
    finally:
        app.dependency_overrides.clear()

    listed = next(rule for rule in row["matched_rules_json"] if rule["code"] == "group_metadata")
    shown = next(rule for rule in detail["matched_rules_json"] if rule["code"] == "group_metadata")
    assert "scanners" not in listed and (listed["scanner_count"], listed["connections"]) == (30, 765)
    assert shown["scanners"] == scanners
    assert row["matched_rules_json"][0] == detail["matched_rules_json"][0], "the rules themselves are listed in full"
