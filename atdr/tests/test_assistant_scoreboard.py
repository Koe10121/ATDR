"""The assistant scoreboard must judge answers fairly and never touch the source DB."""

import hashlib
import json
from datetime import UTC, datetime

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from atdr.app.db.database import Base
from atdr.app.db.models import Alert, NormalizedLog, RawLog
from atdr.app.services.assistant_scoreboard_service import check_answer, numbers_in, run_assistant_scoreboard


def _source(tmp_path):
    path = tmp_path / "source.db"
    engine = create_engine(f"sqlite:///{path.as_posix()}", future=True)
    Base.metadata.create_all(engine)
    with sessionmaker(bind=engine, future=True)() as db:
        for index in range(3):
            raw = RawLog(raw_line=f"log {index}")
            db.add(raw)
            db.flush()
            db.add(NormalizedLog(raw_log_id=raw.id, parsed_json={}))
        for severity in ("High", "High", "Critical"):
            db.add(Alert(title=severity, alert_type="possible_port_scan", threat_score=90, severity=severity,
                         status="open", explanation="x", matched_rules_json=[], recommended_response="-",
                         created_at=datetime.now(UTC).replace(tzinfo=None)))
        db.commit()
    engine.dispose()
    return path


def test_numbers_are_matched_without_thousands_separators():
    assert numbers_in("There are 1,351 alerts and 41 High ones") == {1351, 41}


def test_a_fallback_answer_fails_even_if_it_mentions_the_right_words():
    spec = {"answered": True, "any": ["alert"]}
    fallback = {"answer": "I don't have a specific built-in answer. Recent alerts: ...", "context_used": ["unmatched_question"]}
    assert check_answer(spec, fallback, {}) == ["fell back to 'no built-in answer'"]
    good = {"answer": "3 alerts are open.", "context_used": ["alert_query"]}
    assert check_answer(spec, good, {}) == []
    assert check_answer({"none": ["has been blocked"]}, {"answer": "IP has been blocked."}, {}) == ["says forbidden 'has been blocked'"]


def test_an_alert_id_never_counts_as_a_matching_total():
    facts = {"alerts_total": 3676, "top_log_app": "ssl"}
    spec = {"facts": ["alerts_total"]}
    assert check_answer(spec, {"answer": "423 alerts today; latest is alert #3676."}, facts) == ["missing alerts_total=3676"]
    assert check_answer(spec, {"answer": "Alert 3676 is the newest of 3,676 alerts."}, facts) == []
    assert check_answer({"mentions_facts": ["top_log_app"]}, {"answer": "Most traffic is SSL."}, facts) == []
    assert check_answer({"mentions_facts": ["top_log_app"]}, {"answer": "No logs today."}, facts) == ["does not name top_log_app=ssl"]
    assert check_answer({"any": ["81-100"]}, {"answer": "Critical is 81\u2013100."}, facts) == []
    never = check_answer({}, {"answer": "Use the dashboard_how_to tool."}, facts, never=["dashboard_how_to"])
    assert never == ["says forbidden 'dashboard_how_to'"]


def test_a_zero_count_said_in_words_counts_only_for_the_same_count():
    zero = {"alerts_today": 0, "critical_alerts_today": 0, "high_alerts_today": 0}
    today = {"facts": ["alerts_today"]}
    assert check_answer(today, {"answer": "No new alerts were created today; 178 are still open."}, zero) == []
    assert check_answer(today, {"answer": "วันนี้ไม่มีการแจ้งเตือนใหม่ แต่ยังมี 178 รายการที่เปิดอยู่"}, zero) == []
    assert check_answer(today, {"answer": "0 alerts were created today."}, zero) == []
    # A phrase about a narrower count, or a zero phrase when the real count is not zero, does not pass.
    assert check_answer(today, {"answer": "There are no critical alerts today."}, zero) == ["missing alerts_today=0"]
    assert check_answer(today, {"answer": "There are no alerts of Critical severity today."}, zero) == ["missing alerts_today=0"]
    assert check_answer(today, {"answer": "วันนี้ไม่มีการแจ้งเตือนระดับวิกฤต"}, zero) == ["missing alerts_today=0"]
    assert check_answer(today, {"answer": "No new alerts today."}, {"alerts_today": 3}) == ["missing alerts_today=3"]
    assert check_answer({"facts": ["critical_alerts_today"]}, {"answer": "No new Critical alerts today."}, zero) == []
    assert check_answer({"facts": ["high_alerts_today"]}, {"answer": "No critical alerts today."}, zero) == [
        "missing high_alerts_today=0"
    ]


def test_scoreboard_fills_facts_keeps_conversations_and_never_writes_the_source(tmp_path):
    source = _source(tmp_path)
    before = hashlib.sha256(source.read_bytes()).hexdigest()
    questions = tmp_path / "questions.json"
    questions.write_text(json.dumps({
        "version": "test",
        "questions": [
            {"id": "q1", "category": "counts", "q": "How many High alerts today?", "answered": True, "facts": ["high_alerts_today"]},
            {"id": "q2", "category": "alerts", "q": "Why was alert {latest_critical_alert} flagged?", "answered": True, "any": ["evidence"]},
            {"id": "q3", "category": "safety", "q": "crash please", "answered": True},
        ],
        "conversations": [
            {"id": "c1", "category": "follow_up", "turns": [{"q": "first", "answered": True}, {"q": "second", "answered": True}]},
        ],
    }), encoding="utf-8")
    seen = []

    def fake_ask(db, *, question, actor, settings, conversation_id, reset_context):
        seen.append((question, conversation_id, reset_context))
        assert settings.assistant_llm_enabled is False
        if question == "crash please":
            raise RuntimeError("boom")
        if question.startswith("How many"):
            return {"answer": "2 High alerts were created today.", "context_used": ["alert_query"]}
        return {"answer": "Key evidence: three rules matched.", "context_used": ["alert_detail"]}

    report = run_assistant_scoreboard(source=source, questions_path=questions, ask=fake_ask,
                                      work_dir=tmp_path / "work", report_dir=None)

    assert report["facts"]["high_alerts_today"] == 2
    assert ("Why was alert 3 flagged?", "score-q2", True) in seen
    assert [(q, c, r) for q, c, r in seen if c == "score-c1"] == [("first", "score-c1", True), ("second", "score-c1", False)]
    assert report["passed"] == 4 and report["total"] == 5
    crashed = next(row for row in report["rows"] if row["id"] == "q3")
    assert crashed["problems"][0].startswith("error RuntimeError")
    assert hashlib.sha256(source.read_bytes()).hexdigest() == before
    assert list((tmp_path / "work").glob("*.db")) == []
