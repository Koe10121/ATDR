from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from atdr.app.core.config import get_settings
from atdr.app.db.database import Base
from atdr.app.db.models import Alert
from atdr.app.detection.rule_catalog import RULE_CATALOG
from atdr.app.main import app
from atdr.app.services import assistant_data_query, assistant_service
from atdr.app.services.assistant_data_query import answer_data_question, parse_data_question
from atdr.app.services.assistant_help import answer_help_question, answer_rule_question
from atdr.tests.test_assistant import _client_with_session, _login

BANGKOK = timezone(timedelta(hours=7))
NOW = datetime(2026, 9, 26, 10, 0, tzinfo=BANGKOK)


@pytest.fixture(autouse=True)
def _local_llm_and_fixed_clock(monkeypatch):
    monkeypatch.setenv("ASSISTANT_LLM_ENABLED", "false")
    monkeypatch.setattr(assistant_data_query, "_local_now", lambda: NOW)
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def _parse(question: str):
    return parse_data_question(question, now=NOW)


# ------------------------------------------------------------------ parsing


@pytest.mark.parametrize(
    ("question", "expected"),
    [
        ("How many high alerts do we have today?", ("alerts", "count", "High", None, None, None, "today")),
        ("How many critical alerts are open?", ("alerts", "count", "Critical", "open", None, None, "in total")),
        ("Which source IP has the most alerts this week?", ("alerts", "top", None, None, None, "src_ip", "this week (since Monday 21 Sep)")),
        ("How many port scan alerts were there yesterday?", ("alerts", "count", None, None, "port_scan", None, "yesterday")),
        ("What is the most common attack type?", ("alerts", "top", None, None, None, "attack_type", "in total")),
        ("How many false positives this week?", ("alerts", "count", None, "false_positive", None, None, "this week (since Monday 21 Sep)")),
        ("Alerts per day this week", ("alerts", "trend", None, None, None, None, "this week (since Monday 21 Sep)")),
        ("How many alerts by severity?", ("alerts", "top", None, None, None, "severity", "in total")),
        ("Which rule fires the most?", ("alerts", "top", None, None, None, "rule", "in total")),
        ("Show high alerts from today", ("alerts", "list", "High", None, None, None, "today")),
        ("How many alerts in the last 48 hours?", ("alerts", "count", None, None, None, None, "in the last 48 hours")),
        ("top 3 destination ports for denied traffic", ("logs", "top", None, None, None, "dst_port", "in total")),
    ],
)
def test_data_questions_become_the_right_structured_query(question, expected):
    parsed = _parse(question)
    assert parsed is not None, question
    subject, intent, severity, status, attack_type, group_by, window = expected
    assert (parsed.subject, parsed.intent, parsed.severity, parsed.status, parsed.attack_type, parsed.group_by, parsed.window.phrase) == (
        subject,
        intent,
        severity,
        status,
        attack_type,
        group_by,
        window,
    )


@pytest.mark.parametrize(
    "question",
    [
        "Why was alert 3224 flagged?",
        "How many logs are related to alert 12?",
        "Is this likely a false positive?",
        "How do I add an IP to a watchlist?",
        "Show latest critical alerts.",
        "Show open alerts",
        "Explain the latest critical alert.",
        "What are the most recent alerts?",
        "Summarize source health.",
        "How many users are there?",
        "How many detection runs failed?",
    ],
)
def test_questions_for_other_routes_are_left_alone(question):
    # Guessing here is what made "how many high alerts today" explain alert #3224.
    assert _parse(question) is None


def test_time_windows_are_calendar_days_in_local_time():
    today = _parse("How many alerts today?").window
    yesterday = _parse("How many alerts yesterday?").window
    assert today.start == datetime(2026, 9, 26, tzinfo=BANGKOK) and today.end is None
    assert (yesterday.start, yesterday.end) == (datetime(2026, 9, 25, tzinfo=BANGKOK), datetime(2026, 9, 26, tzinfo=BANGKOK))
    assert _parse("How many alerts last week?").window.start == datetime(2026, 9, 14, tzinfo=BANGKOK)
    assert _parse("How many alerts in the last 24 hours?").window.start == NOW - timedelta(hours=24)


def test_ips_and_log_filters_are_read_from_the_question():
    parsed = _parse("How many denied connections from 203.0.113.44?")
    assert (parsed.subject, parsed.src_ip, parsed.actions) == ("logs", "203.0.113.44", ("deny", "drop"))
    assert _parse("How many alerts to 10.0.0.9?").dst_ip == "10.0.0.9"
    assert _parse("How many alerts involving 10.0.0.9?").any_ip == "10.0.0.9"
    risky = _parse("Which high risk apps have the most traffic?")
    assert (risky.subject, risky.severity, risky.min_app_risk, risky.group_by) == ("logs", None, 4, "app")


# ---------------------------------------------------------------- answering


def _utc(local: datetime) -> datetime:
    return local.astimezone(UTC).replace(tzinfo=None)


def _alert(alert_id, severity, code, created_local, *, src_ip=None, status="open", score=60):
    return Alert(
        id=alert_id,
        title=f"{severity}: {code}",
        alert_type=code,
        src_ip=src_ip,
        dst_ip="10.9.9.9",
        threat_score=score,
        severity=severity,
        status=status,
        explanation="Test.",
        matched_rules_json=[{"code": code, "title": code, "score": 25, "explanation": "x"}],
        recommended_response="Review.",
        created_at=_utc(created_local),
        updated_at=_utc(created_local),
    )


@pytest.fixture()
def db():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool, future=True)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, future=True)()
    session.add_all(
        [
            _alert(1, "High", "possible_port_scan", datetime(2026, 9, 26, 9, 0, tzinfo=BANGKOK), src_ip="10.0.0.1", score=70),
            _alert(2, "High", "brute_force_like_attempts", datetime(2026, 9, 25, 12, 0, tzinfo=BANGKOK), src_ip="10.0.0.1", status="resolved"),
            _alert(3, "Critical", "possible_port_scan", datetime(2026, 9, 26, 8, 0, tzinfo=BANGKOK), src_ip="10.0.0.2", score=95),
            _alert(4, "Low", "deny_drop_action", datetime(2026, 6, 1, 9, 0, tzinfo=BANGKOK)),
            # 01:00 local on the 26th is still the 25th in UTC: it must count as today.
            _alert(5, "Medium", "possible_port_scan", datetime(2026, 9, 26, 1, 0, tzinfo=BANGKOK), src_ip="10.0.0.2"),
        ]
    )
    session.commit()
    yield session
    session.close()


def test_counts_use_local_days_and_say_what_was_counted(db):
    today = answer_data_question(db, _parse("How many alerts today?"))
    assert today.counts["total"] == 3  # alerts 1, 3 and 5 (5 is still the 25th in UTC)
    assert today.summary == "3 alerts were created today."
    assert "any severity, any status" in today.basis and "UTC+07:00" in today.basis

    high_today = answer_data_question(db, _parse("How many high alerts do we have today?"))
    assert high_today.summary == "1 High alert was created today."
    assert high_today.counts["total"] == 1

    port_scans = answer_data_question(db, _parse("How many port scan alerts this week?"))
    assert port_scans.counts["total"] == 3


def test_an_empty_window_points_to_the_latest_matching_alert(db):
    answer = answer_data_question(db, _parse("How many high alerts last month?"))
    assert answer.counts["total"] == 0
    assert answer.summary == "0 High alerts were created last month (August)."
    assert answer.lines == ["Most recent: alert #1 (High) on 26 Sep 2026 09:00."]


def test_rankings_leave_out_missing_ips_and_name_an_example_alert(db):
    answer = answer_data_question(db, _parse("Which source IPs have the most alerts?"))
    assert answer.counts["ranked"] == [("10.0.0.1", 2), ("10.0.0.2", 2)]
    assert answer.lines[0].startswith("10.0.0.1: 2 alerts (40%), e.g. alert #")
    assert "1 alert had no source IP and is not ranked" in answer.basis

    attack_types = answer_data_question(db, _parse("What is the most common attack type?"))
    assert attack_types.counts["ranked"][0] == ("port scan", 3)


def test_trend_lists_busy_days_newest_first(db):
    answer = answer_data_question(db, _parse("How many alerts per day this week?"))
    assert answer.counts["per_day"] == {"2026-09-26": 3, "2026-09-25": 1}
    assert answer.lines == ["Sat 26 Sep: 3 alerts", "Fri 25 Sep: 1 alert"]


def test_list_answers_show_the_highest_scoring_matches(db):
    answer = answer_data_question(db, _parse("Show high alerts from today"))
    assert answer.counts["alert_ids"] == [1]
    assert answer.lines[0].startswith("Alert #1: High, port scan, source 10.0.0.1, score 70")


# ------------------------------------------------------------ help and rules


@pytest.mark.parametrize(
    ("question", "topic", "must_mention"),
    [
        ("How do I add an IP to a watchlist?", "watchlist", "Create watchlist item"),
        ("How do I mark an alert as false positive?", "status", "False positive"),
        ("How can I block an IP?", "block", "Record simulated block"),
        ("How do I run detection?", "run_detection", "Run detection"),
        ("How do I update many alerts at once?", "bulk", "tick the box"),
        ("Where can I download a PDF report?", "report", "Download PDF"),
    ],
)
def test_how_to_questions_get_steps_that_name_real_buttons(question, topic, must_mention):
    answer = answer_help_question(question)
    assert answer is not None and answer.context == f"dashboard_help:{topic}"
    assert any(must_mention in step for step in answer.steps)


def test_rule_answers_come_from_the_catalog():
    brute = answer_rule_question("What does the brute force rule check?")
    assert brute.codes == ["brute_force_like_attempts"]
    assert brute.lines[0] == f"Checks: {RULE_CATALOG['brute_force_like_attempts'].condition}."

    port_scan = answer_rule_question("What does the port scan rule check?")
    assert set(port_scan.codes) == {"possible_port_scan", "possible_horizontal_scan"}

    listing = answer_rule_question("How many rules are there?")
    assert listing.summary.startswith(f"ATDR has {len(RULE_CATALOG) - 1} fixed detection rules")
    assert answer_rule_question("What are the response safety rules?") is None


# ------------------------------------------------------------- through the API


def test_chat_answers_flexible_questions_on_topic_and_keeps_old_routes():
    client, _ = _client_with_session()
    headers = _login(client)
    try:
        expectations = {
            "How many critical alerts are open?": ("data_answer", "alert_query"),
            "What is the most common attack type?": ("data_answer", "alert_query"),
            "How many denied connections?": ("data_answer", "log_query"),
            "How do I add an IP to a watchlist?": ("how_to", "dashboard_help"),
            "What does the brute force rule check?": ("data_answer", "rule_catalog"),
            "What can you do?": ("data_answer", "assistant_capabilities"),
            "Why was alert 1 flagged?": ("alert_explanation", "alert_detail"),
            "Show latest critical alerts.": ("list_summary", None),
        }
        for question, (mode, context) in expectations.items():
            payload = client.post("/api/assistant/chat", json={"question": question}, headers=headers).json()
            assert payload["response_mode"] == mode, (question, payload["response_mode"])
            if context:
                assert context in payload["context_used"], (question, payload["context_used"])

        critical = client.post("/api/assistant/chat", json={"question": "How many critical alerts are open?"}, headers=headers).json()
        assert critical["answer"].startswith("1 open Critical alert in total.")

        refused = client.post("/api/assistant/chat", json={"question": "block this ip 203.0.113.10"}, headers=headers).json()
        assert "assistant_safety_guardrail" in refused["context_used"]
    finally:
        app.dependency_overrides.clear()


def test_a_question_that_only_mentions_alerts_is_not_answered_with_an_alert_explanation():
    client, _ = _client_with_session()
    headers = _login(client)
    try:
        payload = client.post("/api/assistant/chat", json={"question": "Tell me about the alerts"}, headers=headers).json()
        assert "alert_detail" not in payload["context_used"]
        assert "unmatched_question" in payload["context_used"]
    finally:
        app.dependency_overrides.clear()


def test_exact_data_answers_skip_the_provider_but_help_answers_may_use_it(monkeypatch):
    calls: list[str] = []

    def fake_provider(request, settings):
        calls.append(request.response_mode)
        return assistant_service.AssistantLLMResult(used=False, provider="gemini", fallback_reason="provider_disabled")

    monkeypatch.setattr(assistant_service, "maybe_generate_external_answer", fake_provider)
    client, _ = _client_with_session()
    headers = _login(client)
    try:
        client.post("/api/assistant/chat", json={"question": "How many critical alerts are open?"}, headers=headers)
        assert calls == []
        client.post("/api/assistant/chat", json={"question": "How do I add an IP to a watchlist?"}, headers=headers)
        assert calls == ["how_to"]
    finally:
        app.dependency_overrides.clear()


def test_ranked_ips_stay_redacted_in_answers_but_keep_an_alert_to_open():
    client, _ = _client_with_session()
    headers = _login(client)
    try:
        payload = client.post("/api/assistant/chat", json={"question": "Which source IPs have the most alerts?"}, headers=headers).json()
        assert "203.0.113.10" not in payload["answer"]
        assert "[redacted-ip]: 1 alert (100%), e.g. alert #1" in payload["answer"]
    finally:
        app.dependency_overrides.clear()
