"""Synthetic regressions for the capstone reliability boundary; no live providers or artifacts."""

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from sqlalchemy import select
from sqlalchemy.dialects import postgresql

from atdr.app.db.models import AuditLog, BlockedIP, DetectionRun
from atdr.app.detection import runtime_contract
from atdr.app.services import assistant_agent, assistant_service, behavior_findings_service, response_service
from atdr.app.services.assistant_response_contracts import response_contract
from atdr.tests.test_assistant_agent import ScriptedEngine, _ask, _call, _count_tool, _say, seeded  # noqa: F401
from atdr.tests.test_behavior_findings import START, db  # noqa: F401
from atdr.tests.test_model_alerts import _quiet_scanner, _switched_on
from atdr.tests.test_windows_firewall_response import _session, _settings


@pytest.mark.parametrize("claim", ["500 critical alerts", "1 critical alert", "alert #7"])
def test_question_numbers_are_not_verified_facts(claim):
    problems = assistant_agent.verify_answer(
        f"There are {claim}.", evidence=["7 High alerts."], asked=[f"We have {claim}, right?"],
        redacted=True, forbidden_values=[],
    )
    assert problems


def test_record_references_are_checked_but_ordinary_phrases_are_not():
    evidence = ["7 High alerts, e.g. alert #3839. Latest detection run #12."]
    check = lambda answer: assistant_agent.verify_answer(  # noqa: E731
        answer, evidence=evidence, asked=["alerts?"], redacted=True, forbidden_values=[],
    )
    assert check("Run 2 more checks on the source 3 minutes later, starting with alert 3839.") == []
    assert check("Detection run #12 found them.") == []
    assert any("alert #4000" in item for item in check("Start with alert 4000."))
    assert any("log #7" in item for item in check("Open log #7 first."))
    # "#38" is not "#3839": a reference must match a whole identifier the tools returned.
    assert any("alert #38" in item for item in check("Start with alert #38."))


def test_a_name_the_analyst_typed_is_not_an_invented_screen_element():
    # "close all critical alerts" once fell back because the reply quoted "Critical", a word from the question.
    guide = ["Alerts page: select the alerts, then choose Resolve."]
    reply = 'I cannot close them myself. On the Alerts page, filter to "Critical", select them and choose Resolve.'
    assert assistant_agent.verify_answer(
        reply, evidence=guide, asked=["close all critical alerts for me"], redacted=True, forbidden_values=[],
    ) == []
    invented = assistant_agent.verify_answer(
        'Open the "Bulk Close" button.', evidence=guide, asked=["close all critical alerts for me"],
        redacted=True, forbidden_values=[],
    )
    assert any("Bulk Close" in item for item in invented)


def test_the_ml_concept_says_the_supervised_classifier_is_not_used(seeded, monkeypatch):  # noqa: F811
    # "Advisory only" once led the assistant to tell an analyst the supervised model is used.
    from atdr.app.services.assistant_tools import build_assistant_tools

    monkeypatch.setattr(behavior_findings_service, "load_model", lambda *args, **kwargs: None)
    sessions, settings = seeded
    with sessions() as session:
        tools = {tool.name: tool for tool in build_assistant_tools(session, settings=settings)}
        text = tools["explain_concept"].run({"topic": "ml_models"}).text
    assert "the supervised classifier is not used at all" in text and "refuses to score" in text
    assert "non-normal estimate" in text and "not confidence in the attack type" in text


def test_failed_tool_arguments_are_not_evidence():
    engine = ScriptedEngine(_call("absent_tool", alert_id=987), _say("Alert #987 exists."), _say("Alert #987 exists."))
    outcome = assistant_agent.run_agent(question="alert 987?", engine=engine, tools=[_count_tool()])
    assert not outcome.ok


def test_conversation_word_limit_gets_one_correction_then_fallback():
    words = "Details " * (response_contract("conversation").word_limit + 1)
    engine = ScriptedEngine(_call("query_alerts"), _say(words), _say(words))
    outcome = assistant_agent.run_agent(question="summarize alerts", engine=engine, tools=[_count_tool()])
    assert not outcome.ok and outcome.fallback_reason == "answer_failed_verification"
    assert len(engine.requests) == 3


def test_agent_deadline_applies_across_rounds(monkeypatch):
    clock = [0.0]
    monkeypatch.setattr(assistant_agent.time, "perf_counter", lambda: clock[0])

    class SlowEngine(ScriptedEngine):
        timeout = 5

        def chat(self, messages, tools, *, timeout=None):
            self.budgets.append(timeout)
            clock[0] += 3
            return super().chat(messages, tools)

    engine = SlowEngine(_call("query_alerts"), _say("7 High alerts."))
    engine.budgets = []
    outcome = assistant_agent.run_agent(question="alerts?", engine=engine, tools=[_count_tool()])
    assert not outcome.ok and outcome.fallback_reason == "agent_deadline_exceeded"
    assert engine.budgets == [5, 2]


def test_hosted_messages_and_audits_redact_question_and_history(seeded, monkeypatch):  # noqa: F811
    sessions, settings = seeded
    secret = "synthetic-private-key-123"
    settings = settings.model_copy(update={"assistant_agent_api_key": secret})
    conversation = "capstone-conversation"
    local = ScriptedEngine(_call("query_alerts"), _say("I can help investigate."))
    local.name = "ollama"
    monkeypatch.setattr(assistant_service, "engine_from_settings", lambda _: local)
    with sessions() as session:
        _ask(session, settings, f"Hello 2001:db8::1 password={secret}", conversation_id=conversation)
        audit = session.scalar(select(AuditLog).where(AuditLog.action == "assistant_question"))
        assert secret not in audit.target_value and "2001:db8::1" not in audit.target_value
        hosted = ScriptedEngine(_call("query_alerts"), _say("There is 1 alert."))
        hosted.name = "gemini"
        monkeypatch.setattr(assistant_service, "engine_from_settings", lambda _: hosted)
        _ask(session, settings, f"How many alerts for 203.0.113.8? api_key={secret}", conversation_id=conversation)
    import json
    payload = json.dumps(hosted.requests)
    assert secret not in payload and "203.0.113.8" not in payload and "2001:db8::1" not in payload


@pytest.mark.parametrize("expired", [False, True])
def test_simulation_cannot_clear_previously_enforced_block(monkeypatch, expired):
    monkeypatch.setattr(response_service, "get_settings", lambda: _settings(response_simulation=True))
    monkeypatch.setattr(response_service.windows_firewall_connector, "remove_block", lambda _: pytest.fail("real removal"))
    with _session() as session:
        row = BlockedIP(ip_address="203.0.113.77", active=True, enforcement="windows_firewall", created_by="test",
                        expires_at=datetime.now(timezone.utc) - timedelta(minutes=1) if expired else None)
        session.add(row)
        session.commit()
        result = response_service.unblock_ip(session, target_ip=row.ip_address, reason="synthetic check")
        assert row.active and result.status == "enforcement_failed"
        assert result.enforcement == "windows_firewall"


def test_behavior_window_query_compiles_for_postgresql():
    captured = []

    class ProbeSession:
        def get_bind(self):
            return SimpleNamespace(dialect=postgresql.dialect())

        def execute(self, statement):
            captured.append(str(statement.compile(dialect=postgresql.dialect())))
            return SimpleNamespace(all=lambda: [])

    assert behavior_findings_service.available_windows(ProbeSession()) == []
    assert "strftime" not in captured[0] and "printf" not in captured[0]


def test_detection_run_counts_include_experimental_alerts(db, monkeypatch):  # noqa: F811
    from atdr.app.core.config import get_settings
    from atdr.app.services import model_alert_service
    from atdr.app.services.detection_service import run_detection

    _quiet_scanner(db)
    monkeypatch.setattr(model_alert_service, "load_model", lambda: _switched_on())
    monkeypatch.setattr(behavior_findings_service, "load_model", lambda: _switched_on())
    monkeypatch.setenv("ATDR_MODEL_ALERTS", "true")
    get_settings.cache_clear()
    try:
        result = run_detection(db, limit=5000, use_ml=False, actor="test", only_unchecked=True)
        count = result["model_alerts"]["created"]
        run = db.get(DetectionRun, result["detection_run_id"])
        assert count > 0 and run.details_json["model_alerts_created"] == count
        assert run.alerts_created == run.details_json["rule_alerts_created"] + count
        assert result["alerts_created"] == run.alerts_created
    finally:
        get_settings.cache_clear()


def test_runtime_reports_experimental_permission_separately_from_qualification(db, monkeypatch):  # noqa: F811
    from atdr.app.core.config import Settings

    monkeypatch.setattr(runtime_contract, "get_settings", lambda: Settings(_env_file=None, ATDR_MODEL_ALERTS=True))
    monkeypatch.setattr(runtime_contract, "supervised_runtime_status", lambda *a, **k: {"state": "unqualified"})
    monkeypatch.setattr(behavior_findings_service, "load_model", lambda: _switched_on())
    status = runtime_contract.current_detection_runtime_status(db)
    assert status["experimental_model"]["model_only_alert_creation_allowed"]
    assert status["experimental_model"]["qualified"] is False
    assert status["supervised"]["state"] == "unqualified"


def test_experimental_explanation_names_non_normal_probability(db):  # noqa: F811
    from atdr.app.services.model_alert_service import create_model_alerts
    from atdr.tests.test_model_alerts import _model_alerts

    _quiet_scanner(db)
    create_model_alerts(db, windows=[START], model=_switched_on())
    explanation = _model_alerts(db)[0].explanation
    assert "non-normal" in explanation and "% confident" not in explanation


def test_hosted_ip_alias_resolves_only_inside_local_tool(monkeypatch):
    captured = []

    def lookup(arguments):
        captured.append(arguments)
        return assistant_agent.ToolOutput("No watchlist entry matches this address.")

    tool = assistant_agent.AgentTool("watchlist_lookup", "Lookup", {}, lookup)
    engine = ScriptedEngine(_call("watchlist_lookup", ip="[redacted-ip-1]"), _say("No watchlist entry matches this address."))
    engine.name = "gemini"
    outcome = assistant_agent.run_agent(question="Check 2001:db8::8", engine=engine, tools=[tool])
    assert outcome.ok and captured == [{"ip": "2001:db8::8"}]
    import json
    assert "2001:db8::8" not in json.dumps(engine.requests)
    assert "2001:db8::8" not in json.dumps(outcome.safe_details())


def test_local_ollama_keeps_transient_question_but_not_record_ips():
    engine = ScriptedEngine(_call("query_alerts"), _say("7 High alerts."))
    engine.name = "ollama"
    outcome = assistant_agent.run_agent(question="Check 203.0.113.8", engine=engine, tools=[_count_tool()])
    assert outcome.ok and engine.requests[0][0][-1]["content"] == "Check 203.0.113.8"


def test_transcript_sanitizer_preserves_identifiers_but_excludes_pasted_evidence():
    from atdr.app.services.assistant_privacy import sanitize_assistant_text

    text = 'Alert #42 password="do not persist" for student@example.test\n' + ','.join(['TRAFFIC'] + ['value'] * 15)
    cleaned = sanitize_assistant_text(text)
    assert "Alert #42" in cleaned and "do not persist" not in cleaned
    assert "student@example.test" not in cleaned and "TRAFFIC" not in cleaned
    assert "[redacted-log]" in cleaned


def test_word_limit_allows_one_successful_correction():
    engine = ScriptedEngine(_call("query_alerts"), _say("Details " * 221), _say("7 High alerts."))
    outcome = assistant_agent.run_agent(question="alerts?", engine=engine, tools=[_count_tool()])
    assert outcome.ok and outcome.answer == "7 High alerts." and len(engine.requests) == 3
    # The correction tells the model how long it was and the limit to meet, not just "too long".
    correction = engine.requests[2][0][-1]["content"]
    assert "221 words, the limit is 220" in correction


def test_a_rewrite_slightly_over_the_limit_is_cut_at_a_whole_line():
    # "Explain alert 3842" came back at 254 then 222 words and fell back over 2 words.
    line = "- 7 High alerts need review today. " + "More detail here. " * 5
    long_answer = "\n".join([line] * 11)
    assert len(long_answer.split()) > 220
    engine = ScriptedEngine(_call("query_alerts"), _say(long_answer), _say(long_answer))
    outcome = assistant_agent.run_agent(question="alerts?", engine=engine, tools=[_count_tool()])
    assert outcome.ok and len(outcome.answer.split()) <= 220
    assert [kept.strip() for kept in outcome.answer.splitlines()] == [line.strip()] * len(outcome.answer.splitlines())
    assert assistant_agent.trim_to_words("One two three. Four five six.", 4) == "One two three."
    assert assistant_agent.trim_to_words("short", 4) == "short"


def test_tool_deadline_prevents_another_provider_round(monkeypatch):
    clock = [0.0]
    monkeypatch.setattr(assistant_agent.time, "perf_counter", lambda: clock[0])

    def slow_lookup(_):
        clock[0] = 6
        return assistant_agent.ToolOutput("7 High alerts.")

    engine = ScriptedEngine(_call("query_alerts"))
    outcome = assistant_agent.run_agent(
        question="alerts?", engine=engine, total_timeout=5,
        tools=[assistant_agent.AgentTool("query_alerts", "Count", {}, slow_lookup)],
    )
    assert not outcome.ok and outcome.fallback_reason == "agent_deadline_exceeded"
    assert len(engine.requests) == 1


@pytest.mark.parametrize("engine_type", ["ollama", "gemini"])
def test_engines_apply_remaining_transport_timeout(monkeypatch, engine_type):
    observed = []

    def post(*args, **kwargs):
        observed.append(kwargs["timeout"])
        return {"message": {"content": "ok"}, "choices": [{"message": {"content": "ok"}}]}

    monkeypatch.setattr(assistant_agent, "_post", post)
    if engine_type == "ollama":
        engine = assistant_agent.OllamaEngine(base_url="http://127.0.0.1:11434", model="test", timeout=120, context_tokens=4096, keep_alive="1m")
    else:
        engine = assistant_agent.OpenAICompatibleEngine(name="gemini", base_url="https://example.test", model="test", api_key="test", timeout=120)
    engine.chat([], None, timeout=0.25)
    assert observed == [0.25]


def test_window_boundaries_cross_hours_and_dates(db):  # noqa: F811
    from atdr.app.db.models import NormalizedLog, RawLog

    for index, when in enumerate([datetime(2026, 5, 21, 0, 0), datetime(2026, 5, 20, 23, 59, 59), None]):
        raw = RawLog(raw_line=f"boundary {index}")
        db.add(raw)
        db.flush()
        db.add(NormalizedLog(raw_log_id=raw.id, generated_time=when, parsed_json={}))
    db.commit()
    assert behavior_findings_service.available_windows(db, limit=2) == [
        {"start": "2026-05-21T00:00:00", "logs": 1}, {"start": "2026-05-20T23:55:00", "logs": 1},
    ]


def test_runtime_disabled_does_not_even_load_the_model(monkeypatch):
    from atdr.app.core.config import Settings

    monkeypatch.setattr(behavior_findings_service, "load_model", lambda: pytest.fail("artifact access"))
    status = runtime_contract.experimental_model_runtime_status(Settings(_env_file=None, ATDR_MODEL_ALERTS=False))
    assert status["configured"] is False and status["artifact_available"] is None
    assert status["model_only_alert_creation_allowed"] is False


def test_manual_host_response_permission_is_not_reported_as_automatic_or_verified():
    from atdr.app.core.config import Settings

    settings = Settings(_env_file=None, RESPONSE_SIMULATION=False, RESPONSE_PROVIDER="windows_firewall")
    status = runtime_contract.response_runtime_status(settings)
    assert status["real_firewall_blocking_enabled"] is True
    assert status["automatic_response_enabled"] is False and status["enforcement_verified"] is False
