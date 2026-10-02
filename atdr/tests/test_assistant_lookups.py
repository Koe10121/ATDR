"""Facts the SOC assistant looks up before the model answers, and the topics they come from.

Each case is a question a professor might type during the demo (2 October) that the model first answered wrongly
or from memory.
"""

from __future__ import annotations

import pytest

from atdr.app.db.models import WatchlistItem
from atdr.app.services import assistant_service
from atdr.app.services.assistant_agent import drop_tool_mentions
from atdr.app.services.assistant_help import answer_rule_question
from atdr.app.services.assistant_tools import build_assistant_tools
from atdr.tests.test_assistant_agent import ScriptedEngine, _ask, _call, _say, seeded  # noqa: F401
from atdr.tests.test_detection_grouping import _session
from atdr.tests.test_plain_summary import XMRIG, _alert, _log


@pytest.mark.parametrize(
    ("question", "expected"),
    [
        # "ATDR does not work with live traffic"; "the data is real" with no word of the export.
        ("Does ATDR work with live traffic?", [("explain_concept", {"topic": "data_sources"})]),
        ("Is the data in this system real?", [("explain_concept", {"topic": "data_sources"})]),
        # A guess that crypto mining may go unseen, while ATDR names XMRig miners.
        ("Which attack types can ATDR not detect yet?", [("explain_concept", {"topic": "detection_coverage"})]),
        # System jobs described as "what changed".
        ("What changed between the first version and now?", [("explain_concept", {"topic": "improvements"})]),
        # Rule-backed findings listed as the experimental alerts, in 30 seconds.
        ("Tell me about the experimental alerts", [("explain_concept", {"topic": "experimental_alerts"})]),
        # ATDR's overall accuracy instead of the model's own figures.
        ("How accurate is the MFU behaviour model?", [("explain_concept", {"topic": "ml_models"})]),
        # "I'm here to assist" with no lookup.
        ("Brief the IT director in two sentences", [("security_overview", {"time_window": "all_time"})]),
        # Ended with "Let me look up the source IPs" and no lookup.
        (
            "Which MFU devices might be infected with malware?",
            [("explain_concept", {"topic": "malware_c2"}), ("watchlist_lookup", {})],
        ),
        # One alert's investigation brief, ATDR's overall accuracy and a ranking of risks keep their own paths.
        ("Create an investigation brief for alert 3738", []),
        ("How accurate is ATDR?", []),
        ("What are our biggest risks and how do I fix them?", []),
    ],
)
def test_a_question_whose_answer_is_in_one_topic_gets_it_looked_up_first(question, expected):
    assert assistant_service._topic_lookups(question) == expected


def test_the_most_dangerous_thing_is_the_one_alert_the_overview_opens_first():
    # "What is the most dangerous thing happening on our network right now?" named #3839 and said, wrongly, that the
    # firewall had not blocked it.
    urgent = assistant_service.URGENT_ALERT_QUESTION
    assert urgent.search("What is the most dangerous thing happening on our network right now?")
    assert urgent.search("What's the biggest threat right now?")
    assert not urgent.search("What are our biggest risks and how do I fix them?")


def test_a_named_country_goes_to_the_log_tool_before_the_model_answers():
    # "Show me the traffic from Malaysia" was answered with the count of every stored log, called Malaysia's.
    db = _session()
    _log(db, src="10.1.1.1", dst="111.90.158.40", port=80, src_zone="Inside", dst_zone="Outside", dst_country="Malaysia")
    _log(db, src="10.1.1.2", dst="10.1.1.3", port=80, src_zone="Inside", dst_zone="Inside", src_country="Unknown",
         dst_country="10.0.0.0-10.255.255.255")
    assert assistant_service._country_lookup(db, "Show me the traffic from Malaysia") == [("query_logs", {"ip": "Malaysia"})]
    # Country fields that are not places name no country.
    assert assistant_service._country_lookup(db, "What is unknown about this alert?") == []


def test_a_named_threat_gets_its_alert_looked_up_first():
    # "How do you know the GHOSTENGINE alert is not a false positive?" was answered from the false-positive
    # definition without reading the alert.
    db = _session()
    db.add(WatchlistItem(
        indicator_type="dst_ip", indicator_value="111.90.158.40", created_by="koe",
        description="GHOSTENGINE C2 server (Elastic Security Labs, May 2024). Found 2026-09-27: it beaconed.",
    ))
    log = _log(db, src="10.1.200.251", dst="111.90.158.40", port=80, src_zone="Inside", dst_zone="Outside")
    watch = _alert(db, "watchlist_match", [log], explanation="Matched active watchlist indicator(s): dst_ip:111.90.158.40.")
    miner = _alert(db, "paloalto_malware_threat", [log], explanation=XMRIG)
    lookup = assistant_service._named_threat_lookup
    assert lookup(db, "How do you know the GHOSTENGINE alert is not a false positive?") == [("get_alert", {"alert_id": watch.id})]
    assert lookup(db, "What should we do about the XMRig miners?") == [("get_alert", {"alert_id": miner.id})]
    # Words every scan signature shares do not pick out one alert.
    assert lookup(db, "How many port scan alerts are there?") == []


def test_a_privacy_question_gets_the_built_in_answer_without_the_model(seeded, monkeypatch):  # noqa: F811
    # "Are my questions stored?" got "Your questions are not stored" from the model; ATDR saves each one.
    sessions, settings = seeded
    engine = ScriptedEngine(_say("Your questions are not stored."))
    monkeypatch.setattr(assistant_service, "engine_from_settings", lambda _settings: engine)
    with sessions() as db:
        response = _ask(db, settings, "Are my questions stored?")
    assert engine.requests == []
    assert response["answer"].startswith(
        "Your questions and the assistant's answers are saved on this machine, in ATDR's audit log and assistant history."
    )
    assert "Nothing is sent outside" in response["answer"]


def test_a_watchlist_lookup_of_a_hidden_address_lists_the_whole_watchlist(seeded):  # noqa: F811
    # "Are any MFU devices talking to a known malicious server?" looked up "[redacted-ip]", read "not on the
    # watchlist, 0 connections" and was answered "no", while alert #3738 was exactly that.
    sessions, settings = seeded
    with sessions() as db:
        tools = {tool.name: tool for tool in build_assistant_tools(db, settings=settings)}
        hidden = tools["watchlist_lookup"].run({"ip": "[redacted-ip]"}).text
        whole = tools["watchlist_lookup"].run({}).text
    assert hidden == whole
    assert "not on ATDR's watchlist" not in hidden


@pytest.mark.parametrize(
    ("question", "asks"),
    [
        ("what should I do about it?", True),
        ("What should I do about alert 3738?", True),
        ("How do I handle this alert?", True),
        ("What should we do next?", True),
        # A threat the question names, the most urgent alert and a dashboard task keep their own lookups.
        ("What should I do about the XMRig miners?", False),
        ("What should I do about the most urgent alert?", False),
        ("How do I add an IP to a watchlist?", False),
    ],
)
def test_what_to_do_about_the_alert_in_context_is_asked_only_of_that_alert(question, asks):
    assert bool(assistant_service.RESPONSE_QUESTION.search(question)) is asks


def test_asked_what_to_do_about_the_alert_in_context_the_model_gets_its_playbook_first(seeded, monkeypatch):  # noqa: F811
    # "What should I do about it?" after "Why was alert 3842 flagged?" also listed the five highest-scoring alerts and
    # was answered with those.
    sessions, settings = seeded
    engine = ScriptedEngine(
        _call("get_alert", alert_id=1),
        _say("Alert #1 is a port scan."),
        _say("Confirm the scan in the logs of alert #1, then decide on a simulated block."),
    )
    monkeypatch.setattr(assistant_service, "engine_from_settings", lambda _settings: engine)
    with sessions() as db:
        _ask(db, settings, "tell me about alert 1", conversation_id="playbook-follow-up")
        response = _ask(db, settings, "what should I do about it?", conversation_id="playbook-follow-up")
    messages = engine.requests[2][0]
    assert [message["name"] for message in messages if message["role"] == "tool"] == ["get_alert_playbook"]
    assert any("playbook of alert #1" in message["content"] for message in messages if message["role"] == "system")
    assert response["mode"] == "assistant_agent_scripted" and "alert #1" in response["answer"]
    # Without an alert in context there is no playbook to fetch.
    assert assistant_service._response_lookup("what should I do about it?", None) == ([], None)


@pytest.mark.parametrize(
    ("question", "says"),
    [
        # Given the model's own figures, it listed "port scan 96.5%, flood 100.0%..." as its accuracy without saying
        # they were measured on simulated attacks.
        ("How accurate is the MFU behaviour model?", "not on real attacks"),
        # Given the data topic, it said only that the logs are real MFU traffic, not that they are one exported file.
        ("Is the data in this system real?", "nothing on the dashboard is live"),
    ],
)
def test_a_looked_up_topic_comes_with_what_the_answer_must_say(seeded, monkeypatch, question, says):  # noqa: F811
    sessions, settings = seeded
    engine = ScriptedEngine(_say("It comes from one exported file of MFU's firewall traffic."))
    monkeypatch.setattr(assistant_service, "engine_from_settings", lambda _settings: engine)
    with sessions() as db:
        _ask(db, settings, question)
    messages = engine.requests[0][0]
    assert [message["name"] for message in messages if message["role"] == "tool"] == ["explain_concept"]
    assert any(says in message["content"] for message in messages if message["role"] == "system")


def test_the_overview_follow_up_about_the_most_urgent_alert_goes_to_the_alert_the_overview_opens_first(seeded):  # noqa: F811
    sessions, settings = seeded
    with sessions() as db:
        tools = {tool.name: tool for tool in build_assistant_tools(db, settings=settings)}
        followups = tools["security_overview"].run({"time_window": "all_time"}).followups
    assert followups and all(assistant_service.URGENT_ALERT_QUESTION.search(question) for question in followups)


def test_a_step_that_only_named_a_tool_leaves_no_bare_number_behind():
    # "3." was left on its own line when the step it numbered only named a tool.
    cleaned = drop_tool_mentions(
        "Do this:\n1. Open the alert.\n2. Check the source.\n3. Use get_alert to read it.\n4. Mark it false positive.",
        ["get_alert"],
    )
    assert cleaned == "Do this:\n1. Open the alert.\n2. Check the source.\n3. Mark it false positive."


def test_the_data_topic_says_the_logs_are_not_live_how_live_logs_arrive_and_where_the_watchlist_comes_from(seeded):  # noqa: F811
    sessions, settings = seeded
    with sessions() as db:
        db.add(WatchlistItem(indicator_type="dst_ip", indicator_value="203.0.113.7", created_by="koe",
                             source="ThreatFox recent", description="feed address"))
        db.add(WatchlistItem(indicator_type="dst_ip", indicator_value="203.0.113.8", created_by="koe",
                             description="GHOSTENGINE C2 server (Elastic). Found later: more."))
        db.commit()
        tools = {tool.name: tool for tool in build_assistant_tools(db, settings=settings)}
        text = tools["explain_concept"].run({"topic": "data_sources"}).text
    assert "nothing on the dashboard is live" in text
    assert f"its syslog receiver listens on UDP port {settings.syslog_port}" in text
    assert "ThreatFox recent (1 address)" in text
    assert "such as GHOSTENGINE C2 server (Elastic)." in text and "Found later" not in text


def test_the_coverage_topic_counts_the_rules_like_the_rule_answer_and_says_what_atdr_cannot_see(seeded):  # noqa: F811
    sessions, settings = seeded
    with sessions() as db:
        tools = {tool.name: tool for tool in build_assistant_tools(db, settings=settings)}
        coverage = tools["explain_concept"].run({"topic": "detection_coverage"}).text
        changes = tools["explain_concept"].run({"topic": "improvements"}).text
    assert coverage.startswith(answer_rule_question("how many rules").summary)
    assert "email and phishing" in coverage and "not continuously" in coverage
    assert changes.startswith("Compared with ATDR's first version") and "from 3,676 alerts to" in changes
