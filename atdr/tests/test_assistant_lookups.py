"""Facts the SOC assistant looks up before the model answers, and the topics they come from.

Each case is a question a professor might type during the demo (2 October) that the model first answered wrongly
or from memory.
"""

from __future__ import annotations

from datetime import datetime

import pytest

from atdr.app.core.config import get_settings
from atdr.app.db.models import WatchlistItem
from atdr.app.detection.plain_summary import build_situation_summary
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
        # "18 alerts from our AI detection" (the unclassified rule alerts), "1 alert" (see the named-threat test) and
        # "the AI (ATDR) raised 178".
        ("How many alerts come from our AI detection?", [("explain_concept", {"topic": "alert_creation"})]),
        ("How many alerts were detected by our AI model and rules together?", [("explain_concept", {"topic": "alert_creation"})]),
        ("How many alerts did the AI raise?", [("explain_concept", {"topic": "alert_creation"})]),
        ("Can the AI create alerts by itself?", [("explain_concept", {"topic": "alert_creation"})]),
        # The demo's count question names no AI part.
        ("How many critical alerts are open right now, and what attack types are they?", []),
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


def test_a_threat_goes_by_the_first_word_of_its_name_not_by_ordinary_words_in_it():
    # "How many alerts were detected by our AI model and rules together?" was answered "1 alert": "detected" matched the
    # firewall's "RPC Portmapper DUMP Request Detected", so alert #3824 was fetched and the model described it. "print"
    # and "option" fetched the Nmap alert the same way, and "nmap" itself, at four letters, fetched nothing.
    db = _session()
    log = _log(db, src="45.33.32.156", dst="10.1.0.5", port=111, src_zone="Outside", dst_zone="Inside")

    def named(name):
        return _alert(db, "paloalto_threat_log", [log], explanation=XMRIG.replace("XMRig Miner Command and Control Traffic Detection", name))

    named("RPC Portmapper DUMP Request Detected")
    nmap = named("Nmap Aggressive Option Print Detection")
    named("Non-RFC Compliant HTTP Traffic on Port 80")
    named("HTTP Unauthorized Brute Force Attack")
    lookup = assistant_service._named_threat_lookup
    for question in (
        "How many alerts were detected by our AI model and rules together?",
        "Print the report for me",
        "What option do I have?",
        "Is this aggressive scanning?",
        "Which alerts use HTTP?",
    ):
        assert lookup(db, question) == [], question
    assert lookup(db, "Any Nmap scans today?") == [("get_alert", {"alert_id": nmap.id})]


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


def test_an_answer_about_one_looked_up_alert_opens_with_its_number_when_it_gives_none():
    # "How do you know the GHOSTENGINE alert is not a false positive?" explained alert #3738 without its number (4 Oct);
    # the demo's follow-up about the most urgent alert did the same the day before.
    naming = assistant_service._naming_the_alert
    assert naming("The GHOSTENGINE alert is a watchlist match.", 3738, opens_first=False) == (
        "Alert #3738\nThe GHOSTENGINE alert is a watchlist match."
    )
    assert naming("- Check the source device.", 3738, opens_first=True).startswith(
        "Alert #3738 comes first: the Overview says to open it first.\n- Check"
    )
    # An answer that already gives the number, with or without "#", is left alone; #37380 is another alert.
    for named in ("Alert #3738 is a watchlist match.", "Look at alert 3738 first."):
        assert naming(named, 3738, opens_first=False) == named
    assert naming("See #37380 too.", 3738, opens_first=False).startswith("Alert #3738\n")
    # A Thai answer gets the line in Thai.
    assert naming("ตรวจสอบเครื่องต้นทาง", 3738, opens_first=False, thai=True) == "การแจ้งเตือน #3738\nตรวจสอบเครื่องต้นทาง"


def test_what_to_do_about_the_alert_in_context_says_which_alert(seeded, monkeypatch):  # noqa: F811
    sessions, settings = seeded
    engine = ScriptedEngine(
        _call("get_alert", alert_id=1),
        _say("Alert #1 is a port scan."),
        _say("Confirm the scan in its logs, then decide on a simulated block."),
    )
    monkeypatch.setattr(assistant_service, "engine_from_settings", lambda _settings: engine)
    with sessions() as db:
        _ask(db, settings, "tell me about alert 1", conversation_id="which-alert")
        response = _ask(db, settings, "what should I do about it?", conversation_id="which-alert")
    assert response["answer"] == "Alert #1\nConfirm the scan in its logs, then decide on a simulated block."


def test_the_overview_follow_up_about_the_most_urgent_alert_goes_to_the_alert_the_overview_opens_first(seeded):  # noqa: F811
    sessions, settings = seeded
    with sessions() as db:
        tools = {tool.name: tool for tool in build_assistant_tools(db, settings=settings)}
        followups = tools["security_overview"].run({"time_window": "all_time"}).followups
    assert followups and all(assistant_service.URGENT_ALERT_QUESTION.search(question) for question in followups)


def test_asked_in_thai_what_needs_dealing_with_first_the_question_is_about_the_most_urgent_alert():
    # "ตอนนี้มีอะไรที่ต้องรีบจัดการไหม" was answered from the whole overview, without the alert the Overview opens first
    # (21 Oct): only English questions asked for the most urgent one.
    urgent = assistant_service.URGENT_ALERT_QUESTION
    for question in (
        "ตอนนี้มีอะไรที่ต้องรีบจัดการไหม",  # anything to deal with in a hurry now?
        "มีการแจ้งเตือนไหนด่วนที่สุด",  # which alert is the most urgent?
        "ควรจัดการอะไรก่อนดี",  # what should I handle first?
        "ควรแก้ปัญหาไหนเป็นอันดับแรก",  # which problem should I fix first?
        "ภัยคุกคามไหนสำคัญที่สุดตอนนี้",  # which threat matters most now?
    ):
        assert urgent.search(question), question
    for question in (
        "IP ไหนอันตรายที่สุด",  # which IP is the most dangerous: a ranking of addresses, as in English
        "ต้องรีบูตเครื่องไหม",  # do I need to reboot?
        "ระบบตรวจจับการโจมตีได้ก่อนไหม",  # can the system detect attacks beforehand?
        "ต้องจัดการอะไรก่อนติดตั้ง",  # what must I deal with before installing?
        "ก่อนหน้านี้มีการแจ้งเตือนอะไรบ้าง",  # which alerts were there earlier?
        "สรุปสถานการณ์ความปลอดภัยวันนี้ให้หน่อย",  # summarise today's security situation
    ):
        assert not urgent.search(question), question


def test_asked_in_thai_what_needs_dealing_with_first_the_answer_names_the_alert_the_overview_opens_first(seeded, monkeypatch):  # noqa: F811
    sessions, settings = seeded
    with sessions() as db:
        first = build_situation_summary(db)["open_first"]
    assert first, "the seeded alerts give the Overview an alert to open first"
    engine = ScriptedEngine(_say("- ตรวจสอบเครื่องต้นทางก่อน\n- แล้วดูล็อกที่เกี่ยวข้อง"))
    monkeypatch.setattr(assistant_service, "engine_from_settings", lambda _settings: engine)
    with sessions() as db:
        response = _ask(db, settings, "ตอนนี้มีอะไรที่ต้องรีบจัดการไหม")
    messages = engine.requests[0][0]
    assert [message["name"] for message in messages if message["role"] == "tool"] == ["get_alert"]
    assert any(f"open alert #{first['alert_id']} first" in message["content"] for message in messages if message["role"] == "system")
    assert response["mode"] == "assistant_agent_scripted"
    assert response["answer"].startswith(
        f"การแจ้งเตือน #{first['alert_id']} มาก่อน: หน้า Overview แนะนำให้เปิดดูเป็นอันดับแรก\n- ตรวจสอบ"
    )


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


def test_alerts_are_counted_by_who_raised_them(seeded, monkeypatch):  # noqa: F811
    from sqlalchemy import func, select

    from atdr.app.db.models import Alert
    from atdr.app.services import behavior_findings_service

    monkeypatch.setattr(behavior_findings_service, "load_model", lambda *args, **kwargs: None)
    monkeypatch.setattr(behavior_findings_service, "model_status", lambda model: {"alerting_types": ["port_scan"]})
    sessions, settings = seeded
    with sessions() as db:
        def add(alert_type):
            alert = Alert(title=alert_type, alert_type=alert_type, threat_score=40, severity="Medium", status="open",
                          explanation="x", matched_rules_json=[], recommended_response="-")
            db.add(alert)
            db.flush()
            return alert.id

        model_id, legacy_id = add(behavior_findings_service.MODEL_ALERT_CODE), add("ml_anomaly_detected")
        db.commit()
        total = db.scalar(select(func.count(Alert.id)))
        tools = {tool.name: tool for tool in build_assistant_tools(db, settings=settings)}
        text = tools["explain_concept"].run({"topic": "alert_creation"}).text
    assert f"1 of the {total:,} alerts came from it (#{model_id})." in text
    # One split that adds up: the model's alerts, and all the others, among them the old anomaly rule's.
    assert (
        f"The other {total - 1:,} came from the rules and the watchlist, 1 of them (#{legacy_id}) from an old rule that "
        "used the earlier anomaly model and no longer creates alerts."
    ) in text
    assert any("Answer with the count from each source" in note for note in assistant_service._topic_notes("How many alerts did the AI raise?"))


def test_the_coverage_topic_counts_the_rules_like_the_rule_answer_and_says_what_atdr_cannot_see(seeded):  # noqa: F811
    sessions, settings = seeded
    manual = settings.model_copy(update={"auto_detection_enabled": False})
    with sessions() as db:
        tools = {tool.name: tool for tool in build_assistant_tools(db, settings=manual)}
        coverage = tools["explain_concept"].run({"topic": "detection_coverage"}).text
        changes = tools["explain_concept"].run({"topic": "improvements"}).text
    assert coverage.startswith(answer_rule_question("how many rules").summary)
    assert "email and phishing" in coverage and "not continuously" in coverage
    assert changes.startswith("Compared with ATDR's first version") and "3,676 alerts then" in changes


def test_what_changed_since_the_first_version_opens_its_points_with_the_figures_counted_now():
    # Asked "what changed between the first version and now?", the model kept every point and dropped the figures that
    # ended them; and "unclassified ... to 10%" had gone stale (10 of 87 alerts is 11%).
    db = _session()
    for code in ("possible_port_scan", "possible_port_scan", "possible_port_scan", "a_rule_that_names_no_attack"):
        _alert(db, code, [])
    tools = {tool.name: tool for tool in build_assistant_tools(db, settings=get_settings())}
    lines = tools["explain_concept"].run({"topic": "improvements"}).text.splitlines()

    assert lines[1] == (
        "- Fewer, clearer alerts: 3,676 alerts then, 4 now. Rules that only describe context (a risky app, a busy source) "
        "now add points but never raise an alert alone."
    )
    assert lines[2].startswith("- Every alert names its attack type: 53% of alerts were unclassified then, 25% now. ")


def test_an_answer_about_what_changed_since_the_first_version_always_gives_the_alert_figures(seeded, monkeypatch):  # noqa: F811
    # With the figures opening their points, the model still left them out in 4 of 6 fresh asks on the evening of
    # 21 October, and in none of 6 an hour later, as its state changed. ATDR adds them when they are missing.
    first_version = assistant_service.FIRST_VERSION_QUESTION
    for question in ("What changed between the first version and now?", "What is different now compared with the first version of ATDR?",
                     "How has ATDR improved since it was first presented?"):
        assert first_version.search(question), question
    for question in ("What changed recently?", "What's new in the logs today?"):
        assert not first_version.search(question), question
    sessions, settings = seeded
    with sessions() as db:
        alerts, unclassified = assistant_service.improvement_figures(db)
    figures = f"In figures: 3,676 alerts then, {alerts:,} now; 53% of alerts were unclassified then, {unclassified}% now."
    asked = [
        ("What changed between the first version and now?", "Alerts are fewer and clearer.",
         f"Alerts are fewer and clearer.\n{figures}"),
        ("What changed between the first version and now?", "3,676 alerts then, fewer now.", "3,676 alerts then, fewer now."),
        # "What changed recently?" asks about the audit trail, not the first version.
        ("What changed recently?", "Nothing was changed today.", "Nothing was changed today."),
    ]
    for question, said, shown in asked:
        engine = ScriptedEngine(_say(said))
        monkeypatch.setattr(assistant_service, "engine_from_settings", lambda _settings, engine=engine: engine)
        with sessions() as db:
            response = _ask(db, settings, question)
        assert response["mode"] == "assistant_agent_scripted", question
        assert response["answer"] == shown, question


def _alerts_from_everywhere(db, *, created=None):
    """Outside scanners and an outside exploit, an MFU device with a miner in 3 alerts, and the hour's scanning alert."""

    def raised(src, code, logs, score, **fields):
        alert = _alert(db, code, logs, **fields)
        alert.src_ip, alert.threat_score = src, score
        if created is not None:
            alert.created_at = created
        return alert

    inbound = {"dst": "10.1.1.9", "port": 22, "src_zone": "SG-Outside", "dst_zone": "WLAN-Inside"}
    alerts = {
        # The alert to open is the one scoring highest, here the older one.
        "scan": [raised("91.92.93.94", "possible_port_scan", [_log(db, src="91.92.93.94", **inbound)], score) for score in (70, 60)],
        "exploit": raised("185.199.10.20", "paloalto_threat_log", [_log(db, src="185.199.10.20", **inbound)], 90,
                          rules=[{"code": "paloalto_threat_log", "attack_type": "exploit_attempt"}]),
        # One alert as well, scoring lower: ranked after the exploit though its address sorts first.
        "probe": raised("100.20.30.40", "possible_port_scan", [_log(db, src="100.20.30.40", **inbound)], 40),
        # A fourth outside address, past the three the overview names.
        "fourth": raised("100.20.30.41", "possible_port_scan", [_log(db, src="100.20.30.41", **inbound)], 30),
        "miner": [
            raised("10.1.44.163", "paloalto_malware_threat", [_log(db, src="10.1.44.163", dst="51.222.106.1", port=14444,
                   src_zone="WLAN-Inside", dst_zone="SG-Outside")], 100, explanation=XMRIG)
            for _ in range(3)
        ],
        "scanning": raised(None, "internet_scanning", [], 50, rules=[
            {"code": "internet_scanning", "attack_type": "port_scan"},
            {"code": "group_metadata", "scanner_count": 2, "connections": 30, "scanners": {
                "77.88.99.2": {"connections": 5, "targets": 5, "ports": [23]},
                "77.88.99.1": {"connections": 25, "targets": 20, "ports": [80]},
            }},
        ]),
    }
    db.flush()
    return alerts


def test_asked_who_attacks_mfu_the_overview_names_outside_addresses_scanners_and_mfu_devices_apart():
    # "Who is attacking us the most?" was answered "ATDR does not identify specific IP addresses", or with the top
    # source: an MFU device with a crypto miner. On a day without new alerts the overview had only "nothing to rank".
    db = _session()
    alerts = _alerts_from_everywhere(db, created=datetime(2026, 5, 20, 6, 0))
    settings = get_settings().model_copy(update={"assistant_redact_ips": False})
    overview = {tool.name: tool for tool in build_assistant_tools(db, settings=settings)}["security_overview"]
    text = overview.run({}).text

    assert (
        "Who the open alerts come from:\n"
        f"- Outside addresses with the most alerts: 91.92.93.94 (2 alerts, e.g. alert #{alerts['scan'][0].id}, port scan); "
        f"185.199.10.20 (1 alert, e.g. alert #{alerts['exploit'].id}, exploit attempt); "
        f"100.20.30.40 (1 alert, e.g. alert #{alerts['probe'].id}, port scan).\n"
        f"- Internet scanning, alert #{alerts['scanning'].id}: 2 outside addresses scanned or probed MFU (30 connections); "
        "the busiest, 77.88.99.1, made 25 connections to 20 or more MFU addresses.\n"
        "- MFU devices with the most alerts, MFU's own devices to check for infection or misuse: "
        f"10.1.44.163 (3 alerts, e.g. alert #{alerts['miner'][2].id}, malware / C2)."
    ) in text
    assert "100.20.30.41" not in text
    # What a quiet day's overview no longer repeats.
    assert "nothing to rank" not in text and "Created at any time instead" not in text
    assert "Who the alerts come from:\n- Outside addresses" in overview.run({"time_window": "all_time"}).text


def test_on_a_day_with_new_alerts_the_overview_says_who_they_come_from():
    db = _session()
    _alerts_from_everywhere(db)
    overview = {tool.name: tool for tool in build_assistant_tools(db, settings=get_settings())}["security_overview"]
    text = overview.run({}).text

    assert "Who the alerts created today come from:\n- Outside addresses with the most alerts: [redacted-ip] (2 alerts" in text
    assert "attack types" in text


def test_the_assistant_says_when_new_logs_are_checked_as_the_settings_have_it(seeded):  # noqa: F811
    # "Detection runs only when someone runs it" stopped being true once the background worker could check new logs.
    sessions, settings = seeded
    manual = "Detection checks new logs only when someone runs it from the dashboard, not continuously."
    automatic = (
        "Detection checks new logs by itself, a five-minute window at a time once the window after it is complete: "
        "about 5 to 10 minutes after the traffic, not as it happens."
    )
    cases = [
        ({"auto_detection_enabled": False, "operation_worker_enabled": True}, manual),
        # Switched on without the worker that runs the checks, nothing is checked by itself.
        ({"auto_detection_enabled": True, "operation_worker_enabled": False}, manual),
        ({"auto_detection_enabled": True, "operation_worker_enabled": True}, automatic),
    ]
    with sessions() as db:
        for update, sentence in cases:
            explain = {tool.name: tool for tool in build_assistant_tools(db, settings=settings.model_copy(update=update))}["explain_concept"]
            for topic in ("detection_coverage", "data_sources"):
                text = explain.run({"topic": topic}).text
                assert sentence in text, (update, topic)
                assert (manual if sentence is automatic else automatic) not in text
    note = assistant_service._topic_notes("Does ATDR work with live traffic?")[0]
    assert "as the topic says it" in note and "only when someone runs it" not in note


def test_a_ranking_of_alert_sources_gives_each_alerts_size_and_the_busiest_outside_addresses():
    # "Is any single IP hammering our network?": the model ranked the flood alerts' sources, one alert each, and
    # answered no, though one outside address had made 1,057 connections, all in the hourly scanning alert.
    db = _session()
    alerts = _alerts_from_everywhere(db)
    inbound = {"port": 443, "src_zone": "SG-Outside", "dst_zone": "WLAN-Inside"}
    for n in range(5):
        _log(db, src="45.82.76.10", dst=f"10.1.1.{n}", minute=36 + n, **inbound)
    for _ in range(2):
        _log(db, src="185.199.10.20", dst="10.1.1.9", **inbound)
    db.flush()
    settings = get_settings().model_copy(update={"assistant_redact_ips": False})
    query_alerts = {tool.name: tool for tool in build_assistant_tools(db, settings=settings)}["query_alerts"]
    text = query_alerts.run({"intent": "top", "group_by": "src_ip"}).text

    assert f"91.92.93.94 (outside address): 2 alerts (22%), e.g. alert #{alerts['scan'][0].id}, 1 connection\n" in text
    # The MFU device with the miner has more connections than two of these, but is not an outside address.
    assert text.endswith(
        "Busiest single outside addresses in the stored firewall logs, by connections rather than alerts: "
        "45.82.76.10: 5 connections to 5 destination addresses in about 4 minutes (20 May 2026 13:36 to 13:40), in no alert; "
        "185.199.10.20: 3 connections to 1 destination address within a minute (20 May 2026 13:36), "
        f"in alert #{alerts['exploit'].id} (exploit attempt); "
        "91.92.93.94: 2 connections to 1 destination address within a minute (20 May 2026 13:36), "
        f"in alert #{alerts['scan'][1].id} (port scan)."
    )
    # For floods, how much one address sent is the answer, so the busiest come first.
    flood = query_alerts.run({"intent": "top", "group_by": "src_ip", "attack_type": "dos_ddos"}).text
    assert flood.startswith("Busiest single outside addresses in the stored firewall logs") and "\n\nNo flood" in flood
    # Not beside a ranking of something else, nor of one address's alerts.
    assert "Busiest single" not in query_alerts.run({"intent": "top", "group_by": "attack_type"}).text
    assert "Busiest single" not in query_alerts.run({"intent": "top", "group_by": "src_ip", "ip": "10.1.1.9"}).text


def test_on_a_day_with_new_alerts_the_overview_keeps_the_days_counts_and_the_open_ones_apart():
    # Given the day's counts and the open ones in separate paragraphs, the model wrote "Open alerts: 20 (Critical: 4,
    # High: 4, Medium: 17, Low: 5)", the severities of all 30 alerts created that day.
    db = _session()
    alerts = _alerts_from_everywhere(db)
    alerts["probe"].severity = alerts["fourth"].severity = "Medium"
    alerts["scan"][1].status = "resolved"
    alerts["fourth"].created_at = datetime(2026, 5, 20, 6, 0)
    db.flush()
    overview = {tool.name: tool for tool in build_assistant_tools(db, settings=get_settings())}["security_overview"]
    parts = overview.run({}).text.split("\n\n")

    # In place of the day's own count, which only repeated its figures.
    assert not any(part.startswith("8 alerts were created today.") for part in parts)
    assert parts[2] == (
        "The counts, kept apart: 8 alerts were created today (Critical 7, Medium 1), and 7 of them are still open "
        "(Critical 6, Medium 1). Open now, from any day: 8 alerts (Critical 6, Medium 2)."
    )
    # Over all time there is no period to keep apart from the open alerts.
    assert "kept apart" not in overview.run({"time_window": "all_time"}).text
