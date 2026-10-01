"""The alert drawer's "In plain words" summary, and the fallback for "is MFU under attack right now?"."""

from __future__ import annotations

from datetime import datetime, timedelta

from sqlalchemy import func, select

from atdr.app.db.models import Alert, AlertEvidence, NormalizedLog, RawLog, WatchlistItem
from atdr.app.detection.explanations import build_alert_detection_summary
from atdr.app.detection.plain_summary import build_plain_summary, threat_name
from atdr.app.services import assistant_service
from atdr.tests.test_assistant_agent import ScriptedEngine, _ask, _call, _say, seeded  # noqa: F401
from atdr.tests.test_detection_grouping import _session

XMRIG = (
    "The firewall classified this row as a malware-class THREAT event; vendor severity is critical, type is spyware, "
    "category is any, and threat name is XMRig Miner Command and Control Traffic Detection(85886)."
)


def _log(db, *, src, dst, port, src_zone, dst_zone, action="allow", minute=36, **fields):
    raw = RawLog(raw_line=f"{src} {dst} {port}")
    db.add(raw)
    db.flush()
    log = NormalizedLog(
        raw_log_id=raw.id, generated_time=datetime(2026, 5, 20, 13, minute, 15), log_type="TRAFFIC", src_ip=src,
        dst_ip=dst, dst_port=port, src_zone=src_zone, dst_zone=dst_zone, action=action, parsed_json={}, **fields,
    )
    db.add(log)
    db.flush()
    return log


def _alert(db, alert_type, logs, *, explanation="", rules=None):
    alert = Alert(
        title=alert_type, alert_type=alert_type, threat_score=100, severity="Critical", status="open",
        explanation=explanation or f"{alert_type} explanation", recommended_response="look",
        matched_rules_json=rules or [{"code": alert_type}],
    )
    db.add(alert)
    db.flush()
    for log in logs:
        db.add(AlertEvidence(alert_id=alert.id, normalized_log_id=log.id))
    db.flush()
    return alert


def test_a_malware_alert_names_the_device_the_threat_and_that_the_firewall_blocked_it():
    db = _session()
    logs = [
        _log(db, src="10.1.44.163", dst=f"51.222.106.{n}", port=14444, src_zone="WLAN-Inside", dst_zone="SG-Outside",
             action="drop", minute=36 + n, dst_country="Canada")
        for n in range(3)
    ]
    text = build_plain_summary(db, _alert(db, "paloalto_malware_threat", logs, explanation=XMRIG), "malware_c2")

    assert text.startswith(
        "On 20 May, 13:36–13:38, an MFU device (10.1.44.163) made 3 connections to 3 outside servers on port 14444."
    )
    assert 'The firewall recognised it as "XMRig Miner Command and Control Traffic Detection" and blocked all 3.' in text
    assert "This may be malware on the MFU device contacting whoever controls it." in text
    assert text.endswith("Next: decide whether an internal host is contacting an outside server the way malware would.")


def test_one_blocked_connection_from_outside_names_its_country_and_target():
    db = _session()
    log = _log(db, src="147.45.50.171", dst="202.28.44.41", port=80, src_zone="SG-Outside", dst_zone="WLAN-Inside",
               action="drop", minute=38, src_country="Netherlands", dst_country="Thailand")
    text = build_plain_summary(db, _alert(db, "paloalto_threat_log", [log]), "exploit_attempt")

    assert text.startswith(
        "On 20 May at 13:38, an outside address (147.45.50.171, Netherlands) made one connection to an MFU device "
        "(202.28.44.41) on port 80. The firewall blocked it."
    )
    assert "Thailand" not in text


def test_a_watchlist_alert_gives_the_first_sentence_of_the_indicator_note():
    db = _session()
    db.add(WatchlistItem(
        indicator_type="dst_ip", indicator_value="111.90.158.40", created_by="koe",
        description="GHOSTENGINE C2 server (Elastic Security Labs, May 2024). Found 2026-09-27: it beaconed every 14 s.",
    ))
    logs = [
        _log(db, src="10.1.200.251", dst="111.90.158.40", port=80, src_zone="WLAN-Inside", dst_zone="SG-Outside",
             minute=36 + n, dst_country="Malaysia")
        for n in range(2)
    ]
    rules = [{"code": "watchlist_match", "explanation": "Matched active watchlist indicator(s): dst_ip:111.90.158.40."}]
    text = build_plain_summary(db, _alert(db, "watchlist_match", logs, rules=rules), "malware_c2")

    assert "made 2 connections to an outside server (111.90.158.40, Malaysia) on port 80." in text
    assert "111.90.158.40 is on ATDR's watchlist: GHOSTENGINE C2 server (Elastic Security Labs, May 2024)." in text
    assert "Found 2026-09-27" not in text
    assert "The firewall allowed both." in text


def test_a_model_alert_says_no_rule_fired_and_gives_the_reading_as_low_confidence():
    db = _session()
    logs = [
        _log(db, src="45.82.76.118", dst=f"202.28.44.{n}", port=port, src_zone="SG-Outside", dst_zone="WLAN-Inside",
             minute=38, src_country="Germany")
        for n, port in enumerate((465, 873, 3269, 32080))
    ]
    text = build_plain_summary(db, _alert(db, "mfu_behavior_model", logs), "port_scan")

    assert "an outside address (45.82.76.118, Germany) made 4 connections to 4 MFU devices on 4 different ports." in text
    assert "No rule fired on it; ATDR's experimental behaviour model reads it as possibly a port scan, with low confidence." in text
    assert "This may be" not in text


def test_a_private_address_is_an_mfu_device_whatever_its_zone_is_called():
    db = _session()
    logs = [
        _log(db, src="10.1.94.28", dst="192.168.1.5", port=53, src_zone="WLAN-Outside", dst_zone="WLAN-Inside", action=action)
        for action in ("allow", "deny", "allow")
    ]
    text = build_plain_summary(db, _alert(db, "connection_flood_suspicion", logs), "dos_ddos")

    assert text.startswith(
        "On 20 May at 13:36, an MFU device (10.1.94.28) made 3 connections to another MFU device (192.168.1.5) on port 53."
    )
    assert "The firewall blocked 1 of the 3 and allowed the rest." in text


def test_the_drawer_summary_counts_every_evidence_log_not_only_the_first_25():
    db = _session()
    logs = [
        _log(db, src="45.82.76.10", dst=f"10.0.0.{n}", port=10000 + n, src_zone="SG-Outside", dst_zone="LAN-Inside",
             action="deny" if n >= 25 else "allow")
        for n in range(30)
    ]
    summary = build_alert_detection_summary(db, _alert(db, "possible_horizontal_scan", logs))

    assert "made 30 connections to 30 MFU devices on 30 different ports." in summary["plain_summary"]
    assert "The firewall blocked 5 of the 30 and allowed the rest." in summary["plain_summary"]
    assert summary["plain_summary"].endswith("Next: decide whether this is approved scanning or someone mapping your services.")


def test_an_alert_without_evidence_has_no_summary_and_the_threat_name_drops_its_number():
    db = _session()
    assert build_plain_summary(db, _alert(db, "app_risk_5", []), "policy_violation") == ""
    assert threat_name(XMRIG) == "XMRig Miner Command and Control Traffic Detection"
    assert threat_name("Palo Alto application risk is 4.") is None


def test_attack_status_drafts_that_fail_the_checks_fall_back_to_what_atdr_can_say(seeded, monkeypatch):  # noqa: F811
    testing_session, settings = seeded
    engine = ScriptedEngine(
        _call("security_overview", time_window="today"),
        _say("MFU is not under attack right now."),
        _say("MFU is safe and not under attack."),
    )
    monkeypatch.setattr(assistant_service, "engine_from_settings", lambda _settings: engine)
    with testing_session() as db:
        response = _ask(db, settings, "Is MFU under attack right now?")
        newest = db.scalar(select(func.max(NormalizedLog.generated_time)))

    assert response["details"]["agent"]["fallback_reason"] == "answer_failed_verification"
    assert response["answer"].startswith(
        f"ATDR cannot tell whether MFU is under attack right now: it sees only imported firewall logs, and the newest "
        f"is from {newest:%d %b %Y %H:%M} (firewall local time)."
    )
    assert "alerts are still open" in response["answer"]
    assert "import the newest firewall logs and run detection" in response["answer"]
    assert "built-in answer" not in response["answer"]


def test_asked_for_all_of_the_system_status_the_tool_gives_one_health_view(seeded):  # noqa: F811
    # "Is the system healthy?" sent area=all, got an error, and walked the areas one by one until it ran out of rounds.
    from atdr.app.services.assistant_tools import build_assistant_tools

    testing_session, settings = seeded
    with testing_session() as db:
        status = {tool.name: tool for tool in build_assistant_tools(db, settings=settings)}["system_status"]
        overview = status.run({"area": "all"}).text
        parts = [status.run({"area": area}).text for area in ("sources", "operations", "detection_runs", "failed_jobs")]

    assert overview == "\n\n".join(parts)


def _typed_alert(db, alert_type, rule_codes, logs, *, severity="High", score=70, status="open", explanation=""):
    alert = _alert(db, alert_type, logs, explanation=explanation, rules=[{"code": code} for code in rule_codes])
    alert.severity, alert.threat_score, alert.status = severity, score, status
    db.flush()
    return alert


def test_the_overview_says_what_the_open_alerts_show_most_dangerous_first():
    from atdr.app.detection.plain_summary import build_situation_summary

    db = _session()
    db.add(WatchlistItem(indicator_type="dst_ip", indicator_value="111.90.158.40", created_by="koe",
                         description="GHOSTENGINE C2 server (Elastic Security Labs, May 2024). Found later."))
    miners = [
        _typed_alert(db, "paloalto_malware_threat", ["paloalto_malware_threat"], [
            _log(db, src=f"10.1.44.{n}", dst="51.222.106.1", port=14444, src_zone="WLAN-Inside", dst_zone="SG-Outside", action="drop")
        ], severity="Critical", score=100, explanation=XMRIG)
        for n in range(2)
    ]
    watchlist = _typed_alert(db, "watchlist_match", [], [
        _log(db, src="10.1.200.251", dst="111.90.158.40", port=80, src_zone="WLAN-Inside", dst_zone="SG-Outside")
        for _ in range(3)
    ], severity="Critical", score=90)
    watchlist.matched_rules_json = [{
        "code": "watchlist_match", "attack_type": "malware_c2",
        "explanation": "Matched active watchlist indicator(s): dst_ip:111.90.158.40.",
    }]
    scans = [
        _typed_alert(db, "possible_port_scan", ["possible_port_scan"], [
            _log(db, src="45.82.76.10", dst=f"202.28.44.{n}", port=22, src_zone="SG-Outside", dst_zone="WLAN-Inside")
        ], severity="Critical", score=100)
        for n in range(3)
    ]
    _typed_alert(db, "brute_force_like_attempts", ["brute_force_like_attempts"], [
        _log(db, src="189.140.30.191", dst="202.28.45.230", port=22, src_zone="SG-Outside", dst_zone="WLAN-Inside", action="deny")
    ])
    _typed_alert(db, "high_outbound_bytes", ["high_outbound_bytes"], [
        _log(db, src="10.1.5.27", dst="57.145.10.145", port=443, src_zone="WLAN-Inside", dst_zone="SG-Outside")
    ])
    _typed_alert(db, "app_risk_5", ["app_risk_5"], [
        _log(db, src="10.1.5.28", dst="57.145.10.146", port=443, src_zone="WLAN-Inside", dst_zone="SG-Outside")
    ])
    _typed_alert(db, "connection_flood_suspicion", ["connection_flood_suspicion"], [
        _log(db, src="10.1.5.29", dst="192.168.1.5", port=53, src_zone="WLAN-Inside", dst_zone="WLAN-Inside")
    ])
    _typed_alert(db, "possible_port_scan", ["possible_port_scan"], [
        _log(db, src="45.82.76.99", dst="202.28.44.99", port=23, src_zone="SG-Outside", dst_zone="WLAN-Inside")
    ], severity="Critical", score=100, status="resolved")
    situation = build_situation_summary(db)

    # The resolved scan is left out of everything but the newest-log date.
    assert situation["headline"] == (
        "10 alerts are open (6 Critical), from MFU's firewall logs of 20 May at 13:36. The newest log ATDR has is "
        "from 20 May 2026 13:36, so this is not live traffic."
    )
    malware, data_theft, guessing, floods, rest = situation["points"]
    assert malware == (
        "Malware calling out: 3 alerts from 3 MFU devices; the firewall blocked 2 of 5 connections. Named by the "
        "firewall or the watchlist: GHOSTENGINE C2 server, on ATDR's watchlist (1 MFU device, let through); XMRig "
        "Miner Command and Control (2 MFU devices, blocked)."
    )
    assert data_theft == "Possible data theft: 1 alert from 1 MFU device; the firewall let it through."
    assert guessing == "Password guessing: 1 alert from 1 outside address; the firewall blocked it."
    assert floods.startswith("Floods: 1 alert from 1 MFU device")
    assert rest == "Also open: 3 scanning and 1 policy alerts."
    # A named threat the firewall let through comes before Critical alerts the firewall blocked or that name nothing.
    assert situation["open_first"]["alert_id"] == watchlist.id
    assert situation["open_first"]["reason"] == "a threat the firewall or the watchlist named, and the firewall let it through"
    assert miners and scans


def test_the_dashboard_summary_carries_the_plain_words_situation():
    from atdr.app.detection.plain_summary import build_situation_summary
    from atdr.app.services.dashboard_service import build_dashboard_summary

    db = _session()
    scan = _typed_alert(db, "possible_port_scan", ["possible_port_scan"], [
        _log(db, src="45.82.76.10", dst="202.28.44.1", port=22, src_zone="SG-Outside", dst_zone="WLAN-Inside")
    ])
    db.commit()
    situation = build_dashboard_summary(db)["situation"]

    assert situation == build_situation_summary(db)
    assert situation["points"] == ["Scanning: 1 alert from 1 outside address; the firewall let it through."]
    assert situation["open_first"]["alert_id"] == scan.id


def test_the_overview_with_nothing_open_says_so():
    from atdr.app.detection.plain_summary import build_situation_summary

    db = _session()
    _typed_alert(db, "possible_port_scan", ["possible_port_scan"], [
        _log(db, src="45.82.76.10", dst="202.28.44.1", port=22, src_zone="SG-Outside", dst_zone="WLAN-Inside")
    ], status="resolved")
    assert build_situation_summary(db) == {"headline": "No alerts are open.", "points": [], "open_first": None}


def test_no_alerts_on_a_day_the_stored_logs_cover_is_sent_back():
    # "What happened on 20 May?" was answered "no new alerts were created on that day".
    from atdr.app.services.assistant_agent import calendar_days, verify_answer

    logs = ["Stored firewall logs: 151,002, with event times from 20 May 2026 13:36 to 20 May 2026 13:39 (firewall local time)."]
    check = lambda answer, asked="What happened on 20 May?": verify_answer(  # noqa: E731
        answer, evidence=logs, asked=[asked], redacted=True, forbidden_values=[],
    )
    for claim in ("On 20 May there were no new alerts created on that day.", "No alerts were triggered on 20 May."):
        assert any("every alert describes the stored firewall traffic" in problem for problem in check(claim)), claim
    assert check("On 20 May the firewall logs show malware calling out from MFU devices.") == []
    assert check("No new alerts were created today.", asked="What happened today?") == []
    assert check("There were no alerts on that day.", asked="What happened on 21 May?") == []
    assert calendar_days(["May 20th", "2026-05-20", "at 13:36", "May 2026"]) == [(5, 20), (5, 20)]


def test_a_question_about_a_day_falls_back_to_that_days_traffic_in_plain_words(seeded, monkeypatch):  # noqa: F811
    testing_session, settings = seeded
    claim = "There were no new alerts created on that day."
    engine = ScriptedEngine(_call("security_overview", time_window="all_time"), _say(claim), _say(claim))
    monkeypatch.setattr(assistant_service, "engine_from_settings", lambda _settings: engine)
    with testing_session() as db:
        first, last = db.execute(select(func.min(NormalizedLog.generated_time), func.max(NormalizedLog.generated_time))).one()
        logged = _ask(db, settings, f"What happened on {last.day} {last:%B}?")
        later = last.date() + timedelta(days=1)
        unlogged = assistant_service._answer_traffic_day(db, f"What happened on {later.day} {later:%B}?", redacted=True)

    assert logged["details"]["agent"]["fallback_reason"] == "answer_failed_verification"
    assert logged["answer"].startswith("ATDR's stored firewall logs are from ")
    assert "the open alerts describe that traffic, though each is dated by when detection ran." in logged["answer"]
    assert "Open first: alert #" in logged["answer"]
    assert unlogged.answer.startswith(f"ATDR has no firewall logs from {later.day} {later:%B}: its stored logs are from ")
    assert first is not None


def test_the_overview_tool_tells_what_the_stored_traffic_showed_in_plain_words(seeded):  # noqa: F811
    # Asked "what happened on 20 May?", the model read the alerts' creation dates and said nothing was detected.
    from atdr.app.detection.plain_summary import brief_situation, build_situation_summary
    from atdr.app.services.assistant_tools import build_assistant_tools

    testing_session, settings = seeded
    with testing_session() as db:
        overview = {tool.name: tool for tool in build_assistant_tools(db, settings=settings)}["security_overview"]
        text = overview.run({"time_window": "today"}).text
        situation = build_situation_summary(db)

    headline = situation["headline"].split(" The newest log")[0]
    assert f"What the open alerts show, in plain words: {headline}" in text
    assert all(f"- {line}" in text for line in brief_situation(situation))
    assert text.index("What the open alerts show") < text.index("Open alerts, highest score first:")
    assert "to look at first" not in text


def test_the_assistants_copy_keeps_named_threats_only_on_the_most_dangerous_line():
    # The full lines made "Are we under attack?" run past the length limit and get rewritten: 17 s instead of 5.
    from atdr.app.detection.plain_summary import brief_situation

    situation = {
        "headline": "2 alerts are open.",
        "points": [
            "Malware calling out: 1 alert from 1 MFU device; the firewall blocked it. Named by the firewall or the watchlist: XMRig (1 MFU device, blocked).",
            "Break-in attempts: 1 alert from 1 outside address; the firewall blocked it. Named by the firewall or the watchlist: Bash RCE (1 outside address, blocked).",
        ],
        "open_first": {"alert_id": 7, "severity": "Critical", "title": "t", "reason": "the most serious open alert"},
    }
    assert brief_situation(situation) == [
        situation["points"][0],
        "Break-in attempts: 1 alert from 1 outside address; the firewall blocked it.",
        "Open first: alert #7 (Critical), the most serious open alert.",
    ]


def test_a_list_left_empty_by_removing_tool_names_takes_its_intro_with_it():
    from atdr.app.services.assistant_agent import ATDR_QUESTION, drop_tool_mentions

    answer = "Alert #3773 is XMRig.\n\nTo investigate further, you can:\n- Use query_alerts to list them.\n\nLet me know!"
    assert drop_tool_mentions(answer, ["query_alerts"]) == "Alert #3773 is XMRig.\n\nLet me know!"
    assert drop_tool_mentions("Steps:\n- Open Alerts.\n- Use get_alert.", ["get_alert"]) == "Steps:\n- Open Alerts."
    # The demo's follow-up got generic advice without a lookup.
    assert ATDR_QUESTION.search("What should I check first on the most urgent one?")


def test_a_trust_answer_must_say_that_answers_are_checked():
    # "Why should I trust your answers?" was answered "I can only explain what the tools show", run after run.
    from atdr.app.services.assistant_agent import verify_answer

    account = ["You can check my answers: before you see one, ATDR checks that every number, alert number, IP address "
               "and page name in it appears in what my read-only tools returned."]
    check = lambda answer, evidence=account, asked="Why should I trust your answers?": verify_answer(  # noqa: E731
        answer, evidence=evidence, asked=[asked], redacted=True, forbidden_values=[],
    )
    vague = "I can only read and explain what ATDR's tools show, and I cannot take actions."
    assert any("does not say how answers are checked" in problem for problem in check(vague))
    assert check("Before you see an answer, ATDR checks every number in it against what my tools returned.") == []
    assert check(vague, evidence=["7 High alerts."]) == []
    assert check(vague, asked="What can you do?") == []


def test_trust_drafts_that_fail_the_checks_fall_back_to_the_same_account_of_the_checks(seeded, monkeypatch):  # noqa: F811
    testing_session, settings = seeded
    vague = "I can only read and explain what ATDR's tools show."
    engine = ScriptedEngine(_call("explain_concept", topic="how_you_work"), _say(vague), _say(vague))
    monkeypatch.setattr(assistant_service, "engine_from_settings", lambda _settings: engine)
    with testing_session() as db:
        response = _ask(db, settings, "Why should I trust your answers?")

    assert response["details"]["agent"]["fallback_reason"] == "answer_failed_verification"
    assert response["answer"].startswith("You can check my answers.\n- Before you see one, ATDR checks that every number")
    assert "I cannot block, change, close or delete anything." in response["answer"]
    assert "#" not in response["answer"]


def test_only_trust_questions_take_the_trust_fallback():
    asks = assistant_service.TRUST_QUESTION.search
    for question in ["Why should I trust your answers?", "Can I trust you?", "Is the assistant making things up?", "Do you hallucinate?"]:
        assert asks(question), question
    for question in ["Which alerts can I trust?", "How do I trust a new log source?", "What can you do?"]:
        assert not asks(question), question


def test_only_attack_status_questions_take_the_new_fallback():
    asks = assistant_service.ATTACK_STATUS_QUESTION.search
    for question in ["Is MFU under attack right now?", "Are we being hacked?", "is the network safe?", "MFU ถูกโจมตีอยู่ไหม"]:
        assert asks(question), question
    for question in ["What attack types are there?", "How do I stop an attack?", "Is alert 3773 safe to close?"]:
        assert not asks(question), question
