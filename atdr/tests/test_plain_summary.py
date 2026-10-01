"""The alert drawer's "In plain words" summary, and the fallback for "is MFU under attack right now?"."""

from __future__ import annotations

from datetime import datetime

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
