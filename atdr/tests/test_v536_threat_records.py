"""Rule catalog v5.36.0: informational no-attack threat records support, firewall-named malware leads."""

from __future__ import annotations

from datetime import datetime, timedelta

from sqlalchemy import select

from atdr.app.db.models import Alert, NormalizedLog, RawLog
from atdr.app.detection.explanations import explain_log_triage
from atdr.app.detection.rules import RuleMatch, build_detection_context, evaluate_rules
from atdr.app.services import detection_service
from atdr.app.services.detection_service import run_detection
from atdr.tests.test_attack_types import _threat
from atdr.tests.test_detection_grouping import _session

NON_RFC = "Non-RFC Compliant SSL Traffic on Port 443(56112)"


def _codes(log: NormalizedLog) -> set[str]:
    return {match.code for match in evaluate_rules(log, build_detection_context([log]))}


def _outbound_record(name: str, *, severity: str = "informational", **overrides) -> NormalizedLog:
    values = dict(src_ip="10.1.4.20", dst_ip="198.51.100.7", src_zone="WLAN-Inside", dst_zone="SG-Outside",
                  app="ssl", dst_port=443, action="alert")
    values.update(overrides)
    return _threat(name, severity=severity, **values)


def test_an_informational_record_naming_no_attack_gets_its_own_supporting_rule():
    assert "paloalto_threat_informational" in _codes(_outbound_record(NON_RFC))
    assert "paloalto_threat_log" not in _codes(_outbound_record(NON_RFC))
    # Anything that names an attack, or that the vendor rates above informational, stays a threat event.
    assert "paloalto_threat_log" in _codes(_outbound_record("ENV File Scanning Attempt(93397)"))
    assert "paloalto_threat_log" in _codes(_outbound_record(NON_RFC, severity="low"))
    assert "paloalto_threat_log" in _codes(_outbound_record(NON_RFC, severity=""))
    assert "paloalto_malware_threat" in _codes(_outbound_record("Some Spyware(1)", subtype="spyware"))


def _store(db, log: NormalizedLog, index: int) -> None:
    raw = RawLog(raw_line=f"log {index}")
    db.add(raw)
    db.flush()
    log.raw_log_id = raw.id
    db.add(log)


def test_an_informational_record_alone_raises_no_alert_and_says_why():
    db = _session()
    _store(db, _outbound_record(NON_RFC), 0)
    db.commit()

    run = run_detection(db, limit=100, use_ml=False, actor="test")

    assert db.scalar(select(Alert)) is None
    assert run["supporting_only_logs"] == 1
    log = db.scalar(select(NormalizedLog))
    reasons = " ".join(explain_log_triage(log)["reasons"])
    assert "informational firewall threat record that names no attack" in reasons


def test_an_informational_record_still_counts_as_evidence_alongside_a_scan():
    db = _session()
    for index in range(30):
        _store(db, NormalizedLog(generated_time=datetime(2026, 5, 20, 10, 0) + timedelta(seconds=index), log_type="TRAFFIC",
                                 src_ip="10.1.4.20", dst_ip="198.51.100.7", src_zone="WLAN-Inside", dst_zone="SG-Outside",
                                 app="unknown-tcp", dst_port=20000 + index, action="deny", bytes=60, packets=1, parsed_json={}), index)
    _store(db, _outbound_record(NON_RFC, generated_time=datetime(2026, 5, 20, 10, 0, 31)), 99)
    db.commit()

    run_detection(db, limit=100, use_ml=False, actor="test")

    record = db.scalar(select(NormalizedLog).where(NormalizedLog.log_type == "THREAT"))
    alerted = {evidence.normalized_log_id for alert in db.scalars(select(Alert)) for evidence in alert.evidence}
    assert record.id in alerted


def test_firewall_named_malware_leads_an_alert_whose_retries_also_look_like_a_scan():
    malware = RuleMatch(code="paloalto_malware_threat", title="m", score=65, explanation="e", attack_type="malware_c2")
    scan = RuleMatch(code="possible_port_scan", title="s", score=30, explanation="e")
    horizontal = RuleMatch(code="possible_horizontal_scan", title="h", score=25, explanation="e")
    assert detection_service._primary_rule([scan, horizontal, malware]).code == "paloalto_malware_threat"
