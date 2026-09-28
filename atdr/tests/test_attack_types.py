"""An alert's attack type comes from what its evidence names, not only from which rule fired."""

from __future__ import annotations

from datetime import datetime
from types import SimpleNamespace

import pytest
from sqlalchemy import select

from atdr.app.db.models import Alert, NormalizedLog, RawLog
from atdr.app.detection.attack_mapping import ATTACK_TYPE_MAPPINGS, infer_attack_type_from_rules
from atdr.app.detection.playbooks import PLAYBOOK_GUIDANCE
from atdr.app.detection.rules import DetectionResult, RuleMatch, build_detection_context, evaluate_rules
from atdr.app.services.alert_service import _merge_rule_metadata, create_alert_from_detection
from atdr.app.services.detection_service import run_detection
from atdr.app.services.watchlist_service import watchlist_attack_type
from atdr.tests.test_detection_grouping import _session


def _threat(name: str, *, subtype: str = "vulnerability", severity: str = "informational", **overrides) -> NormalizedLog:
    values = dict(
        generated_time=datetime(2026, 5, 20, 10, 0),
        log_type="THREAT",
        subtype=subtype,
        category="any",
        src_ip="198.51.100.7",
        dst_ip="10.1.4.20",
        src_zone="SG-Outside",
        dst_zone="WLAN-Inside",
        app="web-browsing",
        dst_port=80,
        action="drop",
        parsed_json={"parsed_threat_severity": severity, "parsed_threat_name": name},
    )
    values.update(overrides)
    return NormalizedLog(**values)


THREAT_RULES = {"paloalto_threat_log", "paloalto_threat_informational"}


def _threat_rule(log: NormalizedLog):
    return next(match for match in evaluate_rules(log, build_detection_context([log])) if match.code in THREAT_RULES)


# Signatures seen in the MFU firewall export, plus a few PAN-OS types it has not shown yet.
@pytest.mark.parametrize(
    ("name", "subtype", "severity", "expected"),
    [
        ("Nmap Aggressive Option Print Detection(94318)", "vulnerability", "low", "port_scan"),
        ("RPC Portmapper DUMP Request Detected(32796)", "vulnerability", "medium", "port_scan"),
        ("Bash Remote Code Execution Vulnerability(36729)", "vulnerability", "critical", "exploit_attempt"),
        ("Apache HTTP Server Path Traversal Vulnerability(91752)", "vulnerability", "high", "exploit_attempt"),
        ("ENV File Scanning Attempt(93397)", "vulnerability", "informational", "exploit_attempt"),
        ("SSH2 Login Attempt(31914)", "vulnerability", "informational", "brute_force"),
        ("Non-RFC Compliant SSL Traffic on Port 443(56112)", "vulnerability", "informational", "unknown_anomaly"),
        ("OpenSSL SSLv2 Man-in-the-Middle Vulnerability(59268)", "vulnerability", "informational", "unknown_anomaly"),
        ("TCP Port Scan(8001)", "scan", "critical", "port_scan"),
        ("TCP Flood(8501)", "flood", "critical", "dos_ddos"),
    ],
)
def test_a_firewall_threat_signature_names_the_attack_type(name, subtype, severity, expected):
    assert _threat_rule(_threat(name, subtype=subtype, severity=severity)).attack_type == expected


def test_a_firewall_named_miner_is_malware_not_the_scan_its_retries_look_like():
    # MFU hosts running XMRig tried dozens of mining pools; the retries also
    # match the scan rules, which used to decide the alert's type.
    rules = [
        {"code": "possible_port_scan", "attack_type": "port_scan"},
        {"code": "possible_horizontal_scan", "attack_type": "port_scan"},
        {"code": "paloalto_malware_threat", "attack_type": "malware_c2"},
        {"code": "deny_drop_action", "attack_type": "policy_violation"},
    ]
    assert infer_attack_type_from_rules(rules) == "malware_c2"


def test_a_threat_signature_names_the_attack_behind_repeated_denials():
    rules = [
        {"code": "paloalto_threat_log", "attack_type": "exploit_attempt"},
        {"code": "multiple_denied_connections", "attack_type": "policy_violation"},
        {"code": "ml_anomaly_detected", "attack_type": "unknown_anomaly"},
    ]
    assert infer_attack_type_from_rules(rules) == "exploit_attempt"


def test_needs_investigation_never_hides_a_type_another_rule_names():
    assert infer_attack_type_from_rules([
        {"code": "paloalto_threat_log", "attack_type": "unknown_anomaly"},
        {"code": "deny_drop_action", "attack_type": "policy_violation"},
    ]) == "policy_violation"
    # The catalog calls app risk a policy matter; the alert list used to say "unclassified".
    assert infer_attack_type_from_rules([{"code": "app_risk_5"}]) == "policy_violation"
    assert infer_attack_type_from_rules([{"code": "outside_to_inside"}]) == "unknown_anomaly"


def test_an_unsolicited_unanswered_connection_to_an_odd_port_is_probing():
    probe = NormalizedLog(src_ip="198.51.100.7", dst_ip="10.1.4.20", src_zone="SG-Outside", dst_zone="WLAN-Inside",
                          app="incomplete", dst_port=8728, action="allow", bytes_received=0)
    answered = NormalizedLog(src_ip="198.51.100.7", dst_ip="10.1.4.20", src_zone="SG-Outside", dst_zone="WLAN-Inside",
                             app="ssl", dst_port=8728, action="allow", bytes_received=4200)
    outbound = NormalizedLog(src_ip="10.1.4.20", dst_ip="198.51.100.7", src_zone="WLAN-Inside", dst_zone="SG-Outside",
                             app="incomplete", dst_port=8728, action="allow", bytes_received=0)

    def types(log):
        return {m.code: m.attack_type for m in evaluate_rules(log, build_detection_context([log]))}

    assert types(probe)["unusual_destination_port"] == "port_scan"
    assert types(probe)["unknown_or_incomplete_app"] == "port_scan"
    assert types(answered)["unusual_destination_port"] is None
    assert types(outbound)["unknown_or_incomplete_app"] is None


def test_a_watchlist_hit_says_what_kind_of_indicator_matched():
    outbound = SimpleNamespace(dst_ip="50.16.16.211")
    internal = SimpleNamespace(dst_ip="10.1.4.20")

    def items(*kinds):
        return [SimpleNamespace(indicator_type=kind) for kind in kinds]

    assert watchlist_attack_type(items("dst_ip"), outbound) == "malware_c2"
    assert watchlist_attack_type(items("dst_ip"), internal) is None
    assert watchlist_attack_type(items("app"), outbound) == "policy_violation"
    assert watchlist_attack_type(items("src_ip"), outbound) is None


# Both low severity, so both stay alert-worthy threat records with the same score.
@pytest.mark.parametrize("order", [("Unknown HTTP Request Header(30000)", "ENV File Scanning Attempt(93397)"),
                                   ("ENV File Scanning Attempt(93397)", "Unknown HTTP Request Header(30000)")])
def test_a_grouped_alert_keeps_the_most_specific_type_any_of_its_logs_named(order):
    db = _session()
    for second, name in enumerate(order):
        raw = RawLog(raw_line=name)
        db.add(raw)
        db.flush()
        db.add(_threat(name, severity="low", raw_log_id=raw.id, generated_time=datetime(2026, 5, 20, 10, 0, second)))
    db.commit()

    run_detection(db, limit=100, use_ml=False, actor="test")

    alert = db.scalar(select(Alert))
    assert alert is not None and len(alert.evidence) == 2
    assert infer_attack_type_from_rules(alert.matched_rules_json) == "exploit_attempt"


def test_a_repeat_alert_update_keeps_the_most_specific_type():
    vague = {"code": "paloalto_threat_log", "attack_type": "unknown_anomaly", "score": 10}
    named = {"code": "paloalto_threat_log", "attack_type": "exploit_attempt", "score": 10}
    assert _merge_rule_metadata([vague], [named])[0]["attack_type"] == "exploit_attempt"
    assert _merge_rule_metadata([named], [vague])[0]["attack_type"] == "exploit_attempt"


def test_every_attack_type_has_a_playbook():
    assert set(ATTACK_TYPE_MAPPINGS) - {"normal"} == set(PLAYBOOK_GUIDANCE)


def test_a_single_log_alert_keeps_the_type_its_evidence_named():
    rule = RuleMatch(code="paloalto_threat_log", title="t", score=40, explanation="e", attack_type="exploit_attempt")
    result = DetectionResult(threat_score=40, severity="High", explanation="e", matched_rules=[rule])
    db = _session()
    alert = create_alert_from_detection(db, _threat("Bash Remote Code Execution Vulnerability(36729)"), result)
    assert infer_attack_type_from_rules(alert.matched_rules_json) == "exploit_attempt"
