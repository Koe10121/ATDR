from datetime import datetime, timedelta

from atdr.app.db.models import NormalizedLog
from atdr.app.detection.attack_mapping import infer_attack_type_from_rules
from atdr.app.detection.rules import build_detection_context, evaluate_rules


def test_rule_matches_deny_outside_to_inside_unknown_app():
    log = NormalizedLog(
        src_ip="180.167.128.202",
        dst_ip="202.28.45.207",
        src_zone="SG-Outside",
        dst_zone="WLAN-Inside",
        app="not-applicable",
        app_category="unknown",
        src_port=43010,
        dst_port=22,
        protocol="tcp",
        action="deny",
        subtype="drop",
        session_end_reason="policy-deny",
        app_risk=1,
        bytes=60,
        packets=1,
    )
    context = build_detection_context([log])
    codes = {match.code for match in evaluate_rules(log, context)}

    assert "deny_drop_action" in codes
    assert "outside_to_inside" in codes
    assert "unknown_or_incomplete_app" in codes


def test_rule_matches_repeated_source_and_port_scan():
    logs = [
        NormalizedLog(
            src_ip="203.0.113.10",
            dst_ip=f"10.0.0.{idx}",
            src_zone="SG-Outside",
            dst_zone="LAN-Inside",
            app="unknown",
            dst_port=10000 + idx,
            action="allow",
            bytes=100,
            packets=1,
        )
        for idx in range(30)
    ]
    context = build_detection_context(logs)
    codes = {match.code for match in evaluate_rules(logs[0], context)}

    assert "repeated_source_ip" in codes
    assert "possible_port_scan" in codes


def _repeated_logs(
    *,
    count: int,
    app: str,
    port: int,
    app_risk: int,
    app_characteristic: str,
    src_zone: str = "LAN-Inside",
    dst_zone: str = "SG-Outside",
    action: str = "allow",
) -> list[NormalizedLog]:
    started = datetime(2026, 5, 20, 13, 36)
    return [
        NormalizedLog(
            id=index + 1,
            generated_time=started + timedelta(seconds=index),
            log_type="TRAFFIC",
            src_ip="10.0.0.10",
            dst_ip="198.51.100.20",
            src_zone=src_zone,
            dst_zone=dst_zone,
            app=app,
            app_category="general-internet",
            app_characteristic=app_characteristic,
            dst_port=port,
            action=action,
            protocol="tcp",
            app_risk=app_risk,
            bytes=500,
            packets=5,
        )
        for index in range(count)
    ]


def test_common_allowed_ssl_repetition_is_not_called_beaconing():
    logs = _repeated_logs(
        count=8,
        app="ssl",
        port=443,
        app_risk=4,
        app_characteristic="used-by-malware",
    )
    context = build_detection_context(logs)

    codes = {match.code for match in evaluate_rules(logs[0], context)}

    assert "beaconing_like_outbound" not in codes


def test_unknown_uncommon_repetition_keeps_beaconing_signal():
    logs = _repeated_logs(
        count=8,
        app="unknown-tcp",
        port=4444,
        app_risk=5,
        app_characteristic="used-by-malware",
    )
    context = build_detection_context(logs)

    codes = {match.code for match in evaluate_rules(logs[0], context)}

    assert "beaconing_like_outbound" in codes


def test_normal_outbound_quic_burst_is_not_called_connection_flood():
    logs = _repeated_logs(
        count=25,
        app="quic-base",
        port=443,
        app_risk=2,
        app_characteristic="pervasive-use",
    )
    context = build_detection_context(logs)

    codes = {match.code for match in evaluate_rules(logs[0], context)}

    assert "connection_flood_suspicion" not in codes


def test_inbound_repeated_service_connections_keep_flood_signal():
    logs = _repeated_logs(
        count=20,
        app="ssl",
        port=443,
        app_risk=2,
        app_characteristic="pervasive-use",
        src_zone="SG-Outside",
        dst_zone="LAN-Inside",
    )
    context = build_detection_context(logs)

    codes = {match.code for match in evaluate_rules(logs[0], context)}

    assert "connection_flood_suspicion" in codes


def test_anomaly_evidence_does_not_mask_explicit_policy_rule():
    attack_type = infer_attack_type_from_rules(
        [
            {"code": "ml_anomaly_detected"},
            {"code": "deny_drop_action"},
            {"code": "unusual_destination_port"},
        ]
    )

    assert attack_type == "policy_violation"
