from atdr.app.db.models import NormalizedLog
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
