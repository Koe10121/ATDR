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
            generated_time=datetime(2026, 5, 20, 13, 36) + timedelta(seconds=idx),
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
    interval_seconds: int = 1,
    repeat_count: int = 1,
) -> list[NormalizedLog]:
    started = datetime(2026, 5, 20, 13, 36)
    return [
        NormalizedLog(
            id=index + 1,
            generated_time=started + timedelta(seconds=index * interval_seconds),
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
            repeat_count=repeat_count,
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
        interval_seconds=30,
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


def test_allowed_inbound_service_connections_below_volume_threshold_are_not_flood():
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

    assert "connection_flood_suspicion" not in codes


def test_inbound_repeated_service_connections_keep_flood_signal_with_explicit_volume():
    logs = _repeated_logs(
        count=20,
        app="ssl",
        port=443,
        app_risk=2,
        app_characteristic="pervasive-use",
        src_zone="SG-Outside",
        dst_zone="LAN-Inside",
        repeat_count=5,
    )
    context = build_detection_context(logs)

    codes = {match.code for match in evaluate_rules(logs[0], context)}

    assert "connection_flood_suspicion" in codes


def test_irregular_unknown_polling_is_not_called_beaconing():
    started = datetime(2026, 5, 20, 13, 36)
    offsets = [0, 7, 19, 54, 61, 140, 151, 250]
    logs = [
        NormalizedLog(
            id=index + 1,
            generated_time=started + timedelta(seconds=offset),
            log_type="TRAFFIC",
            src_ip="10.0.0.10",
            dst_ip="198.51.100.20",
            src_zone="LAN-Inside",
            dst_zone="SG-Outside",
            app="unknown-tcp",
            app_category="unknown",
            app_characteristic="used-by-malware",
            dst_port=4444,
            action="allow",
            protocol="tcp",
            app_risk=5,
            bytes=500,
            packets=5,
        )
        for index, offset in enumerate(offsets)
    ]
    context = build_detection_context(logs)

    codes = {match.code for match in evaluate_rules(logs[0], context)}

    assert "beaconing_like_outbound" not in codes


def test_auth_denies_across_different_targets_are_not_called_brute_force():
    started = datetime(2026, 5, 20, 13, 36)
    logs = [
        NormalizedLog(
            id=index + 1,
            generated_time=started + timedelta(seconds=index * 10),
            log_type="TRAFFIC",
            src_ip="203.0.113.25",
            dst_ip=f"10.0.0.{index + 1}",
            src_zone="SG-Outside",
            dst_zone="LAN-Inside",
            app="ssh",
            dst_port=22,
            action="deny",
            protocol="tcp",
            bytes=80,
            packets=1,
        )
        for index in range(6)
    ]
    context = build_detection_context(logs)

    codes = {match.code for match in evaluate_rules(logs[0], context)}

    assert "brute_force_like_attempts" not in codes


def test_same_service_multi_destination_denies_are_horizontal_scan_like():
    started = datetime(2026, 5, 20, 13, 36)
    logs = [
        NormalizedLog(
            id=index + 1,
            generated_time=started + timedelta(seconds=index * 10),
            log_type="TRAFFIC",
            src_ip="203.0.113.30",
            dst_ip=f"10.0.1.{index + 1}",
            src_zone="SG-Outside",
            dst_zone="LAN-Inside",
            app="unknown-tcp",
            dst_port=445,
            action="deny",
            protocol="tcp",
            bytes=80,
            packets=1,
        )
        for index in range(10)
    ]
    context = build_detection_context(logs)

    codes = {match.code for match in evaluate_rules(logs[0], context)}

    assert "possible_horizontal_scan" in codes
    assert "possible_port_scan" not in codes


def test_normal_web_fanout_is_not_called_horizontal_scan():
    started = datetime(2026, 5, 20, 13, 36)
    logs = [
        NormalizedLog(
            id=index + 1,
            generated_time=started + timedelta(seconds=index * 10),
            log_type="TRAFFIC",
            src_ip="10.0.0.40",
            dst_ip=f"198.51.100.{index + 1}",
            src_zone="LAN-Inside",
            dst_zone="SG-Outside",
            app="ssl",
            dst_port=443,
            action="allow",
            protocol="tcp",
            bytes=1500,
            packets=12,
        )
        for index in range(12)
    ]
    context = build_detection_context(logs)

    codes = {match.code for match in evaluate_rules(logs[0], context)}

    assert "possible_horizontal_scan" not in codes


def test_internal_lateral_movement_over_allowed_rdp_is_flagged():
    # Regression test: internal-to-internal lateral movement (the textbook
    # post-compromise pattern) was structurally unreachable by this rule --
    # every corroboration signal (deny/drop evidence, external-to-internal
    # direction, unresolved app identity) assumes the traffic looks
    # abnormal in some way none of which can ever be true for a
    # compromised host sweeping other internal hosts over an *allowed*,
    # *identified* admin protocol like RDP. Fan-out on a known
    # lateral-movement-prone port is now corroboration on its own.
    started = datetime(2026, 5, 20, 13, 36)
    logs = [
        NormalizedLog(
            id=index + 1,
            generated_time=started + timedelta(seconds=index * 10),
            log_type="TRAFFIC",
            src_ip="10.0.1.50",
            dst_ip=f"10.0.2.{index + 1}",
            src_zone="LAN-Inside",
            dst_zone="LAN-Inside",
            app="ms-rdp",
            dst_port=3389,
            action="allow",
            protocol="tcp",
            bytes=5000,
            packets=20,
        )
        for index in range(12)
    ]
    context = build_detection_context(logs)

    codes = {match.code for match in evaluate_rules(logs[0], context)}

    assert "possible_horizontal_scan" in codes


def test_internal_fanout_on_a_non_admin_port_is_still_not_flagged():
    # Negative control for the test above: internal-to-internal fan-out on
    # an ordinary internal service port (not one of the specific
    # lateral-movement-prone admin ports) must not be newly flagged --
    # otherwise this fix would trade the coverage gap for a broad new
    # false-positive source on routine internal microservice traffic.
    started = datetime(2026, 5, 20, 13, 36)
    logs = [
        NormalizedLog(
            id=index + 1,
            generated_time=started + timedelta(seconds=index * 10),
            log_type="TRAFFIC",
            src_ip="10.0.1.60",
            dst_ip=f"10.0.2.{index + 1}",
            src_zone="LAN-Inside",
            dst_zone="LAN-Inside",
            app="web-browsing",
            dst_port=8080,
            action="allow",
            protocol="tcp",
            bytes=5000,
            packets=20,
        )
        for index in range(12)
    ]
    context = build_detection_context(logs)

    codes = {match.code for match in evaluate_rules(logs[0], context)}

    assert "possible_horizontal_scan" not in codes


def test_anomaly_evidence_does_not_mask_explicit_policy_rule():
    attack_type = infer_attack_type_from_rules(
        [
            {"code": "ml_anomaly_detected"},
            {"code": "deny_drop_action"},
            {"code": "unusual_destination_port"},
        ]
    )

    assert attack_type == "policy_violation"


def test_default_paloalto_untrust_zone_is_not_misread_as_an_inside_zone():
    # Palo Alto's own default zone names are "trust" (inside) and "untrust"
    # (outside). A naive substring check ("trust" in zone) misreads "untrust"
    # as an inside zone, because "untrust" contains "trust" as a substring.
    # Traffic that never leaves the untrust zone must not be treated as
    # crossing a trust boundary in either direction.
    log = NormalizedLog(
        src_ip="203.0.113.10",
        dst_ip="203.0.113.20",
        src_zone="untrust",
        dst_zone="untrust",
        app="ssl",
        app_category="general-internet",
        dst_port=443,
        action="allow",
        protocol="tcp",
        app_risk=1,
        bytes=500,
        packets=5,
    )
    context = build_detection_context([log])
    codes = {match.code for match in evaluate_rules(log, context)}

    assert "outside_to_inside" not in codes
    assert "unusual_destination_port" not in codes


def test_default_paloalto_trust_untrust_zones_still_detect_real_direction():
    # The fix must not regress genuine trust/untrust traffic in either
    # direction using Palo Alto's actual default zone names.
    outbound = NormalizedLog(
        src_ip="10.0.0.5",
        dst_ip="203.0.113.20",
        src_zone="trust",
        dst_zone="untrust",
        app="ssl",
        app_category="general-internet",
        dst_port=4444,
        action="allow",
        protocol="tcp",
        app_risk=1,
        bytes=500,
        packets=5,
    )
    inbound = NormalizedLog(
        src_ip="203.0.113.20",
        dst_ip="10.0.0.5",
        src_zone="untrust",
        dst_zone="trust",
        app="ssl",
        app_category="general-internet",
        dst_port=4444,
        action="allow",
        protocol="tcp",
        app_risk=1,
        bytes=500,
        packets=5,
    )
    context = build_detection_context([outbound, inbound])

    outbound_codes = {match.code for match in evaluate_rules(outbound, context)}
    inbound_codes = {match.code for match in evaluate_rules(inbound, context)}

    assert "unusual_destination_port" not in outbound_codes  # direction, not zone, gates this rule
    assert "outside_to_inside" in inbound_codes
    assert "unusual_destination_port" in inbound_codes


def test_scan_with_only_external_direction_signal_is_flagged_low_confidence():
    # Regression test: possible_port_scan/possible_horizontal_scan scored
    # identically (score=25) whether a source had one bare, non-specific
    # corroborating signal or several strong ones -- indistinguishable from
    # routine internet background-radiation scanning (any rotating scanner
    # IP crossing the threshold gets treated the same as a genuinely
    # targeted, sustained scan). Rather than merging different source IPs
    # into one alert (which would destroy per-attacker visibility for a
    # real attack) or changing the score (risking already-calibrated
    # severity behavior), a weak single-signal match must now say so in
    # its own explanation text.
    started = datetime(2026, 5, 20, 13, 36)
    weak_logs = [
        NormalizedLog(
            id=index + 1,
            generated_time=started + timedelta(seconds=index * 10),
            log_type="TRAFFIC",
            src_ip="198.51.100.99",
            dst_ip="10.0.0.5",
            src_zone="SG-Outside",
            dst_zone="LAN-Inside",
            app="web-browsing",
            dst_port=8000 + index,
            action="allow",
            protocol="tcp",
            bytes=80,
            packets=1,
        )
        for index in range(11)
    ]
    context = build_detection_context(weak_logs)
    match = next(m for m in evaluate_rules(weak_logs[0], context) if m.code == "possible_port_scan")

    assert "low-confidence" in match.explanation
    assert "routine internet background-radiation scanning" in match.explanation


def test_scan_with_multiple_signals_is_not_flagged_low_confidence():
    # Negative control: a source with several corroborating signals (not
    # just the one generic "external-to-internal direction" signal) is
    # genuinely stronger evidence and must not carry the low-confidence
    # caveat.
    started = datetime(2026, 5, 20, 13, 36)
    strong_logs = [
        NormalizedLog(
            id=index + 1,
            generated_time=started + timedelta(seconds=index * 10),
            log_type="TRAFFIC",
            src_ip="198.51.100.88",
            dst_ip="10.0.0.6",
            src_zone="SG-Outside",
            dst_zone="LAN-Inside",
            app="unknown",
            dst_port=9000 + index,
            action="deny",
            protocol="tcp",
            bytes=80,
            packets=1,
        )
        for index in range(11)
    ]
    context = build_detection_context(strong_logs)
    match = next(m for m in evaluate_rules(strong_logs[0], context) if m.code == "possible_port_scan")

    assert "low-confidence" not in match.explanation


def _byte_batch(big: NormalizedLog, background_size: int = 30) -> list[NormalizedLog]:
    # Outlier thresholds come from the batch (max(10MB, mean + 3 stdev)), so a
    # single large transfer needs a backdrop of ordinary sessions.
    background = [
        NormalizedLog(
            generated_time=datetime(2026, 5, 20, 9, 0) + timedelta(seconds=idx),
            src_ip=f"10.0.1.{idx}",
            dst_ip="93.184.216.34",
            src_zone="LAN-Inside",
            dst_zone="SG-Outside",
            app="ssl",
            app_category="networking",
            dst_port=443,
            action="allow",
            bytes=1_000,
            bytes_sent=500,
            packets=10,
        )
        for idx in range(background_size)
    ]
    return [*background, big]


def _big_transfer(**overrides) -> NormalizedLog:
    values = dict(
        generated_time=datetime(2026, 5, 20, 9, 5),
        src_ip="10.0.1.200",
        dst_ip="198.51.100.9",
        src_zone="LAN-Inside",
        dst_zone="SG-Outside",
        app="ssl",
        app_category="networking",
        dst_port=443,
        action="allow",
        bytes=50_000_000,
        packets=10,
    )
    values.update(overrides)
    return NormalizedLog(**values)


def test_one_large_outbound_transfer_is_not_scored_twice():
    big = _big_transfer()
    matches = evaluate_rules(big, build_detection_context(_byte_batch(big)))
    codes = {match.code for match in matches}

    assert "high_outbound_bytes" in codes
    assert "high_bytes_outlier" not in codes
    assert "repeated_large_outbound" not in codes
    assert sum(match.score for match in matches if match.code.startswith("high_") and "bytes" in match.code) == 35


def test_large_inbound_transfer_still_flags_the_generic_byte_outlier():
    big = _big_transfer(src_ip="198.51.100.9", dst_ip="10.0.1.200", src_zone="SG-Outside", dst_zone="LAN-Inside")
    codes = {match.code for match in evaluate_rules(big, build_detection_context(_byte_batch(big)))}

    assert "high_bytes_outlier" in codes
    assert "high_outbound_bytes" not in codes


def test_large_download_on_an_outbound_session_is_a_byte_outlier_not_exfiltration():
    big = _big_transfer(bytes_sent=2_000, bytes_received=49_998_000)
    codes = {match.code for match in evaluate_rules(big, build_detection_context(_byte_batch(big)))}

    assert "high_bytes_outlier" in codes
    assert "high_outbound_bytes" not in codes


def test_repeated_large_uploads_to_one_destination_add_corroboration():
    # 200 ordinary sessions so four large uploads don't lift the batch's own
    # outlier threshold above themselves.
    burst = [
        _big_transfer(generated_time=datetime(2026, 5, 20, 9, 5) + timedelta(seconds=30 * idx), bytes=45_000_000 + idx)
        for idx in range(4)
    ]
    context = build_detection_context([*_byte_batch(burst[0], background_size=200)[:-1], *burst])
    for log in burst:
        codes = {match.code for match in evaluate_rules(log, context)}
        assert {"high_outbound_bytes", "repeated_large_outbound"} <= codes


def test_large_uploads_to_different_destinations_are_not_a_repeat():
    spread = [
        _big_transfer(
            generated_time=datetime(2026, 5, 20, 9, 5) + timedelta(seconds=30 * idx),
            dst_ip=f"198.51.100.{20 + idx}",
        )
        for idx in range(4)
    ]
    context = build_detection_context([*_byte_batch(spread[0], background_size=200)[:-1], *spread])
    for log in spread:
        codes = {match.code for match in evaluate_rules(log, context)}
        assert "high_outbound_bytes" in codes
        assert "repeated_large_outbound" not in codes
