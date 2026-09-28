from datetime import datetime

from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from atdr.app.db.database import Base
from atdr.app.db.models import (
    Alert,
    LogSource,
    NormalizedLog,
    RawLog,
    ResponseAction,
)
from atdr.app.detection.rules import DetectionResult, RuleMatch
from atdr.app.services.alert_service import (
    alert_evidence_summaries,
    get_alert,
)
from atdr.app.services.case_service import count_alert_cases, list_alert_cases
from atdr.app.services import detection_service
from atdr.app.services.detection_service import DetectionCandidate, run_detection


def _session():
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, future=True)()


def _add_scan_log(db, index: int) -> None:
    raw = RawLog(raw_line=f"scan log {index}")
    db.add(raw)
    db.flush()
    db.add(
        NormalizedLog(
            raw_log_id=raw.id,
            generated_time=datetime(2026, 5, 20, 13, 36, 15),
            log_type="TRAFFIC",
            src_ip="203.0.113.10",
            dst_ip=f"10.0.0.{index}",
            src_zone="SG-Outside",
            dst_zone="LAN-Inside",
            app="unknown",
            app_category="unknown",
            dst_port=10000 + index,
            action="allow",
            protocol="tcp",
            bytes=100,
            packets=1,
            parsed_json={},
        )
    )


def test_run_detection_groups_related_logs_into_one_alert():
    db = _session()
    for index in range(30):
        _add_scan_log(db, index)
    db.commit()

    result = run_detection(db, limit=100, use_ml=False, actor="test")
    alerts = list(db.scalars(select(Alert)))

    assert result["candidate_logs"] == 30
    assert result["created_alerts"] == 1
    assert len(alerts) == 1
    assert alerts[0].alert_type == "possible_port_scan"
    assert len(alerts[0].evidence) == 30


def test_run_detection_groups_internet_sweep_by_destination_port():
    db = _session()
    for index in range(20):
        raw = RawLog(raw_line=f"incomplete inbound {index}")
        db.add(raw)
        db.flush()
        db.add(
            NormalizedLog(
                raw_log_id=raw.id,
                generated_time=datetime(2026, 5, 20, 13, 36, 15),
                log_type="TRAFFIC",
                src_ip=f"198.51.100.{index}",
                dst_ip="10.0.0.50",
                src_zone="SG-Outside",
                dst_zone="WLAN-Inside",
                app="incomplete",
                app_category="unknown",
                dst_port=4040,
                action="allow",
                protocol="tcp",
                bytes=60,
                packets=1,
                parsed_json={},
            )
        )
    db.commit()

    result = run_detection(db, limit=100, use_ml=False, actor="test")
    alerts = list(db.scalars(select(Alert)))

    assert result["candidate_logs"] == 20
    assert result["created_alerts"] == 1
    assert alerts[0].alert_type == "unusual_destination_port"
    assert alerts[0].src_ip is None
    assert len(alerts[0].evidence) == 20


def test_low_severity_singletons_are_suppressed():
    db = _session()
    for index in range(3):
        raw = RawLog(raw_line=f"app risk only {index}")
        db.add(raw)
        db.flush()
        db.add(
            NormalizedLog(
                raw_log_id=raw.id,
                generated_time=datetime(2026, 5, 20, 13, 36, 15),
                log_type="TRAFFIC",
                src_ip=f"172.25.1.{index}",
                dst_ip=f"203.0.113.{index}",
                src_zone="WLAN-Inside",
                dst_zone="SG-Outside",
                app="ssl",
                app_risk=4,
                app_characteristic="able-to-transfer-file",
                dst_port=443,
                action="allow",
                protocol="tcp",
                bytes=1000,
                packets=10,
                parsed_json={},
            )
        )
    db.commit()

    result = run_detection(db, limit=100, use_ml=False, actor="test")
    alerts = list(db.scalars(select(Alert)))

    # Application-risk signals alone are supporting-only: they never become
    # alert candidates, so no low-severity group is even formed.
    assert result["candidate_logs"] == 0
    assert result["supporting_only_logs"] == 3
    assert result["created_alerts"] == 0
    assert alerts == []


def test_context_signals_add_points_but_never_raise_an_alert_alone():
    """A busy source using a risky app is context, not an attack; a scan is.

    Busy source (20) + app risk 4 (15) + suspicious characteristic (15) used to
    reach 50 points and alert on normal heavy browsing. On MFU labels those
    alerts were right about a quarter of the time.
    """

    db = _session()

    def add(index: int, **fields) -> None:
        raw = RawLog(raw_line=f"context signals {index}")
        db.add(raw)
        db.flush()
        db.add(NormalizedLog(raw_log_id=raw.id, generated_time=datetime(2026, 5, 20, 13, 36, index % 60),
                             log_type="TRAFFIC", protocol="tcp", bytes=2000, packets=12, parsed_json={}, **fields))

    for index in range(30):  # a busy WLAN client browsing with a risky app
        add(index, src_ip="172.27.6.242", dst_ip=f"93.184.216.{index}", src_zone="WLAN-Inside",
            dst_zone="SG-Outside", app="hola-unblocker", app_risk=4, app_characteristic="able-to-transfer-file",
            dst_port=443, action="allow")
    for index in range(12):  # an outside scanner using the same risky app
        add(100 + index, src_ip="203.0.113.50", dst_ip="10.20.30.40", src_zone="SG-Outside",
            dst_zone="LAN-Inside", app="hola-unblocker", app_risk=4, dst_port=30000 + index, action="deny")
    for index in range(30):  # a busy outside source on one uncommon port
        add(200 + index, src_ip="198.51.100.9", dst_ip="10.20.30.41", src_zone="SG-Outside",
            dst_zone="LAN-Inside", app="ssl", app_risk=1, dst_port=4444, action="allow")
    db.commit()

    result = run_detection(db, limit=None, use_ml=False, actor="test")
    alerts = {alert.src_ip: alert for alert in db.scalars(select(Alert))}

    assert result["supporting_only_logs"] == 30
    assert set(alerts) == {"203.0.113.50", "198.51.100.9"}
    assert alerts["203.0.113.50"].alert_type == "possible_port_scan"
    assert "app_risk_4" in {item["code"] for item in alerts["203.0.113.50"].matched_rules_json}
    # A supporting rule can outrank the behavioural one in priority ("busy
    # source" 60 vs "unusual port" 55) but must never name the alert.
    assert alerts["198.51.100.9"].alert_type == "unusual_destination_port"
    assert "repeated_source_ip" in {item["code"] for item in alerts["198.51.100.9"].matched_rules_json}


def test_peer_to_peer_file_sharing_is_policy_activity_unless_there_is_malicious_evidence():
    """BitTorrent fans out to hundreds of peers and ports and carries app risk 5; that is policy, not an attack."""

    db = _session()

    def add(index: int, **fields) -> None:
        raw = RawLog(raw_line=f"p2p policy {index}")
        db.add(raw)
        db.flush()
        db.add(NormalizedLog(raw_log_id=raw.id, generated_time=datetime(2026, 5, 20, 13, 36, index % 60),
                             protocol="udp", bytes=2000, packets=12, parsed_json={}, action="allow", **fields))

    for index in range(40):  # a campus laptop seeding a torrent to many peers on many ports
        add(index, log_type="TRAFFIC", src_ip="172.27.6.10", dst_ip=f"93.184.{index}.7", src_zone="WLAN-Inside",
            dst_zone="SG-Outside", app="bittorrent", app_risk=5, app_technology="peer-to-peer",
            app_subcategory="file-sharing", dst_port=40000 + index)
    for index in range(3):  # another torrent client whose traffic the firewall flagged as spyware
        add(100 + index, log_type="THREAT", subtype="spyware", src_ip="172.27.6.11", dst_ip="93.184.99.9",
            src_zone="WLAN-Inside", dst_zone="SG-Outside", app="bittorrent", app_risk=5,
            app_technology="peer-to-peer", app_subcategory="file-sharing", dst_port=6881)
    db.commit()

    result = run_detection(db, limit=None, use_ml=False, actor="test")
    alerted_sources = {alert.src_ip for alert in db.scalars(select(Alert))}

    assert result["p2p_policy_logs"] == 40
    assert alerted_sources == {"172.27.6.11"}, "file sharing alerts only when the firewall saw a threat in it"


def test_anomaly_signal_is_advisory_and_cannot_create_alert(monkeypatch):
    db = _session()
    raw = RawLog(raw_line="normal backup flow")
    db.add(raw)
    db.flush()
    log = NormalizedLog(
        raw_log_id=raw.id,
        generated_time=datetime(2026, 5, 20, 13, 36, 15),
        log_type="TRAFFIC",
        src_ip="10.0.0.10",
        dst_ip="198.51.100.20",
        src_zone="LAN-Inside",
        dst_zone="SG-Outside",
        app="ssl",
        app_characteristic="able-to-transfer-file",
        dst_port=443,
        action="allow",
        protocol="tcp",
        bytes=2_000_000,
        packets=500,
        parsed_json={},
    )
    db.add(log)
    db.commit()

    def mark_anomaly(_db, *, limit=None):
        log.is_anomaly = True
        log.anomaly_score = -0.2
        return [{"log_id": log.id, "is_anomaly": True}]

    monkeypatch.setattr(detection_service, "apply_model_to_db", mark_anomaly)
    result = run_detection(db, limit=100, use_ml=True, actor="test")

    assert result["created_alerts"] == 0
    assert result["candidate_logs"] == 0
    assert result["advisory_anomaly_signals"] == 1
    assert result["rule_detection_authoritative"] is True
    assert list(db.scalars(select(Alert))) == []


def _add_deny_log(db, *, src_ip: str, parsed_json: dict) -> NormalizedLog:
    raw = RawLog(raw_line=f"deny log {src_ip}")
    db.add(raw)
    db.flush()
    log = NormalizedLog(
        raw_log_id=raw.id,
        generated_time=datetime(2026, 5, 20, 13, 36, 15),
        log_type="TRAFFIC",
        src_ip=src_ip,
        dst_ip="10.0.0.50",
        src_zone="SG-Outside",
        dst_zone="LAN-Inside",
        app="ssl",
        dst_port=443,
        action="deny",
        protocol="tcp",
        bytes=100,
        packets=2,
        parsed_json=parsed_json,
    )
    db.add(log)
    return log


def test_low_parse_quality_evidence_still_creates_an_alert_but_is_flagged():
    # Regression test: ML scoring already abstains on a log whose parse
    # didn't satisfy the governed schema contract (see
    # v520_schema_aware_abstention.assess_log_schema_compatibility), but
    # rule evaluation had no equivalent check at all -- a structurally-odd
    # log could drive a rule match with zero quality signal on the result.
    # Rules must stay authoritative (this must NOT suppress the alert --
    # that would be a new detection blind spot, worse than the gap it
    # fixes), but the alert must now carry a visible caveat.
    db = _session()
    _add_deny_log(db, src_ip="203.0.113.60", parsed_json={"parse_status": "error"})
    db.commit()

    result = run_detection(db, limit=100, use_ml=False, actor="test")
    alerts = list(db.scalars(select(Alert)))

    assert result["created_alerts"] == 1
    assert result["low_parse_quality_signals"] == 1
    assert len(alerts) == 1
    codes = [rule.get("code") for rule in alerts[0].matched_rules_json]
    assert "deny_drop_action" in codes
    assert "low_parse_quality" in codes
    low_pq = next(rule for rule in alerts[0].matched_rules_json if rule["code"] == "low_parse_quality")
    assert low_pq["score"] == 0
    assert "did not fully match the governed PAN-OS parsing contract" in low_pq["explanation"]


def test_well_formed_evidence_is_not_flagged_with_a_parse_quality_caveat():
    # Negative control for the test above: a log with every required field
    # populated and a clean parse status must not get the caveat.
    db = _session()
    _add_deny_log(
        db,
        src_ip="203.0.113.61",
        parsed_json={"parser_profile": "palo_alto", "parse_status": "parsed"},
    )
    db.commit()

    result = run_detection(db, limit=100, use_ml=False, actor="test")
    alerts = list(db.scalars(select(Alert)))

    assert result["created_alerts"] == 1
    assert result["low_parse_quality_signals"] == 0
    codes = [rule.get("code") for rule in alerts[0].matched_rules_json]
    assert "low_parse_quality" not in codes


def _grouped_detection_snapshot(db) -> dict:
    alerts = list(db.scalars(select(Alert).order_by(Alert.id)))
    return {
        "alerts": [
            {
                "title": alert.title,
                "alert_type": alert.alert_type,
                "src_ip": alert.src_ip,
                "dst_ip": alert.dst_ip,
                "threat_score": alert.threat_score,
                "severity": alert.severity,
                "explanation": alert.explanation,
                "matched_rules": alert.matched_rules_json,
                "recommended_response": alert.recommended_response,
                "evidence_ids": sorted(
                    evidence.normalized_log_id for evidence in alert.evidence
                ),
            }
            for alert in alerts
        ],
        "case_count": count_alert_cases(db),
        "response_actions": len(list(db.scalars(select(ResponseAction.id)))),
    }


def test_bounded_rule_detection_matches_legacy_and_releases_session_state():
    legacy_db = _session()
    bounded_db = _session()
    for index in range(30):
        _add_scan_log(legacy_db, index)
        _add_scan_log(bounded_db, index)
    legacy_db.commit()
    bounded_db.commit()

    legacy_profile: dict = {}
    bounded_profile: dict = {}
    legacy_result = run_detection(
        legacy_db,
        limit=100,
        use_ml=False,
        actor="test",
        runtime_profile=legacy_profile,
    )
    bounded_result = run_detection(
        bounded_db,
        limit=100,
        use_ml=False,
        actor="test",
        bounded_memory=True,
        release_session_state=True,
        runtime_profile=bounded_profile,
    )

    comparable_fields = {
        "evaluated",
        "candidate_logs",
        "created_alerts",
        "deduplicated_alert_updates",
        "suppressed_low_groups",
        "suppressed_by_rules",
        "watchlist_matches",
        "advisory_anomaly_signals",
        "advisory_only_logs",
        "rule_detection_authoritative",
        "top_attack_types",
    }
    assert {
        key: legacy_result[key] for key in comparable_fields
    } == {
        key: bounded_result[key] for key in comparable_fields
    }
    assert len(bounded_db.identity_map) == 0
    assert _grouped_detection_snapshot(legacy_db) == _grouped_detection_snapshot(
        bounded_db
    )
    assert count_alert_cases(bounded_db) == len(
        list_alert_cases(bounded_db, limit=100)
    )
    assert bounded_profile["peak_identity_map_size"] < legacy_profile[
        "peak_identity_map_size"
    ]


def test_alert_and_case_summaries_use_bounded_group_metadata():
    db = _session()
    source = LogSource(
        name="bounded-summary-source",
        source_type="firewall",
        parser_profile="palo_alto",
    )
    db.add(source)
    db.flush()
    for index in range(150):
        raw = RawLog(
            raw_line=f"bounded scan {index}",
            source_id=source.id,
        )
        db.add(raw)
        db.flush()
        db.add(
            NormalizedLog(
                raw_log_id=raw.id,
                generated_time=datetime(2026, 5, 20, 13, 36, 15),
                log_type="TRAFFIC",
                src_ip="203.0.113.20",
                dst_ip=f"10.0.0.{index % 250}",
                src_zone="SG-Outside",
                dst_zone="LAN-Inside",
                app="unknown",
                app_category="unknown",
                dst_port=10_000 + index,
                action="allow",
                protocol="tcp",
                bytes=100,
                packets=1,
                parsed_json={},
            )
        )
    db.commit()

    result = run_detection(
        db,
        limit=200,
        use_ml=False,
        actor="test",
        bounded_memory=True,
    )
    alert_id = int(db.scalar(select(Alert.id)))
    alert = get_alert(db, alert_id, load_evidence=False)
    assert alert is not None

    summary = alert_evidence_summaries(
        db,
        [alert_id],
        alerts=[alert],
        evidence_id_limit=10,
    )[alert_id]
    cases = list_alert_cases(db, limit=20)

    assert result["created_alerts"] == 1
    assert summary["evidence_count"] == 150
    assert len(summary["evidence_log_ids"]) == 10
    assert summary["evidence_log_ids_truncated"] is True
    assert summary["source_ids"] == [source.id]
    assert summary["source_names"] == [source.name]
    assert cases[0]["total_related_logs"] == 150


def _candidate(*, src_zone: str, dst_zone: str, primary_code: str) -> DetectionCandidate:
    log = NormalizedLog(
        src_ip="203.0.113.99",
        dst_ip="198.51.100.5",
        src_zone=src_zone,
        dst_zone=dst_zone,
        app="ssl",
        dst_port=443,
        action="allow",
        protocol="tcp",
    )
    rule = RuleMatch(code=primary_code, title=primary_code, score=10, explanation="test")
    result = DetectionResult(threat_score=10, severity="Low", explanation="test", matched_rules=[rule])
    return DetectionCandidate(log=log, result=result, primary_rule=rule)


def test_group_key_does_not_merge_same_zone_untrust_traffic_as_internet_sweep():
    # Regression test: Palo Alto's own default zone names are "trust"
    # (inside) and "untrust" (outside). A prior substring-matching bug
    # ("trust" in "untrust") made _group_key treat untrust->untrust traffic
    # (which never crosses a trust boundary) as "outside_to_inside", merging
    # unrelated sources into a single "multiple-internet-sources" group.
    candidate = _candidate(src_zone="untrust", dst_zone="untrust", primary_code="unknown_or_incomplete_app")

    key = detection_service._group_key(candidate)

    source_group = key[2]
    assert source_group == "203.0.113.99"
    assert source_group != "multiple-internet-sources"


def test_group_key_still_merges_genuine_outside_to_inside_internet_sweep():
    # The fix must not regress genuine trust/untrust traffic using Palo
    # Alto's actual default zone names.
    candidate = _candidate(src_zone="untrust", dst_zone="trust", primary_code="unknown_or_incomplete_app")

    key = detection_service._group_key(candidate)

    assert key[2] == "multiple-internet-sources"


def test_group_key_does_not_falsely_merge_app_risk_sources_for_untrust_traffic():
    # Before the fix, untrust->untrust traffic was misread as
    # outside-to-inside, so `not is_outside_to_inside(log)` was False and the
    # app-risk-policy merge never triggered even though this traffic never
    # left the untrust zone in the first place. Genuinely outbound
    # (trust->untrust) app-risk traffic must still merge correctly.
    outbound = _candidate(src_zone="trust", dst_zone="untrust", primary_code="app_risk_5")
    same_zone = _candidate(src_zone="untrust", dst_zone="untrust", primary_code="app_risk_5")

    assert detection_service._group_key(outbound)[2] == "multiple-app-risk-sources"
    assert detection_service._group_key(same_zone)[2] == "multiple-app-risk-sources"


def _seed_malware_threat_with_country_watch(db) -> None:
    from atdr.app.db.models import WatchlistItem

    raw = RawLog(raw_line="threat spyware log")
    db.add(raw)
    db.flush()
    db.add(
        NormalizedLog(
            raw_log_id=raw.id,
            generated_time=datetime(2026, 5, 20, 10, 0, 0),
            log_type="THREAT",
            subtype="spyware",
            category="spyware",
            src_ip="10.0.2.15",
            dst_ip="198.51.100.30",
            src_zone="LAN-Inside",
            dst_zone="SG-Outside",
            dst_country="Germany",
            app="web-browsing",
            dst_port=80,
            action="alert",
            protocol="tcp",
            bytes=500,
            packets=4,
            parsed_json={"parsed_threat_severity": "medium", "parsed_threat_name": "Test Spyware"},
        )
    )
    db.add(
        WatchlistItem(
            indicator_type="dst_country",
            indicator_value="germany",
            description="Country watch test",
            severity_boost=20,
            created_by="test",
        )
    )
    db.commit()


def test_malware_threat_and_country_watch_work_in_both_detection_modes():
    # The bounded (large-import) path evaluates a lightweight record, not the
    # ORM row; it lacked the threat category and country fields, so the new
    # malware rule would have raised AttributeError and a country watch could
    # never match there.
    results = {}
    for mode, bounded in (("full", False), ("bounded", True)):
        db = _session()
        _seed_malware_threat_with_country_watch(db)
        result = run_detection(db, limit=100, use_ml=False, actor="test", bounded_memory=bounded)
        alert = db.scalar(select(Alert))
        results[mode] = (result["watchlist_matches"], alert.alert_type if alert else None)
        db.close()

    assert results["full"] == (1, "paloalto_malware_threat")
    assert results["bounded"] == results["full"]


def _inbound_probe(db, *, src, dst, port, log_type="TRAFFIC"):
    raw = RawLog(raw_line=f"probe {src} {dst} {port} {log_type}")
    db.add(raw)
    db.flush()
    db.add(NormalizedLog(
        raw_log_id=raw.id, generated_time=datetime(2026, 5, 20, 13, 36, 15), log_type=log_type, src_ip=src, dst_ip=dst,
        src_zone="SG-Outside", dst_zone="WLAN-Inside", app="incomplete", app_category="unknown", dst_port=port,
        action="allow", protocol="tcp", bytes=60, bytes_received=0, packets=1, parsed_json={},
    ))


def test_internet_background_probing_is_summarised_not_alerted():
    # 20 internet hosts, one unanswered probe each: what every public network receives all day.
    db = _session()
    for index in range(20):
        _inbound_probe(db, src=f"45.33.32.{index + 1}", dst="10.0.0.50", port=4040)
    db.commit()
    result = run_detection(db, limit=100, use_ml=False, actor="test")
    assert result["created_alerts"] == 0
    assert result["background_probe_logs"] == 20


def test_a_source_beyond_background_limits_or_with_a_threat_log_still_alerts():
    db = _session()
    for host in range(12):  # 12 MFU hosts: a horizontal scan, not background
        _inbound_probe(db, src="45.33.32.200", dst=f"10.0.0.{host + 1}", port=4040)
    _inbound_probe(db, src="45.33.32.201", dst="10.0.0.99", port=4040, log_type="THREAT")  # small, but the firewall saw a threat
    db.commit()
    run_detection(db, limit=100, use_ml=False, actor="test")
    alerted = {alert.src_ip for alert in db.scalars(select(Alert))}
    assert "45.33.32.200" in alerted, "10 or more hosts is a scan"
    assert "45.33.32.201" in alerted, "a firewall threat log escalates a small probe"


def test_repeated_denied_attempts_from_a_small_internet_source_still_alert():
    db = _session()
    for attempt in range(6):  # one host, one port, six denials: repeated attempts, not background noise
        raw = RawLog(raw_line=f"denied {attempt}")
        db.add(raw)
        db.flush()
        db.add(NormalizedLog(
            raw_log_id=raw.id, generated_time=datetime(2026, 5, 20, 13, 36, 15 + attempt), log_type="TRAFFIC",
            src_ip="45.33.32.210", dst_ip="10.0.0.60", src_zone="SG-Outside", dst_zone="WLAN-Inside", app="incomplete",
            app_category="unknown", dst_port=8443, action="deny", protocol="tcp", bytes=60, bytes_received=0, packets=1,
            parsed_json={},
        ))
    db.commit()
    result = run_detection(db, limit=100, use_ml=False, actor="test")
    assert {alert.src_ip for alert in db.scalars(select(Alert))} == {"45.33.32.210"}
    assert result["background_probe_logs"] == 0
