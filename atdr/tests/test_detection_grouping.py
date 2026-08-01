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
from atdr.app.services.alert_service import (
    alert_evidence_summaries,
    get_alert,
)
from atdr.app.services.case_service import count_alert_cases, list_alert_cases
from atdr.app.services import detection_service
from atdr.app.services.detection_service import run_detection


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

    assert result["candidate_logs"] == 3
    assert result["created_alerts"] == 0
    assert result["suppressed_low_groups"] == 1
    assert alerts == []


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
