"""Scanning from the internet goes on one alert an hour; a scanner that does more keeps its own alert."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from atdr.app.core.config import get_settings
from atdr.app.db.database import Base
from atdr.app.db.models import Alert, AlertEvidence, LogSource, NormalizedLog, RawLog
from atdr.app.detection.attack_mapping import infer_attack_type_from_rules
from atdr.app.services.alert_service import SCAN_SAMPLE_LOGS_PER_ADDRESS, update_alert_status
from atdr.app.services.detection_service import run_detection
from atdr.app.services.retention_service import run_live_retention

AT = datetime(2026, 5, 20, 13, 36, 15)
SCANNER, SECOND_SCANNER, THIRD_SCANNER = "45.33.32.200", "45.33.32.201", "45.33.32.202"


def _session():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool, future=True)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)()


def _connection(db, *, src: str, dst: str, port: int, at: datetime = AT, inside: bool = False, log_type: str = "TRAFFIC",
                source_id: int | None = None, imported_at: datetime | None = None) -> None:
    raw = RawLog(raw_line=f"scan {src} {dst} {port} {at.isoformat()} {log_type}", source_id=source_id)
    if imported_at is not None:
        raw.imported_at = imported_at
    db.add(raw)
    db.flush()
    db.add(NormalizedLog(
        raw_log_id=raw.id, generated_time=at, log_type=log_type, src_ip=src, dst_ip=dst,
        src_zone="LAN-Inside" if inside else "SG-Outside", dst_zone="WLAN-Inside", app="incomplete", app_category="unknown",
        dst_port=port, action="allow", protocol="tcp", bytes=60, bytes_received=0, packets=1, parsed_json={},
    ))


def _sweep(db, src: str, *, hosts: int = 12, port: int = 4040, at: datetime = AT, **fields) -> None:
    """One source trying one port on `hosts` MFU addresses: ten or more is a horizontal scan."""
    for host in range(hosts):
        _connection(db, src=src, dst=f"10.0.{host // 250}.{host % 250 + 1}", port=port, at=at + timedelta(seconds=host % 50), **fields)
    db.commit()


def _check(db) -> dict:
    return run_detection(db, limit=None, use_ml=False, actor="test", only_unchecked=True)


def _alerts(db, alert_type: str | None = None) -> list[Alert]:
    statement = select(Alert).order_by(Alert.id)
    return list(db.scalars(statement.where(Alert.alert_type == alert_type) if alert_type else statement))


def _metadata(alert: Alert) -> dict:
    return next(rule for rule in alert.matched_rules_json if rule.get("code") == "group_metadata")


def _evidence(db, alert: Alert) -> int:
    return int(db.scalar(select(func.count(AlertEvidence.id)).where(AlertEvidence.alert_id == alert.id)) or 0)


def test_scanners_from_the_internet_share_one_alert_for_the_hour():
    # Each scanner used to get its own alert: 4 alerts in 10 at MFU's firewall rate.
    db = _session()
    _sweep(db, SCANNER)
    _sweep(db, SECOND_SCANNER, hosts=15, port=22)

    first = _check(db)

    (alert,) = _alerts(db)
    metadata = _metadata(alert)
    assert first["created_alerts"] == 1 and first["internet_scanning_groups"] == 2
    assert (alert.alert_type, alert.severity, alert.src_ip, alert.status) == ("internet_scanning", "Medium", None, "open")
    assert alert.title == "Medium: Internet scanning from 2 outside addresses (20 May 13:00 to 14:00)"
    assert {address: (entry["connections"], entry["targets"], entry["ports"]) for address, entry in metadata["scanners"].items()} == {
        SCANNER: (12, 12, [4040]),
        SECOND_SCANNER: (15, 15, [22]),
    }
    assert "2 outside addresses scanned or probed MFU from 20 May 13:00 to 14:00: 27 connections in all." in alert.explanation
    assert f"The busiest: {SECOND_SCANNER} (15 connections to 15 or more MFU addresses, ports 22); {SCANNER} (12 connections" in alert.explanation
    assert "kept as evidence" not in alert.explanation, "imported logs are all evidence"
    assert _evidence(db, alert) == 27
    assert infer_attack_type_from_rules(alert.matched_rules_json) == "port_scan"

    # A scanner seen later in the hour joins the same alert.
    _sweep(db, THIRD_SCANNER, at=AT + timedelta(minutes=12))
    later = _check(db)

    (alert,) = _alerts(db)
    assert (later["created_alerts"], later["deduplicated_alert_updates"]) == (0, 1)
    assert alert.title.startswith("Medium: Internet scanning from 3 outside addresses")
    assert _metadata(alert)["connections"] == 39 and _evidence(db, alert) == 39


def test_each_hour_has_its_own_alert_and_a_closed_hour_is_not_reopened():
    db = _session()
    _sweep(db, SCANNER, at=datetime(2026, 5, 20, 13, 50))
    _sweep(db, SCANNER, at=datetime(2026, 5, 20, 14, 10))
    _check(db)

    first, second = _alerts(db, "internet_scanning")
    assert (_metadata(first)["hour_start"], _metadata(second)["hour_start"]) == ("2026-05-20T13:00:00", "2026-05-20T14:00:00")

    update_alert_status(db, second.id, "resolved", actor="analyst")
    _sweep(db, SECOND_SCANNER, at=datetime(2026, 5, 20, 14, 30))
    assert _check(db)["created_alerts"] == 1
    assert [alert.status for alert in _alerts(db, "internet_scanning")] == ["open", "resolved", "open"]


def test_a_closed_alert_is_never_taken_as_the_hours_open_alert():
    from atdr.app.services.alert_service import _open_scanning_alert

    db = _session()
    _sweep(db, SCANNER)
    _check(db)
    (alert,) = _alerts(db)
    hour = _metadata(alert)["hour_start"]
    assert _open_scanning_alert(db, hour, [alert]) is alert
    assert _open_scanning_alert(db, hour, None) is alert
    assert _open_scanning_alert(db, "2026-05-20T14:00:00", [alert]) is None

    alert.status = "resolved"
    db.commit()
    assert _open_scanning_alert(db, hour, [alert]) is None
    assert _open_scanning_alert(db, hour, None) is None


def test_a_scan_from_inside_mfu_and_a_scanner_that_does_more_keep_their_own_alerts():
    db = _session()
    _sweep(db, "10.1.5.5", inside=True)
    # This scanner's traffic also raised a firewall threat record: that is more than scanning.
    _sweep(db, SCANNER)
    _connection(db, src=SCANNER, dst="10.0.0.99", port=4040, log_type="THREAT")
    _sweep(db, SECOND_SCANNER)
    db.commit()

    _check(db)

    by_source = {alert.src_ip: alert.alert_type for alert in _alerts(db) if alert.src_ip}
    assert by_source["10.1.5.5"] == "possible_horizontal_scan", "a device inside MFU that scans is not background"
    assert "possible_horizontal_scan" in {alert.alert_type for alert in _alerts(db) if alert.src_ip == SCANNER}
    (summary,) = _alerts(db, "internet_scanning")
    assert list(_metadata(summary)["scanners"]) == [SECOND_SCANNER]

    # Once a scanner has another kind of alert open, its later scans stay with it too.
    _sweep(db, SCANNER, port=8080, at=AT + timedelta(minutes=15))
    _check(db)
    assert list(_metadata(_alerts(db, "internet_scanning")[0])["scanners"]) == [SECOND_SCANNER]


def test_live_feed_scans_keep_a_sample_of_evidence_and_the_rest_goes_with_the_other_live_logs():
    # Scanning was 6 evidence logs in 10, and evidence is never deleted: about 13 GB a day at MFU's firewall rate.
    db = _session()
    live = LogSource(name="syslog_udp:198.51.100.1", source_type="syslog_udp", parser_profile="palo_alto", enabled=True)
    db.add(live)
    db.flush()
    received = datetime.now(timezone.utc) - timedelta(hours=9)
    _sweep(db, SCANNER, hosts=50, source_id=live.id, imported_at=received)
    _sweep(db, SECOND_SCANNER, hosts=12, source_id=live.id, imported_at=received)

    _check(db)

    (alert,) = _alerts(db)
    scanners = _metadata(alert)["scanners"]
    assert (scanners[SCANNER]["connections"], scanners[SCANNER]["kept"]) == (50, SCAN_SAMPLE_LOGS_PER_ADDRESS)
    assert (scanners[SECOND_SCANNER]["connections"], scanners[SECOND_SCANNER]["kept"]) == (12, 12)
    assert _evidence(db, alert) == SCAN_SAMPLE_LOGS_PER_ADDRESS + 12
    assert f"32 of the 62 logs are kept as evidence, up to {SCAN_SAMPLE_LOGS_PER_ADDRESS} for each address." in alert.explanation

    settings = get_settings().model_copy(update={"syslog_retention_hours": 6.0})
    deleted = run_live_retention(db, settings=settings)["logs_deleted"]

    assert deleted == 30, "the logs beyond the sample are ordinary live logs"
    assert db.scalar(select(func.count(NormalizedLog.id))) == 32
    assert _evidence(db, alert) == 32


def test_the_scanning_alert_is_put_in_plain_words_from_its_totals_not_its_sample():
    # The drawer's plain summary counts evidence logs, and of live traffic only a sample is evidence.
    from atdr.app.detection.plain_summary import build_plain_summary

    db = _session()
    live = LogSource(name="syslog_udp:198.51.100.1", source_type="syslog_udp", parser_profile="palo_alto", enabled=True)
    db.add(live)
    db.flush()
    _sweep(db, SCANNER, hosts=50, source_id=live.id)
    _sweep(db, SECOND_SCANNER, hosts=12, source_id=live.id)
    _check(db)

    (alert,) = _alerts(db)
    summary = build_plain_summary(db, alert, "port_scan")

    assert _evidence(db, alert) == 32
    assert summary.startswith("On 20 May, 13:00–14:00, 2 outside addresses scanned or probed MFU: 62 connections in all.")
    assert "one alert an hour" in summary and summary.endswith("works on one service.")


def _open_alert(db, alert_type: str, src_ip: str) -> None:
    db.add(Alert(title=f"an open {alert_type} alert", alert_type=alert_type, src_ip=src_ip, threat_score=40, severity="Medium",
                 status="open", explanation="open", matched_rules_json=[], recommended_response="open"))
    db.commit()


def test_another_kind_of_alert_still_open_keeps_a_scanner_out_but_the_models_experimental_alert_does_not():
    # The model's experimental alerts counted as "another kind": every scanner it alerted on got its own scan
    # alerts again from the next check on.
    db = _session()
    _open_alert(db, "brute_force_like_attempts", SCANNER)
    _open_alert(db, "mfu_behavior_model", SECOND_SCANNER)
    _sweep(db, SCANNER)
    _sweep(db, SECOND_SCANNER)

    _check(db)

    (summary,) = _alerts(db, "internet_scanning")
    assert list(_metadata(summary)["scanners"]) == [SECOND_SCANNER]
    assert [alert.src_ip for alert in _alerts(db, "possible_horizontal_scan")] == [SCANNER]


def test_the_hours_alert_is_built_the_same_in_the_bounded_memory_mode_queued_jobs_use():
    db = _session()
    _sweep(db, SCANNER)
    _sweep(db, SECOND_SCANNER, hosts=15, port=22)

    first = run_detection(db, limit=None, use_ml=False, actor="test", only_unchecked=True, bounded_memory=True)

    (alert,) = _alerts(db)
    assert (first["created_alerts"], alert.alert_type, _evidence(db, alert)) == (1, "internet_scanning", 27)

    _sweep(db, THIRD_SCANNER, at=AT + timedelta(minutes=12))
    later = run_detection(db, limit=None, use_ml=False, actor="test", only_unchecked=True, bounded_memory=True)

    db.expire_all()
    (alert,) = _alerts(db)
    assert (later["created_alerts"], later["deduplicated_alert_updates"]) == (0, 1)
    assert (_metadata(alert)["connections"], _evidence(db, alert)) == (39, 39)
    assert alert.title.startswith("Medium: Internet scanning from 3 outside addresses")
