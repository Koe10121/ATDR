"""New activity of the same kind from the same source joins the alert still open for it, for a day."""

from __future__ import annotations

from datetime import datetime, timedelta

from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from atdr.app.db.database import Base
from atdr.app.db.models import Alert, AlertEvidence, NormalizedLog, RawLog
from atdr.app.detection.rules import DetectionResult, RuleMatch
from atdr.app.services.alert_service import ALERT_MERGE_WINDOW_HOURS, create_grouped_alert_from_detections, update_alert_status
from atdr.app.services.detection_service import run_detection

START = datetime(2026, 5, 20, 13, 36)
SCANNER = "203.0.113.10"


def _session():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool, future=True)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)()


def _store(db, entries) -> None:
    for at, fields in entries:
        raw = RawLog(raw_line=f"merge test {at.isoformat()} {fields['src_ip']} {fields['dst_ip']} {fields['dst_port']}")
        db.add(raw)
        db.flush()
        db.add(NormalizedLog(raw_log_id=raw.id, generated_time=at, log_type="TRAFFIC", protocol="tcp", parsed_json={}, **fields))
    db.commit()


def _sweep(at: datetime, port: int, *, src_ip: str = SCANNER, hosts: int = 12):
    """One source trying one port on many MFU hosts, a second apart: a horizontal scan."""
    return [
        (at + timedelta(seconds=index), {
            "src_ip": src_ip, "dst_ip": f"10.20.30.{10 + index}", "src_zone": "SG-Outside", "dst_zone": "LAN-Inside",
            "app": "incomplete", "dst_port": port, "action": "deny", "bytes": 60, "packets": 1,
        })
        for index in range(hosts)
    ]


def _check(db) -> dict:
    return run_detection(db, limit=None, use_ml=False, actor="test", only_unchecked=True)


def _scan_alerts(db) -> list[Alert]:
    return list(db.scalars(select(Alert).where(Alert.alert_type == "possible_horizontal_scan").order_by(Alert.id)))


def _ports(alert: Alert) -> list[int]:
    metadata = next(rule for rule in alert.matched_rules_json if rule.get("code") == "group_metadata")
    return sorted(metadata["sample_dst_ports"])


def test_a_scanner_moving_to_another_port_stays_one_alert():
    # A shared destination port used to be required, so a scanner working through four ports raised four alerts
    # in every five-minute window.
    db = _session()
    _store(db, _sweep(START, 22))
    assert _check(db)["created_alerts"] == 1

    _store(db, _sweep(START + timedelta(minutes=20), 3389))
    later = _check(db)

    alerts = _scan_alerts(db)
    assert (later["created_alerts"], later["deduplicated_alert_updates"]) == (0, 1)
    assert len(alerts) == 1 and _ports(alerts[0]) == [22, 3389]
    assert db.scalar(select(AlertEvidence.alert_id).where(AlertEvidence.alert_id != alerts[0].id)) is None


def test_the_same_scan_a_day_after_the_alert_went_quiet_is_a_new_alert():
    db = _session()
    _store(db, _sweep(START, 22))
    _check(db)
    _store(db, _sweep(START + timedelta(hours=ALERT_MERGE_WINDOW_HOURS - 1), 22))
    assert _check(db)["created_alerts"] == 0, "within a day of the alert's last activity it joins"

    _store(db, _sweep(START + timedelta(hours=2 * ALERT_MERGE_WINDOW_HOURS + 1), 22))
    assert _check(db)["created_alerts"] == 1, "more than a day after its last activity it does not"
    assert len(_scan_alerts(db)) == 2


def test_another_scanner_gets_its_own_alert_and_a_closed_alert_is_not_reopened():
    db = _session()
    _store(db, _sweep(START, 22))
    _check(db)
    _store(db, _sweep(START + timedelta(minutes=10), 22, src_ip="198.51.100.77"))
    assert _check(db)["created_alerts"] == 1
    first, second = _scan_alerts(db)
    assert (first.src_ip, second.src_ip) == (SCANNER, "198.51.100.77")

    update_alert_status(db, first.id, "resolved", actor="analyst")
    _store(db, _sweep(START + timedelta(minutes=30), 22))
    assert _check(db)["created_alerts"] == 1, "an alert an analyst closed is finished; the new activity is a new alert"
    assert [alert.status for alert in _scan_alerts(db)] == ["resolved", "open", "open"]


def test_the_open_alert_is_found_among_many_of_its_kind():
    # Only the 50 most recently updated alerts of a kind used to be compared, so on a busy day a scanner's own
    # alert was missed and a second one raised.
    db = _session()
    _store(db, _sweep(START, 22))
    _check(db)
    others = [entry for number in range(60) for entry in _sweep(START + timedelta(minutes=10), 22, src_ip=f"198.51.100.{number + 1}")]
    _store(db, others)
    assert _check(db)["created_alerts"] == 60

    _store(db, _sweep(START + timedelta(minutes=40), 8080))
    again = _check(db)

    assert (again["created_alerts"], again["deduplicated_alert_updates"]) == (0, 1)
    assert len(_scan_alerts(db)) == 61
    assert _ports(_scan_alerts(db)[0]) == [22, 8080]


def _raised(db, kind: str, at: datetime, destinations: list[str], port: int, *, src_ip: str = "172.25.11.92",
            sources: list[str] | None = None) -> Alert:
    """The alert detection raises (or updates) for one group of logs of this kind, from one source or several."""
    entries = [(at + timedelta(seconds=index), {
        "src_ip": source, "dst_ip": destination, "src_zone": "LAN-Inside", "dst_zone": "SG-Outside",
        "app": "web-browsing", "dst_port": port, "action": "allow", "bytes": 600, "packets": 4,
    }) for index, (source, destination) in enumerate(zip(sources or [src_ip] * len(destinations), destinations))]
    _store(db, entries)
    logs = list(db.scalars(select(NormalizedLog).order_by(NormalizedLog.id.desc()).limit(len(entries))))[::-1]
    rule = RuleMatch(code=kind, title=kind, score=50, explanation="test")
    result = DetectionResult(threat_score=50, severity="Medium", explanation="test", matched_rules=[rule])
    alert = create_grouped_alert_from_detections(db, [(log, result) for log in logs], primary_rule_code=kind)
    db.commit()
    return alert


def test_a_source_s_next_destinations_join_the_alert_it_raised_for_one_destination():
    # 21 Oct, live: one connection to 47.246.167.231 on port 443 was a horizontal-scan alert of its own, which named
    # that address as its destination and so took nothing else; the same device's next 14 connections on port 80,
    # 26 s later, raised a second alert.
    db = _session()
    first = _raised(db, "possible_horizontal_scan", START, ["47.246.167.231"], 443)
    assert first.dst_ip == "47.246.167.231"

    later = _raised(db, "possible_horizontal_scan", START + timedelta(seconds=26), [f"93.184.216.{n}" for n in range(14)], 80)

    assert later.id == first.id and len(_scan_alerts(db)) == 1
    assert later.dst_ip is None, "an alert about several destinations names none"
    assert _ports(later) == [80, 443]
    assert db.scalar(select(func.count(AlertEvidence.id)).where(AlertEvidence.alert_id == first.id)) == 15


def test_a_beacon_to_one_address_does_not_take_a_beacon_to_another():
    # Beaconing and floods are told apart by their destination: each outside server a device calls is its own alert.
    db = _session()
    first = _raised(db, "beaconing_like_outbound", START, ["198.51.100.77"], 4444)
    second = _raised(db, "beaconing_like_outbound", START + timedelta(minutes=5), ["198.51.100.78"], 4444)
    again = _raised(db, "beaconing_like_outbound", START + timedelta(minutes=10), ["198.51.100.77"], 4444)

    assert first.id != second.id and again.id == first.id
    assert (first.dst_ip, second.dst_ip) == ("198.51.100.77", "198.51.100.78")


def test_an_alert_about_many_sources_stays_about_its_one_destination():
    # Many addresses on one server's port are that server's alert; the same on another server is another alert.
    db = _session()
    callers = [f"198.51.100.{n}" for n in range(1, 4)]
    first = _raised(db, "unusual_destination_port", START, ["10.20.30.40"] * 3, 8443, sources=callers)
    second = _raised(db, "unusual_destination_port", START + timedelta(minutes=5), ["10.20.30.41"] * 3, 8443, sources=callers)

    assert (first.src_ip, first.dst_ip) == (None, "10.20.30.40")
    assert second.id != first.id and second.dst_ip == "10.20.30.41"
