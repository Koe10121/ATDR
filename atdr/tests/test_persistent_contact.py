"""Inside computers in constant contact with an outside address that almost nothing else uses.

Built after ATDR missed BOTSv2's command server: four computers made 24,180 HTTPS connections to 45.77.65.211
over two days, which the five-minute beaconing rule cannot see (plain 443, two to four seconds apart).
"""

from __future__ import annotations

from datetime import datetime, timedelta

from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from atdr.app.db.database import Base
from atdr.app.db.models import Alert, NormalizedLog, RawLog
from atdr.app.detection.attack_mapping import infer_attack_type_from_rules
from atdr.app.detection.plain_summary import build_plain_summary
from atdr.app.services.detection_service import run_detection

AT = datetime(2017, 8, 23, 20, 0)
SERVER = "45.77.65.211"
INFECTED = ["10.0.2.107", "10.0.2.109", "10.0.1.100", "10.0.1.101"]


def _db():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool, future=True)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)()


def _contact(db, src: str, dst: str, *, minutes: int, every: int = 10, start: datetime = AT, port: int = 443,
             app: str = "ssl", subtype: str = "end") -> None:
    """One connection from `src` to `dst` every `every` seconds for `minutes` minutes."""

    for index in range(minutes * 60 // every):
        at = start + timedelta(seconds=every * index)
        raw = RawLog(raw_line=f"{src} {dst} {at.isoformat()} {subtype}")
        db.add(raw)
        db.flush()
        db.add(NormalizedLog(
            raw_log_id=raw.id, generated_time=at, log_type="TRAFFIC", subtype=subtype, src_ip=src, dst_ip=dst,
            src_zone="LAN-Inside", dst_zone="SG-Outside", app=app, dst_port=port, src_port=40000 + index % 20000,
            protocol="udp" if port in (53, 123) else "tcp", action="allow", bytes=900, packets=8, packets_received=4,
            session_end_reason="tcp-fin", parsed_json={},
        ))


def _check(db) -> dict:
    return run_detection(db, limit=None, use_ml=False, actor="test", only_unchecked=True, model_alerts=False)


def _contact_alerts(db) -> list[Alert]:
    return list(db.scalars(select(Alert).where(Alert.alert_type == "persistent_outside_contact").order_by(Alert.id)))


def _metadata(alert: Alert) -> dict:
    return next(rule for rule in alert.matched_rules_json if rule.get("code") == "group_metadata")


def test_computers_in_constant_contact_with_a_rarely_used_address_raise_one_medium_alert():
    db = _db()
    for source in INFECTED:
        _contact(db, source, SERVER, minutes=40)
    db.commit()

    result = _check(db)

    alerts = _contact_alerts(db)
    assert result["persistent_contacts"] == 1 and len(alerts) == 1
    alert = alerts[0]
    assert (alert.severity, alert.threat_score, alert.dst_ip) == ("Medium", 60, SERVER)
    assert infer_attack_type_from_rules(alert.matched_rules_json) == "malware_c2"
    metadata = _metadata(alert)
    assert set(metadata["sources"]) == set(INFECTED)
    assert all(item == {"connections": 240, "windows": 8} for item in metadata["sources"].values())
    assert metadata["ports"] == [443] and metadata["apps"] == ["ssl"]
    assert alert.title == f"Medium: 4 inside computers in constant contact with {SERVER}"
    assert "has not been tried on MFU's own traffic" in alert.explanation
    assert 0 < len(alert.evidence) <= 100
    summary = build_plain_summary(db, alert, "malware_c2")
    assert summary.startswith(f"4 MFU computers kept up constant contact with outside address {SERVER}: 960 connections")


def test_an_address_many_computers_use_is_a_service_not_a_command_server():
    db = _db()
    for index in range(6):
        _contact(db, f"10.0.3.{index + 1}", "52.40.10.231", minutes=40)
    db.commit()

    assert _check(db)["persistent_contacts"] == 0
    assert _contact_alerts(db) == []


def test_contact_shorter_than_half_an_hour_is_not_lasting():
    db = _db()
    # Very busy, but within five five-minute windows only.
    _contact(db, INFECTED[0], SERVER, minutes=25, every=2)
    db.commit()

    assert _check(db)["persistent_contacts"] == 0


def test_name_lookups_and_clocks_are_steady_by_design():
    db = _db()
    _contact(db, "10.0.1.100", "8.8.8.8", minutes=40, port=53, app="dns")
    _contact(db, "10.0.1.101", "4.4.4.4", minutes=40, port=53, app="incomplete")
    _contact(db, "10.0.1.102", "129.6.15.28", minutes=40, port=123, app="ntp")
    # A resolver on another port is still a resolver.
    _contact(db, "10.0.1.103", "9.9.9.9", minutes=40, port=5353, app="dns")
    db.commit()

    assert _check(db)["persistent_contacts"] == 0


def test_contact_too_sparse_over_the_hour_is_not_constant():
    db = _db()
    # One connection a minute for an hour: sixty, under the hundred and twenty asked for.
    _contact(db, INFECTED[0], SERVER, minutes=60, every=60)
    db.commit()

    assert _check(db)["persistent_contacts"] == 0


def test_session_start_records_do_not_count_toward_the_hour():
    db = _db()
    # A hundred sessions in forty minutes, logged at their start and their end: a hundred connections, not two.
    _contact(db, INFECTED[0], SERVER, minutes=40, every=24, subtype="start")
    _contact(db, INFECTED[0], SERVER, minutes=40, every=24)
    db.commit()

    assert _check(db)["persistent_contacts"] == 0


def test_only_pairs_busy_in_the_batch_being_checked_are_looked_up():
    db = _db()
    # Forty minutes of contact that earlier checks already went through, then a few more connections.
    _contact(db, INFECTED[0], SERVER, minutes=40)
    db.flush()
    for log in db.scalars(select(NormalizedLog)):
        log.last_detection_run_id = 0
    _contact(db, INFECTED[0], SERVER, minutes=1, start=AT + timedelta(minutes=40))
    db.commit()

    assert _check(db)["persistent_contacts"] == 0


def test_a_private_or_inbound_address_is_not_an_outside_contact():
    db = _db()
    _contact(db, INFECTED[0], "10.0.9.9", minutes=40)
    db.commit()

    assert _check(db)["persistent_contacts"] == 0


def test_a_later_hour_adds_to_the_same_alert():
    db = _db()
    for source in INFECTED[:2]:
        _contact(db, source, SERVER, minutes=40)
    db.commit()
    _check(db)
    first = _contact_alerts(db)
    assert len(first) == 1 and len(_metadata(first[0])["sources"]) == 2

    later = AT + timedelta(hours=3)
    # The first computer's later hour is shorter: what the alert recorded for it does not shrink.
    _contact(db, INFECTED[0], SERVER, minutes=35, start=later)
    for source in INFECTED[1:]:
        _contact(db, source, SERVER, minutes=40, start=later)
    db.commit()
    _check(db)

    alerts = _contact_alerts(db)
    assert [alert.id for alert in alerts] == [first[0].id]
    metadata = _metadata(alerts[0])
    assert set(metadata["sources"]) == set(INFECTED)
    assert metadata["sources"][INFECTED[0]] == {"connections": 240, "windows": 8}
    assert metadata["first_seen"].startswith("2017-08-23T20:00") and metadata["last_seen"].startswith("2017-08-23T23:39")
    assert alerts[0].title == f"Medium: 4 inside computers in constant contact with {SERVER}"
