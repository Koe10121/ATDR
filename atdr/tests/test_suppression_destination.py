"""A suppression can name a destination: a known-good server such as a log collector.

On the BOTSv2 lab data 109 of 135 alerts were the lab's own computers sending logs to Splunk Cloud (52.40.10.231),
and a suppression could match a source, an app or an alert type, never a destination.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from atdr.app.db.database import Base
from atdr.app.db.models import Alert, NormalizedLog, RawLog
from atdr.app.main import app
from atdr.app.services.detection_service import run_detection
from atdr.app.services.suppression_service import create_suppression
from atdr.tests.test_api import _client, _login
from atdr.tests.test_persistent_contact import INFECTED, SERVER, _contact

AT = datetime(2026, 5, 20, 13, 36)
SCANNER, SERVER_INSIDE = "198.51.100.9", "202.28.46.10"


def _db():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool, future=True)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)()


def _probe(db, dst: str, port: int, index: int) -> None:
    at = AT + timedelta(seconds=index)
    raw = RawLog(raw_line=f"{SCANNER} {dst} {port} {at.isoformat()}")
    db.add(raw)
    db.flush()
    db.add(NormalizedLog(
        raw_log_id=raw.id, generated_time=at, log_type="TRAFFIC", subtype="drop", src_ip=SCANNER, dst_ip=dst,
        src_zone="SG-Outside", dst_zone="DMZ-Inside", app="not-applicable", app_category="unknown", dst_port=port,
        src_port=50000 + index, protocol="tcp", action="deny", bytes=60, packets=1, packets_received=0,
        session_end_reason="policy-deny", parsed_json={},
    ))


def _check(db) -> dict:
    return run_detection(db, limit=None, use_ml=False, actor="test", only_unchecked=True, model_alerts=False)


def _alerts(db) -> list[Alert]:
    return list(db.scalars(select(Alert).where(Alert.alert_type != "internet_exposed_service")))


def test_an_alert_whose_traffic_all_goes_to_the_named_server_is_suppressed():
    db = _db()
    for index in range(15):
        _probe(db, SERVER_INSIDE, 1000 + index, index)
    db.commit()
    rule = create_suppression(db, src_ip=None, dst_ip=SERVER_INSIDE, app=None, alert_type=None,
                              reason="Our own vulnerability scanner's target.", actor="admin")

    result = _check(db)

    assert result["suppressed_by_rules"] >= 1
    assert _alerts(db) == []
    db.refresh(rule)
    assert rule.suppressed_count >= 1 and rule.last_matched_at is not None


def test_a_scan_that_touched_the_named_server_is_still_a_scan():
    db = _db()
    # The same port on fifteen addresses, one of them the named server.
    for index in range(15):
        _probe(db, SERVER_INSIDE if index == 0 else f"202.28.46.{20 + index}", 22, index)
    db.commit()
    create_suppression(db, src_ip=None, dst_ip=SERVER_INSIDE, app=None, alert_type=None,
                       reason="Our own vulnerability scanner's target.", actor="admin")

    result = _check(db)

    assert result["suppressed_by_rules"] == 0
    assert _alerts(db)


def test_constant_contact_with_a_named_server_is_suppressed():
    db = _db()
    for source in INFECTED[:2]:
        _contact(db, source, SERVER, minutes=40)
    db.commit()
    rule = create_suppression(db, src_ip=None, dst_ip=SERVER, app=None, alert_type=None,
                              reason="The lab's log collector.", actor="admin")

    result = _check(db)

    assert result["persistent_contacts"] == 0 and result["suppressed_by_rules"] >= 1
    assert list(db.scalars(select(Alert).where(Alert.alert_type == "persistent_outside_contact"))) == []
    db.refresh(rule)
    assert rule.suppressed_count >= 2

    other = _db()
    for source in INFECTED[:2]:
        _contact(other, source, SERVER, minutes=40)
    other.commit()
    create_suppression(other, src_ip=None, dst_ip="52.40.10.231", app=None, alert_type=None,
                       reason="The lab's log collector.", actor="admin")
    assert _check(other)["persistent_contacts"] == 1


def test_admins_name_a_destination_through_the_api_and_it_must_be_an_address():
    client = _client()
    try:
        headers = _login(client, "admin", "admin123")
        created = client.post("/api/suppressions", json={"dst_ip": " 52.40.10.231 ", "reason": "Splunk Cloud log forwarding."},
                              headers=headers)
        assert created.status_code == 200
        assert (created.json()["dst_ip"], created.json()["src_ip"]) == ("52.40.10.231", None)

        for bad in ("splunk.example.com", "52.40.10.0/24", "52.40.10.231, 8.8.8.8"):
            refused = client.post("/api/suppressions", json={"dst_ip": bad, "reason": "Too broad."}, headers=headers)
            assert refused.status_code == 422, bad

        listed = client.get("/api/suppressions", headers=headers).json()
        assert listed[0]["dst_ip"] == "52.40.10.231"
        audit = client.get("/api/audit", headers=headers).json()
        created_rows = [row for row in audit if row["action"] == "suppression_created"]
        assert created_rows and created_rows[0]["details"]["dst_ip"] == "52.40.10.231"
    finally:
        app.dependency_overrides.clear()


def test_a_suppression_still_needs_at_least_one_criterion():
    client = _client()
    try:
        headers = _login(client, "admin", "admin123")
        refused = client.post("/api/suppressions", json={"dst_ip": "", "reason": "Nothing named."}, headers=headers)
        assert refused.status_code == 422
    finally:
        app.dependency_overrides.clear()
