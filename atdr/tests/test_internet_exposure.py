"""Which MFU services answer the internet, which should not, and what an admin's mark changes (exposure_service)."""

from __future__ import annotations

from collections.abc import Generator
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from atdr.app.db.database import Base, get_db
from atdr.app.db.models import Alert, AlertEvidence, AuditLog, InternetService, NormalizedLog, RawLog
from atdr.app.detection.attack_mapping import infer_attack_type_from_rules
from atdr.app.detection.plain_summary import build_plain_summary
from atdr.app.detection.rules import build_detection_context, evaluate_rules
from atdr.app.main import app
from atdr.app.services.detection_service import run_detection
from atdr.app.services.exposure_service import list_internet_services, review_internet_service, risk_of
from atdr.app.services.user_service import create_user

AT = datetime(2026, 5, 20, 13, 36, 15)
WEB, SSH_ON_210, DEBUGGING, RDP = "202.28.46.10", "202.28.46.155", "202.28.46.216", "202.28.46.30"


def _session_factory():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool, future=True)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)


def _connection(db, *, src: str, dst: str, port: int, at: datetime = AT, app: str = "incomplete", protocol: str = "tcp",
                packets_back: int = 1, ended: str = "aged-out", src_zone: str = "SG-Outside", dst_zone: str = "WLAN-Inside",
                src_port: int | None = None) -> None:
    """One connection; `packets_back` is what the MFU side sent back."""
    raw = RawLog(raw_line=f"{src} {dst} {port} {protocol} {at.isoformat()} {packets_back} {ended}")
    db.add(raw)
    db.flush()
    db.add(NormalizedLog(
        raw_log_id=raw.id, generated_time=at, log_type="TRAFFIC", src_ip=src, dst_ip=dst, src_zone=src_zone, dst_zone=dst_zone,
        app=app, app_category="unknown", src_port=src_port, dst_port=port, action="allow", protocol=protocol, bytes=60 + 60 * packets_back,
        bytes_received=60 * packets_back, packets=1 + packets_back, packets_received=packets_back, session_end_reason=ended,
        parsed_json={},
    ))


def _traffic(db, at: datetime = AT) -> None:
    """A web server two outsiders use, SSH on port 210, Chrome's debugging port, and connections that do not count."""
    _connection(db, src="45.33.32.1", dst=WEB, port=443, app="ssl", packets_back=12, ended="tcp-fin", at=at)
    _connection(db, src="45.33.32.2", dst=WEB, port=443, app="ssl", packets_back=9, ended="tcp-fin", at=at + timedelta(seconds=5))
    _connection(db, src="45.33.32.3", dst=SSH_ON_210, port=210, app="ssh", packets_back=14, ended="tcp-fin", at=at + timedelta(seconds=9))
    _connection(db, src="45.33.32.4", dst=DEBUGGING, port=9222, at=at + timedelta(seconds=12))
    # Refused with one reset, a ping, a blocked attempt, an MFU device going out, and an outside private address:
    # none of them shows a service answering the internet.
    _connection(db, src="45.33.32.5", dst=RDP, port=3389, ended="tcp-rst-from-server", at=at)
    _connection(db, src="45.33.32.6", dst=WEB, port=0, protocol="icmp", app="ping", at=at)
    _connection(db, src="45.33.32.7", dst=RDP, port=3389, packets_back=0, ended="policy-deny", at=at)
    _connection(db, src="202.28.46.40", dst="8.8.8.8", port=53, app="dns", src_zone="WLAN-Inside", dst_zone="SG-Outside", at=at)
    _connection(db, src="10.9.9.9", dst=WEB, port=8443, at=at)
    db.commit()


def _check(db, **options) -> dict:
    return run_detection(db, limit=None, use_ml=False, actor="test", only_unchecked=True, **options)


def _exposure_alerts(db) -> list[Alert]:
    return list(db.scalars(select(Alert).where(Alert.alert_type == "internet_exposed_service").order_by(Alert.id)))


def _metadata(alert: Alert) -> dict:
    return next(rule for rule in alert.matched_rules_json if rule.get("code") == "group_metadata")


def _service(db, address: str, port: int) -> InternetService:
    return db.scalars(select(InternetService).where(InternetService.address == address, InternetService.port == port)).one()


def test_the_services_that_answer_the_internet_are_listed_with_what_they_are():
    db = _session_factory()()
    _traffic(db)

    _check(db)

    services = {(row.address, row.port, row.protocol): row for row in db.scalars(select(InternetService))}
    assert set(services) == {(WEB, 443, "tcp"), (SSH_ON_210, 210, "tcp"), (DEBUGGING, 9222, "tcp")}
    web = services[(WEB, 443, "tcp")]
    assert (web.connections, web.sources, web.sample_sources, web.status) == (2, 2, ["45.33.32.1", "45.33.32.2"], "unreviewed")
    assert web.apps == [{"app": "ssl", "connections": 2}]
    assert (web.first_seen.replace(tzinfo=None), web.last_seen.replace(tzinfo=None)) == (AT, AT + timedelta(seconds=5))

    listed = list_internet_services(db)
    assert [(item["address"], item["what"]) for item in listed["services"]] == [
        (DEBUGGING, "Chrome remote debugging"), (SSH_ON_210, "SSH remote login"), (WEB, "web (HTTPS)")]
    assert listed["services"][0]["risk"]["severity"] == "High" and listed["services"][1]["risk"]["severity"] == "Medium"
    assert (listed["summary"]["services"], listed["summary"]["unreviewed"], listed["summary"]["risky_not_approved"]) == (3, 3, 2)


def test_what_a_service_is_comes_from_the_app_the_firewall_saw_before_its_port():
    assert risk_of(["ssh"], 210).name == "SSH remote login", "SSH on an unusual port is still SSH"
    assert risk_of(["incomplete"], 3389).name == "remote desktop (RDP)", "no app named: the port says what it probably is"
    assert risk_of(["web-browsing"], 3389) is None, "a web site on 3389 is a web site"
    assert risk_of(["mysql"], 4000).name == "a database" and risk_of(["vnc-base"], 9999).name == "remote screen control (VNC)"
    assert risk_of([], 443) is None


def test_an_ftp_server_dialling_back_to_an_mfu_computer_is_no_mfu_service():
    db = _session_factory()()
    # Active-mode FTP: the outside server a user uploads to opens each data connection from its port 20 to a high
    # port the user's computer named. BOTSv2's one user made 725 such "services" on random ports.
    # Twelve of them in a minute: enough ports for the port-scan rule, were they a scan.
    for index, port in enumerate((1076, 23105, 64297, 4217, 5220, 9860, 36117, 43689, 45619, 51000, 58805, 59680)):
        _connection(db, src="160.153.91.7", src_port=20, dst=WEB, port=port, app="ftp", packets_back=4, ended="tcp-fin",
                    at=AT + timedelta(seconds=5 * index))
    # From port 20 to a real FTP server, or to SSH: still a service answering the internet.
    _connection(db, src="45.33.32.8", src_port=20, dst=RDP, port=21, app="ftp", packets_back=4, ended="tcp-fin")
    _connection(db, src="45.33.32.9", src_port=20, dst=SSH_ON_210, port=2222, app="ssh", packets_back=4, ended="tcp-fin")
    # Passive mode: an outsider opens the data connection to MFU's FTP server, which MFU does offer.
    _connection(db, src="45.33.32.8", src_port=51000, dst=RDP, port=50000, app="ftp", packets_back=4, ended="tcp-fin")
    db.commit()

    _check(db)

    services = {(row.address, row.port) for row in db.scalars(select(InternetService))}
    assert services == {(RDP, 21), (SSH_ON_210, 2222), (RDP, 50000)}
    # Nor is it someone scanning MFU: no alert holds one of those connections.
    dial_backs = set(db.scalars(select(NormalizedLog.id).where(NormalizedLog.src_ip == "160.153.91.7")))
    held = set(db.scalars(select(AlertEvidence.normalized_log_id)))
    assert dial_backs and not dial_backs & held
    # Not even a supporting sign of probing.
    dial_back = db.scalars(select(NormalizedLog).where(NormalizedLog.src_ip == "160.153.91.7")).first()
    codes = {match.code for match in evaluate_rules(dial_back, build_detection_context([dial_back]))}
    assert not codes & {"unusual_destination_port", "possible_port_scan", "possible_horizontal_scan"}
    assert {(_metadata(alert)["address"], _metadata(alert)["port"]) for alert in _exposure_alerts(db)} <= services


def test_a_risky_service_gets_an_alert_until_an_admin_marks_it_meant_to_be_public():
    db = _session_factory()()
    _traffic(db)
    first = _check(db)

    debugging, ssh = _exposure_alerts(db)
    assert first["created_alerts"] >= 2
    assert debugging.title == f"High: Chrome remote debugging open to the internet: {DEBUGGING} port 9222"
    assert (debugging.severity, debugging.dst_ip, debugging.src_ip) == ("High", DEBUGGING, None)
    assert (
        f"MFU address {DEBUGGING} answered 1 connection from the internet on port 9222 (tcp), from 1 or more outside address "
        "on 20 May at 13:36."
    ) in debugging.explanation
    assert "It looks like Chrome remote debugging: whoever reaches it can control the browser" in debugging.explanation
    assert debugging.recommended_response.startswith(f"Find out who looks after {DEBUGGING} and what runs on port 9222.")
    assert ssh.title == f"Medium: SSH remote login open to the internet: {SSH_ON_210} port 210" and ssh.severity == "Medium"
    assert "The firewall saw ssh there." in ssh.explanation
    assert infer_attack_type_from_rules(debugging.matched_rules_json) == "exposed_service"
    assert build_plain_summary(db, debugging, "exposed_service").startswith(
        f"MFU address {DEBUGGING} answered 1 connection from the internet on port 9222, from 1 outside address or more. "
        "It looks like Chrome remote debugging, which should rarely be reachable from the internet.")
    assert len(db.scalars(select(AlertEvidence).where(AlertEvidence.alert_id == debugging.id)).all()) == 1

    # More connections join the open alert.
    _connection(db, src="45.33.32.8", dst=DEBUGGING, port=9222, at=AT + timedelta(minutes=30))
    db.commit()
    _check(db)
    debugging, ssh = _exposure_alerts(db)
    assert (_metadata(debugging)["connections"], _metadata(debugging)["sources"]) == (2, 1)
    service = _service(db, DEBUGGING, 9222)
    assert (service.connections, service.sources, service.apps) == (2, 1, [{"app": "incomplete", "connections": 2}]), (
        "outside addresses are the most in one check, not added up")

    # An alert closed by an analyst is not reopened: the next answer is a new alert.
    from atdr.app.services.alert_service import update_alert_status

    update_alert_status(db, ssh.id, "resolved", actor="koe")
    _connection(db, src="45.33.32.12", dst=SSH_ON_210, port=210, app="ssh", packets_back=14, ended="tcp-fin", at=AT + timedelta(minutes=35))
    db.commit()
    _check(db)
    assert [alert.dst_ip for alert in _exposure_alerts(db)] == [DEBUGGING, SSH_ON_210, SSH_ON_210]

    # Marked as meant to be public, it is not reported again.
    review_internet_service(db, _service(db, DEBUGGING, 9222).id, status="expected", note="lab kiosk, approved", actor="koe")
    _connection(db, src="45.33.32.9", dst=DEBUGGING, port=9222, at=AT + timedelta(minutes=40))
    db.commit()
    _check(db)
    assert _metadata(_exposure_alerts(db)[0])["connections"] == 2
    audit = db.scalars(select(AuditLog).where(AuditLog.action == "internet_service_reviewed")).one()
    assert (audit.actor, audit.details["status_before"], audit.details["status"], audit.details["note"]) == ("koe", "unreviewed", "expected", "lab kiosk, approved")


def test_a_service_marked_not_to_be_public_is_reported_when_it_answers():
    db = _session_factory()()
    _traffic(db)
    _check(db)
    assert not [alert for alert in _exposure_alerts(db) if alert.dst_ip == WEB], "a web server is not a risky kind of service"

    review_internet_service(db, _service(db, WEB, 443).id, status="not_expected", note="retired site", actor="koe")
    _connection(db, src="45.33.32.10", dst=WEB, port=443, app="ssl", packets_back=8, ended="tcp-fin", at=AT + timedelta(minutes=10))
    db.commit()
    _check(db)

    (web,) = [alert for alert in _exposure_alerts(db) if alert.dst_ip == WEB]
    assert web.title == f"High: Service open to the internet: {WEB} port 443"
    assert web.explanation.endswith("An admin marked this service as not meant to be reachable from the internet.")


def test_marking_a_service_not_to_be_public_raises_its_alert_at_once():
    # A service is listed because it answered the internet. On live, 6 of 8 services marked not to be public on
    # 22 Oct had no alert: the mark waited for a next connection that never came.
    db = _session_factory()()
    _traffic(db)
    _check(db)

    reviewed = review_internet_service(db, _service(db, WEB, 443).id, status="not_expected", note="retired site", actor="koe")

    (web,) = [alert for alert in _exposure_alerts(db) if alert.dst_ip == WEB]
    assert reviewed["alert"] == {"id": web.id, "severity": "High", "status": "open"}
    assert web.title == f"High: Service open to the internet: {WEB} port 443"
    assert web.explanation.startswith(f"MFU address {WEB} answered 2 connections from the internet on port 443 (tcp), from 2 or more outside addresses")
    assert web.explanation.endswith("An admin marked this service as not meant to be reachable from the internet.")
    assert build_plain_summary(db, web, "exposed_service") == (
        f"MFU address {WEB} answered 2 connections from the internet on port 443, from 2 outside addresses or more. "
        "An admin marked it as not meant to be public. "
        "Next: close it at the firewall, or mark it expected if it should be public after all.")
    assert len(db.scalars(select(AlertEvidence).where(AlertEvidence.alert_id == web.id)).all()) == 2
    audit = db.scalars(select(AuditLog).where(AuditLog.action == "internet_service_reviewed")).one()
    assert (audit.details["alert_id"], audit.details["alert_created"]) == (web.id, True)
    listed = {item["id"]: item for item in list_internet_services(db)["services"]}
    assert listed[_service(db, WEB, 443).id]["alert"] == {"id": web.id, "severity": "High", "status": "open"}
    assert listed[_service(db, DEBUGGING, 9222).id]["alert"]["severity"] == "High"

    # Saving the review again (a better note, say) keeps the one alert.
    review_internet_service(db, _service(db, WEB, 443).id, status="not_expected", note="retired site, owner asked", actor="koe")
    assert [alert.id for alert in _exposure_alerts(db) if alert.dst_ip == WEB] == [web.id]
    again = db.scalars(select(AuditLog).where(AuditLog.action == "internet_service_reviewed").order_by(AuditLog.id.desc())).first()
    assert (again.details["alert_id"], again.details["alert_created"]) == (web.id, False)
    assert _metadata(web)["connections"] == 2
    # The review has its own audit entry; nothing was deduplicated.
    assert not db.scalars(select(AuditLog).where(AuditLog.action == "alert_deduplicated", AuditLog.target_value == str(web.id))).all()


def test_a_risky_service_marked_not_to_be_public_says_so_on_its_open_alert():
    db = _session_factory()()
    _traffic(db)
    _check(db)
    ssh = next(alert for alert in _exposure_alerts(db) if alert.dst_ip == SSH_ON_210)
    assert ssh.severity == "Medium" and "Nobody has marked it as meant to be public." in ssh.explanation

    review_internet_service(db, _service(db, SSH_ON_210, 210).id, status="not_expected", note="no admin uses it", actor="koe")

    (marked,) = [alert for alert in _exposure_alerts(db) if alert.dst_ip == SSH_ON_210]
    assert marked.id == ssh.id
    assert marked.title == f"High: SSH remote login open to the internet: {SSH_ON_210} port 210"
    assert "An admin marked this service as not meant to be reachable from the internet" in marked.explanation
    assert "Nobody has marked" not in marked.explanation
    assert (_metadata(marked)["reason"], _metadata(marked)["connections"]) == ("not_expected", 1)
    assert len(db.scalars(select(AlertEvidence).where(AlertEvidence.alert_id == ssh.id)).all()) == 1


def test_a_service_whose_alert_was_closed_waits_for_its_next_connection():
    from atdr.app.services.alert_service import update_alert_status

    db = _session_factory()()
    _traffic(db)
    _check(db)
    ssh = next(alert for alert in _exposure_alerts(db) if alert.dst_ip == SSH_ON_210)
    update_alert_status(db, ssh.id, "resolved", actor="koe")

    reviewed = review_internet_service(db, _service(db, SSH_ON_210, 210).id, status="not_expected", note=None, actor="koe")

    assert reviewed["alert"] is None
    assert [alert.id for alert in _exposure_alerts(db) if alert.dst_ip == SSH_ON_210] == [ssh.id]
    audit = db.scalars(select(AuditLog).where(AuditLog.action == "internet_service_reviewed")).one()
    assert audit.details["alert_id"] is None


def test_a_marked_service_gets_its_alert_from_the_list_when_its_connections_are_no_longer_stored():
    db = _session_factory()()
    _traffic(db)
    _check(db)
    # Ordinary logs are kept for hours; the list keeps the counts, which cover more than the 10 sample addresses.
    for log in db.scalars(select(NormalizedLog).where(NormalizedLog.dst_ip == WEB, NormalizedLog.dst_port == 443)):
        db.delete(log)
    db.commit()
    service = _service(db, WEB, 443)
    service.connections, service.sources = 55, 40
    db.commit()
    # PostgreSQL hands times back with their zone.
    service.first_seen = AT.replace(tzinfo=timezone.utc)

    review_internet_service(db, service.id, status="not_expected", note=None, actor="koe")

    (web,) = [alert for alert in _exposure_alerts(db) if alert.dst_ip == WEB]
    assert (_metadata(web)["connections"], _metadata(web)["sources"], _metadata(web)["unique_src_count"]) == (55, 40, 40)
    assert _metadata(web)["first_seen"] == AT.isoformat()
    assert web.explanation.startswith(f"MFU address {WEB} answered 55 connections from the internet on port 443 (tcp), from 40 or more outside addresses")
    assert not db.scalars(select(AlertEvidence).where(AlertEvidence.alert_id == web.id)).all()


def test_a_rebuild_leaves_the_services_counts_as_they_were():
    # Checking every log again had doubled every service's connections on a copy of the live database (23 Oct).
    from atdr.app.services.alert_rebuild_service import rebuild_alerts

    db = _session_factory()()
    _traffic(db)
    _check(db)
    counted = {(row.address, row.port): (row.connections, row.sources, row.apps) for row in db.scalars(select(InternetService))}
    # A service missing from the list before the rebuild is counted by it, once.
    db.delete(_service(db, WEB, 443))
    db.commit()

    rebuild_alerts(db, actor="test", reason="test")

    after = {(row.address, row.port): (row.connections, row.sources, row.apps) for row in db.scalars(select(InternetService))}
    assert after == counted
    assert {alert.dst_ip for alert in _exposure_alerts(db)} == {DEBUGGING, SSH_ON_210}


def _users_of_one_service(db, at: datetime, *, users: int = 6) -> None:
    """Outside addresses each using one MFU service on port 3000, answered every time, as on 20 May."""
    for user in range(users):
        for repeat in range(4):
            _connection(db, src=f"171.4.{user}.1", dst=DEBUGGING, port=3000, app="web-browsing", packets_back=5, ended="tcp-fin",
                        at=at + timedelta(seconds=user * 10 + repeat))
    db.commit()


def _logs_flagged_at(db, port: int) -> int:
    return len(db.execute(
        select(AlertEvidence.id).join(NormalizedLog, NormalizedLog.id == AlertEvidence.normalized_log_id).where(NormalizedLog.dst_port == port)
    ).all())


def test_people_using_a_service_marked_expected_are_not_taken_for_probes():
    # On 20 May 39 addresses that each reached one MFU server on port 3000, answered every time, were listed as
    # scanners: the port is not on the common list.
    db = _session_factory()()
    _users_of_one_service(db, AT)
    _check(db)
    flagged_first = _logs_flagged_at(db, 3000)
    assert flagged_first > 0, "unmarked, an unusual port from the internet is flagged"
    # Listed is not approved: until an admin marks it, its users count as before.
    _users_of_one_service(db, AT + timedelta(hours=1))
    _check(db)
    flagged_before = _logs_flagged_at(db, 3000)
    assert flagged_before > flagged_first and _service(db, DEBUGGING, 3000).status == "unreviewed"

    review_internet_service(db, _service(db, DEBUGGING, 3000).id, status="expected", note="the faculty's web app", actor="koe")
    _users_of_one_service(db, AT + timedelta(hours=2))
    later = _check(db)

    assert _logs_flagged_at(db, 3000) == flagged_before, "nothing more is flagged"
    assert later["expected_service_logs"] == 24
    # Sweeping many MFU addresses on that port is still a scan, the expected service among them included.
    for host in range(12):
        _connection(db, src="185.1.1.1", dst=DEBUGGING if host == 0 else f"202.28.45.{host + 1}", port=3000, packets_back=0,
                    at=AT + timedelta(hours=3, seconds=host))
    db.commit()
    _check(db)
    swept = db.execute(
        select(AlertEvidence.id).join(NormalizedLog, NormalizedLog.id == AlertEvidence.normalized_log_id)
        .where(NormalizedLog.src_ip == "185.1.1.1", NormalizedLog.dst_ip == DEBUGGING)
    ).all()
    assert _logs_flagged_at(db, 3000) > flagged_before and len(swept) == 1


def test_a_service_that_starts_answering_after_a_day_is_new():
    db = _session_factory()()
    _connection(db, src="45.33.32.1", dst=WEB, port=443, app="ssl", packets_back=12, ended="tcp-fin")
    db.commit()
    _check(db)
    assert _exposure_alerts(db) == [], "what answers on the first day is listed, not reported"

    later = AT + timedelta(days=2)
    _connection(db, src="45.33.32.2", dst=WEB, port=8443, app="ssl", packets_back=12, ended="tcp-fin", at=later)
    _connection(db, src="45.33.32.3", dst=WEB, port=443, app="ssl", packets_back=12, ended="tcp-fin", at=later)
    db.commit()
    _check(db)

    (new,) = _exposure_alerts(db)
    assert new.title == f"Medium: New service open to the internet: {WEB} port 8443"
    assert "began answering the internet after ATDR had been listing MFU's services for a day" in new.explanation


def test_bounded_detection_lists_and_reports_the_same():
    db = _session_factory()()
    _traffic(db)

    _check(db, bounded_memory=True)

    db.expire_all()
    assert len(db.scalars(select(InternetService)).all()) == 3
    assert [alert.dst_ip for alert in _exposure_alerts(db)] == [DEBUGGING, SSH_ON_210]
    assert len(db.scalars(select(AlertEvidence).where(AlertEvidence.alert_id == _exposure_alerts(db)[0].id)).all()) == 1


def test_analysts_see_the_list_and_only_admins_mark_services():
    factory = _session_factory()
    with factory() as db:
        create_user(db, username="analyst", password="analyst123", role="analyst", full_name="Test Analyst")
        create_user(db, username="admin", password="admin12345", role="admin", full_name="Test Admin")
        _traffic(db)
        _check(db)

    def override_get_db() -> Generator[Session, None, None]:
        db = factory()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    try:
        client = TestClient(app)

        def headers(user: str, password: str) -> dict:
            token = client.post("/api/auth/login", json={"username": user, "password": password}).json()["access_token"]
            return {"Authorization": f"Bearer {token}"}

        analyst, admin = headers("analyst", "analyst123"), headers("admin", "admin12345")
        listed = client.get("/api/exposure/services", headers=analyst).json()
        assert listed["summary"]["services"] == 3 and listed["services"][0]["port"] == 9222
        service_id = listed["services"][2]["id"]
        assert client.patch(f"/api/exposure/services/{service_id}", headers=analyst, json={"status": "expected"}).status_code == 403
        marked = client.patch(f"/api/exposure/services/{service_id}", headers=admin, json={"status": "expected", "note": "main site"})
        assert marked.status_code == 200 and (marked.json()["status"], marked.json()["note"], marked.json()["reviewed_by"]) == ("expected", "main site", "admin")
        assert client.get("/api/exposure/services?status=expected", headers=analyst).json()["total_shown"] == 1
        assert client.patch("/api/exposure/services/999", headers=admin, json={"status": "expected"}).status_code == 404
        assert client.patch(f"/api/exposure/services/{service_id}", headers=admin, json={"status": "maybe"}).status_code == 422
    finally:
        app.dependency_overrides.clear()


def test_the_command_lists_what_the_stored_logs_show_once_after_a_backup(monkeypatch, tmp_path, capsys):
    from atdr.scripts import build_exposure_map as command

    factory = _session_factory()
    with factory() as db:
        _traffic(db)
        # Checked before ATDR listed services: as on the laptop, nothing is listed and nothing reported.
        _connection(db, src="45.33.32.11", dst=WEB, port=443, app="ssl", packets_back=7, ended="tcp-fin", at=AT + timedelta(minutes=1))
        db.commit()
    monkeypatch.setattr(command, "SessionLocal", factory)
    # Logs are read in chunks: the outside addresses are counted over all of them, not the busiest chunk.
    import atdr.app.services.exposure_service as exposure_service

    monkeypatch.setattr(exposure_service, "ANSWERED_LOGS_CHUNK", 2)
    backups: list[str] = []
    monkeypatch.setattr(command, "create_database_backup",
                        lambda **kwargs: backups.append(kwargs["output_dir"]) or {"ok": True, "status": "backup_created", "backup_path": "b.sqlite3"})

    assert command.main([]) == 0
    with factory() as db:
        assert db.scalars(select(InternetService)).all() == [] and _exposure_alerts(db) == [] and backups == []
    said = capsys.readouterr().out
    assert '"services": 3' in said and "Chrome remote debugging (High)" in said

    assert command.main(["--apply", "--actor", "koe", "--backup-dir", str(tmp_path)]) == 0
    with factory() as db:
        web = _service(db, WEB, 443)
        assert (web.connections, web.sources) == (3, 3), "every stored connection, every outside address"
        assert [alert.title for alert in _exposure_alerts(db)] == [
            f"High: Chrome remote debugging open to the internet: {DEBUGGING} port 9222",
            f"Medium: SSH remote login open to the internet: {SSH_ON_210} port 210"]
        audit = db.scalars(select(AuditLog).where(AuditLog.action == "exposure_map_built")).one()
        assert (audit.actor, audit.details["services"]) == ("koe", 3)
    assert backups == [str(tmp_path)]
    assert "Listed 3 services on 3 MFU addresses; 2 alerts." in capsys.readouterr().out

    assert command.main(["--apply"]) == 0 and backups == [str(tmp_path)], "listed already: nothing counted twice, no backup"
    with factory() as db:
        assert _service(db, WEB, 443).connections == 3 and len(_exposure_alerts(db)) == 2


def test_an_exposure_alert_is_no_claim_that_its_connections_are_attacks():
    # The team labelled an SSH connection to port 210 "benign, unusual": it is someone using SSH. The exposure alert
    # says SSH answers the internet; counting its evidence as flagged would make that a false alarm.
    from atdr.app.db.models import MLLabel
    from atdr.app.services.blind_check_service import _verdict
    from atdr.app.services.detection_scoreboard_service import build_scoreboard

    db = _session_factory()()
    _traffic(db)
    _check(db)
    ssh_log = db.scalars(select(NormalizedLog).where(NormalizedLog.dst_ip == SSH_ON_210)).one()
    assert db.scalars(select(AlertEvidence).where(AlertEvidence.normalized_log_id == ssh_log.id)).all(), "it is the SSH alert's evidence"
    db.add(MLLabel(log_id=ssh_log.id, label="benign_unusual", attack_type="normal", confidence=80, reviewer="team"))
    db.commit()

    scoreboard = build_scoreboard(db)
    assert (scoreboard["overall"]["all"]["fp"], scoreboard["overall"]["all"]["tn"]) == (0, 1)
    assert _verdict(db, ssh_log.id)["alerted"] is False
