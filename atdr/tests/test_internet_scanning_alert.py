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
                source_id: int | None = None, imported_at: datetime | None = None, protocol: str = "tcp",
                packets_back: int = 0, ended: str = "aged-out") -> None:
    """One connection; `packets_back` is what the MFU address sent back (none: nothing answered it)."""
    raw = RawLog(raw_line=f"scan {src} {dst} {port} {at.isoformat()} {log_type} {packets_back}", source_id=source_id)
    if imported_at is not None:
        raw.imported_at = imported_at
    db.add(raw)
    db.flush()
    db.add(NormalizedLog(
        raw_log_id=raw.id, generated_time=at, log_type=log_type, src_ip=src, dst_ip=dst,
        src_zone="LAN-Inside" if inside else "SG-Outside", dst_zone="WLAN-Inside", app="incomplete", app_category="unknown",
        dst_port=port, action="allow", protocol=protocol, bytes=60, bytes_received=60 * packets_back, packets=1 + packets_back,
        packets_received=packets_back, session_end_reason=ended, parsed_json={},
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
    assert "Not one of them got an answer from an MFU address." in alert.explanation
    assert {entry["answered"] for entry in metadata["scanners"].values()} == {0}
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


def _answered_sweep(db) -> None:
    """A port-80 sweep that three MFU web servers answered and one refused, and a ping sweep five addresses answered."""
    for host in range(12):
        packets_back, ended = (4, "tcp-fin") if host < 3 else (1, "tcp-rst-from-server") if host == 3 else (0, "aged-out")
        _connection(db, src=SCANNER, dst=f"10.0.0.{host + 1}", port=80, at=AT + timedelta(seconds=host), packets_back=packets_back, ended=ended)
    for host in range(15):
        _connection(db, src=SECOND_SCANNER, dst=f"10.0.1.{host + 1}", port=0, protocol="icmp", at=AT + timedelta(seconds=host),
                    packets_back=1 if host < 5 else 0)
    _sweep(db, THIRD_SCANNER, port=3389)
    db.commit()


def _later_sweep(db) -> None:
    """The first scanner again, twenty minutes on, on port 443: one MFU address answers."""
    for host in range(12):
        _connection(db, src=SCANNER, dst=f"10.0.2.{host + 1}", port=443, at=AT + timedelta(minutes=20, seconds=host),
                    packets_back=3 if host == 0 else 0, ended="tcp-rst-from-client" if host == 0 else "aged-out")
    db.commit()


def test_the_hours_alert_says_which_scanners_got_answers_and_puts_them_first():
    # In the 20 May export one sweep was answered by 83 MFU web servers, and the list showed it like one that
    # reached nothing.
    from atdr.app.detection.plain_summary import build_plain_summary

    db = _session()
    _answered_sweep(db)
    _check(db)

    (alert,) = _alerts(db)
    scanners = _metadata(alert)["scanners"]
    # A single reset from the MFU side refuses the connection: that is no answer.
    assert scanners[SCANNER] | {} == {"connections": 12, "targets": 12, "ports": [80], "kept": 12,
                                      "answered": 3, "answered_by": 3, "answered_ports": [80]}
    # A ping has no port: its answers are counted apart.
    assert (scanners[SECOND_SCANNER]["answered"], scanners[SECOND_SCANNER]["answered_by"], scanners[SECOND_SCANNER]["answered_ping"]) == (5, 5, 5)
    assert "answered_ports" not in scanners[SECOND_SCANNER]
    assert scanners[THIRD_SCANNER]["answered"] == 0 and "answered_by" not in scanners[THIRD_SCANNER]
    assert (
        f"2 of them got answers from MFU addresses, most: {SECOND_SCANNER} (5 of 15 connections answered, by 5 or more MFU "
        f"addresses, ping); {SCANNER} (3 of 12 connections answered, by 3 or more MFU addresses, port 80). The busiest:"
    ) in alert.explanation
    assert alert.recommended_response.startswith(
        "Nothing to do for the list as a whole: every public network is scanned all day. Start with the addresses that got answers")
    summary = build_plain_summary(db, alert, "port_scan")
    assert "None of them did anything else ATDR alerts on. 2 of them got answers from MFU addresses. Every public" in summary
    assert "Next: look first at the addresses that got answers, then at the busiest, and block one" in summary

    # More of the same hour: the answers add up. Like the addresses reached, those that answered are the most
    # seen in one check: the hour's true number is at least that.
    _later_sweep(db)
    _check(db)
    (alert,) = _alerts(db)
    later = _metadata(alert)["scanners"][SCANNER]
    assert (later["connections"], later["answered"], later["answered_by"], later["answered_ports"]) == (24, 4, 3, [80, 443])


def _forget_answers(db, alert: Alert) -> None:
    """As an alert made before ATDR counted answers."""
    rules = []
    for rule in alert.matched_rules_json:
        if rule.get("code") == "group_metadata":
            rule = {**rule, "scanners": {address: {key: value for key, value in entry.items() if not key.startswith("answered")}
                                         for address, entry in rule["scanners"].items()}}
        rules.append(rule)
    alert.matched_rules_json = rules
    alert.explanation, alert.recommended_response = "made before", "made before"
    db.commit()


def test_an_alert_made_before_answers_were_counted_is_counted_from_its_evidence():
    from atdr.app.services.alert_service import count_scanner_answers

    db = _session()
    _answered_sweep(db)
    _check(db)
    (alert,) = _alerts(db)
    counted_as_it_happened = _metadata(alert)["scanners"]
    _forget_answers(db, alert)

    # A later check of the same hour leaves those scanners uncounted: counting from then on would say too few.
    _later_sweep(db)
    _check(db)
    (alert,) = _alerts(db)
    assert _metadata(alert)["scanners"][SCANNER]["connections"] == 24
    assert "answered" not in _metadata(alert)["scanners"][SCANNER]
    assert "got answers" not in alert.explanation and "got an answer" not in alert.explanation
    from atdr.app.detection.plain_summary import build_plain_summary

    before = build_plain_summary(db, alert, "port_scan")
    assert "answer" not in before and "Next: look at the busiest addresses," in before, "nothing is said about answers not counted"

    assert count_scanner_answers(db, alert) == {"counted": 3, "left": 0}
    db.commit()
    scanners = _metadata(alert)["scanners"]
    assert scanners[SECOND_SCANNER] == counted_as_it_happened[SECOND_SCANNER]
    assert scanners[THIRD_SCANNER] == counted_as_it_happened[THIRD_SCANNER]
    # From every evidence log at once: all four MFU addresses that answered in the hour.
    assert (scanners[SCANNER]["answered"], scanners[SCANNER]["answered_by"], scanners[SCANNER]["answered_ports"]) == (4, 4, [80, 443])
    assert "2 of them got answers from MFU addresses" in alert.explanation
    assert alert.recommended_response.startswith("Nothing to do for the list as a whole")
    assert count_scanner_answers(db, alert) == {"counted": 0, "left": 0}, "counted once"


def test_a_live_feed_scanner_whose_evidence_is_a_sample_is_left_without_a_count():
    from atdr.app.services.alert_service import count_scanner_answers

    db = _session()
    live = LogSource(name="syslog_udp:198.51.100.1", source_type="syslog_udp", parser_profile="palo_alto", enabled=True)
    db.add(live)
    db.flush()
    _sweep(db, SCANNER, hosts=50, source_id=live.id)
    _sweep(db, SECOND_SCANNER, hosts=12, source_id=live.id)
    _check(db)
    (alert,) = _alerts(db)
    _forget_answers(db, alert)

    assert count_scanner_answers(db, alert) == {"counted": 1, "left": 1}
    scanners = _metadata(alert)["scanners"]
    assert "answered" not in scanners[SCANNER], f"{SCAN_SAMPLE_LOGS_PER_ADDRESS} of its 50 connections are evidence"
    assert scanners[SECOND_SCANNER]["answered"] == 0


def test_the_command_counts_older_alerts_after_a_backup_and_a_dry_run_changes_nothing(monkeypatch, tmp_path, capsys):
    from sqlalchemy.orm import sessionmaker

    from atdr.app.db.models import AuditLog
    from atdr.scripts import count_scanner_answers as command

    db = _session()
    _answered_sweep(db)
    _check(db)
    (alert,) = _alerts(db)
    _forget_answers(db, alert)
    monkeypatch.setattr(command, "SessionLocal", sessionmaker(bind=db.get_bind(), future=True))
    backups: list[str] = []
    monkeypatch.setattr(command, "create_database_backup",
                        lambda **kwargs: backups.append(kwargs["output_dir"]) or {"ok": True, "status": "backup_created", "backup_path": "b.sqlite3"})

    assert command.main([]) == 0
    db.expire_all()
    assert "answered" not in _metadata(_alerts(db)[0])["scanners"][SCANNER] and backups == []
    assert '"got_answers": 2' in capsys.readouterr().out

    assert command.main(["--apply", "--actor", "koe", "--backup-dir", str(tmp_path)]) == 0
    db.expire_all()
    (alert,) = _alerts(db)
    assert _metadata(alert)["scanners"][SCANNER]["answered"] == 3 and backups == [str(tmp_path)]
    audit = db.scalars(select(AuditLog).where(AuditLog.action == "scanner_answers_counted")).one()
    assert (audit.actor, audit.target_value, audit.details["counted"]) == ("koe", str(alert.id), 3)
    assert "Counted: 3 scanners on 1 alerts." in capsys.readouterr().out

    assert command.main(["--apply"]) == 0 and backups == [str(tmp_path)], "nothing left to count: no backup"


def test_answers_are_counted_the_same_in_the_bounded_memory_mode_queued_jobs_use():
    db = _session()
    _answered_sweep(db)

    run_detection(db, limit=None, use_ml=False, actor="test", only_unchecked=True, bounded_memory=True)

    db.expire_all()
    scanners = _metadata(_alerts(db)[0])["scanners"]
    assert (scanners[SCANNER]["answered"], scanners[SCANNER]["answered_ports"]) == (3, [80])
    assert (scanners[SECOND_SCANNER]["answered"], scanners[SECOND_SCANNER]["answered_ping"]) == (5, 5)
