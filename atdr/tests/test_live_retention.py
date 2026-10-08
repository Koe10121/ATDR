"""Live syslog logs are summarised by hour and deleted after SYSLOG_RETENTION_HOURS; nothing else is touched."""

from __future__ import annotations

import itertools
from datetime import datetime, timedelta, timezone

from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from atdr.app.core.config import Settings, get_settings, validate_runtime_settings
from atdr.app.db.database import Base
from atdr.app.db.models import (
    Alert,
    AlertEvidence,
    AuditLog,
    LogSource,
    MLLabel,
    NormalizedLog,
    RawLog,
    TrafficHourlySummary,
)
from atdr.app.services import operation_worker, retention_service
from atdr.app.services.retention_service import RetentionProgress, run_live_retention

NOW = datetime(2026, 10, 8, 12, 30, tzinfo=timezone.utc)
_lines = itertools.count(1)


def _session():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool, future=True)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)()


def _source(db, name: str, source_type: str) -> int:
    source = LogSource(name=name, source_type=source_type, parser_profile="palo_alto", enabled=True)
    db.add(source)
    db.flush()
    return int(source.id)


def _log(db, source_id: int, imported_at: datetime, src_ip: str, *, action: str = "allow", dst_port: int = 443,
         checked: bool = True) -> NormalizedLog:
    raw = RawLog(source_id=source_id, raw_line=f"retention test line {next(_lines)}", imported_at=imported_at)
    db.add(raw)
    db.flush()
    log = NormalizedLog(
        raw_log_id=raw.id, generated_time=imported_at - timedelta(seconds=2), src_ip=src_ip, dst_ip="203.0.113.5",
        dst_port=dst_port, action=action, bytes_sent=100, bytes_received=200, parsed_json={},
        last_detection_run_id=1 if checked else None,
    )
    db.add(log)
    db.flush()
    return log


def _settings(**overrides):
    return get_settings().model_copy(update={"syslog_retention_hours": 6.0, "syslog_summary_retention_days": 30, **overrides})


def _at(hour: int, minute: int) -> datetime:
    return NOW.replace(hour=hour, minute=minute)


def _live_lines(db, live: int) -> set[str]:
    return set(db.scalars(select(RawLog.raw_line).where(RawLog.source_id == live)))


def test_live_logs_past_the_limit_are_summarised_by_hour_then_deleted_and_nothing_else_is_touched():
    db = _session()
    live = _source(db, "syslog_udp:198.51.100.1", "syslog_udp")
    imported = _source(db, "mfu-export.log", "file_import")
    # 04:00-05:00, more than six hours ago: two connections from .1 and a denied one from .2.
    _log(db, live, _at(4, 10), "10.0.0.1")
    _log(db, live, _at(4, 11), "10.0.0.1")
    _log(db, live, _at(4, 12), "10.0.0.2", action="deny", dst_port=22)
    # 05:00-06:00: an ordinary log, then one detection has not checked yet, alert evidence and a labelled log.
    ordinary = _log(db, live, _at(5, 20), "10.0.0.1", dst_port=80)
    unchecked = _log(db, live, _at(5, 25), "10.0.0.3", checked=False)
    evidence = _log(db, live, _at(5, 30), "10.0.0.4")
    labelled = _log(db, live, _at(5, 40), "10.0.0.5")
    # 06:10 is past six hours, but its hour ends after the limit: it waits for the whole hour.
    late_in_hour = _log(db, live, _at(6, 10), "10.0.0.1")
    recent = _log(db, live, _at(11, 0), "10.0.0.1")
    old_import = _log(db, imported, _at(1, 0), "10.0.0.1")
    alert = Alert(title="t", alert_type="possible_port_scan", src_ip="10.0.0.4", threat_score=50, severity="High",
                  status="open", explanation="t", matched_rules_json=[], recommended_response="t")
    db.add(alert)
    db.flush()
    db.add(AlertEvidence(alert_id=alert.id, normalized_log_id=evidence.id))
    db.add(MLLabel(log_id=labelled.id, label="benign", attack_type="none", confidence=3, reviewer="team"))
    db.commit()
    kept_lines = {log.raw_log.raw_line for log in (unchecked, evidence, labelled, late_in_hour, recent)}
    ordinary_id, old_import_id = ordinary.id, old_import.id

    progress = RetentionProgress()
    result = run_live_retention(db, settings=_settings(), now=NOW, progress=progress)

    assert (result["hours_summarised"], result["logs_deleted"]) == (2, 4)
    assert _live_lines(db, live) == kept_lines
    assert db.scalar(select(func.count(RawLog.id)).where(RawLog.source_id == imported)) == 1, "imports are never deleted"
    assert db.scalar(select(func.count(NormalizedLog.id)).where(NormalizedLog.id == old_import_id)) == 1
    summaries = {
        (row.hour_start.hour, row.src_ip): (row.connections, row.denied, row.bytes_sent, row.destination_ports)
        for row in db.scalars(select(TrafficHourlySummary))
    }
    assert summaries == {
        (4, "10.0.0.1"): (2, 0, 200, 1),
        (4, "10.0.0.2"): (1, 1, 100, 1),
        # Every log received in the hour is counted, including those that are kept.
        (5, "10.0.0.1"): (1, 0, 100, 1),
        (5, "10.0.0.3"): (1, 0, 100, 1),
        (5, "10.0.0.4"): (1, 0, 100, 1),
        (5, "10.0.0.5"): (1, 0, 100, 1),
    }
    assert db.scalar(select(func.count(AuditLog.id)).where(AuditLog.action == "live_logs_retained")) == 1
    assert db.scalar(select(func.count(NormalizedLog.id)).where(NormalizedLog.id == ordinary_id)) == 0

    again = run_live_retention(db, settings=_settings(), now=NOW, progress=progress)
    assert (again["hours_summarised"], again["logs_deleted"]) == (0, 0)
    assert db.scalar(select(func.count(TrafficHourlySummary.id))) == 6

    # An hour later 06:00-07:00 is past the limit, and the log detection has checked since goes too.
    unchecked.last_detection_run_id = 2
    db.commit()
    later = run_live_retention(db, settings=_settings(), now=NOW + timedelta(hours=1), progress=progress)
    assert (later["hours_summarised"], later["logs_deleted"]) == (1, 2)
    assert _live_lines(db, live) == {log.raw_log.raw_line for log in (evidence, labelled, recent)}


def test_summaries_past_their_limit_go_but_each_source_keeps_its_newest_hour():
    db = _session()
    live = _source(db, "syslog_udp:198.51.100.1", "syslog_udp")
    for hours_ago in (80, 79):
        db.add(TrafficHourlySummary(hour_start=(NOW - timedelta(hours=hours_ago)).replace(minute=0), source_id=live,
                                    src_ip="10.0.0.1", connections=1, denied=0, bytes_sent=1, bytes_received=1,
                                    destinations=1, destination_ports=1))
    db.commit()

    result = run_live_retention(db, settings=_settings(syslog_summary_retention_days=1), now=NOW)

    assert result["summaries_pruned"] == 1
    assert [row.hour_start.hour for row in db.scalars(select(TrafficHourlySummary))] == [(NOW - timedelta(hours=79)).hour]


def test_with_no_limit_every_live_log_is_kept():
    db = _session()
    live = _source(db, "syslog_udp:198.51.100.1", "syslog_udp")
    _log(db, live, NOW - timedelta(days=3), "10.0.0.1")
    db.commit()

    assert run_live_retention(db, settings=_settings(syslog_retention_hours=0), now=NOW) == {"enabled": False, "more_due": False}
    assert db.scalar(select(func.count(RawLog.id))) == 1


def test_a_pass_that_runs_out_of_time_says_more_is_due(monkeypatch):
    db = _session()
    live = _source(db, "syslog_udp:198.51.100.1", "syslog_udp")
    for minute in range(3):
        _log(db, live, _at(4, minute), "10.0.0.1")
    db.commit()
    monkeypatch.setattr(retention_service, "DELETE_CHUNK", 1)

    first = run_live_retention(db, settings=_settings(), now=NOW, budget_seconds=0)
    assert first["more_due"] is True and first["logs_deleted"] == 0
    done = run_live_retention(db, settings=_settings(), now=NOW)
    assert done["more_due"] is False and done["logs_deleted"] == 3


def test_the_worker_looks_again_at_once_when_more_is_due_and_a_failed_pass_never_stops_it(monkeypatch):
    calls: list[str] = []

    class _Session:
        def __enter__(self):
            return object()

        def __exit__(self, *_exc):
            return False

    monkeypatch.setattr(operation_worker, "SessionLocal", _Session)
    monkeypatch.setattr(operation_worker, "get_settings", lambda: _settings())

    def more(_db, **_kwargs):
        calls.append("more")
        return {"more_due": True}

    monkeypatch.setattr(operation_worker, "run_live_retention", more)
    before = operation_worker.time.monotonic()
    assert operation_worker._retention_look(0.0, RetentionProgress()) <= operation_worker.time.monotonic()

    def broken(_db, **_kwargs):
        calls.append("broken")
        raise RuntimeError("database file is gone")

    monkeypatch.setattr(operation_worker, "run_live_retention", broken)
    next_look = operation_worker._retention_look(0.0, RetentionProgress())
    assert next_look >= before + retention_service.RETENTION_EVERY_SECONDS - 1
    assert calls == ["more", "broken"]
    # Not due yet: no pass at all.
    assert operation_worker._retention_look(next_look, RetentionProgress()) == next_look
    assert calls == ["more", "broken"]


def test_retention_settings_cannot_be_negative():
    for name in ("SYSLOG_RETENTION_HOURS", "SYSLOG_SUMMARY_RETENTION_DAYS", "SYSLOG_MIN_FREE_DISK_GB"):
        assert f"{name} cannot be negative." in validate_runtime_settings(Settings(**{name: -1}))
        assert f"{name} cannot be negative." not in validate_runtime_settings(Settings())


def test_stored_logs_leave_out_the_fields_of_the_line_and_the_api_reads_them_again():
    from atdr.app.db.database import get_db
    from atdr.app.main import app
    from atdr.app.parsers.paloalto_parser import parse_log_line_for_profile
    from atdr.app.services.log_service import persist_parsed_log
    from atdr.tests.test_api import _client, _login
    from atdr.tests.test_parser import TRAFFIC_LINE

    client = _client()
    try:
        sessions = app.dependency_overrides[get_db]
        db_iter = sessions()
        db = next(db_iter)
        parsed = parse_log_line_for_profile(TRAFFIC_LINE, None)
        stored = persist_parsed_log(db, parsed)
        db.commit()
        log_id = stored.id
        assert "payload_fields" not in db.get(NormalizedLog, log_id).parsed_json
        admin = _login(client, "admin", "admin123")
        detail = client.get(f"/api/logs/{log_id}", headers=admin).json()
        listed = client.get("/api/logs", headers=admin).json()
    finally:
        app.dependency_overrides.clear()

    assert detail["parsed_json"] == parsed.parsed_json
    assert list(detail["parsed_json"]) == list(parsed.parsed_json), "the fields come back in their place"
    assert [row["parsed_json"] for row in listed if row["id"] == log_id] == [parsed.parsed_json]


def test_the_hourly_summaries_api_lists_the_newest_hour_first_for_one_address():
    from atdr.app.db.database import get_db
    from atdr.app.main import app
    from atdr.tests.test_api import _client, _login

    client = _client()
    try:
        db = next(app.dependency_overrides[get_db]())
        for hours_ago, src_ip, connections in ((9, "10.0.0.1", 5), (8, "10.0.0.1", 7), (8, "10.0.0.2", 900)):
            db.add(TrafficHourlySummary(hour_start=(NOW - timedelta(hours=hours_ago)).replace(minute=0), source_id=1,
                                        src_ip=src_ip, connections=connections, denied=0, bytes_sent=10, bytes_received=20,
                                        destinations=2, destination_ports=1))
        db.commit()
        analyst = _login(client, "analyst", "analyst123")
        everyone = client.get("/api/logs/hourly-summaries", headers=analyst)
        one = client.get("/api/logs/hourly-summaries", params={"src_ip": "10.0.0.1"}, headers=analyst)
    finally:
        app.dependency_overrides.clear()

    assert everyone.status_code == 200 and everyone.headers["X-Total-Count"] == "3"
    assert [row["connections"] for row in everyone.json()] == [900, 7, 5]
    assert one.headers["X-Total-Count"] == "2"
    assert [row["connections"] for row in one.json()] == [7, 5]
