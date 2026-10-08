import socket
import sqlite3
import threading
import time
from datetime import datetime, timedelta, timezone

from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from atdr.app.core.config import Settings, validate_runtime_settings
from atdr.app.db.database import Base
from atdr.app.db.models import (
    AuditLog,
    IngestionRun,
    LogSource,
    NormalizedLog,
    RawLog,
    ResponseAction,
)
from atdr.app.services import syslog_service
from atdr.tests.test_parser import TRAFFIC_LINE


def _free_udp_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])
    finally:
        sock.close()


def test_udp_syslog_receiver_ingests_live_datagrams(monkeypatch):
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    Base.metadata.create_all(engine)
    TestingSession = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
    port = _free_udp_port()
    result: dict = {}
    ready = threading.Event()

    def receive() -> None:
        result.update(
            syslog_service.run_udp_syslog_receiver(
                host="127.0.0.1",
                port=port,
                batch_size=2,
                max_messages=2,
                socket_timeout=5,
                session_factory=TestingSession,
                initialize_database=False,
                on_ready=ready.set,
            )
        )

    thread = threading.Thread(target=receive)
    thread.start()
    assert ready.wait(2)
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sender.sendto(TRAFFIC_LINE.encode("utf-8"), ("127.0.0.1", port))
        sender.sendto(TRAFFIC_LINE.encode("utf-8"), ("127.0.0.1", port))
    finally:
        sender.close()
    thread.join(7)

    assert thread.is_alive() is False
    # The second datagram is a re-sent copy of the same Palo Alto record: received, counted, stored once.
    assert result["received"] == 2
    assert result["duplicates"] == 1
    assert result["parsed"] == 1
    assert result["sender_count"] == 1
    assert result["non_loopback_sender_observed"] is False
    assert result["parser_quality"]["observed_rows"] == 1
    with TestingSession() as db:
        assert db.scalar(select(func.count(RawLog.id))) == 1
        assert db.scalar(select(func.count(NormalizedLog.id))) == 1
        assert db.scalar(select(func.count(ResponseAction.id))) == 0
        audit = db.scalar(select(AuditLog).where(AuditLog.action == "ingest_syslog_batch"))
        source = db.scalar(select(LogSource).where(LogSource.source_type == "syslog_udp"))
        assert audit is not None
        assert audit.details["received"] == 2
        assert audit.details["sender_count"] == 1
        assert audit.details["non_loopback_sender_observed"] is False
        assert source is not None
        assert source.parser_profile == "palo_alto"
        assert source.logs_received_count == 2
        assert source.parse_success_count == 1
        assert source.parser_quality_json["observed_rows"] == 1
        assert audit.details["parser_quality"]["observed_rows"] == 1
        assert audit.details["duplicates"] == 1


def _file_database(tmp_path, receiver_lock_timeout: float = 5):
    """Two engines on one SQLite file: the receiver's, and a checker that gives up on a held lock fast."""
    url = f"sqlite:///{(tmp_path / 'syslog.db').as_posix()}"
    receiver_engine = create_engine(url, connect_args={"check_same_thread": False, "timeout": receiver_lock_timeout}, future=True)
    Base.metadata.create_all(receiver_engine)
    checker_engine = create_engine(url, connect_args={"timeout": 0.5}, future=True)
    return (
        sessionmaker(bind=receiver_engine, autoflush=False, autocommit=False, future=True),
        sessionmaker(bind=checker_engine, autoflush=False, autocommit=False, future=True),
    )


def _start_receiver(session_factory, port: int, **options) -> tuple[threading.Thread, dict]:
    result: dict = {}
    ready = threading.Event()

    def receive() -> None:
        result.update(
            syslog_service.run_udp_syslog_receiver(
                host="127.0.0.1",
                port=port,
                session_factory=session_factory,
                initialize_database=False,
                on_ready=ready.set,
                **options,
            )
        )

    thread = threading.Thread(target=receive, daemon=True)
    thread.start()
    assert ready.wait(2)
    return thread, result


def _stored_raw_logs(checker) -> int:
    with checker() as db:
        return int(db.scalar(select(func.count(RawLog.id))) or 0)


def test_udp_syslog_receiver_saves_a_quiet_stream_without_holding_the_database(tmp_path):
    receiver_session, checker = _file_database(tmp_path)
    port = _free_udp_port()
    thread, result = _start_receiver(
        receiver_session, port, batch_size=100, max_messages=2, socket_timeout=10, flush_seconds=0.2
    )
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Waiting for traffic, the receiver has saved its run and holds no write lock.
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            with checker() as db:
                if db.scalar(select(func.count(IngestionRun.id))):
                    break
            time.sleep(0.05)
        with checker() as db:
            db.add(AuditLog(actor="checker", action="lock_check", target_type="test", target_value="idle", details={}))
            db.commit()
        sender.sendto(TRAFFIC_LINE.encode("utf-8"), ("127.0.0.1", port))
        # One record and then silence: it is saved within the flush time, not when a batch of 100 fills
        # or the receiver stops.
        deadline = time.monotonic() + 5
        while _stored_raw_logs(checker) == 0 and time.monotonic() < deadline:
            time.sleep(0.05)
        assert _stored_raw_logs(checker) == 1
        assert thread.is_alive()
        # Nothing is left unsaved, so another writer gets the database at once instead of "database is locked".
        with checker() as db:
            db.add(AuditLog(actor="checker", action="lock_check", target_type="test", target_value="syslog", details={}))
            db.commit()
        sender.sendto(TRAFFIC_LINE.encode("utf-8"), ("127.0.0.1", port))
    finally:
        sender.close()
    thread.join(5)

    assert thread.is_alive() is False
    assert result["received"] == 2
    assert result["duplicates"] == 1
    assert result["timed_out"] is False
    with checker() as db:
        assert db.scalar(select(func.count(RawLog.id))) == 1
        assert db.scalar(select(func.count(AuditLog.id)).where(AuditLog.action == "ingest_syslog_batch")) == 1
        assert db.scalar(select(func.count(AuditLog.id)).where(AuditLog.action == "lock_check")) == 2


def test_udp_syslog_receiver_saves_a_steady_trickle_before_its_batch_fills(tmp_path):
    receiver_session, checker = _file_database(tmp_path)
    port = _free_udp_port()
    thread, result = _start_receiver(
        receiver_session, port, batch_size=100, max_messages=12, socket_timeout=10, flush_seconds=0.3
    )
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # A datagram every 0.1 s never leaves the stream idle for the 0.3 s flush time.
        for index in range(10):
            sender.sendto(f"<14>Oct  1 10:00:{index:02d} lab-host app: trickle {index}".encode("utf-8"), ("127.0.0.1", port))
            time.sleep(0.1)
        deadline = time.monotonic() + 0.2
        while _stored_raw_logs(checker) == 0 and time.monotonic() < deadline:
            time.sleep(0.02)
        assert _stored_raw_logs(checker) >= 1
        assert thread.is_alive()
        for index in range(10, 12):
            sender.sendto(f"<14>Oct  1 10:00:{index:02d} lab-host app: trickle {index}".encode("utf-8"), ("127.0.0.1", port))
    finally:
        sender.close()
    thread.join(5)

    assert thread.is_alive() is False
    assert result["received"] == 12
    assert _stored_raw_logs(checker) == 12


def test_syslog_flush_time_must_be_positive():
    assert "SYSLOG_FLUSH_SECONDS must be greater than zero." in validate_runtime_settings(Settings(SYSLOG_FLUSH_SECONDS=0))
    assert "SYSLOG_FLUSH_SECONDS must be greater than zero." not in validate_runtime_settings(Settings())


def test_syslog_receiver_sizes_must_be_positive():
    for name in ("SYSLOG_BATCH_SIZE", "SYSLOG_MAX_PENDING_LINES", "SYSLOG_RECEIVE_BUFFER_BYTES", "SYSLOG_STATUS_SECONDS"):
        assert f"{name} must be greater than zero." in validate_runtime_settings(Settings(**{name: 0}))
        assert f"{name} must be greater than zero." not in validate_runtime_settings(Settings())


def _distinct_traffic_lines(count: int) -> list[str]:
    """Distinct Palo Alto records of realistic size: the same traffic line with its own session number."""
    return [TRAFFIC_LINE.replace("35845233", str(35845233 + index)) for index in range(count)]


def _send(port: int, lines: list[str], per_second: float) -> None:
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    started = time.monotonic()
    try:
        for index, line in enumerate(lines):
            due = started + index / per_second
            if due > time.monotonic():
                time.sleep(due - time.monotonic())
            sender.sendto(line.encode("utf-8"), ("127.0.0.1", port))
    finally:
        sender.close()


def _hold_write_lock(tmp_path):
    """Another writer that keeps SQLite's only write lock, as a detection run writing its alerts does."""
    holder = sqlite3.connect(str(tmp_path / "syslog.db"), timeout=5, isolation_level=None)
    holder.execute("BEGIN IMMEDIATE")
    return holder


def test_receiver_keeps_every_line_while_another_writer_holds_the_database(tmp_path):
    # The receiver gives up on the lock after 0.3 s; before, that "database is locked" ended the receiver,
    # and lines arriving meanwhile overflowed the operating system's socket buffer unnoticed.
    receiver_session, checker = _file_database(tmp_path, receiver_lock_timeout=0.3)
    port = _free_udp_port()
    lines = _distinct_traffic_lines(2000)
    thread, result = _start_receiver(
        receiver_session, port, batch_size=200, max_messages=len(lines), socket_timeout=10, flush_seconds=0.2
    )
    holder = _hold_write_lock(tmp_path)
    try:
        _send(port, lines, per_second=2000)
        time.sleep(1.0)
        assert thread.is_alive(), "the receiver must wait out a busy database, not end"
    finally:
        holder.execute("ROLLBACK")
        holder.close()
    thread.join(20)

    assert thread.is_alive() is False
    assert result["received"] == len(lines)
    assert result["saved"] == len(lines)
    assert result["dropped"] == 0
    assert result["unstorable"] == 0
    assert result["busy_retries"] > 0
    assert _stored_raw_logs(checker) == len(lines)


def test_receiver_counts_the_lines_it_has_no_room_for(tmp_path):
    receiver_session, checker = _file_database(tmp_path, receiver_lock_timeout=0.2)
    port = _free_udp_port()
    lines = _distinct_traffic_lines(300)
    thread, result = _start_receiver(
        receiver_session, port, batch_size=10, max_messages=len(lines), socket_timeout=10, flush_seconds=0.1,
        max_pending=50,
    )
    holder = _hold_write_lock(tmp_path)
    try:
        _send(port, lines, per_second=1000)
        time.sleep(0.5)
    finally:
        holder.execute("ROLLBACK")
        holder.close()
    thread.join(20)

    assert thread.is_alive() is False
    # Every line is accounted for: saved, or dropped and counted because memory already held 50 waiting lines.
    assert result["received"] == len(lines)
    assert result["dropped"] > 0
    assert result["saved"] + result["dropped"] == len(lines)
    assert _stored_raw_logs(checker) == result["saved"]
    with checker() as db:
        run = db.get(IngestionRun, result["run_id"])
        audit = db.scalar(select(AuditLog).where(AuditLog.action == "ingest_syslog_batch"))
        assert run.details_json["dropped"] == result["dropped"]
        assert audit.details["dropped"] == result["dropped"]


def test_receiver_reports_its_counts_while_it_runs_and_stops_when_asked(tmp_path):
    receiver_session, checker = _file_database(tmp_path)
    port = _free_udp_port()
    stop = threading.Event()
    thread, result = _start_receiver(
        receiver_session, port, batch_size=100, socket_timeout=30, flush_seconds=0.1, status_seconds=0.2, stop_event=stop
    )
    _send(port, _distinct_traffic_lines(30), per_second=300)
    reported = None
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        with checker() as db:
            run = db.scalar(select(IngestionRun).where(IngestionRun.source_type == "syslog_udp"))
            if run is not None and run.raw_logs_created == 30:
                reported = (run.status, run.total_lines_received, dict(run.details_json))
                break
        time.sleep(0.1)
    assert thread.is_alive()
    assert reported is not None, "the run's counts are saved while the receiver runs, not only when it stops"
    status, received, details = reported
    assert (status, received) == ("running", 30)
    assert details["status"] == "receiving"
    assert details["dropped"] == 0
    assert details["last_received_at"]

    stop.set()
    thread.join(5)
    assert thread.is_alive() is False
    assert result["received"] == 30
    assert result["timed_out"] is False
    with checker() as db:
        run = db.get(IngestionRun, result["run_id"])
        assert run.status == "completed"
        assert run.details_json["status"] == "stopped"


def test_receiver_closes_a_run_left_open_when_its_process_ended(tmp_path):
    receiver_session, checker = _file_database(tmp_path)
    now = datetime.now(timezone.utc)
    with checker() as db:
        db.add(IngestionRun(
            source_type="syslog_udp", input_name="udp:127.0.0.1:5514", status="running", started_at=now - timedelta(hours=1),
            total_lines_received=7, raw_logs_created=7, details_json={"reported_at": (now - timedelta(hours=1)).isoformat()},
        ))
        # Another receiver, on another port, still reporting: its run is left alone.
        db.add(IngestionRun(
            source_type="syslog_udp", input_name="udp:127.0.0.1:5600", status="running", started_at=now - timedelta(minutes=5),
            details_json={"reported_at": now.isoformat()},
        ))
        db.commit()
    port = _free_udp_port()
    thread, result = _start_receiver(receiver_session, port, max_messages=1, socket_timeout=10, flush_seconds=0.1)
    _send(port, _distinct_traffic_lines(1), per_second=10)
    thread.join(5)

    assert thread.is_alive() is False
    with checker() as db:
        runs = list(db.scalars(select(IngestionRun).order_by(IngestionRun.id)))
        assert [run.status for run in runs] == ["stopped", "running", "completed"]
        assert runs[0].total_lines_received == 7
        assert "process ended" in runs[0].error_summary
        assert runs[2].id == result["run_id"]


def test_a_receiver_stopped_while_the_database_stays_busy_gives_up_once_for_the_whole_stop(tmp_path, monkeypatch):
    # Giving up on one batch while the rest each waited as long again, a receiver holding 100,000 lines in
    # batches of 1,000 could take 100 limits to stop.
    monkeypatch.setattr(syslog_service, "STOPPING_BUSY_LIMIT_SECONDS", 1.0)
    receiver_session, _checker = _file_database(tmp_path, receiver_lock_timeout=0.1)
    port = _free_udp_port()
    stop = threading.Event()
    thread, result = _start_receiver(receiver_session, port, batch_size=10, socket_timeout=30, flush_seconds=0.05, stop_event=stop)
    holder = _hold_write_lock(tmp_path)
    try:
        _send(port, _distinct_traffic_lines(50), per_second=500)
        time.sleep(0.3)
        stop.set()
        time.sleep(3.5)
    finally:
        holder.execute("ROLLBACK")
        holder.close()
    thread.join(15)

    assert thread.is_alive() is False
    assert result["received"] == 50
    # One limit for the whole stop: everything still unsaved when it ran out is dropped and counted.
    assert (result["saved"], result["dropped"]) == (0, 50)


def test_the_receiver_service_starts_again_after_a_failure_without_logging_log_lines(monkeypatch, caplog):
    import logging
    import sys

    from sqlalchemy.exc import IntegrityError

    from atdr.scripts import run_syslog_receiver as script

    calls = []

    def receiver(**options):
        calls.append(options)
        if len(calls) == 1:
            raise IntegrityError("INSERT INTO raw_logs ...", {"raw_line": "198.51.100.10 secret line"}, Exception("constraint failed"))
        options["stop_event"].set()
        return {"received": 3, "saved": 3, "dropped": 0}

    monkeypatch.setattr(script, "run_udp_syslog_receiver", receiver)
    monkeypatch.setattr(script, "RESTART_DELAY_SECONDS", 0.01)
    monkeypatch.setattr(script.signal, "signal", lambda *_args: None)
    monkeypatch.setattr(sys, "argv", ["run_syslog_receiver"])
    with caplog.at_level(logging.INFO, logger="atdr.syslog_receiver"):
        script.main()

    assert len(calls) == 2, "a receiver that fails is started again"
    logged = caplog.text
    assert "starting it again" in logged and "constraint failed" in logged
    assert "198.51.100.10" not in logged and "secret line" not in logged


def test_the_page_is_told_whether_the_live_feed_is_receiving_and_what_was_lost():
    from datetime import datetime, timedelta, timezone

    from atdr.app.core.config import get_settings
    from atdr.app.services.syslog_service import live_feed_status

    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool, future=True)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
    now = datetime(2026, 10, 8, 12, 0, tzinfo=timezone.utc)
    on = get_settings().model_copy(update={"syslog_enabled": True, "syslog_status_seconds": 10.0})
    off = on.model_copy(update={"syslog_enabled": False})
    with session() as db:
        assert live_feed_status(db, settings=off, now=now)["state"] == "off"
        assert live_feed_status(db, settings=on, now=now)["state"] == "not_started"
        run = IngestionRun(
            source_type="syslog_udp", input_name="udp:0.0.0.0:5514", status="running", started_at=now - timedelta(hours=1),
            total_lines_received=1200, raw_logs_created=1150,
            details_json={"dropped": 50, "lines_per_second": 600.0, "reported_at": (now - timedelta(seconds=5)).isoformat(),
                          "last_received_at": (now - timedelta(seconds=1)).isoformat()},
        )
        db.add(run)
        db.commit()
        receiving = live_feed_status(db, settings=on, now=now)
        assert {key: receiving[key] for key in ("state", "received", "saved", "dropped", "lines_per_second")} == {
            "state": "receiving", "received": 1200, "saved": 1150, "dropped": 50, "lines_per_second": 600.0,
        }
        # Three reports missed (every 10 s, so 30 s): the receiver's process is gone although its run says running.
        assert live_feed_status(db, settings=on, now=now + timedelta(seconds=26))["state"] == "not_reporting"
        assert live_feed_status(db, settings=off, now=now)["state"] == "receiving", "a running receiver shows even if switched off since"
        run.status = "stopped"
        db.commit()
        assert live_feed_status(db, settings=on, now=now)["state"] == "stopped"
        assert live_feed_status(db, settings=off, now=now)["state"] == "off"


def _stored_rows(session_factory) -> list[tuple]:
    raw_columns = [column for column in RawLog.__table__.columns if column.key not in {"id", "imported_at"}]
    normalized_columns = [column for column in NormalizedLog.__table__.columns if column.key not in {"id", "raw_log_id"}]
    with session_factory() as db:
        return [
            tuple(getattr(raw, column.key) for column in raw_columns) + tuple(getattr(raw.normalized, column.key) for column in normalized_columns)
            for raw in db.scalars(select(RawLog).order_by(RawLog.id))
        ]


def test_store_parsed_batch_writes_the_rows_persist_parsed_log_writes(tmp_path):
    from atdr.app.parsers.paloalto_parser import parse_log_line_for_profile
    from atdr.app.services.log_service import (
        _existing_raw_log_id,
        is_repeat_of_stored_record,
        persist_parsed_log,
        store_parsed_batch,
    )
    from atdr.tests.test_parser import SYSTEM_LINE, THREAT_LINE

    partial = "2026-05-20T13:36:19+07:00 lab-fw.example.invalid 1,not,a,complete,record"
    broken = "unparseable-line"
    lines = [TRAFFIC_LINE, THREAT_LINE, SYSTEM_LINE, partial, broken, TRAFFIC_LINE, broken, partial]
    for profile in (None, "generic_syslog"):
        one_at_a_time = sessionmaker(bind=create_engine(f"sqlite:///{(tmp_path / f'single-{profile}.db').as_posix()}", future=True), autoflush=False, future=True)
        batched = sessionmaker(bind=create_engine(f"sqlite:///{(tmp_path / f'batch-{profile}.db').as_posix()}", future=True), autoflush=False, future=True)
        for factory in (one_at_a_time, batched):
            Base.metadata.create_all(factory.kw["bind"])
        # Twice: the second round meets every line already stored.
        for _round in range(2):
            with one_at_a_time() as db:
                for line in lines:
                    parsed = parse_log_line_for_profile(line, profile)
                    if _existing_raw_log_id(db, parsed.raw_line) is not None and is_repeat_of_stored_record(parsed, profile):
                        continue
                    persist_parsed_log(db, parsed, source_id=3)
                    db.flush()
                db.commit()
            with batched() as db:
                stored = store_parsed_batch(db, [parse_log_line_for_profile(line, profile) for line in lines], source_id=3, parser_profile=profile)
                db.commit()
            assert stored.stored + stored.skipped_repeats == len(lines)

        rows = _stored_rows(batched)
        assert rows == _stored_rows(one_at_a_time)
        if profile is None:
            # Palo Alto records, partial ones included, are stored once; a line that did not parse is kept every
            # time it arrives.
            assert len(rows) == 4 + 4
        else:
            assert len(rows) == 2 * len(lines)
