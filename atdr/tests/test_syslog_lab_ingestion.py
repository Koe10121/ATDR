import socket
import threading
import time

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


def _file_database(tmp_path):
    """Two engines on one SQLite file: the receiver's, and a checker that gives up on a held lock fast."""
    url = f"sqlite:///{(tmp_path / 'syslog.db').as_posix()}"
    receiver_engine = create_engine(url, connect_args={"check_same_thread": False, "timeout": 5}, future=True)
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
