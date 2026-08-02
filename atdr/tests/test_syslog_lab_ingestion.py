import socket
import threading

from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from atdr.app.db.database import Base
from atdr.app.db.models import (
    AuditLog,
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
    assert result["received"] == 2
    assert result["parsed"] == 2
    assert result["sender_count"] == 1
    assert result["non_loopback_sender_observed"] is False
    assert result["parser_quality"]["observed_rows"] == 2
    with TestingSession() as db:
        assert db.scalar(select(func.count(RawLog.id))) == 2
        assert db.scalar(select(func.count(NormalizedLog.id))) == 2
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
        assert source.parse_success_count == 2
        assert source.parser_quality_json["observed_rows"] == 2
        assert audit.details["parser_quality"]["observed_rows"] == 2
