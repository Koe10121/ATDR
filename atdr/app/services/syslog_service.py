from collections.abc import Callable
import ipaddress
import logging
import socket
import time

from sqlalchemy.orm import Session

from atdr.app.core.config import get_settings
from atdr.app.db.database import SessionLocal, init_db
from atdr.app.db.models import AuditLog
from atdr.app.services.log_service import import_raw_log_line
from atdr.app.services.operation_run_service import complete_ingestion_run, start_ingestion_run
from atdr.app.services.runtime_parser_quality_service import (
    empty_runtime_parser_quality,
    merge_runtime_parser_quality,
)


logger = logging.getLogger(__name__)


def run_udp_syslog_receiver(
    host: str | None = None,
    port: int | None = None,
    batch_size: int | None = None,
    *,
    max_messages: int | None = None,
    socket_timeout: float | None = None,
    flush_seconds: float | None = None,
    session_factory: Callable[[], Session] | None = None,
    initialize_database: bool = True,
    on_ready: Callable[[], None] | None = None,
) -> dict:
    """Receive UDP syslog until max_messages datagrams, or until socket_timeout seconds pass without one.

    Every batch_size records are audited and saved. Records are also saved once the oldest unsaved one
    is flush_seconds old, so a quiet stream neither leaves them unsaved nor holds the database's write
    lock while the receiver waits for more traffic.
    """
    settings = get_settings()
    bind_host = host or settings.syslog_host
    bind_port = port or settings.syslog_port
    flush_every = batch_size or settings.syslog_batch_size
    save_within = flush_seconds or settings.syslog_flush_seconds

    if initialize_database:
        init_db()
    make_session = session_factory or SessionLocal
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    pending = 0
    received = 0
    parsed = 0
    failed = 0
    duplicates = 0
    parser_quality = empty_runtime_parser_quality()
    timed_out = False
    sender_hosts: set[str] = set()
    non_loopback_sender_observed = False
    try:
        sock.bind((bind_host, bind_port))
        logger.info("ATDR syslog receiver listening on %s:%s", bind_host, bind_port)
        if on_ready is not None:
            on_ready()

        with make_session() as db:
            run = start_ingestion_run(
                db,
                source_type="syslog_udp",
                input_name=f"udp:{bind_host}:{bind_port}",
                details={"batch_size": flush_every, "max_messages": max_messages},
            )
            # Save the run now: an open write would hold SQLite's only write lock while no traffic arrives.
            db.commit()
            last_datagram = time.monotonic()
            unsaved_since: float | None = None
            while max_messages is None or received < max_messages:
                deadlines = [] if socket_timeout is None else [last_datagram + socket_timeout]
                if unsaved_since is not None:
                    deadlines.append(unsaved_since + save_within)
                wait = min(deadlines) - time.monotonic() if deadlines else None
                datagram = None
                if wait is None or wait > 0:
                    sock.settimeout(wait)
                    try:
                        datagram = sock.recvfrom(65535)
                    except (TimeoutError, socket.timeout):
                        pass
                now = time.monotonic()
                if unsaved_since is not None and now - unsaved_since >= save_within:
                    db.commit()
                    unsaved_since = None
                if datagram is None:
                    if socket_timeout is not None and now - last_datagram >= socket_timeout:
                        timed_out = True
                        break
                    continue
                payload, address = datagram
                last_datagram = now
                line = payload.decode("utf-8", errors="replace").strip()
                if not line:
                    continue
                sender_host = str(address[0])
                sender_hosts.add(sender_host)
                try:
                    non_loopback_sender_observed = (
                        non_loopback_sender_observed
                        or not ipaddress.ip_address(sender_host).is_loopback
                    )
                except ValueError:
                    non_loopback_sender_observed = True
                result = import_raw_log_line(
                    db,
                    line,
                    source_name=f"syslog_udp:{address[0]}",
                    actor="syslog_receiver",
                    commit=False,
                    source_type="syslog_udp",
                    host=address[0],
                    port=address[1],
                )
                received += 1
                if not result.get("stored", True):
                    duplicates += 1
                else:
                    parsed += 1 if result["parsed"] else 0
                    failed += 0 if result["parsed"] else 1
                    parser_quality = merge_runtime_parser_quality(
                        parser_quality,
                        result.get("parser_quality"),
                    )
                pending += 1
                if pending >= flush_every:
                    db.add(
                        AuditLog(
                            actor="syslog_receiver",
                            action="ingest_syslog_batch",
                            target_type="syslog",
                            target_value=f"udp:{bind_host}:{bind_port}",
                            details={
                                "received": received,
                                "parsed": parsed,
                                "failed": failed,
                                "duplicates": duplicates,
                                "sender_count": len(sender_hosts),
                                "non_loopback_sender_observed": non_loopback_sender_observed,
                                "parser_quality": parser_quality,
                            },
                        )
                    )
                    db.commit()
                    pending = 0
                    unsaved_since = None
                elif unsaved_since is None:
                    unsaved_since = now
            if pending:
                db.add(
                    AuditLog(
                        actor="syslog_receiver",
                        action="ingest_syslog_batch",
                        target_type="syslog",
                        target_value=f"udp:{bind_host}:{bind_port}",
                        details={
                            "received": received,
                            "parsed": parsed,
                            "failed": failed,
                            "duplicates": duplicates,
                            "sender_count": len(sender_hosts),
                            "non_loopback_sender_observed": non_loopback_sender_observed,
                            "parser_quality": parser_quality,
                        },
                    )
                )
            complete_ingestion_run(
                db,
                run,
                total_lines_received=received,
                raw_logs_created=received - duplicates,
                parsed_successfully=parsed,
                parse_failures=failed,
                duplicate_raw_logs=duplicates,
                details={
                    "timed_out": timed_out,
                    "sender_count": len(sender_hosts),
                    "non_loopback_sender_observed": non_loopback_sender_observed,
                    "parser_quality": parser_quality,
                },
            )
            db.commit()
    finally:
        sock.close()

    return {
        "host": bind_host,
        "port": bind_port,
        "received": received,
        "parsed": parsed,
        "failed": failed,
        "duplicates": duplicates,
        "timed_out": timed_out,
        "sender_count": len(sender_hosts),
        "non_loopback_sender_observed": non_loopback_sender_observed,
        "parser_quality": parser_quality,
    }
