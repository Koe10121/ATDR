import logging
import socket

from atdr.app.core.config import get_settings
from atdr.app.db.database import SessionLocal, init_db
from atdr.app.db.models import AuditLog
from atdr.app.services.log_service import import_raw_log_line


logger = logging.getLogger(__name__)


def run_udp_syslog_receiver(
    host: str | None = None,
    port: int | None = None,
    batch_size: int | None = None,
    *,
    max_messages: int | None = None,
    socket_timeout: float | None = None,
) -> dict:
    settings = get_settings()
    bind_host = host or settings.syslog_host
    bind_port = port or settings.syslog_port
    flush_every = batch_size or settings.syslog_batch_size

    init_db()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    if socket_timeout is not None:
        sock.settimeout(socket_timeout)

    pending = 0
    received = 0
    parsed = 0
    failed = 0
    timed_out = False
    try:
        sock.bind((bind_host, bind_port))
        logger.info("ATDR syslog receiver listening on %s:%s", bind_host, bind_port)

        with SessionLocal() as db:
            while max_messages is None or received < max_messages:
                try:
                    payload, address = sock.recvfrom(65535)
                except (TimeoutError, socket.timeout):
                    timed_out = True
                    break
                line = payload.decode("utf-8", errors="replace").strip()
                if not line:
                    continue
                result = import_raw_log_line(
                    db,
                    line,
                    source_name=f"udp:{address[0]}:{address[1]}",
                    actor="syslog_receiver",
                    commit=False,
                )
                received += 1
                parsed += 1 if result["parsed"] else 0
                failed += 0 if result["parsed"] else 1
                pending += 1
                if pending >= flush_every:
                    db.add(
                        AuditLog(
                            actor="syslog_receiver",
                            action="ingest_syslog_batch",
                            target_type="syslog",
                            target_value=f"udp:{bind_host}:{bind_port}",
                            details={"received": received, "parsed": parsed, "failed": failed},
                        )
                    )
                    db.commit()
                    pending = 0
            if pending:
                db.add(
                    AuditLog(
                        actor="syslog_receiver",
                        action="ingest_syslog_batch",
                        target_type="syslog",
                        target_value=f"udp:{bind_host}:{bind_port}",
                        details={"received": received, "parsed": parsed, "failed": failed},
                    )
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
        "timed_out": timed_out,
    }
