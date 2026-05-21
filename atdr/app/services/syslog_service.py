import logging
import socket

from atdr.app.core.config import get_settings
from atdr.app.db.database import SessionLocal, init_db
from atdr.app.services.log_service import import_raw_log_line


logger = logging.getLogger(__name__)


def run_udp_syslog_receiver(host: str | None = None, port: int | None = None, batch_size: int | None = None) -> None:
    settings = get_settings()
    bind_host = host or settings.syslog_host
    bind_port = port or settings.syslog_port
    flush_every = batch_size or settings.syslog_batch_size

    init_db()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((bind_host, bind_port))
    logger.info("ATDR syslog receiver listening on %s:%s", bind_host, bind_port)

    pending = 0
    with SessionLocal() as db:
        while True:
            payload, address = sock.recvfrom(65535)
            line = payload.decode("utf-8", errors="replace").strip()
            if not line:
                continue
            import_raw_log_line(
                db,
                line,
                source_name=f"udp:{address[0]}:{address[1]}",
                actor="syslog_receiver",
                commit=False,
            )
            pending += 1
            if pending >= flush_every:
                db.commit()
                pending = 0
