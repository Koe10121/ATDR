import argparse
import logging
import signal
import threading

from atdr.app.core.config import get_settings
from atdr.app.services.syslog_service import run_udp_syslog_receiver

# A receiver that stops by itself is started again after this pause, unless it was asked to stop.
RESTART_DELAY_SECONDS = 5.0

logger = logging.getLogger("atdr.syslog_receiver")


def _short_reason(exc: BaseException) -> str:
    """The error's kind and the database's own message, never the SQL parameters (they hold whole log lines)."""

    return f"{exc.__class__.__name__}: {str(getattr(exc, 'orig', None) or exc).splitlines()[0][:200]}"


def main() -> None:
    settings = get_settings()
    parser = argparse.ArgumentParser(description="Run the ATDR UDP syslog receiver.")
    parser.add_argument("--host", default=settings.syslog_host)
    parser.add_argument("--port", type=int, default=settings.syslog_port)
    parser.add_argument("--batch-size", type=int, default=settings.syslog_batch_size)
    parser.add_argument(
        "--flush-seconds",
        type=float,
        default=settings.syslog_flush_seconds,
        help="Save received records at most this many seconds after they arrive, even on a quiet stream.",
    )
    parser.add_argument("--max-messages", type=int, default=None, help="Stop after N datagrams. Useful for lab smoke tests.")
    parser.add_argument("--timeout", type=float, default=None, help="Stop after this many seconds without a datagram. Useful with --max-messages.")
    args = parser.parse_args()
    if args.flush_seconds <= 0:
        parser.error("--flush-seconds must be greater than zero")

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    lab_run = args.max_messages is not None or args.timeout is not None
    stop = threading.Event()
    for name in ("SIGINT", "SIGTERM", "SIGBREAK"):
        shutdown_signal = getattr(signal, name, None)
        if shutdown_signal is not None:
            signal.signal(shutdown_signal, lambda _signum, _frame: stop.set())

    while True:
        try:
            result = run_udp_syslog_receiver(
                host=args.host,
                port=args.port,
                batch_size=args.batch_size,
                flush_seconds=args.flush_seconds,
                max_messages=args.max_messages,
                socket_timeout=args.timeout,
                stop_event=stop,
            )
        except Exception as exc:
            if lab_run:
                raise
            logger.error("Syslog receiver stopped (%s); starting it again in %.0f s.", _short_reason(exc), RESTART_DELAY_SECONDS)
            if stop.wait(RESTART_DELAY_SECONDS):
                break
            continue
        if lab_run:
            print(result)
            break
        if stop.is_set():
            logger.info("Syslog receiver stopped on request: %s lines received, %s saved, %s dropped.", result["received"], result["saved"], result["dropped"])
            break


if __name__ == "__main__":
    main()
