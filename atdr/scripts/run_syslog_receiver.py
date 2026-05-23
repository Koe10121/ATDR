import argparse
import logging

from atdr.app.core.config import get_settings
from atdr.app.services.syslog_service import run_udp_syslog_receiver


def main() -> None:
    settings = get_settings()
    parser = argparse.ArgumentParser(description="Run the ATDR UDP syslog receiver for lab ingestion.")
    parser.add_argument("--host", default=settings.syslog_host)
    parser.add_argument("--port", type=int, default=settings.syslog_port)
    parser.add_argument("--batch-size", type=int, default=settings.syslog_batch_size)
    parser.add_argument("--max-messages", type=int, default=None, help="Stop after N datagrams. Useful for lab smoke tests.")
    parser.add_argument("--timeout", type=float, default=None, help="Socket timeout in seconds. Useful with --max-messages.")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    result = run_udp_syslog_receiver(
        host=args.host,
        port=args.port,
        batch_size=args.batch_size,
        max_messages=args.max_messages,
        socket_timeout=args.timeout,
    )
    if args.max_messages is not None or args.timeout is not None:
        print(result)


if __name__ == "__main__":
    main()
