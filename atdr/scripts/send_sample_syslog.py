import argparse
import json
import socket
import time
from typing import Any

from atdr.app.core.config import get_settings


SAMPLE_SYSLOG_LINE = (
    '2026-05-20T13:36:16+07:00 lab-fw.example.invalid '
    '1,2026/05/20 13:36:15,000000000001,TRAFFIC,end,2561,2026/05/20 13:36:15,'
    '198.51.100.10,203.0.113.20,0.0.0.0,0.0.0.0,Synthetic-Allow-Test,,,ping,'
    'vsys1,Outside-Lab,Inside-Lab,ethernet1/1,ethernet1/2,Synthetic-Forwarding,'
    '2026/05/20 13:36:15,35845233,1,0,0,0,0,0x100019,icmp,allow,172,86,86,2,'
    '2026/05/20 13:36:02,0,any,,7588383920033660891,0x0,TEST-NET,TEST-NET,,1,1,'
    'aged-out,0,0,0,0,vsys1,LAB-FW,from-policy,,,0,,0,,N/A,0,0,0,0,'
    '00000000-0000-4000-8000-000000000001,0,0,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,'
    '2026-05-20T13:36:16.534+07:00,,,internet-utility,general-internet,network-protocol,'
    '2,"has-known-vulnerability,tunnel-other-application,pervasive-use",,untunneled,no,no,0'
)


def send_sample_syslog(
    *,
    host: str | None = None,
    port: int | None = None,
    count: int = 1,
    delay_seconds: float = 0.1,
    line: str = SAMPLE_SYSLOG_LINE,
) -> dict[str, Any]:
    settings = get_settings()
    target_host = host or settings.syslog_host
    target_port = port or settings.syslog_port
    payload = line.encode("utf-8")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sent = 0
    try:
        for _ in range(max(1, count)):
            sock.sendto(payload, (target_host, target_port))
            sent += 1
            if delay_seconds > 0:
                time.sleep(delay_seconds)
    finally:
        sock.close()
    return {"host": target_host, "port": target_port, "sent": sent, "bytes_per_message": len(payload)}


def main() -> None:
    settings = get_settings()
    parser = argparse.ArgumentParser(description="Send harmless sample Palo Alto syslog lines to the local ATDR UDP receiver.")
    parser.add_argument("--host", default=settings.syslog_host)
    parser.add_argument("--port", type=int, default=settings.syslog_port)
    parser.add_argument("--count", type=int, default=1)
    parser.add_argument("--delay", type=float, default=0.1)
    args = parser.parse_args()

    result = send_sample_syslog(host=args.host, port=args.port, count=args.count, delay_seconds=args.delay)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
