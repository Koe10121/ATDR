import argparse
import json
import socket
import time
from typing import Any

from atdr.app.core.config import get_settings


SAMPLE_SYSLOG_LINE = (
    '2026-05-20T13:36:16+07:00 MFU-FW.mfu.ac.th '
    '1,2026/05/20 13:36:15,013101011043,TRAFFIC,end,2561,2026/05/20 13:36:15,'
    '43.210.171.152,202.28.46.69,0.0.0.0,0.0.0.0,Allow-Outside_to_WLAN,,,ping,'
    'vsys1,SG-Outside,WLAN-Inside,ethernet1/22.240,ethernet1/22.241,Forward-to-FortiSIEM,'
    '2026/05/20 13:36:15,35845233,1,0,0,0,0,0x100019,icmp,allow,172,86,86,2,'
    '2026/05/20 13:36:02,0,any,,7588383920033660891,0x0,Thailand,Thailand,,1,1,'
    'aged-out,0,0,0,0,WLAN,MFU-FW,from-policy,,,0,,0,,N/A,0,0,0,0,'
    'e3702b83-bc00-4ee6-bc8d-a5c7f19568da,0,0,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,'
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
