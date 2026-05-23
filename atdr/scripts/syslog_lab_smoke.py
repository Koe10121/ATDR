import argparse
import json
import socket
import threading
import time
from pathlib import Path
from typing import Any

from sqlalchemy import func, select

from atdr.app.core.config import PROJECT_ROOT, get_settings
from atdr.app.db.database import SessionLocal, init_db
from atdr.app.db.models import NormalizedLog, RawLog
from atdr.app.services.syslog_service import run_udp_syslog_receiver


def _resolve_sample_path(path: str | None) -> Path:
    settings = get_settings()
    candidate = Path(path or settings.demo_sample_log_path)
    if not candidate.is_absolute():
        candidate = PROJECT_ROOT / candidate
    return candidate


def _read_lines(path: Path, count: int) -> list[str]:
    lines: list[str] = []
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            if line.strip():
                lines.append(line.strip())
            if len(lines) >= count:
                break
    return lines


def _counts() -> dict[str, int]:
    with SessionLocal() as db:
        return {
            "raw_logs": int(db.scalar(select(func.count(RawLog.id))) or 0),
            "normalized_logs": int(db.scalar(select(func.count(NormalizedLog.id))) or 0),
        }


def run_syslog_lab_smoke(
    *,
    host: str = "127.0.0.1",
    port: int = 5515,
    count: int = 5,
    sample_path: str | None = None,
    timeout: float = 10.0,
) -> dict[str, Any]:
    init_db()
    path = _resolve_sample_path(sample_path)
    if not path.exists():
        return {"ok": False, "error": f"Sample log file does not exist: {path}"}
    lines = _read_lines(path, count)
    if not lines:
        return {"ok": False, "error": f"Sample log file has no usable lines: {path}"}

    before = _counts()
    receiver_result: dict[str, Any] = {}
    receiver_error: list[str] = []

    def receive() -> None:
        try:
            receiver_result.update(
                run_udp_syslog_receiver(
                    host=host,
                    port=port,
                    batch_size=max(1, min(count, 25)),
                    max_messages=len(lines),
                    socket_timeout=timeout,
                )
            )
        except Exception as exc:  # pragma: no cover - reported in command output
            receiver_error.append(f"{exc.__class__.__name__}: {exc}")

    thread = threading.Thread(target=receive, daemon=True)
    thread.start()
    time.sleep(0.3)

    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        for line in lines:
            sender.sendto(line.encode("utf-8"), (host, port))
    finally:
        sender.close()

    thread.join(timeout + 2)
    after = _counts()
    raw_delta = after["raw_logs"] - before["raw_logs"]
    normalized_delta = after["normalized_logs"] - before["normalized_logs"]
    ok = (
        not thread.is_alive()
        and not receiver_error
        and receiver_result.get("received") == len(lines)
        and raw_delta >= len(lines)
        and normalized_delta >= len(lines)
    )
    return {
        "ok": ok,
        "host": host,
        "port": port,
        "sample_path": str(path),
        "sent": len(lines),
        "receiver": receiver_result,
        "receiver_error": receiver_error,
        "before": before,
        "after": after,
        "delta": {"raw_logs": raw_delta, "normalized_logs": normalized_delta},
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run a localhost UDP syslog ingestion smoke test for ATDR.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5515)
    parser.add_argument("--count", type=int, default=5)
    parser.add_argument("--sample-path", default=None)
    parser.add_argument("--timeout", type=float, default=10.0)
    args = parser.parse_args()

    result = run_syslog_lab_smoke(
        host=args.host,
        port=args.port,
        count=args.count,
        sample_path=args.sample_path,
        timeout=args.timeout,
    )
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result["ok"] else 1)


if __name__ == "__main__":
    main()
