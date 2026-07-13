from __future__ import annotations

import argparse
import json
import signal
import sys
from threading import Event

from atdr.app.core.config import get_settings
from atdr.app.services.operation_worker import WorkerConcurrencyError, run_worker_cycle, run_worker_loop


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run the opt-in ATDR durable operation worker. It never starts with the API by default."
    )
    parser.add_argument("--once", action="store_true", help="Process at most one queued job, then exit (default).")
    parser.add_argument("--watch", action="store_true", help="Keep polling for queued work. Requires OPERATION_WORKER_ENABLED=true.")
    parser.add_argument("--max-jobs", type=int, default=None, help="Stop after this many processed jobs in watch mode.")
    parser.add_argument("--poll-seconds", type=float, default=None, help="Polling interval for watch mode.")
    parser.add_argument("--worker-id", default=None, help="Safe local worker label for operational history.")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print safe status output.")
    return parser


def main() -> int:
    args = _parser().parse_args()
    if args.watch and not get_settings().operation_worker_enabled:
        print(
            json.dumps(
                {
                    "ok": False,
                    "status": "worker_disabled",
                    "message": "Set OPERATION_WORKER_ENABLED=true only when you intentionally want a persistent local/shared-lab worker.",
                    "secrets_exposed": False,
                },
                indent=2 if args.pretty else None,
                default=str,
            )
        )
        return 2
    stop_event = Event()
    previous_handlers: dict[signal.Signals, object] = {}

    def request_shutdown(_signum, _frame) -> None:
        stop_event.set()

    if args.watch:
        for signal_name in ("SIGINT", "SIGTERM"):
            shutdown_signal = getattr(signal, signal_name, None)
            if shutdown_signal is None:
                continue
            previous_handlers[shutdown_signal] = signal.getsignal(shutdown_signal)
            signal.signal(shutdown_signal, request_shutdown)
    try:
        if args.watch:
            result = run_worker_loop(
                worker_id=args.worker_id,
                poll_seconds=args.poll_seconds,
                max_jobs=args.max_jobs,
                stop_event=stop_event,
            )
        else:
            result = run_worker_cycle(worker_id=args.worker_id)
    except WorkerConcurrencyError as exc:
        print(
            json.dumps(
                {
                    "ok": False,
                    "status": "worker_concurrency_rejected",
                    "message": str(exc),
                    "secrets_exposed": False,
                },
                indent=2 if args.pretty else None,
            )
        )
        return 2
    except KeyboardInterrupt:
        result = {
            "ok": True,
            "status": "stopped",
            "message": "Operation worker stopped gracefully.",
            "secrets_exposed": False,
        }
    finally:
        for shutdown_signal, previous in previous_handlers.items():
            signal.signal(shutdown_signal, previous)
    print(json.dumps(result, indent=2 if args.pretty else None, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
