from __future__ import annotations

import argparse
import json

from atdr.app.services.v515_runtime_soak_service import (
    run_v515_runtime_soak_acceptance,
)


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Run privacy-safe progressive ingestion, recovery, detection, "
            "integrity, and cleanup acceptance in disposable storage."
        )
    )
    parser.add_argument(
        "--sample-path",
        required=True,
        help="Private PAN-OS input. Its path and raw contents are never returned.",
    )
    parser.add_argument(
        "--target-rows",
        type=int,
        default=250_000,
        help="Cumulative rows to process; omit the value only by using the default.",
    )
    parser.add_argument("--chunk-size", type=int, default=1_000)
    parser.add_argument(
        "--use-temp-db",
        action="store_true",
        help="Required for processing; configured databases are never targets.",
    )
    parser.add_argument(
        "--fault-plan",
        default="combined",
        choices=[
            "none",
            "worker_handoff",
            "repeated_interruption",
            "cancellation_resume",
            "stale_lease_recovery",
            "sqlite_lock_wait",
            "combined",
        ],
    )
    parser.add_argument("--run-detection", action="store_true")
    parser.add_argument(
        "--preflight-only",
        action="store_true",
        help="Return aggregate resource/parser checks without disposable writes.",
    )
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()

    result = run_v515_runtime_soak_acceptance(
        sample_path=args.sample_path,
        target_rows=args.target_rows,
        chunk_size=args.chunk_size,
        use_temp_db=args.use_temp_db,
        fault_plan=args.fault_plan,
        run_detection_after=args.run_detection,
        preflight_only=args.preflight_only,
    )
    print(json.dumps(result, indent=2 if args.pretty else None, default=str))
    raise SystemExit(0 if result.get("ok") else 1)


if __name__ == "__main__":
    main()
