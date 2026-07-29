from __future__ import annotations

import argparse
import json

from atdr.app.services.v514_large_file_runtime_service import (
    run_v514_large_file_runtime_acceptance,
)


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Run privacy-safe large-file ingestion, resume, source, detection, "
            "and performance acceptance in disposable storage."
        )
    )
    parser.add_argument(
        "--sample-path",
        required=True,
        help="Private local PAN-OS file. Its path and raw contents are never returned.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=100_000,
        help="Rows processed in disposable storage (default: 100000).",
    )
    parser.add_argument("--chunk-size", type=int, default=1_000)
    parser.add_argument(
        "--use-temp-db",
        action="store_true",
        help="Required for runtime processing; the configured database is never a target.",
    )
    parser.add_argument("--simulate-interruption", action="store_true")
    parser.add_argument(
        "--resume",
        action="store_true",
        help="Resume after --simulate-interruption in the same isolated acceptance run.",
    )
    parser.add_argument("--run-detection", action="store_true")
    parser.add_argument(
        "--preflight-only",
        action="store_true",
        help="Scan aggregate format/quality only; do not create disposable database rows.",
    )
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()

    result = run_v514_large_file_runtime_acceptance(
        sample_path=args.sample_path,
        limit=args.limit,
        chunk_size=args.chunk_size,
        use_temp_db=args.use_temp_db,
        simulate_interruption=args.simulate_interruption,
        resume=args.resume,
        run_detection_after=args.run_detection,
        preflight_only=args.preflight_only,
    )
    print(json.dumps(result, indent=2 if args.pretty else None, default=str))
    raise SystemExit(0 if result.get("ok") else 1)


if __name__ == "__main__":
    main()
