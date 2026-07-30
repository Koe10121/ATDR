from __future__ import annotations

import argparse
import json

from atdr.app.services.v516_memory_query_service import (
    run_v516_memory_query_stabilization,
)


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Run privacy-safe ATDR memory and query stabilization acceptance "
            "against a disposable database."
        )
    )
    parser.add_argument(
        "--sample-path",
        required=True,
        help="Private PAN-OS input; its path and contents are never returned.",
    )
    parser.add_argument("--target-rows", type=int, default=100_000)
    parser.add_argument("--chunk-size", type=int, default=1_000)
    parser.add_argument(
        "--use-temp-db",
        action="store_true",
        help="Required; configured databases are never validation targets.",
    )
    parser.add_argument(
        "--profile-only",
        action="store_true",
        help="Profile ingestion and queries without running detection.",
    )
    parser.add_argument("--run-detection", action="store_true")
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()

    result = run_v516_memory_query_stabilization(
        sample_path=args.sample_path,
        target_rows=args.target_rows,
        chunk_size=args.chunk_size,
        use_temp_db=args.use_temp_db,
        profile_only=args.profile_only,
        run_detection_after=args.run_detection,
    )
    print(json.dumps(result, indent=2 if args.pretty else None, default=str))
    raise SystemExit(0 if result.get("ok") else 1)


if __name__ == "__main__":
    main()
