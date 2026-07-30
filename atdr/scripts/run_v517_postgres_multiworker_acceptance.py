from __future__ import annotations

import argparse
import json

from atdr.app.services.v517_postgres_multiworker_service import (
    run_v517_postgres_multiworker_acceptance,
)


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Run fail-closed ATDR PostgreSQL multi-worker capacity, recovery, "
            "deduplication, and backup/restore acceptance."
        )
    )
    parser.add_argument("--preflight-only", action="store_true")
    parser.add_argument("--target-rows", type=int, default=100_000)
    parser.add_argument("--chunk-size", type=int, default=1_000)
    parser.add_argument("--workers", type=int, default=2)
    parser.add_argument("--synthetic", action="store_true")
    parser.add_argument(
        "--sample-path",
        help="Private evidence path; never returned or persisted in reports.",
    )
    parser.add_argument("--run-detection", action="store_true")
    parser.add_argument("--test-recovery", action="store_true")
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()

    result = run_v517_postgres_multiworker_acceptance(
        target_rows=args.target_rows,
        chunk_size=args.chunk_size,
        workers=args.workers,
        synthetic=args.synthetic,
        sample_path=args.sample_path,
        run_detection_after=args.run_detection,
        test_recovery=args.test_recovery,
        preflight_only=args.preflight_only,
    )
    print(json.dumps(result, indent=2 if args.pretty else None, default=str))
    raise SystemExit(0 if result.get("ok") else 1)


if __name__ == "__main__":
    main()
