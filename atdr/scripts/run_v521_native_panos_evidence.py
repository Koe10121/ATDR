from __future__ import annotations

import argparse
import json
from pathlib import Path

from atdr.app.detection.v521_native_panos_evidence import (
    run_v521_native_panos_evidence,
)


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Prepare privacy-safe native PAN-OS chronological evidence roles "
            "in disposable storage."
        )
    )
    parser.add_argument("--sample-path", required=True)
    parser.add_argument(
        "--use-temp-db",
        action="store_true",
        help=(
            "Required acknowledgement that all derived evidence must stay in "
            "disposable storage."
        ),
    )
    parser.add_argument("--preflight-only", action="store_true")
    parser.add_argument("--review-limit", type=int, default=160)
    parser.add_argument("--chunk-size", type=int, default=2000)
    parser.add_argument("--no-report", action="store_true")
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()

    result = run_v521_native_panos_evidence(
        sample_path=Path(args.sample_path),
        use_temp_db=args.use_temp_db,
        preflight_only=args.preflight_only,
        review_limit=args.review_limit,
        chunk_size=args.chunk_size,
        write_output=not args.no_report,
    )
    print(json.dumps(result, indent=2 if args.pretty else None, default=str))
    raise SystemExit(0 if result.get("ok") else 1)


if __name__ == "__main__":
    main()
