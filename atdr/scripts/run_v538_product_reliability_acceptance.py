from __future__ import annotations

import argparse
import json
from pathlib import Path

from atdr.app.services.v538_product_reliability_service import (
    DEFAULT_OUTPUT_DIR,
    run_v538_product_reliability_acceptance,
)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run ATDR v5.38 end-to-end reliability acceptance in disposable storage."
    )
    parser.add_argument(
        "--use-temp-db",
        action="store_true",
        help="Required confirmation that the configured database is not an acceptance target.",
    )
    parser.add_argument("--log-count", type=int, default=64)
    parser.add_argument("--preflight-only", action="store_true")
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--no-write", action="store_true")
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()

    report = run_v538_product_reliability_acceptance(
        use_temp_db=args.use_temp_db,
        log_count=args.log_count,
        preflight_only=args.preflight_only,
        output_dir=args.output_dir,
        write_reports=not args.no_write,
    )
    print(json.dumps(report, indent=2 if args.pretty else None, sort_keys=True, default=str))
    raise SystemExit(0 if report.get("ok") else 1)


if __name__ == "__main__":
    main()
