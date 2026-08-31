from __future__ import annotations

import argparse
import json
from pathlib import Path

from atdr.app.db.database import SessionLocal, init_db
from atdr.app.detection.v544_chronological_evidence import (
    run_v544_chronological_evidence_expansion,
)


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Build aggregate-only chronological development evidence in "
            "disposable storage without opening protected evaluation labels."
        )
    )
    parser.add_argument(
        "--sample-path",
        type=Path,
        default=None,
        help="Private PAN-OS source path. The path is never returned in output.",
    )
    parser.add_argument(
        "--use-temp-db",
        action="store_true",
        help="Acknowledge that full processing must use disposable storage.",
    )
    parser.add_argument(
        "--preflight-only",
        action="store_true",
        help="Validate custody and source availability without reading log rows.",
    )
    parser.add_argument("--min-samples", type=int, default=100)
    parser.add_argument("--review-limit", type=int, default=200)
    parser.add_argument("--output-dir", type=Path, default=None)
    parser.add_argument(
        "--no-report",
        action="store_true",
        help="Do not write ignored diagnostic output or a private custody lock.",
    )
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()

    init_db()
    kwargs = {
        "sample_path": args.sample_path,
        "use_temp_db": args.use_temp_db,
        "preflight_only": args.preflight_only,
        "min_samples": args.min_samples,
        "review_limit": args.review_limit,
        "write_output": not args.no_report,
    }
    if args.output_dir is not None:
        kwargs["output_dir"] = args.output_dir
    with SessionLocal() as db:
        result = run_v544_chronological_evidence_expansion(db, **kwargs)
    print(json.dumps(result, indent=2 if args.pretty else None, default=str))
    raise SystemExit(0 if result.get("ok") else 1)


if __name__ == "__main__":
    main()
