from __future__ import annotations

import argparse
import json
from pathlib import Path

from atdr.app.db.database import SessionLocal, init_db
from atdr.app.detection.v542_development_candidate_freeze import (
    run_v542_candidate_freeze_readiness,
)


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Evaluate the fixed v5.42 development-only candidate set and freeze "
            "at most one diagnostic artifact without activation or promotion."
        )
    )
    parser.add_argument("--min-samples", type=int, default=100)
    parser.add_argument(
        "--preflight-only",
        action="store_true",
        help="Validate evidence custody and boundaries without fitting candidates.",
    )
    parser.add_argument("--output-dir", type=Path, default=None)
    parser.add_argument("--no-report", action="store_true")
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()

    init_db()
    kwargs = {
        "min_samples": args.min_samples,
        "preflight_only": args.preflight_only,
        "write_output": not args.no_report,
    }
    if args.output_dir is not None:
        kwargs["output_dir"] = args.output_dir
    with SessionLocal() as db:
        result = run_v542_candidate_freeze_readiness(db, **kwargs)
    print(json.dumps(result, indent=2 if args.pretty else None, default=str))
    raise SystemExit(0 if result.get("ok") else 1)


if __name__ == "__main__":
    main()
