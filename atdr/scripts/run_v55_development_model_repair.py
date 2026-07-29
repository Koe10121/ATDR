from __future__ import annotations

import argparse
import json
from pathlib import Path

from atdr.app.db.database import SessionLocal, init_db
from atdr.app.detection.v55_development_model_repair import (
    run_v55_development_model_repair,
)


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Run development-only supervised model repair and a read-only "
            "IsolationForest reliability audit under the frozen v5.4 evidence lock."
        )
    )
    parser.add_argument("--min-samples", type=int, default=100)
    parser.add_argument("--output-dir", default=None)
    parser.add_argument(
        "--skip-controlled-scenarios",
        action="store_true",
        help="Skip disposable benign scenario scoring.",
    )
    parser.add_argument(
        "--skip-locked-final",
        action="store_true",
        help="Stop after development-only selection and candidate freezing.",
    )
    parser.add_argument("--no-report", action="store_true")
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()

    init_db()
    with SessionLocal() as db:
        kwargs = {
            "min_samples": args.min_samples,
            "include_controlled_scenarios": not args.skip_controlled_scenarios,
            "run_locked_final": not args.skip_locked_final,
            "write_output": not args.no_report,
        }
        if args.output_dir:
            kwargs["output_dir"] = Path(args.output_dir)
        result = run_v55_development_model_repair(db, **kwargs)
    print(
        json.dumps(
            result,
            indent=2 if args.pretty else None,
            default=str,
        )
    )
    raise SystemExit(0 if result.get("ok") else 1)


if __name__ == "__main__":
    main()
