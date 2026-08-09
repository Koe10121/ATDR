from __future__ import annotations

import argparse
import json
from pathlib import Path

from atdr.app.db.database import SessionLocal
from atdr.app.detection.v530_supervised_evidence_closure import (
    DEFAULT_OUTPUT_DIR,
    run_v530_supervised_evidence_closure,
)


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Close supervised evidence and make a conservative promotion-readiness decision "
            "without training, activation, label writes, or response actions."
        )
    )
    parser.add_argument("--sample-path", type=Path)
    parser.add_argument(
        "--use-temp-db",
        action="store_true",
        help="Required when --sample-path is supplied; private evidence is inspected in disposable storage only.",
    )
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--max-evaluation-rows", type=int, default=3_000)
    parser.add_argument("--skip-current-shadow-evaluation", action="store_true")
    parser.add_argument("--no-write", action="store_true")
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()

    with SessionLocal() as db:
        report = run_v530_supervised_evidence_closure(
            db,
            output_dir=args.output_dir,
            sample_path=args.sample_path,
            use_temp_db=args.use_temp_db,
            evaluate_registered_shadow=not args.skip_current_shadow_evaluation,
            max_evaluation_rows=args.max_evaluation_rows,
            write_reports=not args.no_write,
        )
    print(json.dumps(report, indent=2 if args.pretty else None, sort_keys=True, default=str))
    raise SystemExit(0 if report.get("ok") else 1)


if __name__ == "__main__":
    main()
