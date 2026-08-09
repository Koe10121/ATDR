from __future__ import annotations

import argparse
import json
from pathlib import Path

from atdr.app.db.database import SessionLocal
from atdr.app.detection.v528_supervised_readiness import (
    DEFAULT_OUTPUT_DIR,
    run_v528_supervised_readiness_audit,
)


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Audit the current governed supervised shadow contract without "
            "retraining, scoring locked evidence, or changing lifecycle state."
        )
    )
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--no-write", action="store_true")
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()

    with SessionLocal() as db:
        report = run_v528_supervised_readiness_audit(
            db,
            output_dir=args.output_dir,
            write_reports=not args.no_write,
        )
    print(json.dumps(report, indent=2 if args.pretty else None, sort_keys=True))


if __name__ == "__main__":
    main()
