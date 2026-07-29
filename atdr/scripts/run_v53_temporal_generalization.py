from __future__ import annotations

import argparse
import json
from pathlib import Path

from atdr.app.db.database import SessionLocal, init_db
from atdr.app.detection.v53_temporal_generalization import run_v53_temporal_generalization


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run read-only v5.3 temporal drift, OOD, abstention, and split-stability validation."
    )
    parser.add_argument("--min-samples", type=int, default=100)
    parser.add_argument("--output-dir", default=None)
    parser.add_argument("--no-report", action="store_true")
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()

    init_db()
    with SessionLocal() as db:
        kwargs = {
            "min_samples": args.min_samples,
            "write_output": not args.no_report,
        }
        if args.output_dir:
            kwargs["output_dir"] = Path(args.output_dir)
        result = run_v53_temporal_generalization(db, **kwargs)
    print(json.dumps(result, indent=2 if args.pretty else None, default=str))
    raise SystemExit(0 if result.get("ok") else 1)


if __name__ == "__main__":
    main()
