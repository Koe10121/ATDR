from __future__ import annotations

import argparse
import json
from typing import Any

from atdr.app.db.database import SessionLocal
from atdr.app.detection.v49_detection_ml_reliability import run_v49_detection_ml_reliability


def _json_default(value: Any) -> str:
    return str(value)


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Run the read-only v4.9 detection and ML reliability lock. "
            "No model artifact, model activation, label, or response action is written."
        )
    )
    parser.add_argument("--output-dir", default="ml_baseline_reviews")
    parser.add_argument("--min-samples", type=int, default=100)
    parser.add_argument("--no-report", action="store_true")
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()

    with SessionLocal() as db:
        result = run_v49_detection_ml_reliability(
            db,
            output_dir=args.output_dir,
            min_samples=args.min_samples,
            write_output=not args.no_report,
        )
    print(json.dumps(result, indent=2 if args.pretty else None, default=_json_default))
    raise SystemExit(0 if result.get("ok") else 1)


if __name__ == "__main__":
    main()
