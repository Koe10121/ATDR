import argparse
import json
from typing import Any

from atdr.app.db.database import SessionLocal
from atdr.app.detection.v372_unified_detection_ml_evaluation import run_v372_unified_detection_ml_evaluation


def _json_default(value: Any) -> str:
    return str(value)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run a read-only unified ATDR detection/ML productization evaluation."
    )
    parser.add_argument("--include-scenarios", action="store_true", help="Run controlled scenarios in a temp DB.")
    parser.add_argument("--scenario", action="append", help="Scenario to include when --include-scenarios is set.")
    parser.add_argument("--use-ml", action="store_true", help="Include assistive ML scoring in scenario validation.")
    parser.add_argument("--output-dir", default=None, help="Directory containing latest ignored ML diagnostic artifacts.")
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()

    with SessionLocal() as db:
        result = run_v372_unified_detection_ml_evaluation(
            db,
            output_dir=args.output_dir or "ml_baseline_reviews",
            include_scenarios=args.include_scenarios,
            scenarios=args.scenario,
            use_ml=args.use_ml,
        )
    print(json.dumps(result, indent=2 if args.pretty else None, default=_json_default))
    raise SystemExit(0 if result.get("ok") else 1)


if __name__ == "__main__":
    main()
