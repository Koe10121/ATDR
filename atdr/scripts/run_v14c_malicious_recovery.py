import argparse
import json

from atdr.app.db.database import SessionLocal
from atdr.app.detection.v14c_malicious_recovery import (
    run_v14c_malicious_recovery,
)


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Run candidate-only v1.4c malicious-recall recovery and confidence "
            "calibration without activating a model."
        )
    )
    parser.add_argument(
        "--split",
        choices=["time", "random", "grouped_stratified"],
        default="time",
    )
    parser.add_argument("--test-size", type=float, default=0.3)
    parser.add_argument("--min-samples", type=int, default=6)
    parser.add_argument("--review-limit", type=int, default=150)
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()
    with SessionLocal() as db:
        result = run_v14c_malicious_recovery(
            db,
            split=args.split,
            test_size=args.test_size,
            min_samples=args.min_samples,
            review_limit=args.review_limit,
        )
    print(json.dumps(result, indent=2 if args.pretty else None, default=str))
    raise SystemExit(0 if result.get("ok") else 1)


if __name__ == "__main__":
    main()
