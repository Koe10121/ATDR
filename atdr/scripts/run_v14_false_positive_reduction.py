import argparse
import json

from atdr.app.db.database import SessionLocal
from atdr.app.detection.v14_false_positive import run_v14_false_positive_reduction


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run candidate-only v1.4 false-positive reduction and confidence calibration.",
    )
    parser.add_argument("--split", choices=["time", "random", "grouped_stratified"], default="time")
    parser.add_argument("--test-size", type=float, default=0.3)
    parser.add_argument("--min-samples", type=int, default=6)
    parser.add_argument("--review-limit", type=int, default=200)
    parser.add_argument(
        "--include-manual",
        action="store_true",
        help="Explicitly include protected manual rows in the diagnostic review CSV.",
    )
    parser.add_argument(
        "--include-reviewed",
        action="store_true",
        help="Include reviewed non-manual rows that require correction mode to import.",
    )
    parser.add_argument(
        "--only-actionable",
        action=argparse.BooleanOptionalAction,
        default=True,
    )
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()
    with SessionLocal() as db:
        result = run_v14_false_positive_reduction(
            db,
            split=args.split,
            test_size=args.test_size,
            min_samples=args.min_samples,
            review_limit=args.review_limit,
            include_manual=args.include_manual,
            include_reviewed=args.include_reviewed,
            only_actionable=args.only_actionable,
        )
    print(json.dumps(result, indent=2 if args.pretty else None, default=str))


if __name__ == "__main__":
    main()
