import argparse
import json

from atdr.app.db.database import SessionLocal
from atdr.app.detection.v333_guard_refinement import run_v333_guard_refinement


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Run v3.33 evidence-aware low-signal guard refinement diagnostics without "
            "activating models or response automation."
        )
    )
    parser.add_argument("--test-size", type=float, default=0.3)
    parser.add_argument("--min-samples", type=int, default=6)
    parser.add_argument("--review-limit", type=int, default=100)
    parser.add_argument("--output-dir", default="ml_baseline_reviews")
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()

    with SessionLocal() as db:
        result = run_v333_guard_refinement(
            db,
            test_size=args.test_size,
            min_samples=args.min_samples,
            review_limit=args.review_limit,
            output_dir=args.output_dir,
        )
    print(json.dumps(result, indent=2 if args.pretty else None, default=str))
    raise SystemExit(0 if result.get("ok") else 1)


if __name__ == "__main__":
    main()
