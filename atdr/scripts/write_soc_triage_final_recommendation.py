import argparse
import json

from atdr.app.db.database import SessionLocal, init_db
from atdr.app.detection.supervised_recovery import write_soc_triage_final_recommendation


def main() -> None:
    parser = argparse.ArgumentParser(description="Write the final SOC triage recommendation report.")
    parser.add_argument("--split", default="time", choices=["random", "time"])
    parser.add_argument("--test-size", type=float, default=0.3)
    parser.add_argument("--min-samples", type=int, default=6)
    parser.add_argument("--output", default="ml_baseline_reviews/soc_triage_final_recommendation.md")
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()

    init_db()
    with SessionLocal() as db:
        result = write_soc_triage_final_recommendation(
            db,
            output_path=args.output,
            split=args.split,
            test_size=args.test_size,
            min_samples=args.min_samples,
        )
    print(json.dumps(result, indent=2 if args.pretty else None, default=str))


if __name__ == "__main__":
    main()
