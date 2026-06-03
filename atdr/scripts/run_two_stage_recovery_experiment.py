import argparse
import json

from atdr.app.db.database import SessionLocal, init_db
from atdr.app.detection.supervised_recovery import TWO_STAGE_EXPERIMENT_PATH, run_two_stage_recovery_experiment


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the experimental two-stage supervised recovery evaluation.")
    parser.add_argument("--output", default=str(TWO_STAGE_EXPERIMENT_PATH))
    parser.add_argument("--split", choices=["random", "time", "grouped_stratified"], default="time")
    parser.add_argument("--test-size", type=float, default=0.3)
    parser.add_argument("--min-samples", type=int, default=6)
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()

    init_db()
    with SessionLocal() as db:
        result = run_two_stage_recovery_experiment(
            db,
            output_path=args.output,
            split=args.split,
            test_size=args.test_size,
            min_samples=args.min_samples,
        )
    print(json.dumps(result, indent=2 if args.pretty else None, default=str))


if __name__ == "__main__":
    main()
