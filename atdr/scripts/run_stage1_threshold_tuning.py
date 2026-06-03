import argparse
import json

from atdr.app.db.database import SessionLocal, init_db
from atdr.app.detection.supervised_recovery import STAGE1_THRESHOLD_TUNING_PATH, run_stage1_threshold_tuning


def main() -> None:
    parser = argparse.ArgumentParser(description="Run Stage-1 threat-positive threshold tuning.")
    parser.add_argument("--output", default=str(STAGE1_THRESHOLD_TUNING_PATH))
    parser.add_argument("--split", choices=["random", "time", "grouped_stratified"], default="time")
    parser.add_argument("--test-size", type=float, default=0.3)
    parser.add_argument("--min-samples", type=int, default=6)
    parser.add_argument(
        "--model",
        choices=["random_forest", "hist_gradient_boosting", "logistic_regression", "extra_trees"],
        default="random_forest",
    )
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()

    init_db()
    with SessionLocal() as db:
        result = run_stage1_threshold_tuning(
            db,
            output_path=args.output,
            split=args.split,
            test_size=args.test_size,
            min_samples=args.min_samples,
            model_type=args.model,
        )
    print(json.dumps(result, indent=2 if args.pretty else None, default=str))


if __name__ == "__main__":
    main()
