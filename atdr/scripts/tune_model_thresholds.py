import argparse
import json

from atdr.app.db.database import SessionLocal, init_db
from atdr.app.detection.threshold_tuning import DEFAULT_THRESHOLD_REPORT_PATH, tune_model_thresholds


def main() -> None:
    parser = argparse.ArgumentParser(description="Tune ATDR supervised model decision thresholds for SOC triage.")
    parser.add_argument("--split", choices=["random", "time"], default="time")
    parser.add_argument("--test-size", type=float, default=0.3)
    parser.add_argument("--min-samples", type=int, default=6)
    parser.add_argument("--output", default=str(DEFAULT_THRESHOLD_REPORT_PATH))
    args = parser.parse_args()

    init_db()
    with SessionLocal() as db:
        result = tune_model_thresholds(
            db,
            split=args.split,
            test_size=args.test_size,
            min_samples=args.min_samples,
            output_path=args.output,
        )
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
