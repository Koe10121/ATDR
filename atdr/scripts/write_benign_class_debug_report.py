import argparse
import json

from atdr.app.db.database import SessionLocal, init_db
from atdr.app.detection.supervised_recovery import BENIGN_CLASS_DEBUG_REPORT_PATH, write_benign_class_debug_report


def main() -> None:
    parser = argparse.ArgumentParser(description="Write a benign-class supervised ML debug report.")
    parser.add_argument("--output", default=str(BENIGN_CLASS_DEBUG_REPORT_PATH))
    parser.add_argument("--split", choices=["random", "time"], default="time")
    parser.add_argument("--test-size", type=float, default=0.3)
    parser.add_argument("--min-samples", type=int, default=6)
    parser.add_argument("--model", choices=["random_forest", "extra_trees", "logistic_regression"], default="extra_trees")
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()

    init_db()
    with SessionLocal() as db:
        result = write_benign_class_debug_report(
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
