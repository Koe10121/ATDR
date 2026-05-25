import argparse
import json

from atdr.app.db.database import SessionLocal, init_db
from atdr.app.detection.model_comparison import DEFAULT_REPORT_PATH, compare_supervised_models


def main() -> None:
    parser = argparse.ArgumentParser(description="Compare supervised ATDR classifiers without replacing the active model.")
    parser.add_argument("--test-size", type=float, default=0.3)
    parser.add_argument("--min-samples", type=int, default=6)
    parser.add_argument("--output", default=str(DEFAULT_REPORT_PATH))
    args = parser.parse_args()

    init_db()
    with SessionLocal() as db:
        result = compare_supervised_models(
            db,
            output_path=args.output,
            test_size=args.test_size,
            min_samples=args.min_samples,
        )
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
