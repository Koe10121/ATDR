import argparse
import json

from atdr.app.db.database import SessionLocal, init_db
from atdr.app.detection.supervised_recovery import CURRENT_ERROR_ANALYSIS_PATH, write_current_supervised_error_analysis


def main() -> None:
    parser = argparse.ArgumentParser(description="Export current supervised error analysis for recovery planning.")
    parser.add_argument("--output", default=str(CURRENT_ERROR_ANALYSIS_PATH))
    parser.add_argument("--split", choices=["random", "time"], default="time")
    parser.add_argument("--test-size", type=float, default=0.3)
    parser.add_argument("--min-samples", type=int, default=6)
    args = parser.parse_args()

    init_db()
    with SessionLocal() as db:
        result = write_current_supervised_error_analysis(
            db,
            output_path=args.output,
            split=args.split,
            test_size=args.test_size,
            min_samples=args.min_samples,
        )
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
