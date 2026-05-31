import argparse
import json

from atdr.app.db.database import SessionLocal, init_db
from atdr.app.detection.supervised_workflow import SANITY_REPORT_PATH, generate_supervised_sanity_report


def main() -> None:
    parser = argparse.ArgumentParser(description="Debug supervised ML training/experiment parity without activating a model.")
    parser.add_argument("--output", default=str(SANITY_REPORT_PATH))
    parser.add_argument("--split", choices=["random", "time"], default="time")
    parser.add_argument("--test-size", type=float, default=0.3)
    parser.add_argument("--min-samples", type=int, default=6)
    parser.add_argument("--threshold-profile", default="balanced")
    args = parser.parse_args()

    init_db()
    with SessionLocal() as db:
        result = generate_supervised_sanity_report(
            db,
            output_path=args.output,
            split=args.split,
            test_size=args.test_size,
            min_samples=args.min_samples,
            threshold_profile=args.threshold_profile,
        )
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
