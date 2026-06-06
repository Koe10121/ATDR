import argparse
import json

from atdr.app.db.database import SessionLocal, init_db
from atdr.app.detection.v13_training import analyze_v13_ml_errors


def main() -> None:
    parser = argparse.ArgumentParser(description="Analyze v1.3 supervised ML errors and recommend the next review focus.")
    parser.add_argument("--output", default=None)
    parser.add_argument("--split", choices=["random", "time"], default="time")
    parser.add_argument("--test-size", type=float, default=0.3)
    parser.add_argument("--min-samples", type=int, default=6)
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()
    init_db()
    with SessionLocal() as db:
        result = analyze_v13_ml_errors(
            db,
            output_path=args.output,
            split=args.split,
            test_size=args.test_size,
            min_samples=args.min_samples,
        )
    print(json.dumps(result, indent=2 if args.pretty else None, default=str))


if __name__ == "__main__":
    main()
