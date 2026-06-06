import argparse
import json

from atdr.app.db.database import SessionLocal, init_db
from atdr.app.detection.v13_training import audit_training_data_quality


def main() -> None:
    parser = argparse.ArgumentParser(description="Audit ATDR supervised training data quality for v1.3.")
    parser.add_argument("--output", default=None)
    parser.add_argument("--split", choices=["random", "time"], default="time")
    parser.add_argument("--test-size", type=float, default=0.3)
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()
    init_db()
    with SessionLocal() as db:
        result = audit_training_data_quality(
            db,
            output_path=args.output,
            split=args.split,
            test_size=args.test_size,
        )
    print(json.dumps(result, indent=2 if args.pretty else None, default=str))


if __name__ == "__main__":
    main()
