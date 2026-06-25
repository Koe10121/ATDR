import argparse
import json

from atdr.app.db.database import SessionLocal
from atdr.app.detection.v362_supervised_training_target_contract import (
    run_v362_supervised_training_target_contract,
)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run v3.62 supervised training target contract diagnostics.")
    parser.add_argument("--test-size", type=float, default=0.3)
    parser.add_argument("--min-samples", type=int, default=6)
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()

    db = SessionLocal()
    try:
        result = run_v362_supervised_training_target_contract(
            db,
            test_size=args.test_size,
            min_samples=args.min_samples,
        )
    finally:
        db.close()
    print(json.dumps(result, indent=2 if args.pretty else None, default=str))


if __name__ == "__main__":
    main()
