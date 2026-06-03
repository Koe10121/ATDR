import argparse
import json

from atdr.app.db.database import SessionLocal, init_db
from atdr.app.detection.supervised_recovery import (
    EVALUATION_SPLIT_DIAGNOSTICS_PATH,
    write_evaluation_split_diagnostics,
)


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate supervised evaluation split diagnostics.")
    parser.add_argument("--test-size", type=float, default=0.3)
    parser.add_argument("--min-samples", type=int, default=6)
    parser.add_argument("--output", default=str(EVALUATION_SPLIT_DIAGNOSTICS_PATH))
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()

    init_db()
    with SessionLocal() as db:
        result = write_evaluation_split_diagnostics(
            db,
            output_path=args.output,
            test_size=args.test_size,
            min_samples=args.min_samples,
        )
    print(json.dumps(result, indent=2 if args.pretty else None, default=str))


if __name__ == "__main__":
    main()
