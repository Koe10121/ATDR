import argparse
import json

from atdr.app.db.database import SessionLocal
from atdr.app.detection.v351_queue_severity_interface import run_v351_queue_severity_interface


def main() -> None:
    parser = argparse.ArgumentParser(description="Run v3.51 queue/severity target interface repair diagnostics.")
    parser.add_argument("--test-size", type=float, default=0.3)
    parser.add_argument("--min-samples", type=int, default=6)
    args = parser.parse_args()

    db = SessionLocal()
    try:
        result = run_v351_queue_severity_interface(
            db,
            test_size=args.test_size,
            min_samples=args.min_samples,
        )
    finally:
        db.close()
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
