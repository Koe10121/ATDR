import argparse
import json

from atdr.app.db.database import SessionLocal
from atdr.app.detection.v350_queued_severity_semantics import run_v350_queued_severity_semantics


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run v3.50 queued severity target semantics and feature-support audit."
    )
    parser.add_argument("--test-size", type=float, default=0.3)
    parser.add_argument("--min-samples", type=int, default=6)
    args = parser.parse_args()

    db = SessionLocal()
    try:
        result = run_v350_queued_severity_semantics(
            db,
            test_size=args.test_size,
            min_samples=args.min_samples,
        )
    finally:
        db.close()
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
