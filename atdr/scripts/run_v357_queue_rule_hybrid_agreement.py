import argparse
import json

from atdr.app.db.database import SessionLocal
from atdr.app.detection.v357_queue_rule_hybrid_agreement import run_v357_queue_rule_hybrid_agreement


def main() -> None:
    parser = argparse.ArgumentParser(description="Run v3.57 queue-vs-rule/hybrid agreement diagnostics.")
    parser.add_argument("--test-size", type=float, default=0.3)
    parser.add_argument("--min-samples", type=int, default=6)
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()

    db = SessionLocal()
    try:
        result = run_v357_queue_rule_hybrid_agreement(
            db,
            test_size=args.test_size,
            min_samples=args.min_samples,
        )
    finally:
        db.close()
    print(json.dumps(result, indent=2 if args.pretty else None, default=str))


if __name__ == "__main__":
    main()
