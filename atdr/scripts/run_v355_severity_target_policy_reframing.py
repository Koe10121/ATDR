import argparse
import json

from atdr.app.db.database import SessionLocal
from atdr.app.detection.v355_severity_target_policy_reframing import run_v355_severity_target_policy_reframing


def main() -> None:
    parser = argparse.ArgumentParser(description="Run v3.55 severity target policy reframing diagnostics.")
    parser.add_argument("--test-size", type=float, default=0.3)
    parser.add_argument("--min-samples", type=int, default=6)
    args = parser.parse_args()

    db = SessionLocal()
    try:
        result = run_v355_severity_target_policy_reframing(
            db,
            test_size=args.test_size,
            min_samples=args.min_samples,
        )
    finally:
        db.close()
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
