import argparse
import json

from atdr.app.db.database import SessionLocal
from atdr.app.detection.v352_repaired_interface_severity_model import run_v352_repaired_interface_severity_model


def main() -> None:
    parser = argparse.ArgumentParser(description="Run v3.52 repaired-interface severity model diagnostics.")
    parser.add_argument("--test-size", type=float, default=0.3)
    parser.add_argument("--min-samples", type=int, default=6)
    args = parser.parse_args()

    db = SessionLocal()
    try:
        result = run_v352_repaired_interface_severity_model(
            db,
            test_size=args.test_size,
            min_samples=args.min_samples,
        )
    finally:
        db.close()
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
