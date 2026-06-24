import argparse
import json

from atdr.app.db.database import SessionLocal
from atdr.app.detection.v359_supervised_output_policy_contract import run_v359_supervised_output_policy_contract


def main() -> None:
    parser = argparse.ArgumentParser(description="Run v3.59 supervised output policy contract diagnostics.")
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()

    db = SessionLocal()
    try:
        result = run_v359_supervised_output_policy_contract(db)
    finally:
        db.close()
    print(json.dumps(result, indent=2 if args.pretty else None, default=str))


if __name__ == "__main__":
    main()
