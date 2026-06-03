import argparse
import json

from atdr.app.db.database import SessionLocal, init_db
from atdr.app.detection.supervised_recovery import LABEL_TARGET_PLAN_PATH, write_supervised_label_target_plan


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate the supervised label target plan for reviewed-label recovery.")
    parser.add_argument("--split", choices=["random", "time"], default="time")
    parser.add_argument("--test-size", type=float, default=0.3)
    parser.add_argument("--output", default=str(LABEL_TARGET_PLAN_PATH))
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()

    init_db()
    with SessionLocal() as db:
        result = write_supervised_label_target_plan(db, output_path=args.output, split=args.split, test_size=args.test_size)
    print(json.dumps(result, indent=2 if args.pretty else None, default=str))


if __name__ == "__main__":
    main()
