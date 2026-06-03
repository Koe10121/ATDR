import argparse
import json

from atdr.app.db.database import SessionLocal, init_db
from atdr.app.detection.supervised_recovery import DATASET_AUDIT_PATH, build_current_supervised_dataset_audit


def main() -> None:
    parser = argparse.ArgumentParser(description="Export a current supervised dataset audit for ATDR ML recovery.")
    parser.add_argument("--output", default=str(DATASET_AUDIT_PATH))
    parser.add_argument("--split", choices=["random", "time"], default="time")
    parser.add_argument("--test-size", type=float, default=0.3)
    args = parser.parse_args()

    init_db()
    with SessionLocal() as db:
        result = build_current_supervised_dataset_audit(db, output_path=args.output, split=args.split, test_size=args.test_size)
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
