import argparse
import json

from atdr.app.db.database import SessionLocal, init_db
from atdr.app.detection.supervised_workflow import SNAPSHOT_DIR, export_supervised_dataset_snapshot


def main() -> None:
    parser = argparse.ArgumentParser(description="Export an ignored supervised ML dataset snapshot for reproducible ATDR experiments.")
    parser.add_argument("--output-root", default=str(SNAPSHOT_DIR))
    parser.add_argument("--split", choices=["random", "time"], default="time")
    parser.add_argument("--test-size", type=float, default=0.3)
    parser.add_argument("--include-raw", action="store_true", help="Include raw log payloads. Off by default to avoid private data leakage.")
    args = parser.parse_args()

    init_db()
    with SessionLocal() as db:
        result = export_supervised_dataset_snapshot(
            db,
            output_root=args.output_root,
            split=args.split,
            test_size=args.test_size,
            include_raw=args.include_raw,
        )
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
