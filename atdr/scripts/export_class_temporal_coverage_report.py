import argparse
import json

from atdr.app.db.database import SessionLocal, init_db
from atdr.app.services.class_temporal_coverage_service import (
    DEFAULT_CLASS_TEMPORAL_COVERAGE_PATH,
    write_class_temporal_coverage_report,
)


def main() -> None:
    parser = argparse.ArgumentParser(description="Export ATDR class temporal coverage report for time-split validation.")
    parser.add_argument("--test-size", type=float, default=0.3)
    parser.add_argument("--output", default=str(DEFAULT_CLASS_TEMPORAL_COVERAGE_PATH))
    args = parser.parse_args()

    init_db()
    with SessionLocal() as db:
        result = write_class_temporal_coverage_report(db, output_path=args.output, test_size=args.test_size)
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
