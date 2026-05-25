import argparse
import json

from atdr.app.db.database import SessionLocal, init_db
from atdr.app.services.label_quality_service import DEFAULT_LABEL_QUALITY_PATH, write_label_quality_issues


def main() -> None:
    parser = argparse.ArgumentParser(description="Export possible ATDR ML label quality issues for analyst review.")
    parser.add_argument("--limit", type=int, default=500)
    parser.add_argument("--output", default=str(DEFAULT_LABEL_QUALITY_PATH))
    args = parser.parse_args()

    init_db()
    with SessionLocal() as db:
        result = write_label_quality_issues(db, limit=args.limit, output_path=args.output)
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
