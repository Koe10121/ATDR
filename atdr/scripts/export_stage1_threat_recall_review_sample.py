import argparse
import json

from atdr.app.db.database import SessionLocal, init_db
from atdr.app.services.active_learning_service import (
    DEFAULT_STAGE1_THREAT_RECALL_REVIEW_PATH,
    write_stage1_threat_recall_review_sample,
)


def main() -> None:
    parser = argparse.ArgumentParser(description="Export a Stage-1 threat-positive recall recovery review sample.")
    parser.add_argument("--limit", type=int, default=300)
    parser.add_argument("--output", default=str(DEFAULT_STAGE1_THREAT_RECALL_REVIEW_PATH))
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()

    init_db()
    with SessionLocal() as db:
        result = write_stage1_threat_recall_review_sample(db, limit=args.limit, output_path=args.output)
    print(json.dumps(result, indent=2 if args.pretty else None, default=str))


if __name__ == "__main__":
    main()
