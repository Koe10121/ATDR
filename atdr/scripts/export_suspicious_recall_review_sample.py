import argparse
import json

from atdr.app.db.database import SessionLocal
from atdr.app.services.active_learning_service import (
    DEFAULT_SUSPICIOUS_RECALL_REVIEW_PATH,
    write_suspicious_recall_review_sample,
)


def main() -> None:
    parser = argparse.ArgumentParser(description="Export suspicious-recall-focused rows for analyst review.")
    parser.add_argument("--limit", type=int, default=150)
    parser.add_argument("--output", default=str(DEFAULT_SUSPICIOUS_RECALL_REVIEW_PATH))
    args = parser.parse_args()

    with SessionLocal() as db:
        result = write_suspicious_recall_review_sample(db, limit=args.limit, output_path=args.output)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
