import argparse
import json

from atdr.app.db.database import SessionLocal, init_db
from atdr.app.services.active_learning_service import (
    DEFAULT_ACTIVE_LEARNING_ROUND3_MALICIOUS_PATH,
    write_active_learning_review_sample,
)


def main() -> None:
    parser = argparse.ArgumentParser(description="Export ATDR active-learning round 3 with malicious/suspicious focus.")
    parser.add_argument("--limit", type=int, default=200)
    parser.add_argument("--focus", default="malicious,suspicious,needs_context")
    parser.add_argument("--output", default=str(DEFAULT_ACTIVE_LEARNING_ROUND3_MALICIOUS_PATH))
    args = parser.parse_args()

    init_db()
    with SessionLocal() as db:
        result = write_active_learning_review_sample(db, limit=args.limit, output_path=args.output, focus=args.focus)
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
