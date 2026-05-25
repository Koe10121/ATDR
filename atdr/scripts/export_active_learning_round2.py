import argparse
import json

from atdr.app.db.database import SessionLocal, init_db
from atdr.app.services.active_learning_service import DEFAULT_ACTIVE_LEARNING_ROUND2_PATH, write_active_learning_review_sample


def main() -> None:
    parser = argparse.ArgumentParser(description="Export ATDR active-learning round 2 review sample.")
    parser.add_argument("--limit", type=int, default=200)
    parser.add_argument("--output", default=str(DEFAULT_ACTIVE_LEARNING_ROUND2_PATH))
    args = parser.parse_args()

    init_db()
    with SessionLocal() as db:
        result = write_active_learning_review_sample(db, limit=args.limit, output_path=args.output)
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
