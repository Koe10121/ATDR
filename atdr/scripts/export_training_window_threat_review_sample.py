import argparse
import json

from atdr.app.db.database import SessionLocal, init_db
from atdr.app.services.active_learning_service import (
    DEFAULT_TRAINING_WINDOW_THREAT_REVIEW_PATH,
    write_training_window_threat_review_sample,
)


def main() -> None:
    parser = argparse.ArgumentParser(description="Export training-window threat rows for focused analyst review.")
    parser.add_argument("--limit", type=int, default=150)
    parser.add_argument("--output", default=str(DEFAULT_TRAINING_WINDOW_THREAT_REVIEW_PATH))
    args = parser.parse_args()

    init_db()
    with SessionLocal() as db:
        result = write_training_window_threat_review_sample(db, limit=args.limit, output_path=args.output)
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
