import argparse
import json

from atdr.app.db.database import SessionLocal, init_db
from atdr.app.services.active_learning_service import (
    DEFAULT_LARGE_POOL_ACTIVE_LEARNING_PATH,
    write_large_pool_active_learning_sample,
)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Export high-value active-learning rows from the full normalized log pool."
    )
    parser.add_argument("--limit", type=int, default=300)
    parser.add_argument("--candidate-pool-limit", type=int, default=None)
    parser.add_argument("--output", default=str(DEFAULT_LARGE_POOL_ACTIVE_LEARNING_PATH))
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()

    init_db()
    with SessionLocal() as db:
        result = write_large_pool_active_learning_sample(
            db,
            limit=args.limit,
            candidate_pool_limit=args.candidate_pool_limit,
            output_path=args.output,
        )
    print(json.dumps(result, indent=2 if args.pretty else None, default=str))


if __name__ == "__main__":
    main()
