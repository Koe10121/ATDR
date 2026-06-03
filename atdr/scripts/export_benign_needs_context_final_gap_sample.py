import argparse
import json

from atdr.app.db.database import SessionLocal, init_db
from atdr.app.services.active_learning_service import (
    DEFAULT_BENIGN_NEEDS_CONTEXT_FINAL_GAP_PATH,
    write_benign_needs_context_final_gap_sample,
)


def main() -> None:
    parser = argparse.ArgumentParser(description="Export a benign/needs_context final-gap human review sample.")
    parser.add_argument("--limit", type=int, default=100)
    parser.add_argument("--output", default=str(DEFAULT_BENIGN_NEEDS_CONTEXT_FINAL_GAP_PATH))
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()

    init_db()
    with SessionLocal() as db:
        result = write_benign_needs_context_final_gap_sample(db, limit=args.limit, output_path=args.output)
    print(json.dumps(result, indent=2 if args.pretty else None, default=str))


if __name__ == "__main__":
    main()
