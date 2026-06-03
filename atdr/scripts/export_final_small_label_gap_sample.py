import argparse
import json

from atdr.app.db.database import SessionLocal, init_db
from atdr.app.services.active_learning_service import write_final_small_label_gap_sample


def main() -> None:
    parser = argparse.ArgumentParser(description="Export a final small benign/needs_context label-gap review sample.")
    parser.add_argument("--limit", type=int, default=64)
    parser.add_argument("--output", default="ml_baseline_reviews/final_small_label_gap_sample.csv")
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()

    init_db()
    with SessionLocal() as db:
        result = write_final_small_label_gap_sample(db, limit=args.limit, output_path=args.output)
    print(json.dumps(result, indent=2 if args.pretty else None, default=str))


if __name__ == "__main__":
    main()
