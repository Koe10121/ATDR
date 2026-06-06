import argparse
import json

from atdr.app.db.database import SessionLocal, init_db
from atdr.app.detection.v13_training import V13_REVIEW_PATH, export_v13_ai_training_review_sample


def main() -> None:
    parser = argparse.ArgumentParser(description="Export the v1.3 high-value AI training review sample.")
    parser.add_argument("--limit", type=int, default=500)
    parser.add_argument(
        "--focus",
        choices=["balanced", "threat_positive", "benign_gap", "boundary", "benchmark"],
        default="balanced",
    )
    parser.add_argument("--output", default=str(V13_REVIEW_PATH))
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()
    init_db()
    with SessionLocal() as db:
        result = export_v13_ai_training_review_sample(
            db,
            limit=args.limit,
            focus=args.focus,
            output_path=args.output,
        )
    print(json.dumps(result, indent=2 if args.pretty else None, default=str))


if __name__ == "__main__":
    main()
