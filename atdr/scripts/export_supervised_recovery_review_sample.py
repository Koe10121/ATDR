import argparse
import json

from atdr.app.db.database import SessionLocal, init_db
from atdr.app.detection.supervised_recovery import RECOVERY_REVIEW_SAMPLE_PATH, export_supervised_recovery_review_sample


def main() -> None:
    parser = argparse.ArgumentParser(description="Export a supervised recovery active-learning review sample.")
    parser.add_argument("--output", default=str(RECOVERY_REVIEW_SAMPLE_PATH))
    parser.add_argument("--limit", type=int, default=150)
    args = parser.parse_args()

    init_db()
    with SessionLocal() as db:
        result = export_supervised_recovery_review_sample(db, output_path=args.output, limit=args.limit)
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
