import argparse
import json
from pathlib import Path

from atdr.app.db.database import SessionLocal, init_db
from atdr.app.services.assisted_label_service import export_label_review_sample


def main() -> None:
    parser = argparse.ArgumentParser(description="Export a balanced sample of assisted labels for human review.")
    parser.add_argument("--output", default="ml_baseline_reviews/assisted_label_human_review_sample.csv")
    args = parser.parse_args()

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    init_db()
    with SessionLocal() as db:
        csv_text = export_label_review_sample(db)
    output_path.write_text(csv_text, encoding="utf-8")
    row_count = max(0, len(csv_text.splitlines()) - 1)
    print(json.dumps({"output": str(output_path), "rows": row_count}, indent=2))


if __name__ == "__main__":
    main()
