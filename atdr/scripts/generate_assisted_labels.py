import argparse
import json
from pathlib import Path

from atdr.app.db.database import SessionLocal, init_db
from atdr.app.services.assisted_label_service import generate_assisted_labels


def _str_to_bool(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "y", "on"}


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate weak AI-assisted labels from ATDR rule, ML, and behavior evidence.")
    parser.add_argument("--limit", type=int, default=1000)
    parser.add_argument("--dry-run", action="store_true", help="Preview labels without writing ml_labels rows.")
    parser.add_argument("--apply", action="store_true", help="Write assisted labels that meet the minimum confidence threshold.")
    parser.add_argument("--reviewer", default="codex_assisted")
    parser.add_argument("--min-confidence", type=int, default=3, choices=[1, 2, 3, 4, 5])
    parser.add_argument("--overwrite", type=_str_to_bool, default=False)
    parser.add_argument("--only-unlabeled", type=_str_to_bool, default=True)
    parser.add_argument("--export-preview", default="ml_baseline_reviews/assisted_label_preview.csv")
    args = parser.parse_args()

    apply_labels = args.apply and not args.dry_run
    output_path = Path(args.export_preview)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    init_db()
    with SessionLocal() as db:
        result = generate_assisted_labels(
            db,
            limit=args.limit,
            apply=apply_labels,
            reviewer=args.reviewer,
            min_confidence=args.min_confidence,
            overwrite=args.overwrite,
            only_unlabeled=args.only_unlabeled,
        )
    output_path.write_text(result.pop("csv"), encoding="utf-8")
    candidate_count = len(result.get("decisions", []))
    result.pop("decisions", None)
    result["previewed_candidates"] = candidate_count
    result["preview_csv"] = str(output_path)
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
