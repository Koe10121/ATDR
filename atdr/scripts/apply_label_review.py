"""Apply a label-review decisions file to the configured database.

Usage:
    python -m atdr.scripts.apply_label_review decisions.json --reviewer "Name"          # dry run
    python -m atdr.scripts.apply_label_review decisions.json --reviewer "Name" --apply  # write

decisions.json: {"note": "...", "decisions": [{"source_ip", "pattern", "decision", "attack_type" (optional),
"note", "log_ids": [...], "atdr_alert_type"}]}. Decisions are "Real threat",
"Normal", "Normal but unusual" or "Unsure"; each change becomes a new
reviewed label and earlier labels are kept.
"""

import argparse
import json
from pathlib import Path

from atdr.app.db.database import SessionLocal
from atdr.app.services.label_review_service import apply_label_review


def main() -> None:
    parser = argparse.ArgumentParser(description="Apply a human label review as new reviewed labels.")
    parser.add_argument("decisions", type=Path)
    parser.add_argument("--reviewer", required=True, help="Who made the decisions (stored on each new label).")
    parser.add_argument("--apply", action="store_true", help="Write the labels. Without it, only report the plan.")
    args = parser.parse_args()
    payload = json.loads(args.decisions.read_text(encoding="utf-8"))
    with SessionLocal() as db:
        summary = apply_label_review(
            db,
            payload["decisions"],
            reviewer=args.reviewer,
            note_prefix=payload.get("note", f"label review from {args.decisions.name}"),
            apply=args.apply,
        )
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
