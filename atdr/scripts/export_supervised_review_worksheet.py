from __future__ import annotations

import argparse
import json
from pathlib import Path

from atdr.app.db.database import SessionLocal
from atdr.app.detection.v562_supervised_qualification_campaign import ALLOWED_DECISIONS
from atdr.app.services.supervised_review_worksheet_service import (
    CONFIRM_TOKEN,
    export_worksheet,
    resolve_reviewer,
    write_worksheet_csv,
)


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Export pending prediction-blind supervised review rows to a CSV worksheet "
            "so a human reviewer can record independent decisions offline (Excel, "
            "Google Sheets, etc.) instead of one row at a time in the review UI. Every "
            "decision/attack_type/confidence/rationale/confirm cell is left blank -- "
            "this tool never suggests or infers a decision. Fill it in yourself, then "
            "replay it with import_supervised_review_worksheet.py."
        )
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--workspace", choices=("v562", "v563", "v565", "v567", "both", "all"), default="all"
    )
    parser.add_argument("--user-id", type=int, default=None)
    parser.add_argument("--username", default=None)
    parser.add_argument(
        "--include-reviewed",
        action="store_true",
        help="Also export already-reviewed rows (for audit/correction), not just pending ones.",
    )
    parser.add_argument(
        "--auto-start-batches",
        action="store_true",
        help="For v5.63/v5.65, automatically self-assign any not-yet-started batch before exporting it.",
    )
    args = parser.parse_args()

    with SessionLocal() as db:
        try:
            user = resolve_reviewer(db, user_id=args.user_id, username=args.username)
        except ValueError as exc:
            print(json.dumps({"ok": False, "detail": str(exc)}))
            raise SystemExit(1) from exc
        result = export_worksheet(
            user=user,
            workspace=args.workspace,
            include_reviewed=args.include_reviewed,
            auto_start_batches=args.auto_start_batches,
        )

    write_worksheet_csv(args.output, result["rows"])
    print(
        json.dumps(
            {
                "ok": True,
                "output": str(args.output),
                "rows_exported": result["row_count"],
                "allowed_decisions": sorted(ALLOWED_DECISIONS),
                "column_rules": {
                    "attack_type": "required only when decision is suspicious or malicious",
                    "confidence": "integer 1-100",
                    "rationale": "free text, minimum 8 characters -- your own independent judgment, never AI-assisted",
                    "confirm": f"must be exactly '{CONFIRM_TOKEN}' or the row is not submitted on import",
                },
                "warnings": result["warnings"],
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
