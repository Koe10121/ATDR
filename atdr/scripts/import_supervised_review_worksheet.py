from __future__ import annotations

import argparse
import json
from pathlib import Path

from atdr.app.db.database import SessionLocal
from atdr.app.services.supervised_review_worksheet_service import (
    import_worksheet,
    read_worksheet_csv,
    resolve_reviewer,
)


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Replay decisions recorded in a CSV worksheet (produced by "
            "export_supervised_review_worksheet.py and filled in by a human reviewer) "
            "back into the protected v5.62/v5.63/v5.65/v5.67 review workspaces. Each row is applied "
            "through the exact same save function the web review UI uses -- same "
            "single-owner lock, same revision-based concurrency check, same "
            "prediction-blind validation -- and only rows with 'yes' in the confirm "
            "column are submitted. This tool never fills in or infers a decision "
            "itself; it only replays what a human already typed into the sheet."
        )
    )
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--user-id", type=int, default=None)
    parser.add_argument("--username", default=None)
    parser.add_argument(
        "--overwrite-existing",
        action="store_true",
        help="Also apply rows whose target is already reviewed (default: skip them).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate the worksheet and report what would happen without saving anything.",
    )
    args = parser.parse_args()

    rows = read_worksheet_csv(args.input)

    with SessionLocal() as db:
        try:
            user = resolve_reviewer(db, user_id=args.user_id, username=args.username)
        except ValueError as exc:
            print(json.dumps({"ok": False, "detail": str(exc)}))
            raise SystemExit(1) from exc
        result = import_worksheet(
            user=user,
            rows=rows,
            overwrite_existing=args.overwrite_existing,
            dry_run=args.dry_run,
        )

    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result["ok"] else 1)


if __name__ == "__main__":
    main()
