"""Archive labels made before the log they point at was imported (they describe other records).

Usage:
    python -m atdr.scripts.archive_misattached_labels                       # dry run: what would move
    python -m atdr.scripts.archive_misattached_labels --apply --actor NAME  # back up, then archive

Stop ATDR first (scripts/stop_system.cmd). The labels move to the ml_label_archive table in full;
see atdr/app/services/label_archive_service.py. To undo, restore the backup taken before.
"""

from __future__ import annotations

import argparse
import json
import sys

from atdr.app.core.config import Settings
from atdr.app.db.database import SessionLocal
from atdr.app.services.label_archive_service import archive_misattached_labels
from atdr.app.services.persistence_service import create_database_backup


def main() -> None:
    sys.stdout.reconfigure(errors="replace")
    parser = argparse.ArgumentParser(description="Archive labels that no longer describe their log.")
    parser.add_argument("--apply", action="store_true", help="back up the database, then archive")
    parser.add_argument("--actor", default="archive_misattached_labels", help="who is doing this, for the audit log")
    parser.add_argument("--backup-dir", default="backups")
    args = parser.parse_args()

    with SessionLocal() as db:
        plan = archive_misattached_labels(db, actor=args.actor)
    print("Plan:", json.dumps(plan, indent=2))
    if not args.apply:
        print("Dry run: nothing changed. Add --apply to back up and archive.")
        return
    backup = create_database_backup(settings=Settings(), output_dir=args.backup_dir, execute=True)
    if not (backup.get("ok") and backup.get("status") == "backup_created"):
        raise SystemExit(f"Backup failed, nothing changed: {backup.get('status')}")
    print("Backup:", backup["backup_path"])
    with SessionLocal() as db:
        print("Archived:", json.dumps(archive_misattached_labels(db, actor=args.actor, apply=True), indent=2))


if __name__ == "__main__":
    main()
