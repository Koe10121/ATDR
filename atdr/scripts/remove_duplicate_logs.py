"""Remove repeated copies of stored log lines, then rebuild the alert list from the logs that remain.

Usage:
    python -m atdr.scripts.remove_duplicate_logs                       # dry run: what would change
    python -m atdr.scripts.remove_duplicate_logs --apply --actor NAME  # back up, remove the copies, rebuild alerts

Stop ATDR first (scripts/stop_system.cmd) so nothing else writes to the database, and apply the database
migrations (python -m alembic upgrade head) so new alerts are numbered after every alert ever raised. One copy of
each line is kept, with the newest label made for it; alerts an analyst has worked on are kept; every other alert
moves to the alert_archive table and the current rules run over every log.
See atdr/app/services/duplicate_log_service.py and atdr/app/services/alert_rebuild_service.py.
"""

from __future__ import annotations

import argparse
import json
import sys

from atdr.app.core.config import Settings
from atdr.app.db.database import SessionLocal
from atdr.app.services.alert_rebuild_service import plan_rebuild, rebuild_alerts
from atdr.app.services.duplicate_log_service import plan_duplicate_removal, remove_duplicate_logs
from atdr.app.services.persistence_service import create_database_backup

REBUILD_REASON = (
    "Its counts and score were worked out with repeated copies of log lines. The copies were removed and the "
    "current rules re-run over every log."
)


def main() -> None:
    sys.stdout.reconfigure(errors="replace")
    parser = argparse.ArgumentParser(description="Remove repeated copies of log lines, then rebuild the alerts.")
    parser.add_argument("--apply", action="store_true", help="back up the database, remove the copies, rebuild the alerts")
    parser.add_argument("--actor", default="remove_duplicate_logs", help="who is doing this, for the audit log")
    parser.add_argument("--backup-dir", default="backups")
    args = parser.parse_args()

    with SessionLocal() as db:
        plan = {"duplicates": plan_duplicate_removal(db), "alerts": plan_rebuild(db)}
    print("Plan:", json.dumps(plan, indent=2))
    if not args.apply:
        print("Dry run: nothing changed. Add --apply to back up, remove the copies and rebuild the alerts.")
        return
    if not plan["duplicates"]["copies_to_remove"]:
        print("No line is stored more than once: nothing changed.")
        return
    backup = create_database_backup(settings=Settings(), output_dir=args.backup_dir, execute=True)
    if not (backup.get("ok") and backup.get("status") == "backup_created"):
        raise SystemExit(f"Backup failed, nothing changed: {backup.get('status')}")
    print("Backup:", backup["backup_path"])
    with SessionLocal() as db:
        removed = remove_duplicate_logs(db, actor=args.actor)
        print("Removed:", json.dumps(removed, indent=2))
        rebuilt = rebuild_alerts(db, actor=args.actor, reason=REBUILD_REASON)
    print("Rebuilt:", json.dumps(rebuilt, indent=2, default=str))


if __name__ == "__main__":
    main()
