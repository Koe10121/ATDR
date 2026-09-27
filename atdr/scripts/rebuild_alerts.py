"""Replace alerts raised by retired rules with what the current rules find.

Usage:
    python -m atdr.scripts.rebuild_alerts                       # dry run: what would change
    python -m atdr.scripts.rebuild_alerts --apply --actor NAME  # back up, then rebuild

Stop ATDR first (scripts/stop_system.cmd) so nothing else writes to the database. Alerts an analyst
has worked on are kept; every other alert moves to the alert_archive table, with its evidence, and
the current rules and watchlist run over every log. See atdr/app/services/alert_rebuild_service.py.
"""

from __future__ import annotations

import argparse
import json
import sys

from atdr.app.core.config import Settings
from atdr.app.db.database import SessionLocal
from atdr.app.services.alert_rebuild_service import plan_rebuild, rebuild_alerts
from atdr.app.services.persistence_service import create_database_backup

REASON = ("Raised by rules the catalog has since retired or narrowed; replaced by a re-run of the current "
          "rules over every log.")


def main() -> None:
    sys.stdout.reconfigure(errors="replace")
    parser = argparse.ArgumentParser(description="Rebuild alerts with the current rules.")
    parser.add_argument("--apply", action="store_true", help="back up the database, then rebuild")
    parser.add_argument("--actor", default="rebuild_alerts", help="who is doing this, for the audit log")
    parser.add_argument("--backup-dir", default="backups")
    args = parser.parse_args()

    with SessionLocal() as db:
        plan = plan_rebuild(db)
    print("Plan:", json.dumps({key: value for key, value in plan.items()}, indent=2))
    if not args.apply:
        print("Dry run: nothing changed. Add --apply to back up and rebuild.")
        return

    backup = create_database_backup(settings=Settings(), output_dir=args.backup_dir, execute=True)
    if not (backup.get("ok") and backup.get("status") == "backup_created"):
        raise SystemExit(f"Backup failed, nothing changed: {backup.get('status')}")
    print("Backup:", backup["backup_path"])
    with SessionLocal() as db:
        summary = rebuild_alerts(db, actor=args.actor, reason=REASON)
    print("Rebuilt:", json.dumps(summary, indent=2, default=str))


if __name__ == "__main__":
    main()
