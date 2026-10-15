"""Count which scanners got answers on the internet-scanning alerts made before ATDR counted them.

Usage:
    python -m atdr.scripts.count_scanner_answers                       # dry run: what would be counted
    python -m atdr.scripts.count_scanner_answers --apply --actor NAME  # back up, then count

Since 15 Oct 2026 the hourly "Internet scanning" alert says, for each scanner, how many of its connections an MFU
address answered. An alert made before that is counted from its evidence logs, for the scanners whose every
connection is evidence (all of an imported file is; of the live feed only a sample is kept, and those are left
without a count). Only the alert's scanner list and its two texts change; no alert, log or evidence is added or
removed. ATDR may run meanwhile. See count_scanner_answers in atdr/app/services/alert_service.py.
"""

from __future__ import annotations

import argparse
import json
import sys

from sqlalchemy import select

from atdr.app.core.config import Settings
from atdr.app.db.database import SessionLocal
from atdr.app.db.models import Alert, AuditLog
from atdr.app.detection.attack_mapping import INTERNET_SCANNING_ALERT
from atdr.app.services.alert_service import count_scanner_answers
from atdr.app.services.persistence_service import create_database_backup


def _count(db, *, actor: str | None) -> list[dict]:
    counted = []
    for alert in db.scalars(select(Alert).where(Alert.alert_type == INTERNET_SCANNING_ALERT).order_by(Alert.id)):
        result = count_scanner_answers(db, alert)
        if not result["counted"] and not result["left"]:
            continue
        scanners = next((rule for rule in alert.matched_rules_json or [] if rule.get("code") == "group_metadata"), {}).get("scanners") or {}
        answered = sorted(((address, entry) for address, entry in scanners.items() if int(entry.get("answered") or 0) > 0),
                          key=lambda item: -int(item[1]["answered"]))
        counted.append({
            "alert": alert.id, **result,
            "got_answers": len(answered),
            "most_answered": [f"{address}: {entry['answered']} of {entry['connections']} answered by "
                              f"{entry.get('answered_by', 0)} or more MFU addresses, ports {entry.get('answered_ports', [])}, ping {entry.get('answered_ping', 0)}"
                              for address, entry in answered[:3]],
        })
        if actor and result["counted"]:
            db.add(AuditLog(actor=actor, action="scanner_answers_counted", target_type="alert", target_value=str(alert.id),
                            details={"counted": result["counted"], "left": result["left"], "got_answers": len(answered)}))
    return counted


def main(argv: list[str] | None = None) -> int:
    sys.stdout.reconfigure(errors="replace")
    parser = argparse.ArgumentParser(description="Count which scanners got answers on older internet-scanning alerts.")
    parser.add_argument("--apply", action="store_true", help="back up the database, then count")
    parser.add_argument("--actor", default="count_scanner_answers", help="who is doing this, for the audit log")
    parser.add_argument("--backup-dir", default="backups")
    args = parser.parse_args(argv)

    with SessionLocal() as db:
        plan = _count(db, actor=None)
        db.rollback()
    print("Would count:" if not args.apply else "Counting:", json.dumps(plan, indent=2))
    if not args.apply:
        print("Dry run: nothing changed. Add --apply to back up and count.")
        return 0
    if not any(item["counted"] for item in plan):
        print("Nothing to count.")
        return 0

    backup = create_database_backup(settings=Settings(), output_dir=args.backup_dir, execute=True)
    if not (backup.get("ok") and backup.get("status") == "backup_created"):
        print(f"Backup failed, nothing changed: {backup.get('status')}")
        return 1
    print("Backup:", backup["backup_path"])
    with SessionLocal() as db:
        done = _count(db, actor=args.actor)
        db.commit()
    print("Counted:", sum(item["counted"] for item in done), "scanners on", sum(1 for item in done if item["counted"]), "alerts.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
