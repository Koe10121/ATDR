"""List the MFU services that answered the internet in the logs ATDR already holds, and report the risky ones.

Usage:
    python -m atdr.scripts.build_exposure_map                       # dry run: what would be listed and reported
    python -m atdr.scripts.build_exposure_map --apply --actor NAME  # back up, then list and report

Since 15 Oct 2026 detection lists every MFU address and port that answers a connection from the internet, as it
checks logs (exposure_service). Logs checked before that are listed with this, once: every stored connection from the
internet that the MFU side answered. A service that should rarely be public (remote control, a database, file
sharing, a debugging port) or that an admin marked as not to be public gets its alert, as detection would have given
it; none counts as new, since all of them were there from the start. Run it again and nothing is counted twice: a
service whose connections were listed already is left as it is. ATDR may run meanwhile.
"""

from __future__ import annotations

import argparse
import json
import sys

from sqlalchemy import func, select

from atdr.app.core.config import Settings
from atdr.app.db.database import SessionLocal
from atdr.app.db.models import Alert, AuditLog, InternetService
from atdr.app.detection.attack_mapping import INTERNET_EXPOSURE_ALERT
from atdr.app.services.alert_service import ALERT_DEDUP_ACTIVE_STATUSES, EXPOSURE_EVIDENCE_PER_CHECK, record_internet_exposure
from atdr.app.services.exposure_service import answered_internet_logs, describe, exposure_findings, note_internet_services
from atdr.app.services.persistence_service import create_database_backup


def _build(db, *, actor: str | None) -> dict:
    if db.scalar(select(func.count(InternetService.id))):
        return {"listed_already": True}
    noted: dict = {}
    sources: dict = {}
    for chunk in answered_internet_logs(db):
        for key, (service, logs) in note_internet_services(db, chunk).items():
            kept = noted.get(key, (service, []))[1]
            # Evidence is the first few connections; the counts are on the service.
            noted[key] = (service, [*kept, *logs][:EXPOSURE_EVIDENCE_PER_CHECK])
            sources.setdefault(key, set()).update(str(log.src_ip) for log in logs if log.src_ip)
    # Every stored log is one look: the outside addresses are counted over all of them, not the busiest chunk.
    for key, (service, _logs) in noted.items():
        service.sources = max(int(service.sources or 0), len(sources.get(key, ())))
    findings = exposure_findings(noted, started=None)
    open_alerts = list(db.scalars(select(Alert).where(Alert.alert_type == INTERNET_EXPOSURE_ALERT,
                                                      Alert.status.in_(ALERT_DEDUP_ACTIVE_STATUSES))))
    touched = record_internet_exposure(db, findings, dedup_alerts=open_alerts) if findings else []
    if actor:
        db.add(AuditLog(actor=actor, action="exposure_map_built", target_type="internet_services", target_value="all",
                        details={"services": len(noted), "alerts": [alert.id for alert, _created in touched]}))
    db.flush()
    services = [describe(service) for service, _logs in noted.values()]
    return {
        "services": len(services),
        "addresses": len({item["address"] for item in services}),
        "risky": [f"{item['address']} port {item['port']}/{item['protocol']}: {item['what']} ({item['risk']['severity']})"
                  for item in services if item["risk"]],
        "alerts": [{"title": alert.title, "created": created} for alert, created in touched],
        "busiest": [f"{item['address']} port {item['port']}/{item['protocol']}: {item['what']}, {item['sources']} or more outside addresses"
                    for item in sorted(services, key=lambda item: -item["sources"])[:5]],
    }


def main(argv: list[str] | None = None) -> int:
    sys.stdout.reconfigure(errors="replace")
    parser = argparse.ArgumentParser(description="List the MFU services that answered the internet in the stored logs.")
    parser.add_argument("--apply", action="store_true", help="back up the database, then list and report")
    parser.add_argument("--actor", default="build_exposure_map", help="who is doing this, for the audit log")
    parser.add_argument("--backup-dir", default="backups")
    args = parser.parse_args(argv)

    with SessionLocal() as db:
        plan = _build(db, actor=None)
        db.rollback()
    print("Would list:" if not args.apply else "Listing:", json.dumps(plan, indent=2))
    if plan.get("listed_already"):
        print("The services are listed already: detection keeps the list up to date.")
        return 0
    if not args.apply:
        print("Dry run: nothing changed. Add --apply to back up and list.")
        return 0

    backup = create_database_backup(settings=Settings(), output_dir=args.backup_dir, execute=True)
    if not (backup.get("ok") and backup.get("status") == "backup_created"):
        print(f"Backup failed, nothing changed: {backup.get('status')}")
        return 1
    print("Backup:", backup["backup_path"])
    with SessionLocal() as db:
        done = _build(db, actor=args.actor)
        db.commit()
    print(f"Listed {done['services']} services on {done['addresses']} MFU addresses; {len(done['alerts'])} alerts.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
