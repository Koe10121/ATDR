"""Import a threat intelligence feed file into ATDR's watchlist.

Usage:
    python -m atdr.scripts.import_threat_intel --file threatfox.csv --source "ThreatFox recent"            # dry run
    python -m atdr.scripts.import_threat_intel --file threatfox.csv --source "ThreatFox recent" --apply --actor NAME

Download the file first (for example https://threatfox.abuse.ch/export/csv/ip-port/recent/ or
https://feodotracker.abuse.ch/downloads/ipblocklist.csv); ATDR itself never reaches the internet.
Re-importing a newer file under the same --source replaces that feed's list. The watchlist applies to
logs checked from now on; the report also says how many stored logs already contacted these addresses.
See atdr/app/services/threat_intel_service.py.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from atdr.app.db.database import SessionLocal
from atdr.app.services.threat_intel_service import import_feed, parse_feed, stored_log_matches


def main() -> None:
    sys.stdout.reconfigure(errors="replace")
    parser = argparse.ArgumentParser(description="Import a threat intelligence feed into the watchlist.")
    parser.add_argument("--file", type=Path, required=True)
    parser.add_argument("--source", required=True, help="the feed's name; re-imports under the same name replace it")
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--actor", default="import_threat_intel", help="who is doing this, for the audit log")
    args = parser.parse_args()

    feed = parse_feed(args.file.read_text(encoding="utf-8", errors="replace"))
    with SessionLocal() as db:
        summary = import_feed(db, source=args.source, feed=feed, actor=args.actor, apply=args.apply)
        summary["stored_logs_already_matching"] = stored_log_matches(db, [indicator.ip for indicator in feed.indicators])
    print(json.dumps(summary, indent=2))
    if not args.apply:
        print("Dry run: nothing changed. Add --apply to import.")


if __name__ == "__main__":
    main()
