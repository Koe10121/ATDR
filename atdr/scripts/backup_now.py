"""A checked backup of ATDR's database, now, in the folder its scheduled backups go to.

Usage:
    python -m atdr.scripts.backup_now                             # a backup taken by hand; it is never thinned out
    python -m atdr.scripts.backup_now --purpose before_release    # what a release takes before it changes the database

The copy counts only once its checksum matches and SQLite finds it whole (scheduled_backup_service.take_backup).
scripts/release.cmd runs the second form, in the live copy, before it migrates the database; of those backups the
newest three are kept. Exit code 0: the backup is there; 1: it is not, and nothing that is not a healthy backup
was left behind.
"""

from __future__ import annotations

import argparse
import json
import sys

from atdr.app.core.config import get_settings
from atdr.app.services.scheduled_backup_service import (
    PURPOSE_BEFORE_RELEASE,
    backup_folder,
    failure_words,
    take_backup,
    thin_before_release,
)

PURPOSES = ("manual", PURPOSE_BEFORE_RELEASE)


def main(argv: list[str] | None = None) -> int:
    sys.stdout.reconfigure(errors="replace")
    parser = argparse.ArgumentParser(description="Take a checked backup of ATDR's database now.")
    parser.add_argument("--purpose", choices=PURPOSES, default="manual")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    settings = get_settings()
    folder = backup_folder(settings)
    result = take_backup(settings, purpose=args.purpose, folder=folder)
    if not result.get("ok"):
        words = failure_words(result.get("status"))
        print(json.dumps({"ok": False, "status": result.get("status"), "words": words}) if args.json else f"No backup was taken: {words}.")
        return 1
    thinned = thin_before_release(folder, settings) if args.purpose == PURPOSE_BEFORE_RELEASE else []
    said = {"ok": True, "backup_path": result["backup_path"], "artifact_name": result["artifact_name"],
            "size_bytes": result.get("size_bytes"), "folder": str(folder), "thinned": thinned}
    print(json.dumps(said) if args.json else f"Backup taken and checked: {result['backup_path']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
