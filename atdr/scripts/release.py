"""Put a checked version of ATDR live, from the folder it is developed in.

Usage (scripts\\release.cmd runs this):
    python -m atdr.scripts.release                    # what runs, and what is waiting to be released
    python -m atdr.scripts.release check [COMMIT]     # check a commit without releasing it
    python -m atdr.scripts.release go [COMMIT]        # check it and make it the version that runs (default: HEAD)
    python -m atdr.scripts.release back               # the version before, when a released one is still wrong
    python -m atdr.scripts.release recover            # after a release that was cut off: put back what was running
    python -m atdr.scripts.release setup [COMMIT]     # once: make the live copy and move ATDR to it

A commit is checked when GitHub's checks for exactly it are green or, when it is not on GitHub, when the whole
test suite passes here (--local runs the tests here in any case). A version that does not come up healthy is put
back by itself. Exit code 0: done; 1: refused, or the version before was put back; 2: ATDR is not running.
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

from atdr.app.services import release_service
from atdr.app.services.release_service import DEFAULT_LIVE_ROOT, PROJECT_ROOT, ReleaseError, Tools


def _when(value: Any) -> str:
    moment = release_service._time(value)
    return moment.astimezone().strftime("%d %b %Y %H:%M") if isinstance(moment, datetime) else "an unknown time"


def describe(found: dict[str, Any]) -> list[str]:
    """What `status` found, in sentences."""

    lines = []
    live = found.get("live")
    if live is None:
        lines += ["ATDR has no live copy on this machine: it runs from this folder, so a change to a file goes live when a "
                  "part restarts.", "  Make the live copy once: scripts\\release.cmd setup"]
    else:
        record = live["record"]
        lines.append(f"Live copy: {live['root']}")
        lines.append(f"  Version {record.get('short')} ({record.get('subject')}), live since {_when(record.get('released_at'))}.")
        if record.get("check"):
            lines.append(f"  Checked before it went live: {record['check']}.")
        if live["unfinished"]:
            lines.append(f"  A RELEASE DID NOT FINISH (it began {_when(live['unfinished'].get('started_at'))}). Put back the version "
                         "that was running: scripts\\release.cmd recover")
        if not live["as_released"]:
            lines.append("  ITS FILES ARE NOT AT THAT VERSION: someone moved them to another commit by hand.")
        if live["changed_by_hand"]:
            shown = ", ".join(live["changed_by_hand"][:5])
            lines.append(f"  {len(live['changed_by_hand'])} of its files were changed by hand: {shown}.")
        lines.append("  ATDR is running: every part is up and answers." if not live["wrong"] else f"  ATDR: {'; '.join(live['wrong'])}.")
    development = found["development"]
    lines.append(f"Development folder: {development['root']}")
    lines.append(f"  HEAD is {development['short']} ({development['subject']}).")
    if live is not None and live["commits_not_live"] is not None:
        waiting = live["commits_not_live"]
        lines.append("  It is the version that runs." if waiting == 0 and live["record"]["commit"] == development["commit"]
                     else f"  {waiting} {'commit is' if waiting == 1 else 'commits are'} not live yet: scripts\\release.cmd go")
    if development["checked"]:
        lines.append(f"  HEAD was checked {_when(development['checked'].get('at'))}: {development['checked'].get('words')}.")
    if development["uncommitted"]:
        count = len(development["uncommitted"])
        lines.append(f"  {count} {'file is' if count == 1 else 'files are'} not committed; a release takes commits only.")
    return lines


def main(argv: list[str] | None = None) -> int:
    sys.stdout.reconfigure(errors="replace")
    parser = argparse.ArgumentParser(description="Put a checked version of ATDR live.")
    parser.add_argument("action", nargs="?", default="status", choices=("status", "check", "go", "back", "recover", "setup"))
    parser.add_argument("commit", nargs="?", default="HEAD", help="the commit to check or release (default: HEAD)")
    parser.add_argument("--local", action="store_true", help="run the tests here even when GitHub has checked the commit")
    parser.add_argument("--live", default=None, help=f"where the live copy is made by setup (default: {DEFAULT_LIVE_ROOT})")
    args = parser.parse_args(argv)

    tools, dev = Tools(), PROJECT_ROOT
    try:
        record = release_service.read_record(dev)
        if record is not None:
            print(f"This folder is the live copy (version {record.get('short')}). Releases are made from the folder ATDR is "
                  f"developed in: {record.get('source')}")
            return 1
        known = release_service.live_copy_of(dev)
        live = Path(args.live).resolve() if args.live else known or DEFAULT_LIVE_ROOT
        if args.action == "status":
            print("\n".join(describe(release_service.status(tools, dev, live))))
            return 0
        if args.action == "check":
            commit = release_service.resolve_commit(tools, dev, args.commit)
            print(f"Checking {commit[:7]}.")
            checked = release_service.check_commit(tools, dev, commit, local=args.local)
            print(f"Checked: {checked['words']}{' (checked earlier)' if checked.get('earlier') else ''}." if checked["ok"] else checked["words"])
            return 0 if checked["ok"] else 1
        if args.action == "setup":
            result = release_service.setup(tools, dev, live, args.commit, local=args.local)
            print(result["words"])
            if result["ok"]:
                print(f"  Its settings are in {live}\\.env from now on; this folder's own .env no longer writes backups or sends "
                      f"messages ({', '.join(result['quieted']) or 'nothing had to change'}).")
                print("  A new version goes there with: scripts\\release.cmd go")
            return 0 if result["ok"] else 1
        if args.action == "recover":
            result = release_service.recover(tools, live)
        elif args.action == "back":
            result = release_service.go_back(tools, dev, live)
        else:
            result = release_service.release(tools, dev, live, args.commit, local=args.local)
        print(result["words"])
        return 0 if result["ok"] else 2 if result.get("live_down") else 1
    except ReleaseError as refused:
        print(str(refused))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
