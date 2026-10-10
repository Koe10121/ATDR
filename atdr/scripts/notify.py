"""Report a problem of ATDR's own from outside the worker, report it over, or send a test message.

Usage:
    python -m atdr.scripts.notify --part atdr-worker            # that part keeps stopping
    python -m atdr.scripts.notify --part atdr-worker --over     # it is running again
    python -m atdr.scripts.notify --not-starting                # ATDR could not be started
    python -m atdr.scripts.notify --not-starting --over
    python -m atdr.scripts.notify --test email                  # one test message: windows, email or chat

scripts/watch_system.ps1 runs the first four: the watcher is not part of the worker, and the worker may be the
part that stopped. The notification is written down and sent at once, by this process. Exit code 0: done (also
when notifications are switched off, or there was nothing new to say); 1: a channel did not take the message (it
is tried again by the worker); 2: it could not be reported at all.
"""

from __future__ import annotations

import argparse
import sys

from atdr.app.db.database import SessionLocal
from atdr.app.services.notification_channels import CHANNELS
from atdr.app.services.notification_service import NOT_STARTING, part_problem, report_problem, send_test


def main(argv: list[str] | None = None) -> int:
    sys.stdout.reconfigure(errors="replace")
    parser = argparse.ArgumentParser(description="Report a problem of ATDR's own, or send a test message.")
    what = parser.add_mutually_exclusive_group(required=True)
    what.add_argument("--part", help="the part that keeps stopping, such as atdr-worker")
    what.add_argument("--not-starting", action="store_true", help="ATDR could not be started")
    what.add_argument("--test", choices=CHANNELS, help="send one test message through this channel")
    parser.add_argument("--over", action="store_true", help="the problem is over")
    args = parser.parse_args(argv)
    if args.test and args.over:
        parser.error("--over goes with --part or --not-starting")

    try:
        with SessionLocal() as db:
            if args.test:
                result = send_test(db, args.test, actor="atdr.scripts.notify")
                print(result["words"])
                return 0 if result["ok"] else 1
            problem = NOT_STARTING if args.not_starting else part_problem(args.part.strip())
            result = report_problem(db, problem, over=args.over)
    except Exception as error:  # the database is what cannot be reached: say so and let the caller try later
        print(f"could not be reported ({error.__class__.__name__})")
        return 2
    if not result["enabled"]:
        print("notifications are switched off")
        return 0
    if not result["made"]:
        print("nothing new to say")
        return 0
    failed = [sent for sent in result["sent"] if not sent["ok"]]
    for made in result["made"]:
        print(f"told: {made['title']}")
    for sent in failed:
        print(f"{sent['channel']}: {sent['error']}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
