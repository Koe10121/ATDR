"""Build the dashboard when its source is newer than its built files.

Usage:
    python -m atdr.scripts.build_dashboard            # build if the source changed since the last build
    python -m atdr.scripts.build_dashboard --force    # build anyway
    python -m atdr.scripts.build_dashboard --check    # say whether a build is needed; build nothing

scripts/start_system.cmd runs this before it starts the dashboard. It exits 0 when there is a build to serve (a new
one, the current one, or the last good one after a build that failed) and 1 when there is none.
"""

from __future__ import annotations

import argparse
import json
import sys

from atdr.app.services.dashboard_build_service import build_dashboard, build_state


def describe(result: dict) -> str:
    built_at = str(result.get("built_at") or "")[:16].replace("T", " ")
    status = result.get("status")
    if status == "current":
        return f"dashboard build is current (built {built_at} UTC)"
    if status == "built":
        return f"dashboard built in {result.get('seconds')} s"
    if status == "npm_missing":
        problem = "npm was not found, so the dashboard could not be built"
    else:
        problem = "the dashboard build FAILED"
    if result.get("ok"):
        return f"{problem}; ATDR serves the last good build ({built_at} UTC). Run: cd frontend; npm run build"
    return f"{problem}, and there is no earlier build to serve. Run: cd frontend; npm run build"


def main() -> None:
    sys.stdout.reconfigure(errors="replace")
    parser = argparse.ArgumentParser(description="Build the ATDR dashboard when its source has changed.")
    parser.add_argument("--force", action="store_true", help="build even when the source has not changed")
    parser.add_argument("--check", action="store_true", help="report only; build nothing")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    if args.check:
        state = build_state()
        print(json.dumps(state) if args.json else ("a build is needed" if state["stale"] else "dashboard build is current"))
        raise SystemExit(0)
    result = build_dashboard(force=args.force)
    print(json.dumps(result) if args.json else describe(result))
    if result.get("status") == "build_failed" and not args.json:
        print(result.get("output", ""), file=sys.stderr)
    raise SystemExit(0 if result.get("ok") else 1)


if __name__ == "__main__":
    main()
