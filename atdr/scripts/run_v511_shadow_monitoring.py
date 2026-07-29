from __future__ import annotations

import argparse
import json
from typing import Any

from atdr.app.services.v511_shadow_monitoring_service import (
    build_shadow_monitoring_diagnostics,
    enqueue_monitoring_cycle_if_due,
    rehearse_shadow_retention,
)


def _render(value: dict[str, Any], *, pretty: bool) -> str:
    return json.dumps(
        value,
        indent=2 if pretty else None,
        sort_keys=pretty,
        default=str,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Inspect aggregate v5.11 shadow diagnostics, enqueue a bounded "
            "monitoring cycle when due, or rehearse retention in disposable storage."
        )
    )
    action = parser.add_mutually_exclusive_group()
    action.add_argument(
        "--enqueue-if-due",
        action="store_true",
        help="Queue one idempotent durable cycle only when monitoring is enabled and due.",
    )
    action.add_argument(
        "--retention-rehearsal",
        action="store_true",
        help="Exercise preview/apply retention in an in-memory disposable database.",
    )
    parser.add_argument("--actor", default="shadow-monitor")
    parser.add_argument("--limit", type=int, default=365)
    parser.add_argument("--pretty", action="store_true")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.retention_rehearsal:
        result = rehearse_shadow_retention()
    else:
        from atdr.app.db.database import SessionLocal

        with SessionLocal() as db:
            if args.enqueue_if_due:
                result = enqueue_monitoring_cycle_if_due(
                    db,
                    actor=args.actor,
                )
            else:
                result = build_shadow_monitoring_diagnostics(
                    db,
                    limit=max(1, min(int(args.limit), 1000)),
                )
    print(_render(result, pretty=args.pretty))
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
