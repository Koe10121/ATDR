from __future__ import annotations

import argparse
import json

from atdr.app.db.database import SessionLocal, init_db
from atdr.app.detection.v51_supervised_lifecycle import (
    activate_governed_supervised_model,
    disable_governed_supervised_model,
    persist_supervised_telemetry_snapshot,
    rollback_governed_supervised_model,
    supervised_lifecycle_status,
)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Inspect or safely change the governed supervised model lifecycle.")
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--status", action="store_true", help="Inspect the current lifecycle without changing it.")
    action.add_argument("--activate-model-id", type=int)
    action.add_argument("--disable", action="store_true")
    action.add_argument("--rollback", action="store_true")
    action.add_argument(
        "--snapshot-telemetry",
        action="store_true",
        help="Persist aggregate-only shadow telemetry without raw evidence or response side effects.",
    )
    parser.add_argument(
        "--mode",
        choices=["shadow_observation", "decision_support"],
        default="shadow_observation",
    )
    parser.add_argument("--actor", default="cli")
    parser.add_argument("--pretty", action="store_true")
    return parser


def main() -> None:
    args = _build_parser().parse_args()

    init_db()
    with SessionLocal() as db:
        if args.activate_model_id is not None:
            result = activate_governed_supervised_model(
                db,
                model_id=args.activate_model_id,
                lifecycle_state=args.mode,
                actor=args.actor,
            )
        elif args.disable:
            result = disable_governed_supervised_model(db, actor=args.actor)
        elif args.rollback:
            result = rollback_governed_supervised_model(db, actor=args.actor)
        elif args.snapshot_telemetry:
            result = persist_supervised_telemetry_snapshot(db, actor=args.actor)
        else:
            result = supervised_lifecycle_status(db)
    print(json.dumps(result, indent=2 if args.pretty else None, default=str))
    raise SystemExit(0 if result.get("ok", True) else 1)


if __name__ == "__main__":
    main()
