from __future__ import annotations

import argparse
import json

from atdr.app.core.config import get_settings
from atdr.app.db.database import SessionLocal
from atdr.app.services.staged_input_retention_service import (
    apply_staged_cleanup,
    build_staged_cleanup_plan,
    public_cleanup_plan,
)


CONFIRMATION = "APPLY-STAGED-CLEANUP"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Preview expired ATDR staged-input cleanup.")
    parser.add_argument("--retention-hours", type=int, default=None)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--confirm", default="")
    parser.add_argument("--pretty", action="store_true")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    settings = get_settings()
    retention_hours = args.retention_hours or settings.operation_staging_retention_hours
    if args.apply and args.confirm != CONFIRMATION:
        raise SystemExit(f"Apply requires --confirm {CONFIRMATION}")
    with SessionLocal() as db:
        plan = build_staged_cleanup_plan(db, retention_hours=retention_hours)
        result = apply_staged_cleanup(plan) if args.apply else public_cleanup_plan(plan)
    print(json.dumps(result, indent=2 if args.pretty else None, default=str))


if __name__ == "__main__":
    main()
