from __future__ import annotations

import argparse
import json
import sys

from atdr.app.core.config import get_settings
from atdr.app.db.database import SessionLocal
from atdr.app.services.audit_retention_service import (
    APPLY_CONFIRMATION,
    apply_audit_retention,
    build_audit_retention_report,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Report eligible old audit events. Applying is explicit and never deletes raw log evidence."
    )
    parser.add_argument("--retention-days", type=int, default=None)
    parser.add_argument("--batch-size", type=int, default=None)
    parser.add_argument("--apply", action="store_true", help="Apply one bounded eligible audit-event batch.")
    parser.add_argument("--confirm", default="", help=f"Required with --apply: {APPLY_CONFIRMATION}")
    parser.add_argument("--pretty", action="store_true")
    return parser


def main() -> int:
    args = _parser().parse_args()
    settings = get_settings()
    retention_days = args.retention_days or settings.audit_retention_days
    batch_size = args.batch_size or settings.audit_retention_batch_size
    if args.apply and args.confirm != APPLY_CONFIRMATION:
        print(
            json.dumps(
                {
                    "ok": False,
                    "status": "confirmation_required",
                    "message": f"Use --confirm {APPLY_CONFIRMATION} only after reviewing dry-run output.",
                    "secrets_exposed": False,
                },
                indent=2 if args.pretty else None,
            )
        )
        return 2
    try:
        with SessionLocal() as db:
            if args.apply:
                result = apply_audit_retention(
                    db,
                    retention_days=retention_days,
                    minimum_days=settings.audit_retention_min_days,
                    batch_size=batch_size,
                    confirmation=args.confirm,
                )
            else:
                result = build_audit_retention_report(
                    db,
                    retention_days=retention_days,
                    minimum_days=settings.audit_retention_min_days,
                    batch_size=batch_size,
                )
    except ValueError as exc:
        print(json.dumps({"ok": False, "status": "invalid_policy", "message": str(exc), "secrets_exposed": False}))
        return 2
    print(json.dumps({"ok": True, **result}, indent=2 if args.pretty else None, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
