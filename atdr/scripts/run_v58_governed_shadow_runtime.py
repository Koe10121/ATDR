from __future__ import annotations

import argparse
import json
from datetime import datetime
from pathlib import Path

from atdr.app.db.database import SessionLocal
from atdr.app.services.v58_shadow_scoring_service import (
    governed_evidence_intake_preflight,
    governed_shadow_runtime_status,
)


def _date(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Inspect or execute the bounded v5.8 read-only shadow runtime, "
            "or preflight genuinely independent evidence."
        )
    )
    parser.add_argument("--execute-shadow", action="store_true")
    parser.add_argument("--source-id", type=int)
    parser.add_argument("--start-at")
    parser.add_argument("--end-at")
    parser.add_argument("--limit", type=int)
    parser.add_argument("--sample-path")
    parser.add_argument("--evidence-manifest")
    parser.add_argument("--preflight-only", action="store_true")
    parser.add_argument("--use-temp-db", action="store_true")
    parser.add_argument("--min-samples", type=int, default=100)
    parser.add_argument("--chunk-size", type=int, default=2000)
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()

    evidence_mode = bool(
        args.sample_path
        or args.evidence_manifest
        or args.preflight_only
    )
    if evidence_mode and (
        not args.sample_path
        or not args.evidence_manifest
        or not args.preflight_only
        or not args.use_temp_db
    ):
        result = {
            "ok": False,
            "status": "failed_closed_evidence_arguments_incomplete",
            "required": [
                "--sample-path",
                "--evidence-manifest",
                "--preflight-only",
                "--use-temp-db",
            ],
            "private_path_returned": False,
        }
        print(
            json.dumps(
                result,
                indent=2 if args.pretty else None,
            )
        )
        raise SystemExit(2)
    if evidence_mode and args.execute_shadow:
        result = {
            "ok": False,
            "status": "failed_closed_conflicting_modes",
        }
        print(
            json.dumps(
                result,
                indent=2 if args.pretty else None,
            )
        )
        raise SystemExit(2)

    with SessionLocal() as db:
        if evidence_mode:
            result = governed_evidence_intake_preflight(
                db,
                sample_path=Path(str(args.sample_path)),
                evidence_manifest_path=Path(
                    str(args.evidence_manifest)
                ),
                min_samples=args.min_samples,
                chunk_size=args.chunk_size,
            )
        else:
            try:
                start_at = _date(args.start_at)
                end_at = _date(args.end_at)
            except ValueError:
                result = {
                    "ok": False,
                    "status": "failed_closed_invalid_datetime",
                }
            else:
                result = governed_shadow_runtime_status(
                    db,
                    execute=args.execute_shadow,
                    source_id=args.source_id,
                    start_at=start_at,
                    end_at=end_at,
                    limit=args.limit,
                )
    print(
        json.dumps(
            result,
            indent=2 if args.pretty else None,
            default=str,
        )
    )
    raise SystemExit(0 if result.get("ok") else 1)


if __name__ == "__main__":
    main()
