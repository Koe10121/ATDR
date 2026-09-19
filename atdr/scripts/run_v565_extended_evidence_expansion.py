from __future__ import annotations

import argparse
import json
from pathlib import Path

from atdr.app.db.database import SessionLocal
from atdr.app.detection.v565_extended_evidence_expansion import (
    BATCH_SIZE,
    PREPARE_CONFIRMATION,
    TARGET_EXTENDED_ROWS,
    V565_OUTPUT_DIR,
    get_public_v565_status,
    run_v565_extended_evidence_expansion,
)


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Expand the protected supervised evidence campaign a third time, on top "
            "of the locked v562+v563 1,000-row pack, without training, evaluation, "
            "activation, or authoritative writes. Coverage-group round-robin "
            "selection is weighted toward the categories that empirically produced "
            "threat-positive decisions in the completed v562/v563 review."
        )
    )
    parser.add_argument(
        "--sample-path",
        type=Path,
        default=None,
        help="Private primary PAN-OS path; never returned in command output.",
    )
    parser.add_argument(
        "--use-temp-db",
        action="store_true",
        help="Acknowledge disposable private-evidence processing.",
    )
    parser.add_argument("--preflight-only", action="store_true")
    parser.add_argument("--prepare-extended-review", action="store_true")
    parser.add_argument("--status-only", action="store_true")
    parser.add_argument("--confirm", default=None)
    parser.add_argument("--extended-limit", type=int, default=TARGET_EXTENDED_ROWS)
    parser.add_argument("--batch-size", type=int, default=BATCH_SIZE)
    parser.add_argument("--output-dir", type=Path, default=V565_OUTPUT_DIR)
    parser.add_argument("--no-report", action="store_true")
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()

    if args.status_only:
        result = get_public_v565_status(args.output_dir)
    else:
        with SessionLocal() as db:
            result = run_v565_extended_evidence_expansion(
                db,
                sample_path=args.sample_path,
                use_temp_db=args.use_temp_db,
                preflight_only=(args.preflight_only or not args.prepare_extended_review),
                prepare_extended_review=args.prepare_extended_review,
                confirmation=args.confirm,
                extended_limit=args.extended_limit,
                batch_size=args.batch_size,
                output_dir=args.output_dir,
                write_report=not args.no_report,
            )
    if not args.prepare_extended_review and not args.status_only:
        result.setdefault("required_confirmation", PREPARE_CONFIRMATION)
    print(json.dumps(result, indent=2 if args.pretty else None, default=str))
    raise SystemExit(0 if result.get("ok", True) else 1)


if __name__ == "__main__":
    main()
