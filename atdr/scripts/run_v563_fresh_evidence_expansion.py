from __future__ import annotations

import argparse
import json
from pathlib import Path

from atdr.app.db.database import SessionLocal
from atdr.app.detection.v563_fresh_evidence_expansion import (
    BATCH_SIZE,
    PREPARE_CONFIRMATION,
    TARGET_SUPPLEMENTAL_ROWS,
    V563_OUTPUT_DIR,
    get_public_v563_status,
    run_second_source_intake_preflight,
    run_v563_fresh_evidence_expansion,
)


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Expand the protected supervised evidence campaign without training, "
            "evaluation, activation, or authoritative writes."
        )
    )
    parser.add_argument(
        "--sample-path",
        type=Path,
        default=None,
        help="Private primary PAN-OS path; never returned in command output.",
    )
    parser.add_argument(
        "--second-source-path",
        type=Path,
        default=None,
        help="Future private second-source path; never returned or retained.",
    )
    parser.add_argument(
        "--use-temp-db",
        action="store_true",
        help="Acknowledge disposable private-evidence processing.",
    )
    parser.add_argument("--preflight-only", action="store_true")
    parser.add_argument("--prepare-supplemental-review", action="store_true")
    parser.add_argument("--check-second-source", action="store_true")
    parser.add_argument("--status-only", action="store_true")
    parser.add_argument("--confirm", default=None)
    parser.add_argument(
        "--supplemental-limit", type=int, default=TARGET_SUPPLEMENTAL_ROWS
    )
    parser.add_argument("--batch-size", type=int, default=BATCH_SIZE)
    parser.add_argument("--output-dir", type=Path, default=V563_OUTPUT_DIR)
    parser.add_argument("--no-report", action="store_true")
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()

    if sum(
        bool(value)
        for value in (
            args.status_only,
            args.check_second_source,
            args.prepare_supplemental_review,
        )
    ) > 1:
        parser.error(
            "Choose only one of --status-only, --check-second-source, or "
            "--prepare-supplemental-review."
        )

    if args.status_only:
        result = get_public_v563_status(args.output_dir)
    else:
        with SessionLocal() as db:
            if args.check_second_source:
                result = run_second_source_intake_preflight(
                    db,
                    second_source_path=args.second_source_path,
                    use_temp_db=args.use_temp_db,
                    output_dir=args.output_dir,
                )
            else:
                result = run_v563_fresh_evidence_expansion(
                    db,
                    sample_path=args.sample_path,
                    use_temp_db=args.use_temp_db,
                    preflight_only=(
                        args.preflight_only
                        or not args.prepare_supplemental_review
                    ),
                    prepare_supplemental_review=args.prepare_supplemental_review,
                    confirmation=args.confirm,
                    supplemental_limit=args.supplemental_limit,
                    batch_size=args.batch_size,
                    output_dir=args.output_dir,
                    write_report=not args.no_report,
                )
    if not args.prepare_supplemental_review and not args.status_only:
        result.setdefault("required_confirmation", PREPARE_CONFIRMATION)
    print(json.dumps(result, indent=2 if args.pretty else None, default=str))
    raise SystemExit(0 if result.get("ok", True) else 1)


if __name__ == "__main__":
    main()
