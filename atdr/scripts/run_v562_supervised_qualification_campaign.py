from __future__ import annotations

import argparse
import json
from pathlib import Path

from atdr.app.db.database import SessionLocal
from atdr.app.detection.v562_supervised_qualification_campaign import (
    PREPARE_CONFIRMATION,
    TARGET_REVIEW_ROWS,
    get_public_v562_status,
    run_v562_supervised_qualification_campaign,
)


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Prepare a fresh prediction-blind supervised qualification campaign "
            "without training, evaluation, activation, or authoritative writes."
        )
    )
    parser.add_argument(
        "--sample-path",
        type=Path,
        default=None,
        help="Private PAN-OS path; never returned in command output.",
    )
    parser.add_argument(
        "--use-temp-db",
        action="store_true",
        help="Acknowledge disposable private-evidence processing.",
    )
    parser.add_argument("--preflight-only", action="store_true")
    parser.add_argument("--prepare-protected-review", action="store_true")
    parser.add_argument("--status-only", action="store_true")
    parser.add_argument("--confirm", default=None)
    parser.add_argument("--review-limit", type=int, default=TARGET_REVIEW_ROWS)
    parser.add_argument("--output-dir", type=Path, default=None)
    parser.add_argument("--no-report", action="store_true")
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()

    kwargs = {}
    if args.output_dir is not None:
        kwargs["output_dir"] = args.output_dir
    if args.status_only:
        result = get_public_v562_status(**kwargs)
    else:
        with SessionLocal() as db:
            result = run_v562_supervised_qualification_campaign(
                db,
                sample_path=args.sample_path,
                use_temp_db=args.use_temp_db,
                preflight_only=(
                    args.preflight_only or not args.prepare_protected_review
                ),
                prepare_protected_review=args.prepare_protected_review,
                confirmation=args.confirm,
                review_limit=args.review_limit,
                write_report=not args.no_report,
                **kwargs,
            )
    if not args.prepare_protected_review and not args.status_only:
        result.setdefault("required_confirmation", PREPARE_CONFIRMATION)
    print(json.dumps(result, indent=2 if args.pretty else None, default=str))
    raise SystemExit(0 if result.get("ok", True) else 1)


if __name__ == "__main__":
    main()
