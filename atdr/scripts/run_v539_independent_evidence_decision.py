from __future__ import annotations

import argparse
import json
from pathlib import Path

from atdr.app.core.config import get_settings
from atdr.app.db.database import SessionLocal
from atdr.app.services.evidence_review_service import EvidenceReviewError
from atdr.app.services.v539_independent_evidence_decision_service import (
    DEFAULT_OUTPUT_DIR,
    DEFAULT_STATE_PATH,
    V539_EXECUTION_CONFIRMATION,
    get_v539_evaluation_status,
    run_v539_frozen_activation_decision,
)


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Inspect v5.39 human-evidence readiness or execute the single "
            "governed read-only activation evaluation."
        )
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--preflight-only", action="store_true")
    mode.add_argument("--execute", action="store_true")
    parser.add_argument(
        "--confirm",
        default="",
        help=(
            "Required only with --execute; exact value: "
            f"{V539_EXECUTION_CONFIRMATION}"
        ),
    )
    parser.add_argument("--state-file", type=Path, default=DEFAULT_STATE_PATH)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--no-write", action="store_true")
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()
    settings = get_settings()
    try:
        if args.execute:
            with SessionLocal() as db:
                report = run_v539_frozen_activation_decision(
                    db,
                    settings=settings,
                    confirmation=args.confirm,
                    state_path=args.state_file,
                    output_dir=args.output_dir,
                    write_reports=not args.no_write,
                )
        else:
            report = get_v539_evaluation_status(
                settings=settings,
                state_path=args.state_file,
            )
    except EvidenceReviewError as exc:
        report = {
            "ok": False,
            "status": exc.code,
            "message": exc.public_message,
            "secrets_exposed": False,
            "private_paths_exposed": False,
            "reviewer_identities_exposed": False,
        }
    print(
        json.dumps(
            report,
            indent=2 if args.pretty else None,
            sort_keys=True,
            default=str,
        )
    )
    raise SystemExit(0 if report.get("ok") else 1)


if __name__ == "__main__":
    main()
