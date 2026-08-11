from __future__ import annotations

import argparse
import json
from pathlib import Path

from atdr.app.core.config import get_settings
from atdr.app.db.database import SessionLocal
from atdr.app.services.v533_independent_acceptance_service import (
    DEFAULT_ASSISTANT_MANIFEST_PATH,
    DEFAULT_ASSISTANT_REVIEW_PATH,
    DEFAULT_OUTPUT_DIR,
    run_v533_independent_detection_assistant_acceptance,
)


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Validate frozen independent detection evidence and prepare or validate "
            "a separate human acceptance worksheet for the read-only SOC Assistant."
        )
    )
    parser.add_argument(
        "--detection-review-file",
        type=Path,
        help="Optional completed copy of the existing sealed blind detection review pack.",
    )
    parser.add_argument(
        "--prepare-detection-review",
        action="store_true",
        help="Create or resume the ignored prediction-blind human working copy without filling decisions.",
    )
    parser.add_argument(
        "--assistant-review-file",
        type=Path,
        default=DEFAULT_ASSISTANT_REVIEW_PATH,
    )
    parser.add_argument(
        "--assistant-manifest-file",
        type=Path,
        default=DEFAULT_ASSISTANT_MANIFEST_PATH,
    )
    parser.add_argument(
        "--prepare-assistant-review",
        action="store_true",
        help="Create or resume the ignored Assistant human acceptance worksheet.",
    )
    parser.add_argument(
        "--refresh-assistant-review",
        action="store_true",
        help="Refresh an unreviewed Assistant worksheet; refuses to overwrite any human input.",
    )
    parser.add_argument(
        "--execute-provider",
        action="store_true",
        help="Use the configured provider for the bounded redacted question set.",
    )
    parser.add_argument("--provider-interval-seconds", type=float, default=0.0)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--no-write", action="store_true")
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()

    if args.refresh_assistant_review and not args.prepare_assistant_review:
        parser.error("--refresh-assistant-review requires --prepare-assistant-review")

    with SessionLocal() as db:
        report = run_v533_independent_detection_assistant_acceptance(
            db,
            settings=get_settings(),
            output_dir=args.output_dir,
            detection_review_path=args.detection_review_file,
            prepare_detection_review=args.prepare_detection_review,
            assistant_review_path=args.assistant_review_file,
            assistant_manifest_path=args.assistant_manifest_file,
            prepare_assistant_review=args.prepare_assistant_review,
            refresh_assistant_review=args.refresh_assistant_review,
            execute_provider=args.execute_provider,
            provider_interval_seconds=max(0.0, args.provider_interval_seconds),
            write_reports=not args.no_write,
        )
    print(json.dumps(report, indent=2 if args.pretty else None, sort_keys=True, default=str))
    raise SystemExit(0 if report.get("ok") else 1)


if __name__ == "__main__":
    main()
