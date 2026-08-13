from __future__ import annotations

import argparse
import json
from pathlib import Path

from atdr.app.core.config import get_settings
from atdr.app.db.database import SessionLocal
from atdr.app.services.v533_independent_acceptance_service import (
    DEFAULT_ASSISTANT_MANIFEST_PATH,
    DEFAULT_ASSISTANT_REVIEW_PATH,
)
from atdr.app.services.v536_independent_evidence_activation_service import (
    DEFAULT_OUTPUT_DIR,
    run_v536_independent_evidence_activation_decision,
)


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Execute the read-only v5.36 independent-evidence audit and make a "
            "fixed, fail-closed supervised activation decision."
        )
    )
    parser.add_argument(
        "--detection-review-file",
        type=Path,
        help="Optional completed human-only copy of the sealed detection review pack.",
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
        "--execute-provider",
        action="store_true",
        help="Run the bounded, redacted Gemini operational probe if configured.",
    )
    parser.add_argument("--provider-interval-seconds", type=float, default=0.0)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--no-write", action="store_true")
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()

    with SessionLocal() as db:
        report = run_v536_independent_evidence_activation_decision(
            db,
            settings=get_settings(),
            output_dir=args.output_dir,
            detection_review_path=args.detection_review_file,
            assistant_review_path=args.assistant_review_file,
            assistant_manifest_path=args.assistant_manifest_file,
            execute_provider=args.execute_provider,
            provider_interval_seconds=max(0.0, args.provider_interval_seconds),
            write_reports=not args.no_write,
        )
    print(json.dumps(report, indent=2 if args.pretty else None, sort_keys=True, default=str))
    raise SystemExit(0 if report.get("ok") else 1)


if __name__ == "__main__":
    main()
