from __future__ import annotations

import argparse
import json
from pathlib import Path

from atdr.app.detection.v527_blind_review_evaluation import (
    DEFAULT_EVIDENCE_DIR,
    run_v527_blind_review_evaluation,
)


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Validate independent blind reviews and evaluate the existing frozen "
            "v5.26 predictions without rerunning any detector."
        )
    )
    parser.add_argument(
        "--evidence-dir",
        type=Path,
        default=DEFAULT_EVIDENCE_DIR,
        help="Private ignored evidence directory.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_EVIDENCE_DIR,
        help="Private ignored diagnostic-report directory.",
    )
    parser.add_argument(
        "--review-file",
        type=Path,
        default=None,
        help=(
            "Optional ignored reviewed working copy. The sealed blind pack remains "
            "immutable and supplies evidence only."
        ),
    )
    parser.add_argument(
        "--no-write",
        action="store_true",
        help="Validate without writing private reports or the first-use integrity seal.",
    )
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()

    report = run_v527_blind_review_evaluation(
        evidence_dir=args.evidence_dir,
        output_dir=args.output_dir,
        review_path=args.review_file,
        write_reports=not args.no_write,
        write_private_seal=not args.no_write,
    )
    print(json.dumps(report, indent=2 if args.pretty else None, sort_keys=True))


if __name__ == "__main__":
    main()
