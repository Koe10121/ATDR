from __future__ import annotations

import argparse
import json
from pathlib import Path

from atdr.app.detection.v528_blind_review_helper import (
    DEFAULT_PACK_PATH,
    DEFAULT_PROGRESS_PATH,
    DEFAULT_WORKING_PATH,
    prepare_review_working_copy,
    review_progress,
    run_interactive_review,
    write_progress_report,
)


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Prepare or use a private blind-first human review working copy. "
            "No detector predictions or AI suggestions are displayed."
        )
    )
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--prepare", action="store_true")
    action.add_argument("--status", action="store_true")
    action.add_argument("--interactive", action="store_true")
    parser.add_argument("--pack-file", type=Path, default=DEFAULT_PACK_PATH)
    parser.add_argument("--working-file", type=Path, default=DEFAULT_WORKING_PATH)
    parser.add_argument("--progress-file", type=Path, default=DEFAULT_PROGRESS_PATH)
    parser.add_argument(
        "--reviewer",
        default="",
        help="Independent human reviewer identity; required for interactive mode.",
    )
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()

    if args.interactive:
        if not args.reviewer.strip():
            parser.error("--reviewer is required for interactive review.")
        result = run_interactive_review(
            pack_path=args.pack_file,
            working_path=args.working_file,
            progress_path=args.progress_file,
            reviewer=args.reviewer,
        )
    elif args.prepare:
        result = prepare_review_working_copy(
            pack_path=args.pack_file,
            working_path=args.working_file,
        )
    else:
        result = review_progress(
            pack_path=args.pack_file,
            working_path=args.working_file,
        )
        write_progress_report(result, progress_path=args.progress_file)
    print(json.dumps(result, indent=2 if args.pretty else None, sort_keys=True))


if __name__ == "__main__":
    main()
