from __future__ import annotations

import argparse
import json
from pathlib import Path

from atdr.app.core.config import get_settings
from atdr.app.services.v525_integrated_acceptance_service import (
    DEFAULT_OUTPUT_DIR,
    DEFAULT_V524_EVIDENCE,
    run_v525_integrated_acceptance,
)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run ATDR v5.25 integrated acceptance against disposable evidence only."
    )
    parser.add_argument(
        "--use-temp-db",
        action="store_true",
        help="Required confirmation that configured databases are not acceptance targets.",
    )
    parser.add_argument(
        "--execute-provider",
        action="store_true",
        help="Run a fresh bounded provider quality lock instead of using locked v5.24 evidence.",
    )
    parser.add_argument(
        "--assistant-evidence",
        type=Path,
        default=DEFAULT_V524_EVIDENCE,
        help="Ignored v5.24 quality-lock JSON used when a fresh provider run is not requested.",
    )
    parser.add_argument("--log-count", type=int, default=5_000)
    parser.add_argument("--preflight-only", action="store_true")
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--no-write", action="store_true")
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()

    result = run_v525_integrated_acceptance(
        settings=get_settings(),
        use_temp_db=args.use_temp_db,
        execute_provider=args.execute_provider,
        log_count=args.log_count,
        preflight_only=args.preflight_only,
        assistant_evidence_path=args.assistant_evidence,
        output_dir=args.output_dir,
        write_reports=not args.no_write,
    )
    print(json.dumps(result, indent=2 if args.pretty else None, default=str))
    raise SystemExit(0 if result.get("ok") else 1)


if __name__ == "__main__":
    main()
