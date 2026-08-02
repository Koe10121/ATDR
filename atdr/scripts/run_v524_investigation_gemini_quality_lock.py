from __future__ import annotations

import argparse
import json
from pathlib import Path

from atdr.app.core.config import get_settings
from atdr.app.services.v524_investigation_gemini_quality_service import run_v524_quality_lock


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Evaluate bounded ATDR investigation and Gemini quality using disposable synthetic evidence."
    )
    parser.add_argument(
        "--execute-provider",
        action="store_true",
        help="Run the bounded external-provider question set. Omit for a no-provider preflight.",
    )
    parser.add_argument(
        "--provider-interval-seconds",
        type=float,
        default=0.0,
        help="Optional delay between bounded provider calls for constrained quotas.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="Optional generated-report directory. Reports remain private/ignored.",
    )
    parser.add_argument("--no-write", action="store_true", help="Do not write generated diagnostic reports.")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print the privacy-safe JSON summary.")
    args = parser.parse_args()

    report = run_v524_quality_lock(
        settings=get_settings(),
        execute_provider=args.execute_provider,
        provider_interval_seconds=max(0.0, args.provider_interval_seconds),
        output_dir=args.output_dir,
        write_reports=not args.no_write,
    )
    print(json.dumps(report, indent=2 if args.pretty else None, sort_keys=True, default=str))


if __name__ == "__main__":
    main()
