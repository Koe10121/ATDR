from __future__ import annotations

import argparse
import json
from pathlib import Path

from atdr.app.core.config import get_settings
from atdr.app.db.database import SessionLocal
from atdr.app.services.v527_gemini_real_alert_quality_service import (
    DEFAULT_OUTPUT_DIR,
    run_v527_gemini_real_alert_quality,
)


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Evaluate the read-only SOC Assistant on a bounded, redacted snapshot "
            "of existing dashboard records."
        )
    )
    parser.add_argument(
        "--execute-provider",
        action="store_true",
        help="Run the bounded external-provider question set when safely configured.",
    )
    parser.add_argument("--max-alerts", type=int, default=3)
    parser.add_argument("--provider-interval-seconds", type=float, default=0.0)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--no-write", action="store_true")
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()

    with SessionLocal() as db:
        report = run_v527_gemini_real_alert_quality(
            db,
            settings=get_settings(),
            execute_provider=args.execute_provider,
            max_alerts=max(1, min(args.max_alerts, 5)),
            provider_interval_seconds=max(0.0, args.provider_interval_seconds),
            output_dir=args.output_dir,
            write_reports=not args.no_write,
        )
    print(json.dumps(report, indent=2 if args.pretty else None, sort_keys=True, default=str))


if __name__ == "__main__":
    main()
