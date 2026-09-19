from __future__ import annotations

import argparse
import json
from pathlib import Path

from atdr.app.detection.v564_window_aware_anomaly import (
    DEFAULT_LIMIT,
    run_window_aware_anomaly_redesign,
    safe_window_aware_error,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Compare window-aware advisory anomaly designs using private evidence "
            "without installing an artifact or exposing source details."
        )
    )
    parser.add_argument(
        "--sample-path",
        type=Path,
        required=True,
        help="Private PAN-OS evidence path. It is never included in output.",
    )
    parser.add_argument("--limit", type=int, default=DEFAULT_LIMIT)
    parser.add_argument(
        "--preflight-only",
        action="store_true",
        help="Validate evidence roles and safety without fitting candidates.",
    )
    parser.add_argument("--pretty", action="store_true")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        report = run_window_aware_anomaly_redesign(
            sample_path=args.sample_path,
            limit=args.limit,
            preflight_only=args.preflight_only,
        )
    except Exception as exc:  # Public failures must not disclose private evidence.
        report = safe_window_aware_error(exc)
    print(json.dumps(report, indent=2 if args.pretty else None, sort_keys=args.pretty))
    return 0 if report.get("ok") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
