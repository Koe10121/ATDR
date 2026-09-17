from __future__ import annotations

import argparse
import json
from pathlib import Path

from atdr.app.detection.v5631_advisor_demo_reliability import (
    DEFAULT_LIMIT,
    INSTALL_CONFIRMATION,
    run_anomaly_reliability_evaluation,
    safe_anomaly_reliability_error,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Evaluate ATDR's advisory IsolationForest against private development "
            "aggregates and controlled scenarios without exposing evidence."
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
        "--install-candidate",
        action="store_true",
        help="Install only a candidate that passes every fixed advisory gate.",
    )
    parser.add_argument(
        "--confirm",
        default="",
        help="Exact confirmation required for governed candidate installation.",
    )
    parser.add_argument("--pretty", action="store_true")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        report = run_anomaly_reliability_evaluation(
            sample_path=args.sample_path,
            limit=args.limit,
            install_candidate=args.install_candidate,
            confirmation=args.confirm,
        )
    except Exception as exc:  # Public failures must not disclose private evidence.
        report = safe_anomaly_reliability_error(exc)
    print(json.dumps(report, indent=2 if args.pretty else None, sort_keys=args.pretty))
    if report.get("ok") is True:
        return 0
    if args.install_candidate and args.confirm != INSTALL_CONFIRMATION:
        return 2
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
