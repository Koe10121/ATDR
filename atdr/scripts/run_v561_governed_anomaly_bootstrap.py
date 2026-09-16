from __future__ import annotations

import argparse
import json
from pathlib import Path

from atdr.app.core.config import PROJECT_ROOT
from atdr.app.services.v561_anomaly_bootstrap_service import (
    DEFAULT_EVIDENCE_LIMIT,
    EXECUTION_CONFIRMATION,
    run_governed_anomaly_bootstrap,
    safe_bootstrap_error,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Preflight or explicitly bootstrap ATDR's advisory IsolationForest capability.",
    )
    source = parser.add_mutually_exclusive_group()
    source.add_argument(
        "--evidence-path",
        type=Path,
        help="Private operator evidence file or directory. The path is never included in output.",
    )
    source.add_argument(
        "--use-committed-synthetic-sample",
        action="store_true",
        help="Use committed benign synthetic scenarios for capability testing.",
    )
    parser.add_argument("--limit", type=int, default=DEFAULT_EVIDENCE_LIMIT)
    parser.add_argument("--execute", action="store_true", help="Train after a passing preflight.")
    parser.add_argument(
        "--confirm",
        default="",
        help="Exact execution confirmation returned by preflight.",
    )
    parser.add_argument(
        "--replace-existing",
        action="store_true",
        help="Replace an existing advisory artifact with rollback protection.",
    )
    parser.add_argument("--pretty", action="store_true")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        report = run_governed_anomaly_bootstrap(
            project_root=PROJECT_ROOT,
            evidence_path=args.evidence_path,
            use_committed_synthetic_sample=args.use_committed_synthetic_sample,
            limit=args.limit,
            execute=args.execute,
            confirmation=args.confirm,
            replace_existing=args.replace_existing,
        )
    except Exception as exc:  # Public failures must not disclose private evidence.
        report = safe_bootstrap_error(exc)
    print(json.dumps(report, indent=2 if args.pretty else None, sort_keys=args.pretty))
    if report.get("ok") is True:
        return 0
    if args.execute and args.confirm != EXECUTION_CONFIRMATION:
        return 2
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
