from __future__ import annotations

import argparse
import json
from pathlib import Path

from atdr.app.services.template_bridge_contract import (
    PROJECT_TEMPLATE_DEFAULT,
    build_template_bridge_contract_report,
)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Validate the supervisor-template outer-shell to ATDR handoff contract without exposing secrets."
    )
    parser.add_argument(
        "--template-root",
        default=str(PROJECT_TEMPLATE_DEFAULT),
        help="Path to the official supervisor template project.",
    )
    parser.add_argument(
        "--atdr-root",
        default=".",
        help="Path to the ATDR repo root.",
    )
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON output.")
    args = parser.parse_args()

    report = build_template_bridge_contract_report(
        template_root=Path(args.template_root),
        atdr_root=Path(args.atdr_root),
    )
    print(json.dumps(report, indent=2 if args.pretty else None, sort_keys=True))
    raise SystemExit(0 if report["ok"] else 1)


if __name__ == "__main__":
    main()
