from __future__ import annotations

import argparse
import json
from pathlib import Path

from atdr.app.detection.v520_schema_aware_abstention_validation import (
    OUTPUT_DIR,
    run_v520_schema_aware_abstention_validation,
)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate v5.19 terminal lock and v5.20 fail-closed schema abstention policy."
    )
    parser.add_argument("--output-dir", type=Path, default=OUTPUT_DIR)
    parser.add_argument("--no-write", action="store_true")
    parser.add_argument("--pretty", action="store_true")
    return parser


def main() -> None:
    args = _build_parser().parse_args()
    result = run_v520_schema_aware_abstention_validation(
        output_dir=args.output_dir,
        write_output=not args.no_write,
    )
    print(json.dumps(result, indent=2 if args.pretty else None, sort_keys=True, default=str))
    raise SystemExit(0 if result.get("ok") else 1)


if __name__ == "__main__":
    main()
