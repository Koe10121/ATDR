from __future__ import annotations

import argparse
import json
from pathlib import Path

from atdr.app.detection.v549_fixed_revalidation_decision import (
    V549DecisionError,
    get_public_v549_status,
)


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Validate and report the read-only v5.49 supervised candidate "
            "decision. This command does not train or activate a model."
        )
    )
    parser.add_argument("--output-dir", type=Path, default=None)
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()

    kwargs = {}
    if args.output_dir is not None:
        kwargs["output_dir"] = args.output_dir
    try:
        result = get_public_v549_status(**kwargs)
        exit_code = 0
    except V549DecisionError as exc:
        result = {
            "ok": False,
            "status": "failed_closed_integrity_error",
            "message": str(exc),
            "model_activated": False,
            "model_promoted": False,
            "response_automation_allowed": False,
            "secrets_exposed": False,
        }
        exit_code = 1
    print(json.dumps(result, indent=2 if args.pretty else None, default=str))
    raise SystemExit(exit_code)


if __name__ == "__main__":
    main()
