from __future__ import annotations

import argparse
import json
from pathlib import Path

from atdr.app.detection.v548_manual_anchor_fixed_revalidation import (
    MEASURED_CONFIRMATION,
    run_v548_manual_anchor_fixed_revalidation,
)


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Lock and inspect the v5.48 development-only manual-anchor "
            "revalidation protocol. No model is activated."
        )
    )
    parser.add_argument("--preflight-only", action="store_true")
    parser.add_argument("--status-only", action="store_true")
    parser.add_argument(
        "--use-temp-db",
        action="store_true",
        help="Confirm that disposable validation storage is intended.",
    )
    parser.add_argument(
        "--confirm-fixed-revalidation",
        action="store_true",
        help="Explicitly authorize the one-time measured development run.",
    )
    parser.add_argument("--output-dir", type=Path, default=None)
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()

    kwargs = {
        "status_only": args.status_only,
        "preflight_only": args.preflight_only,
        "use_temp_db": args.use_temp_db,
        "confirmation": (
            MEASURED_CONFIRMATION if args.confirm_fixed_revalidation else None
        ),
    }
    if args.output_dir is not None:
        kwargs["output_dir"] = args.output_dir
    result = run_v548_manual_anchor_fixed_revalidation(**kwargs)
    print(json.dumps(result, indent=2 if args.pretty else None, default=str))
    raise SystemExit(0 if result.get("ok", True) else 1)


if __name__ == "__main__":
    main()
