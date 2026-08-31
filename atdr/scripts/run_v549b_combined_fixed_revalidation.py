from __future__ import annotations

import argparse
import json
from pathlib import Path

from atdr.app.detection.v549b_combined_fixed_revalidation import (
    MEASURED_CONFIRMATION,
    V549BRevalidationError,
    run_v549b_combined_fixed_revalidation,
)


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Lock and consume the combined manual-anchor diagnostic evaluation "
            "at most once without activating a model."
        )
    )
    parser.add_argument("--status-only", action="store_true")
    parser.add_argument("--preflight-only", action="store_true")
    parser.add_argument("--use-temp-db", action="store_true")
    parser.add_argument("--confirm-fixed-revalidation", action="store_true")
    parser.add_argument("--output-dir", type=Path, default=None)
    parser.add_argument("--original-output-dir", type=Path, default=None)
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()

    kwargs = {
        "status_only": args.status_only,
        "preflight_only": args.preflight_only,
        "confirmation": (
            MEASURED_CONFIRMATION if args.confirm_fixed_revalidation else None
        ),
        "use_temp_db": args.use_temp_db,
    }
    if args.output_dir is not None:
        kwargs["output_dir"] = args.output_dir
    if args.original_output_dir is not None:
        kwargs["original_output_dir"] = args.original_output_dir
    try:
        result = run_v549b_combined_fixed_revalidation(**kwargs)
    except V549BRevalidationError:
        result = {
            "ok": False,
            "version": "v5.49b-immutable-combined-fixed-revalidation-v1",
            "status": "failed_closed_integrity_error",
            "message": (
                "Combined fixed revalidation failed closed; no private details "
                "were returned."
            ),
            "lifecycle_state": "shadow_observation",
            "rules_alert_authoritative": True,
            "model_activated": False,
            "model_promoted": False,
            "response_automation_allowed": False,
            "private_paths_exposed": False,
            "fingerprints_exposed": False,
            "digests_exposed": False,
            "secrets_exposed": False,
        }
    print(json.dumps(result, indent=2 if args.pretty else None, default=str))
    raise SystemExit(0 if result.get("ok", True) else 1)


if __name__ == "__main__":
    main()
