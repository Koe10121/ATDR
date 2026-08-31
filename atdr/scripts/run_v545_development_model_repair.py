from __future__ import annotations

import argparse
import json
from pathlib import Path

from atdr.app.db.database import SessionLocal
from atdr.app.detection.v545_development_model_repair import (
    run_v545_development_model_repair,
)


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Run development-only supervised repair against locked v5.44 "
            "cohorts without opening untouched-future labels."
        )
    )
    parser.add_argument(
        "--sample-path",
        type=Path,
        default=None,
        help="Private PAN-OS source path; never returned in command output.",
    )
    parser.add_argument(
        "--use-temp-db",
        action="store_true",
        help="Acknowledge disposable derived-feature storage.",
    )
    parser.add_argument("--preflight-only", action="store_true")
    parser.add_argument("--min-samples", type=int, default=100)
    parser.add_argument("--max-fit-rows", type=int, default=8000)
    parser.add_argument("--max-calibration-rows", type=int, default=3000)
    parser.add_argument("--max-threshold-rows", type=int, default=3500)
    parser.add_argument("--output-dir", type=Path, default=None)
    parser.add_argument("--no-report", action="store_true")
    parser.add_argument(
        "--summary-only",
        action="store_true",
        help="Print only aggregate decision and safety status.",
    )
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()

    kwargs = {
        "sample_path": args.sample_path,
        "use_temp_db": args.use_temp_db,
        "preflight_only": args.preflight_only,
        "min_samples": args.min_samples,
        "max_fit_rows": args.max_fit_rows,
        "max_calibration_rows": args.max_calibration_rows,
        "max_threshold_rows": args.max_threshold_rows,
        "write_output": not args.no_report,
    }
    if args.output_dir is not None:
        kwargs["output_dir"] = args.output_dir
    with SessionLocal() as db:
        result = run_v545_development_model_repair(db, **kwargs)
    printable = result
    if args.summary_only:
        printable = {
            "ok": result.get("ok"),
            "version": result.get("version"),
            "status": result.get("status"),
            "failure_stage": result.get("failure_stage"),
            "error_type": result.get("error_type"),
            "diagnostics": result.get("diagnostics"),
            "diagnostic_leader": (
                (result.get("diagnostic_leader") or {}).get("name")
            ),
            "candidate_freeze": result.get("candidate_freeze"),
            "readiness": result.get("readiness"),
            "safety": result.get("safety"),
            "runtime_seconds": result.get("runtime_seconds"),
            "future_labels_opened": result.get("future_labels_opened"),
            "private_paths_returned": result.get("private_paths_returned"),
            "fingerprints_returned": result.get("fingerprints_returned"),
            "secrets_exposed": result.get("secrets_exposed"),
        }
    print(json.dumps(printable, indent=2 if args.pretty else None, default=str))
    raise SystemExit(0 if result.get("ok") else 1)


if __name__ == "__main__":
    main()
