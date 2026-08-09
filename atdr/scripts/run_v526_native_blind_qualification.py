from __future__ import annotations

import argparse
import json
from pathlib import Path

from atdr.app.db.database import SessionLocal
from atdr.app.detection.v526_native_blind_qualification import (
    run_v526_native_blind_qualification,
)


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Run the one-time native PAN-OS blind qualification with a "
            "development-frozen, read-only detection stack."
        )
    )
    parser.add_argument("--sample-path", required=True)
    parser.add_argument(
        "--use-temp-db",
        action="store_true",
        help=(
            "Required acknowledgement that private derived evidence remains "
            "in disposable storage."
        ),
    )
    parser.add_argument("--preflight-only", action="store_true")
    parser.add_argument(
        "--no-write",
        action="store_true",
        help=(
            "Run eligibility preflight without consuming blind labels or "
            "writing qualification reports."
        ),
    )
    parser.add_argument("--min-samples", type=int, default=100)
    parser.add_argument("--chunk-size", type=int, default=2000)
    parser.add_argument("--max-fit-rows", type=int, default=8000)
    parser.add_argument("--max-calibration-rows", type=int, default=3000)
    parser.add_argument("--max-threshold-rows", type=int, default=3500)
    parser.add_argument("--evidence-dir", default=None)
    parser.add_argument("--output-dir", default=None)
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()

    if not args.use_temp_db:
        result = {
            "ok": False,
            "status": "failed_closed_temp_db_acknowledgement_required",
            "message": "Re-run with --use-temp-db.",
            "path_returned": False,
            "model_activated": False,
            "response_automation_allowed": False,
        }
        print(json.dumps(result, indent=2 if args.pretty else None))
        raise SystemExit(2)

    kwargs = {
        "sample_path": Path(args.sample_path),
        "use_temp_db": True,
        "preflight_only": bool(args.preflight_only or args.no_write),
        "write_output": not args.no_write,
        "min_samples": args.min_samples,
        "chunk_size": args.chunk_size,
        "max_fit_rows": args.max_fit_rows,
        "max_calibration_rows": args.max_calibration_rows,
        "max_threshold_rows": args.max_threshold_rows,
    }
    if args.evidence_dir:
        kwargs["evidence_dir"] = Path(args.evidence_dir)
    if args.output_dir:
        kwargs["output_dir"] = Path(args.output_dir)

    if kwargs["preflight_only"]:
        result = run_v526_native_blind_qualification(None, **kwargs)
    else:
        with SessionLocal() as db:
            result = run_v526_native_blind_qualification(db, **kwargs)
    print(json.dumps(result, indent=2 if args.pretty else None, default=str))
    raise SystemExit(0 if result.get("ok") else 1)


if __name__ == "__main__":
    main()
