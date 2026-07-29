from __future__ import annotations

import argparse
import json
from pathlib import Path

from atdr.app.db.database import SessionLocal, init_db
from atdr.app.detection.v56_private_panos_model_repair import (
    run_v56_private_panos_model_repair,
)


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Stream private PAN-OS evidence through disposable storage and run "
            "v5.6 assisted, diagnostic-only model repair."
        )
    )
    parser.add_argument("--sample-path", required=True)
    parser.add_argument(
        "--use-temp-db",
        action="store_true",
        help=(
            "Required safety acknowledgement. Private derived evidence is "
            "always stored in disposable SQLite, never the configured database."
        ),
    )
    parser.add_argument("--preflight-only", action="store_true")
    parser.add_argument("--min-samples", type=int, default=100)
    parser.add_argument("--chunk-size", type=int, default=2000)
    parser.add_argument("--max-fit-rows", type=int, default=8000)
    parser.add_argument("--max-calibration-rows", type=int, default=3000)
    parser.add_argument("--max-threshold-rows", type=int, default=3500)
    parser.add_argument("--max-future-rows", type=int, default=4500)
    parser.add_argument("--output-dir", default=None)
    parser.add_argument("--no-report", action="store_true")
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()

    if not args.use_temp_db:
        print(
            json.dumps(
                {
                    "ok": False,
                    "status": "failed_closed_temp_db_acknowledgement_required",
                    "message": "Re-run with --use-temp-db.",
                    "configured_database_written": False,
                    "path_returned": False,
                },
                indent=2 if args.pretty else None,
            )
        )
        raise SystemExit(2)

    init_db()
    with SessionLocal() as db:
        kwargs = {
            "sample_path": Path(args.sample_path),
            "min_samples": args.min_samples,
            "chunk_size": args.chunk_size,
            "max_fit_rows": args.max_fit_rows,
            "max_calibration_rows": args.max_calibration_rows,
            "max_threshold_rows": args.max_threshold_rows,
            "max_future_rows": args.max_future_rows,
            "preflight_only": args.preflight_only,
            "write_output": not args.no_report,
        }
        if args.output_dir:
            kwargs["output_dir"] = Path(args.output_dir)
        result = run_v56_private_panos_model_repair(db, **kwargs)
    print(
        json.dumps(
            result,
            indent=2 if args.pretty else None,
            default=str,
        )
    )
    raise SystemExit(0 if result.get("ok") else 1)


if __name__ == "__main__":
    main()
