from __future__ import annotations

import argparse
import json
from pathlib import Path

from atdr.app.db.database import SessionLocal
from atdr.app.detection.v57_independent_shadow_revalidation import (
    run_v57_independent_shadow_revalidation,
)


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Freeze the v5.6 diagnostic candidate and enforce a "
            "prediction-before-label independent shadow protocol."
        )
    )
    parser.add_argument("--sample-path", required=True)
    parser.add_argument("--evidence-manifest")
    parser.add_argument(
        "--use-temp-db",
        action="store_true",
        help=(
            "Required acknowledgement that private derived evidence is "
            "processed only in disposable SQLite."
        ),
    )
    parser.add_argument("--preflight-only", action="store_true")
    parser.add_argument("--predictions-only", action="store_true")
    parser.add_argument("--reveal-labels", action="store_true")
    parser.add_argument("--min-samples", type=int, default=100)
    parser.add_argument("--chunk-size", type=int, default=2000)
    parser.add_argument("--max-prediction-rows", type=int, default=1200)
    parser.add_argument("--output-dir")
    parser.add_argument("--no-report", action="store_true")
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()

    if not args.use_temp_db:
        print(
            json.dumps(
                {
                    "ok": False,
                    "status": (
                        "failed_closed_temp_db_acknowledgement_required"
                    ),
                    "message": "Re-run with --use-temp-db.",
                    "configured_database_written": False,
                    "path_returned": False,
                },
                indent=2 if args.pretty else None,
            )
        )
        raise SystemExit(2)
    if sum(
        int(value)
        for value in (
            args.preflight_only,
            args.predictions_only,
            args.reveal_labels,
        )
    ) > 1:
        print(
            json.dumps(
                {
                    "ok": False,
                    "status": "failed_closed_conflicting_modes",
                },
                indent=2 if args.pretty else None,
            )
        )
        raise SystemExit(2)

    with SessionLocal() as db:
        kwargs = {
            "sample_path": Path(args.sample_path),
            "evidence_manifest_path": (
                Path(args.evidence_manifest)
                if args.evidence_manifest
                else None
            ),
            "min_samples": args.min_samples,
            "chunk_size": args.chunk_size,
            "max_prediction_rows": args.max_prediction_rows,
            "preflight_only": args.preflight_only,
            "predictions_only": args.predictions_only,
            "reveal_labels": args.reveal_labels,
            "write_output": not args.no_report,
        }
        if args.output_dir:
            kwargs["output_dir"] = Path(args.output_dir)
        result = run_v57_independent_shadow_revalidation(db, **kwargs)
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
