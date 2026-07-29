from __future__ import annotations

import argparse
import json
from pathlib import Path

from atdr.app.core.config import get_settings
from atdr.app.db.database import SessionLocal, init_db
from atdr.app.detection.v54_temporal_evidence import (
    inspect_private_temporal_regimes,
    run_v54_temporal_evidence_preparation,
)
from atdr.app.services.v50_shadow_validation_service import (
    run_v50_real_paloalto_shadow_validation,
)


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Prepare locked temporal development evidence and aggregate shadow "
            "drift telemetry without training, activation, or response actions."
        )
    )
    parser.add_argument(
        "--sample-path",
        default=None,
        help="Optional private PAN-OS path. The path and raw content are never returned.",
    )
    parser.add_argument(
        "--use-temp-db",
        action="store_true",
        help="Required when a private sample is supplied for full disposable validation.",
    )
    parser.add_argument(
        "--preflight-only",
        action="store_true",
        help="Inspect only aggregate private temporal regimes; no configured DB access.",
    )
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--min-samples", type=int, default=100)
    parser.add_argument("--output-dir", default=None)
    parser.add_argument("--no-report", action="store_true")
    parser.add_argument("--no-review-pack", action="store_true")
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()

    settings = get_settings()
    private_evidence = None
    if args.sample_path:
        sample_path = Path(args.sample_path).expanduser()
        private_evidence = inspect_private_temporal_regimes(
            sample_path,
            current_database_url=None
            if args.preflight_only
            else settings.database_url,
            max_lines=args.limit,
        )
        if args.preflight_only:
            print(
                json.dumps(
                    private_evidence,
                    indent=2 if args.pretty else None,
                    default=str,
                )
            )
            raise SystemExit(0 if private_evidence.get("ok") else 1)
        if not args.use_temp_db:
            result = {
                "ok": False,
                "status": "explicit_temp_database_required",
                "message": (
                    "Re-run with --use-temp-db when supplying private evidence. "
                    "The configured database is never a private-validation target."
                ),
                "path_returned": False,
                "raw_evidence_returned": False,
                "secrets_exposed": False,
            }
            print(json.dumps(result, indent=2 if args.pretty else None))
            raise SystemExit(1)
        disposable = run_v50_real_paloalto_shadow_validation(
            evidence_path=sample_path,
            use_temp_db=True,
            current_database_url=settings.database_url,
            line_limit=args.limit,
            write_review_sample=False,
            write_reports=False,
            run_ml=False,
            run_assistant_audit=False,
        )
        private_evidence["disposable_validation"] = {
            "ok": disposable.get("ok"),
            "status": disposable.get("status"),
            "temporary_database_counts": disposable.get(
                "temporary_database_counts"
            ),
            "current_database_unchanged": disposable.get(
                "current_database_unchanged"
            ),
            "model_artifacts_unchanged": disposable.get(
                "model_artifacts_unchanged"
            ),
            "response_actions_created": disposable.get(
                "response_actions_created",
                0,
            ),
            "path_returned": False,
            "raw_evidence_returned": False,
            "secrets_exposed": False,
        }

    init_db()
    with SessionLocal() as db:
        kwargs = {
            "min_samples": args.min_samples,
            "private_evidence": private_evidence,
            "write_output": not args.no_report,
            "write_review_pack": not args.no_review_pack,
        }
        if args.output_dir:
            kwargs["output_dir"] = Path(args.output_dir)
        result = run_v54_temporal_evidence_preparation(db, **kwargs)
    print(json.dumps(result, indent=2 if args.pretty else None, default=str))
    raise SystemExit(0 if result.get("ok") else 1)


if __name__ == "__main__":
    main()
