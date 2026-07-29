from __future__ import annotations

import argparse
import json
from pathlib import Path

from atdr.app.core.config import get_settings
from atdr.app.db.database import SessionLocal
from atdr.app.db.models import MLModelRun
from atdr.app.detection.v51_supervised_lifecycle import supervised_lifecycle_status
from atdr.app.services.private_log_preflight_service import (
    preflight_private_paloalto_file,
)
from atdr.app.services.v50_shadow_validation_service import (
    DEFAULT_ML_SAMPLE_LIMIT,
    run_v50_real_paloalto_shadow_validation,
)


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Run privacy-safe PAN-OS evidence preflight and disposable shadow "
            "validation without writing to the configured ATDR database."
        )
    )
    parser.add_argument(
        "--sample-path",
        required=True,
        help="Private local PAN-OS log path. The path is never returned in output.",
    )
    parser.add_argument(
        "--use-temp-db",
        action="store_true",
        help="Required for ingestion/detection validation.",
    )
    parser.add_argument(
        "--preflight-only",
        action="store_true",
        help="Inspect aggregate structure and current-DB fingerprint overlap only.",
    )
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--chunk-size", type=int, default=1_000)
    parser.add_argument(
        "--ml-sample-limit",
        type=int,
        default=DEFAULT_ML_SAMPLE_LIMIT,
        help=(
            "Deterministic diagnostic sample size for read-only ML queue comparison "
            f"(default: {DEFAULT_ML_SAMPLE_LIMIT})."
        ),
    )
    parser.add_argument("--no-review-sample", action="store_true")
    parser.add_argument("--no-reports", action="store_true")
    parser.add_argument("--no-ml", action="store_true")
    parser.add_argument("--no-assistant-audit", action="store_true")
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()

    evidence_path = Path(args.sample_path).expanduser()
    current_database_url = get_settings().database_url
    if args.preflight_only:
        result = preflight_private_paloalto_file(
            evidence_path,
            current_database_url=current_database_url,
            max_lines=args.limit,
        )
    else:
        governed_artifact_path = None
        with SessionLocal() as db:
            lifecycle = supervised_lifecycle_status(db)
            model_run_id = lifecycle.get("model_run_id")
            if lifecycle.get("lifecycle_state") in {"shadow_observation", "decision_support"} and model_run_id:
                model_run = db.get(MLModelRun, int(model_run_id))
                if model_run is not None:
                    governed_artifact_path = Path(model_run.model_path)
        result = run_v50_real_paloalto_shadow_validation(
            evidence_path=evidence_path,
            use_temp_db=args.use_temp_db,
            current_database_url=current_database_url,
            line_limit=args.limit,
            chunk_size=args.chunk_size,
            ml_sample_limit=args.ml_sample_limit,
            write_review_sample=not args.no_review_sample,
            write_reports=not args.no_reports,
            run_ml=not args.no_ml,
            run_assistant_audit=not args.no_assistant_audit,
            governed_supervised_artifact_path=governed_artifact_path,
        )
    print(json.dumps(result, indent=2 if args.pretty else None, default=str))
    raise SystemExit(0 if result.get("ok") else 1)


if __name__ == "__main__":
    main()
