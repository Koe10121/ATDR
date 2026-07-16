import argparse
import json
from pathlib import Path
from typing import Any

from atdr.app.db.database import SessionLocal
from atdr.app.detection.v400_provider_blinded_external_validation import (
    DEFAULT_ROWS_PER_FILE,
    DEFAULT_SAMPLE_SEED,
    V400_EVIDENCE_DIR,
    V400_OUTPUT_DIR,
    run_v400_provider_blinded_external_validation,
)


def _json_default(value: Any) -> str:
    return str(value)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run the read-only v4.0 provider-blinded external benchmark validation.",
    )
    parser.add_argument("--evidence-dir", default=str(V400_EVIDENCE_DIR))
    parser.add_argument("--output-dir", default=str(V400_OUTPUT_DIR))
    parser.add_argument("--rows-per-file", type=int, default=DEFAULT_ROWS_PER_FILE)
    parser.add_argument("--seed", type=int, default=DEFAULT_SAMPLE_SEED)
    parser.add_argument("--no-report", action="store_true")
    parser.add_argument("--summary-only", action="store_true")
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()

    with SessionLocal() as db:
        result = run_v400_provider_blinded_external_validation(
            db,
            evidence_dir=Path(args.evidence_dir),
            output_dir=Path(args.output_dir),
            rows_per_file=args.rows_per_file,
            seed=args.seed,
            write_output=not args.no_report,
        )
    if args.summary_only:
        result = {
            "ok": result.get("ok"),
            "status": result.get("status"),
            "runtime_seconds": result.get("runtime_seconds"),
            "dataset": result.get("dataset"),
            "evidence_manifest": result.get("evidence_manifest"),
            "protocol": result.get("protocol"),
            "overlap_and_quarantine": result.get("overlap_and_quarantine"),
            "label_integrity": result.get("label_integrity"),
            "worst_primary": (result.get("evaluation") or {}).get("worst_primary"),
            "stability": (result.get("evaluation") or {}).get("stability"),
            "readiness": result.get("readiness"),
            "safety": result.get("safety"),
            "reports": result.get("reports"),
        }
    print(json.dumps(result, indent=2 if args.pretty else None, default=_json_default))


if __name__ == "__main__":
    main()
