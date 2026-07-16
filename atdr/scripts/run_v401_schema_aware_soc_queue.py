import argparse
import json
from pathlib import Path
from typing import Any

from atdr.app.db.database import SessionLocal
from atdr.app.detection.v401_schema_aware_soc_queue import (
    DEFAULT_ROWS_PER_PROVIDER_LABEL,
    DEFAULT_SEED,
    V401_DEVELOPMENT_DIR,
    V401_OUTPUT_DIR,
    run_v401_schema_aware_soc_queue,
)


def _json_default(value: Any) -> str:
    return str(value)


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Run the read-only v4.1 schema-aware SOC queue model redesign against "
            "development-only evidence."
        ),
    )
    parser.add_argument("--development-dir", default=str(V401_DEVELOPMENT_DIR))
    parser.add_argument("--output-dir", default=str(V401_OUTPUT_DIR))
    parser.add_argument(
        "--rows-per-provider-label",
        type=int,
        default=DEFAULT_ROWS_PER_PROVIDER_LABEL,
    )
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--min-samples", type=int, default=100)
    parser.add_argument("--no-report", action="store_true")
    parser.add_argument("--summary-only", action="store_true")
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()

    with SessionLocal() as db:
        result = run_v401_schema_aware_soc_queue(
            db,
            development_dir=Path(args.development_dir),
            output_dir=Path(args.output_dir),
            rows_per_provider_label=args.rows_per_provider_label,
            seed=args.seed,
            min_samples=args.min_samples,
            write_output=not args.no_report,
        )
    if args.summary_only:
        result = {
            "ok": result.get("ok"),
            "status": result.get("status"),
            "version": result.get("version"),
            "runtime_seconds": result.get("runtime_seconds"),
            "v400_evidence_lock": result.get("v400_evidence_lock"),
            "development_evidence": result.get("development_evidence"),
            "development_sample": result.get("development_sample"),
            "diagnostic_selection": result.get("diagnostic_selection"),
            "worst_cross_schema_split": result.get("worst_cross_schema_split"),
            "reserved_future_benchmark": result.get("reserved_future_benchmark"),
            "readiness": result.get("readiness"),
            "safety": result.get("safety"),
            "reports": result.get("reports"),
        }
    print(json.dumps(result, indent=2 if args.pretty else None, default=_json_default))


if __name__ == "__main__":
    main()
