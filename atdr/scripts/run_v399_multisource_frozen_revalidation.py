import argparse
import json
from pathlib import Path
from typing import Any

from atdr.app.db.database import SessionLocal
from atdr.app.detection.v399_multisource_frozen_revalidation import (
    DEFAULT_ROWS_PER_SOURCE,
    V399_OUTPUT_DIR,
    run_v399_multisource_frozen_revalidation,
)


def _json_default(value: Any) -> str:
    return str(value)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run the read-only v3.99 independent multi-source frozen revalidation.",
    )
    parser.add_argument("--output-dir", default=str(V399_OUTPUT_DIR))
    parser.add_argument("--rows-per-source", type=int, default=DEFAULT_ROWS_PER_SOURCE)
    parser.add_argument("--seed", type=int, default=399)
    parser.add_argument("--no-report", action="store_true")
    parser.add_argument("--summary-only", action="store_true")
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()

    with SessionLocal() as db:
        result = run_v399_multisource_frozen_revalidation(
            db,
            output_dir=Path(args.output_dir),
            rows_per_source=args.rows_per_source,
            seed=args.seed,
            write_output=not args.no_report,
        )
    if args.summary_only:
        result = {
            "ok": result.get("ok"),
            "status": result.get("status"),
            "runtime_seconds": result.get("runtime_seconds"),
            "current_corpus_limitations": result.get("current_corpus_limitations"),
            "evidence_audit": result.get("evidence_audit"),
            "frozen_protocol": result.get("frozen_protocol"),
            "worst_primary_split": result.get("worst_primary_split"),
            "readiness": result.get("readiness"),
            "safety": result.get("safety"),
            "evidence_pack": result.get("evidence_pack"),
            "reports": result.get("reports"),
        }
    print(json.dumps(result, indent=2 if args.pretty else None, default=_json_default))


if __name__ == "__main__":
    main()
