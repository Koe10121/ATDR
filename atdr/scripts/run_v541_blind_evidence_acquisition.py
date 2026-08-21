from __future__ import annotations

import argparse
import json
from pathlib import Path

from atdr.app.db.database import SessionLocal, init_db
from atdr.app.detection.v541_governed_blind_evidence import (
    run_v541_blind_evidence_acquisition,
)


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Prepare governed v5.41 blind evidence in disposable storage without "
            "training, activation, or response side effects."
        )
    )
    parser.add_argument("--sample-path", type=Path, default=None)
    parser.add_argument("--source-name", default="")
    parser.add_argument("--source-type", default="firewall")
    parser.add_argument("--collection-window", default="")
    parser.add_argument("--parser-profile", default="palo_alto")
    parser.add_argument("--source-attestation", type=Path, default=None)
    parser.add_argument("--use-temp-db", action="store_true")
    parser.add_argument("--rehearsal-only", action="store_true")
    parser.add_argument("--preflight-only", action="store_true")
    parser.add_argument("--candidate-limit", type=int, default=240)
    parser.add_argument("--output-dir", type=Path, default=None)
    parser.add_argument("--no-report", action="store_true")
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()

    if args.source_type != "firewall":
        parser.error("v5.41 currently accepts only --source-type firewall")

    init_db()
    kwargs = {
        "sample_path": args.sample_path,
        "source_name": args.source_name,
        "collection_window": args.collection_window,
        "parser_profile": args.parser_profile,
        "source_attestation": args.source_attestation,
        "use_temp_db": args.use_temp_db,
        "rehearsal_only": args.rehearsal_only,
        "preflight_only": args.preflight_only,
        "candidate_limit": args.candidate_limit,
        "write_output": not args.no_report,
    }
    if args.output_dir is not None:
        kwargs["output_dir"] = args.output_dir
    with SessionLocal() as db:
        result = run_v541_blind_evidence_acquisition(db, **kwargs)
    print(json.dumps(result, indent=2 if args.pretty else None, default=str))
    raise SystemExit(0 if result.get("ok") else 1)


if __name__ == "__main__":
    main()
