from __future__ import annotations

import argparse
import json
from pathlib import Path

from atdr.app.db.database import SessionLocal
from atdr.app.detection.v567_signal_concentrated_evidence_expansion import (
    BATCH_SIZE,
    PREPARE_CONFIRMATION,
    TARGET_SIGNAL_ROWS,
    V567_OUTPUT_DIR,
    get_public_v567_status,
    run_v567_signal_concentrated_evidence_expansion,
)


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Expand the protected supervised evidence campaign a fourth time, on top "
            "of the locked v562+v563+v565 1,500-row pack, without training, evaluation, "
            "activation, or authoritative writes. Coverage-group round-robin selection "
            "is re-calibrated to the categories that ACTUALLY produced threat-positive "
            "decisions across the full 1,455-row development review so far, dropping "
            "vendor_security_context (which v5.65 weighted but which produced zero new "
            "threat-positive rows)."
        )
    )
    parser.add_argument(
        "--sample-path",
        type=Path,
        default=None,
        help="Private primary PAN-OS path; never returned in command output.",
    )
    parser.add_argument(
        "--use-temp-db",
        action="store_true",
        help="Acknowledge disposable private-evidence processing.",
    )
    parser.add_argument("--preflight-only", action="store_true")
    parser.add_argument("--prepare-signal-review", action="store_true")
    parser.add_argument("--status-only", action="store_true")
    parser.add_argument("--confirm", default=None)
    parser.add_argument("--signal-limit", type=int, default=TARGET_SIGNAL_ROWS)
    parser.add_argument("--batch-size", type=int, default=BATCH_SIZE)
    parser.add_argument("--output-dir", type=Path, default=V567_OUTPUT_DIR)
    parser.add_argument("--no-report", action="store_true")
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()

    if args.status_only:
        result = get_public_v567_status(args.output_dir)
    else:
        with SessionLocal() as db:
            result = run_v567_signal_concentrated_evidence_expansion(
                db,
                sample_path=args.sample_path,
                use_temp_db=args.use_temp_db,
                preflight_only=(args.preflight_only or not args.prepare_signal_review),
                prepare_signal_review=args.prepare_signal_review,
                confirmation=args.confirm,
                signal_limit=args.signal_limit,
                batch_size=args.batch_size,
                output_dir=args.output_dir,
                write_report=not args.no_report,
            )
    if not args.prepare_signal_review and not args.status_only:
        result.setdefault("required_confirmation", PREPARE_CONFIRMATION)
    print(json.dumps(result, indent=2 if args.pretty else None, default=str))
    raise SystemExit(0 if result.get("ok", True) else 1)


if __name__ == "__main__":
    main()
