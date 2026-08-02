from __future__ import annotations

import argparse
import json
from pathlib import Path

from atdr.app.db.database import SessionLocal
from atdr.app.detection.v519_independent_labeled_validation import (
    run_v519_label_adapter_recovery,
    run_v519_independent_labeled_validation,
)


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Run the one-shot v5.19 independent labeled blind validation."
        )
    )
    parser.add_argument("--dataset-path", required=True)
    parser.add_argument("--manifest-path", required=True)
    parser.add_argument("--preflight-only", action="store_true")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--confirm", action="store_true")
    parser.add_argument("--recover-label-adapter", action="store_true")
    parser.add_argument("--rows-per-scenario", type=int, default=5000)
    parser.add_argument("--output-dir")
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()

    if sum(
        int(value)
        for value in (
            args.preflight_only,
            args.execute,
            args.recover_label_adapter,
        )
    ) != 1:
        parser.error(
            "Select exactly one of --preflight-only, --execute, or "
            "--recover-label-adapter."
        )
    kwargs = {
        "dataset_path": Path(args.dataset_path),
        "manifest_path": Path(args.manifest_path),
        "preflight_only": args.preflight_only,
        "execute": args.execute,
        "confirm": args.confirm,
        "rows_per_scenario": args.rows_per_scenario,
    }
    if args.output_dir:
        kwargs["output_dir"] = Path(args.output_dir)
    with SessionLocal() as db:
        if args.recover_label_adapter:
            recovery_kwargs = {"dataset_path": Path(args.dataset_path)}
            if args.output_dir:
                recovery_kwargs["output_dir"] = Path(args.output_dir)
            result = run_v519_label_adapter_recovery(db, **recovery_kwargs)
        else:
            result = run_v519_independent_labeled_validation(db, **kwargs)
    print(json.dumps(result, indent=2 if args.pretty else None, default=str))
    raise SystemExit(0 if result.get("ok") else 1)


if __name__ == "__main__":
    main()
