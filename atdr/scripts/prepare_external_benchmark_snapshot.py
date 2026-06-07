import argparse
import json
from pathlib import Path
from typing import Any

from atdr.app.core.config import PROJECT_ROOT
from atdr.scripts.build_fixed_unseen_holdout import (
    DEFAULT_OUTPUT as DEFAULT_HOLDOUT_OUTPUT,
    build_fixed_unseen_holdout,
)
from atdr.scripts.prepare_benchmark_dataset import prepare_benchmark_dataset


DEFAULT_OUTPUT_DIR = PROJECT_ROOT / "demo_exports" / "benchmarks"


def prepare_external_benchmark_snapshot(
    *,
    input_csv: Path | None = None,
    mapping_config: Path | None = None,
    label_config: Path | None = None,
    limit: int | None = None,
    sample_strategy: str = "balanced",
    holdout_from_current_data: bool = False,
    output_dir: Path = DEFAULT_OUTPUT_DIR,
) -> dict[str, Any]:
    if input_csv is None and not holdout_from_current_data:
        raise ValueError(
            "Provide --input-csv or explicitly use --holdout-from-current-data."
        )
    holdout = None
    source_path = input_csv
    source_kind = "external_csv"
    if source_path is None:
        holdout = build_fixed_unseen_holdout(output_path=DEFAULT_HOLDOUT_OUTPUT)
        source_path = DEFAULT_HOLDOUT_OUTPUT
        source_kind = "fixed_safe_unseen_holdout"
    snapshot = prepare_benchmark_dataset(
        input_csv=source_path,
        mapping_config=mapping_config,
        label_config=label_config,
        limit=limit,
        sample_strategy=sample_strategy,
        output_dir=output_dir,
    )
    profile = snapshot.get("profile") or {}
    return {
        **snapshot,
        "source_kind": source_kind,
        "holdout": holdout,
        "benchmark_label_count": int(profile.get("total_rows") or 0),
        "minimum_target_met": int(profile.get("total_rows") or 0) >= 100,
        "preferred_target_met": int(profile.get("total_rows") or 0) >= 300,
        "source_diversity": int(profile.get("source_count") or 0),
        "time_coverage": profile.get("time_range") or {},
        "private_raw_payloads_excluded": True,
        "training_contamination": False if holdout is not None else "caller_controlled",
        "model_activated": False,
        "response_automation_allowed": False,
        "production_readiness_claim": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Prepare a sanitized external CSV or fixed unseen holdout snapshot."
    )
    parser.add_argument("--input-csv", default=None)
    parser.add_argument("--mapping-config", default=None)
    parser.add_argument("--label-config", default=None)
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument(
        "--sample-strategy",
        choices=["balanced", "random", "time"],
        default="balanced",
    )
    parser.add_argument("--holdout-from-current-data", action="store_true")
    parser.add_argument("--output-dir", default=None)
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()
    result = prepare_external_benchmark_snapshot(
        input_csv=Path(args.input_csv) if args.input_csv else None,
        mapping_config=Path(args.mapping_config) if args.mapping_config else None,
        label_config=Path(args.label_config) if args.label_config else None,
        limit=args.limit,
        sample_strategy=args.sample_strategy,
        holdout_from_current_data=args.holdout_from_current_data,
        output_dir=Path(args.output_dir) if args.output_dir else DEFAULT_OUTPUT_DIR,
    )
    print(json.dumps(result, indent=2 if args.pretty else None, default=str))
    raise SystemExit(0 if result.get("ok") else 1)


if __name__ == "__main__":
    main()
