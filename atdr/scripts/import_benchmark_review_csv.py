import argparse
import json
from pathlib import Path

from atdr.app.benchmarks.review import (
    DEFAULT_REVIEW_ARTIFACT_DIR,
    import_benchmark_review_csv,
)


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Import a reviewed benchmark/holdout CSV keyed by "
            "benchmark_row_id without writing to ml_labels."
        )
    )
    parser.add_argument("--input-csv", required=True)
    parser.add_argument("--benchmark-kind", default="external_holdout")
    parser.add_argument("--reviewer", default="benchmark-review-import")
    parser.add_argument("--output-dir", default=None)
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()
    result = import_benchmark_review_csv(
        Path(args.input_csv),
        benchmark_kind=args.benchmark_kind,
        reviewer=args.reviewer,
        output_dir=(
            Path(args.output_dir)
            if args.output_dir
            else DEFAULT_REVIEW_ARTIFACT_DIR
        ),
    )
    printable = {
        key: value for key, value in result.items() if key != "reviews"
    }
    print(
        json.dumps(
            printable,
            indent=2 if args.pretty else None,
            default=str,
        )
    )
    raise SystemExit(0 if result.get("ok") else 1)


if __name__ == "__main__":
    main()
