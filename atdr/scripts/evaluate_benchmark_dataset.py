import argparse
import json

from atdr.app.ml.benchmark_adapter import write_benchmark_report


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate a public/benchmark CSV through the isolated ATDR benchmark adapter.")
    parser.add_argument("csv_path")
    parser.add_argument("--dataset-name", required=True)
    parser.add_argument("--source-type", default="benchmark_csv")
    parser.add_argument("--test-size", type=float, default=0.3)
    parser.add_argument("--output", default="ml_baseline_reviews/benchmark_dataset_report.md")
    args = parser.parse_args()

    result = write_benchmark_report(
        args.csv_path,
        dataset_name=args.dataset_name,
        source_type=args.source_type,
        output_path=args.output,
        test_size=args.test_size,
    )
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
