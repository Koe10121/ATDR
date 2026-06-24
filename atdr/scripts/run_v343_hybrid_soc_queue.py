import argparse
import json

from atdr.app.db.database import SessionLocal
from atdr.app.detection.v343_hybrid_soc_queue import run_v343_hybrid_soc_queue


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Run v3.43 hybrid evidence-first SOC queue diagnostics without writing "
            "labels, activating models, or enabling response automation."
        )
    )
    parser.add_argument("--test-size", type=float, default=0.3)
    parser.add_argument("--min-samples", type=int, default=6)
    parser.add_argument("--output-dir", default="ml_baseline_reviews")
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()

    with SessionLocal() as db:
        result = run_v343_hybrid_soc_queue(
            db,
            test_size=args.test_size,
            min_samples=args.min_samples,
            output_dir=args.output_dir,
        )
    print(json.dumps(result, indent=2 if args.pretty else None, default=str))
    raise SystemExit(0 if result.get("ok") else 1)


if __name__ == "__main__":
    main()
