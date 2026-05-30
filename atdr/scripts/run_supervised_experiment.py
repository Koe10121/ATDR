import argparse
import json

from atdr.app.db.database import SessionLocal, init_db
from atdr.app.detection.supervised_workflow import EXPERIMENT_DIR, run_supervised_experiment


def main() -> None:
    parser = argparse.ArgumentParser(description="Run a supervised ATDR model comparison experiment without activating a model.")
    parser.add_argument("--output-root", default=str(EXPERIMENT_DIR))
    parser.add_argument("--split", choices=["random", "time"], default="time")
    parser.add_argument("--test-size", type=float, default=0.3)
    parser.add_argument("--min-samples", type=int, default=6)
    args = parser.parse_args()

    init_db()
    with SessionLocal() as db:
        result = run_supervised_experiment(
            db,
            output_root=args.output_root,
            split=args.split,
            test_size=args.test_size,
            min_samples=args.min_samples,
        )
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
