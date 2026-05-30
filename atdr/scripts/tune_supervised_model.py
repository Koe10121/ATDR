import argparse
import json

from atdr.app.db.database import SessionLocal, init_db
from atdr.app.detection.supervised_workflow import TUNING_DIR, tune_supervised_model_candidates


def main() -> None:
    parser = argparse.ArgumentParser(description="Tune supervised ATDR model candidates and threshold profiles safely.")
    parser.add_argument("--output-root", default=str(TUNING_DIR))
    parser.add_argument("--split", choices=["random", "time"], default="time")
    parser.add_argument("--test-size", type=float, default=0.3)
    parser.add_argument("--min-samples", type=int, default=6)
    args = parser.parse_args()

    init_db()
    with SessionLocal() as db:
        result = tune_supervised_model_candidates(
            db,
            output_root=args.output_root,
            split=args.split,
            test_size=args.test_size,
            min_samples=args.min_samples,
        )
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
