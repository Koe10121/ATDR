import argparse
import json

from atdr.app.db.database import SessionLocal, init_db
from atdr.app.detection.supervised_recovery import BINARY_EXPERIMENT_PATH, run_binary_threat_positive_experiment


def main() -> None:
    parser = argparse.ArgumentParser(description="Run an experimental binary threat-positive supervised ML evaluation.")
    parser.add_argument("--output", default=str(BINARY_EXPERIMENT_PATH))
    parser.add_argument("--split", choices=["random", "time"], default="time")
    parser.add_argument("--test-size", type=float, default=0.3)
    parser.add_argument("--min-samples", type=int, default=6)
    args = parser.parse_args()

    init_db()
    with SessionLocal() as db:
        result = run_binary_threat_positive_experiment(
            db,
            output_path=args.output,
            split=args.split,
            test_size=args.test_size,
            min_samples=args.min_samples,
        )
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
