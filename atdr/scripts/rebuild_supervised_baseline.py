import argparse
import json

from atdr.app.db.database import SessionLocal, init_db
from atdr.app.detection.supervised_recovery import RECOVERY_DIR, rebuild_clean_registered_baseline


def main() -> None:
    parser = argparse.ArgumentParser(description="Build clean registered supervised baseline candidates without activation.")
    parser.add_argument("--output-root", default=str(RECOVERY_DIR))
    parser.add_argument("--split", choices=["random", "time"], default="time")
    parser.add_argument("--test-size", type=float, default=0.3)
    parser.add_argument("--min-samples", type=int, default=6)
    parser.add_argument("--actor", default="supervised_recovery")
    args = parser.parse_args()

    init_db()
    with SessionLocal() as db:
        result = rebuild_clean_registered_baseline(
            db,
            output_root=args.output_root,
            split=args.split,
            test_size=args.test_size,
            min_samples=args.min_samples,
            actor=args.actor,
        )
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
