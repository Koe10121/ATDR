import argparse
import json

from atdr.app.db.database import SessionLocal, init_db
from atdr.app.detection.supervised_detector import train_supervised_classifier


def main() -> None:
    parser = argparse.ArgumentParser(description="Train the ATDR supervised classifier from analyst-reviewed ML labels.")
    parser.add_argument("--test-size", type=float, default=0.3)
    parser.add_argument("--min-samples", type=int, default=6)
    parser.add_argument("--model-path", default=None)
    parser.add_argument("--actor", default="cli")
    args = parser.parse_args()

    init_db()
    with SessionLocal() as db:
        result = train_supervised_classifier(
            db,
            actor=args.actor,
            model_path=args.model_path,
            test_size=args.test_size,
            min_samples=args.min_samples,
        )
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
