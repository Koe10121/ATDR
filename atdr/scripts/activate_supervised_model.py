import argparse
import json

from atdr.app.db.database import SessionLocal, init_db
from atdr.app.detection.supervised_workflow import activate_supervised_model


def main() -> None:
    parser = argparse.ArgumentParser(description="Explicitly activate a supervised model artifact for analyst decision support.")
    parser.add_argument("--model-id", type=int, required=True)
    parser.add_argument("--actor", default="cli")
    args = parser.parse_args()

    init_db()
    with SessionLocal() as db:
        result = activate_supervised_model(db, model_id=args.model_id, actor=args.actor)
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
