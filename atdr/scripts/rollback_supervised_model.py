import argparse
import json

from atdr.app.db.database import SessionLocal, init_db
from atdr.app.detection.supervised_workflow import rollback_supervised_model


def main() -> None:
    parser = argparse.ArgumentParser(description="Rollback the active supervised model artifact to the previous backup if available.")
    parser.add_argument("--actor", default="cli")
    args = parser.parse_args()

    init_db()
    with SessionLocal() as db:
        result = rollback_supervised_model(db, actor=args.actor)
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
