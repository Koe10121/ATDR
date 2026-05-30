import argparse
import json

from atdr.app.db.database import SessionLocal, init_db
from atdr.app.detection.supervised_workflow import list_supervised_models


def main() -> None:
    parser = argparse.ArgumentParser(description="List ATDR supervised model registry entries.")
    parser.add_argument("--limit", type=int, default=25)
    args = parser.parse_args()

    init_db()
    with SessionLocal() as db:
        result = list_supervised_models(db, limit=args.limit)
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
