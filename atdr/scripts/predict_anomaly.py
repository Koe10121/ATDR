import argparse

from atdr.app.db.database import SessionLocal, init_db
from atdr.app.services.ml_service import apply_anomaly_scoring


def main() -> None:
    parser = argparse.ArgumentParser(description="Apply the trained ATDR anomaly model to normalized logs.")
    parser.add_argument("--limit", type=int, default=5000, help="Score the latest N normalized logs")
    args = parser.parse_args()

    init_db()
    with SessionLocal() as db:
        result = apply_anomaly_scoring(db, limit=args.limit, actor="cli")
    print(result)


if __name__ == "__main__":
    main()
