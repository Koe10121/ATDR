import argparse

from atdr.app.db.database import SessionLocal, init_db
from atdr.app.services.demo_service import reset_and_seed_demo


def main() -> None:
    parser = argparse.ArgumentParser(description="Clear local demo data, import sample logs, and run grouped detection.")
    parser.add_argument("--path", default=None, help="Path to the sample log file")
    parser.add_argument("--limit", type=int, default=5000, help="Maximum rows to import; use 0 for full file")
    parser.add_argument("--use-ml", action="store_true", help="Apply a trained ML model while creating alerts")
    parser.add_argument("--yes", action="store_true", help="Confirm deletion of current demo database rows")
    args = parser.parse_args()

    if not args.yes:
        raise SystemExit("Refusing to clear demo data without --yes.")

    limit = None if args.limit <= 0 else args.limit
    init_db()
    with SessionLocal() as db:
        result = reset_and_seed_demo(db, sample_path=args.path, limit=limit, use_ml=args.use_ml)
    print(result)


if __name__ == "__main__":
    main()
