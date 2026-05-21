import argparse

from atdr.app.core.config import get_settings
from atdr.app.db.database import SessionLocal, init_db
from atdr.app.services.log_service import import_log_file


def main() -> None:
    parser = argparse.ArgumentParser(description="Import Palo Alto syslog CSV logs into ATDR.")
    parser.add_argument("path", help="Path to a .log file")
    parser.add_argument("--limit", type=int, default=None, help="Maximum rows to import")
    parser.add_argument("--actor", default="script", help="Audit actor")
    args = parser.parse_args()

    init_db()
    settings = get_settings()
    limit = settings.default_import_limit if args.limit is None else args.limit
    if limit is not None and limit <= 0:
        limit = None
    with SessionLocal() as db:
        result = import_log_file(db, args.path, limit=limit, actor=args.actor)
    print(result)


if __name__ == "__main__":
    main()
