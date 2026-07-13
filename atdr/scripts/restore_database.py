import argparse
import json

from atdr.app.core.config import Settings
from atdr.app.services.persistence_service import restore_database_backup


CONFIRMATION = "RESTORE_TO_NEW_EMPTY_TARGET"


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate or restore an ATDR backup into a new empty target.")
    parser.add_argument("--backup-path", required=True)
    parser.add_argument("--manifest-path", default=None)
    parser.add_argument("--target-database-url", required=True)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--confirm", default="", help=f"Required for execution: {CONFIRMATION}")
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()
    result = restore_database_backup(
        settings=Settings(),
        backup_path=args.backup_path,
        manifest_path=args.manifest_path,
        target_database_url=args.target_database_url,
        execute=args.execute,
        confirmed=args.confirm == CONFIRMATION,
    )
    print(json.dumps(result, indent=2 if args.pretty else None, default=str))
    raise SystemExit(0 if result.get("ok") else 1)


if __name__ == "__main__":
    main()
