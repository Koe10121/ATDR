import argparse
import json

from atdr.app.core.config import Settings
from atdr.app.services.persistence_service import create_database_backup


def main() -> None:
    parser = argparse.ArgumentParser(description="Create a safe ATDR database backup. Dry-run is the default.")
    parser.add_argument("--output-dir", required=True, help="Ignored in-repo directory or an external backup directory.")
    parser.add_argument("--execute", action="store_true", help="Create the backup and checksum manifest.")
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()
    result = create_database_backup(settings=Settings(), output_dir=args.output_dir, execute=args.execute)
    print(json.dumps(result, indent=2 if args.pretty else None, default=str))
    raise SystemExit(0 if result.get("ok") else 1)


if __name__ == "__main__":
    main()
