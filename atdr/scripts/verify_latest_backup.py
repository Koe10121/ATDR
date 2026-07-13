import argparse
import json
from pathlib import Path

from atdr.app.services.backup_monitoring_service import verify_latest_backup_status


def verify_latest_backup(*, backup_dir: str | Path, max_age_hours: float) -> dict:
    return verify_latest_backup_status(backup_dir=backup_dir, max_age_hours=max_age_hours)


def main() -> None:
    parser = argparse.ArgumentParser(description="Verify the newest ATDR backup artifact without restoring it.")
    parser.add_argument("--backup-dir", required=True)
    parser.add_argument("--max-age-hours", type=float, default=30.0)
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()
    result = verify_latest_backup(backup_dir=args.backup_dir, max_age_hours=args.max_age_hours)
    print(json.dumps(result, indent=2 if args.pretty else None, default=str))
    raise SystemExit(0 if result.get("ok") else 1)


if __name__ == "__main__":
    main()
