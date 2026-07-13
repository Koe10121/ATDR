import argparse
import json
from pathlib import Path
from typing import Any

from atdr.app.core.config import Settings
from atdr.app.services.persistence_service import create_database_backup


def create_postgres_backup(
    *,
    output_dir: str | Path = "backups",
    database_url: str | None = None,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Backward-compatible, secret-safe PostgreSQL backup wrapper."""

    settings = Settings(DATABASE_URL=database_url) if database_url else Settings()
    result = create_database_backup(settings=settings, output_dir=output_dir, execute=not dry_run)
    result["dry_run"] = dry_run
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Create a PostgreSQL logical backup with pg_dump.")
    parser.add_argument("--output-dir", default="backups")
    parser.add_argument("--database-url", default=None, help="Prefer DATABASE_URL in a private environment file.")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    result = create_postgres_backup(output_dir=args.output_dir, database_url=args.database_url, dry_run=args.dry_run)
    print(json.dumps(result, indent=2, default=str))
    raise SystemExit(0 if result.get("ok") else 1)


if __name__ == "__main__":
    main()
