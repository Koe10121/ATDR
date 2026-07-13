import argparse
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from atdr.app.core.config import PROJECT_ROOT, Settings
from atdr.app.db.engine import database_kind
from atdr.app.services.persistence_service import create_database_backup, restore_database_backup


def _resolve_output_dir(output_dir: str | Path) -> Path:
    path = Path(output_dir)
    return (PROJECT_ROOT / path).resolve() if not path.is_absolute() else path.resolve()


def run_backup_restore_drill(
    *,
    settings: Settings | None = None,
    output_dir: str | Path = ".tmp/atdr-backups",
    dry_run: bool = False,
    run_postgres_dump: bool = False,
) -> dict[str, Any]:
    """Backward-compatible drill backed by checksum-validated persistence services."""

    settings = settings or Settings()
    kind = database_kind(settings.database_url)
    if kind == "postgresql" and not run_postgres_dump:
        return {
            "ok": True,
            "status": "postgres_backup_drill_requires_explicit_dump",
            "database_kind": kind,
            "dry_run": dry_run,
            "current_database_modified": False,
            "restore_check_performed": False,
            "production_ready": False,
            "secrets_exposed": False,
        }

    backup = create_database_backup(settings=settings, output_dir=output_dir, execute=not dry_run)
    if dry_run or not backup.get("ok") or kind != "sqlite":
        return {
            "ok": bool(backup.get("ok")),
            "status": "dry_run" if dry_run else "postgres_backup_attempted" if kind == "postgresql" else backup.get("status"),
            "database_kind": kind,
            "dry_run": dry_run,
            "planned": backup.get("planned"),
            "postgres_dump": backup if kind == "postgresql" else None,
            "current_database_modified": False,
            "restore_check_performed": False,
            "production_ready": False,
            "secrets_exposed": False,
        }

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    restore_path = _resolve_output_dir(output_dir) / f"atdr-sqlite-restored-{timestamp}-{uuid.uuid4().hex[:8]}.sqlite3"
    restore = restore_database_backup(
        settings=settings,
        backup_path=backup["backup_path"],
        manifest_path=backup["manifest_path"],
        target_database_url=f"sqlite:///{restore_path}",
        execute=True,
        confirmed=True,
    )
    return {
        "ok": bool(restore.get("ok")),
        "status": "sqlite_backup_restore_drill_passed" if restore.get("ok") else "sqlite_backup_restore_validation_failed",
        "database_kind": kind,
        "dry_run": False,
        "current_database_modified": False,
        "backup_path": backup["backup_path"],
        "manifest_path": backup["manifest_path"],
        "backup_size_bytes": backup["size_bytes"],
        "restore_check_performed": True,
        "row_counts": restore.get("restored_table_counts", {}),
        "source_row_counts": backup.get("table_counts", {}),
        "checksum_valid": restore.get("checksum_valid", False),
        "migration_revision_match": restore.get("migration_revision_match", False),
        "production_ready": False,
        "secrets_exposed": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run a safe ATDR backup/restore readiness drill.")
    parser.add_argument("--output-dir", default=".tmp/atdr-backups")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--run-postgres-dump", action="store_true")
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()
    result = run_backup_restore_drill(
        output_dir=args.output_dir,
        dry_run=args.dry_run,
        run_postgres_dump=args.run_postgres_dump,
    )
    print(json.dumps(result, indent=2 if args.pretty else None, default=str))
    raise SystemExit(0 if result.get("ok") else 1)


if __name__ == "__main__":
    main()
