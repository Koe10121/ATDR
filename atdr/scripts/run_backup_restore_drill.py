import argparse
import json
import shutil
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

from atdr.app.core.config import PROJECT_ROOT, Settings
from atdr.scripts.backup_postgres import create_postgres_backup


TABLES_TO_COUNT = (
    "users",
    "log_sources",
    "raw_logs",
    "normalized_logs",
    "alerts",
    "alert_evidence",
    "ingestion_runs",
    "detection_runs",
    "response_actions",
    "audit_logs",
    "ml_labels",
)


def _database_kind(database_url: str) -> str:
    try:
        backend = make_url(database_url).get_backend_name()
    except Exception:
        return "unknown"
    if backend.startswith("sqlite"):
        return "sqlite"
    if backend.startswith("postgresql"):
        return "postgresql"
    return backend or "unknown"


def _safe_database_url(database_url: str) -> str:
    try:
        return make_url(database_url).render_as_string(hide_password=True)
    except Exception:
        return "<unparseable>"


def _sqlite_path(database_url: str) -> Path | None:
    try:
        url = make_url(database_url)
    except Exception:
        return None
    database = url.database
    if not database or database in {":memory:", ""}:
        return None
    path = Path(database)
    if not path.is_absolute():
        path = PROJECT_ROOT / path
    return path.resolve()


def _resolve_output_dir(output_dir: str | Path) -> Path:
    path = Path(output_dir)
    if not path.is_absolute():
        path = PROJECT_ROOT / path
    return path.resolve()


def _table_exists(connection, table_name: str) -> bool:
    row = connection.execute(
        text("SELECT name FROM sqlite_master WHERE type='table' AND name=:name"),
        {"name": table_name},
    ).first()
    return row is not None


def _sqlite_row_counts(database_path: Path) -> dict[str, int]:
    engine = create_engine(f"sqlite:///{database_path}", future=True)
    try:
        with engine.connect() as connection:
            counts: dict[str, int] = {}
            for table_name in TABLES_TO_COUNT:
                if _table_exists(connection, table_name):
                    counts[table_name] = int(connection.execute(text(f"SELECT COUNT(*) FROM {table_name}")).scalar() or 0)
            return counts
    finally:
        engine.dispose()


def _create_sqlite_backup_copy(source_path: Path, backup_path: Path) -> None:
    backup_path.parent.mkdir(parents=True, exist_ok=True)
    source_uri = f"file:{source_path.as_posix()}?mode=ro"
    with sqlite3.connect(source_uri, uri=True) as source, sqlite3.connect(backup_path) as destination:
        source.backup(destination)


def run_backup_restore_drill(
    *,
    settings: Settings | None = None,
    output_dir: str | Path = ".tmp/atdr-backups",
    dry_run: bool = False,
    run_postgres_dump: bool = False,
) -> dict[str, Any]:
    """Validate backup/restore readiness without overwriting the live database."""

    settings = settings or Settings()
    database_kind = _database_kind(settings.database_url)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output_path = _resolve_output_dir(output_dir)

    if database_kind == "sqlite":
        source_path = _sqlite_path(settings.database_url)
        backup_path = output_path / f"atdr-sqlite-backup-{timestamp}.sqlite3"
        if source_path is None:
            return {
                "ok": True,
                "status": "sqlite_backup_not_applicable",
                "database_kind": database_kind,
                "database_url": _safe_database_url(settings.database_url),
                "dry_run": dry_run,
                "current_database_modified": False,
                "production_ready": False,
                "message": "SQLite database URL is in-memory or unparseable, so no file backup is available.",
            }
        source_exists = source_path.exists()
        planned = {
            "source_path": str(source_path),
            "backup_path": str(backup_path),
            "source_exists": source_exists,
            "output_dir": str(output_path),
        }
        if dry_run:
            return {
                "ok": True,
                "status": "dry_run",
                "database_kind": database_kind,
                "database_url": _safe_database_url(settings.database_url),
                "dry_run": True,
                "planned": planned,
                "current_database_modified": False,
                "restore_check_performed": False,
                "production_ready": False,
                "recommended_next_step": "Rerun without --dry-run to create an ignored backup copy under .tmp and verify it opens.",
            }
        if not source_exists:
            return {
                "ok": False,
                "status": "sqlite_database_missing",
                "database_kind": database_kind,
                "database_url": _safe_database_url(settings.database_url),
                "dry_run": False,
                "planned": planned,
                "current_database_modified": False,
                "production_ready": False,
            }
        before_counts = _sqlite_row_counts(source_path)
        _create_sqlite_backup_copy(source_path, backup_path)
        restore_counts = _sqlite_row_counts(backup_path)
        return {
            "ok": before_counts == restore_counts,
            "status": "sqlite_backup_restore_drill_passed" if before_counts == restore_counts else "sqlite_backup_restore_count_mismatch",
            "database_kind": database_kind,
            "database_url": _safe_database_url(settings.database_url),
            "dry_run": False,
            "current_database_modified": False,
            "backup_path": str(backup_path),
            "backup_size_bytes": backup_path.stat().st_size if backup_path.exists() else 0,
            "restore_check_performed": True,
            "row_counts": restore_counts,
            "source_row_counts": before_counts,
            "production_ready": False,
            "warning": "Backup copy is written under an ignored local .tmp path. It is validation evidence, not a retention policy.",
        }

    if database_kind == "postgresql":
        if not run_postgres_dump:
            return {
                "ok": True,
                "status": "postgres_backup_drill_requires_explicit_dump",
                "database_kind": database_kind,
                "database_url": _safe_database_url(settings.database_url),
                "dry_run": dry_run,
                "current_database_modified": False,
                "production_ready": False,
                "recommended_next_step": "Run with --run-postgres-dump on the PostgreSQL lab host after confirming pg_dump is available.",
            }
        dump_result = create_postgres_backup(output_dir=output_path, database_url=settings.database_url, dry_run=dry_run)
        return {
            "ok": bool(dump_result.get("dry_run") or dump_result.get("ok")),
            "status": "postgres_backup_dry_run" if dry_run else "postgres_backup_attempted",
            "database_kind": database_kind,
            "database_url": _safe_database_url(settings.database_url),
            "dry_run": dry_run,
            "current_database_modified": False,
            "production_ready": False,
            "postgres_dump": dump_result,
            "restore_check_performed": False,
            "warning": "PostgreSQL restore must be validated against a separate lab database; this script never overwrites the live database.",
        }

    return {
        "ok": False,
        "status": "unsupported_database_kind",
        "database_kind": database_kind,
        "database_url": _safe_database_url(settings.database_url),
        "dry_run": dry_run,
        "current_database_modified": False,
        "production_ready": False,
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
