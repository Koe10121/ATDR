from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import Engine, create_engine, inspect, text
from sqlalchemy.engine import URL, make_url

from atdr.app.core.config import PROJECT_ROOT, Settings
from atdr.app.db import models  # noqa: F401
from atdr.app.db.database import Base
from atdr.app.db.engine import build_engine_kwargs, database_kind
from atdr.app.services.database_coordination_service import (
    acquire_backup_exclusive_lock,
    release_backup_exclusive_lock,
)


BACKUP_FORMAT_VERSION = 1
SAFE_PROJECT_BACKUP_ROOTS = {".tmp", ".atdr_runtime", "backups", "atdr"}


def _timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _artifact_stamp() -> str:
    return f"{_timestamp()}-{uuid.uuid4().hex[:8]}"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _resolve_output_dir(output_dir: str | Path) -> Path:
    path = Path(output_dir).expanduser()
    if not path.is_absolute():
        path = PROJECT_ROOT / path
    resolved = path.resolve()
    try:
        relative = resolved.relative_to(PROJECT_ROOT.resolve())
    except ValueError:
        return resolved
    if not relative.parts or relative.parts[0] not in SAFE_PROJECT_BACKUP_ROOTS:
        raise ValueError("Backup output inside the repository must use backups/, .tmp/, .atdr_runtime/, or atdr/data/processed/.")
    if relative.parts[0] == "atdr" and relative.parts[:3] != ("atdr", "data", "processed"):
        raise ValueError("Backup output under atdr/ is allowed only below atdr/data/processed/.")
    return resolved


def _sqlite_path(database_url: str) -> Path | None:
    try:
        url = make_url(database_url)
    except Exception:
        return None
    if not url.drivername.startswith("sqlite") or not url.database or url.database == ":memory:":
        return None
    path = Path(url.database)
    if not path.is_absolute():
        path = PROJECT_ROOT / path
    return path.resolve()


def _database_identity(database_url: str) -> tuple[Any, ...]:
    url = make_url(database_url)
    if url.drivername.startswith("sqlite"):
        return ("sqlite", _sqlite_path(database_url))
    return (url.get_backend_name(), url.host, url.port, url.database, url.username)


def _engine_for_url(database_url: str, settings: Settings | None = None) -> Engine:
    effective = settings or Settings(DATABASE_URL=database_url)
    if effective.database_url != database_url:
        effective = effective.model_copy(update={"database_url": database_url})
    return create_engine(database_url, **build_engine_kwargs(effective))


def _table_counts(engine: Engine) -> dict[str, int]:
    available = set(inspect(engine).get_table_names())
    table_names = sorted(name for name in Base.metadata.tables if name in available)
    with engine.connect() as connection:
        return {
            name: int(connection.execute(text(f'SELECT COUNT(*) FROM "{name}"')).scalar() or 0)
            for name in table_names
        }


def _table_counts_on_connection(connection) -> dict[str, int]:
    available = set(inspect(connection).get_table_names())
    table_names = sorted(name for name in Base.metadata.tables if name in available)
    return {
        name: int(connection.execute(text(f'SELECT COUNT(*) FROM "{name}"')).scalar() or 0)
        for name in table_names
    }


def _migration_revision_on_connection(connection) -> str | None:
    if not inspect(connection).has_table("alembic_version"):
        return None
    value = connection.execute(text("SELECT version_num FROM alembic_version")).scalar()
    return str(value) if value else None


def _active_mutating_job_count(connection) -> int:
    if not inspect(connection).has_table("operation_jobs"):
        return 0
    statement = text(
        "SELECT COUNT(*) FROM operation_jobs "
        "WHERE status IN ('running', 'cancel_requested') "
        "AND job_type IN ('import_logs', 'replay_logs', 'run_detection', 'train_ml', 'apply_ml_scoring')"
    )
    return int(connection.execute(statement).scalar() or 0)


def _migration_revision(engine: Engine) -> str | None:
    if not inspect(engine).has_table("alembic_version"):
        return None
    with engine.connect() as connection:
        value = connection.execute(text("SELECT version_num FROM alembic_version")).scalar()
    return str(value) if value else None


def _sqlite_integrity(path: Path) -> bool:
    uri = f"file:{path.as_posix()}?mode=ro"
    with sqlite3.connect(uri, uri=True) as connection:
        return connection.execute("PRAGMA quick_check").fetchone() == ("ok",)


def _pg_environment(url: URL) -> dict[str, str]:
    env = os.environ.copy()
    if url.password:
        env["PGPASSWORD"] = url.password
    return env


def _pg_args(url: URL) -> list[str]:
    args: list[str] = []
    if url.host:
        args.extend(["--host", url.host])
    if url.port:
        args.extend(["--port", str(url.port)])
    if url.username:
        args.extend(["--username", url.username])
    if url.database:
        args.extend(["--dbname", url.database])
    return args


def _public_pg_command(tool: str, *, output_path: Path | None = None) -> list[str]:
    command = [tool, "--host", "<configured>", "--username", "<configured>", "--dbname", "<configured>"]
    if output_path is not None:
        command.extend(["--file", str(output_path)])
    return command


def _run_pg_tool(command: list[str], *, url: URL, timeout: int = 600) -> dict[str, Any]:
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            check=False,
            env=_pg_environment(url),
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"ok": False, "returncode": None, "error_type": exc.__class__.__name__}
    return {
        "ok": result.returncode == 0,
        "returncode": result.returncode,
        "error_type": None if result.returncode == 0 else "PostgreSQLToolError",
    }


def _manifest_path(backup_path: Path) -> Path:
    return backup_path.with_name(f"{backup_path.name}.manifest.json")


def _load_manifest(backup_path: Path, manifest_path: str | Path | None = None) -> tuple[Path, dict[str, Any]]:
    path = Path(manifest_path).resolve() if manifest_path else _manifest_path(backup_path)
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or payload.get("format_version") != BACKUP_FORMAT_VERSION:
        raise ValueError("Unsupported or invalid ATDR backup manifest.")
    return path, payload


def verify_database_backup_artifact(
    *,
    backup_path: str | Path,
    manifest_path: str | Path | None = None,
    max_age_hours: float | None = None,
) -> dict[str, Any]:
    """Verify backup metadata, size, checksum, and optional freshness without restoring or exposing its path."""

    artifact = Path(backup_path).resolve()
    try:
        _, manifest = _load_manifest(artifact, manifest_path)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return {
            "ok": False,
            "status": "manifest_invalid",
            "error_type": exc.__class__.__name__,
            "artifact_read_only": True,
            "database_modified": False,
            "secrets_exposed": False,
        }
    required = {
        "artifact_name",
        "artifact_size_bytes",
        "sha256",
        "dialect",
        "created_at",
        "alembic_revision",
        "table_counts",
    }
    if not required.issubset(manifest) or Path(str(manifest.get("artifact_name", ""))).name != artifact.name:
        return {
            "ok": False,
            "status": "manifest_invalid",
            "artifact_read_only": True,
            "database_modified": False,
            "secrets_exposed": False,
        }
    if not artifact.is_file():
        return {
            "ok": False,
            "status": "artifact_missing",
            "artifact_name": artifact.name,
            "artifact_read_only": True,
            "database_modified": False,
            "secrets_exposed": False,
        }
    size_valid = artifact.stat().st_size == manifest.get("artifact_size_bytes")
    checksum_valid = size_valid and _sha256(artifact) == manifest.get("sha256")
    try:
        created_at = datetime.fromisoformat(str(manifest["created_at"]).replace("Z", "+00:00"))
        if created_at.tzinfo is None:
            created_at = created_at.replace(tzinfo=timezone.utc)
        age_hours = max(0.0, (datetime.now(timezone.utc) - created_at).total_seconds() / 3600)
    except (TypeError, ValueError):
        return {
            "ok": False,
            "status": "manifest_invalid",
            "artifact_name": artifact.name,
            "artifact_read_only": True,
            "database_modified": False,
            "secrets_exposed": False,
        }
    freshness_valid = max_age_hours is None or age_hours <= max_age_hours
    ok = bool(size_valid and checksum_valid and freshness_valid)
    status = "backup_verified" if ok else "backup_stale" if checksum_valid else "checksum_mismatch"
    table_counts = manifest.get("table_counts")
    return {
        "ok": ok,
        "status": status,
        "artifact_name": artifact.name,
        "dialect": manifest.get("dialect"),
        "artifact_size_bytes": artifact.stat().st_size,
        "size_valid": size_valid,
        "checksum_valid": checksum_valid,
        "freshness_valid": freshness_valid,
        "age_hours": round(age_hours, 3),
        "alembic_revision_recorded": bool(manifest.get("alembic_revision")),
        "table_count_entries": len(table_counts) if isinstance(table_counts, dict) else 0,
        "artifact_read_only": True,
        "database_modified": False,
        "secrets_exposed": False,
        "production_ready": False,
    }


def create_database_backup(
    *,
    settings: Settings,
    output_dir: str | Path,
    execute: bool = False,
    pg_dump_path: str | None = None,
) -> dict[str, Any]:
    """Create a consistent logical backup; dry-run unless execute is explicit."""

    kind = database_kind(settings.database_url)
    output = _resolve_output_dir(output_dir)
    suffix = ".sqlite3" if kind == "sqlite" else ".dump" if kind == "postgresql" else ".backup"
    backup_path = output / f"atdr-{kind}-{_artifact_stamp()}{suffix}"
    manifest_path = _manifest_path(backup_path)
    tool = pg_dump_path or shutil.which("pg_dump")
    planned = {
        "dialect": kind,
        "backup_path": str(backup_path),
        "manifest_path": str(manifest_path),
        "pg_dump_available": bool(tool) if kind == "postgresql" else None,
        "secrets_exposed": False,
    }
    if not execute:
        return {
            "ok": True,
            "status": "dry_run",
            "dry_run": True,
            "planned": planned,
            "source_database_modified": False,
            "command": _public_pg_command("pg_dump", output_path=backup_path) if kind == "postgresql" else None,
            "production_ready": False,
        }

    if kind == "sqlite":
        source_path = _sqlite_path(settings.database_url)
        if source_path is None or not source_path.exists():
            return {**planned, "ok": False, "status": "sqlite_source_missing", "source_database_modified": False}
        output.mkdir(parents=True, exist_ok=True)
        source_engine = _engine_for_url(settings.database_url, settings)
        try:
            source_counts = _table_counts(source_engine)
            revision = _migration_revision(source_engine)
        finally:
            source_engine.dispose()
        source_uri = f"file:{source_path.as_posix()}?mode=ro"
        with sqlite3.connect(source_uri, uri=True) as source, sqlite3.connect(backup_path) as destination:
            source.backup(destination)
    elif kind == "postgresql":
        if not tool:
            return {**planned, "ok": False, "status": "pg_dump_unavailable", "source_database_modified": False}
        source_engine = _engine_for_url(settings.database_url, settings)
        try:
            with source_engine.connect() as coordination_connection:
                if not acquire_backup_exclusive_lock(coordination_connection):
                    return {
                        **planned,
                        "ok": False,
                        "status": "operation_workers_active",
                        "source_database_modified": False,
                        "retryable": True,
                    }
                try:
                    active_jobs = _active_mutating_job_count(coordination_connection)
                    if active_jobs:
                        return {
                            **planned,
                            "ok": False,
                            "status": "active_mutating_jobs",
                            "active_mutating_jobs": active_jobs,
                            "source_database_modified": False,
                            "retryable": True,
                        }
                    source_counts = _table_counts_on_connection(coordination_connection)
                    revision = _migration_revision_on_connection(coordination_connection)
                    output.mkdir(parents=True, exist_ok=True)
                    url = make_url(settings.database_url)
                    command = [
                        tool,
                        "--format=custom",
                        "--no-owner",
                        "--no-privileges",
                        "--serializable-deferrable",
                        "--file",
                        str(backup_path),
                        *_pg_args(url),
                    ]
                    result = _run_pg_tool(command, url=url)
                finally:
                    release_backup_exclusive_lock(coordination_connection)
        finally:
            source_engine.dispose()
        if not result["ok"]:
            return {
                **planned,
                "ok": False,
                "status": "pg_dump_failed",
                "source_database_modified": False,
                "error_type": result["error_type"],
            }
    else:
        return {**planned, "ok": False, "status": "unsupported_database", "source_database_modified": False}

    artifact_sha = _sha256(backup_path)
    manifest = {
        "format_version": BACKUP_FORMAT_VERSION,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "dialect": kind,
        "artifact_name": backup_path.name,
        "artifact_size_bytes": backup_path.stat().st_size,
        "sha256": artifact_sha,
        "alembic_revision": revision,
        "table_counts": source_counts,
        "contains_private_data": True,
        "secrets_exposed": False,
    }
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return {
        "ok": True,
        "status": "backup_created",
        "dry_run": False,
        "dialect": kind,
        "backup_path": str(backup_path),
        "manifest_path": str(manifest_path),
        "size_bytes": manifest["artifact_size_bytes"],
        "sha256": artifact_sha,
        "alembic_revision": revision,
        "table_counts": source_counts,
        "source_database_modified": False,
        "secrets_exposed": False,
        "production_ready": False,
    }


def restore_database_backup(
    *,
    settings: Settings,
    backup_path: str | Path,
    target_database_url: str,
    manifest_path: str | Path | None = None,
    execute: bool = False,
    confirmed: bool = False,
    pg_restore_path: str | None = None,
) -> dict[str, Any]:
    """Restore only to a separate empty target; never overwrite the configured database."""

    artifact = Path(backup_path).resolve()
    try:
        loaded_manifest_path, manifest = _load_manifest(artifact, manifest_path)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return {
            "ok": False,
            "status": "manifest_invalid",
            "error_type": exc.__class__.__name__,
            "target_database_modified": False,
            "current_database_modified": False,
            "secrets_exposed": False,
        }
    if not artifact.exists() or _sha256(artifact) != manifest.get("sha256"):
        return {
            "ok": False,
            "status": "checksum_mismatch",
            "target_database_modified": False,
            "current_database_modified": False,
            "secrets_exposed": False,
        }
    try:
        same_database = _database_identity(settings.database_url) == _database_identity(target_database_url)
    except Exception:
        same_database = True
    if same_database:
        return {
            "ok": False,
            "status": "active_database_target_refused",
            "target_database_modified": False,
            "current_database_modified": False,
            "secrets_exposed": False,
        }

    target_kind = database_kind(target_database_url)
    if target_kind != manifest.get("dialect"):
        return {
            "ok": False,
            "status": "dialect_mismatch",
            "target_database_modified": False,
            "current_database_modified": False,
            "secrets_exposed": False,
        }
    planned = {
        "dialect": target_kind,
        "backup_path": str(artifact),
        "manifest_path": str(loaded_manifest_path),
        "checksum_valid": True,
        "secrets_exposed": False,
    }
    if not execute:
        return {
            **planned,
            "ok": True,
            "status": "dry_run",
            "dry_run": True,
            "target_database_modified": False,
            "current_database_modified": False,
            "production_ready": False,
        }
    if not confirmed:
        return {
            **planned,
            "ok": False,
            "status": "confirmation_required",
            "target_database_modified": False,
            "current_database_modified": False,
        }

    if target_kind == "sqlite":
        target_path = _sqlite_path(target_database_url)
        if target_path is None or target_path.exists():
            return {
                **planned,
                "ok": False,
                "status": "nonempty_or_invalid_target_refused",
                "target_database_modified": False,
                "current_database_modified": False,
            }
        target_path.parent.mkdir(parents=True, exist_ok=True)
        source_uri = f"file:{artifact.as_posix()}?mode=ro"
        with sqlite3.connect(source_uri, uri=True) as source, sqlite3.connect(target_path) as destination:
            source.backup(destination)
        integrity_ok = _sqlite_integrity(target_path)
    elif target_kind == "postgresql":
        tool = pg_restore_path or shutil.which("pg_restore")
        if not tool:
            return {
                **planned,
                "ok": False,
                "status": "pg_restore_unavailable",
                "target_database_modified": False,
                "current_database_modified": False,
            }
        target_engine = _engine_for_url(target_database_url)
        try:
            existing = [name for name in inspect(target_engine).get_table_names() if not name.startswith("pg_")]
        finally:
            target_engine.dispose()
        if existing:
            return {
                **planned,
                "ok": False,
                "status": "nonempty_or_invalid_target_refused",
                "target_database_modified": False,
                "current_database_modified": False,
            }
        url = make_url(target_database_url)
        command = [tool, "--no-owner", "--no-privileges", *_pg_args(url), str(artifact)]
        result = _run_pg_tool(command, url=url)
        if not result["ok"]:
            return {
                **planned,
                "ok": False,
                "status": "pg_restore_failed",
                "target_database_modified": True,
                "current_database_modified": False,
                "error_type": result["error_type"],
            }
        integrity_ok = True
    else:
        return {
            **planned,
            "ok": False,
            "status": "unsupported_database",
            "target_database_modified": False,
            "current_database_modified": False,
        }

    target_engine = _engine_for_url(target_database_url)
    try:
        restored_counts = _table_counts(target_engine)
        restored_revision = _migration_revision(target_engine)
    finally:
        target_engine.dispose()
    counts_match = restored_counts == manifest.get("table_counts", {})
    revision_match = restored_revision == manifest.get("alembic_revision")
    ok = integrity_ok and counts_match and revision_match
    return {
        **planned,
        "ok": ok,
        "status": "restore_validated" if ok else "restore_validation_failed",
        "dry_run": False,
        "target_database_modified": True,
        "current_database_modified": False,
        "integrity_ok": integrity_ok,
        "row_counts_match": counts_match,
        "migration_revision_match": revision_match,
        "restored_table_counts": restored_counts,
        "restored_alembic_revision": restored_revision,
        "production_ready": False,
    }
