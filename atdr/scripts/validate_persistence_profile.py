from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any

from sqlalchemy import create_engine, inspect, select
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session

from atdr.app.core.config import PROJECT_ROOT, Settings
from atdr.app.db.engine import build_engine_kwargs, database_kind
from atdr.app.db.models import LogSource, MLLabel, MLModelRun, RawLog, ResponseAction, User
from atdr.app.services.persistence_service import create_database_backup, restore_database_backup


POSTGRES_CONFIRMATION = "ISOLATED_POSTGRES_DATABASES"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _configured_sqlite_path(settings: Settings) -> Path | None:
    if database_kind(settings.database_url) != "sqlite":
        return None
    from sqlalchemy.engine import make_url

    database = make_url(settings.database_url).database
    if not database or database == ":memory:":
        return None
    path = Path(database)
    return (PROJECT_ROOT / path).resolve() if not path.is_absolute() else path.resolve()


def _run_alembic_upgrade(database_url: str) -> dict[str, Any]:
    env = os.environ.copy()
    env.update(
        {
            "DATABASE_URL": database_url,
            "ENVIRONMENT": "development",
            "AUTO_CREATE_TABLES": "false",
            "RESPONSE_SIMULATION": "true",
            "ASSISTANT_ENABLED": "false",
            "ASSISTANT_LLM_ENABLED": "false",
            "ASSISTANT_ALLOW_RAW_LOG_CONTEXT": "false",
            "MFU_IAM_ENABLED": "false",
            "OIDC_ENABLED": "false",
            "SMTP_ENABLED": "false",
            "JWT_SECRET_KEY": "v389-isolated-validation-secret-not-for-deployment",
        }
    )
    try:
        result = subprocess.run(
            [sys.executable, "-m", "alembic", "upgrade", "head"],
            cwd=PROJECT_ROOT,
            capture_output=True,
            check=False,
            env=env,
            text=True,
            timeout=180,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"ok": False, "error_type": exc.__class__.__name__, "secrets_exposed": False}
    return {
        "ok": result.returncode == 0,
        "returncode": result.returncode,
        "error_type": None if result.returncode == 0 else "AlembicUpgradeError",
        "secrets_exposed": False,
    }


def _create_engine(database_url: str) -> Any:
    settings = Settings(DATABASE_URL=database_url)
    return create_engine(database_url, **build_engine_kwargs(settings))


def _database_identity(database_url: str) -> tuple[object, ...] | None:
    try:
        url = make_url(database_url)
    except Exception:
        return None
    if url.drivername.startswith("sqlite"):
        database = url.database or ""
        path = Path(database)
        if database and database != ":memory:" and not path.is_absolute():
            path = (PROJECT_ROOT / path).resolve()
        return ("sqlite", str(path) if database and database != ":memory:" else database)
    return (url.get_backend_name(), url.host, url.port, url.database, url.username)


def _database_is_empty(database_url: str) -> tuple[bool | None, str | None]:
    if database_kind(database_url) == "sqlite":
        try:
            database = make_url(database_url).database
        except Exception:
            return None, "DatabaseUrlParseError"
        if database and database != ":memory:":
            path = Path(database)
            path = (PROJECT_ROOT / path).resolve() if not path.is_absolute() else path.resolve()
            if not path.exists():
                return True, None
    engine = None
    try:
        engine = _create_engine(database_url)
        return not inspect(engine).get_table_names(), None
    except Exception as exc:
        return None, exc.__class__.__name__
    finally:
        if engine is not None:
            engine.dispose()


def _seed_synthetic_data(database_url: str) -> dict[str, int]:
    engine = _create_engine(database_url)
    try:
        with Session(engine) as session:
            session.add(
                User(
                    username="v389-persistence-analyst",
                    email="v389.persistence@example.invalid",
                    role="analyst",
                    password_hash="not-a-login-credential",
                    is_active=True,
                )
            )
            source = LogSource(
                name="v389-synthetic-source",
                source_type="sample",
                parser_profile="raw_fallback",
                enabled=True,
            )
            session.add(source)
            session.flush()
            session.add(RawLog(source_id=source.id, raw_line="v389 synthetic persistence validation"))
            session.commit()
        with Session(engine) as session:
            return {
                "users": len(session.scalars(select(User.id)).all()),
                "log_sources": len(session.scalars(select(LogSource.id)).all()),
                "raw_logs": len(session.scalars(select(RawLog.id)).all()),
                "response_actions": len(session.scalars(select(ResponseAction.id)).all()),
                "ml_model_runs": len(session.scalars(select(MLModelRun.id)).all()),
                "ml_labels": len(session.scalars(select(MLLabel.id)).all()),
            }
    finally:
        engine.dispose()


def _validate_pair(
    *,
    source_url: str,
    restore_url: str,
    output_dir: Path,
    protected_database_url: str,
) -> dict[str, Any]:
    protected_identity = _database_identity(protected_database_url)
    if protected_identity is not None and protected_identity in {_database_identity(source_url), _database_identity(restore_url)}:
        return {
            "ok": False,
            "status": "configured_database_target_refused",
            "current_database_modified": False,
            "secrets_exposed": False,
        }
    source_empty, source_error = _database_is_empty(source_url)
    restore_empty, restore_error = _database_is_empty(restore_url)
    if source_error or restore_error:
        return {
            "ok": False,
            "status": "isolated_target_check_failed",
            "error_type": source_error or restore_error,
            "current_database_modified": False,
            "secrets_exposed": False,
        }
    if not source_empty or not restore_empty:
        return {
            "ok": False,
            "status": "isolated_targets_must_be_empty",
            "current_database_modified": False,
            "secrets_exposed": False,
        }
    migration = _run_alembic_upgrade(source_url)
    if not migration["ok"]:
        return {
            "ok": False,
            "status": "migration_failed",
            "migration": migration,
            "current_database_modified": False,
            "secrets_exposed": False,
        }
    synthetic_counts = _seed_synthetic_data(source_url)
    source_settings = Settings(DATABASE_URL=source_url, AUTO_CREATE_TABLES=False)
    backup = create_database_backup(settings=source_settings, output_dir=output_dir, execute=True)
    if not backup.get("ok"):
        return {
            "ok": False,
            "status": "backup_failed",
            "migration": migration,
            "backup": backup,
            "synthetic_counts": synthetic_counts,
            "current_database_modified": False,
            "secrets_exposed": False,
        }
    restore = restore_database_backup(
        settings=source_settings,
        backup_path=backup["backup_path"],
        manifest_path=backup["manifest_path"],
        target_database_url=restore_url,
        execute=True,
        confirmed=True,
    )
    no_unsafe_side_effects = all(synthetic_counts.get(name, 0) == 0 for name in ("response_actions", "ml_model_runs", "ml_labels"))
    return {
        "ok": bool(backup.get("ok") and restore.get("ok") and no_unsafe_side_effects),
        "status": "persistence_validation_passed" if restore.get("ok") and no_unsafe_side_effects else "persistence_validation_failed",
        "migration": migration,
        "backup": backup,
        "restore": restore,
        "synthetic_counts": synthetic_counts,
        "no_response_or_model_side_effects": no_unsafe_side_effects,
        "current_database_modified": False,
        "secrets_exposed": False,
    }


def validate_persistence_profile(
    *,
    settings: Settings | None = None,
    include_postgres: bool = False,
    execute_postgres: bool = False,
    postgres_confirmed: bool = False,
) -> dict[str, Any]:
    settings = settings or Settings()
    started = time.perf_counter()
    run_id = uuid.uuid4().hex[:12]
    temp_root = PROJECT_ROOT / ".tmp" / f"v389-persistence-{run_id}"
    source_path = temp_root / "source.sqlite3"
    restore_path = temp_root / "restored.sqlite3"
    backup_dir = temp_root / "backups"
    temp_root.mkdir(parents=True, exist_ok=True)
    current_path = _configured_sqlite_path(settings)
    current_before = _sha256(current_path) if current_path and current_path.exists() else None

    sqlite_result = _validate_pair(
        source_url=f"sqlite:///{source_path}",
        restore_url=f"sqlite:///{restore_path}",
        output_dir=backup_dir,
        protected_database_url=settings.database_url,
    )
    current_after = _sha256(current_path) if current_path and current_path.exists() else None
    current_unchanged = current_before == current_after

    postgres_tools = {
        "psql": bool(shutil.which("psql")),
        "pg_dump": bool(shutil.which("pg_dump")),
        "pg_restore": bool(shutil.which("pg_restore")),
        "docker": bool(shutil.which("docker")),
    }
    postgres_result: dict[str, Any] = {
        "ok": True,
        "status": "not_requested",
        "postgres_runtime_validated": False,
        "current_database_modified": False,
        "secrets_exposed": False,
    }
    if include_postgres:
        source_url = os.environ.get("ATDR_PERSISTENCE_SOURCE_DATABASE_URL", "")
        restore_url = os.environ.get("ATDR_PERSISTENCE_RESTORE_DATABASE_URL", "")
        if not execute_postgres or not postgres_confirmed:
            postgres_result.update(status="explicit_execution_and_confirmation_required")
        elif not source_url or not restore_url:
            postgres_result.update(status="isolated_postgres_urls_missing")
        elif not all(postgres_tools[name] for name in ("pg_dump", "pg_restore")):
            postgres_result.update(status="postgres_tools_unavailable")
        elif database_kind(source_url) != "postgresql" or database_kind(restore_url) != "postgresql":
            postgres_result.update(status="isolated_postgres_urls_invalid")
        else:
            postgres_result = _validate_pair(
                source_url=source_url,
                restore_url=restore_url,
                output_dir=backup_dir / "postgres",
                protected_database_url=settings.database_url,
            )
            postgres_result["postgres_runtime_validated"] = bool(postgres_result.get("ok"))

    overall_ok = bool(sqlite_result.get("ok") and current_unchanged and postgres_result.get("ok"))
    return {
        "ok": overall_ok,
        "status": "persistence_profile_validated" if overall_ok else "persistence_profile_validation_failed",
        "configured_dialect": database_kind(settings.database_url),
        "sqlite_validation": sqlite_result,
        "postgresql_validation": postgres_result,
        "postgresql_tools": postgres_tools,
        "postgres_runtime_validated": bool(postgres_result.get("postgres_runtime_validated")),
        "current_database_fingerprint_checked": current_before is not None,
        "current_database_unchanged": current_unchanged,
        "current_database_modified": False,
        "raw_logs_sent_external": False,
        "response_automation_allowed": False,
        "model_activation_performed": False,
        "secrets_exposed": False,
        "production_ready": False,
        "runtime_seconds": round(time.perf_counter() - started, 4),
        "recommended_postgres_command": (
            "Set ATDR_PERSISTENCE_SOURCE_DATABASE_URL and ATDR_PERSISTENCE_RESTORE_DATABASE_URL to two new empty "
            "PostgreSQL databases, then run this command with --include-postgres --execute-postgres "
            f"--confirm {POSTGRES_CONFIRMATION}."
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate ATDR migrations, backup, and restore using isolated databases.")
    parser.add_argument("--include-postgres", action="store_true")
    parser.add_argument("--execute-postgres", action="store_true")
    parser.add_argument("--confirm", default="")
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()
    result = validate_persistence_profile(
        include_postgres=args.include_postgres,
        execute_postgres=args.execute_postgres,
        postgres_confirmed=args.confirm == POSTGRES_CONFIRMATION,
    )
    print(json.dumps(result, indent=2 if args.pretty else None, default=str))
    raise SystemExit(0 if result.get("ok") else 1)


if __name__ == "__main__":
    main()
