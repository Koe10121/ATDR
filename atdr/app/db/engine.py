from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import Engine, create_engine, inspect, text
from sqlalchemy.engine import make_url
from sqlalchemy.pool import Pool

from atdr.app.core.config import Settings
from atdr.app.core.config import PROJECT_ROOT


def database_kind(database_url: str) -> str:
    try:
        backend = make_url(database_url).get_backend_name()
    except Exception:
        return "unknown"
    if backend.startswith("postgresql"):
        return "postgresql"
    if backend.startswith("sqlite"):
        return "sqlite"
    return backend or "unknown"


def build_engine_kwargs(settings: Settings, *, poolclass: type[Pool] | None = None) -> dict[str, Any]:
    """Build dialect-aware engine options without exposing connection values."""

    kind = database_kind(settings.database_url)
    kwargs: dict[str, Any] = {"future": True}

    if kind == "sqlite":
        kwargs["connect_args"] = {
            "check_same_thread": False,
            "timeout": float(settings.db_connect_timeout_seconds),
        }
    elif kind == "postgresql":
        connect_args: dict[str, Any] = {"connect_timeout": settings.db_connect_timeout_seconds}
        if settings.db_statement_timeout_ms > 0:
            connect_args["options"] = f"-c statement_timeout={settings.db_statement_timeout_ms}"
        kwargs.update(
            {
                "connect_args": connect_args,
                "pool_pre_ping": settings.db_pool_pre_ping,
            }
        )
        if poolclass is None:
            kwargs.update(
                {
                    "pool_size": settings.db_pool_size,
                    "max_overflow": settings.db_max_overflow,
                    "pool_timeout": float(settings.db_pool_timeout_seconds),
                }
            )

    if poolclass is not None:
        kwargs["poolclass"] = poolclass
    return kwargs


def create_configured_engine(settings: Settings, *, poolclass: type[Pool] | None = None) -> Engine:
    return create_engine(settings.database_url, **build_engine_kwargs(settings, poolclass=poolclass))


def public_database_profile(settings: Settings) -> dict[str, Any]:
    """Return an intentionally minimal profile suitable for health/config output."""

    kind = database_kind(settings.database_url)
    return {
        "dialect": kind,
        "configured": kind != "unknown",
        "host_configured": kind == "postgresql" and bool(make_url(settings.database_url).host),
        "pool_pre_ping": settings.db_pool_pre_ping if kind == "postgresql" else False,
        "secrets_exposed": False,
    }


def _sqlite_file(settings: Settings) -> Path | None:
    if database_kind(settings.database_url) != "sqlite":
        return None
    database = make_url(settings.database_url).database
    if not database or database == ":memory:":
        return None
    path = Path(database)
    return (PROJECT_ROOT / path).resolve() if not path.is_absolute() else path.resolve()


def migration_head_revision() -> str | None:
    try:
        config = Config(str(PROJECT_ROOT / "alembic.ini"))
        return ScriptDirectory.from_config(config).get_current_head()
    except Exception:
        return None


def inspect_database_runtime(settings: Settings, *, probe_connection: bool = True) -> dict[str, Any]:
    """Inspect availability and migration state without returning connection metadata."""

    profile = public_database_profile(settings)
    tools = {
        "sqlite_backup_api": True,
        "pg_dump": bool(shutil.which("pg_dump")),
        "pg_restore": bool(shutil.which("pg_restore")),
        "psql": bool(shutil.which("psql")),
    }
    if not probe_connection:
        return {
            **profile,
            "connection_status": "not_checked",
            "migration_status": "not_checked",
            "current_revision": None,
            "head_revision": migration_head_revision(),
            "backup_tools": tools,
        }
    sqlite_file = _sqlite_file(settings)
    if profile["dialect"] == "sqlite" and sqlite_file is not None and not sqlite_file.exists():
        return {
            **profile,
            "connection_status": "missing",
            "migration_status": "unavailable",
            "current_revision": None,
            "head_revision": migration_head_revision(),
            "backup_tools": tools,
        }
    engine: Engine | None = None
    try:
        engine = create_configured_engine(settings)
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
            inspector = inspect(connection)
            revision = (
                connection.execute(text("SELECT version_num FROM alembic_version")).scalar()
                if inspector.has_table("alembic_version")
                else None
            )
        head = migration_head_revision()
        migration_status = "at_head" if revision and revision == head else "unversioned" if not revision else "not_at_head"
        return {
            **profile,
            "connection_status": "available",
            "migration_status": migration_status,
            "current_revision": str(revision) if revision else None,
            "head_revision": head,
            "backup_tools": tools,
        }
    except Exception as exc:
        return {
            **profile,
            "connection_status": "unavailable",
            "connection_error_type": exc.__class__.__name__,
            "migration_status": "unavailable",
            "current_revision": None,
            "head_revision": migration_head_revision(),
            "backup_tools": tools,
        }
    finally:
        if engine is not None:
            engine.dispose()
