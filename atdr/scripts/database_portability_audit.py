import argparse
import json
import shutil
from typing import Any

from sqlalchemy import Boolean, DateTime, JSON, create_engine, text
from sqlalchemy.engine import make_url

from atdr.app.core.config import PROJECT_ROOT, Settings
from atdr.app.db import models  # noqa: F401
from atdr.app.db.database import Base


def _database_kind(database_url: str) -> str:
    try:
        backend = make_url(database_url).get_backend_name()
    except Exception:
        return "unknown"
    if backend.startswith("postgresql"):
        return "postgresql"
    if backend.startswith("sqlite"):
        return "sqlite"
    return backend or "unknown"


def _safe_database_url(database_url: str) -> str:
    try:
        return make_url(database_url).render_as_string(hide_password=True)
    except Exception:
        return "<unparseable>"


def _column_names_by_type(type_class: type) -> list[str]:
    names: list[str] = []
    for table in Base.metadata.sorted_tables:
        for column in table.columns:
            if isinstance(column.type, type_class):
                names.append(f"{table.name}.{column.name}")
    return names


def run_database_portability_audit(settings: Settings | None = None) -> dict[str, Any]:
    settings = settings or Settings()
    database_kind = _database_kind(settings.database_url)
    blockers: list[str] = []
    warnings: list[str] = []
    checks: list[dict[str, Any]] = []

    try:
        engine_kwargs: dict[str, Any] = {}
        if database_kind == "sqlite":
            engine_kwargs["connect_args"] = {"check_same_thread": False}
        engine = create_engine(settings.database_url, future=True, **engine_kwargs)
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        connection_ok = True
        connection_detail = "Database connection succeeded."
    except Exception as exc:
        connection_ok = False
        connection_detail = f"{exc.__class__.__name__}: {exc}"
        blockers.append("Database connection failed.")

    checks.append({"name": "database_connection", "passed": connection_ok, "detail": connection_detail})
    alembic_available = (PROJECT_ROOT / "alembic.ini").exists() and (PROJECT_ROOT / "migrations" / "versions").exists()
    checks.append(
        {
            "name": "alembic_available",
            "passed": alembic_available,
            "detail": "Alembic configuration and migration versions exist."
            if alembic_available
            else "Alembic configuration or migration versions are missing.",
        }
    )
    if not alembic_available:
        blockers.append("Alembic migrations are required for PostgreSQL/shared-lab validation.")

    json_columns = _column_names_by_type(JSON)
    datetime_columns = _column_names_by_type(DateTime)
    boolean_columns = _column_names_by_type(Boolean)
    sqlite_only_assumptions = [
        "SQLite uses AUTO_CREATE_TABLES=true for local development unless disabled.",
        "SQLite engine uses check_same_thread=false for local FastAPI access.",
        "Local atdr.db is a demo/lab file and must not be shared as production state.",
    ]
    if settings.auto_create_tables and database_kind == "postgresql":
        blockers.append("AUTO_CREATE_TABLES must be false for PostgreSQL/shared-lab validation; use Alembic migrations.")
    if database_kind == "sqlite" and settings.environment.lower() == "production":
        blockers.append("Production-like deployment cannot use SQLite.")
    if database_kind == "sqlite":
        warnings.append("SQLite is valid for normal local development, but PostgreSQL validation is still pending.")
    if json_columns:
        warnings.append("JSON fields exist; verify JSON query behavior on PostgreSQL during lab validation.")
    if datetime_columns:
        warnings.append("Timestamp fields exist; validate timezone and ordering behavior on PostgreSQL.")

    portability_status = "blocked" if blockers else "postgres_ready_to_validate" if database_kind == "postgresql" else "sqlite_local_ready_postgres_pending"
    return {
        "ok": connection_ok and alembic_available,
        "database_kind": database_kind,
        "database_url": _safe_database_url(settings.database_url),
        "portability_status": portability_status,
        "sqlite_local_compatibility": database_kind == "sqlite",
        "postgresql_expected_compatibility": True,
        "production_ready": False,
        "production_readiness_claim": False,
        "auto_create_tables": settings.auto_create_tables,
        "alembic_available": alembic_available,
        "pg_dump_available": bool(shutil.which("pg_dump")),
        "known_sqlite_only_assumptions": sqlite_only_assumptions,
        "timestamp_date_handling_concerns": datetime_columns,
        "json_field_handling_concerns": json_columns,
        "boolean_handling_concerns": boolean_columns,
        "index_migration_coverage": {
            "tables": len(Base.metadata.tables),
            "indexes": sum(len(table.indexes) for table in Base.metadata.tables.values()),
            "note": "Alembic check remains the source of truth for migration drift.",
        },
        "checks": checks,
        "blockers": blockers,
        "warnings": warnings,
        "recommended_next_steps": [
            "Keep SQLite for normal local development.",
            "Run Alembic check before PostgreSQL lab validation.",
            "Run atdr.scripts.run_postgres_lab_validation on a PostgreSQL/Docker-capable host.",
            "Run backup_demo --dry-run locally and backup_postgres --dry-run on the PostgreSQL host.",
            "Do not claim production readiness until real-device forwarding, PostgreSQL, backup/restore, and secrets are validated.",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run a read-only ATDR database portability audit.")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON output.")
    args = parser.parse_args()
    result = run_database_portability_audit()
    print(json.dumps(result, indent=2 if args.pretty else None, default=str))
    raise SystemExit(0 if result.get("ok") else 1)


if __name__ == "__main__":
    main()
