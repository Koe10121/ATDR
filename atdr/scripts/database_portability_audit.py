import argparse
import json
from typing import Any

from sqlalchemy import Boolean, DateTime, JSON

from atdr.app.core.config import PROJECT_ROOT, Settings
from atdr.app.db import models  # noqa: F401
from atdr.app.db.database import Base
from atdr.app.db.engine import database_kind, inspect_database_runtime


def _column_names_by_type(type_class: type) -> list[str]:
    names: list[str] = []
    for table in Base.metadata.sorted_tables:
        for column in table.columns:
            if isinstance(column.type, type_class):
                names.append(f"{table.name}.{column.name}")
    return names


def run_database_portability_audit(settings: Settings | None = None) -> dict[str, Any]:
    settings = settings or Settings()
    kind = database_kind(settings.database_url)
    blockers: list[str] = []
    warnings: list[str] = []
    checks: list[dict[str, Any]] = []

    runtime = inspect_database_runtime(settings)
    connection_ok = runtime["connection_status"] == "available"
    connection_detail = "Database connection succeeded." if connection_ok else runtime["connection_status"]
    if not connection_ok:
        blockers.append("Database connection failed or the configured SQLite file is missing.")

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
    if settings.auto_create_tables and kind == "postgresql":
        blockers.append("AUTO_CREATE_TABLES must be false for PostgreSQL/shared-lab validation; use Alembic migrations.")
    if kind == "sqlite" and settings.environment.lower() == "production":
        blockers.append("Production-like deployment cannot use SQLite.")
    if kind == "sqlite":
        warnings.append("SQLite is valid for normal local development, but PostgreSQL validation is still pending.")
    if json_columns:
        warnings.append("JSON fields exist; verify JSON query behavior on PostgreSQL during lab validation.")
    if datetime_columns:
        warnings.append("Timestamp fields exist; validate timezone and ordering behavior on PostgreSQL.")

    portability_status = "blocked" if blockers else "postgres_ready_to_validate" if kind == "postgresql" else "sqlite_local_ready_postgres_pending"
    return {
        "ok": connection_ok and alembic_available,
        "database_kind": kind,
        "database_profile": runtime,
        "portability_status": portability_status,
        "sqlite_local_compatibility": kind == "sqlite",
        "postgresql_expected_compatibility": True,
        "production_ready": False,
        "production_readiness_claim": False,
        "auto_create_tables": settings.auto_create_tables,
        "alembic_available": alembic_available,
        "pg_dump_available": runtime["backup_tools"]["pg_dump"],
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
            "Run atdr.scripts.backup_database with an explicit output directory; execution requires --execute.",
            "Run atdr.scripts.validate_persistence_profile for isolated migration, backup, checksum, and restore validation.",
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
