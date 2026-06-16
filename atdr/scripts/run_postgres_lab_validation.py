import argparse
import json
import subprocess
import time
from typing import Any

from sqlalchemy import create_engine, text
from sqlalchemy.exc import SQLAlchemyError

from atdr.app.core.config import PROJECT_ROOT, Settings


def _run_command(command: list[str], timeout: int = 60) -> dict[str, Any]:
    started = time.perf_counter()
    try:
        result = subprocess.run(
            command,
            cwd=PROJECT_ROOT,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {
            "ok": False,
            "command": command,
            "returncode": None,
            "stdout": "",
            "stderr": str(exc),
            "runtime_seconds": round(time.perf_counter() - started, 4),
        }
    return {
        "ok": result.returncode == 0,
        "command": command,
        "returncode": result.returncode,
        "stdout": result.stdout[-2000:],
        "stderr": result.stderr[-2000:],
        "runtime_seconds": round(time.perf_counter() - started, 4),
    }


def run_postgres_lab_validation(
    *,
    settings: Settings | None = None,
    run_alembic_check: bool = True,
) -> dict[str, Any]:
    settings = settings or Settings()
    started = time.perf_counter()
    is_postgres = settings.database_url.startswith("postgresql")
    if not is_postgres:
        return {
            "ok": True,
            "status": "postgres_lab_validation_blocked_by_environment",
            "postgres_lab_validated": False,
            "database_kind": "sqlite" if settings.database_url.startswith("sqlite") else "other",
            "current_database_modified": False,
            "message": (
                "Current configuration is not PostgreSQL. Normal local SQLite workflow remains valid; "
                "PostgreSQL lab validation must be run on a PostgreSQL/Docker-capable lab host."
            ),
            "checks": [
                {
                    "name": "postgres_database_configured",
                    "passed": False,
                    "detail": "DATABASE_URL is not PostgreSQL.",
                    "target": "postgresql+psycopg2://...",
                }
            ],
            "recommended_commands": [
                "Copy-Item .env.lab.example .env",
                "docker compose --profile postgres up -d postgres",
                "docker compose --profile postgres run --rm migrate",
                "python -m atdr.scripts.run_postgres_lab_validation --pretty",
            ],
            "runtime_seconds": round(time.perf_counter() - started, 4),
            "production_ready": False,
            "response_automation_allowed": False,
            "real_firewall_blocking_enabled": False,
        }

    checks: list[dict[str, Any]] = []
    try:
        engine = create_engine(settings.database_url, future=True)
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        checks.append({"name": "database_connection", "passed": True, "detail": "PostgreSQL connection succeeded."})
    except SQLAlchemyError as exc:
        checks.append(
            {
                "name": "database_connection",
                "passed": False,
                "detail": f"{exc.__class__.__name__}: {exc}",
            }
        )

    if run_alembic_check:
        alembic = _run_command(["python", "-m", "alembic", "check"], timeout=90)
        checks.append(
            {
                "name": "alembic_check",
                "passed": bool(alembic["ok"]),
                "detail": "Alembic check passed." if alembic["ok"] else (alembic["stderr"] or alembic["stdout"]),
                "runtime_seconds": alembic["runtime_seconds"],
            }
        )

    checks.extend(
        [
            {
                "name": "auto_create_tables_disabled",
                "passed": not settings.auto_create_tables,
                "detail": f"AUTO_CREATE_TABLES={settings.auto_create_tables}.",
            },
            {
                "name": "response_remains_simulated",
                "passed": settings.response_simulation,
                "detail": f"RESPONSE_SIMULATION={settings.response_simulation}.",
            },
        ]
    )
    passed = all(item["passed"] for item in checks)
    return {
        "ok": passed,
        "status": "postgres_lab_validated" if passed else "postgres_lab_validation_failed",
        "postgres_lab_validated": passed,
        "database_kind": "postgresql",
        "current_database_modified": False,
        "checks": checks,
        "runtime_seconds": round(time.perf_counter() - started, 4),
        "production_ready": False,
        "production_readiness_claim": False,
        "response_automation_allowed": False,
        "real_firewall_blocking_enabled": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate optional PostgreSQL lab deployment readiness.")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON output.")
    parser.add_argument("--skip-alembic-check", action="store_true", help="Skip running alembic check.")
    args = parser.parse_args()
    result = run_postgres_lab_validation(run_alembic_check=not args.skip_alembic_check)
    print(json.dumps(result, indent=2 if args.pretty else None, default=str))
    raise SystemExit(0 if result.get("ok") else 1)


if __name__ == "__main__":
    main()
