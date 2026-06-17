import argparse
import json
import subprocess
import sys
import time
from typing import Any

from sqlalchemy import create_engine, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.engine import make_url

from atdr.app.core.config import PROJECT_ROOT, Settings


def _database_kind(database_url: str) -> str:
    try:
        driver = make_url(database_url).get_backend_name()
    except Exception:
        return "unknown"
    if driver.startswith("postgresql"):
        return "postgresql"
    if driver.startswith("sqlite"):
        return "sqlite"
    return driver or "unknown"


def _safe_database_url(database_url: str) -> str:
    try:
        return make_url(database_url).render_as_string(hide_password=True)
    except Exception:
        return "<unparseable>"


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
    include_smoke: bool = False,
    include_sample_ingest: bool = False,
    include_release_gate: bool = False,
) -> dict[str, Any]:
    settings = settings or Settings()
    started = time.perf_counter()
    database_kind = _database_kind(settings.database_url)
    is_postgres = database_kind == "postgresql"
    if not is_postgres:
        return {
            "ok": True,
            "status": "postgres_lab_validation_blocked_by_environment",
            "postgres_lab_validated": False,
            "database_kind": database_kind,
            "database_url": _safe_database_url(settings.database_url),
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
                ".\\.venv\\Scripts\\python.exe -m atdr.scripts.run_postgres_lab_validation --pretty",
                ".\\.venv\\Scripts\\python.exe -m atdr.scripts.run_postgres_lab_validation --include-smoke --include-sample-ingest --pretty",
            ],
            "optional_flags": {
                "include_smoke": include_smoke,
                "include_sample_ingest": include_sample_ingest,
                "include_release_gate": include_release_gate,
            },
            "runtime_seconds": round(time.perf_counter() - started, 4),
            "production_ready": False,
            "production_readiness_claim": False,
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
        alembic = _run_command([sys.executable, "-m", "alembic", "check"], timeout=90)
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
    if include_sample_ingest:
        seed = _run_command([sys.executable, "-m", "atdr.scripts.seed_users"], timeout=90)
        checks.append(
            {
                "name": "seed_users_idempotent",
                "passed": bool(seed["ok"]),
                "detail": "seed_users completed." if seed["ok"] else (seed["stderr"] or seed["stdout"]),
                "runtime_seconds": seed["runtime_seconds"],
                "writes_safe_sample_data": True,
            }
        )
        pilot = _run_command(
            [sys.executable, "-m", "atdr.scripts.run_v32_no_hardware_source_pilot", "--count", "100", "--pretty"],
            timeout=180,
        )
        checks.append(
            {
                "name": "safe_no_hardware_source_pilot",
                "passed": bool(pilot["ok"]),
                "detail": "No-hardware source pilot completed." if pilot["ok"] else (pilot["stderr"] or pilot["stdout"]),
                "runtime_seconds": pilot["runtime_seconds"],
                "writes_safe_sample_data": True,
            }
        )
    else:
        checks.append(
            {
                "name": "safe_sample_ingest",
                "passed": True,
                "skipped": True,
                "detail": "Not run. Pass --include-sample-ingest to write safe sample rows on PostgreSQL.",
            }
        )
    if include_smoke:
        smoke = _run_command([sys.executable, "-m", "atdr.scripts.performance_smoke", "--pretty"], timeout=180)
        checks.append(
            {
                "name": "performance_smoke",
                "passed": bool(smoke["ok"]),
                "detail": "Performance smoke completed." if smoke["ok"] else (smoke["stderr"] or smoke["stdout"]),
                "runtime_seconds": smoke["runtime_seconds"],
            }
        )
    else:
        checks.append(
            {
                "name": "performance_smoke",
                "passed": True,
                "skipped": True,
                "detail": "Not run. Pass --include-smoke for read-only performance timings.",
            }
        )
    if include_release_gate:
        release = _run_command([sys.executable, "-m", "atdr.scripts.verify_release"], timeout=600)
        checks.append(
            {
                "name": "release_gate",
                "passed": bool(release["ok"]),
                "detail": "Release gate completed." if release["ok"] else (release["stderr"] or release["stdout"]),
                "runtime_seconds": release["runtime_seconds"],
            }
        )
    else:
        checks.append(
            {
                "name": "release_gate",
                "passed": True,
                "skipped": True,
                "detail": "Not run. Pass --include-release-gate to run the full backend release gate.",
            }
        )
    passed = all(item["passed"] for item in checks)
    return {
        "ok": passed,
        "status": "postgres_lab_validated" if passed else "postgres_lab_validation_failed",
        "postgres_lab_validated": passed,
        "database_kind": "postgresql",
        "database_url": _safe_database_url(settings.database_url),
        "current_database_modified": include_sample_ingest,
        "safe_sample_data_written": include_sample_ingest,
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
    parser.add_argument("--include-smoke", action="store_true", help="Run read-only performance smoke on PostgreSQL.")
    parser.add_argument(
        "--include-sample-ingest",
        action="store_true",
        help="Run seed users and safe no-hardware sample ingest/detection on PostgreSQL.",
    )
    parser.add_argument("--include-release-gate", action="store_true", help="Run full backend release gate.")
    args = parser.parse_args()
    result = run_postgres_lab_validation(
        run_alembic_check=not args.skip_alembic_check,
        include_smoke=args.include_smoke,
        include_sample_ingest=args.include_sample_ingest,
        include_release_gate=args.include_release_gate,
    )
    print(json.dumps(result, indent=2 if args.pretty else None, default=str))
    raise SystemExit(0 if result.get("ok") else 1)


if __name__ == "__main__":
    main()
