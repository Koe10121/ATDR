import argparse
import importlib.util
import json
import os
import shutil
import sqlite3
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen

from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

from atdr.app.core.config import PROJECT_ROOT, Settings


@dataclass(frozen=True)
class CheckResult:
    name: str
    status: str
    level: str
    message: str
    details: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "name": self.name,
            "status": self.status,
            "level": self.level,
            "message": self.message,
        }
        if self.details:
            payload["details"] = self.details
        return payload


def _ok(name: str, message: str, **details: Any) -> CheckResult:
    return CheckResult(name=name, status="ok", level="info", message=message, details=details or None)


def _warning(name: str, message: str, **details: Any) -> CheckResult:
    return CheckResult(name=name, status="warning", level="warning", message=message, details=details or None)


def _error(name: str, message: str, **details: Any) -> CheckResult:
    return CheckResult(name=name, status="error", level="critical", message=message, details=details or None)


def _run_command(command: list[str], *, timeout: float = 20.0) -> tuple[int, str, str]:
    try:
        completed = subprocess.run(
            command,
            cwd=PROJECT_ROOT,
            capture_output=True,
            check=False,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError as exc:
        return 127, "", str(exc)
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout if isinstance(exc.stdout, str) else ""
        stderr = exc.stderr if isinstance(exc.stderr, str) else ""
        return 124, stdout, stderr or f"Command timed out after {timeout} seconds."
    return completed.returncode, completed.stdout.strip(), completed.stderr.strip()


def _sqlite_path(database_url: str, *, root: Path = PROJECT_ROOT) -> Path | None:
    url = make_url(database_url)
    if url.drivername not in {"sqlite", "sqlite+pysqlite"}:
        return None
    database = url.database
    if not database or database == ":memory:":
        return None
    path = Path(database)
    if not path.is_absolute():
        path = root / path
    return path


def _safe_database_url_label(database_url: str) -> str:
    try:
        return make_url(database_url).render_as_string(hide_password=True)
    except Exception:
        return "unparseable-database-url"


def _running_inside_container() -> bool:
    return Path("/.dockerenv").exists() or os.environ.get("ATDR_RUNNING_IN_CONTAINER", "").lower() in {"1", "true", "yes"}


def check_database_url(database_url: str, *, root: Path = PROJECT_ROOT) -> CheckResult:
    safe_url = _safe_database_url_label(database_url)
    sqlite_path = _sqlite_path(database_url, root=root)
    if sqlite_path is not None:
        if not sqlite_path.exists():
            return _warning(
                "database",
                "SQLite database file is missing. Run Alembic migrations before starting the backend.",
                database_url=safe_url,
                path=str(sqlite_path),
            )
        try:
            connection = sqlite3.connect(f"file:{sqlite_path}?mode=rw", uri=True, timeout=5)
            connection.execute("SELECT 1")
            connection.close()
        except sqlite3.Error as exc:
            return _error("database", "SQLite database connection failed.", error=exc.__class__.__name__)
        return _ok("database", "SQLite database connection works.", database_url=safe_url, path=str(sqlite_path))

    try:
        url = make_url(database_url)
    except Exception:
        return _error("database", "DATABASE_URL could not be parsed.", database_url=safe_url)

    if url.drivername.startswith("postgresql") and (url.host or "").lower() == "postgres" and not _running_inside_container():
        return _error(
            "database",
            "PostgreSQL host 'postgres' is a Docker Compose service name. For normal local Windows workflow use sqlite:///./atdr.db, or start the PostgreSQL/Docker lab service first.",
            database_url=safe_url,
            recommendation='DATABASE_URL="sqlite:///./atdr.db"',
        )

    try:
        engine = create_engine(database_url, future=True)
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
    except Exception as exc:
        return _error("database", "Database connection failed.", database_url=safe_url, error=exc.__class__.__name__)
    return _ok("database", "Database connection works.", database_url=safe_url)


def _check_python() -> CheckResult:
    version = sys.version_info
    version_text = f"{version.major}.{version.minor}.{version.micro}"
    if (version.major, version.minor) < (3, 11):
        return _error("python_version", "Python 3.11 or newer is required.", version=version_text)
    return _ok("python_version", "Python version is supported.", version=version_text)


def _check_virtualenv() -> CheckResult:
    active = sys.prefix != sys.base_prefix
    local_venv = (PROJECT_ROOT / ".venv").exists()
    if active:
        return _ok("virtualenv", "Python virtual environment is active.", prefix=sys.prefix)
    if local_venv:
        return _warning("virtualenv", "A .venv exists but is not active in this shell.", prefix=sys.prefix)
    return _warning("virtualenv", "No active virtual environment detected.", prefix=sys.prefix)


def _check_imports() -> CheckResult:
    required = ["fastapi", "sqlalchemy", "alembic", "pydantic", "sklearn", "pandas", "uvicorn"]
    missing = [name for name in required if importlib.util.find_spec(name) is None]
    if missing:
        return _error("backend_dependencies", "Backend dependencies are missing. Run pip install -r requirements.txt.", missing=missing)
    return _ok("backend_dependencies", "Backend dependencies are importable.", checked=required)


def _check_node_npm() -> list[CheckResult]:
    checks: list[CheckResult] = []
    node_path = shutil.which("node")
    npm_path = shutil.which("npm.cmd") or shutil.which("npm")
    if node_path:
        code, stdout, stderr = _run_command(["node", "--version"])
        checks.append(_ok("node", "Node.js is available.", path=node_path, version=stdout or stderr) if code == 0 else _warning("node", "Node.js exists but version check failed.", path=node_path, error=stderr))
    else:
        checks.append(_warning("node", "Node.js was not found. Install Node.js before running the React dashboard."))
    if npm_path:
        command = ["npm.cmd", "--version"] if npm_path.lower().endswith("npm.cmd") else ["npm", "--version"]
        code, stdout, stderr = _run_command(command)
        checks.append(_ok("npm", "npm is available.", path=npm_path, version=stdout or stderr) if code == 0 else _warning("npm", "npm exists but version check failed.", path=npm_path, error=stderr))
    else:
        checks.append(_warning("npm", "npm was not found. Install Node.js/npm before running the React dashboard."))
    return checks


def _check_api_health(api_url: str) -> CheckResult:
    try:
        request = Request(f"{api_url.rstrip('/')}/health", headers={"User-Agent": "atdr-check-dev-environment"})
        with urlopen(request, timeout=5) as response:
            body = response.read(2000).decode("utf-8", errors="replace")
            if response.status == 200:
                return _ok("api_health", "Backend API health endpoint is reachable.", url=f"{api_url.rstrip('/')}/health", response=body)
            return _warning("api_health", "Backend API health endpoint returned a non-200 status.", status=response.status, response=body)
    except Exception as exc:
        return _warning(
            "api_health",
            "Backend API is not reachable. This is expected if you have not started Uvicorn yet.",
            url=f"{api_url.rstrip('/')}/health",
            error=exc.__class__.__name__,
        )


def build_report(*, check_api: bool = True, check_alembic: bool = True, api_url: str | None = None) -> dict[str, Any]:
    settings = Settings()
    api_url = api_url or settings.api_base_url
    checks: list[CheckResult] = [
        _check_python(),
        _check_virtualenv(),
        _check_imports(),
        _ok("project_root", "ATDR project root found.", path=str(PROJECT_ROOT)),
        _ok("env_example", ".env.example exists.", path=str(PROJECT_ROOT / ".env.example"))
        if (PROJECT_ROOT / ".env.example").exists()
        else _error("env_example", ".env.example is missing."),
        _ok("env_file", ".env exists.", path=str(PROJECT_ROOT / ".env"))
        if (PROJECT_ROOT / ".env").exists()
        else _warning("env_file", ".env is missing. Copy .env.example to .env before starting the backend."),
        _ok("frontend_package", "Frontend package.json exists.", path=str(PROJECT_ROOT / "frontend" / "package.json"))
        if (PROJECT_ROOT / "frontend" / "package.json").exists()
        else _error("frontend_package", "frontend/package.json is missing."),
        _ok("frontend_env_example", "frontend/.env.example exists.", path=str(PROJECT_ROOT / "frontend" / ".env.example"))
        if (PROJECT_ROOT / "frontend" / ".env.example").exists()
        else _warning("frontend_env_example", "frontend/.env.example is missing."),
        _ok("safe_sample", "Safe demo sample exists.", path=str(PROJECT_ROOT / "data" / "samples" / "paloalto-demo.txt"))
        if (PROJECT_ROOT / "data" / "samples" / "paloalto-demo.txt").exists()
        else _error("safe_sample", "Safe sample data/samples/paloalto-demo.txt is missing."),
        check_database_url(settings.database_url),
    ]
    checks.extend(_check_node_npm())

    if check_alembic:
        code, stdout, stderr = _run_command([sys.executable, "-m", "alembic", "check"], timeout=60)
        if code == 0:
            checks.append(_ok("alembic_check", "Alembic reports no migration drift.", stdout=stdout))
        else:
            checks.append(_warning("alembic_check", "Alembic check did not pass. Run migrations or inspect schema drift.", return_code=code, stdout=stdout, stderr=stderr))

    if check_api:
        checks.append(_check_api_health(api_url))

    payload_checks = [check.to_dict() for check in checks]
    critical_count = sum(1 for check in payload_checks if check["status"] == "error")
    warning_count = sum(1 for check in payload_checks if check["status"] == "warning")
    return {
        "ok": critical_count == 0,
        "critical_count": critical_count,
        "warning_count": warning_count,
        "project_root": str(PROJECT_ROOT),
        "database_url": _safe_database_url_label(settings.database_url),
        "api_url": api_url,
        "checks": payload_checks,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Check whether a teammate's local ATDR dev environment is ready.")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON output.")
    parser.add_argument("--no-api", action="store_true", help="Do not check the running backend /health endpoint.")
    parser.add_argument("--skip-alembic", action="store_true", help="Do not run alembic check.")
    parser.add_argument("--api-url", default=None, help="Override API URL for the health check.")
    parser.add_argument("--no-fail", action="store_true", help="Always exit 0; useful during first-time setup.")
    args = parser.parse_args()

    report = build_report(check_api=not args.no_api, check_alembic=not args.skip_alembic, api_url=args.api_url)
    print(json.dumps(report, indent=2 if args.pretty else None, default=str))
    raise SystemExit(0 if args.no_fail or report["ok"] else 1)


if __name__ == "__main__":
    main()
