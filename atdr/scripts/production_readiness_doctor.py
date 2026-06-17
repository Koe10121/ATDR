import argparse
import json
import subprocess
from pathlib import Path
from typing import Any

from atdr.app.core.config import PROJECT_ROOT, Settings, validate_runtime_settings


DEFAULT_SECRETS = {
    "change-this-dev-secret",
    "change-this-secret-before-production",
}
DEMO_PASSWORDS = {
    "admin123",
    "analyst123",
    "password",
    "changeme",
}
SENSITIVE_TRACKED_PATTERNS = (
    ".env",
    "atdr.db",
    ".sqlite",
    ".sqlite3",
    ".db",
    ".joblib",
    ".pkl",
    "ml_baseline_reviews/",
    "demo_exports/",
    "atdr/data/processed/",
    "paloalto-firewall",
)


def _check(name: str, passed: bool, severity: str, detail: str, fix: str) -> dict[str, Any]:
    return {
        "name": name,
        "passed": passed,
        "severity": "info" if passed else severity,
        "detail": detail,
        "recommended_fix": fix,
    }


def _tracked_files() -> list[str]:
    git_dir = PROJECT_ROOT / ".git"
    if not git_dir.exists():
        return []
    try:
        result = subprocess.run(
            ["git", "ls-files"],
            cwd=PROJECT_ROOT,
            check=True,
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return []
    return [line.strip().replace("\\", "/") for line in result.stdout.splitlines() if line.strip()]


def _tracked_sensitive_files(files: list[str]) -> list[str]:
    matched: list[str] = []
    for file_name in files:
        lower = file_name.lower()
        if lower.endswith(".env.example") or lower in {
            ".env.example",
            ".env.lab.example",
            ".env.production.example",
            "frontend/.env.example",
        }:
            continue
        for pattern in SENSITIVE_TRACKED_PATTERNS:
            normalized = pattern.lower()
            if lower == normalized or lower.endswith(normalized) or normalized in lower:
                if file_name.endswith(".gitkeep"):
                    continue
                matched.append(file_name)
                break
    return sorted(set(matched))


def run_production_readiness_doctor(settings: Settings | None = None) -> dict[str, Any]:
    settings = settings or Settings()
    environment = settings.environment.lower()
    is_production = environment == "production"
    tracked = _tracked_files()
    sensitive_tracked = _tracked_sensitive_files(tracked)
    runtime_issues = validate_runtime_settings(settings)
    has_runtime_blockers = bool(runtime_issues) and is_production
    checks = [
        _check(
            "environment_explicit",
            bool(settings.environment.strip()),
            "blocker",
            f"ENVIRONMENT={settings.environment!r}.",
            "Set ENVIRONMENT to development, lab, staging, or production intentionally.",
        ),
        _check(
            "strong_jwt_secret",
            settings.jwt_secret_key not in DEFAULT_SECRETS and len(settings.jwt_secret_key) >= 32,
            "blocker" if is_production else "warning",
            "JWT secret is non-default and at least 32 characters."
            if settings.jwt_secret_key not in DEFAULT_SECRETS
            else "JWT secret uses a known demo/default value.",
            "Replace JWT_SECRET_KEY with a long random secret before shared lab or production use.",
        ),
        _check(
            "demo_passwords_replaced",
            settings.demo_admin_password not in DEMO_PASSWORDS and settings.demo_analyst_password not in DEMO_PASSWORDS,
            "blocker" if is_production else "warning",
            "Demo passwords are not known defaults."
            if settings.demo_admin_password not in DEMO_PASSWORDS and settings.demo_analyst_password not in DEMO_PASSWORDS
            else "One or more demo passwords use known classroom defaults.",
            "Set non-default DEMO_ADMIN_PASSWORD and DEMO_ANALYST_PASSWORD before shared lab use.",
        ),
        _check(
            "postgres_for_production",
            not is_production or settings.database_url.startswith("postgresql"),
            "blocker",
            "Production profile uses PostgreSQL." if settings.database_url.startswith("postgresql") else "SQLite is configured.",
            "SQLite is fine for local development. Validate PostgreSQL before shared-lab or production-like claims.",
        ),
        _check(
            "postgres_lab_validation_required",
            not is_production,
            "warning",
            "PostgreSQL shared-lab validation is tracked separately.",
            "Run atdr.scripts.run_postgres_lab_validation on a Docker/PostgreSQL-capable host before shared-lab claims.",
        ),
        _check(
            "alembic_required_for_production",
            not is_production or not settings.auto_create_tables,
            "blocker",
            f"AUTO_CREATE_TABLES={settings.auto_create_tables}.",
            "Set AUTO_CREATE_TABLES=false and run Alembic migrations explicitly for production-like deployment.",
        ),
        _check(
            "cors_not_wildcard",
            "*" not in settings.cors_origins,
            "blocker" if is_production else "warning",
            f"CORS origins: {settings.cors_origins}.",
            "Use exact frontend origins instead of wildcard CORS.",
        ),
        _check(
            "response_simulation_enabled",
            settings.response_simulation and settings.response_provider.lower() == "simulation",
            "blocker",
            f"RESPONSE_SIMULATION={settings.response_simulation}; RESPONSE_PROVIDER={settings.response_provider}.",
            "Keep response simulation enabled until an approved connector, allowlist, rollback, and change control exist.",
        ),
        _check(
            "syslog_public_binding_reviewed",
            not settings.syslog_enabled or settings.syslog_host not in {"0.0.0.0", "::"} or is_production,
            "warning",
            f"SYSLOG_ENABLED={settings.syslog_enabled}; SYSLOG_HOST={settings.syslog_host}.",
            "Bind syslog to localhost for demo, or document firewall/network scope for lab pilot.",
        ),
        _check(
            "external_iam_not_required_but_documented",
            not settings.oidc_enabled or bool(settings.oidc_provider_name and settings.oidc_issuer_url and settings.oidc_allowed_domains),
            "blocker" if is_production else "warning",
            "OIDC disabled or minimally configured.",
            "Keep OIDC disabled for local login, or configure provider, issuer, and allowed school domains.",
        ),
        _check(
            "smtp_disabled_or_configured",
            not settings.smtp_enabled or bool(settings.smtp_host and settings.smtp_from_email),
            "warning",
            "SMTP disabled or configured.",
            "Do not enable SMTP until host and sender are configured and tested.",
        ),
        _check(
            "tls_reverse_proxy_documented",
            not is_production,
            "warning",
            "TLS/reverse proxy cannot be verified from local settings.",
            "Document and validate TLS termination, HSTS, and trusted proxy headers before production-like exposure.",
        ),
        _check(
            "backup_retention_documented",
            (PROJECT_ROOT / "docs" / "V3_3_BACKUP_RESTORE_AND_RETENTION_PLAN.md").exists() and not is_production,
            "warning",
            "Backup/retention plan is documented, but restore is not validated by this doctor.",
            "Validate database backup, restore, retention, and audit retention before production-like deployment.",
        ),
        _check(
            "repo_hygiene",
            not sensitive_tracked,
            "blocker",
            "No sensitive/generated tracked files detected."
            if not sensitive_tracked
            else f"Sensitive/generated files appear tracked: {sensitive_tracked[:10]}",
            "Remove sensitive/generated files from Git tracking and keep them ignored.",
        ),
        _check(
            "performance_smoke_reviewed",
            not is_production,
            "warning",
            "Performance smoke must be reviewed separately before production-like claims.",
            "Run atdr.scripts.performance_smoke on the target dataset; for large shared labs, validate PostgreSQL "
            "instead of relying only on local SQLite cache behavior.",
        ),
        _check(
            "runtime_settings_validation",
            not has_runtime_blockers,
            "blocker",
            "Runtime settings validation has no production blockers."
            if not runtime_issues
            else "; ".join(runtime_issues[:5]),
            "Fix runtime settings reported by validate_runtime_settings.",
        ),
    ]
    blockers = [
        f"{item['name']}: {item['detail']}"
        for item in checks
        if not item["passed"] and item["severity"] == "blocker"
    ]
    warnings = [
        f"{item['name']}: {item['detail']}"
        for item in checks
        if not item["passed"] and item["severity"] == "warning"
    ]
    return {
        "ok": not blockers,
        "status": "blocked" if blockers else "warnings" if warnings else "passed",
        "environment": settings.environment,
        "database_kind": "postgresql"
        if settings.database_url.startswith("postgresql")
        else "sqlite"
        if settings.database_url.startswith("sqlite")
        else "other",
        "production_ready": False,
        "production_readiness_claim": False,
        "model_activation_allowed": False,
        "response_automation_allowed": False,
        "real_firewall_blocking_enabled": False,
        "checks": checks,
        "blockers": blockers,
        "warnings": warnings,
        "tracked_sensitive_files": sensitive_tracked,
        "recommended_next_steps": [
            "Complete controlled real-device syslog pilot.",
            "Validate PostgreSQL lab deployment on a Docker/PostgreSQL-capable host.",
            "Run database_portability_audit before changing database backends.",
            "Run performance_smoke after large imports and compare cold/uncached and cached Overview timings.",
            "Replace demo secrets before shared lab use.",
            "Validate backup/restore and retention using dry-run-first helpers before shared lab handoff.",
            "Add TLS/reverse proxy, backup/restore, retention, and monitoring validation before production-like exposure.",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the ATDR v3.0 production-readiness doctor.")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON output.")
    args = parser.parse_args()
    result = run_production_readiness_doctor()
    print(json.dumps(result, indent=2 if args.pretty else None, default=str))
    raise SystemExit(0)


if __name__ == "__main__":
    main()
