import argparse
import json
from pathlib import Path
from typing import Any

from atdr.app.core.config import PROJECT_ROOT, Settings, validate_runtime_settings


DEFAULT_SECRETS = {"change-this-dev-secret", "change-this-secret-before-production"}
DEMO_PASSWORDS = {"admin123", "analyst123", "password", "changeme"}


def _resolve_project_path(path_value: str | Path) -> Path:
    path = Path(path_value)
    if not path.is_absolute():
        return PROJECT_ROOT / path
    return path


def _issue(severity: str, code: str, message: str) -> dict[str, str]:
    return {"severity": severity, "code": code, "message": message}


def run_config_doctor(settings: Settings | None = None) -> dict[str, Any]:
    settings = settings or Settings()
    environment = settings.environment.lower()
    is_production = environment == "production"
    issues: list[dict[str, str]] = []

    for message in validate_runtime_settings(settings):
        severity = "critical" if is_production else "warning"
        code = message.split(" ", 1)[0].lower().replace("_", "-").replace(".", "")
        issues.append(_issue(severity, code, message))

    if settings.jwt_secret_key in DEFAULT_SECRETS:
        issues.append(
            _issue(
                "critical" if is_production else "warning",
                "default-jwt-secret",
                "JWT_SECRET_KEY uses a known demo/default value.",
            )
        )
    elif len(settings.jwt_secret_key) < 32:
        issues.append(_issue("warning", "short-jwt-secret", "JWT_SECRET_KEY should be at least 32 characters."))

    if settings.demo_admin_password in DEMO_PASSWORDS or settings.demo_analyst_password in DEMO_PASSWORDS:
        issues.append(
            _issue(
                "critical" if is_production else "warning",
                "default-demo-password",
                "One or more demo user passwords use classroom defaults.",
            )
        )

    if is_production and settings.database_url.startswith("sqlite"):
        issues.append(_issue("critical", "production-sqlite", "Production environment must use PostgreSQL, not SQLite."))

    if "*" in settings.cors_origins:
        issues.append(
            _issue(
                "critical" if is_production else "warning",
                "wildcard-cors",
                "CORS_ALLOWED_ORIGINS includes '*'. Use exact dashboard origins.",
            )
        )

    if settings.syslog_enabled and settings.syslog_host in {"0.0.0.0", "::"}:
        issues.append(
            _issue(
                "critical" if is_production else "warning",
                "public-syslog-bind",
                "SYSLOG_HOST binds publicly. Use host firewall rules and approved network scope.",
            )
        )

    if not settings.response_simulation:
        issues.append(
            _issue(
                "critical" if is_production else "warning",
                "response-simulation-disabled",
                "RESPONSE_SIMULATION is false. Real enforcement requires an approved connector, allowlist, and rollback plan.",
            )
        )
    if settings.response_provider.lower() != "simulation" and settings.response_simulation:
        issues.append(
            _issue(
                "warning",
                "response-provider-ignored",
                "RESPONSE_PROVIDER is set but RESPONSE_SIMULATION=true, so enforcement remains simulated.",
            )
        )

    oidc_fields = [
        settings.oidc_provider_name,
        settings.oidc_client_id,
        settings.oidc_client_secret,
        settings.oidc_issuer_url,
        settings.oidc_allowed_domains,
    ]
    if not settings.oidc_enabled and any(value.strip() for value in oidc_fields):
        issues.append(
            _issue(
                "warning",
                "oidc-partial-disabled",
                "OIDC fields are present while OIDC_ENABLED=false. Local login remains active; verify this is intentional.",
            )
        )

    if is_production and settings.api_base_url.startswith("http://"):
        issues.append(
            _issue(
                "critical",
                "missing-tls-api-url",
                "API_BASE_URL uses http:// in production. Validate TLS/reverse proxy before production-like exposure.",
            )
        )

    sample_path = _resolve_project_path(settings.demo_sample_log_path)
    if not sample_path.exists():
        issues.append(_issue("warning", "missing-sample-log", f"Demo sample log path does not exist: {sample_path}"))

    model_path = settings.resolved_model_path
    model_dir = model_path.parent
    supervised_model_path = settings.resolved_supervised_model_path
    if not model_dir.exists():
        issues.append(_issue("warning", "missing-model-dir", f"ML model directory does not exist: {model_dir}"))

    critical_count = sum(1 for item in issues if item["severity"] == "critical")
    warning_count = sum(1 for item in issues if item["severity"] == "warning")
    return {
        "ok": critical_count == 0,
        "environment": settings.environment,
        "database": "postgresql" if settings.database_url.startswith("postgresql") else "sqlite" if settings.database_url.startswith("sqlite") else "other",
        "response_simulation": settings.response_simulation,
        "response_provider": settings.response_provider,
        "syslog": {
            "enabled": settings.syslog_enabled,
            "host": settings.syslog_host,
            "port": settings.syslog_port,
        },
        "paths": {
            "sample_log": str(sample_path),
            "sample_log_exists": sample_path.exists(),
            "model_path": str(model_path),
            "supervised_model_path": str(supervised_model_path),
            "model_dir_exists": model_dir.exists(),
        },
        "critical_count": critical_count,
        "warning_count": warning_count,
        "issues": issues,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Inspect ATDR environment configuration for demo, lab, and production safety.")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON output.")
    args = parser.parse_args()

    result = run_config_doctor()
    print(json.dumps(result, indent=2 if args.pretty else None, default=str))
    raise SystemExit(0 if result["ok"] else 1)


if __name__ == "__main__":
    main()
