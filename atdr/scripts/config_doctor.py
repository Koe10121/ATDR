import argparse
import json
import os
import shutil
from pathlib import Path
from typing import Any

from sqlalchemy.engine import make_url

from atdr.app.core.config import PROJECT_ROOT, Settings, validate_runtime_settings
from atdr.app.db.engine import inspect_database_runtime
from atdr.app.services.mfu_iam_service import build_mfu_iam_status


DEFAULT_SECRETS = {"change-this-dev-secret", "change-this-secret-before-production"}
DEMO_PASSWORDS = {"admin123", "analyst123", "password", "changeme"}


def _resolve_project_path(path_value: str | Path) -> Path:
    path = Path(path_value)
    if not path.is_absolute():
        return PROJECT_ROOT / path
    return path


def _issue(severity: str, code: str, message: str) -> dict[str, str]:
    return {"severity": severity, "code": code, "message": message}


def _database_url_info(database_url: str) -> dict[str, str | None]:
    try:
        url = make_url(database_url)
    except Exception:
        return {"kind": "other", "driver": None, "host": None}
    driver = url.drivername
    kind = "postgresql" if driver.startswith("postgresql") else "sqlite" if driver.startswith("sqlite") else "other"
    return {"kind": kind, "driver": driver, "host": url.host}


def _running_inside_container() -> bool:
    return Path("/.dockerenv").exists() or os.environ.get("ATDR_RUNNING_IN_CONTAINER", "").lower() in {"1", "true", "yes"}


def run_config_doctor(settings: Settings | None = None) -> dict[str, Any]:
    settings = settings or Settings()
    environment = settings.environment.lower()
    is_production = environment == "production"
    issues: list[dict[str, str]] = []
    database_info = _database_url_info(settings.database_url)
    known_docker_alias = database_info["kind"] == "postgresql" and (database_info["host"] or "").lower() == "postgres" and not _running_inside_container()
    database_runtime = inspect_database_runtime(settings, probe_connection=not known_docker_alias)
    mfu_iam_status = build_mfu_iam_status(settings)

    if settings.local_login_enabled:
        issues.append(
            _issue(
                "warning",
                "local-recovery-auth-mode",
                "ATDR_AUTH_MODE=local_recovery is explicitly enabled. Use template_shell for the normal MFU user path.",
            )
        )

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

    if database_info["kind"] == "sqlite" and not is_production:
        issues.append(
            _issue(
                "info",
                "local-sqlite-profile",
                "Normal local workflow is using SQLite. This is the recommended teammate/laptop profile.",
            )
        )

    if database_info["kind"] == "postgresql":
        host = (database_info["host"] or "").lower()
        if host == "postgres" and not _running_inside_container():
            issues.append(
                _issue(
                    "warning",
                    "postgres-docker-host-local",
                    "DATABASE_URL uses PostgreSQL host 'postgres'. That hostname normally only works inside Docker Compose; normal local Windows workflow should use sqlite:///./atdr.db unless the PostgreSQL/Docker lab service is running.",
                )
            )
        if not is_production:
            issues.append(
                _issue(
                    "warning",
                    "postgres-local-optional",
                    "PostgreSQL is optional for shared-lab validation. Local teammate workflow does not require Docker/PostgreSQL.",
                )
            )

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

    if settings.assistant_enabled:
        issues.append(
            _issue(
                "critical" if is_production else "warning",
                "assistant-external-enabled",
                "ASSISTANT_ENABLED=true. External assistant provider use must stay disabled until privacy/security review approves it.",
            )
        )
    if settings.assistant_provider.strip().lower() not in {"", "disabled", "none"} or settings.assistant_api_key.strip():
        issues.append(
            _issue(
                "warning",
                "assistant-provider-configured",
                "Assistant provider/key fields are configured. Do not enable external LLM calls by default or commit secrets.",
            )
        )
    if settings.assistant_allow_raw_log_context:
        issues.append(
            _issue(
                "critical" if is_production else "warning",
                "assistant-raw-log-context",
                "ASSISTANT_ALLOW_RAW_LOG_CONTEXT=true. Raw log context must remain disabled until privacy review approves it.",
            )
        )

    if settings.operation_worker_enabled:
        issues.append(
            _issue(
                "info",
                "operation-worker-enabled",
                "OPERATION_WORKER_ENABLED=true. Confirm that a separately managed worker is intended; the API does not start one automatically.",
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

    mfu_config_present = any(
        [
            settings.mfu_iam_base_url.strip(),
            settings.mfu_iam_client_id.strip(),
            settings.mfu_iam_client_secret.strip(),
            settings.mfu_iam_audience.strip(),
            settings.mfu_iam_scope.strip(),
            settings.mfu_iam_allowed_domains.strip(),
            settings.mfu_iam_template_shell_enabled,
            settings.mfu_iam_template_shell_base_url.strip(),
            settings.mfu_iam_handoff_enabled,
            settings.mfu_iam_handoff_shared_secret.strip(),
            settings.mfu_iam_handoff_allowed_origins.strip(),
            settings.mfu_iam_admin_client_id.strip(),
            settings.mfu_iam_admin_client_secret.strip(),
            settings.mfu_iam_permission_source.strip(),
            settings.mfu_iam_managed_client_id.strip(),
            settings.google_sso_enabled,
            settings.google_client_id.strip(),
        ]
    )
    if not settings.mfu_iam_enabled and mfu_config_present:
        issues.append(
            _issue(
                "warning",
                "mfu-iam-config-present-disabled",
                "MFU IAM fields are configured while MFU_IAM_ENABLED=false. The selected authentication profile will not use them.",
            )
        )
    if settings.mfu_iam_enabled and settings.mfu_iam_template_shell_enabled and not mfu_iam_status["handoff_ready"]:
        issues.append(
            _issue(
                "warning",
                "mfu-iam-handoff-not-ready",
                "MFU template-shell mode is enabled but the secure handoff is not ready. Check the private bridge secret, template backend URL, frontend origin, and allowed domains. Do not use browser token handoff as a fallback.",
            )
        )
    if settings.mfu_iam_enabled and not mfu_iam_status["allowed_domains"]:
        issues.append(
            _issue(
                "warning",
                "mfu-iam-missing-allowed-domains",
                "MFU IAM is enabled but no allowed school-email domains are configured. Add MFU_IAM_ALLOWED_DOMAINS such as lamduan.mfu.ac.th after advisor approval.",
            )
        )
    if settings.mfu_iam_enabled and settings.mfu_iam_mock_enabled and is_production:
        issues.append(
            _issue(
                "critical",
                "mfu-iam-mock-production",
                "MFU_IAM_MOCK_ENABLED=true is not allowed in production-like environments.",
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
    info_count = sum(1 for item in issues if item["severity"] == "info")
    return {
        "ok": critical_count == 0,
        "environment": settings.environment,
        "database": database_info["kind"],
        "database_profile": database_runtime,
        "database_host_configured": bool(database_info["host"]),
        "postgres_tools": {
            "psql": bool(shutil.which("psql")),
            "pg_dump": bool(shutil.which("pg_dump")),
            "pg_restore": bool(shutil.which("pg_restore")),
        },
        "local_workflow_recommendation": "Use DATABASE_URL=\"sqlite:///./atdr.db\" for normal local dashboard testing.",
        "response_simulation": settings.response_simulation,
        "response_provider": settings.response_provider,
        "authentication": {
            "mode": settings.normalized_auth_mode,
            "template_shell_required": settings.template_shell_required,
            "local_login_enabled": settings.local_login_enabled,
            "secrets_exposed": False,
        },
        "operation_worker": {
            "enabled": settings.operation_worker_enabled,
            "poll_seconds": settings.operation_worker_poll_seconds,
            "lease_seconds": settings.operation_worker_lease_seconds,
            "heartbeat_seconds": settings.operation_worker_heartbeat_seconds,
            "default_max_attempts": settings.operation_job_default_max_attempts,
            "secrets_exposed": False,
        },
        "mfu_iam": {
            "enabled": mfu_iam_status["enabled"],
            "mode": mfu_iam_status["mode"],
            "b2b_ready": mfu_iam_status["b2b_ready"],
            "template_shell_enabled": mfu_iam_status["template_shell_enabled"],
            "template_shell_ready": mfu_iam_status["template_shell_ready"],
            "template_shell_base_url_configured": mfu_iam_status["template_shell_base_url_configured"],
            "template_shell_me_path": mfu_iam_status["template_shell_me_path"],
            "template_shell_header": mfu_iam_status["template_shell_header"],
            "handoff_enabled": mfu_iam_status["handoff_enabled"],
            "handoff_ready": mfu_iam_status["handoff_ready"],
            "handoff_secret_configured": mfu_iam_status["handoff_secret_configured"],
            "handoff_allowed_origins_configured": mfu_iam_status["handoff_allowed_origins_configured"],
            "admin_api_ready": mfu_iam_status["admin_api_ready"],
            "permission_bootstrap_ready": mfu_iam_status["permission_bootstrap_ready"],
            "mock_enabled": mfu_iam_status["mock_enabled"],
            "google_sso_enabled": mfu_iam_status["google_sso_enabled"],
            "allowed_domains": mfu_iam_status["allowed_domains"],
            "domain_hints": mfu_iam_status["domain_hints"],
            "default_role": mfu_iam_status["default_role"],
            "auth_require_2fa": mfu_iam_status["auth_require_2fa"],
            "secrets_exposed": False,
        },
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
        "info_count": info_count,
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
