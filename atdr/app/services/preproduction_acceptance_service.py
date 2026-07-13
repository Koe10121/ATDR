from __future__ import annotations

import os
from pathlib import Path
import platform
import shutil
import stat
from typing import Callable
from ipaddress import ip_network
from urllib.parse import urlparse

from atdr.app.core.config import Settings, validate_runtime_settings
from atdr.app.db.engine import database_kind, inspect_database_runtime
from atdr.app.services.mfu_iam_service import build_mfu_iam_status
from atdr.app.services.backup_monitoring_service import verify_latest_backup_status


CommandLookup = Callable[[str], str | None]
BackupStatusFunction = Callable[..., dict]
_APPROVED_SECRET_PROVIDERS = {
    "aws_secrets_manager",
    "azure_key_vault",
    "gcp_secret_manager",
    "kubernetes_secret",
    "systemd_credentials",
    "vault",
}


def _configured(value: str) -> bool:
    clean = value.strip().lower()
    return bool(clean and "replace-with" not in clean and not clean.startswith("<"))


def _url_state(value: str, *, require_https: bool) -> tuple[bool, str | None]:
    try:
        parsed = urlparse(value.strip())
    except ValueError:
        return False, None
    scheme_ok = parsed.scheme == "https" if require_https else parsed.scheme in {"http", "https"}
    return bool(scheme_ok and parsed.hostname), parsed.hostname


def _file_state(value: str) -> tuple[bool, Path | None]:
    if not _configured(value):
        return False, None
    path = Path(value).expanduser()
    if not path.is_absolute():
        return False, None
    try:
        resolved = path.resolve()
    except OSError:
        return False, None
    return resolved.is_file(), resolved


def _private_key_permissions_safe(path: Path | None, *, system_name: str) -> bool:
    if path is None or system_name.lower() != "linux":
        return False
    try:
        mode = stat.S_IMODE(path.stat().st_mode)
    except OSError:
        return False
    return mode & 0o077 == 0


def _directory_state(
    value: str,
    *,
    system_name: str,
    allow_group_write: bool,
) -> dict[str, bool]:
    if not _configured(value):
        return {
            "absolute": False,
            "available": False,
            "writable": False,
            "owned_by_operator": False,
            "permissions_safe": False,
        }
    try:
        expanded = Path(value).expanduser()
        absolute = expanded.is_absolute()
        path = expanded.resolve()
        available = path.is_dir()
        writable = available and os.access(path, os.R_OK | os.W_OK | os.X_OK)
        stat_result = path.stat() if available else None
    except OSError:
        return {
            "absolute": False,
            "available": False,
            "writable": False,
            "owned_by_operator": False,
            "permissions_safe": False,
        }
    owner_check_supported = hasattr(os, "geteuid")
    owned_by_operator = bool(
        available
        and (
            not owner_check_supported
            or stat_result is not None
            and stat_result.st_uid == os.geteuid()
        )
    )
    permissions_safe = False
    if available and stat_result is not None and system_name.lower() == "linux":
        mode = stat.S_IMODE(stat_result.st_mode)
        unsafe_write_mask = 0o002 if allow_group_write else 0o022
        permissions_safe = mode & unsafe_write_mask == 0
    return {
        "absolute": absolute,
        "available": available,
        "writable": writable,
        "owned_by_operator": owned_by_operator,
        "permissions_safe": permissions_safe,
    }


def _trusted_proxy_scope_safe(values: list[str]) -> bool:
    if not values:
        return False
    try:
        networks = [ip_network(value, strict=False) for value in values]
    except ValueError:
        return False
    return all(
        network.prefixlen > 0 and (network.is_private or network.is_loopback)
        for network in networks
    )


def _secret_is_deployable(value: str) -> bool:
    clean = value.strip()
    return bool(
        len(clean) >= 32
        and "replace" not in clean.lower()
        and "change-this" not in clean.lower()
        and not clean.startswith("<")
    )


def build_preproduction_acceptance_report(
    settings: Settings,
    *,
    probe_database: bool = False,
    system_name: str | None = None,
    command_lookup: CommandLookup = shutil.which,
    backup_status_function: BackupStatusFunction = verify_latest_backup_status,
) -> dict:
    """Build a secret-safe preproduction readiness report without mutating state."""

    host_system = system_name or platform.system()
    tools = {
        name: bool(command_lookup(name))
        for name in ("nginx", "systemctl", "psql", "pg_dump", "pg_restore")
    }
    public_url_ok, public_hostname = _url_state(settings.deployment_public_base_url, require_https=True)
    prometheus_ok, _ = _url_state(settings.deployment_prometheus_url, require_https=False)
    dns_configured = _configured(settings.deployment_dns_name)
    dns_matches = bool(
        dns_configured
        and public_hostname
        and settings.deployment_dns_name.strip().lower() == public_hostname.lower()
    )
    certificate_exists, _ = _file_state(settings.deployment_tls_certificate_path)
    private_key_exists, private_key_path = _file_state(settings.deployment_tls_private_key_path)
    private_key_safe = _private_key_permissions_safe(private_key_path, system_name=host_system)
    staging = _directory_state(
        settings.operation_staging_root,
        system_name=host_system,
        allow_group_write=True,
    )
    backup = _directory_state(
        settings.backup_directory,
        system_name=host_system,
        allow_group_write=False,
    )
    backup_status = backup_status_function(
        backup_dir=settings.backup_directory,
        max_age_hours=settings.backup_max_age_hours,
    )
    secret_provider = settings.deployment_secret_provider.strip().lower()
    secret_provider_ready = secret_provider in _APPROVED_SECRET_PROVIDERS
    cors_ready = bool(settings.cors_origins) and all(
        origin.startswith("https://") and "*" not in origin for origin in settings.cors_origins
    )
    database_profile = inspect_database_runtime(settings, probe_connection=probe_database)
    iam = build_mfu_iam_status(settings)
    runtime_issues = validate_runtime_settings(settings)
    trusted_proxy_ready = bool(
        settings.trust_proxy_headers
        and _trusted_proxy_scope_safe(settings.trusted_proxy_cidr_list)
    )
    assistant_provider_safe = bool(
        not settings.assistant_allow_raw_log_context
        and (
            not settings.assistant_llm_enabled
            or all(
                _configured(value)
                for value in (
                    settings.assistant_llm_provider,
                    settings.assistant_llm_model,
                    settings.assistant_llm_api_key,
                )
            )
        )
    )

    checks: list[dict[str, object]] = []

    def add(check_id: str, passed: bool, detail: str) -> None:
        rendered_detail = (
            f"Verified: {detail}"
            if passed
            else f"Requirement not met: verify that {detail[0].lower()}{detail[1:]}"
        )
        checks.append(
            {
                "id": check_id,
                "passed": bool(passed),
                "required": True,
                "detail": rendered_detail,
            }
        )

    add("approved_rehearsal", settings.deployment_rehearsal_approved, "Operator approval flag is enabled.")
    add("linux_host", host_system.lower() == "linux", "The rehearsal is running on Linux.")
    add(
        "shared_environment",
        settings.environment.strip().lower() in {"shared_lab", "preproduction"},
        "ENVIRONMENT identifies a shared-lab or preproduction profile, never production.",
    )
    add("postgresql_database", database_kind(settings.database_url) == "postgresql", "PostgreSQL is configured.")
    add("database_at_head", database_profile.get("migration_status") == "at_head", "Database probe is at Alembic head.")
    add("alembic_only", not settings.auto_create_tables, "AUTO_CREATE_TABLES is disabled.")
    add("jwt_secret", _secret_is_deployable(settings.jwt_secret_key), "The JWT signing secret is non-placeholder and deployment length.")
    add("https_public_url", public_url_ok, "A valid HTTPS public base URL is configured.")
    add("dns_matches_url", dns_matches, "The configured DNS name matches the public URL.")
    add("tls_certificate", certificate_exists, "The TLS certificate file is available.")
    add("tls_private_key", private_key_exists, "The TLS private-key file is available.")
    add("tls_private_key_permissions", private_key_safe, "The TLS private key has owner-only permissions.")
    add(
        "trusted_proxy",
        trusted_proxy_ready,
        "Forwarded headers are accepted only from private or loopback trusted peers.",
    )
    add("cors_origins", cors_ready, "CORS uses explicit HTTPS origins without wildcards.")
    add("security_headers", settings.security_headers_enabled, "Application security headers are enabled.")
    add(
        "shared_staging_profile",
        settings.operation_staging_shared
        and staging["absolute"]
        and settings.operation_staging_storage_id.strip().lower() != "local",
        "Shared staging has an absolute root and non-local storage identity.",
    )
    add("shared_staging_access", staging["available"] and staging["writable"], "Shared staging is readable and writable.")
    add(
        "shared_staging_permissions",
        staging["owned_by_operator"] and staging["permissions_safe"],
        "Shared staging is operator-owned and not world-writable.",
    )
    add(
        "backup_directory",
        backup["absolute"] and backup["available"] and backup["writable"],
        "The protected backup directory is absolute, readable, and writable.",
    )
    add(
        "backup_permissions",
        backup["owned_by_operator"] and backup["permissions_safe"],
        "The backup directory is operator-owned without group/world write access.",
    )
    add("backup_freshness", bool(backup_status.get("ok")), "A manifest-backed backup is valid and inside its age budget.")
    add("prometheus", prometheus_ok, "A Prometheus endpoint is configured.")
    add("managed_secrets", secret_provider_ready, "An approved managed-secret provider is selected.")
    add("nginx_available", tools["nginx"], "Nginx is installed on the rehearsal host.")
    add("systemd_available", tools["systemctl"], "systemd is available on the rehearsal host.")
    add("postgres_tools", all(tools[name] for name in ("psql", "pg_dump", "pg_restore")), "PostgreSQL client tools are installed.")
    add(
        "worker_profile",
        settings.operation_worker_enabled
        and settings.operation_worker_concurrency >= 2
        and settings.operation_worker_deployment_id.strip().lower() != "local",
        "The separately managed multi-worker profile is enabled.",
    )
    add("mfu_secure_handoff", bool(iam["handoff_ready"]), "MFU outer-shell one-time-code handoff is ready.")
    add("secure_handoff_cookie", bool(iam["handoff_cookie_secure"]), "The handoff session cookie is Secure.")
    add(
        "response_simulation",
        settings.response_simulation and settings.response_provider.strip().lower() == "simulation",
        "Response simulation remains enabled with the simulation provider.",
    )
    add("assistant_raw_logs_disabled", not settings.assistant_allow_raw_log_context, "External raw-log context remains disabled.")
    add("assistant_provider_safety", assistant_provider_safe, "Any enabled assistant provider has private configuration and no raw-log context.")
    add("runtime_configuration", not runtime_issues, "Runtime configuration has no safety issues.")

    missing = [str(check["id"]) for check in checks if check["required"] and not check["passed"]]
    operator_guidance = {
        "approved_rehearsal": "Obtain written approval for the named preproduction host and set the private approval flag.",
        "linux_host": "Provision an approved Linux host; this Windows workstation cannot supply host evidence.",
        "shared_environment": "Set ENVIRONMENT=preproduction (or shared_lab for an approved shared lab) in private deployment configuration.",
        "postgresql_database": "Provide a private PostgreSQL DATABASE_URL and run migrations on the approved target.",
        "database_at_head": "Run the explicit read-only database probe after PostgreSQL and Alembic are available.",
        "alembic_only": "Set AUTO_CREATE_TABLES=false and manage the approved database only through Alembic migrations.",
        "https_public_url": "Obtain the approved HTTPS base URL and configure it privately.",
        "dns_matches_url": "Create or confirm the approved DNS record and matching public URL.",
        "tls_certificate": "Install the approved certificate outside Git.",
        "tls_private_key": "Install the matching private key outside Git.",
        "tls_private_key_permissions": "Restrict the deployed private key to its service owner (for example mode 0600).",
        "trusted_proxy": "Set TRUSTED_PROXY_CIDRS to only the private or loopback addresses used by the approved reverse proxy.",
        "cors_origins": "Set CORS_ALLOWED_ORIGINS to the exact approved HTTPS frontend origins without wildcards.",
        "security_headers": "Enable SECURITY_HEADERS_ENABLED in the private deployment profile.",
        "shared_staging_profile": "Enable shared staging with an absolute mount path and a non-local OPERATION_STAGING_STORAGE_ID.",
        "shared_staging_access": "Create the shared staging mount with the API/worker service ownership and permissions.",
        "shared_staging_permissions": "Remove world-write permission and run the check as the staging service owner.",
        "backup_directory": "Create a protected backup directory writable by the backup operator only.",
        "backup_permissions": "Restrict backup-directory write permission to its operator account.",
        "backup_freshness": "Create an approved backup, manifest, and checksum, then run the read-only freshness verifier.",
        "jwt_secret": "Provide a managed, randomly generated JWT secret of at least 32 characters.",
        "prometheus": "Provide the internal Prometheus URL and approved alert destination.",
        "managed_secrets": "Choose and configure an approved managed-secret provider.",
        "nginx_available": "Install and validate Nginx on the approved host.",
        "systemd_available": "Use an approved Linux service manager and install the reviewed unit files.",
        "postgres_tools": "Install version-compatible psql, pg_dump, and pg_restore tools.",
        "worker_profile": "Enable separately managed workers only after PostgreSQL/shared staging are ready.",
        "mfu_secure_handoff": "Configure the private bridge secret and approved origins in both the MFU shell and ATDR.",
        "secure_handoff_cookie": "Require Secure cookies for the HTTPS deployment.",
        "response_simulation": "Set RESPONSE_SIMULATION=true and RESPONSE_PROVIDER=simulation; do not configure real enforcement.",
        "assistant_raw_logs_disabled": "Set ASSISTANT_ALLOW_RAW_LOG_CONTEXT=false in the private deployment profile.",
        "assistant_provider_safety": "Keep the assistant disabled or configure its provider privately while raw-log context remains disabled.",
        "runtime_configuration": "Run the configuration doctor and resolve every reported safety issue before rehearsal.",
    }
    actions = [operator_guidance[item] for item in missing if item in operator_guidance]
    accepted = not missing
    return {
        "ok": True,
        "status": "operational_acceptance_passed" if accepted else "preproduction_requirements_incomplete",
        "accepted": accepted,
        "approved_host_evidence": accepted,
        "probe_database": probe_database,
        "database_probe_status": database_profile.get("connection_status"),
        "database_migration_status": database_profile.get("migration_status"),
        "host_profile": {
            "system": host_system,
            "approved": settings.deployment_rehearsal_approved,
            "tools": tools,
        },
        "resource_availability": {
            "postgresql_configured": database_kind(settings.database_url) == "postgresql",
            "dns_configured": dns_configured,
            "https_public_url_configured": public_url_ok,
            "tls_certificate_available": certificate_exists,
            "tls_private_key_available": private_key_exists,
            "shared_staging_available": staging["available"],
            "shared_staging_writable": staging["writable"],
            "shared_staging_permissions_safe": staging["permissions_safe"],
            "backup_directory_available": backup["available"],
            "backup_directory_permissions_safe": backup["permissions_safe"],
            "backup_fresh": bool(backup_status.get("ok")),
            "prometheus_configured": prometheus_ok,
            "managed_secret_provider_configured": secret_provider_ready,
            "mfu_secure_handoff_ready": bool(iam["handoff_ready"]),
        },
        "external_provider_state": {
            "mfu_iam_enabled": settings.mfu_iam_enabled,
            "mfu_handoff_ready": bool(iam["handoff_ready"]),
            "assistant_llm_enabled": settings.assistant_llm_enabled,
            "assistant_raw_log_context": settings.assistant_allow_raw_log_context,
        },
        "checks": checks,
        "missing_requirement_ids": missing,
        "operator_actions": actions,
        "runtime_issue_count": len(runtime_issues),
        "database_connection_probe_performed": probe_database,
        "external_network_calls_made": bool(
            probe_database and database_kind(settings.database_url) == "postgresql"
        ),
        "filesystem_writes_performed": False,
        "current_database_modified": False,
        "response_automation_allowed": False,
        "real_firewall_blocking_enabled": False,
        "model_activation_performed": False,
        "secrets_exposed": False,
        "production_ready": False,
    }
