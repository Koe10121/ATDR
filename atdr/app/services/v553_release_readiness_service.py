from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any

from atdr.app.core.config import PROJECT_ROOT, Settings, validate_runtime_settings
from atdr.app.services.assistant_service import assistant_status
from atdr.app.services.mfu_iam_service import build_mfu_iam_status
from atdr.app.services.preproduction_acceptance_service import (
    build_preproduction_acceptance_report,
)


_EVIDENCE_CONTRACTS: dict[str, dict[str, Any]] = {
    "mfu_iam": {
        "filename": "mfu-iam-acceptance.json",
        "checks": (
            "provider_login",
            "approved_origins",
            "issuer_audience",
            "school_domain",
            "group_role_mapping",
            "session_expiry",
            "logout",
            "two_factor",
            "recovery",
            "deprovisioning",
        ),
    },
    "deployment": {
        "filename": "shared-deployment-acceptance.json",
        "checks": (
            "approved_linux_host",
            "postgresql",
            "multiworker",
            "shared_storage",
            "https_tls",
            "managed_secrets",
            "monitoring_alerts",
            "backup_restore",
            "rpo_rto",
            "rollback",
            "disaster_recovery",
            "load_test",
        ),
    },
    "assistant_provider": {
        "filename": "assistant-provider-governance.json",
        "checks": (
            "institutional_privacy",
            "retention_policy",
            "quota_owner",
            "billing_owner",
            "key_rotation",
            "monitoring_alerts",
            "representative_evaluation",
        ),
    },
    "team_runtime": {
        "filename": "team-runtime-acceptance.json",
        "checks": (
            "clean_clone",
            "approved_shell_package",
            "private_configuration",
            "setup",
            "shell_login_entry",
            "secure_handoff",
            "health_check",
            "shutdown",
            "database_preserved",
            "private_data_excluded",
        ),
    },
}

_SENSITIVE_MANIFEST_KEYS = {
    "access_token",
    "api_key",
    "client_secret",
    "password",
    "private_key",
    "refresh_token",
    "secret",
    "token",
}

_DEPLOYMENT_SOURCE_FILES = (
    "deploy/nginx/atdr.conf.example",
    "deploy/monitoring/prometheus.yml.example",
    "deploy/monitoring/atdr-alerts.yml",
    "deploy/systemd/atdr-api.service.example",
    "deploy/systemd/atdr-worker@.service.example",
    "deploy/systemd/atdr-backup-verify.timer.example",
    "deploy/secrets/README.md",
    "atdr/scripts/validate_deployment_operations.py",
    "atdr/scripts/run_disaster_recovery_drill.py",
)

_TEAM_SOURCE_FILES = (
    "config/mfu-shell-contract.json",
    "scripts/setup_team.cmd",
    "scripts/setup_team.ps1",
    "scripts/start_system.cmd",
    "scripts/start_system.ps1",
    "scripts/check_system.cmd",
    "scripts/check_system.ps1",
    "scripts/stop_system.cmd",
    "scripts/stop_system.ps1",
)

_SECURITY_SOURCE_FILES = (
    ".github/workflows/ci.yml",
    ".github/workflows/codeql.yml",
    "atdr/scripts/run_v553_security_acceptance.py",
)


def _safe_manifest_result(*, status: str, configured: bool, present: bool) -> dict[str, Any]:
    return {
        "status": status,
        "configured": configured,
        "present": present,
        "valid": False,
        "expired": False,
        "checks_passed": 0,
        "checks_total": 0,
        "missing_checks": [],
        "secrets_exposed": False,
    }


def _contains_sensitive_key(value: Any) -> bool:
    if isinstance(value, dict):
        for key, item in value.items():
            if str(key).strip().lower() in _SENSITIVE_MANIFEST_KEYS:
                return True
            if _contains_sensitive_key(item):
                return True
    elif isinstance(value, list):
        return any(_contains_sensitive_key(item) for item in value)
    return False


def _parse_timestamp(value: object) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def _external_acceptance_state(evidence: dict[str, Any]) -> str:
    if evidence.get("valid") is True:
        return "externally_accepted"
    status = str(evidence.get("status") or "")
    if status in {"evidence_root_not_configured", "evidence_missing"}:
        return "externally_pending"
    if status == "evidence_root_unavailable":
        return "unavailable"
    return "failed"


def _aggregate_external_state(states: list[str]) -> str:
    if states and all(state == "externally_accepted" for state in states):
        return "externally_accepted"
    if "failed" in states:
        return "failed"
    if "unavailable" in states:
        return "unavailable"
    return "externally_pending"


def validate_acceptance_manifest(
    settings: Settings,
    evidence_type: str,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Validate a private operator manifest without returning its contents or path."""

    contract = _EVIDENCE_CONTRACTS[evidence_type]
    root_value = settings.acceptance_evidence_root.strip()
    if not root_value:
        result = _safe_manifest_result(
            status="evidence_root_not_configured",
            configured=False,
            present=False,
        )
        result["checks_total"] = len(contract["checks"])
        result["missing_checks"] = list(contract["checks"])
        return result

    root = Path(root_value).expanduser()
    if not root.is_absolute():
        result = _safe_manifest_result(
            status="evidence_root_not_absolute",
            configured=True,
            present=False,
        )
        result["checks_total"] = len(contract["checks"])
        result["missing_checks"] = list(contract["checks"])
        return result
    try:
        resolved_root = root.resolve(strict=True)
    except OSError:
        result = _safe_manifest_result(
            status="evidence_root_unavailable",
            configured=True,
            present=False,
        )
        result["checks_total"] = len(contract["checks"])
        result["missing_checks"] = list(contract["checks"])
        return result
    if not resolved_root.is_dir():
        result = _safe_manifest_result(
            status="evidence_root_unavailable",
            configured=True,
            present=False,
        )
        result["checks_total"] = len(contract["checks"])
        result["missing_checks"] = list(contract["checks"])
        return result

    path = resolved_root / str(contract["filename"])
    if not path.is_file() or path.is_symlink():
        result = _safe_manifest_result(
            status="evidence_missing",
            configured=True,
            present=False,
        )
        result["checks_total"] = len(contract["checks"])
        result["missing_checks"] = list(contract["checks"])
        return result
    try:
        if path.stat().st_size > 65_536:
            raise ValueError("manifest too large")
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
        result = _safe_manifest_result(
            status="evidence_invalid",
            configured=True,
            present=True,
        )
        result["checks_total"] = len(contract["checks"])
        result["missing_checks"] = list(contract["checks"])
        return result
    if not isinstance(payload, dict) or _contains_sensitive_key(payload):
        result = _safe_manifest_result(
            status="evidence_unsafe",
            configured=True,
            present=True,
        )
        result["checks_total"] = len(contract["checks"])
        result["missing_checks"] = list(contract["checks"])
        return result

    required_checks = tuple(contract["checks"])
    supplied_checks = payload.get("checks")
    checks = supplied_checks if isinstance(supplied_checks, dict) else {}
    missing = [name for name in required_checks if checks.get(name) is not True]
    recorded_at = _parse_timestamp(payload.get("recorded_at"))
    expires_at = _parse_timestamp(payload.get("expires_at"))
    current_time = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    expired = bool(expires_at and expires_at <= current_time)
    metadata_valid = bool(
        payload.get("schema_version") == 1
        and payload.get("evidence_type") == evidence_type
        and payload.get("environment") == settings.environment.strip().lower()
        and payload.get("template_only") is False
        and recorded_at
        and recorded_at <= current_time
        and expires_at
        and expires_at > recorded_at
        and not expired
        and 2 <= len(str(payload.get("approved_by_role") or "").strip()) <= 80
    )
    valid = metadata_valid and not missing
    return {
        "status": "accepted_evidence_valid" if valid else "evidence_expired" if expired else "evidence_incomplete",
        "configured": True,
        "present": True,
        "valid": valid,
        "expired": expired,
        "checks_passed": len(required_checks) - len(missing),
        "checks_total": len(required_checks),
        "missing_checks": missing,
        "secrets_exposed": False,
    }


def build_v553_evidence_templates(environment: str) -> dict[str, dict[str, Any]]:
    """Return false-by-default templates that cannot be mistaken for acceptance."""

    normalized_environment = environment.strip().lower() or "preproduction"
    return {
        str(contract["filename"]): {
            "schema_version": 1,
            "evidence_type": evidence_type,
            "environment": normalized_environment,
            "template_only": True,
            "recorded_at": "",
            "expires_at": "",
            "approved_by_role": "",
            "checks": {name: False for name in contract["checks"]},
        }
        for evidence_type, contract in _EVIDENCE_CONTRACTS.items()
    }


def _source_checks(root: Path, paths: tuple[str, ...]) -> dict[str, Any]:
    missing = [path for path in paths if not (root / path).is_file()]
    return {
        "ready": not missing,
        "required_file_count": len(paths),
        "missing_file_count": len(missing),
        "missing_files": missing,
    }


def _check_map(items: dict[str, bool]) -> dict[str, Any]:
    failed = [name for name, passed in items.items() if not passed]
    return {
        "ready": not failed,
        "checks_passed": len(items) - len(failed),
        "checks_total": len(items),
        "failed_checks": failed,
    }


def build_v553_release_readiness_report(
    settings: Settings,
    *,
    project_root: Path = PROJECT_ROOT,
    probe_database: bool = False,
    preproduction_report: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Aggregate local controls and external evidence without mutating state."""

    iam_status = build_mfu_iam_status(settings)
    runtime_issues = validate_runtime_settings(settings)
    shared_profile = settings.environment.strip().lower() in {"shared_lab", "preproduction", "production"}
    iam_local = _check_map(
        {
            "template_shell_required": settings.template_shell_required,
            "local_login_disabled": not settings.local_login_enabled,
            "iam_enabled": settings.mfu_iam_enabled,
            "secure_handoff_ready": bool(iam_status["handoff_ready"]),
            "school_domain_configured": bool(iam_status["allowed_domains"]),
            "default_role_analyst": settings.mfu_iam_default_role == "analyst",
            "mock_disabled": not settings.mfu_iam_mock_enabled,
            "secure_cookie_for_shared_profile": not shared_profile or settings.mfu_iam_handoff_cookie_secure,
            "runtime_configuration_valid": not runtime_issues,
        }
    )
    iam_evidence = validate_acceptance_manifest(settings, "mfu_iam")

    deployment_sources = _source_checks(project_root, _DEPLOYMENT_SOURCE_FILES)
    deployment_local = _check_map(
        {
            "reference_assets": deployment_sources["ready"],
            "response_simulation": settings.response_simulation and settings.response_provider.strip().lower() == "simulation",
            "security_headers": settings.security_headers_enabled,
            "explicit_cors_origins": bool(settings.cors_origins) and "*" not in settings.cors_origins,
            "explicit_cors_methods": bool(settings.cors_methods) and "*" not in settings.cors_methods,
            "explicit_cors_headers": bool(settings.cors_headers) and "*" not in settings.cors_headers,
            "raw_log_context_disabled": not settings.assistant_allow_raw_log_context,
        }
    )
    host_report = preproduction_report or build_preproduction_acceptance_report(
        settings,
        probe_database=probe_database,
    )
    host_checks = {
        str(item.get("id")): bool(item.get("passed"))
        for item in host_report.get("checks", [])
        if isinstance(item, dict) and item.get("id")
    }
    host_resources = host_report.get("resource_availability", {})
    if not isinstance(host_resources, dict):
        host_resources = {}
    deployment_evidence = validate_acceptance_manifest(settings, "deployment")

    assistant = assistant_status(settings)
    assistant_local = _check_map(
        {
            "assistant_available": bool(assistant["available"]),
            "deterministic_fallback": assistant["external_provider_used_by_default"] is False,
            "ip_redaction": bool(assistant["redaction_enabled"]),
            "raw_log_context_disabled": not assistant["raw_log_context_allowed"],
            "secrets_hidden": not assistant["llm_secrets_exposed"],
            "bounded_prompt": int(assistant["llm_max_prompt_chars"]) <= 50_000,
            "bounded_output": int(assistant["llm_max_output_tokens"]) <= 4_096,
            "circuit_breaker": int(assistant["llm_circuit_breaker_failures"]) > 0,
        }
    )
    assistant_evidence = validate_acceptance_manifest(settings, "assistant_provider")

    team_sources = _source_checks(project_root, _TEAM_SOURCE_FILES)
    team_local = _check_map(
        {
            "one_command_setup": team_sources["ready"],
            "one_command_start": (project_root / "scripts/start_system.cmd").is_file(),
            "health_check": (project_root / "scripts/check_system.cmd").is_file(),
            "one_command_shutdown": (project_root / "scripts/stop_system.cmd").is_file(),
            "approved_shell_contract": (project_root / "config/mfu-shell-contract.json").is_file(),
        }
    )
    team_evidence = validate_acceptance_manifest(settings, "team_runtime")

    security_sources = _source_checks(project_root, _SECURITY_SOURCE_FILES)
    ci_text = ""
    try:
        ci_text = (project_root / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    except OSError:
        pass
    security_local = _check_map(
        {
            "repository_secret_scan": "run_v553_security_acceptance" in ci_text,
            "backend_dependency_audit": "pip_audit" in ci_text or "pip-audit" in ci_text,
            "frontend_dependency_audit": "npm audit" in ci_text,
            "sbom_generation": "cyclonedx" in ci_text.lower() or "sbom" in ci_text.lower(),
            "codeql_workflow": (project_root / ".github/workflows/codeql.yml").is_file(),
            "security_headers": settings.security_headers_enabled,
            "least_privilege_cors": "*" not in settings.cors_origins + settings.cors_methods + settings.cors_headers,
            "security_sources": security_sources["ready"],
        }
    )

    local_sections = {
        "iam": iam_local,
        "deployment": deployment_local,
        "assistant": assistant_local,
        "team_runtime": team_local,
        "security": security_local,
    }
    local_ready = all(section["ready"] for section in local_sections.values())
    external_evidence = {
        "iam": iam_evidence,
        "deployment": deployment_evidence,
        "assistant_provider": assistant_evidence,
        "team_runtime": team_evidence,
    }
    for evidence in external_evidence.values():
        evidence["acceptance_state"] = _external_acceptance_state(evidence)
    external_evidence_complete = all(item["valid"] for item in external_evidence.values())
    approved_host_ready = bool(host_report.get("accepted"))
    shared_lab_ready = local_ready and external_evidence_complete and approved_host_ready
    external_state = _aggregate_external_state(
        [str(item["acceptance_state"]) for item in external_evidence.values()]
    )
    host_state = "externally_accepted" if approved_host_ready else "externally_pending"
    shared_lab_state = (
        "externally_accepted"
        if shared_lab_ready
        else "failed"
        if not local_ready or external_state == "failed"
        else "unavailable"
        if external_state == "unavailable"
        else "externally_pending"
    )
    status = (
        "shared_lab_acceptance_complete"
        if shared_lab_ready
        else "local_controls_ready_external_evidence_required"
        if local_ready
        else "local_controls_incomplete"
    )
    return {
        "phase": "v5.53",
        "status": status,
        "local_controls_ready": local_ready,
        "external_evidence_complete": external_evidence_complete,
        "approved_host_ready": approved_host_ready,
        "shared_lab_ready": shared_lab_ready,
        "production_ready": False,
        "readiness_states": {
            "local_controls": "locally_verified" if local_ready else "failed",
            "external_evidence": external_state,
            "approved_host": host_state,
            "shared_lab": shared_lab_state,
        },
        "sections": {
            "iam": {
                **iam_local,
                "mode": iam_status["mode"],
                "admin_group_mapping_configured": bool(iam_status["admin_group_mapping_configured"]),
                "external_evidence": iam_evidence,
            },
            "deployment": {
                **deployment_local,
                "current_host_status": host_report.get("status"),
                "current_host_accepted": approved_host_ready,
                "missing_host_requirement_count": len(host_report.get("missing_requirement_ids", [])),
                "database_profile": (
                    "shared PostgreSQL"
                    if host_resources.get("postgresql_configured")
                    else "local SQLite"
                ),
                "database_migration_ready": bool(host_checks.get("database_at_head")),
                "workers_ready": bool(host_checks.get("worker_profile")),
                "backup_ready": bool(
                    host_checks.get("backup_directory")
                    and host_checks.get("backup_permissions")
                    and host_checks.get("backup_freshness")
                ),
                "monitoring_ready": bool(host_checks.get("prometheus")),
                "https_ready": bool(
                    host_checks.get("https_public_url")
                    and host_checks.get("tls_certificate")
                    and host_checks.get("tls_private_key")
                    and host_checks.get("tls_private_key_permissions")
                ),
                "managed_secrets_ready": bool(host_checks.get("managed_secrets")),
                "recovery_evidence_ready": bool(deployment_evidence["valid"]),
                "external_evidence": deployment_evidence,
            },
            "assistant": {
                **assistant_local,
                "provider_configured": bool(assistant["llm_ready"]),
                "provider_name": assistant["llm_provider_name"] if assistant["llm_ready"] else "disabled",
                "provider_health": assistant["llm_operational"].get("status", "idle"),
                "external_evidence": assistant_evidence,
            },
            "team_runtime": {
                **team_local,
                "external_evidence": team_evidence,
            },
            "security": security_local,
        },
        "remaining_external_actions": [
            name
            for name, passed in (
                ("MFU provider lifecycle acceptance", iam_evidence["valid"]),
                ("approved shared-host deployment rehearsal", approved_host_ready and deployment_evidence["valid"]),
                ("Gemini institutional governance", assistant_evidence["valid"]),
                ("physical teammate clean-clone exercise", team_evidence["valid"]),
            )
            if not passed
        ],
        "runtime_issue_count": len(runtime_issues),
        "database_probe_performed": probe_database,
        "filesystem_writes_performed": False,
        "current_database_modified": False,
        "model_activation_performed": False,
        "response_automation_allowed": False,
        "real_firewall_blocking_enabled": False,
        "raw_log_context_allowed": bool(settings.assistant_allow_raw_log_context),
        "secrets_exposed": False,
    }
