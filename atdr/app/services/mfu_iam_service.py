from __future__ import annotations

from typing import Any

from atdr.app.core.config import Settings


def _configured(value: str | None) -> bool:
    return bool((value or "").strip())


def _normalize_domains(domains: list[str]) -> list[str]:
    normalized: list[str] = []
    for domain in domains:
        clean = domain.strip().lower()
        if clean and clean not in normalized:
            normalized.append(clean)
    return normalized


def build_mfu_iam_status(settings: Settings) -> dict[str, Any]:
    """Build a non-secret MFU IAM status payload.

    The supervisor template has two related integration surfaces: a B2B IAM SDK
    and Google/MFU Mail user login. This payload intentionally exposes only
    booleans and policy hints so Admin / Settings can show readiness without
    leaking client secrets or copied template env values.
    """

    allowed_domains = _normalize_domains(settings.mfu_iam_allowed_domain_list)
    domain_hints = _normalize_domains(settings.mfu_iam_domain_hints)
    permission_paths = settings.mfu_iam_permission_path_list
    admin_client_configured = _configured(settings.mfu_iam_admin_client_id)
    admin_secret_configured = _configured(settings.mfu_iam_admin_client_secret)
    client_secret_configured = _configured(settings.mfu_iam_client_secret)
    b2b_ready = all(
        [
            _configured(settings.mfu_iam_base_url),
            _configured(settings.mfu_iam_client_id),
            client_secret_configured,
            _configured(settings.mfu_iam_audience),
            _configured(settings.mfu_iam_token_path),
            _configured(settings.mfu_iam_introspect_path),
            _configured(settings.mfu_iam_profile_path),
        ]
    )
    admin_ready = all(
        [
            admin_client_configured,
            admin_secret_configured,
            _configured(settings.mfu_iam_admin_audience),
            _configured(settings.mfu_iam_admin_scope),
            _configured(settings.mfu_iam_admin_base_path),
        ]
    )
    permission_ready = bool(
        settings.mfu_iam_permission_source.strip().lower() == "iam"
        and permission_paths
        and _configured(settings.mfu_iam_permission_root_path)
    )

    return {
        "enabled": settings.mfu_iam_enabled,
        "base_url_configured": _configured(settings.mfu_iam_base_url),
        "client_id_configured": _configured(settings.mfu_iam_client_id),
        "client_secret_configured": client_secret_configured,
        "audience_configured": _configured(settings.mfu_iam_audience),
        "scope_configured": _configured(settings.mfu_iam_scope),
        "timeout_ms": settings.mfu_iam_timeout_ms,
        "token_path_configured": _configured(settings.mfu_iam_token_path),
        "introspect_path_configured": _configured(settings.mfu_iam_introspect_path),
        "profile_path_configured": _configured(settings.mfu_iam_profile_path),
        "admin_base_path_configured": _configured(settings.mfu_iam_admin_base_path),
        "admin_client_configured": admin_client_configured,
        "admin_secret_configured": admin_secret_configured,
        "admin_audience_configured": _configured(settings.mfu_iam_admin_audience),
        "admin_scope_configured": _configured(settings.mfu_iam_admin_scope),
        "compat_profile_configured": _configured(settings.mfu_iam_compat_profile),
        "allowed_domains": allowed_domains,
        "domain_hints": domain_hints,
        "default_role": settings.mfu_iam_default_role,
        "google_sso_enabled": settings.google_sso_enabled,
        "google_client_id_configured": _configured(settings.google_client_id),
        "permission_source": settings.mfu_iam_permission_source.strip() or None,
        "permission_bootstrap_mode": settings.mfu_iam_permission_bootstrap_mode.strip() or None,
        "permission_root_configured": _configured(settings.mfu_iam_permission_root_path),
        "permission_paths_count": len(permission_paths),
        "project_account_email_configured": _configured(settings.mfu_iam_project_account_email),
        "auth_require_2fa": settings.mfu_iam_auth_require_2fa,
        "audit_retention_days": settings.mfu_iam_audit_retention_days,
        "managed_client_configured": _configured(settings.mfu_iam_managed_client_id),
        "managed_client_endpoint_configured": _configured(settings.mfu_iam_managed_client_endpoint),
        "managed_client_owner_configured": _configured(settings.mfu_iam_managed_client_owner_email),
        "managed_client_scopes_configured": _configured(settings.mfu_iam_managed_client_allowed_scopes),
        "managed_client_audiences_configured": _configured(settings.mfu_iam_managed_client_allowed_audiences),
        "init_admin_emails_configured": bool(settings.mfu_iam_init_admin_email_list),
        "seed_admin_email_configured": _configured(settings.mfu_iam_init_seed_admin_email),
        "b2b_ready": b2b_ready,
        "admin_api_ready": admin_ready,
        "permission_bootstrap_ready": permission_ready,
        "mode": "mfu_iam_configured" if settings.mfu_iam_enabled else "local_login_only",
        "secrets_exposed": False,
    }
