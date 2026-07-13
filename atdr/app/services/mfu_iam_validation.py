from __future__ import annotations

import base64
from typing import Any

import requests

from atdr.app.core.config import Settings, get_settings, validate_runtime_settings
from atdr.app.services.mfu_iam_service import (
    MfuIamAuthenticationError,
    authenticate_mfu_iam_token,
    build_mfu_iam_status,
)


def _timeout_seconds(settings: Settings) -> float:
    return max(1.0, min(settings.mfu_iam_timeout_ms / 1000, 60.0))


def _join_url(base_url: str, path: str) -> str:
    return f"{base_url.rstrip('/')}/{path.lstrip('/')}"


def _basic_auth_header(client_id: str, client_secret: str) -> str:
    raw = f"{client_id}:{client_secret}".encode("utf-8")
    return "Basic " + base64.b64encode(raw).decode("ascii")


def _safe_error(exc: Exception) -> dict[str, str]:
    return {
        "error_type": exc.__class__.__name__,
        "message": "MFU IAM validation probe failed. Check provider availability, credentials, audience, and paths.",
    }


def _configured_checks(status: dict[str, Any]) -> dict[str, bool]:
    return {
        "enabled": bool(status["enabled"]),
        "base_url": bool(status["base_url_configured"]),
        "client_id": bool(status["client_id_configured"]),
        "client_secret": bool(status["client_secret_configured"]),
        "audience": bool(status["audience_configured"]),
        "token_path": bool(status["token_path_configured"]),
        "introspect_path": bool(status["introspect_path_configured"]),
        "profile_path": bool(status["profile_path_configured"]),
        "template_shell": bool(status["template_shell_ready"]),
        "template_shell_base_url": bool(status["template_shell_base_url_configured"]),
        "handoff": bool(status["handoff_ready"]),
        "handoff_shared_secret": bool(status["handoff_secret_configured"]),
        "handoff_origins": bool(status["handoff_allowed_origins_configured"]),
        "allowed_domains": bool(status["allowed_domains"]),
    }


def build_mfu_iam_validation_report(
    *,
    execute: bool = False,
    token: str | None = None,
    settings: Settings | None = None,
) -> dict[str, Any]:
    """Return a non-secret MFU IAM validation report.

    By default this performs no network calls. With ``execute=True`` it performs
    either a mock-token validation, an explicit token introspection/profile
    validation, or a client-credentials bootstrap probe. Access tokens and
    secrets are never returned.
    """

    runtime_settings = settings or get_settings()
    status = build_mfu_iam_status(runtime_settings)
    runtime_issues = validate_runtime_settings(runtime_settings)
    report: dict[str, Any] = {
        "ok": True,
        "executed_provider_call": False,
        "execute_requested": execute,
        "mode": status["mode"],
        "enabled": status["enabled"],
        "mock_enabled": status["mock_enabled"],
        "template_shell_enabled": status["template_shell_enabled"],
        "template_shell_ready": status["template_shell_ready"],
        "handoff_enabled": status["handoff_enabled"],
        "handoff_ready": status["handoff_ready"],
        "b2b_ready": status["b2b_ready"],
        "admin_api_ready": status["admin_api_ready"],
        "permission_bootstrap_ready": status["permission_bootstrap_ready"],
        "configured_checks": _configured_checks(status),
        "allowed_domains": status["allowed_domains"],
        "domain_hints": status["domain_hints"],
        "default_role": status["default_role"],
        "auth_require_2fa": status["auth_require_2fa"],
        "audit_retention_days": status["audit_retention_days"],
        "google_sso_enabled": status["google_sso_enabled"],
        "google_client_id_configured": status["google_client_id_configured"],
        "secrets_exposed": False,
        "runtime_issues": runtime_issues,
        "provider_result": None,
        "message": "MFU IAM configuration status checked without a provider call.",
    }

    if runtime_issues:
        report["ok"] = False
        report["message"] = "Runtime configuration has safety issues; no provider call was made."
        return report

    if not execute:
        return report

    if not runtime_settings.mfu_iam_enabled:
        report["ok"] = False
        report["message"] = "MFU_IAM_ENABLED is false; no provider call was made."
        return report

    try:
        if runtime_settings.mfu_iam_mock_enabled:
            mock_token = token or _default_mock_token(runtime_settings)
            identity = authenticate_mfu_iam_token(mock_token, runtime_settings)
            report["executed_provider_call"] = True
            report["provider_result"] = {
                "mode": "mock",
                "identity_validated": True,
                "email_domain": identity.details.get("email_domain"),
                "role": identity.role,
                "secrets_exposed": False,
            }
            report["message"] = "MFU IAM mock validation completed."
            return report

        if runtime_settings.mfu_iam_template_shell_enabled:
            report["ok"] = bool(status["handoff_ready"])
            report["message"] = (
                "Secure template-shell handoff is configured. No browser session token is accepted by this tool; "
                "run atdr.scripts.validate_template_shell_runtime --check-runtime to validate the two service endpoints."
                if report["ok"]
                else "Template-shell mode is enabled but the secure one-time-code handoff is incomplete. "
                "Configure the private bridge secret and approved origin in both services before enabling it."
            )
            return report

        probe_token = token or _fetch_client_credentials_token(runtime_settings)
        introspection = _introspect_token(probe_token, runtime_settings)
        profile = _fetch_profile(probe_token, runtime_settings)
        report["executed_provider_call"] = True
        report["provider_result"] = {
            "mode": "live",
            "token_acquired": token is None,
            "introspection_active": _is_active(introspection),
            "audience_accepted": _audience_matches(introspection, runtime_settings),
            "profile_available": bool(profile),
            "profile_email_present": _profile_has_email(profile),
            "secrets_exposed": False,
        }
        report["ok"] = bool(
            report["provider_result"]["introspection_active"] and report["provider_result"]["audience_accepted"]
        )
        report["message"] = "MFU IAM live validation probe completed." if report["ok"] else "MFU IAM live validation probe returned non-ready status."
        return report
    except (requests.RequestException, MfuIamAuthenticationError, ValueError) as exc:
        report["ok"] = False
        report["executed_provider_call"] = True
        report["provider_result"] = _safe_error(exc)
        return report


def _default_mock_token(settings: Settings) -> str:
    email = settings.mfu_iam_init_seed_admin_email or settings.mfu_iam_project_account_email
    if not email:
        domains = settings.mfu_iam_allowed_domain_list
        domain = domains[0] if domains else "lamduan.mfu.ac.th"
        email = f"analyst@{domain}"
    return f"mock:{email}"


def _fetch_client_credentials_token(settings: Settings) -> str:
    url = _join_url(settings.mfu_iam_base_url, settings.mfu_iam_token_path)
    response = requests.post(
        url,
        headers={
            "Authorization": _basic_auth_header(settings.mfu_iam_client_id, settings.mfu_iam_client_secret),
            "Content-Type": "application/json",
        },
        json={
            "grant_type": "client_credentials",
            "client_id": settings.mfu_iam_client_id,
            "client_secret": settings.mfu_iam_client_secret,
            "scope": settings.mfu_iam_scope or None,
            "audience": settings.mfu_iam_audience or None,
        },
        timeout=_timeout_seconds(settings),
    )
    response.raise_for_status()
    payload = response.json()
    if not isinstance(payload, dict) or not payload.get("access_token"):
        raise ValueError("MFU IAM token endpoint did not return an access token.")
    return str(payload["access_token"])


def _introspect_token(token: str, settings: Settings) -> dict[str, Any]:
    response = requests.post(
        _join_url(settings.mfu_iam_base_url, settings.mfu_iam_introspect_path),
        headers={"Content-Type": "application/json"},
        json={"token": token},
        timeout=_timeout_seconds(settings),
    )
    response.raise_for_status()
    payload = response.json()
    if not isinstance(payload, dict):
        raise ValueError("MFU IAM introspection endpoint returned an invalid payload.")
    return payload


def _fetch_profile(token: str, settings: Settings) -> dict[str, Any]:
    response = requests.get(
        _join_url(settings.mfu_iam_base_url, settings.mfu_iam_profile_path),
        headers={"Authorization": f"Bearer {token}"},
        timeout=_timeout_seconds(settings),
    )
    if response.status_code >= 400:
        return {}
    payload = response.json()
    return payload if isinstance(payload, dict) else {}


def _is_active(payload: dict[str, Any]) -> bool:
    active = payload.get("active", payload.get("is_active", False))
    if isinstance(active, str):
        return active.strip().lower() in {"true", "1", "yes", "active"}
    return bool(active)


def _audience_matches(payload: dict[str, Any], settings: Settings) -> bool:
    expected = settings.mfu_iam_audience.strip()
    if not expected:
        return True
    audience = payload.get("aud") or payload.get("audience")
    if audience is None:
        return True
    if isinstance(audience, str):
        return audience == expected
    if isinstance(audience, list):
        return expected in {str(item) for item in audience}
    return False


def _profile_has_email(payload: dict[str, Any]) -> bool:
    def walk(value: Any) -> bool:
        if isinstance(value, dict):
            return any(walk(item) for item in value.values())
        if isinstance(value, list):
            return any(walk(item) for item in value)
        return isinstance(value, str) and "@" in value

    return walk(payload)
