from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urljoin

import requests
from sqlalchemy.orm import Session

from atdr.app.core.config import Settings
from atdr.app.db.models import AuditLog, User
from atdr.app.services.user_service import create_user, get_user_by_email, get_user_by_username, record_successful_login


class MfuIamAuthenticationError(ValueError):
    """Raised when the external MFU IAM login attempt is not acceptable."""


@dataclass(frozen=True)
class MfuIamIdentity:
    email: str
    subject: str
    full_name: str | None
    provider: str
    role: str
    details: dict[str, Any]


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
    template_shell_ready = all(
        [
            settings.mfu_iam_template_shell_enabled,
            _configured(settings.mfu_iam_template_shell_base_url),
            _configured(settings.mfu_iam_template_shell_me_path),
            _configured(settings.mfu_iam_template_shell_header),
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
        "mock_enabled": settings.mfu_iam_mock_enabled,
        "template_shell_enabled": settings.mfu_iam_template_shell_enabled,
        "template_shell_base_url_configured": _configured(settings.mfu_iam_template_shell_base_url),
        "template_shell_me_path": settings.mfu_iam_template_shell_me_path,
        "template_shell_header": settings.mfu_iam_template_shell_header,
        "template_shell_ready": template_shell_ready,
        "admin_email_mapping_configured": bool(settings.mfu_iam_admin_email_list),
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
        "token_login_ready": bool(settings.mfu_iam_enabled and (b2b_ready or settings.mfu_iam_mock_enabled or template_shell_ready)),
        "admin_api_ready": admin_ready,
        "permission_bootstrap_ready": permission_ready,
        "mode": _mfu_iam_mode(settings, b2b_ready=b2b_ready, template_shell_ready=template_shell_ready),
        "secrets_exposed": False,
    }


def build_mfu_iam_public_status(settings: Settings) -> dict[str, Any]:
    """Return a minimal non-secret status payload safe for the login page."""

    status = build_mfu_iam_status(settings)
    return {
        "enabled": status["enabled"],
        "token_login_ready": status["token_login_ready"],
        "b2b_ready": status["b2b_ready"],
        "mock_enabled": status["mock_enabled"],
        "template_shell_enabled": status["template_shell_enabled"],
        "template_shell_ready": status["template_shell_ready"],
        "google_sso_enabled": status["google_sso_enabled"],
        "google_client_id_configured": status["google_client_id_configured"],
        "allowed_domains": status["allowed_domains"],
        "domain_hints": status["domain_hints"],
        "default_role": status["default_role"],
        "auth_require_2fa": status["auth_require_2fa"],
        "mode": status["mode"],
        "secrets_exposed": False,
    }


def authenticate_mfu_iam_token(token: str, settings: Settings) -> MfuIamIdentity:
    """Validate a provided external token and return a normalized identity.

    The real MFU IAM path is intentionally behind MFU_IAM_ENABLED. Tests and
    local dry runs can use MFU_IAM_MOCK_ENABLED with a token formatted as
    ``mock:user@lamduan.mfu.ac.th``. No provider secret is returned or logged.
    """

    clean_token = token.strip()
    if not settings.mfu_iam_enabled:
        raise MfuIamAuthenticationError("MFU IAM login is disabled.")
    if not clean_token:
        raise MfuIamAuthenticationError("MFU IAM token is required.")
    if settings.mfu_iam_mock_enabled:
        return _mock_identity_from_token(clean_token, settings)
    if settings.mfu_iam_template_shell_enabled:
        return _template_shell_identity_from_token(clean_token, settings)
    if not build_mfu_iam_status(settings)["b2b_ready"]:
        raise MfuIamAuthenticationError("MFU IAM token login is not fully configured.")

    introspection = _introspect_token(clean_token, settings)
    if not _is_active_introspection(introspection):
        raise MfuIamAuthenticationError("MFU IAM token is inactive or invalid.")
    _validate_audience(introspection, settings)
    profile = _fetch_profile(clean_token, settings)
    return _identity_from_payloads(introspection, profile, settings)


def upsert_mfu_iam_user(db: Session, identity: MfuIamIdentity) -> User:
    """Create or update a local ATDR user for a verified MFU IAM identity."""

    existing = get_user_by_email(db, identity.email) or get_user_by_username(db, identity.email)
    if existing is not None:
        if not existing.is_active:
            raise MfuIamAuthenticationError("Matched ATDR account is disabled.")
        changed = False
        if existing.email is None:
            existing.email = identity.email
            changed = True
        if not existing.email_verified:
            existing.email_verified = True
            changed = True
        if not existing.external_subject:
            existing.external_subject = identity.subject
            changed = True
        if changed:
            db.add(existing)
            db.commit()
            db.refresh(existing)
        record_successful_login(db, existing)
        return existing

    user = create_user(
        db,
        username=identity.email,
        password=None,
        role=identity.role,
        full_name=identity.full_name,
        email=identity.email,
        email_verified=True,
        auth_provider="external",
        external_subject=identity.subject,
    )
    db.add(
        AuditLog(
            actor=identity.email,
            action="mfu_iam_user_created",
            target_type="user",
            target_value=user.username,
            details={"role": user.role, "provider": identity.provider, "email_domain": _domain_of(identity.email)},
        )
    )
    db.commit()
    db.refresh(user)
    record_successful_login(db, user)
    return user


def audit_mfu_iam_login(
    db: Session,
    *,
    actor: str,
    success: bool,
    reason: str,
    client_ip: str | None,
    email_domain: str | None = None,
) -> None:
    db.add(
        AuditLog(
            actor=actor or "anonymous",
            action="mfu_iam_login_success" if success else "mfu_iam_login_failed",
            target_type="auth",
            target_value=email_domain or "school_email",
            details={
                "reason": reason,
                "client_ip": client_ip,
                "email_domain": email_domain,
                "secrets_exposed": False,
            },
        )
    )
    db.commit()


def _mock_identity_from_token(token: str, settings: Settings) -> MfuIamIdentity:
    if not token.lower().startswith("mock:"):
        raise MfuIamAuthenticationError("MFU IAM mock token must start with 'mock:'.")
    email = token.split(":", 1)[1].strip().lower()
    if not email or "@" not in email:
        raise MfuIamAuthenticationError("MFU IAM mock token must include an email address.")
    return _identity_from_email(email, subject=f"mock:{email}", full_name="MFU IAM Test User", provider="mfu_iam_mock", settings=settings)


def _mfu_iam_mode(settings: Settings, *, b2b_ready: bool, template_shell_ready: bool) -> str:
    if not settings.mfu_iam_enabled:
        return "local_login_only"
    if settings.mfu_iam_mock_enabled:
        return "mfu_iam_mock"
    if template_shell_ready:
        return "template_shell_session_handoff"
    if b2b_ready:
        return "mfu_iam_b2b_token"
    return "mfu_iam_incomplete"


def _template_shell_identity_from_token(token: str, settings: Settings) -> MfuIamIdentity:
    if not settings.mfu_iam_template_shell_base_url.strip():
        raise MfuIamAuthenticationError("Template shell base URL is not configured.")
    url = _join_url(settings.mfu_iam_template_shell_base_url, settings.mfu_iam_template_shell_me_path)
    header_name = settings.mfu_iam_template_shell_header.strip() or "x-access-token"
    try:
        response = requests.get(
            url,
            headers={header_name: token},
            timeout=max(1.0, min(settings.mfu_iam_timeout_ms / 1000, 60.0)),
        )
    except requests.RequestException as exc:
        raise MfuIamAuthenticationError("Template shell session validation failed.") from exc
    if response.status_code >= 400:
        raise MfuIamAuthenticationError("Template shell session is invalid.")
    data = response.json()
    if not isinstance(data, dict):
        raise MfuIamAuthenticationError("Template shell returned an invalid profile payload.")
    payload = _extract_template_shell_profile(data)
    email = _first_text(
        payload,
        "email",
        "authen.0.email",
        "authen.0.username",
        "username",
        "account.email",
        "data.email",
    )
    if not email or "@" not in email:
        raise MfuIamAuthenticationError("Template shell profile did not include an email address.")
    subject = _first_text(payload, "_id", "id", "account_id", "data._id") or email
    full_name = _template_full_name(payload)
    return _identity_from_email(
        email.lower(),
        subject=f"template-shell:{subject}",
        full_name=full_name,
        provider="template_shell",
        settings=settings,
    )


def _extract_template_shell_profile(data: dict[str, Any]) -> dict[str, Any]:
    raw_profile = data.get("data") if isinstance(data.get("data"), dict) else data
    flattened = _flatten_candidates(raw_profile)
    if isinstance(raw_profile.get("authen"), list):
        for index, item in enumerate(raw_profile["authen"]):
            if isinstance(item, dict):
                for key, value in item.items():
                    flattened[f"authen.{index}.{key}"] = value
    return flattened


def _template_full_name(payload: dict[str, Any]) -> str | None:
    explicit = _first_text(payload, "name", "full_name", "display_name")
    if explicit:
        return explicit
    first_name = _lang_value(payload.get("userinfo.firstName"))
    last_name = _lang_value(payload.get("userinfo.lastName"))
    full_name = " ".join(part for part in [first_name, last_name] if part).strip()
    return full_name or None


def _lang_value(value: Any) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    if isinstance(value, list):
        for item in value:
            if isinstance(item, dict) and isinstance(item.get("value"), str) and item["value"].strip():
                return item["value"].strip()
    return None


def _identity_from_payloads(
    introspection: dict[str, Any],
    profile: dict[str, Any],
    settings: Settings,
) -> MfuIamIdentity:
    merged = _flatten_candidates(profile) | _flatten_candidates(introspection)
    email = _first_text(
        merged,
        "email",
        "mail",
        "preferred_username",
        "username",
        "user_email",
        "account_email",
    )
    if email and "@" not in email:
        email = _first_text(merged, "mail", "email", "account.email")
    subject = _first_text(merged, "sub", "subject", "id", "account_id", "client_id") or email or "mfu-iam-user"
    full_name = _first_text(merged, "name", "full_name", "display_name")
    if not email or "@" not in email:
        raise MfuIamAuthenticationError("MFU IAM profile did not include an email address.")
    return _identity_from_email(email.lower(), subject=subject, full_name=full_name, provider="mfu_iam", settings=settings)


def _identity_from_email(
    email: str,
    *,
    subject: str,
    full_name: str | None,
    provider: str,
    settings: Settings,
) -> MfuIamIdentity:
    domain = _domain_of(email)
    allowed = settings.mfu_iam_allowed_domain_list
    if not allowed:
        raise MfuIamAuthenticationError("MFU IAM allowed domains are not configured.")
    if domain not in allowed:
        raise MfuIamAuthenticationError("MFU IAM email domain is not allowed.")
    role = "admin" if email in settings.mfu_iam_admin_email_list else "analyst"
    if role != "admin" and settings.mfu_iam_default_role == "analyst":
        role = "analyst"
    return MfuIamIdentity(
        email=email,
        subject=subject,
        full_name=full_name,
        provider=provider,
        role=role,
        details={"email_domain": domain, "role_source": "explicit_admin_mapping" if role == "admin" else "default_analyst"},
    )


def _introspect_token(token: str, settings: Settings) -> dict[str, Any]:
    url = _join_url(settings.mfu_iam_base_url, settings.mfu_iam_introspect_path)
    response = requests.post(
        url,
        json={"token": token},
        timeout=max(1.0, min(settings.mfu_iam_timeout_ms / 1000, 60.0)),
    )
    if response.status_code >= 400:
        raise MfuIamAuthenticationError("MFU IAM token introspection failed.")
    data = response.json()
    if not isinstance(data, dict):
        raise MfuIamAuthenticationError("MFU IAM token introspection returned an invalid payload.")
    return data


def _fetch_profile(token: str, settings: Settings) -> dict[str, Any]:
    url = _join_url(settings.mfu_iam_base_url, settings.mfu_iam_profile_path)
    response = requests.get(
        url,
        headers={"Authorization": f"Bearer {token}"},
        timeout=max(1.0, min(settings.mfu_iam_timeout_ms / 1000, 60.0)),
    )
    if response.status_code >= 400:
        return {}
    data = response.json()
    return data if isinstance(data, dict) else {}


def _join_url(base_url: str, path: str) -> str:
    return urljoin(f"{base_url.rstrip('/')}/", path.lstrip("/"))


def _is_active_introspection(payload: dict[str, Any]) -> bool:
    active = payload.get("active", payload.get("is_active", True))
    if isinstance(active, str):
        return active.strip().lower() in {"true", "1", "yes", "active"}
    return bool(active)


def _validate_audience(payload: dict[str, Any], settings: Settings) -> None:
    expected = settings.mfu_iam_audience.strip()
    if not expected:
        return
    audience = payload.get("aud") or payload.get("audience")
    if audience is None:
        return
    if isinstance(audience, str) and audience == expected:
        return
    if isinstance(audience, list) and expected in [str(item) for item in audience]:
        return
    raise MfuIamAuthenticationError("MFU IAM token audience is not accepted.")


def _flatten_candidates(payload: dict[str, Any]) -> dict[str, Any]:
    candidates: dict[str, Any] = {}

    def walk(prefix: str, value: Any) -> None:
        if isinstance(value, dict):
            for key, nested in value.items():
                child_key = f"{prefix}.{key}" if prefix else str(key)
                walk(child_key, nested)
        else:
            candidates[prefix] = value

    walk("", payload)
    for key, value in payload.items():
        candidates.setdefault(str(key), value)
    return candidates


def _first_text(payload: dict[str, Any], *keys: str) -> str | None:
    for key in keys:
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _domain_of(email: str) -> str:
    return email.rsplit("@", 1)[-1].lower() if "@" in email else ""
