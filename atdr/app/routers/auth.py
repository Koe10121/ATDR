import time

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from atdr.app.core.config import get_settings
from atdr.app.core.security import create_access_token, get_current_user, require_analyst_or_admin
from atdr.app.db.database import get_db
from atdr.app.db.models import AuditLog, User
from atdr.app.schemas.account_email import (
    EmailVerificationRequestRead,
    EmailVerificationStatusRead,
    EmailVerificationVerifyRequest,
    EmailVerificationVerifyResponse,
)
from atdr.app.schemas.auth import (
    ChangePasswordRequest,
    LoginRequest,
    MfuIamPublicStatusRead,
    MfuIamStatusRead,
    MfuIamTokenLoginRequest,
    MfuIamTokenLoginResponse,
    OidcStatusRead,
    TokenResponse,
    UserRead,
)
from atdr.app.services.account_verification_service import request_email_verification, verify_email_code
from atdr.app.services.email_service import get_email_delivery_status
from atdr.app.services.mfu_iam_service import (
    MfuIamAuthenticationError,
    audit_mfu_iam_login,
    authenticate_mfu_iam_token,
    build_mfu_iam_public_status,
    build_mfu_iam_status,
    upsert_mfu_iam_user,
)
from atdr.app.services.user_service import authenticate_user, change_own_password, record_successful_login

router = APIRouter(prefix="/api/auth", tags=["auth"])
_login_failures: dict[str, list[float]] = {}


def _rate_key(request: Request, username: str) -> str:
    client = request.client.host if request.client else "unknown"
    return f"{client}:{username.lower()}"


def _check_rate_limit(request: Request, username: str) -> None:
    settings = get_settings()
    key = _rate_key(request, username)
    now = time.monotonic()
    window_start = now - settings.login_rate_limit_window_seconds
    attempts = [item for item in _login_failures.get(key, []) if item >= window_start]
    _login_failures[key] = attempts
    if len(attempts) >= settings.login_rate_limit_attempts:
        raise HTTPException(status_code=429, detail="Too many failed login attempts. Try again later.")


def _record_failed_login(db: Session, request: Request, username: str, reason: str) -> None:
    key = _rate_key(request, username)
    _login_failures.setdefault(key, []).append(time.monotonic())
    db.add(
        AuditLog(
            actor=username or "anonymous",
            action="login_failed",
            target_type="user",
            target_value=username or "unknown",
            details={"reason": reason, "client_ip": request.client.host if request.client else None},
        )
    )
    db.commit()


def _clear_failed_logins(request: Request, username: str) -> None:
    _login_failures.pop(_rate_key(request, username), None)


def _split_allowed_domains(value: str) -> list[str]:
    return [domain.strip().lower() for domain in value.split(",") if domain.strip()]


@router.post("/login", response_model=TokenResponse)
def login(payload: LoginRequest, request: Request, db: Session = Depends(get_db)) -> dict:
    _check_rate_limit(request, payload.username)
    user = authenticate_user(db, payload.username, payload.password)
    if user is None:
        _record_failed_login(db, request, payload.username, "bad_credentials")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    _clear_failed_logins(request, payload.username)
    record_successful_login(db, user)
    settings = get_settings()
    token = create_access_token(subject=user.username, role=user.role)
    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in_minutes": settings.access_token_expire_minutes,
        "username": user.username,
        "role": user.role,
    }


@router.get("/mfu-iam/public-status", response_model=MfuIamPublicStatusRead)
def mfu_iam_public_status() -> dict:
    settings = get_settings()
    return build_mfu_iam_public_status(settings)


@router.post("/mfu-iam/token-login", response_model=MfuIamTokenLoginResponse)
def mfu_iam_token_login(
    payload: MfuIamTokenLoginRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> dict:
    _check_rate_limit(request, "mfu-iam-token-login")
    settings = get_settings()
    client_ip = request.client.host if request.client else None
    try:
        identity = authenticate_mfu_iam_token(payload.token, settings)
        user = upsert_mfu_iam_user(db, identity)
    except MfuIamAuthenticationError as exc:
        audit_mfu_iam_login(
            db,
            actor="anonymous",
            success=False,
            reason=str(exc),
            client_ip=client_ip,
        )
        _login_failures.setdefault(_rate_key(request, "mfu-iam-token-login"), []).append(time.monotonic())
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="MFU IAM login failed.") from exc

    _clear_failed_logins(request, "mfu-iam-token-login")
    audit_mfu_iam_login(
        db,
        actor=user.username,
        success=True,
        reason="validated_external_token",
        client_ip=client_ip,
        email_domain=(user.email or "").rsplit("@", 1)[-1].lower() if user.email and "@" in user.email else None,
    )
    token = create_access_token(subject=user.username, role=user.role)
    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in_minutes": settings.access_token_expire_minutes,
        "username": user.username,
        "role": user.role,
        "email": user.email,
        "auth_provider": user.auth_provider,
        "external_login": True,
    }


@router.get("/me", response_model=UserRead)
def me(current_user: User = Depends(get_current_user)) -> User:
    return current_user


@router.post("/change-password")
def change_password(
    request: ChangePasswordRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict:
    try:
        change_own_password(
            db,
            current_user,
            current_password=request.current_password,
            new_password=request.new_password,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"changed": True}


@router.get("/oidc/status", response_model=OidcStatusRead)
def oidc_status(current_user: User = Depends(require_analyst_or_admin)) -> dict:
    del current_user
    settings = get_settings()
    return {
        "enabled": settings.oidc_enabled,
        "provider_name": settings.oidc_provider_name.strip() or None,
        "issuer_configured": bool(settings.oidc_issuer_url.strip()),
        "client_configured": bool(settings.oidc_client_id.strip()),
        "allowed_domains": _split_allowed_domains(settings.oidc_allowed_domains),
        "default_role": settings.oidc_default_role,
        "mode": "external_oidc" if settings.oidc_enabled else "local_login_only",
        "school_email_domains": settings.school_email_domain_list,
        "require_school_email": settings.require_school_email,
        "local_email_login_enabled": settings.local_email_login_enabled,
        "smtp_enabled": settings.smtp_enabled,
    }


@router.get("/mfu-iam/status", response_model=MfuIamStatusRead)
def mfu_iam_status(current_user: User = Depends(require_analyst_or_admin)) -> dict:
    del current_user
    settings = get_settings()
    return build_mfu_iam_status(settings)


@router.get("/email/status", response_model=EmailVerificationStatusRead)
def email_status(current_user: User = Depends(require_analyst_or_admin)) -> dict:
    del current_user
    return get_email_delivery_status()


@router.post("/email/request-verification", response_model=EmailVerificationRequestRead)
def request_own_email_verification(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> EmailVerificationRequestRead:
    result = request_email_verification(db, user=current_user, actor=current_user.username)
    return EmailVerificationRequestRead(**result.__dict__)


@router.post("/email/verify", response_model=EmailVerificationVerifyResponse)
def verify_own_email(
    request: EmailVerificationVerifyRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> EmailVerificationVerifyResponse:
    result = verify_email_code(db, user=current_user, code=request.code, actor=current_user.username)
    return EmailVerificationVerifyResponse(**result.__dict__)
