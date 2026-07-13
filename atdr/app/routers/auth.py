import time
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from atdr.app.core.config import get_settings
from atdr.app.core.security import create_access_token, get_current_user, require_admin, require_analyst_or_admin
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
    OidcStatusRead,
    TokenResponse,
    UserRead,
)
from atdr.app.services.account_verification_service import request_email_verification, verify_email_code
from atdr.app.services.email_service import get_email_delivery_status
from atdr.app.services.mfu_iam_service import (
    MfuIamAuthenticationError,
    authenticate_mfu_iam_handoff_code,
    audit_mfu_iam_login,
    build_mfu_iam_public_status,
    build_mfu_iam_status,
    get_mfu_iam_last_safe_validation,
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


def _safe_handoff_return_path(value: object, settings) -> str:
    default_path = "/overview"
    clean = str(value or "").strip()
    if not clean or not clean.startswith("/") or clean.startswith("//") or "://" in clean:
        return default_path
    path = clean.split("?", 1)[0].split("#", 1)[0]
    allowed = set(settings.mfu_iam_handoff_allowed_return_path_list)
    return path if path in allowed else default_path


def _handoff_redirect_url(settings, *, return_path: str, error: str | None = None) -> str:
    base = settings.mfu_iam_handoff_frontend_url.rstrip("/")
    target = f"{base}{return_path}"
    if error:
        target = f"{base}/login?{urlencode({'handoff_error': error})}"
    return target


def _validate_template_handoff_origin(request: Request, settings) -> bool:
    origin = (request.headers.get("origin") or "").strip().rstrip("/")
    return bool(origin and origin in set(settings.mfu_iam_handoff_allowed_origin_list))


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


@router.post("/mfu-iam/handoff/consume", include_in_schema=False)
async def consume_mfu_iam_template_handoff(request: Request, db: Session = Depends(get_db)) -> Response:
    """Consume a template-generated one-time code and establish an HttpOnly ATDR session.

    This route intentionally accepts a browser form POST. The code is never
    included in the redirect URL, and the template bearer token is never
    submitted to ATDR by the browser.
    """

    settings = get_settings()
    return_path = _safe_handoff_return_path(request.query_params.get("return_to"), settings)
    if not settings.mfu_iam_handoff_enabled:
        return RedirectResponse(
            _handoff_redirect_url(settings, return_path=return_path, error="handoff_not_configured"),
            status_code=status.HTTP_303_SEE_OTHER,
        )
    if not _validate_template_handoff_origin(request, settings):
        audit_mfu_iam_login(
            db,
            actor="anonymous",
            success=False,
            reason="handoff_origin_not_allowed",
            client_ip=request.client.host if request.client else None,
        )
        return RedirectResponse(
            _handoff_redirect_url(settings, return_path=return_path, error="handoff_origin_not_allowed"),
            status_code=status.HTTP_303_SEE_OTHER,
        )

    form = await request.form()
    handoff_code = str(form.get("handoff_code") or "").strip()
    return_path = _safe_handoff_return_path(form.get("return_to") or return_path, settings)
    client_ip = request.client.host if request.client else None
    try:
        identity = authenticate_mfu_iam_handoff_code(handoff_code, settings)
        user = upsert_mfu_iam_user(db, identity)
    except MfuIamAuthenticationError as exc:
        audit_mfu_iam_login(
            db,
            actor="anonymous",
            success=False,
            reason="template_handoff_rejected",
            client_ip=client_ip,
        )
        return RedirectResponse(
            _handoff_redirect_url(settings, return_path=return_path, error="handoff_rejected"),
            status_code=status.HTTP_303_SEE_OTHER,
        )

    audit_mfu_iam_login(
        db,
        actor=user.username,
        success=True,
        reason="template_handoff_validated",
        client_ip=client_ip,
        email_domain=(user.email or "").rsplit("@", 1)[-1].lower() if user.email and "@" in user.email else None,
    )
    response = RedirectResponse(
        _handoff_redirect_url(settings, return_path=return_path),
        status_code=status.HTTP_303_SEE_OTHER,
    )
    response.set_cookie(
        key=settings.mfu_iam_handoff_cookie_name,
        value=create_access_token(subject=user.username, role=user.role),
        max_age=settings.access_token_expire_minutes * 60,
        httponly=True,
        secure=settings.mfu_iam_handoff_cookie_secure,
        samesite="lax",
        path="/",
    )
    return response


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(response: Response, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)) -> Response:
    settings = get_settings()
    db.add(
        AuditLog(
            actor=current_user.username,
            action="logout",
            target_type="auth",
            target_value=current_user.username,
            details={"provider": current_user.auth_provider, "secrets_exposed": False},
        )
    )
    db.commit()
    response.delete_cookie(key=settings.mfu_iam_handoff_cookie_name, path="/")
    response.status_code = status.HTTP_204_NO_CONTENT
    return response


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
def mfu_iam_status(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
) -> dict:
    del current_user
    settings = get_settings()
    return build_mfu_iam_status(settings, last_safe_validation=get_mfu_iam_last_safe_validation(db))


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
