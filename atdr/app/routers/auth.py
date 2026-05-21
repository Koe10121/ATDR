import time

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from atdr.app.core.config import get_settings
from atdr.app.core.security import create_access_token, get_current_user
from atdr.app.db.database import get_db
from atdr.app.db.models import AuditLog, User
from atdr.app.schemas.auth import ChangePasswordRequest, LoginRequest, TokenResponse, UserRead
from atdr.app.services.user_service import authenticate_user, change_own_password

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
    settings = get_settings()
    token = create_access_token(subject=user.username, role=user.role)
    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in_minutes": settings.access_token_expire_minutes,
        "username": user.username,
        "role": user.role,
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
