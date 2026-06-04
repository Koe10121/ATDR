from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from atdr.app.core.config import get_settings
from atdr.app.core.security import hash_password, verify_password
from atdr.app.db.models import AuditLog, User


def get_user_by_username(db: Session, username: str) -> User | None:
    return db.scalar(select(User).where(User.username == username))


def _normalize_email(email: str | None) -> str | None:
    if email is None:
        return None
    clean = email.strip().lower()
    return clean or None


def get_user_by_email(db: Session, email: str | None) -> User | None:
    clean = _normalize_email(email)
    if clean is None:
        return None
    return db.scalar(select(User).where(User.email == clean))


def get_user_by_login_identifier(db: Session, identifier: str) -> User | None:
    user = get_user_by_username(db, identifier)
    if user is not None:
        return user
    settings = get_settings()
    if settings.local_email_login_enabled and "@" in identifier:
        return get_user_by_email(db, identifier)
    return None


def _validate_school_email(email: str | None) -> None:
    settings = get_settings()
    if not settings.require_school_email or email is None:
        return
    domain = email.rsplit("@", 1)[-1].lower()
    allowed = set(settings.school_email_domain_list)
    if domain not in allowed:
        allowed_text = ", ".join(sorted(allowed)) or "configured school domains"
        raise ValueError(f"Email domain must be one of: {allowed_text}.")


def _provider_password_hash(auth_provider: str, password: str | None) -> str:
    if auth_provider == "local":
        if not password:
            raise ValueError("Password is required for local users.")
        return hash_password(password)
    return hash_password("__external_account_no_local_password__")


def create_user(
    db: Session,
    *,
    username: str,
    password: str | None,
    role: str = "analyst",
    full_name: str | None = None,
    email: str | None = None,
    email_verified: bool = False,
    auth_provider: str = "local",
    external_subject: str | None = None,
    is_active: bool = True,
) -> User:
    clean_email = _normalize_email(email)
    _validate_school_email(clean_email)
    user = User(
        username=username,
        email=clean_email,
        full_name=full_name,
        role=role,
        password_hash=_provider_password_hash(auth_provider, password),
        is_active=is_active,
        email_verified=email_verified,
        auth_provider=auth_provider,
        external_subject=external_subject,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def list_users(db: Session) -> list[User]:
    return list(db.scalars(select(User).order_by(User.username.asc())))


def create_managed_user(
    db: Session,
    *,
    username: str,
    password: str | None,
    role: str,
    full_name: str | None,
    email: str | None = None,
    email_verified: bool = False,
    auth_provider: str = "local",
    is_active: bool = True,
    actor: str,
) -> User:
    if get_user_by_username(db, username) is not None:
        raise ValueError(f"User already exists: {username}")
    clean_email = _normalize_email(email)
    if clean_email and get_user_by_email(db, clean_email) is not None:
        raise ValueError(f"Email already exists: {clean_email}")
    user = create_user(
        db,
        username=username,
        password=password,
        role=role,
        full_name=full_name,
        email=clean_email,
        email_verified=email_verified,
        auth_provider=auth_provider,
        is_active=is_active,
    )
    db.add(
        AuditLog(
            actor=actor,
            action="user_created",
            target_type="user",
            target_value=username,
            details={
                "role": role,
                "full_name": full_name,
                "email": clean_email,
                "email_verified": email_verified,
                "auth_provider": auth_provider,
                "is_active": is_active,
            },
        )
    )
    db.commit()
    db.refresh(user)
    return user


def disable_user(db: Session, user_id: int, *, actor: str) -> User | None:
    user = db.get(User, user_id)
    if user is None:
        return None
    if user.username == actor:
        raise ValueError("Admins cannot disable their own account.")
    user.is_active = False
    user.disabled_at = datetime.now(timezone.utc)
    db.add(
        AuditLog(
            actor=actor,
            action="user_disabled",
            target_type="user",
            target_value=user.username,
            details={"user_id": user.id, "role": user.role},
        )
    )
    db.commit()
    db.refresh(user)
    return user


def update_managed_user(
    db: Session,
    user_id: int,
    *,
    actor: str,
    username: str | None = None,
    full_name: str | None = None,
    email: str | None = None,
    role: str | None = None,
    is_active: bool | None = None,
    email_verified: bool | None = None,
    auth_provider: str | None = None,
) -> User | None:
    user = db.get(User, user_id)
    if user is None:
        return None
    changes: dict[str, object] = {}
    if username is not None and username != user.username:
        if get_user_by_username(db, username) is not None:
            raise ValueError(f"User already exists: {username}")
        changes["username"] = {"old": user.username, "new": username}
        user.username = username
    if email is not None:
        clean_email = _normalize_email(email)
        _validate_school_email(clean_email)
        existing = get_user_by_email(db, clean_email)
        if existing is not None and existing.id != user.id:
            raise ValueError(f"Email already exists: {clean_email}")
        if clean_email != user.email:
            changes["email"] = {"old": user.email, "new": clean_email}
            user.email = clean_email
    if full_name is not None and full_name != user.full_name:
        changes["full_name"] = {"old": user.full_name, "new": full_name}
        user.full_name = full_name
    if role is not None and role != user.role:
        changes["role"] = {"old": user.role, "new": role}
        user.role = role
    if is_active is not None and is_active != user.is_active:
        if not is_active and user.username == actor:
            raise ValueError("Admins cannot disable their own account.")
        changes["is_active"] = {"old": user.is_active, "new": is_active}
        user.is_active = is_active
        user.disabled_at = None if is_active else datetime.now(timezone.utc)
    if email_verified is not None and email_verified != user.email_verified:
        changes["email_verified"] = {"old": user.email_verified, "new": email_verified}
        user.email_verified = email_verified
    if auth_provider is not None and auth_provider != user.auth_provider:
        if auth_provider == "external" and user.username == actor:
            raise ValueError("Admins cannot convert their own account to external-only.")
        changes["auth_provider"] = {"old": user.auth_provider, "new": auth_provider}
        user.auth_provider = auth_provider
    if changes:
        db.add(
            AuditLog(
                actor=actor,
                action="user_updated",
                target_type="user",
                target_value=user.username,
                details={"user_id": user.id, "changes": changes},
            )
        )
        db.commit()
        db.refresh(user)
    return user


def reset_user_password(db: Session, user_id: int, *, new_password: str, actor: str) -> User | None:
    user = db.get(User, user_id)
    if user is None:
        return None
    user.password_hash = hash_password(new_password)
    db.add(
        AuditLog(
            actor=actor,
            action="user_password_reset",
            target_type="user",
            target_value=user.username,
            details={"user_id": user.id},
        )
    )
    db.commit()
    db.refresh(user)
    return user


def change_user_role(db: Session, user_id: int, *, role: str, actor: str) -> User | None:
    user = db.get(User, user_id)
    if user is None:
        return None
    old_role = user.role
    user.role = role
    db.add(
        AuditLog(
            actor=actor,
            action="user_role_changed",
            target_type="user",
            target_value=user.username,
            details={"user_id": user.id, "old_role": old_role, "new_role": role},
        )
    )
    db.commit()
    db.refresh(user)
    return user


def change_own_password(db: Session, user: User, *, current_password: str, new_password: str) -> None:
    db_user = db.get(User, user.id)
    if db_user is None or not verify_password(current_password, db_user.password_hash):
        raise ValueError("Current password is incorrect.")
    db_user.password_hash = hash_password(new_password)
    db.add(
        AuditLog(
            actor=user.username,
            action="password_changed",
            target_type="user",
            target_value=user.username,
            details={"user_id": user.id},
        )
    )
    db.commit()


def authenticate_user(db: Session, username: str, password: str) -> User | None:
    user = get_user_by_login_identifier(db, username)
    if user is None or not user.is_active or user.auth_provider != "local":
        return None
    if not verify_password(password, user.password_hash):
        return None
    return user


def record_successful_login(db: Session, user: User) -> None:
    db_user = db.get(User, user.id)
    if db_user is None:
        return
    db_user.last_login_at = datetime.now(timezone.utc)
    db.commit()


def ensure_demo_users(db: Session) -> dict[str, str]:
    settings = get_settings()
    created: dict[str, str] = {}
    demo_users = [
        (
            settings.demo_admin_username,
            settings.demo_admin_password,
            "admin",
            "Demo Administrator",
        ),
        (
            settings.demo_analyst_username,
            settings.demo_analyst_password,
            "analyst",
            "Demo Analyst",
        ),
    ]
    for username, password, role, full_name in demo_users:
        if get_user_by_username(db, username) is None:
            create_user(db, username=username, password=password, role=role, full_name=full_name)
            created[username] = role
    return created
