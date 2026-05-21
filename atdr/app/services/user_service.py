from sqlalchemy import select
from sqlalchemy.orm import Session

from atdr.app.core.config import get_settings
from atdr.app.core.security import hash_password, verify_password
from atdr.app.db.models import AuditLog, User


def get_user_by_username(db: Session, username: str) -> User | None:
    return db.scalar(select(User).where(User.username == username))


def create_user(
    db: Session,
    *,
    username: str,
    password: str,
    role: str = "analyst",
    full_name: str | None = None,
    is_active: bool = True,
) -> User:
    user = User(
        username=username,
        full_name=full_name,
        role=role,
        password_hash=hash_password(password),
        is_active=is_active,
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
    password: str,
    role: str,
    full_name: str | None,
    actor: str,
) -> User:
    if get_user_by_username(db, username) is not None:
        raise ValueError(f"User already exists: {username}")
    user = create_user(db, username=username, password=password, role=role, full_name=full_name)
    db.add(
        AuditLog(
            actor=actor,
            action="user_created",
            target_type="user",
            target_value=username,
            details={"role": role, "full_name": full_name},
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
    user = get_user_by_username(db, username)
    if user is None or not user.is_active:
        return None
    if not verify_password(password, user.password_hash):
        return None
    return user


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
