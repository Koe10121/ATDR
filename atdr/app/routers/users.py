from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from atdr.app.core.security import require_admin
from atdr.app.db.database import get_db
from atdr.app.db.models import User
from atdr.app.schemas.users import UserCreateRequest, UserRead, UserResetPasswordRequest, UserRoleRequest
from atdr.app.services.user_service import (
    change_user_role,
    create_managed_user,
    disable_user,
    list_users,
    reset_user_password,
)

router = APIRouter(prefix="/api/users", tags=["users"])


@router.get("", response_model=list[UserRead])
def api_list_users(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    return list_users(db)


@router.post("", response_model=UserRead)
def api_create_user(
    request: UserCreateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    try:
        return create_managed_user(
            db,
            username=request.username,
            password=request.password,
            role=request.role,
            full_name=request.full_name,
            actor=current_user.username,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/{user_id}/disable", response_model=UserRead)
def api_disable_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    try:
        user = disable_user(db, user_id, actor=current_user.username)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if user is None:
        raise HTTPException(status_code=404, detail="User not found.")
    return user


@router.post("/{user_id}/reset-password", response_model=UserRead)
def api_reset_password(
    user_id: int,
    request: UserResetPasswordRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    user = reset_user_password(db, user_id, new_password=request.new_password, actor=current_user.username)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found.")
    return user


@router.post("/{user_id}/role", response_model=UserRead)
def api_change_role(
    user_id: int,
    request: UserRoleRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    user = change_user_role(db, user_id, role=request.role, actor=current_user.username)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found.")
    return user
