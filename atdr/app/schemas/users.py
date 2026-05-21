from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class UserCreateRequest(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=8, max_length=256)
    role: str = Field(pattern="^(admin|analyst)$")
    full_name: str | None = Field(default=None, max_length=255)


class UserResetPasswordRequest(BaseModel):
    new_password: str = Field(min_length=8, max_length=256)


class UserRoleRequest(BaseModel):
    role: str = Field(pattern="^(admin|analyst)$")


class UserRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    full_name: str | None = None
    role: str
    is_active: bool
    created_at: datetime
