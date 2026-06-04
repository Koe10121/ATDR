from datetime import datetime
import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def normalize_email(value: str | None) -> str | None:
    if value is None:
        return None
    email = value.strip().lower()
    if not email:
        return None
    if not EMAIL_RE.match(email):
        raise ValueError("Invalid email address.")
    return email


class UserCreateRequest(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: str | None = Field(default=None, min_length=8, max_length=256)
    role: str = Field(pattern="^(admin|analyst)$")
    full_name: str | None = Field(default=None, max_length=255)
    email: str | None = Field(default=None, max_length=255)
    email_verified: bool = False
    auth_provider: str = Field(default="local", pattern="^(local|external)$")
    is_active: bool = True

    @field_validator("email")
    @classmethod
    def validate_email(cls, value: str | None) -> str | None:
        return normalize_email(value)


class UserUpdateRequest(BaseModel):
    username: str | None = Field(default=None, min_length=1, max_length=128)
    full_name: str | None = Field(default=None, max_length=255)
    email: str | None = Field(default=None, max_length=255)
    role: str | None = Field(default=None, pattern="^(admin|analyst)$")
    is_active: bool | None = None
    email_verified: bool | None = None
    auth_provider: str | None = Field(default=None, pattern="^(local|external)$")

    @field_validator("email")
    @classmethod
    def validate_email(cls, value: str | None) -> str | None:
        return normalize_email(value)


class UserResetPasswordRequest(BaseModel):
    new_password: str = Field(min_length=8, max_length=256)


class UserRoleRequest(BaseModel):
    role: str = Field(pattern="^(admin|analyst)$")


class UserRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    email: str | None = None
    full_name: str | None = None
    role: str
    is_active: bool
    email_verified: bool
    auth_provider: str
    external_subject: str | None = None
    last_login_at: datetime | None = None
    invited_at: datetime | None = None
    disabled_at: datetime | None = None
    created_at: datetime
