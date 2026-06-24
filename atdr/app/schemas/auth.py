from pydantic import BaseModel, ConfigDict, Field


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=256)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in_minutes: int
    username: str
    role: str


class UserRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    email: str | None = None
    full_name: str | None = None
    role: str
    is_active: bool
    email_verified: bool = False
    auth_provider: str = "local"


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=8, max_length=256)


class OidcStatusRead(BaseModel):
    enabled: bool
    provider_name: str | None = None
    issuer_configured: bool
    client_configured: bool
    allowed_domains: list[str]
    default_role: str
    mode: str
    school_email_domains: list[str]
    require_school_email: bool
    local_email_login_enabled: bool
    smtp_enabled: bool


class MfuIamStatusRead(BaseModel):
    enabled: bool
    base_url_configured: bool
    client_id_configured: bool
    audience_configured: bool
    allowed_domains: list[str]
    default_role: str
    google_sso_enabled: bool
    google_client_id_configured: bool
    mode: str
    secrets_exposed: bool = False
