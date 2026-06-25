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
    client_secret_configured: bool = False
    audience_configured: bool
    scope_configured: bool
    timeout_ms: int = 5000
    token_path_configured: bool
    introspect_path_configured: bool
    profile_path_configured: bool
    admin_base_path_configured: bool
    admin_client_configured: bool = False
    admin_secret_configured: bool = False
    admin_audience_configured: bool = False
    admin_scope_configured: bool = False
    compat_profile_configured: bool = False
    allowed_domains: list[str]
    domain_hints: list[str] = Field(default_factory=list)
    default_role: str
    google_sso_enabled: bool
    google_client_id_configured: bool
    permission_source: str | None = None
    permission_bootstrap_mode: str | None = None
    permission_root_configured: bool = False
    permission_paths_count: int = 0
    project_account_email_configured: bool = False
    auth_require_2fa: bool = False
    audit_retention_days: int = 90
    managed_client_configured: bool = False
    managed_client_endpoint_configured: bool = False
    managed_client_owner_configured: bool = False
    managed_client_scopes_configured: bool = False
    managed_client_audiences_configured: bool = False
    init_admin_emails_configured: bool = False
    seed_admin_email_configured: bool = False
    b2b_ready: bool = False
    admin_api_ready: bool = False
    permission_bootstrap_ready: bool = False
    mode: str
    secrets_exposed: bool = False
