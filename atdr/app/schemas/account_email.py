from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class EmailVerificationStatusRead(BaseModel):
    notifications_enabled: bool
    verification_enabled: bool
    delivery_mode: str
    smtp_configured: bool
    smtp_enabled_legacy: bool
    from_email_configured: bool
    dev_outbox_available: bool
    code_ttl_minutes: int
    code_length: int
    verification_required_for_login: bool = False
    verification_required_for_admin_actions: bool = False
    school_email_domains: list[str] = Field(default_factory=list)
    require_school_email: bool = False
    local_email_login_enabled: bool = True
    secrets_exposed: bool = False


class EmailVerificationRequestRead(BaseModel):
    created: bool
    status: str
    message: str
    user_id: int | None = None
    email: str | None = None
    expires_at: datetime | None = None
    delivery_mode: str
    delivery_status: str
    outbox_id: int | None = None


class EmailVerificationVerifyRequest(BaseModel):
    code: str = Field(min_length=4, max_length=32)


class EmailVerificationVerifyResponse(BaseModel):
    verified: bool
    status: str
    message: str


class DevEmailOutboxItemRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    user_id: int | None = None
    recipient_email: str
    subject: str
    body_preview: str
    purpose: str
    delivery_mode: str
    delivery_status: str
    created_by: str | None = None
    created_at: datetime
    sent_at: datetime | None = None
    error_summary: str | None = None
