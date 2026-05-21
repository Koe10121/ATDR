from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class BlockIPRequest(BaseModel):
    target_ip: str = Field(min_length=3, max_length=64)
    reason: str | None = None
    alert_id: int | None = None
    actor: str = "analyst"


class UnblockIPRequest(BaseModel):
    target_ip: str = Field(min_length=3, max_length=64)
    reason: str | None = None
    actor: str = "analyst"


class ResponseActionRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    alert_id: int | None = None
    action_type: str
    target_ip: str
    status: str
    result_message: str
    executed_by: str
    executed_at: datetime


class BlockedIPRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    ip_address: str
    reason: str | None = None
    created_at: datetime
    created_by: str
    active: bool


class AuditLogRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    actor: str
    action: str
    target_type: str
    target_value: str
    details: dict
    created_at: datetime
