from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


ALLOWED_ALERT_STATUSES = {"open", "investigating", "contained", "resolved", "false_positive"}


class AlertRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    title: str
    alert_type: str
    src_ip: str | None = None
    dst_ip: str | None = None
    threat_score: int
    severity: str
    status: str
    assigned_to: str | None = None
    assigned_at: datetime | None = None
    priority_owner: str | None = None
    escalation_reason: str | None = None
    ticket_reference: str | None = None
    escalated_at: datetime | None = None
    explanation: str
    matched_rules_json: list[dict[str, Any]]
    recommended_response: str
    created_at: datetime
    updated_at: datetime
    evidence_count: int = 0
    evidence_log_ids: list[int] = Field(default_factory=list)
    sla: dict[str, Any] = Field(default_factory=dict)
    detection_summary: dict[str, Any] = Field(default_factory=dict)


class AlertStatusResponse(BaseModel):
    id: int
    status: str
    updated_at: datetime


class AlertStatusUpdate(BaseModel):
    status: str = Field(description="One of: open, investigating, contained, resolved, false_positive")

    def normalized_status(self) -> str:
        return self.status.strip().lower().replace("-", "_")


class AlertAssignRequest(BaseModel):
    username: str | None = Field(default=None, max_length=128)


class AlertNoteCreate(BaseModel):
    note: str = Field(min_length=1, max_length=5000)


class AlertNoteRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    alert_id: int
    author: str
    note: str
    created_at: datetime


class AlertTimelineEvent(BaseModel):
    event_time: datetime
    event_type: str
    actor: str
    summary: str
    details: dict = Field(default_factory=dict)


class AlertEscalateRequest(BaseModel):
    priority_owner: str = Field(min_length=1, max_length=128)
    escalation_reason: str = Field(min_length=3, max_length=2000)
    ticket_reference: str | None = Field(default=None, max_length=255)


class AlertReportRead(BaseModel):
    alert: dict[str, Any]
    matched_rules: list[dict[str, Any]]
    detection_summary: dict[str, Any] = Field(default_factory=dict)
    evidence_logs: list[dict[str, Any]]
    timeline: list[AlertTimelineEvent]
    notes: list[AlertNoteRead]
    response_actions: list[dict[str, Any]]
