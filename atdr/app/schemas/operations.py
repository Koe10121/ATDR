from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class IngestionRunRead(BaseModel):
    run_id: int
    started_at: datetime
    finished_at: datetime | None = None
    source_type: str
    input_name: str | None = None
    status: str
    total_lines_received: int
    raw_logs_created: int
    parsed_successfully: int
    parse_failures: int
    duplicate_raw_logs: int
    alerts_created: int
    alerts_deduplicated: int
    alerts_suppressed: int
    runtime_seconds: float | None = None
    error_summary: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)


class DetectionRunRead(BaseModel):
    run_id: int
    started_at: datetime
    finished_at: datetime | None = None
    detection_type: str
    status: str
    logs_evaluated: int
    alerts_created: int
    alerts_deduplicated: int
    alerts_suppressed: int
    top_attack_types: list[dict[str, Any]] = Field(default_factory=list)
    runtime_seconds: float | None = None
    error_summary: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)


class OperationJobRead(BaseModel):
    job_id: int
    job_type: str
    status: str
    requested_by: str
    started_at: datetime | None = None
    finished_at: datetime | None = None
    progress_current: int
    progress_total: int
    progress_percentage: float = 0.0
    progress_status: str = "unknown"
    checkpoint_line: int = 0
    checkpoint_bytes: int = 0
    checkpoint_at: datetime | None = None
    chunk_commits: int = 0
    input_size_bytes: int | None = None
    cancellation_requested: bool = False
    cancellation_requested_at: datetime | None = None
    resume_eligible: bool = False
    resume_ineligible_reason: str | None = None
    resume_of_job_id: int | None = None
    original_job_id: int | None = None
    resume_expires_at: datetime | None = None
    latest_heartbeat_at: datetime | str | None = None
    result_summary: dict[str, Any] = Field(default_factory=dict)
    error_summary: str | None = None
    related_ingestion_run_id: int | None = None
    related_detection_run_id: int | None = None
    related_ml_model_run_id: int | None = None
    attempt_count: int = 0
    max_attempts: int = 1
    next_attempt_at: datetime | None = None
    lease_expires_at: datetime | None = None
    can_cancel: bool = False
    can_request_cancel: bool = False
    can_retry: bool = False
    can_resume: bool = False
    details: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime
    updated_at: datetime


class OperationJobSummaryRead(BaseModel):
    counts: dict[str, int] = Field(default_factory=dict)
    active_count: int
    failed_count: int
    stale_count: int
    stale_job_ids: list[int] = Field(default_factory=list)
    latest_failed_job: OperationJobRead | None = None
    latest_successful_job: OperationJobRead | None = None
    retention_policy: dict[str, Any] = Field(default_factory=dict)
    worker: dict[str, Any] = Field(default_factory=dict)
    staging: dict[str, Any] = Field(default_factory=dict)
    queue: dict[str, Any] = Field(default_factory=dict)
    health_status: str = "healthy"
    warnings: list[dict[str, str]] = Field(default_factory=list)
    warning_count: int = 0
    recent_failure_count: int = 0


class ReleaseReadinessRead(BaseModel):
    phase: str
    status: str
    local_controls_ready: bool
    external_evidence_complete: bool
    approved_host_ready: bool
    shared_lab_ready: bool
    production_ready: bool = False
    readiness_states: dict[str, str] = Field(default_factory=dict)
    sections: dict[str, Any] = Field(default_factory=dict)
    remaining_external_actions: list[str] = Field(default_factory=list)
    runtime_issue_count: int = 0
    database_probe_performed: bool = False
    filesystem_writes_performed: bool = False
    current_database_modified: bool = False
    model_activation_performed: bool = False
    response_automation_allowed: bool = False
    real_firewall_blocking_enabled: bool = False
    raw_log_context_allowed: bool = False
    secrets_exposed: bool = False


class OperationJobSubmit(BaseModel):
    job_type: str
    payload: dict[str, Any] = Field(default_factory=dict)
    idempotency_key: str | None = Field(default=None, min_length=8, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$")
    max_attempts: int | None = Field(default=None, ge=1, le=3)
