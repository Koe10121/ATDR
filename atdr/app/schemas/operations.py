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
    result_summary: dict[str, Any] = Field(default_factory=dict)
    error_summary: str | None = None
    related_ingestion_run_id: int | None = None
    related_detection_run_id: int | None = None
    related_ml_model_run_id: int | None = None
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
