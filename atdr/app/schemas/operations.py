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
