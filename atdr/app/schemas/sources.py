from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


SourceType = Literal["file_import", "replay", "syslog_udp", "syslog_tcp", "router", "firewall", "sample"]
ParserProfile = Literal["palo_alto", "generic_syslog", "raw_fallback"]


class SourceHealthRead(BaseModel):
    source_id: int
    status: Literal["healthy", "idle", "warning", "error", "disabled"]
    enabled: bool
    logs_received_count: int
    parse_success_count: int
    parse_failure_count: int
    parse_success_rate: float
    last_seen: datetime | None = None
    last_log_received_at: datetime | None = None
    latest_error: str | None = None
    recommendation: str
    warnings: list[str] = Field(default_factory=list)


class SourceQualityRead(BaseModel):
    raw_logs: int
    normalized_logs: int
    unknown_app_count: int
    unknown_app_rate: float
    alert_count: int
    parse_failure_examples: list[dict[str, Any]] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class LogSourceRead(BaseModel):
    source_id: int
    name: str
    source_type: SourceType
    parser_profile: ParserProfile = "palo_alto"
    host: str | None = None
    port: int | None = None
    enabled: bool
    last_seen: datetime | None = None
    last_log_received_at: datetime | None = None
    logs_received_count: int
    parse_success_count: int
    parse_failure_count: int
    latest_error: str | None = None
    created_at: datetime
    updated_at: datetime
    health: SourceHealthRead
    quality: SourceQualityRead | None = None
    recent_ingestion_runs: list[dict[str, Any]] = Field(default_factory=list)
    recent_detection_runs: list[dict[str, Any]] = Field(default_factory=list)


class LogSourceCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    source_type: SourceType = "file_import"
    parser_profile: ParserProfile = "palo_alto"
    host: str | None = Field(default=None, max_length=255)
    port: int | None = Field(default=None, ge=1, le=65535)
    enabled: bool = True


class LogSourceUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    source_type: SourceType | None = None
    parser_profile: ParserProfile | None = None
    host: str | None = Field(default=None, max_length=255)
    port: int | None = Field(default=None, ge=1, le=65535)
    enabled: bool | None = None
