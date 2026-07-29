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
    parser_quality_state: str = "legacy"
    parser_contract_state: str = "legacy_contract"
    runtime_parser_error_count: int = 0
    runtime_parser_error_rate: float = 0.0
    structural_warning_count: int = 0
    unresolved_application_count: int = 0
    unresolved_application_rate: float = 0.0
    generic_syslog_count: int = 0
    raw_fallback_count: int = 0
    operational_alerts: list[dict[str, Any]] = Field(default_factory=list)


class SourceQualityRead(BaseModel):
    raw_logs: int
    normalized_logs: int
    unknown_app_count: int
    unknown_app_rate: float
    alert_count: int
    parse_failure_examples: list[dict[str, Any]] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    parser_quality: dict[str, Any] = Field(default_factory=dict)
    parser_quality_state: str = "legacy"
    parser_contract_state: str = "legacy_contract"
    runtime_observed_rows: int = 0
    legacy_contract_rows: int = 0
    parser_error_count: int = 0
    parser_error_rate: float = 0.0
    structural_warning_count: int = 0
    compatible_layout_count: int = 0
    extended_layout_count: int = 0
    partial_layout_count: int = 0
    unsupported_layout_count: int = 0
    unresolved_application_count: int = 0
    unresolved_application_rate: float = 0.0
    absent_application_count: int = 0
    not_applicable_application_count: int = 0
    generic_syslog_count: int = 0
    raw_fallback_count: int = 0
    operational_alerts: list[dict[str, Any]] = Field(default_factory=list)


class HistoricalReparsePreviewRead(BaseModel):
    version: str
    status: str
    scope: Literal["selected_source"]
    preview_only: Literal[True]
    reparse_performed: Literal[False]
    database_mutated: Literal[False]
    total_rows: int
    rows_scanned: int
    coverage_complete: bool
    current_contract_metadata_rows: int
    legacy_contract_rows_scanned: int
    parser_profiles: dict[str, int] = Field(default_factory=dict)
    parser_contract_versions: dict[str, int] = Field(default_factory=dict)
    compatibility_statuses: dict[str, int] = Field(default_factory=dict)
    application_resolution_statuses: dict[str, int] = Field(default_factory=dict)
    raw_evidence_accessed: Literal[False]
    raw_logs_returned: Literal[False]
    private_paths_included: Literal[False]
    ip_addresses_included: Literal[False]
    source_identity_included: Literal[False]
    labels_accessed: Literal[False]
    alerts_created: Literal[0]
    response_actions_created: Literal[0]


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
