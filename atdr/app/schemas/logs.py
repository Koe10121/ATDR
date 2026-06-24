from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ImportResult(BaseModel):
    source: str
    imported: int
    parsed: int
    failed: int
    duplicate_raw_logs: int = 0
    run_id: int | None = None
    job_id: int | None = None
    source_id: int | None = None


class NormalizedLogRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    raw_log_id: int
    source_id: int | None = None
    source_name: str | None = None
    source_type: str | None = None
    parser_profile: str | None = None
    receive_time: datetime | None = None
    generated_time: datetime | None = None
    log_type: str | None = None
    subtype: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    app: str | None = None
    src_zone: str | None = None
    dst_zone: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    protocol: str | None = None
    action: str | None = None
    bytes: int | None = None
    packets: int | None = None
    src_country: str | None = None
    dst_country: str | None = None
    app_risk: int | None = None
    app_characteristic: str | None = None
    is_anomaly: bool = False
    anomaly_score: float | None = None
    parsed_json: dict[str, Any] = Field(default_factory=dict)


class LogDetail(NormalizedLogRead):
    raw_line: str | None = None
    alert_ids: list[int] = Field(default_factory=list)
    triage_explanation: dict[str, Any] = Field(default_factory=dict)
