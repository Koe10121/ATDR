from typing import Literal

from pydantic import BaseModel, Field


class DemoLimitRequest(BaseModel):
    limit: int | None = None
    sample_path: str | None = None


class DemoResetRequest(BaseModel):
    limit: int | None = None
    use_ml: bool = False
    sample_path: str | None = None


class DemoDetectionRequest(BaseModel):
    limit: int | None = None
    use_ml: bool = False
    # "newest" checks the newest `limit` logs; "unchecked" checks the oldest
    # `limit` logs no detection run has evaluated yet (one batch per call).
    mode: Literal["newest", "unchecked"] = "newest"


class DemoExportRequest(BaseModel):
    alert_id: int | None = None
    output_dir: str | None = None
    top_alert_limit: int = Field(default=10, ge=1, le=100)
    audit_limit: int = Field(default=50, ge=1, le=500)
