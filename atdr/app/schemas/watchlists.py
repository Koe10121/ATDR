from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator


ALLOWED_WATCHLIST_TYPES = {"src_ip", "dst_ip", "app"}


class WatchlistCreateRequest(BaseModel):
    indicator_type: str = Field(description="One of: src_ip, dst_ip, app")
    indicator_value: str = Field(min_length=1, max_length=255)
    description: str = Field(min_length=3, max_length=2000)
    severity_boost: int = Field(default=30, ge=5, le=60)

    @field_validator("indicator_type")
    @classmethod
    def normalize_indicator_type(cls, value: str) -> str:
        normalized = value.strip().lower()
        if normalized not in ALLOWED_WATCHLIST_TYPES:
            raise ValueError(f"Unsupported watchlist indicator type: {value}")
        return normalized

    @field_validator("indicator_value")
    @classmethod
    def normalize_indicator_value(cls, value: str) -> str:
        return value.strip()


class WatchlistRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    indicator_type: str
    indicator_value: str
    description: str
    severity_boost: int
    active: bool
    match_count: int
    last_matched_at: datetime | None = None
    created_by: str
    created_at: datetime
    disabled_by: str | None = None
    disabled_at: datetime | None = None
