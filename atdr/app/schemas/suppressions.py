from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, model_validator

ALLOWED_SUPPRESSION_REVIEW_STATUSES = {"pending", "reviewed", "needs_changes"}


class SuppressionCreateRequest(BaseModel):
    src_ip: str | None = Field(default=None, max_length=64)
    app: str | None = Field(default=None, max_length=255)
    alert_type: str | None = Field(default=None, max_length=128)
    reason: str = Field(min_length=3, max_length=2000)

    @model_validator(mode="after")
    def at_least_one_criterion(self):
        if not any([self.src_ip, self.app, self.alert_type]):
            raise ValueError("At least one suppression criterion is required.")
        return self


class SuppressionReviewRequest(BaseModel):
    review_status: str = Field(description="One of: pending, reviewed, needs_changes")
    review_notes: str | None = Field(default=None, max_length=2000)

    def normalized_status(self) -> str:
        return self.review_status.strip().lower().replace("-", "_")


class SuppressionRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    src_ip: str | None = None
    app: str | None = None
    alert_type: str | None = None
    reason: str
    active: bool
    suppressed_count: int
    last_matched_at: datetime | None = None
    created_by: str
    created_at: datetime
    review_status: str
    review_notes: str | None = None
    reviewed_by: str | None = None
    reviewed_at: datetime | None = None
    disabled_by: str | None = None
    disabled_at: datetime | None = None
