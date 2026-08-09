from typing import Any, Literal

from pydantic import BaseModel, Field


class AssistantChatRequest(BaseModel):
    question: str = Field(min_length=1, max_length=2000)
    alert_id: int | None = Field(default=None, ge=1)
    log_id: int | None = Field(default=None, ge=1)
    source_id: int | None = Field(default=None, ge=1)
    case_id: str | None = Field(default=None, max_length=120)
    include_recent_context: bool = True
    conversation_id: str | None = Field(default=None, min_length=8, max_length=64, pattern=r"^[A-Za-z0-9_-]+$")
    reset_context: bool = False


class AssistantActiveContext(BaseModel):
    alert_id: int | None = None
    log_id: int | None = None
    source_id: int | None = None
    case_id: str | None = None
    primary: Literal["alert", "log", "source", "case"] | None = None


class AssistantCitation(BaseModel):
    label: str
    source: str
    reference_id: str | None = None


class AssistantChatResponse(BaseModel):
    answer: str
    mode: str
    response_mode: Literal[
        "direct_fact",
        "alert_explanation",
        "safe_next_step",
        "related_logs",
        "source_health",
        "list_summary",
        "investigation_brief",
        "how_to",
        "governance",
    ]
    external_provider_used: bool
    safety: list[str] = Field(default_factory=list)
    context_used: list[str] = Field(default_factory=list)
    citations: list[AssistantCitation] = Field(default_factory=list)
    redaction_applied: bool
    raw_log_context_included: bool
    suggested_followups: list[str] = Field(default_factory=list)
    details: dict[str, Any] = Field(default_factory=dict)
    conversation_id: str
    active_context: AssistantActiveContext


AssistantFeedbackRating = Literal["helpful", "not_helpful", "unsafe", "incorrect", "unclear"]


class AssistantFeedbackRequest(BaseModel):
    question: str = Field(min_length=1, max_length=2000)
    rating: AssistantFeedbackRating
    answer: str | None = Field(default=None, max_length=10000)
    feedback_note: str | None = Field(default=None, max_length=500)
    context_type: str | None = Field(default=None, max_length=64)
    context_reference: str | None = Field(default=None, max_length=255)
    external_provider_used: bool = False
    raw_log_context_included: bool = False
    action_requested: bool | None = None
    assistant_audit_id: int | None = Field(default=None, ge=1)


class AssistantFeedbackItem(BaseModel):
    feedback_id: int
    created_at: str
    actor_user_id: int | None = None
    actor_username: str
    question: str
    answer_summary: str | None = None
    answer_hash: str
    context_type: str | None = None
    context_reference: str | None = None
    rating: str
    feedback_note: str | None = None
    external_provider_used: bool
    raw_log_context_included: bool
    action_requested: bool
    action_executed: bool
    assistant_audit_id: int | None = None
    review_recommended: bool = False
    review_reason: str | None = None


class AssistantFeedbackSummary(BaseModel):
    total_count: int
    rating_counts: dict[str, int] = Field(default_factory=dict)
    unsafe_or_incorrect_count: int = 0
    needs_review_count: int = 0
    external_provider_used_count: int
    raw_log_context_included_count: int
    action_requested_count: int
    action_executed_count: int
    latest_unsafe_or_incorrect: list[AssistantFeedbackItem] = Field(default_factory=list)
    recent: list[AssistantFeedbackItem] = Field(default_factory=list)
    scope: str
    filtered_rating: str | None = None
    filtered_context_type: str | None = None
    filtered_since_days: int | None = None
    review_warning: bool = False
    secrets_exposed: bool = False


class AssistantStatusResponse(BaseModel):
    available: bool
    mode: str
    external_provider_configured: bool
    external_provider_used_by_default: bool
    provider: str
    model_configured: bool
    llm_enabled: bool = False
    llm_provider_configured: bool = False
    llm_provider_name: str = ""
    llm_ready: bool = False
    llm_model_configured: bool = False
    llm_secret_configured: bool = False
    llm_base_url_configured: bool = False
    llm_timeout_seconds: float = 15.0
    llm_max_retries: int = 2
    llm_max_prompt_chars: int = 12000
    llm_max_output_tokens: int = 800
    llm_max_visible_chars: int = 4000
    llm_circuit_breaker_failures: int = 3
    llm_circuit_breaker_cooldown_seconds: int = 60
    llm_operational: dict[str, Any] = Field(default_factory=dict)
    conversation_history_turns: int = 4
    rate_limit_requests: int = 30
    rate_limit_window_seconds: int = 60
    llm_secrets_exposed: bool = False
    redaction_enabled: bool
    raw_log_context_allowed: bool
    max_context_rows: int
    safety: list[str] = Field(default_factory=list)


class AssistantHistoryItem(BaseModel):
    id: int
    actor: str
    question: str
    created_at: str
    context_used: list[str] = Field(default_factory=list)
    external_provider_used: bool = False
    conversation_id: str | None = None
    question_category: str | None = None
