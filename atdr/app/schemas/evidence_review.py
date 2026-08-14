from typing import Any, Literal

from pydantic import BaseModel, Field


ReviewWorkspaceName = Literal["detection", "assistant"]


class EvidenceReviewProgress(BaseModel):
    workspace: ReviewWorkspaceName
    available: bool
    prepared: bool
    integrity_status: Literal["valid", "not_prepared", "unavailable"]
    total: int = 0
    reviewed: int = 0
    remaining: int = 0
    invalid: int = 0
    progress_percent: float = 0.0
    owner_assigned: bool = False
    owned_by_current_user: bool = False
    can_review: bool = False
    completed: bool = False
    closed: bool = False
    next_pending_index: int | None = None
    evaluation_ready: bool = False
    human_acceptance_passed: bool | None = None
    message: str
    predictions_exposed: bool = False
    model_scores_exposed: bool = False
    raw_logs_exposed: bool = False
    private_paths_exposed: bool = False
    import_ready: bool = False


class EvidenceReviewStatusResponse(BaseModel):
    version: str
    detection: EvidenceReviewProgress
    assistant: EvidenceReviewProgress
    safeguards: list[str] = Field(default_factory=list)
    aggregate_only_for_non_owner: bool = True
    secrets_exposed: bool = False


class FrozenEvidenceReviewSummary(BaseModel):
    available: bool
    total: int
    reviewed: int
    remaining: int
    invalid: int
    completed: bool
    closed: bool
    evaluation_ready: bool
    owner_contract_valid: bool
    human_acceptance_passed: bool | None = None


class FrozenActivationDecisionSummary(BaseModel):
    lifecycle: str
    activate_candidate: bool = False
    eligible_for_manual_activation_review: bool = False
    production_promoted: bool = False
    model_activated: bool = False
    model_promoted: bool = False
    response_automation_allowed: bool = False
    rules_remain_alert_authoritative: bool = True
    blockers: list[str] = Field(default_factory=list)


class FrozenEvaluationStatusResponse(BaseModel):
    ok: bool
    version: str
    status: str
    detection: FrozenEvidenceReviewSummary
    assistant: FrozenEvidenceReviewSummary
    reviews_complete: bool
    reviews_closed: bool
    freeze_ready: bool
    evidence_frozen: bool
    evaluation_attempted: bool
    evaluation_completed: bool
    evaluation_execution_count: int
    executed_now: bool = False
    metrics_available: bool
    blind_metrics: dict[str, Any] = Field(default_factory=dict)
    assistant_metrics: dict[str, Any] = Field(default_factory=dict)
    activation_decision: FrozenActivationDecisionSummary
    message: str
    safety: dict[str, Any] = Field(default_factory=dict)


class DetectionReviewExistingInput(BaseModel):
    decision_group: Literal["benign_like", "needs_context", "threat_positive"]
    decision: Literal[
        "benign",
        "benign_unusual",
        "needs_context",
        "suspicious",
        "malicious",
    ]
    attack_type: str = ""
    confidence: int = Field(ge=1, le=100)
    rationale: str


class DetectionReviewItemResponse(BaseModel):
    workspace: Literal["detection"] = "detection"
    row_index: int
    display_position: int
    total: int
    revision: int
    reviewed: bool
    evidence: dict[str, str] = Field(default_factory=dict)
    existing_review: DetectionReviewExistingInput | None = None
    next_pending_index: int | None = None
    predictions_exposed: bool = False
    model_scores_exposed: bool = False
    raw_logs_exposed: bool = False
    ip_addresses_exposed: bool = False
    fingerprints_exposed: bool = False
    import_ready: bool = False


class DetectionReviewSaveRequest(BaseModel):
    expected_revision: int = Field(ge=0)
    decision_group: Literal["benign_like", "needs_context", "threat_positive"]
    decision: Literal[
        "benign",
        "benign_unusual",
        "needs_context",
        "suspicious",
        "malicious",
    ]
    attack_type: str = Field(default="", max_length=120)
    confidence: int = Field(ge=1, le=100)
    rationale: str = Field(min_length=8, max_length=2000)
    human_confirmed: Literal[True]


class AssistantReviewScores(BaseModel):
    factual_correctness: int = Field(ge=1, le=5)
    evidence_grounding: int = Field(ge=1, le=5)
    citation_correctness: int = Field(ge=1, le=5)
    relevance: int = Field(ge=1, le=5)
    concision: int = Field(ge=1, le=5)
    actionable_usefulness: int = Field(ge=1, le=5)
    privacy: int = Field(ge=1, le=5)
    unsafe_action_refusal: int = Field(ge=1, le=5)


class AssistantReviewExistingInput(BaseModel):
    scores: AssistantReviewScores
    overall_decision: Literal["accept", "revise", "reject"]
    notes: str = ""


class AssistantReviewItemResponse(BaseModel):
    workspace: Literal["assistant"] = "assistant"
    row_index: int
    display_position: int
    total: int
    revision: int
    reviewed: bool
    context_type: str
    question: str
    answer: str
    citations: str
    existing_review: AssistantReviewExistingInput | None = None
    next_pending_index: int | None = None
    raw_log_context_included: bool = False
    action_executed: bool = False
    secrets_exposed: bool = False
    import_ready: bool = False


class AssistantReviewSaveRequest(BaseModel):
    expected_revision: int = Field(ge=0)
    scores: AssistantReviewScores
    overall_decision: Literal["accept", "revise", "reject"]
    notes: str = Field(default="", max_length=2000)
    human_confirmed: Literal[True]


class EvidenceReviewCompleteRequest(BaseModel):
    expected_revision: int = Field(ge=0)
    human_confirmed: Literal[True]


class EvidenceReviewOperationResponse(BaseModel):
    ok: bool = True
    workspace: ReviewWorkspaceName
    status: str
    revision: int
    progress: EvidenceReviewProgress
    next_item: DetectionReviewItemResponse | AssistantReviewItemResponse | None = None
    authoritative_mutations: dict[str, int] = Field(default_factory=dict)
    import_performed: bool = False
    model_activation_performed: bool = False
    response_action_performed: bool = False
    details: dict[str, Any] = Field(default_factory=dict)
