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


class BlindEvidenceStatusResponse(BaseModel):
    version: str
    status: Literal[
        "Designed",
        "Collecting",
        "Insufficient Sources",
        "Ready For Human Review",
        "Review Complete",
        "Ready For Frozen Evaluation",
    ]
    qualifying_collection_count: int = 0
    independent_source_count: int = 0
    required_source_count: int = 2
    collection_window_count: int = 0
    required_window_count: int = 3
    candidate_rows: int = 0
    target_review_rows: int = 240
    review_pack_available: bool = False
    human_reviewed_rows: int = 0
    human_review_complete: bool = False
    class_support: dict[str, int] = Field(default_factory=dict)
    prediction_sealed_separately: bool = False
    metrics_available: bool = False
    lifecycle_state: Literal["shadow_observation"] = "shadow_observation"
    rules_alert_authoritative: Literal[True] = True
    model_activated: Literal[False] = False
    model_promoted: Literal[False] = False
    response_automation_allowed: Literal[False] = False
    raw_logs_exposed: Literal[False] = False
    ip_addresses_exposed: Literal[False] = False
    private_paths_exposed: Literal[False] = False
    source_identities_exposed: Literal[False] = False
    fingerprints_exposed: Literal[False] = False
    secrets_exposed: Literal[False] = False
    message: str


class CandidateFreezeStatusResponse(BaseModel):
    version: str
    status: str
    best_candidate: str | None = None
    passing_folds: int = 0
    required_folds: int = 3
    candidate_frozen: bool = False
    calibration_status: Literal["not_evaluated", "weak", "passed"]
    blind_evidence_status: str
    supervised_phases_remaining: int
    blockers: list[str] = Field(default_factory=list)
    lifecycle_state: Literal["shadow_observation"] = "shadow_observation"
    rules_alert_authoritative: Literal[True] = True
    model_activated: Literal[False] = False
    model_promoted: Literal[False] = False
    response_automation_allowed: Literal[False] = False
    private_paths_exposed: Literal[False] = False
    digests_exposed: Literal[False] = False
    blind_predictions_exposed: Literal[False] = False
    secrets_exposed: Literal[False] = False


class TemporalStabilityStatusResponse(BaseModel):
    version: str
    status: str
    best_variant: str | None = None
    passing_folds: int = 0
    required_folds: int = 3
    candidate_frozen: bool = False
    calibration_status: Literal["not_evaluated", "weak", "passed"]
    queue_stability_status: Literal["not_evaluated", "unstable", "passed"]
    feature_ablation_status: Literal["not_evaluated", "incomplete", "complete"]
    supervised_phases_remaining: int
    blockers: list[str] = Field(default_factory=list)
    lifecycle_state: Literal["shadow_observation"] = "shadow_observation"
    rules_alert_authoritative: Literal[True] = True
    model_activated: Literal[False] = False
    model_promoted: Literal[False] = False
    response_automation_allowed: Literal[False] = False
    private_paths_exposed: Literal[False] = False
    digests_exposed: Literal[False] = False
    blind_predictions_exposed: Literal[False] = False
    secrets_exposed: Literal[False] = False


class DevelopmentModelRepairStatusResponse(BaseModel):
    version: str
    status: str
    generated_at: str | None = None
    diagnostic_leader: str | None = None
    passing_views: int = 0
    required_views: int = 3
    candidate_freeze_ready: bool = False
    candidate_frozen: bool = False
    isolation_forest_reliable: bool = False
    supervised_phases_remaining: int = 5
    blockers: list[str] = Field(default_factory=list)
    lifecycle_state: Literal["shadow_observation"] = "shadow_observation"
    model_activated: Literal[False] = False
    model_promoted: Literal[False] = False
    response_automation_allowed: Literal[False] = False
    future_labels_opened: Literal[False] = False
    private_paths_returned: Literal[False] = False
    fingerprints_returned: Literal[False] = False
    secrets_exposed: Literal[False] = False


class ManualAnchorTransferStatusResponse(BaseModel):
    version: str
    status: str
    generated_at: str | None = None
    diagnostic_leader: str | None = None
    passing_views: int = 0
    required_views: int = 3
    manual_anchor_transfer_status: Literal[
        "not_evaluated", "improved", "blocked"
    ] = "not_evaluated"
    calibration_status: str = "not_evaluated"
    manual_anchor_queue_f1: float | None = None
    manual_anchor_fpr: float | None = None
    manual_anchor_suspicious_recall: float | None = None
    manual_anchor_malicious_recall: float | None = None
    queue_f1_transfer_gap: float | None = None
    candidate_freeze_ready: bool = False
    candidate_frozen: bool = False
    isolation_forest_reliable: bool = False
    supervised_phases_remaining: int = 5
    blockers: list[str] = Field(default_factory=list)
    lifecycle_state: Literal["shadow_observation"] = "shadow_observation"
    rules_alert_authoritative: Literal[True] = True
    model_activated: Literal[False] = False
    model_promoted: Literal[False] = False
    response_automation_allowed: Literal[False] = False
    future_labels_opened: Literal[False] = False
    private_paths_returned: Literal[False] = False
    fingerprints_returned: Literal[False] = False
    secrets_exposed: Literal[False] = False


class ManualAnchorAcquisitionStatusResponse(BaseModel):
    version: str
    status: str
    generated_at: str | None = None
    selected_rows: int = 0
    target_rows: int = 120
    represented_strata: int = 0
    coverage_counts: dict[str, int] = Field(default_factory=dict)
    coverage_gate_passed: bool = False
    review_status: str = "not_prepared"
    reviewed_rows: int = 0
    total_review_rows: int = 0
    invalid_review_rows: int = 0
    class_support: dict[str, int] = Field(default_factory=dict)
    ready_for_fixed_revalidation: bool = False
    independent_source_count: int = 0
    second_real_source_present: bool = False
    development_evidence_only: Literal[True] = True
    workspace_created: bool = False
    lifecycle_state: Literal["shadow_observation"] = "shadow_observation"
    rules_alert_authoritative: Literal[True] = True
    model_activated: Literal[False] = False
    model_promoted: Literal[False] = False
    response_automation_allowed: Literal[False] = False
    future_labels_opened: Literal[False] = False
    predictions_exposed: Literal[False] = False
    assisted_labels_exposed: Literal[False] = False
    private_paths_returned: Literal[False] = False
    fingerprints_returned: Literal[False] = False
    secrets_exposed: Literal[False] = False


class FixedRevalidationProtocolStatus(BaseModel):
    version: str
    locked: bool
    valid: bool
    strategy_count: int
    eligible_roles: list[str] = Field(default_factory=list)
    quality_gates_unchanged: bool = False
    evaluation_labels_accessed: Literal[False] = False
    digest_exposed: Literal[False] = False


class ManualAnchorReviewProgress(BaseModel):
    workspace: Literal["manual_anchors"] = "manual_anchors"
    available: bool
    prepared: bool
    integrity_status: Literal["valid", "not_prepared", "unavailable"]
    total: int = 0
    reviewed: int = 0
    remaining: int = 0
    invalid: int = 0
    progress_percent: float = 0.0
    revision: int = 0
    owner_assigned: bool = False
    owned_by_current_user: bool = False
    can_review: bool = False
    completed: bool = False
    closed: bool = False
    evaluation_ready: bool = False
    protocol_locked: bool = False
    protocol_valid: bool = False
    class_support: dict[str, int] = Field(default_factory=dict)
    minimum_class_support: dict[str, int] = Field(default_factory=dict)
    class_support_passed: bool = False
    coverage_counts: dict[str, int] = Field(default_factory=dict)
    coverage_strata: list[str] = Field(default_factory=list)
    next_pending_index: int | None = None
    message: str
    predictions_exposed: Literal[False] = False
    model_scores_exposed: Literal[False] = False
    assisted_labels_exposed: Literal[False] = False
    raw_logs_exposed: Literal[False] = False
    ip_addresses_exposed: Literal[False] = False
    source_identities_exposed: Literal[False] = False
    fingerprints_exposed: Literal[False] = False
    private_paths_exposed: Literal[False] = False
    reviewer_identity_exposed: Literal[False] = False
    import_ready: Literal[False] = False
    automatic_import_performed: Literal[False] = False
    model_activation_performed: Literal[False] = False
    response_action_performed: Literal[False] = False
    secrets_exposed: Literal[False] = False


class ManualAnchorReviewStatusResponse(BaseModel):
    version: str
    status: str
    protocol: FixedRevalidationProtocolStatus
    review: dict[str, Any]
    evaluation_attempted: bool = False
    evaluation_execution_count: int = 0
    metrics_available: bool = False
    diagnostic_leader: str | None = None
    leader_metrics: dict[str, Any] = Field(default_factory=dict)
    lifecycle_state: Literal["shadow_observation"] = "shadow_observation"
    rules_alert_authoritative: Literal[True] = True
    model_activated: Literal[False] = False
    model_promoted: Literal[False] = False
    response_automation_allowed: Literal[False] = False
    automatic_import_performed: Literal[False] = False
    predictions_exposed: Literal[False] = False
    raw_logs_exposed: Literal[False] = False
    private_paths_exposed: Literal[False] = False
    fingerprints_exposed: Literal[False] = False
    secrets_exposed: Literal[False] = False


class CombinedFixedRevalidationProtocolStatus(BaseModel):
    version: str
    locked: bool
    valid: bool
    immutable: bool
    strategy_count: int
    combined_rows: int
    contracts_unchanged: bool
    supplemental_evidence_threat_enriched: Literal[True] = True
    representative_of_production_prevalence: Literal[False] = False
    digest_exposed: Literal[False] = False


class CombinedFixedRevalidationStatusResponse(BaseModel):
    version: str
    status: str
    custody: dict[str, Any] = Field(default_factory=dict)
    protocol: CombinedFixedRevalidationProtocolStatus
    evaluation_attempted: bool = False
    evaluation_execution_count: int = 0
    metrics_available: bool = False
    strategy_count: int = 0
    evaluated_strategy_count: int = 0
    strategies: list[dict[str, Any]] = Field(default_factory=list)
    diagnostic_candidate: str | None = None
    diagnostic_candidate_qualified: bool = False
    selection_bias_notice: str
    lifecycle_state: Literal["shadow_observation"] = "shadow_observation"
    rules_alert_authoritative: Literal[True] = True
    model_activated: Literal[False] = False
    model_promoted: Literal[False] = False
    active_artifact_written: Literal[False] = False
    response_automation_allowed: Literal[False] = False
    real_firewall_blocking_enabled: Literal[False] = False
    labels_written: Literal[0] = 0
    model_runs_written: Literal[0] = 0
    detection_runs_written: Literal[0] = 0
    alerts_written: Literal[0] = 0
    response_actions_written: Literal[0] = 0
    predictions_exposed: Literal[False] = False
    raw_logs_exposed: Literal[False] = False
    ip_addresses_exposed: Literal[False] = False
    source_identities_exposed: Literal[False] = False
    private_paths_exposed: Literal[False] = False
    fingerprints_exposed: Literal[False] = False
    digests_exposed: Literal[False] = False
    secrets_exposed: Literal[False] = False


class ManualAnchorReviewExistingInput(BaseModel):
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


class ManualAnchorReviewItemResponse(BaseModel):
    workspace: Literal["manual_anchors"] = "manual_anchors"
    row_index: int
    display_position: int
    total: int
    revision: int
    reviewed: bool
    closed: bool
    coverage_stratum: str
    evidence: dict[str, str] = Field(default_factory=dict)
    existing_review: ManualAnchorReviewExistingInput | None = None
    next_pending_index: int | None = None
    predictions_exposed: Literal[False] = False
    model_scores_exposed: Literal[False] = False
    assisted_labels_exposed: Literal[False] = False
    raw_logs_exposed: Literal[False] = False
    ip_addresses_exposed: Literal[False] = False
    source_identities_exposed: Literal[False] = False
    fingerprints_exposed: Literal[False] = False
    private_paths_exposed: Literal[False] = False
    reviewer_identity_exposed: Literal[False] = False
    import_ready: Literal[False] = False
    automatic_import_performed: Literal[False] = False
    model_activation_performed: Literal[False] = False
    response_action_performed: Literal[False] = False
    secrets_exposed: Literal[False] = False


class ManualAnchorReviewListItem(BaseModel):
    row_index: int
    display_position: int
    reviewed: bool
    coverage_stratum: str
    evidence: dict[str, str] = Field(default_factory=dict)


class ManualAnchorReviewPageResponse(BaseModel):
    workspace: Literal["manual_anchors"] = "manual_anchors"
    offset: int
    limit: int
    filtered_total: int
    items: list[ManualAnchorReviewListItem] = Field(default_factory=list)
    predictions_exposed: Literal[False] = False
    raw_logs_exposed: Literal[False] = False
    private_paths_exposed: Literal[False] = False
    reviewer_identities_exposed: Literal[False] = False
    secrets_exposed: Literal[False] = False


class ManualAnchorReviewSaveRequest(BaseModel):
    expected_revision: int = Field(ge=0)
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


class ManualAnchorReviewCloseRequest(BaseModel):
    expected_revision: int = Field(ge=0)
    human_confirmed: Literal[True]


class ManualAnchorReviewOperationResponse(BaseModel):
    ok: bool = True
    workspace: Literal["manual_anchors"] = "manual_anchors"
    status: str
    revision: int
    progress: ManualAnchorReviewProgress
    next_item: ManualAnchorReviewItemResponse | None = None
    authoritative_mutations: dict[str, int] = Field(default_factory=dict)
    import_performed: Literal[False] = False
    model_activation_performed: Literal[False] = False
    response_action_performed: Literal[False] = False


class SupplementalThreatAnchorStatusResponse(BaseModel):
    version: str
    status: str
    generated_at: str | None = None
    original_review: dict[str, Any] = Field(default_factory=dict)
    selected_rows: int = 0
    target_rows: int = 60
    coverage_counts: dict[str, int] = Field(default_factory=dict)
    represented_threat_strata: int = 0
    threat_enriched_rows: int = 0
    coverage_gate_passed: bool = False
    exclusion_counts: dict[str, int] = Field(default_factory=dict)
    review: dict[str, Any] = Field(default_factory=dict)
    combined_support_visible: bool = False
    combined_class_support: dict[str, int] = Field(default_factory=dict)
    minimum_class_support: dict[str, int] = Field(default_factory=dict)
    combined_support_passed: bool = False
    ready_for_relocked_protocol: bool = False
    proposed_protocol_created: bool = False
    evaluation_execution_count: Literal[0] = 0
    evaluation_claim_created: Literal[False] = False
    evaluation_result_created: Literal[False] = False
    predictions_used_for_selection: Literal[False] = False
    predictions_exposed: Literal[False] = False
    assisted_labels_exposed: Literal[False] = False
    development_evidence_only: Literal[True] = True
    lifecycle_state: Literal["shadow_observation"] = "shadow_observation"
    rules_alert_authoritative: Literal[True] = True
    model_activated: Literal[False] = False
    model_promoted: Literal[False] = False
    response_automation_allowed: Literal[False] = False
    automatic_import_performed: Literal[False] = False
    raw_logs_exposed: Literal[False] = False
    ip_addresses_exposed: Literal[False] = False
    source_identities_exposed: Literal[False] = False
    private_paths_returned: Literal[False] = False
    fingerprints_returned: Literal[False] = False
    secrets_exposed: Literal[False] = False


class SupplementalThreatAnchorReviewProgress(BaseModel):
    workspace: Literal["supplemental_threat_anchors"] = (
        "supplemental_threat_anchors"
    )
    available: bool
    prepared: bool
    integrity_status: Literal["valid", "not_prepared", "unavailable"]
    total: int = 0
    reviewed: int = 0
    remaining: int = 0
    invalid: int = 0
    progress_percent: float = 0.0
    revision: int = 0
    owner_assigned: bool = False
    owned_by_current_user: bool = False
    can_review: bool = False
    completed: bool = False
    closed: bool = False
    combined_support_visible: bool = False
    combined_class_support: dict[str, int] = Field(default_factory=dict)
    minimum_class_support: dict[str, int] = Field(default_factory=dict)
    combined_support_passed: bool = False
    ready_for_relocked_protocol: bool = False
    proposed_protocol_created: bool = False
    coverage_counts: dict[str, int] = Field(default_factory=dict)
    coverage_strata: list[str] = Field(default_factory=list)
    next_pending_index: int | None = None
    evaluation_execution_count: Literal[0] = 0
    message: str
    predictions_exposed: Literal[False] = False
    model_scores_exposed: Literal[False] = False
    assisted_labels_exposed: Literal[False] = False
    raw_logs_exposed: Literal[False] = False
    ip_addresses_exposed: Literal[False] = False
    source_identities_exposed: Literal[False] = False
    fingerprints_exposed: Literal[False] = False
    private_paths_exposed: Literal[False] = False
    reviewer_identity_exposed: Literal[False] = False
    import_ready: Literal[False] = False
    automatic_import_performed: Literal[False] = False
    model_activation_performed: Literal[False] = False
    response_action_performed: Literal[False] = False
    secrets_exposed: Literal[False] = False


class SupplementalThreatAnchorReviewItemResponse(BaseModel):
    workspace: Literal["supplemental_threat_anchors"] = (
        "supplemental_threat_anchors"
    )
    row_index: int
    display_position: int
    total: int
    revision: int
    reviewed: bool
    closed: bool
    coverage_stratum: str
    evidence: dict[str, str] = Field(default_factory=dict)
    existing_review: ManualAnchorReviewExistingInput | None = None
    next_pending_index: int | None = None
    predictions_exposed: Literal[False] = False
    model_scores_exposed: Literal[False] = False
    assisted_labels_exposed: Literal[False] = False
    raw_logs_exposed: Literal[False] = False
    ip_addresses_exposed: Literal[False] = False
    source_identities_exposed: Literal[False] = False
    fingerprints_exposed: Literal[False] = False
    private_paths_exposed: Literal[False] = False
    reviewer_identity_exposed: Literal[False] = False
    import_ready: Literal[False] = False
    automatic_import_performed: Literal[False] = False
    model_activation_performed: Literal[False] = False
    response_action_performed: Literal[False] = False
    secrets_exposed: Literal[False] = False


class SupplementalThreatAnchorReviewListItem(BaseModel):
    row_index: int
    display_position: int
    reviewed: bool
    coverage_stratum: str
    evidence: dict[str, str] = Field(default_factory=dict)


class SupplementalThreatAnchorReviewPageResponse(BaseModel):
    workspace: Literal["supplemental_threat_anchors"] = (
        "supplemental_threat_anchors"
    )
    offset: int
    limit: int
    filtered_total: int
    items: list[SupplementalThreatAnchorReviewListItem] = Field(
        default_factory=list
    )
    predictions_exposed: Literal[False] = False
    raw_logs_exposed: Literal[False] = False
    private_paths_exposed: Literal[False] = False
    reviewer_identities_exposed: Literal[False] = False
    secrets_exposed: Literal[False] = False


class SupplementalThreatAnchorReviewOperationResponse(BaseModel):
    ok: bool = True
    workspace: Literal["supplemental_threat_anchors"] = (
        "supplemental_threat_anchors"
    )
    status: str
    revision: int
    progress: SupplementalThreatAnchorReviewProgress
    next_item: SupplementalThreatAnchorReviewItemResponse | None = None
    authoritative_mutations: dict[str, int] = Field(default_factory=dict)
    evaluation_execution_count: Literal[0] = 0
    evaluation_claim_created: Literal[False] = False
    import_performed: Literal[False] = False
    model_activation_performed: Literal[False] = False
    response_action_performed: Literal[False] = False


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
