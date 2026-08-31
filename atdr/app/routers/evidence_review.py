from __future__ import annotations

from typing import Literal, NoReturn

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from atdr.app.core.config import Settings, get_settings
from atdr.app.core.security import require_analyst_or_admin
from atdr.app.db.database import get_db
from atdr.app.db.models import AuditLog, User
from atdr.app.schemas.evidence_review import (
    AssistantReviewItemResponse,
    AssistantReviewSaveRequest,
    BlindEvidenceStatusResponse,
    CandidateFreezeStatusResponse,
    CombinedFixedRevalidationStatusResponse,
    DevelopmentModelRepairStatusResponse,
    DetectionReviewItemResponse,
    DetectionReviewSaveRequest,
    EvidenceReviewCompleteRequest,
    EvidenceReviewOperationResponse,
    EvidenceReviewStatusResponse,
    FrozenEvaluationStatusResponse,
    ManualAnchorAcquisitionStatusResponse,
    ManualAnchorReviewCloseRequest,
    ManualAnchorReviewItemResponse,
    ManualAnchorReviewOperationResponse,
    ManualAnchorReviewPageResponse,
    ManualAnchorReviewProgress,
    ManualAnchorReviewSaveRequest,
    ManualAnchorReviewStatusResponse,
    ManualAnchorTransferStatusResponse,
    SupplementalThreatAnchorReviewItemResponse,
    SupplementalThreatAnchorReviewOperationResponse,
    SupplementalThreatAnchorReviewPageResponse,
    SupplementalThreatAnchorReviewProgress,
    SupplementalThreatAnchorStatusResponse,
    TemporalStabilityStatusResponse,
)
from atdr.app.detection.v541_governed_blind_evidence import (
    V541EvidenceError,
    get_public_blind_evidence_status,
)
from atdr.app.detection.v542_development_candidate_freeze import (
    V542FreezeError,
    get_public_candidate_freeze_status,
)
from atdr.app.detection.v543_temporal_stability_repair import (
    V543RepairError,
    get_public_temporal_stability_status,
)
from atdr.app.detection.v545_development_model_repair import (
    V545RepairError,
    get_public_v545_status,
)
from atdr.app.detection.v546_manual_anchor_transfer_repair import (
    V546TransferRepairError,
    get_public_v546_status,
)
from atdr.app.detection.v547_manual_anchor_acquisition import (
    V547AcquisitionError,
    get_public_v547_status,
)
from atdr.app.detection.v548_manual_anchor_fixed_revalidation import (
    V548RevalidationError,
    get_public_v548_status,
)
from atdr.app.detection.v549a_supplemental_threat_anchor_acquisition import (
    V549ASupplementalAcquisitionError,
    get_public_v549a_status,
)
from atdr.app.detection.v549b_combined_fixed_revalidation import (
    V549BRevalidationError,
    get_public_v549b_status,
)
from atdr.app.services.evidence_review_service import (
    EvidenceReviewError,
    EvidenceReviewIntegrityError,
    complete_evidence_review,
    get_assistant_review_item,
    get_detection_review_item,
    get_evidence_review_status,
    save_assistant_review_item,
    save_detection_review_item,
    start_assistant_review,
    start_detection_review,
)
from atdr.app.services.v539_independent_evidence_decision_service import (
    get_v539_evaluation_status,
)
from atdr.app.services.v548_manual_anchor_review_service import (
    close_manual_anchor_review,
    get_manual_anchor_review_item,
    get_manual_anchor_review_status,
    list_manual_anchor_review_items,
    save_manual_anchor_review_item,
    start_manual_anchor_review,
)
from atdr.app.services.v549a_supplemental_threat_anchor_review_service import (
    close_supplemental_review,
    get_supplemental_review_item,
    get_supplemental_review_status,
    list_supplemental_review_items,
    save_supplemental_review_item,
    start_supplemental_review,
)


router = APIRouter(prefix="/api/evidence-review", tags=["evidence-review"])


def _audit(
    db: Session,
    current_user: User,
    *,
    action: str,
    workspace: str,
    row_index: int | None = None,
    revision: int | None = None,
    reason_code: str | None = None,
) -> None:
    details: dict[str, object] = {
        "workspace": workspace,
        "human_review_workflow": True,
        "predictions_exposed": False,
        "raw_logs_exposed": False,
        "automatic_import": False,
        "model_activation": False,
        "response_action": False,
    }
    if row_index is not None:
        details["row_index"] = row_index
    if revision is not None:
        details["revision"] = revision
    if reason_code:
        details["reason_code"] = reason_code
    db.add(
        AuditLog(
            actor=current_user.username,
            action=action,
            target_type="evidence_review_workspace",
            target_value=workspace,
            details=details,
        )
    )
    db.commit()


def _raise_review_error(
    db: Session,
    current_user: User,
    error: EvidenceReviewError,
    *,
    workspace: str,
    row_index: int | None = None,
) -> NoReturn:
    _audit(
        db,
        current_user,
        action=(
            "evidence_review_integrity_failed"
            if isinstance(error, EvidenceReviewIntegrityError)
            else "evidence_review_rejected"
        ),
        workspace=workspace,
        row_index=row_index,
        reason_code=error.code,
    )
    raise HTTPException(
        status_code=error.status_code,
        detail=error.public_message,
    ) from error


@router.get("/status", response_model=EvidenceReviewStatusResponse)
def evidence_review_status(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
    settings: Settings = Depends(get_settings),
) -> dict:
    try:
        return get_evidence_review_status(current_user, settings=settings)
    except EvidenceReviewError as exc:
        _raise_review_error(db, current_user, exc, workspace="aggregate")


@router.get(
    "/evaluation-status",
    response_model=FrozenEvaluationStatusResponse,
)
def frozen_evaluation_status(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
    settings: Settings = Depends(get_settings),
) -> dict:
    try:
        return get_v539_evaluation_status(settings=settings)
    except EvidenceReviewError as exc:
        _raise_review_error(db, current_user, exc, workspace="evaluation")


@router.get(
    "/blind-evidence/status",
    response_model=BlindEvidenceStatusResponse,
)
def blind_evidence_status(
    current_user: User = Depends(require_analyst_or_admin),
) -> dict:
    del current_user
    try:
        return get_public_blind_evidence_status()
    except V541EvidenceError as exc:
        raise HTTPException(
            status_code=409,
            detail="The private blind-evidence workspace failed integrity validation.",
        ) from exc


@router.get(
    "/candidate-freeze/status",
    response_model=CandidateFreezeStatusResponse,
)
def candidate_freeze_status(
    current_user: User = Depends(require_analyst_or_admin),
) -> dict:
    del current_user
    try:
        return get_public_candidate_freeze_status()
    except V542FreezeError as exc:
        raise HTTPException(
            status_code=409,
            detail="The private candidate-freeze workspace failed integrity validation.",
        ) from exc


@router.get(
    "/temporal-stability/status",
    response_model=TemporalStabilityStatusResponse,
)
def temporal_stability_status(
    current_user: User = Depends(require_analyst_or_admin),
) -> dict:
    del current_user
    try:
        return get_public_temporal_stability_status()
    except V543RepairError as exc:
        raise HTTPException(
            status_code=409,
            detail="The private temporal-stability workspace failed integrity validation.",
        ) from exc


@router.get(
    "/development-model-repair/status",
    response_model=DevelopmentModelRepairStatusResponse,
)
def development_model_repair_status(
    current_user: User = Depends(require_analyst_or_admin),
) -> dict:
    del current_user
    try:
        return get_public_v545_status()
    except V545RepairError as exc:
        raise HTTPException(
            status_code=409,
            detail="The private development-repair workspace failed integrity validation.",
        ) from exc


@router.get(
    "/manual-anchor-transfer/status",
    response_model=ManualAnchorTransferStatusResponse,
)
def manual_anchor_transfer_status(
    current_user: User = Depends(require_analyst_or_admin),
) -> dict:
    del current_user
    try:
        return get_public_v546_status()
    except V546TransferRepairError as exc:
        raise HTTPException(
            status_code=409,
            detail="The private transfer-repair workspace failed integrity validation.",
        ) from exc


@router.get(
    "/manual-anchor-acquisition/status",
    response_model=ManualAnchorAcquisitionStatusResponse,
)
def manual_anchor_acquisition_status(
    current_user: User = Depends(require_analyst_or_admin),
) -> dict:
    del current_user
    try:
        return get_public_v547_status()
    except V547AcquisitionError as exc:
        raise HTTPException(
            status_code=409,
            detail="The private manual-anchor workspace failed integrity validation.",
        ) from exc


@router.get(
    "/manual-anchors/revalidation-status",
    response_model=ManualAnchorReviewStatusResponse,
)
def manual_anchor_revalidation_status(
    current_user: User = Depends(require_analyst_or_admin),
) -> dict:
    del current_user
    try:
        return get_public_v548_status()
    except (V547AcquisitionError, V548RevalidationError) as exc:
        raise HTTPException(
            status_code=409,
            detail="The fixed manual-anchor protocol failed integrity validation.",
        ) from exc


@router.get(
    "/combined-manual-anchors/revalidation-status",
    response_model=CombinedFixedRevalidationStatusResponse,
)
def combined_manual_anchor_revalidation_status(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
) -> dict:
    try:
        result = get_public_v549b_status()
    except V549BRevalidationError as exc:
        _audit(
            db,
            current_user,
            action="evidence_review_integrity_failed",
            workspace="combined_manual_anchor_revalidation",
            reason_code="combined_fixed_revalidation_status_invalid",
        )
        raise HTTPException(
            status_code=409,
            detail="The combined fixed-revalidation status failed integrity validation.",
        ) from exc
    _audit(
        db,
        current_user,
        action="combined_fixed_revalidation_status_viewed",
        workspace="combined_manual_anchor_revalidation",
    )
    return result


@router.get(
    "/manual-anchors/status",
    response_model=ManualAnchorReviewProgress,
)
def manual_anchor_review_status(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
) -> dict:
    try:
        return get_manual_anchor_review_status(current_user)
    except EvidenceReviewError as exc:
        _raise_review_error(db, current_user, exc, workspace="manual_anchors")


@router.post(
    "/manual-anchors/start",
    response_model=ManualAnchorReviewOperationResponse,
)
def start_manual_anchor_workspace(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
) -> dict:
    try:
        result = start_manual_anchor_review(current_user)
    except EvidenceReviewError as exc:
        _raise_review_error(db, current_user, exc, workspace="manual_anchors")
    _audit(
        db,
        current_user,
        action="manual_anchor_review_started",
        workspace="manual_anchors",
        revision=int(result["revision"]),
    )
    return result


@router.get(
    "/manual-anchors/items",
    response_model=ManualAnchorReviewPageResponse,
)
def manual_anchor_review_items(
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=20, ge=1, le=100),
    coverage_stratum: str | None = Query(default=None, max_length=120),
    review_state: Literal["all", "pending", "reviewed"] = "all",
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
) -> dict:
    try:
        return list_manual_anchor_review_items(
            current_user,
            offset=offset,
            limit=limit,
            coverage_stratum=coverage_stratum,
            review_state=review_state,
        )
    except EvidenceReviewError as exc:
        _raise_review_error(db, current_user, exc, workspace="manual_anchors")


@router.get(
    "/manual-anchors/items/{row_index}",
    response_model=ManualAnchorReviewItemResponse,
)
def manual_anchor_review_item(
    row_index: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
) -> dict:
    try:
        return get_manual_anchor_review_item(
            current_user,
            row_index=row_index,
        )
    except EvidenceReviewError as exc:
        _raise_review_error(
            db,
            current_user,
            exc,
            workspace="manual_anchors",
            row_index=row_index,
        )


@router.post(
    "/manual-anchors/items/{row_index}",
    response_model=ManualAnchorReviewOperationResponse,
)
def save_manual_anchor_workspace_item(
    row_index: int,
    request: ManualAnchorReviewSaveRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
) -> dict:
    try:
        result = save_manual_anchor_review_item(
            current_user,
            row_index=row_index,
            expected_revision=request.expected_revision,
            decision=request.decision,
            attack_type=request.attack_type,
            confidence=request.confidence,
            rationale=request.rationale,
        )
    except EvidenceReviewError as exc:
        _raise_review_error(
            db,
            current_user,
            exc,
            workspace="manual_anchors",
            row_index=row_index,
        )
    _audit(
        db,
        current_user,
        action="manual_anchor_review_saved",
        workspace="manual_anchors",
        row_index=row_index,
        revision=int(result["revision"]),
    )
    return result


@router.post(
    "/manual-anchors/close",
    response_model=ManualAnchorReviewOperationResponse,
)
def close_manual_anchor_workspace(
    request: ManualAnchorReviewCloseRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
) -> dict:
    try:
        result = close_manual_anchor_review(
            current_user,
            expected_revision=request.expected_revision,
        )
    except EvidenceReviewError as exc:
        _raise_review_error(db, current_user, exc, workspace="manual_anchors")
    _audit(
        db,
        current_user,
        action="manual_anchor_review_closed",
        workspace="manual_anchors",
        revision=int(result["revision"]),
    )
    return result


@router.get(
    "/supplemental-threat-anchors/acquisition-status",
    response_model=SupplementalThreatAnchorStatusResponse,
)
def supplemental_threat_anchor_acquisition_status(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
) -> dict:
    try:
        result = get_public_v549a_status()
    except V549ASupplementalAcquisitionError as exc:
        _audit(
            db,
            current_user,
            action="evidence_review_integrity_failed",
            workspace="supplemental_threat_anchors",
            reason_code="supplemental_anchor_status_invalid",
        )
        raise HTTPException(
            status_code=409,
            detail="The supplemental threat-anchor workspace failed integrity validation.",
        ) from exc
    _audit(
        db,
        current_user,
        action="supplemental_anchor_status_viewed",
        workspace="supplemental_threat_anchors",
    )
    return result


@router.get(
    "/supplemental-threat-anchors/status",
    response_model=SupplementalThreatAnchorReviewProgress,
)
def supplemental_threat_anchor_review_status(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
) -> dict:
    try:
        result = get_supplemental_review_status(current_user)
    except EvidenceReviewError as exc:
        _raise_review_error(
            db,
            current_user,
            exc,
            workspace="supplemental_threat_anchors",
        )
    _audit(
        db,
        current_user,
        action="supplemental_anchor_review_status_viewed",
        workspace="supplemental_threat_anchors",
        revision=int(result["revision"]),
    )
    return result


@router.post(
    "/supplemental-threat-anchors/start",
    response_model=SupplementalThreatAnchorReviewOperationResponse,
)
def start_supplemental_threat_anchor_workspace(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
) -> dict:
    try:
        result = start_supplemental_review(current_user)
    except EvidenceReviewError as exc:
        _raise_review_error(
            db,
            current_user,
            exc,
            workspace="supplemental_threat_anchors",
        )
    _audit(
        db,
        current_user,
        action="supplemental_anchor_review_started",
        workspace="supplemental_threat_anchors",
        revision=int(result["revision"]),
    )
    return result


@router.get(
    "/supplemental-threat-anchors/items",
    response_model=SupplementalThreatAnchorReviewPageResponse,
)
def supplemental_threat_anchor_review_items(
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=20, ge=1, le=100),
    coverage_stratum: str | None = Query(default=None, max_length=120),
    review_state: Literal["all", "pending", "reviewed"] = "all",
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
) -> dict:
    try:
        return list_supplemental_review_items(
            current_user,
            offset=offset,
            limit=limit,
            coverage_stratum=coverage_stratum,
            review_state=review_state,
        )
    except EvidenceReviewError as exc:
        _raise_review_error(
            db,
            current_user,
            exc,
            workspace="supplemental_threat_anchors",
        )


@router.get(
    "/supplemental-threat-anchors/items/{row_index}",
    response_model=SupplementalThreatAnchorReviewItemResponse,
)
def supplemental_threat_anchor_review_item(
    row_index: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
) -> dict:
    try:
        return get_supplemental_review_item(current_user, row_index=row_index)
    except EvidenceReviewError as exc:
        _raise_review_error(
            db,
            current_user,
            exc,
            workspace="supplemental_threat_anchors",
            row_index=row_index,
        )


@router.post(
    "/supplemental-threat-anchors/items/{row_index}",
    response_model=SupplementalThreatAnchorReviewOperationResponse,
)
def save_supplemental_threat_anchor_workspace_item(
    row_index: int,
    request: ManualAnchorReviewSaveRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
) -> dict:
    try:
        result = save_supplemental_review_item(
            current_user,
            row_index=row_index,
            expected_revision=request.expected_revision,
            decision=request.decision,
            attack_type=request.attack_type,
            confidence=request.confidence,
            rationale=request.rationale,
        )
    except EvidenceReviewError as exc:
        _raise_review_error(
            db,
            current_user,
            exc,
            workspace="supplemental_threat_anchors",
            row_index=row_index,
        )
    _audit(
        db,
        current_user,
        action="supplemental_anchor_review_saved",
        workspace="supplemental_threat_anchors",
        row_index=row_index,
        revision=int(result["revision"]),
    )
    return result


@router.post(
    "/supplemental-threat-anchors/close",
    response_model=SupplementalThreatAnchorReviewOperationResponse,
)
def close_supplemental_threat_anchor_workspace(
    request: ManualAnchorReviewCloseRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
) -> dict:
    try:
        result = close_supplemental_review(
            current_user,
            expected_revision=request.expected_revision,
        )
    except EvidenceReviewError as exc:
        _raise_review_error(
            db,
            current_user,
            exc,
            workspace="supplemental_threat_anchors",
        )
    _audit(
        db,
        current_user,
        action="supplemental_anchor_review_closed",
        workspace="supplemental_threat_anchors",
        revision=int(result["revision"]),
    )
    return result


@router.post(
    "/detection/start",
    response_model=EvidenceReviewOperationResponse,
)
def start_detection_workspace(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
    settings: Settings = Depends(get_settings),
) -> dict:
    try:
        result = start_detection_review(current_user, settings=settings)
    except EvidenceReviewError as exc:
        _raise_review_error(db, current_user, exc, workspace="detection")
    _audit(
        db,
        current_user,
        action="evidence_review_started",
        workspace="detection",
        revision=int(result["revision"]),
    )
    return result


@router.get(
    "/detection/items/{row_index}",
    response_model=DetectionReviewItemResponse,
)
def detection_review_item(
    row_index: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
) -> dict:
    try:
        return get_detection_review_item(current_user, row_index=row_index)
    except EvidenceReviewError as exc:
        _raise_review_error(
            db,
            current_user,
            exc,
            workspace="detection",
            row_index=row_index,
        )


@router.post(
    "/detection/items/{row_index}",
    response_model=EvidenceReviewOperationResponse,
)
def save_detection_workspace_item(
    row_index: int,
    request: DetectionReviewSaveRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
) -> dict:
    try:
        result = save_detection_review_item(
            current_user,
            row_index=row_index,
            expected_revision=request.expected_revision,
            decision_group=request.decision_group,
            decision=request.decision,
            attack_type=request.attack_type,
            confidence=request.confidence,
            rationale=request.rationale,
        )
    except (EvidenceReviewError, ValueError) as exc:
        error = (
            exc
            if isinstance(exc, EvidenceReviewError)
            else EvidenceReviewError(
                "review_contract_rejected",
                "The human decision did not satisfy the sealed review contract.",
                status_code=422,
            )
        )
        _raise_review_error(
            db,
            current_user,
            error,
            workspace="detection",
            row_index=row_index,
        )
    _audit(
        db,
        current_user,
        action="evidence_review_saved",
        workspace="detection",
        row_index=row_index,
        revision=int(result["revision"]),
    )
    return result


@router.post(
    "/detection/complete",
    response_model=EvidenceReviewOperationResponse,
)
def complete_detection_workspace(
    request: EvidenceReviewCompleteRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
    settings: Settings = Depends(get_settings),
) -> dict:
    try:
        result = complete_evidence_review(
            current_user,
            workspace_name="detection",
            expected_revision=request.expected_revision,
            settings=settings,
        )
    except EvidenceReviewError as exc:
        _raise_review_error(db, current_user, exc, workspace="detection")
    _audit(
        db,
        current_user,
        action="evidence_review_completed",
        workspace="detection",
        revision=int(result["revision"]),
    )
    return result


@router.post(
    "/assistant/start",
    response_model=EvidenceReviewOperationResponse,
)
def start_assistant_workspace(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
    settings: Settings = Depends(get_settings),
) -> dict:
    try:
        result = start_assistant_review(
            db,
            current_user,
            settings=settings,
        )
    except EvidenceReviewError as exc:
        _raise_review_error(db, current_user, exc, workspace="assistant")
    _audit(
        db,
        current_user,
        action="evidence_review_started",
        workspace="assistant",
        revision=int(result["revision"]),
    )
    return result


@router.get(
    "/assistant/items/{row_index}",
    response_model=AssistantReviewItemResponse,
)
def assistant_review_item(
    row_index: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
    settings: Settings = Depends(get_settings),
) -> dict:
    try:
        return get_assistant_review_item(
            current_user,
            row_index=row_index,
            settings=settings,
        )
    except EvidenceReviewError as exc:
        _raise_review_error(
            db,
            current_user,
            exc,
            workspace="assistant",
            row_index=row_index,
        )


@router.post(
    "/assistant/items/{row_index}",
    response_model=EvidenceReviewOperationResponse,
)
def save_assistant_workspace_item(
    row_index: int,
    request: AssistantReviewSaveRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
    settings: Settings = Depends(get_settings),
) -> dict:
    try:
        result = save_assistant_review_item(
            current_user,
            row_index=row_index,
            expected_revision=request.expected_revision,
            scores=request.scores.model_dump(),
            overall_decision=request.overall_decision,
            notes=request.notes,
            settings=settings,
        )
    except EvidenceReviewError as exc:
        _raise_review_error(
            db,
            current_user,
            exc,
            workspace="assistant",
            row_index=row_index,
        )
    _audit(
        db,
        current_user,
        action=(
            "evidence_review_rejected"
            if request.overall_decision == "reject"
            else "evidence_review_saved"
        ),
        workspace="assistant",
        row_index=row_index,
        revision=int(result["revision"]),
    )
    return result


@router.post(
    "/assistant/complete",
    response_model=EvidenceReviewOperationResponse,
)
def complete_assistant_workspace(
    request: EvidenceReviewCompleteRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
    settings: Settings = Depends(get_settings),
) -> dict:
    try:
        result = complete_evidence_review(
            current_user,
            workspace_name="assistant",
            expected_revision=request.expected_revision,
            settings=settings,
        )
    except EvidenceReviewError as exc:
        _raise_review_error(db, current_user, exc, workspace="assistant")
    _audit(
        db,
        current_user,
        action="evidence_review_completed",
        workspace="assistant",
        revision=int(result["revision"]),
    )
    return result
