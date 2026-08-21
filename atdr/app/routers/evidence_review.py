from __future__ import annotations

from typing import NoReturn

from fastapi import APIRouter, Depends, HTTPException
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
    DetectionReviewItemResponse,
    DetectionReviewSaveRequest,
    EvidenceReviewCompleteRequest,
    EvidenceReviewOperationResponse,
    EvidenceReviewStatusResponse,
    FrozenEvaluationStatusResponse,
)
from atdr.app.detection.v541_governed_blind_evidence import (
    V541EvidenceError,
    get_public_blind_evidence_status,
)
from atdr.app.detection.v542_development_candidate_freeze import (
    V542FreezeError,
    get_public_candidate_freeze_status,
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
