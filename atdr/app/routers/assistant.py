from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from atdr.app.core.config import Settings, get_settings
from atdr.app.core.security import require_analyst_or_admin
from atdr.app.db.database import get_db
from atdr.app.db.models import User
from atdr.app.schemas.assistant import (
    AssistantChatRequest,
    AssistantChatResponse,
    AssistantFeedbackItem,
    AssistantFeedbackRequest,
    AssistantFeedbackSummary,
    AssistantHistoryItem,
    AssistantStatusResponse,
)
from atdr.app.services.assistant_service import (
    answer_assistant_question,
    assistant_feedback_summary,
    assistant_status,
    list_assistant_feedback,
    list_assistant_history,
    submit_assistant_feedback,
)

router = APIRouter(prefix="/api/assistant", tags=["assistant"])


@router.get("/status", response_model=AssistantStatusResponse)
def get_assistant_status(
    settings: Settings = Depends(get_settings),
    current_user: User = Depends(require_analyst_or_admin),
) -> dict:
    """Return safe assistant configuration status without exposing secrets."""
    return assistant_status(settings)


@router.post("/chat", response_model=AssistantChatResponse)
def ask_assistant(
    request: AssistantChatRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
    settings: Settings = Depends(get_settings),
) -> dict:
    """Answer an analyst question using read-only ATDR context."""
    return answer_assistant_question(
        db,
        question=request.question,
        actor=current_user.username,
        settings=settings,
        alert_id=request.alert_id,
        log_id=request.log_id,
        source_id=request.source_id,
        case_id=request.case_id,
        include_recent_context=request.include_recent_context,
    )


@router.get("/history", response_model=list[AssistantHistoryItem])
def get_assistant_history(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
    limit: int = 20,
) -> list[dict]:
    """Return recent assistant audit summaries without raw logs or secrets."""
    return list_assistant_history(db, limit=limit)


@router.post("/feedback", response_model=AssistantFeedbackItem)
def create_assistant_feedback(
    request: AssistantFeedbackRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
) -> dict:
    """Record analyst feedback on an assistant answer without executing actions."""
    try:
        return submit_assistant_feedback(
            db,
            current_user=current_user,
            question=request.question,
            rating=request.rating,
            answer=request.answer,
            feedback_note=request.feedback_note,
            context_type=request.context_type,
            context_reference=request.context_reference,
            external_provider_used=request.external_provider_used,
            raw_log_context_included=request.raw_log_context_included,
            action_requested=request.action_requested,
            assistant_audit_id=request.assistant_audit_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/feedback/summary", response_model=AssistantFeedbackSummary)
def get_assistant_feedback_summary(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
    rating: str | None = Query(default=None, max_length=32),
    context_type: str | None = Query(default=None, max_length=64),
    since_days: int | None = Query(default=None, ge=1, le=365),
) -> dict:
    """Return safe assistant answer-quality counts without raw logs or secrets."""
    try:
        return assistant_feedback_summary(
            db,
            current_user=current_user,
            rating=rating,
            context_type=context_type,
            since_days=since_days,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/feedback/recent", response_model=list[AssistantFeedbackItem])
def get_recent_assistant_feedback(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
    limit: int = 20,
    rating: str | None = Query(default=None, max_length=32),
    context_type: str | None = Query(default=None, max_length=64),
    since_days: int | None = Query(default=None, ge=1, le=365),
) -> list[dict]:
    """Return recent assistant feedback scoped by role."""
    try:
        return list_assistant_feedback(
            db,
            current_user=current_user,
            limit=limit,
            rating=rating,
            context_type=context_type,
            since_days=since_days,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
