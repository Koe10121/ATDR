from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from atdr.app.core.config import PROJECT_ROOT, Settings
from atdr.app.db.models import Alert, AssistantFeedback, AuditLog, DetectionRun, NormalizedLog, OperationJob, User
from atdr.app.detection.supervised_detector import supervised_model_report
from atdr.app.detection.explanations import build_alert_detection_summary, explain_log_triage
from atdr.app.services.case_service import list_alert_cases
from atdr.app.services.alert_service import get_alert, list_alerts
from atdr.app.services.assistant_llm import AssistantLLMRequest, maybe_generate_external_answer
from atdr.app.services.job_service import build_job_summary, job_to_dict
from atdr.app.services.log_service import get_log
from atdr.app.services.ml_service import evaluation_report
from atdr.app.services.operation_run_service import detection_run_to_dict
from atdr.app.services.source_service import get_source, list_sources, source_to_dict


IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
ALERT_ID_PATTERN = re.compile(r"\b(?:alert|id|#)\s*#?\s*(\d{1,10})\b", re.IGNORECASE)
LOG_ID_PATTERN = re.compile(r"\b(?:log|row|event)\s*#?\s*(\d{1,10})\b", re.IGNORECASE)
SOURCE_ID_PATTERN = re.compile(r"\b(?:source|sensor)\s*#?\s*(\d{1,10})\b", re.IGNORECASE)
CASE_ID_PATTERN = re.compile(r"\bcase\s*#?\s*([a-zA-Z0-9_-]{4,120})\b", re.IGNORECASE)

ALERT_EXPLANATION_TERMS = [
    "why",
    "flagged",
    "alert",
    "evidence supports",
    "rule contributed",
    "model contributed",
    "false positive",
    "noise",
    "evidence is missing",
    "missing evidence",
    "compare this alert",
    "attack mapping",
    "att&ck",
    "not automatically blocked",
    "automatic block",
]

ALERT_RELATED_LOG_TERMS = [
    "related log",
    "related logs",
    "logs are related",
    "what logs",
    "show logs",
    "linked logs",
    "evidence logs",
]

ALERT_NEXT_STEP_TERMS = [
    "recommended next step",
    "recommend next step",
    "next step",
    "next steps",
    "what should",
    "verify before response",
    "verify before",
    "analyst verify",
    "check next",
    "check first",
    "do next",
    "safe to approve",
    "safe to respond",
    "safely respond",
    "approve response",
    "response safe",
]


@dataclass
class Citation:
    label: str
    source: str
    reference_id: str | None = None


@dataclass
class AssistantResult:
    answer: str
    context_used: list[str]
    citations: list[Citation]
    details: dict[str, Any] = field(default_factory=dict)
    suggested_followups: list[str] = field(default_factory=list)


def _redact(value: Any, *, enabled: bool) -> Any:
    if not enabled:
        return value
    if isinstance(value, str):
        return IP_PATTERN.sub("[redacted-ip]", value)
    if isinstance(value, list):
        return [_redact(item, enabled=enabled) for item in value]
    if isinstance(value, dict):
        return {key: _redact(item, enabled=enabled) for key, item in value.items()}
    return value


def _text(value: Any, *, redacted: bool) -> str:
    return str(_redact(value, enabled=redacted))


def _without_raw_context(value: Any) -> Any:
    raw_keys = {"raw_line", "raw_line_excerpt", "raw_log", "raw_log_line"}
    if isinstance(value, list):
        return [_without_raw_context(item) for item in value]
    if isinstance(value, dict):
        return {
            key: _without_raw_context(item)
            for key, item in value.items()
            if key not in raw_keys
        }
    return value


def _question_alert_id(question: str, explicit_alert_id: int | None) -> int | None:
    match = ALERT_ID_PATTERN.search(question)
    if match:
        try:
            return int(match.group(1))
        except ValueError:
            return explicit_alert_id
    return explicit_alert_id


def _question_log_id(question: str, explicit_log_id: int | None = None) -> int | None:
    match = LOG_ID_PATTERN.search(question)
    if match:
        try:
            return int(match.group(1))
        except ValueError:
            return explicit_log_id
    return explicit_log_id


def _question_source_id(question: str, explicit_source_id: int | None = None) -> int | None:
    match = SOURCE_ID_PATTERN.search(question)
    if match:
        try:
            return int(match.group(1))
        except ValueError:
            return explicit_source_id
    return explicit_source_id


def _question_case_id(question: str, explicit_case_id: str | None = None) -> str | None:
    match = CASE_ID_PATTERN.search(question)
    if match:
        return match.group(1).strip()[:120] or None
    if explicit_case_id:
        value = explicit_case_id.strip()
        return value[:120] if value else None
    return None


def _has_any_term(value: str, terms: list[str]) -> bool:
    return any(term in value for term in terms)


def _is_alert_related_log_followup(value: str) -> bool:
    return _has_any_term(value, ALERT_RELATED_LOG_TERMS)


def _is_alert_next_step_followup(value: str) -> bool:
    return _has_any_term(value, ALERT_NEXT_STEP_TERMS)


def _is_alert_explanation_followup(value: str) -> bool:
    return _has_any_term(value, ALERT_EXPLANATION_TERMS)


def _record_assistant_audit(
    db: Session,
    *,
    actor: str,
    question: str,
    context_used: list[str],
    external_provider_used: bool,
    redaction_applied: bool,
) -> int:
    audit = AuditLog(
        actor=actor,
        action="assistant_question",
        target_type="assistant",
        target_value=question.strip()[:255] or "empty-question",
        details={
            "context_used": context_used,
            "external_provider_used": external_provider_used,
            "redaction_applied": redaction_applied,
            "raw_log_context_included": False,
        },
    )
    db.add(audit)
    db.commit()
    return int(audit.id)


def _llm_answer_guard_reason(
    *,
    deterministic_answer: str,
    provider_answer: str | None,
    context_used: list[str],
) -> str | None:
    """Reject external wording that drops too much ATDR evidence or implies action."""
    answer = (provider_answer or "").strip()
    if not answer:
        return "empty_provider_answer"

    lowered = answer.lower()
    unsafe_action_phrases = [
        "i blocked",
        "i have blocked",
        "i ran detection",
        "i have run detection",
        "i deleted",
        "i changed the label",
        "i activated the model",
        "i promoted the model",
        "firewall rule has been",
        "containment has been applied",
    ]
    if any(phrase in lowered for phrase in unsafe_action_phrases):
        return "provider_answer_implies_action_execution"

    deterministic_length = len(deterministic_answer.strip())
    if deterministic_length >= 400 and len(answer) < 180:
        return "provider_answer_too_short_for_evidence_context"

    if "alert_detail" in context_used and not any(token in lowered for token in ["alert", "flagged", "evidence"]):
        return "provider_answer_lost_alert_context"

    return None


def assistant_status(settings: Settings) -> dict[str, Any]:
    llm_provider_name = settings.assistant_llm_provider.strip().lower()
    legacy_external_configured = bool(
        settings.assistant_enabled
        and settings.assistant_provider.strip().lower() not in {"", "disabled", "none"}
        and settings.assistant_api_key.strip()
    )
    llm_configured = bool(
        settings.assistant_llm_enabled
        and settings.assistant_llm_provider.strip()
        and (settings.assistant_llm_api_key.strip() or llm_provider_name == "mock")
    )
    external_configured = legacy_external_configured or llm_configured
    provider = "disabled"
    if llm_configured:
        provider = settings.assistant_llm_provider.strip()
    elif legacy_external_configured:
        provider = settings.assistant_provider.strip()
    return {
        "available": True,
        "mode": "deterministic_local" if not external_configured else "external_llm_configured",
        "external_provider_configured": external_configured,
        "external_provider_used_by_default": False,
        "provider": provider,
        "model_configured": bool(settings.assistant_model.strip() or settings.assistant_llm_model.strip()),
        "llm_enabled": settings.assistant_llm_enabled,
        "llm_provider_configured": bool(settings.assistant_llm_provider.strip()),
        "llm_provider_name": settings.assistant_llm_provider.strip(),
        "llm_ready": llm_configured,
        "llm_model_configured": bool(settings.assistant_llm_model.strip()),
        "llm_secret_configured": bool(settings.assistant_llm_api_key.strip()),
        "llm_base_url_configured": bool(settings.assistant_llm_base_url.strip()),
        "llm_timeout_seconds": settings.assistant_llm_timeout_seconds,
        "llm_secrets_exposed": False,
        "redaction_enabled": settings.assistant_redact_ips,
        "raw_log_context_allowed": settings.assistant_allow_raw_log_context,
        "max_context_rows": settings.assistant_max_context_rows,
        "safety": _safety_notes(),
    }


def list_assistant_history(db: Session, *, limit: int = 20) -> list[dict[str, Any]]:
    statement = (
        select(AuditLog)
        .where(AuditLog.action == "assistant_question")
        .order_by(desc(AuditLog.created_at), desc(AuditLog.id))
        .limit(max(1, min(limit, 100)))
    )
    rows = []
    for item in db.scalars(statement):
        details = item.details or {}
        question = item.target_value or ""
        rows.append(
            {
                "id": item.id,
                "actor": item.actor,
                "question": question[:160],
                "created_at": item.created_at.isoformat() if item.created_at is not None else "",
                "context_used": details.get("context_used") if isinstance(details.get("context_used"), list) else [],
                "external_provider_used": bool(details.get("external_provider_used", False)),
            }
        )
    return rows


def _safety_notes() -> list[str]:
    return [
        "Read Only",
        "Decision Support Only",
        "Response Automation Disabled",
        "Simulation Mode",
        "No real firewall blocking",
        "External LLM disabled unless explicitly configured",
    ]


def _is_how_to_question(lowered: str) -> bool:
    return any(
        phrase in lowered
        for phrase in [
            "how do i",
            "how to",
            "what command",
            "show me how",
            "instructions",
            "help me understand",
            "explain how",
        ]
    )


def _unsafe_action_requested(lowered: str) -> bool:
    if _is_how_to_question(lowered):
        return False
    unsafe_phrases = [
        "block this ip",
        "block ip",
        "block the ip",
        "unblock",
        "delete log",
        "delete logs",
        "delete alert",
        "delete data",
        "remove logs",
        "run detection",
        "start detection",
        "trigger detection",
        "activate model",
        "activate the model",
        "promote model",
        "promote the model",
        "change label",
        "change labels",
        "update label",
        "update labels",
        "send email",
        "send verification",
        "expose raw log",
        "expose raw logs",
        "show raw log",
        "show raw logs",
        "send raw log",
        "send raw logs",
        "create user",
        "delete user",
        "disable user",
        "change user",
        "change account",
        "enable automation",
        "turn on automation",
        "enable response",
        "turn on response",
        "real firewall",
    ]
    command_prefixes = ["can you ", "please ", "do ", "execute ", "run ", "start ", "trigger "]
    return any(phrase in lowered for phrase in unsafe_phrases) and (
        any(lowered.startswith(prefix) for prefix in command_prefixes)
        or any(term in lowered for term in [" now", " for me", " this ", " please", "?"])
    )


def _brief_requested(lowered: str) -> bool:
    return any(
        term in lowered
        for term in [
            "investigation brief",
            "create brief",
            "brief for",
            "brief builder",
            "summarize this investigation",
            "for my report",
            "tell my supervisor",
            "supervisor about this alert",
            "advisor summary",
            "mention to my advisor",
            "evidence should i mention",
            "executive evidence summary",
            "leadership brief",
        ]
    )


def answer_assistant_question(
    db: Session,
    *,
    question: str,
    actor: str,
    settings: Settings,
    alert_id: int | None = None,
    log_id: int | None = None,
    source_id: int | None = None,
    case_id: str | None = None,
    include_recent_context: bool = True,
) -> dict[str, Any]:
    clean_question = question.strip()
    lowered = clean_question.lower()
    context_limit = min(max(1, settings.assistant_max_context_rows), 50)
    redacted = settings.assistant_redact_ips
    requested_alert_id = _question_alert_id(clean_question, alert_id)
    requested_log_id = _question_log_id(clean_question, log_id)
    requested_source_id = _question_source_id(clean_question, source_id)

    if not clean_question:
        result = AssistantResult(
            answer="Ask a question about alerts, source health, operations, ML governance, or ATDR workflow.",
            context_used=[],
            citations=[],
            suggested_followups=["What is the latest critical alert?", "Summarize source health."],
        )
    elif _brief_requested(lowered):
        result = _answer_investigation_brief(
            db,
            clean_question,
            alert_id=_question_alert_id(clean_question, alert_id),
            log_id=requested_log_id,
            source_id=requested_source_id,
            case_id=_question_case_id(clean_question, case_id),
            limit=context_limit,
            redacted=redacted,
        )
    elif any(
        term in lowered
        for term in [
            "safe scenario",
            "demo scenario",
            "controlled validation scenario",
            "controlled scenario",
            "run scenario",
            "source scenario",
        ]
    ):
        result = _answer_scenario_help(redacted=redacted)
    elif any(term in lowered for term in ["import reviewed", "reviewed labels", "label import", "import labels"]):
        result = _answer_reviewed_label_import_help(redacted=redacted)
    elif _unsafe_action_requested(lowered):
        result = _answer_unsafe_action_refusal(clean_question, redacted=redacted)
    elif any(term in lowered for term in ["response safety", "safety rules", "can assistant block", "can the assistant block", "can chatbot block"]):
        result = _answer_response_safety(redacted=redacted)
    elif any(term in lowered for term in ["changed recently", "what changed", "recent changes"]):
        result = _answer_recent_changes(db, limit=context_limit, redacted=redacted)
    elif any(term in lowered for term in ["failed job", "failed jobs", "job failure"]):
        result = _answer_failed_jobs(db, settings=settings, redacted=redacted)
    elif any(
        term in lowered
        for term in [
            "supervised output contract",
            "safe supervised",
            "supervised ml output",
            "ml output safe",
            "model output safe",
            "queue score",
            "soc review queue",
            "exact severity",
            "exact label",
            "exact labels",
            "ml trigger response",
            "model trigger response",
            "ml trigger automatic response",
            "can ml classify severity",
            "can the model classify exact severity",
        ]
    ):
        result = _answer_supervised_output_policy(redacted=redacted)
    elif any(
        term in lowered
        for term in [
            "queue evidence",
            "evidence agreement",
            "ml agree",
            "model agree",
            "agree with rules",
            "rule hybrid",
            "rule/hybrid",
            "hybrid evidence",
        ]
    ):
        result = _answer_queue_evidence_agreement(redacted=redacted)
    elif any(term in lowered for term in ["not production promoted", "production promoted", "why model", "promotion"]):
        result = _answer_model_promotion_question(db, redacted=redacted)
    elif any(term in lowered for term in ["detection run", "detection runs", "recent detection"]):
        result = _answer_detection_runs_question(db, redacted=redacted)
    elif any(term in lowered for term in ["open alerts", "latest critical alerts", "critical alerts", "show alerts"]):
        result = _answer_alert_list_question(db, question=clean_question, redacted=redacted)
    elif any(term in lowered for term in ["case", "alert group", "related alert group"]) or case_id:
        result = _answer_case_question(
            db,
            case_id=_question_case_id(clean_question, case_id),
            source_id=source_id,
            limit=context_limit,
            redacted=redacted,
        )
    elif requested_alert_id and _is_alert_related_log_followup(lowered):
        result = _answer_alert_question(db, clean_question, alert_id=requested_alert_id, redacted=redacted)
    elif requested_alert_id and _is_alert_next_step_followup(lowered):
        result = _answer_safe_next_steps(db, clean_question, alert_id=requested_alert_id, redacted=redacted)
    elif requested_alert_id and _is_alert_explanation_followup(lowered):
        result = _answer_alert_question(db, clean_question, alert_id=requested_alert_id, redacted=redacted)
    elif requested_log_id and "log" in lowered and not _is_alert_related_log_followup(lowered):
        result = _answer_log_triage_question(db, clean_question, log_id=requested_log_id, redacted=redacted)
    elif requested_source_id and any(term in lowered for term in ["source", "sensor", "syslog", "parser", "health", "check next", "safe next"]):
        result = _answer_source_question(db, source_id=requested_source_id, limit=context_limit, redacted=redacted, warnings_only="warning" in lowered or "error" in lowered)
    elif _is_alert_next_step_followup(lowered):
        result = _answer_safe_next_steps(db, clean_question, alert_id=requested_alert_id, redacted=redacted)
    elif requested_log_id and ("log" in lowered or ("flagged" in lowered and requested_alert_id is None)):
        result = _answer_log_triage_question(db, clean_question, log_id=requested_log_id, redacted=redacted)
    elif _is_alert_explanation_followup(lowered) or alert_id:
        result = _answer_alert_question(db, clean_question, alert_id=requested_alert_id, redacted=redacted)
    elif any(term in lowered for term in ["source", "sensor", "syslog", "parser", "health"]) or requested_source_id:
        result = _answer_source_question(db, source_id=requested_source_id, limit=context_limit, redacted=redacted, warnings_only="warning" in lowered or "error" in lowered)
    elif any(term in lowered for term in ["job", "operation", "detection run", "ingestion run", "stale"]):
        result = _answer_operations_question(db, settings=settings, redacted=redacted)
    elif any(term in lowered for term in ["ml", "model", "ai", "governance", "label", "anomaly"]):
        result = _answer_ml_question(db, redacted=redacted)
    elif any(term in lowered for term in ["import logs", "import log", "add logs", "load logs"]):
        result = _answer_import_logs_help(redacted=redacted)
    elif any(term in lowered for term in ["replay", "import", "run detection", "detection", "start", "command", "how do i"]):
        result = _answer_workflow_question(redacted=redacted)
    else:
        result = _answer_general_question(db, limit=context_limit if include_recent_context else 0, redacted=redacted)

    _ensure_answer_sections(result)
    response = {
        "answer": result.answer,
        "mode": "deterministic_local",
        "external_provider_used": False,
        "safety": _safety_notes(),
        "context_used": result.context_used,
        "citations": [
            {"label": citation.label, "source": citation.source, "reference_id": citation.reference_id}
            for citation in result.citations
        ],
        "redaction_applied": redacted,
        "raw_log_context_included": False,
        "suggested_followups": result.suggested_followups,
        "details": result.details,
    }
    llm_result = maybe_generate_external_answer(
        AssistantLLMRequest(
            question=clean_question,
            deterministic_answer=response["answer"],
            context_used=response["context_used"],
            citations=response["citations"],
            suggested_followups=response["suggested_followups"],
            safety=response["safety"],
        ),
        settings,
    )
    llm_guard_reason = _llm_answer_guard_reason(
        deterministic_answer=response["answer"],
        provider_answer=llm_result.answer,
        context_used=response["context_used"],
    ) if llm_result.used else None
    if settings.assistant_llm_enabled or settings.assistant_llm_provider.strip():
        response["details"]["llm"] = {
            **llm_result.safe_details(),
            "provider_called": bool(llm_result.used),
            "answer_used": bool(llm_result.used and llm_result.answer and not llm_guard_reason),
            "answer_guard_reason": llm_guard_reason,
        }
    if llm_result.used and llm_result.answer and not llm_guard_reason:
        response["answer"] = llm_result.answer
        response["mode"] = f"external_llm_{llm_result.provider}"
        response["external_provider_used"] = True
        response["raw_log_context_included"] = llm_result.raw_log_context_included
        response["context_used"] = [*response["context_used"], f"external_llm:{llm_result.provider}"]
    elif llm_result.used:
        response["mode"] = f"deterministic_local_llm_guarded_{llm_result.provider}"
        response["external_provider_used"] = True
        response["raw_log_context_included"] = llm_result.raw_log_context_included
        response["context_used"] = [*response["context_used"], f"external_llm_guarded:{llm_result.provider}"]
    audit_id = _record_assistant_audit(
        db,
        actor=actor,
        question=clean_question,
        context_used=response["context_used"],
        external_provider_used=bool(response["external_provider_used"]),
        redaction_applied=redacted,
    )
    response["details"]["assistant_audit_id"] = audit_id
    return response


ALLOWED_FEEDBACK_RATINGS = {"helpful", "not_helpful", "unsafe", "incorrect", "unclear"}
REVIEW_RECOMMENDED_FEEDBACK_RATINGS = {"not_helpful", "unsafe", "incorrect", "unclear"}
HIGH_PRIORITY_FEEDBACK_RATINGS = {"unsafe", "incorrect"}


def _compact_text(value: str | None, *, limit: int) -> str | None:
    if value is None:
        return None
    compact = " ".join(value.strip().split())
    if not compact:
        return None
    return compact[:limit]


def _feedback_to_dict(item: AssistantFeedback) -> dict[str, Any]:
    review_recommended = item.rating in REVIEW_RECOMMENDED_FEEDBACK_RATINGS
    return {
        "feedback_id": item.id,
        "created_at": item.created_at.isoformat() if item.created_at is not None else "",
        "actor_user_id": item.actor_user_id,
        "actor_username": item.actor_username,
        "question": item.question,
        "answer_summary": item.answer_summary,
        "answer_hash": item.answer_hash,
        "context_type": item.context_type,
        "context_reference": item.context_reference,
        "rating": item.rating,
        "feedback_note": item.feedback_note,
        "external_provider_used": item.external_provider_used,
        "raw_log_context_included": item.raw_log_context_included,
        "action_requested": item.action_requested,
        "action_executed": item.action_executed,
        "assistant_audit_id": item.assistant_audit_id,
        "review_recommended": review_recommended,
        "review_reason": (
            "Review recommended for unsafe/incorrect assistant feedback."
            if item.rating in HIGH_PRIORITY_FEEDBACK_RATINGS
            else "Review recommended for answer-quality improvement."
            if review_recommended
            else None
        ),
    }


def _scoped_feedback_statement(current_user: User):
    statement = select(AssistantFeedback)
    if current_user.role != "admin":
        statement = statement.where(AssistantFeedback.actor_user_id == current_user.id)
    return statement


def _filtered_feedback_statement(
    current_user: User,
    *,
    rating: str | None = None,
    context_type: str | None = None,
    since_days: int | None = None,
):
    normalized_rating = _compact_text(rating, limit=32)
    normalized_context = _compact_text(context_type, limit=64)
    statement = _scoped_feedback_statement(current_user)
    if normalized_rating:
        normalized_rating = normalized_rating.lower()
        if normalized_rating not in ALLOWED_FEEDBACK_RATINGS:
            raise ValueError("Invalid assistant feedback rating filter.")
        statement = statement.where(AssistantFeedback.rating == normalized_rating)
    if normalized_context:
        statement = statement.where(AssistantFeedback.context_type == normalized_context.lower())
    if since_days is not None:
        safe_days = max(1, min(int(since_days), 365))
        statement = statement.where(AssistantFeedback.created_at >= datetime.now(UTC) - timedelta(days=safe_days))
    return statement, normalized_rating, normalized_context


def submit_assistant_feedback(
    db: Session,
    *,
    current_user: User,
    question: str,
    rating: str,
    answer: str | None = None,
    feedback_note: str | None = None,
    context_type: str | None = None,
    context_reference: str | None = None,
    external_provider_used: bool = False,
    raw_log_context_included: bool = False,
    action_requested: bool | None = None,
    assistant_audit_id: int | None = None,
) -> dict[str, Any]:
    normalized_rating = rating.strip().lower()
    if normalized_rating not in ALLOWED_FEEDBACK_RATINGS:
        raise ValueError("Invalid assistant feedback rating.")
    clean_question = _compact_text(question, limit=2000) or "empty-question"
    clean_answer = _compact_text(answer, limit=800)
    answer_hash_source = answer or clean_question
    requested_action = _unsafe_action_requested(clean_question.lower()) if action_requested is None else bool(action_requested)
    item = AssistantFeedback(
        actor_user_id=current_user.id,
        actor_username=current_user.username,
        question=clean_question,
        answer_summary=clean_answer,
        answer_hash=hashlib.sha256(answer_hash_source.encode("utf-8")).hexdigest(),
        context_type=_compact_text(context_type, limit=64),
        context_reference=_compact_text(context_reference, limit=255),
        rating=normalized_rating,
        feedback_note=_compact_text(feedback_note, limit=500),
        external_provider_used=bool(external_provider_used),
        raw_log_context_included=bool(raw_log_context_included),
        action_requested=requested_action,
        action_executed=False,
        assistant_audit_id=assistant_audit_id,
    )
    db.add(item)
    db.flush()
    db.add(
        AuditLog(
            actor=current_user.username,
            action="assistant_feedback_submitted",
            target_type="assistant_feedback",
            target_value=str(item.id),
            details={
                "rating": item.rating,
                "context_type": item.context_type,
                "context_reference": item.context_reference,
                "external_provider_used": item.external_provider_used,
                "raw_log_context_included": item.raw_log_context_included,
                "action_requested": item.action_requested,
                "action_executed": False,
                "assistant_audit_id": assistant_audit_id,
            },
        )
    )
    db.commit()
    return _feedback_to_dict(item)


def list_assistant_feedback(
    db: Session,
    *,
    current_user: User,
    limit: int = 20,
    rating: str | None = None,
    context_type: str | None = None,
    since_days: int | None = None,
) -> list[dict[str, Any]]:
    statement, _, _ = _filtered_feedback_statement(
        current_user,
        rating=rating,
        context_type=context_type,
        since_days=since_days,
    )
    statement = statement.order_by(desc(AssistantFeedback.created_at), desc(AssistantFeedback.id))
    statement = statement.limit(max(1, min(limit, 100)))
    return [_feedback_to_dict(item) for item in db.scalars(statement)]


def assistant_feedback_summary(
    db: Session,
    *,
    current_user: User,
    rating: str | None = None,
    context_type: str | None = None,
    since_days: int | None = None,
) -> dict[str, Any]:
    statement, normalized_rating, normalized_context = _filtered_feedback_statement(
        current_user,
        rating=rating,
        context_type=context_type,
        since_days=since_days,
    )
    rows = list(db.scalars(statement))
    counts = {rating: 0 for rating in sorted(ALLOWED_FEEDBACK_RATINGS)}
    for item in rows:
        counts[item.rating] = counts.get(item.rating, 0) + 1
    recent = sorted(rows, key=lambda item: (item.created_at, item.id), reverse=True)[:5]
    unsafe_or_incorrect = [
        item
        for item in sorted(rows, key=lambda row: (row.created_at, row.id), reverse=True)
        if item.rating in HIGH_PRIORITY_FEEDBACK_RATINGS
    ]
    needs_review_count = sum(1 for item in rows if item.rating in REVIEW_RECOMMENDED_FEEDBACK_RATINGS)
    return {
        "total_count": len(rows),
        "rating_counts": counts,
        "unsafe_or_incorrect_count": len(unsafe_or_incorrect),
        "needs_review_count": needs_review_count,
        "external_provider_used_count": sum(1 for item in rows if item.external_provider_used),
        "raw_log_context_included_count": sum(1 for item in rows if item.raw_log_context_included),
        "action_requested_count": sum(1 for item in rows if item.action_requested),
        "action_executed_count": sum(1 for item in rows if item.action_executed),
        "latest_unsafe_or_incorrect": [_feedback_to_dict(item) for item in unsafe_or_incorrect[:5]],
        "recent": [_feedback_to_dict(item) for item in recent],
        "scope": "all" if current_user.role == "admin" else "own",
        "filtered_rating": normalized_rating,
        "filtered_context_type": normalized_context,
        "filtered_since_days": since_days,
        "review_warning": needs_review_count > 0,
        "secrets_exposed": False,
    }


def _answer_alert_list_question(db: Session, *, question: str, redacted: bool) -> AssistantResult:
    lowered = question.lower()
    severity = "Critical" if "critical" in lowered else None
    alerts = list_alerts(db, severity=severity, status="open", sort_by="updated", limit=5)
    if not alerts:
        label = "critical " if severity else ""
        answer = (
            f"No open {label}alerts were found in the current context.\n\n"
            "What to do next\n"
            "- Open Alerts to confirm current filters.\n"
            "- Run a controlled validation scenario if you need representative local evidence.\n"
            "- Ask about source health or recent operations to verify ingestion and detection status.\n\n"
            "Controlled validation command\n"
            "`.\\.venv\\Scripts\\python.exe -m atdr.scripts.run_source_scenario --scenario port_scan_like_traffic --source-name controlled-validation-firewall --source-type firewall --parser-profile palo_alto --run-detection --pretty`"
        )
        return AssistantResult(
            answer=_text(answer, redacted=redacted),
            context_used=["alerts", "controlled_validation_fallback"],
            citations=[
                Citation("Alerts API", "/api/alerts"),
                Citation("Controlled validation runner", "atdr/scripts/run_source_scenario.py"),
                Citation("Lab runbook", "docs/LAB_RUNBOOK.md"),
            ],
            details={
                "answer_sections": {
                    "summary": [f"No open {label}alerts were found."],
                    "what_to_check_next": ["Open Alerts.", "Run a controlled validation scenario if local evidence is needed.", "Summarize source health."],
                    "safe_next_steps": ["Use the controlled validation runner; it does not enable response automation."],
                    "safety_note": ["No response action was executed.", "Real firewall blocking remains disabled."],
                }
            },
            suggested_followups=["How do I run a controlled validation scenario?", "Summarize source health.", "What changed recently?"],
        )
    singular_latest = (
        ("latest critical alert" in lowered and "latest critical alerts" not in lowered)
        or "summarize the latest" in lowered
    )
    if severity and singular_latest:
        return _answer_alert_question(db, question, alert_id=alerts[0].id, redacted=redacted)
    parts = [
        f"#{alert.id} {alert.severity} {alert.alert_type} score {alert.threat_score} status {alert.status}"
        for alert in alerts
    ]
    answer = (
        f"Latest open {'critical ' if severity else ''}alerts: "
        + "; ".join(parts)
        + ". Review the alert detail and Why flagged panel before any simulated response."
    )
    return AssistantResult(
        answer=_text(answer, redacted=redacted),
        context_used=["alerts", "alert_summary"],
        citations=[Citation("Alerts API", "/api/alerts"), *[Citation("Alert", "/api/alerts/{alert_id}", str(alert.id)) for alert in alerts]],
        details={"alerts": _redact([{"id": a.id, "severity": a.severity, "alert_type": a.alert_type, "status": a.status, "src_ip": a.src_ip, "dst_ip": a.dst_ip} for a in alerts], enabled=redacted)},
        suggested_followups=[
            f"Why was alert {alerts[0].id} flagged?",
            f"What logs are related to alert {alerts[0].id}?",
            f"What should an analyst verify before response for alert {alerts[0].id}?",
        ],
    )


def _group_metadata(alert: Alert) -> dict[str, Any]:
    for rule in alert.matched_rules_json or []:
        if isinstance(rule, dict) and rule.get("code") == "group_metadata":
            return rule
    return {}


def _alert_source_rows(alert: Alert) -> list[dict[str, Any]]:
    rows: dict[int, dict[str, Any]] = {}
    for item in alert.evidence:
        log = item.normalized_log
        raw = getattr(log, "raw_log", None) if log is not None else None
        source = getattr(raw, "source", None) if raw is not None else None
        if source is None:
            continue
        rows[source.id] = {
            "source_id": source.id,
            "name": source.name,
            "source_type": source.source_type,
            "parser_profile": source.parser_profile,
            "enabled": source.enabled,
            "parse_success_count": source.parse_success_count,
            "parse_failure_count": source.parse_failure_count,
            "latest_error": source.latest_error,
        }
    return list(rows.values())


def _alert_parser_notes(alert: Alert) -> list[str]:
    notes: list[str] = []
    for item in alert.evidence:
        log = item.normalized_log
        parsed = log.parsed_json if log is not None and isinstance(log.parsed_json, dict) else {}
        warnings = parsed.get("parser_warnings")
        if isinstance(warnings, list):
            notes.extend(str(warning) for warning in warnings[:4])
        parser_error = parsed.get("parser_error")
        if parser_error:
            notes.append(str(parser_error))
    return list(dict.fromkeys(notes))[:6]


def _safe_log_context(log: NormalizedLog) -> dict[str, Any]:
    raw = getattr(log, "raw_log", None)
    source = getattr(raw, "source", None) if raw is not None else None
    return {
        "id": log.id,
        "generated_time": log.generated_time.isoformat() if log.generated_time is not None else None,
        "receive_time": log.receive_time.isoformat() if log.receive_time is not None else None,
        "src_ip": log.src_ip,
        "dst_ip": log.dst_ip,
        "src_port": log.src_port,
        "dst_port": log.dst_port,
        "app": log.app,
        "action": log.action,
        "protocol": log.protocol,
        "app_risk": log.app_risk,
        "is_anomaly": log.is_anomaly,
        "anomaly_score": log.anomaly_score,
        "source_id": source.id if source is not None else None,
        "source_name": source.name if source is not None else None,
        "source_type": source.source_type if source is not None else None,
        "parser_profile": source.parser_profile if source is not None else None,
    }


def _alert_related_log_rows(alert: Alert, *, limit: int = 8) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for item in alert.evidence[:limit]:
        log = item.normalized_log
        if log is None:
            continue
        rows.append(_safe_log_context(log))
    return rows


def _log_alert_rows(log: NormalizedLog) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for item in log.alert_evidence:
        alert = item.alert
        if alert is None:
            continue
        rows.append(
            {
                "id": alert.id,
                "title": alert.title,
                "severity": alert.severity,
                "status": alert.status,
                "alert_type": alert.alert_type,
                "threat_score": alert.threat_score,
            }
        )
    return rows[:8]


def _alert_response_history(alert: Alert) -> list[dict[str, Any]]:
    return [
        {
            "id": action.id,
            "action_type": action.action_type,
            "target_ip": action.target_ip,
            "status": action.status,
            "result_message": action.result_message,
            "executed_by": action.executed_by,
            "executed_at": action.executed_at.isoformat() if action.executed_at is not None else None,
        }
        for action in sorted(alert.response_actions, key=lambda item: (item.executed_at, item.id))[:10]
    ]


def _top_rule_names(alert: Alert, detection_summary: dict[str, Any]) -> list[str]:
    names = [str(item) for item in detection_summary.get("matched_rule_names") or [] if item]
    if names:
        return names[:8]
    fallback = []
    for rule in alert.matched_rules_json or []:
        if not isinstance(rule, dict) or rule.get("code") == "group_metadata":
            continue
        fallback.append(str(rule.get("title") or rule.get("name") or rule.get("code") or "rule"))
    return fallback[:8]


def _markdown_list(items: list[Any], *, fallback: str = "-") -> str:
    clean = [str(item) for item in items if str(item).strip()]
    if not clean:
        return f"- {fallback}"
    return "\n".join(f"- {item}" for item in clean)


def _citation_reference(citation: Citation) -> str:
    suffix = f" #{citation.reference_id}" if citation.reference_id else ""
    return f"{citation.label}: {citation.source}{suffix}"


def _first_answer_lines(answer: str, *, limit: int = 3) -> list[str]:
    lines: list[str] = []
    for raw_line in answer.splitlines():
        line = raw_line.strip()
        if not line or line.lower() in {"summary", "evidence", "safe next steps", "analyst next steps"}:
            continue
        lines.append(line.removeprefix("- ").strip())
        if len(lines) >= limit:
            break
    return lines or ["Read-only ATDR assistant response generated from available system context."]


def _contains_weak_or_missing(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, str):
        return value.strip().lower() in {"", "-", "unknown", "none", "null", "n/a"}
    return False


def _confidence_from_evidence(
    *,
    threat_score: int | float | None,
    evidence_count: int,
    related_log_count: int,
    rule_count: int,
    anomaly_present: bool,
    parser_note_count: int,
) -> str:
    score = float(threat_score or 0)
    if score >= 85 and (evidence_count >= 5 or related_log_count >= 5) and rule_count >= 1 and parser_note_count == 0:
        return "high confidence"
    if score >= 60 and (evidence_count >= 2 or rule_count >= 1 or anomaly_present):
        return "moderate confidence"
    return "low confidence / needs review"


def _alert_false_positive_notes(
    alert: Alert,
    *,
    related_log_rows: list[dict[str, Any]],
    parser_notes: list[str],
    rule_names: list[str],
    detection_summary: dict[str, Any],
    related_log_count: int,
) -> list[str]:
    notes: list[str] = []
    apps = {str(row.get("app") or "").lower() for row in related_log_rows}
    actions = {str(row.get("action") or "").lower() for row in related_log_rows}
    if {"", "unknown", "incomplete", "not-applicable", "unknown-tcp"} & apps:
        notes.append("Unknown or incomplete app values can create noisy triage signals; review parser/source quality before escalating.")
    if any("allow" in action for action in actions) and len(rule_names) <= 1:
        notes.append("Allowed traffic with limited rule evidence can be a false-positive candidate unless behavior-window evidence supports escalation.")
    if parser_notes:
        notes.append("Parser warnings or fallback fields reduce confidence in exact classification.")
    if related_log_count <= 1:
        notes.append("Low related-log support means this may need neighboring traffic review before containment.")
    if not rule_names:
        notes.append("No named rule is available, so the analyst should verify whether anomaly/ML evidence alone is enough.")
    source_rows = _alert_source_rows(alert)
    if any(str((row.get("latest_error") or "")).strip() for row in source_rows):
        notes.append("Linked source has parser/data-quality errors that can increase noise.")
    supervised = detection_summary.get("supervised") or {}
    predicted = str(supervised.get("predicted_label") or "").lower()
    if predicted in {"benign", "benign_unusual", "needs_context"}:
        notes.append(f"Supervised decision-support signal is {predicted}; treat the rule/model disagreement as review-required.")
    return list(dict.fromkeys(notes))[:6]


def _alert_missing_evidence_notes(
    alert: Alert,
    *,
    source_rows: list[dict[str, Any]],
    related_log_rows: list[dict[str, Any]],
    detection_summary: dict[str, Any],
) -> list[str]:
    missing: list[str] = []
    if _contains_weak_or_missing(alert.src_ip):
        missing.append("Source IP is missing or unknown.")
    if _contains_weak_or_missing(alert.dst_ip):
        missing.append("Destination IP is missing or unknown.")
    if not related_log_rows:
        missing.append("No related normalized-log rows are available in the assistant context.")
    if not source_rows:
        missing.append("No linked log source is available for this alert.")
    if not (detection_summary.get("matched_rule_names") or []):
        missing.append("Named rule evidence is missing.")
    if not (detection_summary.get("attack_mapping") or {}).get("technique_id"):
        missing.append("ATT&CK technique mapping is incomplete.")
    if not missing:
        missing.append("No major evidence gaps were visible in the compact assistant context.")
    return missing[:6]


def _checklist_for_alert(*, parser_notes: list[str], related_log_rows: list[dict[str, Any]]) -> list[str]:
    checks = [
        "Inspect related logs and verify whether the same source repeats the behavior.",
        "Check destination IP spread, destination ports, and action distribution.",
        "Compare rule evidence with anomaly/ML decision-support signals.",
        "Check source health and parser quality before trusting missing fields.",
        "Review case/group context and previous similar alerts.",
        "Use simulated response only after confirmation and justification.",
        "Verify protected-IP checks before any simulated response approval.",
    ]
    if parser_notes:
        checks.insert(0, "Resolve parser warnings or raw-fallback notes before making a containment decision.")
    if not related_log_rows:
        checks.insert(0, "Find neighboring logs for the same source/destination/time window before escalating.")
    return checks[:7]


def _ensure_answer_sections(result: AssistantResult) -> None:
    if isinstance(result.details.get("answer_sections"), dict):
        sections = result.details["answer_sections"]
        if "risk_interpretation" not in sections:
            sections["risk_interpretation"] = sections.get("why_flagged_or_not") or sections.get("evidence") or []
        if "what_to_check_next" not in sections:
            sections["what_to_check_next"] = sections.get("safe_next_steps") or result.suggested_followups[:4]
        if "safety_note" not in sections:
            sections["safety_note"] = sections.get("safety_limitation") or [
                "Read-only assistant response.",
                "Response automation is disabled.",
            ]
        return
    result.details["answer_sections"] = {
        "summary": _first_answer_lines(result.answer),
        "evidence": [
            f"Context used: {', '.join(result.context_used) or 'none'}",
            *[_citation_reference(citation) for citation in result.citations[:6]],
        ],
        "risk_interpretation": [
            "Evidence is limited to the available ATDR context; analyst review is required before response.",
        ],
        "what_to_check_next": result.suggested_followups[:4] or ["Open the relevant dashboard page and review evidence before action."],
        "safe_next_steps": result.suggested_followups[:4] or ["Open the relevant dashboard page and review evidence before action."],
        "safety_note": [
            "Read-only assistant response.",
            "Response automation is disabled.",
            "No detection, label, model, data, email, or firewall action was executed.",
        ],
        "safety_limitation": [
            "Read-only assistant response.",
            "Response automation is disabled.",
            "No detection, label, model, data, email, or firewall action was executed.",
        ],
        "citations": [_citation_reference(citation) for citation in result.citations[:8]],
    }


def _answer_alert_question(db: Session, question: str, *, alert_id: int | None, redacted: bool) -> AssistantResult:
    alert = get_alert(db, alert_id) if alert_id is not None else None
    if alert is None:
        alerts = list_alerts(db, severity="Critical", status="open", sort_by="score", limit=1)
        alert = alerts[0] if alerts else None
    if alert is None:
        answer = (
            "No matching alert was found for that request. Provide an alert ID or run the controlled port-scan validation scenario first.\n\n"
            "What to do next\n"
            "- Open Alerts and choose an alert ID.\n"
            "- Ask `Explain alert <id>`.\n"
            "- Or run a controlled validation scenario to create representative local evidence.\n\n"
            "Controlled validation command\n"
            "`.\\.venv\\Scripts\\python.exe -m atdr.scripts.run_source_scenario --scenario port_scan_like_traffic --source-name controlled-validation-firewall --source-type firewall --parser-profile palo_alto --run-detection --pretty`"
        )
        return AssistantResult(
            answer=_text(answer, redacted=redacted),
            context_used=["alerts", "controlled_validation_fallback"],
            citations=[
                Citation("Alerts API", "atdr/app/routers/alerts.py"),
                Citation("Controlled validation runner", "atdr/scripts/run_source_scenario.py"),
                Citation("Lab runbook", "docs/LAB_RUNBOOK.md"),
            ],
            details={
                "answer_sections": {
                    "summary": ["No matching alert was found."],
                    "what_to_check_next": ["Open Alerts and choose an alert ID.", "Ask about source health.", "Run a controlled validation scenario if local evidence is needed."],
                    "safe_next_steps": ["Use safe synthetic validation scenarios only; no automatic response is triggered."],
                    "safety_note": ["No response action was executed.", "No detection or model run was triggered by the assistant."],
                }
            },
            suggested_followups=["How do I run a controlled validation scenario?", "Summarize source health.", "Summarize recent operations."],
        )
    detection_summary = build_alert_detection_summary(db, alert)
    attack_mapping = detection_summary.get("attack_mapping") or {}
    group_metadata = _group_metadata(alert)
    source_rows = _alert_source_rows(alert)
    parser_notes = _alert_parser_notes(alert)
    related_log_rows = _alert_related_log_rows(alert)
    response_history = _alert_response_history(alert)
    occurrence_count = group_metadata.get("occurrence_count") or group_metadata.get("evidence_count") or len(alert.evidence)
    related_log_count = group_metadata.get("related_log_count") or group_metadata.get("evidence_count") or len(alert.evidence)
    rule_names = _top_rule_names(alert, detection_summary)
    evidence_points = [str(item) for item in detection_summary.get("top_evidence_points") or [] if item]
    related_log_points = [
        (
            f"Log {row['id']}: {row.get('action') or 'unknown-action'} "
            f"{row.get('app') or 'unknown-app'} to port {row.get('dst_port') or '-'} "
            f"from source {row.get('source_name') or 'unlinked source'}"
        )
        for row in related_log_rows[:5]
    ]
    detection_sources = [str(item) for item in detection_summary.get("detection_source") or ["rule"]]
    source_names = [str(row["name"]) for row in source_rows if row.get("name")]
    supervised = detection_summary.get("supervised") or {}
    anomaly = detection_summary.get("anomaly") or {}
    confidence_label = _confidence_from_evidence(
        threat_score=alert.threat_score,
        evidence_count=len(alert.evidence),
        related_log_count=int(related_log_count or 0),
        rule_count=len(rule_names),
        anomaly_present=bool(anomaly.get("present")),
        parser_note_count=len(parser_notes),
    )
    false_positive_notes = _alert_false_positive_notes(
        alert,
        related_log_rows=related_log_rows,
        parser_notes=parser_notes,
        rule_names=rule_names,
        detection_summary=detection_summary,
        related_log_count=int(related_log_count or 0),
    )
    missing_evidence_notes = _alert_missing_evidence_notes(
        alert,
        source_rows=source_rows,
        related_log_rows=related_log_rows,
        detection_summary=detection_summary,
    )
    risk_interpretation = [
        f"Evidence strength: {confidence_label}.",
        f"This alert matters because {detection_summary.get('why_flagged') or alert.explanation or 'ATDR found threat-like evidence that needs analyst review.'}",
        f"Rule evidence: {'present' if rule_names else 'missing or unnamed'}.",
        f"Anomaly evidence: {'present' if anomaly.get('present') else 'not present in the compact context'}.",
        f"Supervised signal: {supervised.get('predicted_label') or 'not available'} with confidence {supervised.get('confidence', 0.0)}; decision support only.",
    ]
    if false_positive_notes:
        risk_interpretation.append("False-positive/noise review recommended: " + " ".join(false_positive_notes[:3]))
    else:
        risk_interpretation.append("No obvious false-positive caveat was found in the compact context, but analyst validation is still required.")
    missing_evidence_text = missing_evidence_notes[:]

    analyst_steps = _checklist_for_alert(parser_notes=parser_notes, related_log_rows=related_log_rows)

    response_text = (
        "No response action is recorded for this alert."
        if not response_history
        else "; ".join(
            f"{item['action_type']} {item['target_ip']} -> {item['status']}"
            for item in response_history[:5]
        )
    )

    answer = f"""Summary
- Alert #{alert.id}: {alert.severity} {alert.alert_type} with risk score {alert.threat_score}.
- Status: {alert.status}; detection source: {", ".join(detection_sources)}.
- Observed flow: source {alert.src_ip or "unknown"} to destination {alert.dst_ip or "unknown"}.
- Evidence logs: {len(alert.evidence)}; occurrences: {occurrence_count}; related logs: {related_log_count}.
- Log source: {", ".join(source_names) if source_names else "not linked"}.

Evidence / Why flagged
{detection_summary.get("why_flagged") or alert.explanation}

Evidence
{_markdown_list(evidence_points[:6], fallback="No compact evidence points were recorded.")}

Related logs
{_markdown_list(related_log_points, fallback="No compact related-log summary was available.")}

ATT&CK mapping
- Tactic: {attack_mapping.get("tactic", "Unknown")}
- Technique: {attack_mapping.get("technique", "Needs Investigation")}
- Technique ID: {attack_mapping.get("technique_id", "N/A")}

Rule / model contribution
- Rules: {", ".join(rule_names) if rule_names else "No rule names recorded"}
- Anomaly evidence: {"present" if anomaly.get("present") else "not present"}; count {anomaly.get("count", 0)}
- Supervised signal: {supervised.get("predicted_label") or "not available"}; confidence {supervised.get("confidence", 0.0)}
- ML status: decision support only, not automatic truth.

Risk interpretation
{_markdown_list(risk_interpretation)}

False-positive and missing-evidence review
{_markdown_list([*false_positive_notes, *missing_evidence_text], fallback="No major false-positive or missing-evidence caveat was visible in compact context.")}

What to check next / Analyst next steps
{_markdown_list(analyst_steps)}

Safety note
- Response automation is disabled.
- Real firewall blocking is not implemented.
- Current response history: {response_text}

References
- Alert ID: {alert.id}
- Related log IDs: {", ".join(str(item.normalized_log_id) for item in alert.evidence[:12]) or "-"}
- Source IDs: {", ".join(str(row["source_id"]) for row in source_rows) or "-"}
"""
    return AssistantResult(
        answer=_text(answer, redacted=redacted),
        context_used=["alert_detail", "why_flagged", "alert_evidence", "attack_mapping", "response_safety"],
        citations=[
            Citation("Alert detail", "/api/alerts/{alert_id}", str(alert.id)),
            Citation("Alert explanation builder", "atdr/app/detection/explanations.py"),
            Citation("Detection rule catalog", "docs/DETECTION_RULE_CATALOG.md"),
            *[Citation("Related log", "/api/logs/{log_id}", str(row["id"])) for row in related_log_rows[:5]],
            *[Citation("Source", "/api/sources/{source_id}", str(row["source_id"])) for row in source_rows],
        ],
        details={
            "alert": _redact(
                {
                    "id": alert.id,
                    "title": alert.title,
                    "severity": alert.severity,
                    "status": alert.status,
                    "alert_type": alert.alert_type,
                    "threat_score": alert.threat_score,
                    "src_ip": alert.src_ip,
                    "dst_ip": alert.dst_ip,
                    "evidence_count": len(alert.evidence),
                    "occurrence_count": occurrence_count,
                    "related_log_count": related_log_count,
                    "confidence_label": confidence_label,
                    "detection_source": detection_sources,
                    "matched_rule_names": rule_names,
                    "source_rows": source_rows,
                    "related_logs": related_log_rows,
                    "parser_notes": parser_notes,
                    "false_positive_notes": false_positive_notes,
                    "missing_evidence_notes": missing_evidence_notes,
                    "response_history": response_history,
                },
                enabled=redacted,
            ),
            "detection_summary": _redact(detection_summary, enabled=redacted),
            "answer_sections": _redact(
                {
                    "summary": [
                        f"Alert #{alert.id}: {alert.severity} {alert.alert_type} with risk score {alert.threat_score}.",
                        f"Detection source: {', '.join(detection_sources)}.",
                        f"Evidence logs: {len(alert.evidence)}; occurrences: {occurrence_count}; related logs: {related_log_count}.",
                        f"Linked source: {', '.join(source_names) if source_names else 'not linked'}.",
                        f"Evidence strength: {confidence_label}.",
                    ],
                    "evidence": [
                        detection_summary.get("why_flagged") or alert.explanation or "No compact why-flagged summary recorded.",
                        *evidence_points[:6],
                        *related_log_points,
                        f"Rules: {', '.join(rule_names) if rule_names else 'No rule names recorded'}.",
                        f"ATT&CK mapping: {attack_mapping.get('tactic', 'Unknown')} / {attack_mapping.get('technique', 'Needs Investigation')} / {attack_mapping.get('technique_id', 'N/A')}.",
                        f"Anomaly evidence: {'present' if anomaly.get('present') else 'not present'}; count {anomaly.get('count', 0)}.",
                        f"Supervised signal: {supervised.get('predicted_label') or 'not available'}; confidence {supervised.get('confidence', 0.0)}.",
                    ],
                    "risk_interpretation": [
                        *risk_interpretation,
                        *[f"Possible false-positive factor: {item}" for item in false_positive_notes[:4]],
                        *[f"Missing evidence note: {item}" for item in missing_evidence_notes[:4]],
                    ],
                    "what_to_check_next": analyst_steps,
                    "safe_next_steps": analyst_steps,
                    "safety_note": [
                        "ML output is decision support only.",
                        "Response automation is disabled.",
                        "Real firewall blocking is not implemented.",
                        "Review recommended before any simulated response.",
                        f"Current response history: {response_text}",
                    ],
                    "safety_limitation": [
                        "ML output is decision support only.",
                        "Response automation is disabled.",
                        "Real firewall blocking is not implemented.",
                        "Review recommended before any simulated response.",
                        f"Current response history: {response_text}",
                    ],
                    "citations": [
                        _citation_reference(Citation("Alert detail", "/api/alerts/{alert_id}", str(alert.id))),
                        _citation_reference(Citation("Alert explanation builder", "atdr/app/detection/explanations.py")),
                        _citation_reference(Citation("Detection rule catalog", "docs/DETECTION_RULE_CATALOG.md")),
                        *[
                            _citation_reference(Citation("Related log", "/api/logs/{log_id}", str(row["id"])))
                            for row in related_log_rows[:5]
                        ],
                        *[
                            _citation_reference(Citation("Source", "/api/sources/{source_id}", str(row["source_id"])))
                            for row in source_rows
                        ],
                    ],
                },
                enabled=redacted,
            ),
        },
        suggested_followups=[
            f"Show related logs for alert {alert.id}.",
            *( [f"Why was log {related_log_rows[0]['id']} flagged?"] if related_log_rows else [] ),
            "What should an analyst check next?",
            "Is this response safe to approve?",
            "What ATT&CK mapping applies?",
            "Summarize source health.",
        ],
    )


def _answer_unsafe_action_refusal(question: str, *, redacted: bool) -> AssistantResult:
    answer = f"""I cannot execute that request.

Requested action
- {question}

Safety boundary
- I am a read-only SOC assistant.
- I cannot block or unblock IPs.
- I cannot delete logs, alerts, labels, or users.
- I cannot run detection, change labels, train, activate, or promote models.
- I cannot send email or enable automation.
- Response actions must remain simulated and analyst-approved in the Response & Audit workflow.

Safe alternative
- I can explain the alert, summarize evidence, list source health warnings, and suggest what an analyst should check next.
- If a response is needed, use the Response & Audit page with confirmation, justification, protected-IP checks, and audit logging.
"""
    return AssistantResult(
        answer=_text(answer, redacted=redacted),
        context_used=["assistant_safety_guardrail", "response_safety"],
        citations=[
            Citation("Response safety service", "atdr/app/services/response_service.py"),
            Citation("Response API", "/api/response"),
            Citation("Assistant safety docs", "docs/V3_21_SOC_ASSISTANT_DEMO_QUALITY.md"),
        ],
        details={"refused": True, "reason": "assistant_read_only"},
        suggested_followups=[
            "Why was this alert flagged?",
            "What can I safely do next for this alert?",
            "Summarize source health.",
        ],
    )


def _answer_response_safety(*, redacted: bool) -> AssistantResult:
    answer = """Response safety rules
- The SOC Assistant is read-only and cannot block, unblock, delete, run detection, change labels, activate models, create users, send email, or expose raw logs.
- Response automation is disabled.
- Real firewall blocking is disabled and not implemented.
- Simulated block/unblock actions must be done from Response & Audit by an authorized analyst/admin.
- High-impact response requires confirmation and a justification note.
- Protected/internal/management IP ranges are denied by safety controls.
- Denied and simulated attempts are audited.

Presentation wording
- Say: response is simulated and analyst-approved.
- Do not say: ATDR performs real automatic blocking.
"""
    citations = [
        Citation("Response safety service", "atdr/app/services/response_service.py"),
        Citation("Response & Audit page", "frontend/src/pages/ResponseCenter.tsx"),
        Citation("SOC Assistant safety docs", "docs/V3_21_SOC_ASSISTANT_DEMO_QUALITY.md"),
    ]
    return AssistantResult(
        answer=_text(answer, redacted=redacted),
        context_used=["response_safety", "assistant_safety_guardrail"],
        citations=citations,
        details={
            "answer_sections": {
                "summary": ["Response is simulated, analyst-approved, and audited."],
                "safe_next_steps": [
                    "Use Response & Audit for simulated response actions.",
                    "Require confirmation and justification.",
                    "Verify protected-IP checks before approval.",
                ],
                "safety_note": [
                    "The assistant cannot execute actions.",
                    "Response automation and real firewall blocking remain disabled.",
                ],
                "citations": [_citation_reference(citation) for citation in citations],
            },
            "action_executed": False,
        },
        suggested_followups=["What should I safely check next for this alert?", "Explain the latest critical alert."],
    )


def _answer_log_triage_question(db: Session, question: str, *, log_id: int | None, redacted: bool) -> AssistantResult:
    if log_id is None:
        return AssistantResult(
            answer="Tell me the log ID, for example: why was log 123 not flagged?",
            context_used=["log_triage_help"],
            citations=[Citation("Log detail API", "/api/logs/{log_id}")],
            suggested_followups=["Open a log from Investigation and ask why it was flagged.", "Explain the latest critical alert."],
        )
    log = get_log(db, log_id)
    if log is None:
        return AssistantResult(
            answer=f"Log #{log_id} was not found. Check the Investigation page filters or confirm the normalized log ID.",
            context_used=["log_detail"],
            citations=[Citation("Log detail API", "/api/logs/{log_id}", str(log_id))],
            suggested_followups=["Search logs by source IP.", "Summarize open alerts."],
        )
    explanation = explain_log_triage(log)
    signal_text = "; ".join(explanation["normalized_signals"][:4]) if explanation["normalized_signals"] else "no strong normalized signal listed"
    reason_text = " ".join(explanation["reasons"][:3])
    linked_alerts = _log_alert_rows(log)
    source_id = _safe_log_context(log).get("source_id")
    parser_warnings = explanation.get("parser_warnings") or []
    confidence_label = (
        "moderate confidence"
        if linked_alerts and explanation["normalized_signals"] and not parser_warnings
        else "low confidence / needs review"
        if parser_warnings or not linked_alerts
        else "moderate confidence"
    )
    risk_interpretation = [
        f"Evidence strength: {confidence_label}.",
        "This log is alert-linked evidence." if linked_alerts else "This log is not linked to an alert in the current context.",
        "Parser warnings can reduce confidence." if parser_warnings else "No parser warning was recorded for this log.",
        "Review recommended before changing labels or treating the row as benign/threat.",
    ]
    answer = f"""Summary
- Log #{log.id} triage status: {explanation['status']}.
- {explanation['summary']}
- Linked alerts: {", ".join(str(item["id"]) for item in linked_alerts) if linked_alerts else "none"}.

Why {"flagged" if explanation["status"] == "flagged" else "not flagged"}
- Signals: {signal_text}.
- Reasoning: {reason_text or "No compact reasoning was recorded."}

Evidence
{_markdown_list(explanation.get("normalized_signals", [])[:6], fallback="No compact normalized signals were available.")}
{_markdown_list(explanation.get("reasons", [])[:4], fallback="No compact reasons were available.")}

Parser and source notes
{_markdown_list(parser_warnings[:4], fallback="No parser warning was recorded for this log.")}

Risk interpretation
{_markdown_list(risk_interpretation)}

What to check next
- Open linked alerts if they exist.
- Review nearby logs from the same source and destination before changing labels.
- Add a human-reviewed label only when analyst context supports it.
- Do not use this assistant response to trigger containment.

Safety note
- This is decision support only.
- The assistant did not run detection, modify labels, or trigger response.
"""
    citations = [
        Citation("Log detail", "/api/logs/{log_id}", str(log.id)),
        Citation("Log triage explanation", "atdr/app/detection/explanations.py"),
        *[Citation("Linked alert", "/api/alerts/{alert_id}", str(item["id"])) for item in linked_alerts[:5]],
    ]
    if source_id:
        citations.append(Citation("Source", "/api/sources/{source_id}", str(source_id)))
    return AssistantResult(
        answer=_text(answer, redacted=redacted),
        context_used=["log_detail", "why_not_flagged" if explanation["status"] != "flagged" else "why_flagged"],
        citations=citations,
        details={
            "log": _redact(_safe_log_context(log), enabled=redacted),
            "linked_alerts": _redact(linked_alerts, enabled=redacted),
            "log_triage": _redact(_without_raw_context(explanation), enabled=redacted),
            "answer_sections": _redact(
                {
                    "summary": [
                        f"Log #{log.id} triage status: {explanation['status']}.",
                        explanation["summary"],
                        f"Linked alerts: {', '.join(str(item['id']) for item in linked_alerts) if linked_alerts else 'none'}.",
                        f"Evidence strength: {confidence_label}.",
                    ],
                    "evidence": [
                        f"Signals: {signal_text}.",
                        f"Reasoning: {reason_text or 'No compact reasoning was recorded.'}",
                        *[str(item) for item in explanation.get("normalized_signals", [])[:6]],
                        *[str(item) for item in parser_warnings[:4]],
                    ],
                    "risk_interpretation": risk_interpretation,
                    "what_to_check_next": [
                        "Open linked alerts if they exist.",
                        "Review nearby logs from the same source and destination before changing labels.",
                        "Add a human-reviewed label only when analyst context supports it.",
                        "Do not use this assistant response to trigger containment.",
                    ],
                    "safe_next_steps": [
                        "Open linked alerts if they exist.",
                        "Review nearby logs from the same source and destination before changing labels.",
                        "Add a human-reviewed label only when analyst context supports it.",
                        "Do not use this assistant response to trigger containment.",
                    ],
                    "safety_note": [
                        "Decision support only.",
                        "No detection, label, response, model, or data action was executed.",
                        "Raw log context is disabled by default.",
                    ],
                    "safety_limitation": [
                        "Decision support only.",
                        "No detection, label, response, model, or data action was executed.",
                        "Raw log context is disabled by default.",
                    ],
                    "citations": [_citation_reference(citation) for citation in citations[:8]],
                },
                enabled=redacted,
            ),
        },
        suggested_followups=[
            "Open related alerts if any are listed.",
            "Review nearby logs from the same source IP.",
            *( [f"Explain alert {linked_alerts[0]['id']}"] if linked_alerts else [] ),
            "Add a human-reviewed label if analyst context changes the decision.",
        ],
    )
def _answer_source_question(db: Session, *, source_id: int | None, limit: int, redacted: bool, warnings_only: bool = False) -> AssistantResult:
    sources = []
    if source_id is not None:
        source = get_source(db, source_id)
        if source is not None:
            sources = [source]
        else:
            answer = (
                f"No matching source #{source_id} was found. Check the Log Sources panel or ask for a general source-health summary.\n\n"
                "What to do next\n"
                "- Open Overview and inspect Log Sources.\n"
                "- Register or replay a named source if you need representative local evidence.\n"
                "- Ask `Summarize source health` for all known sources."
            )
            return AssistantResult(
                answer=_text(answer, redacted=redacted),
                context_used=["source_health", "missing_source"],
                citations=[Citation("Source API", "/api/sources"), Citation("Log Sources panel", "frontend/src/pages/ExecutiveOverview.tsx")],
                details={
                    "answer_sections": {
                        "summary": [f"No matching source #{source_id} was found."],
                        "what_to_check_next": ["Open Overview Log Sources.", "Ask for general source health.", "Replay a named safe source if needed."],
                        "safe_next_steps": ["Use safe replay/scenario flows only; no automatic response is triggered."],
                    }
                },
                suggested_followups=["Summarize source health.", "How do I run a controlled validation scenario?"],
            )
    if not sources:
        sources = list_sources(db, limit=limit)
    if not sources:
        return AssistantResult(
            answer="No log sources are registered yet. Import logs, replay logs, or receive syslog to create the local source automatically.",
            context_used=["sources"],
            citations=[Citation("Source API", "atdr/app/routers/sources.py")],
            suggested_followups=["How do I replay logs?", "How do I test syslog locally?"],
        )
    rows = [source_to_dict(source, include_quality=True, db=db) for source in sources[:limit]]
    if warnings_only:
        rows = [
            item
            for item in rows
            if (item.get("health") or {}).get("status") in {"warning", "error", "idle", "disabled"}
            or item.get("parse_failure_count", 0)
            or ((item.get("quality") or {}).get("unknown_app_rate") or 0) >= 50
        ]
        if not rows:
            return AssistantResult(
                answer="No source warning/error rows were found in the current context.",
                context_used=["source_health", "source_quality"],
                citations=[Citation("Source API", "/api/sources")],
                suggested_followups=["Summarize source health.", "What changed recently?"],
            )
    parts = []
    recent_alerts_by_source: dict[int, list[dict[str, Any]]] = {}
    for item in rows[:5]:
        health = item.get("health", {})
        quality = item.get("quality") or {}
        source_row_id = item.get("source_id")
        recent_alert_rows: list[dict[str, Any]] = []
        if isinstance(source_row_id, int):
            recent_alert_rows = [
                {
                    "id": alert.id,
                    "severity": alert.severity,
                    "status": alert.status,
                    "alert_type": alert.alert_type,
                    "threat_score": alert.threat_score,
                    "title": alert.title,
                }
                for alert in list_alerts(db, source_id=source_row_id, sort_by="updated", limit=5)
            ]
            recent_alerts_by_source[source_row_id] = recent_alert_rows
        parts.append(
            f"{item.get('name')} ({item.get('source_type')}/{item.get('parser_profile')}): "
            f"{health.get('status')} with {item.get('logs_received_count')} logs, "
            f"{item.get('parse_success_count')} parsed, {item.get('parse_failure_count')} failures, "
            f"{quality.get('alert_count', 0)} linked alerts, "
            f"{len(recent_alert_rows)} recent alert references loaded."
        )
    source_risk_lines: list[str] = []
    for item in rows[:5]:
        health = item.get("health") or {}
        quality = item.get("quality") or {}
        status = str(health.get("status") or "unknown")
        alert_count = int(quality.get("alert_count") or 0)
        parse_failures = int(item.get("parse_failure_count") or 0)
        unknown_app_rate = quality.get("unknown_app_rate")
        confidence = "high confidence" if status == "healthy" and parse_failures == 0 else "low confidence / needs review" if status in {"warning", "error", "idle", "disabled"} else "moderate confidence"
        notes = [f"Source {item.get('source_id')} is {status}; evidence strength {confidence}."]
        if alert_count:
            notes.append(f"{alert_count} linked alerts make this source relevant for triage.")
        if parse_failures:
            notes.append(f"{parse_failures} parse failures can reduce trust in normalized fields.")
        if unknown_app_rate is not None and float(unknown_app_rate or 0) >= 50:
            notes.append(f"Unknown app rate is {unknown_app_rate}%, which can create noisy detections.")
        source_risk_lines.append(" ".join(notes))
    source_next_steps = [
        "Check source health, parser profile, and latest parser errors before trusting missing fields.",
        "Review recent source-linked alerts and related logs before containment.",
        "If parser warnings are high, validate the device log format or parser profile.",
        "Keep response actions simulated and analyst-approved.",
    ]
    prefix = "Sources needing review: " if warnings_only else "Source health summary: "
    answer = (
        prefix
        + " ".join(parts)
        + "\n\nRisk interpretation\n"
        + _markdown_list(source_risk_lines, fallback="No source risk caveat was visible in compact context.")
        + "\n\nSafe next steps\n"
        + _markdown_list(source_next_steps)
    )
    citations = [
        Citation("Source API", "/api/sources"),
        Citation("Source health service", "atdr/app/services/source_service.py"),
        *[Citation("Source", "/api/sources/{source_id}", str(item.get("source_id"))) for item in rows[:5] if item.get("source_id")],
    ]
    for alert_rows in recent_alerts_by_source.values():
        citations.extend(Citation("Source-linked alert", "/api/alerts/{alert_id}", str(alert["id"])) for alert in alert_rows[:3])
    return AssistantResult(
        answer=_text(answer, redacted=redacted),
        context_used=["source_health", "source_quality", "source_alerts"],
        citations=citations,
        details={
            "sources": _redact(_without_raw_context(rows), enabled=redacted),
            "recent_alerts_by_source": _redact(recent_alerts_by_source, enabled=redacted),
            "answer_sections": _redact(
                {
                    "summary": parts[:5],
                    "evidence": [
                        f"Source rows evaluated: {len(rows)}.",
                        *[
                            f"Source {item.get('source_id')} status {(item.get('health') or {}).get('status')} with {(item.get('quality') or {}).get('alert_count', 0)} linked alerts."
                            for item in rows[:5]
                        ],
                    ],
                    "risk_interpretation": source_risk_lines,
                    "what_to_check_next": source_next_steps,
                    "safe_next_steps": source_next_steps,
                    "safety_note": [
                        "Source answers are read-only.",
                        "No detection run, parser change, source toggle, or response action was executed.",
                        "Raw log context is disabled by default.",
                    ],
                    "safety_limitation": [
                        "Source answers are read-only.",
                        "No detection run, parser change, source toggle, or response action was executed.",
                        "Raw log context is disabled by default.",
                    ],
                    "citations": [_citation_reference(citation) for citation in citations[:8]],
                },
                enabled=redacted,
            ),
        },
        suggested_followups=[
            "Which source has parser warnings?",
            "Summarize this source's recent alerts.",
            "How do I replay logs as a source?",
        ],
    )


def _answer_case_question(
    db: Session,
    *,
    case_id: str | None,
    source_id: int | None,
    limit: int,
    redacted: bool,
) -> AssistantResult:
    cases = list_alert_cases(db, active_only=True, source_id=source_id, limit=max(5, min(limit, 25)))
    selected_case = None
    if case_id:
        selected_case = next((item for item in cases if str(item.get("case_id")) == case_id), None)
    if selected_case is None and cases:
        selected_case = cases[0]
    if selected_case is None:
        return AssistantResult(
            answer="No active computed alert groups were found. Open Alerts after detection runs, or ask about open alerts/source health.",
            context_used=["alert_cases"],
            citations=[Citation("Alert cases API", "/api/alerts/cases")],
            suggested_followups=["Summarize open alerts.", "Summarize source health."],
        )

    attack_types = selected_case.get("attack_types") or []
    source_ips = selected_case.get("source_ips") or []
    destination_ips = selected_case.get("destination_ips") or []
    top_ports = selected_case.get("top_destination_ports") or []
    top_actions = selected_case.get("top_actions") or []
    focus = selected_case.get("recommended_analyst_focus") or "Review linked alerts and evidence logs before deciding status."
    top_port_text = ", ".join(f"{item.get('name')} ({item.get('count')})" for item in top_ports[:5]) or "-"
    top_action_text = ", ".join(f"{item.get('name')} ({item.get('count')})" for item in top_actions[:5]) or "-"
    evidence_points = [
        f"Related alerts: {selected_case.get('related_alert_count', 0)}.",
        f"Related logs: {selected_case.get('total_related_logs', 0)}.",
        f"Attack types: {', '.join(attack_types) if attack_types else 'unknown'}.",
        f"Top destination ports: {top_port_text}.",
        f"Top actions: {top_action_text}.",
    ]
    related_alert_count = int(selected_case.get("related_alert_count") or 0)
    total_related_logs = int(selected_case.get("total_related_logs") or 0)
    confidence_label = (
        "high confidence"
        if related_alert_count >= 2 and total_related_logs >= 5
        else "moderate confidence"
        if related_alert_count >= 1 and total_related_logs >= 1
        else "low confidence / needs review"
    )
    risk_interpretation = [
        f"Evidence strength: {confidence_label}.",
        "This case is a computed alert grouping, useful for triage but not a persisted incident record.",
        f"Boundary check: {related_alert_count} related alerts and {total_related_logs} related logs are available.",
        "Review recommended before using the group for containment or escalation.",
    ]
    case_next_steps = [
        focus,
        "Open related alerts and evidence logs before containment.",
        "Check whether the same source repeats across alerts or destination ports.",
        "Assign an analyst or move status only through the Alerts workflow.",
        "Keep response actions simulated and justification-backed.",
    ]
    answer = f"""Summary
- Case/group {selected_case.get('case_id')}: {selected_case.get('title')}.
- Severity: {selected_case.get('severity')}; status: {selected_case.get('status')}; owner: {selected_case.get('assigned_analyst') or 'unassigned'}.
- First seen: {selected_case.get('first_seen')}; last seen: {selected_case.get('last_seen')}.

Evidence
{_markdown_list(evidence_points)}

Source and destination context
- Source IPs: {', '.join(source_ips) if source_ips else '-'}.
- Destination IPs: {', '.join(destination_ips) if destination_ips else '-'}.

Recommended analyst focus
- {focus}

Risk interpretation
{_markdown_list(risk_interpretation)}

What to check next
{_markdown_list(case_next_steps)}

Safety note
- This is a computed grouping summary only.
- The assistant did not create a case record, change alert status, run detection, or trigger response.
"""
    citations = [
        Citation("Alert cases API", "/api/alerts/cases", str(selected_case.get("case_id"))),
        Citation("Case grouping service", "atdr/app/services/case_service.py"),
        Citation("Alerts page", "/api/alerts"),
    ]
    return AssistantResult(
        answer=_text(answer, redacted=redacted),
        context_used=["alert_cases", "case_grouping", "source_context" if source_id else "case_summary"],
        citations=citations,
        details={
            "case": _redact(selected_case, enabled=redacted),
            "available_case_count": len(cases),
            "answer_sections": _redact(
                {
                    "summary": [
                        f"Case/group {selected_case.get('case_id')}: {selected_case.get('title')}.",
                        f"Severity {selected_case.get('severity')}, status {selected_case.get('status')}, owner {selected_case.get('assigned_analyst') or 'unassigned'}.",
                        f"Evidence strength: {confidence_label}.",
                    ],
                    "evidence": evidence_points,
                    "risk_interpretation": risk_interpretation,
                    "what_to_check_next": case_next_steps,
                    "safe_next_steps": case_next_steps,
                    "safety_note": [
                        "Computed case grouping only; no persisted incident was created.",
                        "No detection, response, label, model, source, or data action was executed.",
                    ],
                    "safety_limitation": [
                        "Computed case grouping only; no persisted incident was created.",
                        "No detection, response, label, model, source, or data action was executed.",
                    ],
                    "citations": [_citation_reference(citation) for citation in citations],
                },
                enabled=redacted,
            ),
        },
        suggested_followups=[
            "Summarize open alerts.",
            "What evidence supports this alert?",
            "What is the safest analyst action here?",
        ],
    )


def _as_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value if str(item).strip()]
    if value is None:
        return []
    text = str(value).strip()
    return [text] if text else []


def _answer_investigation_brief(
    db: Session,
    question: str,
    *,
    alert_id: int | None,
    log_id: int | None,
    source_id: int | None,
    case_id: str | None,
    limit: int,
    redacted: bool,
) -> AssistantResult:
    lowered = question.lower()
    if log_id is not None and "log" in lowered and "alert" not in lowered:
        brief_kind = "log"
        base = _answer_log_triage_question(db, question, log_id=log_id, redacted=redacted)
    elif case_id is not None or "case" in lowered or "alert group" in lowered:
        brief_kind = "case"
        base = _answer_case_question(db, case_id=case_id, source_id=source_id, limit=limit, redacted=redacted)
    elif source_id is not None and "alert" not in lowered:
        brief_kind = "source"
        base = _answer_source_question(db, source_id=source_id, limit=limit, redacted=redacted)
    else:
        brief_kind = "alert"
        base = _answer_alert_question(db, question, alert_id=alert_id, redacted=redacted)

    base_sections = base.details.get("answer_sections") if isinstance(base.details, dict) else None
    sections = base_sections if isinstance(base_sections, dict) else {}
    summary = _as_list(sections.get("summary")) or _first_answer_lines(base.answer)
    evidence = _as_list(sections.get("evidence"))
    risk_interpretation = _as_list(sections.get("risk_interpretation")) or _as_list(sections.get("why_flagged_or_not"))
    safe_next_steps = _as_list(sections.get("safe_next_steps")) or base.suggested_followups[:4]
    limitations = [
        "Decision support only; analyst judgment is required.",
        "Response automation is disabled.",
        "No real firewall blocking is implemented.",
        "Raw log context is disabled by default.",
        "This brief was generated from current ATDR context and does not mutate data.",
    ]
    if brief_kind == "case":
        limitations.insert(0, "Computed case/group summary only; no persisted incident record was created.")

    citation_lines = [_citation_reference(citation) for citation in base.citations[:10]]
    related_context = [
        f"Brief context type: {brief_kind}.",
        f"Context used: {', '.join(base.context_used) or 'none'}.",
        *citation_lines[:6],
    ]
    what_happened = summary[:4]
    why_lines = evidence[:5] or ["No compact why-flagged/why-not-flagged evidence was available in this context."]

    answer = f"""Investigation Brief

Summary
{_markdown_list(summary[:5], fallback="No summary context was available.")}

What happened
{_markdown_list(what_happened, fallback="No compact timeline was available.")}

Why flagged or not flagged
{_markdown_list(why_lines, fallback="No compact decision evidence was available.")}

Evidence to mention
{_markdown_list(evidence[:8], fallback="No compact evidence points were available.")}

Risk interpretation
{_markdown_list(risk_interpretation[:8], fallback="Evidence is limited to current ATDR context; analyst review is required.")}

Related context
{_markdown_list(related_context[:8], fallback="No related context was available.")}

Safe analyst next steps
{_markdown_list(safe_next_steps[:6], fallback="Open the related dashboard page and verify evidence before action.")}

Limitations
{_markdown_list(limitations)}

Citations
{_markdown_list(citation_lines[:10], fallback="No citations were available.")}
"""
    citations = [
        *base.citations,
        Citation("Assistant brief builder docs", "docs/V3_25_SOC_ASSISTANT_INVESTIGATION_BRIEF_BUILDER.md"),
    ]
    return AssistantResult(
        answer=_text(answer, redacted=redacted),
        context_used=["investigation_brief", *base.context_used],
        citations=citations,
        details={
            "brief": _redact(
                {
                    "kind": brief_kind,
                    "source_context_used": base.context_used,
                    "non_mutating": True,
                    "external_provider_used": False,
                    "raw_log_context_included": False,
                },
                enabled=redacted,
            ),
            "source_answer_details": _redact(_without_raw_context(base.details), enabled=redacted),
            "answer_sections": _redact(
                {
                    "summary": summary[:5],
                    "what_happened": what_happened,
                    "why_flagged_or_not": why_lines,
                    "evidence": evidence[:8],
                    "risk_interpretation": risk_interpretation[:8] or ["Evidence is limited to current ATDR context; analyst review is required."],
                    "related_context": related_context[:8],
                    "what_to_check_next": safe_next_steps[:6],
                    "safe_next_steps": safe_next_steps[:6],
                    "limitations": limitations,
                    "safety_note": limitations,
                    "safety_limitation": limitations,
                    "citations": citation_lines[:10],
                },
                enabled=redacted,
            ),
        },
        suggested_followups=[
            "What should an analyst verify before response?",
            "Generate executive evidence summary.",
            "Explain the strongest evidence in this brief.",
            "Summarize source health.",
        ],
    )


def _answer_failed_jobs(db: Session, *, settings: Settings, redacted: bool) -> AssistantResult:
    summary = build_job_summary(
        db,
        stale_after_minutes=settings.job_stale_after_minutes,
        job_retention_days=settings.job_retention_days,
        run_history_retention_days=settings.run_history_retention_days,
    )
    failed_jobs = list(
        db.scalars(
            select(OperationJob)
            .where(OperationJob.status == "failed")
            .order_by(desc(OperationJob.updated_at), desc(OperationJob.id))
            .limit(5)
        )
    )
    if not failed_jobs:
        answer = "No failed operation jobs were found. Current failed job count is 0."
    else:
        parts = [
            f"job #{job.id} {job.job_type} requested by {job.requested_by}: {job.error_summary or 'no error summary'}"
            for job in failed_jobs
        ]
        answer = f"Failed job summary: {summary.get('failed_count')} failed jobs. " + " ".join(parts)
    return AssistantResult(
        answer=_text(answer, redacted=redacted),
        context_used=["operation_jobs", "failed_jobs"],
        citations=[Citation("Jobs API", "/api/jobs"), *[Citation("Operation job", "/api/jobs/{job_id}", str(job.id)) for job in failed_jobs]],
        details={"job_summary": _redact(summary, enabled=redacted), "failed_jobs": _redact([job_to_dict(job) for job in failed_jobs], enabled=redacted)},
        suggested_followups=["What changed recently?", "How do I run job maintenance dry-run?"],
    )


def _format_attack_types(run: DetectionRun) -> str:
    rows = run.top_attack_types_json or []
    if not rows:
        return "none recorded"
    parts = []
    for item in rows[:5]:
        if isinstance(item, dict):
            parts.append(f"{item.get('name', 'unknown')}={item.get('count', 0)}")
        else:
            parts.append(str(item))
    return ", ".join(parts)


def _answer_detection_runs_question(db: Session, *, redacted: bool) -> AssistantResult:
    runs = list(
        db.scalars(
            select(DetectionRun)
            .order_by(desc(DetectionRun.started_at), desc(DetectionRun.id))
            .limit(5)
        )
    )
    if not runs:
        return AssistantResult(
            answer="No detection runs are recorded yet. Use the dashboard detection action or the lab runbook when you are ready to run detection manually.",
            context_used=["detection_runs"],
            citations=[Citation("Detection runs API", "/api/detection/runs")],
            suggested_followups=["How do I run detection safely?", "How do I run a controlled validation scenario?"],
        )
    latest = runs[0]
    rows = [
        (
            f"run #{run.id}: {run.detection_type} {run.status}, "
            f"{run.logs_evaluated} logs evaluated, {run.alerts_created} alerts created, "
            f"{run.alerts_deduplicated} deduplicated, top attack types: {_format_attack_types(run)}"
        )
        for run in runs
    ]
    answer = (
        "Recent detection runs:\n"
        + "\n".join(f"- {row}" for row in rows)
        + "\n\nDetection runs are operator-triggered records. The assistant is read-only and did not run detection."
    )
    return AssistantResult(
        answer=_text(answer, redacted=redacted),
        context_used=["detection_runs"],
        citations=[
            Citation("Detection runs API", "/api/detection/runs"),
            *[Citation("Detection run", "/api/detection/runs/{run_id}", str(run.id)) for run in runs],
        ],
        details={
            "latest_detection_run": _redact(detection_run_to_dict(latest), enabled=redacted),
            "detection_runs": _redact([detection_run_to_dict(run) for run in runs], enabled=redacted),
        },
        suggested_followups=["Summarize failed jobs.", "Show latest critical alerts."],
    )


def _answer_operations_question(db: Session, *, settings: Settings, redacted: bool) -> AssistantResult:
    summary = build_job_summary(
        db,
        stale_after_minutes=settings.job_stale_after_minutes,
        job_retention_days=settings.job_retention_days,
        run_history_retention_days=settings.run_history_retention_days,
    )
    answer = (
        f"Operations summary: {summary.get('active_count')} active jobs, "
        f"{summary.get('stale_count')} stale jobs, and {summary.get('failed_count')} failed jobs. "
        "Use the Operations Health panel or /api/jobs/summary for current job state. "
        "Maintenance is dry-run first and does not delete logs, alerts, labels, or audit records."
    )
    return AssistantResult(
        answer=_text(answer, redacted=redacted),
        context_used=["operation_jobs"],
        citations=[
            Citation("Job summary API", "/api/jobs/summary"),
            Citation("Job maintenance script", "atdr/scripts/maintenance_jobs.py"),
        ],
        details={"job_summary": _redact(summary, enabled=redacted)},
        suggested_followups=["How do I run job maintenance dry-run?", "Summarize source health."],
    )


def _answer_ml_question(db: Session, *, redacted: bool) -> AssistantResult:
    ml = evaluation_report(db)
    supervised = supervised_model_report(db)
    latest_run = supervised.get("latest_run") or {}
    promotion_gate = latest_run.get("promotion_gate") or {}
    answer = (
        "AI Governance summary: ML is decision support only. "
        f"Anomaly model artifact is {'present' if ml.get('model_status', {}).get('artifact_exists') else 'missing'}, "
        f"current anomaly rate is {ml.get('anomaly_rate', '-')}. "
        f"Supervised label count is {supervised.get('label_count', 0)}. "
        f"Production promoted: {bool(promotion_gate.get('production_promoted', False))}. "
        f"Response automation allowed: {bool(promotion_gate.get('response_automation_allowed', False))}."
    )
    return AssistantResult(
        answer=_text(answer, redacted=redacted),
        context_used=["ml_governance", "supervised_model_report"],
        citations=[
            Citation("ML report API", "/api/ml/report"),
            Citation("Supervised report API", "/api/ml/supervised/report"),
        ],
        details={
            "ml": _redact(
                {
                    "anomaly_rate": ml.get("anomaly_rate"),
                    "scored_log_count": ml.get("scored_log_count"),
                    "model_status": ml.get("model_status"),
                },
                enabled=redacted,
            ),
            "supervised": _redact(
                {
                    "label_count": supervised.get("label_count"),
                    "decision_support_only": supervised.get("decision_support_only"),
                    "latest_run": {
                        "status": latest_run.get("status"),
                        "split_strategy": latest_run.get("split_strategy"),
                        "promotion_gate": promotion_gate,
                    },
                },
                enabled=redacted,
            ),
        },
        suggested_followups=["Why is the model not production promoted?", "How do I import reviewed labels?"],
    )


def _latest_v357_queue_evidence_payload() -> dict[str, Any] | None:
    path = PROJECT_ROOT / "ml_baseline_reviews" / "v3_57_queue_rule_hybrid_agreement_latest.json"
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def _latest_v359_supervised_output_policy_payload() -> dict[str, Any] | None:
    path = PROJECT_ROOT / "ml_baseline_reviews" / "v3_59_supervised_output_policy_contract_latest.json"
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def _answer_supervised_output_policy(*, redacted: bool) -> AssistantResult:
    payload = _latest_v359_supervised_output_policy_payload()
    if payload is None:
        answer = (
            "The supervised output policy contract has not been generated yet. "
            "Run `.\\.venv\\Scripts\\python.exe -m atdr.scripts.run_v359_supervised_output_policy_contract --pretty` "
            "to create the local ignored report. This does not activate a model, write labels, or enable response automation."
        )
        return AssistantResult(
            answer=_text(answer, redacted=redacted),
            context_used=["v359_supervised_output_policy_missing"],
            citations=[
                Citation("v3.59 policy runner", "atdr/scripts/run_v359_supervised_output_policy_contract.py"),
                Citation("v3.59 status doc", "docs/V3_59_SUPERVISED_OUTPUT_POLICY_CONTRACT.md"),
            ],
            suggested_followups=["Explain current ML model status.", "Does ML agree with rule/hybrid evidence?"],
        )

    contract = payload.get("contract") or {}
    queue = contract.get("queue") or {}
    agreement = contract.get("queue_evidence_agreement") or {}
    exact = contract.get("exact_severity") or {}
    safety = payload.get("safety") or {}
    allowed = contract.get("allowed_outputs") or {}
    blocked = contract.get("blocked_uses") or []
    blocked_text = "; ".join(str(item) for item in blocked[:5]) or "automatic response and production promotion remain blocked"
    answer = (
        "Supervised output policy\n"
        f"- Decision: {contract.get('decision', 'decision_support_contract_ready')}.\n"
        f"- Safe supervised strategy: {contract.get('recommended_supervised_strategy', 'binary_soc_review_queue')}.\n"
        "- SOC review-queue score: decision support for analyst prioritization.\n"
        f"- Exact severity / attack labels: {contract.get('exact_classification_policy', 'explanation_or_ranking_only')}.\n"
        "- Rule, anomaly, and hybrid evidence remain the primary detection evidence.\n\n"
        "Validation snapshot\n"
        f"- Queue status: {queue.get('status', 'unknown')}; splits {queue.get('passing_splits', 0)}/{queue.get('evaluated_splits', 0)}; "
        f"F1 min {queue.get('queue_f1_min')}; FPR max {queue.get('benign_like_false_positive_rate_max')}.\n"
        f"- Queue/evidence agreement: {agreement.get('status', 'unknown')}; splits {agreement.get('passing_splits', 0)}/{agreement.get('evaluated_splits', 0)}; "
        f"agreement min {agreement.get('agreement_rate_min')}.\n"
        f"- Exact severity policy status: {exact.get('status', 'unstable')}; stable policies {exact.get('stable_policy_count', 0)}/{exact.get('evaluated_policy_count', 0)}.\n\n"
        "Safety boundary\n"
        f"- Runtime activation ready: {bool(contract.get('contract_ready_for_runtime_activation', False))}.\n"
        f"- Model activated: {bool(safety.get('model_activated', False))}.\n"
        f"- Labels written: {bool(safety.get('labels_written', False))}.\n"
        f"- Response automation allowed: {bool(safety.get('response_automation_allowed', False))}.\n"
        f"- Real firewall blocking enabled: {bool(safety.get('real_firewall_blocking_enabled', False))}.\n"
        f"- Blocked uses: {blocked_text}."
    )
    return AssistantResult(
        answer=_text(answer, redacted=redacted),
        context_used=["v359_supervised_output_policy", "ml_governance"],
        citations=[
            Citation("v3.59 latest policy contract", "ml_baseline_reviews/v3_59_supervised_output_policy_contract_latest.json"),
            Citation("v3.59 status doc", "docs/V3_59_SUPERVISED_OUTPUT_POLICY_CONTRACT.md"),
            Citation("ML Governance page", "frontend/src/pages/MLGovernance.tsx"),
        ],
        details={
            "v359_supervised_output_policy": _redact(
                {
                    "phase": payload.get("phase"),
                    "decision": contract.get("decision"),
                    "recommended_supervised_strategy": contract.get("recommended_supervised_strategy"),
                    "exact_classification_policy": contract.get("exact_classification_policy"),
                    "allowed_output_statuses": {
                        str(key): value.get("status")
                        for key, value in allowed.items()
                        if isinstance(value, dict)
                    },
                    "queue": queue,
                    "queue_evidence_agreement": agreement,
                    "exact_severity": exact,
                    "blocked_uses": blocked,
                    "safety": {
                        "production_promoted": bool(safety.get("production_promoted", False)),
                        "model_activated": bool(safety.get("model_activated", False)),
                        "model_artifact_written": bool(safety.get("model_artifact_written", False)),
                        "labels_written": bool(safety.get("labels_written", False)),
                        "raw_logs_included": bool(safety.get("raw_logs_included", False)),
                        "response_automation_allowed": bool(safety.get("response_automation_allowed", False)),
                        "real_firewall_blocking_enabled": bool(safety.get("real_firewall_blocking_enabled", False)),
                    },
                },
                enabled=redacted,
            )
        },
        suggested_followups=["Does ML agree with rule/hybrid evidence?", "Why is the model not production promoted?"],
    )


def _answer_queue_evidence_agreement(*, redacted: bool) -> AssistantResult:
    payload = _latest_v357_queue_evidence_payload()
    if payload is None:
        answer = (
            "The queue-vs-rule/hybrid agreement diagnostic has not been generated yet. "
            "Run `.\\.venv\\Scripts\\python.exe -m atdr.scripts.run_v357_queue_rule_hybrid_agreement --test-size 0.3 --min-samples 6 --pretty` "
            "to create the local ignored report. This does not activate a model or enable response automation."
        )
        return AssistantResult(
            answer=_text(answer, redacted=redacted),
            context_used=["v357_queue_evidence_agreement_missing"],
            citations=[
                Citation("v3.57 diagnostic runner", "atdr/scripts/run_v357_queue_rule_hybrid_agreement.py"),
                Citation("v3.57 status doc", "docs/V3_57_QUEUE_RULE_HYBRID_AGREEMENT.md"),
            ],
            suggested_followups=["Explain current ML model status.", "Why is the model not production promoted?"],
        )
    aggregate = payload.get("aggregate") or {}
    readiness = payload.get("readiness") or {}
    safety = payload.get("safety") or {}
    top_evidence_only = aggregate.get("top_evidence_only_patterns") or []
    top_queue_only = aggregate.get("top_queue_only_patterns") or []
    evidence_only_text = ", ".join(f"{pattern} ({count})" for pattern, count in top_evidence_only[:4]) or "none reported"
    queue_only_text = ", ".join(f"{pattern} ({count})" for pattern, count in top_queue_only[:4]) or "none reported"
    answer = (
        "Queue-vs-rule/hybrid agreement summary\n"
        f"- Evaluated splits: {aggregate.get('evaluated_splits', 0)}; passing splits: {aggregate.get('passing_splits', 0)}.\n"
        f"- Queue F1 minimum: {aggregate.get('queue_f1_min')}.\n"
        f"- Queue false-positive rate maximum: {aggregate.get('queue_false_positive_rate_max')}.\n"
        f"- Queue/evidence agreement minimum: {aggregate.get('agreement_rate_min')}.\n"
        f"- Readiness: {readiness.get('decision', 'diagnostic_only')}.\n\n"
        "Evidence / disagreement notes\n"
        f"- Top evidence-only review patterns: {evidence_only_text}.\n"
        f"- Top queue-only review patterns: {queue_only_text}.\n\n"
        "Risk interpretation\n"
        "- The queue candidate is strong as decision support, but evidence-only disagreements still need analyst review.\n"
        "- This diagnostic helps explain where ML agrees with deterministic evidence and where deterministic evidence should remain primary.\n\n"
        "Safety note\n"
        f"- Production promoted: {bool(safety.get('production_promoted', False))}.\n"
        f"- Model activated: {bool(safety.get('model_activated', False))}.\n"
        f"- Labels written: {bool(safety.get('labels_written', False))}.\n"
        f"- Response automation allowed: {bool(safety.get('response_automation_allowed', False))}."
    )
    return AssistantResult(
        answer=_text(answer, redacted=redacted),
        context_used=["v357_queue_evidence_agreement", "ml_governance"],
        citations=[
            Citation("v3.57 latest diagnostic", "ml_baseline_reviews/v3_57_queue_rule_hybrid_agreement_latest.json"),
            Citation("v3.57 status doc", "docs/V3_57_QUEUE_RULE_HYBRID_AGREEMENT.md"),
            Citation("ML Governance page", "frontend/src/pages/MLGovernance.tsx"),
        ],
        details={
            "v357_queue_evidence_agreement": _redact(
                {
                    "phase": payload.get("phase"),
                    "aggregate": aggregate,
                    "readiness": readiness,
                    "safety": {
                        "production_promoted": bool(safety.get("production_promoted", False)),
                        "model_activated": bool(safety.get("model_activated", False)),
                        "model_artifact_written": bool(safety.get("model_artifact_written", False)),
                        "labels_written": bool(safety.get("labels_written", False)),
                        "raw_logs_included": bool(safety.get("raw_logs_included", False)),
                        "response_automation_allowed": bool(safety.get("response_automation_allowed", False)),
                    },
                },
                enabled=redacted,
            )
        },
        suggested_followups=["Explain current ML model status.", "What should I safely check next for this alert?"],
    )


def _answer_model_promotion_question(db: Session, *, redacted: bool) -> AssistantResult:
    supervised = supervised_model_report(db)
    latest_run = supervised.get("latest_run") or {}
    promotion_gate = latest_run.get("promotion_gate") or {}
    readiness = latest_run.get("model_readiness_checklist") or supervised.get("model_readiness_checklist") or {}
    warnings = latest_run.get("validation_warnings") or supervised.get("validation_warnings") or []
    failed_items = [
        item
        for item in readiness.get("items", [])
        if isinstance(item, dict) and not item.get("passed", False)
    ]
    reason_parts = []
    if promotion_gate:
        reason_parts.append(f"decision={promotion_gate.get('decision', 'candidate_only')}")
        reason_parts.append(f"production_promoted={bool(promotion_gate.get('production_promoted', False))}")
        reason_parts.append(f"response_automation_allowed={bool(promotion_gate.get('response_automation_allowed', False))}")
    if readiness:
        reason_parts.append(f"readiness={readiness.get('passed', 0)}/{readiness.get('total', 0)} checks passed")
    if failed_items:
        reason_parts.append("open checks: " + "; ".join(str(item.get("name")) for item in failed_items[:4]))
    if warnings:
        reason_parts.append("warnings: " + "; ".join(str(item) for item in warnings[:3]))
    answer = (
        "The supervised model is not production promoted. "
        + (" ".join(reason_parts) if reason_parts else "No production promotion evidence is present.")
        + " ATDR keeps ML as SOC triage decision support and response automation disabled."
    )
    return AssistantResult(
        answer=_text(answer, redacted=redacted),
        context_used=["supervised_model_report", "promotion_gate"],
        citations=[
            Citation("Supervised model report", "/api/ml/supervised/report"),
            Citation("AI training runbook", "docs/AI_TRAINING_RUNBOOK.md"),
        ],
        details={"promotion_gate": _redact(promotion_gate, enabled=redacted), "readiness": _redact(readiness, enabled=redacted)},
        suggested_followups=["How do I import reviewed labels?", "Explain current ML model status."],
    )


def _answer_workflow_question(*, redacted: bool) -> AssistantResult:
    answer = (
        "Common ATDR workflow: start FastAPI with `.\\.venv\\Scripts\\python.exe -m uvicorn atdr.app.main:app --host 127.0.0.1 --port 8000 --reload`, "
        "start React with `cd frontend` then `npm.cmd run dev`, then open `http://127.0.0.1:5173`. "
        "For replay dry-run use `.\\.venv\\Scripts\\python.exe -m atdr.scripts.replay_logs --dry-run --limit 20 --rate 5 --pretty`. "
        "Detection can be run from the dashboard or POST `/api/detection/run`. "
        "All response actions remain simulated and analyst-approved."
    )
    return AssistantResult(
        answer=_text(answer, redacted=redacted),
        context_used=["lab_runbook"],
        citations=[
            Citation("Lab runbook", "docs/LAB_RUNBOOK.md"),
            Citation("README startup commands", "README.md"),
        ],
        suggested_followups=["How do I run a controlled validation scenario?", "Summarize recent operations."],
    )


def _answer_import_logs_help(*, redacted: bool) -> AssistantResult:
    answer = (
        "To import logs from the dashboard, use Demo Controls or the log import workflow and provide a safe sample path if you want more than the tiny demo sample. "
        "The result summary separates requested limit, available lines, raw logs imported, normalized logs created, parse failures, alerts created, and deduplicated alerts. "
        "For command-line replay, use `.\\.venv\\Scripts\\python.exe -m atdr.scripts.replay_logs --send-to direct --sample-path <path> --limit 1000 --pretty`. "
        "Dry-run mode writes nothing: `.\\.venv\\Scripts\\python.exe -m atdr.scripts.replay_logs --dry-run --limit 20 --rate 5 --pretty`."
    )
    return AssistantResult(
        answer=_text(answer, redacted=redacted),
        context_used=["log_import_help", "lab_runbook"],
        citations=[
            Citation("Lab runbook", "docs/LAB_RUNBOOK.md"),
            Citation("Replay script", "atdr/scripts/replay_logs.py"),
            Citation("Demo controls", "frontend/src/pages/DemoControls.tsx"),
        ],
        suggested_followups=["How do I run a controlled validation scenario?", "Summarize source health."],
    )


def _answer_reviewed_label_import_help(*, redacted: bool) -> AssistantResult:
    answer = (
        "Reviewed labels can be imported from AI Governance using the label import control. "
        "Use CSVs exported by ATDR review workflows, keep `human_review_decision` and `human_review_note`, and do not overwrite manual labels unless an explicit correction mode is intended. "
        "After import, retrain/evaluate from AI Governance or the supervised training scripts. Metrics remain decision-support evidence, not production accuracy."
    )
    return AssistantResult(
        answer=_text(answer, redacted=redacted),
        context_used=["lab_runbook", "ml_governance_docs"],
        citations=[
            Citation("AI Training Runbook", "docs/AI_TRAINING_RUNBOOK.md"),
            Citation("ML labels import API", "/api/ml/labels/import"),
            Citation("ML Governance page", "frontend/src/pages/MLGovernance.tsx"),
        ],
        suggested_followups=["Explain current ML model status.", "Why is the model not production promoted?"],
    )


def _answer_scenario_help(*, redacted: bool) -> AssistantResult:
    answer = (
        "Run controlled validation scenarios with `.\\.venv\\Scripts\\python.exe -m atdr.scripts.run_source_scenario --scenario port_scan_like_traffic --source-name lab-scenario --source-type firewall --parser-profile palo_alto --run-detection --pretty`. "
        "Use `--use-temp-db` for isolated validation when you do not want to write to the current DB. "
        "Expected scenario output includes logs parsed, alerts created/deduplicated, cases affected, source health, and confirmation that no automatic response was triggered."
    )
    return AssistantResult(
        answer=_text(answer, redacted=redacted),
        context_used=["lab_runbook", "source_scenarios"],
        citations=[
            Citation("Lab runbook", "docs/LAB_RUNBOOK.md"),
            Citation("Source scenario runner", "atdr/scripts/run_source_scenario.py"),
        ],
        suggested_followups=["Summarize source health.", "Show latest critical alerts."],
    )


def _answer_safe_next_steps(db: Session, question: str, *, alert_id: int | None, redacted: bool) -> AssistantResult:
    alert = get_alert(db, alert_id) if alert_id is not None else None
    if alert is None:
        alerts = list_alerts(db, severity="Critical", status="open", sort_by="score", limit=1)
        alert = alerts[0] if alerts else None
    if alert is None:
        checklist = [
            "Choose an alert from Alerts and open the detail view.",
            "Review Why flagged, related logs, source health, and case grouping.",
            "Document analyst notes before changing lifecycle status.",
            "Do not run containment without evidence, confirmation, and approval.",
        ]
        answer = "Safe next steps\n" + _markdown_list(checklist)
        citations = [Citation("Alerts page", "frontend/src/pages/AlertsTriage.tsx")]
        details = {
            "answer_sections": {
                "summary": ["No specific alert context was provided."],
                "evidence": ["Open an alert detail to load evidence, source, and case context."],
                "risk_interpretation": ["Low confidence / needs review until a specific alert is selected."],
                "what_to_check_next": checklist,
                "safe_next_steps": checklist,
                "safety_note": ["Response automation is disabled.", "No response action was executed."],
                "safety_limitation": ["Response automation is disabled.", "No response action was executed."],
                "citations": [_citation_reference(citations[0])],
            }
        }
    else:
        checklist = [
            "Open the alert detail and read Why flagged before deciding status.",
            "Review related logs, source health, parser notes, and case/group context.",
            "Check whether the traffic matches expected business activity or noisy parser/source behavior.",
            "Add an analyst note and move status to Investigating if more context is needed.",
            "Use simulated response only after confirmation, justification, and protected-IP checks.",
        ]
        answer = (
            f"Safe next steps for alert #{alert.id}\n"
            + _markdown_list(checklist)
            + "\n\nSafety note\n- Do not treat ML output as final truth.\n- No response action was executed by the assistant."
        )
        citations = [Citation("Alert detail", "/api/alerts/{alert_id}", str(alert.id)), Citation("Response safety", "atdr/app/services/response_service.py")]
        details = {
            "alert": {"id": alert.id, "severity": alert.severity, "status": alert.status, "alert_type": alert.alert_type},
            "answer_sections": {
                "summary": [f"Alert #{alert.id}: {alert.severity} {alert.alert_type}, status {alert.status}."],
                "evidence": ["Use the alert detail, related logs, source health, and case grouping before response."],
                "risk_interpretation": [
                    "Response safety depends on evidence quality, source/parser health, and analyst confirmation.",
                    "ML evidence is decision support only and cannot authorize containment by itself.",
                ],
                "what_to_check_next": checklist,
                "safe_next_steps": checklist,
                "safety_note": ["Response automation is disabled.", "No response action was executed by the assistant."],
                "safety_limitation": ["Response automation is disabled.", "No response action was executed by the assistant."],
                "citations": [_citation_reference(citation) for citation in citations],
            },
        }
    return AssistantResult(
        answer=_text(answer, redacted=redacted),
        context_used=["alert_workflow", "response_safety"],
        citations=citations,
        details=_redact(details, enabled=redacted),
        suggested_followups=[
            f"Why was alert {alert.id} flagged?" if alert is not None else "Explain the latest critical alert.",
            f"What logs are related to alert {alert.id}?" if alert is not None else "Summarize open alerts.",
            "Summarize source health.",
        ],
    )


def _answer_recent_changes(db: Session, *, limit: int, redacted: bool) -> AssistantResult:
    audits = list(
        db.scalars(
            select(AuditLog)
            .order_by(desc(AuditLog.created_at), desc(AuditLog.id))
            .limit(max(1, min(limit, 10)))
        )
    )
    jobs = list(
        db.scalars(
            select(OperationJob)
            .order_by(desc(OperationJob.updated_at), desc(OperationJob.id))
            .limit(5)
        )
    )
    audit_text = "; ".join(f"{row.action} by {row.actor}" for row in audits[:5]) or "no recent audit rows"
    job_text = "; ".join(f"job #{job.id} {job.job_type} {job.status}" for job in jobs[:3]) or "no recent operation jobs"
    answer = f"Recent ATDR activity: audit trail shows {audit_text}. Operation jobs show {job_text}. Use Audit Trail and Operations Health for full detail."
    return AssistantResult(
        answer=_text(answer, redacted=redacted),
        context_used=["audit_summary", "operation_jobs"],
        citations=[
            Citation("Audit API", "/api/audit"),
            Citation("Jobs API", "/api/jobs"),
            *[Citation("Operation job", "/api/jobs/{job_id}", str(job.id)) for job in jobs[:3]],
        ],
        details={
            "audits": _redact(
                [
                    {
                        "id": row.id,
                        "actor": row.actor,
                        "action": row.action,
                        "target_type": row.target_type,
                        "target_value": row.target_value,
                        "created_at": row.created_at.isoformat() if row.created_at is not None else None,
                    }
                    for row in audits
                ],
                enabled=redacted,
            ),
            "jobs": _redact([job_to_dict(job) for job in jobs], enabled=redacted),
        },
        suggested_followups=["Summarize failed jobs.", "Which sources have warnings?"],
    )


def _answer_general_question(db: Session, *, limit: int, redacted: bool) -> AssistantResult:
    alert_count = int(db.scalar(select(func.count(Alert.id))) or 0)
    log_count = int(db.scalar(select(func.count(NormalizedLog.id))) or 0)
    recent_alerts = list_alerts(db, limit=max(0, min(limit, 5)), sort_by="updated") if limit else []
    alert_text = " ".join(
        f"#{alert.id} {alert.severity} {alert.alert_type} status {alert.status}."
        for alert in recent_alerts
    )
    answer = (
        f"ATDR currently tracks {log_count} normalized logs and {alert_count} alerts. "
        "It ingests logs, preserves raw evidence, parses fields, runs rule/anomaly/supervised decision-support detection, groups alerts into cases, "
        "and records simulated analyst-approved response actions. "
        f"Recent alerts: {alert_text or 'none in the current context.'}"
    )
    return AssistantResult(
        answer=_text(answer, redacted=redacted),
        context_used=["system_summary", "recent_alerts"],
        citations=[
            Citation("ATDR PRD", "docs/prd/PRD-ATDR.md"),
            Citation("Alerts API", "/api/alerts"),
        ],
        details={
            "summary": {
                "normalized_logs": log_count,
                "alerts": alert_count,
                "recent_alert_count": len(recent_alerts),
            }
        },
        suggested_followups=["What is the latest critical alert?", "Explain current ML model status.", "Summarize source health."],
    )
