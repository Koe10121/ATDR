from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func, not_, or_, select
from sqlalchemy.orm import Session

from atdr.app.db.models import AuditLog


APPLY_CONFIRMATION = "APPLY-AUDIT-RETENTION"


def _protected_event_condition():
    action = func.lower(AuditLog.action)
    return or_(
        action.contains("denied"),
        action.like("mfu_iam%"),
        action.like("iam_%"),
        action.contains("_iam_"),
        action.like("auth_%"),
        action.like("login_%"),
        action.like("account_%"),
        action.like("email_verification_%"),
        action.like("response_%"),
        action.like("block_%"),
        action.like("unblock_%"),
    )


def _validate_policy(*, retention_days: int, minimum_days: int, batch_size: int) -> None:
    if minimum_days <= 0:
        raise ValueError("Minimum audit retention must be greater than zero days.")
    if retention_days < minimum_days:
        raise ValueError(f"Audit retention cannot be shorter than the configured minimum of {minimum_days} days.")
    if batch_size <= 0:
        raise ValueError("Audit retention batch size must be greater than zero.")


def build_audit_retention_report(
    db: Session,
    *,
    retention_days: int,
    minimum_days: int,
    batch_size: int,
) -> dict[str, Any]:
    """Describe eligible audit cleanup without mutating any row."""

    _validate_policy(retention_days=retention_days, minimum_days=minimum_days, batch_size=batch_size)
    cutoff = datetime.now(timezone.utc) - timedelta(days=int(retention_days))
    old_filter = AuditLog.created_at < cutoff
    protected = _protected_event_condition()
    old_count = int(db.scalar(select(func.count(AuditLog.id)).where(old_filter)) or 0)
    protected_count = int(db.scalar(select(func.count(AuditLog.id)).where(old_filter, protected)) or 0)
    eligible_count = int(db.scalar(select(func.count(AuditLog.id)).where(old_filter, not_(protected))) or 0)
    batch_count = min(eligible_count, int(batch_size))
    return {
        "mode": "dry_run",
        "retention_days": int(retention_days),
        "minimum_retention_days": int(minimum_days),
        "batch_size": int(batch_size),
        "cutoff": cutoff,
        "old_event_count": old_count,
        "protected_security_event_count": protected_count,
        "eligible_event_count": eligible_count,
        "would_delete_count": batch_count,
        "raw_log_rows_touched": 0,
        "response_action_rows_touched": 0,
        "requires_explicit_apply": True,
        "secrets_exposed": False,
    }


def apply_audit_retention(
    db: Session,
    *,
    retention_days: int,
    minimum_days: int,
    batch_size: int,
    confirmation: str,
    actor: str = "audit-retention-cli",
) -> dict[str, Any]:
    """Delete only eligible old audit rows after an exact explicit confirmation."""

    if confirmation != APPLY_CONFIRMATION:
        raise ValueError(f"Applying retention requires --confirm {APPLY_CONFIRMATION}.")
    report = build_audit_retention_report(
        db,
        retention_days=retention_days,
        minimum_days=minimum_days,
        batch_size=batch_size,
    )
    cutoff = datetime.now(timezone.utc) - timedelta(days=int(retention_days))
    candidates = list(
        db.scalars(
            select(AuditLog)
            .where(AuditLog.created_at < cutoff, not_(_protected_event_condition()))
            .order_by(AuditLog.created_at.asc(), AuditLog.id.asc())
            .limit(int(batch_size))
        )
    )
    for event in candidates:
        db.delete(event)
    db.flush()
    db.add(
        AuditLog(
            actor=actor,
            action="audit_retention_applied",
            target_type="audit_log",
            target_value="retention_batch",
            details={
                "retention_days": int(retention_days),
                "minimum_retention_days": int(minimum_days),
                "deleted_count": len(candidates),
                "protected_security_events_preserved": True,
                "raw_log_rows_touched": 0,
            },
        )
    )
    db.commit()
    return {
        **report,
        "mode": "apply",
        "deleted_count": len(candidates),
        "would_delete_count": 0,
        "raw_log_rows_touched": 0,
        "response_action_rows_touched": 0,
    }
