from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from atdr.app.db.models import AuditLog, NormalizedLog, SuppressionRule
from atdr.app.schemas.suppressions import ALLOWED_SUPPRESSION_REVIEW_STATUSES


def list_suppressions(db: Session, *, active_only: bool = False) -> list[SuppressionRule]:
    statement = select(SuppressionRule).order_by(SuppressionRule.created_at.desc(), SuppressionRule.id.desc())
    if active_only:
        statement = statement.where(SuppressionRule.active.is_(True))
    return list(db.scalars(statement))


def create_suppression(
    db: Session,
    *,
    src_ip: str | None,
    app: str | None,
    alert_type: str | None,
    reason: str,
    actor: str,
) -> SuppressionRule:
    rule = SuppressionRule(
        src_ip=src_ip or None,
        app=app or None,
        alert_type=alert_type or None,
        reason=reason,
        created_by=actor,
    )
    db.add(rule)
    db.flush()
    db.add(
        AuditLog(
            actor=actor,
            action="suppression_created",
            target_type="suppression_rule",
            target_value=str(rule.id),
            details={"src_ip": rule.src_ip, "app": rule.app, "alert_type": rule.alert_type, "reason": reason},
        )
    )
    db.commit()
    db.refresh(rule)
    return rule


def disable_suppression(db: Session, rule_id: int, *, actor: str) -> SuppressionRule | None:
    rule = db.get(SuppressionRule, rule_id)
    if rule is None:
        return None
    rule.active = False
    rule.disabled_by = actor
    rule.disabled_at = datetime.now(timezone.utc)
    db.add(
        AuditLog(
            actor=actor,
            action="suppression_disabled",
            target_type="suppression_rule",
            target_value=str(rule.id),
            details={"suppressed_count": rule.suppressed_count},
        )
    )
    db.commit()
    db.refresh(rule)
    return rule


def review_suppression(
    db: Session,
    rule_id: int,
    *,
    review_status: str,
    review_notes: str | None,
    actor: str,
) -> SuppressionRule | None:
    normalized_status = review_status.strip().lower().replace("-", "_")
    if normalized_status not in ALLOWED_SUPPRESSION_REVIEW_STATUSES:
        raise ValueError(f"Unsupported suppression review status: {review_status}")
    rule = db.get(SuppressionRule, rule_id)
    if rule is None:
        return None
    rule.review_status = normalized_status
    rule.review_notes = review_notes.strip() if review_notes else None
    rule.reviewed_by = actor
    rule.reviewed_at = datetime.now(timezone.utc)
    db.add(
        AuditLog(
            actor=actor,
            action="suppression_reviewed",
            target_type="suppression_rule",
            target_value=str(rule.id),
            details={"review_status": normalized_status, "review_notes": rule.review_notes},
        )
    )
    db.commit()
    db.refresh(rule)
    return rule


def matching_suppression(
    db: Session,
    *,
    alert_type: str,
    logs: list[NormalizedLog],
    rules: list[SuppressionRule] | None = None,
) -> SuppressionRule | None:
    active_rules = rules
    if active_rules is None:
        active_rules = list(
            db.scalars(
                select(SuppressionRule)
                .where(SuppressionRule.active.is_(True))
                .order_by(SuppressionRule.id.asc())
            )
        )
    for rule in active_rules:
        if rule.alert_type and rule.alert_type != alert_type:
            continue
        for log in logs:
            if rule.src_ip and rule.src_ip != log.src_ip:
                continue
            if rule.app and (log.app or "").lower() != rule.app.lower():
                continue
            return rule
    return None


def record_suppression_hit(rule: SuppressionRule, *, count: int) -> None:
    rule.suppressed_count += count
    rule.last_matched_at = datetime.now(timezone.utc)
