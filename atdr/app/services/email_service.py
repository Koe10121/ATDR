from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from atdr.app.core.config import get_settings
from atdr.app.db.models import AuditLog, EmailNotificationEvent, User


DELIVERY_MODES = {"disabled", "log_only", "dev_outbox", "smtp"}


def normalize_delivery_mode(value: str | None = None) -> str:
    mode = (value if value is not None else get_settings().email_delivery_mode).strip().lower()
    return mode if mode in DELIVERY_MODES else "disabled"


def get_email_delivery_status() -> dict:
    settings = get_settings()
    mode = normalize_delivery_mode()
    smtp_configured = bool(settings.smtp_host.strip() and settings.smtp_from_email.strip())
    return {
        "notifications_enabled": settings.email_notifications_enabled,
        "verification_enabled": settings.email_verification_enabled,
        "delivery_mode": mode,
        "smtp_configured": smtp_configured,
        "smtp_enabled_legacy": settings.smtp_enabled,
        "from_email_configured": bool(settings.smtp_from_email.strip()),
        "dev_outbox_available": mode == "dev_outbox",
        "code_ttl_minutes": settings.email_verification_code_ttl_minutes,
        "code_length": settings.email_verification_code_length,
        "verification_required_for_login": settings.email_verification_required_for_login,
        "verification_required_for_admin_actions": settings.email_verification_required_for_admin_actions,
        "school_email_domains": settings.school_email_domain_list,
        "require_school_email": settings.require_school_email,
        "local_email_login_enabled": settings.local_email_login_enabled,
        "secrets_exposed": False,
    }


def record_email_notification(
    db: Session,
    *,
    user: User | None,
    recipient_email: str,
    subject: str,
    body_preview: str,
    purpose: str,
    actor: str,
    delivery_mode: str,
    delivery_status: str,
    error_summary: str | None = None,
    sent_at: datetime | None = None,
) -> EmailNotificationEvent:
    event = EmailNotificationEvent(
        user_id=user.id if user is not None else None,
        recipient_email=recipient_email,
        subject=subject,
        body_preview=body_preview,
        purpose=purpose,
        delivery_mode=delivery_mode,
        delivery_status=delivery_status,
        created_by=actor,
        sent_at=sent_at,
        error_summary=error_summary,
    )
    db.add(event)
    db.flush()
    db.add(
        AuditLog(
            actor=actor,
            action="email_notification_recorded",
            target_type="user",
            target_value=user.username if user is not None else recipient_email,
            details={
                "purpose": purpose,
                "delivery_mode": delivery_mode,
                "delivery_status": delivery_status,
                "user_id": user.id if user is not None else None,
                "recipient_email": recipient_email,
            },
        )
    )
    return event


def deliver_verification_code(
    db: Session,
    *,
    user: User,
    code: str,
    expires_at: datetime,
    actor: str,
) -> dict:
    settings = get_settings()
    mode = normalize_delivery_mode()
    if not settings.email_notifications_enabled or mode == "disabled":
        return {
            "delivery_mode": mode,
            "delivery_status": "disabled",
            "outbox_id": None,
            "message": "Email notifications are disabled; no email was sent.",
        }

    if mode == "dev_outbox":
        event = record_email_notification(
            db,
            user=user,
            recipient_email=user.email or "",
            subject="ATDR email verification code",
            body_preview=f"Verification code: {code}. Expires at {expires_at.isoformat()}.",
            purpose="email_verification",
            actor=actor,
            delivery_mode=mode,
            delivery_status="stored",
        )
        return {
            "delivery_mode": mode,
            "delivery_status": "stored",
            "outbox_id": event.id,
            "message": "Verification code stored in the local dev outbox. No real email was sent.",
        }

    if mode == "log_only":
        db.add(
            AuditLog(
                actor=actor,
                action="email_verification_code_generated",
                target_type="user",
                target_value=user.username,
                details={
                    "user_id": user.id,
                    "recipient_email": user.email,
                    "delivery_mode": mode,
                    "code_not_logged": True,
                },
            )
        )
        return {
            "delivery_mode": mode,
            "delivery_status": "logged",
            "outbox_id": None,
            "message": "Verification code generated in log-only mode. No real email was sent.",
        }

    record = record_email_notification(
        db,
        user=user,
        recipient_email=user.email or "",
        subject="ATDR email verification code",
        body_preview="SMTP delivery requested for an ATDR verification code.",
        purpose="email_verification",
        actor=actor,
        delivery_mode=mode,
        delivery_status="not_sent",
        error_summary="SMTP delivery is configuration groundwork only in v3.14.",
        sent_at=None,
    )
    return {
        "delivery_mode": mode,
        "delivery_status": "not_sent",
        "outbox_id": record.id,
        "message": "SMTP delivery is not active in this foundation phase. No real email was sent.",
    }


def list_dev_email_outbox(db: Session, *, limit: int = 25) -> list[EmailNotificationEvent]:
    safe_limit = min(max(limit, 1), 100)
    return list(
        db.scalars(
            select(EmailNotificationEvent)
            .order_by(EmailNotificationEvent.created_at.desc(), EmailNotificationEvent.id.desc())
            .limit(safe_limit)
        )
    )
