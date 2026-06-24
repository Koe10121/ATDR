from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import secrets

from sqlalchemy import select
from sqlalchemy.orm import Session

from atdr.app.core.config import get_settings
from atdr.app.db.models import AccountEmailVerificationToken, AuditLog, User
from atdr.app.services.email_service import deliver_verification_code, normalize_delivery_mode


@dataclass(frozen=True)
class VerificationRequestResult:
    created: bool
    status: str
    message: str
    user_id: int | None
    email: str | None
    expires_at: datetime | None
    delivery_mode: str
    delivery_status: str
    outbox_id: int | None = None


@dataclass(frozen=True)
class VerificationCheckResult:
    verified: bool
    status: str
    message: str


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _as_aware(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


def _generate_code(length: int) -> str:
    upper = 10**length
    return f"{secrets.randbelow(upper):0{length}d}"


def _hash_code(code: str) -> str:
    settings = get_settings()
    return hashlib.sha256(f"{settings.jwt_secret_key}:{code.strip()}".encode("utf-8")).hexdigest()


def request_email_verification(db: Session, *, user: User, actor: str) -> VerificationRequestResult:
    settings = get_settings()
    mode = normalize_delivery_mode()
    if not user.email:
        db.add(
            AuditLog(
                actor=actor,
                action="email_verification_request_failed",
                target_type="user",
                target_value=user.username,
                details={"reason": "missing_email", "user_id": user.id},
            )
        )
        db.commit()
        return VerificationRequestResult(
            created=False,
            status="missing_email",
            message="User does not have an email address to verify.",
            user_id=user.id,
            email=None,
            expires_at=None,
            delivery_mode=mode,
            delivery_status="not_created",
        )

    if not settings.email_verification_enabled:
        db.add(
            AuditLog(
                actor=actor,
                action="email_verification_request_skipped",
                target_type="user",
                target_value=user.username,
                details={"reason": "email_verification_disabled", "user_id": user.id, "delivery_mode": mode},
            )
        )
        db.commit()
        return VerificationRequestResult(
            created=False,
            status="disabled",
            message="Email verification is disabled; no token was created.",
            user_id=user.id,
            email=user.email,
            expires_at=None,
            delivery_mode=mode,
            delivery_status="disabled",
        )

    code = _generate_code(settings.email_verification_code_length)
    expires_at = _now() + timedelta(minutes=settings.email_verification_code_ttl_minutes)
    token = AccountEmailVerificationToken(
        user_id=user.id,
        email=user.email,
        token_hash=_hash_code(code),
        purpose="email_verification",
        expires_at=expires_at,
        created_by=actor,
        delivery_mode=mode,
        delivery_status="pending",
    )
    db.add(token)
    db.flush()
    delivery = deliver_verification_code(db, user=user, code=code, expires_at=expires_at, actor=actor)
    token.delivery_status = delivery["delivery_status"]
    db.add(
        AuditLog(
            actor=actor,
            action="email_verification_requested",
            target_type="user",
            target_value=user.username,
            details={
                "user_id": user.id,
                "email": user.email,
                "token_id": token.id,
                "expires_at": expires_at.isoformat(),
                "delivery_mode": delivery["delivery_mode"],
                "delivery_status": delivery["delivery_status"],
                "outbox_id": delivery.get("outbox_id"),
            },
        )
    )
    db.commit()
    return VerificationRequestResult(
        created=True,
        status="created",
        message=delivery["message"],
        user_id=user.id,
        email=user.email,
        expires_at=expires_at,
        delivery_mode=delivery["delivery_mode"],
        delivery_status=delivery["delivery_status"],
        outbox_id=delivery.get("outbox_id"),
    )


def verify_email_code(db: Session, *, user: User, code: str, actor: str) -> VerificationCheckResult:
    settings = get_settings()
    if not settings.email_verification_enabled:
        db.add(
            AuditLog(
                actor=actor,
                action="email_verification_failed",
                target_type="user",
                target_value=user.username,
                details={"reason": "email_verification_disabled", "user_id": user.id},
            )
        )
        db.commit()
        return VerificationCheckResult(
            verified=False,
            status="disabled",
            message="Email verification is disabled.",
        )

    tokens = list(
        db.scalars(
            select(AccountEmailVerificationToken)
            .where(
                AccountEmailVerificationToken.user_id == user.id,
                AccountEmailVerificationToken.purpose == "email_verification",
                AccountEmailVerificationToken.used_at.is_(None),
            )
            .order_by(AccountEmailVerificationToken.created_at.desc(), AccountEmailVerificationToken.id.desc())
        )
    )
    if not tokens:
        _audit_verification_failure(db, user=user, actor=actor, reason="no_active_token")
        return VerificationCheckResult(verified=False, status="not_found", message="No active verification code was found.")

    now = _now()
    provided_hash = _hash_code(code)
    saw_expired = False
    for token in tokens:
        if _as_aware(token.expires_at) < now:
            saw_expired = True
            continue
        if hmac.compare_digest(token.token_hash, provided_hash):
            db_user = db.get(User, user.id)
            if db_user is None:
                _audit_verification_failure(db, user=user, actor=actor, reason="user_missing")
                return VerificationCheckResult(verified=False, status="not_found", message="User no longer exists.")
            token.used_at = now
            token.delivery_status = "used"
            db_user.email_verified = True
            db.add(
                AuditLog(
                    actor=actor,
                    action="email_verified",
                    target_type="user",
                    target_value=user.username,
                    details={"user_id": user.id, "email": user.email, "token_id": token.id},
                )
            )
            db.commit()
            return VerificationCheckResult(verified=True, status="verified", message="Email address verified.")

    reason = "expired" if saw_expired and len(tokens) == 1 else "invalid_code"
    _audit_verification_failure(db, user=user, actor=actor, reason=reason)
    return VerificationCheckResult(
        verified=False,
        status=reason,
        message="Verification code expired." if reason == "expired" else "Verification code is invalid.",
    )


def _audit_verification_failure(db: Session, *, user: User, actor: str, reason: str) -> None:
    db.add(
        AuditLog(
            actor=actor,
            action="email_verification_failed",
            target_type="user",
            target_value=user.username,
            details={"reason": reason, "user_id": user.id, "email": user.email},
        )
    )
    db.commit()
