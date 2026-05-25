from ipaddress import ip_address, ip_network

from sqlalchemy import select
from sqlalchemy.orm import Session

from atdr.app.core.config import get_settings
from atdr.app.db.models import AlertEvidence, AuditLog, BlockedIP, ResponseAction


PROTECTED_RESPONSE_NETWORKS = [
    ip_network("10.0.0.0/8"),
    ip_network("172.16.0.0/12"),
    ip_network("192.168.0.0/16"),
    ip_network("127.0.0.0/8"),
    ip_network("169.254.0.0/16"),
    ip_network("::1/128"),
    ip_network("fc00::/7"),
    ip_network("fe80::/10"),
]


def _protected_ip_reason(target_ip: str) -> str | None:
    try:
        parsed = ip_address(target_ip)
    except ValueError:
        return "Target is not a valid IP address."
    if parsed.is_multicast or parsed.is_unspecified:
        return "Target IP is not a valid containment target."
    if any(parsed in network for network in PROTECTED_RESPONSE_NETWORKS):
        return "Target IP is in the protected internal/management allowlist."
    return None


def _alert_has_evidence(db: Session, alert_id: int | None) -> bool:
    if alert_id is None:
        return True
    return db.scalar(select(AlertEvidence.id).where(AlertEvidence.alert_id == alert_id).limit(1)) is not None


def _record_denied_response(
    db: Session,
    *,
    action_type: str,
    target_ip: str,
    message: str,
    reason: str | None,
    alert_id: int | None,
    actor: str,
) -> ResponseAction:
    action = ResponseAction(
        alert_id=alert_id,
        action_type=action_type,
        target_ip=target_ip,
        status="denied",
        result_message=message,
        executed_by=actor,
    )
    db.add(action)
    db.add(
        AuditLog(
            actor=actor,
            action=f"{action_type}_denied",
            target_type="ip_address",
            target_value=target_ip,
            details={"alert_id": alert_id, "reason": reason, "status": "denied", "message": message},
        )
    )
    db.commit()
    db.refresh(action)
    return action


def _response_outcome(action: str, target_ip: str) -> tuple[str, str, bool]:
    settings = get_settings()
    provider = settings.response_provider.lower()
    if settings.response_simulation or provider == "simulation":
        verb = "blocked" if action == "block_ip" else "marked unblocked"
        return "simulated", f"Simulation mode: {target_ip} {verb}; no firewall device was changed.", True
    return (
        "pending_connector",
        (
            f"{target_ip} {action.replace('_', ' ')} was recorded, but no approved firewall connector is implemented. "
            f"Configured provider is '{settings.response_provider}'."
        ),
        False,
    )


def block_ip(
    db: Session,
    *,
    target_ip: str,
    reason: str | None = None,
    alert_id: int | None = None,
    actor: str = "analyst",
) -> ResponseAction:
    cleaned_reason = reason.strip() if reason else ""
    if not cleaned_reason:
        return _record_denied_response(
            db,
            action_type="block_ip",
            target_ip=target_ip,
            message="Denied: a response justification note is required before simulated containment.",
            reason=reason,
            alert_id=alert_id,
            actor=actor,
        )

    protected_reason = _protected_ip_reason(target_ip)
    if protected_reason is not None:
        return _record_denied_response(
            db,
            action_type="block_ip",
            target_ip=target_ip,
            message=f"Denied: {protected_reason}",
            reason=cleaned_reason,
            alert_id=alert_id,
            actor=actor,
        )

    if not _alert_has_evidence(db, alert_id):
        return _record_denied_response(
            db,
            action_type="block_ip",
            target_ip=target_ip,
            message="Denied: linked alert has no evidence logs. Review evidence before containment.",
            reason=cleaned_reason,
            alert_id=alert_id,
            actor=actor,
        )

    existing = db.scalar(select(BlockedIP).where(BlockedIP.ip_address == target_ip, BlockedIP.active.is_(True)))
    if existing is None:
        db.add(BlockedIP(ip_address=target_ip, reason=cleaned_reason, created_by=actor, active=True))

    status, result_message, simulated = _response_outcome("block_ip", target_ip)
    action = ResponseAction(
        alert_id=alert_id,
        action_type="block_ip",
        target_ip=target_ip,
        status=status,
        result_message=result_message,
        executed_by=actor,
    )
    db.add(action)
    db.add(
        AuditLog(
            actor=actor,
            action="block_ip",
            target_type="ip_address",
            target_value=target_ip,
            details={"alert_id": alert_id, "reason": cleaned_reason, "simulation": simulated, "status": status},
        )
    )
    db.commit()
    db.refresh(action)
    return action


def unblock_ip(
    db: Session,
    *,
    target_ip: str,
    reason: str | None = None,
    actor: str = "analyst",
) -> ResponseAction:
    cleaned_reason = reason.strip() if reason else ""
    if not cleaned_reason:
        return _record_denied_response(
            db,
            action_type="unblock_ip",
            target_ip=target_ip,
            message="Denied: a response justification note is required before changing simulated containment state.",
            reason=reason,
            alert_id=None,
            actor=actor,
        )

    blocked = db.scalar(select(BlockedIP).where(BlockedIP.ip_address == target_ip, BlockedIP.active.is_(True)))
    if blocked is not None:
        blocked.active = False

    status, result_message, simulated = _response_outcome("unblock_ip", target_ip)
    action = ResponseAction(
        action_type="unblock_ip",
        target_ip=target_ip,
        status=status,
        result_message=result_message,
        executed_by=actor,
    )
    db.add(action)
    db.add(
        AuditLog(
            actor=actor,
            action="unblock_ip",
            target_type="ip_address",
            target_value=target_ip,
            details={"reason": cleaned_reason, "simulation": simulated, "status": status},
        )
    )
    db.commit()
    db.refresh(action)
    return action


def list_blocked_ips(db: Session, active_only: bool = True) -> list[BlockedIP]:
    statement = select(BlockedIP).order_by(BlockedIP.created_at.desc(), BlockedIP.id.desc())
    if active_only:
        statement = statement.where(BlockedIP.active.is_(True))
    return list(db.scalars(statement))
