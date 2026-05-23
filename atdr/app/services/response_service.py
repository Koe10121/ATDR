from sqlalchemy import select
from sqlalchemy.orm import Session

from atdr.app.core.config import get_settings
from atdr.app.db.models import AuditLog, BlockedIP, ResponseAction


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
    existing = db.scalar(select(BlockedIP).where(BlockedIP.ip_address == target_ip, BlockedIP.active.is_(True)))
    if existing is None:
        db.add(BlockedIP(ip_address=target_ip, reason=reason, created_by=actor, active=True))

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
            details={"alert_id": alert_id, "reason": reason, "simulation": simulated, "status": status},
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
            details={"reason": reason, "simulation": simulated, "status": status},
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
