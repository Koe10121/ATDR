from sqlalchemy import select
from sqlalchemy.orm import Session

from atdr.app.core.config import get_settings
from atdr.app.db.models import AuditLog, BlockedIP, ResponseAction


def block_ip(
    db: Session,
    *,
    target_ip: str,
    reason: str | None = None,
    alert_id: int | None = None,
    actor: str = "analyst",
) -> ResponseAction:
    settings = get_settings()
    existing = db.scalar(select(BlockedIP).where(BlockedIP.ip_address == target_ip, BlockedIP.active.is_(True)))
    if existing is None:
        db.add(BlockedIP(ip_address=target_ip, reason=reason, created_by=actor, active=True))

    status = "simulated" if settings.response_simulation else "executed"
    result_message = (
        f"Simulation mode: {target_ip} recorded as blocked; no firewall device was changed."
        if settings.response_simulation
        else f"{target_ip} block action recorded for firewall enforcement."
    )
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
            details={"alert_id": alert_id, "reason": reason, "simulation": settings.response_simulation},
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
    settings = get_settings()
    blocked = db.scalar(select(BlockedIP).where(BlockedIP.ip_address == target_ip, BlockedIP.active.is_(True)))
    if blocked is not None:
        blocked.active = False

    status = "simulated" if settings.response_simulation else "executed"
    result_message = (
        f"Simulation mode: {target_ip} marked unblocked; no firewall device was changed."
        if settings.response_simulation
        else f"{target_ip} unblock action recorded for firewall enforcement."
    )
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
            details={"reason": reason, "simulation": settings.response_simulation},
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
