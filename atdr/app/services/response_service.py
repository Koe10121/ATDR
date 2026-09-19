import socket
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from ipaddress import ip_address, ip_network

from sqlalchemy import select
from sqlalchemy.orm import Session

from atdr.app.core.config import get_settings
from atdr.app.db.models import AlertEvidence, AuditLog, BlockedIP, ResponseAction
from atdr.app.services import windows_firewall_connector


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


@lru_cache(maxsize=1)
def _local_host_addresses() -> frozenset[str]:
    # Real enforcement runs on this host's own Windows Firewall, so an
    # analyst must never be able to block the address(es) this host is
    # itself reachable on and lock out the ATDR backend. Best-effort,
    # stdlib-only discovery; failures degrade to an empty set rather than
    # raising, since PROTECTED_RESPONSE_NETWORKS already covers loopback.
    found: set[str] = set()
    try:
        _, _, addrs = socket.gethostbyname_ex(socket.gethostname())
        found.update(addrs)
    except OSError:
        pass
    for probe_target in ("8.8.8.8", "1.1.1.1"):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
                probe.settimeout(0.2)
                probe.connect((probe_target, 80))  # no packet is sent; UDP "connect" only sets routing
                found.add(probe.getsockname()[0])
        except OSError:
            continue
    return frozenset(found)


def _protected_ip_reason(target_ip: str) -> str | None:
    try:
        parsed = ip_address(target_ip)
    except ValueError:
        return "Target is not a valid IP address."
    if parsed.is_multicast or parsed.is_unspecified:
        return "Target IP is not a valid containment target."
    if any(parsed in network for network in PROTECTED_RESPONSE_NETWORKS):
        return "Target IP is in the protected internal/management allowlist."
    if target_ip in _local_host_addresses():
        return "Target IP is an address of the ATDR backend host itself and cannot be blocked."
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
        enforcement="not_applicable",
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


def _pending_connector_configured() -> bool:
    settings = get_settings()
    return not settings.response_simulation and settings.response_provider.lower() not in {"simulation", "windows_firewall"}


def _execute_block(target_ip: str) -> tuple[str, str, str, bool]:
    """Returns (status, message, enforcement_label, applied)."""
    settings = get_settings()
    if settings.response_simulation or settings.response_provider.lower() == "simulation":
        return (
            "simulated",
            f"Simulation mode: {target_ip} blocked; no firewall device was changed.",
            "simulated",
            True,
        )
    if _pending_connector_configured():
        return (
            "pending_connector",
            (
                f"{target_ip} block was recorded, but no approved firewall connector is implemented. "
                f"Configured provider is '{settings.response_provider}'."
            ),
            "pending_connector",
            False,
        )
    result = windows_firewall_connector.apply_block(target_ip)
    if result.ok:
        return "enforced", result.message, "windows_firewall", True
    return "enforcement_failed", result.message, "windows_firewall", False


def _execute_unblock(target_ip: str) -> tuple[str, str, str, bool]:
    """Returns (status, message, enforcement_label, applied). Always attempts
    real removal when real enforcement is configured, even if no tracked row
    exists, so a firewall rule can never be silently orphaned."""
    settings = get_settings()
    if settings.response_simulation or settings.response_provider.lower() == "simulation":
        return (
            "simulated",
            f"Simulation mode: {target_ip} marked unblocked; no firewall device was changed.",
            "simulated",
            True,
        )
    if _pending_connector_configured():
        return (
            "pending_connector",
            (
                f"{target_ip} unblock was recorded, but no approved firewall connector is implemented. "
                f"Configured provider is '{settings.response_provider}'."
            ),
            "pending_connector",
            False,
        )
    result = windows_firewall_connector.remove_block(target_ip)
    if result.ok:
        return "enforced", result.message, "windows_firewall", True
    return "enforcement_failed", result.message, "windows_firewall", False


def _sweep_expired_blocks(db: Session, *, actor: str = "system") -> None:
    now = datetime.now(timezone.utc)
    expired = db.scalars(
        select(BlockedIP).where(BlockedIP.active.is_(True), BlockedIP.expires_at.is_not(None), BlockedIP.expires_at <= now)
    )
    changed = False
    for row in expired:
        if row.enforcement == "windows_firewall":
            result = windows_firewall_connector.remove_block(row.ip_address)
            if not result.ok:
                # Leave active; the next sweep (or a manual unblock) retries.
                # A real, still-applied block must never silently disappear
                # from the dashboard while still in effect.
                continue
        row.active = False
        db.add(
            AuditLog(
                actor=actor,
                action="unblock_ip_expired",
                target_type="ip_address",
                target_value=row.ip_address,
                details={"reason": "timeout expired", "enforcement": row.enforcement},
            )
        )
        changed = True
    if changed:
        db.commit()


def block_ip(
    db: Session,
    *,
    target_ip: str,
    reason: str | None = None,
    alert_id: int | None = None,
    actor: str = "analyst",
    duration_minutes: int | None = None,
) -> ResponseAction:
    _sweep_expired_blocks(db, actor=actor)
    cleaned_reason = reason.strip() if reason else ""
    if not cleaned_reason:
        return _record_denied_response(
            db,
            action_type="block_ip",
            target_ip=target_ip,
            message="Denied: a response justification note is required before containment.",
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

    settings = get_settings()
    capped_duration = None
    if duration_minutes is not None:
        capped_duration = min(int(duration_minutes), settings.response_max_block_minutes)
    expires_at = (
        datetime.now(timezone.utc) + timedelta(minutes=capped_duration) if capped_duration is not None else None
    )

    status, result_message, enforcement, applied = _execute_block(target_ip)

    if applied:
        existing = db.scalar(select(BlockedIP).where(BlockedIP.ip_address == target_ip, BlockedIP.active.is_(True)))
        if existing is None:
            db.add(
                BlockedIP(
                    ip_address=target_ip,
                    reason=cleaned_reason,
                    created_by=actor,
                    active=True,
                    enforcement=enforcement,
                    expires_at=expires_at,
                )
            )
        else:
            existing.reason = cleaned_reason
            existing.enforcement = enforcement
            existing.expires_at = expires_at

    action = ResponseAction(
        alert_id=alert_id,
        action_type="block_ip",
        target_ip=target_ip,
        status=status,
        result_message=result_message,
        executed_by=actor,
        enforcement=enforcement,
    )
    db.add(action)
    db.add(
        AuditLog(
            actor=actor,
            action="block_ip",
            target_type="ip_address",
            target_value=target_ip,
            details={
                "alert_id": alert_id,
                "reason": cleaned_reason,
                "enforcement": enforcement,
                "status": status,
                "duration_minutes": capped_duration,
            },
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
    _sweep_expired_blocks(db, actor=actor)
    cleaned_reason = reason.strip() if reason else ""
    if not cleaned_reason:
        return _record_denied_response(
            db,
            action_type="unblock_ip",
            target_ip=target_ip,
            message="Denied: a response justification note is required before changing containment state.",
            reason=reason,
            alert_id=None,
            actor=actor,
        )

    status, result_message, enforcement, applied = _execute_unblock(target_ip)

    if applied:
        blocked = db.scalar(select(BlockedIP).where(BlockedIP.ip_address == target_ip, BlockedIP.active.is_(True)))
        if blocked is not None:
            blocked.active = False

    action = ResponseAction(
        action_type="unblock_ip",
        target_ip=target_ip,
        status=status,
        result_message=result_message,
        executed_by=actor,
        enforcement=enforcement,
    )
    db.add(action)
    db.add(
        AuditLog(
            actor=actor,
            action="unblock_ip",
            target_type="ip_address",
            target_value=target_ip,
            details={"reason": cleaned_reason, "status": status, "enforcement": enforcement},
        )
    )
    db.commit()
    db.refresh(action)
    return action


def list_blocked_ips(db: Session, active_only: bool = True) -> list[BlockedIP]:
    _sweep_expired_blocks(db)
    statement = select(BlockedIP).order_by(BlockedIP.created_at.desc(), BlockedIP.id.desc())
    if active_only:
        statement = statement.where(BlockedIP.active.is_(True))
    return list(db.scalars(statement))
