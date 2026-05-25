from collections import defaultdict
from datetime import datetime, timedelta, timezone
from hashlib import sha1
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from atdr.app.db.models import Alert
from atdr.app.detection.attack_mapping import infer_attack_type_from_rules


ACTIVE_CASE_STATUSES = {"open", "investigating", "contained", "needs_more_context"}
SEVERITY_RANK = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
STATUS_RANK = {
    "open": 5,
    "needs_more_context": 4,
    "investigating": 3,
    "contained": 2,
    "resolved": 1,
    "false_positive": 0,
}


def _aware(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _window_start(value: datetime, hours: int) -> datetime:
    current = _aware(value)
    bucket_hour = (current.hour // hours) * hours
    return current.replace(hour=bucket_hour, minute=0, second=0, microsecond=0)


def _case_key(alert: Alert, *, window_hours: int) -> tuple[str, str, str, datetime]:
    attack_type = infer_attack_type_from_rules(alert.matched_rules_json or [])
    return (
        alert.src_ip or "unknown-source",
        alert.dst_ip or "any-destination",
        attack_type,
        _window_start(alert.created_at, window_hours),
    )


def _case_id(parts: tuple[str, str, str, datetime]) -> str:
    seed = "|".join([parts[0], parts[1], parts[2], parts[3].isoformat()])
    return sha1(seed.encode("utf-8")).hexdigest()[:12]


def _case_status(alerts: list[Alert]) -> str:
    return max((alert.status for alert in alerts), key=lambda status: STATUS_RANK.get(status, 0))


def _case_owner(alerts: list[Alert]) -> str | None:
    owners = sorted({alert.assigned_to for alert in alerts if alert.assigned_to})
    if len(owners) == 1:
        return owners[0]
    if len(owners) > 1:
        return "multiple"
    return None


def list_alert_cases(
    db: Session,
    *,
    active_only: bool = True,
    limit: int = 50,
    window_hours: int = 24,
) -> list[dict[str, Any]]:
    statement = select(Alert).order_by(Alert.updated_at.desc(), Alert.id.desc()).limit(max(limit * 4, limit))
    if active_only:
        statement = statement.where(Alert.status.in_(ACTIVE_CASE_STATUSES))
    alerts = list(db.scalars(statement))

    grouped: dict[tuple[str, str, str, datetime], list[Alert]] = defaultdict(list)
    for alert in alerts:
        grouped[_case_key(alert, window_hours=window_hours)].append(alert)

    cases: list[dict[str, Any]] = []
    for key, group in grouped.items():
        src_ips = sorted({alert.src_ip for alert in group if alert.src_ip})
        dst_ips = sorted({alert.dst_ip for alert in group if alert.dst_ip})
        attack_types = sorted({infer_attack_type_from_rules(alert.matched_rules_json or []) for alert in group})
        severity = max((alert.severity for alert in group), key=lambda value: SEVERITY_RANK.get(value, 0))
        first_seen = min(alert.created_at for alert in group)
        last_seen = max(alert.updated_at for alert in group)
        source_label = src_ips[0] if len(src_ips) == 1 else f"{len(src_ips)} sources"
        attack_label = attack_types[0] if len(attack_types) == 1 else "multiple attack types"
        cases.append(
            {
                "case_id": _case_id(key),
                "title": f"{severity} {attack_label} case from {source_label}",
                "related_alert_count": len(group),
                "source_ips": src_ips[:10],
                "destination_ips": dst_ips[:10],
                "attack_types": attack_types,
                "severity": severity,
                "status": _case_status(group),
                "assigned_analyst": _case_owner(group),
                "first_seen": first_seen,
                "last_seen": last_seen,
                "notes": [
                    "Computed case grouping only; no separate incident record is persisted yet.",
                    "Grouping uses source, destination, inferred attack type, and time bucket.",
                ],
            }
        )

    cases.sort(key=lambda item: (SEVERITY_RANK.get(item["severity"], 0), item["related_alert_count"], item["last_seen"]), reverse=True)
    return cases[:limit]
