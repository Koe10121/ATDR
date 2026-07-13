from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from hashlib import sha1
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from atdr.app.db.models import Alert, AlertEvidence, LogSource, NormalizedLog, RawLog
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


def _case_evidence_summary(alerts: list[Alert]) -> dict[str, Any]:
    dst_ports: Counter[str] = Counter()
    actions: Counter[str] = Counter()
    related_logs = 0
    for alert in alerts:
        for evidence in alert.evidence:
            related_logs += 1
            log = evidence.normalized_log
            if log is None:
                continue
            if log.dst_port is not None:
                dst_ports[str(log.dst_port)] += 1
            if log.action:
                actions[str(log.action)] += 1
    return {
        "total_related_logs": related_logs,
        "top_destination_ports": [{"name": name, "count": count} for name, count in dst_ports.most_common(5)],
        "top_actions": [{"name": name, "count": count} for name, count in actions.most_common(5)],
    }


def _recommended_focus(alerts: list[Alert], attack_types: list[str], evidence: dict[str, Any]) -> str:
    if "port_scan" in attack_types:
        return "Review repeated destination-port/service patterns and confirm whether the source is expected scanner traffic."
    if "malware_c2" in attack_types:
        return "Prioritize C2 validation, affected host ownership, and containment evidence before response."
    if evidence.get("top_actions"):
        top_action = evidence["top_actions"][0]["name"]
        return f"Start with {top_action} events, linked raw logs, and affected source/destination ownership."
    return "Review linked evidence logs, assign an analyst, and document the investigation decision."


def list_alert_cases(
    db: Session,
    *,
    active_only: bool = True,
    source_id: int | None = None,
    source_ids: list[int] | None = None,
    source_name: str | None = None,
    source_type: str | None = None,
    limit: int = 50,
    window_hours: int = 24,
) -> list[dict[str, Any]]:
    statement = (
        select(Alert)
        .options(selectinload(Alert.evidence).joinedload(AlertEvidence.normalized_log))
        .order_by(Alert.updated_at.desc(), Alert.id.desc())
        .limit(max(limit * 4, limit))
    )
    if active_only:
        statement = statement.where(Alert.status.in_(ACTIVE_CASE_STATUSES))
    if source_id is not None:
        statement = statement.where(Alert.id.in_(_alert_ids_for_sources(source_id=source_id)))
    elif source_ids is not None:
        if not source_ids:
            statement = statement.where(False)
        else:
            statement = statement.where(Alert.id.in_(_alert_ids_for_sources(source_ids=source_ids)))
    elif source_name or source_type:
        statement = statement.where(Alert.id.in_(_alert_ids_for_sources(source_name=source_name, source_type=source_type)))
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
        evidence_summary = _case_evidence_summary(group)
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
                **evidence_summary,
                "recommended_analyst_focus": _recommended_focus(group, attack_types, evidence_summary),
                "notes": [
                    "Computed case grouping only; no separate incident record is persisted yet.",
                    "Grouping uses source, destination, inferred attack type, time bucket, and repeated evidence patterns.",
                ],
            }
        )

    cases.sort(key=lambda item: (SEVERITY_RANK.get(item["severity"], 0), item["related_alert_count"], item["last_seen"]), reverse=True)
    return cases[:limit]


def _alert_ids_for_sources(
    *,
    source_id: int | None = None,
    source_ids: list[int] | None = None,
    source_name: str | None = None,
    source_type: str | None = None,
):
    statement = (
        select(AlertEvidence.alert_id)
        .join(NormalizedLog, NormalizedLog.id == AlertEvidence.normalized_log_id)
        .join(RawLog, RawLog.id == NormalizedLog.raw_log_id)
    )
    if source_id is not None:
        statement = statement.where(RawLog.source_id == source_id)
    if source_ids is not None:
        statement = statement.where(RawLog.source_id.in_(source_ids))
    if source_name or source_type:
        statement = statement.join(LogSource, LogSource.id == RawLog.source_id)
        if source_name:
            statement = statement.where(LogSource.name.ilike(f"%{source_name}%"))
        if source_type:
            statement = statement.where(LogSource.source_type == source_type)
    return statement
