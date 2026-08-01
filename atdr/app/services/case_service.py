from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from hashlib import sha1
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session, noload

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
    return _case_key_values(
        src_ip=alert.src_ip,
        dst_ip=alert.dst_ip,
        matched_rules=alert.matched_rules_json or [],
        created_at=alert.created_at,
        window_hours=window_hours,
    )


def _case_key_values(
    *,
    src_ip: str | None,
    dst_ip: str | None,
    matched_rules: list[dict[str, Any]],
    created_at: datetime,
    window_hours: int,
) -> tuple[str, str, str, datetime]:
    attack_type = infer_attack_type_from_rules(matched_rules)
    return (
        src_ip or "unknown-source",
        dst_ip or "any-destination",
        attack_type,
        _window_start(created_at, window_hours),
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


def _case_evidence_summary(
    alerts: list[Alert],
    *,
    evidence_by_alert: dict[int, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    dst_ports: Counter[str] = Counter()
    actions: Counter[str] = Counter()
    related_logs = 0
    if evidence_by_alert is not None:
        for alert in alerts:
            summary = evidence_by_alert.get(int(alert.id), {})
            related_logs += int(summary.get("total_related_logs") or 0)
            dst_ports.update(summary.get("destination_ports") or {})
            actions.update(summary.get("actions") or {})
        return {
            "total_related_logs": related_logs,
            "top_destination_ports": [
                {"name": name, "count": count}
                for name, count in dst_ports.most_common(5)
            ],
            "top_actions": [
                {"name": name, "count": count}
                for name, count in actions.most_common(5)
            ],
        }
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


def _alert_evidence_aggregates(
    db: Session,
    alert_ids: list[int],
) -> dict[int, dict[str, Any]]:
    """Aggregate case evidence in SQL instead of hydrating every log row."""

    unique_ids = sorted({int(alert_id) for alert_id in alert_ids})
    if not unique_ids:
        return {}
    summaries: dict[int, dict[str, Any]] = {
        alert_id: {
            "total_related_logs": 0,
            "destination_ports": Counter(),
            "actions": Counter(),
        }
        for alert_id in unique_ids
    }
    rows = db.execute(
        select(
            AlertEvidence.alert_id,
            NormalizedLog.dst_port,
            NormalizedLog.action,
            func.count(AlertEvidence.id),
        )
        .join(
            NormalizedLog,
            NormalizedLog.id == AlertEvidence.normalized_log_id,
        )
        .where(AlertEvidence.alert_id.in_(unique_ids))
        .group_by(
            AlertEvidence.alert_id,
            NormalizedLog.dst_port,
            NormalizedLog.action,
        )
    )
    for alert_id, dst_port, action, count in rows:
        summary = summaries[int(alert_id)]
        row_count = int(count or 0)
        summary["total_related_logs"] += row_count
        if dst_port is not None:
            summary["destination_ports"][str(dst_port)] += row_count
        if action:
            summary["actions"][str(action)] += row_count
    return summaries


def _metadata_evidence_aggregates(
    alerts: list[Alert],
) -> tuple[dict[int, dict[str, Any]], list[int]]:
    summaries: dict[int, dict[str, Any]] = {}
    fallback_ids: list[int] = []
    for alert in alerts:
        metadata = next(
            (
                item
                for item in alert.matched_rules_json or []
                if item.get("code") == "group_metadata"
            ),
            {},
        )
        evidence_count = metadata.get(
            "related_log_count",
            metadata.get("evidence_count"),
        )
        if (
            evidence_count is None
            or "destination_port_counts" not in metadata
            or "action_counts" not in metadata
        ):
            fallback_ids.append(int(alert.id))
            continue
        summaries[int(alert.id)] = {
            "total_related_logs": int(evidence_count or 0),
            "destination_ports": Counter(
                {
                    str(key): int(value or 0)
                    for key, value in (
                        metadata.get("destination_port_counts") or {}
                    ).items()
                }
            ),
            "actions": Counter(
                {
                    str(key): int(value or 0)
                    for key, value in (
                        metadata.get("action_counts") or {}
                    ).items()
                }
            ),
        }
    return summaries, fallback_ids


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
        .options(noload(Alert.evidence))
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
    evidence_by_alert, fallback_ids = _metadata_evidence_aggregates(
        alerts
    )
    evidence_by_alert.update(
        _alert_evidence_aggregates(db, fallback_ids)
    )

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
        evidence_summary = _case_evidence_summary(
            group,
            evidence_by_alert=evidence_by_alert,
        )
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


def count_alert_cases(
    db: Session,
    *,
    active_only: bool = True,
    source_id: int | None = None,
    source_ids: list[int] | None = None,
    source_name: str | None = None,
    source_type: str | None = None,
    window_hours: int = 24,
    yield_per: int = 1_000,
) -> int:
    """Count computed case groups without loading alert evidence graphs."""

    statement = select(
        Alert.src_ip,
        Alert.dst_ip,
        Alert.matched_rules_json,
        Alert.created_at,
    ).order_by(Alert.id.asc())
    if active_only:
        statement = statement.where(Alert.status.in_(ACTIVE_CASE_STATUSES))
    if source_id is not None:
        statement = statement.where(
            Alert.id.in_(_alert_ids_for_sources(source_id=source_id))
        )
    elif source_ids is not None:
        if not source_ids:
            return 0
        statement = statement.where(
            Alert.id.in_(_alert_ids_for_sources(source_ids=source_ids))
        )
    elif source_name or source_type:
        statement = statement.where(
            Alert.id.in_(
                _alert_ids_for_sources(
                    source_name=source_name,
                    source_type=source_type,
                )
            )
        )

    keys: set[tuple[str, str, str, datetime]] = set()
    rows = db.execute(
        statement.execution_options(yield_per=max(1, yield_per))
    )
    for row in rows:
        keys.add(
            _case_key_values(
                src_ip=row.src_ip,
                dst_ip=row.dst_ip,
                matched_rules=row.matched_rules_json or [],
                created_at=row.created_at,
                window_hours=window_hours,
            )
        )
    return len(keys)


def _alert_ids_for_sources(
    *,
    source_id: int | None = None,
    source_ids: list[int] | None = None,
    source_name: str | None = None,
    source_type: str | None = None,
):
    statement = (
        select(AlertEvidence.alert_id)
        .distinct()
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
