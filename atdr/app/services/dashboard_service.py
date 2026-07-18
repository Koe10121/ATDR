from copy import deepcopy
from time import monotonic

from sqlalchemy import desc, func, or_, select
from sqlalchemy.orm import Session

from atdr.app.core.config import get_settings
from atdr.app.db.models import (
    Alert,
    AlertEvidence,
    AuditLog,
    DetectionRun,
    IngestionRun,
    NormalizedLog,
    RawLog,
    SuppressionRule,
    WatchlistItem,
)
from atdr.app.services.alert_service import alert_sla
from atdr.app.services.operation_run_service import detection_run_to_dict, ingestion_run_to_dict

UNKNOWN_APPS = {"unknown", "unknown-tcp", "unknown-udp", "unknown-p2p", "incomplete", "not-applicable"}
EXACT_JSON_QUALITY_LIMIT = 50_000
_SUMMARY_CACHE: dict[str, object] = {"expires_at": 0.0, "payload": None, "signature": None}


def _group_counts(db: Session, column, limit: int = 10) -> list[dict]:
    rows = db.execute(
        select(column, func.count()).where(column.is_not(None)).group_by(column).order_by(desc(func.count())).limit(limit)
    ).all()
    return [{"name": str(name), "count": int(count)} for name, count in rows]


def _json_parser_error_filter():
    return NormalizedLog.parsed_json["parser_error"].as_string().is_not(None)


def _count_where(db: Session, *filters) -> int:
    statement = select(func.count(NormalizedLog.id))
    for filter_clause in filters:
        statement = statement.where(filter_clause)
    return int(db.scalar(statement) or 0)


def _count_subquery(column, *filters):
    statement = select(func.count(column))
    if filters:
        statement = statement.where(*filters)
    return statement.scalar_subquery()


def _quality_missing_counts_statement():
    return select(
        _count_subquery(
            NormalizedLog.id,
            NormalizedLog.generated_time.is_(None),
            NormalizedLog.receive_time.is_(None),
        ).label("missing_timestamp"),
        _count_subquery(
            NormalizedLog.id,
            or_(NormalizedLog.src_ip.is_(None), NormalizedLog.src_ip == ""),
        ).label("missing_source_ip"),
        _count_subquery(
            NormalizedLog.id,
            or_(NormalizedLog.dst_ip.is_(None), NormalizedLog.dst_ip == ""),
        ).label("missing_destination_ip"),
        _count_subquery(
            NormalizedLog.id,
            or_(NormalizedLog.action.is_(None), NormalizedLog.action == ""),
        ).label("missing_action"),
    )


def _quality_app_counts_statement():
    return (
        select(NormalizedLog.app, func.count(NormalizedLog.id))
        .where(NormalizedLog.app.is_not(None))
        .group_by(NormalizedLog.app)
    )


def _parser_error_count(db: Session, total_logs: int) -> int:
    if total_logs <= EXACT_JSON_QUALITY_LIMIT:
        return _count_where(db, _json_parser_error_filter())
    return int(db.scalar(select(func.coalesce(func.sum(IngestionRun.parse_failures), 0))) or 0)


def _parser_error_examples(db: Session, *, total_logs: int, limit: int = 3) -> list[dict]:
    if total_logs > EXACT_JSON_QUALITY_LIMIT:
        return []
    rows = db.execute(
        select(
            NormalizedLog.id,
            NormalizedLog.raw_log_id,
            NormalizedLog.parsed_json,
            RawLog.raw_line,
        )
        .outerjoin(RawLog, RawLog.id == NormalizedLog.raw_log_id)
        .where(_json_parser_error_filter())
        .order_by(NormalizedLog.id.desc())
        .limit(limit)
    ).all()
    return [
        {
            "normalized_log_id": row.id,
            "raw_log_id": row.raw_log_id,
            "parser_error": row.parsed_json.get("parser_error"),
            "raw_line_excerpt": row.raw_line[:180] if row.raw_line else None,
        }
        for row in rows
    ]


def _alert_occurrence_count(db: Session) -> int:
    total = 0
    for rules in db.scalars(select(Alert.matched_rules_json)):
        metadata = next((rule for rule in (rules or []) if rule.get("code") == "group_metadata"), None)
        if metadata:
            total += int(metadata.get("occurrence_count") or metadata.get("related_log_count") or metadata.get("evidence_count") or 1)
        else:
            total += 1
    return total


def _quality_aggregate(db: Session) -> dict:
    row = db.execute(_quality_missing_counts_statement()).mappings().one()
    unknown_app_count = sum(
        int(count or 0)
        for app, count in db.execute(_quality_app_counts_statement()).all()
        if str(app).lower() in UNKNOWN_APPS
    )
    return {
        **{key: int(value or 0) for key, value in row.items()},
        "unknown_app_count": unknown_app_count,
    }


def _ingestion_stats(
    db: Session,
    total_logs: int,
    *,
    parse_failures: int,
    total_raw_logs: int | None = None,
) -> dict:
    total_raw = total_raw_logs if total_raw_logs is not None else int(db.scalar(select(func.count(RawLog.id))) or 0)
    duplicate_raw_logs = int(db.scalar(select(func.coalesce(func.sum(IngestionRun.duplicate_raw_logs), 0))) or 0)
    latest_generated = db.scalar(select(func.max(NormalizedLog.generated_time)))
    latest_receive = db.scalar(select(func.max(NormalizedLog.receive_time)))
    latest_detection_run_time = db.scalar(select(func.max(DetectionRun.finished_at)))
    return {
        "latest_raw_log_time": db.scalar(select(func.max(RawLog.imported_at))),
        "latest_normalized_log_time": latest_generated or latest_receive,
        "latest_detection_run_time": latest_detection_run_time,
        "import_count": total_raw,
        "parse_success_count": max(0, total_logs - parse_failures),
        "parse_failure_count": parse_failures,
        "duplicate_raw_line_groups": duplicate_raw_logs,
        "deduplicated_alert_updates": int(
            db.scalar(select(func.count(AuditLog.id)).where(AuditLog.action == "alert_deduplicated")) or 0
        ),
        "alert_occurrence_count": _alert_occurrence_count(db),
    }


def _data_quality_stats(db: Session, *, total_logs: int) -> dict:
    quality = _quality_aggregate(db)
    return {
        "missing_timestamp": quality["missing_timestamp"],
        "missing_source_ip": quality["missing_source_ip"],
        "missing_destination_ip": quality["missing_destination_ip"],
        "missing_action": quality["missing_action"],
        "unknown_app_count": quality["unknown_app_count"],
        "parser_error_examples": _parser_error_examples(db, total_logs=total_logs),
    }


def build_dashboard_summary(db: Session) -> dict:
    total_logs = int(db.scalar(select(func.count(NormalizedLog.id))) or 0)
    total_raw_logs = int(db.scalar(select(func.count(RawLog.id))) or 0)
    total_alerts = int(db.scalar(select(func.count(Alert.id))) or 0)
    active_statuses = ["open", "investigating", "needs_more_context", "contained"]
    active_alerts = int(db.scalar(select(func.count(Alert.id)).where(Alert.status.in_(active_statuses))) or 0)
    critical_open = int(db.scalar(select(func.count(Alert.id)).where(Alert.severity == "Critical", Alert.status == "open")) or 0)
    high_open = int(db.scalar(select(func.count(Alert.id)).where(Alert.severity == "High", Alert.status == "open")) or 0)
    unassigned_alerts = int(
        db.scalar(
            select(func.count(Alert.id)).where(Alert.assigned_to.is_(None), Alert.status.in_(active_statuses))
        )
        or 0
    )
    false_positive_alerts = int(db.scalar(select(func.count(Alert.id)).where(Alert.status == "false_positive")) or 0)
    anomaly_logs = int(db.scalar(select(func.count(NormalizedLog.id)).where(NormalizedLog.is_anomaly.is_(True))) or 0)
    active_suppressions = int(db.scalar(select(func.count(SuppressionRule.id)).where(SuppressionRule.active.is_(True))) or 0)
    suppressed_hits = int(db.scalar(select(func.coalesce(func.sum(SuppressionRule.suppressed_count), 0))) or 0)
    active_watchlist_items = int(db.scalar(select(func.count(WatchlistItem.id)).where(WatchlistItem.active.is_(True))) or 0)
    watchlist_hits = int(db.scalar(select(func.coalesce(func.sum(WatchlistItem.match_count), 0))) or 0)
    anomaly_rate = round((anomaly_logs / total_logs) * 100, 2) if total_logs else 0.0
    severity_rows = db.execute(select(Alert.severity, func.count(Alert.id)).group_by(Alert.severity)).all()
    status_rows = db.execute(select(Alert.status, func.count(Alert.id)).group_by(Alert.status)).all()
    alert_type_rows = db.execute(
        select(Alert.alert_type, func.count(Alert.id)).group_by(Alert.alert_type).order_by(desc(func.count(Alert.id))).limit(10)
    ).all()
    suspicious_rows = db.execute(
        select(Alert.src_ip, func.count(Alert.id))
        .where(Alert.src_ip.is_not(None))
        .group_by(Alert.src_ip)
        .order_by(desc(func.count(Alert.id)))
        .limit(10)
    ).all()
    evidence_count = (
        select(func.count(AlertEvidence.id))
        .where(AlertEvidence.alert_id == Alert.id)
        .correlate(Alert)
        .scalar_subquery()
    )
    recent_alert_rows = db.execute(
        select(Alert, evidence_count.label("evidence_count"))
        .order_by(Alert.created_at.desc(), Alert.id.desc())
        .limit(10)
    ).all()
    latest_ingestion_run = db.scalar(select(IngestionRun).order_by(desc(IngestionRun.started_at), desc(IngestionRun.id)).limit(1))
    latest_detection_run = db.scalar(select(DetectionRun).order_by(desc(DetectionRun.started_at), desc(DetectionRun.id)).limit(1))

    parse_failures = _parser_error_count(db, total_logs)
    ingestion_stats = _ingestion_stats(
        db,
        total_logs,
        parse_failures=parse_failures,
        total_raw_logs=total_raw_logs,
    )
    data_quality = _data_quality_stats(db, total_logs=total_logs)

    return {
        "total_logs": total_logs,
        "total_raw_logs": total_raw_logs,
        "total_alerts": total_alerts,
        "active_alerts": active_alerts,
        "critical_open_alerts": critical_open,
        "high_open_alerts": high_open,
        "unassigned_active_alerts": unassigned_alerts,
        "false_positive_alerts": false_positive_alerts,
        "ml_anomaly_logs": anomaly_logs,
        "anomaly_rate": anomaly_rate,
        "active_suppressions": active_suppressions,
        "suppressed_hits": suppressed_hits,
        "active_watchlist_items": active_watchlist_items,
        "watchlist_hits": watchlist_hits,
        "severity_counts": {severity: int(count) for severity, count in severity_rows},
        "status_counts": {status: int(count) for status, count in status_rows},
        "top_alert_types": [{"name": str(alert_type), "count": int(count)} for alert_type, count in alert_type_rows],
        "top_suspicious_source_ips": [{"name": str(src_ip), "count": int(count)} for src_ip, count in suspicious_rows],
        "top_destination_countries": _group_counts(db, NormalizedLog.dst_country),
        "action_distribution": _group_counts(db, NormalizedLog.action),
        "protocol_distribution": _group_counts(db, NormalizedLog.protocol),
        "app_risk_distribution": _group_counts(db, NormalizedLog.app_risk),
        "recent_alerts": [
            {
                "id": alert.id,
                "title": alert.title,
                "src_ip": alert.src_ip,
                "dst_ip": alert.dst_ip,
                "severity": alert.severity,
                "status": alert.status,
                "threat_score": alert.threat_score,
                "evidence_count": int(evidence_count or 0),
                "created_at": alert.created_at,
                "sla": alert_sla(alert),
            }
            for alert, evidence_count in recent_alert_rows
        ],
        "ingestion_stats": ingestion_stats,
        "data_quality": data_quality,
        "latest_ingestion_run": ingestion_run_to_dict(latest_ingestion_run) if latest_ingestion_run else None,
        "latest_detection_run": detection_run_to_dict(latest_detection_run) if latest_detection_run else None,
    }


def clear_dashboard_summary_cache() -> None:
    _SUMMARY_CACHE["expires_at"] = 0.0
    _SUMMARY_CACHE["payload"] = None
    _SUMMARY_CACHE["signature"] = None


def _dashboard_cache_signature_statement():
    return select(
        _count_subquery(NormalizedLog.id).label("normalized_log_count"),
        _count_subquery(RawLog.id).label("raw_log_count"),
        _count_subquery(Alert.id).label("alert_count"),
        select(func.max(Alert.updated_at)).scalar_subquery().label("latest_alert_update"),
        select(func.coalesce(func.max(IngestionRun.id), 0)).scalar_subquery().label("latest_ingestion_run_id"),
        select(func.max(IngestionRun.finished_at)).scalar_subquery().label("latest_ingestion_finish"),
        select(func.coalesce(func.max(DetectionRun.id), 0)).scalar_subquery().label("latest_detection_run_id"),
        select(func.max(DetectionRun.finished_at)).scalar_subquery().label("latest_detection_finish"),
        select(func.coalesce(func.max(AuditLog.id), 0)).scalar_subquery().label("latest_audit_id"),
        _count_subquery(SuppressionRule.id, SuppressionRule.active.is_(True)).label("active_suppression_count"),
        select(func.coalesce(func.sum(SuppressionRule.suppressed_count), 0))
        .scalar_subquery()
        .label("suppressed_hit_count"),
        _count_subquery(WatchlistItem.id, WatchlistItem.active.is_(True)).label("active_watchlist_count"),
        select(func.coalesce(func.sum(WatchlistItem.match_count), 0)).scalar_subquery().label("watchlist_hit_count"),
    )


def _dashboard_cache_signature(db: Session) -> tuple:
    bind = db.get_bind()
    row = db.execute(_dashboard_cache_signature_statement()).one()
    return (str(bind.url) if hasattr(bind, "url") else id(bind), *tuple(row))


def build_dashboard_summary_cached(db: Session) -> dict:
    ttl = max(0, get_settings().dashboard_summary_cache_seconds)
    if ttl <= 0:
        return build_dashboard_summary(db)
    now = monotonic()
    signature = _dashboard_cache_signature(db)
    cached_payload = _SUMMARY_CACHE.get("payload")
    if cached_payload is not None and _SUMMARY_CACHE.get("signature") == signature and now < float(_SUMMARY_CACHE.get("expires_at") or 0):
        payload = deepcopy(cached_payload)
        payload["performance"] = {"cached": True, "cache_ttl_seconds": ttl}
        return payload
    payload = build_dashboard_summary(db)
    payload["performance"] = {"cached": False, "cache_ttl_seconds": ttl}
    _SUMMARY_CACHE["payload"] = deepcopy(payload)
    _SUMMARY_CACHE["expires_at"] = now + ttl
    _SUMMARY_CACHE["signature"] = signature
    return payload
