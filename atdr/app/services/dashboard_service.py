from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from atdr.app.db.models import Alert, NormalizedLog, SuppressionRule, WatchlistItem
from atdr.app.services.alert_service import alert_sla


def _group_counts(db: Session, column, limit: int = 10) -> list[dict]:
    rows = db.execute(
        select(column, func.count()).where(column.is_not(None)).group_by(column).order_by(desc(func.count())).limit(limit)
    ).all()
    return [{"name": str(name), "count": int(count)} for name, count in rows]


def build_dashboard_summary(db: Session) -> dict:
    total_logs = int(db.scalar(select(func.count(NormalizedLog.id))) or 0)
    total_alerts = int(db.scalar(select(func.count(Alert.id))) or 0)
    active_alerts = int(db.scalar(select(func.count(Alert.id)).where(Alert.status.in_(["open", "investigating", "contained"]))) or 0)
    critical_open = int(db.scalar(select(func.count(Alert.id)).where(Alert.severity == "Critical", Alert.status == "open")) or 0)
    high_open = int(db.scalar(select(func.count(Alert.id)).where(Alert.severity == "High", Alert.status == "open")) or 0)
    unassigned_alerts = int(
        db.scalar(
            select(func.count(Alert.id)).where(Alert.assigned_to.is_(None), Alert.status.in_(["open", "investigating", "contained"]))
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
    recent_alerts = db.scalars(select(Alert).order_by(Alert.created_at.desc(), Alert.id.desc()).limit(10)).all()

    return {
        "total_logs": total_logs,
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
                "evidence_count": len(alert.evidence),
                "created_at": alert.created_at,
                "sla": alert_sla(alert),
            }
            for alert in recent_alerts
        ],
    }
