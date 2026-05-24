from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import case, func, select
from sqlalchemy.orm import Session

from atdr.app.db.models import NormalizedLog
from atdr.app.detection.ml_detector import CATEGORICAL_FEATURES as BASE_CATEGORICAL_FEATURES
from atdr.app.detection.ml_detector import NUMERIC_FEATURES as BASE_NUMERIC_FEATURES
from atdr.app.services.ml_service import UNKNOWN_APPS


WINDOW_NUMERIC_FEATURES = [
    "src_ip_5min_log_count",
    "src_ip_5min_deny_count",
    "src_ip_5min_unique_dst_ports",
    "src_ip_5min_unique_dst_ips",
    "src_ip_5min_total_bytes",
    "src_ip_5min_avg_packets",
    "src_ip_5min_unknown_app_count",
    "src_ip_5min_high_risk_app_count",
    "dst_ip_5min_connection_count",
    "deny_rate_5min",
    "hour_of_day",
    "is_after_hours",
]

NUMERIC_FEATURES = [*BASE_NUMERIC_FEATURES, *WINDOW_NUMERIC_FEATURES]
CATEGORICAL_FEATURES = list(BASE_CATEGORICAL_FEATURES)
FEATURE_COLUMNS = [*NUMERIC_FEATURES, *CATEGORICAL_FEATURES]


def _log_time(log: NormalizedLog) -> datetime:
    value = log.generated_time or log.receive_time or log.start_time
    if value is None:
        return datetime.now(timezone.utc)
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def _window_statement(log: NormalizedLog):
    end = _log_time(log)
    start = end - timedelta(minutes=5)
    statement = select(NormalizedLog).where(NormalizedLog.generated_time >= start, NormalizedLog.generated_time <= end)
    if log.src_ip:
        statement = statement.where(NormalizedLog.src_ip == log.src_ip)
    else:
        statement = statement.where(NormalizedLog.id == log.id)
    return statement


def _src_window_metrics(db: Session, log: NormalizedLog) -> dict[str, Any]:
    window = _window_statement(log).subquery()
    lower_action = func.lower(window.c.action)
    lower_app = func.lower(window.c.app)
    row = db.execute(
        select(
            func.count(),
            func.sum(case((lower_action.in_(["deny", "drop"]), 1), else_=0)),
            func.count(func.distinct(window.c.dst_port)),
            func.count(func.distinct(window.c.dst_ip)),
            func.coalesce(func.sum(window.c.bytes), 0),
            func.avg(window.c.packets),
            func.sum(case((lower_app.in_(UNKNOWN_APPS), 1), else_=0)),
            func.sum(case((window.c.app_risk >= 4, 1), else_=0)),
        )
    ).one()
    log_count = int(row[0] or 0)
    deny_count = int(row[1] or 0)
    return {
        "src_ip_5min_log_count": log_count,
        "src_ip_5min_deny_count": deny_count,
        "src_ip_5min_unique_dst_ports": int(row[2] or 0),
        "src_ip_5min_unique_dst_ips": int(row[3] or 0),
        "src_ip_5min_total_bytes": int(row[4] or 0),
        "src_ip_5min_avg_packets": float(row[5] or 0),
        "src_ip_5min_unknown_app_count": int(row[6] or 0),
        "src_ip_5min_high_risk_app_count": int(row[7] or 0),
        "deny_rate_5min": round(deny_count / log_count, 4) if log_count else 0.0,
    }


def _dst_window_count(db: Session, log: NormalizedLog) -> int:
    if not log.dst_ip:
        return 0
    end = _log_time(log)
    start = end - timedelta(minutes=5)
    statement = select(func.count(NormalizedLog.id)).where(
        NormalizedLog.dst_ip == log.dst_ip,
        NormalizedLog.generated_time >= start,
        NormalizedLog.generated_time <= end,
    )
    return int(db.scalar(statement) or 0)


def build_log_features(db: Session, log: NormalizedLog) -> dict[str, Any]:
    features = {feature: getattr(log, feature) for feature in BASE_NUMERIC_FEATURES}
    features.update({feature: getattr(log, feature) for feature in BASE_CATEGORICAL_FEATURES})
    window_features = _src_window_metrics(db, log)
    log_time = _log_time(log)
    hour = int(log_time.hour)
    features.update(window_features)
    features["dst_ip_5min_connection_count"] = _dst_window_count(db, log)
    features["hour_of_day"] = hour
    features["is_after_hours"] = int(hour < 7 or hour >= 18)
    return features


def build_feature_rows(db: Session, logs: list[NormalizedLog]) -> list[dict[str, Any]]:
    return [build_log_features(db, log) for log in logs]
