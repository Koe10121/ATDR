from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import case, func, select
from sqlalchemy.orm import Session

from atdr.app.db.models import NormalizedLog
from atdr.app.detection.ml_detector import CATEGORICAL_FEATURES as BASE_CATEGORICAL_FEATURES
from atdr.app.detection.ml_detector import NUMERIC_FEATURES as BASE_NUMERIC_FEATURES
from atdr.app.detection.rules import COMMON_PORTS
from atdr.app.services.ml_service import UNKNOWN_APPS


def _dedupe(items: list[str]) -> list[str]:
    return list(dict.fromkeys(items))


LEGACY_WINDOW_NUMERIC_FEATURES = [
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

WINDOW_DEFINITIONS = {
    "5min": 5,
    "15min": 15,
    "1h": 60,
    "24h": 24 * 60,
}

EXTENDED_WINDOW_NUMERIC_FEATURES = [
    feature
    for label in WINDOW_DEFINITIONS
    for feature in [
        f"src_ip_{label}_event_count",
        f"dst_ip_{label}_event_count",
        f"src_ip_{label}_unique_dst_ports",
        f"src_ip_{label}_unique_dst_ips",
        f"src_ip_{label}_deny_drop_reset_count",
        f"src_ip_{label}_allow_count",
        f"src_ip_{label}_deny_ratio",
        f"src_ip_{label}_total_bytes",
        f"src_ip_{label}_bytes_sent",
        f"src_ip_{label}_bytes_received",
        f"src_ip_{label}_avg_packets",
        f"src_ip_{label}_unknown_app_count",
        f"src_ip_{label}_high_risk_app_count",
    ]
]

BEHAVIOR_NUMERIC_FEATURES = [
    "rare_dst_port_flag",
    "rare_app_flag",
    "unknown_app_flag",
    "external_to_internal_flag",
    "internal_to_external_flag",
    "first_seen_src_ip_flag",
    "first_seen_app_flag",
    "repeated_connection_attempts",
    "scanning_like_behavior_score",
]

WINDOW_NUMERIC_FEATURES = _dedupe([*LEGACY_WINDOW_NUMERIC_FEATURES, *EXTENDED_WINDOW_NUMERIC_FEATURES, *BEHAVIOR_NUMERIC_FEATURES])
NUMERIC_FEATURES = _dedupe([*BASE_NUMERIC_FEATURES, *WINDOW_NUMERIC_FEATURES])
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
    if log.generated_time is None and log.receive_time is None and log.start_time is None:
        return select(NormalizedLog).where(NormalizedLog.id == log.id)
    end = _log_time(log)
    start = end - timedelta(minutes=5)
    statement = select(NormalizedLog).where(NormalizedLog.generated_time >= start, NormalizedLog.generated_time <= end)
    if log.src_ip:
        statement = statement.where(NormalizedLog.src_ip == log.src_ip)
    else:
        statement = statement.where(NormalizedLog.id == log.id)
    return statement


def _src_window_statement(log: NormalizedLog, minutes: int):
    if log.generated_time is None and log.receive_time is None and log.start_time is None:
        return select(NormalizedLog).where(NormalizedLog.id == log.id)
    end = _log_time(log)
    start = end - timedelta(minutes=minutes)
    statement = select(NormalizedLog).where(NormalizedLog.generated_time >= start, NormalizedLog.generated_time <= end)
    if log.src_ip:
        statement = statement.where(NormalizedLog.src_ip == log.src_ip)
    else:
        statement = statement.where(NormalizedLog.id == log.id)
    return statement


def _src_window_metrics_for_minutes(db: Session, log: NormalizedLog, minutes: int, label: str) -> dict[str, Any]:
    window = _src_window_statement(log, minutes).subquery()
    lower_action = func.lower(window.c.action)
    lower_app = func.lower(window.c.app)
    row = db.execute(
        select(
            func.count(),
            func.sum(case((lower_action.in_(["deny", "drop"]), 1), else_=0)),
            func.count(func.distinct(window.c.dst_port)),
            func.count(func.distinct(window.c.dst_ip)),
            func.coalesce(func.sum(window.c.bytes), 0),
            func.coalesce(func.sum(window.c.bytes_sent), 0),
            func.coalesce(func.sum(window.c.bytes_received), 0),
            func.avg(window.c.packets),
            func.sum(case((lower_app.in_(UNKNOWN_APPS), 1), else_=0)),
            func.sum(case((window.c.app_risk >= 4, 1), else_=0)),
            func.sum(case((lower_action == "allow", 1), else_=0)),
        )
    ).one()
    log_count = int(row[0] or 0)
    deny_count = int(row[1] or 0)
    return {
        f"src_ip_{label}_event_count": log_count,
        f"src_ip_{label}_unique_dst_ports": int(row[2] or 0),
        f"src_ip_{label}_unique_dst_ips": int(row[3] or 0),
        f"src_ip_{label}_deny_drop_reset_count": deny_count,
        f"src_ip_{label}_total_bytes": int(row[4] or 0),
        f"src_ip_{label}_bytes_sent": int(row[5] or 0),
        f"src_ip_{label}_bytes_received": int(row[6] or 0),
        f"src_ip_{label}_avg_packets": float(row[7] or 0),
        f"src_ip_{label}_unknown_app_count": int(row[8] or 0),
        f"src_ip_{label}_high_risk_app_count": int(row[9] or 0),
        f"src_ip_{label}_allow_count": int(row[10] or 0),
        f"src_ip_{label}_deny_ratio": round(deny_count / log_count, 4) if log_count else 0.0,
    }


def _src_window_metrics(db: Session, log: NormalizedLog) -> dict[str, Any]:
    metrics = _src_window_metrics_for_minutes(db, log, 5, "5min")
    return {
        "src_ip_5min_log_count": metrics["src_ip_5min_event_count"],
        "src_ip_5min_deny_count": metrics["src_ip_5min_deny_drop_reset_count"],
        "src_ip_5min_unique_dst_ports": metrics["src_ip_5min_unique_dst_ports"],
        "src_ip_5min_unique_dst_ips": metrics["src_ip_5min_unique_dst_ips"],
        "src_ip_5min_total_bytes": metrics["src_ip_5min_total_bytes"],
        "src_ip_5min_avg_packets": metrics["src_ip_5min_avg_packets"],
        "src_ip_5min_unknown_app_count": metrics["src_ip_5min_unknown_app_count"],
        "src_ip_5min_high_risk_app_count": metrics["src_ip_5min_high_risk_app_count"],
        "deny_rate_5min": metrics["src_ip_5min_deny_ratio"],
    }


def _dst_window_count(db: Session, log: NormalizedLog, minutes: int = 5) -> int:
    if not log.dst_ip:
        return 0
    end = _log_time(log)
    start = end - timedelta(minutes=minutes)
    statement = select(func.count(NormalizedLog.id)).where(
        NormalizedLog.dst_ip == log.dst_ip,
        NormalizedLog.generated_time >= start,
        NormalizedLog.generated_time <= end,
    )
    return int(db.scalar(statement) or 0)


def _lower(value: str | None) -> str:
    return (value or "").strip().lower()


def _zone_contains(value: str | None, tokens: tuple[str, ...]) -> bool:
    lowered = _lower(value)
    return any(token in lowered for token in tokens)


def _is_deny_drop_reset(action: str | None) -> bool:
    lowered = _lower(action)
    return "deny" in lowered or "drop" in lowered or lowered.startswith("reset")


def _global_count(db: Session, column, value: Any) -> int:
    if value is None or value == "":
        return 0
    return int(db.scalar(select(func.count(NormalizedLog.id)).where(column == value)) or 0)


def _has_prior_value(db: Session, column, value: Any, log: NormalizedLog) -> bool:
    if value is None or value == "":
        return False
    log_time = _log_time(log)
    return bool(
        db.scalar(
            select(NormalizedLog.id)
            .where(column == value, NormalizedLog.id != log.id, NormalizedLog.generated_time < log_time)
            .limit(1)
        )
    )


def _repeated_connection_attempts(db: Session, log: NormalizedLog) -> int:
    if not log.src_ip or not log.dst_ip or log.dst_port is None:
        return 0
    end = _log_time(log)
    start = end - timedelta(minutes=5)
    return int(
        db.scalar(
            select(func.count(NormalizedLog.id)).where(
                NormalizedLog.src_ip == log.src_ip,
                NormalizedLog.dst_ip == log.dst_ip,
                NormalizedLog.dst_port == log.dst_port,
                NormalizedLog.generated_time >= start,
                NormalizedLog.generated_time <= end,
            )
        )
        or 0
    )


def _behavior_flags(db: Session, log: NormalizedLog, five_min: dict[str, Any]) -> dict[str, Any]:
    src_external = _zone_contains(log.src_zone, ("outside", "untrust", "internet", "wan"))
    src_internal = _zone_contains(log.src_zone, ("inside", "trust", "lan", "wlan", "corp"))
    dst_external = _zone_contains(log.dst_zone, ("outside", "untrust", "internet", "wan"))
    dst_internal = _zone_contains(log.dst_zone, ("inside", "trust", "lan", "wlan", "corp"))
    app_name = _lower(log.app)
    rare_dst_port = int(log.dst_port is not None and log.dst_port not in COMMON_PORTS and _global_count(db, NormalizedLog.dst_port, log.dst_port) <= 3)
    rare_app = int(bool(app_name) and app_name not in UNKNOWN_APPS and _global_count(db, NormalizedLog.app, log.app) <= 3)
    unique_ports = int(five_min.get("src_ip_5min_unique_dst_ports") or 0)
    unique_ips = int(five_min.get("src_ip_5min_unique_dst_ips") or 0)
    deny_ratio = float(five_min.get("deny_rate_5min") or 0)
    scanning_score = min(100, int((unique_ports * 4) + (unique_ips * 2) + (deny_ratio * 30)))
    return {
        "rare_dst_port_flag": rare_dst_port,
        "rare_app_flag": rare_app,
        "unknown_app_flag": int(app_name in UNKNOWN_APPS or app_name in {"unknown", "incomplete", "not-applicable"}),
        "external_to_internal_flag": int(src_external and dst_internal),
        "internal_to_external_flag": int(src_internal and dst_external),
        "first_seen_src_ip_flag": int(bool(log.src_ip) and not _has_prior_value(db, NormalizedLog.src_ip, log.src_ip, log)),
        "first_seen_app_flag": int(bool(log.app) and not _has_prior_value(db, NormalizedLog.app, log.app, log)),
        "repeated_connection_attempts": _repeated_connection_attempts(db, log),
        "scanning_like_behavior_score": scanning_score,
    }


def build_log_features(db: Session, log: NormalizedLog) -> dict[str, Any]:
    features = {feature: getattr(log, feature) for feature in BASE_NUMERIC_FEATURES}
    features.update({feature: getattr(log, feature) for feature in BASE_CATEGORICAL_FEATURES})
    window_features = _src_window_metrics(db, log)
    log_time = _log_time(log)
    hour = int(log_time.hour)
    features.update(window_features)
    for label, minutes in WINDOW_DEFINITIONS.items():
        features.update(_src_window_metrics_for_minutes(db, log, minutes, label))
        features[f"dst_ip_{label}_event_count"] = _dst_window_count(db, log, minutes)
    features["dst_ip_5min_connection_count"] = features["dst_ip_5min_event_count"]
    features.update(_behavior_flags(db, log, window_features))
    features["hour_of_day"] = hour
    features["is_after_hours"] = int(hour < 7 or hour >= 18)
    return features


def build_feature_rows(db: Session, logs: list[NormalizedLog]) -> list[dict[str, Any]]:
    return [build_log_features(db, log) for log in logs]
