import hashlib
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import and_, case, func, or_, select
from sqlalchemy.orm import Session

from atdr.app.db.models import NormalizedLog, RawLog
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
    "repeat_count_effective",
    "parser_warning_count",
    "required_field_missing_count",
    "parser_confidence_score",
]

WINDOW_NUMERIC_FEATURES = _dedupe([*LEGACY_WINDOW_NUMERIC_FEATURES, *EXTENDED_WINDOW_NUMERIC_FEATURES, *BEHAVIOR_NUMERIC_FEATURES])
NUMERIC_FEATURES = _dedupe([*BASE_NUMERIC_FEATURES, *WINDOW_NUMERIC_FEATURES])
CATEGORICAL_FEATURES = list(BASE_CATEGORICAL_FEATURES)
FEATURE_COLUMNS = [*NUMERIC_FEATURES, *CATEGORICAL_FEATURES]
FEATURE_SET_VERSION = "behavior_windows_v3_leakage_safe"


def feature_code_hash() -> str:
    """Return a short hash of this feature pipeline source for model metadata."""
    digest = hashlib.sha256()
    digest.update(Path(__file__).read_bytes())
    return digest.hexdigest()[:16]


def feature_set_metadata(*, row_count: int | None = None, missing_value_summary: dict[str, int] | None = None) -> dict[str, Any]:
    return {
        "feature_set_version": FEATURE_SET_VERSION,
        "feature_code_hash": feature_code_hash(),
        "feature_count": len(FEATURE_COLUMNS),
        "numeric_feature_count": len(NUMERIC_FEATURES),
        "categorical_feature_count": len(CATEGORICAL_FEATURES),
        "feature_columns": FEATURE_COLUMNS,
        "numeric_columns": NUMERIC_FEATURES,
        "categorical_columns": CATEGORICAL_FEATURES,
        "row_count": row_count,
        "missing_value_summary": missing_value_summary or {},
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


def _log_time(log: NormalizedLog) -> datetime:
    value = log.generated_time or log.receive_time or log.start_time
    if value is None:
        return datetime.now(timezone.utc)
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def _event_time_expression():
    return func.coalesce(NormalizedLog.generated_time, NormalizedLog.receive_time, NormalizedLog.start_time)


def _source_id(db: Session, log: NormalizedLog) -> int | None:
    raw_log = getattr(log, "raw_log", None)
    if raw_log is not None:
        return raw_log.source_id
    if log.raw_log_id is None:
        return None
    return db.scalar(select(RawLog.source_id).where(RawLog.id == log.raw_log_id))


def _scope_to_log_source(statement, db: Session, log: NormalizedLog):
    source_id = _source_id(db, log)
    statement = statement.join(RawLog, NormalizedLog.raw_log_id == RawLog.id)
    if source_id is None:
        return statement.where(RawLog.source_id.is_(None))
    return statement.where(RawLog.source_id == source_id)


def _through_current_log(log: NormalizedLog, end: datetime):
    event_time = _event_time_expression()
    if log.id is None:
        return event_time <= end
    return or_(event_time < end, and_(event_time == end, NormalizedLog.id <= log.id))


def _strictly_before_log(log: NormalizedLog, end: datetime):
    event_time = _event_time_expression()
    if log.id is None:
        return event_time < end
    return or_(event_time < end, and_(event_time == end, NormalizedLog.id < log.id))


def _window_statement(db: Session, log: NormalizedLog):
    if log.generated_time is None and log.receive_time is None and log.start_time is None:
        return select(NormalizedLog).where(NormalizedLog.id == log.id)
    end = _log_time(log)
    start = end - timedelta(minutes=5)
    event_time = _event_time_expression()
    statement = select(NormalizedLog).where(event_time >= start, _through_current_log(log, end))
    statement = _scope_to_log_source(statement, db, log)
    if log.src_ip:
        statement = statement.where(NormalizedLog.src_ip == log.src_ip)
    else:
        statement = statement.where(NormalizedLog.id == log.id)
    return statement


def _src_window_statement(db: Session, log: NormalizedLog, minutes: int):
    if log.generated_time is None and log.receive_time is None and log.start_time is None:
        return select(NormalizedLog).where(NormalizedLog.id == log.id)
    end = _log_time(log)
    start = end - timedelta(minutes=minutes)
    event_time = _event_time_expression()
    statement = select(NormalizedLog).where(event_time >= start, _through_current_log(log, end))
    statement = _scope_to_log_source(statement, db, log)
    if log.src_ip:
        statement = statement.where(NormalizedLog.src_ip == log.src_ip)
    else:
        statement = statement.where(NormalizedLog.id == log.id)
    return statement


def _src_window_metrics_for_minutes(db: Session, log: NormalizedLog, minutes: int, label: str) -> dict[str, Any]:
    window = _src_window_statement(db, log, minutes).subquery()
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
    event_time = _event_time_expression()
    statement = select(func.count(NormalizedLog.id)).where(
        NormalizedLog.dst_ip == log.dst_ip,
        event_time >= start,
        _through_current_log(log, end),
    )
    statement = _scope_to_log_source(statement, db, log)
    return int(db.scalar(statement) or 0)


def _lower(value: str | None) -> str:
    return (value or "").strip().lower()


def _zone_contains(value: str | None, tokens: tuple[str, ...]) -> bool:
    lowered = _lower(value)
    return any(token in lowered for token in tokens)


def _is_deny_drop_reset(action: str | None) -> bool:
    lowered = _lower(action)
    return "deny" in lowered or "drop" in lowered or lowered.startswith("reset")


def _prior_count(db: Session, column, value: Any, log: NormalizedLog) -> int:
    if value is None or value == "":
        return 0
    statement = select(func.count(NormalizedLog.id)).where(
        column == value,
        _strictly_before_log(log, _log_time(log)),
    )
    statement = _scope_to_log_source(statement, db, log)
    return int(db.scalar(statement) or 0)


def _has_prior_value(db: Session, column, value: Any, log: NormalizedLog) -> bool:
    if value is None or value == "":
        return False
    log_time = _log_time(log)
    statement = select(NormalizedLog.id).where(
        column == value,
        NormalizedLog.id != log.id,
        _strictly_before_log(log, log_time),
    )
    statement = _scope_to_log_source(statement, db, log).limit(1)
    return bool(db.scalar(statement))


def _repeated_connection_attempts(db: Session, log: NormalizedLog) -> int:
    if not log.src_ip or not log.dst_ip or log.dst_port is None:
        return 0
    end = _log_time(log)
    start = end - timedelta(minutes=5)
    event_time = _event_time_expression()
    statement = select(func.count(NormalizedLog.id)).where(
        NormalizedLog.src_ip == log.src_ip,
        NormalizedLog.dst_ip == log.dst_ip,
        NormalizedLog.dst_port == log.dst_port,
        event_time >= start,
        _through_current_log(log, end),
    )
    statement = _scope_to_log_source(statement, db, log)
    return int(db.scalar(statement) or 0)


def _parser_quality_features(log: NormalizedLog) -> dict[str, int | float]:
    parsed = log.parsed_json if isinstance(log.parsed_json, dict) else {}
    warnings = parsed.get("parser_warnings") if isinstance(parsed.get("parser_warnings"), list) else []
    required_values = (log.src_ip, log.dst_ip, log.dst_port, log.protocol, log.action, log.app)
    missing = sum(1 for value in required_values if value is None or str(value).strip() == "")
    profile = str(parsed.get("parser_profile") or "palo_alto").strip().lower()
    base_confidence = {"palo_alto": 1.0, "generic_syslog": 0.45, "raw_fallback": 0.1}.get(profile, 0.25)
    confidence = max(0.0, base_confidence - (0.08 * len(warnings)) - (0.08 * missing))
    return {
        "repeat_count_effective": min(max(int(log.repeat_count or 1), 1), 10_000),
        "parser_warning_count": len(warnings),
        "required_field_missing_count": missing,
        "parser_confidence_score": round(confidence, 4),
    }


def _behavior_flags(db: Session, log: NormalizedLog, five_min: dict[str, Any]) -> dict[str, Any]:
    src_external = _zone_contains(log.src_zone, ("outside", "untrust", "internet", "wan"))
    src_internal = _zone_contains(log.src_zone, ("inside", "trust", "lan", "wlan", "corp"))
    dst_external = _zone_contains(log.dst_zone, ("outside", "untrust", "internet", "wan"))
    dst_internal = _zone_contains(log.dst_zone, ("inside", "trust", "lan", "wlan", "corp"))
    app_name = _lower(log.app)
    rare_dst_port = int(
        log.dst_port is not None
        and log.dst_port not in COMMON_PORTS
        and _prior_count(db, NormalizedLog.dst_port, log.dst_port, log) <= 3
    )
    rare_app = int(
        bool(app_name)
        and app_name not in UNKNOWN_APPS
        and _prior_count(db, NormalizedLog.app, log.app, log) <= 3
    )
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
    features.update(_parser_quality_features(log))
    features["hour_of_day"] = hour
    features["is_after_hours"] = int(hour < 7 or hour >= 18)
    return features


@dataclass(frozen=True)
class _BulkEvent:
    timestamp: datetime
    dst_port: int | None
    dst_ip: str | None
    deny: int
    allow: int
    bytes_total: int
    bytes_sent: int
    bytes_received: int
    packets: float | None
    unknown_app: int
    high_risk_app: int


@dataclass
class _RollingAggregate:
    minutes: int
    events: deque[_BulkEvent] = field(default_factory=deque)
    dst_ports: Counter[int] = field(default_factory=Counter)
    dst_ips: Counter[str] = field(default_factory=Counter)
    deny_count: int = 0
    allow_count: int = 0
    bytes_total: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0
    packet_total: float = 0.0
    packet_rows: int = 0
    unknown_app_count: int = 0
    high_risk_app_count: int = 0

    def add(self, event: _BulkEvent) -> None:
        self.events.append(event)
        if event.dst_port is not None:
            self.dst_ports[event.dst_port] += 1
        if event.dst_ip:
            self.dst_ips[event.dst_ip] += 1
        self.deny_count += event.deny
        self.allow_count += event.allow
        self.bytes_total += event.bytes_total
        self.bytes_sent += event.bytes_sent
        self.bytes_received += event.bytes_received
        if event.packets is not None:
            self.packet_total += event.packets
            self.packet_rows += 1
        self.unknown_app_count += event.unknown_app
        self.high_risk_app_count += event.high_risk_app
        self.expire(event.timestamp)

    def expire(self, current: datetime) -> None:
        cutoff = current - timedelta(minutes=self.minutes)
        while self.events and self.events[0].timestamp < cutoff:
            event = self.events.popleft()
            if event.dst_port is not None:
                self.dst_ports[event.dst_port] -= 1
                if self.dst_ports[event.dst_port] <= 0:
                    del self.dst_ports[event.dst_port]
            if event.dst_ip:
                self.dst_ips[event.dst_ip] -= 1
                if self.dst_ips[event.dst_ip] <= 0:
                    del self.dst_ips[event.dst_ip]
            self.deny_count -= event.deny
            self.allow_count -= event.allow
            self.bytes_total -= event.bytes_total
            self.bytes_sent -= event.bytes_sent
            self.bytes_received -= event.bytes_received
            if event.packets is not None:
                self.packet_total -= event.packets
                self.packet_rows -= 1
            self.unknown_app_count -= event.unknown_app
            self.high_risk_app_count -= event.high_risk_app

    def metrics(self, label: str) -> dict[str, Any]:
        count = len(self.events)
        return {
            f"src_ip_{label}_event_count": count,
            f"src_ip_{label}_unique_dst_ports": len(self.dst_ports),
            f"src_ip_{label}_unique_dst_ips": len(self.dst_ips),
            f"src_ip_{label}_deny_drop_reset_count": self.deny_count,
            f"src_ip_{label}_total_bytes": self.bytes_total,
            f"src_ip_{label}_bytes_sent": self.bytes_sent,
            f"src_ip_{label}_bytes_received": self.bytes_received,
            f"src_ip_{label}_avg_packets": self.packet_total / self.packet_rows if self.packet_rows else 0.0,
            f"src_ip_{label}_unknown_app_count": self.unknown_app_count,
            f"src_ip_{label}_high_risk_app_count": self.high_risk_app_count,
            f"src_ip_{label}_allow_count": self.allow_count,
            f"src_ip_{label}_deny_ratio": round(self.deny_count / count, 4) if count else 0.0,
        }


def _utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _bulk_source_ids(db: Session, logs: list[NormalizedLog]) -> dict[int, int | None]:
    raw_ids = {int(log.raw_log_id) for log in logs if log.raw_log_id is not None}
    if not raw_ids:
        return {}
    return {
        int(raw_id): (int(source_id) if source_id is not None else None)
        for raw_id, source_id in db.execute(select(RawLog.id, RawLog.source_id).where(RawLog.id.in_(raw_ids)))
    }


def _bulk_behavior_flags(
    log: NormalizedLog,
    five_min: dict[str, Any],
    *,
    prior_port_count: int,
    prior_app_count: int,
    prior_src_count: int,
    repeated_attempts: int,
) -> dict[str, Any]:
    src_external = _zone_contains(log.src_zone, ("outside", "untrust", "internet", "wan"))
    src_internal = _zone_contains(log.src_zone, ("inside", "trust", "lan", "wlan", "corp"))
    dst_external = _zone_contains(log.dst_zone, ("outside", "untrust", "internet", "wan"))
    dst_internal = _zone_contains(log.dst_zone, ("inside", "trust", "lan", "wlan", "corp"))
    app_name = _lower(log.app)
    unique_ports = int(five_min.get("src_ip_5min_unique_dst_ports") or 0)
    unique_ips = int(five_min.get("src_ip_5min_unique_dst_ips") or 0)
    deny_ratio = float(five_min.get("deny_rate_5min") or 0)
    return {
        "rare_dst_port_flag": int(
            log.dst_port is not None and log.dst_port not in COMMON_PORTS and prior_port_count <= 3
        ),
        "rare_app_flag": int(bool(app_name) and app_name not in UNKNOWN_APPS and prior_app_count <= 3),
        "unknown_app_flag": int(app_name in UNKNOWN_APPS or app_name in {"unknown", "incomplete", "not-applicable"}),
        "external_to_internal_flag": int(src_external and dst_internal),
        "internal_to_external_flag": int(src_internal and dst_external),
        "first_seen_src_ip_flag": int(bool(log.src_ip) and prior_src_count == 0),
        "first_seen_app_flag": int(bool(log.app) and prior_app_count == 0),
        "repeated_connection_attempts": repeated_attempts,
        "scanning_like_behavior_score": min(100, int((unique_ports * 4) + (unique_ips * 2) + (deny_ratio * 30))),
    }


def _bulk_feature_rows(db: Session, logs: list[NormalizedLog]) -> list[dict[str, Any]]:
    source_by_raw_id = _bulk_source_ids(db, logs)
    sources = {
        source_by_raw_id.get(int(log.raw_log_id)) if log.raw_log_id is not None else None
        for log in logs
    }
    target_positions: dict[int, list[int]] = defaultdict(list)
    for position, log in enumerate(logs):
        if log.id is not None:
            target_positions[int(log.id)].append(position)
    target_src_ips = {str(log.src_ip) for log in logs if log.src_ip}
    target_dst_ips = {str(log.dst_ip) for log in logs if log.dst_ip}
    target_ports = {int(log.dst_port) for log in logs if log.dst_port is not None}
    target_apps = {_lower(log.app) for log in logs if log.app}
    target_repeat_keys = {
        (
            source_by_raw_id.get(int(log.raw_log_id)) if log.raw_log_id is not None else None,
            str(log.src_ip),
            str(log.dst_ip),
            int(log.dst_port),
        )
        for log in logs
        if log.src_ip and log.dst_ip and log.dst_port is not None
    }

    event_time = _event_time_expression().label("event_time")
    statement = (
        select(
            NormalizedLog.id,
            RawLog.source_id,
            event_time,
            NormalizedLog.src_ip,
            NormalizedLog.dst_ip,
            NormalizedLog.dst_port,
            NormalizedLog.action,
            NormalizedLog.app,
            NormalizedLog.app_risk,
            NormalizedLog.bytes,
            NormalizedLog.bytes_sent,
            NormalizedLog.bytes_received,
            NormalizedLog.packets,
        )
        .join(RawLog, NormalizedLog.raw_log_id == RawLog.id)
        .order_by(event_time.asc(), NormalizedLog.id.asc())
    )
    concrete_sources = [source for source in sources if source is not None]
    source_filters = []
    if concrete_sources:
        source_filters.append(RawLog.source_id.in_(concrete_sources))
    if None in sources:
        source_filters.append(RawLog.source_id.is_(None))
    if source_filters:
        statement = statement.where(or_(*source_filters))
    evidence_filters = []
    if target_src_ips:
        evidence_filters.append(NormalizedLog.src_ip.in_(target_src_ips))
    if target_dst_ips:
        evidence_filters.append(NormalizedLog.dst_ip.in_(target_dst_ips))
    if target_ports:
        evidence_filters.append(NormalizedLog.dst_port.in_(target_ports))
    if target_apps:
        evidence_filters.append(func.lower(NormalizedLog.app).in_(target_apps))
    if evidence_filters:
        statement = statement.where(or_(*evidence_filters))

    src_windows: dict[tuple[int | None, str, str], _RollingAggregate] = {}
    dst_windows: dict[tuple[int | None, str, str], deque[datetime]] = defaultdict(deque)
    repeat_windows: dict[tuple[int | None, str, str, int], deque[datetime]] = defaultdict(deque)
    prior_ports: dict[int | None, Counter[int]] = defaultdict(Counter)
    prior_apps: dict[int | None, Counter[str]] = defaultdict(Counter)
    prior_sources: dict[int | None, Counter[str]] = defaultdict(Counter)
    results: list[dict[str, Any] | None] = [None] * len(logs)

    for row in db.execute(statement):
        timestamp = _utc(row.event_time)
        if timestamp is None:
            continue
        source_id = int(row.source_id) if row.source_id is not None else None
        src_ip = str(row.src_ip or "")
        dst_ip = str(row.dst_ip or "")
        app_name = _lower(row.app)
        action = _lower(row.action)
        prior_port_count = prior_ports[source_id][int(row.dst_port)] if row.dst_port is not None else 0
        prior_app_count = prior_apps[source_id][app_name] if app_name else 0
        prior_src_count = prior_sources[source_id][src_ip] if src_ip else 0
        event = _BulkEvent(
            timestamp=timestamp,
            dst_port=int(row.dst_port) if row.dst_port is not None else None,
            dst_ip=dst_ip or None,
            deny=int(_is_deny_drop_reset(action)),
            allow=int(action == "allow"),
            bytes_total=int(row.bytes or 0),
            bytes_sent=int(row.bytes_sent or 0),
            bytes_received=int(row.bytes_received or 0),
            packets=float(row.packets) if row.packets is not None else None,
            unknown_app=int(app_name in UNKNOWN_APPS),
            high_risk_app=int(row.app_risk is not None and int(row.app_risk) >= 4),
        )

        current_metrics: dict[str, Any] = {}
        if src_ip and src_ip in target_src_ips:
            for label, minutes in WINDOW_DEFINITIONS.items():
                key = (source_id, src_ip, label)
                state = src_windows.get(key)
                if state is None:
                    state = _RollingAggregate(minutes=minutes)
                    src_windows[key] = state
                state.add(event)
                current_metrics.update(state.metrics(label))
        else:
            for label in WINDOW_DEFINITIONS:
                current_metrics.update(_RollingAggregate(minutes=WINDOW_DEFINITIONS[label]).metrics(label))

        for label, minutes in WINDOW_DEFINITIONS.items():
            if not dst_ip or dst_ip not in target_dst_ips:
                current_metrics[f"dst_ip_{label}_event_count"] = 0
                continue
            destination_key = (source_id, dst_ip, label)
            destination_events = dst_windows[destination_key]
            destination_events.append(timestamp)
            cutoff = timestamp - timedelta(minutes=minutes)
            while destination_events and destination_events[0] < cutoff:
                destination_events.popleft()
            current_metrics[f"dst_ip_{label}_event_count"] = len(destination_events)

        repeated_attempts = 0
        repeat_key = (
            source_id,
            src_ip,
            dst_ip,
            int(row.dst_port) if row.dst_port is not None else -1,
        )
        if repeat_key in target_repeat_keys:
            repeats = repeat_windows[repeat_key]
            repeats.append(timestamp)
            cutoff = timestamp - timedelta(minutes=5)
            while repeats and repeats[0] < cutoff:
                repeats.popleft()
            repeated_attempts = len(repeats)

        if int(row.id) in target_positions:
            five_min = {
                "src_ip_5min_log_count": current_metrics.get("src_ip_5min_event_count", 0),
                "src_ip_5min_deny_count": current_metrics.get("src_ip_5min_deny_drop_reset_count", 0),
                "src_ip_5min_unique_dst_ports": current_metrics.get("src_ip_5min_unique_dst_ports", 0),
                "src_ip_5min_unique_dst_ips": current_metrics.get("src_ip_5min_unique_dst_ips", 0),
                "src_ip_5min_total_bytes": current_metrics.get("src_ip_5min_total_bytes", 0),
                "src_ip_5min_avg_packets": current_metrics.get("src_ip_5min_avg_packets", 0.0),
                "src_ip_5min_unknown_app_count": current_metrics.get("src_ip_5min_unknown_app_count", 0),
                "src_ip_5min_high_risk_app_count": current_metrics.get("src_ip_5min_high_risk_app_count", 0),
                "deny_rate_5min": current_metrics.get("src_ip_5min_deny_ratio", 0.0),
            }
            for position in target_positions[int(row.id)]:
                target = logs[position]
                features = {feature: getattr(target, feature) for feature in BASE_NUMERIC_FEATURES}
                features.update({feature: getattr(target, feature) for feature in BASE_CATEGORICAL_FEATURES})
                features.update(current_metrics)
                features.update(five_min)
                features["dst_ip_5min_connection_count"] = current_metrics.get("dst_ip_5min_event_count", 0)
                features.update(
                    _bulk_behavior_flags(
                        target,
                        five_min,
                        prior_port_count=prior_port_count,
                        prior_app_count=prior_app_count,
                        prior_src_count=prior_src_count,
                        repeated_attempts=repeated_attempts,
                    )
                )
                features.update(_parser_quality_features(target))
                hour = int(timestamp.hour)
                features["hour_of_day"] = hour
                features["is_after_hours"] = int(hour < 7 or hour >= 18)
                results[position] = features

        if row.dst_port is not None and int(row.dst_port) in target_ports:
            prior_ports[source_id][int(row.dst_port)] += 1
        if app_name in target_apps:
            prior_apps[source_id][app_name] += 1
        if src_ip in target_src_ips:
            prior_sources[source_id][src_ip] += 1

    for position, result in enumerate(results):
        if result is None:
            results[position] = build_log_features(db, logs[position])
    return [result for result in results if result is not None]


def build_feature_rows(db: Session, logs: list[NormalizedLog]) -> list[dict[str, Any]]:
    if len(logs) <= 1 or any(log.id is None for log in logs):
        return [build_log_features(db, log) for log in logs]
    return _bulk_feature_rows(db, logs)
