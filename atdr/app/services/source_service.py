from datetime import datetime, timezone
from typing import Any

from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from atdr.app.db.models import Alert, AlertEvidence, DetectionRun, IngestionRun, LogSource, NormalizedLog, RawLog
from atdr.app.services.operation_run_service import detection_run_to_dict, ingestion_run_to_dict

SOURCE_TYPES = {"file_import", "replay", "syslog_udp", "syslog_tcp", "router", "firewall", "sample"}
PARSER_PROFILES = {"palo_alto", "generic_syslog", "raw_fallback"}
DEFAULT_SOURCE_NAME = "local_import"


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _normalize_source_type(source_type: str | None) -> str:
    value = (source_type or "file_import").strip().lower()
    return value if value in SOURCE_TYPES else "sample"


def _normalize_parser_profile(parser_profile: str | None) -> str:
    value = (parser_profile or "palo_alto").strip().lower()
    return value if value in PARSER_PROFILES else "raw_fallback"


def source_health(source: LogSource, *, now: datetime | None = None) -> dict[str, Any]:
    current = now or utc_now()
    warnings = _source_warnings(source, current)
    if not source.enabled:
        status = "disabled"
    elif not source.last_log_received_at:
        status = "idle"
    else:
        last_log = _aware(source.last_log_received_at)
        age_seconds = (current - last_log).total_seconds() if last_log else None
        failure_rate = (source.parse_failure_count / source.logs_received_count) if source.logs_received_count else 0.0
        if failure_rate >= 0.5 and source.parse_failure_count >= 3:
            status = "error"
        elif source.latest_error or failure_rate >= 0.1:
            status = "warning"
        elif age_seconds is not None and age_seconds > 15 * 60:
            status = "idle"
        else:
            status = "healthy"
    if status == "healthy" and warnings:
        status = "warning"
    return {
        "source_id": source.id,
        "status": status,
        "enabled": source.enabled,
        "logs_received_count": source.logs_received_count,
        "parse_success_count": source.parse_success_count,
        "parse_failure_count": source.parse_failure_count,
        "parse_success_rate": round((source.parse_success_count / source.logs_received_count) * 100, 2)
        if source.logs_received_count
        else 0.0,
        "last_seen": source.last_seen,
        "last_log_received_at": source.last_log_received_at,
        "latest_error": source.latest_error,
        "recommendation": _health_recommendation(status),
        "warnings": warnings,
    }


def _source_warnings(source: LogSource, current: datetime) -> list[str]:
    warnings: list[str] = []
    if source.enabled and source.last_log_received_at:
        last_log = _aware(source.last_log_received_at)
        if last_log and (current - last_log).total_seconds() > 15 * 60:
            warnings.append("Source has not sent logs recently.")
    if source.logs_received_count:
        failure_rate = source.parse_failure_count / source.logs_received_count
        if failure_rate >= 0.1:
            warnings.append(f"Parse failure rate is {failure_rate:.1%}.")
    if source.latest_error:
        warnings.append("Latest parser/source error should be reviewed.")
    if source.parser_profile == "raw_fallback":
        warnings.append("Source uses raw fallback parser profile; normalized fields may be limited.")
    if source.source_type in {"firewall", "router", "syslog_udp", "syslog_tcp"} and source.parser_profile == "generic_syslog":
        warnings.append("Generic syslog parser profile may not extract Palo Alto CSV fields.")
    return warnings


def _health_recommendation(status: str) -> str:
    return {
        "healthy": "Source is receiving parseable logs recently.",
        "idle": "No recent logs. Confirm sender forwarding, receiver port, and lab network path.",
        "warning": "Review parser failures, unknown formats, or device profile mismatch.",
        "error": "Repeated parser failures. Pause response decisions from this source until format is reviewed.",
        "disabled": "Source is disabled by an administrator.",
    }.get(status, "Review source configuration and latest ingestion run.")


def source_to_dict(source: LogSource, *, include_quality: bool = False, db: Session | None = None) -> dict[str, Any]:
    data = {
        "source_id": source.id,
        "name": source.name,
        "source_type": source.source_type,
        "parser_profile": source.parser_profile,
        "host": source.host,
        "port": source.port,
        "enabled": source.enabled,
        "last_seen": source.last_seen,
        "last_log_received_at": source.last_log_received_at,
        "logs_received_count": source.logs_received_count,
        "parse_success_count": source.parse_success_count,
        "parse_failure_count": source.parse_failure_count,
        "latest_error": source.latest_error,
        "created_at": source.created_at,
        "updated_at": source.updated_at,
        "health": source_health(source),
    }
    if include_quality and db is not None:
        data["quality"] = source_quality(db, source.id)
        data["recent_ingestion_runs"] = recent_source_ingestion_runs(db, source.id)
        data["recent_detection_runs"] = recent_source_detection_runs(db, source.id)
    return data


def list_sources(
    db: Session,
    *,
    include_disabled: bool = True,
    source_type: str | None = None,
    parser_profile: str | None = None,
    status: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[LogSource]:
    statement = select(LogSource).order_by(desc(LogSource.last_log_received_at), desc(LogSource.updated_at), LogSource.id.desc())
    if not include_disabled:
        statement = statement.where(LogSource.enabled.is_(True))
    if source_type:
        statement = statement.where(LogSource.source_type == _normalize_source_type(source_type))
    if parser_profile:
        statement = statement.where(LogSource.parser_profile == _normalize_parser_profile(parser_profile))
    rows = list(db.scalars(statement.limit(limit).offset(offset)))
    if status:
        expected = status.strip().lower()
        rows = [source for source in rows if source_health(source)["status"] == expected]
    return rows


def get_source(db: Session, source_id: int) -> LogSource | None:
    return db.get(LogSource, source_id)


def create_source(
    db: Session,
    *,
    name: str,
    source_type: str,
    parser_profile: str = "palo_alto",
    host: str | None = None,
    port: int | None = None,
    enabled: bool = True,
) -> LogSource:
    source = LogSource(
        name=name.strip()[:255],
        source_type=_normalize_source_type(source_type),
        parser_profile=_normalize_parser_profile(parser_profile),
        host=host.strip()[:255] if host else None,
        port=port,
        enabled=enabled,
    )
    db.add(source)
    db.commit()
    db.refresh(source)
    return source


def update_source(db: Session, source: LogSource, updates: dict[str, Any]) -> LogSource:
    for field in ["name", "source_type", "parser_profile", "host", "port", "enabled"]:
        if field not in updates:
            continue
        value = updates[field]
        if field == "source_type":
            value = _normalize_source_type(value)
        if field == "parser_profile":
            value = _normalize_parser_profile(value)
        if field in {"name", "host"} and isinstance(value, str):
            value = value.strip()[:255] or None
        setattr(source, field, value)
    source.updated_at = utc_now()
    db.commit()
    db.refresh(source)
    return source


def get_or_create_source(
    db: Session,
    *,
    source_id: int | None = None,
    name: str | None = None,
    source_type: str = "file_import",
    parser_profile: str | None = None,
    host: str | None = None,
    port: int | None = None,
) -> LogSource:
    if source_id is not None:
        source = db.get(LogSource, source_id)
        if source is not None:
            return source
    resolved_name = (name or DEFAULT_SOURCE_NAME).strip()[:255] or DEFAULT_SOURCE_NAME
    source = db.scalar(select(LogSource).where(LogSource.name == resolved_name).limit(1))
    if source is not None:
        return source
    source = LogSource(
        name=resolved_name,
        source_type=_normalize_source_type(source_type),
        parser_profile=_normalize_parser_profile(parser_profile),
        host=host.strip()[:255] if host else None,
        port=port,
        enabled=True,
    )
    db.add(source)
    db.flush()
    return source


def record_source_ingestion(
    source: LogSource | None,
    *,
    logs_received: int,
    parsed_successfully: int,
    parse_failures: int,
    latest_error: str | None = None,
    observed_at: datetime | None = None,
) -> None:
    if source is None:
        return
    now = observed_at or utc_now()
    source.last_seen = now
    if logs_received:
        source.last_log_received_at = now
    source.logs_received_count += max(0, logs_received)
    source.parse_success_count += max(0, parsed_successfully)
    source.parse_failure_count += max(0, parse_failures)
    if latest_error:
        source.latest_error = latest_error[:1000]
    elif parse_failures == 0:
        source.latest_error = None
    source.updated_at = now


def source_ids_for_filters(
    db: Session,
    *,
    source_id: int | None = None,
    source_name: str | None = None,
    source_type: str | None = None,
    source_status: str | None = None,
) -> list[int] | None:
    if not any([source_id, source_name, source_type, source_status]):
        return None
    statement = select(LogSource)
    if source_id is not None:
        statement = statement.where(LogSource.id == source_id)
    if source_name:
        statement = statement.where(LogSource.name.ilike(f"%{source_name}%"))
    if source_type:
        statement = statement.where(LogSource.source_type == _normalize_source_type(source_type))
    sources = list(db.scalars(statement))
    if source_status:
        expected = source_status.strip().lower()
        sources = [source for source in sources if source_health(source)["status"] == expected]
    return [source.id for source in sources]


def source_quality(db: Session, source_id: int) -> dict[str, Any]:
    total_logs = int(db.scalar(select(func.count(RawLog.id)).where(RawLog.source_id == source_id)) or 0)
    normalized_logs = int(
        db.scalar(select(func.count(NormalizedLog.id)).join(RawLog).where(RawLog.source_id == source_id)) or 0
    )
    unknown_app_count = int(
        db.scalar(
            select(func.count(NormalizedLog.id))
            .join(RawLog)
            .where(RawLog.source_id == source_id, func.lower(NormalizedLog.app).in_(["unknown", "unknown-tcp", "unknown-udp", "incomplete"]))
        )
        or 0
    )
    alert_count = int(
        db.scalar(
            select(func.count(func.distinct(Alert.id)))
            .join(AlertEvidence, AlertEvidence.alert_id == Alert.id)
            .join(NormalizedLog, NormalizedLog.id == AlertEvidence.normalized_log_id)
            .join(RawLog, RawLog.id == NormalizedLog.raw_log_id)
            .where(RawLog.source_id == source_id)
        )
        or 0
    )
    parser_error_filter = NormalizedLog.parsed_json["parser_error"].as_string().is_not(None)
    parse_failure_examples = [
        {
            "raw_log_id": row.raw_log_id,
            "normalized_log_id": row.id,
            "parser_error": row.parsed_json.get("parser_error"),
            "raw_line_excerpt": row.raw_log.raw_line[:180] if row.raw_log else None,
        }
        for row in db.scalars(
            select(NormalizedLog)
            .join(RawLog)
            .where(RawLog.source_id == source_id, parser_error_filter)
            .order_by(NormalizedLog.id.desc())
            .limit(5)
        )
    ]
    unknown_app_rate = round((unknown_app_count / normalized_logs) * 100, 2) if normalized_logs else 0.0
    warnings = []
    if unknown_app_rate >= 25:
        warnings.append(f"Unknown/incomplete app rate is high at {unknown_app_rate}%.")
    if parse_failure_examples:
        warnings.append("Parser failure examples are available for review.")
    return {
        "raw_logs": total_logs,
        "normalized_logs": normalized_logs,
        "unknown_app_count": unknown_app_count,
        "unknown_app_rate": unknown_app_rate,
        "alert_count": alert_count,
        "parse_failure_examples": parse_failure_examples,
        "warnings": warnings,
    }


def recent_source_ingestion_runs(db: Session, source_id: int, *, limit: int = 5) -> list[dict[str, Any]]:
    rows = db.scalars(select(IngestionRun).order_by(desc(IngestionRun.started_at), desc(IngestionRun.id)).limit(100)).all()
    selected = [row for row in rows if (row.details_json or {}).get("source_id") == source_id][:limit]
    return [ingestion_run_to_dict(row) for row in selected]


def recent_source_detection_runs(db: Session, source_id: int, *, limit: int = 5) -> list[dict[str, Any]]:
    rows = db.scalars(select(DetectionRun).order_by(desc(DetectionRun.started_at), desc(DetectionRun.id)).limit(100)).all()
    selected = [row for row in rows if (row.details_json or {}).get("source_id") == source_id][:limit]
    return [detection_run_to_dict(row) for row in selected]
