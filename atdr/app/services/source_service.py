from datetime import datetime, timezone
from typing import Any

from sqlalchemy import case, desc, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from atdr.app.db.models import AlertEvidence, DetectionRun, IngestionRun, LogSource, NormalizedLog, RawLog
from atdr.app.services.operation_run_service import detection_run_to_dict, ingestion_run_to_dict
from atdr.app.services.runtime_parser_quality_service import (
    historical_reparse_impact_preview,
    merge_runtime_parser_quality,
    runtime_parser_quality_summary,
)

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
    parser_quality = runtime_parser_quality_summary(
        source.parser_quality_json,
        total_rows=source.logs_received_count,
    )
    warnings = _source_warnings(source, current, parser_quality)
    warning_alerts = [
        alert
        for alert in parser_quality["operational_alerts"]
        if alert["severity"] in {"warning", "error"}
    ]
    if not source.enabled:
        status = "disabled"
    elif not source.last_log_received_at:
        status = "idle"
    else:
        last_log = _aware(source.last_log_received_at)
        age_seconds = (current - last_log).total_seconds() if last_log else None
        if parser_quality["observed_rows"]:
            if parser_quality["quality_state"] == "error":
                status = "error"
            elif (
                parser_quality["quality_state"] in {"warning", "limited"}
                or warning_alerts
            ):
                status = "warning"
            elif age_seconds is not None and age_seconds > 15 * 60:
                status = "idle"
            else:
                status = "healthy"
        else:
            failure_rate = (
                source.parse_failure_count / source.logs_received_count
                if source.logs_received_count
                else 0.0
            )
            if failure_rate >= 0.5 and source.parse_failure_count >= 3:
                status = "error"
            elif source.latest_error or failure_rate >= 0.1:
                status = "warning"
            elif age_seconds is not None and age_seconds > 15 * 60:
                status = "idle"
            else:
                status = "healthy"
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
        "recommendation": _health_recommendation(
            status,
            parser_quality["quality_state"],
        ),
        "warnings": warnings,
        "parser_quality_state": parser_quality["quality_state"],
        "parser_contract_state": parser_quality["contract_state"],
        "runtime_parser_error_count": parser_quality["parser_error_rows"],
        "runtime_parser_error_rate": round(
            parser_quality["parser_error_rate"] * 100,
            2,
        ),
        "structural_warning_count": parser_quality[
            "structural_warning_count"
        ],
        "unresolved_application_count": parser_quality[
            "unresolved_application_rows"
        ],
        "unresolved_application_rate": round(
            parser_quality["unresolved_application_rate"] * 100,
            2,
        ),
        "generic_syslog_count": parser_quality["generic_syslog_rows"],
        "raw_fallback_count": parser_quality["raw_fallback_rows"],
        "operational_alerts": parser_quality["operational_alerts"],
    }


def _source_warnings(
    source: LogSource,
    current: datetime,
    parser_quality: dict[str, Any],
) -> list[str]:
    warnings: list[str] = []
    if source.enabled and source.last_log_received_at:
        last_log = _aware(source.last_log_received_at)
        if last_log and (current - last_log).total_seconds() > 15 * 60:
            warnings.append("Source has not sent logs recently.")
    if source.logs_received_count and not parser_quality["observed_rows"]:
        failure_rate = source.parse_failure_count / source.logs_received_count
        if failure_rate >= 0.1:
            warnings.append(
                f"Legacy parse failure history is {failure_rate:.1%}; "
                "future ingestion will use the v5.13 runtime contract."
            )
    if source.latest_error and parser_quality["quality_state"] in {"error", "warning"}:
        warnings.append("Latest parser/source error should be reviewed.")
    warnings.extend(
        alert["message"]
        for alert in parser_quality["operational_alerts"]
    )
    if (
        source.parser_profile == "raw_fallback"
        and not parser_quality["raw_fallback_rows"]
    ):
        warnings.append(
            "Source is configured for raw fallback; future evidence will be "
            "preserved without structured fields."
        )
    if (
        source.source_type
        in {"firewall", "router", "syslog_udp", "syslog_tcp"}
        and source.parser_profile == "generic_syslog"
        and not parser_quality["generic_syslog_rows"]
    ):
        warnings.append(
            "Generic syslog is configured and will preserve only limited "
            "structured fields."
        )
    return warnings


def _health_recommendation(status: str, quality_state: str) -> str:
    if status == "warning" and quality_state == "limited":
        return (
            "Limited profile: evidence is preserved, but structured fields "
            "are intentionally limited."
        )
    if status == "warning" and quality_state == "warning":
        return (
            "Warning: review parser errors, structural layout alerts, or raw "
            "fallback usage. Unresolved applications alone are not failures."
        )
    return {
        "healthy": "Healthy: logs recently received and parsed successfully.",
        "idle": "Idle: no recent logs. Confirm sender forwarding, receiver port, and lab network path.",
        "warning": "Warning: logs were received, but parser profile limits, parse errors, or device mismatch need review.",
        "error": "Error: repeated parser failures. Pause response decisions from this source until format is reviewed.",
        "disabled": "Disabled: source is disabled and existing data is preserved.",
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
    try:
        with db.begin_nested():
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
    except IntegrityError:
        source = db.scalar(
            select(LogSource)
            .where(LogSource.name == resolved_name)
            .execution_options(populate_existing=True)
            .limit(1)
        )
        if source is None:
            raise
        return source


def lock_source_for_ingestion(db: Session, source_id: int) -> LogSource:
    """Refresh and lock source counters before a concurrent ingestion chunk updates them."""

    statement = (
        select(LogSource)
        .where(LogSource.id == source_id)
        .execution_options(populate_existing=True)
        .with_for_update()
    )
    source = db.scalar(statement)
    if source is None:
        raise ValueError("Log source no longer exists.")
    return source


def record_source_ingestion(
    source: LogSource | None,
    *,
    logs_received: int,
    parsed_successfully: int,
    parse_failures: int,
    latest_error: str | None = None,
    observed_at: datetime | None = None,
    parser_quality: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if source is None:
        return runtime_parser_quality_summary({})
    now = observed_at or utc_now()
    source.last_seen = now
    if logs_received:
        source.last_log_received_at = now
    source.logs_received_count += max(0, logs_received)
    source.parse_success_count += max(0, parsed_successfully)
    source.parse_failure_count += max(0, parse_failures)
    if latest_error:
        source.latest_error = latest_error[:1000]
    if (
        parser_quality
        and parser_quality.get("observed_rows")
        and not parser_quality.get("parser_error_rows")
        and parser_quality.get("raw_fallback_rows")
        == parser_quality.get("observed_rows")
    ):
        source.latest_error = None
    elif parse_failures == 0:
        source.latest_error = None
    if parser_quality:
        source.parser_quality_json = merge_runtime_parser_quality(
            source.parser_quality_json,
            parser_quality,
        )
    source.updated_at = now
    return runtime_parser_quality_summary(
        source.parser_quality_json,
        total_rows=source.logs_received_count,
    )


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


def _source_normalized_quality_statement(source_id: int):
    return (
        select(
            func.count(NormalizedLog.id).label("normalized_logs"),
            func.coalesce(
                func.sum(
                    case(
                        (
                            func.lower(NormalizedLog.app).in_(
                                [
                                    "unknown",
                                    "unknown-tcp",
                                    "unknown-udp",
                                    "incomplete",
                                ]
                            ),
                            1,
                        ),
                        else_=0,
                    )
                ),
                0,
            ).label("unknown_app_count"),
        )
        .join(RawLog, RawLog.id == NormalizedLog.raw_log_id)
        .where(RawLog.source_id == source_id)
    )


def _source_alert_count_statement(source_id: int):
    return (
        select(func.count(func.distinct(AlertEvidence.alert_id)))
        .join(
            NormalizedLog,
            NormalizedLog.id == AlertEvidence.normalized_log_id,
        )
        .join(RawLog, RawLog.id == NormalizedLog.raw_log_id)
        .where(RawLog.source_id == source_id)
    )


def source_quality(db: Session, source_id: int) -> dict[str, Any]:
    source = db.get(LogSource, source_id)
    total_logs = int(
        db.scalar(
            select(func.count(RawLog.id)).where(RawLog.source_id == source_id)
        )
        or 0
    )
    normalized_row = db.execute(
        _source_normalized_quality_statement(source_id)
    ).one()
    normalized_logs = int(normalized_row.normalized_logs or 0)
    unknown_app_count = int(normalized_row.unknown_app_count or 0)
    alert_count = int(
        db.scalar(_source_alert_count_statement(source_id))
        or 0
    )
    parser_error_filter = (
        NormalizedLog.parsed_json["parser_error"].as_string().is_not(None)
        & (
            func.coalesce(
                NormalizedLog.parsed_json["parser_profile"].as_string(),
                "",
            )
            != "raw_fallback"
        )
    )
    unknown_app_rate = round((unknown_app_count / normalized_logs) * 100, 2) if normalized_logs else 0.0
    parser_quality = runtime_parser_quality_summary(
        source.parser_quality_json if source is not None else {},
        total_rows=normalized_logs,
    )
    aggregate_proves_no_errors = (
        normalized_logs > 0
        and int(parser_quality.get("observed_rows") or 0) >= normalized_logs
        and int(parser_quality.get("parser_error_rows") or 0) == 0
    )
    parse_failure_examples: list[dict[str, Any]] = []
    if not aggregate_proves_no_errors:
        parse_failure_examples = [
            {
                "raw_log_id": row.raw_log_id,
                "normalized_log_id": row.id,
                "parser_error": (row.parsed_json or {}).get("parser_error"),
                "raw_line_excerpt": (
                    "<redacted; open authorized raw evidence by log ID>"
                    if row.raw_evidence_id
                    else None
                ),
                "raw_evidence_available": bool(row.raw_evidence_id),
            }
            for row in db.execute(
                select(
                    NormalizedLog.id,
                    NormalizedLog.raw_log_id,
                    NormalizedLog.parsed_json,
                    RawLog.id.label("raw_evidence_id"),
                )
                .join(RawLog, RawLog.id == NormalizedLog.raw_log_id)
                .where(
                    RawLog.source_id == source_id,
                    parser_error_filter,
                )
                .order_by(NormalizedLog.id.desc())
                .limit(5)
            )
        ]
    warnings: list[str] = []
    if unknown_app_rate >= 25:
        warnings.append(
            "Data quality note: unknown/incomplete application values are "
            f"present in {unknown_app_rate}% of this source's normalized logs. "
            "This can be expected for scan-style or partially established "
            "sessions and does not by itself mean source failure."
        )
    if parse_failure_examples:
        warnings.append("Parser failure examples are available for review.")
    warnings.extend(
        alert["message"]
        for alert in parser_quality["operational_alerts"]
    )
    return {
        "raw_logs": total_logs,
        "normalized_logs": normalized_logs,
        "unknown_app_count": unknown_app_count,
        "unknown_app_rate": unknown_app_rate,
        "alert_count": alert_count,
        "parse_failure_examples": parse_failure_examples,
        "warnings": warnings,
        "parser_quality": parser_quality,
        "parser_quality_state": parser_quality["quality_state"],
        "parser_contract_state": parser_quality["contract_state"],
        "runtime_observed_rows": parser_quality["observed_rows"],
        "legacy_contract_rows": parser_quality["legacy_contract_rows"],
        "parser_error_count": parser_quality["parser_error_rows"],
        "parser_error_rate": round(
            parser_quality["parser_error_rate"] * 100,
            2,
        ),
        "structural_warning_count": parser_quality[
            "structural_warning_count"
        ],
        "compatible_layout_count": parser_quality[
            "compatible_layout_rows"
        ],
        "extended_layout_count": parser_quality["extended_layout_rows"],
        "partial_layout_count": parser_quality["partial_layout_rows"],
        "unsupported_layout_count": parser_quality[
            "unsupported_layout_rows"
        ],
        "unresolved_application_count": parser_quality[
            "unresolved_application_rows"
        ],
        "unresolved_application_rate": round(
            parser_quality["unresolved_application_rate"] * 100,
            2,
        ),
        "absent_application_count": parser_quality[
            "absent_application_rows"
        ],
        "not_applicable_application_count": parser_quality[
            "not_applicable_application_rows"
        ],
        "generic_syslog_count": parser_quality["generic_syslog_rows"],
        "raw_fallback_count": parser_quality["raw_fallback_rows"],
        "operational_alerts": parser_quality["operational_alerts"],
    }


def source_reparse_impact_preview(
    db: Session,
    source_id: int,
    *,
    scan_limit: int = 5000,
) -> dict[str, Any]:
    return historical_reparse_impact_preview(
        db,
        source_id=source_id,
        scan_limit=scan_limit,
    )


def recent_source_ingestion_runs(db: Session, source_id: int, *, limit: int = 5) -> list[dict[str, Any]]:
    rows = db.scalars(select(IngestionRun).order_by(desc(IngestionRun.started_at), desc(IngestionRun.id)).limit(100)).all()
    selected = [row for row in rows if (row.details_json or {}).get("source_id") == source_id][:limit]
    return [ingestion_run_to_dict(row) for row in selected]


def recent_source_detection_runs(db: Session, source_id: int, *, limit: int = 5) -> list[dict[str, Any]]:
    rows = db.scalars(select(DetectionRun).order_by(desc(DetectionRun.started_at), desc(DetectionRun.id)).limit(100)).all()
    selected = [row for row in rows if (row.details_json or {}).get("source_id") == source_id][:limit]
    return [detection_run_to_dict(row) for row in selected]
