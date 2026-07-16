import logging
from pathlib import Path
from typing import TextIO

from sqlalchemy import Select, desc, func, or_, select
from sqlalchemy.orm import Session, joinedload

from atdr.app.core.log_fingerprint import raw_line_fingerprint
from atdr.app.db.models import Alert, AlertEvidence, AuditLog, LogSource, NormalizedLog, RawLog
from atdr.app.parsers.paloalto_parser import ParsedPaloAltoLog, parse_log_line_for_profile
from atdr.app.services.operation_run_service import (
    complete_ingestion_run,
    fail_ingestion_run,
    safe_source_label,
    start_ingestion_run,
)
from atdr.app.services.source_service import DEFAULT_SOURCE_NAME, get_or_create_source, record_source_ingestion

logger = logging.getLogger(__name__)


def count_nonblank_log_lines(file_path: str | Path) -> int:
    path = Path(file_path)
    with path.open("r", encoding="utf-8", errors="replace", newline="") as stream:
        return sum(1 for line in stream if line.strip())


def persist_parsed_log(db: Session, parsed: ParsedPaloAltoLog, *, source_id: int | None = None) -> NormalizedLog | None:
    raw = RawLog(
        source_id=source_id,
        raw_line=parsed.raw_line,
        raw_line_hash=raw_line_fingerprint(parsed.raw_line),
        syslog_timestamp=parsed.syslog_timestamp,
        device_hostname=parsed.device_hostname,
    )
    normalized = NormalizedLog(parsed_json=parsed.parsed_json, **({} if parsed.error else parsed.normalized))
    raw.normalized = normalized
    db.add(raw)
    return normalized


def import_log_stream(
    db: Session,
    stream: TextIO,
    *,
    source_name: str = "uploaded-log",
    source_type: str = "file_import",
    limit: int | None = None,
    actor: str = "system",
    track_run: bool = True,
    source_id: int | None = None,
    parser_profile: str | None = None,
    available_lines: int | None = None,
) -> dict:
    imported = 0
    parsed = 0
    failed = 0
    duplicate_raw_logs = 0
    source_label = safe_source_label(source_name) or DEFAULT_SOURCE_NAME
    source_record_name = DEFAULT_SOURCE_NAME if source_id is None and source_type == "file_import" else source_label
    source = get_or_create_source(
        db,
        source_id=source_id,
        name=source_record_name,
        source_type=source_type,
        parser_profile=parser_profile,
    )
    run = (
        start_ingestion_run(
            db,
            source_type=source_type,
            input_name=source_name,
            details={"limit": limit, "source_id": source.id, "available_lines": available_lines},
        )
        if track_run
        else None
    )
    latest_error: str | None = None

    try:
        for line_number, line in enumerate(stream, start=1):
            if limit is not None and imported >= limit:
                break
            if not line.strip():
                continue
            existing_raw = db.scalar(select(RawLog.id).where(RawLog.raw_line == line.rstrip("\r\n")).limit(1))
            duplicate_raw_logs += 1 if existing_raw is not None else 0
            parsed_log = parse_log_line_for_profile(line, source.parser_profile)
            persist_parsed_log(db, parsed_log, source_id=source.id)
            imported += 1
            if parsed_log.error:
                failed += 1
                latest_error = parsed_log.error
                logger.debug("Parser issue in %s line %s: %s", source_name, line_number, parsed_log.error)
            else:
                parsed += 1
            if imported % 500 == 0:
                db.flush()
    except Exception as exc:
        if run is not None:
            fail_ingestion_run(
                db,
                run,
                error=f"{exc.__class__.__name__}: {exc}",
                details={"imported_before_failure": imported, "parsed_before_failure": parsed, "failed_before_failure": failed},
            )
            db.commit()
        raise

    audit = AuditLog(
        actor=actor,
        action="import_logs",
        target_type=source_type,
        target_value=safe_source_label(source_name) or source_name,
        details={
            "imported": imported,
            "parsed": parsed,
            "failed": failed,
            "duplicate_raw_logs": duplicate_raw_logs,
            "limit": limit,
            "available_lines": available_lines,
            "source_id": source.id,
        },
    )
    db.add(audit)
    record_source_ingestion(
        source,
        logs_received=imported,
        parsed_successfully=parsed,
        parse_failures=failed,
        latest_error=latest_error,
    )
    if run is not None:
        complete_ingestion_run(
            db,
            run,
            total_lines_received=imported,
            raw_logs_created=imported,
            parsed_successfully=parsed,
            parse_failures=failed,
            duplicate_raw_logs=duplicate_raw_logs,
            details={"actor": actor, "source_id": source.id, "available_lines": available_lines},
        )
    db.commit()
    return {
        "source": source_name,
        "source_label": safe_source_label(source_name) or source_name,
        "requested_limit": limit,
        "available_lines": available_lines,
        "imported": imported,
        "raw_logs_imported": imported,
        "normalized_logs_created": imported,
        "parsed": parsed,
        "parsed_successfully": parsed,
        "failed": failed,
        "parse_failures": failed,
        "duplicate_raw_logs": duplicate_raw_logs,
        "alerts_created": 0,
        "alerts_deduplicated": 0,
        "alerts_suppressed": 0,
        "run_id": run.id if run is not None else None,
        "source_id": source.id,
    }


def import_raw_log_line(
    db: Session,
    raw_line: str,
    *,
    source_name: str = "syslog",
    actor: str = "syslog_receiver",
    commit: bool = True,
    source_id: int | None = None,
    source_type: str = "syslog_udp",
    parser_profile: str | None = None,
    host: str | None = None,
    port: int | None = None,
) -> dict:
    source = get_or_create_source(
        db,
        source_id=source_id,
        name=source_name,
        source_type=source_type,
        parser_profile=parser_profile,
        host=host,
        port=port,
    )
    parsed_log = parse_log_line_for_profile(raw_line, source.parser_profile)
    duplicate_raw_log = db.scalar(select(RawLog.id).where(RawLog.raw_line == raw_line.rstrip("\r\n")).limit(1)) is not None
    normalized = persist_parsed_log(db, parsed_log, source_id=source.id)
    db.flush()
    record_source_ingestion(
        source,
        logs_received=1,
        parsed_successfully=0 if parsed_log.error else 1,
        parse_failures=1 if parsed_log.error else 0,
        latest_error=parsed_log.error,
    )
    if commit:
        db.add(
            AuditLog(
                actor=actor,
                action="ingest_syslog",
                target_type="syslog",
                target_value=source_name,
                details={"parsed": not bool(parsed_log.error), "normalized_log_id": getattr(normalized, "id", None), "source_id": source.id},
            )
        )
        db.commit()
    return {
        "parsed": not bool(parsed_log.error),
        "error": parsed_log.error,
        "normalized_log_id": getattr(normalized, "id", None),
        "duplicate_raw_log": duplicate_raw_log,
        "source_id": source.id,
    }


def import_log_file(
    db: Session,
    file_path: str | Path,
    *,
    limit: int | None = None,
    actor: str = "system",
    source_type: str = "file_import",
    source_id: int | None = None,
    parser_profile: str | None = None,
) -> dict:
    path = Path(file_path)
    available_lines = count_nonblank_log_lines(path)
    with path.open("r", encoding="utf-8", errors="replace", newline="") as stream:
        return import_log_stream(
            db,
            stream,
            source_name=str(path),
            source_type=source_type,
            limit=limit,
            actor=actor,
            source_id=source_id,
            parser_profile=parser_profile,
            available_lines=available_lines,
        )


def build_log_query(
    *,
    search: str | None = None,
    src_ip: str | None = None,
    dst_ip: str | None = None,
    app: str | None = None,
    action: str | None = None,
    protocol: str | None = None,
    src_zone: str | None = None,
    dst_zone: str | None = None,
    severity: str | None = None,
    country: str | None = None,
    app_risk: int | None = None,
    source_id: int | None = None,
    source_ids: list[int] | None = None,
    source_name: str | None = None,
    source_type: str | None = None,
    sort_by: str = "generated",
) -> Select:
    sort_columns = {
        "generated": NormalizedLog.generated_time,
        "time": NormalizedLog.generated_time,
        "app_risk": NormalizedLog.app_risk,
        "action": NormalizedLog.action,
        "src_ip": NormalizedLog.src_ip,
        "dst_ip": NormalizedLog.dst_ip,
        "id": NormalizedLog.id,
    }
    order_column = sort_columns.get(sort_by, NormalizedLog.generated_time)
    statement = select(NormalizedLog).options(joinedload(NormalizedLog.raw_log).joinedload(RawLog.source))
    if severity:
        statement = statement.join(AlertEvidence).join(Alert).where(Alert.severity == severity)
    if search:
        pattern = f"%{search}%"
        statement = statement.where(
            or_(
                NormalizedLog.src_ip.ilike(pattern),
                NormalizedLog.dst_ip.ilike(pattern),
                NormalizedLog.app.ilike(pattern),
                NormalizedLog.action.ilike(pattern),
                NormalizedLog.protocol.ilike(pattern),
                NormalizedLog.src_zone.ilike(pattern),
                NormalizedLog.dst_zone.ilike(pattern),
                NormalizedLog.rule_name.ilike(pattern),
                NormalizedLog.category.ilike(pattern),
            )
        )
    if src_ip:
        statement = statement.where(NormalizedLog.src_ip == src_ip)
    if dst_ip:
        statement = statement.where(NormalizedLog.dst_ip == dst_ip)
    if app:
        statement = statement.where(NormalizedLog.app.ilike(f"%{app}%"))
    if action:
        statement = statement.where(NormalizedLog.action == action)
    if protocol:
        statement = statement.where(NormalizedLog.protocol == protocol)
    if src_zone:
        statement = statement.where(NormalizedLog.src_zone.ilike(f"%{src_zone}%"))
    if dst_zone:
        statement = statement.where(NormalizedLog.dst_zone.ilike(f"%{dst_zone}%"))
    if country:
        statement = statement.where(
            (NormalizedLog.src_country.ilike(f"%{country}%")) | (NormalizedLog.dst_country.ilike(f"%{country}%"))
        )
    if app_risk is not None:
        statement = statement.where(NormalizedLog.app_risk == app_risk)
    if source_id is not None:
        statement = statement.join(RawLog, NormalizedLog.raw_log_id == RawLog.id).where(RawLog.source_id == source_id)
    elif source_ids is not None:
        if not source_ids:
            statement = statement.where(False)
        else:
            statement = statement.join(RawLog, NormalizedLog.raw_log_id == RawLog.id).where(RawLog.source_id.in_(source_ids))
    elif source_name or source_type:
        statement = (
            statement.join(RawLog, NormalizedLog.raw_log_id == RawLog.id)
            .join(LogSource, RawLog.source_id == LogSource.id)
        )
        if source_name:
            statement = statement.where(LogSource.name.ilike(f"%{source_name}%"))
        if source_type:
            statement = statement.where(LogSource.source_type == source_type)
    if sort_by in {"action", "src_ip", "dst_ip"}:
        return statement.order_by(order_column.asc(), NormalizedLog.id.desc())
    return statement.order_by(desc(order_column), NormalizedLog.id.desc())


def list_logs(db: Session, *, limit: int = 100, offset: int = 0, **filters) -> list[NormalizedLog]:
    statement = build_log_query(**filters).limit(limit).offset(offset)
    return list(db.scalars(statement).unique())


def get_log(db: Session, log_id: int) -> NormalizedLog | None:
    statement = (
        select(NormalizedLog)
        .options(joinedload(NormalizedLog.raw_log).joinedload(RawLog.source), joinedload(NormalizedLog.alert_evidence))
        .where(NormalizedLog.id == log_id)
    )
    return db.scalars(statement).unique().first()


def count_logs(db: Session) -> int:
    return int(db.scalar(select(func.count(NormalizedLog.id))) or 0)
