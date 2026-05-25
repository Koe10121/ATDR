import logging
from pathlib import Path
from typing import TextIO

from sqlalchemy import Select, desc, func, or_, select
from sqlalchemy.orm import Session, joinedload

from atdr.app.db.models import Alert, AlertEvidence, AuditLog, NormalizedLog, RawLog
from atdr.app.parsers.paloalto_parser import ParsedPaloAltoLog, parse_log_line

logger = logging.getLogger(__name__)


def _persist_parsed_log(db: Session, parsed: ParsedPaloAltoLog) -> NormalizedLog | None:
    raw = RawLog(
        raw_line=parsed.raw_line,
        syslog_timestamp=parsed.syslog_timestamp,
        device_hostname=parsed.device_hostname,
    )
    db.add(raw)
    db.flush()

    if parsed.error:
        raw.normalized = NormalizedLog(raw_log_id=raw.id, parsed_json=parsed.parsed_json)
        return raw.normalized

    normalized = NormalizedLog(raw_log_id=raw.id, parsed_json=parsed.parsed_json, **parsed.normalized)
    db.add(normalized)
    return normalized


def import_log_stream(
    db: Session,
    stream: TextIO,
    *,
    source_name: str = "uploaded-log",
    limit: int | None = None,
    actor: str = "system",
) -> dict:
    imported = 0
    parsed = 0
    failed = 0

    for line_number, line in enumerate(stream, start=1):
        if limit is not None and imported >= limit:
            break
        if not line.strip():
            continue
        parsed_log = parse_log_line(line)
        _persist_parsed_log(db, parsed_log)
        imported += 1
        if parsed_log.error:
            failed += 1
            logger.debug("Parser issue in %s line %s: %s", source_name, line_number, parsed_log.error)
        else:
            parsed += 1
        if imported % 500 == 0:
            db.flush()

    audit = AuditLog(
        actor=actor,
        action="import_logs",
        target_type="log_file",
        target_value=source_name,
        details={"imported": imported, "parsed": parsed, "failed": failed, "limit": limit},
    )
    db.add(audit)
    db.commit()
    return {"source": source_name, "imported": imported, "parsed": parsed, "failed": failed}


def import_raw_log_line(
    db: Session,
    raw_line: str,
    *,
    source_name: str = "syslog",
    actor: str = "syslog_receiver",
    commit: bool = True,
) -> dict:
    parsed_log = parse_log_line(raw_line)
    normalized = _persist_parsed_log(db, parsed_log)
    db.flush()
    if commit:
        db.add(
            AuditLog(
                actor=actor,
                action="ingest_syslog",
                target_type="syslog",
                target_value=source_name,
                details={"parsed": not bool(parsed_log.error), "normalized_log_id": getattr(normalized, "id", None)},
            )
        )
        db.commit()
    return {
        "parsed": not bool(parsed_log.error),
        "error": parsed_log.error,
        "normalized_log_id": getattr(normalized, "id", None),
    }


def import_log_file(db: Session, file_path: str | Path, *, limit: int | None = None, actor: str = "system") -> dict:
    path = Path(file_path)
    with path.open("r", encoding="utf-8", errors="replace", newline="") as stream:
        return import_log_stream(db, stream, source_name=str(path), limit=limit, actor=actor)


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
    statement = select(NormalizedLog).options(joinedload(NormalizedLog.raw_log))
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
    if sort_by in {"action", "src_ip", "dst_ip"}:
        return statement.order_by(order_column.asc(), NormalizedLog.id.desc())
    return statement.order_by(desc(order_column), NormalizedLog.id.desc())


def list_logs(db: Session, *, limit: int = 100, offset: int = 0, **filters) -> list[NormalizedLog]:
    statement = build_log_query(**filters).limit(limit).offset(offset)
    return list(db.scalars(statement).unique())


def get_log(db: Session, log_id: int) -> NormalizedLog | None:
    statement = (
        select(NormalizedLog)
        .options(joinedload(NormalizedLog.raw_log), joinedload(NormalizedLog.alert_evidence))
        .where(NormalizedLog.id == log_id)
    )
    return db.scalars(statement).unique().first()


def count_logs(db: Session) -> int:
    return int(db.scalar(select(func.count(NormalizedLog.id))) or 0)
