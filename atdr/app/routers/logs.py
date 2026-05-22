from datetime import datetime
from io import TextIOWrapper
from pathlib import Path

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Response, UploadFile
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from atdr.app.core.config import PROJECT_ROOT, get_settings
from atdr.app.core.security import require_admin, require_analyst_or_admin
from atdr.app.db.database import get_db
from atdr.app.db.models import User
from atdr.app.parsers.paloalto_parser import parse_datetime
from atdr.app.schemas.logs import ImportResult, LogDetail, NormalizedLogRead
from atdr.app.services.log_service import build_log_query, get_log, import_log_file, import_log_stream

router = APIRouter(prefix="/api/logs", tags=["logs"])


def _log_to_dict(log) -> dict:
    data = {
        "id": log.id,
        "raw_log_id": log.raw_log_id,
        "receive_time": log.receive_time,
        "generated_time": log.generated_time,
        "log_type": log.log_type,
        "subtype": log.subtype,
        "serial": log.serial,
        "src_ip": log.src_ip,
        "dst_ip": log.dst_ip,
        "nat_src_ip": log.nat_src_ip,
        "nat_dst_ip": log.nat_dst_ip,
        "rule_name": log.rule_name,
        "src_user": log.src_user,
        "dst_user": log.dst_user,
        "app": log.app,
        "vsys": log.vsys,
        "src_zone": log.src_zone,
        "dst_zone": log.dst_zone,
        "inbound_interface": log.inbound_interface,
        "outbound_interface": log.outbound_interface,
        "log_action": log.log_action,
        "session_id": log.session_id,
        "repeat_count": log.repeat_count,
        "src_port": log.src_port,
        "dst_port": log.dst_port,
        "protocol": log.protocol,
        "action": log.action,
        "bytes": log.bytes,
        "bytes_sent": log.bytes_sent,
        "bytes_received": log.bytes_received,
        "packets": log.packets,
        "elapsed_time": log.elapsed_time,
        "category": log.category,
        "src_country": log.src_country,
        "dst_country": log.dst_country,
        "packets_sent": log.packets_sent,
        "packets_received": log.packets_received,
        "session_end_reason": log.session_end_reason,
        "device_name": log.device_name,
        "action_source": log.action_source,
        "rule_uuid": log.rule_uuid,
        "high_res_timestamp": log.high_res_timestamp,
        "app_subcategory": log.app_subcategory,
        "app_category": log.app_category,
        "app_technology": log.app_technology,
        "app_risk": log.app_risk,
        "app_characteristic": log.app_characteristic,
        "is_anomaly": log.is_anomaly,
        "anomaly_score": log.anomaly_score,
        "parsed_json": log.parsed_json,
    }
    if getattr(log, "raw_log", None):
        data["raw_line"] = log.raw_log.raw_line
        data["syslog_timestamp"] = log.raw_log.syslog_timestamp
        data["device_hostname"] = log.raw_log.device_hostname
    if getattr(log, "alert_evidence", None):
        data["alert_ids"] = [evidence.alert_id for evidence in log.alert_evidence]
    return data


@router.post("/import", response_model=ImportResult)
def import_logs(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
    upload: UploadFile | None = File(default=None),
    file_path: str | None = Form(default=None),
    limit: int | None = Form(default=None),
) -> dict:
    settings = get_settings()
    import_limit = settings.default_import_limit if limit is None else limit
    if import_limit is not None and import_limit <= 0:
        import_limit = None

    if upload is not None:
        text_stream = TextIOWrapper(upload.file, encoding="utf-8", errors="replace", newline="")
        return import_log_stream(
            db,
            text_stream,
            source_name=upload.filename or "uploaded-log",
            limit=import_limit,
            actor=current_user.username,
        )

    if not file_path:
        raise HTTPException(status_code=400, detail="Provide either multipart file field 'upload' or form field 'file_path'.")

    path = Path(file_path)
    if not path.is_absolute():
        path = PROJECT_ROOT / path
    if not path.exists():
        raise HTTPException(status_code=404, detail=f"Log file not found: {path}")
    return import_log_file(db, path, limit=import_limit, actor=current_user.username)


@router.get("", response_model=list[NormalizedLogRead])
def list_normalized_logs(
    response: Response,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
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
    generated_from: str | None = None,
    generated_to: str | None = None,
    sort_by: str = "generated",
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
) -> list[dict]:
    statement = build_log_query(
        search=search,
        src_ip=src_ip,
        dst_ip=dst_ip,
        app=app,
        action=action,
        protocol=protocol,
        src_zone=src_zone,
        dst_zone=dst_zone,
        severity=severity,
        country=country,
        sort_by=sort_by,
    )
    start = parse_datetime(generated_from)
    end = parse_datetime(generated_to)
    if start is not None:
        from atdr.app.db.models import NormalizedLog

        statement = statement.where(NormalizedLog.generated_time >= start)
    if end is not None:
        from atdr.app.db.models import NormalizedLog

        statement = statement.where(NormalizedLog.generated_time <= end)
    total = int(db.scalar(select(func.count()).select_from(statement.order_by(None).subquery())) or 0)
    response.headers["X-Total-Count"] = str(total)
    logs = list(db.scalars(statement.limit(limit).offset(offset)).unique())
    return [_log_to_dict(log) for log in logs]


@router.get("/{log_id}", response_model=LogDetail)
def get_normalized_log(
    log_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
) -> dict:
    log = get_log(db, log_id)
    if log is None:
        raise HTTPException(status_code=404, detail="Log not found.")
    return _log_to_dict(log)
