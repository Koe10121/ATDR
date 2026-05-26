from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from atdr.app.db.models import Alert, DetectionRun, IngestionRun
from atdr.app.detection.attack_mapping import infer_attack_type_from_rules


def safe_source_label(source_name: str | None) -> str | None:
    if not source_name:
        return None
    text = str(source_name)
    if text.startswith(("udp:", "api:", "demo:")):
        return text[:255]
    return Path(text).name[:255]


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def start_ingestion_run(
    db: Session,
    *,
    source_type: str,
    input_name: str | None,
    details: dict[str, Any] | None = None,
) -> IngestionRun:
    run = IngestionRun(
        source_type=source_type,
        input_name=safe_source_label(input_name),
        status="running",
        total_lines_received=0,
        raw_logs_created=0,
        parsed_successfully=0,
        parse_failures=0,
        duplicate_raw_logs=0,
        alerts_created=0,
        alerts_deduplicated=0,
        alerts_suppressed=0,
        details_json=details or {},
    )
    db.add(run)
    db.flush()
    return run


def complete_ingestion_run(
    db: Session,
    run: IngestionRun,
    *,
    total_lines_received: int,
    raw_logs_created: int,
    parsed_successfully: int,
    parse_failures: int,
    duplicate_raw_logs: int = 0,
    alerts_created: int = 0,
    alerts_deduplicated: int = 0,
    alerts_suppressed: int = 0,
    status: str = "completed",
    error_summary: str | None = None,
    details: dict[str, Any] | None = None,
) -> IngestionRun:
    finished_at = utc_now()
    run.finished_at = finished_at
    run.status = status
    run.total_lines_received = total_lines_received
    run.raw_logs_created = raw_logs_created
    run.parsed_successfully = parsed_successfully
    run.parse_failures = parse_failures
    run.duplicate_raw_logs = duplicate_raw_logs
    run.alerts_created = alerts_created
    run.alerts_deduplicated = alerts_deduplicated
    run.alerts_suppressed = alerts_suppressed
    run.runtime_seconds = max(0.0, round((finished_at - _aware(run.started_at)).total_seconds(), 3))
    run.error_summary = error_summary
    if details:
        run.details_json = {**(run.details_json or {}), **details}
    return run


def fail_ingestion_run(db: Session, run: IngestionRun, *, error: str, details: dict[str, Any] | None = None) -> IngestionRun:
    return complete_ingestion_run(
        db,
        run,
        total_lines_received=run.total_lines_received,
        raw_logs_created=run.raw_logs_created,
        parsed_successfully=run.parsed_successfully,
        parse_failures=run.parse_failures,
        duplicate_raw_logs=run.duplicate_raw_logs,
        alerts_created=run.alerts_created,
        alerts_deduplicated=run.alerts_deduplicated,
        alerts_suppressed=run.alerts_suppressed,
        status="failed",
        error_summary=error[:500],
        details=details,
    )


def start_detection_run(
    db: Session,
    *,
    detection_type: str,
    details: dict[str, Any] | None = None,
) -> DetectionRun:
    run = DetectionRun(
        detection_type=detection_type,
        status="running",
        logs_evaluated=0,
        alerts_created=0,
        alerts_deduplicated=0,
        alerts_suppressed=0,
        top_attack_types_json=[],
        details_json=details or {},
    )
    db.add(run)
    db.flush()
    return run


def complete_detection_run(
    db: Session,
    run: DetectionRun,
    *,
    logs_evaluated: int,
    alerts_created: int,
    alerts_deduplicated: int,
    alerts_suppressed: int,
    top_attack_types: list[dict[str, Any]] | None = None,
    status: str = "completed",
    error_summary: str | None = None,
    details: dict[str, Any] | None = None,
) -> DetectionRun:
    finished_at = utc_now()
    run.finished_at = finished_at
    run.status = status
    run.logs_evaluated = logs_evaluated
    run.alerts_created = alerts_created
    run.alerts_deduplicated = alerts_deduplicated
    run.alerts_suppressed = alerts_suppressed
    run.top_attack_types_json = top_attack_types or []
    run.runtime_seconds = max(0.0, round((finished_at - _aware(run.started_at)).total_seconds(), 3))
    run.error_summary = error_summary
    if details:
        run.details_json = {**(run.details_json or {}), **details}
    return run


def fail_detection_run(db: Session, run: DetectionRun, *, error: str, details: dict[str, Any] | None = None) -> DetectionRun:
    return complete_detection_run(
        db,
        run,
        logs_evaluated=run.logs_evaluated,
        alerts_created=run.alerts_created,
        alerts_deduplicated=run.alerts_deduplicated,
        alerts_suppressed=run.alerts_suppressed,
        status="failed",
        error_summary=error[:500],
        details=details,
    )


def recent_attack_type_counts(db: Session, *, limit: int = 500, top_n: int = 10) -> list[dict[str, Any]]:
    alerts = db.scalars(select(Alert).order_by(desc(Alert.updated_at), desc(Alert.id)).limit(limit)).all()
    counts: Counter[str] = Counter(infer_attack_type_from_rules(alert.matched_rules_json or []) for alert in alerts)
    return [{"name": name, "count": count} for name, count in counts.most_common(top_n)]


def list_ingestion_runs(db: Session, *, limit: int = 20, offset: int = 0) -> list[IngestionRun]:
    return list(db.scalars(select(IngestionRun).order_by(desc(IngestionRun.started_at), desc(IngestionRun.id)).limit(limit).offset(offset)))


def get_ingestion_run(db: Session, run_id: int) -> IngestionRun | None:
    return db.get(IngestionRun, run_id)


def list_detection_runs(db: Session, *, limit: int = 20, offset: int = 0) -> list[DetectionRun]:
    return list(db.scalars(select(DetectionRun).order_by(desc(DetectionRun.started_at), desc(DetectionRun.id)).limit(limit).offset(offset)))


def get_detection_run(db: Session, run_id: int) -> DetectionRun | None:
    return db.get(DetectionRun, run_id)


def ingestion_run_to_dict(run: IngestionRun) -> dict[str, Any]:
    return {
        "run_id": run.id,
        "started_at": run.started_at,
        "finished_at": run.finished_at,
        "source_type": run.source_type,
        "input_name": run.input_name,
        "status": run.status,
        "total_lines_received": run.total_lines_received,
        "raw_logs_created": run.raw_logs_created,
        "parsed_successfully": run.parsed_successfully,
        "parse_failures": run.parse_failures,
        "duplicate_raw_logs": run.duplicate_raw_logs,
        "alerts_created": run.alerts_created,
        "alerts_deduplicated": run.alerts_deduplicated,
        "alerts_suppressed": run.alerts_suppressed,
        "runtime_seconds": run.runtime_seconds,
        "error_summary": run.error_summary,
        "details": run.details_json,
    }


def detection_run_to_dict(run: DetectionRun) -> dict[str, Any]:
    return {
        "run_id": run.id,
        "started_at": run.started_at,
        "finished_at": run.finished_at,
        "detection_type": run.detection_type,
        "status": run.status,
        "logs_evaluated": run.logs_evaluated,
        "alerts_created": run.alerts_created,
        "alerts_deduplicated": run.alerts_deduplicated,
        "alerts_suppressed": run.alerts_suppressed,
        "top_attack_types": run.top_attack_types_json,
        "runtime_seconds": run.runtime_seconds,
        "error_summary": run.error_summary,
        "details": run.details_json,
    }
