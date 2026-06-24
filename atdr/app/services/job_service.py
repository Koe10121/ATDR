from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from atdr.app.db.models import OperationJob


JOB_TYPES = {
    "import_logs",
    "replay_logs",
    "run_detection",
    "train_ml",
    "apply_ml_scoring",
    "export_report",
    "validation",
}
JOB_STATUSES = {"queued", "running", "completed", "failed", "cancelled"}
ACTIVE_JOB_STATUSES = {"queued", "running"}
TERMINAL_JOB_STATUSES = {"completed", "failed", "cancelled"}
MAX_SUMMARY_LENGTH = 500


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _cutoff(minutes: int) -> datetime:
    return _now() - timedelta(minutes=max(1, int(minutes)))


def _days_cutoff(days: int) -> datetime:
    return _now() - timedelta(days=max(1, int(days)))


def _safe_text(value: object, *, max_length: int = MAX_SUMMARY_LENGTH) -> str:
    text = str(value)
    if len(text) <= max_length:
        return text
    return f"{text[: max_length - 3]}..."


def _summary_value(result: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in result:
            return result[key]
    return None


def build_result_summary(job_type: str, result: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(result, dict):
        return {}
    if job_type in {"import_logs", "replay_logs"}:
        return {
            "requested_limit": result.get("requested_limit"),
            "limit": result.get("limit"),
            "available_lines": result.get("available_lines"),
            "lines_read": result.get("read"),
            "raw_logs_imported": _summary_value(result, "raw_logs_imported", "imported", "raw_logs_created"),
            "normalized_logs_created": _summary_value(result, "normalized_logs_created", "parsed", "parsed_successfully"),
            "parse_failures": _summary_value(result, "parse_failures", "failed"),
            "duplicate_raw_logs": result.get("duplicate_raw_logs"),
            "source": result.get("source_label") or result.get("source"),
            "alerts_created": result.get("alerts_created"),
            "alerts_deduplicated": result.get("alerts_deduplicated"),
        }
    if job_type == "run_detection":
        return {
            "logs_evaluated": result.get("evaluated"),
            "candidate_logs": result.get("candidate_logs"),
            "alerts_created": result.get("created_alerts"),
            "alerts_deduplicated": result.get("deduplicated_alert_updates"),
            "alerts_suppressed": (result.get("suppressed_low_groups") or 0) + (result.get("suppressed_by_rules") or 0),
            "top_attack_types": result.get("top_attack_types"),
            "source_id": result.get("source_id"),
        }
    if job_type == "train_ml":
        metrics = result.get("metrics") if isinstance(result.get("metrics"), dict) else {}
        return {
            "status": result.get("status"),
            "trained": result.get("trained"),
            "model_type": result.get("model_type"),
            "training_rows": result.get("training_rows") or result.get("training_log_count"),
            "test_rows": result.get("test_rows"),
            "weighted_f1": metrics.get("weighted_f1") if isinstance(metrics, dict) else None,
            "macro_f1": metrics.get("macro_f1") if isinstance(metrics, dict) else None,
            "message": result.get("message"),
        }
    if job_type == "apply_ml_scoring":
        return {
            "scored": result.get("scored"),
            "anomalies": result.get("anomalies"),
            "anomaly_rate": result.get("anomaly_rate"),
        }
    if job_type == "export_report":
        files = result.get("files")
        return {
            "selected_alert_id": result.get("selected_alert_id"),
            "file_count": len(files) if isinstance(files, dict) else None,
            "counts": result.get("counts"),
            "export_name": _safe_text(result.get("export_dir", "")) if result.get("export_dir") else None,
        }
    return {key: result.get(key) for key in ["ok", "status", "message"] if key in result}


def start_job(
    db: Session,
    *,
    job_type: str,
    requested_by: str,
    progress_total: int = 1,
    details: dict[str, Any] | None = None,
) -> OperationJob:
    if job_type not in JOB_TYPES:
        raise ValueError(f"Unsupported job type: {job_type}")
    job = OperationJob(
        job_type=job_type,
        status="running",
        requested_by=requested_by,
        started_at=_now(),
        progress_current=0,
        progress_total=max(0, int(progress_total)),
        result_summary_json={},
        details_json=details or {},
    )
    db.add(job)
    db.commit()
    db.refresh(job)
    return job


def complete_job(
    db: Session,
    job: OperationJob,
    *,
    result_summary: dict[str, Any] | None = None,
    progress_current: int | None = None,
    progress_total: int | None = None,
    related_ingestion_run_id: int | None = None,
    related_detection_run_id: int | None = None,
    related_ml_model_run_id: int | None = None,
) -> OperationJob:
    job.status = "completed"
    job.finished_at = _now()
    if progress_total is not None:
        job.progress_total = max(0, int(progress_total))
    job.progress_current = progress_current if progress_current is not None else job.progress_total
    job.result_summary_json = {key: value for key, value in (result_summary or {}).items() if value is not None}
    job.error_summary = None
    if related_ingestion_run_id is not None:
        job.related_ingestion_run_id = related_ingestion_run_id
    if related_detection_run_id is not None:
        job.related_detection_run_id = related_detection_run_id
    if related_ml_model_run_id is not None:
        job.related_ml_model_run_id = related_ml_model_run_id
    db.add(job)
    db.commit()
    db.refresh(job)
    return job


def fail_job(db: Session, job: OperationJob, error: BaseException | str) -> OperationJob:
    job_id = job.id
    db.rollback()
    failed_job = db.get(OperationJob, job_id)
    if failed_job is None:
        failed_job = job
        db.add(failed_job)
    failed_job.status = "failed"
    failed_job.finished_at = _now()
    failed_job.error_summary = _safe_text(f"{error.__class__.__name__}: {error}" if isinstance(error, BaseException) else error)
    db.commit()
    db.refresh(failed_job)
    return failed_job


def cancel_job(db: Session, job: OperationJob) -> OperationJob:
    if job.status != "queued":
        raise ValueError("Only queued jobs can be cancelled. Running operations complete synchronously in this lab build.")
    job.status = "cancelled"
    job.finished_at = _now()
    db.add(job)
    db.commit()
    db.refresh(job)
    return job


def list_jobs(
    db: Session,
    *,
    limit: int = 20,
    offset: int = 0,
    job_type: str | None = None,
    status: str | None = None,
) -> list[OperationJob]:
    statement = select(OperationJob).order_by(desc(OperationJob.created_at), desc(OperationJob.id))
    if job_type:
        statement = statement.where(OperationJob.job_type == job_type)
    if status:
        statement = statement.where(OperationJob.status == status)
    return list(db.scalars(statement.limit(limit).offset(offset)))


def get_job(db: Session, job_id: int) -> OperationJob | None:
    return db.get(OperationJob, job_id)


def list_stale_jobs(db: Session, *, stale_after_minutes: int, limit: int = 50) -> list[OperationJob]:
    cutoff = _cutoff(stale_after_minutes)
    stale_time = func.coalesce(OperationJob.updated_at, OperationJob.started_at, OperationJob.created_at)
    statement = (
        select(OperationJob)
        .where(OperationJob.status.in_(ACTIVE_JOB_STATUSES))
        .where(stale_time <= cutoff)
        .order_by(OperationJob.created_at.asc(), OperationJob.id.asc())
        .limit(max(1, int(limit)))
    )
    return list(db.scalars(statement))


def list_cleanup_candidates(db: Session, *, older_than_days: int, limit: int = 100) -> list[OperationJob]:
    cutoff = _days_cutoff(older_than_days)
    statement = (
        select(OperationJob)
        .where(OperationJob.status.in_(TERMINAL_JOB_STATUSES))
        .where(OperationJob.created_at <= cutoff)
        .order_by(OperationJob.created_at.asc(), OperationJob.id.asc())
        .limit(max(1, int(limit)))
    )
    return list(db.scalars(statement))


def mark_jobs_stale(db: Session, jobs: list[OperationJob], *, actor: str, stale_after_minutes: int) -> list[OperationJob]:
    marked: list[OperationJob] = []
    timestamp = _now()
    for job in jobs:
        if job.status not in ACTIVE_JOB_STATUSES:
            continue
        job.status = "failed"
        job.finished_at = timestamp
        job.error_summary = (
            f"Marked stale by {actor}; job was active longer than {max(1, int(stale_after_minutes))} minutes. "
            "No underlying logs, alerts, labels, audit records, or evidence were deleted."
        )
        details = dict(job.details_json or {})
        details["stale_marked_by"] = actor
        details["stale_marked_at"] = timestamp.isoformat()
        details["stale_after_minutes"] = max(1, int(stale_after_minutes))
        job.details_json = details
        db.add(job)
        marked.append(job)
    db.commit()
    for job in marked:
        db.refresh(job)
    return marked


def cleanup_terminal_jobs(db: Session, jobs: list[OperationJob]) -> int:
    deleted = 0
    for job in jobs:
        if job.status not in TERMINAL_JOB_STATUSES:
            continue
        db.delete(job)
        deleted += 1
    db.commit()
    return deleted


def build_job_summary(
    db: Session,
    *,
    stale_after_minutes: int,
    job_retention_days: int,
    run_history_retention_days: int,
) -> dict[str, Any]:
    counts = {
        status: int(
            db.scalar(select(func.count(OperationJob.id)).where(OperationJob.status == status))
            or 0
        )
        for status in sorted(JOB_STATUSES)
    }
    stale_jobs = list_stale_jobs(db, stale_after_minutes=stale_after_minutes, limit=25)
    latest_failed = db.scalar(
        select(OperationJob)
        .where(OperationJob.status == "failed")
        .order_by(desc(OperationJob.updated_at), desc(OperationJob.id))
        .limit(1)
    )
    latest_successful = db.scalar(
        select(OperationJob)
        .where(OperationJob.status == "completed")
        .order_by(desc(OperationJob.updated_at), desc(OperationJob.id))
        .limit(1)
    )
    return {
        "counts": counts,
        "active_count": counts.get("queued", 0) + counts.get("running", 0),
        "failed_count": counts.get("failed", 0),
        "stale_count": len(stale_jobs),
        "stale_job_ids": [job.id for job in stale_jobs],
        "latest_failed_job": job_to_dict(latest_failed) if latest_failed is not None else None,
        "latest_successful_job": job_to_dict(latest_successful) if latest_successful is not None else None,
        "retention_policy": {
            "job_stale_after_minutes": max(1, int(stale_after_minutes)),
            "job_retention_days": max(1, int(job_retention_days)),
            "run_history_retention_days": max(1, int(run_history_retention_days)),
            "automatic_cleanup_enabled": False,
            "raw_evidence_cleanup_enabled": False,
        },
    }


def job_to_dict(job: OperationJob) -> dict[str, Any]:
    return {
        "job_id": job.id,
        "job_type": job.job_type,
        "status": job.status,
        "requested_by": job.requested_by,
        "started_at": job.started_at,
        "finished_at": job.finished_at,
        "progress_current": job.progress_current,
        "progress_total": job.progress_total,
        "result_summary": job.result_summary_json or {},
        "error_summary": job.error_summary,
        "related_ingestion_run_id": job.related_ingestion_run_id,
        "related_detection_run_id": job.related_detection_run_id,
        "related_ml_model_run_id": job.related_ml_model_run_id,
        "details": job.details_json or {},
        "created_at": job.created_at,
        "updated_at": job.updated_at,
    }
