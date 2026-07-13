from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone
from threading import Lock
from typing import Any

from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from atdr.app.core.config import get_settings, validate_runtime_settings
from atdr.app.db.database import check_database_connection
from atdr.app.db.models import DetectionRun, IngestionRun, OperationJob, OperationWorkerHeartbeat
from atdr.app.services.job_service import JOB_STATUSES, JOB_TYPES
from atdr.app.services.staging_service import staging_pressure_state


_HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"}
_http_lock = Lock()
_http_counts: dict[tuple[str, str], int] = defaultdict(int)
_http_duration_seconds: dict[tuple[str, str], float] = defaultdict(float)


def _method_label(method: str) -> str:
    normalized = method.strip().upper()
    return normalized if normalized in _HTTP_METHODS else "OTHER"


def _status_family(status_code: int) -> str:
    return f"{status_code // 100}xx" if 100 <= status_code <= 599 else "other"


def _utc(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


def record_http_request(*, method: str, status_code: int, duration_seconds: float) -> None:
    """Record bounded HTTP dimensions only; paths, actors, request IDs, and addresses are intentionally absent."""

    key = (_method_label(method), _status_family(status_code))
    with _http_lock:
        _http_counts[key] += 1
        _http_duration_seconds[key] += max(0.0, float(duration_seconds))


def _metric(lines: list[str], name: str, value: int | float, labels: dict[str, str] | None = None) -> None:
    rendered_labels = ""
    if labels:
        rendered_labels = "{" + ",".join(f'{key}="{value}"' for key, value in sorted(labels.items())) + "}"
    lines.append(f"{name}{rendered_labels} {value}")


def _http_metrics(lines: list[str]) -> None:
    lines.extend(
        [
            "# HELP atdr_http_requests_total HTTP requests grouped only by method and status family.",
            "# TYPE atdr_http_requests_total counter",
            "# HELP atdr_http_request_duration_seconds HTTP request duration grouped only by method and status family.",
            "# TYPE atdr_http_request_duration_seconds summary",
        ]
    )
    with _http_lock:
        counts = dict(_http_counts)
        durations = dict(_http_duration_seconds)
    for method, family in sorted(counts):
        labels = {"method": method, "status_family": family}
        _metric(lines, "atdr_http_requests_total", counts[(method, family)], labels)
        _metric(lines, "atdr_http_request_duration_seconds_count", counts[(method, family)], labels)
        _metric(lines, "atdr_http_request_duration_seconds_sum", round(durations[(method, family)], 6), labels)


def _job_metrics(lines: list[str], db: Session, *, heartbeat_seconds: int, failure_window_minutes: int) -> None:
    lines.extend(
        [
            "# HELP atdr_operation_queue_depth Durable operation queue depth by bounded job type and state.",
            "# TYPE atdr_operation_queue_depth gauge",
            "# HELP atdr_operation_jobs_total Durable operation job outcomes by bounded job type.",
            "# TYPE atdr_operation_jobs_total gauge",
            "# HELP atdr_operation_job_duration_seconds Terminal operation job duration.",
            "# TYPE atdr_operation_job_duration_seconds summary",
        ]
    )
    grouped = db.execute(
        select(OperationJob.job_type, OperationJob.status, func.count(OperationJob.id)).group_by(
            OperationJob.job_type,
            OperationJob.status,
        )
    )
    for job_type, status, count in grouped:
        if job_type not in JOB_TYPES or status not in JOB_STATUSES:
            continue
        labels = {"job_type": job_type, "state": status}
        _metric(lines, "atdr_operation_queue_depth", int(count or 0), labels)
        if status in {"completed", "failed", "retry_wait"}:
            _metric(lines, "atdr_operation_jobs_total", int(count or 0), {"job_type": job_type, "outcome": status})

    durations: dict[tuple[str, str], list[float]] = defaultdict(list)
    terminal_jobs = db.execute(
        select(OperationJob.job_type, OperationJob.status, OperationJob.started_at, OperationJob.finished_at)
        .where(OperationJob.status.in_({"completed", "failed"}))
        .order_by(desc(OperationJob.finished_at))
        .limit(5000)
    )
    for job_type, status, started_at, finished_at in terminal_jobs:
        if job_type not in JOB_TYPES or started_at is None or finished_at is None:
            continue
        durations[(job_type, status)].append(max(0.0, (_utc(finished_at) - _utc(started_at)).total_seconds()))
    for (job_type, status), values in sorted(durations.items()):
        labels = {"job_type": job_type, "outcome": status}
        _metric(lines, "atdr_operation_job_duration_seconds_count", len(values), labels)
        _metric(lines, "atdr_operation_job_duration_seconds_sum", round(sum(values), 6), labels)

    now = datetime.now(timezone.utc)
    states = {"fresh": 0, "stale": 0, "stopped": 0}
    for heartbeat in db.scalars(select(OperationWorkerHeartbeat)):
        if heartbeat.status == "stopped":
            states["stopped"] += 1
        elif (now - _utc(heartbeat.last_seen_at)).total_seconds() > max(1, heartbeat_seconds) * 3:
            states["stale"] += 1
        else:
            states["fresh"] += 1
    lines.extend(
        [
            "# HELP atdr_operation_workers Worker heartbeat state without worker identifiers.",
            "# TYPE atdr_operation_workers gauge",
        ]
    )
    for state, count in states.items():
        _metric(lines, "atdr_operation_workers", count, {"state": state})

    failure_cutoff = now - timedelta(minutes=max(1, failure_window_minutes))
    recent_failures = db.execute(
        select(OperationJob.job_type, func.count(OperationJob.id))
        .where(OperationJob.status == "failed", OperationJob.finished_at >= failure_cutoff)
        .group_by(OperationJob.job_type)
    )
    lines.extend(
        [
            "# HELP atdr_operation_recent_failures Failed jobs inside the configured monitoring window.",
            "# TYPE atdr_operation_recent_failures gauge",
        ]
    )
    failure_counts = {job_type: int(count or 0) for job_type, count in recent_failures if job_type in JOB_TYPES}
    for job_type in sorted(JOB_TYPES):
        _metric(lines, "atdr_operation_recent_failures", failure_counts.get(job_type, 0), {"job_type": job_type})

    import_filter = OperationJob.job_type.in_({"import_logs", "replay_logs"})
    chunk_commits = int(db.scalar(select(func.coalesce(func.sum(OperationJob.chunk_commits), 0)).where(import_filter)) or 0)
    resumed = int(db.scalar(select(func.count(OperationJob.id)).where(import_filter, OperationJob.resume_of_job_id.is_not(None))) or 0)
    cancellation_requests = int(
        db.scalar(select(func.count(OperationJob.id)).where(import_filter, OperationJob.cancellation_requested_at.is_not(None))) or 0
    )
    cancelled = int(
        db.scalar(select(func.count(OperationJob.id)).where(import_filter, OperationJob.status == "cancelled")) or 0
    )
    interrupted = int(
        db.scalar(select(func.count(OperationJob.id)).where(import_filter, OperationJob.status == "failed")) or 0
    )
    lines.extend(
        [
            "# HELP atdr_ingestion_chunk_commits_total Persisted import chunk checkpoints.",
            "# TYPE atdr_ingestion_chunk_commits_total gauge",
            "# HELP atdr_ingestion_resumes_total Resumable import child jobs created.",
            "# TYPE atdr_ingestion_resumes_total gauge",
            "# HELP atdr_ingestion_cancellations_total Cooperative import cancellation state.",
            "# TYPE atdr_ingestion_cancellations_total gauge",
            "# HELP atdr_ingestion_interrupted_total Failed resumable import jobs.",
            "# TYPE atdr_ingestion_interrupted_total gauge",
        ]
    )
    _metric(lines, "atdr_ingestion_chunk_commits_total", chunk_commits)
    _metric(lines, "atdr_ingestion_resumes_total", resumed)
    _metric(lines, "atdr_ingestion_cancellations_total", cancellation_requests, {"state": "requested"})
    _metric(lines, "atdr_ingestion_cancellations_total", cancelled, {"state": "completed"})
    _metric(lines, "atdr_ingestion_interrupted_total", interrupted)


def _pipeline_metrics(lines: list[str], db: Session, *, failure_window_minutes: int) -> None:
    ingestion = db.execute(
        select(
            func.coalesce(func.sum(IngestionRun.parsed_successfully), 0),
            func.coalesce(func.sum(IngestionRun.parse_failures), 0),
        )
    ).one()
    detection = db.execute(
        select(
            func.coalesce(func.sum(DetectionRun.alerts_created), 0),
            func.coalesce(func.sum(DetectionRun.alerts_deduplicated), 0),
        )
    ).one()
    lines.extend(
        [
            "# HELP atdr_ingestion_parse_results_total Persisted ingestion parse outcomes.",
            "# TYPE atdr_ingestion_parse_results_total gauge",
        ]
    )
    _metric(lines, "atdr_ingestion_parse_results_total", int(ingestion[0]), {"outcome": "success"})
    _metric(lines, "atdr_ingestion_parse_results_total", int(ingestion[1]), {"outcome": "failure"})
    lines.extend(
        [
            "# HELP atdr_detection_alert_results_total Persisted detection alert outcomes.",
            "# TYPE atdr_detection_alert_results_total gauge",
        ]
    )
    _metric(lines, "atdr_detection_alert_results_total", int(detection[0]), {"outcome": "created"})
    _metric(lines, "atdr_detection_alert_results_total", int(detection[1]), {"outcome": "deduplicated"})

    cutoff = datetime.now(timezone.utc) - timedelta(minutes=max(1, failure_window_minutes))
    recent_ingestion = db.execute(
        select(
            func.count(IngestionRun.id),
            func.coalesce(func.sum(IngestionRun.parse_failures), 0),
        ).where(IngestionRun.finished_at >= cutoff, IngestionRun.status == "failed")
    ).one()
    recent_detection_failures = int(
        db.scalar(
            select(func.count(DetectionRun.id)).where(
                DetectionRun.finished_at >= cutoff,
                DetectionRun.status == "failed",
            )
        )
        or 0
    )
    lines.extend(
        [
            "# HELP atdr_ingestion_recent_failed_runs Failed ingestion runs inside the monitoring window.",
            "# TYPE atdr_ingestion_recent_failed_runs gauge",
            "# HELP atdr_ingestion_recent_parse_failures Parse failures in failed runs inside the monitoring window.",
            "# TYPE atdr_ingestion_recent_parse_failures gauge",
            "# HELP atdr_detection_recent_failed_runs Failed detection runs inside the monitoring window.",
            "# TYPE atdr_detection_recent_failed_runs gauge",
        ]
    )
    _metric(lines, "atdr_ingestion_recent_failed_runs", int(recent_ingestion[0] or 0))
    _metric(lines, "atdr_ingestion_recent_parse_failures", int(recent_ingestion[1] or 0))
    _metric(lines, "atdr_detection_recent_failed_runs", recent_detection_failures)


def render_prometheus_metrics(db: Session, *, heartbeat_seconds: int) -> str:
    """Render a dependency-free Prometheus text snapshot with intentionally low-cardinality labels."""

    lines: list[str] = []
    _http_metrics(lines)
    try:
        settings = get_settings()
        _job_metrics(
            lines,
            db,
            heartbeat_seconds=heartbeat_seconds,
            failure_window_minutes=settings.operation_job_failure_warning_window_minutes,
        )
        _pipeline_metrics(
            lines,
            db,
            failure_window_minutes=settings.operation_job_failure_warning_window_minutes,
        )
        staging = staging_pressure_state(
            max_total_bytes=settings.operation_staging_max_total_bytes,
            min_free_bytes=settings.operation_staging_min_free_bytes,
        )
        database = check_database_connection(db)
        configuration_issues = validate_runtime_settings(settings)
        migration_status = (database.get("migration") or {}).get("status")
        ready = database.get("status") == "ok" and migration_status == "at_head" and not configuration_issues
        _metric(lines, "atdr_ingestion_staging_pressure", 1 if staging["pressure"] else 0)
        _metric(lines, "atdr_database_ready", 1 if database.get("status") == "ok" else 0)
        _metric(lines, "atdr_service_ready", 1 if ready else 0)
        _metric(lines, "atdr_runtime_configuration_issues", len(configuration_issues))
        _metric(lines, "atdr_response_simulation_enabled", 1 if settings.response_simulation else 0)
        _metric(lines, "atdr_metrics_collection_errors_total", 0)
    except Exception:
        db.rollback()
        _metric(lines, "atdr_database_ready", 0)
        _metric(lines, "atdr_service_ready", 0)
        _metric(lines, "atdr_metrics_collection_errors_total", 1)
    return "\n".join(lines) + "\n"


def metrics_snapshot_for_tests() -> dict[str, Any]:
    with _http_lock:
        return {"counts": dict(_http_counts), "durations": dict(_http_duration_seconds)}
