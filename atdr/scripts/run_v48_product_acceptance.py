from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import gc
import json
import logging
import math
import os
from pathlib import Path
import shutil
import statistics
import subprocess
import sys
import time
from typing import Any, Iterator
from unittest.mock import patch
from uuid import uuid4

from sqlalchemy import func, select, text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session

from atdr.app.core.config import PROJECT_ROOT, Settings, get_settings
from atdr.app.db.engine import create_configured_engine, migration_head_revision
from atdr.app.db.models import (
    Alert,
    AlertEvidence,
    AuditLog,
    DetectionRun,
    IngestionRun,
    LogSource,
    MLLabel,
    MLModelRun,
    NormalizedLog,
    OperationJob,
    RawLog,
    ResponseAction,
    User,
)
from atdr.app.detection.explanations import build_alert_detection_summary
from atdr.app.services.alert_service import get_alert, list_alerts
from atdr.app.services.assistant_llm import AssistantLLMResult
from atdr.app.services.assistant_service import answer_assistant_question
from atdr.app.services.case_service import list_alert_cases
from atdr.app.services.dashboard_service import build_dashboard_summary_cached, clear_dashboard_summary_cache
from atdr.app.services.detection_service import run_detection
from atdr.app.services.job_service import (
    claim_next_job,
    enqueue_job,
    recover_expired_leases,
    request_job_cancellation,
    resume_import_job,
)
from atdr.app.services.metrics_service import render_prometheus_metrics
from atdr.app.services.operation_worker import run_worker_once
from atdr.app.services.persistence_service import (
    create_database_backup,
    restore_database_backup,
    verify_database_backup_artifact,
)
from atdr.app.services.resumable_ingestion_service import CooperativeImportCancelled, run_resumable_import
from atdr.app.services.source_service import create_source, source_health
from atdr.app.services.staging_service import stage_upload_for_job, staged_payload_fields


_ACTOR = "v48-product-acceptance"
_MIN_LOG_COUNT = 40
_MAX_LOG_COUNT = 1_000_000
_RESERVED_SCENARIO_LOGS = 29
_CONFIGURED_DB_FILES = ("", "-wal", "-shm")

logger = logging.getLogger(__name__)


class _StopAfterFirstCommittedChunk:
    def __init__(self) -> None:
        self._checks = 0

    def is_set(self) -> bool:
        self._checks += 1
        return self._checks >= 3


def _safe_url(path: Path) -> str:
    return f"sqlite:///{path.resolve().as_posix()}"


def _configured_sqlite_path() -> Path | None:
    try:
        url = make_url(get_settings().database_url)
    except Exception:
        return None
    if not url.drivername.startswith("sqlite") or not url.database or url.database == ":memory:":
        return None
    path = Path(url.database)
    return (PROJECT_ROOT / path).resolve() if not path.is_absolute() else path.resolve()


def _configured_database_marker(path: Path | None) -> dict[str, tuple[int, int] | None] | None:
    if path is None:
        return None
    marker: dict[str, tuple[int, int] | None] = {}
    for suffix in _CONFIGURED_DB_FILES:
        candidate = Path(f"{path}{suffix}")
        if candidate.exists():
            stat = candidate.stat()
            marker[suffix or "main"] = (int(stat.st_size), int(stat.st_mtime_ns))
        else:
            marker[suffix or "main"] = None
    return marker


def _run_alembic_upgrade(database_url: str) -> dict[str, Any]:
    env = os.environ.copy()
    env.update(_safe_environment(database_url=database_url, staging_root=None))
    try:
        completed = subprocess.run(
            [sys.executable, "-m", "alembic", "upgrade", "head"],
            cwd=PROJECT_ROOT,
            capture_output=True,
            check=False,
            env=env,
            text=True,
            timeout=180,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"ok": False, "error_type": exc.__class__.__name__, "secrets_exposed": False}
    return {
        "ok": completed.returncode == 0,
        "returncode": completed.returncode,
        "error_type": None if completed.returncode == 0 else "AlembicUpgradeError",
        "secrets_exposed": False,
    }


def _safe_environment(
    *,
    database_url: str,
    staging_root: Path | None,
    chunk_size: int = 500,
) -> dict[str, str]:
    values = {
        "DATABASE_URL": database_url,
        "ENVIRONMENT": "development",
        "AUTO_CREATE_TABLES": "false",
        "JWT_SECRET_KEY": "v48-isolated-acceptance-secret-not-for-deployment",
        "RESPONSE_SIMULATION": "true",
        "RESPONSE_PROVIDER": "simulation",
        "ASSISTANT_ENABLED": "true",
        "ASSISTANT_PROVIDER": "deterministic",
        "ASSISTANT_API_KEY": "",
        "ASSISTANT_LLM_ENABLED": "false",
        "ASSISTANT_LLM_PROVIDER": "disabled",
        "ASSISTANT_LLM_MODEL": "",
        "ASSISTANT_LLM_API_KEY": "",
        "ASSISTANT_ALLOW_RAW_LOG_CONTEXT": "false",
        "ASSISTANT_REDACT_IPS": "true",
        "ASSISTANT_RATE_LIMIT_REQUESTS": "1000",
        "ASSISTANT_RATE_LIMIT_WINDOW_SECONDS": "60",
        "MFU_IAM_ENABLED": "false",
        "OIDC_ENABLED": "false",
        "SMTP_ENABLED": "false",
        "OPERATION_WORKER_ENABLED": "false",
        "OPERATION_WORKER_CONCURRENCY": "1",
        "OPERATION_WORKER_LEASE_SECONDS": "900",
        "OPERATION_JOB_RETRY_DELAY_SECONDS": "1",
        "OPERATION_STAGING_MIN_FREE_BYTES": "0",
        "OPERATION_STAGING_MAX_TOTAL_BYTES": str(512 * 1024 * 1024),
        "OPERATION_JOB_MAX_INPUT_BYTES": str(256 * 1024 * 1024),
        "OPERATION_STAGING_STORAGE_ID": "v48-temp",
        "INGESTION_CHUNK_SIZE": str(max(1, int(chunk_size))),
        "INGESTION_PROGRESS_UPDATE_INTERVAL": str(max(1, int(chunk_size))),
    }
    if staging_root is not None:
        values["OPERATION_STAGING_ROOT"] = str(staging_root.resolve())
    return values


@contextmanager
def _isolated_runtime(database_url: str, staging_root: Path, *, chunk_size: int) -> Iterator[Settings]:
    with patch.dict(
        os.environ,
        _safe_environment(database_url=database_url, staging_root=staging_root, chunk_size=chunk_size),
        clear=False,
    ):
        get_settings.cache_clear()
        clear_dashboard_summary_cache()
        try:
            yield get_settings()
        finally:
            clear_dashboard_summary_cache()
            get_settings.cache_clear()


def _write_bulk_syslog(path: Path, count: int) -> None:
    duplicate_interval = max(5, count // 10) if count else 5
    repeated = "2026-07-16T08:00:00Z v48-router event_id=duplicate action=allow protocol=tcp service=https"
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for index in range(count):
            if index and index % duplicate_interval == 0:
                handle.write(f"{repeated}\n")
            else:
                handle.write(
                    "2026-07-16T08:00:00Z v48-router "
                    f"event_id={index:09d} action=allow protocol=tcp service=https\n"
                )


def _write_recovery_syslog(path: Path, count: int = 6) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for index in range(count):
            handle.write(
                "2026-07-16T08:01:00Z v48-recovery-router "
                f"event_id=recovery-{index:03d} action=allow protocol=udp service=dns\n"
            )


def _stage_and_enqueue(
    db: Session,
    *,
    path: Path,
    source: LogSource,
    limit: int,
    name: str,
) -> OperationJob:
    with path.open("rb") as stream:
        staged = stage_upload_for_job(stream, filename=name)
    payload = {
        **staged_payload_fields(staged),
        "input_name": staged.safe_name,
        "input_bytes": staged.byte_count,
        "input_fingerprint": staged.fingerprint,
        "available_lines": staged.available_lines,
        "source_type": source.source_type,
        "parser_profile": source.parser_profile,
        "limit": limit,
        "source_id": source.id,
    }
    job, _ = enqueue_job(
        db,
        job_type="import_logs",
        requested_by=_ACTOR,
        payload=payload,
        details={
            "input_name": staged.safe_name,
            "available_lines": staged.available_lines,
            "parser_profile": source.parser_profile,
            "source_id": source.id,
            "validation_scope": "disposable_temp_database",
        },
        progress_total=limit,
        input_size_bytes=staged.byte_count,
        input_fingerprint=staged.fingerprint,
        resume_expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        staging_storage_id=staged.storage_id,
    )
    return job


def _process_job(
    db: Session,
    job: OperationJob,
    *,
    worker_id: str,
    simulate_interruption: bool = False,
) -> dict[str, Any]:
    progress = [int(job.progress_current or 0)]
    first = run_worker_once(
        db,
        worker_id=worker_id,
        stop_event=_StopAfterFirstCommittedChunk() if simulate_interruption else None,
    )
    db.expire_all()
    persisted = db.get(OperationJob, job.id)
    if persisted is None:
        raise RuntimeError("Queued import disappeared during acceptance validation.")
    progress.append(int(persisted.progress_current or 0))
    interrupted = bool(first.get("shutdown_requested"))
    resume_seconds = 0.0
    if interrupted:
        resume_started = time.perf_counter()
        second = run_worker_once(db, worker_id=f"{worker_id}-resume")
        resume_seconds = time.perf_counter() - resume_started
        db.expire_all()
        persisted = db.get(OperationJob, job.id)
        if persisted is None:
            raise RuntimeError("Interrupted import disappeared during resume validation.")
        progress.append(int(persisted.progress_current or 0))
    else:
        second = None
    return {
        "ok": bool(first.get("ok") and persisted.status == "completed" and (second is None or second.get("ok"))),
        "status": persisted.status,
        "interrupted": interrupted,
        "resume_completed": bool(interrupted and second and second.get("ok") and persisted.status == "completed"),
        "resume_runtime_seconds": round(resume_seconds, 4),
        "progress_samples": progress,
        "progress_monotonic": progress == sorted(progress),
        "checkpoint_line": int(persisted.checkpoint_line or 0),
        "chunk_commits": int(persisted.chunk_commits or 0),
        "ingestion_run_id": persisted.related_ingestion_run_id,
    }


def _cancel_and_resume(db: Session, job: OperationJob) -> dict[str, Any]:
    claimed = claim_next_job(
        db,
        worker_id="v48-cancel-worker",
        lease_seconds=60,
        staging_storage_id=job.staging_storage_id,
    )
    if claimed is None or claimed.id != job.id or not claimed.lease_token:
        return {"ok": False, "status": "claim_failed"}

    def cancel_after_first(chunk_commits: int, running_job: OperationJob) -> None:
        if chunk_commits == 1:
            request_job_cancellation(db, running_job, actor=_ACTOR)

    cancelled_cleanly = False
    try:
        run_resumable_import(
            db,
            job_id=claimed.id,
            worker_id="v48-cancel-worker",
            lease_token=claimed.lease_token,
            payload=dict(claimed.payload_json or {}),
            actor=_ACTOR,
            after_chunk=cancel_after_first,
        )
    except CooperativeImportCancelled:
        cancelled_cleanly = True
    db.expire_all()
    cancelled = db.get(OperationJob, claimed.id)
    if cancelled is None:
        return {"ok": False, "status": "cancelled_job_missing"}
    checkpoint = int(cancelled.checkpoint_line or 0)
    resumed = resume_import_job(db, cancelled, requested_by=_ACTOR)
    resume_started = time.perf_counter()
    worker_result = run_worker_once(db, worker_id="v48-cancel-resume-worker")
    resume_seconds = time.perf_counter() - resume_started
    db.expire_all()
    completed = db.get(OperationJob, resumed.id)
    return {
        "ok": bool(
            cancelled_cleanly
            and cancelled.status == "cancelled"
            and checkpoint > 0
            and completed is not None
            and completed.status == "completed"
            and worker_result.get("ok")
        ),
        "cancelled_status": cancelled.status,
        "checkpoint_line": checkpoint,
        "resume_status": completed.status if completed is not None else "missing",
        "resume_of_job_id": resumed.resume_of_job_id,
        "resume_runtime_seconds": round(resume_seconds, 4),
    }


def _stale_lease_recovery(db: Session) -> dict[str, Any]:
    job = OperationJob(
        job_type="run_detection",
        status="running",
        requested_by=_ACTOR,
        progress_current=0,
        progress_total=1,
        payload_json={},
        details_json={"validation_scope": "disposable_temp_database"},
        result_summary_json={},
        attempt_count=1,
        max_attempts=1,
        lease_owner="v48-stale-worker",
        lease_token="v48-expired-lease",
        lease_expires_at=datetime.now(timezone.utc) - timedelta(minutes=1),
        started_at=datetime.now(timezone.utc) - timedelta(minutes=2),
    )
    db.add(job)
    db.commit()
    db.refresh(job)
    recovered = recover_expired_leases(db, retry_delay_seconds=1)
    db.expire_all()
    persisted = db.get(OperationJob, job.id)
    return {
        "ok": bool(
            any(item.id == job.id for item in recovered)
            and persisted is not None
            and persisted.status == "failed"
            and persisted.error_summary == "Worker lease expired before completion."
        ),
        "status": persisted.status if persisted is not None else "missing",
        "diagnostic_present": bool(persisted and persisted.error_summary),
        "unsafe_retry_performed": bool(persisted and persisted.status == "retry_wait"),
    }


def _count(db: Session, model: Any, column: Any | None = None) -> int:
    target = column if column is not None else model.id
    return int(db.scalar(select(func.count(target))) or 0)


def _database_counts(db: Session) -> dict[str, int]:
    return {
        "sources": _count(db, LogSource),
        "raw_logs": _count(db, RawLog),
        "normalized_logs": _count(db, NormalizedLog),
        "alerts": _count(db, Alert),
        "alert_evidence": _count(db, AlertEvidence),
        "ingestion_runs": _count(db, IngestionRun),
        "detection_runs": _count(db, DetectionRun),
        "operation_jobs": _count(db, OperationJob),
        "audit_logs": _count(db, AuditLog),
        "response_actions": _count(db, ResponseAction),
        "labels": _count(db, MLLabel),
        "model_runs": _count(db, MLModelRun),
        "users": _count(db, User),
    }


def _alert_group_counts(alert: Alert | None) -> tuple[int, int]:
    if alert is None:
        return 0, 0
    metadata = next(
        (item for item in (alert.matched_rules_json or []) if item.get("code") == "group_metadata"),
        {},
    )
    evidence_count = len(alert.evidence)
    occurrence_count = int(metadata.get("occurrence_count") or metadata.get("evidence_count") or evidence_count)
    related_log_count = int(metadata.get("related_log_count") or metadata.get("evidence_count") or evidence_count)
    return occurrence_count, related_log_count


def _remove_temp_root(temp_root: Path) -> bool:
    gc.collect()
    for _ in range(20):
        shutil.rmtree(temp_root, ignore_errors=True)
        if not temp_root.exists():
            return True
        time.sleep(0.1)
    return not temp_root.exists()


def _migration_state(db: Session) -> dict[str, Any]:
    current = db.scalar(text("SELECT version_num FROM alembic_version"))
    head = migration_head_revision()
    return {"current_revision": current, "head_revision": head, "at_head": bool(current and current == head)}


def _percentile(values: list[float], proportion: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, math.ceil(proportion * len(ordered)) - 1))
    return round(ordered[index], 4)


def _timed(callable_: Any) -> tuple[Any, float]:
    started = time.perf_counter()
    value = callable_()
    return value, time.perf_counter() - started


def _performance_checks(db: Session, *, assistant_seconds: float | None) -> dict[str, Any]:
    cold: list[float] = []
    warm: list[float] = []
    for _ in range(3):
        clear_dashboard_summary_cache()
        _, cold_seconds = _timed(lambda: build_dashboard_summary_cached(db))
        _, warm_seconds = _timed(lambda: build_dashboard_summary_cached(db))
        cold.append(cold_seconds)
        warm.append(warm_seconds)
    _, alert_seconds = _timed(lambda: list_alerts(db, limit=100))
    _, case_seconds = _timed(lambda: list_alert_cases(db, limit=50))
    return {
        "overview_cold_app_cache_median_seconds": round(statistics.median(cold), 4),
        "overview_cold_app_cache_p95_seconds": _percentile(cold, 0.95),
        "overview_warm_cache_median_seconds": round(statistics.median(warm), 4),
        "overview_warm_cache_p95_seconds": _percentile(warm, 0.95),
        "alert_list_seconds": round(alert_seconds, 4),
        "case_summary_seconds": round(case_seconds, 4),
        "assistant_seconds": round(assistant_seconds, 4) if assistant_seconds is not None else None,
    }


def _assistant_validation(db: Session, *, alert_id: int, settings: Settings) -> tuple[dict[str, Any], float]:
    mutation_models = (RawLog, NormalizedLog, Alert, DetectionRun, ResponseAction, MLLabel, MLModelRun, User)
    before = {model.__tablename__: _count(db, model) for model in mutation_models}
    conversation_id = f"v48-{uuid4().hex[:12]}"
    started = time.perf_counter()
    first = answer_assistant_question(
        db,
        question=f"Why was alert {alert_id} flagged?",
        actor=_ACTOR,
        settings=settings,
        alert_id=alert_id,
        conversation_id=conversation_id,
    )
    related = answer_assistant_question(
        db,
        question="What logs are related?",
        actor=_ACTOR,
        settings=settings,
        conversation_id=conversation_id,
    )
    next_step = answer_assistant_question(
        db,
        question="What should an analyst verify before response?",
        actor=_ACTOR,
        settings=settings,
        conversation_id=conversation_id,
    )
    provider_settings = settings.model_copy(
        update={
            "assistant_llm_enabled": True,
            "assistant_llm_provider": "gemini",
            "assistant_llm_model": "v48-failure-probe",
            "assistant_llm_api_key": "v48-secret-sentinel",
        }
    )
    failed_provider = AssistantLLMResult(
        used=False,
        provider="gemini",
        model="v48-failure-probe",
        fallback_reason="provider_request_failed",
        raw_log_context_included=False,
        secrets_exposed=False,
    )
    with patch("atdr.app.services.assistant_service.maybe_generate_external_answer", return_value=failed_provider):
        fallback = answer_assistant_question(
            db,
            question=f"Explain alert {alert_id}.",
            actor=_ACTOR,
            settings=provider_settings,
            alert_id=alert_id,
            conversation_id=f"v48-fallback-{uuid4().hex[:8]}",
        )
    elapsed = time.perf_counter() - started
    after = {model.__tablename__: _count(db, model) for model in mutation_models}
    serialized = json.dumps([first, related, next_step, fallback], default=str)
    contexts = [first.get("active_context", {}), related.get("active_context", {}), next_step.get("active_context", {})]
    citation_ids = {
        str(item.get("reference_id"))
        for response in (first, related, next_step)
        for item in response.get("citations", [])
        if item.get("reference_id") is not None
    }
    return {
        "ok": all(
            (
                all(int(context.get("alert_id") or 0) == alert_id for context in contexts),
                str(alert_id) in citation_ids,
                all(not response.get("external_provider_used") for response in (first, related, next_step, fallback)),
                all(not response.get("raw_log_context_included") for response in (first, related, next_step, fallback)),
                fallback.get("mode") == "deterministic_local_llm_fallback_gemini",
                before == after,
                "203.0.113.44" not in serialized,
                "raw_line" not in serialized.lower(),
                "v48-secret-sentinel" not in serialized,
            )
        ),
        "conversation_context_preserved": all(int(context.get("alert_id") or 0) == alert_id for context in contexts),
        "citation_references_alert": str(alert_id) in citation_ids,
        "deterministic_provider_used": False,
        "provider_failure_fallback": fallback.get("mode") == "deterministic_local_llm_fallback_gemini",
        "raw_log_context_included": any(
            response.get("raw_log_context_included") for response in (first, related, next_step, fallback)
        ),
        "redaction_applied": all(response.get("redaction_applied") for response in (first, related, next_step, fallback)),
        "mutating_counts_unchanged": before == after,
        "response_actions_created": after[ResponseAction.__tablename__] - before[ResponseAction.__tablename__],
        "secrets_exposed": "v48-secret-sentinel" in serialized,
    }, elapsed


def _backup_restore_validation(settings: Settings, temp_root: Path) -> tuple[dict[str, Any], float]:
    output = temp_root / "backup"
    restore_path = temp_root / "restored.sqlite3"
    restore_url = _safe_url(restore_path)
    started = time.perf_counter()
    backup = create_database_backup(settings=settings, output_dir=output, execute=True)
    backup_seconds = time.perf_counter() - started
    if not backup.get("ok"):
        return {"ok": False, "status": backup.get("status"), "secrets_exposed": False}, time.perf_counter() - started
    verified = verify_database_backup_artifact(
        backup_path=str(backup["backup_path"]),
        manifest_path=str(backup["manifest_path"]),
    )
    active_refusal = restore_database_backup(
        settings=settings,
        backup_path=str(backup["backup_path"]),
        manifest_path=str(backup["manifest_path"]),
        target_database_url=settings.database_url,
        execute=True,
        confirmed=True,
    )
    restore_started = time.perf_counter()
    restored = restore_database_backup(
        settings=settings,
        backup_path=str(backup["backup_path"]),
        manifest_path=str(backup["manifest_path"]),
        target_database_url=restore_url,
        execute=True,
        confirmed=True,
    )
    restore_seconds = time.perf_counter() - restore_started
    elapsed = time.perf_counter() - started
    return {
        "ok": bool(
            verified.get("ok")
            and active_refusal.get("status") == "active_database_target_refused"
            and restored.get("ok")
            and restored.get("row_counts_match")
            and restored.get("migration_revision_match")
        ),
        "backup_created": bool(backup.get("ok")),
        "checksum_valid": bool(verified.get("ok")),
        "active_database_target_refused": active_refusal.get("status") == "active_database_target_refused",
        "restore_validated": bool(restored.get("ok")),
        "row_counts_match": bool(restored.get("row_counts_match")),
        "migration_revision_match": bool(restored.get("migration_revision_match")),
        "artifact_size_bytes": int(backup.get("size_bytes") or 0),
        "backup_seconds": round(backup_seconds, 4),
        "restore_seconds": round(restore_seconds, 4),
        "current_database_modified": False,
        "secrets_exposed": False,
    }, elapsed


def _safe_metrics_validation(db: Session, settings: Settings) -> dict[str, Any]:
    rendered = render_prometheus_metrics(db, heartbeat_seconds=settings.operation_worker_heartbeat_seconds)
    required = ("atdr_", "operation", "ingestion")
    lowered = rendered.lower()
    return {
        "ok": all(token in lowered for token in required),
        "metrics_rendered": bool(rendered.strip()),
        "operational_metrics_present": all(token in lowered for token in required),
        "raw_evidence_exposed": "raw_line" in lowered or "203.0.113.44" in rendered,
        "secrets_exposed": "v48-isolated-acceptance-secret" in rendered,
    }


def run_v48_product_acceptance(
    *,
    use_temp_db: bool,
    log_count: int = 50_000,
    simulate_interruption: bool = False,
    run_detection_enabled: bool = False,
    test_assistant: bool = False,
    test_backup_restore: bool = False,
    temp_parent: Path | None = None,
) -> dict[str, Any]:
    if not use_temp_db:
        return {
            "ok": False,
            "status": "explicit_temp_database_required",
            "current_database_modified": False,
            "production_ready": False,
            "secrets_exposed": False,
        }
    if log_count < _MIN_LOG_COUNT or log_count > _MAX_LOG_COUNT:
        return {
            "ok": False,
            "status": "invalid_log_count",
            "allowed_range": [_MIN_LOG_COUNT, _MAX_LOG_COUNT],
            "current_database_modified": False,
            "production_ready": False,
            "secrets_exposed": False,
        }
    if test_assistant and not run_detection_enabled:
        return {
            "ok": False,
            "status": "assistant_requires_detection",
            "current_database_modified": False,
            "production_ready": False,
            "secrets_exposed": False,
        }

    configured_path = _configured_sqlite_path()
    marker_before = _configured_database_marker(configured_path)
    parent = (temp_parent or (PROJECT_ROOT / ".tmp")).resolve()
    temp_root = parent / f"v48-product-acceptance-{uuid4().hex[:12]}"
    database_path = temp_root / "acceptance.sqlite3"
    staging_root = temp_root / "staging"
    database_url = _safe_url(database_path)
    engine = None
    result: dict[str, Any] | None = None
    stage = "initialize"
    started = time.perf_counter()
    temp_root.mkdir(parents=True, exist_ok=False)
    try:
        stage = "prepare_synthetic_inputs"
        bulk_count = log_count - _RESERVED_SCENARIO_LOGS
        bulk_path = temp_root / "bulk-generic-syslog.log"
        recovery_path = temp_root / "recovery-generic-syslog.log"
        _write_bulk_syslog(bulk_path, bulk_count)
        _write_recovery_syslog(recovery_path)
        port_scan_path = PROJECT_ROOT / "data" / "samples" / "scenarios" / "port_scan_like_traffic.txt"
        malformed_path = PROJECT_ROOT / "data" / "samples" / "scenarios" / "malformed_raw_fallback.txt"
        if not port_scan_path.is_file() or not malformed_path.is_file():
            raise FileNotFoundError("Required safe scenario sample is missing.")

        stage = "migrate_disposable_database"
        migration = _run_alembic_upgrade(database_url)
        if not migration.get("ok"):
            raise RuntimeError("Disposable database migration failed.")

        stage = "exercise_runtime_services"
        chunk_size = min(500, max(2, bulk_count // 2))
        with _isolated_runtime(database_url, staging_root, chunk_size=chunk_size) as settings:
            engine = create_configured_engine(settings)
            ingestion_started = time.perf_counter()
            with Session(engine) as db:
                migration_state = _migration_state(db)
                sources = {
                    "bulk": create_source(db, name="v48-bulk-router", source_type="router", parser_profile="generic_syslog"),
                    "recovery": create_source(
                        db,
                        name="v48-recovery-router",
                        source_type="router",
                        parser_profile="generic_syslog",
                    ),
                    "firewall": create_source(
                        db,
                        name="v48-portscan-firewall",
                        source_type="firewall",
                        parser_profile="palo_alto",
                    ),
                    "fallback": create_source(
                        db,
                        name="v48-raw-fallback",
                        source_type="sample",
                        parser_profile="raw_fallback",
                    ),
                }

                bulk_job = _stage_and_enqueue(
                    db,
                    path=bulk_path,
                    source=sources["bulk"],
                    limit=bulk_count,
                    name="v48-bulk-generic-syslog.log",
                )
                bulk_result = _process_job(
                    db,
                    bulk_job,
                    worker_id="v48-bulk-worker",
                    simulate_interruption=simulate_interruption,
                )

                recovery_job = _stage_and_enqueue(
                    db,
                    path=recovery_path,
                    source=sources["recovery"],
                    limit=6,
                    name="v48-recovery-generic-syslog.log",
                )
                recovery_result = (
                    _cancel_and_resume(db, recovery_job)
                    if simulate_interruption
                    else _process_job(db, recovery_job, worker_id="v48-recovery-worker")
                )

                first_scan_job = _stage_and_enqueue(
                    db,
                    path=port_scan_path,
                    source=sources["firewall"],
                    limit=10,
                    name="v48-port-scan-first.log",
                )
                first_scan_import = _process_job(db, first_scan_job, worker_id="v48-portscan-first")
                first_detection: dict[str, Any] | None = None
                second_detection: dict[str, Any] | None = None
                detection_seconds = 0.0
                if run_detection_enabled:
                    first_detection, seconds = _timed(
                        lambda: run_detection(
                            db,
                            limit=None,
                            use_ml=False,
                            actor=_ACTOR,
                            source_id=sources["firewall"].id,
                            source_name=sources["firewall"].name,
                            source_type=sources["firewall"].source_type,
                        )
                    )
                    detection_seconds += seconds

                second_scan_job = _stage_and_enqueue(
                    db,
                    path=port_scan_path,
                    source=sources["firewall"],
                    limit=10,
                    name="v48-port-scan-repeat.log",
                )
                second_scan_import = _process_job(db, second_scan_job, worker_id="v48-portscan-repeat")
                if run_detection_enabled:
                    second_detection, seconds = _timed(
                        lambda: run_detection(
                            db,
                            limit=None,
                            use_ml=False,
                            actor=_ACTOR,
                            source_id=sources["firewall"].id,
                            source_name=sources["firewall"].name,
                            source_type=sources["firewall"].source_type,
                        )
                    )
                    detection_seconds += seconds

                fallback_job = _stage_and_enqueue(
                    db,
                    path=malformed_path,
                    source=sources["fallback"],
                    limit=3,
                    name="v48-malformed-raw-fallback.log",
                )
                fallback_import = _process_job(db, fallback_job, worker_id="v48-fallback-worker")
                ingestion_seconds = time.perf_counter() - ingestion_started

                stale_recovery = _stale_lease_recovery(db)
                counts = _database_counts(db)
                source_states: dict[str, dict[str, Any]] = {}
                for key, source in sources.items():
                    db.refresh(source)
                    health = source_health(source)
                    source_states[key] = {
                        "source_id": source.id,
                        "source_type": source.source_type,
                        "parser_profile": source.parser_profile,
                        "status": health["status"],
                        "logs_received": source.logs_received_count,
                        "parse_success": source.parse_success_count,
                        "parse_failures": source.parse_failure_count,
                        "warnings": list(health["warnings"]),
                    }

                missing_source_links = int(
                    db.scalar(select(func.count(RawLog.id)).where(RawLog.source_id.is_(None))) or 0
                )
                empty_raw_evidence = int(
                    db.scalar(select(func.count(RawLog.id)).where(func.length(func.trim(RawLog.raw_line)) == 0)) or 0
                )
                duplicate_total = int(db.scalar(select(func.sum(IngestionRun.duplicate_raw_logs))) or 0)
                parse_failure_total = int(db.scalar(select(func.sum(IngestionRun.parse_failures))) or 0)

                alert = None
                alert_case = None
                explanation = None
                source_alerts: list[Alert] = []
                if run_detection_enabled:
                    source_alerts = list_alerts(db, source_id=sources["firewall"].id, limit=20)
                    alert = source_alerts[0] if source_alerts else None
                    if alert is not None:
                        alert = get_alert(db, alert.id)
                        explanation = build_alert_detection_summary(db, alert)
                        alert_cases = list_alert_cases(db, source_id=sources["firewall"].id, limit=20)
                        alert_case = alert_cases[0] if alert_cases else None

                assistant_result = None
                assistant_seconds = None
                if test_assistant and alert is not None:
                    assistant_result, assistant_seconds = _assistant_validation(
                        db,
                        alert_id=alert.id,
                        settings=settings,
                    )

                observability = _safe_metrics_validation(db, settings)
                performance = _performance_checks(db, assistant_seconds=assistant_seconds)
                performance.update(
                    {
                        "total_ingestion_seconds": round(ingestion_seconds, 4),
                        "raw_rows_per_second": round(log_count / ingestion_seconds, 2) if ingestion_seconds else None,
                        "normalized_rows_per_second": round(log_count / ingestion_seconds, 2) if ingestion_seconds else None,
                        "detection_seconds": round(detection_seconds, 4) if run_detection_enabled else None,
                        "resume_overhead_seconds": round(
                            float(bulk_result.get("resume_runtime_seconds") or 0)
                            + float(recovery_result.get("resume_runtime_seconds") or 0),
                            4,
                        ),
                        "database_size_bytes": database_path.stat().st_size if database_path.exists() else 0,
                    }
                )

                backup_restore = None
                backup_seconds = None
                if test_backup_restore:
                    backup_restore, backup_seconds = _backup_restore_validation(settings, temp_root)
                    backup_restore["runtime_seconds"] = round(backup_seconds, 4)

                alert_source_ids = {
                    evidence.normalized_log.raw_log.source_id
                    for evidence in (alert.evidence if alert is not None else [])
                    if evidence.normalized_log is not None and evidence.normalized_log.raw_log is not None
                }
                occurrence_count, related_log_count = _alert_group_counts(alert)
                ingestion_run_consistency = all(
                    run.status == "completed"
                    and run.total_lines_received == run.raw_logs_created
                    and run.raw_logs_created == run.parsed_successfully + run.parse_failures
                    for run in db.scalars(select(IngestionRun))
                )
                expected_alert = bool(
                    alert is not None
                    and alert.alert_type == "possible_port_scan"
                    and occurrence_count >= 20
                    and related_log_count >= 20
                )
                detection_consistent = bool(
                    not run_detection_enabled
                    or (
                        first_detection
                        and second_detection
                        and first_detection.get("created_alerts", 0) >= 1
                        and second_detection.get("deduplicated_alert_updates", 0) >= 1
                        and expected_alert
                    )
                )
                investigation_consistent = bool(
                    not run_detection_enabled
                    or (
                        alert_case
                        and alert_case.get("total_related_logs", 0) >= 20
                        and sources["firewall"].id in alert_source_ids
                        and explanation
                        and explanation.get("why_flagged")
                    )
                )

                checks = {
                    "migration_at_head": bool(migration_state["at_head"]),
                    "exact_raw_log_count": counts["raw_logs"] == log_count,
                    "exact_normalized_log_count": counts["normalized_logs"] == log_count,
                    "all_raw_evidence_preserved": empty_raw_evidence == 0,
                    "all_logs_source_linked": missing_source_links == 0,
                    "source_counters_match": sum(item["logs_received"] for item in source_states.values()) == log_count,
                    "parse_accounting_consistent": ingestion_run_consistency,
                    "parse_failures_tracked": parse_failure_total >= 3,
                    "duplicates_tracked": duplicate_total >= 10,
                    "bulk_import_completed": bool(bulk_result.get("ok")),
                    "recovery_import_completed": bool(recovery_result.get("ok")),
                    "scenario_imports_completed": all(
                        item.get("ok") for item in (first_scan_import, second_scan_import, fallback_import)
                    ),
                    "interruption_resume_validated": bool(
                        not simulate_interruption
                        or (bulk_result.get("resume_completed") and recovery_result.get("ok"))
                    ),
                    "stale_lease_failed_closed": bool(stale_recovery.get("ok")),
                    "source_scoped_detection_consistent": detection_consistent,
                    "investigation_traceability_consistent": investigation_consistent,
                    "assistant_safe_and_grounded": bool(not test_assistant or (assistant_result and assistant_result.get("ok"))),
                    "observability_safe": bool(
                        observability.get("ok")
                        and not observability.get("raw_evidence_exposed")
                        and not observability.get("secrets_exposed")
                    ),
                    "backup_restore_validated": bool(
                        not test_backup_restore or (backup_restore and backup_restore.get("ok"))
                    ),
                    "no_response_actions": counts["response_actions"] == 0,
                    "no_labels_or_models": counts["labels"] == 0 and counts["model_runs"] == 0,
                    "no_users_created": counts["users"] == 0,
                }
                failed_checks = [name for name, passed in checks.items() if not passed]
                warnings: list[str] = []
                if source_states["fallback"]["status"] in {"warning", "error"}:
                    warnings.append("Raw fallback scenario intentionally records parser/data-quality warnings.")
                if performance["overview_cold_app_cache_p95_seconds"] and performance[
                    "overview_cold_app_cache_p95_seconds"
                ] > 2.0:
                    warnings.append("Overview cold app-cache latency exceeded the 2-second acceptance target.")
                if performance["overview_warm_cache_p95_seconds"] and performance[
                    "overview_warm_cache_p95_seconds"
                ] > 0.25:
                    warnings.append("Overview warm-cache latency exceeded the 250-millisecond acceptance target.")

                result = {
                    "ok": not failed_checks,
                    "status": "v48_product_acceptance_passed" if not failed_checks else "v48_product_acceptance_failed",
                    "scope": "synthetic_disposable_sqlite_only",
                    "options": {
                        "log_count": log_count,
                        "simulate_interruption": simulate_interruption,
                        "run_detection": run_detection_enabled,
                        "test_assistant": test_assistant,
                        "test_backup_restore": test_backup_restore,
                    },
                    "lifecycle": {
                        "normal_startup_commands_changed": False,
                        "runtime_services_exercised": [
                            "durable_import_jobs",
                            "resumable_ingestion",
                            "source_management",
                            "rule_detection",
                            "alert_deduplication",
                            "case_grouping",
                            "explainability",
                            "assistant",
                            "observability",
                            "backup_restore",
                        ],
                    },
                    "migration": migration_state,
                    "sources": source_states,
                    "ingestion": {
                        "attempted": log_count,
                        "raw_logs_imported": counts["raw_logs"],
                        "normalized_logs_created": counts["normalized_logs"],
                        "parse_failures": parse_failure_total,
                        "duplicate_raw_logs": duplicate_total,
                        "missing_source_links": missing_source_links,
                        "empty_raw_evidence": empty_raw_evidence,
                    },
                    "recovery": {
                        "bulk_graceful_interruption": bulk_result,
                        "cancellation_resume": recovery_result,
                        "stale_lease": stale_recovery,
                    },
                    "detection": {
                        "enabled": run_detection_enabled,
                        "first_run": first_detection,
                        "second_run": second_detection,
                        "source_scoped_alert_count": len(source_alerts),
                        "alert_id": alert.id if alert is not None else None,
                        "alert_type": alert.alert_type if alert is not None else None,
                        "occurrence_count": occurrence_count,
                        "related_log_count": related_log_count,
                    },
                    "investigation": {
                        "source_traceable": bool(alert and sources["firewall"].id in alert_source_ids),
                        "case_id": alert_case.get("case_id") if alert_case else None,
                        "case_attack_types": alert_case.get("attack_types", []) if alert_case else [],
                        "case_related_logs": alert_case.get("total_related_logs", 0) if alert_case else 0,
                        "why_flagged_available": bool(explanation and explanation.get("why_flagged")),
                        "decision_support_only": True,
                    },
                    "assistant": assistant_result
                    or {
                        "tested": False,
                        "raw_log_context_included": False,
                        "external_provider_used": False,
                        "response_actions_created": 0,
                        "secrets_exposed": False,
                    },
                    "backup_restore": backup_restore
                    or {
                        "tested": False,
                        "current_database_modified": False,
                        "secrets_exposed": False,
                    },
                    "observability": observability,
                    "performance": performance,
                    "counts": counts,
                    "checks": checks,
                    "warnings": warnings,
                    "failed_checks": failed_checks,
                    "current_database_marker_checked": marker_before is not None,
                    "current_database_unchanged": None,
                    "current_database_modified": False,
                    "response_automation_allowed": False,
                    "real_firewall_blocking_enabled": False,
                    "model_activation_performed": False,
                    "production_ready": False,
                    "secrets_exposed": False,
                    "total_runtime_seconds": round(time.perf_counter() - started, 4),
                }
    except Exception as exc:
        logger.exception("v4.8 product acceptance failed during %s", stage)
        result = {
            "ok": False,
            "status": "v48_product_acceptance_error",
            "error_type": exc.__class__.__name__,
            "error_stage": stage,
            "current_database_modified": False,
            "response_automation_allowed": False,
            "real_firewall_blocking_enabled": False,
            "model_activation_performed": False,
            "production_ready": False,
            "secrets_exposed": False,
            "total_runtime_seconds": round(time.perf_counter() - started, 4),
        }
    finally:
        if engine is not None:
            engine.dispose()
        _remove_temp_root(temp_root)
        clear_dashboard_summary_cache()
        get_settings.cache_clear()

    marker_after = _configured_database_marker(configured_path)
    configured_unchanged = marker_before == marker_after
    _remove_temp_root(temp_root)
    result = result or {
        "ok": False,
        "status": "v48_product_acceptance_error",
        "secrets_exposed": False,
    }
    result["current_database_marker_checked"] = marker_before is not None
    result["current_database_unchanged"] = configured_unchanged
    result["current_database_modified"] = not configured_unchanged
    result["temp_artifacts_removed"] = not temp_root.exists()
    result["ok"] = bool(result.get("ok") and configured_unchanged and not temp_root.exists())
    if not result["ok"] and result.get("status") == "v48_product_acceptance_passed":
        result["status"] = "v48_product_acceptance_failed"
    return result


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run ATDR v4.8 end-to-end product acceptance against a disposable SQLite database."
    )
    parser.add_argument("--use-temp-db", action="store_true", help="Required isolated-database safety confirmation.")
    parser.add_argument("--log-count", type=int, default=50_000)
    parser.add_argument("--simulate-interruption", action="store_true")
    parser.add_argument("--run-detection", action="store_true")
    parser.add_argument("--test-assistant", action="store_true")
    parser.add_argument("--test-backup-restore", action="store_true")
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()
    result = run_v48_product_acceptance(
        use_temp_db=args.use_temp_db,
        log_count=args.log_count,
        simulate_interruption=args.simulate_interruption,
        run_detection_enabled=args.run_detection,
        test_assistant=args.test_assistant,
        test_backup_restore=args.test_backup_restore,
    )
    print(json.dumps(result, indent=2 if args.pretty else None, default=str))
    raise SystemExit(0 if result.get("ok") else 1)


if __name__ == "__main__":
    main()
