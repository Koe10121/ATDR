from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timezone
import logging
from pathlib import Path
from typing import Any, BinaryIO

from sqlalchemy import select
from sqlalchemy.orm import Session

from atdr.app.core.config import get_settings
from atdr.app.db.models import AuditLog, IngestionRun, OperationJob, RawLog
from atdr.app.parsers.paloalto_parser import parse_log_line_for_profile
from atdr.app.services.job_service import (
    LeaseOwnershipError,
    complete_cooperative_cancellation,
    public_job_details,
    record_worker_heartbeat,
    release_job_for_graceful_shutdown,
    renew_job_lease,
)
from atdr.app.services.log_service import persist_parsed_log
from atdr.app.services.operation_run_service import complete_ingestion_run, fail_ingestion_run, safe_source_label, start_ingestion_run
from atdr.app.services.source_service import (
    DEFAULT_SOURCE_NAME,
    get_or_create_source,
    lock_source_for_ingestion,
    record_source_ingestion,
)
from atdr.app.services.staging_service import StagedInputMetadata, validate_staged_payload


logger = logging.getLogger(__name__)


class CooperativeImportCancelled(RuntimeError):
    """Signals that a running import stopped cleanly at a committed checkpoint."""

    def __init__(self, job_id: int) -> None:
        super().__init__("Import cancelled at a committed chunk boundary.")
        self.job_id = job_id


class CooperativeWorkerShutdown(RuntimeError):
    """Signals that an import lease was released at a committed checkpoint."""

    def __init__(self, job_id: int) -> None:
        super().__init__("Import released at a committed chunk boundary for graceful worker shutdown.")
        self.job_id = job_id


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _job(db: Session, job_id: int, worker_id: str, lease_token: str) -> OperationJob:
    job = db.get(OperationJob, job_id)
    if job is None:
        raise ValueError("Operation job no longer exists.")
    if (
        job.lease_owner != worker_id
        or job.lease_token != lease_token
        or job.status not in {"running", "cancel_requested"}
    ):
        raise LeaseOwnershipError("Operation job lease is no longer owned by this worker.")
    return job


def _safe_input_name(payload: dict[str, Any], metadata: StagedInputMetadata) -> str:
    return safe_source_label(str(payload.get("input_name") or metadata.safe_name)) or "uploaded-log.txt"


def _target_total(metadata: StagedInputMetadata, limit: int | None) -> int:
    if limit is None:
        return metadata.available_lines
    return min(metadata.available_lines, max(0, int(limit)))


def _initialize_run(
    db: Session,
    *,
    job: OperationJob,
    payload: dict[str, Any],
    metadata: StagedInputMetadata,
    source_id: int,
    input_name: str,
) -> IngestionRun:
    run_id = job.related_ingestion_run_id or payload.get("ingestion_run_id")
    run = db.get(IngestionRun, int(run_id)) if run_id else None
    if run is None:
        run = start_ingestion_run(
            db,
            source_type=str(payload.get("source_type") or "file_import"),
            input_name=input_name,
            details={
                "limit": payload.get("limit"),
                "source_id": source_id,
                "available_lines": metadata.available_lines,
                "operation_job_id": job.id,
                "processing_guarantee": "transactional_committed_chunks",
            },
        )
    else:
        run.status = "running"
        run.finished_at = None
        run.error_summary = None
        run.details_json = {
            **(run.details_json or {}),
            "resumed_by_job_id": job.id,
            "resume_count": int((run.details_json or {}).get("resume_count") or 0) + 1,
        }
    job.related_ingestion_run_id = run.id
    return run


def _read_chunk(
    stream: BinaryIO,
    *,
    max_records: int,
    physical_line: int,
) -> tuple[list[tuple[int, str]], int, int, bool]:
    records: list[tuple[int, str]] = []
    reached_eof = False
    while len(records) < max_records:
        line_bytes = stream.readline()
        if not line_bytes:
            reached_eof = True
            break
        physical_line += 1
        line = line_bytes.decode("utf-8", errors="replace")
        if not line.strip():
            continue
        records.append((physical_line, line))
    return records, physical_line, int(stream.tell()), reached_eof


def _cancel_at_boundary(
    db: Session,
    *,
    job: OperationJob,
    run: IngestionRun,
    worker_id: str,
    lease_token: str,
) -> None:
    complete_ingestion_run(
        db,
        run,
        total_lines_received=run.total_lines_received,
        raw_logs_created=run.raw_logs_created,
        parsed_successfully=run.parsed_successfully,
        parse_failures=run.parse_failures,
        duplicate_raw_logs=run.duplicate_raw_logs,
        status="cancelled",
        details={
            "cancelled_at_checkpoint_line": job.checkpoint_line,
            "cancelled_at_checkpoint_bytes": job.checkpoint_bytes,
            "resume_preserves_committed_evidence": True,
        },
    )
    complete_cooperative_cancellation(
        db,
        job,
        worker_id=worker_id,
        lease_token=lease_token,
        details={
            "checkpoint_line": job.checkpoint_line,
            "checkpoint_bytes": job.checkpoint_bytes,
            "committed_logs": job.progress_current,
        },
    )
    db.commit()
    raise CooperativeImportCancelled(job.id)


def _release_at_boundary(
    db: Session,
    *,
    job: OperationJob,
    worker_id: str,
    lease_token: str,
) -> None:
    release_job_for_graceful_shutdown(
        db,
        job,
        worker_id=worker_id,
        lease_token=lease_token,
    )
    db.commit()
    raise CooperativeWorkerShutdown(job.id)


def run_resumable_import(
    db: Session,
    *,
    job_id: int,
    worker_id: str,
    lease_token: str,
    payload: dict[str, Any],
    actor: str,
    after_chunk: Callable[[int, OperationJob], None] | None = None,
    should_stop: Callable[[], bool] | None = None,
) -> dict[str, Any]:
    """Import a staged file in atomic chunks whose log writes and checkpoint commit together."""

    settings = get_settings()
    path, metadata = validate_staged_payload(payload)
    job = _job(db, job_id, worker_id, lease_token)
    if job.input_fingerprint and job.input_fingerprint != metadata.fingerprint:
        raise ValueError("Queued import staging fingerprint changed; resume is blocked.")
    if job.input_size_bytes is not None and job.input_size_bytes != metadata.byte_count:
        raise ValueError("Queued import staging file size changed; resume is blocked.")

    input_name = _safe_input_name(payload, metadata)
    source_type = str(payload.get("source_type") or "file_import")
    source_label = input_name or DEFAULT_SOURCE_NAME
    source_record_name = DEFAULT_SOURCE_NAME if payload.get("source_id") is None and source_type == "file_import" else source_label
    source = get_or_create_source(
        db,
        source_id=payload.get("source_id"),
        name=source_record_name,
        source_type=source_type,
        parser_profile=payload.get("parser_profile"),
    )
    run = _initialize_run(
        db,
        job=job,
        payload=payload,
        metadata=metadata,
        source_id=source.id,
        input_name=input_name,
    )
    total = _target_total(metadata, payload.get("limit"))
    payload = {
        **payload,
        "input_name": input_name,
        "input_bytes": metadata.byte_count,
        "input_fingerprint": metadata.fingerprint,
        "available_lines": metadata.available_lines,
        "ingestion_run_id": run.id,
    }
    job.payload_json = payload
    job.input_size_bytes = metadata.byte_count
    job.input_fingerprint = metadata.fingerprint
    job.progress_total = total
    details = dict(job.details_json or {})
    details.update(
        {
            "input_name": input_name,
            "input_bytes": metadata.byte_count,
            "available_lines": metadata.available_lines,
            "parser_profile": source.parser_profile,
            "source_id": source.id,
            "processing_guarantee": "transactional_committed_chunks",
        }
    )
    job.details_json = public_job_details(details)
    db.commit()
    db.refresh(job)
    db.refresh(run)
    db.refresh(source)

    if should_stop is not None and should_stop():
        _release_at_boundary(
            db,
            job=job,
            worker_id=worker_id,
            lease_token=lease_token,
        )

    chunk_size = max(1, min(int(settings.ingestion_chunk_size), int(settings.ingestion_progress_update_interval)))
    imported = max(0, int(job.progress_current or 0))
    physical_line = max(0, int(job.checkpoint_line or 0))
    latest_error = source.latest_error

    with Path(path).open("rb") as stream:
        stream.seek(max(0, int(job.checkpoint_bytes or 0)))
        while imported < total:
            db.expire(job)
            job = _job(db, job_id, worker_id, lease_token)
            if job.status == "cancel_requested":
                run = db.get(IngestionRun, int(job.related_ingestion_run_id or 0)) or run
                _cancel_at_boundary(
                    db,
                    job=job,
                    run=run,
                    worker_id=worker_id,
                    lease_token=lease_token,
                )
            if should_stop is not None and should_stop():
                _release_at_boundary(
                    db,
                    job=job,
                    worker_id=worker_id,
                    lease_token=lease_token,
                )

            records, physical_line, checkpoint_bytes, reached_eof = _read_chunk(
                stream,
                max_records=min(chunk_size, total - imported),
                physical_line=physical_line,
            )
            if not records:
                job.checkpoint_line = physical_line
                job.checkpoint_bytes = checkpoint_bytes
                break

            chunk_parsed = 0
            chunk_failed = 0
            chunk_duplicates = 0
            for line_number, line in records:
                raw_text = line.rstrip("\r\n")
                existing_raw = db.scalar(select(RawLog.id).where(RawLog.raw_line == raw_text).limit(1))
                chunk_duplicates += int(existing_raw is not None)
                parsed_log = parse_log_line_for_profile(line, source.parser_profile)
                persist_parsed_log(db, parsed_log, source_id=source.id)
                if parsed_log.error:
                    chunk_failed += 1
                    latest_error = parsed_log.error
                    logger.debug("Parser issue in %s line %s: %s", input_name, line_number, parsed_log.error)
                else:
                    chunk_parsed += 1

            committed_count = len(records)
            imported += committed_count
            source = lock_source_for_ingestion(db, source.id)
            record_source_ingestion(
                source,
                logs_received=committed_count,
                parsed_successfully=chunk_parsed,
                parse_failures=chunk_failed,
                latest_error=latest_error if chunk_failed else None,
            )
            run.total_lines_received += committed_count
            run.raw_logs_created += committed_count
            run.parsed_successfully += chunk_parsed
            run.parse_failures += chunk_failed
            run.duplicate_raw_logs += chunk_duplicates

            job.progress_current = imported
            job.checkpoint_line = physical_line
            job.checkpoint_bytes = checkpoint_bytes
            job.checkpoint_at = _now()
            job.chunk_commits += 1
            renew_job_lease(
                db,
                job,
                worker_id=worker_id,
                lease_token=lease_token,
                lease_seconds=settings.operation_worker_lease_seconds,
            )
            job_details = dict(job.details_json or {})
            job_details.update(
                {
                    "latest_heartbeat_at": job.checkpoint_at.isoformat(),
                    "last_chunk_records": committed_count,
                    "last_chunk_parse_failures": chunk_failed,
                }
            )
            job.details_json = public_job_details(job_details)
            record_worker_heartbeat(
                db,
                worker_id=worker_id,
                status="running",
                current_job_id=job.id,
                details={"job_type": job.job_type, "chunk_commits": job.chunk_commits},
                commit=False,
            )
            db.commit()
            db.refresh(job)
            db.refresh(run)
            db.refresh(source)
            if after_chunk is not None:
                after_chunk(job.chunk_commits, job)
            if should_stop is not None and should_stop() and imported < total and not reached_eof:
                _release_at_boundary(
                    db,
                    job=job,
                    worker_id=worker_id,
                    lease_token=lease_token,
                )
            if reached_eof:
                break

    job = _job(db, job_id, worker_id, lease_token)
    if job.status == "cancel_requested":
        run = db.get(IngestionRun, int(job.related_ingestion_run_id or 0)) or run
        _cancel_at_boundary(
            db,
            job=job,
            run=run,
            worker_id=worker_id,
            lease_token=lease_token,
        )

    complete_ingestion_run(
        db,
        run,
        total_lines_received=run.total_lines_received,
        raw_logs_created=run.raw_logs_created,
        parsed_successfully=run.parsed_successfully,
        parse_failures=run.parse_failures,
        duplicate_raw_logs=run.duplicate_raw_logs,
        details={
            "actor": actor,
            "source_id": source.id,
            "available_lines": metadata.available_lines,
            "operation_job_id": job.id,
            "checkpoint_line": job.checkpoint_line,
            "checkpoint_bytes": job.checkpoint_bytes,
            "chunk_commits": job.chunk_commits,
        },
    )
    db.add(
        AuditLog(
            actor=actor,
            action="import_logs",
            target_type=source_type,
            target_value=input_name,
            details={
                "imported": run.raw_logs_created,
                "parsed": run.parsed_successfully,
                "failed": run.parse_failures,
                "duplicate_raw_logs": run.duplicate_raw_logs,
                "limit": payload.get("limit"),
                "available_lines": metadata.available_lines,
                "source_id": source.id,
                "operation_job_id": job.id,
                "resumed": job.resume_of_job_id is not None,
            },
        )
    )
    db.commit()
    return {
        "source": input_name,
        "source_label": input_name,
        "requested_limit": payload.get("limit"),
        "available_lines": metadata.available_lines,
        "imported": run.raw_logs_created,
        "raw_logs_imported": run.raw_logs_created,
        "normalized_logs_created": run.raw_logs_created,
        "parsed": run.parsed_successfully,
        "parsed_successfully": run.parsed_successfully,
        "failed": run.parse_failures,
        "parse_failures": run.parse_failures,
        "duplicate_raw_logs": run.duplicate_raw_logs,
        "alerts_created": 0,
        "alerts_deduplicated": 0,
        "alerts_suppressed": 0,
        "run_id": run.id,
        "source_id": source.id,
        "chunk_commits": job.chunk_commits,
        "checkpoint_line": job.checkpoint_line,
        "checkpoint_bytes": job.checkpoint_bytes,
        "resumed": job.resume_of_job_id is not None,
    }


def mark_resumable_ingestion_failed(db: Session, job: OperationJob, *, error: BaseException | str) -> None:
    if not job.related_ingestion_run_id:
        return
    run = db.get(IngestionRun, job.related_ingestion_run_id)
    if run is None or run.status == "completed":
        return
    error_text = f"{error.__class__.__name__}: {error}" if isinstance(error, BaseException) else str(error)
    fail_ingestion_run(
        db,
        run,
        error=error_text,
        details={
            "operation_job_id": job.id,
            "checkpoint_line": job.checkpoint_line,
            "checkpoint_bytes": job.checkpoint_bytes,
            "resume_possible_if_staged_input_is_valid": True,
        },
    )
    db.commit()
