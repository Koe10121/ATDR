from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import shutil
import time
import tracemalloc
from typing import Any, Iterator
from unittest.mock import patch
from uuid import uuid4

from sqlalchemy import create_engine, func, select
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session

from atdr.app.core.config import PROJECT_ROOT, get_settings
from atdr.app.db.database import Base
from atdr.app.db.models import DetectionRun, IngestionRun, MLLabel, MLModelRun, NormalizedLog, OperationJob, RawLog, ResponseAction
from atdr.app.services.job_service import claim_next_job, enqueue_job, request_job_cancellation
from atdr.app.services.operation_worker import run_worker_once
from atdr.app.services.resumable_ingestion_service import CooperativeImportCancelled, run_resumable_import
from atdr.app.services.staging_service import (
    cleanup_staged_payload,
    stage_upload_for_job,
    staged_payload_fields,
    validate_staged_payload,
)


_VALIDATION_ACTOR = "v397-ingestion-validator"
_MAX_VALIDATION_LINES = 1_000_000
_PEAK_MEMORY_BUDGET_MB = 128.0


class _StopAfterFirstCommittedChunk:
    def __init__(self) -> None:
        self._checks = 0

    def is_set(self) -> bool:
        self._checks += 1
        # Initialization, pre-chunk, then the first post-commit boundary.
        return self._checks >= 3


def _configured_sqlite_marker() -> tuple[Path | None, tuple[int, int] | None]:
    settings = get_settings()
    try:
        url = make_url(settings.database_url)
    except Exception:
        return None, None
    if not url.drivername.startswith("sqlite") or not url.database or url.database == ":memory:":
        return None, None
    path = Path(url.database)
    path = (PROJECT_ROOT / path).resolve() if not path.is_absolute() else path.resolve()
    if not path.exists():
        return path, None
    stat = path.stat()
    return path, (int(stat.st_size), int(stat.st_mtime_ns))


def _write_synthetic_syslog(path: Path, lines: int) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for index in range(lines):
            handle.write(
                "2026-07-13T12:00:00Z lab-router "
                f"event_id={index:09d} action=allow protocol=tcp service=synthetic-validation\n"
            )


@contextmanager
def _runtime_settings(staging_root: Path, *, chunk_size: int) -> Iterator[None]:
    values = {
        "OPERATION_STAGING_ROOT": str(staging_root.resolve()),
        "OPERATION_STAGING_MIN_FREE_BYTES": "0",
        "OPERATION_STAGING_MAX_TOTAL_BYTES": str(512 * 1024 * 1024),
        "OPERATION_JOB_MAX_INPUT_BYTES": str(256 * 1024 * 1024),
        "OPERATION_STAGING_STORAGE_ID": "v397-temp",
        "INGESTION_CHUNK_SIZE": str(chunk_size),
        "INGESTION_PROGRESS_UPDATE_INTERVAL": str(chunk_size),
        "OPERATION_WORKER_LEASE_SECONDS": "900",
        "RESPONSE_SIMULATION": "true",
        "ASSISTANT_LLM_ENABLED": "false",
        "ASSISTANT_ALLOW_RAW_LOG_CONTEXT": "false",
    }
    with patch.dict(os.environ, values, clear=False):
        get_settings.cache_clear()
        try:
            yield
        finally:
            get_settings.cache_clear()


def _enqueue_staged_import(db: Session, staged: Any, *, lines: int) -> OperationJob:
    payload = {
        **staged_payload_fields(staged),
        "input_name": staged.safe_name,
        "input_bytes": staged.byte_count,
        "input_fingerprint": staged.fingerprint,
        "available_lines": staged.available_lines,
        "source_type": "file_import",
        "parser_profile": "generic_syslog",
        "limit": lines,
        "source_id": None,
    }
    job, _ = enqueue_job(
        db,
        job_type="import_logs",
        requested_by=_VALIDATION_ACTOR,
        payload=payload,
        details={
            "input_name": staged.safe_name,
            "available_lines": staged.available_lines,
            "parser_profile": "generic_syslog",
            "validation_scope": "disposable_temp_database",
        },
        progress_total=lines,
        input_size_bytes=staged.byte_count,
        input_fingerprint=staged.fingerprint,
        resume_expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        staging_storage_id=staged.storage_id,
    )
    return job


def _changed_input_check(root: Path) -> bool:
    staging_root = root / "changed-staging"
    source_path = root / "changed-source.log"
    _write_synthetic_syslog(source_path, 3)
    with _runtime_settings(staging_root, chunk_size=2):
        with source_path.open("rb") as stream:
            staged = stage_upload_for_job(stream, filename="changed-source.log")
        payload = {
            **staged_payload_fields(staged),
            "input_bytes": staged.byte_count,
            "input_fingerprint": staged.fingerprint,
        }
        with staged.path.open("r+b") as stream:
            first = stream.read(1)
            stream.seek(0)
            stream.write(b"X" if first != b"X" else b"Y")
        try:
            validate_staged_payload(payload)
        except ValueError:
            return True
        finally:
            cleanup_staged_payload(payload)
    return False


def _cancellation_check(root: Path) -> dict[str, Any]:
    database_path = root / "cancellation.sqlite3"
    staging_root = root / "cancel-staging"
    source_path = root / "cancel-source.log"
    _write_synthetic_syslog(source_path, 5)
    engine = create_engine(
        f"sqlite:///{database_path}",
        connect_args={"check_same_thread": False, "timeout": 30.0},
        future=True,
    )
    try:
        Base.metadata.create_all(engine)
        with _runtime_settings(staging_root, chunk_size=2):
            with source_path.open("rb") as stream:
                staged = stage_upload_for_job(stream, filename="cancel-source.log")
            with Session(engine) as db:
                queued = _enqueue_staged_import(db, staged, lines=5)
                claimed = claim_next_job(
                    db,
                    worker_id="v397-cancel-worker",
                    lease_seconds=60,
                    staging_storage_id=staged.storage_id,
                )
                if claimed is None or claimed.id != queued.id or not claimed.lease_token:
                    return {"ok": False, "status": "claim_failed"}

                def request_after_first(chunk_commits: int, running_job: OperationJob) -> None:
                    if chunk_commits == 1:
                        request_job_cancellation(db, running_job, actor=_VALIDATION_ACTOR)

                try:
                    run_resumable_import(
                        db,
                        job_id=claimed.id,
                        worker_id="v397-cancel-worker",
                        lease_token=claimed.lease_token,
                        payload=dict(claimed.payload_json or {}),
                        actor=_VALIDATION_ACTOR,
                        after_chunk=request_after_first,
                    )
                except CooperativeImportCancelled:
                    pass
                db.expire_all()
                persisted = db.get(OperationJob, claimed.id)
                raw_count = int(db.scalar(select(func.count(RawLog.id))) or 0)
                response_count = int(db.scalar(select(func.count(ResponseAction.id))) or 0)
                result = {
                    "ok": bool(persisted is not None and persisted.status == "cancelled" and raw_count == 2),
                    "status": persisted.status if persisted is not None else "missing",
                    "committed_rows": raw_count,
                    "checkpoint_line": persisted.checkpoint_line if persisted is not None else 0,
                    "staged_input_retained_for_resume_window": staged.path.exists(),
                    "response_actions_created": response_count,
                }
                cleanup_staged_payload(dict(claimed.payload_json or {}))
                return result
    finally:
        engine.dispose()


def validate_large_ingestion(*, use_temp_db: bool, lines: int = 100_000) -> dict[str, Any]:
    if not use_temp_db:
        return {
            "ok": False,
            "status": "explicit_temp_database_required",
            "message": "Re-run with --use-temp-db; configured databases are never valid targets for this command.",
            "current_database_modified": False,
            "production_ready": False,
        }
    if lines < 2 or lines > _MAX_VALIDATION_LINES:
        return {
            "ok": False,
            "status": "invalid_line_count",
            "allowed_range": [2, _MAX_VALIDATION_LINES],
            "current_database_modified": False,
            "production_ready": False,
        }

    configured_path, marker_before = _configured_sqlite_marker()
    run_id = uuid4().hex[:12]
    temp_root = PROJECT_ROOT / ".tmp" / f"v397-large-ingestion-{run_id}"
    database_path = temp_root / "validation.sqlite3"
    staging_root = temp_root / "staging"
    source_path = temp_root / "synthetic-generic-syslog.log"
    temp_root.mkdir(parents=True, exist_ok=False)
    engine = None
    started = time.perf_counter()
    try:
        _write_synthetic_syslog(source_path, lines)
        validation_chunk_size = min(500, max(1, lines // 2))
        with _runtime_settings(staging_root, chunk_size=validation_chunk_size):
            with source_path.open("rb") as stream:
                staged = stage_upload_for_job(stream, filename="synthetic-generic-syslog.log")
            source_path.unlink(missing_ok=True)

            engine = create_engine(
                f"sqlite:///{database_path}",
                connect_args={"check_same_thread": False, "timeout": 30.0},
                future=True,
            )
            Base.metadata.create_all(engine)
            tracemalloc.start()
            ingestion_started = time.perf_counter()
            with Session(engine) as db:
                job = _enqueue_staged_import(db, staged, lines=lines)
                progress_samples = [0]
                first = run_worker_once(
                    db,
                    worker_id="v397-interrupt-worker",
                    stop_event=_StopAfterFirstCommittedChunk(),
                )
                db.expire_all()
                interrupted = db.get(OperationJob, job.id)
                if interrupted is None:
                    raise RuntimeError("Validation operation job disappeared after interruption.")
                interrupted_status = interrupted.status
                interrupted_progress = int(interrupted.progress_current or 0)
                progress_samples.append(interrupted_progress)
                second = run_worker_once(db, worker_id="v397-resume-worker")
                db.expire_all()
                completed = db.get(OperationJob, job.id)
                if completed is None:
                    raise RuntimeError("Validation operation job disappeared after resume.")
                progress_samples.append(int(completed.progress_current or 0))

                counts = {
                    "raw_logs": int(db.scalar(select(func.count(RawLog.id))) or 0),
                    "normalized_logs": int(db.scalar(select(func.count(NormalizedLog.id))) or 0),
                    "response_actions": int(db.scalar(select(func.count(ResponseAction.id))) or 0),
                    "detection_runs": int(db.scalar(select(func.count(DetectionRun.id))) or 0),
                    "labels": int(db.scalar(select(func.count(MLLabel.id))) or 0),
                    "model_runs": int(db.scalar(select(func.count(MLModelRun.id))) or 0),
                }
                ingestion_run = db.get(IngestionRun, int(completed.related_ingestion_run_id or 0))
                details = dict(completed.details_json or {})
                ingestion_seconds = time.perf_counter() - ingestion_started
                _current_memory, peak_memory = tracemalloc.get_traced_memory()
                tracemalloc.stop()

                changed_input_rejected = _changed_input_check(temp_root)
                cancellation = _cancellation_check(temp_root)
                progress_monotonic = progress_samples == sorted(progress_samples)
                count_consistent = counts["raw_logs"] == lines and counts["normalized_logs"] == lines
                no_unsafe_side_effects = all(
                    counts[key] == 0 for key in ("response_actions", "detection_runs", "labels", "model_runs")
                )
                run_consistent = bool(
                    ingestion_run is not None
                    and ingestion_run.raw_logs_created == lines
                    and ingestion_run.parsed_successfully == lines
                    and ingestion_run.parse_failures == 0
                    and ingestion_run.duplicate_raw_logs == 0
                )
                peak_memory_mb = peak_memory / (1024 * 1024)
                all_checks = all(
                    (
                        bool(first.get("shutdown_requested")),
                        interrupted_status == "queued",
                        completed.status == "completed",
                        bool(second.get("ok")),
                        progress_monotonic,
                        count_consistent,
                        run_consistent,
                        changed_input_rejected,
                        bool(cancellation.get("ok")),
                        no_unsafe_side_effects,
                        peak_memory_mb <= _PEAK_MEMORY_BUDGET_MB,
                        not staged.path.exists(),
                        details.get("source_id") is not None,
                    )
                )
                result = {
                    "ok": all_checks,
                    "status": "large_ingestion_validation_passed" if all_checks else "large_ingestion_validation_failed",
                    "scope": "synthetic_temp_sqlite_only",
                    "lines_requested": lines,
                    "counts": counts,
                    "ingestion": {
                        "status": completed.status,
                        "source_id": details.get("source_id"),
                        "source_fallback_without_selection": details.get("source_id") is not None,
                        "parsed_successfully": ingestion_run.parsed_successfully if ingestion_run is not None else None,
                        "parse_failures": ingestion_run.parse_failures if ingestion_run is not None else None,
                        "duplicate_raw_logs": ingestion_run.duplicate_raw_logs if ingestion_run is not None else None,
                        "chunk_commits": completed.chunk_commits,
                        "checkpoint_line": completed.checkpoint_line,
                        "checkpoint_bytes": completed.checkpoint_bytes,
                        "progress_samples": progress_samples,
                        "progress_monotonic": progress_monotonic,
                        "interrupted_status": interrupted_status,
                        "interrupted_after_rows": interrupted_progress,
                        "resume_after_graceful_interruption": bool(first.get("shutdown_requested") and second.get("ok")),
                        "duplicate_rows_after_resume": max(0, counts["raw_logs"] - lines),
                        "staged_input_cleaned_after_completion": not staged.path.exists(),
                    },
                    "safety_checks": {
                        "changed_input_rejected": changed_input_rejected,
                        "cooperative_cancellation": cancellation,
                        "no_unsafe_side_effects": no_unsafe_side_effects,
                    },
                    "performance": {
                        "runtime_seconds": round(ingestion_seconds, 4),
                        "rows_per_second": round(lines / ingestion_seconds, 2) if ingestion_seconds > 0 else None,
                        "peak_python_memory_mb": round(peak_memory_mb, 2),
                        "peak_memory_budget_mb": _PEAK_MEMORY_BUDGET_MB,
                        "bounded_memory_passed": peak_memory_mb <= _PEAK_MEMORY_BUDGET_MB,
                    },
                    "current_database_modified": False,
                    "response_automation_allowed": False,
                    "model_activation_performed": False,
                    "production_ready": False,
                    "secrets_exposed": False,
                }
        marker_after = None
        if configured_path is not None and configured_path.exists():
            stat = configured_path.stat()
            marker_after = (int(stat.st_size), int(stat.st_mtime_ns))
        configured_unchanged = marker_before == marker_after
        result["current_database_marker_checked"] = configured_path is not None
        result["current_database_unchanged"] = configured_unchanged
        result["current_database_modified"] = not configured_unchanged
        result["ok"] = bool(result["ok"] and configured_unchanged)
        if not result["ok"]:
            result["status"] = "large_ingestion_validation_failed"
        result["total_runtime_seconds"] = round(time.perf_counter() - started, 4)
        return result
    except Exception as exc:
        if tracemalloc.is_tracing():
            tracemalloc.stop()
        return {
            "ok": False,
            "status": "large_ingestion_validation_error",
            "error_type": exc.__class__.__name__,
            "current_database_modified": False,
            "response_automation_allowed": False,
            "model_activation_performed": False,
            "production_ready": False,
            "secrets_exposed": False,
        }
    finally:
        if engine is not None:
            engine.dispose()
        shutil.rmtree(temp_root, ignore_errors=True)
        get_settings.cache_clear()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Validate resumable large-file ingestion using synthetic data and a disposable SQLite database."
    )
    parser.add_argument("--use-temp-db", action="store_true", help="Required safety confirmation for isolated validation.")
    parser.add_argument("--lines", type=int, default=100_000)
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()
    result = validate_large_ingestion(use_temp_db=args.use_temp_db, lines=args.lines)
    print(json.dumps(result, indent=2 if args.pretty else None, default=str))
    raise SystemExit(0 if result.get("ok") else 1)


if __name__ == "__main__":
    main()
