from __future__ import annotations

from collections import Counter
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import math
import os
from pathlib import Path
import re
import tempfile
from threading import Event, Thread
import time
import tracemalloc
from typing import Any, Iterator
from unittest.mock import patch
from uuid import uuid4

from sqlalchemy import Engine, create_engine, event, func, select, text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session

from atdr.app.core.config import PROJECT_ROOT, get_settings
from atdr.app.db.database import Base
from atdr.app.db.models import (
    Alert,
    AlertEvidence,
    DetectionRun,
    IngestionRun,
    LogSource,
    MLLabel,
    MLModelRun,
    NormalizedLog,
    OperationJob,
    RawLog,
    ResponseAction,
)
from atdr.app.services.alert_service import list_alerts
from atdr.app.services.case_service import count_alert_cases, list_alert_cases
from atdr.app.services.dashboard_service import (
    build_dashboard_summary,
    build_dashboard_summary_cached,
    clear_dashboard_summary_cache,
)
from atdr.app.services.detection_service import run_detection
from atdr.app.services.job_service import (
    claim_next_job,
    enqueue_job,
    request_job_cancellation,
    resume_eligibility,
)
from atdr.app.services.operation_worker import run_worker_once
from atdr.app.services.private_log_preflight_service import (
    preflight_private_paloalto_file,
)
from atdr.app.services.resumable_ingestion_service import (
    CooperativeImportCancelled,
    run_resumable_import,
)
from atdr.app.services.source_service import (
    create_source,
    source_health,
    source_to_dict,
)
from atdr.app.services.staging_service import (
    StagedInputMetadata,
    stage_upload_for_job,
    staged_payload_fields,
)


_ACTOR = "v514-runtime-acceptance"
_DEFAULT_LIMIT = 100_000
_MAX_LIMIT = 1_000_000
_MIN_ROWS = 4
_IP_PATTERN = re.compile(
    r"(?<![\w:])(?:\d{1,3}\.){3}\d{1,3}(?![\w:])|"
    r"(?<![\w:])(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{1,4}(?![\w:])"
)
_SENSITIVE_KEY_PARTS = (
    "raw_line",
    "sample_path",
    "database_url",
    "client_secret",
    "api_key",
    "password",
    "token",
)


@dataclass(frozen=True, slots=True)
class _Partition:
    label: str
    path: Path
    row_count: int


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


def _marker_for_path(path: Path | None) -> tuple[int, int] | None:
    if path is None or not path.exists():
        return None
    stat = path.stat()
    return int(stat.st_size), int(stat.st_mtime_ns)


@contextmanager
def _runtime_settings(
    staging_root: Path,
    *,
    chunk_size: int,
    input_max_bytes: int,
    storage_id: str,
) -> Iterator[None]:
    input_limit = max(8 * 1024 * 1024, int(input_max_bytes))
    values = {
        "OPERATION_STAGING_ROOT": str(staging_root.resolve()),
        "OPERATION_STAGING_MIN_FREE_BYTES": "0",
        "OPERATION_STAGING_MAX_TOTAL_BYTES": str(max(input_limit * 2, 64 * 1024 * 1024)),
        "OPERATION_JOB_MAX_INPUT_BYTES": str(input_limit),
        "OPERATION_STAGING_STORAGE_ID": storage_id,
        "INGESTION_CHUNK_SIZE": str(chunk_size),
        "INGESTION_PROGRESS_UPDATE_INTERVAL": str(chunk_size),
        "OPERATION_WORKER_LEASE_SECONDS": "1800",
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


def _prepare_partitions(
    evidence_path: Path,
    root: Path,
    *,
    rows: int,
    cancellation_rows: int,
) -> tuple[list[_Partition], Path]:
    first_rows = rows // 2
    second_rows = rows - first_rows
    first_path = root / "simulated-window-a.log"
    second_path = root / "simulated-window-b.log"
    cancellation_path = root / "cancellation-probe.log"
    observed = 0
    cancellation_written = 0

    with (
        evidence_path.open("rb") as source,
        first_path.open("wb") as first,
        second_path.open("wb") as second,
        cancellation_path.open("wb") as cancellation,
    ):
        for line in source:
            if not line.strip():
                continue
            if observed >= rows:
                break
            if observed < first_rows:
                first.write(line)
            else:
                second.write(line)
            if cancellation_written < cancellation_rows:
                cancellation.write(line)
                cancellation_written += 1
            observed += 1

    if observed != rows:
        raise ValueError("Private evidence ended before the requested bounded acceptance rows were prepared.")
    if cancellation_written < min(cancellation_rows, rows):
        raise ValueError("Cancellation probe could not prepare enough bounded rows.")
    return (
        [
            _Partition("simulated-logical-window-a", first_path, first_rows),
            _Partition("simulated-logical-window-b", second_path, second_rows),
        ],
        cancellation_path,
    )


def _stage_partition(partition: _Partition) -> StagedInputMetadata:
    with partition.path.open("rb") as stream:
        staged = stage_upload_for_job(
            stream,
            filename=f"{partition.label}.log",
            max_bytes=max(partition.path.stat().st_size + 1024, 8 * 1024 * 1024),
        )
    partition.path.unlink(missing_ok=True)
    return staged


def _enqueue_import(
    db: Session,
    *,
    staged: StagedInputMetadata,
    source_id: int,
    rows: int,
    idempotency_key: str,
    label: str,
) -> tuple[OperationJob, bool]:
    payload = {
        **staged_payload_fields(staged),
        "input_name": f"{label}.log",
        "input_bytes": staged.byte_count,
        "input_fingerprint": staged.fingerprint,
        "available_lines": staged.available_lines,
        "source_type": "sample",
        "parser_profile": "palo_alto",
        "limit": rows,
        "source_id": source_id,
    }
    return enqueue_job(
        db,
        job_type="import_logs",
        requested_by=_ACTOR,
        payload=payload,
        details={
            "input_name": f"{label}.log",
            "available_lines": staged.available_lines,
            "parser_profile": "palo_alto",
            "logical_source_kind": "simulated_partition_of_one_private_device_stream",
            "validation_scope": "disposable_temp_database",
        },
        idempotency_key=idempotency_key,
        progress_total=rows,
        input_size_bytes=staged.byte_count,
        input_fingerprint=staged.fingerprint,
        resume_expires_at=datetime.now(timezone.utc) + timedelta(hours=2),
        staging_storage_id=staged.storage_id,
    )


def _run_import(
    db: Session,
    *,
    job: OperationJob,
    staged: StagedInputMetadata,
    label: str,
    chunk_size: int,
    simulate_interruption: bool,
    resume: bool,
) -> dict[str, Any]:
    progress = [0]
    interruption_seconds = None
    resume_completion_seconds = None
    interruption_released = False

    if simulate_interruption:
        interruption_started = time.perf_counter()
        first = run_worker_once(
            db,
            worker_id=f"v514-{label}-interrupt",
            stop_event=_StopAfterFirstCommittedChunk(),
        )
        interruption_seconds = time.perf_counter() - interruption_started
        db.expire_all()
        interrupted = db.get(OperationJob, job.id)
        if interrupted is None:
            raise RuntimeError("Disposable acceptance job disappeared after interruption.")
        progress.append(int(interrupted.progress_current or 0))
        interruption_released = bool(
            first.get("shutdown_requested")
            and interrupted.status == "queued"
            and interrupted.checkpoint_line > 0
            and staged.path.exists()
        )
        if not resume:
            return {
                "completed": False,
                "status": interrupted.status,
                "rows": int(interrupted.progress_current or 0),
                "progress_samples": progress,
                "progress_monotonic": progress == sorted(progress),
                "interruption_released_at_checkpoint": interruption_released,
                "interruption_seconds": round(interruption_seconds, 4),
                "resume_completion_seconds": None,
                "chunk_commits": int(interrupted.chunk_commits or 0),
                "bounded_chunks": int(interrupted.progress_current or 0) <= chunk_size,
                "staged_input_retained": staged.path.exists(),
            }
        resume_started = time.perf_counter()
        second = run_worker_once(db, worker_id=f"v514-{label}-resume")
        resume_completion_seconds = time.perf_counter() - resume_started
        if not second.get("ok"):
            raise RuntimeError("Disposable acceptance job failed during resume.")
    else:
        result = run_worker_once(db, worker_id=f"v514-{label}-worker")
        if not result.get("ok"):
            raise RuntimeError("Disposable acceptance job failed.")

    db.expire_all()
    completed = db.get(OperationJob, job.id)
    if completed is None:
        raise RuntimeError("Disposable acceptance job disappeared after processing.")
    progress.append(int(completed.progress_current or 0))
    expected_chunks = math.ceil(max(1, completed.progress_total) / chunk_size)
    return {
        "completed": completed.status == "completed",
        "status": completed.status,
        "rows": int(completed.progress_current or 0),
        "checkpoint_line": int(completed.checkpoint_line or 0),
        "checkpoint_bytes_recorded": int(completed.checkpoint_bytes or 0) > 0,
        "progress_samples": progress,
        "progress_monotonic": progress == sorted(progress),
        "interruption_released_at_checkpoint": interruption_released if simulate_interruption else None,
        "interruption_seconds": round(interruption_seconds, 4) if interruption_seconds is not None else None,
        "resume_completion_seconds": (
            round(resume_completion_seconds, 4) if resume_completion_seconds is not None else None
        ),
        "chunk_commits": int(completed.chunk_commits or 0),
        "expected_chunk_commits": expected_chunks,
        "bounded_chunks": int(completed.chunk_commits or 0) == expected_chunks,
        "staged_input_cleaned": not staged.path.exists(),
    }


def _cancellation_probe(
    source_path: Path,
    root: Path,
    *,
    chunk_size: int,
) -> dict[str, Any]:
    database_path = root / "cancellation.sqlite3"
    staging_root = root / "cancellation-staging"
    engine = create_engine(
        f"sqlite:///{database_path}",
        connect_args={"check_same_thread": False, "timeout": 30.0},
        future=True,
    )
    staged: StagedInputMetadata | None = None
    try:
        Base.metadata.create_all(engine)
        input_bytes = max(source_path.stat().st_size + 1024, 8 * 1024 * 1024)
        with _runtime_settings(
            staging_root,
            chunk_size=chunk_size,
            input_max_bytes=input_bytes,
            storage_id="v514-cancel",
        ):
            with source_path.open("rb") as stream:
                staged = stage_upload_for_job(
                    stream,
                    filename="simulated-cancellation-probe.log",
                    max_bytes=input_bytes,
                )
            source_path.unlink(missing_ok=True)
            with Session(engine) as db:
                source = create_source(
                    db,
                    name="v514-simulated-cancellation-source",
                    source_type="sample",
                    parser_profile="palo_alto",
                )
                job, _ = _enqueue_import(
                    db,
                    staged=staged,
                    source_id=source.id,
                    rows=staged.available_lines,
                    idempotency_key="v514-cancellation-probe",
                    label="simulated-cancellation-probe",
                )
                claimed = claim_next_job(
                    db,
                    worker_id="v514-cancel-worker",
                    lease_seconds=120,
                    staging_storage_id=staged.storage_id,
                )
                if claimed is None or claimed.id != job.id or not claimed.lease_token:
                    raise RuntimeError("Cancellation probe could not claim its disposable job.")

                requested_at = 0.0

                def request_after_first_chunk(chunk_commits: int, running_job: OperationJob) -> None:
                    nonlocal requested_at
                    if chunk_commits == 1:
                        requested_at = time.perf_counter()
                        request_job_cancellation(db, running_job, actor=_ACTOR)

                cancelled_at = 0.0
                try:
                    run_resumable_import(
                        db,
                        job_id=claimed.id,
                        worker_id="v514-cancel-worker",
                        lease_token=str(claimed.lease_token),
                        payload=dict(claimed.payload_json or {}),
                        actor=_ACTOR,
                        after_chunk=request_after_first_chunk,
                    )
                except CooperativeImportCancelled:
                    cancelled_at = time.perf_counter()

                db.expire_all()
                persisted = db.get(OperationJob, job.id)
                raw_count = int(db.scalar(select(func.count(RawLog.id))) or 0)
                response_count = int(db.scalar(select(func.count(ResponseAction.id))) or 0)
                eligible, _reason = resume_eligibility(persisted) if persisted is not None else (False, None)
                ok = bool(
                    persisted is not None
                    and persisted.status == "cancelled"
                    and raw_count == min(chunk_size, staged.available_lines)
                    and eligible
                    and response_count == 0
                    and staged.path.exists()
                )
                return {
                    "ok": ok,
                    "status": persisted.status if persisted is not None else "missing",
                    "committed_rows": raw_count,
                    "cancelled_at_committed_boundary": raw_count == min(chunk_size, staged.available_lines),
                    "resume_eligible": eligible,
                    "staged_input_retained": staged.path.exists(),
                    "cancellation_latency_seconds": (
                        round(cancelled_at - requested_at, 4)
                        if requested_at and cancelled_at >= requested_at
                        else None
                    ),
                    "response_actions_created": response_count,
                }
    finally:
        if staged is not None:
            staged.path.unlink(missing_ok=True)
        source_path.unlink(missing_ok=True)
        engine.dispose()


def _sqlite_lock_probe(engine: Engine, *, source_id: int) -> dict[str, Any]:
    completed = Event()
    error_types: list[str] = []
    started = time.perf_counter()
    locker = engine.raw_connection()
    try:
        cursor = locker.cursor()
        cursor.execute("BEGIN IMMEDIATE")
        cursor.execute(
            "UPDATE log_sources SET updated_at = updated_at WHERE id = ?",
            (source_id,),
        )

        def waiting_writer() -> None:
            try:
                with engine.begin() as connection:
                    connection.execute(
                        text(
                            "UPDATE log_sources SET updated_at = updated_at "
                            "WHERE id = :source_id"
                        ),
                        {"source_id": source_id},
                    )
            except Exception as exc:  # pragma: no cover - only error type is reported
                error_types.append(exc.__class__.__name__)
            finally:
                completed.set()

        thread = Thread(target=waiting_writer, name="v514-sqlite-lock-probe", daemon=True)
        thread.start()
        time.sleep(0.2)
        locker.commit()
        thread.join(timeout=5)
        latency = time.perf_counter() - started
        return {
            "ok": completed.is_set() and not error_types,
            "lock_wait_observed": latency >= 0.18,
            "writer_completed_after_release": completed.is_set(),
            "error_type": error_types[0] if error_types else None,
            "latency_seconds": round(latency, 4),
            "configured_database_touched": False,
        }
    finally:
        try:
            locker.rollback()
        except Exception:
            pass
        locker.close()


def _source_summary(db: Session, source_id: int) -> dict[str, Any]:
    source = db.get(LogSource, source_id)
    if source is None:
        raise RuntimeError("Disposable simulated source disappeared.")
    detail = source_to_dict(source, include_quality=True, db=db)
    quality = detail.get("quality") or {}
    health = source_health(source)
    return {
        "logical_source_kind": "simulated_partition_of_one_private_device_stream",
        "source_type": source.source_type,
        "parser_profile": source.parser_profile,
        "enabled": source.enabled,
        "health_status": health.get("status"),
        "health_reason": health.get("reason"),
        "last_seen_recorded": source.last_seen is not None,
        "logs_received": int(source.logs_received_count or 0),
        "parse_successes": int(source.parse_success_count or 0),
        "parse_failures": int(source.parse_failure_count or 0),
        "parser_quality_state": quality.get("parser_quality_state"),
        "parser_contract_state": quality.get("parser_contract_state"),
        "runtime_parser_errors": int(quality.get("parser_error_count") or 0),
        "structural_warnings": int(quality.get("structural_warning_count") or 0),
        "unresolved_application_count": int(
            quality.get("unresolved_application_count") or 0
        ),
        "ingestion_history_count": len(detail.get("recent_ingestion_runs") or []),
        "detection_history_count": len(detail.get("recent_detection_runs") or []),
        "operational_alert_codes": [
            str(item.get("code"))
            for item in quality.get("operational_alerts") or []
            if item.get("code")
        ],
    }


def _count_rows(db: Session) -> dict[str, int]:
    return {
        "raw_logs": int(db.scalar(select(func.count(RawLog.id))) or 0),
        "normalized_logs": int(db.scalar(select(func.count(NormalizedLog.id))) or 0),
        "alerts": int(db.scalar(select(func.count(Alert.id))) or 0),
        "alert_evidence": int(db.scalar(select(func.count(AlertEvidence.id))) or 0),
        "detection_runs": int(db.scalar(select(func.count(DetectionRun.id))) or 0),
        "response_actions": int(db.scalar(select(func.count(ResponseAction.id))) or 0),
        "labels": int(db.scalar(select(func.count(MLLabel.id))) or 0),
        "model_runs": int(db.scalar(select(func.count(MLModelRun.id))) or 0),
    }


def _detection_summary(
    db: Session,
    *,
    source_ids: list[int],
    source_rows: list[int],
    bounded_memory: bool = False,
    collect_runtime_profile: bool = False,
) -> tuple[dict[str, Any], float]:
    results: list[dict[str, Any]] = []
    runtime_profiles: list[dict[str, Any]] = []
    started = time.perf_counter()
    for source_id, rows in zip(source_ids, source_rows, strict=True):
        runtime_profile: dict[str, Any] | None = (
            {"source_sequence": len(runtime_profiles) + 1}
            if collect_runtime_profile
            else None
        )
        results.append(
            run_detection(
                db,
                limit=rows,
                use_ml=False,
                actor=_ACTOR,
                source_id=source_id,
                source_name="simulated-logical-source",
                source_type="sample",
                bounded_memory=bounded_memory,
                release_session_state=bounded_memory,
                runtime_profile=runtime_profile,
            )
        )
        if runtime_profile is not None:
            runtime_profiles.append(runtime_profile)
    elapsed = time.perf_counter() - started
    evaluated = sum(int(item.get("evaluated") or 0) for item in results)
    created = sum(int(item.get("created_alerts") or 0) for item in results)
    deduplicated = sum(
        int(item.get("deduplicated_alert_updates") or 0) for item in results
    )
    suppressed = sum(
        int(item.get("suppressed_low_groups") or 0)
        + int(item.get("suppressed_by_rules") or 0)
        for item in results
    )
    linked_alerts = int(
        db.scalar(
            select(func.count(func.distinct(AlertEvidence.alert_id)))
            .join(NormalizedLog, NormalizedLog.id == AlertEvidence.normalized_log_id)
            .join(RawLog, RawLog.id == NormalizedLog.raw_log_id)
            .where(RawLog.source_id.in_(source_ids))
        )
        or 0
    )
    source_evidence = int(
        db.scalar(
            select(func.count(AlertEvidence.id))
            .join(
                NormalizedLog,
                NormalizedLog.id == AlertEvidence.normalized_log_id,
            )
            .join(RawLog, RawLog.id == NormalizedLog.raw_log_id)
            .where(RawLog.source_id.in_(source_ids))
        )
        or 0
    )
    case_count = count_alert_cases(
        db,
        active_only=True,
        source_ids=source_ids,
    )
    source_links = int(
        db.scalar(
            select(func.count(func.distinct(RawLog.source_id)))
            .join(NormalizedLog, NormalizedLog.raw_log_id == RawLog.id)
            .join(AlertEvidence, AlertEvidence.normalized_log_id == NormalizedLog.id)
            .where(RawLog.source_id.in_(source_ids))
        )
        or 0
    )
    top_attack_types: Counter[str] = Counter()
    for result in results:
        for item in result.get("top_attack_types") or []:
            name = str(item.get("name") or "unknown")
            top_attack_types[name] += int(item.get("count") or 0)
    return (
        {
            "executed": True,
            "mode": "deterministic_rules_only",
            "rule_detection_authoritative": all(
                bool(item.get("rule_detection_authoritative")) for item in results
            ),
            "ml_advisory_execution": False,
            "supervised_lifecycle_unchanged": True,
            "logs_evaluated": evaluated,
            "alerts_created": created,
            "alerts_deduplicated": deduplicated,
            "alerts_suppressed": suppressed,
            "cases_computed": case_count,
            "alerts_with_source_traceability": linked_alerts,
            "logical_sources_with_alert_evidence": source_links,
            "alert_to_log_traceability": (
                created + deduplicated == 0
                or (linked_alerts > 0 and source_evidence > 0)
            ),
            "top_attack_types": [
                {"name": name, "count": count}
                for name, count in top_attack_types.most_common(20)
            ],
            "response_actions_created": int(
                db.scalar(select(func.count(ResponseAction.id))) or 0
            ),
            "runtime_seconds": round(elapsed, 4),
            "rows_per_second": round(evaluated / elapsed, 2) if elapsed > 0 else None,
            "runtime_profiles": runtime_profiles,
        },
        elapsed,
    )


def _dashboard_timings(
    db: Session,
    *,
    source_id: int,
    include_query_counts: bool = False,
    include_query_plans: bool = False,
) -> dict[str, Any]:
    bind = db.get_bind()
    query_count = 0
    query_records: list[tuple[str, Any]] = []

    def count_query(
        _connection,
        _cursor,
        statement,
        parameters,
        _context,
        _executemany,
    ) -> None:
        nonlocal query_count
        query_count += 1
        if (
            include_query_plans
            and len(query_records) < 100
            and str(statement).lstrip().upper().startswith("SELECT")
        ):
            query_records.append((str(statement), parameters))

    if include_query_counts or include_query_plans:
        event.listen(bind, "before_cursor_execute", count_query)

    def timed(operation) -> tuple[float, int]:
        nonlocal query_count
        before = query_count
        started = time.perf_counter()
        operation()
        return time.perf_counter() - started, query_count - before

    try:
        clear_dashboard_summary_cache()
        overview_cold, overview_cold_queries = timed(
            lambda: build_dashboard_summary(db)
        )

        clear_dashboard_summary_cache()
        build_dashboard_summary_cached(db)
        overview_cached, overview_cached_queries = timed(
            lambda: build_dashboard_summary_cached(db)
        )

        alert_list, alert_list_queries = timed(
            lambda: list_alerts(db, source_id=source_id, limit=20)
        )
        case_summary, case_summary_queries = timed(
            lambda: list_alert_cases(db, source_id=source_id, limit=20)
        )
        source_detail, source_detail_queries = timed(
            lambda: _source_summary(db, source_id)
        )
    finally:
        if include_query_counts or include_query_plans:
            event.remove(bind, "before_cursor_execute", count_query)

    result: dict[str, float | int] = {
        "overview_cold_seconds": round(overview_cold, 4),
        "overview_cached_seconds": round(overview_cached, 4),
        "alert_list_seconds": round(alert_list, 4),
        "case_summary_seconds": round(case_summary, 4),
        "source_detail_seconds": round(source_detail, 4),
    }
    if include_query_counts:
        result.update(
            {
                "overview_cold_query_count": overview_cold_queries,
                "overview_cached_query_count": overview_cached_queries,
                "alert_list_query_count": alert_list_queries,
                "case_summary_query_count": case_summary_queries,
                "source_detail_query_count": source_detail_queries,
            }
        )
    if include_query_plans:
        plans: list[list[str]] = []
        if bind.dialect.name == "sqlite":
            seen_statements: set[str] = set()
            for statement, parameters in query_records:
                if statement in seen_statements:
                    continue
                seen_statements.add(statement)
                try:
                    rows = db.connection().exec_driver_sql(
                        f"EXPLAIN QUERY PLAN {statement}",
                        parameters,
                    ).all()
                except Exception:
                    continue
                plans.append([str(row[3]) for row in rows])
        flattened = [step for plan in plans for step in plan]
        result["query_plan_summary"] = {
            "dialect": bind.dialect.name,
            "unique_select_plans": len(plans),
            "full_scan_steps": sum(
                1
                for step in flattened
                if "SCAN " in step.upper()
                and "USING INDEX" not in step.upper()
                and "USING COVERING INDEX" not in step.upper()
            ),
            "temporary_btree_steps": sum(
                1 for step in flattened if "TEMP B-TREE" in step.upper()
            ),
            "plan_steps": sorted(set(flattened)),
            "sql_text_returned": False,
            "query_parameters_returned": False,
        }
    return result


def _safe_preflight_summary(result: dict[str, Any], *, runtime_seconds: float) -> dict[str, Any]:
    parser = result.get("parser") or {}
    duplicates = result.get("duplicates") or {}
    quality = result.get("field_quality") or {}
    safe_aggregates = result.get("safe_aggregates") or {}
    overlap = result.get("current_database_overlap") or {}
    return {
        "status": result.get("status"),
        "file_readable": bool(result.get("file_readable")),
        "file_size_bytes": int(result.get("file_size_bytes") or 0),
        "physical_lines_observed": int(result.get("physical_lines_observed") or 0),
        "nonblank_lines": int(result.get("nonblank_lines") or 0),
        "blank_lines": int(result.get("blank_lines") or 0),
        "format": result.get("format"),
        "time_range": result.get("time_range"),
        "log_types": result.get("log_types") or [],
        "subtypes": result.get("subtypes") or [],
        "schema_variants": result.get("schema_variants") or [],
        "parser_errors": int(parser.get("errors") or 0),
        "parser_error_rate_percent": float(
            parser.get("error_rate_percent") or 0.0
        ),
        "structural_warnings": parser.get("warnings") or [],
        "exact_duplicate_rows": int(duplicates.get("exact_duplicate_rows") or 0),
        "duplicate_rate_percent": float(
            duplicates.get("duplicate_rate_percent") or 0.0
        ),
        "unknown_application_count": int(quality.get("unknown_app_count") or 0),
        "unknown_application_rate_percent": float(
            quality.get("unknown_app_rate_percent") or 0.0
        ),
        "unique_physical_device_count": int(
            safe_aggregates.get("unique_device_name_count") or 0
        ),
        "unique_serial_count": int(safe_aggregates.get("unique_serial_count") or 0),
        "configured_database_overlap": {
            "status": overlap.get("status"),
            "file_rows_matched_by_multiplicity": int(
                overlap.get("file_rows_matched_by_multiplicity") or 0
            ),
            "file_row_overlap_percent": float(
                overlap.get("file_row_overlap_percent") or 0.0
            ),
            "read_only": bool(overlap.get("read_only")),
        },
        "runtime_seconds": round(runtime_seconds, 4),
        "rows_per_second": (
            round(int(result.get("nonblank_lines") or 0) / runtime_seconds, 2)
            if runtime_seconds > 0
            else None
        ),
        "path_returned": False,
        "raw_evidence_returned": False,
        "private_identifiers_returned": False,
        "fingerprints_returned": False,
        "secrets_exposed": False,
    }


def _privacy_findings(value: Any, *, private_path: Path) -> list[str]:
    findings: list[str] = []
    private_values = {
        str(private_path),
        str(private_path.resolve()),
        private_path.name,
    }

    def walk(current: Any, trail: str) -> None:
        if isinstance(current, dict):
            for key, item in current.items():
                lowered = str(key).lower()
                if any(part in lowered for part in _SENSITIVE_KEY_PARTS):
                    if item not in {False, None, "", 0}:
                        findings.append(f"sensitive_key:{trail}.{key}")
                walk(item, f"{trail}.{key}")
            return
        if isinstance(current, list):
            for index, item in enumerate(current):
                walk(item, f"{trail}[{index}]")
            return
        if not isinstance(current, str):
            return
        lowered = current.lower()
        if any(private.lower() in lowered for private in private_values if private):
            findings.append(f"private_path:{trail}")
        if _IP_PATTERN.search(current):
            findings.append(f"ip_address:{trail}")

    walk(value, "result")
    return sorted(set(findings))


def run_v514_large_file_runtime_acceptance(
    *,
    sample_path: str | Path,
    limit: int | None = _DEFAULT_LIMIT,
    chunk_size: int = 1_000,
    use_temp_db: bool = False,
    simulate_interruption: bool = False,
    resume: bool = False,
    run_detection_after: bool = False,
    preflight_only: bool = False,
) -> dict[str, Any]:
    evidence_path = Path(sample_path).expanduser()
    if not evidence_path.exists() or not evidence_path.is_file():
        return {
            "ok": False,
            "status": "private_evidence_unavailable",
            "path_returned": False,
            "configured_database_modified": False,
            "secrets_exposed": False,
        }
    if chunk_size < 1 or chunk_size > 100_000:
        return {
            "ok": False,
            "status": "invalid_chunk_size",
            "allowed_range": [1, 100_000],
            "path_returned": False,
            "configured_database_modified": False,
            "secrets_exposed": False,
        }
    if limit is not None and (limit < _MIN_ROWS or limit > _MAX_LIMIT):
        return {
            "ok": False,
            "status": "invalid_limit",
            "allowed_range": [_MIN_ROWS, _MAX_LIMIT],
            "path_returned": False,
            "configured_database_modified": False,
            "secrets_exposed": False,
        }
    if resume and not simulate_interruption:
        return {
            "ok": False,
            "status": "resume_requires_simulated_interruption",
            "path_returned": False,
            "configured_database_modified": False,
            "secrets_exposed": False,
        }

    original_settings = get_settings()
    configured_path, marker_before = _configured_sqlite_marker()
    preflight_started = time.perf_counter()
    preflight = preflight_private_paloalto_file(
        evidence_path,
        current_database_url=original_settings.database_url,
    )
    preflight_seconds = time.perf_counter() - preflight_started
    preflight_summary = _safe_preflight_summary(
        preflight,
        runtime_seconds=preflight_seconds,
    )
    if not preflight.get("ok"):
        return {
            "ok": False,
            "status": "preflight_failed",
            "preflight": preflight_summary,
            "path_returned": False,
            "configured_database_modified": False,
            "secrets_exposed": False,
        }
    if preflight_only:
        result = {
            "ok": True,
            "status": "preflight_complete",
            "scope": "aggregate_read_only_private_evidence_preflight",
            "preflight": preflight_summary,
            "configured_database_modified": False,
            "response_automation_allowed": False,
            "real_firewall_blocking_enabled": False,
            "model_activation_performed": False,
            "production_ready": False,
            "path_returned": False,
            "raw_evidence_returned": False,
            "private_identifiers_returned": False,
            "secrets_exposed": False,
        }
        result["privacy_findings"] = _privacy_findings(
            result,
            private_path=evidence_path,
        )
        result["ok"] = not result["privacy_findings"]
        return result
    if not use_temp_db:
        return {
            "ok": False,
            "status": "explicit_temp_database_required",
            "message": "Re-run with --use-temp-db; configured databases are never runtime-acceptance targets.",
            "preflight": preflight_summary,
            "path_returned": False,
            "configured_database_modified": False,
            "secrets_exposed": False,
        }

    available_rows = int(preflight.get("nonblank_lines") or 0)
    requested_rows = available_rows if limit is None else min(limit, available_rows)
    if requested_rows < _MIN_ROWS:
        return {
            "ok": False,
            "status": "insufficient_evidence_rows",
            "available_rows": available_rows,
            "path_returned": False,
            "configured_database_modified": False,
            "secrets_exposed": False,
        }

    run_token = uuid4().hex[:12]
    total_started = time.perf_counter()
    engine: Engine | None = None
    result: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix=f"atdr-v514-{run_token}-") as temporary:
        root = Path(temporary)
        database_path = root / "runtime-acceptance.sqlite3"
        staging_root = root / "staging"
        cancellation_rows = min(requested_rows, max(chunk_size * 2, _MIN_ROWS))
        partitions, cancellation_path = _prepare_partitions(
            evidence_path,
            root,
            rows=requested_rows,
            cancellation_rows=cancellation_rows,
        )
        input_max_bytes = max(
            sum(partition.path.stat().st_size for partition in partitions)
            + 32 * 1024 * 1024,
            64 * 1024 * 1024,
        )
        engine = create_engine(
            f"sqlite:///{database_path}",
            connect_args={"check_same_thread": False, "timeout": 30.0},
            future=True,
        )
        try:
            Base.metadata.create_all(engine)
            baseline_db_size = database_path.stat().st_size if database_path.exists() else 0
            with _runtime_settings(
                staging_root,
                chunk_size=chunk_size,
                input_max_bytes=input_max_bytes,
                storage_id="v514-main",
            ):
                staged_partitions = [
                    (partition, _stage_partition(partition))
                    for partition in partitions
                ]
                tracemalloc.start()
                ingestion_started = time.perf_counter()
                source_ids: list[int] = []
                import_summaries: list[dict[str, Any]] = []
                idempotency_reused = True
                with Session(engine) as db:
                    for index, (partition, staged) in enumerate(staged_partitions):
                        source = create_source(
                            db,
                            name=f"v514-{partition.label}",
                            source_type="sample",
                            parser_profile="palo_alto",
                        )
                        source_ids.append(source.id)
                        idempotency_key = f"v514-{run_token}-{index}"
                        job, reused = _enqueue_import(
                            db,
                            staged=staged,
                            source_id=source.id,
                            rows=partition.row_count,
                            idempotency_key=idempotency_key,
                            label=partition.label,
                        )
                        if reused:
                            raise RuntimeError("First disposable acceptance enqueue unexpectedly reused a job.")
                        duplicate_job, duplicate_reused = _enqueue_import(
                            db,
                            staged=staged,
                            source_id=source.id,
                            rows=partition.row_count,
                            idempotency_key=idempotency_key,
                            label=partition.label,
                        )
                        idempotency_reused = bool(
                            idempotency_reused
                            and duplicate_reused
                            and duplicate_job.id == job.id
                        )
                        summary = _run_import(
                            db,
                            job=job,
                            staged=staged,
                            label=f"source-{index + 1}",
                            chunk_size=chunk_size,
                            simulate_interruption=simulate_interruption and index == 0,
                            resume=resume,
                        )
                        summary["logical_source"] = f"simulated-logical-source-{index + 1}"
                        summary["rows_requested"] = partition.row_count
                        import_summaries.append(summary)
                        if not summary["completed"]:
                            break

                    ingestion_seconds = time.perf_counter() - ingestion_started
                    _current_memory, peak_memory = tracemalloc.get_traced_memory()
                    tracemalloc.stop()
                    counts_after_ingestion = _count_rows(db)
                    ingestion_runs = list(db.scalars(select(IngestionRun).order_by(IngestionRun.id)))
                    source_summaries = [
                        _source_summary(db, source_id) for source_id in source_ids
                    ]

                database_size_after_ingestion = (
                    database_path.stat().st_size if database_path.exists() else 0
                )
                lock_probe = _sqlite_lock_probe(engine, source_id=source_ids[0])
                cancellation = _cancellation_probe(
                    cancellation_path,
                    root,
                    chunk_size=min(chunk_size, cancellation_rows),
                )

                detection_summary: dict[str, Any] = {
                    "executed": False,
                    "mode": "not_requested",
                    "rule_detection_authoritative": True,
                    "ml_advisory_execution": False,
                    "supervised_lifecycle_unchanged": True,
                    "response_actions_created": 0,
                }
                dashboard_timings: dict[str, float] = {}
                with Session(engine) as db:
                    if run_detection_after and all(
                        summary["completed"] for summary in import_summaries
                    ):
                        detection_summary, _detection_seconds = _detection_summary(
                            db,
                            source_ids=source_ids,
                            source_rows=[
                                partition.row_count for partition in partitions
                            ],
                        )
                    counts_final = _count_rows(db)
                    if all(summary["completed"] for summary in import_summaries):
                        dashboard_timings = _dashboard_timings(
                            db,
                            source_id=source_ids[0],
                        )
                    source_summaries = [
                        _source_summary(db, source_id) for source_id in source_ids
                    ]

                database_size_final = (
                    database_path.stat().st_size if database_path.exists() else 0
                )
                completed_rows = counts_after_ingestion["raw_logs"]
                duplicate_counts = sum(
                    int(run.duplicate_raw_logs or 0) for run in ingestion_runs
                )
                all_completed = (
                    len(import_summaries) == len(partitions)
                    and all(summary["completed"] for summary in import_summaries)
                )
                import_checks = {
                    "all_jobs_completed": all_completed,
                    "progress_monotonic": all(
                        bool(summary["progress_monotonic"])
                        for summary in import_summaries
                    ),
                    "bounded_chunks": all(
                        bool(summary["bounded_chunks"])
                        for summary in import_summaries
                    ),
                    "idempotent_enqueue_reused_existing_job": idempotency_reused,
                    "no_extra_rows_after_resume": completed_rows
                    == sum(
                        int(summary["rows"])
                        for summary in import_summaries
                    ),
                    "raw_normalized_counts_match": counts_after_ingestion["raw_logs"]
                    == counts_after_ingestion["normalized_logs"],
                    "source_counts_match": sum(
                        int(source["logs_received"]) for source in source_summaries
                    )
                    == completed_rows,
                    "staging_cleaned_after_completion": all(
                        bool(summary.get("staged_input_cleaned"))
                        for summary in import_summaries
                        if summary["completed"]
                    ),
                }
                unsafe_side_effects = {
                    "response_actions": counts_final["response_actions"],
                    "labels": counts_final["labels"],
                    "model_runs": counts_final["model_runs"],
                }
                result = {
                    "ok": False,
                    "status": "runtime_acceptance_pending_checks",
                    "scope": "private_evidence_disposable_sqlite",
                    "preflight": preflight_summary,
                    "runtime_evidence": {
                        "rows_requested": requested_rows,
                        "rows_processed": completed_rows,
                        "logical_source_count": len(source_summaries),
                        "physical_device_count_claimed": 0,
                        "observed_private_device_identity_count": int(
                            preflight_summary.get("unique_physical_device_count")
                            or 0
                        ),
                        "logical_sources_are_simulated": True,
                    },
                    "ingestion": {
                        "imports": import_summaries,
                        "checks": import_checks,
                        "raw_logs": counts_after_ingestion["raw_logs"],
                        "normalized_logs": counts_after_ingestion["normalized_logs"],
                        "parsed_successfully": sum(
                            int(run.parsed_successfully or 0)
                            for run in ingestion_runs
                        ),
                        "parse_failures": sum(
                            int(run.parse_failures or 0) for run in ingestion_runs
                        ),
                        "exact_duplicates_observed_and_preserved": duplicate_counts,
                        "duplicate_policy": (
                            "Exact repeats are counted and preserved as raw evidence; "
                            "checkpoint resume creates no extra committed rows."
                        ),
                        "runtime_seconds": round(ingestion_seconds, 4),
                        "rows_per_second": (
                            round(completed_rows / ingestion_seconds, 2)
                            if ingestion_seconds > 0
                            else None
                        ),
                        "peak_python_memory_mb": round(
                            peak_memory / (1024 * 1024),
                            2,
                        ),
                    },
                    "cancellation": cancellation,
                    "database_lock_handling": lock_probe,
                    "sources": source_summaries,
                    "detection": detection_summary,
                    "performance": {
                        "preflight_parse_rows_per_second": preflight_summary.get(
                            "rows_per_second"
                        ),
                        "ingestion_rows_per_second": (
                            round(completed_rows / ingestion_seconds, 2)
                            if ingestion_seconds > 0
                            else None
                        ),
                        "detection_rows_per_second": detection_summary.get(
                            "rows_per_second"
                        ),
                        "peak_python_memory_mb": round(
                            peak_memory / (1024 * 1024),
                            2,
                        ),
                        "database_initial_bytes": baseline_db_size,
                        "database_after_ingestion_bytes": database_size_after_ingestion,
                        "database_final_bytes": database_size_final,
                        "database_growth_bytes": max(
                            0,
                            database_size_final - baseline_db_size,
                        ),
                        "dashboard_query_timings": dashboard_timings,
                    },
                    "safety": {
                        "configured_database_targeted": False,
                        "configured_database_modified": False,
                        "private_path_returned": False,
                        "raw_evidence_returned": False,
                        "private_identifiers_returned": False,
                        "fingerprints_returned": False,
                        "secrets_exposed": False,
                        "rules_alert_authoritative": True,
                        "ml_advisory_only": True,
                        "model_activation_performed": False,
                        "model_promotion_performed": False,
                        "response_automation_allowed": False,
                        "real_firewall_blocking_enabled": False,
                        "unsafe_side_effect_counts": unsafe_side_effects,
                    },
                    "production_ready": False,
                }
        except Exception as exc:
            if tracemalloc.is_tracing():
                tracemalloc.stop()
            result = {
                "ok": False,
                "status": "runtime_acceptance_error",
                "error_type": exc.__class__.__name__,
                "preflight": preflight_summary,
                "configured_database_modified": False,
                "path_returned": False,
                "raw_evidence_returned": False,
                "private_identifiers_returned": False,
                "secrets_exposed": False,
                "response_automation_allowed": False,
                "model_activation_performed": False,
                "production_ready": False,
            }
        finally:
            if engine is not None:
                engine.dispose()
            clear_dashboard_summary_cache()
            get_settings.cache_clear()

    marker_after = _marker_for_path(configured_path)
    configured_unchanged = marker_before == marker_after
    safety = result.setdefault("safety", {})
    safety["configured_database_marker_checked"] = configured_path is not None
    safety["configured_database_unchanged"] = configured_unchanged
    safety["configured_database_modified"] = not configured_unchanged
    result["configured_database_modified"] = not configured_unchanged
    result["total_runtime_seconds"] = round(time.perf_counter() - total_started, 4)
    privacy_findings = _privacy_findings(result, private_path=evidence_path)
    result["privacy_findings"] = privacy_findings

    if result.get("status") != "runtime_acceptance_error":
        ingestion_checks = (result.get("ingestion") or {}).get("checks") or {}
        unsafe_counts = (
            ((result.get("safety") or {}).get("unsafe_side_effect_counts")) or {}
        )
        detection_ok = (
            not run_detection_after
            or bool((result.get("detection") or {}).get("executed"))
            and bool(
                (result.get("detection") or {}).get(
                    "rule_detection_authoritative"
                )
            )
            and int(
                (result.get("detection") or {}).get(
                    "response_actions_created"
                )
                or 0
            )
            == 0
        )
        passed = all(
            (
                all(bool(value) for value in ingestion_checks.values()),
                bool((result.get("cancellation") or {}).get("ok")),
                bool((result.get("database_lock_handling") or {}).get("ok")),
                detection_ok,
                all(int(value or 0) == 0 for value in unsafe_counts.values()),
                configured_unchanged,
                not privacy_findings,
            )
        )
        result["ok"] = passed
        result["status"] = (
            "large_file_runtime_acceptance_passed"
            if passed
            else "large_file_runtime_acceptance_failed"
        )
    return result
