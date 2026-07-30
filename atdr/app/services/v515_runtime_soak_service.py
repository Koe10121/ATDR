from __future__ import annotations

from collections import Counter
from contextlib import suppress
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import math
import os
from pathlib import Path
import shutil
import tempfile
import time
import tracemalloc
from typing import Any
from unittest.mock import patch
from uuid import uuid4

from sqlalchemy import Engine, create_engine, func, select, text
from sqlalchemy.orm import Session

from atdr.app.core.config import get_settings
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
from atdr.app.services.case_service import list_alert_cases
from atdr.app.services.job_service import (
    build_result_summary,
    claim_next_job,
    complete_queued_job,
    recover_expired_leases,
    request_job_cancellation,
    resume_eligibility,
    resume_import_job,
)
from atdr.app.services.private_log_preflight_service import (
    preflight_private_paloalto_file,
)
from atdr.app.services.resumable_ingestion_service import (
    CooperativeImportCancelled,
    CooperativeWorkerShutdown,
    run_resumable_import,
)
from atdr.app.services.source_service import create_source
from atdr.app.services.staging_service import (
    StagedInputMetadata,
    cleanup_staged_payload,
    stage_upload_for_job,
)
from atdr.app.services.v514_large_file_runtime_service import (
    _configured_sqlite_marker,
    _count_rows,
    _dashboard_timings,
    _detection_summary,
    _enqueue_import,
    _marker_for_path,
    _privacy_findings,
    _runtime_settings,
    _safe_preflight_summary,
    _source_summary,
    _sqlite_lock_probe,
)


_ACTOR = "v515-runtime-soak"
_MIN_ROWS = 4
_MAX_CHUNK_SIZE = 100_000
_STAGE_A_ROWS = 250_000
_STAGE_B_ROWS = 500_000
_V514_DB_BYTES_PER_ROW = 6_108.40576
_STORAGE_HEADROOM_MULTIPLIER = 3
_FAULT_PLANS = {
    "none",
    "worker_handoff",
    "repeated_interruption",
    "cancellation_resume",
    "stale_lease_recovery",
    "sqlite_lock_wait",
    "combined",
}


@dataclass(frozen=True, slots=True)
class _StageSpec:
    label: str
    row_count: int
    prepared_path: Path


class _SimulatedWorkerCrash(RuntimeError):
    """Represents a process loss immediately after a committed chunk."""


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _percentile(values: list[float], percentile: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    position = (len(ordered) - 1) * percentile
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return round(ordered[lower], 6)
    weight = position - lower
    return round(
        ordered[lower] * (1 - weight) + ordered[upper] * weight,
        6,
    )


def _latency_summary(values: list[float]) -> dict[str, float | int | None]:
    return {
        "sample_count": len(values),
        "p50_seconds": _percentile(values, 0.50),
        "p95_seconds": _percentile(values, 0.95),
        "p99_seconds": _percentile(values, 0.99),
        "max_seconds": round(max(values), 6) if values else None,
    }


def _memory_status() -> dict[str, Any]:
    if os.name == "nt":
        try:
            import ctypes

            class _MemoryStatus(ctypes.Structure):
                _fields_ = [
                    ("length", ctypes.c_ulong),
                    ("memory_load", ctypes.c_ulong),
                    ("total_physical", ctypes.c_ulonglong),
                    ("available_physical", ctypes.c_ulonglong),
                    ("total_page_file", ctypes.c_ulonglong),
                    ("available_page_file", ctypes.c_ulonglong),
                    ("total_virtual", ctypes.c_ulonglong),
                    ("available_virtual", ctypes.c_ulonglong),
                    ("available_extended_virtual", ctypes.c_ulonglong),
                ]

            state = _MemoryStatus()
            state.length = ctypes.sizeof(_MemoryStatus)
            if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(state)):
                return {
                    "status": "observed",
                    "physical_total_bytes": int(state.total_physical),
                    "physical_available_bytes": int(state.available_physical),
                    "memory_load_percent": int(state.memory_load),
                    "process_limit_bytes": None,
                }
        except (AttributeError, OSError, ValueError):
            pass
    try:
        import resource

        soft, _hard = resource.getrlimit(resource.RLIMIT_AS)
        process_limit = None if soft in {-1, resource.RLIM_INFINITY} else int(soft)
        return {
            "status": "process_limit_only",
            "physical_total_bytes": None,
            "physical_available_bytes": None,
            "memory_load_percent": None,
            "process_limit_bytes": process_limit,
        }
    except (ImportError, OSError, ValueError):
        return {
            "status": "unavailable",
            "physical_total_bytes": None,
            "physical_available_bytes": None,
            "memory_load_percent": None,
            "process_limit_bytes": None,
        }


def _stage_counts(target_rows: int) -> list[tuple[str, int]]:
    remaining = target_rows
    counts: list[tuple[str, int]] = []
    for label, ceiling in (
        ("stage-a", _STAGE_A_ROWS),
        ("stage-b", _STAGE_B_ROWS - _STAGE_A_ROWS),
    ):
        if remaining <= 0:
            break
        count = min(remaining, ceiling)
        counts.append((label, count))
        remaining -= count
    if remaining > 0:
        counts.append(("stage-c", remaining))
    return counts


def _storage_estimate(
    *,
    file_size_bytes: int,
    available_rows: int,
    target_rows: int,
) -> dict[str, int | float | bool]:
    source_bytes_per_row = (
        file_size_bytes / available_rows if available_rows > 0 else 0.0
    )
    selected_source_bytes = math.ceil(source_bytes_per_row * target_rows)
    prepared_segment_bytes = selected_source_bytes
    staged_input_bytes = selected_source_bytes
    database_growth_bytes = math.ceil(_V514_DB_BYTES_PER_ROW * target_rows)
    sqlite_journal_headroom_bytes = max(
        256 * 1024 * 1024,
        math.ceil(database_growth_bytes * 0.20),
    )
    orchestration_overhead_bytes = 128 * 1024 * 1024
    estimated_temporary_bytes = (
        prepared_segment_bytes
        + staged_input_bytes
        + database_growth_bytes
        + sqlite_journal_headroom_bytes
        + orchestration_overhead_bytes
    )
    required_free_bytes = (
        estimated_temporary_bytes * _STORAGE_HEADROOM_MULTIPLIER
    )
    return {
        "source_bytes_per_row_estimate": round(source_bytes_per_row, 2),
        "prepared_segment_bytes": prepared_segment_bytes,
        "staged_input_bytes": staged_input_bytes,
        "database_growth_bytes": database_growth_bytes,
        "sqlite_journal_headroom_bytes": sqlite_journal_headroom_bytes,
        "orchestration_overhead_bytes": orchestration_overhead_bytes,
        "estimated_temporary_bytes": estimated_temporary_bytes,
        "headroom_multiplier": _STORAGE_HEADROOM_MULTIPLIER,
        "required_free_bytes": required_free_bytes,
    }


def _resource_preflight(
    *,
    evidence_path: Path,
    target_rows: int | None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    settings = get_settings()
    started = time.perf_counter()
    private_preflight = preflight_private_paloalto_file(
        evidence_path,
        current_database_url=settings.database_url,
    )
    private_seconds = time.perf_counter() - started
    safe_private = _safe_preflight_summary(
        private_preflight,
        runtime_seconds=private_seconds,
    )
    available_rows = int(private_preflight.get("nonblank_lines") or 0)
    selected_rows = (
        available_rows
        if target_rows is None
        else min(max(0, int(target_rows)), available_rows)
    )
    estimate = _storage_estimate(
        file_size_bytes=int(private_preflight.get("file_size_bytes") or 0),
        available_rows=available_rows,
        target_rows=selected_rows,
    )
    disk = shutil.disk_usage(evidence_path.parent)
    disk_ok = int(disk.free) >= int(estimate["required_free_bytes"])
    result = {
        "ok": bool(private_preflight.get("ok"))
        and selected_rows >= _MIN_ROWS
        and disk_ok,
        "private_evidence": safe_private,
        "available_rows": available_rows,
        "selected_rows": selected_rows,
        "disk": {
            "free_bytes": int(disk.free),
            "estimated_temporary_bytes": int(
                estimate["estimated_temporary_bytes"]
            ),
            "required_free_bytes": int(estimate["required_free_bytes"]),
            "headroom_multiplier": _STORAGE_HEADROOM_MULTIPLIER,
            "sufficient": disk_ok,
        },
        "storage_estimate": estimate,
        "memory": _memory_status(),
        "configured_database_marker_captured": True,
        "cleanup_categories": [
            "prepared_segments",
            "staged_inputs",
            "disposable_database",
            "sqlite_journals",
        ],
        "path_returned": False,
        "raw_evidence_returned": False,
        "private_identifiers_returned": False,
        "fingerprints_returned": False,
        "secrets_exposed": False,
    }
    return result, private_preflight


def _prepare_stage_files(
    evidence_path: Path,
    root: Path,
    *,
    stage_counts: list[tuple[str, int]],
) -> list[_StageSpec]:
    specs = [
        _StageSpec(
            label=label,
            row_count=count,
            prepared_path=root / f"simulated-{label}.log",
        )
        for label, count in stage_counts
    ]
    handles = [spec.prepared_path.open("wb") for spec in specs]
    stage_index = 0
    stage_written = 0
    total_written = 0
    try:
        with evidence_path.open("rb") as source:
            for line in source:
                if not line.strip():
                    continue
                if stage_index >= len(specs):
                    break
                handles[stage_index].write(line)
                stage_written += 1
                total_written += 1
                if stage_written == specs[stage_index].row_count:
                    stage_index += 1
                    stage_written = 0
    finally:
        for handle in handles:
            handle.close()
    expected = sum(spec.row_count for spec in specs)
    if total_written != expected:
        raise ValueError(
            "Private evidence ended before the selected aggregate row target."
        )
    return specs


def _stage_file(
    spec: _StageSpec,
    *,
    max_bytes: int,
) -> StagedInputMetadata:
    with spec.prepared_path.open("rb") as stream:
        staged = stage_upload_for_job(
            stream,
            filename=f"simulated-{spec.label}.log",
            max_bytes=max_bytes,
        )
    spec.prepared_path.unlink(missing_ok=True)
    return staged


def _progress_sample(job: OperationJob) -> dict[str, int | str]:
    return {
        "status": str(job.status),
        "progress": int(job.progress_current or 0),
        "checkpoint_line": int(job.checkpoint_line or 0),
        "checkpoint_bytes": int(job.checkpoint_bytes or 0),
        "chunk_commits": int(job.chunk_commits or 0),
    }


def _is_monotonic(samples: list[dict[str, Any]], field: str) -> bool:
    values = [int(item.get(field) or 0) for item in samples]
    return values == sorted(values)


def _fault_sequence(fault_plan: str, stage_index: int) -> list[str]:
    if stage_index > 0:
        return ["handoff"] if fault_plan == "combined" else []
    return {
        "none": [],
        "worker_handoff": ["handoff"],
        "repeated_interruption": ["handoff", "handoff", "handoff"],
        "cancellation_resume": ["cancel"],
        "stale_lease_recovery": ["stale"],
        "sqlite_lock_wait": [],
        "combined": [
            "handoff",
            "handoff",
            "handoff",
            "cancel",
            "stale",
        ],
    }[fault_plan]


def _run_stage_import(
    db: Session,
    *,
    job: OperationJob,
    staged: StagedInputMetadata,
    source_id: int,
    fault_sequence: list[str],
    worker_prefix: str,
) -> dict[str, Any]:
    import_started = time.perf_counter()
    current_job = job
    progress_samples: list[dict[str, Any]] = [_progress_sample(job)]
    source_last_seen: list[str] = []
    transitions: list[dict[str, Any]] = []
    chunk_latencies: list[float] = []
    resume_latencies: list[float] = []
    cancellation_latency: float | None = None
    handoffs = 0
    cancellations = 0
    stale_recoveries = 0

    def run_claimed(action: str, sequence: int) -> tuple[str, dict[str, Any] | None]:
        nonlocal cancellation_latency
        claimed = claim_next_job(
            db,
            worker_id=f"{worker_prefix}-{sequence}",
            lease_seconds=1_800,
            staging_storage_id=staged.storage_id,
        )
        if (
            claimed is None
            or claimed.id != current_job.id
            or not claimed.lease_token
        ):
            raise RuntimeError("Disposable soak worker could not claim its exact job.")
        transitions.append(
            {
                "event": "claimed",
                "action": action,
                "status": claimed.status,
                "progress": int(claimed.progress_current or 0),
            }
        )
        boundary_started = time.perf_counter()
        stop_requested = False
        cancel_requested_at: float | None = None

        def after_chunk(_commits: int, running_job: OperationJob) -> None:
            nonlocal boundary_started, stop_requested, cancel_requested_at
            now = time.perf_counter()
            chunk_latencies.append(now - boundary_started)
            boundary_started = now
            progress_samples.append(_progress_sample(running_job))
            source = db.get(LogSource, source_id)
            if source is not None and source.last_seen is not None:
                source_last_seen.append(source.last_seen.isoformat())
            if action == "handoff":
                stop_requested = True
            elif action == "cancel":
                cancel_requested_at = time.perf_counter()
                request_job_cancellation(db, running_job, actor=_ACTOR)
            elif action == "stale":
                raise _SimulatedWorkerCrash(
                    "Simulated process loss after committed checkpoint."
                )

        try:
            imported = run_resumable_import(
                db,
                job_id=claimed.id,
                worker_id=str(claimed.lease_owner),
                lease_token=str(claimed.lease_token),
                payload=dict(claimed.payload_json or {}),
                actor=_ACTOR,
                after_chunk=after_chunk,
                should_stop=lambda: stop_requested,
            )
        except CooperativeWorkerShutdown:
            db.rollback()
            persisted = db.get(OperationJob, claimed.id)
            if persisted is None:
                raise RuntimeError("Released soak job disappeared.")
            progress_samples.append(_progress_sample(persisted))
            transitions.append(
                {
                    "event": "worker_handoff",
                    "status": persisted.status,
                    "progress": int(persisted.progress_current or 0),
                    "staging_retained": staged.path.exists(),
                }
            )
            return "handoff", None
        except CooperativeImportCancelled:
            cancelled_at = time.perf_counter()
            db.rollback()
            persisted = db.get(OperationJob, claimed.id)
            if persisted is None:
                raise RuntimeError("Cancelled soak job disappeared.")
            progress_samples.append(_progress_sample(persisted))
            cancellation_latency = (
                cancelled_at - cancel_requested_at
                if cancel_requested_at is not None
                else None
            )
            transitions.append(
                {
                    "event": "cancelled_at_boundary",
                    "status": persisted.status,
                    "progress": int(persisted.progress_current or 0),
                    "staging_retained": staged.path.exists(),
                }
            )
            return "cancelled", None
        except _SimulatedWorkerCrash:
            db.rollback()
            persisted = db.get(OperationJob, claimed.id)
            if persisted is None:
                raise RuntimeError("Crashed soak job disappeared.")
            progress_samples.append(_progress_sample(persisted))
            transitions.append(
                {
                    "event": "worker_process_lost",
                    "status": persisted.status,
                    "progress": int(persisted.progress_current or 0),
                    "staging_retained": staged.path.exists(),
                }
            )
            return "stale", None

        completed = complete_queued_job(
            db,
            job_id=claimed.id,
            worker_id=str(claimed.lease_owner),
            lease_token=str(claimed.lease_token),
            result_summary=build_result_summary(claimed.job_type, imported),
            related_ingestion_run_id=int(imported["run_id"]),
        )
        cleanup_staged_payload(dict(completed.payload_json or {}))
        progress_samples.append(_progress_sample(completed))
        transitions.append(
            {
                "event": "completed",
                "status": completed.status,
                "progress": int(completed.progress_current or 0),
                "staging_retained": staged.path.exists(),
            }
        )
        return "completed", imported

    for sequence, action in enumerate([*fault_sequence, "complete"], start=1):
        outcome, imported = run_claimed(action, sequence)
        db.expire_all()
        persisted = db.get(OperationJob, current_job.id)
        if persisted is None:
            raise RuntimeError("Disposable soak operation job disappeared.")
        if outcome == "handoff":
            handoffs += 1
            current_job = persisted
            continue
        if outcome == "cancelled":
            cancellations += 1
            eligible, reason = resume_eligibility(persisted)
            if not eligible:
                raise RuntimeError(
                    reason or "Cancelled soak import was not resumable."
                )
            started = time.perf_counter()
            current_job = resume_import_job(
                db,
                persisted,
                requested_by=_ACTOR,
            )
            resume_latencies.append(time.perf_counter() - started)
            transitions.append(
                {
                    "event": "cancelled_job_resumed",
                    "status": current_job.status,
                    "progress": int(current_job.progress_current or 0),
                }
            )
            continue
        if outcome == "stale":
            persisted.lease_expires_at = _utcnow() - timedelta(seconds=1)
            db.add(persisted)
            db.commit()
            recovered = recover_expired_leases(
                db,
                retry_delay_seconds=1,
            )
            if not recovered:
                raise RuntimeError("Expired soak worker lease was not recovered.")
            db.expire_all()
            failed = db.get(OperationJob, persisted.id)
            if failed is None or failed.status != "failed":
                raise RuntimeError("Evidence-mutating stale job did not fail closed.")
            eligible, reason = resume_eligibility(failed)
            if not eligible:
                raise RuntimeError(
                    reason or "Stale soak import was not explicitly resumable."
                )
            started = time.perf_counter()
            current_job = resume_import_job(
                db,
                failed,
                requested_by=_ACTOR,
            )
            resume_latencies.append(time.perf_counter() - started)
            stale_recoveries += 1
            transitions.extend(
                [
                    {
                        "event": "stale_lease_failed_closed",
                        "status": failed.status,
                        "progress": int(failed.progress_current or 0),
                        "staging_retained": staged.path.exists(),
                    },
                    {
                        "event": "stale_job_explicitly_resumed",
                        "status": current_job.status,
                        "progress": int(current_job.progress_current or 0),
                    },
                ]
            )
            continue
        if outcome == "completed":
            current_job = persisted
            return {
                "completed": True,
                "status": current_job.status,
                "rows": int(current_job.progress_current or 0),
                "checkpoint_line": int(current_job.checkpoint_line or 0),
                "checkpoint_bytes_recorded": int(
                    current_job.checkpoint_bytes or 0
                )
                > 0,
                "chunk_commits": int(current_job.chunk_commits or 0),
                "progress_samples": progress_samples,
                "progress_monotonic": _is_monotonic(
                    progress_samples,
                    "progress",
                ),
                "line_checkpoint_monotonic": _is_monotonic(
                    progress_samples,
                    "checkpoint_line",
                ),
                "byte_checkpoint_monotonic": _is_monotonic(
                    progress_samples,
                    "checkpoint_bytes",
                ),
                "source_last_seen_monotonic": source_last_seen
                == sorted(source_last_seen),
                "worker_handoffs": handoffs,
                "cancellations": cancellations,
                "stale_lease_recoveries": stale_recoveries,
                "resume_latencies_seconds": [
                    round(value, 6) for value in resume_latencies
                ],
                "cancellation_latency_seconds": (
                    round(cancellation_latency, 6)
                    if cancellation_latency is not None
                    else None
                ),
                "chunk_latency": _latency_summary(chunk_latencies),
                "_chunk_latency_samples": chunk_latencies,
                "transitions": transitions,
                "staged_input_cleaned": not staged.path.exists(),
                "raw_logs_imported": int((imported or {}).get("raw_logs_imported") or 0),
                "parse_failures": int((imported or {}).get("parse_failures") or 0),
                "runtime_seconds": round(
                    time.perf_counter() - import_started,
                    4,
                ),
                "rows_per_second": round(
                    int(current_job.progress_current or 0)
                    / (time.perf_counter() - import_started),
                    2,
                ),
            }
    raise RuntimeError("Disposable soak import did not reach completion.")


def _integrity_summary(
    db: Session,
    *,
    target_rows: int,
    source_ids: list[int],
) -> dict[str, Any]:
    integrity_value = str(db.scalar(text("PRAGMA integrity_check")) or "")
    foreign_key_rows = list(db.execute(text("PRAGMA foreign_key_check")).all())
    counts = _count_rows(db)
    orphan_normalized = int(
        db.scalar(
            select(func.count(NormalizedLog.id))
            .outerjoin(RawLog, RawLog.id == NormalizedLog.raw_log_id)
            .where(RawLog.id.is_(None))
        )
        or 0
    )
    raw_without_normalized = int(
        db.scalar(
            select(func.count(RawLog.id))
            .outerjoin(
                NormalizedLog,
                NormalizedLog.raw_log_id == RawLog.id,
            )
            .where(NormalizedLog.id.is_(None))
        )
        or 0
    )
    raw_without_source = int(
        db.scalar(
            select(func.count(RawLog.id))
            .outerjoin(LogSource, LogSource.id == RawLog.source_id)
            .where(LogSource.id.is_(None))
        )
        or 0
    )
    orphan_alert_evidence = int(
        db.scalar(
            select(func.count(AlertEvidence.id))
            .outerjoin(Alert, Alert.id == AlertEvidence.alert_id)
            .outerjoin(
                NormalizedLog,
                NormalizedLog.id == AlertEvidence.normalized_log_id,
            )
            .where((Alert.id.is_(None)) | (NormalizedLog.id.is_(None)))
        )
        or 0
    )
    source_received = int(
        db.scalar(
            select(func.coalesce(func.sum(LogSource.logs_received_count), 0))
            .where(LogSource.id.in_(source_ids))
        )
        or 0
    )
    source_parsed = int(
        db.scalar(
            select(func.coalesce(func.sum(LogSource.parse_success_count), 0))
            .where(LogSource.id.in_(source_ids))
        )
        or 0
    )
    run_received = int(
        db.scalar(
            select(func.coalesce(func.sum(IngestionRun.total_lines_received), 0))
        )
        or 0
    )
    run_raw = int(
        db.scalar(
            select(func.coalesce(func.sum(IngestionRun.raw_logs_created), 0))
        )
        or 0
    )
    passed = all(
        (
            integrity_value.lower() == "ok",
            not foreign_key_rows,
            counts["raw_logs"] == target_rows,
            counts["normalized_logs"] == target_rows,
            orphan_normalized == 0,
            raw_without_normalized == 0,
            raw_without_source == 0,
            orphan_alert_evidence == 0,
            source_received == target_rows,
            source_parsed == target_rows,
            run_received == target_rows,
            run_raw == target_rows,
        )
    )
    return {
        "ok": passed,
        "sqlite_integrity_check": integrity_value.lower(),
        "foreign_key_violation_count": len(foreign_key_rows),
        "raw_logs": counts["raw_logs"],
        "normalized_logs": counts["normalized_logs"],
        "orphan_normalized_rows": orphan_normalized,
        "raw_rows_without_normalized": raw_without_normalized,
        "raw_rows_without_source": raw_without_source,
        "orphan_alert_evidence_rows": orphan_alert_evidence,
        "source_received_rows": source_received,
        "source_parsed_rows": source_parsed,
        "ingestion_run_received_rows": run_received,
        "ingestion_run_raw_rows": run_raw,
    }


def _aggregate_detection(
    db: Session,
    *,
    source_ids: list[int],
    stage_results: list[dict[str, Any]],
) -> dict[str, Any]:
    executed = [item for item in stage_results if item.get("executed")]
    linked_alerts = int(
        db.scalar(
            select(func.count(func.distinct(AlertEvidence.alert_id)))
            .join(
                NormalizedLog,
                NormalizedLog.id == AlertEvidence.normalized_log_id,
            )
            .join(RawLog, RawLog.id == NormalizedLog.raw_log_id)
            .where(RawLog.source_id.in_(source_ids))
        )
        or 0
    )
    linked_evidence = int(
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
    cases = list_alert_cases(
        db,
        active_only=True,
        source_ids=source_ids,
        limit=max(1, linked_alerts),
    )
    top_types: Counter[str] = Counter()
    for item in executed:
        for attack in item.get("top_attack_types") or []:
            top_types[str(attack.get("name") or "unknown")] += int(
                attack.get("count") or 0
            )
    evaluated = sum(int(item.get("logs_evaluated") or 0) for item in executed)
    runtime = sum(float(item.get("runtime_seconds") or 0.0) for item in executed)
    total_alerts = int(db.scalar(select(func.count(Alert.id))) or 0)
    return {
        "executed": bool(executed),
        "mode": "deterministic_rules_only",
        "rule_detection_authoritative": True,
        "ml_advisory_execution": False,
        "supervised_lifecycle": "shadow_observation",
        "logs_evaluated": evaluated,
        "alerts_created": sum(
            int(item.get("alerts_created") or 0) for item in executed
        ),
        "alerts_deduplicated": sum(
            int(item.get("alerts_deduplicated") or 0) for item in executed
        ),
        "alerts_suppressed": sum(
            int(item.get("alerts_suppressed") or 0) for item in executed
        ),
        "alerts_with_source_traceability": linked_alerts,
        "alert_evidence_links": linked_evidence,
        "cases_computed": len(cases),
        "cases_reconcile_with_alert_groups": len(cases) <= linked_alerts,
        "alert_to_log_source_traceability": total_alerts == linked_alerts
        and (linked_alerts == 0 or linked_evidence > 0),
        "top_attack_types": [
            {"name": name, "count": count}
            for name, count in top_types.most_common(20)
        ],
        "runtime_seconds": round(runtime, 4),
        "rows_per_second": round(evaluated / runtime, 2)
        if runtime > 0
        else None,
        "response_actions_created": int(
            db.scalar(select(func.count(ResponseAction.id))) or 0
        ),
    }


def _stage_resource_recheck(
    root: Path,
    *,
    remaining_rows: int,
    source_bytes_per_row: float,
) -> dict[str, Any]:
    remaining_source_bytes = math.ceil(source_bytes_per_row * remaining_rows)
    remaining_database_bytes = math.ceil(
        _V514_DB_BYTES_PER_ROW * remaining_rows
    )
    estimated_remaining = (
        remaining_source_bytes
        + remaining_database_bytes
        + max(128 * 1024 * 1024, math.ceil(remaining_database_bytes * 0.20))
    )
    required = estimated_remaining * _STORAGE_HEADROOM_MULTIPLIER
    disk = shutil.disk_usage(root)
    return {
        "remaining_rows": remaining_rows,
        "free_bytes": int(disk.free),
        "estimated_remaining_bytes": estimated_remaining,
        "required_free_bytes": required,
        "headroom_multiplier": _STORAGE_HEADROOM_MULTIPLIER,
        "sufficient": int(disk.free) >= required,
    }


def _base_failure(status: str) -> dict[str, Any]:
    return {
        "ok": False,
        "status": status,
        "configured_database_modified": False,
        "path_returned": False,
        "raw_evidence_returned": False,
        "private_identifiers_returned": False,
        "fingerprints_returned": False,
        "secrets_exposed": False,
        "response_automation_allowed": False,
        "real_firewall_blocking_enabled": False,
        "model_activation_performed": False,
        "production_ready": False,
    }


def run_v515_runtime_soak_acceptance(
    *,
    sample_path: str | Path,
    target_rows: int | None = _STAGE_A_ROWS,
    chunk_size: int = 1_000,
    use_temp_db: bool = False,
    fault_plan: str = "combined",
    run_detection_after: bool = False,
    preflight_only: bool = False,
) -> dict[str, Any]:
    evidence_path = Path(sample_path).expanduser()
    if not evidence_path.exists() or not evidence_path.is_file():
        return _base_failure("private_evidence_unavailable")
    if chunk_size < 1 or chunk_size > _MAX_CHUNK_SIZE:
        return {
            **_base_failure("invalid_chunk_size"),
            "allowed_range": [1, _MAX_CHUNK_SIZE],
        }
    if target_rows is not None and target_rows < _MIN_ROWS:
        return {
            **_base_failure("invalid_target_rows"),
            "minimum": _MIN_ROWS,
        }
    selected_fault_plan = fault_plan.strip().lower()
    if selected_fault_plan not in _FAULT_PLANS:
        return {
            **_base_failure("invalid_fault_plan"),
            "allowed_fault_plans": sorted(_FAULT_PLANS),
        }

    configured_path, marker_before = _configured_sqlite_marker()
    resource_preflight, _private_preflight = _resource_preflight(
        evidence_path=evidence_path,
        target_rows=target_rows,
    )
    if preflight_only:
        result = {
            **_base_failure("resource_preflight_complete"),
            "ok": bool(resource_preflight.get("ok")),
            "resource_preflight": resource_preflight,
            "configured_database_modified": False,
        }
        findings = _privacy_findings(result, private_path=evidence_path)
        result["privacy_findings"] = findings
        result["ok"] = bool(result["ok"]) and not findings
        return result
    if not use_temp_db:
        return {
            **_base_failure("explicit_temp_database_required"),
            "message": (
                "Re-run with --use-temp-db; the configured database is never "
                "a soak-acceptance target."
            ),
            "resource_preflight": resource_preflight,
        }
    if not resource_preflight.get("ok"):
        return {
            **_base_failure("resource_preflight_failed"),
            "resource_preflight": resource_preflight,
        }

    selected_rows = int(resource_preflight["selected_rows"])
    stage_counts = _stage_counts(selected_rows)
    run_token = uuid4().hex[:12]
    root = Path(tempfile.mkdtemp(prefix=f"atdr-v515-{run_token}-"))
    database_path = root / "runtime-soak.sqlite3"
    staging_root = root / "staging"
    engine: Engine | None = None
    result: dict[str, Any] = {}
    cleanup_started = 0.0
    cleanup_seconds = 0.0
    cleanup_complete = False
    total_started = time.perf_counter()
    try:
        specs = _prepare_stage_files(
            evidence_path,
            root,
            stage_counts=stage_counts,
        )
        prepared_bytes = sum(
            spec.prepared_path.stat().st_size for spec in specs
        )
        input_max_bytes = max(
            prepared_bytes + 64 * 1024 * 1024,
            128 * 1024 * 1024,
        )
        engine = create_engine(
            f"sqlite:///{database_path}",
            connect_args={"check_same_thread": False, "timeout": 30.0},
            future=True,
        )
        Base.metadata.create_all(engine)
        initial_db_bytes = (
            database_path.stat().st_size if database_path.exists() else 0
        )
        source_ids: list[int] = []
        stage_summaries: list[dict[str, Any]] = []
        stage_detection_results: list[dict[str, Any]] = []
        cumulative_rows = 0
        previous_db_bytes = initial_db_bytes
        idempotency_ok = True
        all_chunk_latencies: list[float] = []
        all_resume_latencies: list[float] = []

        with _runtime_settings(
            staging_root,
            chunk_size=chunk_size,
            input_max_bytes=input_max_bytes,
            storage_id="v515-soak",
        ):
            tracemalloc.start()
            for stage_index, spec in enumerate(specs):
                remaining_before = selected_rows - cumulative_rows
                recheck = _stage_resource_recheck(
                    root,
                    remaining_rows=remaining_before,
                    source_bytes_per_row=float(
                        resource_preflight["storage_estimate"][
                            "source_bytes_per_row_estimate"
                        ]
                    ),
                )
                if not recheck["sufficient"]:
                    raise RuntimeError(
                        "Progressive stage stopped by the three-times-storage gate."
                    )
                stage_started = time.perf_counter()
                staged = _stage_file(spec, max_bytes=input_max_bytes)
                with Session(engine) as db:
                    source = create_source(
                        db,
                        name=f"v515-simulated-{spec.label}",
                        source_type="sample",
                        parser_profile="palo_alto",
                    )
                    source_ids.append(source.id)
                    key = f"v515-{run_token}-{stage_index}"
                    job, reused = _enqueue_import(
                        db,
                        staged=staged,
                        source_id=source.id,
                        rows=spec.row_count,
                        idempotency_key=key,
                        label=f"simulated-{spec.label}",
                    )
                    duplicate, duplicate_reused = _enqueue_import(
                        db,
                        staged=staged,
                        source_id=source.id,
                        rows=spec.row_count,
                        idempotency_key=key,
                        label=f"simulated-{spec.label}",
                    )
                    idempotency_ok = bool(
                        idempotency_ok
                        and not reused
                        and duplicate_reused
                        and duplicate.id == job.id
                    )
                    import_summary = _run_stage_import(
                        db,
                        job=job,
                        staged=staged,
                        source_id=source.id,
                        fault_sequence=_fault_sequence(
                            selected_fault_plan,
                            stage_index,
                        ),
                        worker_prefix=f"v515-{spec.label}",
                    )
                    all_chunk_latencies.extend(
                        float(value)
                        for value in import_summary.pop(
                            "_chunk_latency_samples",
                            [],
                        )
                    )
                    all_resume_latencies.extend(
                        float(value)
                        for value in import_summary.get(
                            "resume_latencies_seconds"
                        )
                        or []
                    )
                    detection = {
                        "executed": False,
                        "mode": "not_requested",
                        "rule_detection_authoritative": True,
                        "ml_advisory_execution": False,
                        "response_actions_created": 0,
                    }
                    if run_detection_after:
                        detection, _elapsed = _detection_summary(
                            db,
                            source_ids=[source.id],
                            source_rows=[spec.row_count],
                        )
                    stage_detection_results.append(detection)
                    source_detail_started = time.perf_counter()
                    source_summary = _source_summary(db, source.id)
                    source_detail_seconds = (
                        time.perf_counter() - source_detail_started
                    )
                    dashboard = _dashboard_timings(
                        db,
                        source_id=source.id,
                    )
                    stage_counts_now = _count_rows(db)
                    stage_integrity = _integrity_summary(
                        db,
                        target_rows=cumulative_rows + spec.row_count,
                        source_ids=source_ids,
                    )

                cumulative_rows += spec.row_count
                current_db_bytes = (
                    database_path.stat().st_size
                    if database_path.exists()
                    else 0
                )
                growth = max(0, current_db_bytes - previous_db_bytes)
                previous_db_bytes = current_db_bytes
                stage_seconds = time.perf_counter() - stage_started
                stage_summaries.append(
                    {
                        "stage": spec.label,
                        "logical_source_kind": (
                            "simulated_chronological_window_of_one_private_stream"
                        ),
                        "rows_requested": spec.row_count,
                        "cumulative_rows": cumulative_rows,
                        "resource_recheck": recheck,
                        "import": import_summary,
                        "source": source_summary,
                        "detection": detection,
                        "integrity": stage_integrity,
                        "counts": stage_counts_now,
                        "runtime_seconds": round(stage_seconds, 4),
                        "ingestion_rows_per_second": import_summary.get(
                            "rows_per_second"
                        ),
                        "parsing_rows_per_second": import_summary.get(
                            "rows_per_second"
                        ),
                        "database_growth_bytes": growth,
                        "database_growth_per_100k_rows": round(
                            growth * 100_000 / spec.row_count,
                            2,
                        ),
                        "dashboard_query_timings": {
                            **dashboard,
                            "source_detail_direct_seconds": round(
                                source_detail_seconds,
                                4,
                            ),
                        },
                    }
                )

            _current_memory, peak_memory = tracemalloc.get_traced_memory()
            tracemalloc.stop()
            lock_probe = {
                "ok": True,
                "executed": False,
                "mode": "not_requested",
            }
            if selected_fault_plan in {"sqlite_lock_wait", "combined"}:
                lock_probe = {
                    **_sqlite_lock_probe(engine, source_id=source_ids[0]),
                    "executed": True,
                }
            with Session(engine) as db:
                integrity = _integrity_summary(
                    db,
                    target_rows=selected_rows,
                    source_ids=source_ids,
                )
                detection_summary = _aggregate_detection(
                    db,
                    source_ids=source_ids,
                    stage_results=stage_detection_results,
                )
                final_counts = _count_rows(db)
                final_sources = [
                    _source_summary(db, source_id) for source_id in source_ids
                ]
                ingestion_runs = list(
                    db.scalars(
                        select(IngestionRun).order_by(IngestionRun.id)
                    )
                )
                detection_run_count = int(
                    db.scalar(select(func.count(DetectionRun.id))) or 0
                )

        database_final_bytes = (
            database_path.stat().st_size if database_path.exists() else 0
        )
        duplicate_rows = sum(
            int(run.duplicate_raw_logs or 0) for run in ingestion_runs
        )
        unsafe_counts = {
            "response_actions": final_counts["response_actions"],
            "labels": final_counts["labels"],
            "model_runs": final_counts["model_runs"],
        }
        import_checks = {
            "all_stages_completed": len(stage_summaries) == len(specs)
            and all(
                bool(stage["import"]["completed"]) for stage in stage_summaries
            ),
            "idempotent_enqueue_contained": idempotency_ok,
            "progress_monotonic": all(
                bool(stage["import"]["progress_monotonic"])
                for stage in stage_summaries
            ),
            "line_checkpoints_monotonic": all(
                bool(stage["import"]["line_checkpoint_monotonic"])
                for stage in stage_summaries
            ),
            "byte_checkpoints_monotonic": all(
                bool(stage["import"]["byte_checkpoint_monotonic"])
                for stage in stage_summaries
            ),
            "source_last_seen_monotonic": all(
                bool(stage["import"]["source_last_seen_monotonic"])
                for stage in stage_summaries
            ),
            "no_checkpoint_replay_rows": final_counts["raw_logs"]
            == selected_rows,
            "raw_normalized_counts_match": final_counts["raw_logs"]
            == final_counts["normalized_logs"],
            "staging_cleaned_after_success": all(
                bool(stage["import"]["staged_input_cleaned"])
                for stage in stage_summaries
            ),
            "every_fault_recovered": all(
                stage["import"]["status"] == "completed"
                for stage in stage_summaries
            ),
        }
        result = {
            "ok": False,
            "status": "runtime_soak_pending_checks",
            "scope": "private_evidence_disposable_sqlite",
            "resource_preflight": resource_preflight,
            "largest_stage_completed": stage_summaries[-1]["stage"]
            if stage_summaries
            else None,
            "runtime_evidence": {
                "rows_selected": selected_rows,
                "rows_processed": final_counts["raw_logs"],
                "stage_count": len(stage_summaries),
                "logical_source_count": len(source_ids),
                "logical_sources_are_simulated": True,
                "physical_device_count_claimed": 0,
            },
            "stages": stage_summaries,
            "ingestion": {
                "checks": import_checks,
                "raw_logs": final_counts["raw_logs"],
                "normalized_logs": final_counts["normalized_logs"],
                "parsed_successfully": sum(
                    int(run.parsed_successfully or 0)
                    for run in ingestion_runs
                ),
                "parse_failures": sum(
                    int(run.parse_failures or 0) for run in ingestion_runs
                ),
                "exact_duplicates_observed_and_preserved": duplicate_rows,
                "duplicate_policy": (
                    "Repeated raw events remain evidence; committed checkpoint "
                    "rows are not replayed by resume."
                ),
                "fault_plan": selected_fault_plan,
                "total_worker_handoffs": sum(
                    int(stage["import"]["worker_handoffs"])
                    for stage in stage_summaries
                ),
                "total_cancellations": sum(
                    int(stage["import"]["cancellations"])
                    for stage in stage_summaries
                ),
                "total_stale_lease_recoveries": sum(
                    int(stage["import"]["stale_lease_recoveries"])
                    for stage in stage_summaries
                ),
            },
            "database": {
                "integrity": integrity,
                "initial_bytes": initial_db_bytes,
                "final_bytes": database_final_bytes,
                "growth_bytes": max(
                    0,
                    database_final_bytes - initial_db_bytes,
                ),
                "growth_per_100k_rows": round(
                    max(0, database_final_bytes - initial_db_bytes)
                    * 100_000
                    / selected_rows,
                    2,
                ),
                "growth_baseline_v514_bytes_per_100k": round(
                    _V514_DB_BYTES_PER_ROW * 100_000,
                    2,
                ),
            },
            "sqlite_lock_handling": lock_probe,
            "sources": final_sources,
            "detection": detection_summary,
            "performance": {
                "peak_traced_python_memory_mb": round(
                    peak_memory / (1024 * 1024),
                    2,
                ),
                "chunk_latency": _latency_summary(all_chunk_latencies),
                "resume_latency": _latency_summary(all_resume_latencies),
                "stage_count": len(stage_summaries),
                "detection_run_count": detection_run_count,
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
                "supervised_lifecycle": "shadow_observation",
                "model_activation_performed": False,
                "model_promotion_performed": False,
                "response_automation_allowed": False,
                "real_firewall_blocking_enabled": False,
                "unsafe_side_effect_counts": unsafe_counts,
            },
            "production_ready": False,
        }
    except Exception as exc:
        if tracemalloc.is_tracing():
            tracemalloc.stop()
        result = {
            **_base_failure("runtime_soak_error"),
            "error_type": exc.__class__.__name__,
            "resource_preflight": resource_preflight,
        }
    finally:
        if engine is not None:
            engine.dispose()
        get_settings.cache_clear()
        cleanup_started = time.perf_counter()
        with suppress(OSError):
            shutil.rmtree(root)
        cleanup_seconds = time.perf_counter() - cleanup_started
        cleanup_complete = not root.exists()

    marker_after = _marker_for_path(configured_path)
    configured_unchanged = marker_before == marker_after
    safety = result.setdefault("safety", {})
    safety.update(
        {
            "configured_database_marker_checked": configured_path is not None,
            "configured_database_unchanged": configured_unchanged,
            "configured_database_modified": not configured_unchanged,
        }
    )
    result["configured_database_modified"] = not configured_unchanged
    result["cleanup"] = {
        "complete": cleanup_complete,
        "duration_seconds": round(cleanup_seconds, 4),
        "prepared_segments_removed": cleanup_complete,
        "staged_inputs_removed": cleanup_complete,
        "disposable_database_removed": cleanup_complete,
        "sqlite_journals_removed": cleanup_complete,
        "paths_returned": False,
    }
    result["total_runtime_seconds"] = round(
        time.perf_counter() - total_started,
        4,
    )
    privacy_findings = _privacy_findings(result, private_path=evidence_path)
    result["privacy_findings"] = privacy_findings

    if result.get("status") != "runtime_soak_error":
        checks = (result.get("ingestion") or {}).get("checks") or {}
        unsafe_counts = (
            (result.get("safety") or {}).get("unsafe_side_effect_counts") or {}
        )
        detection_ok = (
            not run_detection_after
            or bool((result.get("detection") or {}).get("executed"))
            and bool(
                (result.get("detection") or {}).get(
                    "rule_detection_authoritative"
                )
            )
        )
        passed = all(
            (
                all(bool(value) for value in checks.values()),
                bool((result.get("database") or {}).get("integrity", {}).get("ok")),
                bool((result.get("sqlite_lock_handling") or {}).get("ok")),
                detection_ok,
                all(int(value or 0) == 0 for value in unsafe_counts.values()),
                configured_unchanged,
                cleanup_complete,
                not privacy_findings,
            )
        )
        result["ok"] = passed
        result["status"] = (
            "long_duration_runtime_soak_passed"
            if passed
            else "long_duration_runtime_soak_failed"
        )
    return result
