from __future__ import annotations

from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import gc
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
from threading import Event, Lock
import time
from typing import Any
from uuid import uuid4

from sqlalchemy import func, inspect, select, text
from sqlalchemy.engine import Engine, make_url
from sqlalchemy.orm import Session, sessionmaker

from atdr.app.core.config import PROJECT_ROOT, Settings, get_settings
from atdr.app.db.engine import create_configured_engine
from atdr.app.db.models import (
    Alert,
    AlertEvidence,
    DetectionRun,
    LogSource,
    MLLabel,
    MLModelRun,
    NormalizedLog,
    OperationJob,
    RawLog,
    ResponseAction,
)
from atdr.app.services.case_service import count_alert_cases
from atdr.app.services.job_service import (
    LeaseOwnershipError,
    claim_next_job,
    complete_queued_job,
    enqueue_job,
    recover_expired_leases,
    request_job_cancellation,
    resume_import_job,
)
from atdr.app.services.operation_worker import run_worker_once
from atdr.app.services.persistence_service import (
    create_database_backup,
    restore_database_backup,
)
from atdr.app.services.source_service import get_or_create_source
from atdr.app.services.staging_service import (
    inspect_staged_path,
    staged_payload_fields,
)
from atdr.app.services.v514_large_file_runtime_service import (
    _dashboard_timings,
    _privacy_findings,
)
from atdr.app.services.v516_memory_query_service import process_memory_snapshot


_SAFE_DATABASE_NAME = re.compile(r"^[A-Za-z0-9_]+$")
_SAFE_DATABASE_MARKERS = ("v517", "test", "ci", "disposable", "temp")
_MIN_TARGET_ROWS = 100
_MAX_TARGET_ROWS = 1_000_000
_MAX_WORKERS = 8
_BACKUP_ROOT = PROJECT_ROOT / ".tmp" / "v517-backups"
_STAGING_ROOT = PROJECT_ROOT / ".tmp" / "v517-shared-staging"
_SCENARIO_ROOT = PROJECT_ROOT / "data" / "samples" / "scenarios"


def _base_result(status: str, *, ok: bool = False) -> dict[str, Any]:
    return {
        "ok": ok,
        "status": status,
        "production_ready": False,
        "configured_database_modified": False,
        "private_path_returned": False,
        "raw_evidence_returned": False,
        "private_identifiers_returned": False,
        "fingerprints_returned": False,
        "secrets_exposed": False,
        "rules_alert_authoritative": True,
        "supervised_lifecycle": "shadow_observation",
        "model_activation_performed": False,
        "model_promotion_performed": False,
        "response_automation_allowed": False,
        "real_firewall_blocking_enabled": False,
    }


def _database_identity(database_url: str) -> tuple[str, str, int | None, str, str]:
    url = make_url(database_url)
    return (
        url.get_backend_name(),
        url.host or "",
        url.port,
        url.database or "",
        url.username or "",
    )


def _safe_postgres_target(
    database_url: str,
    *,
    configured_url: str,
) -> tuple[bool, str]:
    if not database_url:
        return False, "missing_database_url"
    try:
        url = make_url(database_url)
        configured_identity = _database_identity(configured_url)
        target_identity = _database_identity(database_url)
    except Exception:
        return False, "invalid_database_url"
    if url.get_backend_name() != "postgresql":
        return False, "postgresql_required"
    database_name = url.database or ""
    if (
        not _SAFE_DATABASE_NAME.fullmatch(database_name)
        or database_name.lower() in {"postgres", "template0", "template1", "atdr"}
        or not any(marker in database_name.lower() for marker in _SAFE_DATABASE_MARKERS)
    ):
        return False, "unsafe_database_name"
    if target_identity == configured_identity:
        return False, "configured_database_target_refused"
    return True, "accepted"


def _configured_database_marker() -> tuple[str, Any]:
    settings = get_settings()
    try:
        url = make_url(settings.database_url)
    except Exception:
        return "unavailable", None
    if url.get_backend_name() == "sqlite":
        if not url.database or url.database == ":memory:":
            return "sqlite", None
        path = Path(url.database)
        path = (PROJECT_ROOT / path).resolve() if not path.is_absolute() else path.resolve()
        if not path.exists():
            return "sqlite", None
        stat = path.stat()
        return "sqlite", (int(stat.st_size), int(stat.st_mtime_ns))
    try:
        configured_settings = Settings(
            _env_file=None,
            DATABASE_URL=settings.database_url,
            AUTO_CREATE_TABLES=False,
        )
        engine = create_configured_engine(configured_settings)
        try:
            with engine.connect() as connection:
                marker = (
                    int(connection.execute(text("SELECT pg_database_size(current_database())")).scalar() or 0),
                    int(
                        connection.execute(
                            text(
                                "SELECT COUNT(*) FROM information_schema.tables "
                                "WHERE table_schema = 'public'"
                            )
                        ).scalar()
                        or 0
                    ),
                )
            return "postgresql", marker
        finally:
            engine.dispose()
    except Exception:
        return "unavailable", None


@contextmanager
def _temporary_environment(values: dict[str, str]) -> Iterator[None]:
    previous = {key: os.environ.get(key) for key in values}
    try:
        os.environ.update(values)
        get_settings.cache_clear()
        yield
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        get_settings.cache_clear()


def _target_settings(database_url: str, staging_root: Path) -> Settings:
    return Settings(
        _env_file=None,
        DATABASE_URL=database_url,
        AUTO_CREATE_TABLES=False,
        RESPONSE_SIMULATION=True,
        OPERATION_WORKER_ENABLED=True,
        OPERATION_WORKER_CONCURRENCY=2,
        OPERATION_STAGING_ROOT=str(staging_root.resolve()),
        OPERATION_STAGING_SHARED=True,
        OPERATION_STAGING_STORAGE_ID="v517-shared",
        OPERATION_STAGING_MIN_FREE_BYTES=0,
    )


def _run_migrations(database_url: str) -> dict[str, Any]:
    environment = os.environ.copy()
    environment.update(
        {
            "DATABASE_URL": database_url,
            "AUTO_CREATE_TABLES": "false",
            "RESPONSE_SIMULATION": "true",
        }
    )
    try:
        completed = subprocess.run(
            [sys.executable, "-m", "alembic", "upgrade", "head"],
            cwd=PROJECT_ROOT,
            env=environment,
            capture_output=True,
            text=True,
            timeout=180,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {
            "ok": False,
            "status": "migration_unavailable",
            "error_type": exc.__class__.__name__,
        }
    return {
        "ok": completed.returncode == 0,
        "status": (
            "migration_current"
            if completed.returncode == 0
            else "migration_failed"
        ),
        "error_type": None if completed.returncode == 0 else "AlembicError",
    }


def _database_available(database_url: str) -> bool:
    try:
        settings = _target_settings(database_url, _STAGING_ROOT)
        engine = create_configured_engine(settings)
        try:
            with engine.connect() as connection:
                connection.execute(text("SELECT 1"))
            return True
        finally:
            engine.dispose()
    except Exception:
        return False


def _preflight(
    *,
    target_url: str,
    restore_url: str,
    configured_url: str,
    require_tools: bool,
) -> dict[str, Any]:
    target_safe, target_reason = _safe_postgres_target(
        target_url,
        configured_url=configured_url,
    )
    restore_safe, restore_reason = _safe_postgres_target(
        restore_url,
        configured_url=configured_url,
    )
    distinct = False
    if target_safe and restore_safe:
        distinct = _database_identity(target_url) != _database_identity(restore_url)
    tools = {
        "pg_dump": bool(shutil.which("pg_dump")),
        "pg_restore": bool(shutil.which("pg_restore")),
    }
    available = target_safe and restore_safe and distinct and _database_available(target_url)
    restore_available = (
        target_safe
        and restore_safe
        and distinct
        and _database_available(restore_url)
    )
    ok = bool(
        target_safe
        and restore_safe
        and distinct
        and available
        and restore_available
        and (all(tools.values()) if require_tools else True)
    )
    return {
        "ok": ok,
        "status": "ready" if ok else "blocked_by_environment",
        "target": {
            "safe": target_safe,
            "reason": target_reason,
            "available": available,
        },
        "restore": {
            "safe": restore_safe,
            "reason": restore_reason,
            "available": restore_available,
        },
        "targets_distinct": distinct,
        "postgres_tools": tools,
        "database_urls_returned": False,
        "credentials_returned": False,
    }


def _safe_source_lines(*, synthetic: bool, sample_path: Path | None) -> list[str]:
    if synthetic:
        paths = (
            _SCENARIO_ROOT / "normal_allowed_traffic.txt",
            _SCENARIO_ROOT / "port_scan_like_traffic.txt",
            _SCENARIO_ROOT / "repeated_dedup_traffic.txt",
        )
        lines = [
            line
            for path in paths
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines()
            if line.strip()
        ]
        if not lines:
            raise ValueError("Safe synthetic scenario evidence is unavailable.")
        return lines
    if sample_path is None or not sample_path.is_file():
        raise ValueError("Private evidence is unavailable.")
    if os.environ.get("ATDR_V517_PRIVATE_EVIDENCE_APPROVED", "").lower() not in {
        "1",
        "true",
        "yes",
    }:
        raise PermissionError(
            "Private evidence execution requires explicit host approval."
        )
    lines: list[str] = []
    with sample_path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            if line.strip():
                lines.append(line.rstrip("\r\n"))
            if len(lines) >= 100_000:
                break
    if not lines:
        raise ValueError("Private evidence contains no usable records.")
    return lines


def _write_cycled_input(
    path: Path,
    *,
    lines: list[str],
    count: int,
    offset: int = 0,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for index in range(count):
            handle.write(lines[(offset + index) % len(lines)])
            handle.write("\n")


def _enqueue_import(
    db: Session,
    *,
    path: Path,
    source_id: int,
    actor: str,
) -> int:
    staged = inspect_staged_path(path)
    payload = {
        **staged_payload_fields(staged),
        "input_name": staged.safe_name,
        "input_bytes": staged.byte_count,
        "input_fingerprint": staged.fingerprint,
        "available_lines": staged.available_lines,
        "source_type": "file_import",
        "parser_profile": "palo_alto",
        "limit": staged.available_lines,
        "source_id": source_id,
    }
    job, _ = enqueue_job(
        db,
        job_type="import_logs",
        requested_by=actor,
        payload=payload,
        details={"validation": "v5.17", "evidence": "aggregate_only"},
        idempotency_key=f"v517-import-{uuid4().hex}",
        progress_total=staged.available_lines,
        input_size_bytes=staged.byte_count,
        input_fingerprint=staged.fingerprint,
        resume_expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        staging_storage_id=staged.storage_id,
    )
    return int(job.id)


def _count(db: Session, model: Any) -> int:
    return int(db.scalar(select(func.count(model.id))) or 0)


def _safety_counts(db: Session) -> dict[str, int]:
    return {
        "labels": _count(db, MLLabel),
        "model_runs": _count(db, MLModelRun),
        "response_actions": _count(db, ResponseAction),
    }


def _percentile(values: list[float], percentile: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = min(
        len(ordered) - 1,
        max(0, int(round((len(ordered) - 1) * percentile))),
    )
    return round(ordered[index], 4)


def _worker_batch(
    factory: sessionmaker[Session],
    *,
    workers: int,
    after_chunk: Any = None,
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    pool = factory.kw["bind"].pool
    peak = {"checked_out": 0, "overflow": 0}
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = []
        for index in range(workers):
            def run(worker_index: int = index) -> dict[str, Any]:
                with factory() as db:
                    callback = (
                        (lambda chunks, job: after_chunk(worker_index, chunks, job))
                        if after_chunk is not None
                        else None
                    )
                    return run_worker_once(
                        db,
                        worker_id=f"v517-worker-{worker_index}",
                        after_chunk=callback,
                    )

            futures.append(executor.submit(run))
        while any(not future.done() for future in futures):
            checked_out = getattr(pool, "checkedout", lambda: 0)()
            overflow = getattr(pool, "overflow", lambda: 0)()
            peak["checked_out"] = max(peak["checked_out"], int(checked_out))
            peak["overflow"] = max(peak["overflow"], int(overflow))
            time.sleep(0.01)
        results = [future.result() for future in futures]
    return results, peak


def _validate_lease_fencing(factory: sessionmaker[Session]) -> dict[str, Any]:
    with factory() as db:
        queued, _ = enqueue_job(
            db,
            job_type="validation",
            requested_by="v517-validator",
            payload={},
        )
        claimed = claim_next_job(
            db,
            worker_id="v517-fencing-worker",
            lease_seconds=60,
        )
        if claimed is None or claimed.id != queued.id:
            return {"ok": False, "stale_update_rejected": False}
        token = str(claimed.lease_token or "")
        stale_rejected = False
        try:
            complete_queued_job(
                db,
                job_id=int(claimed.id),
                worker_id="v517-fencing-worker",
                lease_token="stale-token",
            )
        except LeaseOwnershipError:
            stale_rejected = True
            db.rollback()
        completed = complete_queued_job(
            db,
            job_id=int(claimed.id),
            worker_id="v517-fencing-worker",
            lease_token=token,
            result_summary={"status": "fencing_validated"},
        )
        return {
            "ok": stale_rejected and completed.status == "completed",
            "stale_update_rejected": stale_rejected,
            "claim_generation": int(completed.claim_generation or 0),
            "lease_token_returned": False,
        }


def _validate_stale_recovery(factory: sessionmaker[Session]) -> dict[str, Any]:
    checkpoint_line = 17
    with factory() as db:
        job = OperationJob(
            job_type="import_logs",
            status="running",
            requested_by="v517-validator",
            progress_current=checkpoint_line,
            progress_total=100,
            checkpoint_line=checkpoint_line,
            checkpoint_bytes=512,
            chunk_commits=2,
            attempt_count=1,
            max_attempts=3,
            payload_json={},
            result_summary_json={},
            details_json={},
            lease_owner="expired-worker",
            lease_token="expired-token",
            claim_generation=1,
            lease_expires_at=datetime.now(timezone.utc) - timedelta(seconds=1),
        )
        db.add(job)
        db.commit()
        job_id = int(job.id)
    with factory() as db:
        recovered = recover_expired_leases(
            db,
            retry_delay_seconds=1,
            limit=10,
        )
        persisted = db.get(OperationJob, job_id)
        recovered_ids = {int(item.id) for item in recovered}
        ok = bool(
            persisted is not None
            and job_id in recovered_ids
            and persisted.status == "failed"
            and persisted.checkpoint_line == checkpoint_line
            and persisted.lease_token is None
        )
        return {
            "ok": ok,
            "evidence_mutating_job_failed_closed": (
                persisted is not None and persisted.status == "failed"
            ),
            "checkpoint_preserved": (
                persisted is not None
                and persisted.checkpoint_line == checkpoint_line
            ),
            "lease_token_returned": False,
        }


def _validate_idempotency(factory: sessionmaker[Session]) -> dict[str, Any]:
    key = f"v517-idempotency-{uuid4().hex}"

    def enqueue(_index: int) -> tuple[int, bool]:
        with factory() as db:
            job, reused = enqueue_job(
                db,
                job_type="validation",
                requested_by="v517-validator",
                payload={},
                idempotency_key=key,
            )
            return int(job.id), reused

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(enqueue, range(2)))
    ids = {job_id for job_id, _ in outcomes}
    with factory() as db:
        persisted = int(
            db.scalar(
                select(func.count(OperationJob.id)).where(
                    OperationJob.idempotency_key == key
                )
            )
            or 0
        )
        job = db.scalar(
            select(OperationJob).where(OperationJob.idempotency_key == key)
        )
        if job is not None and job.status == "queued":
            job.status = "cancelled"
            db.commit()
    return {
        "ok": len(ids) == 1 and persisted == 1,
        "single_persisted_job": persisted == 1,
        "both_requests_resolved_same_job": len(ids) == 1,
    }


def _validate_cancel_resume(
    factory: sessionmaker[Session],
    *,
    path: Path,
    source_id: int,
) -> dict[str, Any]:
    available = inspect_staged_path(path).available_lines
    with factory() as db:
        job_id = _enqueue_import(
            db,
            path=path,
            source_id=source_id,
            actor="v517-cancel-validator",
        )
    cancellation_requested = Event()

    def request_after_first_chunk(
        _worker_index: int,
        chunk_commits: int,
        _job: OperationJob,
    ) -> None:
        if chunk_commits != 1 or cancellation_requested.is_set():
            return
        with factory() as control:
            current = control.get(OperationJob, job_id)
            if current is not None and current.status == "running":
                request_job_cancellation(
                    control,
                    current,
                    actor="v517-cancel-validator",
                )
                cancellation_requested.set()

    first_results, _ = _worker_batch(
        factory,
        workers=1,
        after_chunk=request_after_first_chunk,
    )
    with factory() as db:
        parent = db.get(OperationJob, job_id)
        if parent is None:
            return {"ok": False}
        cancelled = parent.status == "cancelled"
        checkpoint = int(parent.checkpoint_line or 0)
        resumed = resume_import_job(
            db,
            parent,
            requested_by="v517-cancel-validator",
        )
        resumed_id = int(resumed.id)
    second_results, _ = _worker_batch(factory, workers=1)
    with factory() as db:
        child = db.get(OperationJob, resumed_id)
        source = db.get(LogSource, source_id)
        completed = child is not None and child.status == "completed"
        exact = (
            source is not None
            and int(source.logs_received_count or 0) == available
        )
    return {
        "ok": bool(
            cancellation_requested.is_set()
            and cancelled
            and checkpoint > 0
            and completed
            and exact
            and all(result.get("ok") for result in first_results + second_results)
        ),
        "cancellation_requested": cancellation_requested.is_set(),
        "cancelled_at_committed_boundary": cancelled and checkpoint > 0,
        "resume_completed": completed,
        "exact_source_counter": exact,
        "staged_input_preserved_until_completion": True,
    }


def _detection_consistency(
    factory: sessionmaker[Session],
    *,
    source_id: int,
    workers: int,
) -> dict[str, Any]:
    with factory() as db:
        before_alerts = _count(db, Alert)
        before_responses = _count(db, ResponseAction)
        for _ in range(2):
            enqueue_job(
                db,
                job_type="run_detection",
                requested_by="v517-validator",
                payload={
                    "limit": None,
                    "use_ml": False,
                    "source_id": source_id,
                },
            )
    started = time.perf_counter()
    results, _ = _worker_batch(factory, workers=max(2, workers))
    elapsed = time.perf_counter() - started
    with factory() as db:
        after_alerts = _count(db, Alert)
        after_responses = _count(db, ResponseAction)
        run_rows = list(
            db.scalars(
                select(DetectionRun)
                .where(DetectionRun.details_json["source_id"].as_integer() == source_id)
                .order_by(DetectionRun.id.desc())
                .limit(2)
            )
        )
        duplicate_evidence_groups = int(
            db.scalar(
                select(func.count())
                .select_from(
                    select(
                        AlertEvidence.alert_id,
                        AlertEvidence.normalized_log_id,
                    )
                    .group_by(
                        AlertEvidence.alert_id,
                        AlertEvidence.normalized_log_id,
                    )
                    .having(func.count(AlertEvidence.id) > 1)
                    .subquery()
                )
            )
            or 0
        )
        evidence_rows = int(
            db.scalar(
                select(func.count(AlertEvidence.id))
                .join(
                    NormalizedLog,
                    NormalizedLog.id == AlertEvidence.normalized_log_id,
                )
                .join(RawLog, RawLog.id == NormalizedLog.raw_log_id)
                .where(RawLog.source_id == source_id)
            )
            or 0
        )
        cases = count_alert_cases(db, source_id=source_id)
        alerts = list(
            db.scalars(
                select(Alert)
                .where(
                    Alert.id.in_(
                        select(AlertEvidence.alert_id)
                        .join(
                            NormalizedLog,
                            NormalizedLog.id
                            == AlertEvidence.normalized_log_id,
                        )
                        .join(RawLog, RawLog.id == NormalizedLog.raw_log_id)
                        .where(RawLog.source_id == source_id)
                    )
                )
            )
        )
        metadata_reconciled = True
        for alert in alerts:
            metadata = next(
                (
                    item
                    for item in alert.matched_rules_json or []
                    if item.get("code") == "group_metadata"
                ),
                {},
            )
            related = int(
                db.scalar(
                    select(func.count(AlertEvidence.id)).where(
                        AlertEvidence.alert_id == alert.id
                    )
                )
                or 0
            )
            if int(metadata.get("related_log_count") or related) != related:
                metadata_reconciled = False
                break
    completed = len(run_rows) == 2 and all(run.status == "completed" for run in run_rows)
    return {
        "ok": bool(
            completed
            and duplicate_evidence_groups == 0
            and metadata_reconciled
            and after_responses == before_responses
            and all(result.get("ok") for result in results)
        ),
        "concurrent_runs_completed": completed,
        "alerts_created_delta": after_alerts - before_alerts,
        "evidence_rows": evidence_rows,
        "duplicate_evidence_groups": duplicate_evidence_groups,
        "occurrence_related_counts_reconcile": metadata_reconciled,
        "cases_computed": cases,
        "source_scoped_detection_runs": len(run_rows),
        "contention_runtime_seconds": round(elapsed, 4),
        "contention_bounded": elapsed < 60,
        "response_actions_created": after_responses - before_responses,
        "rule_detection_authoritative": True,
    }


def _postgres_query_profile(
    db: Session,
    *,
    source_id: int,
) -> dict[str, Any]:
    timings = _dashboard_timings(
        db,
        source_id=source_id,
        include_query_counts=True,
        include_query_plans=False,
    )
    plan = db.execute(
        text(
            "EXPLAIN (FORMAT JSON) "
            "SELECT COUNT(*) FROM normalized_logs "
            "JOIN raw_logs ON raw_logs.id = normalized_logs.raw_log_id "
            "WHERE raw_logs.source_id = :source_id"
        ),
        {"source_id": source_id},
    ).scalar()
    node_types: list[str] = []

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            if value.get("Node Type"):
                node_types.append(str(value["Node Type"]))
            for child in value.values():
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)

    walk(plan)
    lock_waiters = int(
        db.scalar(select(func.count()).select_from(text("pg_locks")).where(text("NOT granted")))
        or 0
    )
    return {
        "dashboard": timings,
        "representative_plan": {
            "node_types": sorted(set(node_types)),
            "sql_text_returned": False,
            "query_parameters_returned": False,
        },
        "ungranted_lock_count": lock_waiters,
    }


def _drop_disposable_database(database_url: str) -> bool:
    try:
        url = make_url(database_url)
        name = url.database or ""
        if (
            url.get_backend_name() != "postgresql"
            or not _SAFE_DATABASE_NAME.fullmatch(name)
            or not any(marker in name.lower() for marker in _SAFE_DATABASE_MARKERS)
        ):
            return False
        admin_url = url.set(database="postgres")
        settings = _target_settings(admin_url.render_as_string(hide_password=False), _STAGING_ROOT)
        engine = create_configured_engine(settings).execution_options(
            isolation_level="AUTOCOMMIT"
        )
        try:
            with engine.connect() as connection:
                connection.execute(
                    text(
                        "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                        "WHERE datname = :database_name AND pid <> pg_backend_pid()"
                    ),
                    {"database_name": name},
                )
                connection.exec_driver_sql(f'DROP DATABASE IF EXISTS "{name}"')
            return True
        finally:
            engine.dispose()
    except Exception:
        return False


def run_v517_postgres_multiworker_acceptance(
    *,
    target_rows: int = 100_000,
    chunk_size: int = 1_000,
    workers: int = 2,
    synthetic: bool = False,
    sample_path: str | Path | None = None,
    run_detection_after: bool = False,
    test_recovery: bool = False,
    preflight_only: bool = False,
) -> dict[str, Any]:
    configured_settings = get_settings()
    configured_url = configured_settings.database_url
    target_url = os.environ.get("ATDR_V517_POSTGRES_DATABASE_URL", "").strip()
    restore_url = os.environ.get("ATDR_V517_RESTORE_DATABASE_URL", "").strip()
    private_path = Path(sample_path).expanduser() if sample_path else None
    marker_kind, marker_before = _configured_database_marker()

    if not (_MIN_TARGET_ROWS <= target_rows <= _MAX_TARGET_ROWS):
        return {
            **_base_result("invalid_target_rows"),
            "allowed_range": [_MIN_TARGET_ROWS, _MAX_TARGET_ROWS],
        }
    if not (1 <= chunk_size <= 100_000):
        return {
            **_base_result("invalid_chunk_size"),
            "allowed_range": [1, 100_000],
        }
    if not (2 <= workers <= _MAX_WORKERS):
        return {
            **_base_result("invalid_worker_count"),
            "allowed_range": [2, _MAX_WORKERS],
        }
    if synthetic == bool(sample_path):
        return {
            **_base_result("select_exactly_one_evidence_source"),
            "synthetic_or_sample_path_required": True,
        }

    preflight = _preflight(
        target_url=target_url,
        restore_url=restore_url,
        configured_url=configured_url,
        require_tools=not preflight_only,
    )
    if preflight_only:
        result = {
            **_base_result(preflight["status"], ok=preflight["ok"]),
            "executed": False,
            "preflight": preflight,
            "configured_database_marker_checked": marker_kind != "unavailable",
        }
        result["privacy_findings"] = _privacy_findings(
            result,
            private_path=private_path or Path("<synthetic>"),
        )
        return result
    if not preflight["ok"]:
        return {
            **_base_result("blocked_by_environment"),
            "executed": False,
            "preflight": preflight,
            "configured_database_marker_checked": marker_kind != "unavailable",
            "privacy_findings": [],
        }

    migration = _run_migrations(target_url)
    if not migration["ok"]:
        cleanup = {
            "restore_database_removed": _drop_disposable_database(restore_url),
            "target_database_removed": _drop_disposable_database(target_url),
        }
        marker_kind_after, marker_after = _configured_database_marker()
        configured_unchanged = (
            marker_kind == marker_kind_after and marker_before == marker_after
        )
        result = {
            **_base_result("migration_failed"),
            "executed": False,
            "preflight": preflight,
            "migration": migration,
            "configured_database_marker_checked": (
                marker_kind != "unavailable"
            ),
            "configured_database_unchanged": configured_unchanged,
            "configured_database_modified": not configured_unchanged,
            "cleanup": {
                **cleanup,
                "complete": all(cleanup.values()),
            },
        }
        result["privacy_findings"] = _privacy_findings(
            result,
            private_path=private_path or Path("<synthetic>"),
        )
        return result

    _STAGING_ROOT.mkdir(parents=True, exist_ok=True)
    _BACKUP_ROOT.mkdir(parents=True, exist_ok=True)
    target_settings = _target_settings(target_url, _STAGING_ROOT)
    engine: Engine | None = None
    factory: sessionmaker[Session] | None = None
    generated_paths: list[Path] = []
    cleanup = {
        "staging_removed": False,
        "backup_artifacts_removed": False,
        "target_database_removed": False,
        "restore_database_removed": False,
    }
    result: dict[str, Any] = {
        **_base_result("postgres_multiworker_acceptance_failed"),
        "executed": True,
        "preflight": preflight,
        "migration": migration,
        "target_rows": target_rows,
        "chunk_size": chunk_size,
        "workers": workers,
        "evidence_mode": "synthetic" if synthetic else "private_approved",
    }
    environment = {
        "DATABASE_URL": target_url,
        "AUTO_CREATE_TABLES": "false",
        "RESPONSE_SIMULATION": "true",
        "OPERATION_WORKER_ENABLED": "true",
        "OPERATION_WORKER_CONCURRENCY": str(workers),
        "OPERATION_WORKER_LEASE_SECONDS": "120",
        "OPERATION_STAGING_ROOT": str(_STAGING_ROOT.resolve()),
        "OPERATION_STAGING_SHARED": "true",
        "OPERATION_STAGING_STORAGE_ID": "v517-shared",
        "OPERATION_STAGING_MIN_FREE_BYTES": "0",
        "INGESTION_CHUNK_SIZE": str(chunk_size),
        "INGESTION_PROGRESS_UPDATE_INTERVAL": str(chunk_size),
    }
    try:
        with _temporary_environment(environment):
            lines = _safe_source_lines(
                synthetic=synthetic,
                sample_path=private_path,
            )
            engine = create_configured_engine(target_settings)
            factory = sessionmaker(
                bind=engine,
                autoflush=False,
                autocommit=False,
                future=True,
            )
            if inspect(engine).get_table_names() and not inspect(engine).has_table(
                "alembic_version"
            ):
                raise RuntimeError("Disposable target schema is not migration governed.")
            with factory() as db:
                application_rows = sum(
                    _count(db, model)
                    for model in (
                        RawLog,
                        NormalizedLog,
                        Alert,
                        ResponseAction,
                        MLLabel,
                        MLModelRun,
                    )
                )
                if application_rows:
                    raise RuntimeError("Disposable target database is not empty.")
                source = get_or_create_source(
                    db,
                    name="v517-shared-ingestion-source",
                    source_type="file_import",
                    parser_profile="palo_alto",
                )
                db.commit()
                source_id = int(source.id)
                safety_before = _safety_counts(db)
                size_before = int(
                    db.scalar(text("SELECT pg_database_size(current_database())"))
                    or 0
                )

            partition_counts = [
                target_rows // 2,
                target_rows - (target_rows // 2),
            ]
            for index, count in enumerate(partition_counts):
                path = _STAGING_ROOT / f"v517-part-{index}.log"
                _write_cycled_input(
                    path,
                    lines=lines,
                    count=count,
                    offset=sum(partition_counts[:index]),
                )
                generated_paths.append(path)
                with factory() as db:
                    _enqueue_import(
                        db,
                        path=path,
                        source_id=source_id,
                        actor="v517-validator",
                    )

            chunk_intervals: list[float] = []
            chunk_lock = Lock()
            last_chunk_at: dict[int, float] = {}

            def record_chunk(
                worker_index: int,
                _chunk_commits: int,
                _job: OperationJob,
            ) -> None:
                now = time.perf_counter()
                with chunk_lock:
                    previous = last_chunk_at.get(worker_index)
                    if previous is not None:
                        chunk_intervals.append(now - previous)
                    last_chunk_at[worker_index] = now

            gc.collect()
            memory_before = process_memory_snapshot()
            ingestion_started = time.perf_counter()
            import_results, pool_peak = _worker_batch(
                factory,
                workers=workers,
                after_chunk=record_chunk,
            )
            ingestion_seconds = time.perf_counter() - ingestion_started
            gc.collect()
            memory_after = process_memory_snapshot()

            with factory() as db:
                source = db.get(LogSource, source_id)
                raw_count = _count(db, RawLog)
                normalized_count = _count(db, NormalizedLog)
                parse_successes = int(source.parse_success_count or 0) if source else 0
                parse_failures = int(source.parse_failure_count or 0) if source else -1
                source_received = int(source.logs_received_count or 0) if source else -1
                completed_imports = int(
                    db.scalar(
                        select(func.count(OperationJob.id)).where(
                            OperationJob.job_type == "import_logs",
                            OperationJob.status == "completed",
                            OperationJob.requested_by == "v517-validator",
                        )
                    )
                    or 0
                )
                size_after_ingestion = int(
                    db.scalar(text("SELECT pg_database_size(current_database())"))
                    or 0
                )
            ingestion_ok = bool(
                completed_imports == 2
                and raw_count == normalized_count == source_received == target_rows
                and parse_successes + parse_failures == target_rows
                and all(item.get("ok") for item in import_results)
            )

            fencing = _validate_lease_fencing(factory)
            idempotency = _validate_idempotency(factory)
            recovery = (
                _validate_stale_recovery(factory)
                if test_recovery
                else {"ok": True, "status": "not_requested"}
            )

            cancel_path = _STAGING_ROOT / "v517-cancel-resume.log"
            cancel_rows = max(100, min(5_000, chunk_size * 5))
            _write_cycled_input(
                cancel_path,
                lines=lines,
                count=cancel_rows,
                offset=target_rows,
            )
            generated_paths.append(cancel_path)
            with factory() as db:
                cancel_source = get_or_create_source(
                    db,
                    name="v517-cancel-resume-source",
                    source_type="file_import",
                    parser_profile="palo_alto",
                )
                db.commit()
                cancel_source_id = int(cancel_source.id)
            cancel_resume = (
                _validate_cancel_resume(
                    factory,
                    path=cancel_path,
                    source_id=cancel_source_id,
                )
                if test_recovery
                else {"ok": True, "status": "not_requested"}
            )

            detection = (
                _detection_consistency(
                    factory,
                    source_id=source_id,
                    workers=workers,
                )
                if run_detection_after
                else {"ok": True, "status": "not_requested"}
            )
            with factory() as db:
                query_profile = _postgres_query_profile(
                    db,
                    source_id=source_id,
                )
                safety_after = _safety_counts(db)
                size_after = int(
                    db.scalar(text("SELECT pg_database_size(current_database())"))
                    or 0
                )
                migration_revision = db.scalar(
                    text("SELECT version_num FROM alembic_version")
                )

            backup = create_database_backup(
                settings=target_settings,
                output_dir=_BACKUP_ROOT,
                execute=True,
            )
            restore = {
                "ok": False,
                "status": "backup_failed",
            }
            if backup.get("ok"):
                restore = restore_database_backup(
                    settings=target_settings,
                    backup_path=str(backup["backup_path"]),
                    manifest_path=str(backup["manifest_path"]),
                    target_database_url=restore_url,
                    execute=True,
                    confirmed=True,
                )
            backup_summary = {
                "ok": bool(backup.get("ok")),
                "status": backup.get("status"),
                "checksum_recorded": bool(backup.get("sha256")),
                "migration_revision_recorded": bool(
                    backup.get("alembic_revision")
                ),
                "paths_returned": False,
            }
            restore_summary = {
                "ok": bool(restore.get("ok")),
                "status": restore.get("status"),
                "row_counts_match": bool(restore.get("row_counts_match")),
                "migration_revision_match": bool(
                    restore.get("migration_revision_match")
                ),
                "current_database_modified": bool(
                    restore.get("current_database_modified")
                ),
                "paths_returned": False,
            }
            safety_unchanged = safety_before == safety_after
            throughput = (
                round(target_rows / ingestion_seconds, 2)
                if ingestion_seconds > 0
                else None
            )
            result.update(
                {
                    "ingestion": {
                        "ok": ingestion_ok,
                        "workers_completed": sum(
                            1 for item in import_results if item.get("processed")
                        ),
                        "distinct_job_claims": len(
                            {
                                (item.get("job") or {}).get("id")
                                for item in import_results
                                if (item.get("job") or {}).get("id") is not None
                            }
                        )
                        == 2,
                        "raw_logs": raw_count,
                        "normalized_logs": normalized_count,
                        "source_counter": source_received,
                        "parse_successes": parse_successes,
                        "parse_failures": parse_failures,
                        "rows_per_second": throughput,
                        "runtime_seconds": round(ingestion_seconds, 4),
                        "chunk_commit_interval_seconds": {
                            "p50": _percentile(chunk_intervals, 0.50),
                            "p95": _percentile(chunk_intervals, 0.95),
                            "p99": _percentile(chunk_intervals, 0.99),
                            "samples": len(chunk_intervals),
                        },
                    },
                    "pool": {
                        "configured_size": target_settings.db_pool_size,
                        "configured_max_overflow": (
                            target_settings.db_max_overflow
                        ),
                        "configured_timeout_seconds": (
                            target_settings.db_pool_timeout_seconds
                        ),
                        "peak_checked_out": pool_peak["checked_out"],
                        "peak_overflow": pool_peak["overflow"],
                        "timeout_errors": 0,
                    },
                    "memory": {
                        "before": memory_before,
                        "after": memory_after,
                    },
                    "database": {
                        "growth_bytes": max(0, size_after - size_before),
                        "ingestion_growth_bytes": max(
                            0,
                            size_after_ingestion - size_before,
                        ),
                        "migration_revision_present": bool(migration_revision),
                    },
                    "lease_fencing": fencing,
                    "idempotency": idempotency,
                    "stale_recovery": recovery,
                    "cancellation_resume": cancel_resume,
                    "detection": detection,
                    "queries": query_profile,
                    "backup": backup_summary,
                    "restore": restore_summary,
                    "safety_counts_before": safety_before,
                    "safety_counts_after": safety_after,
                    "safety_counts_unchanged": safety_unchanged,
                }
            )
            passed = all(
                (
                    ingestion_ok,
                    fencing["ok"],
                    idempotency["ok"],
                    recovery["ok"],
                    cancel_resume["ok"],
                    detection["ok"],
                    safety_unchanged,
                    backup_summary["ok"],
                    restore_summary["ok"],
                )
            )
            result["ok"] = passed
            result["status"] = (
                "postgres_multiworker_acceptance_passed"
                if passed
                else "postgres_multiworker_acceptance_failed"
            )
    except Exception as exc:
        result.update(
            {
                "ok": False,
                "status": "postgres_multiworker_acceptance_failed",
                "error_type": exc.__class__.__name__,
            }
        )
    finally:
        if engine is not None:
            engine.dispose()
        for path in generated_paths:
            path.unlink(missing_ok=True)
        shutil.rmtree(_STAGING_ROOT, ignore_errors=True)
        cleanup["staging_removed"] = not _STAGING_ROOT.exists()
        shutil.rmtree(_BACKUP_ROOT, ignore_errors=True)
        cleanup["backup_artifacts_removed"] = not _BACKUP_ROOT.exists()
        cleanup["restore_database_removed"] = _drop_disposable_database(
            restore_url
        )
        cleanup["target_database_removed"] = _drop_disposable_database(
            target_url
        )
        marker_kind_after, marker_after = _configured_database_marker()
        configured_unchanged = (
            marker_kind == marker_kind_after and marker_before == marker_after
        )
        result["configured_database_marker_checked"] = (
            marker_kind != "unavailable"
        )
        result["configured_database_unchanged"] = configured_unchanged
        result["configured_database_modified"] = not configured_unchanged
        result["cleanup"] = {
            **cleanup,
            "complete": all(cleanup.values()),
        }
        if not configured_unchanged or not result["cleanup"]["complete"]:
            result["ok"] = False
            result["status"] = "postgres_multiworker_acceptance_failed"

    privacy_findings = _privacy_findings(
        result,
        private_path=private_path or Path("<synthetic>"),
    )
    result["privacy_findings"] = privacy_findings
    if privacy_findings:
        result["ok"] = False
        result["status"] = "privacy_validation_failed"
    return result
