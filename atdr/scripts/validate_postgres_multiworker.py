from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from io import BytesIO
import json
from pathlib import Path
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session, sessionmaker

from atdr.app.core.config import PROJECT_ROOT, Settings, get_settings
from atdr.app.db.engine import create_configured_engine, database_kind
from atdr.app.db.models import (
    MLLabel,
    MLModelRun,
    NormalizedLog,
    OperationJob,
    RawLog,
    ResponseAction,
)
from atdr.app.services.job_service import (
    claim_next_job,
    complete_queued_job,
    enqueue_job,
    recover_expired_leases,
)
from atdr.app.services.operation_worker import run_worker_once
from atdr.app.services.source_service import get_or_create_source
from atdr.app.services.staging_service import stage_upload_for_job, staged_payload_fields


CONFIRMATION = "ISOLATED_V394_POSTGRES"


def _count(db: Session, model) -> int:
    return int(db.scalar(select(func.count(model.id))) or 0)


def _complete_claim(db: Session, job: OperationJob, worker_id: str) -> int:
    completed = complete_queued_job(
        db,
        job_id=job.id,
        worker_id=worker_id,
        lease_token=str(job.lease_token),
        result_summary={"status": "validation_only"},
    )
    return int(completed.id)


def _claim_and_complete(factory: sessionmaker[Session], worker_id: str) -> int | None:
    with factory() as db:
        job = claim_next_job(db, worker_id=worker_id, lease_seconds=60)
        return _complete_claim(db, job, worker_id) if job is not None else None


def _safety_counts(db: Session) -> dict[str, int]:
    return {
        "response_actions": _count(db, ResponseAction),
        "ml_labels": _count(db, MLLabel),
        "ml_model_runs": _count(db, MLModelRun),
    }


def _enqueue_import(db: Session, *, staged, source_id: int, actor: str) -> int:
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
        details={"input_name": staged.safe_name, "validation": "v3.94"},
        progress_total=staged.available_lines,
        input_size_bytes=staged.byte_count,
        input_fingerprint=staged.fingerprint,
        resume_expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        staging_storage_id=staged.storage_id,
    )
    return int(job.id)


def validate_postgres_multiworker(
    *,
    settings: Settings | None = None,
    execute: bool = False,
    confirmed: bool = False,
) -> dict[str, Any]:
    effective = settings or Settings()
    dialect = database_kind(effective.database_url)
    database_name = (make_url(effective.database_url).database or "").lower() if dialect == "postgresql" else ""
    isolated_name = any(marker in database_name for marker in ("v394", "test", "ci"))
    base = {
        "dialect": dialect,
        "isolated_database_name_accepted": isolated_name,
        "shared_staging": effective.operation_staging_shared,
        "staging_storage_id_configured": bool(effective.operation_staging_storage_id.strip()),
        "response_automation_allowed": False,
        "model_activation_performed": False,
        "secrets_exposed": False,
        "production_ready": False,
    }
    if not execute:
        return {
            **base,
            "ok": True,
            "status": "dry_run",
            "executed": False,
            "required_confirmation": CONFIRMATION,
        }
    if not confirmed:
        return {**base, "ok": False, "status": "confirmation_required", "executed": False}
    if dialect != "postgresql" or not isolated_name:
        return {**base, "ok": False, "status": "isolated_postgres_required", "executed": False}
    if not effective.operation_staging_shared:
        return {**base, "ok": False, "status": "shared_staging_required", "executed": False}

    engine = create_configured_engine(effective)
    factory = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
    actor = "v394-postgres-validator"
    try:
        with factory() as db:
            safety_before = _safety_counts(db)
            first, _ = enqueue_job(db, job_type="validation", requested_by=actor, payload={})
            first_id = int(first.id)
            second, _ = enqueue_job(db, job_type="validation", requested_by=actor, payload={})
            second_id = int(second.id)

        lock_session = factory()
        try:
            lock_session.scalar(select(OperationJob).where(OperationJob.id == first_id).with_for_update())
            with factory() as db:
                skipped_locked = claim_next_job(db, worker_id="v394-skip-locked", lease_seconds=60)
                if skipped_locked is None:
                    raise RuntimeError("SKIP LOCKED validation could not claim the second queued job.")
                skipped_locked_id = _complete_claim(db, skipped_locked, "v394-skip-locked")
            lock_session.rollback()
        finally:
            lock_session.close()
        with factory() as db:
            unlocked = claim_next_job(db, worker_id="v394-unlocked", lease_seconds=60)
            if unlocked is None:
                raise RuntimeError("Previously locked job was not claimable after rollback.")
            unlocked_id = _complete_claim(db, unlocked, "v394-unlocked")

        with factory() as db:
            concurrent_job_ids = [
                enqueue_job(db, job_type="validation", requested_by=actor, payload={})[0].id
                for _ in range(12)
            ]
        with ThreadPoolExecutor(max_workers=4) as executor:
            claimed_ids = list(
                executor.map(
                    lambda index: _claim_and_complete(factory, f"v394-claim-{index}"),
                    range(12),
                )
            )
        claimed_clean = [value for value in claimed_ids if value is not None]

        expired_ids: list[int] = []
        with factory() as db:
            expired_at = datetime.now(timezone.utc) - timedelta(minutes=1)
            for index in range(8):
                job = OperationJob(
                    job_type="validation",
                    status="running",
                    requested_by=actor,
                    progress_current=0,
                    progress_total=1,
                    attempt_count=1,
                    max_attempts=1,
                    payload_json={},
                    result_summary_json={},
                    details_json={},
                    lease_owner=f"expired-{index}",
                    lease_token=f"expired-token-{index}",
                    claim_generation=1,
                    lease_expires_at=expired_at,
                )
                db.add(job)
                db.flush()
                expired_ids.append(int(job.id))
            db.commit()

        def recover_batch(_index: int) -> list[int]:
            with factory() as db:
                return [
                    int(job.id)
                    for job in recover_expired_leases(db, retry_delay_seconds=1, limit=4)
                    if int(job.id) in expired_ids
                ]

        with ThreadPoolExecutor(max_workers=2) as executor:
            recovered_batches = list(executor.map(recover_batch, range(2)))
        recovered_ids = [job_id for batch in recovered_batches for job_id in batch]

        sample_lines = [
            line
            for line in (PROJECT_ROOT / "data" / "samples" / "scenarios" / "normal_allowed_traffic.txt")
            .read_text(encoding="utf-8")
            .splitlines()
            if line.strip()
        ][:4]
        if len(sample_lines) < 4:
            raise RuntimeError("Safe validation sample does not contain four records.")

        def create_shared_source(_index: int) -> int:
            with factory() as db:
                source = get_or_create_source(
                    db,
                    name="v394-shared-source",
                    source_type="file_import",
                    parser_profile="palo_alto",
                )
                db.commit()
                db.refresh(source)
                return int(source.id)

        with ThreadPoolExecutor(max_workers=2) as executor:
            source_creation_ids = list(executor.map(create_shared_source, range(2)))
        source_creation_race_safe = len(set(source_creation_ids)) == 1

        staged_a = stage_upload_for_job(BytesIO(("\n".join(sample_lines[:2]) + "\n").encode()), filename="v394-a.log")
        staged_b = stage_upload_for_job(BytesIO(("\n".join(sample_lines[2:4]) + "\n").encode()), filename="v394-b.log")
        with factory() as db:
            source_id = source_creation_ids[0]
            source = get_or_create_source(db, source_id=source_id)
            source_before = int(source.logs_received_count)
            raw_before = _count(db, RawLog)
            normalized_before = _count(db, NormalizedLog)
            import_ids = [
                _enqueue_import(db, staged=staged_a, source_id=source_id, actor=actor),
                _enqueue_import(db, staged=staged_b, source_id=source_id, actor=actor),
            ]

        def run_import(index: int) -> dict[str, Any]:
            with factory() as db:
                return run_worker_once(db, worker_id=f"v394-import-{index}")

        with ThreadPoolExecutor(max_workers=2) as executor:
            import_results = list(executor.map(run_import, range(2)))

        with factory() as db:
            imported_jobs = [db.get(OperationJob, job_id) for job_id in import_ids]
            source = get_or_create_source(db, source_id=source_id)
            raw_delta = _count(db, RawLog) - raw_before
            normalized_delta = _count(db, NormalizedLog) - normalized_before
            source_delta = int(source.logs_received_count) - source_before
            safety_after = _safety_counts(db)

        unique_claims = len(claimed_clean) == len(set(claimed_clean)) == len(concurrent_job_ids)
        recovery_unique = len(recovered_ids) == len(set(recovered_ids)) == len(expired_ids)
        imports_completed = all(job is not None and job.status == "completed" for job in imported_jobs)
        import_counts_ok = raw_delta == normalized_delta == source_delta == 4
        safety_unchanged = safety_before == safety_after
        ok = all(
            [
                skipped_locked_id == second_id,
                unlocked_id == first_id,
                unique_claims,
                recovery_unique,
                source_creation_race_safe,
                imports_completed,
                import_counts_ok,
                safety_unchanged,
                all(result.get("ok") for result in import_results),
            ]
        )
        return {
            **base,
            "ok": ok,
            "status": "postgres_multiworker_validated" if ok else "postgres_multiworker_failed",
            "executed": True,
            "skip_locked_claim_order_valid": skipped_locked_id == second_id and unlocked_id == first_id,
            "concurrent_claim_count": len(claimed_clean),
            "concurrent_claims_unique": unique_claims,
            "expired_lease_count": len(expired_ids),
            "expired_lease_recovery_unique": recovery_unique,
            "concurrent_source_creation_safe": source_creation_race_safe,
            "parallel_import_jobs_completed": imports_completed,
            "parallel_import_raw_delta": raw_delta,
            "parallel_import_normalized_delta": normalized_delta,
            "parallel_import_source_counter_delta": source_delta,
            "safety_counts_unchanged": safety_unchanged,
        }
    except Exception as exc:
        return {
            **base,
            "ok": False,
            "status": "postgres_multiworker_failed",
            "executed": True,
            "error_type": exc.__class__.__name__,
        }
    finally:
        engine.dispose()


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate ATDR PostgreSQL multi-worker behavior on an isolated DB.")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--confirm", default="")
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()
    get_settings.cache_clear()
    result = validate_postgres_multiworker(
        execute=args.execute,
        confirmed=args.confirm == CONFIRMATION,
    )
    print(json.dumps(result, indent=2 if args.pretty else None, default=str))
    raise SystemExit(0 if result.get("ok") else 1)


if __name__ == "__main__":
    main()
