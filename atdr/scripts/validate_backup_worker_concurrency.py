from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session

from atdr.app.core.config import PROJECT_ROOT, Settings
from atdr.app.db.engine import create_configured_engine, database_kind
from atdr.app.db.models import MLLabel, MLModelRun, OperationJob, ResponseAction
from atdr.app.services.persistence_service import create_database_backup, restore_database_backup


CONFIRMATION = "ISOLATED_V394_BACKUP_DATABASES"


def _safe_isolated_postgres(database_url: str) -> bool:
    if database_kind(database_url) != "postgresql":
        return False
    database = (make_url(database_url).database or "").lower()
    return any(marker in database for marker in ("v394", "test", "ci"))


def _count(db: Session, model) -> int:
    return int(db.scalar(select(func.count(model.id))) or 0)


def validate_backup_worker_concurrency(
    *,
    source_url: str,
    restore_url: str,
    execute: bool = False,
    confirmed: bool = False,
    output_dir: str | Path = ".tmp/v394-backup-concurrency",
) -> dict[str, Any]:
    safe_targets = _safe_isolated_postgres(source_url) and _safe_isolated_postgres(restore_url)
    base = {
        "safe_isolated_targets": safe_targets,
        "source_and_restore_are_distinct": source_url != restore_url,
        "current_database_modified": False,
        "response_automation_allowed": False,
        "model_activation_performed": False,
        "secrets_exposed": False,
        "production_ready": False,
    }
    if not execute:
        return {**base, "ok": True, "status": "dry_run", "executed": False}
    if not confirmed:
        return {**base, "ok": False, "status": "confirmation_required", "executed": False}
    if not safe_targets or source_url == restore_url:
        return {**base, "ok": False, "status": "isolated_postgres_required", "executed": False}

    settings = Settings(DATABASE_URL=source_url, AUTO_CREATE_TABLES=False, RESPONSE_SIMULATION=True)
    engine = create_configured_engine(settings)
    try:
        with Session(engine) as db:
            safety_before = {
                "response_actions": _count(db, ResponseAction),
                "ml_labels": _count(db, MLLabel),
                "ml_model_runs": _count(db, MLModelRun),
            }
            active_job = OperationJob(
                job_type="import_logs",
                status="running",
                requested_by="v394-backup-validator",
                progress_current=0,
                progress_total=1,
                payload_json={},
                result_summary_json={},
                details_json={},
                attempt_count=1,
                max_attempts=1,
                lease_owner="v394-active-worker",
                lease_token="v394-active-lease",
                claim_generation=1,
                lease_expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
            )
            db.add(active_job)
            db.commit()
            active_job_id = int(active_job.id)

        blocked = create_database_backup(settings=settings, output_dir=output_dir, execute=True)
        with Session(engine) as db:
            active_job = db.get(OperationJob, active_job_id)
            if active_job is None:
                raise RuntimeError("Backup validation operation job disappeared.")
            active_job.status = "failed"
            active_job.finished_at = datetime.now(timezone.utc)
            active_job.lease_owner = None
            active_job.lease_token = None
            active_job.lease_expires_at = None
            active_job.error_summary = "Controlled backup quiesce validation marker."
            db.commit()

        backup = create_database_backup(settings=settings, output_dir=output_dir, execute=True)
        if not backup.get("ok"):
            return {
                **base,
                "ok": False,
                "status": "backup_after_drain_failed",
                "active_job_guard_status": blocked.get("status"),
                "backup_status": backup.get("status"),
                "executed": True,
            }
        restore = restore_database_backup(
            settings=settings,
            backup_path=backup["backup_path"],
            manifest_path=backup["manifest_path"],
            target_database_url=restore_url,
            execute=True,
            confirmed=True,
        )
        with Session(engine) as db:
            safety_after = {
                "response_actions": _count(db, ResponseAction),
                "ml_labels": _count(db, MLLabel),
                "ml_model_runs": _count(db, MLModelRun),
            }
        guard_ok = blocked.get("status") == "active_mutating_jobs" and blocked.get("active_mutating_jobs") == 1
        restore_ok = bool(
            restore.get("ok")
            and restore.get("row_counts_match")
            and restore.get("migration_revision_match")
        )
        safety_unchanged = safety_before == safety_after
        ok = guard_ok and restore_ok and safety_unchanged
        return {
            **base,
            "ok": ok,
            "status": "backup_worker_concurrency_validated" if ok else "backup_worker_concurrency_failed",
            "executed": True,
            "active_job_guard_valid": guard_ok,
            "backup_after_drain_created": bool(backup.get("ok")),
            "restore_validated": restore_ok,
            "row_counts_match": bool(restore.get("row_counts_match")),
            "migration_revision_match": bool(restore.get("migration_revision_match")),
            "safety_counts_unchanged": safety_unchanged,
        }
    except Exception as exc:
        return {
            **base,
            "ok": False,
            "status": "backup_worker_concurrency_failed",
            "executed": True,
            "error_type": exc.__class__.__name__,
        }
    finally:
        engine.dispose()


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate PostgreSQL backup behavior around ATDR operation workers.")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--confirm", default="")
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()
    result = validate_backup_worker_concurrency(
        source_url=os.environ.get("ATDR_V394_BACKUP_SOURCE_DATABASE_URL", ""),
        restore_url=os.environ.get("ATDR_V394_BACKUP_RESTORE_DATABASE_URL", ""),
        execute=args.execute,
        confirmed=args.confirm == CONFIRMATION,
        output_dir=PROJECT_ROOT / ".tmp" / "v394-backup-concurrency",
    )
    print(json.dumps(result, indent=2 if args.pretty else None, default=str))
    raise SystemExit(0 if result.get("ok") else 1)


if __name__ == "__main__":
    main()
