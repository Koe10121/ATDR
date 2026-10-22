"""What ATDR keeps only for a set time is deleted once that time has passed.

The periods were settings, and code to apply them existed, but only commands run by hand used it, so nothing was
ever deleted (found 22 October 2026). The background worker now runs this every hour:

- audit entries older than AUDIT_RETENTION_DAYS (365), never a sign-in, access, response or blocking record;
- finished operation jobs older than JOB_RETENTION_DAYS (30), but not one that a later job resumed or repeats;
- staged copies of imported files older than OPERATION_STAGING_RETENTION_HOURS (24) that no job still needs.

Each pass deletes only what is past its time, in batches, so it costs little when nothing is.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import select, union
from sqlalchemy.orm import Session

from atdr.app.core.config import Settings
from atdr.app.db.models import AuditLog, OperationJob
from atdr.app.services.audit_retention_service import (
    APPLY_CONFIRMATION,
    apply_audit_retention,
    build_audit_retention_report,
)
from atdr.app.services.job_service import cleanup_terminal_jobs, list_cleanup_candidates
from atdr.app.services.staged_input_retention_service import apply_staged_cleanup, build_staged_cleanup_plan

HOUSEKEEPING_LOOK_SECONDS = 3600
JOBS_PER_PASS = 100
ACTOR = "housekeeping"


def _jobs_past_their_time(db: Session, *, retention_days: int) -> list[OperationJob]:
    """Finished jobs older than the period, without one another job names as the job it resumed or repeats."""

    named = set(
        db.scalars(
            union(
                select(OperationJob.resume_of_job_id).where(OperationJob.resume_of_job_id.is_not(None)),
                select(OperationJob.original_job_id).where(OperationJob.original_job_id.is_not(None)),
            )
        )
    )
    return [job for job in list_cleanup_candidates(db, older_than_days=retention_days, limit=JOBS_PER_PASS) if job.id not in named]


def run_housekeeping(db: Session, *, settings: Settings) -> dict[str, Any]:
    done: dict[str, Any] = {"audit_entries": 0, "jobs": 0, "staged_files": 0, "staged_bytes": 0}
    policy = {
        "retention_days": int(settings.audit_retention_days),
        "minimum_days": int(settings.audit_retention_min_days),
        "batch_size": int(settings.audit_retention_batch_size),
    }
    if build_audit_retention_report(db, **policy)["eligible_event_count"]:
        # The audit entry saying how many were deleted is written by apply_audit_retention itself.
        done["audit_entries"] = apply_audit_retention(db, **policy, confirmation=APPLY_CONFIRMATION, actor=ACTOR)["deleted_count"]

    jobs = _jobs_past_their_time(db, retention_days=int(settings.job_retention_days))
    if jobs:
        done["jobs"] = cleanup_terminal_jobs(db, jobs)

    plan = build_staged_cleanup_plan(db, retention_hours=int(settings.operation_staging_retention_hours))
    if plan["candidate_count"]:
        staged = apply_staged_cleanup(plan)
        done["staged_files"], done["staged_bytes"] = staged["deleted_count"], staged["deleted_bytes"]

    if done["jobs"] or done["staged_files"]:
        db.add(
            AuditLog(
                actor=ACTOR,
                action="housekeeping_applied",
                target_type="system",
                target_value="retention",
                details={
                    "jobs_deleted": done["jobs"],
                    "job_retention_days": int(settings.job_retention_days),
                    "staged_files_deleted": done["staged_files"],
                    "staged_bytes_deleted": done["staged_bytes"],
                    "staging_retention_hours": int(settings.operation_staging_retention_hours),
                },
            )
        )
        db.commit()
    return done
