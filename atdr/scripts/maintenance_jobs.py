import argparse
import json
from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from atdr.app.core.config import get_settings
from atdr.app.db.database import SessionLocal, init_db
from atdr.app.services.job_service import (
    build_job_summary,
    cleanup_terminal_jobs,
    job_to_dict,
    list_cleanup_candidates,
    list_stale_jobs,
    mark_jobs_stale,
)


def _json_default(value: Any) -> str:
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def _preview_jobs(jobs: list[Any]) -> list[dict[str, Any]]:
    return [
        {
            "job_id": job.id,
            "job_type": job.job_type,
            "status": job.status,
            "requested_by": job.requested_by,
            "started_at": job.started_at,
            "updated_at": job.updated_at,
            "created_at": job.created_at,
            "error_summary": job.error_summary,
        }
        for job in jobs
    ]


def run_maintenance_jobs(
    db: Session | None = None,
    *,
    dry_run: bool = True,
    mark_stale_jobs: bool = False,
    cleanup_completed_jobs: bool = False,
    stale_after_minutes: int | None = None,
    older_than_days: int | None = None,
    limit: int = 100,
    actor: str = "maintenance_jobs",
) -> dict[str, Any]:
    settings = get_settings()
    effective_stale_after = stale_after_minutes or settings.job_stale_after_minutes
    effective_older_than = older_than_days or settings.job_retention_days
    effective_limit = max(1, int(limit))

    owns_session = db is None
    if owns_session:
        init_db()
        db = SessionLocal()
    assert db is not None

    try:
        summary_before = build_job_summary(
            db,
            stale_after_minutes=effective_stale_after,
            job_retention_days=settings.job_retention_days,
            run_history_retention_days=settings.run_history_retention_days,
        )
        stale_candidates = list_stale_jobs(
            db,
            stale_after_minutes=effective_stale_after,
            limit=effective_limit,
        )
        cleanup_candidates = list_cleanup_candidates(
            db,
            older_than_days=effective_older_than,
            limit=effective_limit,
        )

        marked_jobs = []
        deleted_count = 0
        if not dry_run and mark_stale_jobs:
            marked_jobs = mark_jobs_stale(
                db,
                stale_candidates,
                actor=actor,
                stale_after_minutes=effective_stale_after,
            )
        if not dry_run and cleanup_completed_jobs:
            deleted_count = cleanup_terminal_jobs(db, cleanup_candidates)

        summary_after = build_job_summary(
            db,
            stale_after_minutes=effective_stale_after,
            job_retention_days=settings.job_retention_days,
            run_history_retention_days=settings.run_history_retention_days,
        )
        return {
            "ok": True,
            "dry_run": dry_run,
            "mutated": not dry_run and (mark_stale_jobs or cleanup_completed_jobs),
            "actions_requested": {
                "mark_stale_jobs": mark_stale_jobs,
                "cleanup_completed_jobs": cleanup_completed_jobs,
            },
            "policy": {
                "job_stale_after_minutes": effective_stale_after,
                "job_retention_days": settings.job_retention_days,
                "run_history_retention_days": settings.run_history_retention_days,
                "cleanup_older_than_days": effective_older_than,
                "limit": effective_limit,
                "automatic_cleanup_enabled": False,
                "raw_evidence_cleanup_enabled": False,
            },
            "summary_before": summary_before,
            "stale_candidates": _preview_jobs(stale_candidates),
            "cleanup_candidates": _preview_jobs(cleanup_candidates),
            "marked_stale_jobs": [job_to_dict(job) for job in marked_jobs],
            "deleted_operation_jobs": deleted_count,
            "protected_tables": [
                "raw_logs",
                "normalized_logs",
                "alerts",
                "alert_evidence",
                "audit_logs",
                "ml_labels",
                "response_actions",
                "ingestion_runs",
                "detection_runs",
            ],
            "summary_after": summary_after,
            "warnings": [
                "Dry-run is the default; pass --execute with an explicit action to mutate operation job records.",
                "Cleanup only targets operation_jobs terminal history. Raw logs, alerts, labels, audit records, and run history are never deleted by this command.",
            ],
        }
    finally:
        if owns_session:
            db.close()


def main() -> None:
    settings = get_settings()
    parser = argparse.ArgumentParser(description="Preview or apply safe ATDR operation job maintenance.")
    parser.add_argument("--dry-run", action="store_true", default=True, help="Preview only. This is the default.")
    parser.add_argument("--execute", action="store_false", dest="dry_run", help="Apply explicit maintenance actions.")
    parser.add_argument("--mark-stale-jobs", action="store_true", help="Mark stale active jobs as failed.")
    parser.add_argument("--cleanup-completed-jobs", action="store_true", help="Delete old terminal operation job history only.")
    parser.add_argument("--older-than-days", type=int, default=settings.job_retention_days)
    parser.add_argument("--stale-after-minutes", type=int, default=settings.job_stale_after_minutes)
    parser.add_argument("--limit", type=int, default=100)
    parser.add_argument("--actor", default="maintenance_jobs")
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()

    result = run_maintenance_jobs(
        dry_run=args.dry_run,
        mark_stale_jobs=args.mark_stale_jobs,
        cleanup_completed_jobs=args.cleanup_completed_jobs,
        stale_after_minutes=args.stale_after_minutes,
        older_than_days=args.older_than_days,
        limit=args.limit,
        actor=args.actor,
    )
    print(json.dumps(result, default=_json_default, indent=2 if args.pretty else None))
    raise SystemExit(0 if result.get("ok") else 1)


if __name__ == "__main__":
    main()
