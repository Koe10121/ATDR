from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from atdr.app.db.models import OperationJob
from atdr.app.services.job_service import ACTIVE_JOB_STATUSES, resume_eligibility
from atdr.app.services.staging_service import STAGING_ROOT, configured_staging_root, staged_path


def _utc_mtime(path: Path) -> datetime:
    return datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)


def build_staged_cleanup_plan(db: Session, *, retention_hours: int) -> dict[str, Any]:
    """List only expired, unreferenced staged files; raw evidence tables are never queried or changed."""

    cutoff = datetime.now(timezone.utc) - timedelta(hours=max(1, int(retention_hours)))
    protected: set[Path] = set()
    jobs = list(
        db.scalars(
            select(OperationJob).where(OperationJob.job_type.in_({"import_logs", "replay_logs"}))
        )
    )
    for job in jobs:
        payload = dict(job.payload_json or {})
        try:
            path = staged_path(payload, require_exists=False)
        except ValueError:
            continue
        resumable, _ = resume_eligibility(job)
        if job.status in ACTIVE_JOB_STATUSES or resumable:
            protected.add(path)

    candidates: list[dict[str, Any]] = []
    staging_root = configured_staging_root()
    if staging_root.exists():
        for path in staging_root.iterdir():
            if not path.is_file() or path.is_symlink() or path.resolve() in protected:
                continue
            try:
                modified_at = _utc_mtime(path)
                byte_count = path.stat().st_size
            except OSError:
                continue
            if modified_at > cutoff:
                continue
            candidates.append(
                {
                    "safe_name": path.name.split("-", 1)[-1][:120],
                    "byte_count": byte_count,
                    "modified_at": modified_at.isoformat(),
                    "_path": path,
                }
            )
    return {
        "dry_run": True,
        "retention_hours": max(1, int(retention_hours)),
        "candidate_count": len(candidates),
        "candidate_bytes": sum(int(item["byte_count"]) for item in candidates),
        "protected_count": len(protected),
        "candidates": candidates,
        "raw_evidence_deleted": 0,
    }


def apply_staged_cleanup(plan: dict[str, Any]) -> dict[str, Any]:
    deleted = 0
    deleted_bytes = 0
    for item in list(plan.get("candidates") or []):
        path = item.get("_path")
        if not isinstance(path, Path) or not path.exists() or not path.is_file() or path.is_symlink():
            continue
        deleted_bytes += path.stat().st_size
        path.unlink()
        deleted += 1
    return {
        **public_cleanup_plan(plan),
        "dry_run": False,
        "deleted_count": deleted,
        "deleted_bytes": deleted_bytes,
        "raw_evidence_deleted": 0,
    }


def public_cleanup_plan(plan: dict[str, Any]) -> dict[str, Any]:
    return {
        key: (
            [{public_key: public_value for public_key, public_value in item.items() if public_key != "_path"} for item in value]
            if key == "candidates" and isinstance(value, list)
            else value
        )
        for key, value in plan.items()
        if key != "_path"
    }
