from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from atdr.app.core.config import Settings, validate_runtime_settings
from atdr.app.db.database import check_database_connection
from atdr.app.services.job_service import build_job_summary


def build_readiness(db: Session, settings: Settings) -> tuple[dict[str, Any], bool]:
    database = check_database_connection(db)
    configuration_issues = validate_runtime_settings(settings)
    migration_status = (database.get("migration") or {}).get("status")
    ready = database.get("status") == "ok" and migration_status == "at_head" and not configuration_issues
    payload = {
        "status": "ready" if ready else "not_ready",
        "service": settings.app_name,
        "version": settings.service_version,
        "checks": {
            "database": {
                "status": database.get("status"),
                "dialect": database.get("dialect"),
                "detail": database.get("detail"),
            },
            "migration": database.get("migration", {"status": "unavailable"}),
            "configuration": {
                "status": "ok" if not configuration_issues else "error",
                "issue_count": len(configuration_issues),
            },
        },
        "secrets_exposed": False,
    }
    return payload, ready


def build_operations_health(db: Session, settings: Settings) -> dict[str, Any]:
    database = check_database_connection(db)
    configuration_issues = validate_runtime_settings(settings)
    jobs = build_job_summary(
        db,
        stale_after_minutes=settings.job_stale_after_minutes,
        job_retention_days=settings.job_retention_days,
        run_history_retention_days=settings.run_history_retention_days,
        worker_enabled=settings.operation_worker_enabled,
        worker_heartbeat_seconds=settings.operation_worker_heartbeat_seconds,
        queue_backlog_warning=settings.operation_queue_backlog_warning,
        job_failure_warning_count=settings.operation_job_failure_warning_count,
        job_failure_warning_window_minutes=settings.operation_job_failure_warning_window_minutes,
        database_check=database,
        runtime_issue_count=len(configuration_issues),
        response_simulation=settings.response_simulation,
    )
    return {
        "status": jobs["health_status"],
        "database": database,
        "configuration": {
            "status": "ok" if not configuration_issues else "error",
            "issue_count": len(configuration_issues),
        },
        "jobs": jobs,
        "response_safety": {
            "simulation_enabled": settings.response_simulation,
            "automatic_response_enabled": False,
            "real_firewall_blocking_enabled": False,
        },
        "secrets_exposed": False,
    }
