import argparse
import json
from datetime import datetime
from typing import Any

from sqlalchemy import func, select

from atdr.app.core.config import Settings
from atdr.app.db.database import SessionLocal, check_database_connection
from atdr.app.db.models import Alert, AuditLog, DetectionRun, IngestionRun, LogSource, NormalizedLog, RawLog, ResponseAction
from atdr.app.services.operation_run_service import detection_run_to_dict, ingestion_run_to_dict
from atdr.app.services.source_service import source_health
from atdr.scripts.profile_dashboard_summary import profile_dashboard_summary
from atdr.scripts.production_readiness_doctor import run_production_readiness_doctor
from atdr.scripts.run_backup_restore_drill import run_backup_restore_drill
from atdr.scripts.run_postgres_lab_validation import run_postgres_lab_validation
from atdr.scripts.run_v35_real_source_pilot_check import run_v35_real_source_pilot_check


REAL_SOURCE_PILOT_CHECKLIST = [
    "source registered and enabled",
    "logs received from the source",
    "raw logs preserved and source-linked",
    "normalized logs created and source-linked",
    "parser profile selected and parser errors visible",
    "source health updated",
    "source-scoped detection run completed",
    "alerts and cases trace back to source evidence",
    "no automatic response actions created",
    "response mode remains simulation",
]


def _json_default(value: Any) -> str:
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def _rate(numerator: int, denominator: int) -> float:
    return round((numerator / denominator) * 100, 4) if denominator else 0.0


def _latest_or_none(rows: list[Any]) -> Any | None:
    return rows[0] if rows else None


def operations_readiness_report() -> dict[str, Any]:
    """Read-only operational readiness snapshot for shared-lab preparation."""

    with SessionLocal() as db:
        db_health = check_database_connection(db)
        raw_logs = int(db.scalar(select(func.count(RawLog.id))) or 0)
        normalized_logs = int(db.scalar(select(func.count(NormalizedLog.id))) or 0)
        alert_count = int(db.scalar(select(func.count(Alert.id))) or 0)
        response_actions = int(db.scalar(select(func.count(ResponseAction.id))) or 0)
        non_simulated_response_actions = int(
            db.scalar(select(func.count(ResponseAction.id)).where(ResponseAction.status.notin_(["simulated", "denied"]))) or 0
        )
        audit_events = int(db.scalar(select(func.count(AuditLog.id))) or 0)
        parse_failures = int(db.scalar(select(func.coalesce(func.sum(IngestionRun.parse_failures), 0))) or 0)
        parse_success = int(db.scalar(select(func.coalesce(func.sum(IngestionRun.parsed_successfully), 0))) or 0)
        latest_ingestion_runs = list(db.scalars(select(IngestionRun).order_by(IngestionRun.started_at.desc()).limit(3)))
        latest_detection_runs = list(db.scalars(select(DetectionRun).order_by(DetectionRun.started_at.desc()).limit(3)))
        sources = list(db.scalars(select(LogSource).order_by(LogSource.updated_at.desc(), LogSource.id.desc()).limit(10)))
        enabled_sources = [source for source in sources if source.enabled]
        source_status_counts: dict[str, int] = {}
        source_summaries: list[dict[str, Any]] = []
        for source in sources:
            health = source_health(source)
            status = str(health.get("status") or "unknown")
            source_status_counts[status] = source_status_counts.get(status, 0) + 1
            source_summaries.append(
                {
                    "source_id": source.id,
                    "name": source.name,
                    "source_type": source.source_type,
                    "parser_profile": source.parser_profile,
                    "enabled": source.enabled,
                    "status": status,
                    "last_log_received_at": source.last_log_received_at,
                    "logs_received_count": source.logs_received_count,
                    "parse_success_count": source.parse_success_count,
                    "parse_failure_count": source.parse_failure_count,
                }
            )
        warnings: list[str] = []
        if db_health.get("status") != "ok":
            warnings.append("Database health check is not ok.")
        if non_simulated_response_actions:
            warnings.append("Response action status outside simulated/denied was found; investigate immediately.")
        if parse_failures and _rate(parse_failures, parse_success + parse_failures) > 10:
            warnings.append("Parser failure rate is above 10%.")
        if not enabled_sources:
            warnings.append("No enabled sources are visible in the latest source sample.")
        return {
            "ok": db_health.get("status") == "ok" and non_simulated_response_actions == 0,
            "read_only": True,
            "api_health_local": "Use /health while backend is running.",
            "database_health": db_health,
            "counts": {
                "raw_logs": raw_logs,
                "normalized_logs": normalized_logs,
                "alerts": alert_count,
                "response_actions": response_actions,
                "non_simulated_response_actions": non_simulated_response_actions,
                "audit_events": audit_events,
                "parse_success": parse_success,
                "parse_failures": parse_failures,
                "parse_failure_rate_percent": _rate(parse_failures, parse_success + parse_failures),
                "source_sample_count": len(sources),
                "enabled_source_sample_count": len(enabled_sources),
            },
            "latest_ingestion_run": ingestion_run_to_dict(_latest_or_none(latest_ingestion_runs)) if latest_ingestion_runs else None,
            "latest_detection_run": detection_run_to_dict(_latest_or_none(latest_detection_runs)) if latest_detection_runs else None,
            "source_status_counts": source_status_counts,
            "source_summaries": source_summaries,
            "warnings": warnings,
            "production_ready": False,
        }


def run_v34_shared_lab_readiness(
    *,
    include_backup_copy: bool = False,
    include_full_profile: bool = True,
    source_name: str | None = None,
) -> dict[str, Any]:
    settings = Settings()
    doctor = run_production_readiness_doctor(settings=settings)
    postgres = run_postgres_lab_validation(settings=settings, include_smoke=False, include_sample_ingest=False)
    backup = run_backup_restore_drill(settings=settings, dry_run=not include_backup_copy)
    performance = profile_dashboard_summary(include_full_summary=include_full_profile)
    operations = operations_readiness_report()
    source_pilot = run_v35_real_source_pilot_check(
        source_name=source_name,
        expected_min_logs=1,
        settings=settings,
    )
    warnings: list[str] = []
    warnings.extend(doctor.get("warnings") or [])
    warnings.extend(performance.get("warnings") or [])
    warnings.extend(operations.get("warnings") or [])
    if not source_pilot.get("real_device_forwarding_validated"):
        warnings.append(f"real_source_pilot: {source_pilot.get('status')}")
    if postgres.get("status") == "postgres_lab_validation_blocked_by_environment":
        warnings.append("PostgreSQL shared-lab validation is pending because current DATABASE_URL is not PostgreSQL.")
    blockers: list[str] = []
    blockers.extend(doctor.get("blockers") or [])
    if not operations.get("ok"):
        blockers.append("operations_readiness_report is not ok.")
    status = "shared_lab_foundation_blocked" if blockers else "shared_lab_foundation_ready_with_warnings" if warnings else "shared_lab_foundation_ready"
    return {
        "ok": not blockers,
        "status": status,
        "production_ready": False,
        "production_readiness_claim": False,
        "model_activation_allowed": False,
        "response_automation_allowed": False,
        "real_firewall_blocking_enabled": False,
        "current_database_modified": False,
        "backup_copy_created": include_backup_copy and backup.get("status") == "sqlite_backup_restore_drill_passed",
        "components": {
            "config_doctor": doctor,
            "postgresql_shared_lab": postgres,
            "backup_restore_drill": backup,
            "dashboard_summary_profile": performance,
            "real_source_pilot": source_pilot,
            "operations_readiness": operations,
        },
        "real_source_pilot_checklist": REAL_SOURCE_PILOT_CHECKLIST,
        "blockers": blockers,
        "warnings": warnings,
        "recommended_next_steps": [
            "Run a real-device syslog pilot for one approved lab router/firewall.",
            "Validate PostgreSQL on a separate shared-lab database host.",
            "Run backup/restore drill with --include-backup-copy and archive the ignored evidence path externally if needed.",
            "Investigate dashboard summary slowest steps if performance warnings recur.",
            "Keep response simulation enabled and ML decision support only.",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run ATDR v3.4 shared-lab production-readiness foundation checks.")
    parser.add_argument("--include-backup-copy", action="store_true", help="Create an ignored SQLite backup copy under .tmp and verify it opens.")
    parser.add_argument("--skip-full-profile", action="store_true", help="Skip the full uncached dashboard summary profile.")
    parser.add_argument("--source-name", default=None, help="Optional source name for real-source pilot validation.")
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()
    result = run_v34_shared_lab_readiness(
        include_backup_copy=args.include_backup_copy,
        include_full_profile=not args.skip_full_profile,
        source_name=args.source_name,
    )
    print(json.dumps(result, indent=2 if args.pretty else None, default=_json_default))
    raise SystemExit(0 if result.get("ok") else 1)


if __name__ == "__main__":
    main()
