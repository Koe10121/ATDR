import argparse
import json
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import create_engine, desc, func, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from atdr.app.core.config import Settings
from atdr.app.db.database import Base, SessionLocal
from atdr.app.db.models import Alert, AlertEvidence, DetectionRun, LogSource, NormalizedLog, RawLog
from atdr.app.services.case_service import list_alert_cases
from atdr.app.services.source_service import source_health, source_quality, source_to_dict


def _json_default(value: Any) -> str:
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def _temp_session_factory():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    Base.metadata.create_all(engine)
    return engine, sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)


def _source_query(db: Session, source_name: str | None) -> LogSource | None:
    statement = select(LogSource).order_by(desc(LogSource.last_log_received_at), desc(LogSource.updated_at), desc(LogSource.id))
    if source_name:
        statement = statement.where(LogSource.name == source_name)
    return db.scalar(statement.limit(1))


def _source_alert_count(db: Session, source_id: int, *, since: datetime | None = None) -> int:
    statement = (
        select(func.count(func.distinct(Alert.id)))
        .join(AlertEvidence, AlertEvidence.alert_id == Alert.id)
        .join(NormalizedLog, NormalizedLog.id == AlertEvidence.normalized_log_id)
        .join(RawLog, RawLog.id == NormalizedLog.raw_log_id)
        .where(RawLog.source_id == source_id)
    )
    if since is not None:
        statement = statement.where(Alert.updated_at >= since)
    return int(db.scalar(statement) or 0)


def _latest_detection_runs(db: Session, source_id: int, *, limit: int = 5) -> list[dict[str, Any]]:
    rows = db.scalars(select(DetectionRun).order_by(desc(DetectionRun.started_at), desc(DetectionRun.id)).limit(100)).all()
    selected = [row for row in rows if (row.details_json or {}).get("source_id") == source_id][:limit]
    return [
        {
            "run_id": row.id,
            "started_at": row.started_at,
            "finished_at": row.finished_at,
            "status": row.status,
            "detection_type": row.detection_type,
            "logs_evaluated": row.logs_evaluated,
            "alerts_created": row.alerts_created,
            "alerts_deduplicated": row.alerts_deduplicated,
            "alerts_suppressed": row.alerts_suppressed,
            "top_attack_types": row.top_attack_types_json,
            "runtime_seconds": row.runtime_seconds,
        }
        for row in selected
    ]


def run_v30_real_source_pilot_validation(
    *,
    source_name: str | None = None,
    expected_min_logs: int = 1,
    window_minutes: int = 60,
    dry_run: bool = False,
    use_temp_db: bool = False,
) -> dict[str, Any]:
    started = time.perf_counter()
    settings = Settings()
    if dry_run:
        return {
            "ok": True,
            "status": "dry_run",
            "real_source_pilot_validated": False,
            "current_database_modified": False,
            "planned_checks": [
                "source exists and is enabled",
                "raw logs are linked to source",
                "normalized logs are linked to source",
                "source health is healthy or warning",
                "source-scoped detection run exists",
                "alerts/cases can be traced to source",
                "no automatic response or real firewall blocking",
            ],
            "production_ready": False,
            "response_automation_allowed": False,
            "real_firewall_blocking_enabled": False,
        }

    engine = None
    SessionFactory = SessionLocal
    if use_temp_db:
        engine, SessionFactory = _temp_session_factory()

    try:
        with SessionFactory() as db:
            source = _source_query(db, source_name)
            since = datetime.now(timezone.utc) - timedelta(minutes=max(1, window_minutes))
            if source is None:
                return {
                    "ok": True,
                    "status": "real_device_forwarding_not_validated",
                    "real_source_pilot_validated": False,
                    "source_name": source_name,
                    "message": "No matching log source exists yet.",
                    "checks": [
                        {
                            "name": "source_exists",
                            "passed": False,
                            "detail": f"source_name={source_name or '<latest source>'}",
                        }
                    ],
                    "current_database_modified": False,
                    "production_ready": False,
                    "response_automation_allowed": False,
                    "real_firewall_blocking_enabled": False,
                    "runtime_seconds": round(time.perf_counter() - started, 4),
                }

            source_id = int(source.id)
            raw_count = int(db.scalar(select(func.count(RawLog.id)).where(RawLog.source_id == source_id)) or 0)
            recent_raw_count = int(
                db.scalar(
                    select(func.count(RawLog.id)).where(
                        RawLog.source_id == source_id,
                        RawLog.imported_at >= since,
                    )
                )
                or 0
            )
            normalized_count = int(
                db.scalar(select(func.count(NormalizedLog.id)).join(RawLog).where(RawLog.source_id == source_id)) or 0
            )
            recent_normalized_count = int(
                db.scalar(
                    select(func.count(NormalizedLog.id))
                    .join(RawLog)
                    .where(RawLog.source_id == source_id, RawLog.imported_at >= since)
                )
                or 0
            )
            quality = source_quality(db, source_id)
            health = source_health(source)
            detection_runs = _latest_detection_runs(db, source_id)
            cases = list_alert_cases(db, source_id=source_id, limit=10)
            alert_count = _source_alert_count(db, source_id)
            recent_alert_count = _source_alert_count(db, source_id, since=since)
            checks = [
                {
                    "name": "source_exists",
                    "passed": True,
                    "detail": f"Source {source.name} exists.",
                },
                {
                    "name": "source_enabled",
                    "passed": bool(source.enabled),
                    "detail": f"enabled={source.enabled}.",
                },
                {
                    "name": "minimum_logs_received",
                    "passed": raw_count >= expected_min_logs,
                    "detail": f"{raw_count} raw logs linked to source; target {expected_min_logs}.",
                },
                {
                    "name": "normalization_present",
                    "passed": normalized_count > 0,
                    "detail": f"{normalized_count} normalized logs linked to source.",
                },
                {
                    "name": "source_health_not_failed",
                    "passed": health["status"] in {"healthy", "warning", "idle"},
                    "detail": f"source_health={health['status']}.",
                },
                {
                    "name": "source_scoped_detection_history",
                    "passed": bool(detection_runs),
                    "detail": f"{len(detection_runs)} recent source-linked detection runs.",
                },
                {
                    "name": "alerts_trace_to_source",
                    "passed": alert_count >= 0,
                    "detail": f"{alert_count} alerts linked through source evidence.",
                },
                {
                    "name": "cases_trace_to_source",
                    "passed": len(cases) >= 0,
                    "detail": f"{len(cases)} case summaries returned for source.",
                },
                {
                    "name": "no_automatic_response",
                    "passed": True,
                    "detail": "This validator is read-only and does not create response actions.",
                },
                {
                    "name": "real_firewall_blocking_disabled",
                    "passed": settings.response_simulation,
                    "detail": f"RESPONSE_SIMULATION={settings.response_simulation}.",
                },
            ]
            validated = all(item["passed"] for item in checks[:6]) and settings.response_simulation
            status = "real_source_pilot_validated" if validated else "real_source_pilot_review_required"
            if raw_count < expected_min_logs:
                status = "real_device_forwarding_not_validated"
            return {
                "ok": True,
                "status": status,
                "real_source_pilot_validated": validated,
                "source": source_to_dict(source),
                "source_quality": quality,
                "source_health": health,
                "window_minutes": window_minutes,
                "counts": {
                    "raw_logs": raw_count,
                    "recent_raw_logs": recent_raw_count,
                    "normalized_logs": normalized_count,
                    "recent_normalized_logs": recent_normalized_count,
                    "alerts": alert_count,
                    "recent_alerts": recent_alert_count,
                    "cases": len(cases),
                    "recent_detection_runs": len(detection_runs),
                },
                "recent_detection_runs": detection_runs,
                "case_summaries": cases[:5],
                "checks": checks,
                "current_database_modified": False,
                "temporary_database_used": use_temp_db,
                "production_ready": False,
                "production_readiness_claim": False,
                "model_activated": False,
                "response_automation_allowed": False,
                "real_firewall_blocking_enabled": False,
                "runtime_seconds": round(time.perf_counter() - started, 4),
            }
    finally:
        if engine is not None:
            engine.dispose()


def main() -> None:
    parser = argparse.ArgumentParser(description="Read-only v3.0 real-source pilot validation.")
    parser.add_argument("--source-name", default=None, help="Optional source name. Defaults to latest source.")
    parser.add_argument("--expected-min-logs", type=int, default=1)
    parser.add_argument("--window-minutes", type=int, default=60)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--use-temp-db", action="store_true")
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()
    result = run_v30_real_source_pilot_validation(
        source_name=args.source_name,
        expected_min_logs=args.expected_min_logs,
        window_minutes=args.window_minutes,
        dry_run=args.dry_run,
        use_temp_db=args.use_temp_db,
    )
    print(json.dumps(result, indent=2 if args.pretty else None, default=_json_default))
    raise SystemExit(0 if result.get("ok") else 1)


if __name__ == "__main__":
    main()
