import argparse
import json
import time
from datetime import datetime
from typing import Any

from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from atdr.app.db.database import Base, SessionLocal, init_db
from atdr.app.db.models import Alert, AlertEvidence, DetectionRun, LogSource, NormalizedLog, RawLog, ResponseAction
from atdr.app.services.case_service import list_alert_cases
from atdr.app.services.detection_service import run_detection
from atdr.app.services.source_service import recent_source_detection_runs, source_to_dict
from atdr.scripts.run_v30_real_source_pilot_validation import run_v30_real_source_pilot_validation
from atdr.scripts.run_v32_syslog_source_simulator import simulate_source_import


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


def _source_alert_count(db, source_id: int) -> int:
    return int(
        db.scalar(
            select(func.count(func.distinct(Alert.id)))
            .join(AlertEvidence, AlertEvidence.alert_id == Alert.id)
            .join(NormalizedLog, NormalizedLog.id == AlertEvidence.normalized_log_id)
            .join(RawLog, RawLog.id == NormalizedLog.raw_log_id)
            .where(RawLog.source_id == source_id)
        )
        or 0
    )


def _source_counts(db, source_id: int) -> dict[str, int]:
    return {
        "raw_logs": int(db.scalar(select(func.count(RawLog.id)).where(RawLog.source_id == source_id)) or 0),
        "normalized_logs": int(
            db.scalar(select(func.count(NormalizedLog.id)).join(RawLog).where(RawLog.source_id == source_id)) or 0
        ),
        "alerts": _source_alert_count(db, source_id),
        "detection_runs": int(
            db.scalar(
                select(func.count(DetectionRun.id)).where(DetectionRun.details_json["source_id"].as_integer() == source_id)
            )
            or 0
        ),
    }


def run_v32_no_hardware_source_pilot(
    *,
    source_name: str = "lab-firewall-sim-1",
    source_type: str = "firewall",
    parser_profile: str = "palo_alto",
    host: str | None = "127.0.0.1",
    port: int | None = 5514,
    count: int = 100,
    scenario: str = "mixed_baseline",
    use_temp_db: bool = False,
    session_factory=None,
) -> dict[str, Any]:
    started = time.perf_counter()
    engine = None
    if session_factory is not None:
        SessionFactory = session_factory
    elif use_temp_db:
        engine, SessionFactory = _temp_session_factory()
    else:
        init_db()
        SessionFactory = SessionLocal

    try:
        with SessionFactory() as db:
            response_before = int(db.scalar(select(func.count(ResponseAction.id))) or 0)
            simulated = simulate_source_import(
                db,
                source_name=source_name,
                source_type=source_type,
                parser_profile=parser_profile,
                host=host,
                port=port,
                count=count,
                scenario=scenario,
                actor="v32_no_hardware_pilot",
            )
            source_id = int(simulated["source"]["source_id"])
            source = db.get(LogSource, source_id)
            counts_after_import = _source_counts(db, source_id)
            detection = run_detection(
                db,
                limit=max(100, count * 2),
                use_ml=False,
                actor="v32_no_hardware_pilot",
                source_id=source_id,
                source_name=source_name,
                source_type=source_type,
            )
            db.refresh(source)
            counts_after_detection = _source_counts(db, source_id)
            cases = list_alert_cases(db, source_id=source_id, limit=10)
            detection_runs = recent_source_detection_runs(db, source_id, limit=5)
            response_after = int(db.scalar(select(func.count(ResponseAction.id))) or 0)

        validator = run_v30_real_source_pilot_validation(
            source_name=source_name,
            expected_min_logs=min(count, 100),
            window_minutes=60,
            session_factory=SessionFactory,
        )
        checks = [
            {
                "name": "source_exists",
                "passed": source is not None,
                "detail": f"source_name={source_name}",
            },
            {
                "name": "source_enabled",
                "passed": bool(source.enabled) if source is not None else False,
                "detail": f"enabled={getattr(source, 'enabled', None)}",
            },
            {
                "name": "logs_received",
                "passed": simulated["import_result"]["raw_logs_imported"] == count,
                "detail": f"{simulated['import_result']['raw_logs_imported']} of {count} requested logs imported.",
            },
            {
                "name": "parse_quality_counted",
                "passed": simulated["import_result"]["parsed_successfully"] > 0
                and simulated["import_result"]["parse_failures"] >= 1,
                "detail": (
                    f"parsed={simulated['import_result']['parsed_successfully']}; "
                    f"failed={simulated['import_result']['parse_failures']}."
                ),
            },
            {
                "name": "detection_run_linked_to_source",
                "passed": bool(detection_runs),
                "detail": f"{len(detection_runs)} source-linked detection runs returned.",
            },
            {
                "name": "alerts_trace_to_source",
                "passed": counts_after_detection["alerts"] >= 1,
                "detail": f"{counts_after_detection['alerts']} alerts linked through source evidence.",
            },
            {
                "name": "cases_trace_to_source",
                "passed": len(cases) >= 1,
                "detail": f"{len(cases)} source case summaries returned.",
            },
            {
                "name": "no_automatic_response",
                "passed": response_after == response_before,
                "detail": f"response actions before/after: {response_before}/{response_after}.",
            },
            {
                "name": "real_firewall_blocking_disabled",
                "passed": True,
                "detail": "No connector or real firewall blocking is enabled by this pilot.",
            },
        ]
        return {
            "ok": all(item["passed"] for item in checks),
            "status": "simulated_source_pilot_validated"
            if all(item["passed"] for item in checks)
            else "simulated_source_pilot_review_required",
            "hardware_required": False,
            "real_device_forwarding_validated": False,
            "simulated_source_validated": all(item["passed"] for item in checks),
            "production_ready": False,
            "production_readiness_claim": False,
            "model_activated": False,
            "response_automation_allowed": False,
            "real_firewall_blocking_enabled": False,
            "temporary_database_used": use_temp_db,
            "current_database_modified": not use_temp_db and session_factory is None,
            "source": source_to_dict(source) if source is not None else None,
            "scenario": scenario,
            "requested_count": count,
            "simulator": {
                "mode": simulated["mode"],
                "scenario_distribution": simulated["scenario_distribution"],
                "import_result": simulated["import_result"],
            },
            "counts": {
                "after_import": counts_after_import,
                "after_detection": counts_after_detection,
                "parse_successes": simulated["import_result"]["parsed_successfully"],
                "parse_failures": simulated["import_result"]["parse_failures"],
            },
            "detection_result": detection,
            "recent_detection_runs": detection_runs,
            "case_summaries": cases,
            "v30_validator": {
                **validator,
                "real_device_forwarding_validated": False,
                "note": "The v30 validator can verify source pipeline state, but v3.2 still marks real device forwarding false because no hardware was connected.",
            },
            "checks": checks,
            "response_safety": {
                "response_actions_before": response_before,
                "response_actions_after": response_after,
                "automatic_response_actions_created": max(0, response_after - response_before),
                "response_automation_allowed": False,
                "real_firewall_blocking_enabled": False,
            },
            "runtime_seconds": round(time.perf_counter() - started, 4),
        }
    finally:
        if engine is not None:
            engine.dispose()


def main() -> None:
    parser = argparse.ArgumentParser(description="Run ATDR v3.2 no-hardware source pilot validation.")
    parser.add_argument("--source-name", default="lab-firewall-sim-1")
    parser.add_argument("--source-type", default="firewall", choices=["file_import", "replay", "syslog_udp", "syslog_tcp", "router", "firewall", "sample"])
    parser.add_argument("--parser-profile", default="palo_alto", choices=["palo_alto", "generic_syslog", "raw_fallback"])
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5514)
    parser.add_argument("--count", type=int, default=100)
    parser.add_argument("--scenario", default="mixed_baseline")
    parser.add_argument("--use-temp-db", action="store_true")
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()
    result = run_v32_no_hardware_source_pilot(
        source_name=args.source_name,
        source_type=args.source_type,
        parser_profile=args.parser_profile,
        host=args.host,
        port=args.port,
        count=args.count,
        scenario=args.scenario,
        use_temp_db=args.use_temp_db,
    )
    print(json.dumps(result, default=_json_default, indent=2 if args.pretty else None))
    raise SystemExit(0 if result.get("ok") else 1)


if __name__ == "__main__":
    main()

