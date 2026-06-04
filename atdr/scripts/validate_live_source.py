import argparse
import json
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from atdr.app.db.database import SessionLocal, init_db
from atdr.app.db.models import LogSource, ResponseAction
from atdr.app.services.detection_service import run_detection
from atdr.app.services.source_service import get_or_create_source, source_to_dict, update_source
from atdr.scripts.export_lab_validation_report import export_lab_validation_report


def _json_default(value: Any) -> str:
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def _source_counts(source_detail: dict[str, Any] | None) -> dict[str, int]:
    if not source_detail:
        return {"raw_logs": 0, "normalized_logs": 0, "alerts": 0}
    quality = source_detail.get("quality") or {}
    return {
        "raw_logs": int(quality.get("raw_logs") or 0),
        "normalized_logs": int(quality.get("normalized_logs") or 0),
        "alerts": int(quality.get("alert_count") or 0),
    }


def _latest_detection_for_source(source_detail: dict[str, Any]) -> dict[str, Any] | None:
    runs = source_detail.get("recent_detection_runs") or []
    return runs[0] if runs else None


def _add_check(checks: list[dict[str, Any]], name: str, passed: bool, detail: str) -> None:
    checks.append({"name": name, "passed": passed, "detail": detail})


def validate_live_source(
    *,
    source_name: str,
    source_type: str = "syslog_udp",
    parser_profile: str = "palo_alto",
    host: str | None = None,
    port: int | None = None,
    duration: float = 60.0,
    run_detection_after: bool = False,
    detection_limit: int = 1000,
    use_ml: bool = False,
    require_activity: bool = False,
    write_report: bool = True,
    report_dir: Path | None = None,
    actor: str = "live_source_validation",
    db: Session | None = None,
) -> dict[str, Any]:
    owns_session = db is None
    if owns_session:
        init_db()
        db = SessionLocal()
    try:
        existing = db.scalar(select(LogSource).where(LogSource.name == source_name).limit(1))
        source = get_or_create_source(
            db,
            name=source_name,
            source_type=source_type,
            parser_profile=parser_profile,
            host=host,
            port=port,
        )
        db.flush()
        updates: dict[str, Any] = {}
        if source_type and source.source_type != source_type:
            updates["source_type"] = source_type
        if parser_profile and source.parser_profile != parser_profile:
            updates["parser_profile"] = parser_profile
        if host is not None and source.host != host:
            updates["host"] = host
        if port is not None and source.port != port:
            updates["port"] = port
        if updates:
            source = update_source(db, source, updates)
        db.commit()
        db.refresh(source)

        before_response_count = int(db.query(ResponseAction).count())
        before = source_to_dict(source, include_quality=True, db=db)
        before_counts = _source_counts(before)
        if duration > 0:
            time.sleep(duration)
            db.refresh(source)

        detection_result = None
        if run_detection_after:
            detection_result = run_detection(
                db,
                limit=detection_limit,
                use_ml=use_ml,
                actor=actor,
                source_id=source.id,
                source_name=source.name,
                source_type=source.source_type,
            )
            db.commit()
            db.refresh(source)

        after = source_to_dict(source, include_quality=True, db=db)
        after_counts = _source_counts(after)
        after_response_count = int(db.query(ResponseAction).count())
        latest_detection = detection_result or _latest_detection_for_source(after)

        checks: list[dict[str, Any]] = []
        _add_check(checks, "source_exists", source.id is not None, f"Source id: {source.id}.")
        _add_check(checks, "source_enabled", bool(source.enabled), f"Enabled: {source.enabled}.")
        raw_delta = after_counts["raw_logs"] - before_counts["raw_logs"]
        if require_activity:
            activity_passed = raw_delta > 0
            activity_detail = f"Raw log delta during validation window: {raw_delta}."
        else:
            activity_passed = after_counts["raw_logs"] >= before_counts["raw_logs"]
            activity_detail = f"Raw logs before/after: {before_counts['raw_logs']}/{after_counts['raw_logs']}."
        _add_check(checks, "ingestion_activity", activity_passed, activity_detail)
        _add_check(
            checks,
            "raw_evidence_preserved",
            after_counts["raw_logs"] >= before_counts["raw_logs"],
            f"Raw logs before/after: {before_counts['raw_logs']}/{after_counts['raw_logs']}.",
        )
        _add_check(
            checks,
            "parser_counts_available",
            source.logs_received_count == 0 or (source.parse_success_count + source.parse_failure_count) >= 0,
            f"Received={source.logs_received_count}, parsed={source.parse_success_count}, failures={source.parse_failure_count}.",
        )
        _add_check(
            checks,
            "detection_checked",
            latest_detection is not None or not run_detection_after,
            "Detection run completed." if latest_detection else "Detection not run; pass --run-detection for source-scoped detection.",
        )
        _add_check(
            checks,
            "no_response_actions_created",
            after_response_count == before_response_count,
            f"Response actions before/after: {before_response_count}/{after_response_count}.",
        )

        report_result = None
        if write_report:
            report_result = export_lab_validation_report(source_name=source.name, output_dir=report_dir, db=db)

        passed = all(item["passed"] for item in checks)
        return {
            "ok": passed,
            "created_source": existing is None,
            "duration_seconds": duration,
            "source_before": before,
            "source_after": after,
            "counts_before": before_counts,
            "counts_after": after_counts,
            "detection_result": detection_result,
            "latest_detection": latest_detection,
            "checks": checks,
            "report_path": report_result.get("path") if report_result else None,
            "report_warnings": report_result.get("warnings") if report_result else [],
            "safety": {
                "simulated_response_only": True,
                "automatic_response_enabled": False,
                "decision_support_only": True,
            },
        }
    finally:
        if owns_session and db is not None:
            db.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate a controlled ATDR live/source pipeline.")
    parser.add_argument("--source-name", required=True)
    parser.add_argument("--source-type", default="syslog_udp", choices=["file_import", "replay", "syslog_udp", "syslog_tcp", "router", "firewall", "sample"])
    parser.add_argument("--parser-profile", default="palo_alto", choices=["palo_alto", "generic_syslog", "raw_fallback"])
    parser.add_argument("--host", default=None)
    parser.add_argument("--port", type=int, default=None)
    parser.add_argument("--duration", type=float, default=60.0)
    parser.add_argument("--run-detection", action="store_true")
    parser.add_argument("--detection-limit", type=int, default=1000)
    parser.add_argument("--use-ml", action="store_true")
    parser.add_argument("--require-activity", action="store_true")
    parser.add_argument("--no-report", action="store_true")
    parser.add_argument("--report-dir", default=None)
    parser.add_argument("--actor", default="live_source_validation")
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()

    result = validate_live_source(
        source_name=args.source_name,
        source_type=args.source_type,
        parser_profile=args.parser_profile,
        host=args.host,
        port=args.port,
        duration=max(0.0, args.duration),
        run_detection_after=args.run_detection,
        detection_limit=args.detection_limit,
        use_ml=args.use_ml,
        require_activity=args.require_activity,
        write_report=not args.no_report,
        report_dir=Path(args.report_dir) if args.report_dir else None,
        actor=args.actor,
    )
    print(json.dumps(result, default=_json_default, indent=2 if args.pretty else None))
    raise SystemExit(0 if result.get("ok") else 1)


if __name__ == "__main__":
    main()
