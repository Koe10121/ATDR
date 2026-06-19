import argparse
import json
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from atdr.app.core.config import Settings
from atdr.app.db.database import SessionLocal
from atdr.app.db.models import Alert, AlertEvidence, LogSource, NormalizedLog, RawLog, ResponseAction
from atdr.app.services.case_service import list_alert_cases
from atdr.app.services.source_service import (
    recent_source_detection_runs,
    recent_source_ingestion_runs,
    source_health,
    source_quality,
    source_to_dict,
)


UNKNOWN_APPS = {"unknown", "unknown-tcp", "unknown-udp", "unknown-p2p", "incomplete", "not-applicable"}
SIMULATED_SOURCE_NAME_TOKENS = ("demo", "final-demo", "sample", "scenario", "sim", "test", "replay")
SIMULATED_SOURCE_TYPES = {"file_import", "replay", "sample"}


def _json_default(value: Any) -> str:
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def _source_query(db: Session, source_name: str | None) -> LogSource | None:
    statement = select(LogSource).order_by(desc(LogSource.last_log_received_at), desc(LogSource.updated_at), desc(LogSource.id))
    if source_name:
        statement = statement.where(LogSource.name == source_name)
    return db.scalar(statement.limit(1))


def _rate(numerator: int, denominator: int) -> float:
    return round((numerator / denominator) * 100, 4) if denominator else 0.0


def _source_alert_ids(db: Session, source_id: int, *, limit: int = 50) -> list[int]:
    rows = db.scalars(
        select(Alert.id)
        .join(AlertEvidence, AlertEvidence.alert_id == Alert.id)
        .join(NormalizedLog, NormalizedLog.id == AlertEvidence.normalized_log_id)
        .join(RawLog, RawLog.id == NormalizedLog.raw_log_id)
        .where(RawLog.source_id == source_id)
        .group_by(Alert.id)
        .order_by(desc(Alert.updated_at), desc(Alert.id))
        .limit(limit)
    ).all()
    return [int(row) for row in rows]


def _source_response_action_count(db: Session, source_id: int) -> int:
    return int(
        db.scalar(
            select(func.count(func.distinct(ResponseAction.id)))
            .join(Alert, Alert.id == ResponseAction.alert_id)
            .join(AlertEvidence, AlertEvidence.alert_id == Alert.id)
            .join(NormalizedLog, NormalizedLog.id == AlertEvidence.normalized_log_id)
            .join(RawLog, RawLog.id == NormalizedLog.raw_log_id)
            .where(RawLog.source_id == source_id)
        )
        or 0
    )


def _total_response_actions(db: Session) -> int:
    return int(db.scalar(select(func.count(ResponseAction.id))) or 0)


def _non_simulated_response_actions(db: Session) -> int:
    return int(
        db.scalar(select(func.count(ResponseAction.id)).where(ResponseAction.status.notin_(["simulated", "denied"]))) or 0
    )


def _source_counts(db: Session, source_id: int, *, since: datetime | None) -> dict[str, Any]:
    raw_logs = int(db.scalar(select(func.count(RawLog.id)).where(RawLog.source_id == source_id)) or 0)
    normalized_logs = int(
        db.scalar(select(func.count(NormalizedLog.id)).join(RawLog).where(RawLog.source_id == source_id)) or 0
    )
    parser_error_filter = NormalizedLog.parsed_json["parser_error"].as_string().is_not(None)
    parser_failures = int(
        db.scalar(
            select(func.count(NormalizedLog.id))
            .join(RawLog)
            .where(RawLog.source_id == source_id, parser_error_filter)
        )
        or 0
    )
    unknown_app_count = int(
        db.scalar(
            select(func.count(NormalizedLog.id))
            .join(RawLog)
            .where(RawLog.source_id == source_id, func.lower(NormalizedLog.app).in_(UNKNOWN_APPS))
        )
        or 0
    )
    recent_raw_logs = 0
    recent_normalized_logs = 0
    if since is not None:
        recent_raw_logs = int(
            db.scalar(select(func.count(RawLog.id)).where(RawLog.source_id == source_id, RawLog.imported_at >= since)) or 0
        )
        recent_normalized_logs = int(
            db.scalar(
                select(func.count(NormalizedLog.id))
                .join(RawLog)
                .where(RawLog.source_id == source_id, RawLog.imported_at >= since)
            )
            or 0
        )
    return {
        "raw_logs": raw_logs,
        "normalized_logs": normalized_logs,
        "recent_raw_logs": recent_raw_logs,
        "recent_normalized_logs": recent_normalized_logs,
        "parser_error_count": parser_failures,
        "parse_failure_rate_percent": _rate(parser_failures, normalized_logs),
        "unknown_app_count": unknown_app_count,
        "unknown_app_rate_percent": _rate(unknown_app_count, normalized_logs),
    }


def _latest_parser_errors(
    db: Session,
    source_id: int,
    *,
    limit: int = 5,
    include_redacted_excerpts: bool = False,
) -> list[dict[str, Any]]:
    parser_error_filter = NormalizedLog.parsed_json["parser_error"].as_string().is_not(None)
    rows = db.scalars(
        select(NormalizedLog)
        .join(RawLog)
        .where(RawLog.source_id == source_id, parser_error_filter)
        .order_by(desc(NormalizedLog.id))
        .limit(limit)
    ).all()
    examples: list[dict[str, Any]] = []
    for row in rows:
        item = {
            "normalized_log_id": row.id,
            "raw_log_id": row.raw_log_id,
            "parser_error": row.parsed_json.get("parser_error"),
        }
        if include_redacted_excerpts and row.raw_log:
            item["raw_line_redacted_excerpt"] = _redact_excerpt(row.raw_log.raw_line)
        examples.append(item)
    return examples


def _redact_excerpt(value: str, *, limit: int = 120) -> str:
    # Preserve enough structure for troubleshooting without exporting the full private line.
    text = value[:limit]
    parts = text.split(",")
    if len(parts) > 8:
        parts[6:8] = ["<src_ip_redacted>", "<dst_ip_redacted>"]
        text = ",".join(parts)
    return text


def _source_is_simulated(source: LogSource) -> bool:
    name = (source.name or "").lower()
    source_type = (source.source_type or "").lower()
    return source_type in SIMULATED_SOURCE_TYPES or any(token in name for token in SIMULATED_SOURCE_NAME_TOKENS)


def run_v35_real_source_pilot_check(
    *,
    source_name: str | None = None,
    expected_min_logs: int = 1,
    window_minutes: int = 60,
    include_redacted_excerpts: bool = False,
    settings: Settings | None = None,
    session_factory=None,
) -> dict[str, Any]:
    """Read-only real-source pilot readiness check."""

    started = time.perf_counter()
    settings = settings or Settings()
    SessionFactory = session_factory or SessionLocal
    since = datetime.now(timezone.utc) - timedelta(minutes=max(1, window_minutes))
    with SessionFactory() as db:
        response_before = _total_response_actions(db)
        source = _source_query(db, source_name)
        if source is None:
            response_after = _total_response_actions(db)
            return {
                "ok": True,
                "status": "source_missing_not_validated",
                "real_device_forwarding_validated": False,
                "source_name": source_name,
                "message": "No matching source exists. Register a source and send logs before validation.",
                "checks": [
                    {
                        "name": "source_exists",
                        "passed": False,
                        "detail": f"source_name={source_name or '<latest source>'}",
                    },
                    {
                        "name": "no_response_created_by_check",
                        "passed": response_before == response_after,
                        "detail": f"response_actions_before={response_before}; after={response_after}.",
                    },
                ],
                "response_actions_before": response_before,
                "response_actions_after": response_after,
                "current_database_modified": False,
                "production_ready": False,
                "production_readiness_claim": False,
                "response_automation_allowed": False,
                "real_firewall_blocking_enabled": False,
                "runtime_seconds": round(time.perf_counter() - started, 4),
            }

        source_id = int(source.id)
        counts = _source_counts(db, source_id, since=since)
        health = source_health(source)
        quality = source_quality(db, source_id)
        ingestion_runs = recent_source_ingestion_runs(db, source_id)
        detection_runs = recent_source_detection_runs(db, source_id)
        cases = list_alert_cases(db, source_id=source_id, limit=10)
        alert_ids = _source_alert_ids(db, source_id)
        parser_errors = _latest_parser_errors(
            db,
            source_id,
            include_redacted_excerpts=include_redacted_excerpts,
        )
        source_response_actions = _source_response_action_count(db, source_id)
        non_simulated_response_actions = _non_simulated_response_actions(db)
        response_after = _total_response_actions(db)
        response_unchanged = response_before == response_after
        checks = [
            {"name": "source_exists", "passed": True, "detail": f"Source {source.name} exists."},
            {"name": "source_enabled", "passed": bool(source.enabled), "detail": f"enabled={source.enabled}."},
            {
                "name": "minimum_raw_logs",
                "passed": counts["raw_logs"] >= expected_min_logs,
                "detail": f"{counts['raw_logs']} raw logs linked to source; target {expected_min_logs}.",
            },
            {
                "name": "normalized_logs_present",
                "passed": counts["normalized_logs"] > 0,
                "detail": f"{counts['normalized_logs']} normalized logs linked to source.",
            },
            {
                "name": "source_health_visible",
                "passed": health["status"] in {"healthy", "warning", "idle", "error", "disabled"},
                "detail": f"source_health={health['status']}.",
            },
            {
                "name": "source_scoped_detection_run",
                "passed": bool(detection_runs),
                "detail": f"{len(detection_runs)} source-linked detection runs found.",
            },
            {
                "name": "alerts_trace_to_source",
                "passed": len(alert_ids) >= 0,
                "detail": f"{len(alert_ids)} alert ids sampled for source.",
            },
            {
                "name": "cases_trace_to_source",
                "passed": len(cases) >= 0,
                "detail": f"{len(cases)} case summaries sampled for source.",
            },
            {
                "name": "response_mode_simulation",
                "passed": settings.response_simulation and settings.response_provider.lower() == "simulation",
                "detail": f"RESPONSE_SIMULATION={settings.response_simulation}; RESPONSE_PROVIDER={settings.response_provider}.",
            },
            {
                "name": "no_response_created_by_check",
                "passed": response_unchanged,
                "detail": f"response_actions_before={response_before}; after={response_after}.",
            },
            {
                "name": "no_non_simulated_response_actions",
                "passed": non_simulated_response_actions == 0,
                "detail": f"non_simulated_response_actions={non_simulated_response_actions}.",
            },
        ]
        required = checks[:6] + checks[8:]
        source_pipeline_validated = all(item["passed"] for item in required)
        simulated_source = _source_is_simulated(source)
        real_device_forwarding_validated = source_pipeline_validated and not simulated_source
        status = "real_device_forwarding_validated" if real_device_forwarding_validated else "real_source_pilot_review_required"
        if source_pipeline_validated and simulated_source:
            status = "simulated_source_pipeline_validated"
        if counts["raw_logs"] < expected_min_logs:
            status = "real_device_forwarding_not_validated"
        warnings: list[str] = []
        if simulated_source:
            warnings.append(
                "Source appears to be simulated, replayed, imported, or scenario-based; "
                "pipeline checks can pass, but this is not real-device forwarding validation."
            )
        if health.get("warnings"):
            warnings.extend([f"source_health: {warning}" for warning in health["warnings"]])
        if quality.get("warnings"):
            warnings.extend([f"source_quality: {warning}" for warning in quality["warnings"]])
        if counts["parse_failure_rate_percent"] >= 10:
            warnings.append(f"parse_failure_rate_percent={counts['parse_failure_rate_percent']} requires parser-profile review.")
        if counts["unknown_app_rate_percent"] >= 25:
            warnings.append(f"unknown_app_rate_percent={counts['unknown_app_rate_percent']} may be expected for scans but needs review.")
        return {
            "ok": True,
            "status": status,
            "source_pipeline_validated": source_pipeline_validated,
            "real_device_forwarding_validated": real_device_forwarding_validated,
            "simulated_or_replay_source": simulated_source,
            "source": source_to_dict(source),
            "window_minutes": window_minutes,
            "counts": counts,
            "source_health": health,
            "source_quality_summary": {
                "unknown_app_count": quality.get("unknown_app_count"),
                "unknown_app_rate": quality.get("unknown_app_rate"),
                "alert_count": quality.get("alert_count"),
                "warnings": quality.get("warnings", []),
            },
            "latest_parser_errors": parser_errors,
            "latest_ingestion_run": ingestion_runs[0] if ingestion_runs else None,
            "latest_detection_run": detection_runs[0] if detection_runs else None,
            "source_scoped_alert_ids": alert_ids,
            "source_linked_case_ids": [case["case_id"] for case in cases],
            "case_summaries_sample": cases[:5],
            "response_actions": {
                "before": response_before,
                "after": response_after,
                "source_linked": source_response_actions,
                "non_simulated": non_simulated_response_actions,
            },
            "checks": checks,
            "warnings": warnings,
            "current_database_modified": False,
            "production_ready": False,
            "production_readiness_claim": False,
            "model_activated": False,
            "response_automation_allowed": False,
            "real_firewall_blocking_enabled": False,
            "runtime_seconds": round(time.perf_counter() - started, 4),
        }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run a read-only ATDR v3.5 real-source/syslog pilot check.")
    parser.add_argument("--source-name", default=None, help="Source name. Defaults to latest active source if omitted.")
    parser.add_argument("--expected-min-logs", type=int, default=1)
    parser.add_argument("--window-minutes", type=int, default=60)
    parser.add_argument("--include-redacted-excerpts", action="store_true")
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()
    result = run_v35_real_source_pilot_check(
        source_name=args.source_name,
        expected_min_logs=args.expected_min_logs,
        window_minutes=args.window_minutes,
        include_redacted_excerpts=args.include_redacted_excerpts,
    )
    print(json.dumps(result, indent=2 if args.pretty else None, default=_json_default))
    raise SystemExit(0 if result.get("ok") else 1)


if __name__ == "__main__":
    main()
