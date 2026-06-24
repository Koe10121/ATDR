import argparse
import json
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from atdr.app.core.config import PROJECT_ROOT
from atdr.app.db.database import SessionLocal, init_db
from atdr.app.db.models import Alert, AlertEvidence, LogSource, MLModelRun, NormalizedLog, RawLog, ResponseAction
from atdr.app.detection.explanations import alert_explanation_completeness, build_alert_detection_summary
from atdr.app.parsers.paloalto_parser import parse_log_line_for_profile
from atdr.app.services.alert_service import list_alerts
from atdr.app.services.detection_service import run_detection
from atdr.app.services.log_service import count_nonblank_log_lines, import_log_file
from atdr.app.services.source_service import get_or_create_source, source_health, source_to_dict
from atdr.scripts.run_detection_validation_suite import _allowed_attack_types, _load_expectations
from atdr.scripts.run_source_scenario import SCENARIOS, ScenarioSpec, _temp_session_factory


SCENARIO_DIR = PROJECT_ROOT / "data" / "samples" / "scenarios"
DEFAULT_SOAK_SCENARIOS = [
    "normal_allowed_traffic",
    "benign_incomplete_allow_noise",
    "generic_syslog_mixed",
    "malformed_raw_fallback",
    "malformed_vendor_mixed_fields",
    "repeated_dedup_traffic",
    "suspicious_horizontal_scan",
    "suspicious_denied_ssh_burst",
    "malicious_like_c2_beacon",
]
BASE_SOURCE_SPECS = [
    {"name": "soak-firewall-1", "source_type": "firewall", "parser_profile": "palo_alto"},
    {"name": "soak-router-1", "source_type": "router", "parser_profile": "generic_syslog"},
    {"name": "soak-workstation-source", "source_type": "sample", "parser_profile": "raw_fallback"},
]
EXPLANATION_REQUIRED_FIELDS = [
    "what_happened",
    "why_suspicious",
    "normalized_fields_used",
    "rule_evidence",
    "anomaly_evidence",
    "ml_evidence",
    "analyst_next_steps",
    "safety_note",
    "decision_support_only",
    "response_automation_allowed",
]


@dataclass(frozen=True, slots=True)
class SoakEvent:
    iteration: int
    scenario: str
    source_name: str
    source_type: str
    parser_profile: str


def _json_default(value: Any) -> str:
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def _scenario_path(spec: ScenarioSpec) -> Path:
    return SCENARIO_DIR / spec.filename


def _parse_scenario_mix(value: str | None) -> list[str]:
    if not value:
        return list(DEFAULT_SOAK_SCENARIOS)
    scenarios = [item.strip() for item in value.split(",") if item.strip()]
    unknown = [item for item in scenarios if item not in SCENARIOS]
    if unknown:
        raise ValueError(f"Unknown scenario(s): {', '.join(unknown)}")
    return scenarios


def _source_specs(source_count: int) -> list[dict[str, str]]:
    requested = max(1, source_count)
    specs = BASE_SOURCE_SPECS[: min(requested, len(BASE_SOURCE_SPECS))]
    for index in range(len(specs), requested):
        specs.append(
            {
                "name": f"soak-firewall-{index + 1}",
                "source_type": "firewall",
                "parser_profile": "palo_alto",
            }
        )
    return specs


def _source_for_scenario(spec: ScenarioSpec, source_specs: list[dict[str, str]]) -> dict[str, str]:
    for source in source_specs:
        if source["parser_profile"] == spec.default_parser_profile:
            return source
    return {
        "name": f"soak-{spec.default_parser_profile.replace('_', '-')}-source",
        "source_type": spec.default_source_type,
        "parser_profile": spec.default_parser_profile,
    }


def _build_events(*, iterations: int, scenario_mix: list[str], source_count: int) -> tuple[list[SoakEvent], list[dict[str, str]]]:
    sources = _source_specs(source_count)
    events: list[SoakEvent] = []
    for iteration in range(1, max(1, iterations) + 1):
        for scenario in scenario_mix:
            spec = SCENARIOS[scenario]
            source = _source_for_scenario(spec, sources)
            events.append(
                SoakEvent(
                    iteration=iteration,
                    scenario=scenario,
                    source_name=source["name"],
                    source_type=source["source_type"],
                    parser_profile=source["parser_profile"],
                )
            )
    return events, sources


def _dry_run_parser_metrics(events: list[SoakEvent]) -> dict[str, Any]:
    totals = {
        "logs_attempted": 0,
        "parsed_successfully": 0,
        "parse_failures": 0,
        "parser_warning_count": 0,
        "raw_fallback_count": 0,
        "unknown_app_count": 0,
        "missing_timestamp_count": 0,
        "missing_src_ip_count": 0,
        "missing_dst_ip_count": 0,
        "missing_action_count": 0,
    }
    for event in events:
        spec = SCENARIOS[event.scenario]
        path = _scenario_path(spec)
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if not line.strip():
                continue
            totals["logs_attempted"] += 1
            parsed = parse_log_line_for_profile(line, event.parser_profile)
            parsed_json = parsed.parsed_json if isinstance(parsed.parsed_json, dict) else {}
            normalized = parsed.normalized if isinstance(parsed.normalized, dict) else {}
            warnings = parsed_json.get("parser_warnings") or []
            totals["parser_warning_count"] += len(warnings)
            totals["raw_fallback_count"] += 1 if parsed_json.get("raw_fallback") else 0
            if parsed.error:
                totals["parse_failures"] += 1
            else:
                totals["parsed_successfully"] += 1
            if not (normalized.get("generated_time") or normalized.get("receive_time") or parsed.syslog_timestamp):
                totals["missing_timestamp_count"] += 1
            if not normalized.get("src_ip"):
                totals["missing_src_ip_count"] += 1
            if not normalized.get("dst_ip"):
                totals["missing_dst_ip_count"] += 1
            if not normalized.get("action"):
                totals["missing_action_count"] += 1
            if str(normalized.get("app") or "").strip().lower() in {"", "unknown", "unknown-tcp", "unknown-udp", "incomplete", "not-applicable"}:
                totals["unknown_app_count"] += 1
    return totals


def _source_parser_metrics(db: Session, source_id: int) -> dict[str, Any]:
    rows = list(
        db.scalars(
            select(NormalizedLog)
            .join(RawLog, RawLog.id == NormalizedLog.raw_log_id)
            .where(RawLog.source_id == source_id)
        )
    )
    parser_warning_count = 0
    raw_fallback_count = 0
    missing_timestamp_count = 0
    missing_src_ip_count = 0
    missing_dst_ip_count = 0
    missing_action_count = 0
    unknown_app_count = 0
    for row in rows:
        parsed_json = row.parsed_json if isinstance(row.parsed_json, dict) else {}
        parser_warning_count += len(parsed_json.get("parser_warnings") or [])
        raw_fallback_count += 1 if parsed_json.get("raw_fallback") else 0
        raw = row.raw_log
        if not (row.generated_time or row.receive_time or (raw and raw.syslog_timestamp)):
            missing_timestamp_count += 1
        if not row.src_ip:
            missing_src_ip_count += 1
        if not row.dst_ip:
            missing_dst_ip_count += 1
        if not row.action:
            missing_action_count += 1
        if str(row.app or "").strip().lower() in {"", "unknown", "unknown-tcp", "unknown-udp", "incomplete", "not-applicable"}:
            unknown_app_count += 1
    return {
        "normalized_logs": len(rows),
        "parser_warning_count": parser_warning_count,
        "raw_fallback_count": raw_fallback_count,
        "missing_timestamp_count": missing_timestamp_count,
        "missing_src_ip_count": missing_src_ip_count,
        "missing_dst_ip_count": missing_dst_ip_count,
        "missing_action_count": missing_action_count,
        "unknown_app_count": unknown_app_count,
        "unknown_app_rate": round((unknown_app_count / len(rows)) * 100, 2) if rows else 0.0,
    }


def _expected_event_result(event: SoakEvent, detection_result: dict[str, Any] | None) -> dict[str, Any]:
    expectations = _load_expectations()
    expected = expectations.get(event.scenario, {})
    expected_alert = bool(expected.get("expected_alert_present"))
    created = int((detection_result or {}).get("created_alerts") or 0)
    dedup = int((detection_result or {}).get("deduplicated_alert_updates") or 0)
    observed_alert = (created + dedup) > 0
    top_attack_types = [str(item.get("name")) for item in (detection_result or {}).get("top_attack_types", []) if item.get("name")]
    allowed = _allowed_attack_types(expected)
    unexpected_types = sorted(set(top_attack_types) - allowed) if allowed and observed_alert else []
    false_positive = not expected_alert and observed_alert
    false_negative = expected_alert and not observed_alert
    return {
        "expected_alert": expected_alert,
        "observed_alert_delta": observed_alert,
        "false_positive": false_positive,
        "false_negative": false_negative,
        "unexpected_attack_types": unexpected_types,
        "created_alerts": created,
        "deduplicated_alert_updates": dedup,
        "top_attack_types": top_attack_types,
        "passed": not false_positive and not false_negative and not unexpected_types,
    }


def _source_alerts(db: Session, source_id: int) -> list[Alert]:
    return list_alerts(db, source_id=source_id, limit=100)


def _explanation_report(db: Session, source_ids: list[int]) -> dict[str, Any]:
    alerts: list[Alert] = []
    for source_id in source_ids:
        alerts.extend(_source_alerts(db, source_id))
    seen: set[int] = set()
    unique_alerts = []
    for alert in alerts:
        if alert.id not in seen:
            seen.add(alert.id)
            unique_alerts.append(alert)
    checks = []
    for alert in unique_alerts:
        summary = build_alert_detection_summary(db, alert)
        missing = []
        for field in EXPLANATION_REQUIRED_FIELDS:
            value = summary.get(field)
            if field == "response_automation_allowed":
                if value is not False:
                    missing.append(field)
            elif field == "decision_support_only":
                if value is not True:
                    missing.append(field)
            elif not value and value not in (False, 0):
                missing.append(field)
        completeness = alert_explanation_completeness(alert, summary)
        checks.append(
            {
                "alert_id": alert.id,
                "alert_type": alert.alert_type,
                "score": completeness["score"],
                "missing_fields": sorted(set(missing + list(completeness.get("missing", [])))),
                "passed": not missing and bool(completeness.get("passed")),
            }
        )
    return {
        "alert_count_checked": len(checks),
        "passed_count": sum(1 for item in checks if item["passed"]),
        "completeness_score": round(sum(float(item["score"]) for item in checks) / max(len(checks), 1), 4) if checks else 1.0,
        "missing_field_count": sum(len(item["missing_fields"]) for item in checks),
        "checks": checks[:25],
    }


def _source_report(db: Session, sources: list[LogSource]) -> list[dict[str, Any]]:
    rows = []
    for source in sources:
        db.refresh(source)
        source_data = source_to_dict(source, include_quality=True, db=db)
        parser_metrics = _source_parser_metrics(db, source.id)
        health = source_health(source)
        expected_ok = health["status"] in {"healthy", "warning", "error"}
        if source.parser_profile == "palo_alto" and source.parse_failure_count == 0:
            expected_ok = health["status"] in {"healthy", "warning"}
        rows.append(
            {
                "source_id": source.id,
                "name": source.name,
                "source_type": source.source_type,
                "parser_profile": source.parser_profile,
                "status": health["status"],
                "status_expected": expected_ok,
                "last_seen": source.last_seen,
                "last_log_received_at": source.last_log_received_at,
                "logs_received_count": source.logs_received_count,
                "parse_success_count": source.parse_success_count,
                "parse_failure_count": source.parse_failure_count,
                "unknown_app_rate": parser_metrics["unknown_app_rate"],
                "alert_count": (source_data.get("quality") or {}).get("alert_count", 0),
                "latest_ingestion_run": (source_data.get("recent_ingestion_runs") or [None])[0],
                "latest_detection_run": (source_data.get("recent_detection_runs") or [None])[0],
                "latest_errors": [
                    item.get("parser_error")
                    for item in (source_data.get("quality") or {}).get("parse_failure_examples", [])
                    if item.get("parser_error")
                ],
                "warnings": health.get("warnings", []) + (source_data.get("quality") or {}).get("warnings", []),
                "parser_metrics": parser_metrics,
            }
        )
    return rows


def _aggregate_event_results(events: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "event_count": len(events),
        "passed_count": sum(1 for item in events if item.get("passed")),
        "false_positive_scenario_count": sum(1 for item in events if item.get("false_positive")),
        "false_positive_scenarios": [item["scenario"] for item in events if item.get("false_positive")],
        "false_negative_scenario_count": sum(1 for item in events if item.get("false_negative")),
        "false_negative_scenarios": [item["scenario"] for item in events if item.get("false_negative")],
        "unexpected_attack_type_count": sum(len(item.get("unexpected_attack_types") or []) for item in events),
    }


def _count_db_state(db: Session) -> dict[str, int]:
    return {
        "raw_logs": int(db.scalar(select(func.count(RawLog.id))) or 0),
        "normalized_logs": int(db.scalar(select(func.count(NormalizedLog.id))) or 0),
        "alerts": int(db.scalar(select(func.count(Alert.id))) or 0),
        "response_actions": int(db.scalar(select(func.count(ResponseAction.id))) or 0),
        "ml_model_runs": int(db.scalar(select(func.count(MLModelRun.id))) or 0),
    }


def run_no_hardware_soak(
    *,
    duration_seconds: float | None = None,
    iterations: int = 1,
    source_count: int = 3,
    scenario_mix: list[str] | None = None,
    dry_run: bool = False,
    use_temp_db: bool = False,
    run_detection_after: bool = False,
) -> dict[str, Any]:
    started = time.perf_counter()
    selected_scenarios = scenario_mix or list(DEFAULT_SOAK_SCENARIOS)
    events, configured_sources = _build_events(
        iterations=iterations,
        scenario_mix=selected_scenarios,
        source_count=source_count,
    )

    if dry_run:
        parser_metrics = _dry_run_parser_metrics(events)
        return {
            "ok": True,
            "dry_run": True,
            "use_temp_db": use_temp_db,
            "current_database_mutated": False,
            "scenario_mix": selected_scenarios,
            "requested_source_count": source_count,
            "configured_sources": configured_sources,
            "event_count": len(events),
            "parser_drift": parser_metrics,
            "detection": {"skipped": True, "reason": "Dry-run parses only and does not import logs or run detection."},
            "safety": {
                "response_actions_created": 0,
                "automatic_response_enabled": False,
                "real_firewall_blocking_enabled": False,
                "ml_activated_or_promoted": False,
            },
            "runtime_seconds": round(time.perf_counter() - started, 3),
        }

    temp_engine = None
    if use_temp_db:
        temp_engine, SessionFactory = _temp_session_factory()
    else:
        init_db()
        SessionFactory = SessionLocal

    try:
        with SessionFactory() as db:
            before_counts = _count_db_state(db)
            source_by_key: dict[tuple[str, str], LogSource] = {}
            event_results: list[dict[str, Any]] = []
            import_totals = {
                "logs_attempted": 0,
                "raw_logs_imported": 0,
                "normalized_logs_created": 0,
                "parse_failures": 0,
                "duplicate_raw_logs": 0,
                "alerts_created": 0,
                "alerts_deduplicated": 0,
                "alerts_suppressed": 0,
            }

            for event in events:
                if duration_seconds is not None and duration_seconds > 0 and (time.perf_counter() - started) > duration_seconds:
                    break
                spec = SCENARIOS[event.scenario]
                path = _scenario_path(spec)
                source = get_or_create_source(
                    db,
                    name=event.source_name,
                    source_type=event.source_type,
                    parser_profile=event.parser_profile,
                )
                db.commit()
                db.refresh(source)
                source_by_key[(source.name, source.parser_profile)] = source
                import_result = import_log_file(
                    db,
                    path,
                    actor="no_hardware_soak",
                    source_id=source.id,
                    parser_profile=event.parser_profile,
                )
                detection_result = None
                if run_detection_after:
                    detection_result = run_detection(
                        db,
                        limit=max(100, count_nonblank_log_lines(path) * 4),
                        use_ml=False,
                        actor="no_hardware_soak",
                        source_id=source.id,
                        source_name=source.name,
                        source_type=source.source_type,
                    )
                import_totals["logs_attempted"] += int(import_result.get("available_lines") or 0)
                import_totals["raw_logs_imported"] += int(import_result.get("raw_logs_imported") or 0)
                import_totals["normalized_logs_created"] += int(import_result.get("normalized_logs_created") or 0)
                import_totals["parse_failures"] += int(import_result.get("parse_failures") or 0)
                import_totals["duplicate_raw_logs"] += int(import_result.get("duplicate_raw_logs") or 0)
                if detection_result:
                    import_totals["alerts_created"] += int(detection_result.get("created_alerts") or 0)
                    import_totals["alerts_deduplicated"] += int(detection_result.get("deduplicated_alert_updates") or 0)
                    import_totals["alerts_suppressed"] += int(detection_result.get("suppressed_low_groups") or 0) + int(
                        detection_result.get("suppressed_by_rules") or 0
                    )
                expected_result = (
                    _expected_event_result(event, detection_result)
                    if run_detection_after
                    else {"passed": True, "skipped": True, "reason": "Detection was not requested."}
                )
                event_results.append(
                    {
                        "iteration": event.iteration,
                        "scenario": event.scenario,
                        "source_name": source.name,
                        "parser_profile": source.parser_profile,
                        "available_lines": import_result.get("available_lines"),
                        "raw_logs_imported": import_result.get("raw_logs_imported"),
                        "normalized_logs_created": import_result.get("normalized_logs_created"),
                        "parse_failures": import_result.get("parse_failures"),
                        "duplicate_raw_logs": import_result.get("duplicate_raw_logs"),
                        "detection_result": detection_result,
                        **expected_result,
                    }
                )

            sources = list(source_by_key.values())
            source_rows = _source_report(db, sources)
            source_ids = [source.id for source in sources]
            explanation = _explanation_report(db, source_ids)
            after_counts = _count_db_state(db)
            response_actions_created = max(0, after_counts["response_actions"] - before_counts["response_actions"])
            ml_runs_created = max(0, after_counts["ml_model_runs"] - before_counts["ml_model_runs"])
            parser_drift = {
                "parser_warning_count": sum((row["parser_metrics"] or {}).get("parser_warning_count", 0) for row in source_rows),
                "raw_fallback_count": sum((row["parser_metrics"] or {}).get("raw_fallback_count", 0) for row in source_rows),
                "missing_timestamp_count": sum((row["parser_metrics"] or {}).get("missing_timestamp_count", 0) for row in source_rows),
                "missing_src_ip_count": sum((row["parser_metrics"] or {}).get("missing_src_ip_count", 0) for row in source_rows),
                "missing_dst_ip_count": sum((row["parser_metrics"] or {}).get("missing_dst_ip_count", 0) for row in source_rows),
                "missing_action_count": sum((row["parser_metrics"] or {}).get("missing_action_count", 0) for row in source_rows),
                "unknown_app_count": sum((row["parser_metrics"] or {}).get("unknown_app_count", 0) for row in source_rows),
            }
            event_summary = _aggregate_event_results(event_results)
            ok = (
                all(item.get("passed", False) for item in event_results)
                and response_actions_created == 0
                and ml_runs_created == 0
                and explanation["missing_field_count"] == 0
                and all(source.get("status_expected") for source in source_rows)
            )
            return {
                "ok": ok,
                "generated_at": datetime.now(timezone.utc),
                "dry_run": False,
                "use_temp_db": use_temp_db,
                "current_database_mutated": not use_temp_db,
                "scenario_mix": selected_scenarios,
                "requested_source_count": source_count,
                "configured_sources": configured_sources,
                "events": event_results,
                "event_summary": event_summary,
                "import_summary": import_totals,
                "parser_drift": parser_drift,
                "source_health": source_rows,
                "explanation_completeness": explanation,
                "safety": {
                    "response_actions_before": before_counts["response_actions"],
                    "response_actions_after": after_counts["response_actions"],
                    "response_actions_created": response_actions_created,
                    "automatic_response_enabled": False,
                    "real_firewall_blocking_enabled": False,
                    "ml_model_runs_before": before_counts["ml_model_runs"],
                    "ml_model_runs_after": after_counts["ml_model_runs"],
                    "ml_activated_or_promoted": False,
                    "ml_model_runs_created": ml_runs_created,
                },
                "runtime_seconds": round(time.perf_counter() - started, 3),
            }
    finally:
        if temp_engine is not None:
            temp_engine.dispose()


def main() -> None:
    parser = argparse.ArgumentParser(description="Run no-hardware ATDR source/parser/detection soak validation.")
    parser.add_argument("--duration-seconds", type=float, default=None)
    parser.add_argument("--iterations", type=int, default=1)
    parser.add_argument("--source-count", type=int, default=3)
    parser.add_argument("--scenario-mix", default=None, help="Comma-separated scenario names. Defaults to v3.19 soak mix.")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--use-temp-db", action="store_true")
    parser.add_argument("--run-detection", action="store_true")
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()

    result = run_no_hardware_soak(
        duration_seconds=args.duration_seconds,
        iterations=args.iterations,
        source_count=args.source_count,
        scenario_mix=_parse_scenario_mix(args.scenario_mix),
        dry_run=args.dry_run,
        use_temp_db=args.use_temp_db,
        run_detection_after=args.run_detection,
    )
    print(json.dumps(result, default=_json_default, indent=2 if args.pretty else None))
    raise SystemExit(0 if result.get("ok") else 1)


if __name__ == "__main__":
    main()
