import argparse
import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from atdr.app.core.config import PROJECT_ROOT
from atdr.app.db.database import Base, SessionLocal, init_db
from atdr.app.db.models import Alert, AlertEvidence, LogSource, NormalizedLog, RawLog, ResponseAction
from atdr.app.parsers.paloalto_parser import parse_log_line_for_profile
from atdr.app.services.alert_service import list_alerts
from atdr.app.services.case_service import list_alert_cases
from atdr.app.services.detection_service import run_detection
from atdr.app.services.log_service import count_nonblank_log_lines, import_log_file
from atdr.app.services.source_service import get_or_create_source, source_health, source_to_dict, update_source


SCENARIO_DIR = PROJECT_ROOT / "data" / "samples" / "scenarios"


@dataclass(frozen=True, slots=True)
class ScenarioSpec:
    name: str
    filename: str
    default_source_type: str
    default_parser_profile: str
    expected: str
    repeat_import_detection: bool = False


SCENARIOS: dict[str, ScenarioSpec] = {
    "normal_allowed_traffic": ScenarioSpec(
        name="normal_allowed_traffic",
        filename="normal_allowed_traffic.txt",
        default_source_type="firewall",
        default_parser_profile="palo_alto",
        expected="No high or critical alerts from normal allowed LAN-to-internet traffic.",
    ),
    "normal_web_dns_quic_traffic": ScenarioSpec(
        name="normal_web_dns_quic_traffic",
        filename="normal_web_dns_quic_traffic.txt",
        default_source_type="firewall",
        default_parser_profile="palo_alto",
        expected="No high or critical alerts from routine web, DNS, and QUIC traffic.",
    ),
    "normal_high_volume_but_allowed_traffic": ScenarioSpec(
        name="normal_high_volume_but_allowed_traffic",
        filename="normal_high_volume_but_allowed_traffic.txt",
        default_source_type="firewall",
        default_parser_profile="palo_alto",
        expected="No high or critical alerts from approved moderate-volume business traffic below exfiltration thresholds.",
    ),
    "normal_repeated_same_service_traffic": ScenarioSpec(
        name="normal_repeated_same_service_traffic",
        filename="normal_repeated_same_service_traffic.txt",
        default_source_type="firewall",
        default_parser_profile="palo_alto",
        expected="No high or critical alerts from repeated allowed access to the same common service.",
    ),
    "mixed_small_subnet_validation": ScenarioSpec(
        name="mixed_small_subnet_validation",
        filename="mixed_small_subnet_validation.txt",
        default_source_type="firewall",
        default_parser_profile="palo_alto",
        expected="Mixed normal, threat-like, and malformed rows should create expected alerts while preserving parser failures.",
    ),
    "port_scan_like_traffic": ScenarioSpec(
        name="port_scan_like_traffic",
        filename="port_scan_like_traffic.txt",
        default_source_type="firewall",
        default_parser_profile="palo_alto",
        expected="At least one suspicious/port-scan alert should be created.",
    ),
    "brute_force_like_traffic": ScenarioSpec(
        name="brute_force_like_traffic",
        filename="brute_force_like_traffic.txt",
        default_source_type="firewall",
        default_parser_profile="palo_alto",
        expected="At least one brute-force-like repeated service attempt alert should be created.",
    ),
    "malware_c2_like_beaconing": ScenarioSpec(
        name="malware_c2_like_beaconing",
        filename="malware_c2_like_beaconing.txt",
        default_source_type="firewall",
        default_parser_profile="palo_alto",
        expected="At least one C2/beaconing-like repeated outbound alert should be created.",
    ),
    "data_exfiltration_suspicion": ScenarioSpec(
        name="data_exfiltration_suspicion",
        filename="data_exfiltration_suspicion.txt",
        default_source_type="firewall",
        default_parser_profile="palo_alto",
        expected="At least one high outbound data transfer alert should be created.",
    ),
    "ddos_or_connection_flood_like": ScenarioSpec(
        name="ddos_or_connection_flood_like",
        filename="ddos_or_connection_flood_like.txt",
        default_source_type="firewall",
        default_parser_profile="palo_alto",
        expected="At least one connection flood-like alert should be created.",
    ),
    "repeated_dedup_traffic": ScenarioSpec(
        name="repeated_dedup_traffic",
        filename="repeated_dedup_traffic.txt",
        default_source_type="firewall",
        default_parser_profile="palo_alto",
        expected="Second detection should deduplicate into an existing active alert.",
        repeat_import_detection=True,
    ),
    "generic_syslog_mixed": ScenarioSpec(
        name="generic_syslog_mixed",
        filename="generic_syslog_mixed.txt",
        default_source_type="router",
        default_parser_profile="generic_syslog",
        expected="Raw evidence should be preserved with limited generic syslog fields.",
    ),
    "malformed_raw_fallback": ScenarioSpec(
        name="malformed_raw_fallback",
        filename="malformed_raw_fallback.txt",
        default_source_type="sample",
        default_parser_profile="raw_fallback",
        expected="Parser failures should be counted without crashing, while raw evidence is preserved.",
    ),
    "policy_violation_suspicious_app": ScenarioSpec(
        name="policy_violation_suspicious_app",
        filename="policy_violation_suspicious_app.txt",
        default_source_type="firewall",
        default_parser_profile="palo_alto",
        expected="At least one policy/suspicious-application alert should be created.",
    ),
}


def _json_default(value: Any) -> str:
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def _scenario_path(spec: ScenarioSpec) -> Path:
    return SCENARIO_DIR / spec.filename


def _temp_session_factory():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    Base.metadata.create_all(engine)
    return engine, sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)


def _parse_dry_run(path: Path, parser_profile: str) -> dict[str, Any]:
    read = parsed = failed = blank = 0
    errors: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8", errors="replace", newline="") as stream:
        for line_number, line in enumerate(stream, start=1):
            if not line.strip():
                blank += 1
                continue
            read += 1
            parsed_line = parse_log_line_for_profile(line, parser_profile)
            if parsed_line.error:
                failed += 1
                errors.append({"line_number": line_number, "error": parsed_line.error})
            else:
                parsed += 1
    return {"read": read, "parsed": parsed, "failed": failed, "blank": blank, "errors": errors[:10]}


def _alert_metadata(alert: Alert) -> dict[str, Any]:
    metadata = next((item for item in alert.matched_rules_json if item.get("code") == "group_metadata"), {})
    return {
        "id": alert.id,
        "title": alert.title,
        "alert_type": alert.alert_type,
        "severity": alert.severity,
        "status": alert.status,
        "threat_score": alert.threat_score,
        "occurrence_count": metadata.get("occurrence_count", metadata.get("evidence_count", len(alert.evidence))),
        "related_log_count": metadata.get("related_log_count", len(alert.evidence)),
        "deduplicated": bool(metadata.get("deduplicated")),
    }


def _source_counts(db: Session, source_id: int) -> dict[str, int]:
    return {
        "raw_logs": int(db.query(RawLog).filter(RawLog.source_id == source_id).count()),
        "normalized_logs": int(db.query(NormalizedLog).join(RawLog).filter(RawLog.source_id == source_id).count()),
        "alerts": int(
            db.query(Alert.id)
            .join(AlertEvidence, AlertEvidence.alert_id == Alert.id)
            .join(NormalizedLog, NormalizedLog.id == AlertEvidence.normalized_log_id)
            .join(RawLog, RawLog.id == NormalizedLog.raw_log_id)
            .filter(RawLog.source_id == source_id)
            .distinct()
            .count()
        ),
    }


def _validate_expected(
    db: Session,
    *,
    spec: ScenarioSpec,
    source: LogSource,
    import_results: list[dict[str, Any]],
    detection_results: list[dict[str, Any]],
    baseline_response_action_count: int,
) -> dict[str, Any]:
    alerts = list_alerts(db, source_id=source.id, limit=50)
    alert_summaries = [_alert_metadata(alert) for alert in alerts]
    counts = _source_counts(db, source.id)
    checks: list[dict[str, Any]] = []

    def add(name: str, passed: bool, detail: str) -> None:
        checks.append({"name": name, "passed": passed, "detail": detail})

    if spec.name in {
        "normal_allowed_traffic",
        "normal_web_dns_quic_traffic",
        "normal_high_volume_but_allowed_traffic",
        "normal_repeated_same_service_traffic",
    }:
        high_critical = [alert for alert in alerts if alert.severity in {"High", "Critical"}]
        add("no_high_or_critical_alerts", not high_critical, f"High/critical alert count: {len(high_critical)}")
    elif spec.name == "mixed_small_subnet_validation":
        alert_codes = {
            str(rule.get("code"))
            for alert in alerts
            for rule in (alert.matched_rules_json or [])
            if rule.get("code")
        }
        add(
            "mixed_port_scan_alert_created",
            "possible_port_scan" in alert_codes,
            f"Observed rule codes: {sorted(alert_codes)}",
        )
        add(
            "mixed_brute_force_alert_created",
            "brute_force_like_attempts" in alert_codes,
            f"Observed rule codes: {sorted(alert_codes)}",
        )
        add(
            "mixed_beaconing_alert_created",
            "beaconing_like_outbound" in alert_codes,
            f"Observed rule codes: {sorted(alert_codes)}",
        )
        add(
            "mixed_parser_handled_odd_rows",
            source.logs_received_count >= 1 and source.parse_failure_count >= 0,
            f"Logs received: {source.logs_received_count}; parse failures: {source.parse_failure_count}.",
        )
    elif spec.name == "port_scan_like_traffic":
        port_scan_alerts = [
            alert
            for alert in alerts
            if alert.alert_type == "possible_port_scan"
            or any(rule.get("code") == "possible_port_scan" for rule in alert.matched_rules_json)
        ]
        add("port_scan_alert_created", bool(port_scan_alerts), f"Port-scan alert count: {len(port_scan_alerts)}")
    elif spec.name == "brute_force_like_traffic":
        brute_force_alerts = [
            alert
            for alert in alerts
            if alert.alert_type == "brute_force_like_attempts"
            or any(rule.get("code") == "brute_force_like_attempts" for rule in alert.matched_rules_json)
        ]
        add("brute_force_alert_created", bool(brute_force_alerts), f"Brute-force-like alert count: {len(brute_force_alerts)}")
    elif spec.name == "malware_c2_like_beaconing":
        beaconing_alerts = [
            alert
            for alert in alerts
            if alert.alert_type == "beaconing_like_outbound"
            or any(rule.get("code") == "beaconing_like_outbound" for rule in alert.matched_rules_json)
        ]
        add("beaconing_alert_created", bool(beaconing_alerts), f"Beaconing-like alert count: {len(beaconing_alerts)}")
    elif spec.name == "data_exfiltration_suspicion":
        exfil_alerts = [
            alert
            for alert in alerts
            if alert.alert_type == "high_outbound_bytes"
            or any(rule.get("code") in {"high_outbound_bytes", "high_bytes_outlier"} for rule in alert.matched_rules_json)
        ]
        add("exfiltration_alert_created", bool(exfil_alerts), f"High outbound transfer alert count: {len(exfil_alerts)}")
    elif spec.name == "ddos_or_connection_flood_like":
        flood_alerts = [
            alert
            for alert in alerts
            if alert.alert_type == "connection_flood_suspicion"
            or any(rule.get("code") == "connection_flood_suspicion" for rule in alert.matched_rules_json)
        ]
        add("connection_flood_alert_created", bool(flood_alerts), f"Connection flood-like alert count: {len(flood_alerts)}")
    elif spec.name == "repeated_dedup_traffic":
        deduped = [alert for alert in alert_summaries if alert["deduplicated"] or alert["occurrence_count"] > 1]
        add("alert_deduplicated", bool(deduped), f"Deduplicated alert count: {len(deduped)}")
        if detection_results:
            add(
                "dedup_count_recorded",
                any(int(result.get("deduplicated_alert_updates") or 0) > 0 for result in detection_results),
                f"Detection dedup counts: {[result.get('deduplicated_alert_updates') for result in detection_results]}",
            )
    elif spec.name == "generic_syslog_mixed":
        add("raw_evidence_preserved", counts["raw_logs"] >= 1, f"Raw logs linked to source: {counts['raw_logs']}")
        add("generic_parse_succeeded", source.parse_success_count >= 1, f"Parse successes: {source.parse_success_count}")
        add(
            "generic_warning_visible",
            source_health(source)["status"] in {"warning", "healthy"},
            f"Source status: {source_health(source)['status']}",
        )
    elif spec.name == "malformed_raw_fallback":
        add("raw_fallback_failures_counted", source.parse_failure_count >= 1, f"Parse failures: {source.parse_failure_count}")
        add("raw_fallback_preserves_rows", counts["raw_logs"] >= 1, f"Raw logs linked to source: {counts['raw_logs']}")
    elif spec.name == "policy_violation_suspicious_app":
        suspicious_app_alerts = [
            alert
            for alert in alerts
            if any(
                rule.get("code") in {"app_risk_5", "suspicious_app_characteristic", "unusual_destination_port"}
                for rule in alert.matched_rules_json
            )
        ]
        add("suspicious_app_alert_created", bool(suspicious_app_alerts), f"Suspicious-app alert count: {len(suspicious_app_alerts)}")

    current_response_action_count = int(db.query(ResponseAction).count())
    add(
        "no_new_response_actions",
        current_response_action_count == baseline_response_action_count,
        f"Response actions before/after: {baseline_response_action_count}/{current_response_action_count}.",
    )
    passed = all(item["passed"] for item in checks)
    return {
        "passed": passed,
        "expected": spec.expected,
        "checks": checks,
        "source_counts": counts,
        "alert_summaries": alert_summaries[:10],
        "cases": list_alert_cases(db, source_id=source.id, limit=10),
    }


def run_source_scenario(
    *,
    scenario: str,
    source_name: str | None = None,
    source_type: str | None = None,
    parser_profile: str | None = None,
    dry_run: bool = False,
    run_detection_after: bool = False,
    use_temp_db: bool = False,
    disable_source_after: bool = False,
) -> dict[str, Any]:
    spec = SCENARIOS[scenario]
    path = _scenario_path(spec)
    resolved_source_type = source_type or spec.default_source_type
    resolved_parser_profile = parser_profile or spec.default_parser_profile
    resolved_source_name = source_name or f"scenario-{scenario}"
    if not path.exists():
        return {"ok": False, "error": f"Scenario sample not found: {path}"}

    if dry_run:
        parsed = _parse_dry_run(path, resolved_parser_profile)
        return {
            "ok": True,
            "dry_run": True,
            "scenario": scenario,
            "sample_path": str(path),
            "source": {
                "name": resolved_source_name,
                "source_type": resolved_source_type,
                "parser_profile": resolved_parser_profile,
            },
            "available_lines": count_nonblank_log_lines(path),
            **parsed,
            "expected_outcome": {"skipped": True, "reason": "Dry-run does not write rows or run detection."},
        }

    temp_engine = None
    if use_temp_db:
        temp_engine, SessionFactory = _temp_session_factory()
    else:
        init_db()
        SessionFactory = SessionLocal

    try:
        with SessionFactory() as db:
            existing = db.scalar(select(LogSource).where(LogSource.name == resolved_source_name).limit(1))
            before = source_to_dict(existing, include_quality=True, db=db) if existing else None
            source = get_or_create_source(
                db,
                name=resolved_source_name,
                source_type=resolved_source_type,
                parser_profile=resolved_parser_profile,
            )
            db.commit()
            db.refresh(source)
            baseline_response_action_count = int(db.query(ResponseAction).count())

            import_results = [
                import_log_file(
                    db,
                    path,
                    actor="source_scenario",
                    source_id=source.id,
                    parser_profile=resolved_parser_profile,
                )
            ]
            detection_results: list[dict[str, Any]] = []
            if run_detection_after:
                detection_results.append(
                    run_detection(
                        db,
                        limit=max(100, count_nonblank_log_lines(path) * 2),
                        use_ml=False,
                        actor="source_scenario",
                        source_id=source.id,
                        source_name=source.name,
                        source_type=source.source_type,
                    )
                )
                if spec.repeat_import_detection:
                    import_results.append(
                        import_log_file(
                            db,
                            path,
                            actor="source_scenario",
                            source_id=source.id,
                            parser_profile=resolved_parser_profile,
                        )
                    )
                    detection_results.append(
                        run_detection(
                            db,
                            limit=max(100, count_nonblank_log_lines(path) * 3),
                            use_ml=False,
                            actor="source_scenario",
                            source_id=source.id,
                            source_name=source.name,
                            source_type=source.source_type,
                        )
                    )

            if disable_source_after:
                raw_before_disable = _source_counts(db, source.id)["raw_logs"]
                source = update_source(db, source, {"enabled": False})
                raw_after_disable = _source_counts(db, source.id)["raw_logs"]
                disabled_check = {
                    "raw_logs_before_disable": raw_before_disable,
                    "raw_logs_after_disable": raw_after_disable,
                    "data_preserved": raw_before_disable == raw_after_disable,
                }
            else:
                disabled_check = None

            db.refresh(source)
            after = source_to_dict(source, include_quality=True, db=db)
            expected_outcome = (
                _validate_expected(
                    db,
                    spec=spec,
                    source=source,
                    import_results=import_results,
                    detection_results=detection_results,
                    baseline_response_action_count=baseline_response_action_count,
                )
                if run_detection_after or spec.name in {"generic_syslog_mixed", "malformed_raw_fallback"}
                else {"skipped": True, "reason": "Pass --run-detection to validate alert/case outcomes."}
            )
            return {
                "ok": bool(expected_outcome.get("passed", True)) if not expected_outcome.get("skipped") else True,
                "dry_run": False,
                "use_temp_db": use_temp_db,
                "scenario": scenario,
                "sample_path": str(path),
                "available_lines": count_nonblank_log_lines(path),
                "source_before": before,
                "source_after": after,
                "import_results": import_results,
                "detection_results": detection_results,
                "disabled_source_check": disabled_check,
                "expected_outcome": expected_outcome,
            }
    finally:
        if temp_engine is not None:
            temp_engine.dispose()


def main() -> None:
    parser = argparse.ArgumentParser(description="Run a safe ATDR source-aware lab scenario.")
    parser.add_argument("--scenario", required=True, choices=sorted(SCENARIOS))
    parser.add_argument("--source-name", default=None)
    parser.add_argument("--source-type", default=None, choices=["file_import", "replay", "syslog_udp", "syslog_tcp", "router", "firewall", "sample"])
    parser.add_argument("--parser-profile", default=None, choices=["palo_alto", "generic_syslog", "raw_fallback"])
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--run-detection", action="store_true")
    parser.add_argument("--use-temp-db", action="store_true")
    parser.add_argument("--disable-source-after", action="store_true")
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()

    result = run_source_scenario(
        scenario=args.scenario,
        source_name=args.source_name,
        source_type=args.source_type,
        parser_profile=args.parser_profile,
        dry_run=args.dry_run,
        run_detection_after=args.run_detection,
        use_temp_db=args.use_temp_db,
        disable_source_after=args.disable_source_after,
    )
    print(json.dumps(result, default=_json_default, indent=2 if args.pretty else None))
    raise SystemExit(0 if result.get("ok") else 1)


if __name__ == "__main__":
    main()
