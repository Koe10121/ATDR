import argparse
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from atdr.app.core.config import PROJECT_ROOT
from atdr.app.db.database import SessionLocal, init_db
from atdr.app.db.models import Alert, AlertEvidence, AuditLog, NormalizedLog, RawLog, ResponseAction
from atdr.app.detection.explanations import build_alert_detection_summary
from atdr.app.services.alert_service import list_alerts
from atdr.app.services.case_service import list_alert_cases
from atdr.app.services.detection_service import run_detection
from atdr.app.services.log_service import count_nonblank_log_lines, import_log_file
from atdr.app.services.response_service import block_ip
from atdr.app.services.source_service import get_or_create_source, source_to_dict
from atdr.scripts.run_detection_validation_suite import SEVERITY_RANK, _json_default, _load_expectations
from atdr.scripts.run_source_scenario import SCENARIOS, _temp_session_factory


SCENARIO_DIR = PROJECT_ROOT / "data" / "samples" / "scenarios"
DEFAULT_OUTPUT_DIR = PROJECT_ROOT / "demo_exports" / "e2e_validation"
DEFAULT_SCENARIOS = ["port_scan_like_traffic", "policy_violation_suspicious_app", "mixed_small_subnet_validation"]
PROTECTED_TEST_IP = "10.0.0.1"
SAFE_EXTERNAL_TEST_IP = "203.0.113.250"


def _count_source_raw_logs(db: Session, source_id: int) -> int:
    return int(db.scalar(select(func.count(RawLog.id)).where(RawLog.source_id == source_id)) or 0)


def _count_source_normalized_logs(db: Session, source_id: int) -> int:
    statement = (
        select(func.count(NormalizedLog.id))
        .join(RawLog, RawLog.id == NormalizedLog.raw_log_id)
        .where(RawLog.source_id == source_id)
    )
    return int(db.scalar(statement) or 0)


def _source_name(base: str, scenario: str, *, multiple: bool, use_temp_db: bool) -> str:
    if multiple or use_temp_db:
        return f"{base}-{scenario}"
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    return f"{base}-{scenario}-{stamp}"


def _expected_attack_types(expectation: dict[str, Any]) -> set[str]:
    if expectation.get("expected_attack_types"):
        return {str(item) for item in expectation["expected_attack_types"]}
    if expectation.get("expected_attack_type"):
        return {str(expectation["expected_attack_type"])}
    return set()


def _alert_rows(db: Session, source_id: int) -> tuple[list[Alert], list[dict[str, Any]], list[dict[str, Any]]]:
    alerts = list_alerts(db, source_id=source_id, limit=75)
    summaries = [build_alert_detection_summary(db, alert) for alert in alerts]
    rows = [
        {
            "alert_id": alert.id,
            "title": alert.title,
            "alert_type": alert.alert_type,
            "status": alert.status,
            "severity": alert.severity,
            "risk_score": alert.threat_score,
            "src_ip": alert.src_ip,
            "dst_ip": alert.dst_ip,
            "evidence_count": len(alert.evidence),
            "attack_type": summary.get("attack_type"),
            "why_flagged": summary.get("why_flagged"),
            "detection_source": summary.get("detection_source"),
            "top_evidence_points": summary.get("top_evidence_points", []),
            "hybrid_risk": summary.get("hybrid_risk"),
            "decision_support_only": (summary.get("supervised") or {}).get("decision_support_only", True),
        }
        for alert, summary in zip(alerts, summaries, strict=False)
    ]
    return alerts, rows, summaries


def _evidence_summary(db: Session, alerts: list[Alert]) -> dict[str, Any]:
    alert_ids = [alert.id for alert in alerts if alert.id is not None]
    if not alert_ids:
        return {
            "linked_evidence_count": 0,
            "linked_raw_logs": 0,
            "linked_normalized_logs": 0,
            "sample_log_ids": [],
        }
    evidence_rows = list(db.scalars(select(AlertEvidence).where(AlertEvidence.alert_id.in_(alert_ids)).limit(100)))
    normalized_ids = sorted({row.normalized_log_id for row in evidence_rows if row.normalized_log_id})
    raw_ids = sorted(
        {
            row.normalized_log.raw_log_id
            for row in evidence_rows
            if row.normalized_log is not None and row.normalized_log.raw_log_id is not None
        }
    )
    return {
        "linked_evidence_count": len(evidence_rows),
        "linked_raw_logs": len(raw_ids),
        "linked_normalized_logs": len(normalized_ids),
        "sample_log_ids": normalized_ids[:10],
    }


def _target_ip_for_response(alert_rows: list[dict[str, Any]]) -> str:
    for row in alert_rows:
        candidate = str(row.get("src_ip") or "")
        if candidate and not candidate.startswith(("10.", "172.16.", "192.168.", "127.")):
            return candidate
    return SAFE_EXTERNAL_TEST_IP


def _response_action_to_dict(action: ResponseAction) -> dict[str, Any]:
    return {
        "action_id": action.id,
        "alert_id": action.alert_id,
        "action_type": action.action_type,
        "target_ip": action.target_ip,
        "status": action.status,
        "result_message": action.result_message,
        "executed_by": action.executed_by,
        "executed_at": action.executed_at,
    }


def _audit_count_for_target(db: Session, target_ip: str) -> int:
    return int(db.scalar(select(func.count(AuditLog.id)).where(AuditLog.target_value == target_ip)) or 0)


def _simulate_response_checks(db: Session, *, alert_rows: list[dict[str, Any]], actor: str, response_reason: str) -> dict[str, Any]:
    primary_alert_id = next((int(row["alert_id"]) for row in alert_rows if row.get("alert_id")), None)
    target_ip = _target_ip_for_response(alert_rows)
    denied_missing_note = block_ip(db, target_ip=target_ip, reason="", alert_id=primary_alert_id, actor=actor)
    denied_protected = block_ip(
        db,
        target_ip=PROTECTED_TEST_IP,
        reason="E2E validation protected-IP safety check.",
        alert_id=primary_alert_id,
        actor=actor,
    )
    approved = block_ip(
        db,
        target_ip=target_ip,
        reason=response_reason,
        alert_id=primary_alert_id,
        actor=actor,
    )
    return {
        "simulate_response": True,
        "target_ip": target_ip,
        "protected_test_ip": PROTECTED_TEST_IP,
        "missing_justification_denied": denied_missing_note.status == "denied",
        "protected_ip_denied": denied_protected.status == "denied",
        "approved_simulated": approved.status == "simulated",
        "real_firewall_changed": False,
        "actions": [
            _response_action_to_dict(denied_missing_note),
            _response_action_to_dict(denied_protected),
            _response_action_to_dict(approved),
        ],
        "audit_entries_for_target": _audit_count_for_target(db, target_ip),
        "audit_entries_for_protected_ip": _audit_count_for_target(db, PROTECTED_TEST_IP),
    }


def _check_scenario(
    *,
    scenario: str,
    expectation: dict[str, Any],
    source_detail: dict[str, Any],
    import_result: dict[str, Any],
    detection_result: dict[str, Any],
    alert_rows: list[dict[str, Any]],
    cases: list[dict[str, Any]],
    evidence: dict[str, Any],
    response_summary: dict[str, Any],
    raw_count: int,
    normalized_count: int,
) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []

    def add(name: str, passed: bool, detail: str) -> None:
        checks.append({"name": name, "passed": bool(passed), "detail": detail})

    expected_alert = bool(expectation.get("expected_alert_present"))
    attack_types = {str(row.get("attack_type") or "") for row in alert_rows}
    expected_attack_types = _expected_attack_types(expectation)
    max_score = max((int(row.get("risk_score") or 0) for row in alert_rows), default=0)
    max_severity = max(
        (str(row.get("severity") or "Low") for row in alert_rows),
        key=lambda value: SEVERITY_RANK.get(value, 0),
        default="Low",
    )

    add("raw_logs_preserved", raw_count > 0, f"Raw logs linked to source: {raw_count}.")
    add(
        "normalized_logs_created",
        normalized_count >= int(expectation.get("expected_parser_success_min", 0)),
        f"Normalized logs: {normalized_count}; expected at least {expectation.get('expected_parser_success_min', 0)}.",
    )
    add(
        "parser_success_min",
        int(source_detail.get("parse_success_count") or 0) >= int(expectation.get("expected_parser_success_min", 0)),
        f"Parser successes: {source_detail.get('parse_success_count')}; expected at least {expectation.get('expected_parser_success_min', 0)}.",
    )
    add(
        "parser_failure_min",
        int(source_detail.get("parse_failure_count") or 0) >= int(expectation.get("expected_parse_failures_min", 0)),
        f"Parse failures: {source_detail.get('parse_failure_count')}; expected at least {expectation.get('expected_parse_failures_min', 0)}.",
    )
    health = (source_detail.get("health") or {}).get("status")
    add("source_health_visible", health in {"healthy", "warning"}, f"Source health: {health}.")
    add("detection_evaluated_logs", int(detection_result.get("evaluated") or 0) > 0, f"Detection evaluated {detection_result.get('evaluated')} logs.")
    if expected_alert:
        add("expected_alert_exists", bool(alert_rows), f"Alert count: {len(alert_rows)}.")
        add(
            "expected_attack_type_present",
            expected_attack_types.issubset(attack_types),
            f"Expected {sorted(expected_attack_types)}; actual {sorted(attack_types)}.",
        )
        add(
            "severity_and_risk_present",
            bool(alert_rows) and SEVERITY_RANK.get(max_severity, 0) >= SEVERITY_RANK.get(str(expectation.get("expected_min_severity") or "Low"), 0) and max_score >= int(expectation.get("expected_min_risk_score", 0)),
            f"Max severity/risk: {max_severity}/{max_score}.",
        )
        add(
            "alert_has_evidence",
            any(int(row.get("evidence_count") or 0) > 0 for row in alert_rows),
            f"Evidence counts: {[row.get('evidence_count') for row in alert_rows[:5]]}.",
        )
        add(
            "why_flagged_present",
            any(str(row.get("why_flagged") or "").strip() for row in alert_rows),
            "At least one alert has a Why flagged explanation.",
        )
        add("case_summary_available", bool(cases), f"Cases returned: {len(cases)}.")
        add(
            "investigation_evidence_linked",
            int(evidence.get("linked_evidence_count") or 0) > 0,
            f"Linked evidence rows: {evidence.get('linked_evidence_count')}.",
        )
    else:
        severe = [row for row in alert_rows if SEVERITY_RANK.get(str(row.get("severity") or "Low"), 0) >= SEVERITY_RANK["High"]]
        add("no_high_critical_alerts", not severe, f"High/critical alerts: {len(severe)}.")

    if response_summary.get("simulate_response"):
        add(
            "missing_justification_denied",
            bool(response_summary.get("missing_justification_denied")),
            "Simulated response without analyst note is denied.",
        )
        add(
            "protected_ip_denied",
            bool(response_summary.get("protected_ip_denied")),
            "Protected internal/management IP is denied.",
        )
        add(
            "approved_response_simulated",
            bool(response_summary.get("approved_simulated")),
            "Approved response remains simulated.",
        )
        add(
            "response_audit_recorded",
            int(response_summary.get("audit_entries_for_target") or 0) > 0
            and int(response_summary.get("audit_entries_for_protected_ip") or 0) > 0,
            "Audit entries exist for simulated and denied response attempts.",
        )
    else:
        add("no_automatic_response", True, "Response simulation was not requested and no response workflow was executed.")
    return checks


def run_e2e_workflow_validation(
    *,
    scenarios: list[str] | None = None,
    source_name: str = "e2e-validation-source",
    use_temp_db: bool = True,
    simulate_response: bool = False,
    response_reason: str = "E2E validation simulated analyst approval.",
    write_output: bool = True,
    output_dir: Path = DEFAULT_OUTPUT_DIR,
) -> dict[str, Any]:
    selected = scenarios or list(DEFAULT_SCENARIOS)
    expectations = _load_expectations()
    unknown = sorted(set(selected) - set(SCENARIOS))
    if unknown:
        raise ValueError(f"Unknown scenario(s): {', '.join(unknown)}")

    temp_engine = None
    if use_temp_db:
        temp_engine, SessionFactory = _temp_session_factory()
    else:
        init_db()
        SessionFactory = SessionLocal

    started = time.perf_counter()
    scenario_results: list[dict[str, Any]] = []
    try:
        with SessionFactory() as db:
            for scenario in selected:
                scenario_start = time.perf_counter()
                spec = SCENARIOS[scenario]
                path = SCENARIO_DIR / spec.filename
                if not path.exists():
                    raise FileNotFoundError(path)
                source = get_or_create_source(
                    db,
                    name=_source_name(source_name, scenario, multiple=len(selected) > 1, use_temp_db=use_temp_db),
                    source_type=spec.default_source_type,
                    parser_profile=spec.default_parser_profile,
                )
                db.commit()
                db.refresh(source)
                response_actions_before = int(db.query(ResponseAction).count())
                import_start = time.perf_counter()
                import_result = import_log_file(
                    db,
                    path,
                    actor="e2e_workflow_validation",
                    source_id=source.id,
                    parser_profile=spec.default_parser_profile,
                )
                import_seconds = round(time.perf_counter() - import_start, 4)
                detection_start = time.perf_counter()
                detection_result = run_detection(
                    db,
                    limit=max(100, count_nonblank_log_lines(path) * 3),
                    use_ml=True,
                    actor="e2e_workflow_validation",
                    source_id=source.id,
                    source_name=source.name,
                    source_type=source.source_type,
                )
                detection_seconds = round(time.perf_counter() - detection_start, 4)
                if spec.repeat_import_detection:
                    import_log_file(
                        db,
                        path,
                        actor="e2e_workflow_validation",
                        source_id=source.id,
                        parser_profile=spec.default_parser_profile,
                    )
                    detection_result = run_detection(
                        db,
                        limit=max(100, count_nonblank_log_lines(path) * 3),
                        use_ml=True,
                        actor="e2e_workflow_validation",
                        source_id=source.id,
                        source_name=source.name,
                        source_type=source.source_type,
                    )
                db.refresh(source)
                raw_count = _count_source_raw_logs(db, source.id)
                normalized_count = _count_source_normalized_logs(db, source.id)
                alerts, alert_rows, _summaries = _alert_rows(db, source.id)
                cases = list_alert_cases(db, source_id=source.id, active_only=False, limit=20)
                evidence = _evidence_summary(db, alerts)
                response_summary: dict[str, Any] = {
                    "simulate_response": False,
                    "response_actions_created": int(db.query(ResponseAction).count()) - response_actions_before,
                    "note": "No response actions were created because --simulate-response was not passed.",
                }
                if simulate_response and alert_rows:
                    response_summary = _simulate_response_checks(
                        db,
                        alert_rows=alert_rows,
                        actor="e2e_workflow_validation",
                        response_reason=response_reason,
                    )
                    response_summary["response_reason"] = response_reason
                    response_summary["response_actions_created"] = int(db.query(ResponseAction).count()) - response_actions_before

                source_detail = source_to_dict(source, include_quality=True, db=db)
                checks = _check_scenario(
                    scenario=scenario,
                    expectation=expectations[scenario],
                    source_detail=source_detail,
                    import_result=import_result,
                    detection_result=detection_result,
                    alert_rows=alert_rows,
                    cases=cases,
                    evidence=evidence,
                    response_summary=response_summary,
                    raw_count=raw_count,
                    normalized_count=normalized_count,
                )
                response_actions_after = int(db.query(ResponseAction).count())
                scenario_results.append(
                    {
                        "scenario": scenario,
                        "passed": all(item["passed"] for item in checks),
                        "sample_file": path.name,
                        "source": source_detail,
                        "ingestion": import_result,
                        "parser_normalization": {
                            "raw_logs": raw_count,
                            "normalized_logs": normalized_count,
                            "parse_success": source.parse_success_count,
                            "parse_failures": source.parse_failure_count,
                        },
                        "detection": detection_result,
                        "alerts": alert_rows,
                        "alert_count": len(alert_rows),
                        "cases": cases,
                        "case_count": len(cases),
                        "investigation_evidence": evidence,
                        "response_safety": response_summary,
                        "audit_summary": {
                            "response_actions_before": response_actions_before,
                            "response_actions_after": response_actions_after,
                            "response_actions_created": response_actions_after - response_actions_before,
                        },
                        "performance": {
                            "import_seconds": import_seconds,
                            "detection_seconds": detection_seconds,
                            "scenario_seconds": round(time.perf_counter() - scenario_start, 4),
                        },
                        "checks": checks,
                    }
                )
    finally:
        if temp_engine is not None:
            temp_engine.dispose()

    report = {
        "ok": all(item["passed"] for item in scenario_results),
        "generated_at": datetime.now(timezone.utc),
        "validation_scope": "controlled end-to-end ATDR workflow validation",
        "use_temp_db": use_temp_db,
        "simulate_response": simulate_response,
        "scenario_count": len(scenario_results),
        "passed_count": sum(1 for item in scenario_results if item["passed"]),
        "failed_count": sum(1 for item in scenario_results if not item["passed"]),
        "scenarios": scenario_results,
        "performance": {
            "total_seconds": round(time.perf_counter() - started, 4),
        },
        "safety": {
            "automatic_response_enabled": False,
            "real_firewall_blocking_enabled": False,
            "response_mode": "simulated analyst-approved only",
            "production_readiness_claim": False,
            "ml_decision_support_only": True,
        },
        "limitations": [
            "Controlled lab-scale validation only; not production certification.",
            "No real firewall blocking or automatic response is enabled.",
            "Real router/firewall forwarding remains future controlled validation.",
        ],
    }
    if write_output:
        report["paths"] = write_report(report, output_dir=output_dir)
    return report


def render_markdown_report(report: dict[str, Any]) -> str:
    lines = [
        "# ATDR v1.0 End-to-End Workflow Validation",
        "",
        f"- Generated at: {report['generated_at']}",
        "- Scope: controlled log-ingestion to analyst-action workflow validation",
        f"- Database mode: {'temporary in-memory SQLite' if report['use_temp_db'] else 'current local database'}",
        f"- Simulated response exercised: {'yes' if report['simulate_response'] else 'no'}",
        "- Response mode: simulated and analyst-approved only",
        "- Real firewall blocking: disabled",
        "- Production readiness claim: none",
        "",
        "## Summary",
        "",
        f"- Passed scenarios: {report['passed_count']} / {report['scenario_count']}",
        f"- Total runtime seconds: {report['performance']['total_seconds']}",
        "",
        "| Scenario | Result | Raw | Normalized | Alerts | Cases | Response actions |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: |",
    ]
    for item in report["scenarios"]:
        parser = item["parser_normalization"]
        audit = item["audit_summary"]
        lines.append(
            "| "
            f"{item['scenario']} | {'PASS' if item['passed'] else 'REVIEW'} | "
            f"{parser['raw_logs']} | {parser['normalized_logs']} | {item['alert_count']} | "
            f"{item['case_count']} | {audit['response_actions_created']} |"
        )
    lines.extend(["", "## Scenario Details", ""])
    for item in report["scenarios"]:
        lines.extend(
            [
                f"### {item['scenario']}",
                "",
                f"- Source: {item['source'].get('name')} ({item['source'].get('source_type')} / {item['source'].get('parser_profile')})",
                f"- Source health: {(item['source'].get('health') or {}).get('status')}",
                f"- Raw logs: {item['parser_normalization']['raw_logs']}",
                f"- Normalized logs: {item['parser_normalization']['normalized_logs']}",
                f"- Detection evaluated: {item['detection'].get('evaluated')}",
                f"- Alerts: {item['alert_count']}",
                f"- Cases: {item['case_count']}",
                f"- Linked evidence rows: {item['investigation_evidence'].get('linked_evidence_count')}",
                "",
                "Checks:",
            ]
        )
        for check in item["checks"]:
            lines.append(f"- {'PASS' if check['passed'] else 'FAIL'} {check['name']}: {check['detail']}")
        if item["alerts"]:
            lines.extend(["", "Alert evidence:"])
            for alert in item["alerts"][:5]:
                lines.append(f"- {alert['alert_type']} ({alert['severity']} / {alert['risk_score']}): {alert['why_flagged']}")
        lines.append("")
    lines.extend(
        [
            "## Limitations",
            "",
            "- This validates a controlled small-subnet/lab-scale workflow, not production readiness.",
            "- No real attacks are executed.",
            "- No real firewall/router blocking is performed.",
            "- ML remains SOC triage decision support.",
            "- Response actions remain simulated and analyst-approved.",
            "",
        ]
    )
    return "\n".join(lines)


def write_report(report: dict[str, Any], output_dir: Path = DEFAULT_OUTPUT_DIR) -> dict[str, str]:
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    stem = f"e2e_workflow_validation_{timestamp}"
    json_path = output_dir / f"{stem}.json"
    markdown_path = output_dir / f"{stem}.md"
    json_path.write_text(json.dumps(report, default=_json_default, indent=2), encoding="utf-8")
    markdown_path.write_text(render_markdown_report(report), encoding="utf-8")
    return {"json": str(json_path), "markdown": str(markdown_path)}


def main() -> None:
    parser = argparse.ArgumentParser(description="Run controlled end-to-end ATDR workflow validation.")
    parser.add_argument("--scenario", action="append", choices=sorted(SCENARIOS), help="Scenario to validate. Repeat for multiple.")
    parser.add_argument("--source-name", default="e2e-validation-source")
    parser.add_argument("--use-temp-db", action="store_true", default=True, help="Use temporary in-memory SQLite; default true.")
    parser.add_argument("--write-to-current-db", action="store_true", help="Opt in to writing validation rows to the current local DB.")
    parser.add_argument("--simulate-response", action="store_true", help="Exercise safe simulated response approval and denial checks.")
    parser.add_argument("--response-reason", default="E2E validation simulated analyst approval.")
    parser.add_argument("--no-report", action="store_true")
    parser.add_argument("--output-dir", default=None)
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()

    report = run_e2e_workflow_validation(
        scenarios=args.scenario,
        source_name=args.source_name,
        use_temp_db=not args.write_to_current_db,
        simulate_response=args.simulate_response,
        response_reason=args.response_reason,
        write_output=not args.no_report,
        output_dir=Path(args.output_dir) if args.output_dir else DEFAULT_OUTPUT_DIR,
    )
    print(json.dumps(report, default=_json_default, indent=2 if args.pretty else None))
    raise SystemExit(0 if report["ok"] else 1)


if __name__ == "__main__":
    main()
