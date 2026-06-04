import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from atdr.app.core.config import PROJECT_ROOT
from atdr.app.db.database import SessionLocal, init_db
from atdr.app.db.models import Alert, LogSource, RawLog, ResponseAction
from atdr.app.detection.explanations import build_alert_detection_summary
from atdr.app.services.alert_service import list_alerts
from atdr.app.services.detection_service import run_detection
from atdr.app.services.log_service import count_nonblank_log_lines, import_log_file
from atdr.app.services.source_service import get_or_create_source, source_to_dict
from atdr.scripts.run_source_scenario import SCENARIOS, _temp_session_factory


SCENARIO_DIR = PROJECT_ROOT / "data" / "samples" / "scenarios"
EXPECTATIONS_PATH = SCENARIO_DIR / "scenario_expectations.json"
DEFAULT_OUTPUT_DIR = PROJECT_ROOT / "demo_exports" / "detection_validation"
SEVERITY_RANK = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}


def _json_default(value: Any) -> str:
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def _load_expectations(path: Path = EXPECTATIONS_PATH) -> dict[str, dict[str, Any]]:
    return json.loads(path.read_text(encoding="utf-8"))


def _scenario_source_name(scenario: str, *, use_temp_db: bool) -> str:
    if use_temp_db:
        return f"validation-{scenario}"
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    return f"validation-{scenario}-{stamp}"


def _severity_at_least(actual: str | None, expected: str | None) -> bool:
    if not expected:
        return True
    return SEVERITY_RANK.get(actual or "Low", 0) >= SEVERITY_RANK.get(expected, 0)


def _alert_text(alert: Alert, summary: dict[str, Any]) -> str:
    rule_text = " ".join(
        f"{rule.get('code', '')} {rule.get('title', '')} {rule.get('explanation', '')}"
        for rule in (alert.matched_rules_json or [])
    )
    evidence_text = " ".join(str(item) for item in summary.get("top_evidence_points", []))
    return " ".join(
        [
            alert.title or "",
            alert.alert_type or "",
            alert.explanation or "",
            rule_text,
            summary.get("why_flagged") or "",
            summary.get("attack_type") or "",
            evidence_text,
        ]
    ).lower()


def _source_counts(db: Session, source_id: int) -> dict[str, int]:
    raw_count = int(db.scalar(select(func.count(RawLog.id)).where(RawLog.source_id == source_id)) or 0)
    source = db.get(LogSource, source_id)
    return {
        "raw_logs": raw_count,
        "logs_received": int(source.logs_received_count if source else 0),
        "parse_success": int(source.parse_success_count if source else 0),
        "parse_failures": int(source.parse_failure_count if source else 0),
    }


def _check_expectations(
    *,
    db: Session,
    scenario: str,
    expectation: dict[str, Any],
    source: LogSource,
    alerts: list[Alert],
    summaries: list[dict[str, Any]],
    response_actions_before: int,
) -> tuple[list[dict[str, Any]], str]:
    checks: list[dict[str, Any]] = []

    def add(name: str, passed: bool, detail: str) -> None:
        checks.append({"name": name, "passed": bool(passed), "detail": detail})

    source_counts = _source_counts(db, source.id)
    alert_present = bool(alerts)
    expected_alert_present = bool(expectation.get("expected_alert_present"))
    max_score = max((alert.threat_score or 0 for alert in alerts), default=0)
    max_severity = max((alert.severity for alert in alerts), key=lambda value: SEVERITY_RANK.get(value, 0), default="Low")
    attack_types = {str(summary.get("attack_type") or "") for summary in summaries}
    evidence_corpus = " ".join(_alert_text(alert, summary) for alert, summary in zip(alerts, summaries, strict=False))
    if source.latest_error:
        evidence_corpus += f" {source.latest_error.lower()}"

    add(
        "parser_success_min",
        source.parse_success_count >= int(expectation.get("expected_parser_success_min", 0)),
        f"Parser successes: {source.parse_success_count}; expected at least {expectation.get('expected_parser_success_min', 0)}.",
    )
    add(
        "raw_evidence_preserved",
        not expectation.get("expected_raw_preserved") or source_counts["raw_logs"] > 0,
        f"Source-linked raw logs: {source_counts['raw_logs']}.",
    )
    if expected_alert_present:
        add("alert_present", alert_present, f"Alert count: {len(alerts)}.")
        expected_attack_type = str(expectation.get("expected_attack_type") or "")
        add(
            "expected_attack_type",
            expected_attack_type in attack_types,
            f"Expected {expected_attack_type}; actual {sorted(attack_types)}.",
        )
        add(
            "min_severity",
            _severity_at_least(max_severity, expectation.get("expected_min_severity")),
            f"Max severity: {max_severity}; expected at least {expectation.get('expected_min_severity')}.",
        )
        add(
            "min_risk_score",
            max_score >= int(expectation.get("expected_min_risk_score", 0)),
            f"Max risk score: {max_score}; expected at least {expectation.get('expected_min_risk_score', 0)}.",
        )
        missing_keywords = [
            keyword for keyword in expectation.get("expected_evidence_keywords", []) if str(keyword).lower() not in evidence_corpus
        ]
        add(
            "evidence_keywords",
            not missing_keywords,
            f"Missing evidence keywords: {missing_keywords or 'none'}.",
        )
    else:
        severe_alerts = [alert for alert in alerts if SEVERITY_RANK.get(alert.severity, 0) >= SEVERITY_RANK["High"]]
        add("no_high_or_critical_alerts", not severe_alerts, f"High/critical alert count: {len(severe_alerts)}.")

    response_actions_after = int(db.query(ResponseAction).count())
    add(
        "no_response_actions",
        response_actions_after == response_actions_before if expectation.get("expected_no_response_actions", True) else True,
        f"Response actions before/after: {response_actions_before}/{response_actions_after}.",
    )
    return checks, evidence_corpus


def run_detection_validation_scenario(
    *,
    scenario: str,
    expectations: dict[str, dict[str, Any]] | None = None,
    use_temp_db: bool = True,
    use_ml: bool = False,
) -> dict[str, Any]:
    expectations = expectations or _load_expectations()
    if scenario not in SCENARIOS:
        raise ValueError(f"Unknown scenario: {scenario}")
    if scenario not in expectations:
        raise ValueError(f"Scenario has no expectation entry: {scenario}")

    spec = SCENARIOS[scenario]
    path = SCENARIO_DIR / spec.filename
    if not path.exists():
        raise FileNotFoundError(path)

    temp_engine = None
    if use_temp_db:
        temp_engine, SessionFactory = _temp_session_factory()
    else:
        init_db()
        SessionFactory = SessionLocal

    try:
        with SessionFactory() as db:
            source = get_or_create_source(
                db,
                name=_scenario_source_name(scenario, use_temp_db=use_temp_db),
                source_type=spec.default_source_type,
                parser_profile=spec.default_parser_profile,
            )
            db.commit()
            db.refresh(source)
            response_actions_before = int(db.query(ResponseAction).count())
            import_result = import_log_file(
                db,
                path,
                actor="detection_validation",
                source_id=source.id,
                parser_profile=spec.default_parser_profile,
            )
            detection_result = run_detection(
                db,
                limit=max(100, count_nonblank_log_lines(path) * 3),
                use_ml=use_ml,
                actor="detection_validation",
                source_id=source.id,
                source_name=source.name,
                source_type=source.source_type,
            )
            db.refresh(source)
            alerts = list_alerts(db, source_id=source.id, limit=50)
            summaries = [build_alert_detection_summary(db, alert) for alert in alerts]
            checks, evidence_corpus = _check_expectations(
                db=db,
                scenario=scenario,
                expectation=expectations[scenario],
                source=source,
                alerts=alerts,
                summaries=summaries,
                response_actions_before=response_actions_before,
            )
            source_detail = source_to_dict(source, include_quality=True, db=db)
            passed = all(check["passed"] for check in checks)
            return {
                "scenario": scenario,
                "passed": passed,
                "sample_path": str(path),
                "expected": expectations[scenario],
                "checks": checks,
                "source": source_detail,
                "import_result": import_result,
                "detection_result": detection_result,
                "alert_count": len(alerts),
                "alerts": [
                    {
                        "alert_id": alert.id,
                        "alert_type": alert.alert_type,
                        "severity": alert.severity,
                        "risk_score": alert.threat_score,
                        "title": alert.title,
                        "evidence_count": len(alert.evidence),
                        "attack_type": summary.get("attack_type"),
                        "why_flagged": summary.get("why_flagged"),
                        "detection_source": summary.get("detection_source"),
                        "top_evidence_points": summary.get("top_evidence_points", []),
                    }
                    for alert, summary in zip(alerts, summaries, strict=False)
                ],
                "ai_soc_triage": {
                    "rule_detection_caught": bool(alerts),
                    "anomaly_signal_present": any(summary.get("anomaly", {}).get("present") for summary in summaries),
                    "supervised_signal_available": any(summary.get("supervised", {}).get("predicted_label") for summary in summaries),
                    "supervised_contributed_to_alert_creation": use_ml,
                    "decision_support_only": True,
                    "hybrid_risk_available": any(bool(summary.get("hybrid_risk")) for summary in summaries),
                },
                "safety": {
                    "controlled_small_subnet_validation": True,
                    "real_production_deployment": False,
                    "automatic_response_enabled": False,
                    "real_firewall_blocking_enabled": False,
                    "response_actions_created": int(db.query(ResponseAction).count()) - response_actions_before,
                },
                "evidence_text_excerpt": evidence_corpus[:1000],
            }
    finally:
        if temp_engine is not None:
            temp_engine.dispose()


def render_markdown_report(report: dict[str, Any]) -> str:
    lines = [
        "# ATDR Controlled Threat Detection Validation",
        "",
        f"- Generated at: {report['generated_at']}",
        "- Validation scope: controlled small-subnet / lab-scale log validation",
        f"- Database mode: {'temporary in-memory SQLite' if report['use_temp_db'] else 'current local database'}",
        "- Response mode: simulated and analyst-approved only",
        "- Real firewall blocking: disabled",
        "- Production readiness claim: none",
        "",
        "## Summary",
        "",
        f"- Passed scenarios: {report['passed_count']} / {report['scenario_count']}",
        "",
        "| Scenario | Result | Alerts | Main actual attack types |",
        "| --- | --- | ---: | --- |",
    ]
    for item in report["scenarios"]:
        attack_types = sorted({str(alert.get("attack_type") or "-") for alert in item.get("alerts", [])}) or ["-"]
        lines.append(
            f"| {item['scenario']} | {'PASS' if item['passed'] else 'FAIL'} | {item['alert_count']} | {', '.join(attack_types)} |"
        )
    lines.extend(["", "## Scenario Details", ""])
    for item in report["scenarios"]:
        lines.extend(
            [
                f"### {item['scenario']}",
                "",
                f"- Result: {'PASS' if item['passed'] else 'FAIL'}",
                f"- Logs imported: {item['import_result'].get('raw_logs_imported', item['import_result'].get('imported', 0))}",
                f"- Parsed successfully: {item['import_result'].get('parsed_successfully', item['import_result'].get('parsed', 0))}",
                f"- Parse failures: {item['import_result'].get('parse_failures', item['import_result'].get('failed', 0))}",
                f"- Alerts created by detection run: {item['detection_result'].get('created_alerts', 0)}",
                f"- Alerts deduplicated: {item['detection_result'].get('deduplicated_alert_updates', 0)}",
                f"- Response actions created: {item['safety']['response_actions_created']}",
                "",
                "Checks:",
            ]
        )
        for check in item["checks"]:
            lines.append(f"- {'PASS' if check['passed'] else 'FAIL'} {check['name']}: {check['detail']}")
        if item["alerts"]:
            lines.append("")
            lines.append("Alert evidence:")
            for alert in item["alerts"][:5]:
                lines.append(
                    f"- {alert['alert_type']} ({alert['severity']} / {alert['risk_score']}): {alert['why_flagged']}"
                )
        lines.append("")
    lines.extend(
        [
            "## Limitations",
            "",
            "- This validates controlled synthetic/replay log scenarios, not production deployment.",
            "- Real router/firewall forwarding remains future lab validation.",
            "- ML remains SOC triage decision support and does not trigger response actions.",
            "- Response actions remain simulated and require analyst approval.",
            "",
        ]
    )
    return "\n".join(lines)


def write_report(report: dict[str, Any], output_dir: Path = DEFAULT_OUTPUT_DIR) -> dict[str, str]:
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    stem = f"detection_validation_{timestamp}"
    json_path = output_dir / f"{stem}.json"
    md_path = output_dir / f"{stem}.md"
    json_path.write_text(json.dumps(report, default=_json_default, indent=2), encoding="utf-8")
    md_path.write_text(render_markdown_report(report), encoding="utf-8")
    return {"json": str(json_path), "markdown": str(md_path)}


def run_detection_validation_suite(
    *,
    scenarios: list[str] | None = None,
    use_temp_db: bool = True,
    use_ml: bool = False,
    write_output: bool = True,
    output_dir: Path = DEFAULT_OUTPUT_DIR,
) -> dict[str, Any]:
    expectations = _load_expectations()
    selected = scenarios or list(expectations.keys())
    results = [
        run_detection_validation_scenario(
            scenario=scenario,
            expectations=expectations,
            use_temp_db=use_temp_db,
            use_ml=use_ml,
        )
        for scenario in selected
    ]
    report = {
        "ok": all(item["passed"] for item in results),
        "generated_at": datetime.now(timezone.utc),
        "validation_scope": "controlled small-subnet / lab-scale threat detection validation",
        "use_temp_db": use_temp_db,
        "use_ml": use_ml,
        "scenario_count": len(results),
        "passed_count": sum(1 for item in results if item["passed"]),
        "scenarios": results,
        "safety": {
            "automatic_response_enabled": False,
            "real_firewall_blocking_enabled": False,
            "response_mode": "simulated analyst-approved only",
            "production_readiness_claim": False,
        },
    }
    if write_output:
        report["paths"] = write_report(report, output_dir=output_dir)
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description="Run controlled small-subnet ATDR detection validation scenarios.")
    parser.add_argument("--scenario", action="append", choices=sorted(SCENARIOS), help="Scenario to validate. Repeat for multiple.")
    parser.add_argument("--all", action="store_true", help="Validate every scenario in scenario_expectations.json.")
    parser.add_argument("--write-to-current-db", action="store_true", help="Opt in to writing scenario rows to the current local DB.")
    parser.add_argument("--use-ml", action="store_true", help="Run detection with assistive ML scoring when available.")
    parser.add_argument("--no-report", action="store_true", help="Do not write JSON/Markdown report files.")
    parser.add_argument("--output-dir", default=None)
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()

    selected = None if args.all or not args.scenario else args.scenario
    report = run_detection_validation_suite(
        scenarios=selected,
        use_temp_db=not args.write_to_current_db,
        use_ml=args.use_ml,
        write_output=not args.no_report,
        output_dir=Path(args.output_dir) if args.output_dir else DEFAULT_OUTPUT_DIR,
    )
    print(json.dumps(report, default=_json_default, indent=2 if args.pretty else None))
    raise SystemExit(0 if report["ok"] else 1)


if __name__ == "__main__":
    main()
