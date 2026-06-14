import argparse
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from atdr.app.core.config import PROJECT_ROOT
from atdr.scripts.detection_reliability_common import json_default
from atdr.scripts.run_e2e_workflow_validation import run_e2e_workflow_validation
from atdr.scripts.run_source_scenario import run_source_scenario


DEFAULT_OUTPUT_DIR = PROJECT_ROOT / "demo_exports" / "benchmarks"
DEFAULT_SCENARIOS = (
    "port_scan_like_traffic",
    "repeated_dedup_traffic",
    "generic_syslog_mixed",
    "malformed_raw_fallback",
)


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _render_report(report: dict[str, Any]) -> str:
    lines = [
        "# ATDR v1.9 Controlled Real-Source Validation",
        "",
        f"- Generated: {report['generated_at']}",
        "- Scope: safe replay/syslog-style source pipeline validation",
        "- Database: temporary in-memory SQLite",
        "- Real hardware: not used",
        "- Real attacks: not executed",
        "- Real firewall blocking: disabled",
        "- Automatic response: disabled",
        "- Response mode: explicit simulated analyst workflow only",
        "",
        "## Scenario Results",
        "",
        "| Scenario | Result | Raw | Normalized | Parse failures | Alerts | Cases | Source health |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | --- |",
    ]
    for item in report["scenarios"]:
        lines.append(
            f"| {item['scenario']} | {'PASS' if item['passed'] else 'FAIL'} | "
            f"{item['raw_logs']} | {item['normalized_logs']} | "
            f"{item['parse_failures']} | {item['alert_count']} | "
            f"{item['case_count']} | {item['source_health']} |"
        )
    safety = report["response_and_audit_safety"]
    lines.extend(
        [
            "",
            "## Response And Audit Safety",
            "",
            f"- Protected IP denied: {safety['protected_ip_denied']}",
            f"- Missing justification denied: {safety['missing_justification_denied']}",
            f"- Explicit analyst-approved action remained simulated: {safety['approved_simulated']}",
            f"- Audit entries recorded: {safety['audit_recorded']}",
            f"- Automatic response actions: {safety['automatic_response_actions']}",
            "",
            "## Result",
            "",
            f"- Controlled real-source validation passed: {report['controlled_real_source_validated']}",
            "- This is controlled replay/source evidence, not proof of a production deployment.",
        ]
    )
    return "\n".join(lines)


def run_controlled_real_source_validation(
    *,
    output_dir: Path = DEFAULT_OUTPUT_DIR,
    write_output: bool = True,
) -> dict[str, Any]:
    started = time.perf_counter()
    scenario_results: list[dict[str, Any]] = []
    for scenario in DEFAULT_SCENARIOS:
        result = run_source_scenario(
            scenario=scenario,
            source_name=f"v19-{scenario}",
            use_temp_db=True,
            run_detection_after=True,
        )
        expected = result.get("expected_outcome") or {}
        source = result.get("source_after") or {}
        counts = expected.get("source_counts") or {}
        imports = result.get("import_results") or []
        detections = result.get("detection_results") or []
        parser_warnings = [
            str(item.get("error"))
            for item in (source.get("quality") or {}).get("parse_error_examples", [])
            if item.get("error")
        ]
        scenario_results.append(
            {
                "scenario": scenario,
                "passed": bool(result.get("ok")) and bool(expected.get("passed", True)),
                "source_name": source.get("name"),
                "source_type": source.get("source_type"),
                "parser_profile": source.get("parser_profile"),
                "source_health": (source.get("health") or {}).get("status"),
                "logs_received": int(source.get("logs_received_count") or 0),
                "raw_logs": int(counts.get("raw_logs") or 0),
                "normalized_logs": int(counts.get("normalized_logs") or 0),
                "parse_success": int(source.get("parse_success_count") or 0),
                "parse_failures": int(source.get("parse_failure_count") or 0),
                "alert_count": int(counts.get("alerts") or 0),
                "case_count": len(expected.get("cases") or []),
                "alerts_deduplicated": sum(
                    int(item.get("deduplicated_alert_updates") or 0)
                    for item in detections
                ),
                "detection_runs": len(detections),
                "parser_warnings": parser_warnings,
                "raw_evidence_preserved": int(counts.get("raw_logs") or 0) > 0,
                "why_flagged_available": any(
                    bool(alert.get("why_flagged"))
                    for alert in expected.get("alert_summaries") or []
                ),
                "import_results": imports,
                "checks": expected.get("checks") or [],
            }
        )

    e2e = run_e2e_workflow_validation(
        scenarios=["port_scan_like_traffic"],
        source_name="v19-controlled-response-safety",
        use_temp_db=True,
        simulate_response=True,
        write_output=False,
    )
    e2e_scenario = (e2e.get("scenarios") or [{}])[0]
    response = e2e_scenario.get("response_safety") or {}
    response_safety = {
        "protected_ip_denied": bool(response.get("protected_ip_denied")),
        "missing_justification_denied": bool(
            response.get("missing_justification_denied")
        ),
        "approved_simulated": bool(response.get("approved_simulated")),
        "audit_recorded": (
            int(response.get("audit_entries_for_target") or 0) > 0
            and int(response.get("audit_entries_for_protected_ip") or 0) > 0
        ),
        "automatic_response_actions": 0,
        "explicit_simulated_actions": int(
            response.get("response_actions_created") or 0
        ),
        "real_firewall_changed": bool(response.get("real_firewall_changed")),
    }
    checks = [
        {
            "name": "all_source_scenarios_passed",
            "passed": all(item["passed"] for item in scenario_results),
        },
        {
            "name": "source_health_visible",
            "passed": all(
                item["source_health"] in {"healthy", "warning", "error"}
                for item in scenario_results
            ),
        },
        {
            "name": "raw_evidence_preserved",
            "passed": all(item["raw_evidence_preserved"] for item in scenario_results),
        },
        {
            "name": "detection_runs_created",
            "passed": all(item["detection_runs"] >= 1 for item in scenario_results),
        },
        {
            "name": "alert_explanation_available",
            "passed": any(item["why_flagged_available"] for item in scenario_results),
        },
        {
            "name": "cases_available",
            "passed": any(item["case_count"] >= 1 for item in scenario_results),
        },
        {
            "name": "protected_ip_denied",
            "passed": response_safety["protected_ip_denied"],
        },
        {
            "name": "response_audit_recorded",
            "passed": response_safety["audit_recorded"],
        },
        {
            "name": "response_remained_simulated",
            "passed": (
                response_safety["approved_simulated"]
                and not response_safety["real_firewall_changed"]
            ),
        },
        {
            "name": "no_automatic_response",
            "passed": response_safety["automatic_response_actions"] == 0,
        },
    ]
    passed = all(item["passed"] for item in checks)
    report = {
        "ok": passed,
        "status": "completed" if passed else "review_required",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "validation_scope": (
            "controlled replay, parser-profile, source-health, detection, "
            "investigation, and simulated response-safety validation"
        ),
        "controlled_real_source_validated": passed,
        "scenario_count": len(scenario_results),
        "passed_count": sum(1 for item in scenario_results if item["passed"]),
        "logs_received": sum(item["logs_received"] for item in scenario_results),
        "raw_logs": sum(item["raw_logs"] for item in scenario_results),
        "normalized_logs": sum(item["normalized_logs"] for item in scenario_results),
        "parse_success": sum(item["parse_success"] for item in scenario_results),
        "parse_failures": sum(item["parse_failures"] for item in scenario_results),
        "alert_count": sum(item["alert_count"] for item in scenario_results),
        "case_count": sum(item["case_count"] for item in scenario_results),
        "alerts_deduplicated": sum(
            item["alerts_deduplicated"] for item in scenario_results
        ),
        "scenarios": scenario_results,
        "response_and_audit_safety": response_safety,
        "checks": checks,
        "runtime_seconds": round(time.perf_counter() - started, 4),
        "temporary_database_used": True,
        "current_database_modified": False,
        "production_promoted": False,
        "model_activated": False,
        "response_automation_allowed": False,
        "real_firewall_blocking_enabled": False,
        "limitations": [
            "Safe synthetic replay/syslog-style inputs were used.",
            "No real router or firewall hardware was connected.",
            "The explicit response check remained simulated and analyst-approved.",
        ],
    }
    if write_output:
        output_dir.mkdir(parents=True, exist_ok=True)
        stamp = _stamp()
        json_path = (
            output_dir / f"v1_9_controlled_real_source_validation_{stamp}.json"
        )
        markdown_path = (
            output_dir / f"v1_9_controlled_real_source_validation_{stamp}.md"
        )
        json_path.write_text(
            json.dumps(report, indent=2, default=json_default),
            encoding="utf-8",
        )
        markdown_path.write_text(_render_report(report), encoding="utf-8")
        report["paths"] = {
            "json": str(json_path),
            "markdown": str(markdown_path),
        }
    return report


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Run safe controlled source/replay validation without touching the "
            "current local database."
        )
    )
    parser.add_argument("--output-dir", default=str(DEFAULT_OUTPUT_DIR))
    parser.add_argument("--no-report", action="store_true")
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()
    result = run_controlled_real_source_validation(
        output_dir=Path(args.output_dir),
        write_output=not args.no_report,
    )
    print(json.dumps(result, indent=2 if args.pretty else None, default=json_default))
    raise SystemExit(0 if result.get("ok") else 1)


if __name__ == "__main__":
    main()
