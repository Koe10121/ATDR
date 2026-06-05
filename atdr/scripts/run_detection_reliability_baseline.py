import argparse
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from atdr.app.core.config import PROJECT_ROOT
from atdr.scripts.detection_reliability_common import RELIABILITY_OUTPUT_DIR, json_default, write_report_files
from atdr.scripts.run_detection_generalization_suite import run_detection_generalization_suite
from atdr.scripts.run_detection_validation_suite import run_detection_validation_suite
from atdr.scripts.run_e2e_workflow_validation import run_e2e_workflow_validation
from atdr.scripts.run_layered_detection_validation import run_layered_detection_validation


def _risk_bucket(score: int) -> str:
    if score >= 90:
        return "90-100"
    if score >= 70:
        return "70-89"
    if score >= 40:
        return "40-69"
    if score > 0:
        return "1-39"
    return "0"


def _severity_and_risk_distribution(report: dict[str, Any]) -> dict[str, Any]:
    severity: Counter[str] = Counter()
    risk: Counter[str] = Counter()
    alert_volume = 0
    for scenario in report.get("scenarios", []):
        for alert in scenario.get("alerts", []):
            alert_volume += 1
            severity[str(alert.get("severity") or "Unknown")] += 1
            risk[_risk_bucket(int(alert.get("risk_score") or 0))] += 1
    return {
        "alert_volume": alert_volume,
        "severity_distribution": dict(sorted(severity.items())),
        "risk_distribution": dict(sorted(risk.items())),
    }


def _layer_contribution(report: dict[str, Any]) -> dict[str, Any]:
    mode_summary = report.get("mode_summary") or []
    rows = {str(item.get("mode")): item for item in mode_summary}
    return {
        "rules": rows.get("rules_only", {}),
        "anomaly": rows.get("anomaly_only", {}),
        "supervised_soc_triage": rows.get("supervised_only", {}),
        "hybrid": rows.get("hybrid", {}),
        "mode_summary": mode_summary,
    }


def _internal_benchmark_manifest_summary() -> dict[str, Any]:
    path = PROJECT_ROOT / "data" / "samples" / "benchmarks" / "internal_controlled_benchmark.json"
    if not path.exists():
        return {"available": False, "path": str(path)}
    payload = json.loads(path.read_text(encoding="utf-8"))
    entries = payload.get("entries") or []
    labels = Counter(str(item.get("expected_label") or "unknown") for item in entries)
    return {
        "available": True,
        "path": str(path),
        "name": payload.get("name"),
        "version": payload.get("version"),
        "entry_count": len(entries),
        "expected_label_distribution": dict(sorted(labels.items())),
        "automatic_response_expected": bool(payload.get("automatic_response_expected")),
        "production_readiness_claim": bool(payload.get("production_readiness_claim")),
    }


def render_markdown(report: dict[str, Any]) -> str:
    validation = report["scenario_validation"]
    generalization = report["generalization_validation"]
    layered = report["layered_validation"]
    e2e = report["e2e_workflow_validation"]
    lines = [
        "# ATDR v1.1 Detection Reliability Baseline",
        "",
        f"- Generated at: {report['generated_at']}",
        f"- Database mode: {'temporary SQLite' if report['use_temp_db'] else 'current local database'}",
        "- Scope: controlled small-subnet/lab-scale validation",
        "- Production readiness claim: none",
        "- Automatic response: disabled",
        "- Real firewall blocking: disabled",
        "",
        "## Summary",
        "",
        f"- Scenario validation: {validation['passed_count']} / {validation['scenario_count']} passed",
        f"- Generalization validation: {generalization['passed_count']} / {generalization['variant_count']} variants passed",
        f"- Layered validation: {layered['passed_count']} / {layered['mode_run_count']} mode runs passed",
        f"- E2E workflow validation: {e2e['passed_count']} / {e2e['scenario_count']} scenarios passed",
        f"- False positives: {report['false_positive_count']}",
        f"- False negatives: {report['false_negative_count']}",
        f"- Alert volume across scenario validation: {report['alert_volume']}",
        "",
        "## Severity Distribution",
        "",
    ]
    for severity, count in report["severity_distribution"].items():
        lines.append(f"- {severity}: {count}")
    lines.extend(["", "## Risk Distribution", ""])
    for bucket, count in report["risk_distribution"].items():
        lines.append(f"- {bucket}: {count}")
    lines.extend(
        [
            "",
            "## Detection Mode Contribution",
            "",
            "- Rules, anomaly, supervised SOC triage, and hybrid mode summaries are included in the JSON report.",
            "- Supervised ML remains decision support only.",
            "",
            "## Limitations",
            "",
        ]
    )
    for item in report["limitations"]:
        lines.append(f"- {item}")
    return "\n".join(lines)


def run_detection_reliability_baseline(
    *,
    use_temp_db: bool = True,
    write_output: bool = True,
    output_dir: Path = RELIABILITY_OUTPUT_DIR,
) -> dict[str, Any]:
    scenario_report = run_detection_validation_suite(use_temp_db=use_temp_db, write_output=False)
    generalization_report = run_detection_generalization_suite(use_temp_db=use_temp_db, variants=5, write_output=False)
    layered_report = run_layered_detection_validation(use_temp_db=use_temp_db, variants=3, write_output=False)
    e2e_report = run_e2e_workflow_validation(use_temp_db=use_temp_db, simulate_response=True, write_output=False)
    distribution = _severity_and_risk_distribution(scenario_report)
    false_positive_count = int(generalization_report.get("false_positive_count") or 0) + int(layered_report.get("false_positive_count") or 0)
    false_negative_count = int(generalization_report.get("false_negative_count") or 0) + int(layered_report.get("false_negative_count") or 0)
    report = {
        "ok": all(
            bool(item.get("ok"))
            for item in (scenario_report, generalization_report, layered_report, e2e_report)
        ),
        "generated_at": datetime.now(timezone.utc),
        "validation_scope": "controlled detection reliability baseline",
        "use_temp_db": use_temp_db,
        "scenario_validation": {
            "scenario_count": scenario_report["scenario_count"],
            "passed_count": scenario_report["passed_count"],
            "failed_count": scenario_report["scenario_count"] - scenario_report["passed_count"],
        },
        "generalization_validation": {
            "scenario_count": generalization_report["scenario_count"],
            "variant_count": generalization_report["variant_count"],
            "passed_count": generalization_report["passed_count"],
            "failed_count": generalization_report["failed_count"],
            "false_positive_count": generalization_report["false_positive_count"],
            "false_negative_count": generalization_report["false_negative_count"],
        },
        "layered_validation": {
            "scenario_count": layered_report["scenario_count"],
            "variant_count": layered_report["variant_count"],
            "mode_run_count": layered_report["mode_run_count"],
            "passed_count": layered_report["passed_count"],
            "failed_count": layered_report["failed_count"],
            "false_positive_count": layered_report["false_positive_count"],
            "false_negative_count": layered_report["false_negative_count"],
        },
        "e2e_workflow_validation": {
            "scenario_count": e2e_report["scenario_count"],
            "passed_count": e2e_report["passed_count"],
            "failed_count": e2e_report["failed_count"],
            "simulate_response": e2e_report["simulate_response"],
        },
        "false_positive_count": false_positive_count,
        "false_negative_count": false_negative_count,
        "detection_mode_contribution": _layer_contribution(layered_report),
        "internal_controlled_benchmark": _internal_benchmark_manifest_summary(),
        "scenario_details": scenario_report.get("scenarios", []),
        "generalization_families": generalization_report.get("families", []),
        "layered_mode_summary": layered_report.get("mode_summary", []),
        "e2e_scenarios": e2e_report.get("scenarios", []),
        "safety": {
            "automatic_response_enabled": False,
            "real_firewall_blocking_enabled": False,
            "response_mode": "simulated analyst-approved only",
            "production_readiness_claim": False,
            "ml_decision_support_only": True,
        },
        "limitations": [
            "Controlled synthetic/replay validation only; not production certification.",
            "No real attacks or offensive tooling are used.",
            "Real firewall/router forwarding validation remains future controlled lab work.",
            "ML remains SOC triage decision support and is not allowed to trigger response actions.",
        ],
        **distribution,
    }
    if write_output:
        report["paths"] = write_report_files(
            report,
            output_dir=output_dir,
            stem_prefix="detection_reliability_baseline",
            markdown=render_markdown(report),
        )
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the ATDR v1.1 detection reliability baseline.")
    parser.add_argument("--use-temp-db", action="store_true", default=True, help="Use temporary SQLite; default true.")
    parser.add_argument("--write-to-current-db", action="store_true", help="Opt in to writing validation rows to current DB.")
    parser.add_argument("--no-report", action="store_true")
    parser.add_argument("--output-dir", default=None)
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()
    report = run_detection_reliability_baseline(
        use_temp_db=not args.write_to_current_db,
        write_output=not args.no_report,
        output_dir=Path(args.output_dir) if args.output_dir else RELIABILITY_OUTPUT_DIR,
    )
    print(json.dumps(report, default=json_default, indent=2 if args.pretty else None))
    raise SystemExit(0 if report["ok"] else 1)


if __name__ == "__main__":
    main()
