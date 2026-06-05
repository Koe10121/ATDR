import argparse
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from atdr.scripts.detection_reliability_common import (
    RELIABILITY_OUTPUT_DIR,
    json_default,
    load_latest_json,
    write_report_files,
)
from atdr.scripts.run_detection_reliability_baseline import run_detection_reliability_baseline


def _load_baseline(path: Path | None) -> dict[str, Any]:
    if path is not None:
        return json.loads(path.read_text(encoding="utf-8"))
    latest = load_latest_json("detection_reliability_baseline_*.json")
    if latest is not None:
        return latest
    return run_detection_reliability_baseline(write_output=False)


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# ATDR Detection Error Analysis",
        "",
        f"- Generated at: {report['generated_at']}",
        f"- False positives: {report['false_positive_count']}",
        f"- False negatives: {report['false_negative_count']}",
        "",
        "## Noisy Normal Patterns",
        "",
    ]
    for item in report["noisy_normal_patterns"] or ["None observed in the latest controlled baseline."]:
        lines.append(f"- {item}")
    lines.extend(["", "## Missed Threat Patterns", ""])
    for item in report["missed_threat_patterns"] or ["None observed in the latest controlled baseline."]:
        lines.append(f"- {item}")
    lines.extend(["", "## Rule Calibration Notes", ""])
    for item in report["recommendations"]:
        lines.append(f"- {item}")
    return "\n".join(lines)


def analyze_detection_errors(
    *,
    baseline_path: Path | None = None,
    write_output: bool = True,
    output_dir: Path = RELIABILITY_OUTPUT_DIR,
) -> dict[str, Any]:
    baseline = _load_baseline(baseline_path)
    noisy_patterns: list[str] = []
    missed_patterns: list[str] = []
    over_triggered: Counter[str] = Counter()
    under_triggered: Counter[str] = Counter()
    risk_issues: list[str] = []

    for scenario in baseline.get("scenario_details", []):
        expected = scenario.get("expected") or {}
        alerts = scenario.get("alerts") or []
        if not expected.get("expected_alert_present") and alerts:
            noisy_patterns.append(f"{scenario.get('scenario')}: {len(alerts)} alert(s) on expected-clean traffic.")
            for alert in alerts:
                over_triggered[str(alert.get("alert_type") or "unknown")] += 1
        if expected.get("expected_alert_present") and not alerts:
            missed_patterns.append(f"{scenario.get('scenario')}: no alert for expected threat-like scenario.")
            under_triggered[str(expected.get("expected_attack_type") or expected.get("expected_attack_types") or "unknown")] += 1
        max_expected = expected.get("expected_max_risk_score")
        if max_expected is not None:
            for alert in alerts:
                score = int(alert.get("risk_score") or 0)
                if score > int(max_expected):
                    risk_issues.append(f"{scenario.get('scenario')}: {alert.get('alert_type')} risk {score} exceeded max {max_expected}.")

    false_positive_count = int(baseline.get("false_positive_count") or 0) + len(noisy_patterns)
    false_negative_count = int(baseline.get("false_negative_count") or 0) + len(missed_patterns)
    recommendations = [
        "Keep normal and negative-control scenarios clean before broadening detection thresholds.",
        "Prioritize missed threat patterns before increasing ML-driven alert volume.",
        "Review over-triggered rules before applying threshold changes.",
    ]
    if not false_positive_count and not false_negative_count:
        recommendations.insert(0, "No controlled false positives or false negatives were observed in the latest baseline.")

    report = {
        "ok": not false_positive_count and not false_negative_count,
        "generated_at": datetime.now(timezone.utc),
        "validation_scope": "controlled detection false-positive/false-negative analysis",
        "false_positive_count": false_positive_count,
        "false_negative_count": false_negative_count,
        "noisy_normal_patterns": noisy_patterns,
        "missed_threat_patterns": missed_patterns,
        "over_triggered_rules": dict(over_triggered),
        "under_triggered_rules": dict(under_triggered),
        "risk_calibration_issues": risk_issues,
        "recommendations": recommendations,
        "safety": {
            "automatic_response_enabled": False,
            "real_firewall_blocking_enabled": False,
            "production_readiness_claim": False,
        },
    }
    if write_output:
        report["paths"] = write_report_files(
            report,
            output_dir=output_dir,
            stem_prefix="detection_error_analysis",
            markdown=render_markdown(report),
        )
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description="Analyze controlled detection false positives and false negatives.")
    parser.add_argument("--baseline-path", default=None)
    parser.add_argument("--no-report", action="store_true")
    parser.add_argument("--output-dir", default=None)
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()
    report = analyze_detection_errors(
        baseline_path=Path(args.baseline_path) if args.baseline_path else None,
        write_output=not args.no_report,
        output_dir=Path(args.output_dir) if args.output_dir else RELIABILITY_OUTPUT_DIR,
    )
    print(json.dumps(report, default=json_default, indent=2 if args.pretty else None))
    raise SystemExit(0 if report["ok"] else 1)


if __name__ == "__main__":
    main()
