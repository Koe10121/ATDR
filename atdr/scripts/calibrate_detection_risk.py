import argparse
import json
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


SEVERITY_RANK = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}


def _load_baseline(path: Path | None) -> dict[str, Any]:
    if path:
        return json.loads(path.read_text(encoding="utf-8"))
    latest = load_latest_json("detection_reliability_baseline_*.json")
    if latest is not None:
        return latest
    return run_detection_reliability_baseline(write_output=False)


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# ATDR Risk/Severity Calibration v2",
        "",
        f"- Generated at: {report['generated_at']}",
        f"- Outliers: {len(report['outliers'])}",
        f"- Recommendation: {report['recommendation']}",
        "- Threshold changes applied: no",
        "",
        "## Outliers",
        "",
    ]
    for item in report["outliers"] or ["None observed in the latest controlled baseline."]:
        lines.append(f"- {item if isinstance(item, str) else item.get('detail')}")
    lines.extend(["", "## Notes", ""])
    for note in report["notes"]:
        lines.append(f"- {note}")
    return "\n".join(lines)


def calibrate_detection_risk(
    *,
    baseline_path: Path | None = None,
    write_output: bool = True,
    output_dir: Path = RELIABILITY_OUTPUT_DIR,
) -> dict[str, Any]:
    baseline = _load_baseline(baseline_path)
    outliers: list[dict[str, Any]] = []
    for scenario in baseline.get("scenario_details", []):
        expected = scenario.get("expected") or {}
        min_score = expected.get("expected_min_risk_score")
        max_score = expected.get("expected_max_risk_score")
        min_severity = str(expected.get("expected_min_severity") or "Low")
        for alert in scenario.get("alerts", []):
            score = int(alert.get("risk_score") or 0)
            severity = str(alert.get("severity") or "Low")
            if min_score is not None and score < int(min_score):
                outliers.append(
                    {
                        "scenario": scenario.get("scenario"),
                        "alert_type": alert.get("alert_type"),
                        "detail": f"Risk {score} below expected minimum {min_score}.",
                    }
                )
            if max_score is not None and score > int(max_score):
                outliers.append(
                    {
                        "scenario": scenario.get("scenario"),
                        "alert_type": alert.get("alert_type"),
                        "detail": f"Risk {score} above expected maximum {max_score}.",
                    }
                )
            if SEVERITY_RANK.get(severity, 0) < SEVERITY_RANK.get(min_severity, 0):
                outliers.append(
                    {
                        "scenario": scenario.get("scenario"),
                        "alert_type": alert.get("alert_type"),
                        "detail": f"Severity {severity} below expected minimum {min_severity}.",
                    }
                )
    recommendation = "keep_current_thresholds" if not outliers else "review_thresholds_before_change"
    report = {
        "ok": not outliers,
        "generated_at": datetime.now(timezone.utc),
        "validation_scope": "controlled risk and severity calibration v2",
        "outliers": outliers,
        "recommendation": recommendation,
        "threshold_changes_applied": False,
        "notes": [
            "Normal and negative-control scenarios must remain clean before thresholds are broadened.",
            "This script reports recommendations only; it does not mutate detection thresholds.",
            "Risk calibration is controlled lab evidence, not production certification.",
        ],
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
            stem_prefix="risk_calibration_v2",
            markdown=render_markdown(report),
        )
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description="Report risk/severity calibration outliers from controlled validation.")
    parser.add_argument("--baseline-path", default=None)
    parser.add_argument("--no-report", action="store_true")
    parser.add_argument("--output-dir", default=None)
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()
    report = calibrate_detection_risk(
        baseline_path=Path(args.baseline_path) if args.baseline_path else None,
        write_output=not args.no_report,
        output_dir=Path(args.output_dir) if args.output_dir else RELIABILITY_OUTPUT_DIR,
    )
    print(json.dumps(report, default=json_default, indent=2 if args.pretty else None))
    raise SystemExit(0 if report["ok"] else 1)


if __name__ == "__main__":
    main()
