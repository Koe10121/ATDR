import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from atdr.app.db.database import SessionLocal
from atdr.app.detection.supervised_detector import supervised_model_report
from atdr.app.services.ml_service import evaluation_report
from atdr.scripts.detection_reliability_common import RELIABILITY_OUTPUT_DIR, json_default, write_report_files


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# ATDR ML/SOC Triage Reliability Report",
        "",
        f"- Generated at: {report['generated_at']}",
        f"- Label count: {report['label_count']}",
        f"- Reviewed labels: {report['reviewed_label_count']}",
        f"- Decision support only: {report['decision_support_only']}",
        f"- Production promoted: {report['production_promoted']}",
        "",
        "## Triage Metrics",
        "",
    ]
    for key, value in report["triage_metrics"].items():
        lines.append(f"- {key}: {value}")
    lines.extend(["", "## Notes", ""])
    for note in report["notes"]:
        lines.append(f"- {note}")
    return "\n".join(lines)


def run_ml_reliability_report(
    *,
    write_output: bool = True,
    output_dir: Path = RELIABILITY_OUTPUT_DIR,
) -> dict[str, Any]:
    with SessionLocal() as db:
        supervised = supervised_model_report(db)
        anomaly = evaluation_report(db)

    readiness = supervised.get("model_readiness_checklist") or {}
    reviewed_target = int(supervised.get("reviewed_label_target") or 300)
    reviewed_count = int(supervised.get("reviewed_label_count") or 0)
    triage_metrics = {
        "threat_positive_precision": supervised.get("threat_positive_precision", "not_available_in_current_report"),
        "threat_positive_recall": supervised.get("threat_positive_recall", "not_available_in_current_report"),
        "threat_positive_f1": supervised.get("threat_positive_f1", "not_available_in_current_report"),
        "suspicious_recall": supervised.get("suspicious_recall", "not_available_in_current_report"),
        "malicious_recall": supervised.get("malicious_recall", "not_available_in_current_report"),
        "anomaly_rate": anomaly.get("anomaly_rate"),
        "scored_log_count": anomaly.get("scored_log_count"),
    }
    threshold_profiles = {
        "conservative": {"goal": "fewer false positives", "status": "available_when_supervised_report_contains_probabilities"},
        "balanced": {"goal": "default SOC triage balance", "status": supervised.get("soc_triage_mode", "current_default")},
        "recall_high": {"goal": "higher threat recall with more review workload", "status": "candidate_only_until_validated"},
    }
    report = {
        "ok": True,
        "generated_at": datetime.now(timezone.utc),
        "validation_scope": "ML/SOC triage reliability summary",
        "read_only": True,
        "label_count": supervised.get("label_count", 0),
        "reviewed_label_count": reviewed_count,
        "reviewed_label_distribution": supervised.get("reviewed_label_distribution", {}),
        "weak_label_distribution": supervised.get("weak_label_distribution", {}),
        "triage_metrics": triage_metrics,
        "threshold_profiles": threshold_profiles,
        "readiness": readiness,
        "reviewer_workload_estimate": {
            "target_reviewed_labels": reviewed_target,
            "reviewed_labels_remaining_to_target": max(0, reviewed_target - reviewed_count),
            "next_focus": "review false negatives, benign-like false positives, and suspicious/malicious boundary cases",
        },
        "decision_support_only": bool(supervised.get("decision_support_only", True)),
        "production_promoted": False,
        "response_automation_allowed": False,
        "notes": [
            "Metrics are reported only when available from supervised model artifacts/reports.",
            "Weak-label and mixed-label metrics must not be described as production accuracy.",
            "ML output cannot trigger automatic response actions.",
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
            stem_prefix="ml_soc_triage_reliability",
            markdown=render_markdown(report),
        )
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate an honest ML/SOC triage reliability report.")
    parser.add_argument("--no-report", action="store_true")
    parser.add_argument("--output-dir", default=None)
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()
    report = run_ml_reliability_report(
        write_output=not args.no_report,
        output_dir=Path(args.output_dir) if args.output_dir else RELIABILITY_OUTPUT_DIR,
    )
    print(json.dumps(report, default=json_default, indent=2 if args.pretty else None))
    raise SystemExit(0 if report["ok"] else 1)


if __name__ == "__main__":
    main()
