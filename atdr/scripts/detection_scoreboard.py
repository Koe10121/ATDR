"""Score the current detection rules against human-reviewed labels.

Usage:
    python -m atdr.scripts.detection_scoreboard            # readable table
    python -m atdr.scripts.detection_scoreboard --json     # full JSON report

Works on a scratch copy of the configured SQLite database; the real database
is only read. The full JSON report is saved under .tmp/detection_scoreboard/.
"""

import argparse
import json
from pathlib import Path

from atdr.app.services.detection_scoreboard_service import run_detection_scoreboard


def _pct(value: float | None) -> str:
    return "-" if value is None else f"{value * 100:.1f}%"


def render(report: dict) -> str:
    lines = []
    labels = report["labels"]
    lines.append(
        f"Detection scoreboard: current rules vs {labels['used']:,} human-labeled logs "
        f"({labels['threat']:,} threat, {labels['harmless']:,} harmless)"
    )
    run = report.get("run") or {}
    if run:
        lines.append(f"Re-ran detection over {run['logs_checked']:,} logs in {run['seconds']}s on a scratch copy.")
    lines.append("")
    lines.append(f"{'':16}{'precision':>11}{'recall':>9}{'false alarms':>14}{'F1':>8}{'labeled':>9}")
    for name, key in (("all labels", "all"), ("manual labels", "manual_labels"), ("dev (tune on)", "dev"), ("test (held out)", "test")):
        m = report["overall"][key]
        lines.append(
            f"{name:16}{_pct(m['precision']):>11}{_pct(m['recall']):>9}{_pct(m['false_alarm_rate']):>14}"
            f"{_pct(m['f1']):>8}{m['labeled_logs']:>9,}"
        )
    lines.append("")
    lines.append("Precision by alert type (labeled logs inside those alerts):")
    for key, row in list(report["by_alert_type"].items())[:12]:
        lines.append(f"  {key:34}{_pct(row['precision']):>8}   {row['threat']:>4} threat / {row['harmless']:>4} harmless")
    missed = report["missed_threats_by_attack_type"]
    if missed:
        lines.append("")
        lines.append("Missed threats by labeled attack type: " + ", ".join(f"{k} {v}" for k, v in missed.items()))
    alerts = report["alerts"]
    lines.append("")
    lines.append(
        f"Alerts produced: {alerts['total']:,} ("
        + ", ".join(f"{k} {v:,}" for k, v in alerts["by_severity"].items())
        + ")"
    )
    if report.get("report_path"):
        lines.append(f"Full report: {report['report_path']}")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Score current detection rules against human-reviewed labels.")
    parser.add_argument("--json", action="store_true", help="Print the full JSON report instead of the table.")
    parser.add_argument("--source", type=Path, default=None, help="SQLite file to score (default: configured database).")
    parser.add_argument("--keep-copy", action="store_true", help="Keep the scratch database copy for inspection.")
    parser.add_argument("--batch-size", type=int, default=5000, help="Logs per detection batch (default 5000, as in production).")
    args = parser.parse_args()
    report = run_detection_scoreboard(source=args.source, keep_copy=args.keep_copy, batch_size=args.batch_size)
    print(json.dumps(report, indent=2, default=str) if args.json else render(report))


if __name__ == "__main__":
    main()
