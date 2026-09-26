"""Score the SOC assistant on realistic questions (data/evaluation/assistant_questions.json).

Usage:
    python -m atdr.scripts.assistant_scoreboard              # summary + failures
    python -m atdr.scripts.assistant_scoreboard --json       # full JSON report

Runs on a scratch copy of the configured database with the local
(deterministic) assistant. The full report is saved under .tmp/assistant_scoreboard/.
"""

import argparse
import json

from atdr.app.services.assistant_scoreboard_service import run_assistant_scoreboard


def render(report: dict) -> str:
    lines = [
        f"Assistant scoreboard ({report['engine']}): {report['passed']}/{report['total']} questions answered well "
        f"({report['pass_rate'] * 100:.0f}%), {report['fallbacks']} fell back to 'no built-in answer'.",
        f"Answer time: {report['seconds_mean']}s on average, {report['seconds_p95']}s at the 95th percentile.",
        "",
        "By category:",
    ]
    for name, row in report["by_category"].items():
        lines.append(f"  {name:20} {row['passed']:>3}/{row['total']:<3}")
    failures = [row for row in report["rows"] if not row["passed"]]
    if failures:
        lines.append("")
        lines.append("Failed questions:")
        for row in failures:
            lines.append(f"  [{row['id']}] {row['question']}")
            lines.append(f"      -> {'; '.join(row['problems'])}")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Score the SOC assistant on realistic questions.")
    parser.add_argument("--json", action="store_true", help="Print the full JSON report.")
    args = parser.parse_args()
    report = run_assistant_scoreboard()
    print(json.dumps(report, indent=2, default=str) if args.json else render(report))


if __name__ == "__main__":
    main()
