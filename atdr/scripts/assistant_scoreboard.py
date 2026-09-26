"""Score the SOC assistant on realistic questions (data/evaluation/assistant_questions.json).

Usage:
    python -m atdr.scripts.assistant_scoreboard                    # keyword router only
    python -m atdr.scripts.assistant_scoreboard --engine ollama    # local model agent
    python -m atdr.scripts.assistant_scoreboard --engine gemini --pause 7
    python -m atdr.scripts.assistant_scoreboard --json             # full JSON report
    python -m atdr.scripts.assistant_scoreboard --engine ollama --questions data/evaluation/assistant_questions_holdout.json

Runs on a scratch copy of the configured database. The full report is saved
under .tmp/assistant_scoreboard/. --pause spaces questions out for a hosted
free tier's per-minute limit.
"""

import argparse
import json
import sys
from pathlib import Path

from atdr.app.services.assistant_scoreboard_service import QUESTIONS_PATH, run_assistant_scoreboard


def render(report: dict) -> str:
    lines = [
        f"Assistant scoreboard ({report['engine']}): {report['passed']}/{report['total']} questions answered well "
        f"({report['pass_rate'] * 100:.0f}%), {report['fallbacks']} fell back to 'no built-in answer'.",
        f"Answer time: {report['seconds_mean']}s on average, {report['seconds_p95']}s at the 95th percentile.",
        *(
            [f"Agent answered {report['agent_answered']}; fell back to the router: {report['agent_fallbacks'] or 'never'}."]
            if report.get("agent_answered") is not None and not report["engine"].startswith(("local", "gemini rewrite"))
            else []
        ),
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
            if row.get("agent_fallback"):
                lines.append(f"      (agent fell back: {row['agent_fallback']})")
    return "\n".join(lines)


def main() -> None:
    # Questions may be in Thai; a Windows console encoding must not crash the report.
    sys.stdout.reconfigure(errors="replace")
    parser = argparse.ArgumentParser(description="Score the SOC assistant on realistic questions.")
    parser.add_argument("--json", action="store_true", help="Print the full JSON report.")
    parser.add_argument("--engine", choices=["off", "ollama", "gemini"], default="off", help="Conversational engine to score.")
    parser.add_argument("--pause", type=float, default=0.0, help="Seconds to wait between questions.")
    parser.add_argument("--questions", type=Path, default=QUESTIONS_PATH, help="Question file (default: the main suite).")
    args = parser.parse_args()
    report = run_assistant_scoreboard(engine=args.engine, pause_seconds=args.pause, questions_path=args.questions)
    print(json.dumps(report, indent=2, default=str) if args.json else render(report))


if __name__ == "__main__":
    main()
