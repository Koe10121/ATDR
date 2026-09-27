"""Blind detection check on MFU traffic the rules were never tuned on.

Usage:
    python -m atdr.scripts.blind_check prepare --log-file "C:\\path\\paloalto-firewall.log"
    python -m atdr.scripts.blind_check score --decisions .tmp/blind_check/decisions.csv

prepare builds .tmp/blind_check/holdout.db from lines 13:45-13:57 of the log
file (a separate database; the live one is not touched), runs the current rules
on it, and writes the labeling rows for the 13:50-13:55 test window
(sample.json / sample.csv, no ATDR verdicts) and the answer key (key.json).
Keep key.json away from the people labeling.

score reads a CSV with columns sample_id and decision (Threat, Normal,
Normal but unusual, Unsure) and prints precision, recall and false-alarm rate
for the whole window with 95% intervals.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from datetime import datetime
from pathlib import Path

from atdr.app.core.config import PROJECT_ROOT
from atdr.app.services.blind_check_service import (
    build_holdout_database,
    detect_holdout,
    draw_blind_sample,
    score_blind_check,
    write_json,
)

OUT_DIR = PROJECT_ROOT / ".tmp" / "blind_check"
# Line numbers of the full 20 May MFU export (773,551 lines, 13:36-13:57): 13:45:00 starts at line 319,644.
DEFAULT_FIRST_LINE = 319_644
DEFAULT_LAST_LINE = 773_551
DEFAULT_WINDOW = ("2026-05-20 13:50:00", "2026-05-20 13:55:00")


def _percent(value: float | None) -> str:
    return "n/a" if value is None else f"{value * 100:.1f}%"


def prepare(args: argparse.Namespace) -> None:
    out = Path(args.out)
    holdout = out / "holdout.db"
    if not holdout.exists():
        print(f"Importing lines {args.first_line:,}-{args.last_line:,} into {holdout} ...", flush=True)
        print(json.dumps(build_holdout_database(Path(args.log_file), holdout, first_line=args.first_line, last_line=args.last_line)))
    print("Running the current detection rules on the holdout ...", flush=True)
    print(json.dumps(detect_holdout(holdout)))
    rows, key = draw_blind_sample(
        holdout,
        window_start=datetime.fromisoformat(args.window_start),
        window_end=datetime.fromisoformat(args.window_end),
        sizes={"alerted": args.alerted, "notable": args.notable, "other": args.other},
        seed=args.seed,
    )
    write_json(out / "sample.json", rows)
    write_json(out / "key.json", key)
    with (out / "sample.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=[*rows[0].keys(), "decision", "note"])
        writer.writeheader()
        writer.writerows(rows)
    print(f"Population in the test window: {key['population']}; sampled: {key['sampled']}")
    print(f"Labeling rows: {out / 'sample.csv'} (no ATDR verdicts). Answer key: {out / 'key.json'}")


def score(args: argparse.Namespace) -> None:
    key = json.loads(Path(args.key).read_text(encoding="utf-8"))
    with Path(args.decisions).open(encoding="utf-8-sig", newline="") as handle:
        decisions = {row["sample_id"]: row.get("decision") for row in csv.DictReader(handle)}
    report = score_blind_check(key, decisions)
    write_json(Path(args.key).with_name("score.json"), report)
    estimate, interval = report["estimate"], report["interval_95"]
    print(f"Blind check, {report['window']['start']} to {report['window']['end']}: {report['labels']}")
    for metric in ("precision", "recall", "false_alarm_rate", "f1"):
        bounds = interval.get(metric)
        span = f" (95% interval {_percent(bounds[0])} to {_percent(bounds[1])})" if bounds else ""
        print(f"  {metric.replace('_', ' ')}: {_percent(estimate[metric])}{span}")
    print(f"  by stratum: {report['by_stratum']}")


def main() -> None:
    sys.stdout.reconfigure(errors="replace")
    parser = argparse.ArgumentParser(description="Blind detection check on unseen MFU traffic.")
    commands = parser.add_subparsers(dest="command", required=True)
    make = commands.add_parser("prepare", help="Build the holdout, run the rules, draw the blind sample.")
    make.add_argument("--log-file", required=True)
    make.add_argument("--first-line", type=int, default=DEFAULT_FIRST_LINE)
    make.add_argument("--last-line", type=int, default=DEFAULT_LAST_LINE)
    make.add_argument("--window-start", default=DEFAULT_WINDOW[0])
    make.add_argument("--window-end", default=DEFAULT_WINDOW[1])
    make.add_argument("--alerted", type=int, default=60)
    make.add_argument("--notable", type=int, default=45)
    make.add_argument("--other", type=int, default=45)
    make.add_argument("--seed", type=int, default=20260927)
    make.add_argument("--out", default=str(OUT_DIR))
    make.set_defaults(handler=prepare)
    grade = commands.add_parser("score", help="Score the team's blind labels.")
    grade.add_argument("--decisions", required=True)
    grade.add_argument("--key", default=str(OUT_DIR / "key.json"))
    grade.set_defaults(handler=score)
    args = parser.parse_args()
    args.handler(args)


if __name__ == "__main__":
    main()
