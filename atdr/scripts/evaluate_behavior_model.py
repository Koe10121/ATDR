"""Evaluate the frozen MFU behaviour model on the untouched test window (20 May 13:50-13:55).

Usage:
    python -m atdr.scripts.evaluate_behavior_model
    python -m atdr.scripts.evaluate_behavior_model --review-decisions .tmp/mfu_model/review_decisions.csv
    python -m atdr.scripts.evaluate_behavior_model --blind-decisions .tmp/blind_check/decisions.csv

The first form measures recall on fresh simulated attacks (bar condition 2),
counts the model's flags on real traffic, and writes the blind review rows for
the model-only alerts (review_sample.json / review_key.json; condition 1).
With --review-decisions it scores that review. With --blind-decisions it scores
rules, model, and "rules or model" on the blind-check labels (condition 3).
See docs/detection/ML_QUALITY_BAR.md.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

from atdr.app.ml.behavior_model import MODEL_PATH, BehaviorModel
from atdr.app.services.behavior_model_service import (
    WORK_DIR,
    draw_model_review,
    evaluate_on_window,
    score_model_review,
)
from atdr.app.services.blind_check_service import score_blind_check, write_json

BLIND_KEY = WORK_DIR.parent / "blind_check" / "key.json"


def _decisions(path: Path, id_column: str) -> dict[str, str]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return {row[id_column]: row.get("decision") for row in csv.DictReader(handle)}


def main() -> None:
    sys.stdout.reconfigure(errors="replace")
    parser = argparse.ArgumentParser(description="Evaluate the MFU behaviour model on the test window.")
    parser.add_argument("--review-decisions", type=Path)
    parser.add_argument("--blind-decisions", type=Path)
    args = parser.parse_args()
    evaluation_path = WORK_DIR / "evaluation.json"

    if args.review_decisions:
        key = json.loads((WORK_DIR / "review_key.json").read_text(encoding="utf-8"))
        result = score_model_review(key, _decisions(args.review_decisions, "review_id"))
        write_json(WORK_DIR / "review_score.json", result)
        print(json.dumps(result, indent=2))
        return
    if args.blind_decisions:
        key = json.loads(BLIND_KEY.read_text(encoding="utf-8"))
        flagged = set(json.loads(evaluation_path.read_text(encoding="utf-8"))["model_flagged_log_ids"])
        decisions = _decisions(args.blind_decisions, "sample_id")
        result = {
            "rules": score_blind_check(key, decisions),
            "model": score_blind_check(key, decisions, flagged=lambda entry: entry["log_id"] in flagged),
            "rules_or_model": score_blind_check(key, decisions, flagged=lambda entry: entry["alerted"] or entry["log_id"] in flagged),
        }
        write_json(WORK_DIR / "blind_comparison.json", result)
        for name, report in result.items():
            print(name.ljust(15), {metric: value for metric, value in report["estimate"].items()})
        rules_f1, combined_f1 = result["rules"]["estimate"]["f1"], result["rules_or_model"]["estimate"]["f1"]
        print("Condition 3 (rules or model F1 >= rules F1):",
              "PASS" if rules_f1 is not None and combined_f1 is not None and combined_f1 >= rules_f1 else "FAIL")
        return

    model = BehaviorModel.load(MODEL_PATH)
    evaluation = evaluate_on_window(model)
    rows, key = draw_model_review(evaluation)
    evaluation.pop("_frames")
    write_json(evaluation_path, evaluation)
    write_json(WORK_DIR / "review_sample.json", rows)
    write_json(WORK_DIR / "review_key.json", key)
    summary = {name: value for name, value in evaluation.items() if name != "model_flagged_log_ids"}
    print(json.dumps(summary, indent=2))
    print(f"Blind review rows: {len(rows)} ({key['groups']}) -> {WORK_DIR / 'review_sample.json'}")


if __name__ == "__main__":
    main()
