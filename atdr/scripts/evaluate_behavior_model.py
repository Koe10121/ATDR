"""Evaluate a frozen MFU behaviour model on held-out windows.

Usage (v1, the untouched 13:50-13:55 window; results in .tmp/mfu_model/):
    python -m atdr.scripts.evaluate_behavior_model
    python -m atdr.scripts.evaluate_behavior_model --review-decisions .tmp/mfu_model/review_decisions.csv
    python -m atdr.scripts.evaluate_behavior_model --blind-decisions .tmp/blind_check/decisions.csv

Later rounds get their own folder, so earlier results are never overwritten:
    python -m atdr.scripts.evaluate_behavior_model --out-dir .tmp/mfu_model/v2_fresh \
        --window "2026-05-20 13:45:00" "2026-05-20 13:50:00" --window "2026-05-20 13:55:00" "2026-05-20 14:00:00" \
        --rules-db .tmp/blind_check/holdout_v5_34.db --seed 9000002 --review-prefix F --min-reviewed 5

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
    HOLDOUT_DB,
    REVIEW_SEED,
    TEST_SEED,
    TEST_WINDOW,
    WORK_DIR,
    draw_model_review,
    evaluate_on_window,
    rule_alerted_logs,
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
    parser.add_argument("--out-dir", type=Path, default=WORK_DIR, help="where this round's files go")
    parser.add_argument("--model", type=Path, default=MODEL_PATH)
    parser.add_argument("--window", nargs=2, action="append", metavar=("START", "END"))
    parser.add_argument("--rules-db", type=Path, help="holdout copy with the current rules' alerts")
    parser.add_argument("--seed", type=int, default=TEST_SEED, help="seed for the simulated attacks")
    parser.add_argument("--review-seed", type=int, default=REVIEW_SEED)
    parser.add_argument("--review-prefix", default="M")
    parser.add_argument("--min-reviewed", type=int, default=1, help="reviewed model-only windows a type needs (5 from v2)")
    parser.add_argument("--no-review", action="store_true", help="measure only; draw no review (windows already seen)")
    args = parser.parse_args()
    WORK_DIR_ = args.out_dir
    WORK_DIR_.mkdir(parents=True, exist_ok=True)
    evaluation_path = WORK_DIR_ / "evaluation.json"

    if args.review_decisions:
        key = json.loads((WORK_DIR_ / "review_key.json").read_text(encoding="utf-8"))
        result = score_model_review(key, _decisions(args.review_decisions, "review_id"), min_judged=args.min_reviewed)
        write_json(WORK_DIR_ / "review_score.json", result)
        print(json.dumps(result, indent=2))
        return
    if args.blind_decisions:
        key = json.loads(BLIND_KEY.read_text(encoding="utf-8"))
        flagged = set(json.loads(evaluation_path.read_text(encoding="utf-8"))["model_flagged_log_ids"])
        decisions = _decisions(args.blind_decisions, "sample_id")
        # The blind key holds the rules' verdicts at the time; --rules-db re-reads them from a newer rules run.
        alerted = rule_alerted_logs(args.rules_db) if args.rules_db else None

        def rules(entry):
            return entry["log_id"] in alerted if alerted is not None else entry["alerted"]

        result = {
            "rules": score_blind_check(key, decisions, flagged=rules),
            "model": score_blind_check(key, decisions, flagged=lambda entry: entry["log_id"] in flagged),
            "rules_or_model": score_blind_check(key, decisions, flagged=lambda entry: rules(entry) or entry["log_id"] in flagged),
        }
        write_json(WORK_DIR_ / "blind_comparison.json", result)
        for name, report in result.items():
            print(name.ljust(15), {metric: value for metric, value in report["estimate"].items()})
        rules_f1, combined_f1 = result["rules"]["estimate"]["f1"], result["rules_or_model"]["estimate"]["f1"]
        print("Condition 3 (rules or model F1 >= rules F1):",
              "PASS" if rules_f1 is not None and combined_f1 is not None and combined_f1 >= rules_f1 else "FAIL")
        return

    # A round's results and review key are written once; a later run must use a new folder.
    existing = [path.name for path in (evaluation_path, WORK_DIR_ / "review_key.json") if path.exists()]
    if existing:
        raise SystemExit(f"{WORK_DIR_} already holds {', '.join(existing)}; use a new --out-dir.")
    model = BehaviorModel.load(args.model)
    windows = [tuple(window) for window in args.window] if args.window else [TEST_WINDOW]
    evaluation = evaluate_on_window(model, HOLDOUT_DB, windows=windows, rules_db=args.rules_db, seed=args.seed)
    rows, key = ([], None) if args.no_review else draw_model_review(evaluation, seed=args.review_seed, id_prefix=args.review_prefix)
    evaluation.pop("_frames")
    write_json(evaluation_path, evaluation)
    summary = {name: value for name, value in evaluation.items() if name != "model_flagged_log_ids"}
    print(json.dumps(summary, indent=2))
    if key is not None:
        write_json(WORK_DIR_ / "review_sample.json", rows)
        write_json(WORK_DIR_ / "review_key.json", key)
        print(f"Blind review rows: {len(rows)} ({key['groups']}) -> {WORK_DIR_ / 'review_sample.json'}")


if __name__ == "__main__":
    main()
