"""Train the MFU behaviour model on 20 May 13:36-13:45 only.

Usage:
    python -m atdr.scripts.train_behavior_model --log-file "C:\\path\\paloalto-firewall(1).log"

Builds .tmp/mfu_model/train.db from lines 1-319,643 of the MFU export if it
does not exist yet (a separate database; the live one is only read for the
team's labels), runs the current rules on it so that rule-alerted windows the
team never labeled can be left out, then trains, chooses the threshold on a
source-grouped validation split, and saves atdr/models/mfu_behavior_model.joblib
with its model card.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

from atdr.app.ml.behavior_features import load_logs
from atdr.app.ml.behavior_model import MODEL_PATH, BehaviorModel, build_dataset, normal_quantiles, train_model
from atdr.app.services.behavior_model_service import (
    TRAIN_DB,
    labels_for_database,
    reviewed_labels_by_fingerprint,
    rule_alerted_logs,
)
from atdr.app.services.blind_check_service import build_holdout_database, detect_holdout
from atdr.app.services.detection_scoreboard_service import configured_sqlite_path

LAST_TRAINING_LINE = 319_643  # 13:44:59; 13:45 onwards is the untouched test data.


def main() -> None:
    sys.stdout.reconfigure(errors="replace")
    parser = argparse.ArgumentParser(description="Train the MFU behaviour model.")
    parser.add_argument("--log-file", required=True)
    parser.add_argument("--attacks-per-type", type=int, default=300)
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--refresh-explanations", action="store_true",
                        help="Recompute the explanation statistics and training period of the saved model without retraining it.")
    args = parser.parse_args()

    if not TRAIN_DB.exists():
        print("Importing 13:36-13:45 into the training database ...", flush=True)
        print(build_holdout_database(Path(args.log_file), TRAIN_DB, first_line=1, last_line=LAST_TRAINING_LINE))
    print("Running the current rules on the training database ...", flush=True)
    print(detect_holdout(TRAIN_DB))

    human = labels_for_database(TRAIN_DB, reviewed_labels_by_fingerprint(configured_sqlite_path()))
    alerted = rule_alerted_logs(TRAIN_DB)
    logs = load_logs(TRAIN_DB)
    print(f"{len(logs):,} training logs, {len(human):,} with a reviewed label, {len(alerted):,} rule-alerted.", flush=True)
    dataset = build_dataset(logs, human_labels=human, rule_alerted=alerted, attacks_per_type=args.attacks_per_type, seed=args.seed)
    print("Dataset:", json.dumps(dataset.summary), flush=True)
    period = {"trained_from": logs["generated_time"].min().isoformat(), "trained_to": logs["generated_time"].max().isoformat()}
    if args.refresh_explanations:
        # The classifier and threshold stay exactly as frozen; only explanation data and the card change.
        model = BehaviorModel.load(MODEL_PATH)
        model.normal_quantiles = normal_quantiles(dataset)
        model.card.update(period)
        model.save()
        MODEL_PATH.with_suffix(".card.json").write_text(json.dumps(model.card, indent=2, default=str), encoding="utf-8")
        print(f"Refreshed explanations and training period of {MODEL_PATH}")
        return
    model, report = train_model(dataset, seed=args.seed, trained_on="MFU export 20 May 13:36-13:45 (lines 1-319,643)")
    commit = subprocess.run(["git", "rev-parse", "--short", "HEAD"], capture_output=True, text=True, check=False).stdout.strip()
    model.card.update(period, code_commit=commit or None)
    model.save()
    MODEL_PATH.with_suffix(".card.json").write_text(json.dumps(model.card, indent=2, default=str), encoding="utf-8")
    print("Validation:", json.dumps(report, indent=2))
    print(f"Saved {MODEL_PATH}")


if __name__ == "__main__":
    main()
