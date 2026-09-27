"""Train and evaluate the MFU behaviour model from separate SQLite databases.

Training reads ``.tmp/mfu_model/train.db`` (20 May 13:36-13:45, built with the
blind check's holdout builder) and the team's reviewed labels from the live
database, matched to training logs by the raw line's fingerprint. The live
database is only read.
"""

from __future__ import annotations

import random
import sqlite3
from collections import Counter
from pathlib import Path
from typing import Any

import pandas as pd

from atdr.app.core.config import PROJECT_ROOT
from atdr.app.ml.attack_simulation import ATTACK_TYPES
from atdr.app.ml.behavior_features import load_logs, window_features
from atdr.app.ml.behavior_model import BehaviorModel, simulate_windows

WORK_DIR = PROJECT_ROOT / ".tmp" / "mfu_model"
TRAIN_DB = WORK_DIR / "train.db"
HOLDOUT_DB = PROJECT_ROOT / ".tmp" / "blind_check" / "holdout.db"
TEST_WINDOW = ("2026-05-20 13:50:00", "2026-05-20 13:55:00")
# Never used for training: the test attacks are fresh draws from the simulator.
TEST_SEED = 9_000_001
REVIEW_PER_TYPE = 20
REVIEW_SEED = 20260927
THREAT_LABELS = {"malicious", "suspicious"}
HARMLESS_LABELS = {"benign", "benign_unusual"}


def label_class(label: str, attack_type: str | None) -> str:
    """Model class for one reviewed label: an attack type, "normal", or "exclude" when it fits neither."""

    if label in HARMLESS_LABELS:
        return "normal"
    if label in THREAT_LABELS and attack_type in ATTACK_TYPES:
        return str(attack_type)
    return "exclude"


def reviewed_labels_by_fingerprint(live_db: Path) -> dict[str, str]:
    """Latest reviewed label per log in the live database, keyed by raw-line fingerprint."""

    query = """
        SELECT r.raw_line_hash, l.label, l.attack_type
        FROM ml_labels l
        JOIN normalized_logs n ON n.id = l.log_id
        JOIN raw_logs r ON r.id = n.raw_log_id
        WHERE l.reviewed = 1
          AND l.id = (SELECT MAX(l2.id) FROM ml_labels l2 WHERE l2.log_id = l.log_id AND l2.reviewed = 1)
    """
    with sqlite3.connect(f"file:{live_db.as_posix()}?mode=ro", uri=True) as connection:
        return {fingerprint: label_class(label, attack_type) for fingerprint, label, attack_type in connection.execute(query) if fingerprint}


def labels_for_database(database: Path, by_fingerprint: dict[str, str]) -> dict[int, str]:
    with sqlite3.connect(f"file:{database.as_posix()}?mode=ro", uri=True) as connection:
        rows = connection.execute(
            "SELECT n.id, r.raw_line_hash FROM normalized_logs n JOIN raw_logs r ON r.id = n.raw_log_id"
        )
        return {int(log_id): by_fingerprint[fingerprint] for log_id, fingerprint in rows if fingerprint in by_fingerprint}


def rule_alerted_logs(database: Path) -> set[int]:
    with sqlite3.connect(f"file:{database.as_posix()}?mode=ro", uri=True) as connection:
        return {int(row[0]) for row in connection.execute("SELECT DISTINCT normalized_log_id FROM alert_evidence")}


# ------------------------------------------------------------------ test window


def evaluate_on_window(
    model: BehaviorModel,
    holdout: Path = HOLDOUT_DB,
    *,
    window: tuple[str, str] = TEST_WINDOW,
    windows: list[tuple[str, str]] | None = None,
    rules_db: Path | None = None,
    attacks_per_type: int = 200,
    seed: int = TEST_SEED,
) -> dict[str, Any]:
    """Score the frozen model on real traffic and on fresh simulated attacks in the test window(s).

    ``rules_db`` is a copy of the holdout with the rules as they are now; model-only means flagged
    by the model and not alerted there. It defaults to the holdout itself.
    """

    windows = windows or [window]
    logs = pd.concat([load_logs(holdout, start=start, end=end) for start, end in windows], ignore_index=True)
    features, evidence = window_features(logs)
    prediction = model.predict(features)
    rule_logs = rule_alerted_logs(rules_db or holdout)
    rule_flag = evidence.map(lambda log_ids: any(log_id in rule_logs for log_id in log_ids))
    flagged = prediction["flagged"]
    model_only = flagged & ~rule_flag

    simulated_features, simulated_types = simulate_windows(logs, attacks_per_type=attacks_per_type, seed=seed)
    simulated = model.predict(simulated_features)
    recall = {}
    for attack_type in ATTACK_TYPES:
        mask = (simulated_types == attack_type).to_numpy()
        found = simulated.loc[mask, "flagged"]
        right = found & (simulated.loc[mask, "attack_type"] == attack_type)
        recall[attack_type] = {"attacks": int(mask.sum()), "found": round(float(found.mean()), 4),
                               "found_with_right_type": round(float(right.mean()), 4)}

    by_type = {}
    for attack_type in ATTACK_TYPES:
        of_type = flagged & (prediction["attack_type"] == attack_type)
        by_type[attack_type] = {
            "model_flags": int(of_type.sum()),
            "also_rule_alerted": int((of_type & rule_flag).sum()),
            "model_only": int((of_type & ~rule_flag).sum()),
        }
    flagged_log_ids = sorted({log_id for log_ids in evidence[flagged] for log_id in log_ids})
    return {
        "window": {"start": windows[0][0], "end": windows[-1][1]},
        "windows": [{"start": start, "end": end} for start, end in windows],
        "model_version": model.card.get("version"),
        "rules_database": (rules_db or holdout).name,
        "threshold": model.threshold,
        "real_windows": int(len(features)),
        "rule_alerted_windows": int(rule_flag.sum()),
        "model_flagged_windows": int(flagged.sum()),
        "model_only_windows": int(model_only.sum()),
        "real_by_type": by_type,
        "simulated_recall": recall,
        "model_flagged_log_ids": flagged_log_ids,
        "_frames": {"logs": logs, "features": features, "evidence": evidence, "prediction": prediction, "rule_flag": rule_flag},
    }


def _window_summary(review_id: str, rows: pd.DataFrame) -> dict[str, Any]:
    """What one source did in the window, in plain terms, for a human reviewer."""

    rows = rows.sort_values("generated_time")
    services = (rows["dst_ip"].fillna("?") + ":" + rows["dst_port"].fillna(-1).astype(int).astype(str)).value_counts()
    actions = rows["action"].fillna("unknown").value_counts()
    apps = rows["app"].fillna("unknown").value_counts()
    direction = (rows["src_zone"].fillna("?") + " -> " + rows["dst_zone"].fillna("?")).value_counts()
    steadiest = ""
    for destination, group in rows.groupby("dst_ip"):
        if len(group) < 4:
            continue
        gaps = group["generated_time"].diff().dt.total_seconds().dropna()
        if gaps.mean() > 0:
            variation = gaps.std() / gaps.mean()
            text = f"{destination}: {len(group)} connections, every {gaps.mean():.0f}s on average (variation {variation:.2f})"
            if not steadiest or variation < steadiest[0]:
                steadiest = (variation, text)
    threats = rows.loc[rows["log_type"].fillna("").str.upper() == "THREAT"]
    return {
        "review_id": review_id,
        "source": rows["src_ip"].iat[0],
        "from": rows["generated_time"].iat[0].strftime("%H:%M:%S"),
        "to": rows["generated_time"].iat[-1].strftime("%H:%M:%S"),
        "direction": ", ".join(f"{name} ({count})" for name, count in direction.head(2).items()),
        "connections": int(len(rows)),
        "different_destinations": int(rows["dst_ip"].nunique()),
        "different_destination_ports": int(rows["dst_port"].nunique()),
        "top_destinations": ", ".join(f"{name} ({count})" for name, count in services.head(4).items()),
        "actions": ", ".join(f"{name} {count}" for name, count in actions.items()),
        "bytes_sent": int(rows["bytes_sent"].fillna(0).sum()),
        "bytes_received": int(rows["bytes_received"].fillna(0).sum()),
        "largest_upload": int(rows["bytes_sent"].fillna(0).max()),
        "top_apps": ", ".join(f"{name} ({count})" for name, count in apps.head(4).items()),
        "steadiest_repeated_destination": steadiest[1] if steadiest else "",
        "firewall_threat_logs": int(len(threats)),
    }


def draw_model_review(
    evaluation: dict[str, Any], *, per_type: int = REVIEW_PER_TYPE, seed: int = REVIEW_SEED, id_prefix: str = "M"
) -> tuple[list[dict], dict]:
    """Blind review rows: up to ``per_type`` model-only alerts per type, mixed with as many random unflagged windows."""

    frames = evaluation["_frames"]
    prediction, rule_flag, logs = frames["prediction"], frames["rule_flag"], frames["logs"]
    rng = random.Random(seed)
    chosen: list[tuple[tuple, str, str | None, float]] = []
    for attack_type in ATTACK_TYPES:
        candidates = sorted(prediction.index[prediction["flagged"] & ~rule_flag & (prediction["attack_type"] == attack_type)])
        for index in rng.sample(candidates, min(per_type, len(candidates))):
            chosen.append((index, "model_only", attack_type, float(prediction.at[index, "attack_probability"])))
    unflagged = sorted(prediction.index[~prediction["flagged"]])
    for index in rng.sample(unflagged, min(len(chosen), len(unflagged))):
        chosen.append((index, "unflagged", None, float(prediction.at[index, "attack_probability"])))
    rng.shuffle(chosen)
    grouped = logs.assign(window=logs["generated_time"].dt.floor("5min")).groupby(["src_ip", "window"])
    rows, key = [], []
    for number, (index, group, attack_type, probability) in enumerate(chosen, start=1):
        review_id = f"{id_prefix}{number:03d}"
        rows.append(_window_summary(review_id, grouped.get_group(index)))
        key.append({"review_id": review_id, "source": index[0], "window": str(index[1]), "group": group,
                    "attack_type": attack_type, "attack_probability": round(probability, 4)})
    return rows, {"window": evaluation["window"], "seed": seed, "per_type": per_type,
                  "groups": dict(Counter(entry["group"] for entry in key)), "reviews": key}


# Only a review a person did or checked can switch a type on (ML_QUALITY_BAR.md addendum).
PERSON_REVIEW_METHODS = ("By a person without AI", "AI-assisted and a person checked every row")
MIN_REVIEWED_FROM_V2 = 5


def quality_bar_record(
    *,
    fresh: dict[str, Any],
    blind: dict[str, Any],
    review_score: dict[str, Any] | None = None,
    review_method: str | None = None,
    min_reviewed: int = MIN_REVIEWED_FROM_V2,
) -> dict[str, Any]:
    """Where each attack type stands on the quality bar after one evaluation round.

    ``fresh`` is the round's evaluation.json (model-only windows, simulated recall), ``blind`` the
    blind-check comparison (condition 3) and ``review_score`` the scored blind review of the
    model-only windows (condition 1), or None while the review is out.
    """

    rules_f1 = blind["rules"]["estimate"]["f1"]
    combined_f1 = blind["rules_or_model"]["estimate"]["f1"]
    condition_3 = {"rules_f1": rules_f1, "rules_or_model_f1": combined_f1,
                   "passes": bool(rules_f1 is not None and combined_f1 is not None and combined_f1 >= rules_f1)}
    person_checked = review_method in PERSON_REVIEW_METHODS
    types = {}
    for attack_type in ATTACK_TYPES:
        model_only = int(fresh["real_by_type"][attack_type]["model_only"])
        found = float(fresh["simulated_recall"][attack_type]["found_with_right_type"])
        if model_only < min_reviewed:
            condition_1 = {"status": "cannot_pass", "model_only": model_only}
        elif review_score is None:
            condition_1 = {"status": "pending", "model_only": model_only}
        else:
            score = review_score.get(attack_type, {})
            status = "pass" if score.get("passes_condition_1") else "fail"
            if status == "pass" and not person_checked:
                status = "needs_person"
            condition_1 = {"status": status, "model_only": model_only, "judged": int(score.get("judged") or 0),
                           "threat": int(score.get("threat") or 0), "precision": score.get("precision")}
        condition_2 = {"found": found, "passes": found >= 0.9}
        types[attack_type] = {
            "condition_1": condition_1,
            "condition_2": condition_2,
            "eligible": condition_1["status"] == "pass" and condition_2["passes"] and condition_3["passes"],
        }
    return {
        "declared_in": "docs/detection/ML_QUALITY_BAR.md",
        "model_version": fresh.get("model_version"),
        "windows": fresh.get("windows") or [fresh.get("window")],
        "min_reviewed": min_reviewed,
        "review_method": review_method,
        "condition_3": condition_3,
        "types": types,
    }


def score_model_review(key: dict[str, Any], decisions: dict[str, Any], *, min_judged: int = 1) -> dict[str, Any]:
    """Share of reviewed model-only alerts that are real threats, per attack type (bar condition 1).

    From v2 on a type also needs ``min_judged`` (5) reviewed windows, so one lucky window cannot pass it.
    """

    from atdr.app.services.blind_check_service import normalise_decision

    by_type: dict[str, Counter] = {}
    for entry in key["reviews"]:
        if entry["group"] != "model_only":
            continue
        raw = decisions.get(entry["review_id"])
        counts = by_type.setdefault(entry["attack_type"], Counter())
        if raw in (None, ""):
            counts["missing"] += 1
            continue
        decision = normalise_decision(raw)
        counts["unsure" if decision is None else decision] += 1
    result = {}
    for attack_type in ATTACK_TYPES:
        counts = by_type.get(attack_type, Counter())
        judged = counts["threat"] + counts["harmless"]
        precision = counts["threat"] / judged if judged else None
        result[attack_type] = {**dict(counts), "judged": judged, "precision": None if precision is None else round(precision, 4),
                               "passes_condition_1": bool(precision is not None and precision >= 0.9 and judged >= min_judged)}
    return result
