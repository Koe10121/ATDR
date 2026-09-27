"""The MFU behaviour model: names the attack a source is carrying out, and why.

Training data (``build_dataset``), for each source's 5-minute window:

- real windows the team labeled as an attack take that attack type;
- real windows the team labeled harmless, and real windows no rule alerted on,
  count as normal;
- real windows a rule alerted on that the team never labeled are left out,
  because their true class is unknown;
- simulated attacks (``attack_simulation``) are blended into the same real
  windows, several per attack type.

Background probing (a few unanswered connections from an internet host, see
``behavior_features.is_background_probe``) is neither normal nor an attack to
alert on, so those windows are left out of training and never flagged; the
dashboard summarises them instead.

The classifier is scikit-learn's HistGradientBoostingClassifier. The alert
threshold is chosen on a validation split grouped by source IP, so no source
appears on both sides. An explanation compares the window's values with what
normal MFU sources do, for example "212 destination ports (normal sources:
at most 4 in 99.9% of windows)".
"""

from __future__ import annotations

import hashlib
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier

from atdr.app.core.config import PROJECT_ROOT
from atdr.app.ml.attack_simulation import ATTACK_TYPES, Network, Simulator
from atdr.app.ml.behavior_features import FEATURES, is_background_probe, window_features

MODEL_VERSION = "mfu_behavior_v1"
MODEL_PATH = PROJECT_ROOT / "atdr" / "models" / "mfu_behavior_model.joblib"
CLASSES = ("normal", *ATTACK_TYPES)
VALIDATION_SALT = "atdr-behavior-model-v1"
MAX_VALIDATION_FALSE_ALARM_RATE = 0.002

# Features that describe each attack, with the direction that is suspicious.
CLASS_FEATURES: dict[str, list[tuple[str, str]]] = {
    "port_scan": [("n_dst_ports", "high"), ("max_ports_per_dst", "high"), ("max_dsts_per_port", "high"),
                  ("n_dst_ips", "high"), ("zero_reply_share", "high"), ("deny_share", "high")],
    "brute_force": [("top_service_logs", "high"), ("auth_port_share", "high"), ("short_session_share", "high"),
                    ("deny_share", "high"), ("n_logs", "high")],
    "dos_ddos": [("top_service_logs", "high"), ("n_logs", "high"), ("zero_reply_share", "high"),
                 ("short_session_share", "high")],
    "malware_c2": [("beacon_count", "high"), ("beacon_cv", "low"), ("uncommon_port_share", "high"),
                   ("top_dst_share", "high")],
    "data_exfiltration_suspicion": [("bytes_sent_total", "high"), ("bytes_sent_max", "high"), ("upload_ratio", "high")],
}
FEATURE_TEXT = {
    "n_dst_ports": "different destination ports",
    "max_ports_per_dst": "ports tried on one destination",
    "max_dsts_per_port": "destinations tried on one port",
    "n_dst_ips": "different destination addresses",
    "zero_reply_share": "share of connections with no reply",
    "deny_share": "share of connections denied",
    "top_service_logs": "connections to one destination port",
    "auth_port_share": "share of connections to login ports",
    "short_session_share": "share of sessions of one second or less",
    "n_logs": "connections in five minutes",
    "beacon_count": "repeated connections to one destination",
    "beacon_cv": "variation in the time between those connections",
    "uncommon_port_share": "share of connections to uncommon ports",
    "top_dst_share": "share of connections to one destination",
    "bytes_sent_total": "bytes uploaded",
    "bytes_sent_max": "largest single upload in bytes",
    "upload_ratio": "bytes uploaded per byte downloaded",
}
SHARE_FEATURES = {"zero_reply_share", "deny_share", "auth_port_share", "short_session_share", "uncommon_port_share", "top_dst_share"}


def validation_side(src_ip: str) -> bool:
    digest = hashlib.sha256(f"{VALIDATION_SALT}:{src_ip}".encode()).digest()
    return digest[0] % 10 < 3


# ------------------------------------------------------------------ dataset


@dataclass(slots=True)
class Dataset:
    features: pd.DataFrame
    labels: pd.Series
    origin: pd.Series  # "real" or "simulated"
    summary: dict[str, Any] = field(default_factory=dict)


def label_real_windows(
    evidence: pd.Series,
    *,
    human_labels: dict[int, str],
    rule_alerted: set[int],
) -> pd.Series:
    """Class per real window, or None when the true class is unknown."""

    classes = []
    for log_ids in evidence:
        labeled = [human_labels[log_id] for log_id in log_ids if log_id in human_labels]
        attacks = [value for value in labeled if value in ATTACK_TYPES]
        if attacks:
            classes.append(Counter(attacks).most_common(1)[0][0])
        elif any(value == "exclude" for value in labeled):
            classes.append(None)
        elif labeled or not any(log_id in rule_alerted for log_id in log_ids):
            classes.append("normal")
        else:
            classes.append(None)
    return pd.Series(classes, index=evidence.index, dtype=object)


def simulate_windows(
    real_logs: pd.DataFrame,
    *,
    attacks_per_type: int,
    seed: int,
) -> tuple[pd.DataFrame, pd.Series]:
    """Blend simulated attacks into each real window; returns their features and classes."""

    real_logs = real_logs.dropna(subset=["generated_time"])
    window_of = real_logs["generated_time"].dt.floor("5min")
    windows = sorted(window_of.unique())
    networks = {window: Network.from_logs(real_logs[window_of == window]) for window in windows}
    by_source = {key: group for key, group in real_logs.groupby([window_of, "src_ip"])}
    empty = real_logs.iloc[0:0]
    rows, classes = [], []
    for index, attack_type in enumerate(ATTACK_TYPES):
        for number in range(attacks_per_type):
            window = windows[number % len(windows)]
            simulator = Simulator(networks[window], pd.Timestamp(window).to_pydatetime(),
                                  seed=seed * 1000 + index * 100_000 + number)
            attack, (src, _start) = simulator.attack(attack_type)
            mixed = pd.concat([by_source.get((window, src), empty), attack], ignore_index=True)
            features, _evidence = window_features(mixed)
            rows.append(features.loc[(src, pd.Timestamp(window))])
            classes.append(attack_type)
    frame = pd.DataFrame(rows)
    return frame, pd.Series(classes, index=frame.index)


def build_dataset(
    real_logs: pd.DataFrame,
    *,
    human_labels: dict[int, str],
    rule_alerted: set[int],
    attacks_per_type: int = 300,
    seed: int = 1,
) -> Dataset:
    features, evidence = window_features(real_logs)
    real_classes = label_real_windows(evidence, human_labels=human_labels, rule_alerted=rule_alerted)
    background = is_background_probe(features)
    known = real_classes.notna() & ~background
    real_features = features[known]
    simulated_features, simulated_classes = simulate_windows(real_logs, attacks_per_type=attacks_per_type, seed=seed)
    simulated_features.index = pd.MultiIndex.from_tuples(
        [(f"sim-{number}:{src}", window) for number, (src, window) in enumerate(simulated_features.index)],
        names=features.index.names,
    )
    simulated_classes.index = simulated_features.index
    all_features = pd.concat([real_features, simulated_features])
    labels = pd.concat([real_classes[known], simulated_classes]).astype(str)
    origin = pd.Series(["real"] * len(real_features) + ["simulated"] * len(simulated_features), index=all_features.index)
    return Dataset(
        features=all_features,
        labels=labels,
        origin=origin,
        summary={
            "real_windows": int(len(features)),
            "real_windows_used": int(known.sum()),
            "real_windows_left_out": int((~known).sum()),
            "background_probe_windows_left_out": int(background.sum()),
            "background_probe_windows_team_labeled_as_attack": int((background & real_classes.isin(ATTACK_TYPES)).sum()),
            "real_attack_windows": dict(Counter(real_classes[known][real_classes[known] != "normal"])),
            "simulated_windows": dict(Counter(simulated_classes)),
        },
    )


# ------------------------------------------------------------------ model


@dataclass(slots=True)
class BehaviorModel:
    classifier: HistGradientBoostingClassifier
    threshold: float
    normal_quantiles: dict[str, dict[str, float]]
    card: dict[str, Any]

    def attack_probability(self, features: pd.DataFrame) -> pd.DataFrame:
        probabilities = self.classifier.predict_proba(features[FEATURES])
        return pd.DataFrame(probabilities, columns=self.classifier.classes_, index=features.index)

    def predict(self, features: pd.DataFrame) -> pd.DataFrame:
        """Per window: the most likely attack type, its probability, and whether it crosses the threshold."""

        probabilities = self.attack_probability(features)
        attack_columns = [name for name in probabilities.columns if name != "normal"]
        attack_score = 1 - probabilities["normal"]
        result = pd.DataFrame({
            "attack_type": probabilities[attack_columns].idxmax(axis=1),
            "attack_probability": attack_score,
        }, index=features.index)
        result["background_probe"] = is_background_probe(features).to_numpy()
        result["flagged"] = (result["attack_probability"] >= self.threshold) & ~result["background_probe"]
        return result

    def explain(self, row: pd.Series, attack_type: str, *, limit: int = 3) -> list[str]:
        """Plain reasons: where this window is far outside what normal MFU sources do."""

        reasons = []
        for name, direction in CLASS_FEATURES.get(attack_type, []):
            value = row.get(name)
            quantiles = self.normal_quantiles.get(name)
            if value is None or pd.isna(value) or not quantiles:
                continue
            if direction == "high":
                reference = quantiles["q999"]
                if value <= reference:
                    continue
                strength = (value + 1e-9) / (reference + 1e-9)
                reasons.append((strength, f"{_fmt(name, value)} {FEATURE_TEXT[name]} (normal MFU sources: at most {_fmt(name, reference)} in 99.9% of windows)"))
            else:
                reference = quantiles["q001"]
                if value >= reference:
                    continue
                strength = (reference + 1e-9) / (value + 1e-9)
                reasons.append((strength, f"{_fmt(name, value)} {FEATURE_TEXT[name]} (normal MFU sources: at least {_fmt(name, reference)} in 99.9% of windows)"))
        reasons.sort(key=lambda item: -item[0])
        return [text for _strength, text in reasons[:limit]]

    def save(self, path: Path = MODEL_PATH) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self, path)

    @staticmethod
    def load(path: Path = MODEL_PATH) -> "BehaviorModel":
        return joblib.load(path)


def _fmt(name: str, value: float) -> str:
    if name in SHARE_FEATURES:
        return f"{value * 100:.0f}%"
    if name == "beacon_cv":
        return f"{value:.2f}"
    return f"{value:,.0f}"


def _classifier(seed: int) -> HistGradientBoostingClassifier:
    return HistGradientBoostingClassifier(max_iter=300, learning_rate=0.08, max_leaf_nodes=31, l2_regularization=1.0,
                                          class_weight="balanced", random_state=seed)


def choose_threshold(normal_scores: np.ndarray, *, max_false_alarm_rate: float = MAX_VALIDATION_FALSE_ALARM_RATE) -> float:
    """Lowest threshold whose false-alarm rate on real normal windows stays within the cap."""

    if len(normal_scores) == 0:
        return 0.5
    ordered = np.sort(normal_scores)[::-1]
    allowed = int(np.floor(max_false_alarm_rate * len(ordered)))
    cut = ordered[allowed] if allowed < len(ordered) else 0.0
    return float(min(0.99, max(0.5, np.nextafter(cut, 1))))


def train_model(dataset: Dataset, *, seed: int = 1, trained_on: str = "") -> tuple[BehaviorModel, dict[str, Any]]:
    sources = dataset.features.index.get_level_values(0).map(lambda value: value.split(":", 1)[-1])
    on_validation = np.array([validation_side(src) for src in sources])
    X, y = dataset.features[FEATURES], dataset.labels

    probe = _classifier(seed).fit(X[~on_validation], y[~on_validation])
    probe_model = BehaviorModel(probe, 0.5, {}, {})
    validation = probe_model.predict(X[on_validation])
    real_normal = (y[on_validation] == "normal") & (dataset.origin[on_validation] == "real")
    threshold = choose_threshold(validation.loc[real_normal.to_numpy(), "attack_probability"].to_numpy())
    validation["flagged"] = validation["attack_probability"] >= threshold
    report = validation_report(validation, y[on_validation], dataset.origin[on_validation], threshold)

    final = _classifier(seed).fit(X, y)
    normal_rows = X[(y == "normal") & (dataset.origin == "real")]
    quantiles = {
        name: {"q001": float(normal_rows[name].quantile(0.001)), "q999": float(normal_rows[name].quantile(0.999))}
        for name in FEATURES if normal_rows[name].notna().any()
    }
    card = {
        "version": MODEL_VERSION,
        "trained_at": datetime.now().isoformat(timespec="seconds"),
        "trained_on": trained_on,
        "features": FEATURES,
        "classes": list(final.classes_),
        "threshold": threshold,
        "dataset": dataset.summary,
        "validation": report,
    }
    return BehaviorModel(final, threshold, quantiles, card), report


def validation_report(prediction: pd.DataFrame, labels: pd.Series, origin: pd.Series, threshold: float) -> dict[str, Any]:
    labels = labels.loc[prediction.index]
    origin = origin.loc[prediction.index]
    normal_real = (labels == "normal") & (origin == "real")
    report: dict[str, Any] = {
        "threshold": threshold,
        "real_normal_windows": int(normal_real.sum()),
        "false_alarm_rate_real_normal": round(float(prediction.loc[normal_real, "flagged"].mean()), 5) if normal_real.any() else None,
        "by_type": {},
    }
    for attack_type in ATTACK_TYPES:
        for source in ("simulated", "real"):
            mask = (labels == attack_type) & (origin == source)
            if not mask.any():
                continue
            found = prediction.loc[mask, "flagged"]
            correct = found & (prediction.loc[mask, "attack_type"] == attack_type)
            report["by_type"].setdefault(attack_type, {})[source] = {
                "windows": int(mask.sum()),
                "found": round(float(found.mean()), 4),
                "found_with_right_type": round(float(correct.mean()), 4),
            }
    return report
