"""The MFU behaviour model: features, simulated attacks, training labels, threshold and review scoring."""

from __future__ import annotations

from datetime import datetime, timedelta

import numpy as np
import pandas as pd
import pytest

from atdr.app.ml.attack_simulation import ATTACK_TYPES, Network, Simulator
from atdr.app.ml.behavior_features import FEATURES, is_background_probe, window_features
from atdr.app.ml.behavior_model import BehaviorModel, build_dataset, choose_threshold, label_real_windows
from atdr.app.services.behavior_model_service import label_class, score_model_review

START = datetime(2026, 5, 20, 13, 40)


def _log(log_id, seconds, src, dst, port, *, inbound=False, action="allow", app="ssl", received=500.0, sent=300.0):
    return {
        "log_id": log_id, "generated_time": START + timedelta(seconds=seconds), "src_ip": src, "dst_ip": dst,
        "dst_port": port, "src_zone": "SG-Outside" if inbound else "WLAN-Inside",
        "dst_zone": "WLAN-Inside" if inbound else "SG-Outside", "action": action, "app": app, "app_risk": 2,
        "bytes_sent": sent, "bytes_received": received, "packets": 5, "elapsed_time": 2,
        "session_end_reason": "tcp-fin", "log_type": "TRAFFIC",
    }


def _network():
    return Network("WLAN-Inside", "SG-Outside", ("10.1.0.5", "10.1.0.6", "10.1.0.7"), ("142.250.1.1", "157.240.1.1"))


def test_window_features_describe_scans_beacons_and_background_probes():
    rows = [_log(index, index, "45.33.32.156", "10.1.0.5", 1000 + index, inbound=True, app="incomplete", received=0) for index in range(30)]
    rows += [_log(100 + index, index * 30, "10.1.0.6", "104.16.1.7", 8443) for index in range(9)]
    rows += [_log(200 + index, second, "10.1.0.6", "142.250.1.1", 443) for index, second in enumerate([0, 3, 11, 12, 29, 44, 45, 51, 58])]
    rows += [_log(300, 12, "185.220.101.5", "10.1.0.7", 80, inbound=True, app="incomplete", received=0)]
    rows += [_log(400, 20, "10.2.2.2", "10.1.0.7", 80, inbound=True, app="incomplete", received=0)]
    features, evidence = window_features(pd.DataFrame(rows))
    window = pd.Timestamp(START)

    scanner = features.loc[("45.33.32.156", window)]
    assert scanner["n_dst_ports"] == 30 and scanner["max_ports_per_dst"] == 30 and scanner["zero_reply_share"] == 1
    beacon_host = features.loc[("10.1.0.6", window)]
    assert beacon_host["beacon_count"] == 9 and beacon_host["beacon_interval"] == 30 and beacon_host["beacon_cv"] == 0
    assert list(features.columns) == FEATURES
    assert sorted(evidence.loc[("10.1.0.6", window)])[:2] == [100, 101]

    background = is_background_probe(features)
    assert background.loc[("185.220.101.5", window)] and not background.loc[("45.33.32.156", window)]
    assert not background.loc[("10.2.2.2", window)], "an internal address is never internet background noise"


@pytest.mark.parametrize("attack_type", ATTACK_TYPES)
def test_every_simulated_attack_is_reproducible_and_stands_out(attack_type):
    first, (src, window) = Simulator(_network(), START, seed=5).attack(attack_type)
    again, _ = Simulator(_network(), START, seed=5).attack(attack_type)
    pd.testing.assert_frame_equal(first, again)
    assert (first["log_id"] < 0).all() and first["generated_time"].between(START, START + timedelta(minutes=5)).all()
    row = window_features(first)[0].loc[(src, pd.Timestamp(window))]
    if attack_type == "port_scan":
        assert row["n_dst_ports"] >= 5 or row["n_dst_ips"] >= 10
    elif attack_type == "brute_force":
        assert row["auth_port_share"] == 1 and row["top_service_logs"] >= 3
    elif attack_type == "dos_ddos":
        assert row["top_service_logs"] >= 150
    elif attack_type == "malware_c2":
        assert row["beacon_count"] >= 4 and row["beacon_cv"] <= 0.35
    else:
        assert row["bytes_sent_total"] >= 30e6


def test_simulated_scans_are_always_bigger_than_background_probing():
    for seed in range(25):
        simulator = Simulator(_network(), START, seed=seed)
        vertical = pd.DataFrame(simulator.vertical_scan())
        horizontal = pd.DataFrame(simulator.horizontal_scan())
        assert vertical["dst_port"].nunique() >= 5
        assert horizontal["dst_ip"].nunique() >= 3


def test_training_labels_prefer_the_team_and_leave_unknown_windows_out():
    evidence = pd.Series({("a", 1): [1, 2], ("b", 1): [3], ("c", 1): [4], ("d", 1): [5], ("e", 1): [6]})
    human = {1: "port_scan", 2: "normal", 3: "exclude", 4: "normal"}
    classes = label_real_windows(evidence, human_labels=human, rule_alerted={4, 5})
    assert classes.to_dict() == {("a", 1): "port_scan", ("b", 1): None, ("c", 1): "normal", ("d", 1): None, ("e", 1): "normal"}
    assert label_class("malicious", "brute_force") == "brute_force"
    assert label_class("suspicious", "policy_violation") == "exclude"
    assert label_class("benign_unusual", "port_scan") == "normal"


def test_the_dataset_leaves_out_background_probes_and_unknown_windows():
    rows = [_log(index, index * 20, "10.1.0.5", "142.250.1.1", 443) for index in range(5)]
    rows += [_log(50, 30, "185.220.101.5", "10.1.0.7", 80, inbound=True, app="incomplete", received=0)]
    rows += [_log(60 + index, index, "10.1.0.6", "157.240.1.1", 443) for index in range(3)]
    human = {50: "port_scan"}
    dataset = build_dataset(pd.DataFrame(rows), human_labels=human, rule_alerted={60}, attacks_per_type=1, seed=3)

    sources = set(dataset.features.index.get_level_values(0))
    assert "10.1.0.5" in sources and "185.220.101.5" not in sources and "10.1.0.6" not in sources
    assert dataset.summary["background_probe_windows_left_out"] == 1
    assert dataset.summary["background_probe_windows_team_labeled_as_attack"] == 1
    assert dataset.summary["simulated_windows"] == {attack_type: 1 for attack_type in ATTACK_TYPES}
    assert (dataset.origin == "simulated").sum() == len(ATTACK_TYPES)


def test_the_threshold_keeps_false_alarms_within_the_cap():
    scores = np.linspace(0, 1, 1000)
    threshold = choose_threshold(scores, max_false_alarm_rate=0.01)
    assert (scores >= threshold).mean() <= 0.01
    assert choose_threshold(np.zeros(100)) == 0.5


class _Fixed:
    classes_ = np.array(["normal", "port_scan"])

    def predict_proba(self, features):
        return np.tile([0.01, 0.99], (len(features), 1))


def test_background_probes_are_never_flagged_and_explanations_quote_normal_traffic():
    rows = [_log(index, index, "45.33.32.156", "10.1.0.5", 1000 + index, inbound=True, app="incomplete", received=0) for index in range(30)]
    rows += [_log(300, 12, "185.220.101.5", "10.1.0.7", 80, inbound=True, app="incomplete", received=0)]
    features, _ = window_features(pd.DataFrame(rows))
    quantiles = {"n_dst_ports": {"q001": 1.0, "q999": 4.0}, "max_ports_per_dst": {"q001": 1.0, "q999": 2.0},
                 "n_dst_ips": {"q001": 1.0, "q999": 5.0}}
    model = BehaviorModel(_Fixed(), 0.9, quantiles, {})
    prediction = model.predict(features)
    window = pd.Timestamp(START)
    assert prediction.at[("45.33.32.156", window), "flagged"]
    assert not prediction.at[("185.220.101.5", window), "flagged"]
    reasons = model.explain(features.loc[("45.33.32.156", window)], "port_scan")
    assert reasons[0] == "30 ports tried on one destination (normal MFU sources: at most 2 in 99.9% of windows)"
    assert len(reasons) == 2 and not any("destination addresses" in reason for reason in reasons)


def test_the_model_only_review_scores_precision_per_attack_type():
    key = {"reviews": [
        *[{"review_id": f"M{index}", "group": "model_only", "attack_type": "port_scan"} for index in range(10)],
        {"review_id": "X1", "group": "unflagged", "attack_type": None},
        {"review_id": "B1", "group": "model_only", "attack_type": "brute_force"},
    ]}
    decisions = {f"M{index}": "Threat" for index in range(9)} | {"M9": "Normal", "X1": "Threat", "B1": "Unsure"}
    result = score_model_review(key, decisions)
    assert result["port_scan"]["precision"] == 0.9 and result["port_scan"]["passes_condition_1"]
    assert result["brute_force"]["precision"] is None and not result["brute_force"]["passes_condition_1"]
    assert result["dos_ddos"] == {"precision": None, "passes_condition_1": False}
