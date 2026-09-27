"""The MFU behaviour model: features, simulated attacks, training labels, threshold and review scoring."""

from __future__ import annotations

from datetime import datetime, timedelta

import numpy as np
import pandas as pd
import pytest

from atdr.app.ml.attack_simulation import ATTACK_TYPES, Network, Simulator
from atdr.app.ml.behavior_features import (
    FEATURES,
    POLICY_COLUMNS,
    destination_pairs,
    is_background_probe,
    is_p2p_policy,
    window_features,
)
from atdr.app.ml.behavior_model import BehaviorModel, build_dataset, choose_threshold, label_real_windows, simulate_windows
from atdr.app.services.behavior_model_service import label_class, score_model_review

START = datetime(2026, 5, 20, 13, 40)


def _log(log_id, seconds, src, dst, port, *, inbound=False, action="allow", app="ssl", received=500.0, sent=300.0, log_type="TRAFFIC"):
    p2p = app == "bittorrent"
    return {
        "log_id": log_id, "generated_time": START + timedelta(seconds=seconds), "src_ip": src, "dst_ip": dst,
        "dst_port": port, "src_zone": "SG-Outside" if inbound else "WLAN-Inside",
        "dst_zone": "WLAN-Inside" if inbound else "SG-Outside", "action": action, "app": app, "app_risk": 2,
        "bytes_sent": sent, "bytes_received": received, "packets": 5, "elapsed_time": 2,
        "session_end_reason": "tcp-fin", "log_type": log_type,
        "app_technology": "peer-to-peer" if p2p else "browser-based",
        "app_subcategory": "file-sharing" if p2p else "internet-utility",
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
    assert list(features.columns) == [*FEATURES, *POLICY_COLUMNS]
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


def _torrent_window():
    rows = [_log(index, index, "10.1.0.8", f"91.{index}.2.3", 6881 + index, app="bittorrent") for index in range(40)]
    rows += [_log(100 + index, index, "10.1.0.9", f"92.{index}.2.3", 6881 + index, app="bittorrent") for index in range(40)]
    rows += [_log(200, 50, "10.1.0.9", "92.0.2.3", 6881, app="bittorrent", log_type="THREAT")]
    rows += [_log(300 + index, index, "10.1.0.5", f"93.{index}.2.3", 7000 + index) for index in range(40)]
    return pd.DataFrame(rows)


def test_peer_to_peer_file_sharing_is_policy_activity_unless_the_firewall_saw_a_threat():
    features, _ = window_features(_torrent_window())
    window = pd.Timestamp(START)
    assert features.at[("10.1.0.8", window), "p2p_share"] == 1
    policy = is_p2p_policy(features)
    assert policy.loc[("10.1.0.8", window)], "plain BitTorrent fan-out is policy activity"
    assert not policy.loc[("10.1.0.9", window)], "BitTorrent with a firewall threat detection is not"
    assert not policy.loc[("10.1.0.5", window)], "a scan-like fan-out that is not file sharing is not"

    prediction = BehaviorModel(_Fixed(), 0.9, {}, {}).predict(features)
    assert not prediction.at[("10.1.0.8", window), "flagged"] and prediction.at[("10.1.0.8", window), "p2p_policy"]
    assert prediction.at[("10.1.0.9", window), "flagged"] and prediction.at[("10.1.0.5", window), "flagged"]


def test_the_dataset_leaves_out_peer_to_peer_policy_windows():
    human = {0: "port_scan", 300: "port_scan"}
    dataset = build_dataset(_torrent_window(), human_labels=human, rule_alerted=set(), attacks_per_type=1, seed=3)
    sources = set(dataset.features.index.get_level_values(0))
    assert "10.1.0.8" not in sources and "10.1.0.5" in sources
    assert dataset.summary["p2p_policy_windows_left_out"] == 1


def test_a_beacon_to_a_server_many_devices_use_is_counted_as_popular():
    rows = [_log(index, index * 30, "10.1.0.6", "104.16.1.7", 8443) for index in range(9)]  # only this host
    rows += [_log(100 + index, index * 30, "10.1.0.8", "142.250.1.1", 443) for index in range(9)]
    rows += [_log(200 + index, index, f"10.1.1.{index}", "142.250.1.1", 443) for index in range(5)]  # 5 more devices
    logs = pd.DataFrame(rows)
    window = pd.Timestamp(START)
    features, _ = window_features(logs)
    assert features.at[("10.1.0.6", window), "beacon_dst_sources"] == 1
    assert features.at[("10.1.0.8", window), "beacon_dst_sources"] == 6

    alone, _ = window_features(logs[logs["src_ip"] == "10.1.0.8"])
    assert alone.at[("10.1.0.8", window), "beacon_dst_sources"] == 1, "one source's logs alone cannot see the others"
    with_context, _ = window_features(logs[logs["src_ip"] == "10.1.0.8"], context_pairs=destination_pairs(logs))
    assert with_context.at[("10.1.0.8", window), "beacon_dst_sources"] == 6


def test_simulated_attacks_see_the_whole_window_when_counting_destination_sources():
    rows = [_log(index, index, f"10.1.0.{5 + index % 3}", "142.250.1.1", 443) for index in range(30)]
    dataset_features, _classes = simulate_windows(pd.DataFrame(rows), attacks_per_type=3, seed=4)
    popular = dataset_features["beacon_dst_sources"].dropna()
    assert (popular >= 1).all()
    real_host_beacons = dataset_features.loc[dataset_features["beacon_dst_sources"] >= 3]
    assert len(real_host_beacons) >= 1, "attacks on real hosts keep the window's other sources in the count"


class _FixedType:
    def __init__(self, attack_type):
        self.classes_ = np.array(["normal", attack_type])

    def predict_proba(self, features):
        return np.tile([0.01, 0.99], (len(features), 1))


def test_c2_and_exfiltration_must_leave_mfu():
    rows = [_log(index, index * 20, "45.33.32.156", "10.1.0.5", 443, inbound=True, sent=9e6) for index in range(12)]
    rows += [_log(100 + index, index * 20, "10.1.0.6", "185.1.2.3", 443, sent=9e6) for index in range(12)]
    features, _ = window_features(pd.DataFrame(rows))
    window = pd.Timestamp(START)
    for attack_type in ("data_exfiltration_suspicion", "malware_c2"):
        prediction = BehaviorModel(_FixedType(attack_type), 0.9, {}, {}).predict(features)
        assert not prediction.at[("45.33.32.156", window), "flagged"] and prediction.at[("45.33.32.156", window), "wrong_direction"]
        assert prediction.at[("10.1.0.6", window), "flagged"]
    scan = BehaviorModel(_FixedType("port_scan"), 0.9, {}, {}).predict(features)
    assert scan.at[("45.33.32.156", window), "flagged"], "scans and floods can come from either side"


def test_a_model_predicts_with_the_features_it_was_trained_on():
    rows = [_log(index, index, "10.1.0.5", "142.250.1.1", 443) for index in range(6)]
    features, _ = window_features(pd.DataFrame(rows))
    seen = []

    class _Recorder(_FixedType):
        def predict_proba(self, frame):
            seen.append(list(frame.columns))
            return super().predict_proba(frame)

    BehaviorModel(_Recorder("port_scan"), 0.9, {}, {"features": FEATURES[:30]}).predict(features)
    BehaviorModel(_Recorder("port_scan"), 0.9, {}, {}).predict(features)
    assert seen == [FEATURES[:30], FEATURES], "a v1 model keeps its 30 features; a new one uses the current list"


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
    assert result["dos_ddos"] == {"judged": 0, "precision": None, "passes_condition_1": False}


def test_from_v2_a_type_needs_five_reviewed_windows():
    key = {"reviews": [{"review_id": f"F{index}", "group": "model_only", "attack_type": "port_scan"} for index in range(5)]}
    four = {f"F{index}": "Threat" for index in range(4)} | {"F4": "Unsure"}
    assert score_model_review(key, four)["port_scan"]["passes_condition_1"], "v1 rule: any number of windows"
    assert not score_model_review(key, four, min_judged=5)["port_scan"]["passes_condition_1"]
    five = {f"F{index}": "Threat" for index in range(5)}
    assert score_model_review(key, five, min_judged=5)["port_scan"]["passes_condition_1"]


def test_an_evaluation_round_never_overwrites_earlier_results(tmp_path, monkeypatch):
    from atdr.scripts import evaluate_behavior_model

    (tmp_path / "review_key.json").write_text("{}", encoding="utf-8")
    monkeypatch.setattr("sys.argv", ["evaluate_behavior_model", "--out-dir", str(tmp_path)])
    with pytest.raises(SystemExit, match="use a new --out-dir"):
        evaluate_behavior_model.main()
    assert (tmp_path / "review_key.json").read_text(encoding="utf-8") == "{}"
