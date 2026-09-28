"""The team review pack's logic: which labels it questions and what the team's answers change."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import select

from atdr.app.db.models import Alert, AlertEvidence, MLLabel, NormalizedLog, RawLog
from atdr.app.services.label_review_service import apply_label_review
from atdr.app.services.team_review_service import (
    PATTERN_CHOICES,
    TORRENT_POLICY,
    blind_comparison,
    human_checked_decisions,
    label_patterns,
    pattern_label_decisions,
    signoff_counts_as_person,
    signoff_problems,
    torrent_label_decisions,
)
from atdr.tests.test_detection_grouping import _session

INBOUND = {"src_zone": "SG-Outside", "dst_zone": "WLAN-Inside"}
OUTBOUND = {"src_zone": "WLAN-Inside", "dst_zone": "SG-Outside"}
P2P = {"app": "bittorrent", "app_technology": "peer-to-peer", "app_subcategory": "file-sharing"}


def _log(db, index: int, label: str, attack_type: str, *, source: str = "manual", **fields) -> int:
    raw = RawLog(raw_line=f"pack {index}")
    db.add(raw)
    db.flush()
    values = {"generated_time": datetime(2026, 5, 20, 13, 36, index), "src_ip": f"10.9.0.{index}", "dst_ip": "198.51.100.9",
              "dst_port": 443, "action": "allow", "parsed_json": {}, **fields}
    log = NormalizedLog(raw_log_id=raw.id, **values)
    db.add(log)
    db.flush()
    db.add(MLLabel(log_id=log.id, label=label, attack_type=attack_type, confidence=3, reviewer="team", label_source=source, reviewed=True))
    db.flush()
    return int(log.id)


def _threat(name: str, subtype: str, severity: str) -> dict:
    return {"log_type": "THREAT", "subtype": subtype, "parsed_json": {"parsed_threat_name": name, "parsed_threat_severity": severity}}


def _seed(db) -> dict[str, int]:
    ids = {
        "torrent_policy": _log(db, 1, "suspicious", "policy_violation", **OUTBOUND, **P2P),
        "torrent_scan": _log(db, 2, "malicious", "port_scan", **OUTBOUND, **P2P),
        "probe": _log(db, 3, "malicious", "port_scan", **INBOUND, src_ip="45.9.148.15", action="deny"),
        "alerted_probe": _log(db, 4, "malicious", "port_scan", **INBOUND, src_ip="45.9.148.16", action="deny"),
        "miner": _log(db, 5, "suspicious", "policy_violation", **OUTBOUND, action="drop",
                      **_threat("XMRig Miner Command and Control Traffic Detection(85886)", "spyware", "critical")),
        "miner_typed": _log(db, 6, "suspicious", "malware_c2", **OUTBOUND, action="drop",
                            **_threat("XMRig Miner Command and Control Traffic Detection(85886)", "spyware", "critical")),
        "shellshock": _log(db, 7, "suspicious", "port_scan", **INBOUND, src_ip="45.9.148.17", action="drop",
                           **_threat("Bash Remote Code Execution Vulnerability(36729)", "vulnerability", "critical")),
        "non_rfc": _log(db, 8, "suspicious", "unknown_anomaly", source="assisted_rule", **OUTBOUND, action="alert",
                        **_threat("Non-RFC Compliant SSL Traffic on Port 443(56112)", "vulnerability", "informational")),
        "harmless": _log(db, 9, "benign", "normal", **INBOUND, src_ip="45.9.148.18", action="deny"),
        "busy_unknown_udp": _log(db, 10, "suspicious", "unknown_anomaly", **OUTBOUND, app="unknown-udp", protocol="udp", dst_port=32100),
        "quiet_unknown_udp": _log(db, 11, "suspicious", "unknown_anomaly", **OUTBOUND, app="unknown-udp", protocol="udp", dst_port=32100),
    }
    alert = Alert(title="scan", alert_type="possible_port_scan", threat_score=40, severity="Medium", status="open",
                  explanation="e", matched_rules_json=[], recommended_response="r")
    db.add(alert)
    db.flush()
    db.add(AlertEvidence(alert_id=alert.id, normalized_log_id=ids["alerted_probe"]))
    unknown_app = Alert(title="app", alert_type="unknown_or_incomplete_app", threat_score=30, severity="Low", status="open",
                        explanation="e", matched_rules_json=[], recommended_response="r")
    db.add(unknown_app)
    db.flush()
    db.add(AlertEvidence(alert_id=unknown_app.id, normalized_log_id=ids["busy_unknown_udp"]))
    db.commit()
    return ids


def test_the_pack_questions_labels_that_contradict_the_firewall_or_the_team_policies():
    db = _session()
    ids = _seed(db)

    patterns = {pattern["key"]: pattern for pattern in label_patterns(db)}

    assert list(patterns) == ["file_sharing", "background_probe", "named:exploit_attempt", "named:malware_c2", "unidentified_app",
                              "informational"]
    assert patterns["unidentified_app"]["log_ids"] == [ids["busy_unknown_udp"]], "only traffic the rules alert on for the app alone"
    assert patterns["file_sharing"]["log_ids"] == [ids["torrent_policy"]], "other file-sharing labels are asked one by one"
    assert patterns["background_probe"]["log_ids"] == [ids["probe"]], "a probe the rules still alert on is not questioned"
    assert patterns["named:malware_c2"]["log_ids"] == [ids["miner"]], "a miner already typed malware is not questioned"
    assert patterns["named:malware_c2"]["proposal"] == {"decision": "Real threat", "attack_type": "malware_c2"}
    assert patterns["named:exploit_attempt"]["log_ids"] == [ids["shellshock"]]
    assert patterns["informational"]["labeled_by"] == "automatically, from ATDR's rule score (1)"
    assert patterns["named:malware_c2"]["current_labels"] == "suspicious / policy violation (1)"
    assert [pattern["id"] for pattern in patterns.values()] == ["L1", "L2", "L3", "L4", "L5", "L6"]
    assert all(ids["harmless"] not in pattern["log_ids"] for pattern in patterns.values())
    assert "XMRig" in patterns["named:malware_c2"]["examples"][0]["threat"]


def test_the_team_answers_become_label_changes_that_keep_history():
    db = _session()
    ids = _seed(db)
    patterns = {pattern["id"]: pattern for pattern in label_patterns(db)}
    answers = {
        "L1": {"choice": PATTERN_CHOICES[0], "note": "file sharing is policy"},
        "L2": {"choice": "Keep the current label", "note": "these were scans"},
        "L3": {"choice": PATTERN_CHOICES[0]},
        "L4": {"choice": PATTERN_CHOICES[0]},
        "L5": {"choice": "Keep the current label"},
        "L6": {"choice": "Unsure"},
    }
    decisions = pattern_label_decisions(patterns, answers)
    decisions += torrent_label_decisions({"T01": ids["torrent_scan"]}, {"T01": {"verdict": TORRENT_POLICY}})

    applied = apply_label_review(db, decisions, reviewer="team", note_prefix="team review pack", apply=True)

    def latest(log_id):
        label = db.scalars(select(MLLabel).where(MLLabel.log_id == log_id).order_by(MLLabel.id.desc())).first()
        return label.label, label.attack_type

    assert applied["labels_to_add"] == 4
    assert latest(ids["torrent_policy"]) == ("benign_unusual", "policy_violation")
    assert latest(ids["torrent_scan"]) == ("benign_unusual", "port_scan")
    assert latest(ids["miner"]) == ("suspicious", "malware_c2")
    assert latest(ids["shellshock"]) == ("suspicious", "exploit_attempt")
    assert latest(ids["probe"]) == ("malicious", "port_scan"), "kept as the team said"
    assert latest(ids["non_rfc"]) == ("suspicious", "unknown_anomaly"), "unsure changes nothing"
    assert db.scalar(select(MLLabel).where(MLLabel.log_id == ids["miner"]).order_by(MLLabel.id)).attack_type == "policy_violation"


def test_blind_comparison_measures_how_often_the_team_and_the_ai_agree():
    ai = {"B1": "Threat", "B2": "Normal", "B3": "Normal but unusual", "B4": "Unsure", "B5": "Threat"}
    team = {"B1": "Threat", "B2": "Normal but unusual", "B3": "Threat", "B4": "Normal", "B5": ""}
    groups = {"threat": ["B1", "B5"], "false_alarm": ["B3"], "unsure": ["B4"]}

    result = blind_comparison(ai, team, groups)

    assert result["judged"] == 4, "a row the team left blank is not compared"
    assert result["overall"]["same_decision"] == 1
    # Threat-or-not: B1 same, B2 same (both harmless), B3 differs; B4 has an Unsure side.
    assert (result["overall"]["threat_or_not_rows"], result["overall"]["same_threat_or_not"]) == (3, 2)
    assert result["by_group"]["false_alarm"]["same_decision"] == 0
    assert result["ai_vs_team"]["Normal but unusual"] == {"Threat": 1}
    assert ["B3", "Normal but unusual", "Threat"] in result["changed"]


def test_human_checked_decisions_replace_only_rows_a_person_judged():
    ai_rows = [{"sample_id": "B1", "decision": "Threat", "confidence": "High", "note": "ai"},
               {"sample_id": "B2", "decision": "Normal", "confidence": "Low", "note": "ai"}]
    merged = human_checked_decisions(ai_rows, {"B1": {"decision": "Normal", "note": "a backup job"}, "B2": {"decision": ""}})
    assert merged[0] == {"sample_id": "B1", "decision": "Normal", "confidence": "", "note": "a backup job", "labeled_by": "team"}
    assert merged[1]["decision"] == "Normal" and merged[1]["labeled_by"] == "ai"


def test_only_a_finished_person_review_counts():
    assert signoff_counts_as_person("By a person without AI", "2026-09-30", "Two of us split parts A and B.")
    assert signoff_counts_as_person("AI-assisted and a person checked every row", "30 Sep", "")
    assert not signoff_counts_as_person("AI only (not checked by a person)", "30 Sep")
    assert not signoff_counts_as_person(None, "30 Sep")
    assert signoff_problems("By a person without AI", None) == ["'Date finished' is blank"]
    assert signoff_problems("By a person without AI", datetime(2026, 9, 28)) == [], "Excel returns a typed date"
    # The first returned pack: a person method picked, but the note says otherwise.
    note = ("AI draft prepared 28 Sep 2026. Human reviewer and completion date remain pending. "
            "This does not yet count as human-checked validation.")
    assert "the note says it is an AI draft or that a person has not reviewed it yet" in signoff_problems("By a person without AI", "28 Sep", note)
    # Mentioning AI help is fine when a person checked every row.
    assert signoff_counts_as_person("AI-assisted and a person checked every row", "28 Sep", "AI helped us sort rows; we then checked each one.")


def test_a_group_is_relabeled_only_where_its_condition_holds():
    from atdr.app.services.team_review_service import pattern_condition_failures

    db = _session()
    ids = _seed(db)
    for second in range(12):  # the probe's source hits many hosts: not isolated background noise
        _log(db, 20 + second, "benign", "normal", **INBOUND, src_ip="45.9.148.99", dst_ip=f"10.1.4.{second}", action="deny")
    busy = _log(db, 40, "malicious", "port_scan", **INBOUND, src_ip="45.9.148.99", action="deny")
    db.commit()
    groups = {
        "probes": {"key": "background_probe", "proposal": {"decision": "Normal but unusual", "attack_type": None},
                   "log_ids": [ids["probe"], busy, ids["alerted_probe"]]},
        "miners": {"key": "named:malware_c2", "proposal": {"decision": "Real threat", "attack_type": "malware_c2"},
                   "log_ids": [ids["miner"], ids["shellshock"]]},
    }

    failures = pattern_condition_failures(db, groups)

    assert set(failures["probes"]) == {busy, ids["alerted_probe"]}
    assert failures["probes"][ids["alerted_probe"]] == "it is in an alert"
    assert failures["probes"][busy].startswith("its source is not isolated")
    assert list(failures["miners"]) == [ids["shellshock"]], "a type is corrected only where the firewall names it"
