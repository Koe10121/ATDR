"""The team review pack: what goes in it, and what the team's answers change.

One workbook collects everything ATDR still needs a person to judge:

A. the MFU behaviour model's extra finds (the blind review behind condition 1 of its quality bar);
B. the blind-check logs, judged from scratch without the AI reviewer's decision, so the two can be
   compared (turning the "independent blind reference labeling" into human-checked labels);
C. BitTorrent logs the team labeled as threats (policy activity since rule catalog v5.34.0);
D. patterns where the team's own labels contradict the firewall's evidence or the team's policies.

This module holds the logic and needs no spreadsheet library; atdr/scripts/team_review_pack.py
reads and writes the workbook.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from atdr.app.db.models import AlertEvidence, MLLabel, NormalizedLog
from atdr.app.detection.attack_mapping import threat_attack_type
from atdr.app.detection.rules import (
    MALWARE_THREAT_CATEGORIES,
    MALWARE_THREAT_TYPES,
    is_informational_threat_record,
    is_p2p_file_sharing,
    looks_like_background_probe,
)
from atdr.app.services.behavior_model_service import PERSON_REVIEW_METHODS
from atdr.app.services.detection_scoreboard_service import THREAT_LABELS

ATTACK_NAMES = {
    "normal": "normal",
    "port_scan": "port scan",
    "brute_force": "brute force",
    "dos_ddos": "flood",
    "malware_c2": "malware / C2",
    "policy_violation": "policy violation",
    "data_exfiltration_suspicion": "data exfiltration",
    "exploit_attempt": "exploit attempt",
    "unknown_anomaly": "unknown",
}
LABEL_NAMES = {"suspicious": "suspicious", "malicious": "malicious", "needs_context": "needs context",
               "benign": "normal", "benign_unusual": "normal but unusual"}
LABELED_BY = {
    "manual": "by hand",
    "reviewed_import": "in the 26 Sep label review (AI-assisted)",
    "assisted_rule": "automatically, from ATDR's rule score",
    "assisted_ml": "automatically, from an ML score",
    "assisted_hybrid": "automatically, from a combined score",
}
PATTERN_CHOICES = ("Relabel as proposed", "Keep the current label", "Unsure")
TORRENT_POLICY = "Policy activity (not a threat)"
EXAMPLES_PER_PATTERN = 3


def _latest_reviewed_labels(db: Session) -> dict[int, MLLabel]:
    latest: dict[int, MLLabel] = {}
    for label in db.scalars(select(MLLabel).where(MLLabel.reviewed.is_(True)).order_by(MLLabel.id)):
        latest[int(label.log_id)] = label
    return latest


def _firewall_named_type(log: NormalizedLog) -> str | None:
    if str(log.log_type or "").upper() != "THREAT":
        return None
    kind = str(log.subtype or "").strip().lower()
    if kind in MALWARE_THREAT_TYPES or str(log.category or "").strip().lower() in MALWARE_THREAT_CATEGORIES:
        return "malware_c2"
    parsed = log.parsed_json if isinstance(log.parsed_json, dict) else {}
    named = threat_attack_type(kind, str(parsed.get("parsed_threat_name") or ""), str(parsed.get("parsed_threat_severity") or ""))
    return None if named == "unknown_anomaly" else named


def _example(log: NormalizedLog) -> dict[str, Any]:
    parsed = log.parsed_json if isinstance(log.parsed_json, dict) else {}
    when = log.generated_time.strftime("%H:%M:%S") if log.generated_time else "-"
    threat = str(parsed.get("parsed_threat_name") or "")
    return {
        "time": when, "source": log.src_ip or "-", "destination": f"{log.dst_ip or '-'}:{log.dst_port if log.dst_port is not None else '-'}",
        "zones": f"{log.src_zone or '?'} -> {log.dst_zone or '?'}", "app": log.app or "-", "action": log.action or "-",
        "threat": f"{threat} ({parsed.get('parsed_threat_severity') or '-'})" if threat else "",
    }


def example_text(example: dict[str, Any]) -> str:
    text = f"{example['time']}  {example['source']} -> {example['destination']}  ({example['zones']})  app {example['app']}, {example['action']}"
    return f"{text}, firewall threat: {example['threat']}" if example.get("threat") else text


def label_patterns(db: Session) -> list[dict[str, Any]]:
    """Groups of threat labels that contradict the firewall's own record or the team's policies.

    Each log joins the first group it fits. File-sharing logs labeled as something other than a policy
    violation are left out: the pack asks about them one by one (part C).
    """

    latest = _latest_reviewed_labels(db)
    alerted = {int(row) for row in db.scalars(select(AlertEvidence.normalized_log_id).distinct())}
    threat_ids = sorted(log_id for log_id, label in latest.items() if label.label in THREAT_LABELS)
    groups: dict[str, list[tuple[NormalizedLog, MLLabel]]] = defaultdict(list)
    for start in range(0, len(threat_ids), 900):
        for log in db.scalars(select(NormalizedLog).where(NormalizedLog.id.in_(threat_ids[start:start + 900]))):
            label = latest[int(log.id)]
            named = _firewall_named_type(log)
            if is_p2p_file_sharing(log):
                if label.attack_type == "policy_violation":
                    groups["file_sharing"].append((log, label))
            elif named and label.attack_type != named:
                groups[f"named:{named}"].append((log, label))
            elif is_informational_threat_record(log):
                groups["informational"].append((log, label))
            elif looks_like_background_probe(log) and int(log.id) not in alerted:
                groups["background_probe"].append((log, label))

    specs = [
        ("file_sharing", "File sharing labeled as a threat",
         "BitTorrent-style file sharing labeled a threat of type 'policy violation'. The team decided on 27 Sep that file "
         "sharing is policy activity, not an attack, unless there is other evidence (a firewall threat, brute force, a "
         "watchlist hit).", {"decision": "Normal but unusual", "attack_type": None}, "Normal but unusual (policy activity)"),
        ("background_probe", "Single unanswered internet probes labeled as threats",
         "An unanswered connection from an internet host into MFU that the current rules do not alert on. The team's "
         "policy is to summarise such background probing and escalate only with stronger evidence (repeated attempts, "
         "wider coverage, a known bad address, a firewall threat).", {"decision": "Normal but unusual", "attack_type": None},
         "Normal but unusual (background probing)"),
    ]
    for named in sorted(key.split(":", 1)[1] for key in groups if key.startswith("named:")):
        specs.append((f"named:{named}", f"The firewall names {ATTACK_NAMES[named]}, the label says something else",
                      f"The firewall's own threat record identifies this traffic as {ATTACK_NAMES[named]} (see the threat names in "
                      "the examples), but the label gives another type. It stays a threat either way; the question is its type.",
                      {"decision": "Real threat", "attack_type": named}, f"Threat, type {ATTACK_NAMES[named]}"))
    specs.append(("informational", "Informational firewall records labeled as threats",
                  "Records the firewall rates informational whose signature names no attack (such as 'Non-RFC Compliant SSL "
                  "Traffic', usually a VPN client, game or tunnel). ATDR treats them as supporting evidence since rule catalog v5.36.0.",
                  {"decision": "Normal but unusual", "attack_type": None}, "Normal but unusual (odd protocol use)"))

    patterns = []
    for key, title, what, proposal, proposal_text in specs:
        members = groups.get(key)
        if not members:
            continue
        members.sort(key=lambda item: (item[0].generated_time is None, item[0].generated_time, item[0].id))
        seen_sources: list[str] = []
        examples = []
        for log, _label in members:
            if log.src_ip not in seen_sources and len(examples) < EXAMPLES_PER_PATTERN:
                seen_sources.append(log.src_ip)
                examples.append(_example(log))
        patterns.append({
            "id": f"L{len(patterns) + 1}",
            "key": key,
            "title": title,
            "what": what,
            "proposal": proposal,
            "proposal_text": proposal_text,
            "log_ids": [int(log.id) for log, _label in members],
            "logs": len(members),
            "sources": len({log.src_ip for log, _label in members}),
            "current_labels": ", ".join(
                f"{LABEL_NAMES.get(label, label)} / {ATTACK_NAMES.get(attack, attack)} ({count})"
                for (label, attack), count in Counter((label.label, label.attack_type) for _log, label in members).most_common()
            ),
            "labeled_by": ", ".join(
                f"{LABELED_BY.get(source, source)} ({count})"
                for source, count in Counter(label.label_source for _log, label in members).most_common()
            ),
            "examples": examples,
        })
    return patterns


def pattern_label_decisions(patterns: dict[str, dict[str, Any]], answers: dict[str, dict[str, str]]) -> list[dict[str, Any]]:
    """Part D answers as label-review decisions (atdr/scripts/apply_label_review.py)."""

    decisions = []
    for pattern_id, pattern in patterns.items():
        answer = answers.get(pattern_id) or {}
        relabel = answer.get("choice") == PATTERN_CHOICES[0]
        decision = {"source_ip": "", "pattern": f"{pattern_id} {pattern['title']}",
                    "decision": pattern["proposal"]["decision"] if relabel else "Unsure",
                    "note": answer.get("note") or "", "log_ids": pattern["log_ids"]}
        if relabel and pattern["proposal"].get("attack_type"):
            decision["attack_type"] = pattern["proposal"]["attack_type"]
        decisions.append(decision)
    return decisions


def torrent_label_decisions(rows: dict[str, int], answers: dict[str, dict[str, str]]) -> list[dict[str, Any]]:
    """Part C answers: a file-sharing log called policy activity becomes Normal but unusual; the rest stay."""

    return [
        {"source_ip": "", "pattern": f"{row} BitTorrent label",
         "decision": "Normal but unusual" if (answers.get(row) or {}).get("verdict") == TORRENT_POLICY else "Unsure",
         "note": (answers.get(row) or {}).get("note") or "", "log_ids": [log_id]}
        for row, log_id in rows.items()
    ]


def blind_comparison(ai: dict[str, str], human: dict[str, str], groups: dict[str, list[str]]) -> dict[str, Any]:
    """How the team's own blind decisions compare with the AI reviewer's, overall and by why each row was chosen."""

    judged = [sample for sample in ai if human.get(sample)]
    group_of = {sample: name for name, samples in groups.items() for sample in samples}

    def threat(decision: str) -> bool | None:
        return None if decision == "Unsure" else decision == "Threat"

    def agreement(samples: list[str]) -> dict[str, Any]:
        same = sum(1 for sample in samples if ai[sample] == human[sample])
        both = [sample for sample in samples if threat(ai[sample]) is not None and threat(human[sample]) is not None]
        same_side = sum(1 for sample in both if threat(ai[sample]) == threat(human[sample]))
        return {"rows": len(samples), "same_decision": same, "same_decision_rate": round(same / len(samples), 4) if samples else None,
                "threat_or_not_rows": len(both), "same_threat_or_not": same_side,
                "same_threat_or_not_rate": round(same_side / len(both), 4) if both else None}

    by_group = defaultdict(list)
    for sample in judged:
        by_group[group_of.get(sample, "other")].append(sample)
    matrix: dict[str, Counter] = defaultdict(Counter)
    for sample in judged:
        matrix[ai[sample]][human[sample]] += 1
    return {
        "judged": len(judged),
        "overall": agreement(judged),
        "by_group": {name: agreement(samples) for name, samples in sorted(by_group.items())},
        "ai_vs_team": {decision: dict(counts) for decision, counts in sorted(matrix.items())},
        "changed": sorted([sample, ai[sample], human[sample]] for sample in judged if ai[sample] != human[sample]),
    }


def human_checked_decisions(ai_rows: list[dict[str, str]], human: dict[str, dict[str, str]]) -> list[dict[str, str]]:
    """The blind-check decisions with every row a person judged replaced by that person's decision."""

    merged = []
    for row in ai_rows:
        answer = human.get(row["sample_id"]) or {}
        if answer.get("decision"):
            merged.append({"sample_id": row["sample_id"], "decision": answer["decision"],
                           "confidence": answer.get("confidence") or "", "note": answer.get("note") or "", "labeled_by": "team"})
        else:
            merged.append({**{key: row.get(key, "") for key in ("sample_id", "decision", "confidence", "note")}, "labeled_by": "ai"})
    return merged


def signoff_counts_as_person(method: str | None) -> bool:
    """Only a review done or checked by a person can switch a model type on or verify labels."""

    return (method or "").strip() in PERSON_REVIEW_METHODS

