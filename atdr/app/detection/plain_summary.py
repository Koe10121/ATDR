"""An alert in plain words: a few sentences for the top of the alert drawer.

Written from the alert's own record and all of its evidence logs, never by a language model: when it
happened, who contacted whom, what the firewall recognised and whether it blocked it, what that may mean,
and the first question to answer. The rule-by-rule evidence stays below it in the drawer.
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Sequence
from datetime import datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from atdr.app.db.models import Alert, AlertEvidence, NormalizedLog, WatchlistItem
from atdr.app.detection.attack_mapping import infer_attack_type_from_rules
from atdr.app.detection.playbooks import PLAYBOOK_GUIDANCE
from atdr.app.detection.rules import (
    INSIDE_ZONE_TOKENS,
    OUTSIDE_ZONE_TOKENS,
    _is_deny_or_drop,
    _is_private_address,
    _zone_tokens,
)

# The firewall's own name for a threat, as an alert's explanation records it:
# "... threat name is XMRig Miner Command and Control Traffic Detection(85886)."
THREAT_NAME = re.compile(r"threat name is ([^.;(]+?)\s*(?:\(\d+\))?[.;]")
WATCHLIST_PREFIX = "Matched active watchlist indicator(s): "
FIRST_SENTENCE = re.compile(r"(.+?)[.!?](?=\s|$)")
MODEL_ALERT_TYPE = "mfu_behavior_model"

# attack type: (what it is, for the model's reading; what it may mean, for a rule alert)
PLAIN_WORDS: dict[str, tuple[str, str]] = {
    "port_scan": ("a port scan", "someone checking which services are open, often a first step before an attack"),
    "brute_force": ("password guessing", "someone guessing passwords to get into an account"),
    "dos_ddos": ("a flood", "an attempt to overload a service so that it stops working"),
    "malware_c2": ("malware contacting its controller", "malware on the MFU device contacting whoever controls it"),
    "exploit_attempt": ("a break-in attempt", "an attempt to break in through a weakness in the target's software"),
    "data_exfiltration_suspicion": ("data theft", "data being copied out of MFU, or an ordinary large upload such as a backup"),
    "policy_violation": ("a policy breach", "traffic that goes against MFU's network or acceptable-use policy, not necessarily an attack"),
}
_NOUNS = {
    ("source", "campus"): ("an MFU device", "MFU devices"),
    ("destination", "campus"): ("an MFU device", "MFU devices"),
    ("source", "outside"): ("an outside address", "outside addresses"),
    ("destination", "outside"): ("an outside server", "outside servers"),
    ("source", None): ("an address", "addresses"),
    ("destination", None): ("an address", "addresses"),
}
_EVIDENCE_COLUMNS = (
    NormalizedLog.generated_time,
    NormalizedLog.src_ip,
    NormalizedLog.dst_ip,
    NormalizedLog.dst_port,
    NormalizedLog.src_zone,
    NormalizedLog.dst_zone,
    NormalizedLog.src_country,
    NormalizedLog.dst_country,
    # The four fields _is_deny_or_drop reads, so "blocked" means what it means to the rules.
    NormalizedLog.action,
    NormalizedLog.subtype,
    NormalizedLog.session_end_reason,
    NormalizedLog.action_source,
)


def threat_name(text: str | None) -> str | None:
    """The firewall's threat name in an alert's explanation, without its signature number."""

    match = THREAT_NAME.search(text or "")
    return match.group(1).strip() if match else None


def _side(address: str | None, zone: str | None) -> str | None:
    """'campus' or 'outside'. A private address is on MFU's side whatever its zone is called ("WLAN-Outside")."""

    if _is_private_address(address):
        return "campus"
    tokens = _zone_tokens(zone)
    if tokens & OUTSIDE_ZONE_TOKENS:
        return "outside"
    if tokens & INSIDE_ZONE_TOKENS:
        return "campus"
    return None


def _main_side(rows: Sequence[Any], prefix: str) -> str | None:
    sides = Counter(_side(getattr(row, f"{prefix}_ip"), getattr(row, f"{prefix}_zone")) for row in rows)
    return sides.most_common(1)[0][0] if sides else None


def _party(rows: Sequence[Any], role: str) -> str:
    """'an MFU device (10.1.44.163)', 'an outside address (147.45.50.171, Netherlands)', '4 outside servers'."""

    prefix = "src" if role == "source" else "dst"
    addresses = list(dict.fromkeys(getattr(row, f"{prefix}_ip") for row in rows if getattr(row, f"{prefix}_ip")))
    side = _main_side(rows, prefix)
    one, many = _NOUNS[(role, side)]
    if role == "destination" and side == "campus" and _main_side(rows, "src") == "campus":
        one, many = "another MFU device", "other MFU devices"
    if len(addresses) != 1:
        return f"{len(addresses):,} {many}"
    # Palo Alto gives a private range ("10.0.0.0-10.255.255.255") where a country would be.
    countries = Counter(getattr(row, f"{prefix}_country") for row in rows if getattr(row, f"{prefix}_country"))
    country = countries.most_common(1)[0][0] if countries and side == "outside" else ""
    place = f", {country}" if country and not any(char.isdigit() for char in country) else ""
    return f"{one} ({addresses[0]}{place})"


def _when(times: list[datetime]) -> str:
    if not times:
        return ""
    first, last = min(times), max(times)
    if first.date() != last.date():
        return f"From {first.day} {first:%b} {first:%H:%M} to {last.day} {last:%b} {last:%H:%M}"
    if first.strftime("%H:%M") == last.strftime("%H:%M"):
        return f"On {first.day} {first:%b} at {first:%H:%M}"
    return f"On {first.day} {first:%b}, {first:%H:%M}–{last:%H:%M}"


def _ports(rows: Sequence[Any]) -> str:
    ports = sorted({row.dst_port for row in rows if row.dst_port is not None})
    if not ports:
        return ""
    if len(ports) == 1:
        return f" on port {ports[0]}"
    if len(ports) <= 3:
        return f" on ports {', '.join(str(port) for port in ports[:-1])} and {ports[-1]}"
    return f" on {len(ports):,} different ports"


def _firewall(rows: Sequence[Any]) -> str:
    blocked = sum(1 for row in rows if _is_deny_or_drop(row))
    total = len(rows)
    every = "it" if total == 1 else "both" if total == 2 else f"all {total:,}"
    if blocked == total:
        return f"blocked {every}"
    if blocked == 0:
        return f"allowed {every}"
    return f"blocked {blocked:,} of the {total:,} and allowed the rest"


def _watchlist_matches(db: Session, alert: Alert) -> list[tuple[str, str | None]]:
    """Each indicator the alert matched, with the first sentence of its watchlist note."""

    matches = []
    for rule in alert.matched_rules_json or []:
        if not isinstance(rule, dict) or rule.get("code") != "watchlist_match":
            continue
        text = str(rule.get("explanation") or "")
        if not text.startswith(WATCHLIST_PREFIX):
            continue
        for indicator in text.removeprefix(WATCHLIST_PREFIX).rstrip(".").split(", "):
            indicator_type, _, value = indicator.partition(":")
            description = db.scalar(
                select(WatchlistItem.description)
                .where(WatchlistItem.indicator_type == indicator_type, WatchlistItem.indicator_value == value)
                .order_by(WatchlistItem.id.desc())
                .limit(1)
            )
            first = FIRST_SENTENCE.match(description or "")
            matches.append((value, first.group(1) if first else None))
    return matches


def _watchlist_notes(db: Session, alert: Alert) -> list[str]:
    """'111.90.158.40 is on ATDR's watchlist: GHOSTENGINE C2 server (...)' for each indicator the alert matched."""

    return [
        f"{value} is on ATDR's watchlist" + (f": {note}." if note else ".")
        for value, note in _watchlist_matches(db, alert)
    ]


def build_plain_summary(db: Session, alert: Alert, attack_type: str | None) -> str:
    """Three to five short sentences about the alert; empty when it has no evidence logs."""

    rows = db.execute(
        select(*_EVIDENCE_COLUMNS)
        .join(AlertEvidence, AlertEvidence.normalized_log_id == NormalizedLog.id)
        .where(AlertEvidence.alert_id == alert.id)
    ).all()
    if not rows:
        return ""
    total = len(rows)
    connections = "one connection" if total == 1 else f"{total:,} connections"
    when = _when([row.generated_time for row in rows if row.generated_time is not None])
    who = _party(rows, "source")
    what = f"{who} made {connections} to {_party(rows, 'destination')}{_ports(rows)}."
    sentences = [f"{when}, {what}" if when else what[0].upper() + what[1:]]
    kind, meaning = PLAIN_WORDS.get(attack_type or "", ("", ""))
    is_model_alert = alert.alert_type == MODEL_ALERT_TYPE
    if is_model_alert:
        reading = f"possibly {kind}" if kind else "unusual"
        sentences.append(
            f"No rule fired on it; ATDR's experimental behaviour model reads it as {reading}, with low confidence."
        )
    sentences.extend(_watchlist_notes(db, alert))
    name = threat_name(alert.explanation)
    verdict = _firewall(rows)
    sentences.append(f'The firewall recognised it as "{name}" and {verdict}.' if name else f"The firewall {verdict}.")
    if not is_model_alert:
        sentences.append(f"This may be {meaning}." if meaning else "ATDR could not tell what kind of activity this is.")
    guidance = PLAYBOOK_GUIDANCE.get(attack_type or "")
    if guidance:
        sentences.append(f"Next: {guidance.objective[0].lower()}{guidance.objective[1:]}")
    return " ".join(sentences)


# The Overview's lines, most dangerous first.
SITUATION_ORDER = (
    "malware_c2",
    "exploit_attempt",
    "data_exfiltration_suspicion",
    "brute_force",
    "dos_ddos",
    "port_scan",
    "policy_violation",
    "unknown_anomaly",
)
SITUATION_LABELS = {
    "malware_c2": "Malware calling out",
    "exploit_attempt": "Break-in attempts",
    "data_exfiltration_suspicion": "Possible data theft",
    "brute_force": "Password guessing",
    "dos_ddos": "Floods",
    "port_scan": "Scanning",
    "policy_violation": "Policy breaches",
    "unknown_anomaly": "Unclassified",
}
# The same kinds as an adjective: "Also open: 4 flood, 119 scanning and 18 unclassified alerts."
SITUATION_ADJECTIVES = {
    "malware_c2": "malware",
    "exploit_attempt": "break-in",
    "data_exfiltration_suspicion": "possible data-theft",
    "brute_force": "password-guessing",
    "dos_ddos": "flood",
    "port_scan": "scanning",
    "policy_violation": "policy",
    "unknown_anomaly": "unclassified",
}
SEVERITY_RANK = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
# Evidence from outside ATDR's own rules: the firewall's threat signature, or an indicator on the watchlist.
NAMED_THREAT_RULES = {"paloalto_malware_threat", "paloalto_threat_log", "watchlist_match"}
SITUATION_LINES = 4


def _count(number: int, one: str, many: str) -> str:
    return f"{number:,} {one if number == 1 else many}"


def _source_noun(rows: Sequence[Any]) -> tuple[str, str]:
    return ("MFU device", "MFU devices") if _main_side(rows, "src") == "campus" else ("outside address", "outside addresses")


def _connections_verdict(blocked: int, total: int) -> str:
    if blocked == total:
        return f"the firewall blocked {'it' if total == 1 else f'all {total:,} connections'}"
    if blocked == 0:
        return f"the firewall let {'it' if total == 1 else f'all {total:,} connections'} through"
    return f"the firewall blocked {blocked:,} of {total:,} connections"


def _short_threat_name(name: str) -> str:
    """'XMRig Miner Command and Control Traffic Detection' -> 'XMRig Miner Command and Control'."""

    return re.sub(r"(?:\s+(?:Traffic|Detection))+$", "", name)


def build_situation_summary(db: Session) -> dict[str, Any]:
    """The open alerts in plain words, for the top of the Overview; written by ATDR, never by a language model.

    A headline (how many are open, from which traffic, and that it is not live), one line per kind of attack, most
    dangerous first, naming the threats the firewall or the watchlist recognised, and the alert to open first: a named
    threat the firewall let through, then the most severe and highest-scoring.
    """

    # The newest log rides along with the alerts: the Overview's first load has a budget of 35 queries.
    found = db.execute(
        select(Alert, select(func.max(NormalizedLog.generated_time)).scalar_subquery()).where(Alert.status == "open")
    ).all()
    if not found:
        return {"headline": "No alerts are open.", "points": [], "open_first": None}
    alerts = {alert.id: alert for alert, _ in found}
    newest = found[0][1]
    rows = db.execute(
        select(AlertEvidence.alert_id, *_EVIDENCE_COLUMNS)
        .join(NormalizedLog, NormalizedLog.id == AlertEvidence.normalized_log_id)
        .join(Alert, Alert.id == AlertEvidence.alert_id)
        .where(Alert.status == "open")
    ).all()
    by_alert: dict[int, list[Any]] = {}
    for row in rows:
        by_alert.setdefault(row.alert_id, []).append(row)
    blocked = {alert_id: sum(1 for row in group if _is_deny_or_drop(row)) for alert_id, group in by_alert.items()}
    kinds: dict[str, list[Alert]] = {}
    for alert in alerts.values():
        kinds.setdefault(infer_attack_type_from_rules(alert.matched_rules_json or []), []).append(alert)

    critical = sum(1 for alert in alerts.values() if alert.severity == "Critical")
    times = [row.generated_time for row in rows if row.generated_time is not None]
    when = _when(times).removeprefix("On ").removeprefix("From ") if times else ""
    headline = f"{_count(len(alerts), 'alert is', 'alerts are')} open ({critical:,} Critical)"
    headline += f", from MFU's firewall logs of {when}." if when else "."
    if newest is not None:
        headline += f" The newest log ATDR has is from {newest.day} {newest:%b %Y %H:%M}, so this is not live traffic."

    points = []
    ordered = [kind for kind in SITUATION_ORDER if kind in kinds] + sorted(set(kinds) - set(SITUATION_ORDER))
    for kind in ordered[:SITUATION_LINES]:
        group = kinds[kind]
        evidence = [row for alert in group for row in by_alert.get(alert.id, [])]
        sources = {row.src_ip for row in evidence if row.src_ip}
        line = f"{SITUATION_LABELS.get(kind, kind)}: {_count(len(group), 'alert', 'alerts')}"
        if sources:
            line += f" from {_count(len(sources), *_source_noun(evidence))}"
        if evidence:
            line += f"; {_connections_verdict(sum(blocked.get(alert.id, 0) for alert in group), len(evidence))}"
        named: dict[str, list[Alert]] = {}
        for alert in group:
            for value, note in _watchlist_matches(db, alert):
                # "GHOSTENGINE C2 server (Elastic Security Labs, May 2024)": the alert's own box keeps the source.
                label = re.sub(r"\s*\([^)]*\)$", "", note) if note else value
                named.setdefault(f"{label}, on ATDR's watchlist", []).append(alert)
            if name := threat_name(alert.explanation):
                named.setdefault(_short_threat_name(name), []).append(alert)
        if named:
            parts = []
            for name, matched in named.items():
                rows_for_name = [row for alert in matched for row in by_alert.get(alert.id, [])]
                devices = {row.src_ip for row in rows_for_name if row.src_ip}
                stopped = sum(blocked.get(alert.id, 0) for alert in matched)
                outcome = "blocked" if stopped == len(rows_for_name) else "let through" if stopped == 0 else "partly blocked"
                parts.append((outcome == "blocked", -len(matched), f"{name} ({_count(len(devices), *_source_noun(rows_for_name))}, {outcome})"))
            # What got through first.
            line += ". Named by the firewall or the watchlist: " + "; ".join(text for *_, text in sorted(parts)[:3])
        points.append(line + ".")
    rest = ordered[SITUATION_LINES:]
    if rest:
        counts = [f"{len(kinds[kind]):,} {SITUATION_ADJECTIVES.get(kind, kind)}" for kind in rest]
        listed = ", ".join(counts[:-1]) + f" and {counts[-1]}" if len(counts) > 1 else counts[0]
        points.append(f"Also open: {listed} {'alert' if len(rest) == 1 and len(kinds[rest[0]]) == 1 else 'alerts'}.")

    def priority(alert: Alert) -> tuple:
        total = len(by_alert.get(alert.id, []))
        let_through = total > blocked.get(alert.id, 0)
        named_threat = any(isinstance(rule, dict) and rule.get("code") in NAMED_THREAT_RULES for rule in alert.matched_rules_json or [])
        return (named_threat and let_through, SEVERITY_RANK.get(alert.severity, 0), let_through, alert.threat_score, alert.id)

    first = max(alerts.values(), key=priority)
    named_first, _, let_through, _, _ = priority(first)
    reason = (
        "a threat the firewall or the watchlist named, and the firewall let it through"
        if named_first
        else "the most serious alert whose traffic the firewall let through"
        if let_through
        else "the most serious open alert"
    )
    return {
        "headline": headline,
        "points": points,
        "open_first": {"alert_id": first.id, "severity": first.severity, "title": first.title, "reason": reason},
    }


def brief_situation(situation: dict[str, Any]) -> list[str]:
    """The situation's lines, shorter, for the assistant: only the most dangerous kind keeps its named threats.

    The full lines made overview answers run past the length limit and get rewritten ("Are we under attack?" took
    17 s instead of 5), and the open-alerts list beside them already names each alert's threat.
    """

    lines = [point if index == 0 else point.split(". Named by")[0].rstrip(".") + "." for index, point in enumerate(situation["points"])]
    if situation["open_first"]:
        first = situation["open_first"]
        lines.append(f"Open first: alert #{first['alert_id']} ({first['severity']}), {first['reason']}.")
    return lines
