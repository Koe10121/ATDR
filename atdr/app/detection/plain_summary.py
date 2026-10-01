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

from sqlalchemy import select
from sqlalchemy.orm import Session

from atdr.app.db.models import Alert, AlertEvidence, NormalizedLog, WatchlistItem
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


def _watchlist_notes(db: Session, alert: Alert) -> list[str]:
    """'111.90.158.40 is on ATDR's watchlist: GHOSTENGINE C2 server (...)' for each indicator the alert matched."""

    notes = []
    for rule in alert.matched_rules_json or []:
        text = str(rule.get("explanation") or "") if isinstance(rule, dict) else ""
        if rule.get("code") != "watchlist_match" or not text.startswith(WATCHLIST_PREFIX):
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
            notes.append(f"{value} is on ATDR's watchlist" + (f": {first.group(1)}." if first else "."))
    return notes


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
