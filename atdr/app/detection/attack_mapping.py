from typing import Any

from atdr.app.detection.rule_catalog import RULE_CATALOG, SUPPORTING_ONLY_RULES


ATTACK_TYPE_MAPPINGS: dict[str, dict[str, str]] = {
    "normal": {
        "tactic": "Normal",
        "technique": "Expected business traffic",
        "technique_id": "N/A",
        "description": "No ATT&CK technique is assigned to normal or accepted traffic.",
        "mapping_confidence": "not_applicable",
        "claim_boundary": "Normal means no supported threat claim from the evaluated evidence, not proof of safety.",
    },
    "port_scan": {
        "tactic": "Discovery",
        "technique": "Network Service Discovery",
        "technique_id": "T1046",
        "description": "Scanning-like behavior can indicate discovery of exposed services.",
        "mapping_confidence": "medium",
        "claim_boundary": "The mapping describes observable service probing; intent and authorization require analyst context.",
    },
    "brute_force": {
        "tactic": "Credential Access",
        "technique": "Brute Force",
        "technique_id": "T1110",
        "description": "Repeated authentication or connection attempts can indicate brute-force behavior.",
        "mapping_confidence": "medium",
        "claim_boundary": "Traffic-log retries do not prove password guessing or account compromise.",
    },
    "dos_ddos": {
        "tactic": "Impact",
        "technique": "Network Denial of Service",
        "technique_id": "T1498",
        "description": "High-volume repeated traffic may affect service availability.",
        "mapping_confidence": "low",
        "claim_boundary": "ATDR observes flood-like volume; service impact requires independent telemetry.",
    },
    "malware_c2": {
        "tactic": "Command and Control",
        "technique": "Application Layer Protocol",
        "technique_id": "T1071",
        "description": "Repeated, risky outbound application traffic can resemble an application-layer C2 channel.",
        "mapping_confidence": "low",
        "claim_boundary": "This is C2-like behavior, not proof of malware or command-and-control.",
    },
    "policy_violation": {
        "tactic": "Governance",
        "technique": "Policy violation",
        "technique_id": "Internal",
        "description": "Traffic violated local firewall or acceptable-use policy.",
        "mapping_confidence": "environment_dependent",
        "claim_boundary": "This is an ATDR governance category and not a MITRE ATT&CK technique.",
    },
    "exploit_attempt": {
        "tactic": "Initial Access",
        "technique": "Exploit Public-Facing Application",
        "technique_id": "T1190",
        "description": "The firewall matched the traffic to a known exploit or web-attack signature aimed at a service.",
        "mapping_confidence": "medium",
        "claim_boundary": "A signature match shows an attempt, not that it succeeded; whether the target was vulnerable needs checking.",
    },
    "data_exfiltration_suspicion": {
        "tactic": "Exfiltration",
        "technique": "Exfiltration Over Alternative Protocol",
        "technique_id": "T1048",
        "description": "Large or unusual outbound transfer patterns may indicate exfiltration risk.",
        "mapping_confidence": "low",
        "claim_boundary": "Transfer volume alone does not establish data theft, protocol misuse, or authorization.",
    },
    "unknown_anomaly": {
        "tactic": "Unknown",
        "technique": "Needs Investigation",
        "technique_id": "Unknown",
        "description": "The behavior is unusual or suspicious but needs analyst context before classification.",
        "mapping_confidence": "unknown",
        "claim_boundary": "No specific ATT&CK technique is supported by the available evidence.",
    },
}

# Each rule's default attack type is the one its catalog entry documents.
RULE_ATTACK_HINTS = {
    **{code: spec.attack_type for code, spec in RULE_CATALOG.items()},
    "watchlist_match": "unknown_anomaly",
    # The MFU behaviour model's experimental alerts; each names its type on the match itself.
    "mfu_behavior_model": "unknown_anomaly",
}

RULE_ATTACK_PRIORITY = {
    "possible_port_scan": 100,
    "possible_horizontal_scan": 99,
    "connection_flood_suspicion": 95,
    "brute_force_like_attempts": 92,
    "beaconing_like_outbound": 90,
    "high_outbound_bytes": 88,
    "repeated_large_outbound": 87,
    "high_bytes_outlier": 80,
    "high_packets_outlier": 78,
    "paloalto_malware_threat": 91,
    "watchlist_match": 89,
    "paloalto_threat_log": 75,
    "paloalto_threat_informational": 10,
    "suspicious_app_characteristic": 70,
    # IsolationForest is advisory evidence. It must never mask a more
    # specific alert-authoritative rule when an attack type is inferred.
    "ml_anomaly_detected": 5,
    "unknown_or_incomplete_app": 40,
    "multiple_denied_connections": 35,
    "deny_drop_action": 30,
    "app_risk_5": 26,
    "app_risk_4": 25,
    "unusual_destination_port": 20,
}

# A firewall threat signature or a known indicator names the activity, so the
# type it names outranks one inferred from the shape of the traffic.
IDENTIFIED_EVIDENCE_RULES = frozenset({"paloalto_malware_threat", "paloalto_threat_log", "watchlist_match"})

# When one rule's evidence names different types, the alert keeps the first of these.
ATTACK_TYPE_SPECIFICITY = (
    "malware_c2",
    "exploit_attempt",
    "data_exfiltration_suspicion",
    "brute_force",
    "dos_ddos",
    "port_scan",
    "policy_violation",
    "unknown_anomaly",
)

# Palo Alto THREAT types that name the activity on their own.
THREAT_SUBTYPE_ATTACK_TYPES = {
    "scan": "port_scan",
    "flood": "dos_ddos",
    "data": "data_exfiltration_suspicion",
    "virus": "malware_c2",
    "wildfire-virus": "malware_c2",
    "spyware": "malware_c2",
}
# A vulnerability signature's name says what it detected.
PROTOCOL_ANOMALY_SIGNATURE_WORDS = ("non-rfc compliant",)
DISCOVERY_SIGNATURE_WORDS = ("nmap", "port scan", "portmapper", "discovery", "enumeration", "sweep")
BRUTE_FORCE_SIGNATURE_WORDS = ("brute force", "brute-force", "login attempt")
EXPLOIT_SIGNATURE_WORDS = (
    "code execution",
    "injection",
    "traversal",
    "overflow",
    "exploit",
    "deserialization",
    "file inclusion",
    "scanning attempt",
    "privilege escalation",
    "authentication bypass",
)
# Informational and low vulnerability signatures mostly flag odd but harmless
# protocol use; from medium up they match known exploit traffic.
EXPLOIT_SIGNATURE_SEVERITIES = frozenset({"medium", "high", "critical"})


def threat_attack_type(threat_type: str | None, threat_name: str | None, severity: str | None) -> str:
    """The activity a firewall THREAT record names, from its type, signature name and severity."""

    kind = (threat_type or "").strip().lower()
    name = (threat_name or "").strip().lower()
    if kind in THREAT_SUBTYPE_ATTACK_TYPES:
        return THREAT_SUBTYPE_ATTACK_TYPES[kind]
    if kind != "vulnerability" or any(word in name for word in PROTOCOL_ANOMALY_SIGNATURE_WORDS):
        return "unknown_anomaly"
    if any(word in name for word in DISCOVERY_SIGNATURE_WORDS):
        return "port_scan"
    if any(word in name for word in BRUTE_FORCE_SIGNATURE_WORDS):
        return "brute_force"
    if any(word in name for word in EXPLOIT_SIGNATURE_WORDS) or (severity or "").strip().lower() in EXPLOIT_SIGNATURE_SEVERITIES:
        return "exploit_attempt"
    return "unknown_anomaly"


def more_specific_attack_type(current: str | None, incoming: str | None) -> str | None:
    if current is None or incoming is None:
        return current or incoming
    order = {attack_type: index for index, attack_type in enumerate(ATTACK_TYPE_SPECIFICITY)}
    return incoming if order.get(incoming, len(order)) < order.get(current, len(order)) else current


def attack_mapping_for_type(attack_type: str | None) -> dict[str, str]:
    normalized = (attack_type or "unknown_anomaly").strip().lower()
    return {"attack_type": normalized, **ATTACK_TYPE_MAPPINGS.get(normalized, ATTACK_TYPE_MAPPINGS["unknown_anomaly"])}


def rule_attack_type(rule: dict[str, Any]) -> str | None:
    """A matched rule's attack type: the one its evidence named, else its catalog default."""

    named = str(rule.get("attack_type") or "").strip()
    if named in ATTACK_TYPE_MAPPINGS and named != "normal":
        return named
    return RULE_ATTACK_HINTS.get(str(rule.get("code") or "").strip())


def infer_attack_type_from_rules(matched_rules: list[dict[str, Any]]) -> str:
    best: tuple[tuple[bool, bool, int], str] | None = None
    for rule in matched_rules:
        attack_type = rule_attack_type(rule)
        if attack_type is None:
            continue
        code = str(rule.get("code") or "").strip()
        named = attack_type != "unknown_anomaly"
        # "Needs investigation" never hides a type a behavioural rule names. A
        # context signal (the app's vendor risk rating, say) is too weak to.
        rank = (
            named and code in IDENTIFIED_EVIDENCE_RULES,
            named and code not in SUPPORTING_ONLY_RULES,
            RULE_ATTACK_PRIORITY.get(code, 0),
        )
        if best is None or rank > best[0]:
            best = (rank, attack_type)
    return best[1] if best else "unknown_anomaly"
