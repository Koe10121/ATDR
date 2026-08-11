from typing import Any


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

RULE_ATTACK_HINTS = {
    "possible_port_scan": "port_scan",
    "possible_horizontal_scan": "port_scan",
    "brute_force_like_attempts": "brute_force",
    "beaconing_like_outbound": "malware_c2",
    "connection_flood_suspicion": "dos_ddos",
    "multiple_denied_connections": "policy_violation",
    "deny_drop_action": "policy_violation",
    "paloalto_threat_log": "unknown_anomaly",
    "suspicious_app_characteristic": "policy_violation",
    "high_outbound_bytes": "data_exfiltration_suspicion",
    "high_bytes_outlier": "unknown_anomaly",
    "high_packets_outlier": "unknown_anomaly",
    "ml_anomaly_detected": "unknown_anomaly",
    "unknown_or_incomplete_app": "unknown_anomaly",
}

RULE_ATTACK_PRIORITY = {
    "possible_port_scan": 100,
    "possible_horizontal_scan": 99,
    "connection_flood_suspicion": 95,
    "brute_force_like_attempts": 92,
    "beaconing_like_outbound": 90,
    "high_outbound_bytes": 88,
    "high_bytes_outlier": 80,
    "high_packets_outlier": 78,
    "paloalto_threat_log": 75,
    "suspicious_app_characteristic": 70,
    # IsolationForest is advisory evidence. It must never mask a more
    # specific alert-authoritative rule when an attack type is inferred.
    "ml_anomaly_detected": 5,
    "unknown_or_incomplete_app": 40,
    "multiple_denied_connections": 35,
    "deny_drop_action": 30,
}


def attack_mapping_for_type(attack_type: str | None) -> dict[str, str]:
    normalized = (attack_type or "unknown_anomaly").strip().lower()
    return {"attack_type": normalized, **ATTACK_TYPE_MAPPINGS.get(normalized, ATTACK_TYPE_MAPPINGS["unknown_anomaly"])}


def infer_attack_type_from_rules(matched_rules: list[dict[str, Any]]) -> str:
    ranked_codes = [
        str(rule.get("code") or "").strip()
        for rule in matched_rules
        if str(rule.get("code") or "").strip() in RULE_ATTACK_HINTS
    ]
    if ranked_codes:
        code = max(ranked_codes, key=lambda item: RULE_ATTACK_PRIORITY.get(item, 0))
        return RULE_ATTACK_HINTS[code]
    return "unknown_anomaly"
