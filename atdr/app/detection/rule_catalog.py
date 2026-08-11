from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


RULE_CATALOG_VERSION = "atdr_rule_catalog_v5.31.0"

PAN_TRAFFIC_FIELDS = (
    "https://docs.paloaltonetworks.com/ngfw/administration/monitoring/"
    "use-syslog-for-monitoring/syslog-field-descriptions/traffic-log-fields"
)
PAN_THREAT_FIELDS = (
    "https://docs.paloaltonetworks.com/ngfw/administration/monitoring/"
    "use-syslog-for-monitoring/syslog-field-descriptions/threat-log-fields"
)
SIGMA_RULE_SPEC = "https://sigmahq.io/sigma-specification/specification/sigma-rules-specification.html"
MITRE_T1046 = "https://attack.mitre.org/techniques/T1046/"
MITRE_T1110 = "https://attack.mitre.org/techniques/T1110/"
MITRE_T1498 = "https://attack.mitre.org/techniques/T1498/"
MITRE_T1071 = "https://attack.mitre.org/techniques/T1071/"
MITRE_T1048 = "https://attack.mitre.org/techniques/T1048/"


@dataclass(frozen=True, slots=True)
class DetectionRuleSpec:
    rule_id: str
    code: str
    title: str
    version: str
    status: str
    log_sources: tuple[str, ...]
    required_fields: tuple[str, ...]
    correlation_window: str
    condition: str
    level: str
    confidence: str
    attack_type: str
    mitre_technique_ids: tuple[str, ...]
    false_positives: tuple[str, ...]
    references: tuple[str, ...]
    explanation_template: str
    claim_boundary: str

    def as_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["log_sources"] = list(self.log_sources)
        payload["required_fields"] = list(self.required_fields)
        payload["mitre_technique_ids"] = list(self.mitre_technique_ids)
        payload["false_positives"] = list(self.false_positives)
        payload["references"] = list(self.references)
        payload["catalog_version"] = RULE_CATALOG_VERSION
        return payload


def _spec(
    rule_id: str,
    code: str,
    title: str,
    *,
    required_fields: tuple[str, ...],
    condition: str,
    level: str,
    confidence: str,
    attack_type: str = "unknown_anomaly",
    mitre: tuple[str, ...] = (),
    window: str = "single_event",
    false_positives: tuple[str, ...] = (),
    references: tuple[str, ...] = (PAN_TRAFFIC_FIELDS, SIGMA_RULE_SPEC),
    status: str = "test",
    version: str = "1.0.0",
    claim_boundary: str = "A rule match is a triage signal, not proof of compromise.",
) -> DetectionRuleSpec:
    return DetectionRuleSpec(
        rule_id=rule_id,
        code=code,
        title=title,
        version=version,
        status=status,
        log_sources=("palo_alto",),
        required_fields=required_fields,
        correlation_window=window,
        condition=condition,
        level=level,
        confidence=confidence,
        attack_type=attack_type,
        mitre_technique_ids=mitre,
        false_positives=false_positives,
        references=references,
        explanation_template="Report observed fields, correlation counts, and missing context without asserting attribution.",
        claim_boundary=claim_boundary,
    )


RULE_CATALOG: dict[str, DetectionRuleSpec] = {
    item.code: item
    for item in (
        _spec(
            "ATDR-NET-001",
            "deny_drop_action",
            "Deny or drop action",
            required_fields=("action",),
            condition="action, subtype, session end reason, or action source indicates deny, drop, or reset",
            level="low",
            confidence="high",
            attack_type="policy_violation",
            false_positives=("Expected firewall policy enforcement", "Routine internet background noise"),
        ),
        _spec(
            "ATDR-NET-002",
            "paloalto_threat_log",
            "Palo Alto threat event",
            required_fields=("log_type", "subtype"),
            condition="vendor log type equals THREAT",
            level="high",
            confidence="high",
            references=(PAN_THREAT_FIELDS, SIGMA_RULE_SPEC),
            false_positives=("Informational or low-severity vendor threat signatures",),
            version="2.0.0",
            claim_boundary="The firewall reported a THREAT event; subtype, severity, signature, and action still require review.",
        ),
        _spec(
            "ATDR-NET-003",
            "app_risk_4",
            "High application risk",
            required_fields=("app_risk",),
            condition="vendor application risk equals 4",
            level="low",
            confidence="medium",
            attack_type="policy_violation",
            false_positives=("Approved high-risk business application",),
        ),
        _spec(
            "ATDR-NET-004",
            "app_risk_5",
            "Very high application risk",
            required_fields=("app_risk",),
            condition="vendor application risk is at least 5",
            level="medium",
            confidence="medium",
            attack_type="policy_violation",
            false_positives=("Approved very-high-risk application",),
        ),
        _spec(
            "ATDR-NET-005",
            "suspicious_app_characteristic",
            "Suspicious application characteristic",
            required_fields=("app_characteristic",),
            condition="vendor application characteristics intersect the ATDR risk characteristic set",
            level="medium",
            confidence="medium",
            attack_type="policy_violation",
            false_positives=("Approved file transfer, remote access, or high-bandwidth application",),
        ),
        _spec(
            "ATDR-NET-006",
            "outside_to_inside",
            "Outside-to-inside traffic",
            required_fields=("src_zone", "dst_zone"),
            condition="source zone is external and destination zone is internal",
            level="informational",
            confidence="high",
            false_positives=("Expected public service traffic",),
        ),
        _spec(
            "ATDR-NET-007",
            "repeated_source_ip",
            "Repeated source activity",
            required_fields=("src_ip", "generated_time"),
            condition="source produces at least 25 events in the same source-scoped five-minute window",
            level="low",
            confidence="medium",
            window="5m",
            false_positives=("NAT gateways", "Monitoring systems", "Busy application clients"),
        ),
        _spec(
            "ATDR-NET-008",
            "multiple_denied_connections",
            "Multiple denied or dropped connections",
            required_fields=("src_ip", "action", "generated_time"),
            condition="source produces at least 5 denied, dropped, or reset events in five minutes",
            level="medium",
            confidence="medium",
            attack_type="policy_violation",
            window="5m",
            false_positives=("Misconfigured client", "Expired service configuration", "Internet scanning noise"),
        ),
        _spec(
            "ATDR-NET-009",
            "brute_force_like_attempts",
            "Brute-force-like service attempts",
            required_fields=("src_ip", "dst_port", "action", "generated_time"),
            condition=(
                "source produces at least 5 denied/reset attempts to the same destination and "
                "authentication/service port in five minutes"
            ),
            level="high",
            confidence="medium",
            attack_type="brute_force",
            mitre=("T1110",),
            window="5m",
            false_positives=("Password manager retries", "Service health checks", "Misconfigured credentials"),
            references=(PAN_TRAFFIC_FIELDS, MITRE_T1110, SIGMA_RULE_SPEC),
            version="2.0.0",
            claim_boundary="Observed behavior resembles repeated access attempts; firewall traffic logs do not prove credential guessing.",
        ),
        _spec(
            "ATDR-NET-010",
            "possible_port_scan",
            "Possible port scanning behavior",
            required_fields=("src_ip", "dst_port", "generated_time"),
            condition=(
                "source touches at least 10 distinct destination ports in five minutes with "
                "deny/drop, inbound, unresolved-app, or vendor scan context"
            ),
            level="high",
            confidence="medium",
            attack_type="port_scan",
            mitre=("T1046",),
            window="5m",
            false_positives=("Vulnerability scanners", "Asset discovery", "Monitoring systems"),
            references=(PAN_TRAFFIC_FIELDS, MITRE_T1046, SIGMA_RULE_SPEC),
            version="2.0.0",
            claim_boundary="Observed service probing is consistent with discovery; intent and authorization require analyst context.",
        ),
        _spec(
            "ATDR-NET-011",
            "beaconing_like_outbound",
            "Beaconing-like repeated outbound behavior",
            required_fields=("src_ip", "dst_ip", "dst_port", "src_zone", "dst_zone", "generated_time"),
            condition=(
                "at least 6 periodic internal-to-external connections to one destination with "
                "5-300 second mean intervals, jitter ratio at most 0.25, and an uncommon service, "
                "unidentified app, vendor THREAT event, or very-high-risk application evidence"
            ),
            level="high",
            confidence="medium",
            attack_type="malware_c2",
            mitre=("T1071",),
            window="5m",
            false_positives=("Telemetry agents", "Keepalive traffic", "Software update polling"),
            references=(PAN_TRAFFIC_FIELDS, MITRE_T1071, SIGMA_RULE_SPEC),
            version="2.0.0",
            claim_boundary="Periodic outbound behavior is C2-like, but ATDR cannot prove command-and-control from this evidence alone.",
        ),
        _spec(
            "ATDR-NET-012",
            "connection_flood_suspicion",
            "Connection flood-like behavior",
            required_fields=("src_ip", "dst_ip", "dst_port", "generated_time"),
            condition=(
                "source makes at least 20 connections to one destination service in five minutes "
                "with deny/reset or vendor flood/packet evidence, or reaches at least 100 repeated "
                "session events regardless of action"
            ),
            level="high",
            confidence="medium",
            attack_type="dos_ddos",
            mitre=("T1498",),
            window="5m",
            false_positives=("Load tests", "Health checks", "High-volume API clients"),
            references=(PAN_TRAFFIC_FIELDS, MITRE_T1498, SIGMA_RULE_SPEC),
            version="2.0.0",
            claim_boundary="High connection volume may affect availability; impact is not established without service telemetry.",
        ),
        _spec(
            "ATDR-NET-013",
            "unusual_destination_port",
            "Unusual destination port",
            required_fields=("dst_port", "src_zone", "dst_zone"),
            condition="outside-to-inside traffic uses a port outside the ATDR common-service allowlist",
            level="low",
            confidence="low",
            false_positives=("Approved service on a non-standard port",),
        ),
        _spec(
            "ATDR-NET-014",
            "high_outbound_bytes",
            "High outbound byte volume",
            required_fields=("bytes_sent", "bytes", "src_zone", "dst_zone"),
            condition=(
                "internal-to-external bytes_sent, or total bytes when bytes_sent is unavailable, "
                "exceed the versioned high-volume threshold"
            ),
            level="high",
            confidence="low",
            attack_type="data_exfiltration_suspicion",
            mitre=("T1048",),
            false_positives=("Backups", "Cloud synchronization", "Large approved uploads"),
            references=(PAN_TRAFFIC_FIELDS, MITRE_T1048, SIGMA_RULE_SPEC),
            version="2.0.0",
            claim_boundary="Large outbound transfer is an exfiltration suspicion only; content, authorization, and baseline context are required.",
        ),
        _spec(
            "ATDR-NET-015",
            "unknown_or_incomplete_app",
            "Unknown or incomplete application",
            required_fields=("app",),
            condition=(
                "application or application category is explicitly unknown, incomplete, "
                "unknown-tcp, or not applicable"
            ),
            level="informational",
            confidence="high",
            false_positives=("Early session identification", "Unsupported protocol", "Encrypted or short-lived sessions"),
            version="2.0.0",
        ),
        _spec(
            "ATDR-NET-016",
            "high_bytes_outlier",
            "High byte-count outlier",
            required_fields=("bytes",),
            condition="total bytes exceed the versioned high-volume threshold",
            level="medium",
            confidence="low",
            false_positives=("Backups", "Media transfer", "Software distribution"),
        ),
        _spec(
            "ATDR-NET-017",
            "high_packets_outlier",
            "High packet-count outlier",
            required_fields=("packets",),
            condition="packet count exceeds the versioned high-volume threshold",
            level="medium",
            confidence="low",
            false_positives=("High-throughput services", "Monitoring", "Bulk transfer"),
        ),
        _spec(
            "ATDR-NET-018",
            "possible_horizontal_scan",
            "Possible horizontal service scanning behavior",
            required_fields=("src_ip", "dst_ip", "dst_port", "generated_time"),
            condition=(
                "source reaches at least 10 distinct destinations on one service port in five "
                "minutes with deny/drop, inbound, or unresolved-app context"
            ),
            level="high",
            confidence="medium",
            attack_type="port_scan",
            mitre=("T1046",),
            window="5m",
            false_positives=("Authorized vulnerability scanners", "Asset discovery", "Service health sweeps"),
            references=(PAN_TRAFFIC_FIELDS, MITRE_T1046, SIGMA_RULE_SPEC),
            claim_boundary=(
                "Same-service probing across hosts resembles network service discovery; intent "
                "and scanner authorization require analyst context."
            ),
        ),
        _spec(
            "ATDR-ML-001",
            "ml_anomaly_detected",
            "ML anomaly detected",
            required_fields=("is_anomaly", "anomaly_score"),
            condition="IsolationForest diagnostic score crosses its configured threshold",
            level="medium",
            confidence="low",
            status="experimental",
            false_positives=("Rare but legitimate behavior", "Distribution shift", "Missing parser fields"),
            references=(SIGMA_RULE_SPEC,),
            claim_boundary="Anomaly means statistically unusual, not malicious. Analyst and rule evidence remain required.",
        ),
    )
}


def rule_spec(code: str) -> DetectionRuleSpec | None:
    return RULE_CATALOG.get(code)


def rule_metadata(code: str) -> dict[str, Any]:
    spec = rule_spec(code)
    return spec.as_dict() if spec else {"code": code, "catalog_version": RULE_CATALOG_VERSION, "status": "unregistered"}


def serialize_rule_match(match: Any) -> dict[str, Any]:
    return {
        **rule_metadata(str(match.code)),
        "code": str(match.code),
        "title": str(match.title),
        "score": int(match.score),
        "explanation": str(match.explanation),
    }
