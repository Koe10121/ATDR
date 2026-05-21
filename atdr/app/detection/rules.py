from collections import Counter, defaultdict
from dataclasses import dataclass
from statistics import mean, pstdev
from typing import Iterable

from atdr.app.db.models import NormalizedLog


SUSPICIOUS_CHARACTERISTICS = {
    "used-by-malware",
    "evasive-behavior",
    "prone-to-misuse",
    "able-to-transfer-file",
    "consume-big-bandwidth",
}

COMMON_PORTS = {
    0,
    20,
    21,
    22,
    25,
    53,
    67,
    68,
    80,
    110,
    123,
    143,
    161,
    389,
    443,
    445,
    465,
    587,
    993,
    995,
    1194,
    1433,
    1521,
    3306,
    3389,
    5432,
    5900,
    8080,
    8443,
}


@dataclass(frozen=True, slots=True)
class RuleMatch:
    code: str
    title: str
    score: int
    explanation: str


@dataclass(slots=True)
class DetectionContext:
    source_counts: Counter[str]
    source_deny_drop_counts: Counter[str]
    source_distinct_ports: dict[str, set[int]]
    byte_outlier_threshold: float
    packet_outlier_threshold: float


@dataclass(slots=True)
class DetectionResult:
    threat_score: int
    severity: str
    explanation: str
    matched_rules: list[RuleMatch]


def _lower(value: str | None) -> str:
    return (value or "").strip().lower()


def _is_deny_or_drop(log: NormalizedLog) -> bool:
    values = {
        _lower(log.action),
        _lower(log.subtype),
        _lower(log.session_end_reason),
        _lower(log.action_source),
    }
    return any(
        "deny" in value or "drop" in value or value.startswith("reset")
        for value in values
        if value
    )


def _is_outside_to_inside(log: NormalizedLog) -> bool:
    src_zone = _lower(log.src_zone)
    dst_zone = _lower(log.dst_zone)
    src_outside = "outside" in src_zone or "untrust" in src_zone or "internet" in src_zone
    dst_inside = any(token in dst_zone for token in ("inside", "trust", "lan", "wlan", "corp"))
    return src_outside and dst_inside


def _characteristic_set(value: str | None) -> set[str]:
    if not value:
        return set()
    return {item.strip().lower() for item in value.split(",") if item.strip()}


def build_detection_context(logs: Iterable[NormalizedLog]) -> DetectionContext:
    source_counts: Counter[str] = Counter()
    source_deny_drop_counts: Counter[str] = Counter()
    source_distinct_ports: dict[str, set[int]] = defaultdict(set)
    byte_values: list[int] = []
    packet_values: list[int] = []

    for log in logs:
        if log.src_ip:
            source_counts[log.src_ip] += 1
            if _is_deny_or_drop(log):
                source_deny_drop_counts[log.src_ip] += 1
            if log.dst_port is not None:
                source_distinct_ports[log.src_ip].add(log.dst_port)
        if log.bytes is not None:
            byte_values.append(log.bytes)
        if log.packets is not None:
            packet_values.append(log.packets)

    byte_threshold = 10_000_000.0
    packet_threshold = 50_000.0
    if len(byte_values) >= 10:
        byte_threshold = max(byte_threshold, mean(byte_values) + (3 * pstdev(byte_values)))
    if len(packet_values) >= 10:
        packet_threshold = max(packet_threshold, mean(packet_values) + (3 * pstdev(packet_values)))

    return DetectionContext(
        source_counts=source_counts,
        source_deny_drop_counts=source_deny_drop_counts,
        source_distinct_ports=source_distinct_ports,
        byte_outlier_threshold=byte_threshold,
        packet_outlier_threshold=packet_threshold,
    )


def evaluate_rules(log: NormalizedLog, context: DetectionContext) -> list[RuleMatch]:
    matches: list[RuleMatch] = []
    src_ip = log.src_ip or "unknown source"

    if _is_deny_or_drop(log):
        matches.append(
            RuleMatch(
                code="deny_drop_action",
                title="Deny or drop action",
                score=25,
                explanation=f"Firewall action or session end reason indicates deny/drop behavior for {src_ip}.",
            )
        )

    if log.log_type == "THREAT":
        matches.append(
            RuleMatch(
                code="paloalto_threat_log",
                title="Palo Alto threat event",
                score=30,
                explanation="The firewall classified this row as a THREAT event.",
            )
        )

    if log.app_risk == 4:
        matches.append(
            RuleMatch(
                code="app_risk_4",
                title="High application risk",
                score=15,
                explanation="Palo Alto application risk is 4.",
            )
        )
    elif log.app_risk and log.app_risk >= 5:
        matches.append(
            RuleMatch(
                code="app_risk_5",
                title="Very high application risk",
                score=25,
                explanation="Palo Alto application risk is 5.",
            )
        )

    risky_characteristics = sorted(_characteristic_set(log.app_characteristic) & SUSPICIOUS_CHARACTERISTICS)
    if risky_characteristics:
        matches.append(
            RuleMatch(
                code="suspicious_app_characteristic",
                title="Suspicious application characteristic",
                score=15,
                explanation=f"Application characteristics include: {', '.join(risky_characteristics)}.",
            )
        )

    if _is_outside_to_inside(log):
        matches.append(
            RuleMatch(
                code="outside_to_inside",
                title="Outside-to-inside traffic",
                score=15,
                explanation=f"Traffic crossed from {log.src_zone or 'unknown'} to {log.dst_zone or 'unknown'}.",
            )
        )

    source_count = context.source_counts.get(src_ip, 0)
    if source_count >= 25:
        matches.append(
            RuleMatch(
                code="repeated_source_ip",
                title="Repeated source activity",
                score=20,
                explanation=f"{src_ip} appears in {source_count} logs in the detection batch.",
            )
        )

    deny_drop_count = context.source_deny_drop_counts.get(src_ip, 0)
    if deny_drop_count >= 5:
        matches.append(
            RuleMatch(
                code="multiple_denied_connections",
                title="Multiple denied or dropped connections",
                score=20,
                explanation=f"{src_ip} has {deny_drop_count} denied or dropped logs in the detection batch.",
            )
        )

    distinct_ports = len(context.source_distinct_ports.get(src_ip, set()))
    if distinct_ports >= 10:
        matches.append(
            RuleMatch(
                code="possible_port_scan",
                title="Possible port scanning behavior",
                score=25,
                explanation=f"{src_ip} touched {distinct_ports} distinct destination ports.",
            )
        )

    if log.dst_port is not None and log.dst_port not in COMMON_PORTS and _is_outside_to_inside(log):
        matches.append(
            RuleMatch(
                code="unusual_destination_port",
                title="Unusual destination port",
                score=10,
                explanation=f"Outside-to-inside traffic used uncommon destination port {log.dst_port}.",
            )
        )

    app_name = _lower(log.app)
    app_category = _lower(log.app_category)
    if app_name in {"unknown", "incomplete", "not-applicable"} or app_category == "unknown":
        matches.append(
            RuleMatch(
                code="unknown_or_incomplete_app",
                title="Unknown or incomplete application",
                score=10,
                explanation=f"Application is {log.app or 'not identified'} with category {log.app_category or 'unknown'}.",
            )
        )

    if log.bytes is not None and log.bytes > context.byte_outlier_threshold:
        matches.append(
            RuleMatch(
                code="high_bytes_outlier",
                title="High byte-count outlier",
                score=20,
                explanation=f"Bytes value {log.bytes} is above the batch outlier threshold.",
            )
        )

    if log.packets is not None and log.packets > context.packet_outlier_threshold:
        matches.append(
            RuleMatch(
                code="high_packets_outlier",
                title="High packet-count outlier",
                score=20,
                explanation=f"Packet count {log.packets} is above the batch outlier threshold.",
            )
        )

    if log.is_anomaly:
        matches.append(
            RuleMatch(
                code="ml_anomaly_detected",
                title="ML anomaly detected",
                score=25,
                explanation="IsolationForest marked this event as unusual compared with imported logs.",
            )
        )

    return matches
