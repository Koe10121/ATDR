from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
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
BEACON_HIGH_SIGNAL_CHARACTERISTICS = {
    "used-by-malware",
    "evasive-behavior",
}
CORRELATION_WINDOW_MINUTES = 5
REPEATED_SOURCE_THRESHOLD = 25
DENY_BURST_THRESHOLD = 5
AUTH_TARGET_DENY_THRESHOLD = 5
VERTICAL_SCAN_PORT_THRESHOLD = 10
HORIZONTAL_SCAN_DESTINATION_THRESHOLD = 10
BEACON_EVENT_THRESHOLD = 6
BEACON_MIN_INTERVAL_SECONDS = 5.0
BEACON_MAX_INTERVAL_SECONDS = 300.0
BEACON_MAX_JITTER_RATIO = 0.25
FLOOD_CORROBORATED_EVENT_THRESHOLD = 20
HIGH_VOLUME_COMMON_SERVICE_THRESHOLD = 100

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

AUTH_SERVICE_PORTS = {21, 22, 23, 25, 110, 143, 389, 445, 465, 587, 993, 995, 1433, 3306, 3389, 5432, 5900}


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
    source_auth_deny_counts: Counter[str]
    source_destination_counts: Counter[tuple[str, str, int | None]]
    source_auth_destination_counts: Counter[tuple[str, str, str, int | None]]
    byte_outlier_threshold: float
    packet_outlier_threshold: float
    event_correlations: dict[int, "CorrelationSnapshot"]
    correlation_window: str = "5m_source_scoped"


@dataclass(frozen=True, slots=True)
class CorrelationSnapshot:
    source_count: int
    deny_drop_count: int
    distinct_ports: frozenset[int]
    auth_deny_count: int
    auth_target_deny_count: int
    destination_repeat_count: int
    destination_event_count: int
    distinct_destinations_for_port: int
    deny_drop_count_for_port: int
    cadence_interval_count: int
    cadence_mean_seconds: float | None
    cadence_jitter_ratio: float | None
    source_scope: str
    window_label: str


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


def _is_internal_to_external(log: NormalizedLog) -> bool:
    src_zone = _lower(log.src_zone)
    dst_zone = _lower(log.dst_zone)
    src_inside = any(token in src_zone for token in ("inside", "trust", "lan", "wlan", "corp"))
    dst_outside = "outside" in dst_zone or "untrust" in dst_zone or "internet" in dst_zone
    return src_inside and dst_outside


def _characteristic_set(value: str | None) -> set[str]:
    if not value:
        return set()
    return {item.strip().lower() for item in value.split(",") if item.strip()}


def _event_key(log: NormalizedLog) -> int:
    return int(log.id) if log.id is not None else id(log)


def _source_scope(log: NormalizedLog) -> str:
    source_id = getattr(log, "source_id", None)
    raw_log = getattr(log, "raw_log", None)
    if source_id is None and raw_log is not None:
        source_id = getattr(raw_log, "source_id", None)
    return f"source:{source_id}" if source_id is not None else "source:unscoped"


def _event_time(log: NormalizedLog) -> datetime | None:
    return log.generated_time or log.receive_time or log.high_res_timestamp or log.start_time


def _window_label(log: NormalizedLog) -> str:
    value = _event_time(log)
    if value is None:
        return "missing-event-time"
    minute = (value.minute // 5) * 5
    return value.replace(minute=minute, second=0, microsecond=0).isoformat()


def _effective_event_count(log: NormalizedLog) -> int:
    # PAN repeatcnt is the number of otherwise identical sessions observed in
    # five seconds. It is useful correlation evidence but is bounded here so a
    # malformed field cannot create an unbounded score contribution.
    return min(max(int(log.repeat_count or 1), 1), 10_000)


def _parsed_value(log: NormalizedLog, key: str) -> str:
    parsed = getattr(log, "parsed_json", None)
    if not isinstance(parsed, dict):
        return ""
    return str(parsed.get(key) or "").strip()


def _threat_event_score(log: NormalizedLog) -> tuple[int, str]:
    severity = _parsed_value(log, "parsed_threat_severity").lower()
    scores = {
        "informational": 10,
        "info": 10,
        "low": 20,
        "medium": 30,
        "high": 40,
        "critical": 45,
    }
    return scores.get(severity, 30), severity or "unavailable"


def _outbound_byte_value(log: NormalizedLog) -> tuple[int | None, str]:
    bytes_sent = getattr(log, "bytes_sent", None)
    if bytes_sent is not None:
        return int(bytes_sent), "bytes_sent"
    if log.bytes is not None:
        return int(log.bytes), "total bytes (bytes_sent unavailable)"
    return None, "bytes unavailable"


def _cadence_metrics(times: list[datetime]) -> tuple[int, float | None, float | None]:
    ordered = sorted(set(times))
    intervals = [
        (current - previous).total_seconds()
        for previous, current in zip(ordered, ordered[1:])
        if current > previous
    ]
    if not intervals:
        return 0, None, None
    interval_mean = mean(intervals)
    jitter_ratio = (pstdev(intervals) / interval_mean) if interval_mean > 0 else None
    return len(intervals), interval_mean, jitter_ratio


def build_detection_context(logs: Iterable[NormalizedLog]) -> DetectionContext:
    materialized_logs = logs if isinstance(logs, list) else list(logs)
    source_counts: Counter[str] = Counter()
    source_deny_drop_counts: Counter[str] = Counter()
    source_distinct_ports: dict[str, set[int]] = defaultdict(set)
    source_auth_deny_counts: Counter[str] = Counter()
    source_destination_counts: Counter[tuple[str, str, int | None]] = Counter()
    source_auth_destination_counts: Counter[tuple[str, str, str, int | None]] = Counter()
    byte_values: list[int] = []
    packet_values: list[int] = []

    source_groups: dict[tuple[str, str], list[NormalizedLog]] = defaultdict(list)

    for log in materialized_logs:
        if log.src_ip:
            effective_count = _effective_event_count(log)
            scope = _source_scope(log)
            source_counts[log.src_ip] += effective_count
            if _is_deny_or_drop(log):
                source_deny_drop_counts[log.src_ip] += effective_count
                if log.dst_port in AUTH_SERVICE_PORTS:
                    source_auth_deny_counts[log.src_ip] += effective_count
                    source_auth_destination_counts[
                        (scope, log.src_ip, log.dst_ip or "", log.dst_port)
                    ] += effective_count
            if log.dst_port is not None:
                source_distinct_ports[log.src_ip].add(log.dst_port)
            if log.dst_ip:
                source_destination_counts[(log.src_ip, log.dst_ip, log.dst_port)] += effective_count
            source_groups[(scope, log.src_ip)].append(log)
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

    correlation_groups: list[tuple[str, str, list[NormalizedLog]]] = []
    for (scope, _src_ip), grouped_logs in source_groups.items():
        timed = sorted(
            (item for item in grouped_logs if _event_time(item) is not None),
            key=lambda item: (_event_time(item), _event_key(item)),
        )
        missing_time = [item for item in grouped_logs if _event_time(item) is None]
        current: list[NormalizedLog] = []
        window_start: datetime | None = None
        for item in timed:
            item_time = _event_time(item)
            if window_start is None or (
                item_time is not None
                and item_time - window_start <= timedelta(minutes=CORRELATION_WINDOW_MINUTES)
            ):
                current.append(item)
                window_start = window_start or item_time
                continue
            correlation_groups.append((scope, window_start.isoformat(), current))
            current = [item]
            window_start = item_time
        if current and window_start is not None:
            correlation_groups.append((scope, window_start.isoformat(), current))
        for item in missing_time:
            # A missing event timestamp cannot support cross-row temporal
            # correlation. Keep each row isolated while still allowing
            # event-local evidence such as PAN repeatcnt to be evaluated.
            correlation_groups.append(
                (
                    scope,
                    f"missing-event-time:{_event_key(item)}",
                    [item],
                )
            )

    event_correlations: dict[int, CorrelationSnapshot] = {}
    for scope, window_label, grouped_logs in correlation_groups:
        source_count = sum(_effective_event_count(item) for item in grouped_logs)
        deny_drop_count = sum(
            _effective_event_count(item) for item in grouped_logs if _is_deny_or_drop(item)
        )
        auth_deny_count = sum(
            _effective_event_count(item)
            for item in grouped_logs
            if _is_deny_or_drop(item) and item.dst_port in AUTH_SERVICE_PORTS
        )
        distinct_ports = frozenset(item.dst_port for item in grouped_logs if item.dst_port is not None)
        destination_counts: Counter[tuple[str, int | None]] = Counter()
        destination_event_counts: Counter[tuple[str, int | None]] = Counter()
        auth_target_deny_counts: Counter[tuple[str, int | None]] = Counter()
        port_destinations: dict[int, set[str]] = defaultdict(set)
        port_deny_drop_counts: Counter[int] = Counter()
        destination_times: dict[tuple[str, int | None], list[datetime]] = defaultdict(list)
        for item in grouped_logs:
            if item.dst_ip:
                destination_counts[(item.dst_ip, item.dst_port)] += _effective_event_count(item)
                destination_event_counts[(item.dst_ip, item.dst_port)] += 1
                if item.dst_port is not None:
                    port_destinations[item.dst_port].add(item.dst_ip)
                item_time = _event_time(item)
                if item_time is not None:
                    destination_times[(item.dst_ip, item.dst_port)].append(item_time)
            if _is_deny_or_drop(item) and item.dst_port is not None:
                port_deny_drop_counts[item.dst_port] += _effective_event_count(item)
                if item.dst_port in AUTH_SERVICE_PORTS:
                    auth_target_deny_counts[(item.dst_ip or "", item.dst_port)] += _effective_event_count(item)
        for item in grouped_logs:
            destination_key = (item.dst_ip or "", item.dst_port)
            interval_count, interval_mean, jitter_ratio = _cadence_metrics(
                destination_times.get(destination_key, [])
            )
            event_correlations[_event_key(item)] = CorrelationSnapshot(
                source_count=source_count,
                deny_drop_count=deny_drop_count,
                distinct_ports=distinct_ports,
                auth_deny_count=auth_deny_count,
                auth_target_deny_count=auth_target_deny_counts.get(destination_key, 0),
                destination_repeat_count=destination_counts.get(destination_key, 0),
                destination_event_count=destination_event_counts.get(destination_key, 0),
                distinct_destinations_for_port=(
                    len(port_destinations.get(item.dst_port, set()))
                    if item.dst_port is not None
                    else 0
                ),
                deny_drop_count_for_port=(
                    port_deny_drop_counts.get(item.dst_port, 0)
                    if item.dst_port is not None
                    else 0
                ),
                cadence_interval_count=interval_count,
                cadence_mean_seconds=interval_mean,
                cadence_jitter_ratio=jitter_ratio,
                source_scope=scope,
                window_label=window_label,
            )

    return DetectionContext(
        source_counts=source_counts,
        source_deny_drop_counts=source_deny_drop_counts,
        source_distinct_ports=source_distinct_ports,
        source_auth_deny_counts=source_auth_deny_counts,
        source_destination_counts=source_destination_counts,
        source_auth_destination_counts=source_auth_destination_counts,
        byte_outlier_threshold=byte_threshold,
        packet_outlier_threshold=packet_threshold,
        event_correlations=event_correlations,
    )


def correlation_window_for_log(
    log: NormalizedLog,
    context: DetectionContext,
) -> str | None:
    snapshot = context.event_correlations.get(_event_key(log))
    return snapshot.window_label if snapshot is not None else None


def evaluate_rules(log: NormalizedLog, context: DetectionContext) -> list[RuleMatch]:
    matches: list[RuleMatch] = []
    src_ip = log.src_ip or "unknown source"
    correlation = context.event_correlations.get(_event_key(log))

    if _is_deny_or_drop(log):
        matches.append(
            RuleMatch(
                code="deny_drop_action",
                title="Deny or drop action",
                score=25,
                explanation=f"Firewall action or session end reason indicates deny/drop behavior for {src_ip}.",
            )
        )

    if str(log.log_type or "").upper() == "THREAT":
        threat_score, threat_severity = _threat_event_score(log)
        threat_name = _parsed_value(log, "parsed_threat_name") or "unavailable"
        matches.append(
            RuleMatch(
                code="paloalto_threat_log",
                title="Palo Alto threat event",
                score=threat_score,
                explanation=(
                    "The firewall classified this row as a THREAT event; "
                    f"vendor severity is {threat_severity} and threat name is {threat_name}."
                ),
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

    source_count = correlation.source_count if correlation else context.source_counts.get(src_ip, 0)
    if source_count >= REPEATED_SOURCE_THRESHOLD:
        matches.append(
            RuleMatch(
                code="repeated_source_ip",
                title="Repeated source activity",
                score=20,
                explanation=(
                    f"{src_ip} represents {source_count} session events in the source-scoped "
                    "five-minute correlation window."
                ),
            )
        )

    deny_drop_count = correlation.deny_drop_count if correlation else context.source_deny_drop_counts.get(src_ip, 0)
    if deny_drop_count >= DENY_BURST_THRESHOLD:
        matches.append(
            RuleMatch(
                code="multiple_denied_connections",
                title="Multiple denied or dropped connections",
                score=20,
                explanation=(
                    f"{src_ip} has {deny_drop_count} denied, dropped, or reset session events in the "
                    "source-scoped five-minute window."
                ),
            )
        )

    auth_deny_count = correlation.auth_deny_count if correlation else context.source_auth_deny_counts.get(src_ip, 0)
    auth_target_deny_count = (
        correlation.auth_target_deny_count
        if correlation
        else context.source_auth_destination_counts.get(
            (_source_scope(log), src_ip, log.dst_ip or "", log.dst_port),
            0,
        )
    )
    if auth_target_deny_count >= AUTH_TARGET_DENY_THRESHOLD:
        matches.append(
            RuleMatch(
                code="brute_force_like_attempts",
                title="Brute-force-like service attempts",
                score=30,
                explanation=(
                    f"{src_ip} has {auth_target_deny_count} denied or reset attempts against the same "
                    f"authentication/service target {log.dst_ip or 'unknown destination'}:"
                    f"{log.dst_port or 'unknown port'}; {auth_deny_count} authentication-port denies "
                    "were observed across the source-scoped five-minute window."
                ),
            )
        )

    distinct_ports = len(correlation.distinct_ports) if correlation else len(context.source_distinct_ports.get(src_ip, set()))
    scan_support: list[str] = []
    if deny_drop_count >= DENY_BURST_THRESHOLD:
        scan_support.append("repeated deny/drop evidence")
    if _is_outside_to_inside(log):
        scan_support.append("external-to-internal direction")
    if _lower(log.app) in {"unknown", "incomplete", "not-applicable", "unknown-tcp"}:
        scan_support.append("unresolved application identity")
    if str(log.log_type or "").upper() == "THREAT" and _lower(log.subtype) == "scan":
        scan_support.append("vendor scan subtype")
    if distinct_ports >= VERTICAL_SCAN_PORT_THRESHOLD and scan_support:
        matches.append(
            RuleMatch(
                code="possible_port_scan",
                title="Possible port scanning behavior",
                score=25,
                explanation=(
                    f"{src_ip} touched {distinct_ports} distinct destination ports in the "
                    "source-scoped five-minute window; supporting context: "
                    f"{', '.join(scan_support)}."
                ),
            )
        )

    distinct_destinations_for_port = (
        correlation.distinct_destinations_for_port if correlation else 0
    )
    deny_drop_count_for_port = correlation.deny_drop_count_for_port if correlation else 0
    horizontal_support: list[str] = []
    if deny_drop_count_for_port >= DENY_BURST_THRESHOLD:
        horizontal_support.append("repeated deny/drop evidence on the service")
    if _is_outside_to_inside(log):
        horizontal_support.append("external-to-internal direction")
    if _lower(log.app) in {"unknown", "incomplete", "not-applicable", "unknown-tcp"}:
        horizontal_support.append("unresolved application identity")
    if (
        log.dst_port is not None
        and distinct_destinations_for_port >= HORIZONTAL_SCAN_DESTINATION_THRESHOLD
        and horizontal_support
    ):
        matches.append(
            RuleMatch(
                code="possible_horizontal_scan",
                title="Possible horizontal service scanning behavior",
                score=25,
                explanation=(
                    f"{src_ip} reached {distinct_destinations_for_port} distinct destinations on port "
                    f"{log.dst_port} in the source-scoped five-minute window; supporting context: "
                    f"{', '.join(horizontal_support)}."
                ),
            )
        )

    destination_repeat_count = (
        correlation.destination_repeat_count
        if correlation
        else context.source_destination_counts.get((src_ip, log.dst_ip or "", log.dst_port), 0)
    )
    destination_event_count = correlation.destination_event_count if correlation else 0
    cadence_interval_count = correlation.cadence_interval_count if correlation else 0
    cadence_mean_seconds = correlation.cadence_mean_seconds if correlation else None
    cadence_jitter_ratio = correlation.cadence_jitter_ratio if correlation else None
    periodic_cadence = bool(
        destination_event_count >= BEACON_EVENT_THRESHOLD
        and cadence_interval_count >= BEACON_EVENT_THRESHOLD - 1
        and cadence_mean_seconds is not None
        and BEACON_MIN_INTERVAL_SECONDS <= cadence_mean_seconds <= BEACON_MAX_INTERVAL_SECONDS
        and cadence_jitter_ratio is not None
        and cadence_jitter_ratio <= BEACON_MAX_JITTER_RATIO
    )
    if (
        destination_repeat_count >= BEACON_EVENT_THRESHOLD
        and periodic_cadence
        and _is_internal_to_external(log)
    ):
        app_name = _lower(log.app)
        characteristics = _characteristic_set(log.app_characteristic)
        beacon_context = []
        if log.dst_port is not None and log.dst_port not in COMMON_PORTS:
            beacon_context.append("uncommon destination service")
        if app_name in {"unknown", "incomplete", "not-applicable", "unknown-tcp"}:
            beacon_context.append("unidentified application")
        if str(log.log_type or "").upper() == "THREAT":
            beacon_context.append("vendor THREAT event")
        if (
            log.app_risk is not None
            and log.app_risk >= 5
            and characteristics & BEACON_HIGH_SIGNAL_CHARACTERISTICS
        ):
            beacon_context.append("very-high-risk application evidence")
        if beacon_context:
            matches.append(
                RuleMatch(
                    code="beaconing_like_outbound",
                    title="Beaconing-like repeated outbound behavior",
                    score=30,
                    explanation=(
                        f"{src_ip} made {destination_repeat_count} repeated outbound connections to "
                        f"{log.dst_ip or 'unknown destination'}:{log.dst_port or 'unknown port'}; "
                        f"mean interval {cadence_mean_seconds:.1f}s with jitter ratio "
                        f"{cadence_jitter_ratio:.3f}; supporting context: {', '.join(beacon_context)}."
                    ),
                )
            )

    flood_context: list[str] = []
    if _is_deny_or_drop(log):
        flood_context.append("denied or reset traffic")
    vendor_flood_evidence = (
        str(log.log_type or "").upper() == "THREAT"
        and _lower(log.subtype) in {"flood", "packet"}
    )
    if vendor_flood_evidence:
        flood_context.append(f"vendor THREAT subtype {_lower(log.subtype)}")
    very_high_volume = destination_repeat_count >= HIGH_VOLUME_COMMON_SERVICE_THRESHOLD
    if very_high_volume:
        flood_context.append("very high repeated connection volume")
    corroborated_volume = (
        destination_repeat_count >= FLOOD_CORROBORATED_EVENT_THRESHOLD
        and (_is_deny_or_drop(log) or vendor_flood_evidence)
    )
    if very_high_volume or corroborated_volume:
        if _is_outside_to_inside(log):
            flood_context.append("external-to-internal direction")
        matches.append(
            RuleMatch(
                code="connection_flood_suspicion",
                title="Connection flood-like behavior",
                score=35,
                explanation=(
                    f"{src_ip} made {destination_repeat_count} repeated connections to "
                    f"{log.dst_ip or 'unknown destination'}:{log.dst_port or 'unknown port'} in the "
                    "source-scoped five-minute window; supporting context: "
                    f"{', '.join(flood_context)}."
                ),
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

    outbound_bytes, outbound_bytes_field = _outbound_byte_value(log)
    if (
        outbound_bytes is not None
        and outbound_bytes > context.byte_outlier_threshold
        and _is_internal_to_external(log)
    ):
        matches.append(
            RuleMatch(
                code="high_outbound_bytes",
                title="High outbound byte volume",
                score=35,
                explanation=(
                    f"Outbound {outbound_bytes_field} value {outbound_bytes} is above the "
                    f"batch outlier threshold {int(context.byte_outlier_threshold)}."
                ),
            )
        )

    app_name = _lower(log.app)
    app_category = _lower(log.app_category)
    if app_name in {"unknown", "incomplete", "not-applicable", "unknown-tcp"} or app_category == "unknown":
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
