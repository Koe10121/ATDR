from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any, Mapping


SCHEMA_CONTRACT_VERSION = "atdr_schema_contracts_v1"

NETWORK_FIELDS = (
    "timestamp",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
    "action",
    "app",
    "bytes_sent",
    "bytes_received",
    "packets",
    "duration_seconds",
    "src_zone",
    "dst_zone",
    "app_risk",
    "behavior_windows",
    "raw_evidence",
)

RULE_FAMILIES = (
    "byte_volume_outlier",
    "packet_volume_outlier",
    "deny_drop_action",
    "palo_alto_threat_log",
    "application_risk",
    "zone_direction",
    "repeated_source_behavior",
    "port_scan_behavior",
    "brute_force_behavior",
    "beaconing_behavior",
    "unknown_application",
    "parse_quality",
)

COMMON_NUMERIC_FEATURES = (
    "dst_port",
    "protocol_number",
    "bytes_sent",
    "bytes_received",
    "total_bytes",
    "packets",
    "duration_seconds",
    "bytes_per_second",
    "packets_per_second",
    "hour_of_day",
    "has_timestamp",
    "has_src_ip",
    "has_dst_ip",
    "has_src_port",
    "has_dst_port",
    "has_protocol",
    "has_action",
    "has_app",
    "has_bytes_sent",
    "has_bytes_received",
    "has_packets",
    "has_duration",
    "has_zones",
    "has_app_risk",
    "has_behavior_windows",
    "schema_is_palo_alto",
    "schema_is_generic_syslog",
    "schema_is_provider_flow",
    "schema_is_raw_fallback",
)

COMMON_CATEGORICAL_FEATURES = (
    "schema_id",
    "protocol_family",
)


@dataclass(frozen=True)
class SchemaContract:
    schema_id: str
    title: str
    evidence_kind: str
    required_fields: tuple[str, ...]
    optional_fields: tuple[str, ...]
    unavailable_fields: tuple[str, ...]
    rule_applicability: Mapping[str, str]
    source_identity_policy: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_id": self.schema_id,
            "title": self.title,
            "evidence_kind": self.evidence_kind,
            "required_fields": list(self.required_fields),
            "optional_fields": list(self.optional_fields),
            "unavailable_fields": list(self.unavailable_fields),
            "rule_applicability": dict(self.rule_applicability),
            "source_identity_policy": self.source_identity_policy,
            "contract_version": SCHEMA_CONTRACT_VERSION,
        }


def _rule_matrix(**overrides: str) -> dict[str, str]:
    values = {name: "unavailable_for_schema" for name in RULE_FAMILIES}
    values.update(overrides)
    return values


SCHEMA_CONTRACTS: dict[str, SchemaContract] = {
    "palo_alto": SchemaContract(
        schema_id="palo_alto",
        title="Palo Alto firewall traffic/threat log",
        evidence_kind="structured_firewall_log",
        required_fields=("timestamp", "src_ip", "dst_ip", "dst_port", "protocol", "action", "app"),
        optional_fields=(
            "src_port",
            "bytes_sent",
            "bytes_received",
            "packets",
            "duration_seconds",
            "src_zone",
            "dst_zone",
            "app_risk",
            "behavior_windows",
            "raw_evidence",
        ),
        unavailable_fields=(),
        rule_applicability=_rule_matrix(
            byte_volume_outlier="applicable_when_bytes_present",
            packet_volume_outlier="applicable_when_packets_present",
            deny_drop_action="applicable",
            palo_alto_threat_log="applicable",
            application_risk="applicable_when_app_risk_present",
            zone_direction="applicable_when_zones_present",
            repeated_source_behavior="applicable_when_source_identity_present",
            port_scan_behavior="applicable_when_source_window_present",
            brute_force_behavior="applicable_when_source_window_present",
            beaconing_behavior="applicable_when_source_and_destination_windows_present",
            unknown_application="applicable",
            parse_quality="applicable",
        ),
        source_identity_policy="firewall_source_id_and_network_identity",
    ),
    "generic_syslog": SchemaContract(
        schema_id="generic_syslog",
        title="Generic structured syslog",
        evidence_kind="partially_structured_syslog",
        required_fields=("timestamp", "raw_evidence"),
        optional_fields=(
            "src_ip",
            "dst_ip",
            "src_port",
            "dst_port",
            "protocol",
            "action",
            "app",
            "bytes_sent",
            "bytes_received",
            "packets",
            "duration_seconds",
            "behavior_windows",
        ),
        unavailable_fields=("src_zone", "dst_zone", "app_risk"),
        rule_applicability=_rule_matrix(
            byte_volume_outlier="conditional_on_parsed_bytes",
            packet_volume_outlier="conditional_on_parsed_packets",
            deny_drop_action="conditional_on_parsed_action",
            repeated_source_behavior="conditional_on_parsed_source_identity",
            port_scan_behavior="conditional_on_parsed_source_and_destination_fields",
            brute_force_behavior="conditional_on_parsed_source_and_action_fields",
            unknown_application="conditional_on_explicit_parsed_application",
            parse_quality="applicable",
        ),
        source_identity_policy="registered_syslog_source_plus_parsed_identity_when_available",
    ),
    "provider_flow": SchemaContract(
        schema_id="provider_flow",
        title="CICFlowMeter provider flow",
        evidence_kind="aggregated_network_flow",
        required_fields=(
            "timestamp",
            "dst_port",
            "protocol",
            "bytes_sent",
            "bytes_received",
            "packets",
            "duration_seconds",
        ),
        optional_fields=(),
        unavailable_fields=(
            "src_ip",
            "dst_ip",
            "src_port",
            "action",
            "app",
            "src_zone",
            "dst_zone",
            "app_risk",
            "behavior_windows",
            "raw_evidence",
        ),
        rule_applicability=_rule_matrix(
            byte_volume_outlier="applicable",
            packet_volume_outlier="applicable",
            parse_quality="applicable_to_feature_validity_only",
        ),
        source_identity_policy="provider_file_and_collection_day_not_network_source_ip",
    ),
    "raw_fallback": SchemaContract(
        schema_id="raw_fallback",
        title="Unmatched raw evidence fallback",
        evidence_kind="raw_evidence_only",
        required_fields=("timestamp", "raw_evidence"),
        optional_fields=(),
        unavailable_fields=tuple(field for field in NETWORK_FIELDS if field not in {"timestamp", "raw_evidence"}),
        rule_applicability=_rule_matrix(parse_quality="applicable"),
        source_identity_policy="registered_source_only_no_inferred_network_identity",
    ),
}


def get_schema_contract(schema_id: str) -> SchemaContract:
    try:
        return SCHEMA_CONTRACTS[schema_id]
    except KeyError as exc:
        raise ValueError(f"Unknown ATDR evidence schema: {schema_id}") from exc


def _present(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, float) and math.isnan(value):
        return False
    return str(value).strip() != ""


def _number(value: Any) -> float:
    if not _present(value):
        return math.nan
    try:
        numeric = float(value)
    except (TypeError, ValueError):
        return math.nan
    return numeric if math.isfinite(numeric) else math.nan


def _protocol_number(value: Any) -> float:
    if not _present(value):
        return math.nan
    text = str(value).strip().lower()
    aliases = {"tcp": 6.0, "udp": 17.0, "icmp": 1.0, "icmpv6": 58.0}
    if text in aliases:
        return aliases[text]
    if text.startswith("ip_protocol_"):
        text = text.removeprefix("ip_protocol_")
    return _number(text)


def validate_schema_row(schema_id: str, values: Mapping[str, Any]) -> dict[str, Any]:
    contract = get_schema_contract(schema_id)
    invented = sorted(field for field in contract.unavailable_fields if _present(values.get(field)))
    missing = sorted(field for field in contract.required_fields if not _present(values.get(field)))
    return {
        "valid": not invented and not missing,
        "schema_id": schema_id,
        "missing_required_fields": missing,
        "invented_unavailable_fields": invented,
    }


def normalize_common_features(schema_id: str, values: Mapping[str, Any]) -> dict[str, Any]:
    validation = validate_schema_row(schema_id, values)
    if validation["invented_unavailable_fields"]:
        joined = ", ".join(validation["invented_unavailable_fields"])
        raise ValueError(f"Schema {schema_id} cannot supply unavailable field(s): {joined}")

    bytes_sent = _number(values.get("bytes_sent"))
    bytes_received = _number(values.get("bytes_received"))
    packets = _number(values.get("packets"))
    duration = _number(values.get("duration_seconds"))
    total_bytes = (
        bytes_sent + bytes_received
        if math.isfinite(bytes_sent) and math.isfinite(bytes_received)
        else math.nan
    )
    bytes_per_second = (
        total_bytes / duration
        if math.isfinite(total_bytes) and math.isfinite(duration) and duration > 0
        else math.nan
    )
    packets_per_second = (
        packets / duration
        if math.isfinite(packets) and math.isfinite(duration) and duration > 0
        else math.nan
    )
    timestamp = values.get("timestamp")
    hour = float(timestamp.hour) if hasattr(timestamp, "hour") else math.nan
    protocol = str(values.get("protocol") or "unavailable").strip().lower()
    has_zones = _present(values.get("src_zone")) and _present(values.get("dst_zone"))

    result: dict[str, Any] = {
        "dst_port": _number(values.get("dst_port")),
        "protocol_number": _protocol_number(values.get("protocol")),
        "bytes_sent": bytes_sent,
        "bytes_received": bytes_received,
        "total_bytes": total_bytes,
        "packets": packets,
        "duration_seconds": duration,
        "bytes_per_second": bytes_per_second,
        "packets_per_second": packets_per_second,
        "hour_of_day": hour,
        "has_timestamp": int(_present(timestamp)),
        "has_src_ip": int(_present(values.get("src_ip"))),
        "has_dst_ip": int(_present(values.get("dst_ip"))),
        "has_src_port": int(_present(values.get("src_port"))),
        "has_dst_port": int(_present(values.get("dst_port"))),
        "has_protocol": int(_present(values.get("protocol"))),
        "has_action": int(_present(values.get("action"))),
        "has_app": int(_present(values.get("app"))),
        "has_bytes_sent": int(_present(values.get("bytes_sent"))),
        "has_bytes_received": int(_present(values.get("bytes_received"))),
        "has_packets": int(_present(values.get("packets"))),
        "has_duration": int(_present(values.get("duration_seconds"))),
        "has_zones": int(has_zones),
        "has_app_risk": int(_present(values.get("app_risk"))),
        "has_behavior_windows": int(_present(values.get("behavior_windows"))),
        "schema_is_palo_alto": int(schema_id == "palo_alto"),
        "schema_is_generic_syslog": int(schema_id == "generic_syslog"),
        "schema_is_provider_flow": int(schema_id == "provider_flow"),
        "schema_is_raw_fallback": int(schema_id == "raw_fallback"),
        "schema_id": schema_id,
        "protocol_family": protocol,
    }
    return result


def public_schema_contracts() -> dict[str, Any]:
    return {
        "contract_version": SCHEMA_CONTRACT_VERSION,
        "common_numeric_features": list(COMMON_NUMERIC_FEATURES),
        "common_categorical_features": list(COMMON_CATEGORICAL_FEATURES),
        "contracts": {name: contract.as_dict() for name, contract in SCHEMA_CONTRACTS.items()},
    }
