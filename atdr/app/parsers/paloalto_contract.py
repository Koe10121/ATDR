from __future__ import annotations

from typing import Any


PARSER_CONTRACT_VERSION = "palo_alto_syslog_v5.12"
PARSER_CONTRACT_FAMILY = "palo_alto_syslog_csv"
OFFICIAL_FIELD_REFERENCE = (
    "https://docs.paloaltonetworks.com/ngfw/administration/monitoring/"
    "use-syslog-for-monitoring/syslog-field-descriptions"
)

LOG_TYPE_CONTRACTS: dict[str, dict[str, Any]] = {
    "TRAFFIC": {
        "minimum_fields": 47,
        "known_field_counts": (115,),
        "required_fields": (
            "generated_time",
            "src_ip",
            "dst_ip",
            "src_port",
            "dst_port",
            "protocol",
            "action",
            "app",
            "src_zone",
            "dst_zone",
        ),
        "high_resolution_timestamp_expected": True,
    },
    "THREAT": {
        "minimum_fields": 40,
        "known_field_counts": (121,),
        "required_fields": (
            "generated_time",
            "src_ip",
            "dst_ip",
            "src_port",
            "dst_port",
            "protocol",
            "action",
            "app",
            "src_zone",
            "dst_zone",
        ),
        "high_resolution_timestamp_expected": True,
    },
    "SYSTEM": {
        "minimum_fields": 15,
        "known_field_counts": (26,),
        "required_fields": (
            "generated_time",
            "log_type",
            "subtype",
            "vsys",
        ),
        "high_resolution_timestamp_expected": False,
    },
}

UNIDENTIFIED_APPLICATION_VALUES = frozenset(
    {
        "unknown",
        "unknown-tcp",
        "unknown-udp",
        "unknown-p2p",
    }
)


def application_resolution(log_type: str | None, app: str | None) -> dict[str, str]:
    normalized_type = str(log_type or "").strip().upper()
    value = str(app or "").strip().lower()
    if normalized_type not in {"TRAFFIC", "THREAT"}:
        return {
            "status": "not_applicable",
            "reason": "log_type_has_no_application_field",
        }
    if value == "incomplete":
        return {
            "status": "unresolved",
            "reason": "session_application_identification_incomplete",
        }
    if value == "insufficient-data":
        return {
            "status": "unresolved",
            "reason": "insufficient_session_data",
        }
    if value in UNIDENTIFIED_APPLICATION_VALUES:
        return {
            "status": "unresolved",
            "reason": "application_not_identified",
        }
    if value in {"", "not-applicable"}:
        return {
            "status": "absent",
            "reason": "application_field_absent_or_not_applicable",
        }
    return {
        "status": "identified",
        "reason": "application_identified",
    }


def compatibility_diagnostics(
    *,
    log_type: str | None,
    field_count: int,
    high_res_timestamp_index: int | None,
    app_metadata_mapping: str,
) -> dict[str, Any]:
    normalized_type = str(log_type or "").strip().upper()
    contract = LOG_TYPE_CONTRACTS.get(normalized_type)
    if contract is None:
        return {
            "status": (
                "missing_log_type"
                if not normalized_type
                else "unsupported_log_type"
            ),
            "confidence": "unsupported",
            "log_type_supported": False,
            "field_count": max(0, int(field_count)),
            "minimum_fields": None,
            "known_layout": False,
            "extended_layout": False,
            "high_resolution_timestamp_present": (
                high_res_timestamp_index is not None
            ),
            "app_metadata_mapping": app_metadata_mapping,
        }

    minimum_fields = int(contract["minimum_fields"])
    known_counts = tuple(int(value) for value in contract["known_field_counts"])
    known_layout = int(field_count) in known_counts
    partial = int(field_count) < minimum_fields
    extended = int(field_count) > max(known_counts, default=minimum_fields)
    if partial:
        status = "partial_layout"
        confidence = "partial"
    elif known_layout:
        status = "supported_known_layout"
        confidence = "full"
    elif extended:
        status = "supported_extended_layout"
        confidence = "compatible"
    else:
        status = "supported_compatible_layout"
        confidence = "compatible"
    return {
        "status": status,
        "confidence": confidence,
        "log_type_supported": True,
        "field_count": max(0, int(field_count)),
        "minimum_fields": minimum_fields,
        "known_layout": known_layout,
        "extended_layout": extended,
        "high_resolution_timestamp_present": (
            high_res_timestamp_index is not None
        ),
        "app_metadata_mapping": app_metadata_mapping,
    }


def required_field_names(log_type: str | None) -> tuple[str, ...]:
    contract = LOG_TYPE_CONTRACTS.get(str(log_type or "").strip().upper())
    if contract is None:
        return ()
    return tuple(str(value) for value in contract["required_fields"])
