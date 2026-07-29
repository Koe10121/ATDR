import csv
import logging
import re
from dataclasses import dataclass
from datetime import datetime
from io import StringIO
from typing import Any

from atdr.app.parsers.paloalto_contract import (
    PARSER_CONTRACT_VERSION,
    application_resolution,
    compatibility_diagnostics,
)

logger = logging.getLogger(__name__)

ISO_TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T")


@dataclass(slots=True)
class ParsedPaloAltoLog:
    raw_line: str
    syslog_timestamp: datetime | None
    device_hostname: str | None
    normalized: dict[str, Any]
    parsed_json: dict[str, Any]
    error: str | None = None


def parse_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    text = value.strip()
    if not text:
        return None
    formats = ("%Y/%m/%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z")
    for fmt in formats:
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        logger.debug("Could not parse datetime value %r", value)
        return None


def _clean(value: str | None) -> str | None:
    if value is None:
        return None
    text = value.strip()
    return text if text else None


def _safe_get(fields: list[str], index: int) -> str | None:
    try:
        return _clean(fields[index])
    except IndexError:
        return None


def _to_int(value: str | None) -> int | None:
    text = _clean(value)
    if text is None:
        return None
    try:
        return int(text)
    except ValueError:
        return None


def _parse_payload(payload: str) -> list[str]:
    reader = csv.reader(StringIO(payload))
    return next(reader)


def _split_syslog_line(raw_line: str) -> tuple[str | None, str | None, str | None]:
    parts = raw_line.rstrip("\r\n").split(maxsplit=2)
    if len(parts) < 3:
        return None, None, None
    return parts[0], parts[1], parts[2]


def _find_high_res_timestamp_index(fields: list[str]) -> int | None:
    for index in range(len(fields) - 1, -1, -1):
        value = fields[index]
        if value and ISO_TIMESTAMP_RE.match(value.strip()):
            return index
    return None


def _find_high_res_timestamp(fields: list[str]) -> str | None:
    index = _find_high_res_timestamp_index(fields)
    if index is not None:
        return fields[index].strip()
    return None


def _app_metadata(fields: list[str], log_type: str | None) -> tuple[dict[str, Any], str]:
    """Read app metadata from the documented high-resolution timestamp anchor.

    PAN-OS adds fields after application metadata over time, so indexing from
    the tail silently shifts on newer releases. Current TRAFFIC and THREAT
    formats both retain a high-resolution timestamp immediately before a small,
    documented group of fields. Legacy tail positions remain a fail-safe for
    historical lab fixtures.
    """

    if log_type not in {"TRAFFIC", "THREAT"}:
        return (
            {
                "high_res_timestamp": parse_datetime(
                    _find_high_res_timestamp(fields)
                ),
                "app_subcategory": None,
                "app_category": None,
                "app_technology": None,
                "app_risk": None,
                "app_characteristic": None,
            },
            "not_applicable",
        )

    high_res_index = _find_high_res_timestamp_index(fields)
    candidates: list[tuple[str, int]] = []
    if high_res_index is not None:
        if log_type == "TRAFFIC":
            candidates.append(("pan_high_res_anchor_traffic", high_res_index + 3))
        elif log_type == "THREAT":
            candidates.append(("pan_high_res_anchor_threat", high_res_index + 4))
        candidates.append(("pan_high_res_anchor_legacy", high_res_index + 1))

    for mapping_name, start in candidates:
        risk = _to_int(_safe_get(fields, start + 3))
        if risk is not None and 1 <= risk <= 5:
            return (
                {
                    "high_res_timestamp": parse_datetime(_safe_get(fields, high_res_index or 0)),
                    "app_subcategory": _safe_get(fields, start),
                    "app_category": _safe_get(fields, start + 1),
                    "app_technology": _safe_get(fields, start + 2),
                    "app_risk": risk,
                    "app_characteristic": _safe_get(fields, start + 4),
                },
                mapping_name,
            )

    tail_risk = _to_int(_safe_get(fields, -7))
    if tail_risk is not None and not 1 <= tail_risk <= 5:
        tail_risk = None
    return (
        {
            "high_res_timestamp": parse_datetime(_find_high_res_timestamp(fields)),
            "app_subcategory": _safe_get(fields, -10),
            "app_category": _safe_get(fields, -9),
            "app_technology": _safe_get(fields, -8),
            "app_risk": tail_risk,
            "app_characteristic": _safe_get(fields, -6),
        },
        "legacy_tail_fallback",
    )


def _traffic_specific(fields: list[str]) -> dict[str, Any]:
    return {
        "bytes": _to_int(_safe_get(fields, 31)),
        "bytes_sent": _to_int(_safe_get(fields, 32)),
        "bytes_received": _to_int(_safe_get(fields, 33)),
        "packets": _to_int(_safe_get(fields, 34)),
        "start_time": parse_datetime(_safe_get(fields, 35)),
        "elapsed_time": _to_int(_safe_get(fields, 36)),
        "category": _safe_get(fields, 37),
        "src_country": _safe_get(fields, 41),
        "dst_country": _safe_get(fields, 42),
        "packets_sent": _to_int(_safe_get(fields, 44)),
        "packets_received": _to_int(_safe_get(fields, 45)),
        "session_end_reason": _safe_get(fields, 46),
        "device_name": _safe_get(fields, 52),
        "action_source": _safe_get(fields, 53),
        "rule_uuid": _safe_get(fields, 65),
    }


def _threat_specific(fields: list[str]) -> dict[str, Any]:
    return {
        "category": _safe_get(fields, 33),
        "src_country": _safe_get(fields, 38),
        "dst_country": _safe_get(fields, 39),
        "device_name": _safe_get(fields, 59),
        "rule_uuid": _safe_get(fields, 76),
        "session_end_reason": _safe_get(fields, 69),
        "parsed_threat_name": _safe_get(fields, 32),
        "parsed_threat_severity": _safe_get(fields, 34),
        "parsed_threat_direction": _safe_get(fields, 35),
    }


def _system_specific(fields: list[str]) -> tuple[dict[str, Any], dict[str, Any]]:
    normalized = {
        "src_ip": None,
        "dst_ip": None,
        "nat_src_ip": None,
        "nat_dst_ip": None,
        "rule_name": None,
        "src_user": None,
        "dst_user": None,
        "app": None,
        "vsys": _safe_get(fields, 7),
        "src_zone": None,
        "dst_zone": None,
        "inbound_interface": None,
        "outbound_interface": None,
        "log_action": None,
        "session_id": None,
        "repeat_count": None,
        "src_port": None,
        "dst_port": None,
        "protocol": None,
        "action": None,
        "device_name": _safe_get(fields, 22),
        "high_res_timestamp": parse_datetime(_safe_get(fields, 25)),
    }
    details = {
        "system_event_id": _safe_get(fields, 8),
        "system_object_present": bool(_safe_get(fields, 9)),
        "system_module": _safe_get(fields, 12),
        "system_severity": _safe_get(fields, 13),
        "system_description_present": bool(_safe_get(fields, 14)),
    }
    return normalized, details


def _error_json(message: str) -> dict[str, Any]:
    return {
        "parser_error": message,
        "parse_status": "error",
        "parser_contract_version": PARSER_CONTRACT_VERSION,
        "parser_profile": "palo_alto",
    }


def parse_log_line(raw_line: str) -> ParsedPaloAltoLog:
    """Parse one syslog-wrapped Palo Alto CSV line without using unsafe comma splitting."""

    raw_line = raw_line.rstrip("\r\n")
    if not raw_line.strip():
        return ParsedPaloAltoLog(
            raw_line=raw_line,
            syslog_timestamp=None,
            device_hostname=None,
            normalized={},
            parsed_json=_error_json("blank line"),
            error="blank line",
        )

    syslog_text, hostname, payload = _split_syslog_line(raw_line)
    if payload is None:
        return ParsedPaloAltoLog(
            raw_line=raw_line,
            syslog_timestamp=parse_datetime(syslog_text),
            device_hostname=hostname,
            normalized={},
            parsed_json=_error_json(
                "line did not contain syslog timestamp, hostname, and payload"
            ),
            error="malformed syslog wrapper",
        )

    try:
        fields = _parse_payload(payload)
    except csv.Error as exc:
        return ParsedPaloAltoLog(
            raw_line=raw_line,
            syslog_timestamp=parse_datetime(syslog_text),
            device_hostname=hostname,
            normalized={},
            parsed_json=_error_json(str(exc)),
            error=str(exc),
        )

    log_type = _safe_get(fields, 3)
    normalized: dict[str, Any] = {
        "receive_time": parse_datetime(_safe_get(fields, 1)),
        "serial": _safe_get(fields, 2),
        "log_type": log_type,
        "subtype": _safe_get(fields, 4),
        "generated_time": parse_datetime(_safe_get(fields, 6)),
        "src_ip": _safe_get(fields, 7),
        "dst_ip": _safe_get(fields, 8),
        "nat_src_ip": _safe_get(fields, 9),
        "nat_dst_ip": _safe_get(fields, 10),
        "rule_name": _safe_get(fields, 11),
        "src_user": _safe_get(fields, 12),
        "dst_user": _safe_get(fields, 13),
        "app": _safe_get(fields, 14),
        "vsys": _safe_get(fields, 15),
        "src_zone": _safe_get(fields, 16),
        "dst_zone": _safe_get(fields, 17),
        "inbound_interface": _safe_get(fields, 18),
        "outbound_interface": _safe_get(fields, 19),
        "log_action": _safe_get(fields, 20),
        "session_id": _safe_get(fields, 22),
        "repeat_count": _to_int(_safe_get(fields, 23)),
        "src_port": _to_int(_safe_get(fields, 24)),
        "dst_port": _to_int(_safe_get(fields, 25)),
        "protocol": _safe_get(fields, 29),
        "action": _safe_get(fields, 30),
    }

    type_details: dict[str, Any] = {}
    if log_type == "TRAFFIC":
        normalized.update(_traffic_specific(fields))
    elif log_type == "THREAT":
        normalized.update(_threat_specific(fields))
    elif log_type == "SYSTEM":
        system_normalized, type_details = _system_specific(fields)
        normalized.update(system_normalized)
    else:
        normalized.update(
            {
                "category": _safe_get(fields, 37),
                "src_country": _safe_get(fields, 41),
                "dst_country": _safe_get(fields, 42),
                "device_name": _safe_get(fields, 52),
            }
        )

    app_metadata, app_metadata_mapping = _app_metadata(fields, log_type)
    normalized.update(app_metadata)

    compatibility = compatibility_diagnostics(
        log_type=log_type,
        field_count=len(fields),
        high_res_timestamp_index=_find_high_res_timestamp_index(fields),
        app_metadata_mapping=app_metadata_mapping,
    )
    parser_warnings: list[str] = []
    if compatibility["status"] == "partial_layout":
        parser_warnings.append(
            f"{str(log_type or 'unknown').lower()} log has fewer fields than "
            f"the contract minimum: {len(fields)}"
        )
    elif compatibility["status"] == "missing_log_type":
        parser_warnings.append("missing Palo Alto log type")
    elif compatibility["status"] == "unsupported_log_type":
        parser_warnings.append(
            "unsupported Palo Alto log type preserved with common fields only"
        )
    if parsed_syslog_timestamp := parse_datetime(syslog_text):
        syslog_timestamp = parsed_syslog_timestamp
    else:
        syslog_timestamp = None
        parser_warnings.append("missing or unparsable syslog timestamp")
    if (
        normalized.get("generated_time") is None
        and normalized.get("receive_time") is None
    ):
        parser_warnings.append("missing generated and receive timestamps")
    if log_type in {"TRAFFIC", "THREAT"} or not log_type:
        if not normalized.get("src_ip"):
            parser_warnings.append("missing source IP")
        if not normalized.get("dst_ip"):
            parser_warnings.append("missing destination IP")
        if not normalized.get("action"):
            parser_warnings.append("missing action")
        if not normalized.get("app"):
            parser_warnings.append("missing application field")

    app_resolution = application_resolution(log_type, normalized.get("app"))
    parser_notices: list[str] = []
    if app_resolution["status"] == "unresolved":
        parser_notices.append(
            "application value is unresolved session evidence, not a parser failure"
        )

    parsed_json = {
        "field_count": len(fields),
        "payload_fields": fields,
        "log_type": log_type,
        "unknown_extra_fields": fields[115:] if log_type == "TRAFFIC" and len(fields) > 115 else [],
        "parser_warnings": parser_warnings,
        "parser_notices": parser_notices,
        "parse_status": (
            "partial"
            if compatibility["confidence"] in {"partial", "unsupported"}
            else "parsed"
        ),
        "parser_contract_version": PARSER_CONTRACT_VERSION,
        "parser_compatibility": compatibility,
        "application_resolution": app_resolution,
        "app_metadata_mapping": app_metadata_mapping,
        **type_details,
    }
    for key in ("parsed_threat_name", "parsed_threat_severity", "parsed_threat_direction"):
        if key in normalized:
            parsed_json[key] = normalized.pop(key)

    return ParsedPaloAltoLog(
        raw_line=raw_line,
        syslog_timestamp=syslog_timestamp,
        device_hostname=hostname,
        normalized=normalized,
        parsed_json=parsed_json,
    )


def parse_log_line_for_profile(raw_line: str, parser_profile: str | None = None) -> ParsedPaloAltoLog:
    """Parse a log line using the configured source parser profile.

    Palo Alto remains the default production parser. The generic and raw
    fallback profiles intentionally preserve evidence with minimal structured
    assumptions so lab source tests never lose raw lines or crash on unknown
    device formats.
    """

    profile = (parser_profile or "palo_alto").strip().lower()
    if profile == "palo_alto":
        parsed = parse_log_line(raw_line)
        parsed.parsed_json["parser_profile"] = "palo_alto"
        return parsed

    raw_line = raw_line.rstrip("\r\n")
    syslog_text, hostname, payload = _split_syslog_line(raw_line)
    syslog_timestamp = parse_datetime(syslog_text)

    if profile == "generic_syslog":
        if payload is None:
            return ParsedPaloAltoLog(
                raw_line=raw_line,
                syslog_timestamp=syslog_timestamp,
                device_hostname=hostname,
                normalized={},
                parsed_json={
                    "parser_profile": "generic_syslog",
                    "parser_error": "generic syslog line did not contain timestamp, hostname, and message",
                    "parse_status": "error",
                    "parser_contract_version": "generic_syslog_v1",
                    "parser_compatibility": {
                        "status": "malformed_generic_syslog",
                        "confidence": "unsupported",
                    },
                },
                error="malformed generic syslog wrapper",
            )
        return ParsedPaloAltoLog(
            raw_line=raw_line,
            syslog_timestamp=syslog_timestamp,
            device_hostname=hostname,
            normalized={},
            parsed_json={
                "parser_profile": "generic_syslog",
                "message": payload,
                "parse_status": "preserved_unstructured",
                "parser_contract_version": "generic_syslog_v1",
                "parser_compatibility": {
                    "status": "generic_syslog_limited",
                    "confidence": "limited",
                },
                "parser_warnings": [
                    "generic syslog profile preserved raw message with limited normalized fields",
                ],
            },
        )

    return ParsedPaloAltoLog(
        raw_line=raw_line,
        syslog_timestamp=syslog_timestamp,
        device_hostname=hostname,
        normalized={},
        parsed_json={
            "parser_profile": "raw_fallback",
            "parser_error": "raw fallback parser profile stored raw evidence without structured parsing",
            "parse_status": "fallback",
            "parser_contract_version": "raw_fallback_v1",
            "parser_compatibility": {
                "status": "raw_fallback",
                "confidence": "unstructured",
            },
            "raw_fallback": True,
        },
        error="raw fallback parser profile",
    )
