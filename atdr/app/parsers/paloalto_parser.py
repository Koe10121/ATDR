import csv
import logging
import re
from dataclasses import dataclass
from datetime import datetime
from io import StringIO
from typing import Any

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


def _find_high_res_timestamp(fields: list[str]) -> str | None:
    for value in reversed(fields):
        if value and ISO_TIMESTAMP_RE.match(value.strip()):
            return value.strip()
    return None


def _tail_app_metadata(fields: list[str]) -> dict[str, Any]:
    """Palo Alto app metadata appears at the end for TRAFFIC and THREAT logs."""

    return {
        "high_res_timestamp": parse_datetime(_find_high_res_timestamp(fields)),
        "app_subcategory": _safe_get(fields, -10),
        "app_category": _safe_get(fields, -9),
        "app_technology": _safe_get(fields, -8),
        "app_risk": _to_int(_safe_get(fields, -7)),
        "app_characteristic": _safe_get(fields, -6),
    }


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


def parse_log_line(raw_line: str) -> ParsedPaloAltoLog:
    """Parse one syslog-wrapped Palo Alto CSV line without using unsafe comma splitting."""

    raw_line = raw_line.rstrip("\r\n")
    if not raw_line.strip():
        return ParsedPaloAltoLog(
            raw_line=raw_line,
            syslog_timestamp=None,
            device_hostname=None,
            normalized={},
            parsed_json={"parser_error": "blank line"},
            error="blank line",
        )

    syslog_text, hostname, payload = _split_syslog_line(raw_line)
    if payload is None:
        return ParsedPaloAltoLog(
            raw_line=raw_line,
            syslog_timestamp=parse_datetime(syslog_text),
            device_hostname=hostname,
            normalized={},
            parsed_json={"parser_error": "line did not contain syslog timestamp, hostname, and payload"},
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
            parsed_json={"parser_error": str(exc), "payload": payload},
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

    if log_type == "TRAFFIC":
        normalized.update(_traffic_specific(fields))
    elif log_type == "THREAT":
        normalized.update(_threat_specific(fields))
    else:
        normalized.update(
            {
                "category": _safe_get(fields, 37),
                "src_country": _safe_get(fields, 41),
                "dst_country": _safe_get(fields, 42),
                "device_name": _safe_get(fields, 52),
            }
        )

    normalized.update(_tail_app_metadata(fields))

    parser_warnings: list[str] = []
    if log_type == "TRAFFIC" and len(fields) < 47:
        parser_warnings.append(f"traffic log has fewer fields than expected: {len(fields)}")
    elif log_type == "THREAT" and len(fields) < 40:
        parser_warnings.append(f"threat log has fewer fields than expected: {len(fields)}")
    elif not log_type:
        parser_warnings.append("missing Palo Alto log type")
    if parsed_syslog_timestamp := parse_datetime(syslog_text):
        syslog_timestamp = parsed_syslog_timestamp
    else:
        syslog_timestamp = None
        parser_warnings.append("missing or unparsable syslog timestamp")
    if normalized.get("generated_time") is None and normalized.get("receive_time") is None:
        parser_warnings.append("missing generated and receive timestamps")
    if not normalized.get("src_ip"):
        parser_warnings.append("missing source IP")
    if not normalized.get("dst_ip"):
        parser_warnings.append("missing destination IP")
    if not normalized.get("action"):
        parser_warnings.append("missing action")
    if (normalized.get("app") or "").strip().lower() in {"", "unknown", "incomplete", "not-applicable"}:
        parser_warnings.append("unknown or incomplete application")

    parsed_json = {
        "field_count": len(fields),
        "payload_fields": fields,
        "log_type": log_type,
        "unknown_extra_fields": fields[115:] if log_type == "TRAFFIC" and len(fields) > 115 else [],
        "parser_warnings": parser_warnings,
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
