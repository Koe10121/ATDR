from __future__ import annotations

from collections import Counter
from typing import Any, Iterable, Mapping

from atdr.app.db.models import NormalizedLog
from atdr.app.detection.schema_contracts import get_schema_contract


V520_VERSION = "v5.20-schema-aware-abstention-v1"
GOVERNED_MODEL_SCHEMA_ID = "palo_alto"
COMPATIBLE_STATUS = "compatible"

_PROFILE_ALIASES = {
    "paloalto": "palo_alto",
    "palo-alto": "palo_alto",
    "pan_os": "palo_alto",
    "pan-os": "palo_alto",
}
_FAILED_PARSE_STATUSES = {"error", "failed", "failure", "fallback", "preserved_unstructured"}


def _present(value: Any) -> bool:
    return value is not None and str(value).strip() != ""


def _normalized_profile(value: Any) -> str:
    profile = str(value or "unknown").strip().lower()
    return _PROFILE_ALIASES.get(profile, profile)


def _log_values(log: NormalizedLog) -> dict[str, Any]:
    return {
        "timestamp": log.generated_time or log.receive_time or log.start_time,
        "src_ip": log.src_ip,
        "dst_ip": log.dst_ip,
        "src_port": log.src_port,
        "dst_port": log.dst_port,
        "protocol": log.protocol,
        "action": log.action,
        "app": log.app,
        "bytes_sent": log.bytes_sent,
        "bytes_received": log.bytes_received,
        "packets": log.packets,
        "duration_seconds": log.elapsed_time,
        "src_zone": log.src_zone,
        "dst_zone": log.dst_zone,
        "app_risk": log.app_risk,
    }


def assess_log_schema_compatibility(
    log: NormalizedLog,
    *,
    expected_schema_id: str = GOVERNED_MODEL_SCHEMA_ID,
) -> dict[str, Any]:
    """Return a privacy-safe, fail-closed inference compatibility decision."""

    parsed = log.parsed_json if isinstance(log.parsed_json, dict) else {}
    profile_inferred = not _present(parsed.get("parser_profile"))
    # Historical normalized rows predate explicit parser_profile metadata; ATDR's
    # parser default for those rows is Palo Alto and the structured fields remain
    # subject to the same required-field gate below.
    observed_schema_id = _normalized_profile(
        parsed.get("parser_profile") or GOVERNED_MODEL_SCHEMA_ID
    )
    parse_status = str(parsed.get("parse_status") or "unknown").strip().lower()
    expected = get_schema_contract(expected_schema_id)
    values = _log_values(log)
    missing = sorted(field for field in expected.required_fields if not _present(values.get(field)))
    present_count = len(expected.required_fields) - len(missing)
    completeness = present_count / max(1, len(expected.required_fields))
    profile_match = observed_schema_id == expected_schema_id
    compatibility_score = round((0.35 if profile_match else 0.0) + (0.65 * completeness), 4)

    reasons: list[str] = []
    status = COMPATIBLE_STATUS
    if observed_schema_id not in {"palo_alto", "generic_syslog", "provider_flow", "raw_fallback"}:
        status = "unknown_schema"
        reasons.append("unknown_schema_profile")
    elif not profile_match:
        status = "incompatible_schema"
        reasons.append("schema_profile_mismatch")
    elif parse_status in _FAILED_PARSE_STATUSES:
        status = "parser_error"
        reasons.append("parser_status_not_scoring_eligible")
    elif missing:
        status = "insufficient_evidence"
        reasons.append("missing_required_fields")

    scoring_allowed = status == COMPATIBLE_STATUS
    if scoring_allowed:
        message = "Evidence matches the governed native PAN-OS scoring contract."
    elif status == "incompatible_schema":
        message = "Supervised scoring abstained because the evidence schema does not match the native PAN-OS model contract."
    elif status == "unknown_schema":
        message = "Supervised scoring abstained because the evidence schema is unknown."
    elif status == "parser_error":
        message = "Supervised scoring abstained because parsing did not produce scoring-eligible structured evidence."
    else:
        message = "Supervised scoring abstained because required native PAN-OS fields are missing."

    return {
        "contract_version": V520_VERSION,
        "expected_schema_id": expected_schema_id,
        "observed_schema_id": observed_schema_id,
        "profile_inferred_from_legacy_default": profile_inferred,
        "parse_status": parse_status,
        "status": status,
        "compatibility_score": compatibility_score,
        "scoring_allowed": scoring_allowed,
        "abstained": not scoring_allowed,
        "abstention_reason_codes": reasons,
        "missing_required_features": missing,
        "required_feature_count": len(expected.required_fields),
        "present_required_feature_count": present_count,
        "message": message,
        "raw_logs_included": False,
        "private_identifiers_included": False,
    }


def summarize_schema_compatibility(
    assessments: Iterable[Mapping[str, Any]],
) -> dict[str, Any]:
    rows = list(assessments)
    status_counts = Counter(str(row.get("status") or "unknown") for row in rows)
    reason_counts = Counter(
        str(reason)
        for row in rows
        for reason in (row.get("abstention_reason_codes") or [])
    )
    scored = sum(1 for row in rows if row.get("scoring_allowed") is True)
    total = len(rows)
    return {
        "contract_version": V520_VERSION,
        "expected_schema_id": GOVERNED_MODEL_SCHEMA_ID,
        "rows_checked": total,
        "scoring_allowed_count": scored,
        "abstained_count": total - scored,
        "abstention_rate": round((total - scored) / total, 6) if total else 0.0,
        "status_counts": dict(sorted(status_counts.items())),
        "reason_counts": dict(sorted(reason_counts.items())),
        "fail_closed": True,
        "rules_remain_authoritative": True,
        "raw_logs_included": False,
        "private_identifiers_included": False,
    }


def public_schema_abstention_policy() -> dict[str, Any]:
    contract = get_schema_contract(GOVERNED_MODEL_SCHEMA_ID)
    return {
        "contract_version": V520_VERSION,
        "expected_schema_id": GOVERNED_MODEL_SCHEMA_ID,
        "required_features": list(contract.required_fields),
        "compatible_status": COMPATIBLE_STATUS,
        "fail_closed": True,
        "incompatible_evidence_scored": False,
        "rules_remain_authoritative": True,
        "decision_support_only": True,
        "production_promoted": False,
        "response_automation_allowed": False,
    }
