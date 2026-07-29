from __future__ import annotations

from collections import Counter
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from atdr.app.db.models import NormalizedLog, RawLog
from atdr.app.parsers.paloalto_contract import PARSER_CONTRACT_VERSION
from atdr.app.parsers.paloalto_parser import ParsedPaloAltoLog


RUNTIME_PARSER_QUALITY_VERSION = "v5.13-runtime-parser-quality-v1"
PARSER_QUALITY_BASELINE_ROWS = 20

_COUNT_FIELDS = (
    "observed_rows",
    "parser_error_rows",
    "structural_warning_rows",
    "structural_warning_count",
    "generic_syslog_rows",
    "raw_fallback_rows",
)
_DISTRIBUTION_FIELDS = (
    "parser_profiles",
    "parser_contract_versions",
    "parse_statuses",
    "compatibility_statuses",
    "layout_statuses",
    "application_resolution_statuses",
)


def _integer(value: Any) -> int:
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError):
        return 0


def _count_map(value: Any) -> dict[str, int]:
    if not isinstance(value, dict):
        return {}
    return {
        str(key)[:128]: _integer(count)
        for key, count in value.items()
        if _integer(count)
    }


def _rate(numerator: int, denominator: int) -> float:
    return round(numerator / max(1, denominator), 6)


def empty_runtime_parser_quality() -> dict[str, Any]:
    result: dict[str, Any] = {
        "version": RUNTIME_PARSER_QUALITY_VERSION,
        **{field: 0 for field in _COUNT_FIELDS},
        **{field: {} for field in _DISTRIBUTION_FIELDS},
        "baseline": None,
        "latest_window": None,
        "operational_alerts": [],
    }
    return result


def _normalize_snapshot(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    observed_rows = _integer(value.get("observed_rows"))
    if not observed_rows:
        return None
    return {
        "observed_rows": observed_rows,
        "parser_error_rows": _integer(value.get("parser_error_rows")),
        "parser_error_rate": float(value.get("parser_error_rate") or 0.0),
        "structural_warning_rows": _integer(
            value.get("structural_warning_rows")
        ),
        "structural_warning_rate": float(
            value.get("structural_warning_rate") or 0.0
        ),
        "raw_fallback_rows": _integer(value.get("raw_fallback_rows")),
        "raw_fallback_rate": float(
            value.get("raw_fallback_rate") or 0.0
        ),
        "unresolved_application_rows": _integer(
            value.get("unresolved_application_rows")
        ),
        "unresolved_application_rate": float(
            value.get("unresolved_application_rate") or 0.0
        ),
        "compatibility_statuses": _count_map(
            value.get("compatibility_statuses")
        ),
        "layout_statuses": _count_map(value.get("layout_statuses")),
    }


def normalize_runtime_parser_quality(value: Any) -> dict[str, Any]:
    result = empty_runtime_parser_quality()
    if not isinstance(value, dict):
        return result
    for field in _COUNT_FIELDS:
        result[field] = _integer(value.get(field))
    for field in _DISTRIBUTION_FIELDS:
        result[field] = _count_map(value.get(field))
    result["baseline"] = _normalize_snapshot(value.get("baseline"))
    result["latest_window"] = _normalize_snapshot(
        value.get("latest_window")
    )
    result["operational_alerts"] = [
        {
            "code": str(row.get("code") or "parser_quality_notice")[:64],
            "severity": str(row.get("severity") or "info")[:16],
            "message": str(row.get("message") or "")[:500],
        }
        for row in value.get("operational_alerts") or []
        if isinstance(row, dict)
    ][:20]
    return result


def _layout_status(compatibility: str, profile: str) -> str:
    if profile == "raw_fallback":
        return "unstructured"
    if profile == "generic_syslog":
        return "limited"
    if compatibility == "supported_extended_layout":
        return "extended"
    if compatibility in {
        "supported_known_layout",
        "supported_compatible_layout",
    }:
        return "compatible"
    if compatibility == "partial_layout":
        return "partial"
    if compatibility in {
        "missing_log_type",
        "unsupported_log_type",
        "malformed_generic_syslog",
        "malformed_input",
    }:
        return "unsupported"
    return "unknown"


def observe_parser_result(
    quality: dict[str, Any],
    parsed_log: ParsedPaloAltoLog,
) -> dict[str, Any]:
    current = normalize_runtime_parser_quality(quality)
    parsed = (
        parsed_log.parsed_json
        if isinstance(parsed_log.parsed_json, dict)
        else {}
    )
    profile = str(parsed.get("parser_profile") or "palo_alto").strip().lower()
    contract_version = str(
        parsed.get("parser_contract_version") or "legacy_contract"
    )[:128]
    parse_status = str(parsed.get("parse_status") or "unknown").strip().lower()
    compatibility_row = (
        parsed.get("parser_compatibility")
        if isinstance(parsed.get("parser_compatibility"), dict)
        else {}
    )
    compatibility = str(
        compatibility_row.get("status")
        or ("malformed_input" if parsed_log.error else "legacy_contract")
    ).strip().lower()
    resolution_row = (
        parsed.get("application_resolution")
        if isinstance(parsed.get("application_resolution"), dict)
        else {}
    )
    resolution = str(
        resolution_row.get("status")
        or ("not_applicable" if profile != "palo_alto" else "unknown")
    ).strip().lower()
    warnings = (
        parsed.get("parser_warnings")
        if isinstance(parsed.get("parser_warnings"), list)
        else []
    )
    structural_warnings = [
        str(warning)
        for warning in warnings
        if "unresolved session evidence" not in str(warning).lower()
        and "unknown or incomplete application" not in str(warning).lower()
        and profile == "palo_alto"
    ]

    current["observed_rows"] += 1
    if profile == "raw_fallback":
        current["raw_fallback_rows"] += 1
    elif parsed_log.error or parse_status in {"error", "failed", "failure"}:
        current["parser_error_rows"] += 1
    if profile == "generic_syslog":
        current["generic_syslog_rows"] += 1
    if structural_warnings:
        current["structural_warning_rows"] += 1
        current["structural_warning_count"] += len(structural_warnings)

    counters = {
        "parser_profiles": profile,
        "parser_contract_versions": contract_version,
        "parse_statuses": parse_status,
        "compatibility_statuses": compatibility,
        "layout_statuses": _layout_status(compatibility, profile),
        "application_resolution_statuses": resolution,
    }
    for field, key in counters.items():
        values = Counter(_count_map(current[field]))
        values[key or "unknown"] += 1
        current[field] = dict(sorted(values.items()))
    return current


def _quality_snapshot(quality: dict[str, Any]) -> dict[str, Any]:
    observed = _integer(quality.get("observed_rows"))
    resolutions = _count_map(
        quality.get("application_resolution_statuses")
    )
    return {
        "observed_rows": observed,
        "parser_error_rows": _integer(quality.get("parser_error_rows")),
        "parser_error_rate": _rate(
            _integer(quality.get("parser_error_rows")),
            observed,
        ),
        "structural_warning_rows": _integer(
            quality.get("structural_warning_rows")
        ),
        "structural_warning_rate": _rate(
            _integer(quality.get("structural_warning_rows")),
            observed,
        ),
        "raw_fallback_rows": _integer(quality.get("raw_fallback_rows")),
        "raw_fallback_rate": _rate(
            _integer(quality.get("raw_fallback_rows")),
            observed,
        ),
        "unresolved_application_rows": resolutions.get("unresolved", 0),
        "unresolved_application_rate": _rate(
            resolutions.get("unresolved", 0),
            observed,
        ),
        "compatibility_statuses": _count_map(
            quality.get("compatibility_statuses")
        ),
        "layout_statuses": _count_map(quality.get("layout_statuses")),
    }


def build_parser_operational_alerts(
    quality: dict[str, Any],
) -> list[dict[str, Any]]:
    value = normalize_runtime_parser_quality(quality)
    observed = value["observed_rows"]
    if not observed:
        return []
    latest = value.get("latest_window") or _quality_snapshot(value)
    latest_rows = _integer(latest.get("observed_rows"))
    latest_error_rows = _integer(latest.get("parser_error_rows"))
    latest_error_rate = float(latest.get("parser_error_rate") or 0.0)
    latest_structural_rows = _integer(
        latest.get("structural_warning_rows")
    )
    latest_structural_rate = float(
        latest.get("structural_warning_rate") or 0.0
    )
    latest_raw_fallback_rows = _integer(
        latest.get("raw_fallback_rows")
    )
    latest_raw_fallback_rate = float(
        latest.get("raw_fallback_rate") or 0.0
    )
    latest_unresolved_rate = float(
        latest.get("unresolved_application_rate") or 0.0
    )
    latest_layouts = _count_map(latest.get("layout_statuses"))
    alerts: list[dict[str, Any]] = []

    baseline = value.get("baseline")
    baseline_error_rate = (
        float(baseline.get("parser_error_rate") or 0.0)
        if isinstance(baseline, dict)
        else None
    )
    error_rate_increased = bool(
        baseline_error_rate is not None
        and latest_rows >= 3
        and latest_error_rows >= 3
        and latest_error_rate >= 0.1
        and latest_error_rate - baseline_error_rate >= 0.1
    )
    if error_rate_increased:
        alerts.append(
            {
                "code": "parser_error_rate_increase",
                "severity": (
                    "error" if latest_error_rate >= 0.5 else "warning"
                ),
                "message": (
                    "The latest runtime window has a materially higher parser "
                    "error rate than the fixed source baseline."
                ),
            }
        )
    elif latest_error_rows >= 3 and latest_error_rate >= 0.1:
        alerts.append(
            {
                "code": "parser_error_rate_high",
                "severity": (
                    "error" if latest_error_rate >= 0.5 else "warning"
                ),
                "message": (
                    f"Runtime parser errors affect {latest_error_rate:.1%} of "
                    "the latest contract-observed window."
                ),
            }
        )
    if latest_layouts.get("unsupported", 0):
        alerts.append(
            {
                "code": "unsupported_layout",
                "severity": "warning",
                "message": (
                    f"{latest_layouts['unsupported']} row(s) in the latest "
                    "runtime window use an unsupported or unidentified layout."
                ),
            }
        )
    if (
        latest_layouts.get("partial", 0)
        or latest_structural_rows >= 3
        or latest_structural_rate >= 0.1
    ):
        alerts.append(
            {
                "code": "structural_schema_drift",
                "severity": "warning",
                "message": (
                    "Structural parser warnings or partial layouts differ from "
                    "the supported parser contract."
                ),
            }
        )
    if (
        latest_raw_fallback_rows >= 3
        or latest_raw_fallback_rate >= 0.5
    ):
        alerts.append(
            {
                "code": "prolonged_raw_fallback",
                "severity": "warning",
                "message": (
                    "Raw fallback is preserving evidence, but structured fields "
                    "remain unavailable for a sustained portion of this source."
                ),
            }
        )
    if value["generic_syslog_rows"]:
        alerts.append(
            {
                "code": "generic_syslog_limited_profile",
                "severity": "info",
                "message": (
                    "Generic syslog evidence is preserved with intentionally "
                    "limited structured fields."
                ),
            }
        )

    if isinstance(baseline, dict) and latest_rows:
        baseline_rate = float(
            baseline.get("unresolved_application_rate") or 0.0
        )
        if (
            latest_unresolved_rate >= 0.2
            and abs(latest_unresolved_rate - baseline_rate) >= 0.15
        ):
            alerts.append(
                {
                    "code": "unresolved_application_shift",
                    "severity": "info",
                    "message": (
                        "Unresolved application prevalence changed materially. "
                        "Treat this as session/source context, not parser failure."
                    ),
                }
            )
    elif latest_unresolved_rate >= 0.25:
        alerts.append(
            {
                "code": "unresolved_application_context",
                "severity": "info",
                "message": (
                    "Unknown or incomplete application values are common in "
                    "this runtime evidence and do not imply parser failure."
                ),
            }
        )
    return alerts


def merge_runtime_parser_quality(
    existing: Any,
    incoming: Any,
) -> dict[str, Any]:
    left = normalize_runtime_parser_quality(existing)
    right = normalize_runtime_parser_quality(incoming)
    merged = empty_runtime_parser_quality()
    for field in _COUNT_FIELDS:
        merged[field] = left[field] + right[field]
    for field in _DISTRIBUTION_FIELDS:
        values = Counter(left[field])
        values.update(right[field])
        merged[field] = dict(sorted(values.items()))
    merged["baseline"] = left.get("baseline")
    if (
        not merged["baseline"]
        and merged["observed_rows"] >= PARSER_QUALITY_BASELINE_ROWS
    ):
        merged["baseline"] = _quality_snapshot(merged)
    if right["observed_rows"]:
        merged["latest_window"] = (
            right.get("latest_window") or _quality_snapshot(right)
        )
    else:
        merged["latest_window"] = left.get("latest_window")
    merged["operational_alerts"] = build_parser_operational_alerts(merged)
    return merged


def finalize_runtime_parser_quality(quality: Any) -> dict[str, Any]:
    return merge_runtime_parser_quality({}, quality)


def runtime_parser_quality_summary(
    quality: Any,
    *,
    total_rows: int | None = None,
) -> dict[str, Any]:
    value = normalize_runtime_parser_quality(quality)
    observed = value["observed_rows"]
    layouts = value["layout_statuses"]
    resolutions = value["application_resolution_statuses"]
    total = max(observed, _integer(total_rows)) if total_rows is not None else observed
    legacy_rows = max(0, total - observed)
    if total == 0:
        contract_state = "no_evidence"
    elif observed == 0:
        contract_state = "legacy_contract"
    elif legacy_rows:
        contract_state = "mixed_contract"
    else:
        contract_state = "current_contract"

    parser_error_rate = _rate(value["parser_error_rows"], observed)
    if value["parser_error_rows"] >= 3 and parser_error_rate >= 0.5:
        quality_state = "error"
    elif (
        value["parser_error_rows"]
        or layouts.get("partial", 0)
        or layouts.get("unsupported", 0)
        or value["raw_fallback_rows"]
    ):
        quality_state = "warning"
    elif value["generic_syslog_rows"]:
        quality_state = "limited"
    elif observed:
        quality_state = "healthy"
    else:
        quality_state = "legacy"

    return {
        "version": RUNTIME_PARSER_QUALITY_VERSION,
        "quality_state": quality_state,
        "contract_state": contract_state,
        "observed_rows": observed,
        "legacy_contract_rows": legacy_rows,
        "parser_error_rows": value["parser_error_rows"],
        "parser_error_rate": parser_error_rate,
        "structural_warning_rows": value["structural_warning_rows"],
        "structural_warning_count": value["structural_warning_count"],
        "structural_warning_rate": _rate(
            value["structural_warning_rows"],
            observed,
        ),
        "compatible_layout_rows": layouts.get("compatible", 0),
        "extended_layout_rows": layouts.get("extended", 0),
        "partial_layout_rows": layouts.get("partial", 0),
        "unsupported_layout_rows": layouts.get("unsupported", 0),
        "generic_syslog_rows": value["generic_syslog_rows"],
        "raw_fallback_rows": value["raw_fallback_rows"],
        "identified_application_rows": resolutions.get("identified", 0),
        "unresolved_application_rows": resolutions.get("unresolved", 0),
        "unresolved_application_rate": _rate(
            resolutions.get("unresolved", 0),
            observed,
        ),
        "absent_application_rows": resolutions.get("absent", 0),
        "not_applicable_application_rows": resolutions.get(
            "not_applicable",
            0,
        ),
        "parser_profiles": value["parser_profiles"],
        "parser_contract_versions": value["parser_contract_versions"],
        "parse_statuses": value["parse_statuses"],
        "compatibility_statuses": value["compatibility_statuses"],
        "layout_statuses": layouts,
        "application_resolution_statuses": resolutions,
        "operational_alerts": build_parser_operational_alerts(value),
    }


def historical_reparse_impact_preview(
    db: Session,
    *,
    source_id: int,
    scan_limit: int = 5000,
) -> dict[str, Any]:
    total_rows = int(
        db.scalar(
            select(func.count(NormalizedLog.id))
            .join(RawLog, RawLog.id == NormalizedLog.raw_log_id)
            .where(RawLog.source_id == source_id)
        )
        or 0
    )
    rows = list(
        db.execute(
            select(
                NormalizedLog.parsed_json,
                NormalizedLog.log_type,
                NormalizedLog.app,
            )
            .join(RawLog, RawLog.id == NormalizedLog.raw_log_id)
            .where(RawLog.source_id == source_id)
            .order_by(NormalizedLog.id.desc())
            .limit(max(1, min(int(scan_limit), 50_000)))
        )
    )
    profiles: Counter[str] = Counter()
    contracts: Counter[str] = Counter()
    compatibility: Counter[str] = Counter()
    resolutions: Counter[str] = Counter()
    current_metadata_rows = 0
    for parsed_json, log_type, app in rows:
        parsed = parsed_json if isinstance(parsed_json, dict) else {}
        profile = str(parsed.get("parser_profile") or "legacy_contract")
        contract = str(
            parsed.get("parser_contract_version") or "legacy_contract"
        )
        compatibility_row = (
            parsed.get("parser_compatibility")
            if isinstance(parsed.get("parser_compatibility"), dict)
            else {}
        )
        resolution_row = (
            parsed.get("application_resolution")
            if isinstance(parsed.get("application_resolution"), dict)
            else {}
        )
        profiles[profile] += 1
        contracts[contract] += 1
        compatibility[
            str(compatibility_row.get("status") or "legacy_contract")
        ] += 1
        resolutions[
            str(
                resolution_row.get("status")
                or (
                    "not_applicable"
                    if str(log_type or "").upper()
                    not in {"TRAFFIC", "THREAT"}
                    else "unresolved"
                    if str(app or "").lower()
                    in {
                        "unknown",
                        "unknown-tcp",
                        "unknown-udp",
                        "unknown-p2p",
                        "incomplete",
                        "insufficient-data",
                    }
                    else "legacy_contract"
                )
            )
        ] += 1
        current_metadata_rows += int(
            contract == PARSER_CONTRACT_VERSION
            or contract in {"generic_syslog_v1", "raw_fallback_v1"}
        )

    scanned = len(rows)
    return {
        "version": RUNTIME_PARSER_QUALITY_VERSION,
        "status": "preview_complete" if scanned == total_rows else "preview_sampled",
        "scope": "selected_source",
        "preview_only": True,
        "reparse_performed": False,
        "database_mutated": False,
        "total_rows": total_rows,
        "rows_scanned": scanned,
        "coverage_complete": scanned == total_rows,
        "current_contract_metadata_rows": current_metadata_rows,
        "legacy_contract_rows_scanned": max(
            0,
            scanned - current_metadata_rows,
        ),
        "parser_profiles": dict(sorted(profiles.items())),
        "parser_contract_versions": dict(sorted(contracts.items())),
        "compatibility_statuses": dict(sorted(compatibility.items())),
        "application_resolution_statuses": dict(sorted(resolutions.items())),
        "raw_evidence_accessed": False,
        "raw_logs_returned": False,
        "private_paths_included": False,
        "ip_addresses_included": False,
        "source_identity_included": False,
        "labels_accessed": False,
        "alerts_created": 0,
        "response_actions_created": 0,
    }
