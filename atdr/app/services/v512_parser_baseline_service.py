from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from statistics import mean
from typing import Any, Iterable

from sqlalchemy import func, select
from sqlalchemy.orm import Session, joinedload

from atdr.app.core.config import PROJECT_ROOT
from atdr.app.db.models import (
    Alert,
    AlertEvidence,
    DetectionRun,
    LogSource,
    MLLabel,
    MLModelRun,
    MLShadowObservation,
    NormalizedLog,
    RawLog,
    ResponseAction,
)
from atdr.app.parsers.paloalto_contract import (
    PARSER_CONTRACT_VERSION,
    application_resolution,
    required_field_names,
)
from atdr.app.parsers.paloalto_parser import parse_log_line
from atdr.app.services import v511_shadow_monitoring_service as v511


V512_VERSION = "v5.12-parser-profile-baseline-repair-v1"
MINIMUM_PROFILE_BASELINE_ROWS = 200
DEFAULT_BASELINE_REPORT = (
    PROJECT_ROOT
    / "ml_baseline_reviews"
    / "v5_6_private_panos_model_repair_latest.json"
)
V511_LOCK_PATH = (
    PROJECT_ROOT
    / "data"
    / "samples"
    / "benchmarks"
    / "v511_operational_diagnostics_lock.json"
)

_AUTHORITATIVE_MODELS = (
    RawLog,
    NormalizedLog,
    Alert,
    AlertEvidence,
    MLLabel,
    MLModelRun,
    DetectionRun,
    ResponseAction,
)


def _stable_hash(value: Any) -> str:
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _number(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _integer(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _safe_json(path: Path) -> dict[str, Any]:
    if not path.exists() or not path.is_file():
        return {}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def _safe_distribution(rows: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "value": str(row.get("value") or "unknown")[:128],
            "count": max(0, _integer(row.get("count"))),
        }
        for row in rows
        if _integer(row.get("count")) > 0
    ][:50]


def _database_state(db: Session) -> dict[str, int]:
    return {
        model.__tablename__: int(
            db.scalar(select(func.count()).select_from(model)) or 0
        )
        for model in _AUTHORITATIVE_MODELS
    }


def _v511_projection(result: dict[str, Any]) -> dict[str, Any]:
    rows = [
        {
            key: value
            for key, value in row.items()
            if key != "observation_time"
        }
        for row in result.get("rows") or []
    ]
    return {
        "version": result.get("version"),
        "status": result.get("status"),
        "observation_count": _integer(result.get("observation_count")),
        "source_scope_count": _integer(result.get("source_scope_count")),
        "current_state": result.get("current_state"),
        "rows": rows,
        "root_cause_counts": result.get("root_cause_counts") or {},
        "operational_metrics": result.get("operational_metrics") or {},
        "thresholds": result.get("thresholds") or {},
        "hysteresis": result.get("hysteresis") or {},
        "lifecycle_state": result.get("lifecycle_state"),
        "rules_alert_authoritative": bool(
            result.get("rules_alert_authoritative")
        ),
        "isolation_forest_advisory_only": bool(
            result.get("isolation_forest_advisory_only")
        ),
        "model_activated": bool(result.get("model_activated")),
        "response_automation_allowed": bool(
            result.get("response_automation_allowed")
        ),
    }


def v511_baseline_lock_status(db: Session) -> dict[str, Any]:
    diagnostics = v511.build_shadow_monitoring_diagnostics(db)
    projection = _v511_projection(diagnostics)
    current_fingerprint = _stable_hash(projection)
    lock = _safe_json(V511_LOCK_PATH)
    expected = str(lock.get("diagnostics_fingerprint") or "")
    return {
        "status": (
            "locked_baseline_matched"
            if expected and expected == current_fingerprint
            else "locked_baseline_mismatched"
            if expected
            else "locked_baseline_missing"
        ),
        "matched": bool(expected and expected == current_fingerprint),
        "diagnostics_fingerprint": current_fingerprint,
        "expected_fingerprint": expected or None,
        "observation_count": projection["observation_count"],
        "source_scope_count": projection["source_scope_count"],
        "current_state": projection["current_state"],
        "fingerprint_values_are_aggregate_only": True,
        "source_identifiers_included": False,
        "raw_logs_included": False,
        "labels_accessed": False,
    }


def controlled_validation_projection(
    report: dict[str, Any],
) -> dict[str, Any]:
    return {
        key: report.get(key)
        for key in (
            "ok",
            "scenario_count",
            "mode_run_count",
            "passed_count",
            "failed_count",
            "false_positive_count",
            "false_negative_count",
            "scenario_summary",
        )
    }


def controlled_validation_lock_status(
    report: dict[str, Any],
) -> dict[str, Any]:
    projection = controlled_validation_projection(report)
    fingerprint = _stable_hash(projection)
    lock = _safe_json(V511_LOCK_PATH)
    expected = str(
        lock.get("controlled_projection_fingerprint") or ""
    )
    return {
        "status": (
            "controlled_baseline_matched"
            if expected and expected == fingerprint
            else "controlled_baseline_mismatched"
            if expected
            else "controlled_baseline_missing"
        ),
        "matched": bool(expected and expected == fingerprint),
        "projection_fingerprint": fingerprint,
        "expected_fingerprint": expected or None,
        "scenario_count": _integer(report.get("scenario_count")),
        "mode_run_count": _integer(report.get("mode_run_count")),
        "passed_count": _integer(report.get("passed_count")),
        "failed_count": _integer(report.get("failed_count")),
        "false_positive_count": _integer(
            report.get("false_positive_count")
        ),
        "false_negative_count": _integer(
            report.get("false_negative_count")
        ),
        "raw_logs_included": False,
        "source_identifiers_included": False,
        "private_paths_included": False,
    }


def build_governed_parser_baseline_catalog(
    *,
    report: dict[str, Any] | None = None,
    report_path: Path = DEFAULT_BASELINE_REPORT,
    minimum_support: int = MINIMUM_PROFILE_BASELINE_ROWS,
) -> dict[str, Any]:
    value = report if report is not None else _safe_json(report_path)
    fit = (
        (((value.get("drift_profile") or {}).get("role_distributions") or {}).get(
            "development_fit"
        ))
        or {}
    )
    quality = fit.get("quality") if isinstance(fit.get("quality"), dict) else {}
    rows = max(0, _integer(quality.get("rows")))
    baseline = {
        "rows": rows,
        "application": _safe_distribution(fit.get("application") or []),
        "schema": _safe_distribution(fit.get("schema") or []),
        "quality": {
            "parser_error_rate": max(
                0.0,
                _number(quality.get("parser_error_rate")),
            ),
            "parser_structural_warning_per_row": max(
                0.0,
                _number(quality.get("required_missing_per_row")),
            ),
            "required_missing_per_row": max(
                0.0,
                _number(quality.get("required_missing_per_row")),
            ),
            "unresolved_application_rate": max(
                0.0,
                _number(quality.get("unknown_app_rate")),
            ),
        },
    }
    baseline["fingerprint"] = _stable_hash(baseline)
    available = bool(
        rows >= max(1, int(minimum_support))
        and baseline["application"]
        and baseline["schema"]
    )
    profiles = (
        [
            {
                "parser_profile": "palo_alto",
                "source_type": "firewall",
                "baseline": baseline,
            }
        ]
        if available
        else []
    )
    return {
        "status": (
            "governed_parser_baseline_available"
            if available
            else "governed_parser_baseline_unavailable"
        ),
        "available": available,
        "minimum_support": max(1, int(minimum_support)),
        "global_baseline": baseline if available else None,
        "profile_baselines": profiles,
        "parser_contract_version": PARSER_CONTRACT_VERSION,
        "provenance": {
            "evidence_role": "governed_development_fit_aggregate",
            "selection_labels_used": False,
            "accuracy_metrics_used": False,
            "source_identity_used": False,
            "locked_final_evidence_used": False,
            "baseline_report_committed": False,
        },
        "private_paths_included": False,
        "raw_logs_included": False,
        "source_identifiers_included": False,
        "labels_accessed": False,
        "accuracy_metrics_calculated": False,
        "secrets_exposed": False,
    }


def select_parser_baseline(
    catalog: dict[str, Any],
    *,
    parser_profile: str | None,
    source_type: str | None,
) -> dict[str, Any]:
    profile = str(parser_profile or "unknown").strip().lower()
    source = str(source_type or "unknown").strip().lower()
    minimum_support = max(1, _integer(catalog.get("minimum_support"), 200))
    for item in catalog.get("profile_baselines") or []:
        baseline = item.get("baseline") or {}
        if (
            item.get("parser_profile") == profile
            and item.get("source_type") == source
            and _integer(baseline.get("rows")) >= minimum_support
        ):
            return {
                "status": "profile_source_type_baseline_selected",
                "scope": "parser_profile_source_type",
                "comparable": True,
                "parser_profile": profile,
                "source_type": source,
                "support_rows": _integer(baseline.get("rows")),
                "baseline": baseline,
            }

    global_baseline = catalog.get("global_baseline") or {}
    global_supported = (
        bool(catalog.get("available"))
        and _integer(global_baseline.get("rows")) >= minimum_support
    )
    comparable = profile == "palo_alto"
    return {
        "status": (
            "global_baseline_selected"
            if global_supported and comparable
            else "global_baseline_incompatible_profile"
            if global_supported
            else "insufficient_baseline_support"
        ),
        "scope": "global_fallback" if global_supported else "none",
        "comparable": bool(global_supported and comparable),
        "parser_profile": profile,
        "source_type": source,
        "support_rows": _integer(global_baseline.get("rows")),
        "baseline": global_baseline if global_supported else None,
    }


def _schema_bucket(log: NormalizedLog) -> str:
    parsed = log.parsed_json if isinstance(log.parsed_json, dict) else {}
    field_count = _integer(parsed.get("field_count"))
    log_type = str(log.log_type or "").strip().upper()
    if log_type == "TRAFFIC":
        return "traffic_complete" if field_count >= 47 else "traffic_limited"
    if log_type == "THREAT":
        return "threat_complete" if field_count >= 40 else "threat_limited"
    if log_type == "SYSTEM":
        return "system_complete" if field_count >= 15 else "system_limited"
    profile = str(parsed.get("parser_profile") or "palo_alto").lower()
    return f"{profile}_unstructured"


def _distribution_distance(
    baseline_rows: list[dict[str, Any]],
    current: Counter[str],
    *,
    baseline_total: int,
) -> float | None:
    current_total = sum(current.values())
    if baseline_total <= 0 or current_total <= 0:
        return None
    baseline = {
        str(row.get("value") or "unknown"): _integer(row.get("count"))
        for row in baseline_rows
    }
    keys = set(baseline)
    baseline_other = max(0, baseline_total - sum(baseline.values()))
    current_other = sum(
        count for key, count in current.items() if key not in keys
    )
    distance = 0.5 * sum(
        abs(
            (baseline.get(key, 0) / baseline_total)
            - (current.get(key, 0) / current_total)
        )
        for key in keys
    )
    distance += 0.5 * abs(
        (baseline_other / baseline_total)
        - (current_other / current_total)
    )
    return round(distance, 6)


def parser_quality_from_logs(
    logs: list[NormalizedLog],
) -> dict[str, Any]:
    applications: Counter[str] = Counter()
    schemas: Counter[str] = Counter()
    compatibility: Counter[str] = Counter()
    resolutions: Counter[str] = Counter()
    structural_warnings = 0
    parser_errors = 0
    required_missing = 0
    for log in logs:
        parsed = log.parsed_json if isinstance(log.parsed_json, dict) else {}
        applications[str(log.app or "unknown").strip().lower() or "unknown"] += 1
        schemas[_schema_bucket(log)] += 1
        compatibility_row = (
            parsed.get("parser_compatibility")
            if isinstance(parsed.get("parser_compatibility"), dict)
            else {}
        )
        compatibility[
            str(
                compatibility_row.get("status")
                or "legacy_contract"
            )
        ] += 1
        resolution_row = (
            parsed.get("application_resolution")
            if isinstance(parsed.get("application_resolution"), dict)
            else application_resolution(log.log_type, log.app)
        )
        resolutions[str(resolution_row.get("status") or "unknown")] += 1
        warnings = (
            parsed.get("parser_warnings")
            if isinstance(parsed.get("parser_warnings"), list)
            else []
        )
        structural_warnings += sum(
            1
            for warning in warnings
            if str(warning) != "unknown or incomplete application"
        )
        parser_errors += int(
            bool(parsed.get("parser_error"))
            or str(parsed.get("parse_status") or "").lower()
            in {"error", "failed", "failure", "fallback"}
        )
        for field in required_field_names(log.log_type):
            value = getattr(log, field, None)
            if value is None or (
                isinstance(value, str) and not value.strip()
            ):
                required_missing += 1
    total = len(logs)
    denominator = max(1, total)
    quality = {
        "rows": total,
        "parser_error_rate": round(parser_errors / denominator, 6),
        "parser_structural_warning_per_row": round(
            structural_warnings / denominator,
            6,
        ),
        "required_missing_per_row": round(
            required_missing / denominator,
            6,
        ),
        "unresolved_application_rate": round(
            resolutions["unresolved"] / denominator,
            6,
        ),
    }
    return {
        "quality": quality,
        "applications": applications,
        "schemas": schemas,
        "compatibility": dict(sorted(compatibility.items())),
        "application_resolution": dict(sorted(resolutions.items())),
    }


def evaluate_parser_profile_baseline(
    logs: list[NormalizedLog],
    *,
    parser_profile: str | None,
    source_type: str | None,
    catalog: dict[str, Any],
    minimum_rows: int = 50,
) -> dict[str, Any]:
    current = parser_quality_from_logs(logs)
    selection = select_parser_baseline(
        catalog,
        parser_profile=parser_profile,
        source_type=source_type,
    )
    baseline = selection.get("baseline") or {}
    baseline_quality = (
        baseline.get("quality")
        if isinstance(baseline.get("quality"), dict)
        else {}
    )
    baseline_total = _integer(baseline.get("rows"))
    application_distance = _distribution_distance(
        list(baseline.get("application") or []),
        current["applications"],
        baseline_total=baseline_total,
    )
    schema_distance = _distribution_distance(
        list(baseline.get("schema") or []),
        current["schemas"],
        baseline_total=baseline_total,
    )
    quality = current["quality"]
    deltas = {
        key: round(
            abs(_number(value) - _number(baseline_quality.get(key))),
            6,
        )
        for key, value in quality.items()
        if key != "rows"
    }
    if len(logs) < max(1, int(minimum_rows)) or not selection["comparable"]:
        status = "Insufficient Evidence"
    else:
        maximum = max(
            [
                value
                for value in (
                    application_distance,
                    schema_distance,
                    *deltas.values(),
                )
                if value is not None
            ],
            default=0.0,
        )
        status = (
            "OOD Warning"
            if maximum >= v511.MONITORING_THRESHOLDS["ood_total_variation"]
            else "Drift Warning"
            if maximum
            >= v511.MONITORING_THRESHOLDS["drift_total_variation"]
            else "Stable"
        )
    causes: list[str] = []
    if len(logs) < max(1, int(minimum_rows)):
        causes.append("short_or_sparse_window")
    if not selection["comparable"]:
        causes.append("comparable_profile_baseline_unavailable")
    if (
        application_distance is not None
        and application_distance
        >= v511.MONITORING_THRESHOLDS["drift_total_variation"]
    ):
        causes.append("application_distribution_shift")
    if (
        schema_distance is not None
        and schema_distance
        >= v511.MONITORING_THRESHOLDS["drift_total_variation"]
    ):
        causes.append("schema_contract_shift")
    if max(
        deltas.get("parser_error_rate", 0.0),
        deltas.get("parser_structural_warning_per_row", 0.0),
        deltas.get("required_missing_per_row", 0.0),
    ) >= v511.MONITORING_THRESHOLDS["drift_total_variation"]:
        causes.append("structural_parser_quality_shift")
    if (
        deltas.get("unresolved_application_rate", 0.0)
        >= v511.MONITORING_THRESHOLDS["drift_total_variation"]
    ):
        causes.append("application_resolution_shift")
    return {
        "status": status,
        "rows_evaluated": len(logs),
        "baseline_selection": {
            key: value
            for key, value in selection.items()
            if key != "baseline"
        },
        "application_total_variation": application_distance,
        "schema_total_variation": schema_distance,
        "quality": quality,
        "quality_absolute_delta": deltas,
        "compatibility_status_counts": current["compatibility"],
        "application_resolution_counts": current["application_resolution"],
        "root_cause_codes": causes or ["no_material_aggregate_shift"],
        "accuracy_metrics_calculated": False,
        "labels_accessed": False,
        "source_identifiers_included": False,
        "raw_logs_included": False,
    }


def _event_time_expression():
    return func.coalesce(
        NormalizedLog.generated_time,
        NormalizedLog.receive_time,
        NormalizedLog.high_res_timestamp,
        NormalizedLog.start_time,
    )


def _logs_for_observation(
    db: Session,
    observation: MLShadowObservation,
) -> list[NormalizedLog]:
    event_time = _event_time_expression()
    statement = (
        select(NormalizedLog)
        .join(RawLog, NormalizedLog.raw_log_id == RawLog.id)
        .options(
            joinedload(NormalizedLog.raw_log).joinedload(RawLog.source)
        )
        .order_by(event_time.asc(), NormalizedLog.id.asc())
        .limit(max(1, int(observation.requested_limit)))
    )
    if observation.source_id is not None:
        statement = statement.where(RawLog.source_id == observation.source_id)
    if observation.window_start is not None:
        statement = statement.where(event_time >= observation.window_start)
    if observation.window_end is not None:
        statement = statement.where(event_time <= observation.window_end)
    return list(db.scalars(statement).unique())


def build_parser_profile_operational_diagnostics(
    db: Session,
    *,
    limit: int = 365,
    catalog: dict[str, Any] | None = None,
) -> dict[str, Any]:
    baseline_catalog = catalog or build_governed_parser_baseline_catalog()
    observations = list(
        db.scalars(
            select(MLShadowObservation)
            .order_by(
                MLShadowObservation.created_at.asc(),
                MLShadowObservation.id.asc(),
            )
            .limit(max(1, min(int(limit), 1000)))
        )
    )
    source_ids = sorted(
        {
            int(row.source_id)
            for row in observations
            if row.source_id is not None
        }
    )
    scope_map = {
        source_id: f"source-scope-{index:02d}"
        for index, source_id in enumerate(source_ids, 1)
    }
    grouped: dict[int | None, list[MLShadowObservation]] = defaultdict(list)
    for row in observations:
        grouped[row.source_id].append(row)

    rows: list[dict[str, Any]] = []
    old_counts: Counter[str] = Counter()
    new_counts: Counter[str] = Counter()
    baseline_counts: Counter[str] = Counter()
    reclassified_legacy_warnings = 0
    for source_id, source_rows in sorted(
        grouped.items(),
        key=lambda item: (item[0] is None, int(item[0] or 0)),
    ):
        raw_states: list[str] = []
        staged: list[dict[str, Any]] = []
        for time_index, observation in enumerate(source_rows, 1):
            source = (
                db.get(LogSource, int(source_id))
                if source_id is not None
                else None
            )
            logs = _logs_for_observation(db, observation)
            parser_profile = (
                source.parser_profile if source is not None else "mixed"
            )
            source_type = (
                source.source_type if source is not None else "mixed"
            )
            evaluation = evaluate_parser_profile_baseline(
                logs,
                parser_profile=parser_profile,
                source_type=source_type,
                catalog=baseline_catalog,
            )
            old_quality = (
                ((observation.aggregate_json or {}).get("drift") or {}).get(
                    "quality"
                )
                or {}
            )
            reclassified_legacy_warnings += int(
                _number(old_quality.get("parser_warning_per_row")) > 0
                and evaluation["quality"][
                    "parser_structural_warning_per_row"
                ]
                == 0
            )
            old_state = str(
                observation.drift_status or "Insufficient Evidence"
            )
            old_counts[old_state] += 1
            raw_states.append(str(evaluation["status"]))
            baseline_counts[
                str(evaluation["baseline_selection"]["scope"])
            ] += 1
            staged.append(
                {
                    "source_scope": scope_map.get(
                        source_id,
                        "aggregate-scope",
                    ),
                    "time_scope": f"time-scope-{time_index:02d}",
                    "rows_evaluated": len(logs),
                    "old_drift_state": old_state,
                    "raw_repaired_state": evaluation["status"],
                    "queue_rate": round(float(observation.queue_rate), 6),
                    "disagreement_rate": round(
                        float(observation.disagreement_rate),
                        6,
                    ),
                    "isolation_anomaly_rate": round(
                        float(observation.isolation_anomaly_rate),
                        6,
                    ),
                    "baseline_selection": evaluation[
                        "baseline_selection"
                    ],
                    "application_total_variation": evaluation[
                        "application_total_variation"
                    ],
                    "schema_total_variation": evaluation[
                        "schema_total_variation"
                    ],
                    "quality": evaluation["quality"],
                    "quality_absolute_delta": evaluation[
                        "quality_absolute_delta"
                    ],
                    "compatibility_status_counts": evaluation[
                        "compatibility_status_counts"
                    ],
                    "application_resolution_counts": evaluation[
                        "application_resolution_counts"
                    ],
                    "root_cause_codes": evaluation[
                        "root_cause_codes"
                    ],
                    "accuracy_metrics_calculated": False,
                }
            )
        effective = v511.apply_drift_hysteresis(raw_states)
        for item, state in zip(staged, effective, strict=True):
            item["drift_state"] = state
            new_counts[state] += 1
            rows.append(item)

    priority = v511.DRIFT_PRIORITY
    current_state = max(
        new_counts,
        key=lambda value: priority.get(value, 1),
        default="Insufficient Evidence",
    )
    return {
        "ok": True,
        "version": V512_VERSION,
        "status": (
            "parser_profile_diagnostics_available"
            if rows
            else "insufficient_operational_evidence"
        ),
        "parser_contract_version": PARSER_CONTRACT_VERSION,
        "observation_count": len(rows),
        "source_scope_count": len(grouped),
        "current_state": current_state,
        "old_state_counts": dict(sorted(old_counts.items())),
        "repaired_state_counts": dict(sorted(new_counts.items())),
        "baseline_scope_counts": dict(sorted(baseline_counts.items())),
        "legacy_warning_windows_reclassified": (
            reclassified_legacy_warnings
        ),
        "baseline_catalog": {
            key: value
            for key, value in baseline_catalog.items()
            if key not in {"global_baseline", "profile_baselines"}
        },
        "rows": rows,
        "lifecycle_state": "shadow_observation",
        "rules_alert_authoritative": True,
        "isolation_forest_advisory_only": True,
        "model_activated": False,
        "production_promoted": False,
        "response_automation_allowed": False,
        "real_firewall_blocking_enabled": False,
        "source_identifiers_included": False,
        "raw_logs_included": False,
        "ip_addresses_included": False,
        "private_paths_included": False,
        "labels_accessed": False,
        "accuracy_metrics_calculated": False,
        "secrets_exposed": False,
    }


def _direction(src_zone: str | None, dst_zone: str | None) -> str:
    source = str(src_zone or "").lower()
    destination = str(dst_zone or "").lower()
    outside = ("outside", "untrust", "internet", "wan")
    inside = ("inside", "trust", "lan", "wlan", "corp")
    if any(value in source for value in inside) and any(
        value in destination for value in outside
    ):
        return "internal_to_external"
    if any(value in source for value in outside) and any(
        value in destination for value in inside
    ):
        return "external_to_internal"
    if source and destination:
        return "other_zone_direction"
    return "zone_direction_unavailable"


def audit_private_panos_contract(
    path: Path,
    *,
    max_lines: int | None = 120_000,
    window_size: int = 10_000,
) -> dict[str, Any]:
    if not path.exists() or not path.is_file():
        return {
            "ok": False,
            "status": "private_evidence_unavailable",
            "path_returned": False,
            "raw_logs_returned": False,
            "ip_addresses_returned": False,
        }

    counters: Counter[str] = Counter()
    schema: Counter[tuple[str, int]] = Counter()
    compatibility: Counter[str] = Counter()
    resolution: Counter[str] = Counter()
    app: Counter[str] = Counter()
    action: Counter[str] = Counter()
    ports: Counter[int] = Counter()
    directions: Counter[str] = Counter()
    threat_severity: Counter[str] = Counter()
    windows: list[Counter[str]] = []
    bytes_total = 0
    bytes_rows = 0
    bytes_maximum = 0
    limit = None if max_lines is None else max(0, int(max_lines))
    bounded_window = max(1, int(window_size))

    with path.open(
        "r",
        encoding="utf-8",
        errors="replace",
        newline="",
    ) as stream:
        for line in stream:
            if limit is not None and counters["rows"] >= limit:
                counters["limited"] = 1
                break
            if not line.strip():
                counters["blank_rows"] += 1
                continue
            counters["rows"] += 1
            parsed = parse_log_line(line)
            normalized = parsed.normalized
            details = parsed.parsed_json
            log_type = str(
                normalized.get("log_type") or "MISSING"
            ).upper()
            field_count = _integer(details.get("field_count"))
            schema[(log_type, field_count)] += 1
            compatibility_row = (
                details.get("parser_compatibility")
                if isinstance(details.get("parser_compatibility"), dict)
                else {}
            )
            compatibility[
                str(compatibility_row.get("status") or "unknown")
            ] += 1
            resolution_row = (
                details.get("application_resolution")
                if isinstance(details.get("application_resolution"), dict)
                else {}
            )
            resolution[
                str(resolution_row.get("reason") or "unknown")
            ] += 1
            application = str(
                normalized.get("app") or "<absent>"
            ).strip().lower()
            app[application] += 1
            action[str(normalized.get("action") or "<absent>").lower()] += 1
            if normalized.get("dst_port") is not None:
                ports[int(normalized["dst_port"])] += 1
            directions[
                _direction(
                    normalized.get("src_zone"),
                    normalized.get("dst_zone"),
                )
            ] += 1
            if details.get("parsed_threat_severity"):
                threat_severity[
                    str(details["parsed_threat_severity"]).lower()
                ] += 1
            byte_value = _integer(normalized.get("bytes"), -1)
            if byte_value >= 0:
                bytes_total += byte_value
                bytes_rows += 1
                bytes_maximum = max(bytes_maximum, byte_value)
            counters["parser_errors"] += int(parsed.error is not None)
            structural = [
                warning
                for warning in details.get("parser_warnings") or []
                if str(warning) != "unknown or incomplete application"
            ]
            counters["structural_warnings"] += len(structural)
            counters["unresolved_applications"] += int(
                resolution_row.get("status") == "unresolved"
            )
            window_index = (counters["rows"] - 1) // bounded_window
            while len(windows) <= window_index:
                windows.append(Counter())
            window = windows[window_index]
            window["rows"] += 1
            window["errors"] += int(parsed.error is not None)
            window["warnings"] += len(structural)
            window["unresolved"] += int(
                resolution_row.get("status") == "unresolved"
            )

    total = max(1, counters["rows"])

    def top(
        values: Counter[Any],
        *,
        key_name: str,
        limit_rows: int = 20,
    ) -> list[dict[str, Any]]:
        return [
            {key_name: str(value), "count": int(count)}
            for value, count in values.most_common(limit_rows)
        ]

    return {
        "ok": counters["rows"] > 0,
        "status": (
            "bounded_private_parser_audit_complete"
            if counters["rows"]
            else "private_evidence_empty"
        ),
        "rows_observed": counters["rows"],
        "blank_rows": counters["blank_rows"],
        "limited": bool(counters["limited"]),
        "schema_variants": [
            {
                "log_type": log_type,
                "field_count": field_count,
                "count": count,
            }
            for (log_type, field_count), count in sorted(schema.items())
        ],
        "compatibility_status_counts": dict(
            sorted(compatibility.items())
        ),
        "application_resolution_reasons": dict(sorted(resolution.items())),
        "quality": {
            "parse_success_rate": round(
                (total - counters["parser_errors"]) / total,
                6,
            ),
            "parser_error_rate": round(
                counters["parser_errors"] / total,
                6,
            ),
            "parser_structural_warning_per_row": round(
                counters["structural_warnings"] / total,
                6,
            ),
            "unresolved_application_rate": round(
                counters["unresolved_applications"] / total,
                6,
            ),
        },
        "top_applications": top(app, key_name="application"),
        "actions": top(action, key_name="action"),
        "destination_ports": top(ports, key_name="port"),
        "zone_directions": dict(sorted(directions.items())),
        "threat_severities": dict(sorted(threat_severity.items())),
        "bytes": {
            "rows_with_value": bytes_rows,
            "mean": round(bytes_total / max(1, bytes_rows), 2),
            "maximum": bytes_maximum,
        },
        "chronological_windows": [
            {
                "window_scope": f"window-{index:02d}",
                "rows": row["rows"],
                "parser_error_rate": round(
                    row["errors"] / max(1, row["rows"]),
                    6,
                ),
                "parser_structural_warning_per_row": round(
                    row["warnings"] / max(1, row["rows"]),
                    6,
                ),
                "unresolved_application_rate": round(
                    row["unresolved"] / max(1, row["rows"]),
                    6,
                ),
            }
            for index, row in enumerate(windows, 1)
        ],
        "system_rows_observed": sum(
            count
            for (log_type, _field_count), count in schema.items()
            if log_type == "SYSTEM"
        ),
        "system_contract_validation_basis": (
            "private_evidence"
            if any(log_type == "SYSTEM" for log_type, _ in schema)
            else "official_contract_and_synthetic_tests_only"
        ),
        "persistent_storage_created": False,
        "bounded_in_memory_aggregates_only": True,
        "path_returned": False,
        "raw_logs_returned": False,
        "ip_addresses_returned": False,
        "source_identifiers_returned": False,
        "fingerprints_returned": False,
        "secrets_exposed": False,
    }


def v512_comparison_summary(
    db: Session,
    *,
    private_audit: dict[str, Any] | None = None,
    catalog: dict[str, Any] | None = None,
) -> dict[str, Any]:
    before = _database_state(db)
    lock = v511_baseline_lock_status(db)
    old = v511.build_shadow_monitoring_diagnostics(db)
    repaired = build_parser_profile_operational_diagnostics(
        db,
        catalog=catalog,
    )
    after = _database_state(db)
    old_queue = [
        _number(row.get("queue_rate")) for row in old.get("rows") or []
    ]
    old_disagreement = [
        _number(row.get("disagreement_rate"))
        for row in old.get("rows") or []
    ]
    private_quality = (private_audit or {}).get("quality") or {}
    return {
        "ok": bool(before == after and lock.get("matched")),
        "version": V512_VERSION,
        "status": (
            "v5.12_comparison_complete"
            if before == after
            else "failed_closed_unexpected_mutation"
        ),
        "v511_baseline_lock": lock,
        "old": {
            "current_state": old.get("current_state"),
            "state_counts": dict(
                Counter(
                    str(row.get("drift_state"))
                    for row in old.get("rows") or []
                )
            ),
            "root_cause_counts": old.get("root_cause_counts") or {},
            "mean_queue_rate": (
                round(mean(old_queue), 6) if old_queue else None
            ),
            "mean_disagreement_rate": (
                round(mean(old_disagreement), 6)
                if old_disagreement
                else None
            ),
        },
        "repaired": {
            "current_state": repaired.get("current_state"),
            "state_counts": repaired.get("repaired_state_counts") or {},
            "baseline_scope_counts": repaired.get(
                "baseline_scope_counts"
            )
            or {},
            "legacy_warning_windows_reclassified": repaired.get(
                "legacy_warning_windows_reclassified"
            ),
            "mean_queue_rate": (
                round(mean(old_queue), 6) if old_queue else None
            ),
            "mean_disagreement_rate": (
                round(mean(old_disagreement), 6)
                if old_disagreement
                else None
            ),
            "queue_and_disagreement_recomputed": False,
        },
        "private_quality": {
            "rows_observed": (private_audit or {}).get("rows_observed"),
            "parse_success_rate": private_quality.get(
                "parse_success_rate"
            ),
            "parser_error_rate": private_quality.get(
                "parser_error_rate"
            ),
            "parser_structural_warning_per_row": private_quality.get(
                "parser_structural_warning_per_row"
            ),
            "unresolved_application_rate": private_quality.get(
                "unresolved_application_rate"
            ),
            "private_path_returned": False,
            "raw_logs_returned": False,
        },
        "safety": {
            "configured_database_unchanged": before == after,
            "entity_deltas": {
                key: after[key] - before[key] for key in before
            },
            "model_activated": False,
            "production_promoted": False,
            "response_automation_allowed": False,
            "rules_alert_authoritative": True,
            "isolation_forest_advisory_only": True,
        },
        "diagnostics": repaired,
        "source_identifiers_included": False,
        "raw_logs_included": False,
        "ip_addresses_included": False,
        "private_paths_included": False,
        "labels_accessed": False,
        "accuracy_metrics_calculated": False,
        "secrets_exposed": False,
    }
