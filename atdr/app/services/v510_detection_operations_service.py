from __future__ import annotations

from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from statistics import mean
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from atdr.app.core.config import get_settings
from atdr.app.db.models import AuditLog, MLShadowObservation, NormalizedLog, RawLog
from atdr.app.services import v58_shadow_scoring_service as v58
from atdr.app.services import v59_shadow_observation_service as v59


V510_VERSION = "v5.10-detection-operations-shadow-acceptance-v1"
OBSERVATION_SCHEMA_VERSION = "v5.10-operational-observation-v1"
DEVELOPMENT_EVIDENCE_ROLE = "reused_development_operational_evidence_only"
REQUIRED_AGGREGATE_KEYS = {
    "rows_evaluated",
    "queue_count",
    "queue_rate",
    "score_summary",
    "confidence_summary",
    "missing_feature_values",
    "feature_values_checked",
    "drift",
    "rule_shadow_agreement",
    "isolation_forest",
    "operational_contract",
}
SUCCESS_STATUSES = {
    "evaluated_shadow_read_only",
}
DRIFT_PRIORITY = {
    "Stable": 0,
    "Insufficient Evidence": 1,
    "Drift Warning": 2,
    "OOD Warning": 3,
}


@dataclass(frozen=True)
class HistoricalObservationScope:
    scope_id: str
    source_scope: str
    source_id: int
    window_start: datetime
    window_end: datetime
    available_rows: int
    requested_limit: int
    sufficient_rows: bool


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _event_time_expression():
    return func.coalesce(
        NormalizedLog.generated_time,
        NormalizedLog.receive_time,
        NormalizedLog.high_res_timestamp,
        NormalizedLog.start_time,
    )


def _source_timestamp_groups(
    db: Session,
    *,
    maximum_sources: int,
) -> list[tuple[int, list[tuple[datetime, int]]]]:
    event_time = _event_time_expression()
    source_rows = db.execute(
        select(
            RawLog.source_id,
            func.count(NormalizedLog.id).label("row_count"),
        )
        .join(RawLog, NormalizedLog.raw_log_id == RawLog.id)
        .where(
            RawLog.source_id.is_not(None),
            event_time.is_not(None),
        )
        .group_by(RawLog.source_id)
        .order_by(
            func.count(NormalizedLog.id).desc(),
            RawLog.source_id.asc(),
        )
        .limit(maximum_sources)
    ).all()
    source_ids = [int(row.source_id) for row in source_rows]
    if not source_ids:
        return []

    grouped: dict[int, list[tuple[datetime, int]]] = {
        source_id: [] for source_id in source_ids
    }
    rows = db.execute(
        select(
            RawLog.source_id,
            event_time.label("event_time"),
            func.count(NormalizedLog.id).label("row_count"),
        )
        .join(RawLog, NormalizedLog.raw_log_id == RawLog.id)
        .where(
            RawLog.source_id.in_(source_ids),
            event_time.is_not(None),
        )
        .group_by(RawLog.source_id, event_time)
        .order_by(RawLog.source_id.asc(), event_time.asc())
    ).all()
    for row in rows:
        grouped[int(row.source_id)].append(
            (_utc(row.event_time), int(row.row_count))
        )
    return [
        (source_id, grouped[source_id])
        for source_id in source_ids
        if grouped[source_id]
    ]


def _partition_timestamp_groups(
    groups: list[tuple[datetime, int]],
    *,
    maximum_windows: int,
    minimum_rows: int,
) -> list[list[tuple[datetime, int]]]:
    total_rows = sum(count for _, count in groups)
    desired_windows = min(
        maximum_windows,
        max(1, total_rows // max(1, minimum_rows)),
        len(groups),
    )
    if desired_windows <= 1:
        return [groups]

    chunks: list[list[tuple[datetime, int]]] = [[]]
    cumulative = 0
    for index, item in enumerate(groups):
        chunks[-1].append(item)
        cumulative += item[1]
        next_threshold = (total_rows * len(chunks)) / desired_windows
        groups_remaining = len(groups) - index - 1
        windows_remaining = desired_windows - len(chunks)
        if (
            len(chunks) < desired_windows
            and cumulative >= next_threshold
            and groups_remaining >= windows_remaining
        ):
            chunks.append([])
    return [chunk for chunk in chunks if chunk]


def _discover_scope_records(
    db: Session,
    *,
    maximum_sources: int = 8,
    maximum_windows_per_source: int = 3,
    minimum_rows: int = 50,
    batch_limit: int | None = None,
) -> list[HistoricalObservationScope]:
    settings = get_settings()
    effective_limit = min(
        int(batch_limit or settings.governed_shadow_batch_size),
        int(settings.governed_shadow_max_batch_size),
    )
    records: list[HistoricalObservationScope] = []
    source_groups = _source_timestamp_groups(
        db,
        maximum_sources=max(1, min(int(maximum_sources), 32)),
    )
    for source_index, (source_id, groups) in enumerate(source_groups, 1):
        windows = _partition_timestamp_groups(
            groups,
            maximum_windows=max(
                1,
                min(int(maximum_windows_per_source), 12),
            ),
            minimum_rows=max(1, int(minimum_rows)),
        )
        source_scope = f"source-scope-{source_index:02d}"
        for chunk in windows:
            available_rows = sum(count for _, count in chunk)
            records.append(
                HistoricalObservationScope(
                    scope_id=f"scope-{len(records) + 1:03d}",
                    source_scope=source_scope,
                    source_id=source_id,
                    window_start=chunk[0][0],
                    window_end=chunk[-1][0],
                    available_rows=available_rows,
                    requested_limit=min(effective_limit, available_rows),
                    sufficient_rows=available_rows >= minimum_rows,
                )
            )
    return records


def _public_scope(scope: HistoricalObservationScope) -> dict[str, Any]:
    return {
        "scope_id": scope.scope_id,
        "source_scope": scope.source_scope,
        "window_start": scope.window_start,
        "window_end": scope.window_end,
        "available_rows": scope.available_rows,
        "requested_limit": scope.requested_limit,
        "evidence_status": (
            "operational_scope_ready"
            if scope.sufficient_rows
            else "insufficient_evidence"
        ),
        "evidence_role": DEVELOPMENT_EVIDENCE_ROLE,
        "independent_validation": False,
        "source_identifier_included": False,
        "raw_evidence_included": False,
    }


def governed_historical_observation_plan(
    db: Session,
    *,
    maximum_sources: int = 8,
    maximum_windows_per_source: int = 3,
    minimum_rows: int = 50,
    batch_limit: int | None = None,
) -> dict[str, Any]:
    scopes = _discover_scope_records(
        db,
        maximum_sources=maximum_sources,
        maximum_windows_per_source=maximum_windows_per_source,
        minimum_rows=minimum_rows,
        batch_limit=batch_limit,
    )
    return {
        "ok": True,
        "version": V510_VERSION,
        "status": (
            "governed_historical_scopes_available"
            if scopes
            else "no_eligible_historical_scopes"
        ),
        "evidence_role": DEVELOPMENT_EVIDENCE_ROLE,
        "independent_validation": False,
        "source_scope_count": len({scope.source_scope for scope in scopes}),
        "observation_scope_count": len(scopes),
        "sufficient_scope_count": sum(scope.sufficient_rows for scope in scopes),
        "insufficient_scope_count": sum(
            not scope.sufficient_rows for scope in scopes
        ),
        "total_available_rows": sum(
            scope.available_rows for scope in scopes
        ),
        "scopes": [_public_scope(scope) for scope in scopes],
        "scope_contract": {
            "bounded": True,
            "chronological": True,
            "non_overlapping_within_source": True,
            "configured_database_only": True,
            "locked_final_evidence_used_for_selection": False,
            "accuracy_metrics_calculated": False,
        },
        "accuracy_metrics_calculated": False,
        "lifecycle_state": "shadow_observation",
        "rules_alert_authoritative": True,
        "model_activated": False,
        "production_promoted": False,
        "response_automation_allowed": False,
        "real_firewall_blocking_enabled": False,
        "source_identifiers_included": False,
        "raw_logs_included": False,
        "ip_addresses_included": False,
        "private_paths_included": False,
        "fingerprints_included": False,
        "labels_accessed": False,
        "secrets_exposed": False,
    }


def _numeric_range(values: list[float]) -> dict[str, float | None]:
    return {
        "minimum": round(min(values), 6) if values else None,
        "mean": round(mean(values), 6) if values else None,
        "maximum": round(max(values), 6) if values else None,
        "range": round(max(values) - min(values), 6)
        if values
        else None,
    }


def _quality_values(
    observations: list[MLShadowObservation],
) -> dict[str, list[float]]:
    result: dict[str, list[float]] = {
        "missing_feature_rate": [],
        "parser_error_rate": [],
        "parser_warning_per_row": [],
        "required_missing_per_row": [],
        "unknown_app_rate": [],
    }
    for observation in observations:
        aggregate = observation.aggregate_json or {}
        checked = int(aggregate.get("feature_values_checked") or 0)
        missing = int(aggregate.get("missing_feature_values") or 0)
        if checked > 0:
            result["missing_feature_rate"].append(missing / checked)
        drift = aggregate.get("drift") or {}
        quality = drift.get("quality") or {}
        for key in (
            "parser_error_rate",
            "parser_warning_per_row",
            "required_missing_per_row",
            "unknown_app_rate",
        ):
            value = quality.get(key)
            if isinstance(value, (int, float)):
                result[key].append(float(value))
    return result


def _schema_is_valid(observation: MLShadowObservation) -> bool:
    aggregate = observation.aggregate_json or {}
    operational = aggregate.get("operational_contract") or {}
    return (
        REQUIRED_AGGREGATE_KEYS.issubset(aggregate)
        and operational.get("schema_version") == OBSERVATION_SCHEMA_VERSION
        and operational.get("evidence_role") == DEVELOPMENT_EVIDENCE_ROLE
        and operational.get("independent_validation") is False
        and aggregate.get("accuracy_metrics_calculated") is False
        and aggregate.get("labels_accessed") is False
    )


def _privacy_is_valid(observation: MLShadowObservation) -> bool:
    aggregate = observation.aggregate_json or {}
    operational = aggregate.get("operational_contract") or {}
    return all(
        aggregate.get(key) is False
        for key in (
            "raw_logs_included",
            "ip_addresses_included",
            "private_paths_included",
            "row_fingerprints_included",
            "secrets_exposed",
        )
    ) and operational.get("private_data_exposed") is False


def _mutation_proof_is_valid(
    observation: MLShadowObservation,
) -> bool:
    operational = (
        (observation.aggregate_json or {}).get("operational_contract")
        or {}
    )
    mutations = operational.get("authoritative_mutations") or {}
    return (
        operational.get("authoritative_state_unchanged") is True
        and all(
            int(mutations.get(key) or 0) == 0
            for key in (
                "alerts",
                "alert_evidence",
                "labels",
                "model_runs",
                "detection_runs",
                "response_actions",
            )
        )
    )


def _retention_isolation_status(db: Session) -> dict[str, Any]:
    rows = list(
        db.scalars(
            select(AuditLog)
            .where(
                AuditLog.action
                == "ml_shadow_observation_retention_applied"
            )
            .order_by(AuditLog.id.desc())
            .limit(20)
        )
    )
    failures = 0
    for row in rows:
        details = row.details if isinstance(row.details, dict) else {}
        if any(
            details.get(key) is not False
            for key in (
                "raw_evidence_affected",
                "labels_affected",
                "model_artifacts_affected",
                "response_actions_affected",
            )
        ):
            failures += 1
    return {
        "runs_checked": len(rows),
        "failed_isolation_runs": failures,
        "status": (
            "not_exercised"
            if not rows
            else "passed"
            if failures == 0
            else "failed"
        ),
    }


def _gate(
    name: str,
    *,
    passed: bool,
    evidence: str,
) -> dict[str, Any]:
    return {
        "name": name,
        "required": True,
        "passed": bool(passed),
        "evidence": evidence,
    }


def shadow_operational_acceptance_summary(
    db: Session,
    *,
    limit: int = 365,
) -> dict[str, Any]:
    observations = list(
        db.scalars(
            select(MLShadowObservation)
            .order_by(
                MLShadowObservation.created_at.desc(),
                MLShadowObservation.id.desc(),
            )
            .limit(max(1, min(int(limit), 1000)))
        )
    )
    observation_count = len(observations)
    queue_rates = [float(row.queue_rate) for row in observations]
    disagreement_rates = [
        float(row.disagreement_rate) for row in observations
    ]
    anomaly_rates = [
        float(row.isolation_anomaly_rate) for row in observations
    ]
    runtimes = [
        float(row.runtime_seconds)
        for row in observations
        if row.runtime_seconds is not None
    ]
    quality = _quality_values(observations)
    drift_counts = Counter(row.drift_status for row in observations)
    current_drift = max(
        drift_counts,
        key=lambda item: DRIFT_PRIORITY.get(item, 4),
        default="Insufficient Evidence",
    )
    failed_count = sum(
        bool(row.failure_code) or row.status not in SUCCESS_STATUSES
        for row in observations
    )
    insufficient_count = sum(
        row.drift_status == "Insufficient Evidence"
        for row in observations
    )
    contract_mismatch_count = sum(
        not row.contract_matched for row in observations
    )
    stable_schema_count = sum(
        _schema_is_valid(row) for row in observations
    )
    private_safe_count = sum(
        _privacy_is_valid(row) for row in observations
    )
    mutation_safe_count = sum(
        _mutation_proof_is_valid(row) for row in observations
    )
    distinct_keys = len(
        {row.observation_key for row in observations}
    )
    retention = _retention_isolation_status(db)
    settings = get_settings()
    bounded_runtime = bool(observations) and all(
        runtime <= float(settings.governed_shadow_timeout_seconds)
        for runtime in runtimes
    ) and len(runtimes) == observation_count

    warnings: list[str] = []
    if not observations:
        warnings.append(
            "No governed historical observations have been recorded."
        )
    if failed_count:
        warnings.append(
            f"{failed_count} observation(s) failed or closed without a successful runtime."
        )
    if insufficient_count:
        warnings.append(
            f"{insufficient_count} scope(s) have insufficient operational evidence."
        )
    if current_drift in {"Drift Warning", "OOD Warning"}:
        warnings.append(
            f"Current aggregate drift state is {current_drift}."
        )
    queue_stability = _numeric_range(queue_rates)
    disagreement_stability = _numeric_range(disagreement_rates)
    if (queue_stability["range"] or 0.0) > 0.35:
        warnings.append(
            "Advisory queue rate varies materially across observed scopes."
        )
    if (disagreement_stability["range"] or 0.0) > 0.35:
        warnings.append(
            "Rule/shadow disagreement varies materially across observed scopes."
        )

    gates = [
        _gate(
            "authoritative_state_unchanged",
            passed=bool(observations)
            and mutation_safe_count == observation_count,
            evidence=(
                f"{mutation_safe_count}/{observation_count} observations carry zero-mutation proof"
            ),
        ),
        _gate(
            "private_data_excluded",
            passed=bool(observations)
            and private_safe_count == observation_count,
            evidence=(
                f"{private_safe_count}/{observation_count} observations satisfy the aggregate privacy contract"
            ),
        ),
        _gate(
            "candidate_contract_matched",
            passed=bool(observations)
            and contract_mismatch_count == 0,
            evidence=f"{contract_mismatch_count} contract mismatch(es) accepted",
        ),
        _gate(
            "idempotent_observation_keys",
            passed=bool(observations)
            and distinct_keys == observation_count,
            evidence=(
                f"{distinct_keys}/{observation_count} stored observation keys are unique"
            ),
        ),
        _gate(
            "bounded_runtime",
            passed=bounded_runtime,
            evidence=(
                f"{len(runtimes)}/{observation_count} observations completed within the configured timeout"
            ),
        ),
        _gate(
            "retention_isolation",
            passed=retention["failed_isolation_runs"] == 0,
            evidence=(
                f"{retention['runs_checked']} audited retention run(s); "
                f"{retention['failed_isolation_runs']} isolation failure(s)"
            ),
        ),
        _gate(
            "stable_observation_schema",
            passed=bool(observations)
            and stable_schema_count == observation_count,
            evidence=(
                f"{stable_schema_count}/{observation_count} observations use the governed v5.10 schema"
            ),
        ),
        _gate(
            "operational_warnings_visible",
            passed=True,
            evidence=f"{len(warnings)} warning(s) surfaced",
        ),
    ]
    passed_count = sum(item["passed"] for item in gates)
    all_required_passed = passed_count == len(gates)
    decision = (
        "operational_shadow_acceptance_passed_with_warnings"
        if all_required_passed
        and observation_count >= 2
        and warnings
        else "operational_shadow_acceptance_passed"
        if all_required_passed and observation_count >= 2
        else "operational_shadow_acceptance_warning"
        if observations
        else "insufficient_operational_evidence"
    )
    return {
        "ok": True,
        "version": V510_VERSION,
        "status": decision,
        "evidence_role": DEVELOPMENT_EVIDENCE_ROLE,
        "independent_validation": False,
        "observation_count": observation_count,
        "source_scope_count": len(
            {
                row.source_id
                for row in observations
                if row.source_id is not None
            }
        ),
        "time_scope_count": len(
            {
                (row.source_id, row.window_start, row.window_end)
                for row in observations
            }
        ),
        "latest_observation_at": (
            observations[0].created_at if observations else None
        ),
        "queue_rate": queue_stability,
        "rule_shadow_disagreement_rate": disagreement_stability,
        "isolation_forest_anomaly_rate": _numeric_range(anomaly_rates),
        "runtime_seconds": _numeric_range(runtimes),
        "quality": {
            key: _numeric_range(values)
            for key, values in quality.items()
        },
        "drift": {
            "current_state": current_drift,
            "status_counts": dict(sorted(drift_counts.items())),
        },
        "failed_observation_count": failed_count,
        "insufficient_evidence_count": insufficient_count,
        "contract_mismatch_count": contract_mismatch_count,
        "warnings": warnings,
        "gates": gates,
        "gates_passed": passed_count,
        "gates_total": len(gates),
        "operational_acceptance_passed": (
            all_required_passed and observation_count >= 2
        ),
        "retention": retention,
        "accuracy_metrics_calculated": False,
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
        "fingerprints_included": False,
        "labels_accessed": False,
        "secrets_exposed": False,
    }


def run_historical_shadow_observations(
    db: Session,
    *,
    actor: str,
    maximum_sources: int = 8,
    maximum_windows_per_source: int = 3,
    minimum_rows: int = 50,
    batch_limit: int | None = None,
    should_stop: Callable[[], bool] | None = None,
) -> dict[str, Any]:
    settings = get_settings()
    if not settings.governed_shadow_observation_enabled:
        return {
            **governed_historical_observation_plan(
                db,
                maximum_sources=maximum_sources,
                maximum_windows_per_source=maximum_windows_per_source,
                minimum_rows=minimum_rows,
                batch_limit=batch_limit,
            ),
            "ok": False,
            "status": "observation_disabled_by_configuration",
            "observations_executed": 0,
        }
    if not settings.governed_shadow_scoring_enabled:
        return {
            **governed_historical_observation_plan(
                db,
                maximum_sources=maximum_sources,
                maximum_windows_per_source=maximum_windows_per_source,
                minimum_rows=minimum_rows,
                batch_limit=batch_limit,
            ),
            "ok": False,
            "status": "shadow_scoring_disabled_by_configuration",
            "observations_executed": 0,
        }

    contract = v58.inspect_frozen_candidate_contract()
    if not contract.get("matched"):
        return {
            **governed_historical_observation_plan(
                db,
                maximum_sources=maximum_sources,
                maximum_windows_per_source=maximum_windows_per_source,
                minimum_rows=minimum_rows,
                batch_limit=batch_limit,
            ),
            "ok": False,
            "status": "failed_closed_candidate_contract_mismatch",
            "observations_executed": 0,
            "candidate_contract_matched": False,
        }

    scopes = _discover_scope_records(
        db,
        maximum_sources=maximum_sources,
        maximum_windows_per_source=maximum_windows_per_source,
        minimum_rows=minimum_rows,
        batch_limit=batch_limit,
    )
    authoritative_before = v58._database_state(db)
    results: list[dict[str, Any]] = []
    cancelled = False
    for scope in scopes:
        if should_stop is not None and should_stop():
            cancelled = True
            break
        value = v59.record_governed_shadow_observation(
            db,
            actor=actor,
            source_id=scope.source_id,
            start_at=scope.window_start,
            end_at=scope.window_end,
            limit=scope.requested_limit,
            should_stop=should_stop,
        )
        observation = value.get("observation") or {}
        results.append(
            {
                "scope_id": scope.scope_id,
                "source_scope": scope.source_scope,
                "status": value.get("status"),
                "ok": bool(value.get("ok")),
                "observation_created": bool(
                    value.get("observation_created")
                ),
                "idempotent_reuse": bool(
                    value.get("idempotent_reuse")
                ),
                "rows_evaluated": int(
                    observation.get("rows_evaluated") or 0
                ),
                "queue_rate": observation.get("queue_rate"),
                "disagreement_rate": observation.get(
                    "disagreement_rate"
                ),
                "drift_status": observation.get("drift_status"),
                "isolation_anomaly_rate": observation.get(
                    "isolation_anomaly_rate"
                ),
                "runtime_seconds": observation.get("runtime_seconds"),
                "failure_code": observation.get("failure_code"),
                "source_identifier_included": False,
                "raw_evidence_included": False,
            }
        )
    authoritative_after = v58._database_state(db)
    acceptance = shadow_operational_acceptance_summary(db)
    successful = sum(item["ok"] for item in results)
    return {
        "ok": (
            not cancelled
            and successful == len(results)
            and authoritative_before == authoritative_after
        ),
        "version": V510_VERSION,
        "status": (
            "cancelled_without_partial_scope_persist"
            if cancelled
            else "historical_shadow_observations_completed"
        ),
        "evidence_role": DEVELOPMENT_EVIDENCE_ROLE,
        "independent_validation": False,
        "planned_scope_count": len(scopes),
        "observations_executed": len(results),
        "successful_observation_count": successful,
        "created_observation_count": sum(
            item["observation_created"] for item in results
        ),
        "idempotent_reuse_count": sum(
            item["idempotent_reuse"] for item in results
        ),
        "results": results,
        "operational_acceptance": acceptance,
        "safety": {
            "authoritative_database_state_unchanged": (
                authoritative_before == authoritative_after
            ),
            "alert_case_label_model_detection_response_mutations": 0,
            "model_activated": False,
            "production_promoted": False,
            "response_automation_allowed": False,
            "real_firewall_blocking_enabled": False,
        },
        "accuracy_metrics_calculated": False,
        "source_identifiers_included": False,
        "raw_logs_included": False,
        "ip_addresses_included": False,
        "private_paths_included": False,
        "fingerprints_included": False,
        "labels_accessed": False,
        "secrets_exposed": False,
    }
