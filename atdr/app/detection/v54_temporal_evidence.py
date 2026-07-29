from __future__ import annotations

import csv
import hashlib
import json
import math
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from statistics import mean
from typing import Any, Iterable

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from atdr.app.core.config import PROJECT_ROOT
from atdr.app.db.models import MLLabel
from atdr.app.detection import v398_independent_holdout_validation as frozen
from atdr.app.detection import v49_detection_ml_reliability as reliability
from atdr.app.detection import v52_shadow_reliability as v52
from atdr.app.detection import v53_temporal_generalization as v53
from atdr.app.detection.rules import build_detection_context, evaluate_rules
from atdr.app.detection.supervised_detector import supervised_model_path
from atdr.app.detection.v330_detection_ml_quality import OUTPUT_DIR
from atdr.app.parsers.paloalto_parser import parse_log_line
from atdr.app.services.private_log_preflight_service import (
    UNKNOWN_APPS,
    preflight_private_paloalto_file,
)


V54_VERSION = "v5.4-temporal-evidence-shadow-drift-v1"
V54_LATEST = "v5_4_temporal_evidence_latest.json"
V54_MANIFEST_LATEST = "v5_4_development_evidence_manifest_latest.json"
V54_REVIEW_SAMPLE = "v5_4_assisted_review_pack.csv"
V53_LOCK_PATH = (
    PROJECT_ROOT / "data" / "samples" / "benchmarks" / "v53_temporal_evidence_lock.json"
)
DEVELOPMENT_ROLES = ("fit", "calibration", "threshold")
LOCKED_ROLES = ("temporal_final", "rolling_future")
ROLE_INDEX_KEYS = {
    "fit": "fit_idx",
    "calibration": "calibration_idx",
    "threshold": "threshold_idx",
    "temporal_final": "final_test_idx",
    "quarantine": "quarantined_idx",
}
DRIFT_TV_WARNING = 0.25
DRIFT_TV_OOD = 0.50
MISSINGNESS_WARNING = 0.10
MISSINGNESS_OOD = 0.20
MIN_DRIFT_ROWS = 100
MAX_REVIEW_PACK_ROWS = 200
PRIVATE_WINDOW_TARGET = 8
LIMITED_VALUES = {"", "-", "missing", "none", "null", "unavailable"}


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _stable_hash(value: Any) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        default=str,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _file_sha256(path: Path) -> str | None:
    if not path.exists() or not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _safe_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def _safe_rate(numerator: int, denominator: int) -> float:
    return round(numerator / max(1, denominator), 6)


def _top_counts(values: Iterable[Any], *, limit: int = 12) -> list[dict[str, Any]]:
    counter = Counter(
        str(value if value is not None and str(value).strip() else "missing")
        for value in values
    )
    return [
        {"value": value, "count": int(count)}
        for value, count in counter.most_common(limit)
    ]


def _counter_top(
    counter: Counter[Any],
    *,
    limit: int = 12,
) -> list[dict[str, Any]]:
    return [
        {"value": str(value), "count": int(count)}
        for value, count in counter.most_common(limit)
    ]


def _ratios(values: Iterable[Any]) -> dict[str, float]:
    counter = Counter(
        str(value if value is not None and str(value).strip() else "missing")
        for value in values
    )
    total = max(1, sum(counter.values()))
    return {
        value: round(count / total, 6)
        for value, count in sorted(counter.items())
    }


def total_variation_distance(
    baseline: dict[str, float],
    observed: dict[str, float],
) -> float:
    keys = set(baseline) | set(observed)
    return round(
        0.5
        * sum(
            abs(float(baseline.get(key, 0.0)) - float(observed.get(key, 0.0)))
            for key in keys
        ),
        6,
    )


def classify_shadow_drift(
    *,
    observed_rows: int,
    distribution_distances: dict[str, float],
    missingness_delta: float,
    ood_rate: float | None,
    score_median_shift: float | None,
    queue_rate_delta: float | None,
) -> dict[str, Any]:
    findings: list[str] = []
    maximum_tv = max(distribution_distances.values(), default=0.0)
    if observed_rows < MIN_DRIFT_ROWS:
        return {
            "status": "Insufficient Evidence",
            "severity": "insufficient",
            "findings": [
                f"Only {observed_rows} rows are available; at least {MIN_DRIFT_ROWS} are required."
            ],
            "thresholds": {
                "minimum_rows": MIN_DRIFT_ROWS,
                "distribution_warning": DRIFT_TV_WARNING,
                "distribution_ood": DRIFT_TV_OOD,
                "missingness_warning": MISSINGNESS_WARNING,
                "missingness_ood": MISSINGNESS_OOD,
            },
        }
    for field, distance in sorted(
        distribution_distances.items(),
        key=lambda item: item[1],
        reverse=True,
    ):
        if distance >= DRIFT_TV_WARNING:
            findings.append(f"{field} distribution shift={distance:.4f}")
    if missingness_delta >= MISSINGNESS_WARNING:
        findings.append(f"missingness delta={missingness_delta:.4f}")
    if ood_rate is not None and ood_rate >= 0.10:
        findings.append(f"fit-profile OOD rate={ood_rate:.4f}")
    if score_median_shift is not None and score_median_shift >= 0.20:
        findings.append(f"score median shift={score_median_shift:.4f}")
    if queue_rate_delta is not None and queue_rate_delta >= 0.20:
        findings.append(f"review-queue rate delta={queue_rate_delta:.4f}")

    is_ood = bool(
        maximum_tv >= DRIFT_TV_OOD
        or missingness_delta >= MISSINGNESS_OOD
        or (ood_rate is not None and ood_rate >= 0.25)
    )
    is_warning = bool(
        maximum_tv >= DRIFT_TV_WARNING
        or missingness_delta >= MISSINGNESS_WARNING
        or (ood_rate is not None and ood_rate >= 0.10)
        or (score_median_shift is not None and score_median_shift >= 0.20)
        or (queue_rate_delta is not None and queue_rate_delta >= 0.20)
    )
    status = "OOD Warning" if is_ood else "Drift Warning" if is_warning else "Stable"
    return {
        "status": status,
        "severity": "ood" if is_ood else "warning" if is_warning else "stable",
        "findings": findings[:8],
        "thresholds": {
            "minimum_rows": MIN_DRIFT_ROWS,
            "distribution_warning": DRIFT_TV_WARNING,
            "distribution_ood": DRIFT_TV_OOD,
            "missingness_warning": MISSINGNESS_WARNING,
            "missingness_ood": MISSINGNESS_OOD,
        },
    }


def _row_fingerprint(row: dict[str, Any]) -> str:
    return _stable_hash(
        {
            "label_id": row["label_id"],
            "log_id": row["log_id"],
            "original_label": row["original_label"],
            "label_source": row["label_source"],
            "exact_fingerprint": row["exact_fingerprint"],
            "feature_fingerprint": row["feature_fingerprint"],
            "timestamp": row.get("timestamp"),
        }
    )


def _role_fingerprint(
    dataset: dict[str, Any],
    indices: Iterable[int],
) -> str:
    return _stable_hash(
        [
            _row_fingerprint(dataset["rows"][index])
            for index in sorted(
                indices,
                key=lambda item: (
                    (
                        dataset["rows"][item]["timestamp"].timestamp()
                        if dataset["rows"][item].get("timestamp") is not None
                        else float("-inf")
                    ),
                    int(dataset["rows"][item]["log_id"]),
                ),
            )
        ]
    )


def _time_range(dataset: dict[str, Any], indices: Iterable[int]) -> dict[str, str | None]:
    timestamps = [
        dataset["rows"][index].get("timestamp")
        for index in indices
        if dataset["rows"][index].get("timestamp") is not None
    ]
    return {
        "earliest": min(timestamps).isoformat() if timestamps else None,
        "latest": max(timestamps).isoformat() if timestamps else None,
    }


def _role_summary(
    dataset: dict[str, Any],
    indices: list[int],
    *,
    role: str,
) -> dict[str, Any]:
    rows = [dataset["rows"][index] for index in indices]
    return {
        "role": role,
        "rows": len(indices),
        "fingerprint": _role_fingerprint(dataset, indices),
        "time_range": _time_range(dataset, indices),
        "label_distribution": dict(Counter(row["original_label"] for row in rows)),
        "provenance_distribution": dict(
            Counter(str(row.get("label_source") or "unknown") for row in rows)
        ),
        "queue_target_distribution": dict(
            Counter(str(dataset["targets"][index]) for index in indices)
        ),
        "leakage_group_count": len(
            {str(row.get("leakage_group") or "") for row in rows}
        ),
        "raw_logs_included": False,
        "private_identifiers_included": False,
    }


def _artifact_locks() -> list[dict[str, Any]]:
    state = frozen._artifact_state()
    path = supervised_model_path()
    return [
        {
            "role": "governed_supervised_artifact",
            "exists": bool(state.get("exists")),
            "artifact_name": state.get("name"),
            "size_bytes": state.get("size_bytes"),
            "sha256": _file_sha256(path),
            "path_returned": False,
        }
    ]


def _external_lock(output_dir: Path) -> dict[str, Any]:
    external = reliability._locked_external_evidence(output_dir)
    safe = {
        "available": bool(external.get("available")),
        "provider": external.get("provider"),
        "dataset": external.get("dataset"),
        "evaluated_rows": external.get("evaluated_rows"),
        "label_count": external.get("label_count"),
        "passed_v49_gates": bool(external.get("passed_v49_gates")),
        "status": external.get("status"),
    }
    return {
        **safe,
        "fingerprint": _stable_hash(safe),
        "row_level_evidence_reopened": False,
        "used_for_development": False,
    }


def build_evidence_lock(
    dataset: dict[str, Any],
    *,
    output_dir: Path,
) -> dict[str, Any]:
    partition = frozen.build_frozen_partition(
        dataset["rows"],
        split_mode="temporal_holdout",
    )
    leakage = frozen.audit_partition_leakage(dataset["rows"], partition)
    if not leakage.get("passed"):
        return {
            "ok": False,
            "status": "failed_closed",
            "reason": "canonical temporal partition did not pass leakage checks",
        }
    roles = {
        role: _role_summary(dataset, list(partition[index_key]), role=role)
        for role, index_key in ROLE_INDEX_KEYS.items()
    }
    rolling = v53.build_rolling_temporal_partitions(dataset["rows"])
    rolling_roles = []
    for item in rolling:
        if item.get("status") != "partitioned":
            rolling_roles.append(
                {
                    "role": str(item.get("split_mode")),
                    "status": "failed_closed",
                    "reason": item.get("reason"),
                }
            )
            continue
        rolling_roles.append(
            _role_summary(
                dataset,
                list(item["final_test_idx"]),
                role=str(item["split_mode"]),
            )
        )
    return {
        "ok": True,
        "version": "v5.4-evidence-lock-v1",
        "dataset_fingerprint": v53._dataset_fingerprint(dataset),
        "reviewed_latest_rows": len(dataset["rows"]),
        "temporal_partition_id": partition.get("partition_id"),
        "roles": roles,
        "rolling_future_roles": rolling_roles,
        "external_evidence": _external_lock(output_dir),
        "model_artifacts": _artifact_locks(),
        "locked_final_labels_used_for_tuning": False,
        "raw_logs_included": False,
        "private_identifiers_included": False,
    }


def _lock_projection(lock: dict[str, Any]) -> dict[str, Any]:
    return {
        "version": lock.get("version"),
        "dataset_fingerprint": lock.get("dataset_fingerprint"),
        "reviewed_latest_rows": lock.get("reviewed_latest_rows"),
        "temporal_partition_id": lock.get("temporal_partition_id"),
        "roles": {
            role: {
                "rows": (lock.get("roles") or {}).get(role, {}).get("rows"),
                "fingerprint": (lock.get("roles") or {})
                .get(role, {})
                .get("fingerprint"),
            }
            for role in ROLE_INDEX_KEYS
        },
        "rolling_future_roles": [
            {
                "role": item.get("role"),
                "rows": item.get("rows"),
                "fingerprint": item.get("fingerprint"),
            }
            for item in lock.get("rolling_future_roles") or []
        ],
        "external_evidence": {
            "available": (lock.get("external_evidence") or {}).get("available"),
            "passed_v49_gates": (lock.get("external_evidence") or {}).get(
                "passed_v49_gates"
            ),
            "fingerprint": (lock.get("external_evidence") or {}).get(
                "fingerprint"
            ),
        },
        "model_artifacts": [
            {
                "role": item.get("role"),
                "exists": item.get("exists"),
                "artifact_name": item.get("artifact_name"),
                "size_bytes": item.get("size_bytes"),
                "sha256": item.get("sha256"),
            }
            for item in lock.get("model_artifacts") or []
        ],
        "locked_final_labels_used_for_tuning": bool(
            lock.get("locked_final_labels_used_for_tuning")
        ),
        "raw_logs_included": bool(lock.get("raw_logs_included")),
        "private_identifiers_included": bool(
            lock.get("private_identifiers_included")
        ),
    }


def validate_evidence_lock(
    current: dict[str, Any],
    *,
    lock_path: Path = V53_LOCK_PATH,
) -> dict[str, Any]:
    expected = _safe_json(lock_path)
    if not expected:
        return {
            "passed": False,
            "status": "lock_manifest_missing",
            "lock_file": lock_path.name,
            "message": "Create the reviewed v5.3 lock manifest before using development evidence.",
            "secrets_exposed": False,
        }
    current_projection = _lock_projection(current)
    comparisons: dict[str, bool] = {
        "dataset_fingerprint": expected.get("dataset_fingerprint")
        == current_projection.get("dataset_fingerprint"),
        "reviewed_latest_rows": expected.get("reviewed_latest_rows")
        == current_projection.get("reviewed_latest_rows"),
        "temporal_partition_id": expected.get("temporal_partition_id")
        == current_projection.get("temporal_partition_id"),
        "external_evidence": expected.get("external_evidence")
        == current_projection.get("external_evidence"),
        "model_artifacts": expected.get("model_artifacts")
        == current_projection.get("model_artifacts"),
        "safety_flags": all(
            expected.get(name) == current_projection.get(name)
            for name in (
                "locked_final_labels_used_for_tuning",
                "raw_logs_included",
                "private_identifiers_included",
            )
        ),
    }
    expected_roles = expected.get("roles") or {}
    current_roles = current_projection.get("roles") or {}
    for role in ROLE_INDEX_KEYS:
        comparisons[f"role:{role}"] = (
            expected_roles.get(role) == current_roles.get(role)
        )
    comparisons["rolling_future_roles"] = expected.get(
        "rolling_future_roles"
    ) == current_projection.get("rolling_future_roles")
    passed = bool(comparisons) and all(comparisons.values())
    return {
        "passed": passed,
        "status": "locked_and_matched" if passed else "lock_mismatch_failed_closed",
        "lock_file": lock_path.name,
        "comparisons": comparisons,
        "mismatches": [
            name for name, comparison_passed in comparisons.items() if not comparison_passed
        ],
        "secrets_exposed": False,
    }


def _schema_bucket(log: Any) -> str:
    app = str(log.app or "").strip().lower()
    protocol = str(log.protocol or "missing").strip().lower()
    if app in UNKNOWN_APPS:
        return f"limited:{app or 'missing'}:{protocol}"
    return f"structured:{protocol}"


def _rule_evidence(log: Any) -> tuple[list[str], float]:
    matches = [
        match
        for match in evaluate_rules(log, build_detection_context([log]))
        if match.code != "ml_anomaly_detected"
    ]
    return sorted({str(match.code) for match in matches}), max(
        (float(match.score) for match in matches),
        default=0.0,
    )


def _history_audit(db: Session, log_ids: list[int]) -> dict[str, Any]:
    history_counts = list(
        db.execute(
            select(MLLabel.log_id, func.count(MLLabel.id))
            .where(MLLabel.log_id.in_(log_ids))
            .group_by(MLLabel.log_id)
        )
    )
    count_distribution = Counter(int(count) for _log_id, count in history_counts)
    latest_only = sum(1 for _log_id, count in history_counts if int(count) == 1)
    with_history = sum(1 for _log_id, count in history_counts if int(count) > 1)
    return {
        "logs_with_one_label_record": latest_only,
        "logs_with_decision_history": with_history,
        "maximum_label_rows_per_log": max(
            (int(count) for _log_id, count in history_counts),
            default=0,
        ),
        "label_rows_per_log_distribution": {
            str(count): rows for count, rows in sorted(count_distribution.items())
        },
        "latest_reviewed_label_only_used_for_evidence": True,
        "prior_decisions_used_as_training_rows": False,
    }


def _quantile_bucket(
    timestamp: datetime | None,
    boundaries: list[float],
) -> str:
    if timestamp is None:
        return "missing_time"
    value = timestamp.timestamp()
    return f"time_q{1 + sum(value >= boundary for boundary in boundaries)}"


def audit_chronological_evidence(
    db: Session,
    dataset: dict[str, Any],
    partition: dict[str, Any],
) -> dict[str, Any]:
    all_indices = list(range(len(dataset["rows"])))
    valid_timestamps = sorted(
        row["timestamp"].timestamp()
        for row in dataset["rows"]
        if row.get("timestamp") is not None
    )
    boundaries = [
        valid_timestamps[
            min(
                len(valid_timestamps) - 1,
                round((len(valid_timestamps) - 1) * fraction),
            )
        ]
        for fraction in (0.25, 0.50, 0.75)
    ] if valid_timestamps else []
    rule_rows = 0
    strong_rule_rows = 0
    rule_codes: Counter[str] = Counter()
    schema_buckets: list[str] = []
    time_buckets: list[str] = []
    review_days: Counter[str] = Counter()
    for index, (row, log, label) in enumerate(
        zip(dataset["rows"], dataset["logs"], dataset["labels"], strict=True)
    ):
        codes, score = _rule_evidence(log)
        if codes:
            rule_rows += 1
            rule_codes.update(codes)
        if score >= 70:
            strong_rule_rows += 1
        schema_buckets.append(_schema_bucket(log))
        time_buckets.append(_quantile_bucket(row.get("timestamp"), boundaries))
        created_at = getattr(label, "created_at", None)
        if isinstance(created_at, datetime):
            review_days[created_at.date().isoformat()] += 1

    roles: dict[str, Any] = {}
    for role, index_key in ROLE_INDEX_KEYS.items():
        indices = list(partition[index_key])
        rows = [dataset["rows"][index] for index in indices]
        logs = [dataset["logs"][index] for index in indices]
        roles[role] = {
            "rows": len(indices),
            "labels": _top_counts(row["original_label"] for row in rows),
            "provenance": _top_counts(row["label_source"] for row in rows),
            "applications": _top_counts(log.app for log in logs),
            "actions": _top_counts(log.action for log in logs),
            "destination_ports": _top_counts(log.dst_port for log in logs),
            "network_zones": _top_counts(
                row["network_zone_group"] for row in rows
            ),
            "schema_profiles": _top_counts(schema_buckets[index] for index in indices),
            "time_buckets": _top_counts(time_buckets[index] for index in indices),
            "source_identity_count": len(
                {str(row.get("source_name") or "unknown") for row in rows}
            ),
            "source_event_counts_ranked": [
                {"rank": rank, "rows": count}
                for rank, (_source, count) in enumerate(
                    Counter(
                        str(row.get("source_name") or "unknown") for row in rows
                    ).most_common(10),
                    start=1,
                )
            ],
        }

    fit_idx = list(partition["fit_idx"])
    final_idx = list(partition["final_test_idx"])
    distances: dict[str, float] = {}
    for field, values in {
        "label": [row["original_label"] for row in dataset["rows"]],
        "provenance": [row["label_source"] for row in dataset["rows"]],
        "application": [log.app for log in dataset["logs"]],
        "action": [log.action for log in dataset["logs"]],
        "destination_port": [log.dst_port for log in dataset["logs"]],
        "network_zone": [
            row["network_zone_group"] for row in dataset["rows"]
        ],
        "schema_profile": schema_buckets,
    }.items():
        distances[field] = total_variation_distance(
            _ratios(values[index] for index in fit_idx),
            _ratios(values[index] for index in final_idx),
        )
    duplicate_audit = frozen.assign_leakage_groups(dataset["rows"])
    problems: list[str] = []
    if distances["label"] >= DRIFT_TV_WARNING:
        problems.append("Label decisions are chronologically clustered.")
    if distances["provenance"] >= DRIFT_TV_WARNING:
        problems.append("Review provenance is chronologically clustered.")
    if distances["application"] >= DRIFT_TV_WARNING:
        problems.append("Application mix changes materially across time.")
    if roles["fit"]["source_identity_count"] < 2:
        problems.append(
            "Reviewed fit evidence contains fewer than two independent real source devices."
        )
    if duplicate_audit.get("rows_in_multirow_groups"):
        problems.append(
            "Duplicate or near-duplicate groups require role containment and quarantine."
        )
    if len(review_days) and max(review_days.values()) > len(all_indices) * 0.25:
        problems.append("Label review activity is concentrated into a small review-time cluster.")
    return {
        "rows": len(all_indices),
        "roles": roles,
        "fit_to_final_distribution_distance": distances,
        "decision_history": _history_audit(
            db,
            [int(row["log_id"]) for row in dataset["rows"]],
        ),
        "review_density": {
            "review_days": len(review_days),
            "largest_review_day_rows": max(review_days.values(), default=0),
            "top_review_day_counts": [
                {"rank": rank, "rows": count}
                for rank, (_day, count) in enumerate(
                    review_days.most_common(10),
                    start=1,
                )
            ],
            "reviewer_names_returned": False,
        },
        "rule_evidence": {
            "rows_with_rule_evidence": rule_rows,
            "rows_with_strong_rule_evidence": strong_rule_rows,
            "top_rule_codes": [
                {"code": code, "rows": count}
                for code, count in rule_codes.most_common(15)
            ],
            "rules_used_as_human_labels": False,
        },
        "duplicate_audit": duplicate_audit,
        "problems": problems,
        "raw_logs_included": False,
        "private_identifiers_included": False,
    }


def _source_token(source_name: str) -> str:
    return _stable_hash({"scope": "v5.4-source-pseudonym", "value": source_name})[:16]


def _manifest_row(
    dataset: dict[str, Any],
    index: int,
    *,
    role: str,
    selected_for_development: bool,
    exclusion_reason: str | None,
) -> dict[str, Any]:
    row = dataset["rows"][index]
    log = dataset["logs"][index]
    rule_codes, rule_score = _rule_evidence(log)
    provenance = str(row.get("label_source") or "unknown")
    human_reviewed = bool(row.get("reviewed")) and provenance in {
        "manual",
        "reviewed_import",
    }
    return {
        "row_fingerprint": _row_fingerprint(row),
        "role": role,
        "selected_for_development": selected_for_development,
        "exclusion_reason": exclusion_reason,
        "label_provenance": provenance,
        "current_reviewed_label": row["original_label"],
        "review_state": (
            "human_reviewed"
            if human_reviewed
            else "assisted_or_weak_review_record"
        ),
        "human_reviewed": human_reviewed,
        "queue_target": dataset["targets"][index],
        "event_time": row.get("timestamp").isoformat()
        if row.get("timestamp") is not None
        else None,
        "source_identity": _source_token(
            str(row.get("source_name") or "unknown_source")
        ),
        "schema_profile": _schema_bucket(log),
        "application": str(log.app or "unknown"),
        "action": str(log.action or "unknown"),
        "destination_port": log.dst_port,
        "leakage_group": _stable_hash(
            {
                "scope": "v5.4-leakage-group",
                "value": row.get("leakage_group"),
            }
        )[:16],
        "rule_evidence_present": bool(rule_codes),
        "rule_evidence_codes": rule_codes,
        "maximum_rule_score": round(rule_score, 4),
        "raw_log_included": False,
        "ip_address_included": False,
    }


def build_development_manifest(
    dataset: dict[str, Any],
    partition: dict[str, Any],
) -> dict[str, Any]:
    role_by_index: dict[int, str] = {}
    for role, index_key in ROLE_INDEX_KEYS.items():
        for index in partition[index_key]:
            role_by_index[int(index)] = role
    manifest_rows = []
    for index in range(len(dataset["rows"])):
        role = role_by_index.get(index, "unassigned")
        selected = role in DEVELOPMENT_ROLES
        exclusion_reason = None
        if role == "temporal_final":
            exclusion_reason = "locked_v5_3_temporal_final"
        elif role == "quarantine":
            exclusion_reason = "duplicate_or_near_duplicate_quarantine"
        elif role == "unassigned":
            exclusion_reason = "not_assigned_by_canonical_temporal_protocol"
        manifest_rows.append(
            _manifest_row(
                dataset,
                index,
                role=role,
                selected_for_development=selected,
                exclusion_reason=exclusion_reason,
            )
        )
    development = [
        row for row in manifest_rows if row["selected_for_development"]
    ]
    excluded = [
        row for row in manifest_rows if not row["selected_for_development"]
    ]
    development_fingerprints = {
        str(row["row_fingerprint"]) for row in development
    }
    final_fingerprints = {
        str(row["row_fingerprint"])
        for row in manifest_rows
        if row["role"] == "temporal_final"
    }
    duplicate_development = len(development) - len(development_fingerprints)
    return {
        "version": "v5.4-development-manifest-v1",
        "dataset_fingerprint": v53._dataset_fingerprint(dataset),
        "rows": manifest_rows,
        "summary": {
            "total_rows": len(manifest_rows),
            "development_rows": len(development),
            "excluded_rows": len(excluded),
            "role_counts": dict(Counter(row["role"] for row in manifest_rows)),
            "exclusion_reasons": dict(
                Counter(
                    str(row["exclusion_reason"])
                    for row in excluded
                    if row["exclusion_reason"]
                )
            ),
            "duplicate_development_row_fingerprints": duplicate_development,
            "development_final_overlap": len(
                development_fingerprints & final_fingerprints
            ),
            "development_human_reviewed_rows": sum(
                1 for row in development if row["human_reviewed"]
            ),
            "development_assisted_or_weak_rows": sum(
                1 for row in development if not row["human_reviewed"]
            ),
            "locked_final_rows_used_for_development": False,
            "external_evidence_used_for_development": False,
            "raw_logs_included": False,
            "private_identifiers_included": False,
        },
    }


def _review_pattern(log: Any, rule_codes: list[str]) -> str:
    app = str(log.app or "").strip().lower()
    protocol = str(log.protocol or "").strip().lower()
    action = str(log.action or "").strip().lower()
    if app in {"quic", "quic-base"} and log.dst_port == 443:
        return "quic_443"
    if app == "incomplete" and action == "allow" and log.dst_port == 80:
        return "incomplete_allow_80"
    if app in {"unknown", "unknown-tcp", "unknown-udp"}:
        return f"unknown_{protocol or 'protocol'}"
    if str(log.log_type or "").upper() == "THREAT":
        return "panos_threat_record"
    if any("scan" in code for code in rule_codes):
        return "scan_like_rule_evidence"
    if action == "allow" and not rule_codes:
        return "routine_allow_no_rule"
    return "other_ambiguous"


def build_assisted_review_pack(
    dataset: dict[str, Any],
    manifest: dict[str, Any],
    *,
    limit: int = MAX_REVIEW_PACK_ROWS,
) -> list[dict[str, Any]]:
    index_by_fingerprint = {
        _row_fingerprint(row): index
        for index, row in enumerate(dataset["rows"])
    }
    buckets: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in manifest["rows"]:
        if not item["selected_for_development"]:
            continue
        index = index_by_fingerprint[str(item["row_fingerprint"])]
        log = dataset["logs"][index]
        rule_codes = list(item["rule_evidence_codes"])
        pattern = _review_pattern(log, rule_codes)
        suggestion = (
            "review_threat_evidence"
            if rule_codes
            else "review_benign_context"
            if pattern in {"quic_443", "routine_allow_no_rule"}
            else "retain_needs_context_until_verified"
        )
        buckets[pattern].append(
            {
                "row_fingerprint": item["row_fingerprint"],
                "development_role": item["role"],
                "evidence_pattern": pattern,
                "current_reviewed_label": item["current_reviewed_label"],
                "label_provenance": item["label_provenance"],
                "application": item["application"],
                "action": item["action"],
                "destination_port": item["destination_port"],
                "schema_profile": item["schema_profile"],
                "rule_evidence_present": item["rule_evidence_present"],
                "rule_evidence_codes": "|".join(rule_codes),
                "assisted_suggestion": suggestion,
                "suggestion_source": "deterministic_evidence_triage",
                "suggestion_is_weak": True,
                "human_must_confirm": True,
                "human_reviewed": False,
                "import_ready": False,
                "raw_log_included": False,
                "ip_address_included": False,
            }
        )
    selected: list[dict[str, Any]] = []
    pattern_names = sorted(buckets)
    while len(selected) < limit and any(buckets.values()):
        for pattern in pattern_names:
            if buckets[pattern] and len(selected) < limit:
                selected.append(buckets[pattern].pop(0))
    return selected


def _write_review_pack(path: Path, rows: list[dict[str, Any]]) -> None:
    if not rows:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def _private_window_id(position: int) -> str:
    return f"private-window-{position:02d}"


def inspect_private_temporal_regimes(
    path: Path,
    *,
    current_database_url: str | None = None,
    max_lines: int | None = None,
) -> dict[str, Any]:
    preflight = preflight_private_paloalto_file(
        path,
        current_database_url=current_database_url,
        max_lines=max_lines,
    )
    if not preflight.get("ok"):
        return {
            "ok": False,
            "status": "private_evidence_unavailable",
            "preflight": preflight,
            "path_returned": False,
            "raw_evidence_returned": False,
            "private_identifiers_returned": False,
            "secrets_exposed": False,
        }
    time_buckets: dict[str, dict[str, Any]] = defaultdict(
        lambda: {
            "rows": 0,
            "apps": Counter(),
            "actions": Counter(),
            "protocols": Counter(),
            "log_types": Counter(),
            "schema": Counter(),
            "unknown_apps": 0,
            "parser_errors": 0,
            "missing_core": 0,
        }
    )
    untimed_rows = 0
    observed = 0
    with path.open("r", encoding="utf-8", errors="replace", newline="") as stream:
        for line in stream:
            if max_lines is not None and observed >= max(0, int(max_lines)):
                break
            if not line.strip():
                continue
            observed += 1
            parsed = parse_log_line(line.rstrip("\r\n"))
            normalized = parsed.normalized
            event_time = (
                normalized.get("generated_time")
                or normalized.get("receive_time")
                or normalized.get("high_res_timestamp")
                or parsed.syslog_timestamp
            )
            if not isinstance(event_time, datetime):
                untimed_rows += 1
                continue
            bucket_key = event_time.replace(
                second=0,
                microsecond=0,
                tzinfo=None,
            ).isoformat()
            bucket = time_buckets[bucket_key]
            bucket["rows"] += 1
            app = str(normalized.get("app") or "missing").strip().lower()
            action = str(normalized.get("action") or "missing").strip().lower()
            protocol = str(normalized.get("protocol") or "missing").strip().lower()
            log_type = str(normalized.get("log_type") or "missing").upper()
            schema = f"{log_type}:{int(parsed.parsed_json.get('field_count') or 0)}"
            bucket["apps"][app] += 1
            bucket["actions"][action] += 1
            bucket["protocols"][protocol] += 1
            bucket["log_types"][log_type] += 1
            bucket["schema"][schema] += 1
            if app in UNKNOWN_APPS:
                bucket["unknown_apps"] += 1
            if parsed.error:
                bucket["parser_errors"] += 1
            if any(
                normalized.get(field) in {None, ""}
                for field in ("app", "action", "src_zone", "dst_zone", "dst_port")
            ):
                bucket["missing_core"] += 1

    ordered_keys = sorted(time_buckets)
    if not ordered_keys:
        return {
            "ok": True,
            "status": "insufficient_timed_evidence",
            "preflight": preflight,
            "rows_observed": observed,
            "timed_rows": 0,
            "untimed_rows": untimed_rows,
            "windows": [],
            "path_returned": False,
            "raw_evidence_returned": False,
            "private_identifiers_returned": False,
            "secrets_exposed": False,
        }
    window_count = min(PRIVATE_WINDOW_TARGET, len(ordered_keys))
    keys_per_window = math.ceil(len(ordered_keys) / window_count)
    windows = []
    for position, start in enumerate(
        range(0, len(ordered_keys), keys_per_window),
        start=1,
    ):
        window_keys = ordered_keys[start : start + keys_per_window]
        aggregate = {
            "rows": 0,
            "apps": Counter(),
            "actions": Counter(),
            "protocols": Counter(),
            "log_types": Counter(),
            "schema": Counter(),
            "unknown_apps": 0,
            "parser_errors": 0,
            "missing_core": 0,
        }
        for key in window_keys:
            source = time_buckets[key]
            aggregate["rows"] += int(source["rows"])
            for counter_name in (
                "apps",
                "actions",
                "protocols",
                "log_types",
                "schema",
            ):
                aggregate[counter_name].update(source[counter_name])
            for count_name in (
                "unknown_apps",
                "parser_errors",
                "missing_core",
            ):
                aggregate[count_name] += int(source[count_name])
        row_count = int(aggregate["rows"])
        windows.append(
            {
                "window_id": _private_window_id(position),
                "start_time": window_keys[0],
                "end_time": window_keys[-1],
                "rows": row_count,
                "applications": _counter_top(aggregate["apps"]),
                "actions": _counter_top(aggregate["actions"]),
                "protocols": _counter_top(aggregate["protocols"]),
                "log_types": _counter_top(aggregate["log_types"]),
                "schema_variants": _counter_top(aggregate["schema"]),
                "unknown_app_rate": _safe_rate(
                    int(aggregate["unknown_apps"]),
                    row_count,
                ),
                "parser_error_rate": _safe_rate(
                    int(aggregate["parser_errors"]),
                    row_count,
                ),
                "core_missing_rate": _safe_rate(
                    int(aggregate["missing_core"]),
                    row_count,
                ),
            }
        )
    return {
        "ok": True,
        "status": "private_temporal_preflight_complete",
        "preflight": preflight,
        "rows_observed": observed,
        "timed_rows": observed - untimed_rows,
        "untimed_rows": untimed_rows,
        "minute_buckets": len(ordered_keys),
        "windows": windows,
        "accuracy_labels_available": False,
        "development_labels_created": False,
        "path_returned": False,
        "raw_evidence_returned": False,
        "private_identifiers_returned": False,
        "secrets_exposed": False,
    }


def _distribution_from_top(rows: list[dict[str, Any]]) -> dict[str, float]:
    counts = {
        str(row.get("value")): int(row.get("count") or 0)
        for row in rows
    }
    total = max(1, sum(counts.values()))
    return {
        key: round(value / total, 6)
        for key, value in sorted(counts.items())
    }


def build_shadow_drift(
    dataset: dict[str, Any],
    partition: dict[str, Any],
    temporal_diagnosis: dict[str, Any],
    *,
    private_evidence: dict[str, Any] | None,
) -> dict[str, Any]:
    fit_idx = list(partition["fit_idx"])
    final_idx = list(partition["final_test_idx"])
    fit_logs = [dataset["logs"][index] for index in fit_idx]
    final_logs = [dataset["logs"][index] for index in final_idx]
    fit_schema = [_schema_bucket(log) for log in fit_logs]
    final_schema = [_schema_bucket(log) for log in final_logs]
    distances = {
        "application": total_variation_distance(
            _ratios(log.app for log in fit_logs),
            _ratios(log.app for log in final_logs),
        ),
        "action": total_variation_distance(
            _ratios(log.action for log in fit_logs),
            _ratios(log.action for log in final_logs),
        ),
        "provenance": total_variation_distance(
            _ratios(dataset["rows"][index]["label_source"] for index in fit_idx),
            _ratios(dataset["rows"][index]["label_source"] for index in final_idx),
        ),
        "schema": total_variation_distance(
            _ratios(fit_schema),
            _ratios(final_schema),
        ),
    }
    missingness = temporal_diagnosis.get("missingness") or {}
    missingness_delta = abs(
        float(missingness.get("final_rate") or 0.0)
        - float(missingness.get("fit_rate") or 0.0)
    )
    threshold = temporal_diagnosis.get("threshold_behavior") or {}
    threshold_scores = threshold.get("threshold_scores") or {}
    final_scores = threshold.get("final_scores") or {}
    score_shift = abs(
        float(final_scores.get("median") or 0.0)
        - float(threshold_scores.get("median") or 0.0)
    )
    queue_delta = abs(
        float(threshold.get("final_test_queue_prevalence") or 0.0)
        - float(threshold.get("threshold_partition_queue_prevalence") or 0.0)
    )
    ood = temporal_diagnosis.get("ood") or {}
    classification = classify_shadow_drift(
        observed_rows=len(final_idx),
        distribution_distances=distances,
        missingness_delta=missingness_delta,
        ood_rate=float(ood.get("ood_rate") or 0.0),
        score_median_shift=score_shift,
        queue_rate_delta=queue_delta,
    )
    private_summary: dict[str, Any] = {
        "available": False,
        "status": "Insufficient Evidence",
        "reason": "No private sample path was supplied for this run.",
    }
    if private_evidence and private_evidence.get("ok"):
        windows = list(private_evidence.get("windows") or [])
        private_summary = {
            "available": True,
            "status": "aggregate_temporal_windows_available",
            "rows": int(private_evidence.get("rows_observed") or 0),
            "window_count": len(windows),
            "window_findings": [
                {
                    "window_id": window.get("window_id"),
                    "rows": window.get("rows"),
                    "unknown_app_rate": window.get("unknown_app_rate"),
                    "parser_error_rate": window.get("parser_error_rate"),
                    "core_missing_rate": window.get("core_missing_rate"),
                    "application_distance_from_fit": total_variation_distance(
                        _ratios(log.app for log in fit_logs),
                        _distribution_from_top(
                            list(window.get("applications") or [])
                        ),
                    ),
                }
                for window in windows
            ],
            "ground_truth_available": False,
            "used_for_accuracy_claims": False,
            "path_returned": False,
            "raw_logs_included": False,
            "private_identifiers_included": False,
        }
    return {
        **classification,
        "baseline_role": "v5.3 governed fit partition",
        "observed_role": "v5.3 locked temporal final shadow observation",
        "observed_rows": len(final_idx),
        "distribution_distances": distances,
        "missingness_delta": round(missingness_delta, 6),
        "fit_profile_ood_rate": ood.get("ood_rate"),
        "score_median_shift": round(score_shift, 6),
        "queue_rate_delta": round(queue_delta, 6),
        "private_evidence": private_summary,
        "raw_logs_included": False,
        "private_identifiers_included": False,
    }


def _render_report(result: dict[str, Any]) -> str:
    audit = result.get("chronological_audit") or {}
    manifest = result.get("development_manifest") or {}
    summary = manifest.get("summary") or {}
    drift = result.get("shadow_drift") or {}
    evidence_lock = result.get("evidence_lock") or {}
    lines = [
        "# v5.4 Temporal Evidence And Shadow Drift",
        "",
        f"- Generated: {result.get('generated_at')}",
        f"- Lifecycle: {result.get('lifecycle_state')}",
        f"- Evidence lock: {(evidence_lock.get('validation') or {}).get('status')}",
        f"- Development rows: {summary.get('development_rows', 0)}",
        f"- Excluded rows: {summary.get('excluded_rows', 0)}",
        f"- Shadow drift: {drift.get('status')}",
        "",
        "## Chronological Evidence Problems",
        "",
    ]
    for problem in audit.get("problems") or ["No material problem detected."]:
        lines.append(f"- {problem}")
    lines.extend(
        [
            "",
            "## Evidence Roles",
            "",
            "| Role | Rows | Purpose |",
            "| --- | ---: | --- |",
        ]
    )
    for role, count in (summary.get("role_counts") or {}).items():
        purpose = (
            "fixed development role"
            if role in DEVELOPMENT_ROLES
            else "locked evaluation"
            if role == "temporal_final"
            else "duplicate containment"
        )
        lines.append(f"| {role} | {count} | {purpose} |")
    lines.extend(
        [
            "",
            "## Shadow Drift",
            "",
            f"- Status: {drift.get('status')}",
        ]
    )
    for finding in drift.get("findings") or []:
        lines.append(f"- {finding}")
    lines.extend(
        [
            "",
            "## Safety",
            "",
            "- Locked temporal-final and rolling evidence was not used for development.",
            "- External locked labels were not reopened or tuned against.",
            "- No label, model run, model artifact, detection run, or response action was created.",
            "- Any review pack is assisted, weak, not human-reviewed, and not import-ready.",
            "- Private evidence output contains aggregates only, without paths, raw logs, IPs, or secrets.",
        ]
    )
    return "\n".join(lines) + "\n"


def run_v54_temporal_evidence_preparation(
    db: Session,
    *,
    output_dir: str | Path = OUTPUT_DIR,
    min_samples: int = 100,
    lock_path: str | Path = V53_LOCK_PATH,
    private_evidence: dict[str, Any] | None = None,
    write_output: bool = True,
    write_review_pack: bool = True,
) -> dict[str, Any]:
    started = time.perf_counter()
    output = Path(output_dir)
    before_counts = frozen._database_counts(db)
    before_artifact = frozen._artifact_state()
    dataset = v52._prepare_dataset(db, min_samples=min_samples)
    if not dataset.get("ok"):
        return {
            "ok": False,
            "status": dataset.get("status", "failed_closed"),
            "message": dataset.get("message"),
            "version": V54_VERSION,
            "lifecycle_state": "shadow_observation",
        }
    partition = frozen.build_frozen_partition(
        dataset["rows"],
        split_mode="temporal_holdout",
    )
    leakage = frozen.audit_partition_leakage(dataset["rows"], partition)
    if not leakage.get("passed"):
        return {
            "ok": False,
            "status": "failed_closed",
            "message": "Canonical temporal evidence failed leakage containment.",
            "version": V54_VERSION,
            "lifecycle_state": "shadow_observation",
        }
    evidence_lock = build_evidence_lock(dataset, output_dir=output)
    lock_validation = validate_evidence_lock(
        evidence_lock,
        lock_path=Path(lock_path),
    )
    manifest = build_development_manifest(dataset, partition)
    audit = audit_chronological_evidence(db, dataset, partition)
    temporal_diagnosis = v53.diagnose_temporal_failure(dataset)
    drift = build_shadow_drift(
        dataset,
        partition,
        temporal_diagnosis,
        private_evidence=private_evidence,
    )
    review_rows = build_assisted_review_pack(
        dataset,
        manifest,
        limit=MAX_REVIEW_PACK_ROWS,
    ) if write_review_pack else []

    after_counts = frozen._database_counts(db)
    after_artifact = frozen._artifact_state()
    safety = {
        "database_counts_before": before_counts,
        "database_counts_after": after_counts,
        "database_counts_unchanged": before_counts == after_counts,
        "active_artifact_before": before_artifact,
        "active_artifact_after": after_artifact,
        "active_artifact_unchanged": before_artifact == after_artifact,
        "labels_created": after_counts["ml_labels"] - before_counts["ml_labels"],
        "model_runs_created": after_counts["ml_model_runs"]
        - before_counts["ml_model_runs"],
        "detection_runs_created": after_counts["detection_runs"]
        - before_counts["detection_runs"],
        "response_actions_created": after_counts["response_actions"]
        - before_counts["response_actions"],
        "model_activated": False,
        "model_promoted": False,
        "active_model_artifact_written": False,
        "automatic_response_enabled": False,
        "real_firewall_blocking_enabled": False,
    }
    lock_passed = bool(lock_validation.get("passed"))
    manifest_safe = bool(
        (manifest.get("summary") or {}).get("development_final_overlap") == 0
        and (manifest.get("summary") or {}).get(
            "duplicate_development_row_fingerprints"
        )
        == 0
    )
    safety_passed = bool(
        safety["database_counts_unchanged"]
        and safety["active_artifact_unchanged"]
        and safety["labels_created"] == 0
        and safety["model_runs_created"] == 0
        and safety["detection_runs_created"] == 0
        and safety["response_actions_created"] == 0
    )
    result = {
        "ok": bool(lock_passed and manifest_safe and safety_passed),
        "status": "completed_read_only_evidence_preparation"
        if lock_passed
        else "failed_closed_evidence_lock",
        "version": V54_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "lifecycle_state": "shadow_observation",
        "evidence_lock": {
            "current": evidence_lock,
            "validation": lock_validation,
        },
        "chronological_audit": audit,
        "development_manifest": {
            "summary": manifest["summary"],
            "written_to_ignored_output": write_output,
            "row_level_manifest_returned": False,
        },
        "shadow_drift": drift,
        "independent_labeled_evidence": {
            "sufficient": False,
            "real_source_device_count": int(
                (audit.get("roles") or {})
                .get("fit", {})
                .get("source_identity_count", 0)
            ),
            "minimum_real_source_devices": 2,
            "locked_external_passed": bool(
                (evidence_lock.get("external_evidence") or {}).get(
                    "passed_v49_gates"
                )
            ),
            "reason": (
                "Reviewed evidence does not yet provide two independent real devices "
                "and the locked external benchmark remains failed."
            ),
        },
        "assisted_review_pack": {
            "generated": bool(review_rows and write_output and write_review_pack),
            "rows": len(review_rows),
            "human_reviewed": False,
            "import_ready": False,
            "suggestions_are_weak": True,
            "human_must_confirm": True,
            "file_name": V54_REVIEW_SAMPLE if review_rows else None,
        },
        "readiness": {
            "decision": "shadow_observation",
            "candidate_selected": False,
            "eligible_for_activation": False,
            "production_promoted": False,
            "response_automation_allowed": False,
            "rules_alert_authoritative": True,
            "blockers": [
                "Temporal and rolling false-positive rates remain unacceptable.",
                "Independent reviewed evidence from at least two real devices is unavailable.",
                "The locked external benchmark remains failed.",
                "v5.4 curates evidence and monitors drift; it does not repair or select a model.",
            ],
        },
        "private_evidence": {
            "supplied": bool(private_evidence),
            "status": (private_evidence or {}).get("status"),
            "rows_observed": (private_evidence or {}).get("rows_observed"),
            "windows": len((private_evidence or {}).get("windows") or []),
            "ground_truth_available": False,
            "path_returned": False,
            "raw_evidence_returned": False,
            "private_identifiers_returned": False,
            "secrets_exposed": False,
        },
        "safety": safety,
        "runtime_seconds": round(time.perf_counter() - started, 4),
    }
    if write_output:
        output.mkdir(parents=True, exist_ok=True)
        stamp = _stamp()
        report_path = output / f"v5_4_temporal_evidence_{stamp}.md"
        latest_path = output / V54_LATEST
        manifest_path = output / V54_MANIFEST_LATEST
        review_path = output / V54_REVIEW_SAMPLE
        manifest_path.write_text(
            json.dumps(manifest, indent=2, default=str),
            encoding="utf-8",
        )
        if write_review_pack:
            _write_review_pack(review_path, review_rows)
        result["reports"] = {
            "markdown_file_name": report_path.name,
            "latest_json_file_name": latest_path.name,
            "manifest_file_name": manifest_path.name,
            "review_pack_file_name": review_path.name if review_rows else None,
            "ignored_output": True,
            "private_path_returned": False,
        }
        report_path.write_text(_render_report(result), encoding="utf-8")
        latest_path.write_text(
            json.dumps(result, indent=2, default=str),
            encoding="utf-8",
        )
    return result
