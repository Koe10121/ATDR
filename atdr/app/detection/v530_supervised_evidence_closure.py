from __future__ import annotations

import json
import random
import re
from collections import Counter, defaultdict
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from atdr.app.core.config import PROJECT_ROOT
from atdr.app.db.models import Alert, DetectionRun, MLLabel, MLModelRun, NormalizedLog, ResponseAction
from atdr.app.detection import v398_independent_holdout_validation as frozen
from atdr.app.detection import v521_native_panos_evidence as v521
from atdr.app.detection.supervised_detector import TRAINABLE_LABELS, _latest_labels, _log_timestamp
from atdr.app.detection.v51_supervised_lifecycle import score_governed_supervised_logs
from atdr.app.detection.v528_supervised_readiness import run_v528_supervised_readiness_audit


V530_VERSION = "v5.30-supervised-evidence-closure-v1"
DEFAULT_OUTPUT_DIR = PROJECT_ROOT / "ml_baseline_reviews"
V530_LATEST = "v5_30_supervised_evidence_closure_latest.json"
HUMAN_PROVENANCE = {"manual", "reviewed_import"}
QUEUE_POSITIVE_LABELS = {"needs_context", "suspicious", "malicious"}
RANDOM_SEEDS = (7, 17, 42)

# Fixed before v5.30 reads any outcome metrics. Quality values reuse the locked
# v5.19 transfer gates plus the existing class-recall development gates.
FIXED_PROMOTION_GATES: dict[str, float | int] = {
    "minimum_independent_human_blind_labels": 20,
    "minimum_independent_comparable_rows": 1_000,
    "minimum_rows_per_binary_class": 100,
    "minimum_real_source_identities": 2,
    "minimum_independent_time_windows": 2,
    "queue_f1_min": 0.85,
    "threat_recall_min": 0.80,
    "benign_like_false_positive_rate_max": 0.05,
    "suspicious_recall_min": 0.70,
    "malicious_recall_min": 0.70,
    "expected_calibration_error_max": 0.10,
    "max_confidence_accuracy_gap_max": 0.15,
}


def _stamp() -> str:
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")


def _database_state(db: Session) -> dict[str, int]:
    return {
        "labels": int(db.scalar(select(func.count(MLLabel.id))) or 0),
        "model_runs": int(db.scalar(select(func.count(MLModelRun.id))) or 0),
        "alerts": int(db.scalar(select(func.count(Alert.id))) or 0),
        "detection_runs": int(db.scalar(select(func.count(DetectionRun.id))) or 0),
        "response_actions": int(db.scalar(select(func.count(ResponseAction.id))) or 0),
    }


def _load_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def _safe_number(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _markdown_metric(text: str, label: str) -> float | int | str | None:
    match = re.search(rf"^- {re.escape(label)}: `([^`]*)`$", text, re.MULTILINE)
    if not match:
        return None
    value = match.group(1)
    if value in {"None", "null", ""}:
        return None
    try:
        numeric = float(value)
    except ValueError:
        return value
    return int(numeric) if numeric.is_integer() else numeric


def _external_transfer_diagnostic(output_dir: Path) -> dict[str, Any]:
    reports = sorted(output_dir.glob("v5_19_independent_labeled_validation_adapter_recovery_*.md"))
    if not reports:
        return {
            "available": False,
            "status": "external_transfer_diagnostic_unavailable",
            "promotion_evidence": False,
        }
    try:
        text = reports[-1].read_text(encoding="utf-8")
    except OSError:
        return {
            "available": False,
            "status": "external_transfer_diagnostic_unreadable",
            "promotion_evidence": False,
        }
    return {
        "available": True,
        "status": _markdown_metric(text, "Status"),
        "schema_family": "external_cross_schema_flow_evidence",
        "comparable_rows": _markdown_metric(text, "Comparable rows"),
        "excluded_ambiguous_rows": _markdown_metric(text, "Excluded ambiguous rows"),
        "queue_precision": _markdown_metric(text, "Threat-positive precision"),
        "queue_recall": _markdown_metric(text, "Threat-positive recall"),
        "queue_f1": _markdown_metric(text, "Threat-positive F1"),
        "benign_like_false_positive_rate": _markdown_metric(text, "Benign-like FPR"),
        "calibration_status": _markdown_metric(text, "Calibration"),
        "binary_transfer_gate_passed": _markdown_metric(text, "Binary transfer gate") == "True",
        "native_panos_evidence": False,
        "promotion_evidence": False,
    }


def _synthetic_scenario_inventory() -> dict[str, Any]:
    scenario_dir = PROJECT_ROOT / "data" / "samples" / "scenarios"
    files = sorted(scenario_dir.glob("*.txt")) if scenario_dir.is_dir() else []
    rows = 0
    for path in files:
        try:
            rows += sum(1 for line in path.read_text(encoding="utf-8").splitlines() if line.strip())
        except OSError:
            continue
    return {
        "scenario_files": len(files),
        "nonblank_synthetic_rows": rows,
        "safe_tracked_samples": True,
        "human_ground_truth": False,
        "supervised_promotion_evidence": False,
        "paths_returned": False,
    }


def _label_inventory(db: Session) -> tuple[dict[str, Any], list[MLLabel]]:
    latest = _latest_labels(db)
    all_trainable = list(db.scalars(select(MLLabel).where(MLLabel.label.in_(TRAINABLE_LABELS))))
    history_counts = Counter(int(label.log_id) for label in all_trainable)
    source_distribution = Counter(str(label.label_source or "unknown") for label in latest)
    label_distribution = Counter(str(label.label) for label in latest)
    reviewed_distribution = Counter(str(label.label) for label in latest if label.reviewed)
    genuine = [
        label
        for label in latest
        if bool(label.reviewed) and str(label.label_source or "") in HUMAN_PROVENANCE
    ]
    assisted = [label for label in latest if label not in genuine]
    assisted_reviewed = [
        label
        for label in latest
        if bool(label.reviewed) and str(label.label_source or "").startswith("assisted")
    ]
    reviewer_assistance_tokens = ("codex", "gemini", "assistant", "automated", "weak_label")
    suspicious_human_authorship = sum(
        1
        for label in genuine
        if any(token in str(label.reviewer or "").lower() for token in reviewer_assistance_tokens)
    )

    source_ids: Counter[int | None] = Counter()
    source_types: Counter[str] = Counter()
    timestamps: list[datetime] = []
    for label in latest:
        log = label.log
        raw = log.raw_log if log is not None else None
        source = raw.source if raw is not None else None
        source_ids[getattr(raw, "source_id", None)] += 1
        source_types[str(getattr(source, "source_type", None) or "unlinked")] += 1
        timestamp = _log_timestamp(log) if log is not None else None
        if timestamp is not None:
            timestamps.append(timestamp)

    return (
        {
            "total_label_rows": int(db.scalar(select(func.count(MLLabel.id))) or 0),
            "latest_trainable_rows": len(latest),
            "superseded_trainable_rows": sum(max(0, count - 1) for count in history_counts.values()),
            "logs_with_multiple_trainable_history_rows": sum(1 for count in history_counts.values() if count > 1),
            "one_latest_trainable_label_per_log": all(count == 1 for count in history_counts.values()),
            "label_distribution": dict(sorted(label_distribution.items())),
            "label_source_distribution": dict(sorted(source_distribution.items())),
            "reviewed_label_distribution": dict(sorted(reviewed_distribution.items())),
            "genuine_human_reviewed_rows": len(genuine),
            "assisted_or_weak_rows": len(assisted),
            "assisted_rows_with_reviewed_flag": len(assisted_reviewed),
            "assisted_rows_counted_as_genuine_human": 0,
            "human_authorship_name_flags": suspicious_human_authorship,
            "rule_derived_rows": int(source_distribution.get("assisted_rule", 0)),
            "ml_assisted_rows": int(source_distribution.get("assisted_ml", 0)),
            "hybrid_assisted_rows": int(source_distribution.get("assisted_hybrid", 0)),
            "real_source_identity_count": len([source_id for source_id in source_ids if source_id is not None]),
            "rows_without_source_identity": int(source_ids.get(None, 0)),
            "source_type_distribution": dict(sorted(source_types.items())),
            "timestamped_rows": len(timestamps),
            "distinct_calendar_days": len({timestamp.date().isoformat() for timestamp in timestamps}),
            "private_identifiers_returned": False,
            "reviewer_identities_returned": False,
        },
        genuine,
    )


def _lock_audit(output_dir: Path) -> dict[str, Any]:
    v519_state = _load_json(output_dir / "v5_19_blind_evaluation_state.json")
    v520 = _load_json(output_dir / "v5_20_schema_aware_abstention_latest.json")
    v521_result = _load_json(output_dir / v521.V521_RESULT_LATEST)
    v522 = _load_json(output_dir / "v5_22_supervised_model_rebuild_latest.json")
    v526 = _load_json(output_dir / "v5_26_native_blind_qualification_latest.json")
    v527 = _load_json(output_dir / "v5_27_blind_review_evaluation_latest.json")

    v520_lock = v520.get("v519_terminal_lock") or {}
    v522_sampling = v522.get("sampling") or {}
    v522_comparison = v522.get("supervised_development_comparison") or {}
    v522_candidate = v522.get("frozen_shadow_candidate") or {}
    v526_labels = v526.get("label_audit") or {}
    v527_intake = v527.get("review_intake") or {}
    checks = {
        "v519_predictions_frozen_before_labels": v519_state.get("predictions_frozen_before_labels") is True,
        "v519_labels_not_used_for_tuning": v519_state.get("labels_used_for_tuning") is False,
        "v519_no_post_reveal_candidate_changes": v519_state.get("post_reveal_candidate_changes") is False,
        "v520_terminal_lock_present": v520_lock.get("locked") is True,
        "v521_duplicate_families_contained": v521_result.get("duplicate_families_contained") is True,
        "v521_cross_role_exact_overlap_zero": int(v521_result.get("exact_family_cross_role_count") or 0) == 0,
        "v521_cross_role_near_overlap_zero": int(v521_result.get("near_family_cross_role_count") or 0) == 0,
        "v522_future_role_not_sampled": v522_sampling.get("future_role_sampled") is False,
        "v522_locked_labels_not_used_for_selection": v522_comparison.get("locked_v53_labels_used_for_selection") is False,
        "v522_future_labels_not_used_for_selection": v522_comparison.get("future_validation_labels_used_for_selection") is False,
        "v522_blind_labels_not_used_for_selection": v522_candidate.get("blind_labels_used_for_selection") is False,
        "v526_prediction_frozen_before_label_access": v526.get("prediction_frozen_before_label_access") is True,
        "v526_assisted_not_counted_as_human": int(v526_labels.get("assisted_or_weak_labels_counted_as_human") or 0) == 0,
        "v527_blindness_not_compromised": v527_intake.get("blindness_compromised") is False,
        "v527_predictions_not_rerun": v527_intake.get("predictions_rerun") is False,
    }
    return {
        "status": "passed" if checks and all(checks.values()) else "failed_closed",
        "checks": checks,
        "checks_passed": sum(1 for passed in checks.values() if passed),
        "checks_total": len(checks),
        "locked_holdout_tuning_detected": not all(checks.values()),
        "fingerprints_compared_privately": True,
        "fingerprints_returned": False,
        "paths_returned": False,
    }


def _historical_evidence(output_dir: Path) -> dict[str, Any]:
    v521_result = _load_json(output_dir / v521.V521_RESULT_LATEST)
    v522 = _load_json(output_dir / "v5_22_supervised_model_rebuild_latest.json")
    v526 = _load_json(output_dir / "v5_26_native_blind_qualification_latest.json")
    v527 = _load_json(output_dir / "v5_27_blind_review_evaluation_latest.json")
    roles = v521_result.get("evidence_roles") or {}
    source = v521_result.get("source_evidence") or {}
    review_packs = v521_result.get("review_packs") or {}
    candidate = v522.get("frozen_shadow_candidate") or {}
    summary = candidate.get("summary") or {}
    label_audit = v526.get("label_audit") or {}
    intake = v527.get("review_intake") or {}

    return {
        "native_panos_unlabeled_evidence": {
            "rows": int(source.get("rows_processed") or 0),
            "parser_successes": int(source.get("parser_successes") or 0),
            "parser_failures": int(source.get("parser_failures") or 0),
            "near_duplicate_rows": int(source.get("near_duplicate_rows") or 0),
            "development_fit_rows": int((roles.get("development_fit") or {}).get("rows") or 0),
            "calibration_rows": int((roles.get("calibration") or {}).get("rows") or 0),
            "threshold_rows": int((roles.get("threshold") or {}).get("rows") or 0),
            "locked_future_rows": int((roles.get("untouched_future_validation") or {}).get("rows") or 0),
            "quarantined_rows": int((roles.get("quarantine") or {}).get("rows") or 0),
            "distinct_time_windows": int(v521_result.get("distinct_time_windows") or 0),
            "second_real_device_available": bool(
                (v521_result.get("evidence_sufficiency") or {}).get("second_real_device_available")
            ),
            "human_labels_created": int(review_packs.get("human_reviewed_rows_created") or 0),
            "used_as_human_ground_truth": False,
        },
        "sealed_native_blind_pack": {
            "rows": int(label_audit.get("rows_in_pack") or review_packs.get("blind_rows") or 0),
            "prediction_rows": int((v526.get("prediction_phase") or {}).get("rows") or 0),
            "genuine_human_labels": int(label_audit.get("genuine_human_labels") or intake.get("valid_reviewed_rows") or 0),
            "minimum_labels_for_metrics": int(label_audit.get("minimum_required") or intake.get("minimum_reviewed_rows") or 20),
            "enough_for_metrics": bool(label_audit.get("enough_for_metrics") or intake.get("enough_for_metrics")),
            "metrics_status": str((v526.get("blind_evaluation") or {}).get("status") or "withheld"),
            "predictions_frozen": v526.get("prediction_frozen_before_label_access") is True,
        },
        "frozen_v522_diagnostic_candidate": {
            "available": bool(candidate),
            "name": candidate.get("name"),
            "model_type": candidate.get("model_type"),
            "target_mode": candidate.get("target_mode"),
            "threshold": candidate.get("threshold"),
            "calibration_method": candidate.get("calibration_method"),
            "evaluated_development_views": int(summary.get("evaluated_views") or 0),
            "passing_development_views": int(summary.get("passing_views") or 0),
            "metric_ranges": summary.get("metric_ranges") or {},
            "calibration_ranges": summary.get("calibration_ranges") or {},
            "artifact_written": bool(candidate.get("active_artifact_written")),
            "eligible_for_activation": bool(candidate.get("eligible_for_activation")),
            "promotion_evidence": False,
        },
        "external_benchmark": _external_transfer_diagnostic(output_dir),
        "synthetic_controlled_evidence": _synthetic_scenario_inventory(),
        "private_paths_returned": False,
        "fingerprints_returned": False,
    }


def _row_source_id(label: MLLabel) -> int | None:
    log = label.log
    raw = log.raw_log if log is not None else None
    value = getattr(raw, "source_id", None)
    return int(value) if value is not None else None


def _diagnostic_records(labels: list[MLLabel], scored: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    rows = list(scored.get("rows") or [])
    if len(rows) != len(labels):
        return [], {
            "status": "score_row_count_mismatch",
            "expected_rows": len(labels),
            "returned_rows": len(rows),
        }
    records: list[dict[str, Any]] = []
    for label, score_row in zip(labels, rows, strict=True):
        log = label.log
        if log is None:
            continue
        timestamp = _log_timestamp(log)
        records.append(
            {
                "label": str(label.label),
                "queue_target": "needs_review" if str(label.label) in QUEUE_POSITIVE_LABELS else "non_threat",
                "prediction": (
                    "needs_review"
                    if score_row.get("queue_decision") == "needs_review"
                    else "non_threat"
                    if score_row.get("queue_decision") == "benign_like"
                    else None
                ),
                "score": _safe_number(score_row.get("queue_probability")),
                "abstained": bool(score_row.get("abstained")),
                "timestamp": timestamp,
                "source_id": _row_source_id(label),
                "exact_family": frozen._raw_fingerprint(log),
                "near_family": frozen._near_fingerprint(log),
            }
        )
    return records, {"status": "scored", "rows": len(records)}


def _metric_slice(records: list[dict[str, Any]], indices: list[int], *, status: str) -> dict[str, Any]:
    selected = [records[index] for index in indices]
    covered = [row for row in selected if not row["abstained"] and row["prediction"] is not None and row["score"] is not None]
    targets = [str(row["queue_target"]) for row in covered]
    predictions = [str(row["prediction"]) for row in covered]
    scores = [float(row["score"]) for row in covered]
    metrics = frozen._binary_metrics(targets, predictions) if covered else {}
    calibration = frozen._calibration_report(targets, scores) if covered else {"status": "missing", "passed": False}
    for label in ("suspicious", "malicious"):
        support = [row for row in covered if row["label"] == label]
        caught = sum(row["prediction"] == "needs_review" for row in support)
        metrics[f"{label}_support"] = len(support)
        metrics[f"{label}_recall"] = round(caught / len(support), 4) if support else None
    return {
        "status": status,
        "rows": len(selected),
        "covered_rows": len(covered),
        "abstained_rows": len(selected) - len(covered),
        "coverage_rate": round(len(covered) / len(selected), 4) if selected else 0.0,
        "abstention_rate": round((len(selected) - len(covered)) / len(selected), 4) if selected else 0.0,
        "metrics": metrics,
        "calibration": calibration,
        "promotion_evidence": False,
    }


def _group_sample(records: list[dict[str, Any]], seed: int, fraction: float = 0.30) -> list[int]:
    groups: dict[str, list[int]] = defaultdict(list)
    for index, row in enumerate(records):
        groups[str(row["near_family"])].append(index)
    keys = sorted(groups)
    random.Random(seed).shuffle(keys)
    target = max(1, round(len(records) * fraction))
    selected: list[int] = []
    for key in keys:
        selected.extend(groups[key])
        if len(selected) >= target:
            break
    return sorted(selected)


def _evaluate_registered_shadow(
    db: Session,
    labels: list[MLLabel],
    *,
    scorer: Callable[[Session, list[NormalizedLog]], dict[str, Any]] | None = None,
    max_rows: int = 3_000,
) -> dict[str, Any]:
    eligible = [label for label in labels if label.log is not None][: max(1, int(max_rows))]
    if not eligible:
        return {
            "available": False,
            "status": "no_genuine_human_rows_available",
            "promotion_evidence": False,
        }
    scoring = scorer or score_governed_supervised_logs
    scored = scoring(db, [label.log for label in eligible if label.log is not None])
    if not scored.get("ok"):
        return {
            "available": False,
            "status": str(scored.get("status") or "registered_shadow_scoring_unavailable"),
            "promotion_evidence": False,
        }
    records, record_status = _diagnostic_records(eligible, scored)
    if not records:
        return {
            "available": False,
            "status": record_status["status"],
            "row_contract": record_status,
            "promotion_evidence": False,
        }

    source_count = len({row["source_id"] for row in records if row["source_id"] is not None})
    calendar_days = len({row["timestamp"].date().isoformat() for row in records if row["timestamp"] is not None})
    exact_counts = Counter(str(row["exact_family"]) for row in records)
    near_counts = Counter(str(row["near_family"]) for row in records)
    near_labels: dict[str, set[str]] = defaultdict(set)
    for row in records:
        near_labels[str(row["near_family"])].add(str(row["queue_target"]))

    ordered = sorted(
        range(len(records)),
        key=lambda index: (records[index]["timestamp"] or datetime.min.replace(tzinfo=UTC), index),
    )
    temporal_start = max(0, int(len(ordered) * 0.70))
    temporal_indices = ordered[temporal_start:]
    temporal_families = {str(records[index]["near_family"]) for index in temporal_indices}
    earlier_families = {str(records[index]["near_family"]) for index in ordered[:temporal_start]}
    crossing_families = temporal_families & earlier_families
    temporal_isolated = [
        index for index in temporal_indices if str(records[index]["near_family"]) not in crossing_families
    ]

    splits: list[dict[str, Any]] = []
    temporal_status = "evaluated_diagnostic_only" if calendar_days >= 2 else "evaluated_single_day_non_independent"
    temporal = _metric_slice(records, temporal_isolated, status=temporal_status)
    temporal.update(
        {
            "name": "temporal_holdout_diagnostic",
            "duplicate_crossing_rows_quarantined": len(temporal_indices) - len(temporal_isolated),
            "independent_time_windows": calendar_days,
        }
    )
    splits.append(temporal)

    if source_count < 2:
        splits.append(
            {
                "name": "grouped_source_holdout",
                "status": "failed_closed_fewer_than_two_real_sources",
                "rows": 0,
                "source_identity_count": source_count,
                "metrics": {},
                "calibration": {"status": "withheld", "passed": False},
                "promotion_evidence": False,
            }
        )
    else:
        source_groups: dict[int, list[int]] = defaultdict(list)
        for index, row in enumerate(records):
            if row["source_id"] is not None:
                source_groups[int(row["source_id"])].append(index)
        holdout = min(source_groups, key=lambda key: (len(source_groups[key]), key))
        grouped = _metric_slice(records, source_groups[holdout], status="evaluated_diagnostic_only")
        grouped.update({"name": "grouped_source_holdout", "source_identity_count": source_count})
        splits.append(grouped)

    for seed in RANDOM_SEEDS:
        random_result = _metric_slice(records, _group_sample(records, seed), status="evaluated_diagnostic_only")
        random_result.update({"name": f"repeated_random_grouped_seed_{seed}", "seed": seed})
        splits.append(random_result)

    all_rows = _metric_slice(records, list(range(len(records))), status="evaluated_diagnostic_only")
    all_rows["name"] = "all_current_genuine_human_rows"

    return {
        "available": True,
        "status": "registered_shadow_scored_read_only",
        "registered_artifact_only": True,
        "latest_v522_candidate_rerun": False,
        "reason_latest_v522_not_rerun": "The frozen v5.22 candidate has no active artifact by design.",
        "rows_considered": len(records),
        "source_identity_count": source_count,
        "distinct_calendar_days": calendar_days,
        "duplicate_audit": {
            "exact_duplicate_groups": sum(count > 1 for count in exact_counts.values()),
            "near_duplicate_groups": sum(count > 1 for count in near_counts.values()),
            "rows_in_near_duplicate_groups": sum(count for count in near_counts.values() if count > 1),
            "near_groups_with_conflicting_queue_labels": sum(len(values) > 1 for values in near_labels.values()),
            "fingerprints_returned": False,
        },
        "all_rows_diagnostic": all_rows,
        "splits": splits,
        "training_overlap_status": "not_independently_excludable",
        "independent_validation": False,
        "promotion_evidence": False,
        "log_ids_returned": False,
        "source_identifiers_returned": False,
        "fingerprints_returned": False,
    }


def _private_sample_audit(
    sample_path: Path | None,
    *,
    use_temp_db: bool,
    inspector: Callable[..., dict[str, Any]] | None = None,
) -> dict[str, Any]:
    if sample_path is None:
        return {
            "executed": False,
            "status": "not_requested",
            "path_returned": False,
            "raw_logs_returned": False,
            "private_identifiers_returned": False,
        }
    if not use_temp_db:
        return {
            "executed": False,
            "status": "failed_closed_temp_db_acknowledgement_required",
            "path_returned": False,
            "raw_logs_returned": False,
            "private_identifiers_returned": False,
        }
    inspect = inspector or v521.run_v521_native_panos_evidence
    result = inspect(
        sample_path=sample_path,
        use_temp_db=True,
        preflight_only=True,
        write_output=False,
    )
    source = result.get("source_evidence") or {}
    roles = result.get("evidence_roles") or {}
    safety = result.get("safety") or {}
    return {
        "executed": True,
        "ok": bool(result.get("ok")),
        "status": result.get("status"),
        "rows_processed": int(source.get("rows_processed") or 0),
        "parser_successes": int(source.get("parser_successes") or 0),
        "parser_failures": int(source.get("parser_failures") or 0),
        "distinct_time_windows": int(result.get("distinct_time_windows") or 0),
        "duplicate_families_contained": bool(result.get("duplicate_families_contained")),
        "role_rows": {
            role: int((roles.get(role) or {}).get("rows") or 0)
            for role in ("development_fit", "calibration", "threshold", "untouched_future_validation", "quarantine")
        },
        "configured_database_accessed": bool(safety.get("configured_database_accessed")),
        "configured_database_written": bool(safety.get("configured_database_written")),
        "temporary_storage_disposed": bool(safety.get("disposable_index_removed")),
        "path_returned": False,
        "raw_logs_returned": False,
        "ip_addresses_returned": False,
        "private_identifiers_returned": False,
        "fingerprints_returned": False,
    }


def _promotion_decision(
    *,
    inventory: dict[str, Any],
    historical: dict[str, Any],
    locks: dict[str, Any],
    artifact_readiness: dict[str, Any],
) -> dict[str, Any]:
    blind = historical.get("sealed_native_blind_pack") or {}
    native = historical.get("native_panos_unlabeled_evidence") or {}
    external = historical.get("external_benchmark") or {}
    artifact = artifact_readiness.get("artifact_contract") or {}
    abstention = artifact_readiness.get("abstention") or {}
    independent_rows = int(external.get("comparable_rows") or 0) if external.get("binary_transfer_gate_passed") else 0
    independent_class_support = 0

    evidence_checks = {
        "one_latest_trainable_label_per_log": bool(inventory.get("one_latest_trainable_label_per_log")),
        "assisted_labels_not_counted_as_human": int(inventory.get("assisted_rows_counted_as_genuine_human") or 0) == 0,
        "evidence_locks_and_leakage_checks_passed": locks.get("status") == "passed",
        "registered_shadow_artifact_integrity": bool(artifact.get("available") and artifact.get("checksum_valid")),
        "schema_abstention_fails_closed": abstention.get("fail_closed") is True,
        "minimum_independent_human_blind_labels": int(blind.get("genuine_human_labels") or 0)
        >= int(FIXED_PROMOTION_GATES["minimum_independent_human_blind_labels"]),
        "minimum_independent_comparable_rows": independent_rows
        >= int(FIXED_PROMOTION_GATES["minimum_independent_comparable_rows"]),
        "minimum_rows_per_binary_class": independent_class_support
        >= int(FIXED_PROMOTION_GATES["minimum_rows_per_binary_class"]),
        "minimum_real_source_identities": int(inventory.get("real_source_identity_count") or 0)
        >= int(FIXED_PROMOTION_GATES["minimum_real_source_identities"]),
        "minimum_independent_time_windows": (
            int(native.get("distinct_time_windows") or 0)
            >= int(FIXED_PROMOTION_GATES["minimum_independent_time_windows"])
            and int(blind.get("genuine_human_labels") or 0) > 0
        ),
    }

    # Quality gates are deliberately not evaluated against current DB rows or
    # cross-schema failed transfer metrics. Those are diagnostics, not clean
    # promotion evidence.
    quality_checks = {
        "queue_f1": {"evaluated": False, "passed": False, "value": None},
        "threat_recall": {"evaluated": False, "passed": False, "value": None},
        "benign_like_false_positive_rate": {"evaluated": False, "passed": False, "value": None},
        "suspicious_recall": {"evaluated": False, "passed": False, "value": None},
        "malicious_recall": {"evaluated": False, "passed": False, "value": None},
        "expected_calibration_error": {"evaluated": False, "passed": False, "value": None},
        "max_confidence_accuracy_gap": {"evaluated": False, "passed": False, "value": None},
    }
    blockers = [name for name, passed in evidence_checks.items() if not passed]
    blockers.extend(f"independent_{name}_not_evaluable" for name in quality_checks)
    return {
        "decision": "shadow_observation",
        "eligible_for_activation": False,
        "production_promoted": False,
        "model_activated": False,
        "response_automation_allowed": False,
        "rules_alert_authoritative": True,
        "fixed_gates": FIXED_PROMOTION_GATES,
        "evidence_checks": evidence_checks,
        "evidence_checks_passed": sum(evidence_checks.values()),
        "evidence_checks_total": len(evidence_checks),
        "quality_checks": quality_checks,
        "quality_metrics_withheld": True,
        "quality_metrics_withheld_reason": (
            "No sufficiently supported independent native human-labeled evaluation exists. "
            "Current-label and cross-schema results remain diagnostic only."
        ),
        "blockers": blockers,
    }


def render_v530_report(report: dict[str, Any]) -> str:
    inventory = report.get("evidence_inventory") or {}
    historical = report.get("historical_evidence") or {}
    blind = historical.get("sealed_native_blind_pack") or {}
    native = historical.get("native_panos_unlabeled_evidence") or {}
    decision = report.get("promotion_readiness") or {}
    registered = report.get("registered_shadow_diagnostics") or {}
    lines = [
        "# v5.30 Supervised ML Evidence Closure",
        "",
        f"- Lifecycle decision: `{decision.get('decision')}`",
        f"- Genuine human-reviewed latest labels: `{inventory.get('genuine_human_reviewed_rows', 0)}`",
        f"- Assisted or weak latest labels: `{inventory.get('assisted_or_weak_rows', 0)}`",
        f"- Real source identities represented by configured labels: `{inventory.get('real_source_identity_count', 0)}`",
        f"- Native PAN-OS unlabeled rows locked: `{native.get('rows', 0)}`",
        f"- Sealed native blind rows: `{blind.get('rows', 0)}`",
        f"- Genuine independent blind labels: `{blind.get('genuine_human_labels', 0)}`",
        f"- Registered shadow diagnostic rows: `{registered.get('rows_considered', 0)}`",
        f"- Promotion metrics withheld: `{decision.get('quality_metrics_withheld')}`",
        "- Model activated by v5.30: `false`",
        "- Rules remain alert-authoritative: `true`",
        "- Response automation enabled: `false`",
        "",
        "## Decision",
        "",
        decision.get("quality_metrics_withheld_reason", "Independent evidence remains insufficient."),
        "",
        "## Blockers",
        "",
    ]
    blockers = decision.get("blockers") or []
    lines.extend(f"- `{blocker}`" for blocker in blockers)
    return "\n".join(lines) + "\n"


def run_v530_supervised_evidence_closure(
    db: Session,
    *,
    output_dir: Path = DEFAULT_OUTPUT_DIR,
    sample_path: Path | None = None,
    use_temp_db: bool = False,
    evaluate_registered_shadow: bool = True,
    max_evaluation_rows: int = 3_000,
    write_reports: bool = True,
    scorer: Callable[[Session, list[NormalizedLog]], dict[str, Any]] | None = None,
    private_inspector: Callable[..., dict[str, Any]] | None = None,
) -> dict[str, Any]:
    before = _database_state(db)
    inventory, genuine_labels = _label_inventory(db)
    locks = _lock_audit(output_dir)
    historical = _historical_evidence(output_dir)
    artifact_readiness = run_v528_supervised_readiness_audit(db, output_dir=output_dir, write_reports=False)
    registered = (
        _evaluate_registered_shadow(
            db,
            genuine_labels,
            scorer=scorer,
            max_rows=max_evaluation_rows,
        )
        if evaluate_registered_shadow
        else {
            "available": False,
            "status": "skipped_by_request",
            "promotion_evidence": False,
        }
    )
    private_audit = _private_sample_audit(
        sample_path,
        use_temp_db=use_temp_db,
        inspector=private_inspector,
    )
    promotion = _promotion_decision(
        inventory=inventory,
        historical=historical,
        locks=locks,
        artifact_readiness=artifact_readiness,
    )
    after = _database_state(db)
    private_audit_ok = sample_path is None or bool(private_audit.get("executed") and private_audit.get("ok"))
    report = {
        "ok": bool(locks.get("status") == "passed" and before == after and private_audit_ok),
        "version": V530_VERSION,
        "generated_at": datetime.now(UTC).isoformat(),
        "status": "supervised_evidence_closed_promotion_withheld",
        "lifecycle_state": "shadow_observation",
        "evidence_inventory": inventory,
        "historical_evidence": historical,
        "evidence_lock_audit": locks,
        "registered_artifact_readiness": artifact_readiness,
        "registered_shadow_diagnostics": registered,
        "private_native_sample_audit": private_audit,
        "review_pack": {
            "generated": False,
            "reason": "The existing sealed 40-row prediction-blind pack is still awaiting legitimate independent human review.",
            "ai_suggestions_added": False,
            "human_decisions_created": False,
            "import_ready": False,
        },
        "promotion_readiness": promotion,
        "safety": {
            "database_state_unchanged": before == after,
            "labels_created_or_updated": 0,
            "model_runs_created": 0,
            "model_artifacts_written": 0,
            "model_activated": False,
            "model_promoted": False,
            "alerts_created": 0,
            "detection_runs_created": 0,
            "response_actions_created": 0,
            "automatic_response_enabled": False,
            "real_firewall_blocking_enabled": False,
            "rules_remain_alert_authoritative": True,
            "private_paths_returned": False,
            "raw_logs_returned": False,
            "ip_addresses_returned": False,
            "fingerprints_returned": False,
            "secrets_exposed": False,
        },
    }
    if write_reports:
        output_dir.mkdir(parents=True, exist_ok=True)
        serialized = json.dumps(report, indent=2, sort_keys=True, default=str)
        (output_dir / V530_LATEST).write_text(serialized, encoding="utf-8")
        stamp = _stamp()
        (output_dir / f"v5_30_supervised_evidence_closure_{stamp}.json").write_text(serialized, encoding="utf-8")
        (output_dir / f"v5_30_supervised_evidence_closure_{stamp}.md").write_text(
            render_v530_report(report),
            encoding="utf-8",
        )
    return report
