from __future__ import annotations

import hashlib
import json
import os
import time
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path
from statistics import mean
from typing import Any, Iterable

from sqlalchemy.orm import Session

from atdr.app.core.config import PROJECT_ROOT
from atdr.app.detection import v398_independent_holdout_validation as frozen
from atdr.app.detection import v49_detection_ml_reliability as reliability
from atdr.app.detection import v52_shadow_reliability as v52
from atdr.app.detection import v540_development_supervised_repair as v540
from atdr.app.detection import v541_governed_blind_evidence as v541
from atdr.app.detection import v55_development_model_repair as v55
from atdr.app.detection.v331_noise_reduction import _build_pipeline_for_columns


V542_VERSION = "v5.42-development-candidate-freeze-v1"
V542_OUTPUT_DIR = PROJECT_ROOT / "ml_baseline_reviews" / "v5_42_candidate_freeze"
V542_LATEST = "v5_42_candidate_freeze_readiness_latest.json"
V542_REPORT_PREFIX = "v5_42_development_candidate_freeze_readiness"
V542_FREEZE_MANIFEST = "v5_42_immutable_candidate_manifest.json"
V542_CANDIDATE_ARTIFACT = "v5_42_diagnostic_candidate.joblib"
V542_FREEZE_LOCK = "v5_42_candidate_freeze.lock"

FIXED_FREEZE_GATES = {
    "queue_precision_min": 0.80,
    "queue_recall_min": 0.80,
    "queue_f1_min": 0.85,
    "benign_like_false_positive_rate_max": 0.10,
    "suspicious_recall_min": 0.80,
    "malicious_recall_min": 0.80,
    "expected_calibration_error_max": 0.10,
    "max_confidence_accuracy_gap_max": 0.15,
    "review_queue_rate_spread_max": 0.20,
}

PREDECLARED_STRATEGIES = (
    {
        "name": "calibrated_extra_trees",
        "model_type": "extra_trees",
        "target_mode": "binary_soc_queue",
        "calibration_method": "sigmoid",
        "class_weight": "balanced",
    },
    {
        "name": "calibrated_hist_gradient_boosting",
        "model_type": "hist_gradient_boosting",
        "target_mode": "binary_soc_queue",
        "calibration_method": "sigmoid",
        "class_weight": None,
    },
    {
        "name": "calibrated_logistic_regression",
        "model_type": "logistic_regression",
        "target_mode": "binary_soc_queue",
        "calibration_method": "sigmoid",
        "class_weight": "balanced",
    },
    {
        "name": "three_class_soc_queue",
        "model_type": "extra_trees",
        "target_mode": "three_class_soc_queue",
        "calibration_method": "isotonic",
        "class_weight": "balanced",
    },
    {
        "name": "hierarchical_two_stage",
        "model_type": "extra_trees",
        "target_mode": "hierarchical_two_stage",
        "calibration_method": "sigmoid",
        "class_weight": "balanced",
    },
)

METRIC_FIELDS = (
    "queue_precision",
    "queue_recall",
    "queue_f1",
    "benign_like_false_positive_rate",
    "suspicious_recall",
    "malicious_recall",
    "macro_f1",
    "weighted_f1",
    "review_queue_rate",
    "false_positive",
    "false_negative",
)
CALIBRATION_FIELDS = (
    "brier_score",
    "expected_calibration_error",
    "max_confidence_accuracy_gap",
)


class V542FreezeError(RuntimeError):
    pass


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _stamp() -> str:
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")


def _stable_hash(value: Any) -> str:
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _file_state(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {"exists": False, "size_bytes": None, "sha256": None}
    return {
        "exists": True,
        "size_bytes": int(path.stat().st_size),
        "sha256": _file_sha256(path),
    }


def _workspace_states(output_dir: Path) -> dict[str, Any]:
    return {
        name: _file_state(output_dir / name)
        for name in (
            v541.V541_MANIFEST,
            v541.V541_PRIVATE_STATE,
            v541.V541_CANDIDATES,
            v541.V541_PREDICTION_SEAL,
            v541.V541_REVIEW_PACK,
        )
    }


def _atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    os.replace(temporary, path)


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise V542FreezeError("The private candidate freeze state is unreadable.") from exc
    if not isinstance(value, dict):
        raise V542FreezeError("The private candidate freeze state is invalid.")
    return value


def _number(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _range(values: Iterable[float]) -> dict[str, float | None]:
    clean = [float(value) for value in values]
    return {
        "min": round(min(clean), 4) if clean else None,
        "max": round(max(clean), 4) if clean else None,
        "mean": round(mean(clean), 4) if clean else None,
    }


def _distribution(values: Iterable[Any]) -> dict[str, int]:
    return dict(sorted(Counter(str(value or "unknown") for value in values).items()))


def _total_variation(left: dict[str, int], right: dict[str, int]) -> float | None:
    left_total = sum(left.values())
    right_total = sum(right.values())
    if not left_total or not right_total:
        return None
    keys = set(left) | set(right)
    value = 0.5 * sum(
        abs((left.get(key, 0) / left_total) - (right.get(key, 0) / right_total))
        for key in keys
    )
    return round(value, 4)


def _development_contract(dataset: dict[str, Any]) -> str:
    return _stable_hash(
        [
            {
                "label_id": row.get("label_id"),
                "log_id": row.get("log_id"),
                "leakage_group": row.get("leakage_group"),
                "feature_fingerprint": row.get("feature_fingerprint"),
                "target": dataset["targets"][index],
                "original_label": dataset["original_labels"][index],
            }
            for index, row in enumerate(dataset["rows"])
        ]
    )


def build_v542_development_state(
    db: Session,
    *,
    min_samples: int = 100,
    state_path: Path = v540.V539_STATE_PATH,
    pack_path: Path = v540.DEFAULT_PACK_PATH,
    blind_output_dir: Path = v541.V541_OUTPUT_DIR,
) -> dict[str, Any]:
    v539_boundary = v540.load_v539_consumed_boundary(
        state_path=state_path,
        pack_path=pack_path,
    )
    v541_boundary = v541.load_v541_development_boundary(
        db,
        min_samples=min_samples,
        state_path=state_path,
        pack_path=pack_path,
    )
    blind_status = v541.get_public_blind_evidence_status(output_dir=blind_output_dir)

    prepared = v52._prepare_dataset(db, min_samples=min_samples)
    if not prepared.get("ok"):
        raise V542FreezeError(str(prepared.get("message") or "Development evidence is unavailable."))
    filtered, exclusion = v540.exclude_v539_consumed_evidence(
        prepared,
        v539_boundary,
    )
    canonical = frozen.build_frozen_partition(
        filtered["rows"],
        split_mode="temporal_holdout",
    )
    leakage = frozen.audit_partition_leakage(filtered["rows"], canonical)
    if not leakage.get("passed"):
        raise V542FreezeError("The development boundary failed duplicate isolation.")
    development = v55.build_development_dataset(filtered, canonical)
    development, feature_audit = v540.augment_v540_features(development)

    exact_hashes = frozenset(
        str(row.get("exact_fingerprint") or "")
        for row in development["rows"]
        if row.get("exact_fingerprint")
    )
    near_hashes = frozenset(
        str(row.get("near_fingerprint") or "")
        for row in development["rows"]
        if row.get("near_fingerprint")
    )
    source_names = frozenset(
        str(row.get("source_name") or "").strip().casefold()
        for row in development["rows"]
        if str(row.get("source_name") or "").strip()
    )
    timestamps = sorted(
        row.get("timestamp")
        for row in development["rows"]
        if row.get("timestamp") is not None
    )
    boundary_checks = {
        "v539_consumed_boundary_valid": v539_boundary.get("status")
        == "consumed_boundary_locked",
        "v540_row_count_matches_v541": len(development["rows"])
        == int(v541_boundary.get("development_rows") or -1),
        "v540_cutoff_matches_v541": bool(timestamps)
        and timestamps[-1] == v541_boundary.get("cutoff"),
        "v540_exact_boundary_matches_v541": exact_hashes
        == v541_boundary.get("development_exact_hashes"),
        "v540_near_boundary_matches_v541": near_hashes
        == v541_boundary.get("development_near_hashes"),
        "v540_source_boundary_matches_v541": source_names
        == v541_boundary.get("development_source_names"),
        "duplicate_group_isolation_passed": bool(leakage.get("passed")),
        "v541_custody_status_valid": blind_status.get("status")
        in v541.PUBLIC_STATUSES,
    }
    if not all(boundary_checks.values()):
        raise V542FreezeError("The v5.39-v5.41 evidence boundaries do not match.")
    return {
        "development": development,
        "canonical": canonical,
        "exclusion": exclusion,
        "feature_audit": feature_audit,
        "v539_boundary": v539_boundary,
        "v541_boundary": v541_boundary,
        "blind_status": blind_status,
        "boundary_checks": boundary_checks,
        "development_contract": _development_contract(development),
    }


def _partition_profile(
    dataset: dict[str, Any],
    indices: list[int],
) -> dict[str, Any]:
    rows = [dataset["rows"][index] for index in indices]
    return {
        "rows": len(indices),
        "queue_targets": _distribution(dataset["targets"][index] for index in indices),
        "original_labels": _distribution(
            dataset["original_labels"][index] for index in indices
        ),
        "evidence_families": _distribution(
            row.get("v540_evidence_family") for row in rows
        ),
        "applications": dict(
            Counter(str(row.get("app") or "unknown") for row in rows).most_common(12)
        ),
        "actions": _distribution(row.get("action") for row in rows),
        "provenance": _distribution(row.get("label_source") for row in rows),
        "source_names_returned": False,
        "row_identifiers_returned": False,
    }


def _fold_evidence_profile(
    dataset: dict[str, Any],
    partition: dict[str, Any],
) -> dict[str, Any]:
    profiles = {
        role: _partition_profile(dataset, list(partition.get(key) or []))
        for role, key in (
            ("fit", "fit_idx"),
            ("calibration", "calibration_idx"),
            ("threshold", "threshold_idx"),
            ("evaluation", "final_test_idx"),
        )
    }
    fit = profiles["fit"]
    evaluation = profiles["evaluation"]
    return {
        "partitions": profiles,
        "fit_to_evaluation_drift": {
            "queue_target_total_variation": _total_variation(
                fit["queue_targets"], evaluation["queue_targets"]
            ),
            "original_label_total_variation": _total_variation(
                fit["original_labels"], evaluation["original_labels"]
            ),
            "evidence_family_total_variation": _total_variation(
                fit["evidence_families"], evaluation["evidence_families"]
            ),
            "application_total_variation": _total_variation(
                fit["applications"], evaluation["applications"]
            ),
            "action_total_variation": _total_variation(
                fit["actions"], evaluation["actions"]
            ),
        },
        "raw_logs_included": False,
        "private_identifiers_included": False,
    }


def _fixed_fold_gate(
    result: dict[str, Any],
    *,
    leakage_passed: bool,
) -> dict[str, Any]:
    if result.get("status") != "evaluated":
        return {
            "passed": False,
            "checks": {"strategy_evaluated": False},
            "gates": FIXED_FREEZE_GATES,
        }
    metrics = result.get("metrics") or {}
    calibration = result.get("calibration") or {}
    method = str(result.get("applied_calibration_method") or "")
    checks = {
        "strategy_evaluated": True,
        "queue_precision": _number(metrics.get("queue_precision"))
        >= FIXED_FREEZE_GATES["queue_precision_min"],
        "queue_recall": _number(metrics.get("queue_recall"))
        >= FIXED_FREEZE_GATES["queue_recall_min"],
        "queue_f1": _number(metrics.get("queue_f1"))
        >= FIXED_FREEZE_GATES["queue_f1_min"],
        "benign_like_false_positive_rate": _number(
            metrics.get("benign_like_false_positive_rate"), 1.0
        )
        <= FIXED_FREEZE_GATES["benign_like_false_positive_rate_max"],
        "suspicious_recall": metrics.get("suspicious_recall") is not None
        and _number(metrics.get("suspicious_recall"))
        >= FIXED_FREEZE_GATES["suspicious_recall_min"],
        "malicious_recall": metrics.get("malicious_recall") is not None
        and _number(metrics.get("malicious_recall"))
        >= FIXED_FREEZE_GATES["malicious_recall_min"],
        "expected_calibration_error": _number(
            calibration.get("expected_calibration_error"), 1.0
        )
        <= FIXED_FREEZE_GATES["expected_calibration_error_max"],
        "max_confidence_accuracy_gap": _number(
            calibration.get("max_confidence_accuracy_gap"), 1.0
        )
        <= FIXED_FREEZE_GATES["max_confidence_accuracy_gap_max"],
        "calibration_applied": method.startswith(("sigmoid_", "isotonic_")),
        "duplicate_group_isolation": leakage_passed,
        "post_prediction_guard_absent": not bool(
            result.get("post_prediction_guard_used")
        ),
    }
    return {
        "passed": all(checks.values()),
        "checks": checks,
        "gates": FIXED_FREEZE_GATES,
    }


def _metric_ranges(rows: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        field: _range(
            _number((row.get("metrics") or {}).get(field))
            for row in rows
            if (row.get("metrics") or {}).get(field) is not None
        )
        for field in METRIC_FIELDS
    }


def _calibration_ranges(rows: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        field: _range(
            _number((row.get("calibration") or {}).get(field))
            for row in rows
            if (row.get("calibration") or {}).get(field) is not None
        )
        for field in CALIBRATION_FIELDS
    }


def run_fixed_candidate_comparison(dataset: dict[str, Any]) -> dict[str, Any]:
    folds = v55.build_nested_temporal_folds(dataset)
    views: list[dict[str, Any]] = []
    by_strategy: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for fold in folds:
        if fold.get("status") != "partitioned":
            views.append(
                {
                    "fold": fold.get("fold"),
                    "status": "failed_closed",
                    "reason": fold.get("reason") or "development fold unavailable",
                }
            )
            continue
        leakage_passed = bool((fold.get("leakage_audit") or {}).get("passed"))
        evidence_profile = _fold_evidence_profile(
            fold["dataset"],
            fold["partition"],
        )
        evaluations: list[dict[str, Any]] = []
        for spec in PREDECLARED_STRATEGIES:
            try:
                result = v540._fit_strategy(fold["dataset"], fold["partition"], spec)
            except Exception as exc:  # diagnostic failures must remain fail closed
                result = {
                    "status": "failed_closed",
                    "name": spec["name"],
                    "error_type": exc.__class__.__name__,
                    "message": "Candidate evaluation failed closed.",
                    "active_artifact_written": False,
                }
            result["fixed_freeze_gate"] = _fixed_fold_gate(
                result,
                leakage_passed=leakage_passed,
            )
            evaluations.append(result)
            by_strategy[str(spec["name"])].append(
                {"fold": fold["fold"], **result}
            )
        views.append(
            {
                "fold": fold["fold"],
                "status": "partitioned",
                "prefix_share": fold.get("prefix_share"),
                "leakage_audit_passed": leakage_passed,
                "partition_sizes": (fold.get("leakage_audit") or {}).get(
                    "partition_sizes"
                ),
                "evidence_profile": evidence_profile,
                "strategies": evaluations,
            }
        )

    required_folds = len(v55.NESTED_PREFIX_SHARES)
    summaries: dict[str, Any] = {}
    for spec in PREDECLARED_STRATEGIES:
        name = str(spec["name"])
        evaluated = [
            row for row in by_strategy.get(name, []) if row.get("status") == "evaluated"
        ]
        queue_rates = [
            _number((row.get("metrics") or {}).get("review_queue_rate"))
            for row in evaluated
            if (row.get("metrics") or {}).get("review_queue_rate") is not None
        ]
        queue_rate_spread = (
            round(max(queue_rates) - min(queue_rates), 4)
            if queue_rates
            else None
        )
        fold_gates_passed = sum(
            1 for row in evaluated if (row.get("fixed_freeze_gate") or {}).get("passed")
        )
        queue_stable = bool(
            queue_rate_spread is not None
            and queue_rate_spread
            <= FIXED_FREEZE_GATES["review_queue_rate_spread_max"]
        )
        complete = len(evaluated) == required_folds
        summaries[name] = {
            "evaluated_folds": len(evaluated),
            "required_folds": required_folds,
            "passing_folds": fold_gates_passed,
            "all_fold_gates_passed": complete and fold_gates_passed == required_folds,
            "review_queue_rate_spread": queue_rate_spread,
            "review_queue_rate_stability_passed": queue_stable,
            "eligible_for_diagnostic_freeze": bool(
                complete and fold_gates_passed == required_folds and queue_stable
            ),
            "metric_ranges": _metric_ranges(evaluated),
            "calibration_ranges": _calibration_ranges(evaluated),
            "calibration_methods": sorted(
                {
                    str(row.get("applied_calibration_method") or "missing")
                    for row in evaluated
                }
            ),
            "threshold_profiles": [
                {
                    "fold": row.get("fold"),
                    "profile": (row.get("threshold_selection") or {}).get(
                        "selected_profile"
                    ),
                    "threshold": (row.get("threshold_selection") or {}).get(
                        "selected_threshold"
                    ),
                }
                for row in evaluated
            ],
            "protected_v539_rows_used": 0,
            "v541_blind_rows_used": 0,
        }
    return {
        "protocol": "v5.42-fixed-development-candidate-comparison-v1",
        "strategy_count": len(PREDECLARED_STRATEGIES),
        "predeclared_strategy_names": [item["name"] for item in PREDECLARED_STRATEGIES],
        "development_rows": len(dataset["rows"]),
        "required_folds": required_folds,
        "views": views,
        "strategy_summaries": summaries,
        "duplicate_group_isolation_required": True,
        "locked_final_rows_used": 0,
        "v539_rows_used": 0,
        "v541_blind_rows_used": 0,
        "active_artifact_written": False,
    }


def select_best_candidate(comparison: dict[str, Any]) -> dict[str, Any] | None:
    ranked: list[tuple[Any, ...]] = []
    for name, summary in (comparison.get("strategy_summaries") or {}).items():
        metrics = summary.get("metric_ranges") or {}
        calibration = summary.get("calibration_ranges") or {}

        def minimum(field: str, default: float = 0.0) -> float:
            value = (metrics.get(field) or {}).get("min")
            return default if value is None else float(value)

        def maximum(field: str, default: float = 1.0) -> float:
            value = (metrics.get(field) or {}).get("max")
            return default if value is None else float(value)

        ece = (calibration.get("expected_calibration_error") or {}).get("max")
        gap = (calibration.get("max_confidence_accuracy_gap") or {}).get("max")
        score = (
            minimum("queue_f1")
            + (0.20 * minimum("queue_recall"))
            + (0.15 * minimum("suspicious_recall"))
            + (0.15 * minimum("malicious_recall"))
            - (0.70 * maximum("benign_like_false_positive_rate"))
            - (0.10 * float(ece if ece is not None else 1.0))
            - (0.10 * float(gap if gap is not None else 1.0))
        )
        ranked.append(
            (
                bool(summary.get("eligible_for_diagnostic_freeze")),
                int(summary.get("passing_folds") or 0),
                round(score, 6),
                minimum("queue_f1"),
                -maximum("benign_like_false_positive_rate"),
                name,
            )
        )
    if not ranked:
        return None
    selected = max(ranked)
    name = str(selected[-1])
    return {
        "name": name,
        "selection_basis": "development_roles_only_fixed_v5_42_gates",
        "eligible_for_diagnostic_freeze": bool(selected[0]),
        "summary": comparison["strategy_summaries"][name],
        "locked_final_used": False,
        "v539_used": False,
        "v541_blind_used": False,
        "eligible_for_activation": False,
    }


def _pattern_audit(dataset: dict[str, Any]) -> dict[str, Any]:
    frame = dataset["frame"]
    definitions = {
        "quic_443_allow": lambda index: bool(
            _number(frame.iloc[index].get("v540_quic_443_allow_flag"))
        ),
        "incomplete_80_allow": lambda index: bool(
            _number(frame.iloc[index].get("v540_incomplete_80_allow_flag"))
        ),
        "ping_or_icmp": lambda index: str(
            dataset["rows"][index].get("app") or ""
        ).casefold()
        in {"ping", "icmp"},
        "unknown_udp_tcp": lambda index: bool(
            _number(frame.iloc[index].get("v540_unknown_udp_flag"))
            or _number(frame.iloc[index].get("v540_unknown_tcp_flag"))
        ),
        "scan_like_behavior": lambda index: bool(
            _number(frame.iloc[index].get("v540_scan_context_flag"))
        ),
    }
    result: dict[str, Any] = {}
    for name, matches in definitions.items():
        indices = [index for index in range(len(dataset["rows"])) if matches(index)]
        result[name] = {
            "rows": len(indices),
            "queue_targets": _distribution(dataset["targets"][index] for index in indices),
            "original_labels": _distribution(
                dataset["original_labels"][index] for index in indices
            ),
            "provenance": _distribution(
                dataset["rows"][index].get("label_source") for index in indices
            ),
        }
    return {
        "patterns": result,
        "raw_logs_included": False,
        "row_identifiers_returned": False,
        "source_names_returned": False,
    }


def diagnose_instability(
    dataset: dict[str, Any],
    comparison: dict[str, Any],
    leader: dict[str, Any] | None,
) -> dict[str, Any]:
    evidence_audit = v540.audit_development_evidence(dataset)
    errors = v540.summarize_development_errors(comparison, leader)
    patterns = _pattern_audit(dataset)
    root_causes: list[str] = list(evidence_audit.get("problems") or [])
    if leader:
        summary = leader.get("summary") or {}
        metrics = summary.get("metric_ranges") or {}
        calibration = summary.get("calibration_ranges") or {}

        def metric_min(field: str) -> float | None:
            value = (metrics.get(field) or {}).get("min")
            return None if value is None else float(value)

        def metric_max(field: str) -> float | None:
            value = (metrics.get(field) or {}).get("max")
            return None if value is None else float(value)

        if (metric_min("queue_recall") or 0.0) < FIXED_FREEZE_GATES["queue_recall_min"]:
            root_causes.append("Threat queue recall is unstable across temporal folds.")
        if (metric_min("suspicious_recall") or 0.0) < FIXED_FREEZE_GATES["suspicious_recall_min"]:
            root_causes.append("Suspicious recall collapses in at least one temporal fold.")
        if (metric_min("malicious_recall") or 0.0) < FIXED_FREEZE_GATES["malicious_recall_min"]:
            root_causes.append("Malicious recall is below the fixed freeze gate.")
        if (metric_max("benign_like_false_positive_rate") or 1.0) > FIXED_FREEZE_GATES[
            "benign_like_false_positive_rate_max"
        ]:
            root_causes.append("Benign-like false-positive rate exceeds the fixed gate in at least one fold.")
        ece = (calibration.get("expected_calibration_error") or {}).get("max")
        gap = (calibration.get("max_confidence_accuracy_gap") or {}).get("max")
        if ece is None or float(ece) > FIXED_FREEZE_GATES["expected_calibration_error_max"]:
            root_causes.append("Probability calibration ECE is weak or unstable.")
        if gap is None or float(gap) > FIXED_FREEZE_GATES[
            "max_confidence_accuracy_gap_max"
        ]:
            root_causes.append("Confidence-to-accuracy gap exceeds the fixed gate.")
        if not summary.get("review_queue_rate_stability_passed"):
            root_causes.append("Review queue rate varies too much across temporal folds.")
        profiles = {
            str(item.get("profile") or "missing")
            for item in summary.get("threshold_profiles") or []
        }
        if len(profiles) > 1:
            root_causes.append("The selected fixed threshold profile changes across folds.")

    drift_values = []
    for view in comparison.get("views") or []:
        drift = (view.get("evidence_profile") or {}).get("fit_to_evaluation_drift") or {}
        drift_values.extend(value for value in drift.values() if value is not None)
    if drift_values and max(drift_values) >= 0.30:
        root_causes.append("Chronological evidence distributions shift materially between fit and evaluation partitions.")
    return {
        "status": "diagnosed",
        "root_causes": list(dict.fromkeys(root_causes)),
        "development_evidence": evidence_audit,
        "pattern_audit": patterns,
        "leader_error_patterns": errors,
        "maximum_fit_to_evaluation_total_variation": round(max(drift_values), 4)
        if drift_values
        else None,
        "private_rows_returned": False,
        "source_names_returned": False,
        "fingerprints_returned": False,
        "raw_logs_included": False,
    }


def _fit_frozen_artifact(
    dataset: dict[str, Any],
    comparison: dict[str, Any],
    leader: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    spec = next(
        item for item in PREDECLARED_STRATEGIES if item["name"] == leader["name"]
    )
    folds = v55.build_nested_temporal_folds(dataset)
    available = [fold for fold in folds if fold.get("status") == "partitioned"]
    if len(available) != len(v55.NESTED_PREFIX_SHARES):
        raise V542FreezeError("All fixed development folds are required before freezing.")
    fold = available[-1]
    partition = fold["partition"]
    fit_idx = list(partition["fit_idx"])
    calibration_idx = list(partition["calibration_idx"])
    threshold_idx = list(partition["threshold_idx"])
    targets, positive_classes = v540._targets_for_strategy(dataset, spec)
    pipeline = _build_pipeline_for_columns(
        dataset["imports"],
        model_type=str(spec["model_type"]),
        class_weight=spec.get("class_weight"),
        numeric_features=dataset["feature_meta"]["numeric_features"],
        categorical_features=dataset["feature_meta"]["categorical_features"],
    )
    weights, weighting = v540._fit_weights(dataset, fit_idx, targets)
    pipeline.fit(
        dataset["frame"].iloc[fit_idx],
        [targets[index] for index in fit_idx],
        model__sample_weight=weights,
    )
    model, calibration_method = reliability._fit_frozen_calibrator(
        pipeline,
        dataset["frame"],
        calibration_idx,
        targets,
        method=str(spec["calibration_method"]),
    )
    threshold_scores = reliability._queue_scores(
        model,
        dataset["frame"],
        threshold_idx,
        positive_classes,
    )
    threshold = v540.select_fixed_threshold_profile(
        [dataset["targets"][index] for index in threshold_idx],
        threshold_scores,
    )
    severity_model = None
    if spec["target_mode"] == "hierarchical_two_stage":
        threat_fit = [
            index
            for index in fit_idx
            if dataset["original_labels"][index] in {"suspicious", "malicious"}
        ]
        severity_targets = [dataset["original_labels"][index] for index in threat_fit]
        if len(set(severity_targets)) < 2:
            raise V542FreezeError("The hierarchical severity stage lacks two fit classes.")
        severity_model = _build_pipeline_for_columns(
            dataset["imports"],
            model_type="extra_trees",
            class_weight="balanced",
            numeric_features=dataset["feature_meta"]["numeric_features"],
            categorical_features=dataset["feature_meta"]["categorical_features"],
        )
        severity_weights, _ = v540._fit_weights(
            dataset,
            threat_fit,
            dataset["original_labels"],
        )
        severity_model.fit(
            dataset["frame"].iloc[threat_fit],
            severity_targets,
            model__sample_weight=severity_weights,
        )
    contract = {
        "schema_version": V542_VERSION,
        "status": "diagnostic_configuration_frozen",
        "strategy": spec,
        "threshold_profile": threshold["selected_profile"],
        "threshold": threshold["selected_threshold"],
        "calibration_method": calibration_method,
        "feature_contract": dataset["feature_meta"].get("v540_features") or [],
        "development_contract": _development_contract(dataset),
        "fixed_gate_summary": leader["summary"],
        "comparison_protocol": comparison.get("protocol"),
        "fit_rows": len(fit_idx),
        "calibration_rows": len(calibration_idx),
        "threshold_rows": len(threshold_idx),
        "evaluation_rows_used_for_fit": 0,
        "locked_final_rows_used": 0,
        "v539_rows_used": 0,
        "v541_blind_rows_used": 0,
        "eligible_for_activation": False,
        "rules_alert_authoritative": True,
    }
    artifact = {
        "schema_version": V542_VERSION,
        "model": model,
        "severity_model": severity_model,
        "threshold": float(threshold["selected_threshold"]),
        "positive_classes": sorted(positive_classes),
        "numeric_features": list(dataset["feature_meta"]["numeric_features"]),
        "categorical_features": list(
            dataset["feature_meta"]["categorical_features"]
        ),
        "strategy": spec,
        "sample_weighting": weighting,
        "decision_support_only": True,
        "active": False,
        "production_promoted": False,
        "response_automation_allowed": False,
    }
    return artifact, contract


def _validate_freeze_manifest(output_dir: Path) -> dict[str, Any] | None:
    manifest_path = output_dir / V542_FREEZE_MANIFEST
    artifact_path = output_dir / V542_CANDIDATE_ARTIFACT
    if manifest_path.is_file() != artifact_path.is_file():
        raise V542FreezeError("The immutable candidate freeze is incomplete.")
    if not manifest_path.is_file():
        return None
    manifest = _read_json(manifest_path)
    if (
        manifest.get("schema_version") != V542_VERSION
        or manifest.get("status") != "diagnostic_candidate_frozen"
        or manifest.get("artifact_sha256") != _file_sha256(artifact_path)
        or not manifest.get("candidate_contract_digest")
    ):
        raise V542FreezeError("The immutable candidate freeze failed integrity validation.")
    return manifest


def seal_immutable_candidate(
    *,
    artifact: Any,
    candidate_contract: dict[str, Any],
    output_dir: Path = V542_OUTPUT_DIR,
) -> dict[str, Any]:
    if candidate_contract.get("status") != "diagnostic_configuration_frozen":
        raise V542FreezeError("Only an eligible diagnostic configuration can be frozen.")
    contract_digest = _stable_hash(candidate_contract)
    existing = _validate_freeze_manifest(output_dir)
    if existing is not None:
        if existing.get("candidate_contract_digest") != contract_digest:
            raise V542FreezeError("A different immutable candidate is already frozen.")
        return {
            "status": "diagnostic_candidate_frozen",
            "candidate_frozen": True,
            "reused_existing_freeze": True,
            "artifact_name": V542_CANDIDATE_ARTIFACT,
            "artifact_path_returned": False,
            "digests_returned": False,
            "active": False,
            "production_promoted": False,
        }

    output_dir.mkdir(parents=True, exist_ok=True)
    lock_path = output_dir / V542_FREEZE_LOCK
    try:
        lock_fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except FileExistsError as exc:
        raise V542FreezeError("Another immutable candidate freeze is in progress.") from exc
    os.close(lock_fd)
    try:
        existing = _validate_freeze_manifest(output_dir)
        if existing is not None:
            if existing.get("candidate_contract_digest") != contract_digest:
                raise V542FreezeError("A different immutable candidate is already frozen.")
            return {
                "status": "diagnostic_candidate_frozen",
                "candidate_frozen": True,
                "reused_existing_freeze": True,
                "artifact_name": V542_CANDIDATE_ARTIFACT,
                "artifact_path_returned": False,
                "digests_returned": False,
                "active": False,
                "production_promoted": False,
            }
        import joblib

        artifact_path = output_dir / V542_CANDIDATE_ARTIFACT
        temporary = artifact_path.with_name(f".{artifact_path.name}.{os.getpid()}.tmp")
        joblib.dump(artifact, temporary)
        os.replace(temporary, artifact_path)
        manifest = {
            "schema_version": V542_VERSION,
            "status": "diagnostic_candidate_frozen",
            "created_at": _now(),
            "artifact_name": V542_CANDIDATE_ARTIFACT,
            "artifact_sha256": _file_sha256(artifact_path),
            "candidate_contract_digest": contract_digest,
            "strategy": candidate_contract.get("strategy"),
            "active": False,
            "production_promoted": False,
            "response_automation_allowed": False,
            "rules_alert_authoritative": True,
        }
        _atomic_write_json(output_dir / V542_FREEZE_MANIFEST, manifest)
    finally:
        lock_path.unlink(missing_ok=True)
    return {
        "status": "diagnostic_candidate_frozen",
        "candidate_frozen": True,
        "reused_existing_freeze": False,
        "artifact_name": V542_CANDIDATE_ARTIFACT,
        "artifact_path_returned": False,
        "digests_returned": False,
        "active": False,
        "production_promoted": False,
    }


def _public_boundary_summary(state: dict[str, Any]) -> dict[str, Any]:
    boundary = state["v541_boundary"]
    return {
        "v539": {
            **v540._public_boundary(state["v539_boundary"]),
            "revalidated": True,
        },
        "v540": {
            "status": "development_boundary_revalidated",
            "development_rows": len(state["development"]["rows"]),
            "duplicate_isolation_passed": True,
            "cutoff_available": boundary.get("cutoff") is not None,
            "digests_returned": False,
            "private_identifiers_returned": False,
        },
        "v541": {
            "status": state["blind_status"]["status"],
            "candidate_rows": state["blind_status"]["candidate_rows"],
            "independent_source_count": state["blind_status"][
                "independent_source_count"
            ],
            "collection_window_count": state["blind_status"][
                "collection_window_count"
            ],
            "custody_valid": state["boundary_checks"]["v541_custody_status_valid"],
            "predictions_exposed": False,
            "blind_rows_used_for_selection": 0,
        },
        "checks": state["boundary_checks"],
        "all_checks_passed": all(state["boundary_checks"].values()),
    }


def _readiness(
    *,
    leader: dict[str, Any] | None,
    freeze: dict[str, Any] | None,
    diagnosis: dict[str, Any],
    blind_status: dict[str, Any],
    safety: dict[str, Any],
) -> dict[str, Any]:
    candidate_frozen = bool(freeze and freeze.get("candidate_frozen"))
    blockers = list(diagnosis.get("root_causes") or [])
    if leader is None:
        blockers.append("No predeclared strategy produced comparable fold metrics.")
    elif not leader.get("eligible_for_diagnostic_freeze"):
        blockers.append("No strategy passed every fixed fold and queue-stability gate.")
    if not candidate_frozen:
        blockers.append("No immutable diagnostic candidate is frozen.")
    if blind_status.get("independent_source_count", 0) < blind_status.get(
        "required_source_count", 2
    ):
        blockers.append("Independent blind evidence still lacks two verified sources.")
    if blind_status.get("collection_window_count", 0) < blind_status.get(
        "required_window_count", 3
    ):
        blockers.append("Independent blind evidence still lacks three future windows.")
    if not blind_status.get("human_review_complete"):
        blockers.append("Prediction-blind human review is not complete.")
    remaining = [
        "freeze one stable development-only diagnostic candidate",
        "collect qualifying future evidence from two independent sources across three windows",
        "complete genuine prediction-blind human review",
        "run one frozen evaluation without tuning",
        "make a separate governance decision and complete shadow observation",
    ]
    if candidate_frozen:
        remaining = remaining[1:]
    return {
        "status": "Diagnostic Candidate Frozen"
        if candidate_frozen
        else "No Candidate Frozen",
        "candidate_frozen": candidate_frozen,
        "candidate_selected_for_activation": False,
        "lifecycle_state": "shadow_observation",
        "model_activated": False,
        "model_promoted": False,
        "production_promoted": False,
        "rules_alert_authoritative": True,
        "response_automation_allowed": False,
        "supervised_phases_remaining": len(remaining),
        "remaining_phases": remaining,
        "blockers": list(dict.fromkeys(blockers)),
        "safety_invariants_passed": all(
            bool(safety.get(key))
            for key in (
                "database_counts_unchanged",
                "active_model_artifacts_unchanged",
                "v539_state_unchanged",
                "v541_workspace_unchanged",
            )
        ),
    }


def _render_report(result: dict[str, Any]) -> str:
    leader = result.get("best_development_candidate") or {}
    summary = leader.get("summary") or {}
    readiness = result.get("readiness") or {}
    diagnosis = result.get("instability_diagnosis") or {}
    lines = [
        "# v5.42 Development Candidate Freeze Readiness",
        "",
        f"Generated: {result.get('generated_at')}",
        "",
        "## Fixed Comparison",
        "",
        f"- Development rows: `{result.get('development_rows')}`",
        f"- Predeclared strategies: `{result.get('strategy_count')}`",
        f"- Best diagnostic strategy: `{leader.get('name') or 'none'}`",
        f"- Passing folds: `{summary.get('passing_folds', 0)}/{summary.get('required_folds', 3)}`",
        f"- Candidate frozen: `{readiness.get('candidate_frozen', False)}`",
        f"- Lifecycle: `{readiness.get('lifecycle_state')}`",
        "",
        "## Root Causes",
        "",
    ]
    lines.extend(f"- {item}" for item in diagnosis.get("root_causes") or [])
    lines.extend(
        [
            "",
            "## Safety",
            "",
            "- v5.39 consumed evidence was not opened for modeling.",
            "- v5.41 blind evidence was not used or changed.",
            "- No model was activated or production-promoted.",
            "- Deterministic rules remain alert-authoritative.",
            "- Automatic response and real blocking remain disabled.",
            "",
            "## Remaining Phases",
            "",
        ]
    )
    lines.extend(f"- {item}" for item in readiness.get("remaining_phases") or [])
    return "\n".join(lines) + "\n"


def run_v542_candidate_freeze_readiness(
    db: Session,
    *,
    min_samples: int = 100,
    preflight_only: bool = False,
    write_output: bool = True,
    output_dir: Path = V542_OUTPUT_DIR,
    state_path: Path = v540.V539_STATE_PATH,
    pack_path: Path = v540.DEFAULT_PACK_PATH,
    blind_output_dir: Path = v541.V541_OUTPUT_DIR,
) -> dict[str, Any]:
    started = time.perf_counter()
    counts_before = frozen._database_counts(db)
    active_artifacts_before = v55._model_artifact_states()
    v539_state_before = {
        "state": _file_state(state_path),
        "pack": _file_state(pack_path),
    }
    v541_before = _workspace_states(blind_output_dir)
    try:
        state = build_v542_development_state(
            db,
            min_samples=min_samples,
            state_path=state_path,
            pack_path=pack_path,
            blind_output_dir=blind_output_dir,
        )
    except (v540.V540EvidenceBoundaryError, v541.V541EvidenceError, V542FreezeError) as exc:
        return {
            "ok": False,
            "version": V542_VERSION,
            "status": "failed_closed",
            "message": str(exc),
            "lifecycle_state": "shadow_observation",
            "candidate_frozen": False,
            "model_activated": False,
            "response_automation_allowed": False,
        }

    comparison = None
    leader = None
    diagnosis = {
        "status": "preflight_only",
        "root_causes": [],
        "raw_logs_included": False,
    }
    freeze = _validate_freeze_manifest(output_dir)
    freeze_public = (
        {
            "status": "diagnostic_candidate_frozen",
            "candidate_frozen": True,
            "reused_existing_freeze": True,
            "artifact_name": V542_CANDIDATE_ARTIFACT,
            "artifact_path_returned": False,
            "digests_returned": False,
            "active": False,
            "production_promoted": False,
        }
        if freeze
        else None
    )
    if not preflight_only:
        comparison = run_fixed_candidate_comparison(state["development"])
        leader = select_best_candidate(comparison)
        diagnosis = diagnose_instability(state["development"], comparison, leader)
        if leader and leader.get("eligible_for_diagnostic_freeze"):
            artifact, contract = _fit_frozen_artifact(
                state["development"],
                comparison,
                leader,
            )
            if write_output:
                freeze_public = seal_immutable_candidate(
                    artifact=artifact,
                    candidate_contract=contract,
                    output_dir=output_dir,
                )

    counts_after = frozen._database_counts(db)
    active_artifacts_after = v55._model_artifact_states()
    v539_state_after = {
        "state": _file_state(state_path),
        "pack": _file_state(pack_path),
    }
    v541_after = _workspace_states(blind_output_dir)
    safety = {
        "database_counts_unchanged": counts_before == counts_after,
        "active_model_artifacts_unchanged": active_artifacts_before
        == active_artifacts_after,
        "v539_state_unchanged": v539_state_before == v539_state_after,
        "v541_workspace_unchanged": v541_before == v541_after,
        "labels_created": counts_after["ml_labels"] - counts_before["ml_labels"],
        "model_runs_created": counts_after["ml_model_runs"]
        - counts_before["ml_model_runs"],
        "detection_runs_created": counts_after["detection_runs"]
        - counts_before["detection_runs"],
        "alerts_created": counts_after["alerts"] - counts_before["alerts"],
        "response_actions_created": counts_after["response_actions"]
        - counts_before["response_actions"],
        "v539_evaluator_called": False,
        "v541_predictions_revealed": False,
        "v541_prediction_seal_written": False,
        "active_model_artifact_written": False,
        "model_activated": False,
        "model_promoted": False,
        "rules_alert_authoritative": True,
        "automatic_response_enabled": False,
        "real_firewall_blocking_enabled": False,
    }
    readiness = _readiness(
        leader=leader,
        freeze=freeze_public,
        diagnosis=diagnosis,
        blind_status=state["blind_status"],
        safety=safety,
    )
    result = {
        "ok": bool(readiness["safety_invariants_passed"]),
        "version": V542_VERSION,
        "status": "preflight_completed"
        if preflight_only
        else "candidate_frozen"
        if readiness["candidate_frozen"]
        else "no_candidate_frozen",
        "generated_at": _now(),
        "lifecycle_state": "shadow_observation",
        "boundary_revalidation": _public_boundary_summary(state),
        "development_rows": len(state["development"]["rows"]),
        "strategy_count": len(PREDECLARED_STRATEGIES),
        "fixed_freeze_gates": FIXED_FREEZE_GATES,
        "development_comparison": comparison,
        "best_development_candidate": leader,
        "instability_diagnosis": diagnosis,
        "candidate_freeze": freeze_public,
        "blind_evidence_status": state["blind_status"],
        "readiness": readiness,
        "safety": safety,
        "runtime_seconds": round(time.perf_counter() - started, 4),
        "locked_final_rows_used": 0,
        "v539_rows_used_for_modeling": 0,
        "v541_blind_rows_used_for_modeling": 0,
        "raw_logs_included": False,
        "private_identifiers_included": False,
        "fingerprints_returned": False,
        "secrets_exposed": False,
    }
    if write_output:
        output_dir.mkdir(parents=True, exist_ok=True)
        latest = output_dir / V542_LATEST
        report = output_dir / f"{V542_REPORT_PREFIX}_{_stamp()}.md"
        _atomic_write_json(latest, result)
        report.write_text(_render_report(result), encoding="utf-8")
        result["reports"] = {
            "latest_file_name": latest.name,
            "report_file_name": report.name,
            "ignored_output": True,
            "private_paths_returned": False,
        }
    return result


def get_public_candidate_freeze_status(
    *,
    output_dir: Path = V542_OUTPUT_DIR,
) -> dict[str, Any]:
    manifest = _validate_freeze_manifest(output_dir)
    latest_path = output_dir / V542_LATEST
    if not latest_path.is_file():
        return {
            "version": V542_VERSION,
            "status": "Designed",
            "best_candidate": None,
            "passing_folds": 0,
            "required_folds": len(v55.NESTED_PREFIX_SHARES),
            "candidate_frozen": manifest is not None,
            "calibration_status": "not_evaluated",
            "blind_evidence_status": "Designed",
            "supervised_phases_remaining": 4 if manifest else 5,
            "blockers": ["Run the development-only candidate freeze evaluator."],
            "lifecycle_state": "shadow_observation",
            "rules_alert_authoritative": True,
            "model_activated": False,
            "model_promoted": False,
            "response_automation_allowed": False,
            "private_paths_exposed": False,
            "digests_exposed": False,
            "blind_predictions_exposed": False,
            "secrets_exposed": False,
        }
    latest = _read_json(latest_path)
    if latest.get("version") != V542_VERSION:
        raise V542FreezeError("The candidate readiness report has an unsupported schema.")
    readiness = latest.get("readiness") or {}
    leader = latest.get("best_development_candidate") or {}
    summary = leader.get("summary") or {}
    if bool(readiness.get("candidate_frozen")) != bool(manifest):
        raise V542FreezeError("The candidate readiness report and freeze state disagree.")
    calibration = summary.get("calibration_ranges") or {}
    ece = (calibration.get("expected_calibration_error") or {}).get("max")
    gap = (calibration.get("max_confidence_accuracy_gap") or {}).get("max")
    calibration_passed = bool(
        ece is not None
        and float(ece) <= FIXED_FREEZE_GATES["expected_calibration_error_max"]
        and gap is not None
        and float(gap) <= FIXED_FREEZE_GATES["max_confidence_accuracy_gap_max"]
    )
    return {
        "version": V542_VERSION,
        "status": readiness.get("status") or "No Candidate Frozen",
        "best_candidate": leader.get("name"),
        "passing_folds": int(summary.get("passing_folds") or 0),
        "required_folds": int(summary.get("required_folds") or len(v55.NESTED_PREFIX_SHARES)),
        "candidate_frozen": bool(manifest),
        "calibration_status": "passed" if calibration_passed else "weak",
        "blind_evidence_status": (latest.get("blind_evidence_status") or {}).get(
            "status", "Designed"
        ),
        "supervised_phases_remaining": int(
            readiness.get("supervised_phases_remaining") or (4 if manifest else 5)
        ),
        "blockers": list(readiness.get("blockers") or [])[:12],
        "lifecycle_state": "shadow_observation",
        "rules_alert_authoritative": True,
        "model_activated": False,
        "model_promoted": False,
        "response_automation_allowed": False,
        "private_paths_exposed": False,
        "digests_exposed": False,
        "blind_predictions_exposed": False,
        "secrets_exposed": False,
    }
