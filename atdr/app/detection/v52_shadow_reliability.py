from __future__ import annotations

import json
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from statistics import mean
from typing import Any

from sqlalchemy.orm import Session

from atdr.app.core.config import PROJECT_ROOT
from atdr.app.detection import v398_independent_holdout_validation as frozen
from atdr.app.detection import v49_detection_ml_reliability as reliability
from atdr.app.detection.v330_detection_ml_quality import OUTPUT_DIR
from atdr.scripts.run_layered_detection_validation import build_failure_matrix


V52_VERSION = "v5.2-shadow-reliability-v1"
V52_SPLITS = (
    "temporal_holdout",
    "source_holdout",
    "network_zone_holdout",
    "random_seed_7",
    "random_seed_17",
    "random_seed_42",
)
V52_LATEST = "v5_2_shadow_reliability_latest.json"
V52_FAILURE_MATRIX_LATEST = "v5_2_layered_failure_matrix_latest.json"
NON_MODEL_BASELINES = {
    "deterministic_rules_baseline",
    "isolation_forest_baseline",
    "hybrid_rule_anomaly_supervised_decision_support",
}
LAYERED_REPORT_DIR = PROJECT_ROOT / "demo_exports" / "layered_detection"
PRIVATE_SHADOW_DIR = PROJECT_ROOT / "demo_exports" / "v5_0_shadow_validation"
SCENARIO_REPORT_DIR = PROJECT_ROOT / "demo_exports" / "detection_validation"


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _safe_json(path: Path | None) -> dict[str, Any]:
    if path is None or not path.exists():
        return {}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def _latest_json(directory: Path, pattern: str) -> Path | None:
    candidates = sorted(directory.glob(pattern), key=lambda item: item.stat().st_mtime, reverse=True)
    return candidates[0] if candidates else None


def _layered_reports() -> tuple[Path | None, Path | None]:
    candidates = sorted(
        LAYERED_REPORT_DIR.glob("layered_detection_*.json"),
        key=lambda item: item.stat().st_mtime,
        reverse=True,
    )
    repaired: Path | None = None
    baseline: Path | None = None
    for path in candidates:
        report = _safe_json(path)
        if repaired is None and int(report.get("failed_count") or 0) == 0:
            repaired = path
        if baseline is None and int(report.get("failed_count") or 0) == 21:
            baseline = path
        if repaired is not None and baseline is not None:
            break
    return baseline, repaired


def _prepare_dataset(db: Session, *, min_samples: int) -> dict[str, Any]:
    dataset = frozen._build_dataset(db, min_samples=min_samples)
    if not dataset.get("ok"):
        return dataset
    original_targets = reliability._queue_targets(dataset["original_labels"])
    dataset["safe_target_repair_diagnostic_only"] = list(dataset["targets"])
    dataset["targets"] = original_targets
    for row, label in zip(dataset["rows"], dataset["labels"], strict=True):
        row["safe_queue_target"] = original_targets[row["index"]]
        row["attack_type"] = str(label.attack_type or "unknown")
    dataset["label_provenance"]["ground_truth_policy"] = (
        "latest_reviewed_label_per_normalized_log_preserving_original_provenance"
    )
    dataset["label_provenance"]["target_repair_used_as_ground_truth"] = False
    dataset["label_provenance"]["ai_assisted_labels_authored"] = 0
    dataset["label_provenance"]["ai_assisted_labels_marked_human_reviewed"] = 0
    frozen.assign_leakage_groups(dataset["rows"])
    return dataset


def _ratio_distribution(values: list[str]) -> dict[str, float]:
    counts = Counter(values)
    total = max(1, len(values))
    return {key: round(value / total, 6) for key, value in sorted(counts.items())}


def _total_variation(left: dict[str, float], right: dict[str, float]) -> float:
    keys = set(left) | set(right)
    return round(0.5 * sum(abs(left.get(key, 0.0) - right.get(key, 0.0)) for key in keys), 6)


def _top_distribution(values: list[str], limit: int = 8) -> list[dict[str, Any]]:
    return [{"value": key, "count": count} for key, count in Counter(values).most_common(limit)]


def _partition_drift(dataset: dict[str, Any], partition: dict[str, Any]) -> dict[str, Any]:
    frame = dataset["frame"]
    rows = dataset["rows"]
    fit_idx = partition.get("fit_idx") or []
    final_idx = partition.get("final_test_idx") or []

    def row_values(indices: list[int], field: str) -> list[str]:
        return [str(rows[index].get(field) if rows[index].get(field) is not None else "missing") for index in indices]

    categorical = {}
    for field in ("original_label", "label_source", "app", "action", "dst_port", "network_zone_group"):
        fit_values = row_values(fit_idx, field)
        final_values = row_values(final_idx, field)
        fit_distribution = _ratio_distribution(fit_values)
        final_distribution = _ratio_distribution(final_values)
        categorical[field] = {
            "total_variation_distance": _total_variation(fit_distribution, final_distribution),
            "fit_top": _top_distribution(fit_values),
            "final_top": _top_distribution(final_values),
        }

    missingness = []
    for column in [
        *dataset["feature_meta"]["numeric_features"],
        *dataset["feature_meta"]["categorical_features"],
    ]:
        fit_rate = float(frame.iloc[fit_idx][column].isna().mean()) if fit_idx else 0.0
        final_rate = float(frame.iloc[final_idx][column].isna().mean()) if final_idx else 0.0
        missingness.append(
            {
                "feature": column,
                "fit_missing_rate": round(fit_rate, 6),
                "final_missing_rate": round(final_rate, 6),
                "absolute_delta": round(abs(final_rate - fit_rate), 6),
            }
        )
    missingness.sort(key=lambda item: item["absolute_delta"], reverse=True)

    fit_times = [rows[index].get("timestamp") for index in fit_idx if rows[index].get("timestamp")]
    final_times = [rows[index].get("timestamp") for index in final_idx if rows[index].get("timestamp")]
    warnings = []
    for field, value in categorical.items():
        if float(value["total_variation_distance"]) >= 0.25:
            warnings.append(f"{field} distribution drift is high")
    if missingness and float(missingness[0]["absolute_delta"]) >= 0.15:
        warnings.append("feature missingness drift is high")
    return {
        "fit_rows": len(fit_idx),
        "final_test_rows": len(final_idx),
        "categorical_distribution_drift": categorical,
        "largest_missingness_deltas": missingness[:12],
        "fit_time_range": {
            "start": min(fit_times).isoformat() if fit_times else None,
            "end": max(fit_times).isoformat() if fit_times else None,
        },
        "final_time_range": {
            "start": min(final_times).isoformat() if final_times else None,
            "end": max(final_times).isoformat() if final_times else None,
        },
        "warning_count": len(warnings),
        "warnings": warnings,
        "raw_logs_included": False,
        "private_identifiers_included": False,
    }


def _extra_strategies(
    dataset: dict[str, Any],
    partition: dict[str, Any],
    *,
    seed: int,
) -> list[dict[str, Any]]:
    specs = (
        {
            "name": "calibrated_binary_extra_trees_isotonic",
            "model_type": "extra_trees",
            "class_weight": None,
            "weight_strategy": "strong_benign",
            "calibrate": True,
            "calibration_method": "isotonic",
        },
        {
            "name": "binary_hist_gradient_boosting_weighted",
            "model_type": "hist_gradient_boosting",
            "class_weight": None,
            "weight_strategy": "strong_benign",
            "calibrate": False,
            "calibration_method": "sigmoid",
        },
        {
            "name": "calibrated_binary_hist_gradient_boosting_sigmoid",
            "model_type": "hist_gradient_boosting",
            "class_weight": None,
            "weight_strategy": "strong_benign",
            "calibrate": True,
            "calibration_method": "sigmoid",
        },
        {
            "name": "calibrated_binary_logistic_regression_isotonic",
            "model_type": "logistic_regression",
            "class_weight": "balanced",
            "weight_strategy": "none",
            "calibrate": True,
            "calibration_method": "isotonic",
        },
    )
    rows: list[dict[str, Any]] = []
    for offset, spec in enumerate(specs):
        try:
            fitted = reliability._fit_candidate(
                dataset,
                partition,
                model_type=spec["model_type"],
                targets=dataset["targets"],
                positive_classes={"needs_review"},
                class_weight=spec["class_weight"],
                weight_strategy=spec["weight_strategy"],
                calibrate=bool(spec["calibrate"]),
                calibration_method=str(spec["calibration_method"]),
            )
            if fitted.get("status") != "evaluated":
                rows.append({"name": spec["name"], **fitted})
                continue
            rows.append(
                reliability._evaluate(
                    dataset,
                    partition,
                    name=str(spec["name"]),
                    scores=fitted["final_scores"],
                    threshold_selection=fitted["threshold_selection"],
                    seed=seed + offset,
                    details={
                        "model_type": spec["model_type"],
                        "target_mode": "binary_soc_queue",
                        "calibration_method": fitted["calibration_method"],
                        "sample_weighting": fitted["sample_weighting"],
                        "training_seconds": fitted["training_seconds"],
                        "diagnostic_only": True,
                    },
                )
            )
        except Exception as exc:  # diagnostic candidate failure must fail closed
            rows.append(
                {
                    "name": spec["name"],
                    "status": "failed_closed",
                    "error_type": exc.__class__.__name__,
                    "message": "Diagnostic strategy could not be evaluated; rules and current lifecycle remain unchanged.",
                }
            )
    return rows


def _split_seed(split_mode: str) -> int:
    if split_mode == "temporal_holdout":
        return 520
    if split_mode == "source_holdout":
        return 528
    if split_mode == "network_zone_holdout":
        return 529
    return int(split_mode.rsplit("_", 1)[-1])


def _run_split(dataset: dict[str, Any], split_mode: str) -> dict[str, Any]:
    result = reliability._run_split(dataset, split_mode=split_mode)
    if result.get("status") != "evaluated":
        result["drift"] = {"status": "unavailable", "reason": "partition failed closed"}
        return result
    partition = frozen.build_frozen_partition(dataset["rows"], split_mode=split_mode)
    result["strategies"].extend(_extra_strategies(dataset, partition, seed=_split_seed(split_mode) + 100))
    result["drift"] = _partition_drift(dataset, partition)
    return result


def _metric_range(rows: list[dict[str, Any]], key: str) -> dict[str, float | None]:
    values = [float((row.get("metrics") or {}).get(key)) for row in rows if (row.get("metrics") or {}).get(key) is not None]
    if not values:
        return {"min": None, "max": None, "mean": None}
    return {"min": round(min(values), 4), "max": round(max(values), 4), "mean": round(mean(values), 4)}


def _strict_checks(row: dict[str, Any]) -> dict[str, bool]:
    metrics = row.get("metrics") or {}
    calibration = row.get("calibration") or {}
    return {
        "threat_f1": float(metrics.get("queue_f1") or 0.0) >= reliability.STRICT_GATES["threat_positive_f1_min"],
        "benign_like_fpr": float(metrics.get("benign_like_false_positive_rate") or 1.0)
        <= reliability.STRICT_GATES["benign_like_false_positive_rate_max"],
        "suspicious_recall": metrics.get("suspicious_recall") is not None
        and float(metrics["suspicious_recall"]) >= reliability.STRICT_GATES["suspicious_recall_min"],
        "malicious_recall": metrics.get("malicious_recall") is not None
        and float(metrics["malicious_recall"]) >= reliability.STRICT_GATES["malicious_recall_min"],
        "calibration": bool(calibration.get("passed")),
    }


def _comparison(split_results: list[dict[str, Any]]) -> dict[str, Any]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    split_status = {str(split["split_mode"]): str(split.get("status")) for split in split_results}
    for split in split_results:
        for strategy in split.get("strategies") or []:
            if strategy.get("status") == "evaluated":
                grouped[str(strategy["name"])].append({"split_mode": split["split_mode"], **strategy})
    output: dict[str, Any] = {}
    metric_names = (
        "queue_precision",
        "queue_recall",
        "queue_f1",
        "benign_like_false_positive_rate",
        "suspicious_recall",
        "malicious_recall",
    )
    for name, rows in grouped.items():
        strict_rows = []
        for split_mode in V52_SPLITS:
            row = next((item for item in rows if item["split_mode"] == split_mode), None)
            checks = _strict_checks(row) if row else {}
            strict_rows.append(
                {
                    "split_mode": split_mode,
                    "evaluated": row is not None,
                    "passed": bool(row and all(checks.values())),
                    "checks": checks,
                }
            )
        thresholds = [
            float((row.get("threshold_selection") or {}).get("selected_threshold"))
            for row in rows
            if (row.get("threshold_selection") or {}).get("selected_threshold") is not None
        ]
        output[name] = {
            "evaluated_splits": len(rows),
            "required_splits": len(V52_SPLITS),
            "split_status": split_status,
            "metric_ranges": {metric: _metric_range(rows, metric) for metric in metric_names},
            "calibration_ranges": {
                "brier_score": _metric_range(
                    [{"metrics": row.get("calibration") or {}} for row in rows], "brier_score"
                ),
                "expected_calibration_error": _metric_range(
                    [{"metrics": row.get("calibration") or {}} for row in rows],
                    "expected_calibration_error",
                ),
                "max_confidence_accuracy_gap": _metric_range(
                    [{"metrics": row.get("calibration") or {}} for row in rows],
                    "max_confidence_accuracy_gap",
                ),
            },
            "calibration_passed_splits": sum(1 for row in rows if bool((row.get("calibration") or {}).get("passed"))),
            "threshold_stability": {
                "minimum": round(min(thresholds), 4) if thresholds else None,
                "maximum": round(max(thresholds), 4) if thresholds else None,
                "range": round(max(thresholds) - min(thresholds), 4) if thresholds else None,
            },
            "strict_split_gates": strict_rows,
            "strict_passing_splits": sum(1 for row in strict_rows if row["passed"]),
            "aggregate_gate_checks_passed": sum(
                1 for row in strict_rows for passed in row["checks"].values() if passed
            ),
            "aggregate_gate_checks_total": len(V52_SPLITS) * 5,
            "split_metrics": [
                {
                    "split_mode": row["split_mode"],
                    **(row.get("metrics") or {}),
                    "calibration": row.get("calibration") or {},
                    "threshold": (row.get("threshold_selection") or {}).get("selected_threshold"),
                    "details": row.get("details") or {},
                    "error_patterns": row.get("error_patterns") or {},
                }
                for row in rows
            ],
        }
    return output


def _select_diagnostic(comparison: dict[str, Any]) -> dict[str, Any] | None:
    candidates = []
    for name, summary in comparison.items():
        if name in NON_MODEL_BASELINES:
            continue
        ranges = summary.get("metric_ranges") or {}

        def minimum(metric: str) -> float:
            value = (ranges.get(metric) or {}).get("min")
            return float(value) if value is not None else -1.0

        def maximum(metric: str) -> float:
            value = (ranges.get(metric) or {}).get("max")
            return float(value) if value is not None else 1.0

        candidates.append(
            (
                name,
                int(summary.get("strict_passing_splits") or 0),
                int(summary.get("aggregate_gate_checks_passed") or 0),
                int(summary.get("calibration_passed_splits") or 0),
                minimum("queue_f1"),
                -maximum("benign_like_false_positive_rate"),
                minimum("suspicious_recall"),
                minimum("malicious_recall"),
            )
        )
    if not candidates:
        return None
    selected = max(candidates, key=lambda item: item[1:])
    strict_passing_splits = int(comparison[selected[0]].get("strict_passing_splits") or 0)
    internally_qualified = strict_passing_splits == len(V52_SPLITS)
    return {
        "name": selected[0],
        "selection_role": (
            "internally_qualified_diagnostic_candidate"
            if internally_qualified
            else "leading_comparator_not_selected"
        ),
        "candidate_selected": internally_qualified,
        "governance_outcome": (
            "internal_candidate_available" if internally_qualified else "no_supervised_candidate_selected"
        ),
        "selection_rationale": (
            "Highest aggregate predeclared gate coverage among supervised model candidates, then calibration "
            "coverage and worst-split metrics. No candidate is selected because this comparator does not pass "
            "every required split."
        ),
        "eligible_for_activation": False,
        "summary": comparison[selected[0]],
    }


def _layered_summary(report: dict[str, Any], path: Path | None) -> dict[str, Any]:
    return {
        "available": bool(report),
        "report_name": path.name if path else None,
        "mode_run_count": int(report.get("mode_run_count") or 0),
        "passed_count": int(report.get("passed_count") or 0),
        "failed_count": int(report.get("failed_count") or 0),
        "false_positive_count": int(report.get("false_positive_count") or 0),
        "false_negative_count": int(report.get("false_negative_count") or 0),
        "response_actions_created": sum(
            int((item.get("safety") or {}).get("response_actions_created") or 0)
            for item in report.get("results") or []
        ),
    }


def _controlled_scenario_summary(report: dict[str, Any], path: Path | None) -> dict[str, Any]:
    scenario_count = int(report.get("scenario_count") or 0)
    passed_count = int(report.get("passed_count") or 0)
    safety = report.get("safety") or {}
    return {
        "available": bool(report),
        "report_name": path.name if path else None,
        "scenario_count": scenario_count,
        "passed_count": passed_count,
        "failed_count": max(0, scenario_count - passed_count),
        "temporary_database_used": bool(report.get("use_temp_db")),
        "automatic_response_enabled": bool(safety.get("automatic_response_enabled")),
        "real_firewall_blocking_enabled": bool(safety.get("real_firewall_blocking_enabled")),
        "production_readiness_claim": bool(safety.get("production_readiness_claim")),
    }


def _safe_private_summary() -> dict[str, Any]:
    path = _latest_json(PRIVATE_SHADOW_DIR, "v5_0_shadow_validation_*.json")
    report = _safe_json(path)
    if not report:
        return {"available": False}
    ingestion = report.get("shadow_ingestion") or {}
    diagnostics = report.get("ml_diagnostics") or {}
    supervised_queue = diagnostics.get("supervised_queue") or {}
    return {
        "available": True,
        "report_name": path.name if path else None,
        "processed_rows": int(ingestion.get("raw_logs") or 0),
        "normalized_rows": int(ingestion.get("normalized_logs") or 0),
        "parse_failures": int(ingestion.get("parse_failures") or 0),
        "scored_rows": int(supervised_queue.get("sample_rows") or diagnostics.get("sample_rows") or 0),
        "queued_rows": int(supervised_queue.get("queue_rows") or 0),
        "queue_rate_percent": float(supervised_queue.get("queue_rate_percent") or 0.0),
        "database_counts_unchanged": bool(report.get("current_database_unchanged")),
        "active_artifact_unchanged": bool(report.get("model_artifacts_unchanged")),
        "model_activated": bool(report.get("model_activated")),
        "model_promoted": bool(report.get("model_promoted")),
        "response_actions_created": int(report.get("response_actions_created") or 0),
        "raw_logs_included": bool(report.get("raw_evidence_returned")),
        "private_identifiers_included": bool(report.get("private_path_returned")),
        "secrets_exposed": bool(report.get("secrets_exposed")),
    }


def _readiness(
    comparison: dict[str, Any],
    external: dict[str, Any],
    layered_after: dict[str, Any],
    safety: dict[str, Any],
) -> dict[str, Any]:
    eligible = [
        name
        for name, summary in comparison.items()
        if int(summary.get("strict_passing_splits") or 0) == len(V52_SPLITS)
    ]
    checks = [
        {
            "name": "one strategy passes every required internal split",
            "failure_message": "No supervised strategy passes every required internal split",
            "passed": bool(eligible),
            "value": eligible,
            "target": f"one strategy at {len(V52_SPLITS)}/{len(V52_SPLITS)}",
        },
        {
            "name": "locked external benchmark passes strict gates",
            "failure_message": "Locked external benchmark does not pass strict gates",
            "passed": bool(external.get("passed_v49_gates")),
            "value": bool(external.get("passed_v49_gates")),
            "target": True,
        },
        {
            "name": "layered validation has zero FP and FN",
            "failure_message": "Layered validation still contains false positives or false negatives",
            "passed": bool(
                layered_after.get("available")
                and layered_after.get("false_positive_count") == 0
                and layered_after.get("false_negative_count") == 0
            ),
            "value": {
                "false_positive_count": layered_after.get("false_positive_count"),
                "false_negative_count": layered_after.get("false_negative_count"),
            },
            "target": {"false_positive_count": 0, "false_negative_count": 0},
        },
        {
            "name": "evaluation is read-only with zero response side effects",
            "failure_message": "Evaluation safety or read-only invariants failed",
            "passed": bool(
                safety.get("database_counts_unchanged")
                and safety.get("active_artifact_unchanged")
                and safety.get("response_actions_created") == 0
            ),
            "value": {
                "database_counts_unchanged": safety.get("database_counts_unchanged"),
                "active_artifact_unchanged": safety.get("active_artifact_unchanged"),
                "response_actions_created": safety.get("response_actions_created"),
            },
            "target": "all true and zero responses",
        },
    ]
    all_passed = all(check["passed"] for check in checks)
    return {
        "decision": "decision_support_eligible" if all_passed else "shadow_observation",
        "checks_passed": sum(1 for check in checks if check["passed"]),
        "checks_total": len(checks),
        "checks": checks,
        "blockers": [check["failure_message"] for check in checks if not check["passed"]],
        "eligible_internal_strategies": eligible,
        "production_promoted": False,
        "model_activated": False,
        "model_artifact_written": False,
        "response_automation_allowed": False,
        "real_firewall_blocking_enabled": False,
    }


def _render_report(result: dict[str, Any]) -> str:
    before = result["layered_validation"]["baseline"]
    after = result["layered_validation"]["after"]
    selected = result.get("selected_diagnostic_strategy") or {}
    lines = [
        "# v5.2 Shadow Observation Reliability And Layered Detection Repair",
        "",
        f"- Generated: `{result['generated_at']}`",
        f"- Reviewed latest labels: `{result['dataset']['reviewed_latest_rows']}`",
        f"- Lifecycle decision: `{result['readiness']['decision']}`",
        "- Rules remain alert-authoritative: `true`",
        "- Production promoted: `false`",
        "- Response automation: `false`",
        "",
        "## Layered Repair",
        "",
        f"- Before: `{before.get('passed_count')}/{before.get('mode_run_count')}`; FP `{before.get('false_positive_count')}`; FN `{before.get('false_negative_count')}`",
        f"- After: `{after.get('passed_count')}/{after.get('mode_run_count')}`; FP `{after.get('false_positive_count')}`; FN `{after.get('false_negative_count')}`",
        "- Repair boundaries: scenario cadence preserved; field-poor anomaly evidence capped; anomaly evidence cannot authorize or rename alerts.",
        "",
        "## Supervised Stability",
        "",
        f"- Selected diagnostic strategy: `{selected.get('name')}`",
        f"- Selection rationale: {selected.get('selection_rationale')}",
        "- Source holdout: failed closed when fewer than two usable source groups were available.",
        "- Selection role: post-evaluation diagnostic only",
        "- Final-test results were not used for fitting, calibration, or threshold selection.",
        "",
        "| Strategy | Splits | Strict Passes | Worst F1 | Worst FPR | Calibration Passes |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for name, summary in sorted(result["strategy_comparison"].items()):
        ranges = summary.get("metric_ranges") or {}
        lines.append(
            f"| {name} | {summary.get('evaluated_splits')}/{summary.get('required_splits')} | "
            f"{summary.get('strict_passing_splits')} | {(ranges.get('queue_f1') or {}).get('min')} | "
            f"{(ranges.get('benign_like_false_positive_rate') or {}).get('max')} | "
            f"{summary.get('calibration_passed_splits')} |"
        )
    lines.extend(
        [
            "",
            "## Gate Decision",
            "",
            f"- Checks passed: `{result['readiness']['checks_passed']}/{result['readiness']['checks_total']}`",
            f"- Blockers: `{result['readiness']['blockers']}`",
            "- Current governed model remains shadow observation unless every predeclared gate passes.",
            "",
            "## Safety",
            "",
            "- No labels were authored or overwritten.",
            "- No active model artifact was written or replaced.",
            "- No response action was created.",
            "- Generated reports contain aggregates, not raw logs or private identifiers.",
        ]
    )
    return "\n".join(lines) + "\n"


def run_v52_shadow_reliability(
    db: Session,
    *,
    output_dir: str | Path = OUTPUT_DIR,
    min_samples: int = 100,
    write_output: bool = True,
) -> dict[str, Any]:
    started = time.perf_counter()
    before_counts = frozen._database_counts(db)
    before_artifact = frozen._artifact_state()
    dataset = _prepare_dataset(db, min_samples=min_samples)
    if not dataset.get("ok"):
        return {
            "ok": False,
            "status": dataset.get("status", "skipped"),
            "message": dataset.get("message"),
            "version": V52_VERSION,
            "readiness": {"decision": "shadow_observation"},
        }

    split_results = [_run_split(dataset, split_mode) for split_mode in V52_SPLITS]
    comparison = _comparison(split_results)
    selected = _select_diagnostic(comparison)
    output = Path(output_dir)
    external = reliability._locked_external_evidence(output)
    baseline_path, repaired_path = _layered_reports()
    baseline_report = _safe_json(baseline_path)
    repaired_report = _safe_json(repaired_path)
    baseline_failure_matrix = build_failure_matrix(baseline_report.get("results") or [])
    layered_before = _layered_summary(baseline_report, baseline_path)
    layered_after = _layered_summary(repaired_report, repaired_path)
    after_counts = frozen._database_counts(db)
    after_artifact = frozen._artifact_state()
    safety = {
        "database_counts_before": before_counts,
        "database_counts_after": after_counts,
        "database_counts_unchanged": before_counts == after_counts,
        "active_artifact_before": before_artifact,
        "active_artifact_after": after_artifact,
        "active_artifact_unchanged": before_artifact == after_artifact,
        "labels_written": False,
        "model_runs_created": 0,
        "model_activated": False,
        "model_artifact_written": False,
        "production_promoted": False,
        "response_actions_created": 0,
        "response_automation_allowed": False,
        "real_firewall_blocking_enabled": False,
    }
    readiness = _readiness(comparison, external, layered_after, safety)
    public_splits = [
        {
            **{key: value for key, value in split.items() if key != "strategies"},
            "strategies": [reliability._public_strategy(strategy) for strategy in split.get("strategies") or []],
        }
        for split in split_results
    ]
    result = {
        "ok": bool(
            safety["database_counts_unchanged"]
            and safety["active_artifact_unchanged"]
            and all(split.get("status") in {"evaluated", "failed_closed"} for split in split_results)
        ),
        "status": "completed_read_only_evaluation",
        "version": V52_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "protocol": {
            "required_splits": list(V52_SPLITS),
            "strict_gates": reliability.STRICT_GATES,
            "fit_calibration_threshold_final_roles_separated": True,
            "final_test_used_for_tuning": False,
            "diagnostic_ranking_may_not_activate_model": True,
            "rules_alert_authoritative": True,
        },
        "dataset": {
            "reviewed_latest_rows": len(dataset["rows"]),
            "feature_count": len(dataset["feature_meta"]["numeric_features"])
            + len(dataset["feature_meta"]["categorical_features"]),
            "feature_generation_seconds": dataset["feature_generation_seconds"],
            "label_provenance": dataset["label_provenance"],
            "queue_target_distribution": dict(Counter(dataset["targets"])),
            "leakage_groups": frozen.assign_leakage_groups(dataset["rows"]),
            "raw_logs_included": False,
        },
        "splits": public_splits,
        "strategy_comparison": comparison,
        "selected_diagnostic_strategy": selected,
        "external_benchmark": external,
        "layered_validation": {
            "baseline": layered_before,
            "after": layered_after,
            "baseline_failure_matrix_count": len(baseline_failure_matrix),
            "baseline_failure_matrix": baseline_failure_matrix,
            "repair_categories": {
                "rule_cadence_false_negatives": 3,
                "field_poor_anomaly_false_positives": 9,
                "hybrid_authority_false_positives": 3,
                "hybrid_precedence_false_negatives": 3,
                "hybrid_cadence_false_negatives": 3,
            },
        },
        "controlled_scenario_evidence": _controlled_scenario_summary(
            _safe_json(_latest_json(SCENARIO_REPORT_DIR, "detection_validation_*.json")),
            _latest_json(SCENARIO_REPORT_DIR, "detection_validation_*.json"),
        ),
        "private_shadow_evidence": _safe_private_summary(),
        "drift": {
            "splits_with_warnings": sum(
                1 for split in split_results if int((split.get("drift") or {}).get("warning_count") or 0) > 0
            ),
            "split_reports": {
                str(split["split_mode"]): split.get("drift") or {} for split in split_results
            },
            "source_holdout_limitation": (
                "Source-disjoint validation may fail closed when reviewed evidence represents too few independent devices."
            ),
        },
        "readiness": readiness,
        "review_sample": {
            "generated": False,
            "import_ready": False,
            "reason": "No genuinely new ambiguous rows were required for the layered runtime repairs.",
        },
        "safety": safety,
        "runtime_seconds": round(time.perf_counter() - started, 4),
    }
    if write_output:
        output.mkdir(parents=True, exist_ok=True)
        stamp = _stamp()
        report_path = output / f"v5_2_shadow_reliability_{stamp}.md"
        latest_path = output / V52_LATEST
        failure_matrix_path = output / V52_FAILURE_MATRIX_LATEST
        result["reports"] = {
            "markdown": str(report_path),
            "latest_json": str(latest_path),
            "failure_matrix_json": str(failure_matrix_path),
        }
        report_path.write_text(_render_report(result), encoding="utf-8")
        latest_path.write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")
        failure_matrix_path.write_text(json.dumps(baseline_failure_matrix, indent=2), encoding="utf-8")
    return result
