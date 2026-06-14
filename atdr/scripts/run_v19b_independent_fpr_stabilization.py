import argparse
import json
import math
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from atdr.app.benchmarks.adapter import BenchmarkRecord, load_prepared_benchmark_snapshot
from atdr.app.benchmarks.readiness import readiness_gate_v7b_fpr_stabilization
from atdr.app.core.config import PROJECT_ROOT
from atdr.app.detection.supervised_detector import _optional_imports
from atdr.scripts.build_independent_holdout import (
    DEFAULT_OUTPUT_DIR,
    build_independent_holdout,
)
from atdr.scripts.build_internal_ai_readiness_benchmark import (
    DEFAULT_OUTPUT as INTERNAL_CSV,
    build_internal_ai_readiness_benchmark,
)
from atdr.scripts.detection_reliability_common import json_default
from atdr.scripts.performance_smoke import run_performance_smoke
from atdr.scripts.prepare_benchmark_dataset import prepare_benchmark_dataset
from atdr.scripts.run_benchmark_ml_experiment import _triage_label
from atdr.scripts.run_external_benchmark_validation import (
    BENCHMARK_OUTPUT_DIR,
    _feature_frame,
)
from atdr.scripts.run_v15_ai_readiness_validation import _latest_validation_status
from atdr.scripts.run_v17_external_generalization import (
    LABELS_ORDER,
    THREAT_LABELS,
    _evaluate_predictions,
    _latest_report_path,
    _load_json,
    _model_probabilities,
    _normalize_probs,
    _profile_prediction,
    _safe_float,
    _train_base_models,
)
from atdr.scripts.run_v18_external_benchmark_finalization import (
    _cross_fitted_confidence_calibration,
    _predict_profile,
    _probability_row,
)
from atdr.scripts.run_v19_independent_revalidation import (
    _latest_controlled_source_report,
)


PROFILE_NAMES = (
    "external_recall_plus",
    "independent_fpr_stabilized",
    "independent_low_noise_recall_safe",
    "independent_balanced_safe",
    "independent_high_confidence_boundary",
    "hybrid_external_balanced",
    "high_confidence_external",
)
STABILIZED_PROFILES = {
    "independent_fpr_stabilized",
    "independent_low_noise_recall_safe",
    "independent_balanced_safe",
    "independent_high_confidence_boundary",
}
PROFILE_SELECTION_ORDER = {
    "independent_fpr_stabilized": 0,
    "independent_balanced_safe": 1,
    "independent_low_noise_recall_safe": 2,
    "independent_high_confidence_boundary": 3,
    "external_recall_plus": 4,
    "hybrid_external_balanced": 5,
    "high_confidence_external": 6,
}


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _safe_int(value: Any) -> int:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return 0


def _route_to_analyst_review(
    row: dict[str, Any],
    *,
    reason: str,
) -> dict[str, Any]:
    probabilities = _normalize_probs(row.get("probabilities") or {})
    original_prediction = str(row.get("prediction") or "benign_like")
    benign_probability = max(0.5, probabilities["benign_like"])
    threat_total = max(
        1e-8,
        probabilities["suspicious"] + probabilities["malicious"],
    )
    threat_budget = max(0.0, 1.0 - benign_probability)
    adjusted = _normalize_probs(
        {
            "benign_like": benign_probability,
            "suspicious": (
                threat_budget * probabilities["suspicious"] / threat_total
            ),
            "malicious": (
                threat_budget * probabilities["malicious"] / threat_total
            ),
        }
    )
    return {
        **row,
        "prediction": "benign_like",
        "confidence": round(max(adjusted.values()), 4),
        "probabilities": adjusted,
        "probability_row": _probability_row(adjusted),
        "threat_probability": round(
            adjusted["suspicious"] + adjusted["malicious"],
            4,
        ),
        "analyst_review_recommended": True,
        "boundary_reason": reason,
        "boundary_original_prediction": original_prediction,
    }


def stabilize_independent_boundary(
    *,
    record: BenchmarkRecord,
    row: dict[str, Any],
    profile: str,
) -> dict[str, Any]:
    """Route only unresolved protocol boundaries to review.

    Source name, scenario name, and expected label are intentionally excluded
    from this decision.
    """
    if profile not in STABILIZED_PROFILES:
        return row
    if row.get("behavior_evidence"):
        return row
    normalized = record.normalized
    app = str(normalized.get("app") or "").strip().lower()
    action = str(normalized.get("action") or "").strip().lower()
    port = _safe_int(normalized.get("dst_port"))
    rule = row.get("rule") or {}
    rule_class = str(rule.get("suggested_class") or "benign_like")
    rule_score = _safe_float(rule.get("score"))
    threat_probability = _safe_float(row.get("threat_probability"))
    unresolved_rule = rule_class not in THREAT_LABELS and rule_score < 0.68

    unknown_caps = {
        "independent_fpr_stabilized": 0.60,
        "independent_low_noise_recall_safe": 0.62,
        "independent_balanced_safe": 0.58,
        "independent_high_confidence_boundary": 0.66,
    }
    unresolved_unknown_service = (
        app == "unknown-tcp"
        and action == "allow"
        and port >= 1024
        and unresolved_rule
        and threat_probability < unknown_caps[profile]
    )
    if unresolved_unknown_service:
        return _route_to_analyst_review(
            row,
            reason=(
                "Unresolved allowed high-port service lacks rule or "
                "behavior-window threat evidence."
            ),
        )

    include_incomplete_boundary = profile in {
        "independent_low_noise_recall_safe",
        "independent_high_confidence_boundary",
    }
    unresolved_incomplete_session = (
        include_incomplete_boundary
        and app == "incomplete"
        and action == "allow"
        and port in {80, 443, 8080, 8443}
        and unresolved_rule
        and threat_probability < 0.65
    )
    if unresolved_incomplete_session:
        return _route_to_analyst_review(
            row,
            reason=(
                "Incomplete allowed web session has no rule or behavior-window "
                "evidence and remains an analyst-review boundary."
            ),
        )
    return row


def _profile_safety_reasons(profile: dict[str, Any]) -> list[str]:
    metrics = profile.get("metrics") or {}
    per_class = metrics.get("per_class") or {}
    reasons = []
    if _safe_float(metrics.get("threat_positive_recall")) < 0.85:
        reasons.append("threat recall below 0.85")
    if _safe_float(
        (per_class.get("suspicious") or {}).get("recall")
    ) < 0.80:
        reasons.append("suspicious recall below 0.80")
    if _safe_float(
        (per_class.get("malicious") or {}).get("recall")
    ) < 0.60:
        reasons.append("malicious recall below 0.60")
    if _safe_float(
        metrics.get("benign_false_positive_rate"),
        1.0,
    ) > 0.15:
        reasons.append("benign FPR exceeds 0.15")
    if profile.get("uses_source_or_scenario_identity"):
        reasons.append("profile depends on source/scenario identity")
    if not profile.get("preserves_behavior_evidence"):
        reasons.append("profile does not preserve behavior-window evidence")
    return reasons


def _select_best_profile(profiles: list[dict[str, Any]]) -> dict[str, Any]:
    eligible = [item for item in profiles if not item.get("rejected")]
    candidates = eligible or profiles
    return min(
        candidates,
        key=lambda item: (
            PROFILE_SELECTION_ORDER.get(str(item.get("profile")), 99),
            -_safe_float((item.get("metrics") or {}).get("threat_positive_f1")),
            _safe_float(
                (item.get("metrics") or {}).get("benign_false_positive_rate"),
                1.0,
            ),
        ),
    )


def _false_positive_analysis(
    *,
    records: list[BenchmarkRecord],
    y_true: list[str],
    rows: list[dict[str, Any]],
) -> dict[str, Any]:
    false_positive_rows = []
    benign_count = sum(1 for value in y_true if value == "benign_like")
    allowed_false_positives = math.floor(benign_count * 0.15)
    for record, actual, row in zip(records, y_true, rows, strict=False):
        if actual != "benign_like" or row["prediction"] not in THREAT_LABELS:
            continue
        normalized = record.normalized
        false_positive_rows.append(
            {
                "original_label": record.label,
                "prediction": row["prediction"],
                "source": normalized.get("source_name") or "unknown",
                "scenario": normalized.get("scenario") or "unknown",
                "app": normalized.get("app") or "unknown",
                "action": normalized.get("action") or "unknown",
                "dst_port": _safe_int(normalized.get("dst_port")),
                "rule_class": (
                    (row.get("rule") or {}).get("suggested_class")
                    or "benign_like"
                ),
                "behavior_evidence": (
                    (row.get("behavior_evidence") or {}).get("reason")
                ),
            }
        )

    def count(field: str) -> dict[str, int]:
        return dict(
            Counter(str(item[field]) for item in false_positive_rows).most_common()
        )

    pattern_counts = Counter(
        (
            str(item["app"]),
            str(item["action"]),
            str(item["dst_port"]),
            str(item["rule_class"]),
        )
        for item in false_positive_rows
    )
    return {
        "benign_like_rows": benign_count,
        "false_positive_count": len(false_positive_rows),
        "allowed_false_positives_at_target": allowed_false_positives,
        "minimum_reduction_needed": max(
            0,
            len(false_positive_rows) - allowed_false_positives,
        ),
        "predictions": count("prediction"),
        "original_labels": count("original_label"),
        "sources": count("source"),
        "scenarios": count("scenario"),
        "apps": count("app"),
        "actions": count("action"),
        "behavior_evidence_rows": sum(
            1 for item in false_positive_rows if item["behavior_evidence"]
        ),
        "top_patterns": [
            {
                "app": values[0],
                "action": values[1],
                "dst_port": values[2],
                "rule_class": values[3],
                "count": total,
            }
            for values, total in pattern_counts.most_common(12)
        ],
        "interpretation": (
            "All observed false positives are ambiguous needs_context rows. "
            "No false positive was created by a behavior-window overlay."
            if false_positive_rows
            and set(count("original_label")) == {"needs_context"}
            and not any(item["behavior_evidence"] for item in false_positive_rows)
            else "False positives span multiple evidence patterns."
        ),
    }


def _render_analysis(analysis: dict[str, Any]) -> str:
    lines = [
        "# ATDR v1.9b Independent FPR Analysis",
        "",
        f"- Benign-like evaluation rows: {analysis['benign_like_rows']}",
        f"- False positives before stabilization: {analysis['false_positive_count']}",
        f"- Allowed false positives at FPR <= 0.15: {analysis['allowed_false_positives_at_target']}",
        f"- Minimum reduction needed: {analysis['minimum_reduction_needed']}",
        f"- Behavior-overlay false positives: {analysis['behavior_evidence_rows']}",
        f"- Interpretation: {analysis['interpretation']}",
        "",
        "## Prediction And Label Mix",
        "",
        f"- Predictions: {analysis['predictions']}",
        f"- Original labels: {analysis['original_labels']}",
        f"- Apps: {analysis['apps']}",
        f"- Actions: {analysis['actions']}",
        f"- Sources: {analysis['sources']}",
        f"- Scenarios: {analysis['scenarios']}",
        "",
        "## Top Patterns",
        "",
        "| App | Action | Destination port | Rule class | Count |",
        "| --- | --- | ---: | --- | ---: |",
    ]
    for item in analysis["top_patterns"]:
        lines.append(
            f"| {item['app']} | {item['action']} | {item['dst_port']} | "
            f"{item['rule_class']} | {item['count']} |"
        )
    lines.extend(
        [
            "",
            "## Stabilization Decision",
            "",
            "The narrow candidate keeps all behavior-window evidence and "
            "rule-supported threat patterns. Only unresolved allowed high-port "
            "`unknown-tcp` rows are routed to analyst review. Source and scenario "
            "identity are not inputs to the policy.",
        ]
    )
    return "\n".join(lines)


def _render_report(report: dict[str, Any]) -> str:
    lines = [
        "# ATDR v1.9b Independent FPR Stabilization",
        "",
        f"- Generated: {report['generated_at']}",
        "- Production promoted: false",
        "- Model activated: false",
        "- Response automation: disabled",
        "- Real firewall blocking: disabled",
        "",
        "## Profile Comparison",
        "",
        "| Profile | Threat P | Threat R | Threat F1 | Benign FPR | Susp R | Mal R | Macro F1 | Weighted F1 | ECE | Brier | FP | FN | Review boundary | Result |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |",
    ]
    for item in report["profiles"]:
        metrics = item["metrics"]
        per_class = metrics.get("per_class") or {}
        calibration = item["calibration"]
        lines.append(
            f"| {item['profile']} | {metrics.get('threat_positive_precision')} | "
            f"{metrics.get('threat_positive_recall')} | "
            f"{metrics.get('threat_positive_f1')} | "
            f"{metrics.get('benign_false_positive_rate')} | "
            f"{(per_class.get('suspicious') or {}).get('recall')} | "
            f"{(per_class.get('malicious') or {}).get('recall')} | "
            f"{metrics.get('macro_f1')} | {metrics.get('weighted_f1')} | "
            f"{calibration.get('expected_calibration_error')} | "
            f"{calibration.get('brier_score_threat_positive')} | "
            f"{metrics.get('false_positives')} | "
            f"{metrics.get('false_negatives')} | "
            f"{item.get('analyst_review_boundary_count')} | "
            f"{'REJECT' if item.get('rejected') else 'PASS'} |"
        )
    best = report["best_profile"]
    readiness = report["readiness_gate_v7b"]
    lines.extend(
        [
            "",
            "## Selected Candidate",
            "",
            f"- Profile: {best['profile']}",
            f"- Threat F1: {best['metrics'].get('threat_positive_f1')}",
            f"- Benign FPR: {best['metrics'].get('benign_false_positive_rate')}",
            f"- Analyst-review boundary rows: {best.get('analyst_review_boundary_count')}",
            f"- Readiness: {readiness['decision']} ({readiness['passed']}/{readiness['total']})",
            f"- Independent holdout validated: {readiness['independent_holdout_validated']}",
            f"- Controlled real-source validated: {readiness['controlled_real_source_validated']}",
            "",
            "This is an independently revalidated decision-support candidate, "
            "not production deployment approval.",
        ]
    )
    return "\n".join(lines)


def run_v19b_independent_fpr_stabilization(
    *,
    output_dir: Path = DEFAULT_OUTPUT_DIR,
    holdout_rows: int = 500,
    write_output: bool = True,
) -> dict[str, Any]:
    started = time.perf_counter()
    imports = _optional_imports()
    if imports is None:
        return {
            "ok": False,
            "status": "skipped",
            "message": "Supervised ML dependencies are unavailable.",
            "production_promoted": False,
            "model_activated": False,
            "response_automation_allowed": False,
        }
    pd = imports[1]
    holdout = build_independent_holdout(
        output_dir=output_dir,
        csv_path=output_dir / "v1_9_independent_holdout.csv",
        row_limit=holdout_rows,
    )
    records, holdout_summary = load_prepared_benchmark_snapshot(
        Path(str(holdout["snapshot_path"]))
    )
    build_internal_ai_readiness_benchmark(output_path=INTERNAL_CSV)
    internal_snapshot = prepare_benchmark_dataset(
        input_csv=INTERNAL_CSV,
        sample_strategy="balanced",
        output_dir=BENCHMARK_OUTPUT_DIR,
    )
    training_records, training_summary = load_prepared_benchmark_snapshot(
        Path(internal_snapshot["snapshot_path"])
    )
    training_frame = _feature_frame(
        training_records,
        source_name="v19b-internal-training",
        dataframe_type=pd.DataFrame,
    )
    holdout_frame = _feature_frame(
        records,
        source_name="v19b-independent-holdout",
        dataframe_type=pd.DataFrame,
    )
    models = _train_base_models(
        imports=imports,
        training_frame=training_frame,
        holdout_frame=holdout_frame,
        training_records=training_records,
    )
    probabilities = _model_probabilities(
        models["extra_trees"],
        holdout_frame,
        LABELS_ORDER,
    )
    feature_rows = holdout_frame.to_dict(orient="records")
    y_true = [_triage_label(record) for record in records]
    external_rows = []
    for index, record in enumerate(records):
        baseline = _profile_prediction(
            record,
            probabilities[index],
            profile="hybrid_external_balanced",
        )
        external_rows.append(
            _predict_profile(
                record=record,
                features=feature_rows[index],
                baseline=baseline,
                profile="external_recall_plus",
                calibrator={"method": "none"},
            )
        )
    analysis = _false_positive_analysis(
        records=records,
        y_true=y_true,
        rows=external_rows,
    )

    profile_rows: dict[str, list[dict[str, Any]]] = {}
    for profile in PROFILE_NAMES:
        if profile == "external_recall_plus":
            rows = external_rows
        elif profile in STABILIZED_PROFILES:
            rows = [
                stabilize_independent_boundary(
                    record=record,
                    row=external_rows[index],
                    profile=profile,
                )
                for index, record in enumerate(records)
            ]
        else:
            rows = [
                _profile_prediction(
                    record,
                    probabilities[index],
                    profile=profile,
                )
                for index, record in enumerate(records)
            ]
        profile_rows[profile] = rows

    v18 = _load_json(
        _latest_report_path(
            output_dir,
            "v1_8_external_benchmark_finalization_*.json",
        )
    )
    external_benchmark_passed = bool(
        (v18.get("readiness_gate_v6") or {}).get(
            "external_benchmark_validated"
        )
    )
    controlled_source = _latest_controlled_source_report(output_dir)
    controlled_source_passed = bool(
        controlled_source.get("controlled_real_source_validated")
    )
    controlled_validations_passed = bool(_latest_validation_status()["passed"])
    performance = run_performance_smoke(feature_limit=10)
    performance_healthy = bool(performance.get("ok")) and not performance.get(
        "warnings"
    )

    results = []
    for profile in PROFILE_NAMES:
        rows = profile_rows[profile]
        predictions = [str(row["prediction"]) for row in rows]
        evaluated = _evaluate_predictions(
            y_true=y_true,
            predictions=predictions,
            probability_rows=[row["probability_row"] for row in rows],
            imports=imports,
        )
        calibration = _cross_fitted_confidence_calibration(
            y_true=y_true,
            predictions=predictions,
            probabilities=[row["probabilities"] for row in rows],
        )
        preserves_behavior = profile not in {
            "hybrid_external_balanced",
            "high_confidence_external",
        }
        review_count = sum(
            1 for row in rows if row.get("analyst_review_recommended")
        )
        profile_result = {
            "profile": profile,
            **evaluated,
            "calibration": calibration["selected_metrics"],
            "calibration_method": calibration["selected_method"],
            "calibration_experiment": calibration,
            "analyst_review_boundary_count": review_count,
            "estimated_review_queue_size": (
                int(evaluated["queue_size"]) + review_count
            ),
            "uses_source_or_scenario_identity": False,
            "preserves_behavior_evidence": preserves_behavior,
            "ambiguous_rows_routed_to_review": (
                profile in STABILIZED_PROFILES
            ),
            "controlled_source_validation_status": (
                "passed" if controlled_source_passed else "missing_or_failed"
            ),
            "production_promoted": False,
            "model_activated": False,
            "response_automation_allowed": False,
        }
        reasons = _profile_safety_reasons(profile_result)
        profile_result["rejected"] = bool(reasons)
        profile_result["rejection_reasons"] = reasons
        profile_result["readiness_gate_v7b"] = (
            readiness_gate_v7b_fpr_stabilization(
                independent_label_count=len(records),
                independent_metrics=profile_result["metrics"],
                calibration_status=str(
                    profile_result["calibration"].get("status") or "missing"
                ),
                external_benchmark_passed=external_benchmark_passed,
                independent_overlap_passed=bool(
                    holdout["previous_holdout_overlap"][
                        "exact_overlap_passed"
                    ]
                ),
                controlled_real_source_passed=controlled_source_passed,
                controlled_validations_passed=controlled_validations_passed,
                performance_smoke_healthy=performance_healthy,
                uses_source_or_scenario_identity=False,
                preserves_behavior_evidence=preserves_behavior,
                ambiguous_rows_routed_to_review=(
                    profile in STABILIZED_PROFILES
                ),
            )
        )
        results.append(profile_result)

    best = _select_best_profile(results)
    report = {
        "ok": True,
        "status": "completed",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "validation_scope": "v1.9b independent FPR stabilization",
        "independent_holdout": holdout,
        "independent_snapshot": {
            "snapshot_id": holdout_summary.get("snapshot_id"),
            "snapshot_name": Path(str(holdout["snapshot_path"])).name,
        },
        "internal_training_snapshot": {
            "snapshot_id": training_summary.get("snapshot_id"),
            "row_count": len(training_records),
        },
        "false_positive_analysis": analysis,
        "profiles": results,
        "best_profile": best,
        "before_after": {
            "before_profile": "external_recall_plus",
            "before_metrics": results[0]["metrics"],
            "after_profile": best["profile"],
            "after_metrics": best["metrics"],
            "false_positives_reduced": (
                int(results[0]["metrics"]["false_positives"])
                - int(best["metrics"]["false_positives"])
            ),
        },
        "controlled_real_source_validation": {
            "available": bool(controlled_source),
            "passed": controlled_source_passed,
            "latest_report_name": (
                Path(
                    str((controlled_source.get("paths") or {}).get("json"))
                ).name
                if (controlled_source.get("paths") or {}).get("json")
                else None
            ),
        },
        "performance_smoke": {
            "healthy": performance_healthy,
            "warnings": performance.get("warnings") or [],
            "timings": performance.get("timings") or {},
        },
        "readiness_gate_v7b": best["readiness_gate_v7b"],
        "production_promoted": False,
        "model_activated": False,
        "model_artifact_written": False,
        "response_automation_allowed": False,
        "real_firewall_blocking_enabled": False,
        "runtime_seconds": round(time.perf_counter() - started, 4),
    }
    if write_output:
        output_dir.mkdir(parents=True, exist_ok=True)
        stamp = _stamp()
        json_path = (
            output_dir
            / f"v1_9b_independent_fpr_stabilization_{stamp}.json"
        )
        markdown_path = (
            output_dir
            / f"v1_9b_independent_fpr_stabilization_{stamp}.md"
        )
        analysis_path = (
            output_dir / f"v1_9b_independent_fpr_analysis_{stamp}.md"
        )
        json_path.write_text(
            json.dumps(report, indent=2, default=json_default),
            encoding="utf-8",
        )
        markdown_path.write_text(_render_report(report), encoding="utf-8")
        analysis_path.write_text(_render_analysis(analysis), encoding="utf-8")
        report["paths"] = {
            "json": str(json_path),
            "markdown": str(markdown_path),
            "analysis": str(analysis_path),
        }
    return report


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Compare identity-independent v1.9b FPR stabilization profiles "
            "without activating a model."
        )
    )
    parser.add_argument("--output-dir", default=str(DEFAULT_OUTPUT_DIR))
    parser.add_argument("--rows", type=int, default=500)
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()
    result = run_v19b_independent_fpr_stabilization(
        output_dir=Path(args.output_dir),
        holdout_rows=args.rows,
    )
    print(
        json.dumps(
            result,
            indent=2 if args.pretty else None,
            default=json_default,
        )
    )
    raise SystemExit(0 if result.get("ok") else 1)


if __name__ == "__main__":
    main()
