import argparse
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from atdr.app.benchmarks.adapter import load_prepared_benchmark_snapshot
from atdr.app.benchmarks.readiness import (
    readiness_gate_v8_fresh_blind_validation,
)
from atdr.app.detection.supervised_detector import _optional_imports
from atdr.scripts.build_fresh_blind_holdout import (
    DEFAULT_OUTPUT_DIR,
    build_fresh_blind_holdout,
)
from atdr.scripts.build_internal_ai_readiness_benchmark import (
    DEFAULT_OUTPUT as INTERNAL_CSV,
    build_internal_ai_readiness_benchmark,
)
from atdr.scripts.detection_reliability_common import json_default
from atdr.scripts.lock_v20_candidate import (
    CALIBRATION_METHOD,
    CANDIDATE_NAME,
    lock_v20_candidate,
)
from atdr.scripts.performance_smoke import run_performance_smoke
from atdr.scripts.prepare_benchmark_dataset import prepare_benchmark_dataset
from atdr.scripts.run_benchmark_ml_experiment import _triage_label
from atdr.scripts.run_external_benchmark_validation import (
    BENCHMARK_OUTPUT_DIR,
    _calibration_metrics,
    _feature_frame,
)
from atdr.scripts.run_v15_ai_readiness_validation import _latest_validation_status
from atdr.scripts.run_v17_external_generalization import (
    LABELS_ORDER,
    _evaluate_predictions,
    _latest_report_path,
    _load_json,
    _model_probabilities,
    _profile_prediction,
    _train_base_models,
)
from atdr.scripts.run_v18_external_benchmark_finalization import (
    _probability_row,
    _predict_profile,
)
from atdr.scripts.run_v19_independent_revalidation import (
    _latest_controlled_source_report,
)
from atdr.scripts.run_v19b_independent_fpr_stabilization import (
    stabilize_independent_boundary,
)


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _fixed_calibration(
    *,
    y_true: list[str],
    predictions: list[str],
    probabilities: list[dict[str, float]],
) -> dict[str, Any]:
    metrics = _calibration_metrics(
        y_true=y_true,
        y_pred=predictions,
        probabilities=[_probability_row(row) for row in probabilities],
        classes=LABELS_ORDER,
    )
    return {
        "locked_method": CALIBRATION_METHOD,
        "method_available": True,
        "metrics": metrics,
        "cross_fitted": False,
        "fold_count": 0,
        "method_selection_performed": False,
        "external_labels_used_for_fit": False,
        "fit_scope": (
            "No calibrator was fitted on the blind holdout. Metrics measure "
            "the frozen candidate's raw confidence against blind labels."
        ),
    }


def _latest_final_acceptance(output_dir: Path) -> dict[str, Any]:
    return _load_json(
        _latest_report_path(
            output_dir,
            "v2_0_final_controlled_source_acceptance_*.json",
        )
    )


def _render_report(report: dict[str, Any]) -> str:
    metrics = report["metrics"]
    per_class = metrics.get("per_class") or {}
    calibration = report["calibration"]
    readiness = report["readiness_gate_v8"]
    overlap = report["fresh_blind_holdout"]["previous_holdout_overlap"]
    return "\n".join(
        [
            "# ATDR v2.0 Fresh Blind Revalidation",
            "",
            f"- Generated: {report['generated_at']}",
            f"- Frozen candidate: `{report['candidate']['name']}`",
            f"- Candidate hash: `{report['candidate']['hash']}`",
            "- Threshold tuning performed: false",
            "- Source/scenario identity used: false",
            "",
            "## Blind Holdout",
            "",
            f"- Rows: {report['fresh_blind_holdout']['row_count']}",
            f"- Sources: {report['fresh_blind_holdout']['source_count']}",
            f"- Scenarios: {report['fresh_blind_holdout']['scenario_count']}",
            f"- Exact previous overlap: {overlap['exact_overlap_rows']}",
            f"- Near-pattern overlap: {overlap['near_overlap_rows']}",
            f"- Labels: {report['fresh_blind_holdout']['label_distribution']}",
            "",
            "## Frozen Candidate Metrics",
            "",
            f"- Threat precision: {metrics.get('threat_positive_precision')}",
            f"- Threat recall: {metrics.get('threat_positive_recall')}",
            f"- Threat F1: {metrics.get('threat_positive_f1')}",
            f"- Benign-like FPR: {metrics.get('benign_false_positive_rate')}",
            f"- Suspicious recall: {(per_class.get('suspicious') or {}).get('recall')}",
            f"- Malicious recall: {(per_class.get('malicious') or {}).get('recall')}",
            f"- Macro F1: {metrics.get('macro_f1')}",
            f"- Weighted F1: {metrics.get('weighted_f1')}",
            f"- False positives: {metrics.get('false_positives')}",
            f"- False negatives: {metrics.get('false_negatives')}",
            f"- Confusion matrix: {metrics.get('confusion_matrix')}",
            "",
            "## Calibration",
            "",
            f"- Locked method: `{calibration['locked_method']}`",
            f"- Status: {calibration['metrics'].get('status')}",
            f"- ECE: {calibration['metrics'].get('expected_calibration_error')}",
            f"- Brier: {calibration['metrics'].get('brier_score_threat_positive')}",
            f"- Maximum gap: {calibration['metrics'].get('max_confidence_accuracy_gap')}",
            "",
            "## Readiness",
            "",
            f"- Decision: `{readiness['decision']}`",
            f"- Checks: {readiness['passed']}/{readiness['total']}",
            f"- Fresh blind passed: {readiness['fresh_blind_revalidated']}",
            "- Production promoted: false",
            "- Model activated: false",
            "- Response automation: disabled",
            "- Real firewall blocking: disabled",
            "",
            "The blind holdout was evaluated once with the frozen v1.9b policy. "
            "A failure requires a separate future improvement phase, not tuning "
            "against this holdout.",
        ]
    )


def run_v20_fresh_blind_revalidation(
    *,
    output_dir: Path = DEFAULT_OUTPUT_DIR,
    holdout_rows: int = 700,
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
    candidate_lock = lock_v20_candidate(
        output_dir=output_dir,
        write_output=write_output,
    )
    holdout = build_fresh_blind_holdout(
        output_dir=output_dir,
        csv_path=output_dir / "v2_0_fresh_blind_holdout.csv",
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
        source_name="v20-frozen-internal-training",
        dataframe_type=pd.DataFrame,
    )
    holdout_frame = _feature_frame(
        records,
        source_name="v20-fresh-blind-holdout",
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
    rows = []
    prediction_started = time.perf_counter()
    for index, record in enumerate(records):
        baseline = _profile_prediction(
            record,
            probabilities[index],
            profile="hybrid_external_balanced",
        )
        external = _predict_profile(
            record=record,
            features=feature_rows[index],
            baseline=baseline,
            profile="external_recall_plus",
            calibrator={"method": "none"},
        )
        rows.append(
            stabilize_independent_boundary(
                record=record,
                row=external,
                profile=CANDIDATE_NAME,
            )
        )
    prediction_runtime = round(time.perf_counter() - prediction_started, 4)
    y_true = [_triage_label(record) for record in records]
    predictions = [str(row["prediction"]) for row in rows]
    evaluated = _evaluate_predictions(
        y_true=y_true,
        predictions=predictions,
        probability_rows=[row["probability_row"] for row in rows],
        imports=imports,
    )
    calibration = _fixed_calibration(
        y_true=y_true,
        predictions=predictions,
        probabilities=[row["probabilities"] for row in rows],
    )
    v18 = _load_json(
        _latest_report_path(
            output_dir,
            "v1_8_external_benchmark_finalization_*.json",
        )
    )
    controlled = _latest_controlled_source_report(output_dir)
    final_acceptance = _latest_final_acceptance(output_dir)
    performance = run_performance_smoke(feature_limit=10)
    performance_healthy = bool(performance.get("ok")) and not performance.get(
        "warnings"
    )
    controlled_validations_passed = bool(_latest_validation_status()["passed"])
    readiness = readiness_gate_v8_fresh_blind_validation(
        candidate_lock_valid=bool(candidate_lock.get("ok")),
        fresh_blind_label_count=len(records),
        fresh_blind_source_count=int(holdout.get("source_count") or 0),
        fresh_blind_scenario_count=int(holdout.get("scenario_count") or 0),
        fresh_blind_metrics=evaluated["metrics"],
        calibration_status=str(
            calibration["metrics"].get("status") or "missing"
        ),
        exact_overlap_passed=bool(
            holdout["previous_holdout_overlap"]["exact_overlap_passed"]
        ),
        threshold_tuning_performed=False,
        uses_source_or_scenario_identity=False,
        controlled_real_source_passed=bool(
            controlled.get("controlled_real_source_validated")
        ),
        final_controlled_acceptance_passed=bool(
            final_acceptance.get("final_controlled_validation_passed")
        ),
        controlled_validations_passed=controlled_validations_passed,
        performance_smoke_healthy=performance_healthy,
        external_benchmark_passed=bool(
            (v18.get("readiness_gate_v6") or {}).get(
                "external_benchmark_validated"
            )
        ),
    )
    report = {
        "ok": True,
        "status": (
            "passed"
            if readiness["fresh_blind_revalidated"]
            else "review_required"
        ),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "validation_scope": (
            "v2.0 frozen-candidate evaluation on a fresh blind synthetic holdout"
        ),
        "candidate": {
            "name": CANDIDATE_NAME,
            "hash": candidate_lock.get("candidate_hash"),
            "lock_valid": bool(candidate_lock.get("ok")),
            "lock_report_name": (
                Path(str((candidate_lock.get("paths") or {}).get("json"))).name
                if (candidate_lock.get("paths") or {}).get("json")
                else None
            ),
            "calibration_method": CALIBRATION_METHOD,
        },
        "fresh_blind_holdout": holdout,
        "fresh_blind_snapshot": {
            "snapshot_id": holdout_summary.get("snapshot_id"),
            "snapshot_name": Path(str(holdout["snapshot_path"])).name,
        },
        "internal_training_snapshot": {
            "snapshot_id": training_summary.get("snapshot_id"),
            "row_count": len(training_records),
        },
        "metrics": evaluated["metrics"],
        "cost_sensitive": evaluated["cost_sensitive"],
        "queue_size": evaluated["queue_size"],
        "analyst_review_boundary_count": sum(
            1 for row in rows if row.get("analyst_review_recommended")
        ),
        "calibration": calibration,
        "confusion_matrix": evaluated["metrics"].get("confusion_matrix"),
        "threshold_tuning_performed": False,
        "profile_comparison_performed": False,
        "uses_source_or_scenario_identity": False,
        "prediction_runtime_seconds": prediction_runtime,
        "controlled_real_source_validation": {
            "available": bool(controlled),
            "passed": bool(
                controlled.get("controlled_real_source_validated")
            ),
        },
        "final_controlled_acceptance": {
            "available": bool(final_acceptance),
            "passed": bool(
                final_acceptance.get("final_controlled_validation_passed")
            ),
        },
        "performance_smoke": {
            "healthy": performance_healthy,
            "warnings": performance.get("warnings") or [],
            "timings": performance.get("timings") or {},
        },
        "readiness_gate_v8": readiness,
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
        json_path = output_dir / f"v2_0_fresh_blind_revalidation_{stamp}.json"
        markdown_path = (
            output_dir / f"v2_0_fresh_blind_revalidation_{stamp}.md"
        )
        json_path.write_text(
            json.dumps(report, indent=2, default=json_default),
            encoding="utf-8",
        )
        markdown_path.write_text(_render_report(report), encoding="utf-8")
        report["paths"] = {
            "json": str(json_path),
            "markdown": str(markdown_path),
        }
    return report


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Evaluate the frozen v1.9b candidate once on a fresh blind holdout."
        )
    )
    parser.add_argument("--output-dir", default=str(DEFAULT_OUTPUT_DIR))
    parser.add_argument("--rows", type=int, default=700)
    parser.add_argument("--no-report", action="store_true")
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()
    result = run_v20_fresh_blind_revalidation(
        output_dir=Path(args.output_dir),
        holdout_rows=args.rows,
        write_output=not args.no_report,
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
