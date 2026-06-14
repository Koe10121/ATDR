import argparse
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from atdr.app.benchmarks.adapter import load_prepared_benchmark_snapshot
from atdr.app.benchmarks.readiness import readiness_gate_v7_independent_validation
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
    _anomaly_signal,
    _evaluate_predictions,
    _latest_report_path,
    _load_json,
    _model_probabilities,
    _normalize_probs,
    _profile_prediction,
    _rule_signal,
    _safe_float,
    _train_base_models,
)
from atdr.scripts.run_v18_external_benchmark_finalization import (
    _cross_fitted_confidence_calibration,
    _predict_profile,
    _probability_row,
)


PROFILE_NAMES = (
    "external_recall_plus",
    "hybrid_external_balanced",
    "low_noise_external",
    "high_confidence_external",
    "rules_only",
    "anomaly_only",
    "supervised_only",
    "hybrid",
)


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _latest_controlled_source_report(output_dir: Path) -> dict[str, Any]:
    return _load_json(
        _latest_report_path(
            output_dir,
            "v1_9_controlled_real_source_validation_*.json",
        )
    )


def _simple_row(
    *,
    prediction: str,
    probabilities: dict[str, float],
    rule: dict[str, Any],
    anomaly: dict[str, Any],
) -> dict[str, Any]:
    normalized = _normalize_probs(probabilities)
    return {
        "prediction": prediction,
        "confidence": round(max(normalized.values()), 4),
        "probabilities": normalized,
        "probability_row": _probability_row(normalized),
        "threat_probability": round(
            normalized["suspicious"] + normalized["malicious"],
            4,
        ),
        "rule": rule,
        "anomaly": anomaly,
        "hybrid_risk": round(
            min(
                1.0,
                0.58 * (normalized["suspicious"] + normalized["malicious"])
                + 0.28 * _safe_float(rule.get("score"))
                + 0.14 * _safe_float(anomaly.get("score")),
            ),
            4,
        ),
    }


def _rules_only_row(record) -> dict[str, Any]:
    rule = _rule_signal(record)
    anomaly = _anomaly_signal(record)
    suggested = str(rule.get("suggested_class") or "benign_like")
    score = _safe_float(rule.get("score"))
    prediction = suggested if suggested in THREAT_LABELS and score >= 0.55 else "benign_like"
    probabilities = {
        "benign_like": 1.0 - score if prediction in THREAT_LABELS else max(0.7, 1.0 - score),
        "suspicious": score if prediction == "suspicious" else 0.04,
        "malicious": score if prediction == "malicious" else 0.04,
    }
    return _simple_row(
        prediction=prediction,
        probabilities=probabilities,
        rule=rule,
        anomaly=anomaly,
    )


def _anomaly_only_row(record) -> dict[str, Any]:
    rule = _rule_signal(record)
    anomaly = _anomaly_signal(record)
    score = _safe_float(anomaly.get("score"))
    prediction = "suspicious" if score >= 0.55 else "benign_like"
    probabilities = {
        "benign_like": 1.0 - score,
        "suspicious": score,
        "malicious": 0.0,
    }
    return _simple_row(
        prediction=prediction,
        probabilities=probabilities,
        rule=rule,
        anomaly=anomaly,
    )


def _supervised_only_row(record, probabilities: dict[str, float]) -> dict[str, Any]:
    rule = _rule_signal(record)
    anomaly = _anomaly_signal(record)
    normalized = _normalize_probs(probabilities)
    prediction = max(normalized.items(), key=lambda item: item[1])[0]
    return _simple_row(
        prediction=prediction,
        probabilities=normalized,
        rule=rule,
        anomaly=anomaly,
    )


def _gap_summary(
    *,
    internal_metrics: dict[str, Any],
    external_metrics: dict[str, Any],
    independent_metrics: dict[str, Any],
) -> dict[str, Any]:
    names = (
        "threat_positive_precision",
        "threat_positive_recall",
        "threat_positive_f1",
        "benign_false_positive_rate",
        "macro_f1",
        "weighted_f1",
    )
    rows = {}
    for name in names:
        internal = _safe_float(internal_metrics.get(name))
        external = _safe_float(external_metrics.get(name))
        independent = _safe_float(independent_metrics.get(name))
        rows[name] = {
            "internal": internal,
            "external": external,
            "independent": independent,
            "external_to_independent_change": round(independent - external, 4),
            "internal_to_independent_change": round(independent - internal, 4),
        }
    external_f1_gap = abs(
        rows["threat_positive_f1"]["external_to_independent_change"]
    )
    fpr_gap = abs(
        rows["benign_false_positive_rate"]["external_to_independent_change"]
    )
    status = (
        "significant_independent_gap"
        if external_f1_gap >= 0.15 or fpr_gap >= 0.15
        else "moderate_independent_gap"
        if external_f1_gap >= 0.05 or fpr_gap >= 0.05
        else "limited_independent_gap"
    )
    return {
        "status": status,
        "metrics": rows,
        "interpretation": (
            "The new independent holdout materially differs from v1.8."
            if status == "significant_independent_gap"
            else "The new holdout shows measurable but bounded degradation."
            if status == "moderate_independent_gap"
            else "The v1.8 profile transfers with a limited measured gap."
        ),
    }


def _best_profile(profiles: list[dict[str, Any]]) -> dict[str, Any]:
    return max(
        profiles,
        key=lambda item: (
            _safe_float(item["metrics"].get("threat_positive_f1"))
            - 0.75
            * max(
                0.0,
                _safe_float(
                    item["metrics"].get("benign_false_positive_rate")
                )
                - 0.15,
            ),
            _safe_float(item["metrics"].get("threat_positive_precision")),
            _safe_float(
                ((item["metrics"].get("per_class") or {}).get("suspicious") or {}).get(
                    "recall"
                )
            ),
            -_safe_float(item["metrics"].get("benign_false_positive_rate")),
        ),
    )


def _render_report(report: dict[str, Any]) -> str:
    lines = [
        "# ATDR v1.9 Independent Revalidation",
        "",
        f"- Generated: {report['generated_at']}",
        f"- Independent rows: {report['independent_holdout']['row_count']}",
        f"- Sources: {report['independent_holdout']['source_count']}",
        f"- Scenarios: {report['independent_holdout']['scenario_count']}",
        f"- Exact previous-holdout overlap: {report['independent_holdout']['previous_holdout_overlap']['exact_overlap_rows']}",
        "- Production promoted: false",
        "- Model activated: false",
        "- Response automation: disabled",
        "",
        "## Profile Comparison",
        "",
        "| Profile | Threat P | Threat R | Threat F1 | Benign FPR | Susp R | Mal R | Macro F1 | Weighted F1 | ECE | Brier | Runtime |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for item in report["profiles"]:
        metrics = item["metrics"]
        per_class = metrics.get("per_class") or {}
        calibration = item["calibration"]
        lines.append(
            f"| {item['profile']} | {metrics.get('threat_positive_precision')} | "
            f"{metrics.get('threat_positive_recall')} | {metrics.get('threat_positive_f1')} | "
            f"{metrics.get('benign_false_positive_rate')} | "
            f"{(per_class.get('suspicious') or {}).get('recall')} | "
            f"{(per_class.get('malicious') or {}).get('recall')} | "
            f"{metrics.get('macro_f1')} | {metrics.get('weighted_f1')} | "
            f"{calibration.get('expected_calibration_error')} | "
            f"{calibration.get('brier_score_threat_positive')} | "
            f"{item.get('runtime_seconds')} |"
        )
    best = report["best_profile"]
    readiness = report["readiness_gate_v7"]
    lines.extend(
        [
            "",
            "## Selected Result",
            "",
            f"- Best profile: {best['profile']}",
            f"- Readiness v7: {readiness['decision']}",
            f"- Independent holdout validated: {readiness['independent_holdout_validated']}",
            f"- Controlled real-source validated: {readiness['controlled_real_source_validated']}",
            f"- Calibration: {best['calibration'].get('status')} using {best['calibration_method']}",
            f"- Independent gap: {report['generalization_gap']['status']}",
            "",
            "This remains SOC triage decision support. It is not production promotion.",
        ]
    )
    return "\n".join(lines)


def run_v19_independent_revalidation(
    *,
    output_dir: Path = DEFAULT_OUTPUT_DIR,
    holdout_rows: int = 500,
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
        source_name="v19-internal-training",
        dataframe_type=pd.DataFrame,
    )
    holdout_frame = _feature_frame(
        records,
        source_name="v19-independent-holdout",
        dataframe_type=pd.DataFrame,
    )
    models = _train_base_models(
        imports=imports,
        training_frame=training_frame,
        holdout_frame=holdout_frame,
        training_records=training_records,
    )
    base_probabilities = _model_probabilities(
        models["extra_trees"],
        holdout_frame,
        LABELS_ORDER,
    )
    low_noise_probabilities = _model_probabilities(
        models["extra_trees_low_noise"],
        holdout_frame,
        LABELS_ORDER,
    )
    feature_rows = holdout_frame.to_dict(orient="records")
    y_true = [_triage_label(record) for record in records]
    profile_rows: dict[str, list[dict[str, Any]]] = {name: [] for name in PROFILE_NAMES}
    profile_runtime: dict[str, float] = {}
    for profile in PROFILE_NAMES:
        profile_started = time.perf_counter()
        for index, record in enumerate(records):
            base = base_probabilities[index]
            low_noise = low_noise_probabilities[index]
            if profile == "rules_only":
                row = _rules_only_row(record)
            elif profile == "anomaly_only":
                row = _anomaly_only_row(record)
            elif profile == "supervised_only":
                row = _supervised_only_row(record, base)
            elif profile == "external_recall_plus":
                baseline = _profile_prediction(
                    record,
                    base,
                    profile="hybrid_external_balanced",
                )
                row = _predict_profile(
                    record=record,
                    features=feature_rows[index],
                    baseline=baseline,
                    profile="external_recall_plus",
                    calibrator={"method": "none"},
                )
            elif profile == "hybrid_external_balanced":
                row = _profile_prediction(
                    record,
                    base,
                    profile="hybrid_external_balanced",
                )
            elif profile == "low_noise_external":
                row = _profile_prediction(
                    record,
                    low_noise,
                    profile="low_noise_external",
                )
            elif profile == "high_confidence_external":
                row = _profile_prediction(
                    record,
                    base,
                    profile="high_confidence_external",
                )
            else:
                row = _profile_prediction(record, base, profile="current_hybrid")
            profile_rows[profile].append(row)
        profile_runtime[profile] = round(time.perf_counter() - profile_started, 4)

    results = []
    for profile in PROFILE_NAMES:
        rows = profile_rows[profile]
        predictions = [row["prediction"] for row in rows]
        evaluated = _evaluate_predictions(
            y_true=y_true,
            predictions=predictions,
            probability_rows=[row["probability_row"] for row in rows],
            imports=imports,
        )
        confidence_calibration = _cross_fitted_confidence_calibration(
            y_true=y_true,
            predictions=predictions,
            probabilities=[row["probabilities"] for row in rows],
        )
        results.append(
            {
                "profile": profile,
                **evaluated,
                "calibration": confidence_calibration["selected_metrics"],
                "calibration_method": confidence_calibration["selected_method"],
                "calibration_experiment": confidence_calibration,
                "runtime_seconds": profile_runtime[profile],
                "model_artifact_written": False,
                "model_activated": False,
                "response_automation_allowed": False,
            }
        )
    best = _best_profile(results)
    v18 = _load_json(
        _latest_report_path(
            output_dir,
            "v1_8_external_benchmark_finalization_*.json",
        )
    )
    v18_metrics = ((v18.get("best_profile") or {}).get("metrics") or {})
    internal_report = _load_json(
        _latest_report_path(
            PROJECT_ROOT / "ml_baseline_reviews",
            "final_ai_readiness_report_*.json",
        )
    )
    internal_metrics = (
        (internal_report.get("best_benchmark_candidate") or {}).get("metrics") or {}
    )
    controlled_source = _latest_controlled_source_report(output_dir)
    performance = run_performance_smoke(feature_limit=10)
    performance_healthy = bool(performance.get("ok")) and not performance.get(
        "warnings"
    )
    controlled_validations_passed = bool(_latest_validation_status()["passed"])
    readiness = readiness_gate_v7_independent_validation(
        independent_label_count=len(records),
        independent_metrics=best["metrics"],
        calibration_status=str(best["calibration"].get("status") or "missing"),
        external_benchmark_passed=bool(
            (v18.get("readiness_gate_v6") or {}).get(
                "external_benchmark_validated"
            )
        ),
        independent_overlap_passed=bool(
            holdout["previous_holdout_overlap"]["exact_overlap_passed"]
        ),
        controlled_real_source_passed=bool(
            controlled_source.get("controlled_real_source_validated")
        ),
        controlled_validations_passed=controlled_validations_passed,
        performance_smoke_healthy=performance_healthy,
    )
    report = {
        "ok": True,
        "status": "completed",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "validation_scope": "v1.9 independent holdout revalidation",
        "independent_holdout": holdout,
        "independent_snapshot": {
            "snapshot_id": holdout_summary.get("snapshot_id"),
            "snapshot_name": Path(str(holdout["snapshot_path"])).name,
        },
        "internal_training_snapshot": {
            "snapshot_id": training_summary.get("snapshot_id"),
            "row_count": len(training_records),
        },
        "profiles": results,
        "best_profile": best,
        "v18_external_metrics": v18_metrics,
        "generalization_gap": _gap_summary(
            internal_metrics=internal_metrics,
            external_metrics=v18_metrics,
            independent_metrics=best["metrics"],
        ),
        "controlled_real_source_validation": {
            "available": bool(controlled_source),
            "passed": bool(
                controlled_source.get("controlled_real_source_validated")
            ),
            "latest_report_name": (
                Path(str((controlled_source.get("paths") or {}).get("json"))).name
                if (controlled_source.get("paths") or {}).get("json")
                else None
            ),
        },
        "performance_smoke": {
            "healthy": performance_healthy,
            "warnings": performance.get("warnings") or [],
            "timings": performance.get("timings") or {},
        },
        "readiness_gate_v7": readiness,
        "production_promoted": False,
        "model_activated": False,
        "model_artifact_written": False,
        "response_automation_allowed": False,
        "real_firewall_blocking_enabled": False,
        "runtime_seconds": round(time.perf_counter() - started, 4),
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    stamp = _stamp()
    json_path = output_dir / f"v1_9_independent_revalidation_{stamp}.json"
    markdown_path = output_dir / f"v1_9_independent_revalidation_{stamp}.md"
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
            "Evaluate v1.8 and baseline profiles on a new independent holdout "
            "without activating a model."
        )
    )
    parser.add_argument("--output-dir", default=str(DEFAULT_OUTPUT_DIR))
    parser.add_argument("--rows", type=int, default=500)
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()
    result = run_v19_independent_revalidation(
        output_dir=Path(args.output_dir),
        holdout_rows=args.rows,
    )
    print(json.dumps(result, indent=2 if args.pretty else None, default=json_default))
    raise SystemExit(0 if result.get("ok") else 1)


if __name__ == "__main__":
    main()
