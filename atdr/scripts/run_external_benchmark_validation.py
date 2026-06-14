import argparse
import json
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import select

from atdr.app.benchmarks.adapter import (
    BenchmarkRecord,
    load_prepared_benchmark_snapshot,
    write_benchmark_snapshot,
)
from atdr.app.benchmarks.review import (
    apply_benchmark_reviews,
    parse_benchmark_review_csv,
)
from atdr.app.benchmarks.readiness import readiness_gate_v5
from atdr.app.core.config import PROJECT_ROOT
from atdr.app.db.models import NormalizedLog
from atdr.app.detection.supervised_detector import _build_pipeline, _optional_imports
from atdr.app.ml.features import build_feature_rows
from atdr.scripts.build_internal_ai_readiness_benchmark import (
    DEFAULT_OUTPUT as INTERNAL_CSV,
    build_internal_ai_readiness_benchmark,
)
from atdr.scripts.compare_layered_benchmark_reliability import (
    compare_layered_benchmark_reliability,
)
from atdr.scripts.prepare_benchmark_dataset import prepare_benchmark_dataset
from atdr.scripts.prepare_external_benchmark_snapshot import (
    prepare_external_benchmark_snapshot,
)
from atdr.scripts.run_benchmark_ml_experiment import (
    _confidence_buckets,
    _metrics,
    _triage_label,
)
from atdr.scripts.run_detection_benchmark import _insert_records
from atdr.scripts.run_source_scenario import _temp_session_factory
from atdr.scripts.run_v15_ai_readiness_validation import (
    BENCHMARK_OUTPUT_DIR,
    _latest_validation_status,
)


FINAL_OUTPUT_DIR = PROJECT_ROOT / "demo_exports" / "benchmarks"
V15_REPORT_DIR = PROJECT_ROOT / "ml_baseline_reviews"


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _latest_json(directory: Path, pattern: str) -> dict[str, Any]:
    candidates = sorted(
        directory.glob(pattern),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    if not candidates:
        return {}
    try:
        return json.loads(candidates[0].read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _feature_frame(
    records: list[BenchmarkRecord],
    *,
    source_name: str,
    dataframe_type,
) -> Any:
    engine, SessionFactory = _temp_session_factory()
    try:
        with SessionFactory() as db:
            normalized_ids, _source_id = _insert_records(
                db,
                records,
                source_name=source_name,
            )
            logs = list(
                db.scalars(
                    select(NormalizedLog)
                    .where(NormalizedLog.id.in_(normalized_ids))
                    .order_by(NormalizedLog.id)
                )
            )
            return dataframe_type(build_feature_rows(db, logs))
    finally:
        engine.dispose()


def _calibration_metrics(
    y_true: list[str],
    y_pred: list[str],
    probabilities: Any,
    classes: list[str],
) -> dict[str, Any]:
    if probabilities is None or len(probabilities) == 0:
        return {
            "status": "not_available",
            "brier_score_threat_positive": None,
            "expected_calibration_error": None,
            "max_confidence_accuracy_gap": None,
            "buckets": [],
        }
    positions = {label: index for index, label in enumerate(classes)}
    threat_positions = [
        positions[label]
        for label in ("suspicious", "malicious")
        if label in positions
    ]
    squared_errors = []
    buckets = _confidence_buckets(y_true, y_pred, probabilities)
    total_rows = len(y_true)
    ece = 0.0
    gaps = []
    for item in buckets:
        if item["count"] and item["accuracy"] is not None:
            gap = abs(float(item["accuracy"]) - float(item["average_confidence"]))
            item["gap"] = round(gap, 4)
            ece += item["count"] / total_rows * gap
            gaps.append(gap)
        else:
            item["gap"] = None
    for actual, row in zip(y_true, probabilities, strict=False):
        threat_probability = sum(float(row[index]) for index in threat_positions)
        actual_threat = 1.0 if actual in {"suspicious", "malicious"} else 0.0
        squared_errors.append((threat_probability - actual_threat) ** 2)
    brier = sum(squared_errors) / len(squared_errors) if squared_errors else None
    max_gap = max(gaps, default=None)
    passed = (
        brier is not None
        and brier <= 0.25
        and ece <= 0.15
        and (max_gap is None or max_gap <= 0.2)
    )
    return {
        "status": "passed" if passed else "weak",
        "brier_score_threat_positive": round(brier, 4) if brier is not None else None,
        "expected_calibration_error": round(ece, 4),
        "max_confidence_accuracy_gap": round(max_gap, 4) if max_gap is not None else None,
        "buckets": buckets,
    }


def _per_attack_metrics(
    records: list[BenchmarkRecord],
    predictions: list[str],
) -> dict[str, Any]:
    counts: dict[str, Counter[str]] = defaultdict(Counter)
    for record, prediction in zip(records, predictions, strict=False):
        actual = _triage_label(record)
        actual_threat = actual in {"suspicious", "malicious"}
        predicted_threat = prediction in {"suspicious", "malicious"}
        counts[record.attack_type]["support"] += 1
        counts[record.attack_type]["detected"] += int(actual_threat and predicted_threat)
        counts[record.attack_type]["missed"] += int(actual_threat and not predicted_threat)
        counts[record.attack_type]["false_positive"] += int(
            not actual_threat and predicted_threat
        )
        counts[record.attack_type]["exact_match"] += int(actual == prediction)
    return {
        attack: {
            **dict(values),
            "threat_recall": (
                round(values["detected"] / (values["detected"] + values["missed"]), 4)
                if values["detected"] + values["missed"]
                else None
            ),
            "exact_class_accuracy": round(
                values["exact_match"] / values["support"], 4
            ),
        }
        for attack, values in sorted(counts.items())
    }


def _cross_dataset_candidate(
    *,
    training_snapshot: Path,
    holdout_snapshot: Path,
    holdout_records_override: list[BenchmarkRecord] | None = None,
    review_metadata: dict[int, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    imports = _optional_imports()
    if imports is None:
        return {
            "ok": False,
            "status": "skipped",
            "message": "Supervised ML dependencies are unavailable.",
        }
    (
        _joblib,
        pd,
        _ColumnTransformer,
        _RandomForestClassifier,
        _SimpleImputer,
        accuracy_score,
        confusion_matrix,
        precision_recall_fscore_support,
        _train_test_split,
        _Pipeline,
        _OneHotEncoder,
    ) = imports
    started = time.perf_counter()
    training_records, training_summary = load_prepared_benchmark_snapshot(
        training_snapshot
    )
    loaded_holdout_records, holdout_summary = load_prepared_benchmark_snapshot(
        holdout_snapshot
    )
    holdout_records = holdout_records_override or loaded_holdout_records
    training_frame = _feature_frame(
        training_records,
        source_name="v16-internal-training",
        dataframe_type=pd.DataFrame,
    )
    holdout_frame = _feature_frame(
        holdout_records,
        source_name="v16-unseen-holdout",
        dataframe_type=pd.DataFrame,
    )
    y_train = [_triage_label(record) for record in training_records]
    y_test = [_triage_label(record) for record in holdout_records]
    pipeline = _build_pipeline(
        imports,
        model_type="random_forest",
        class_weight="balanced",
    )
    pipeline.fit(training_frame, y_train)
    predictions = list(pipeline.predict(holdout_frame))
    probabilities = (
        pipeline.predict_proba(holdout_frame)
        if hasattr(pipeline, "predict_proba")
        else None
    )
    classes = [str(value) for value in pipeline.named_steps["model"].classes_]
    labels_order = ["benign_like", "malicious", "suspicious"]
    metrics = _metrics(
        y_test,
        predictions,
        labels_order,
        accuracy_score=accuracy_score,
        confusion_matrix=confusion_matrix,
        precision_recall_fscore_support=precision_recall_fscore_support,
    )
    false_positives = []
    false_negatives = []
    for record, actual, predicted in zip(
        holdout_records,
        y_test,
        predictions,
        strict=False,
    ):
        actual_threat = actual in {"suspicious", "malicious"}
        predicted_threat = predicted in {"suspicious", "malicious"}
        row = {
            "row_number": record.row_number,
            "scenario": record.normalized.get("scenario"),
            "attack_type": record.attack_type,
            "actual": actual,
            "predicted": predicted,
        }
        review = (review_metadata or {}).get(record.row_number)
        if review:
            row["human_review"] = {
                "decision": review.get("human_review_decision"),
                "attack_type": review.get("human_review_attack_type"),
                "confidence": review.get("human_review_confidence"),
                "normalized_confidence": review.get(
                    "normalized_confidence"
                ),
                "note": review.get("human_review_note"),
            }
        if not actual_threat and predicted_threat:
            false_positives.append(row)
        elif actual_threat and not predicted_threat:
            false_negatives.append(row)
    return {
        "ok": True,
        "status": "evaluated",
        "candidate_name": "v1_5_random_forest_three_class_transfer",
        "training_snapshot_id": training_summary.get("snapshot_id"),
        "holdout_snapshot_id": holdout_summary.get("snapshot_id"),
        "training_rows": len(training_records),
        "holdout_rows": len(holdout_records),
        "training_label_distribution": dict(sorted(Counter(y_train).items())),
        "holdout_label_distribution": dict(sorted(Counter(y_test).items())),
        "metrics": metrics,
        "calibration": _calibration_metrics(
            y_test,
            predictions,
            probabilities,
            classes,
        ),
        "per_attack_metrics": _per_attack_metrics(
            holdout_records,
            predictions,
        ),
        "false_positive_examples": false_positives[:25],
        "false_negative_examples": false_negatives[:25],
        "runtime_seconds": round(time.perf_counter() - started, 4),
        "model_artifact_written": False,
        "model_activated": False,
        "response_automation_allowed": False,
        "reviewed_labels_applied": len(review_metadata or {}),
    }


def _metrics_comparison(
    before: dict[str, Any],
    after: dict[str, Any],
) -> dict[str, Any]:
    before_per_class = before.get("per_class") or {}
    after_per_class = after.get("per_class") or {}
    fields = {
        "threat_positive_precision": (
            before.get("threat_positive_precision"),
            after.get("threat_positive_precision"),
        ),
        "threat_positive_recall": (
            before.get("threat_positive_recall"),
            after.get("threat_positive_recall"),
        ),
        "threat_positive_f1": (
            before.get("threat_positive_f1"),
            after.get("threat_positive_f1"),
        ),
        "benign_false_positive_rate": (
            before.get("benign_false_positive_rate"),
            after.get("benign_false_positive_rate"),
        ),
        "suspicious_recall": (
            (before_per_class.get("suspicious") or {}).get("recall"),
            (after_per_class.get("suspicious") or {}).get("recall"),
        ),
        "malicious_recall": (
            (before_per_class.get("malicious") or {}).get("recall"),
            (after_per_class.get("malicious") or {}).get("recall"),
        ),
        "macro_f1": (before.get("macro_f1"), after.get("macro_f1")),
        "weighted_f1": (
            before.get("weighted_f1"),
            after.get("weighted_f1"),
        ),
    }
    return {
        name: {
            "before": old,
            "after": new,
            "change": (
                round(float(new) - float(old), 4)
                if old is not None and new is not None
                else None
            ),
        }
        for name, (old, new) in fields.items()
    }


def _overfitting_analysis(
    *,
    internal_metrics: dict[str, Any],
    external_metrics: dict[str, Any],
) -> dict[str, Any]:
    fields = {
        "threat_positive_f1": (
            float(internal_metrics.get("threat_positive_f1") or 0),
            float(external_metrics.get("threat_positive_f1") or 0),
        ),
        "threat_positive_recall": (
            float(internal_metrics.get("threat_positive_recall") or 0),
            float(external_metrics.get("threat_positive_recall") or 0),
        ),
        "benign_false_positive_rate": (
            float(internal_metrics.get("benign_false_positive_rate") or 0),
            float(external_metrics.get("benign_false_positive_rate") or 0),
        ),
    }
    class_gaps = {}
    for label in ("benign_like", "suspicious", "malicious"):
        internal_recall = float(
            (((internal_metrics.get("per_class") or {}).get(label) or {}).get("recall"))
            or 0
        )
        external_recall = float(
            (((external_metrics.get("per_class") or {}).get(label) or {}).get("recall"))
            or 0
        )
        class_gaps[label] = {
            "internal_recall": internal_recall,
            "external_recall": external_recall,
            "gap": round(internal_recall - external_recall, 4),
        }
    metric_gaps = {
        name: {
            "internal": internal,
            "external": external,
            "gap": round(
                external - internal
                if name == "benign_false_positive_rate"
                else internal - external,
                4,
            ),
        }
        for name, (internal, external) in fields.items()
    }
    f1_gap = metric_gaps["threat_positive_f1"]["gap"]
    largest_class_gap = max(
        (item["gap"] for item in class_gaps.values()),
        default=0,
    )
    if f1_gap >= 0.15 or largest_class_gap >= 0.25:
        status = "significant_generalization_gap"
    elif f1_gap >= 0.05 or largest_class_gap >= 0.1:
        status = "moderate_generalization_gap"
    else:
        status = "limited_generalization_gap"
    return {
        "status": status,
        "internal_metrics": internal_metrics,
        "external_metrics": external_metrics,
        "metric_gaps": metric_gaps,
        "class_recall_gaps": class_gaps,
        "overfitting_warning": status != "limited_generalization_gap",
        "interpretation": (
            "The internal deterministic fixture is materially easier than the unseen holdout."
            if status == "significant_generalization_gap"
            else "The unseen holdout shows some degradation that should guide data and feature work."
            if status == "moderate_generalization_gap"
            else "The internal-to-holdout gap is limited for this controlled experiment."
        ),
    }


def _render_report(report: dict[str, Any]) -> str:
    candidate = report["cross_dataset_candidate"]
    metrics = candidate.get("metrics") or {}
    calibration = candidate.get("calibration") or {}
    readiness = report["readiness_gate_v5"]
    gap = report["overfitting_check"]
    lines = [
        "# ATDR v1.6 External / Unseen Benchmark Validation",
        "",
        f"- Generated: {report['generated_at']}",
        f"- Benchmark source: {report['external_snapshot']['source_kind']}",
        f"- Holdout rows: {candidate.get('holdout_rows')}",
        f"- Candidate: {candidate.get('candidate_name')}",
        f"- Readiness v5: {readiness.get('decision')}",
        "- Production promoted: false",
        "- Model activated: false",
        "- Response automation allowed: false",
        "",
    ]
    reviewed = report.get("reviewed_benchmark_labels") or {}
    comparison = report.get("reviewed_metrics_comparison") or {}
    if reviewed.get("applied_count"):
        lines.extend(
            [
                "## Human-Reviewed Holdout Labels",
                "",
                f"- Reviewed CSV: {reviewed.get('input_name')}",
                f"- Reviews imported: {reviewed.get('imported')}",
                f"- Reviews applied: {reviewed.get('applied_count')}",
                f"- Unmatched review IDs: {reviewed.get('unmatched_count')}",
                "- Benchmark reviews remain outside `ml_labels`.",
                "",
                "| Metric | Before review | After review | Change |",
                "| --- | ---: | ---: | ---: |",
            ]
        )
        for name, values in comparison.items():
            lines.append(
                f"| {name} | {values.get('before')} | "
                f"{values.get('after')} | {values.get('change')} |"
            )
        lines.append("")
    lines.extend(
        [
            "## Transfer Metrics",
            "",
        f"- Threat-positive precision: {metrics.get('threat_positive_precision')}",
        f"- Threat-positive recall: {metrics.get('threat_positive_recall')}",
        f"- Threat-positive F1: {metrics.get('threat_positive_f1')}",
        f"- Benign-like false-positive rate: {metrics.get('benign_false_positive_rate')}",
        f"- Suspicious recall: {((metrics.get('per_class') or {}).get('suspicious') or {}).get('recall')}",
        f"- Malicious recall: {((metrics.get('per_class') or {}).get('malicious') or {}).get('recall')}",
        f"- Macro F1: {metrics.get('macro_f1')}",
        f"- Weighted F1: {metrics.get('weighted_f1')}",
        f"- False positives: {metrics.get('false_positives')}",
        f"- False negatives: {metrics.get('false_negatives')}",
        "",
        "## Calibration",
        "",
        f"- Status: {calibration.get('status')}",
        f"- Brier score: {calibration.get('brier_score_threat_positive')}",
        f"- ECE: {calibration.get('expected_calibration_error')}",
        f"- Maximum confidence/accuracy gap: {calibration.get('max_confidence_accuracy_gap')}",
        "",
        "## Internal Versus Holdout",
        "",
        f"- Gap status: {gap.get('status')}",
        f"- Threat F1 gap: {(gap.get('metric_gaps') or {}).get('threat_positive_f1')}",
        f"- Class recall gaps: {gap.get('class_recall_gaps')}",
        f"- Interpretation: {gap.get('interpretation')}",
        "",
        "## Layered Detection",
        "",
        "| Mode | Precision | Recall | F1 | Benign FPR | FP | FN | Runtime |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
        ]
    )
    for item in report["layered_detection"]["mode_results"]:
        item_metrics = item.get("metrics") or {}
        lines.append(
            f"| {item['mode']} | {item_metrics.get('precision')} | "
            f"{item_metrics.get('recall')} | {item_metrics.get('f1')} | "
            f"{item_metrics.get('benign_false_positive_rate')} | "
            f"{item_metrics.get('false_positives')} | "
            f"{item_metrics.get('false_negatives')} | "
            f"{item.get('runtime_seconds')} |"
        )
    lines.extend(
        [
            "",
            "## Safety And Interpretation",
            "",
            "- The holdout is safe synthetic/public-style data and is not used for candidate training.",
            "- External or holdout benchmark metrics are not production accuracy.",
            "- ATDR ML remains SOC triage decision support.",
            "- Every response action remains simulated and analyst-approved.",
        ]
    )
    return "\n".join(lines)


def _render_overfitting(report: dict[str, Any]) -> str:
    return f"""# ATDR v1.6 Overfitting Check

Generated: {report['generated_at']}

- Status: {report['status']}
- Warning: {report['overfitting_warning']}
- Metric gaps: {report['metric_gaps']}
- Class recall gaps: {report['class_recall_gaps']}

## Interpretation

{report['interpretation']}

## Recommended Work

- Add more source-diverse reviewed benign boundary rows.
- Add slower and distributed threat patterns to training data.
- Improve behavior-window features for low-and-slow scans and DNS beaconing.
- Validate against an independent approved public dataset when available.
- Keep model activation and response automation disabled.
"""


def run_external_benchmark_validation(
    *,
    input_csv: Path | None = None,
    mapping_config: Path | None = None,
    label_config: Path | None = None,
    limit: int | None = None,
    sample_strategy: str = "balanced",
    holdout_from_current_data: bool = False,
    reviewed_benchmark_csv: Path | None = None,
    output_dir: Path = FINAL_OUTPUT_DIR,
) -> dict[str, Any]:
    generated_at = datetime.now(timezone.utc).isoformat()
    external_snapshot = prepare_external_benchmark_snapshot(
        input_csv=input_csv,
        mapping_config=mapping_config,
        label_config=label_config,
        limit=limit,
        sample_strategy=sample_strategy,
        holdout_from_current_data=holdout_from_current_data or input_csv is None,
        output_dir=output_dir,
    )
    build_internal_ai_readiness_benchmark(output_path=INTERNAL_CSV)
    internal_snapshot = prepare_benchmark_dataset(
        input_csv=INTERNAL_CSV,
        sample_strategy="balanced",
        output_dir=BENCHMARK_OUTPUT_DIR,
    )
    external_snapshot_path = Path(external_snapshot["snapshot_path"])
    internal_snapshot_path = Path(internal_snapshot["snapshot_path"])
    evaluation_snapshot_path = external_snapshot_path
    review_metadata: dict[int, dict[str, Any]] = {}
    reviewed_benchmark_labels: dict[str, Any] = {
        "applied": False,
        "input_name": None,
        "imported": 0,
        "applied_count": 0,
        "unmatched_count": 0,
    }
    baseline_candidate: dict[str, Any] | None = None
    if reviewed_benchmark_csv is not None:
        parsed_reviews = parse_benchmark_review_csv(
            reviewed_benchmark_csv.read_text(
                encoding="utf-8-sig",
                errors="replace",
            ),
            benchmark_kind="external_holdout",
            input_name=reviewed_benchmark_csv.name,
            reviewer="external-benchmark-validation",
        )
        if not parsed_reviews.get("ok"):
            reasons = ", ".join(
                str(item.get("reason"))
                for item in parsed_reviews.get("errors") or []
            )
            raise ValueError(
                "Reviewed benchmark CSV failed validation"
                + (f": {reasons}" if reasons else ".")
            )
        original_records, _ = load_prepared_benchmark_snapshot(
            external_snapshot_path
        )
        reviewed_records, apply_summary, review_metadata = (
            apply_benchmark_reviews(
                original_records,
                parsed_reviews["reviews"],
            )
        )
        baseline_candidate = _cross_dataset_candidate(
            training_snapshot=internal_snapshot_path,
            holdout_snapshot=external_snapshot_path,
        )
        reviewed_snapshot = write_benchmark_snapshot(
            reviewed_records,
            input_name=f"{external_snapshot_path.stem}_human_reviewed",
            mapping_summary={
                **(external_snapshot.get("mapping_summary") or {}),
                "reviewed_benchmark": {
                    "input_name": reviewed_benchmark_csv.name,
                    **apply_summary,
                },
            },
            output_dir=output_dir,
            sample_strategy="reviewed_override",
            requested_limit=limit,
            include_raw=False,
        )
        evaluation_snapshot_path = Path(reviewed_snapshot["snapshot_path"])
        reviewed_benchmark_labels = {
            "applied": True,
            "input_name": reviewed_benchmark_csv.name,
            "imported": parsed_reviews["imported"],
            "skipped": parsed_reviews["skipped"],
            "failed": parsed_reviews["failed"],
            "decision_distribution": parsed_reviews[
                "decision_distribution"
            ],
            "attack_type_distribution": parsed_reviews[
                "attack_type_distribution"
            ],
            "reviewed_snapshot_id": reviewed_snapshot["snapshot_id"],
            "reviewed_snapshot_path": str(evaluation_snapshot_path),
            **apply_summary,
        }
        external_snapshot = {
            **external_snapshot,
            "original_snapshot_path": str(external_snapshot_path),
            "snapshot_path": str(evaluation_snapshot_path),
            "reviewed_snapshot_id": reviewed_snapshot["snapshot_id"],
            "reviewed_labels_applied": apply_summary["applied_count"],
        }
    layered = compare_layered_benchmark_reliability(
        prepared_snapshot=evaluation_snapshot_path,
        output_dir=output_dir,
    )
    candidate = _cross_dataset_candidate(
        training_snapshot=internal_snapshot_path,
        holdout_snapshot=evaluation_snapshot_path,
        review_metadata=review_metadata,
    )
    v15 = _latest_json(V15_REPORT_DIR, "final_ai_readiness_report_*.json")
    internal_candidate = v15.get("best_benchmark_candidate") or {}
    internal_metrics = internal_candidate.get("metrics") or {}
    overfitting = _overfitting_analysis(
        internal_metrics=internal_metrics,
        external_metrics=candidate.get("metrics") or {},
    )
    controlled = _latest_validation_status()
    readiness = readiness_gate_v5(
        external_label_count=int(candidate.get("holdout_rows") or 0),
        external_metrics=candidate.get("metrics") or {},
        calibration_status=str(
            (candidate.get("calibration") or {}).get("status")
            or "not_available"
        ),
        controlled_validations_passed=bool(controlled["passed"]),
        internal_benchmark_validated=bool(
            (v15.get("readiness_gate_v4") or {}).get("benchmark_validated")
        ),
        response_automation_allowed=False,
    )
    reviewed_metrics_comparison = (
        _metrics_comparison(
            baseline_candidate.get("metrics") or {},
            candidate.get("metrics") or {},
        )
        if baseline_candidate
        else {}
    )
    report = {
        "ok": True,
        "status": "completed",
        "generated_at": generated_at,
        "external_snapshot": {
            key: value
            for key, value in external_snapshot.items()
            if key
            not in {
                "records",
            }
        },
        "internal_training_snapshot": {
            "snapshot_id": internal_snapshot.get("snapshot_id"),
            "row_count": internal_snapshot.get("rows_selected"),
        },
        "layered_detection": layered,
        "baseline_unreviewed_candidate": baseline_candidate,
        "cross_dataset_candidate": candidate,
        "reviewed_benchmark_labels": reviewed_benchmark_labels,
        "reviewed_metrics_comparison": reviewed_metrics_comparison,
        "current_active_supervised_artifact": next(
            (
                row
                for row in layered.get("mode_results") or []
                if row.get("mode") == "supervised_only"
            ),
            None,
        ),
        "overfitting_check": overfitting,
        "controlled_validations": controlled,
        "readiness_gate_v5": readiness,
        "production_promoted": False,
        "model_activated": False,
        "model_artifact_written": False,
        "response_automation_allowed": False,
        "real_firewall_blocking_enabled": False,
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    stamp = _stamp()
    report_path = output_dir / f"external_benchmark_validation_{stamp}.json"
    overfitting_path = output_dir / f"overfitting_check_{stamp}.json"
    report_path.write_text(
        json.dumps(report, indent=2, default=str),
        encoding="utf-8",
    )
    report_path.with_suffix(".md").write_text(
        _render_report(report),
        encoding="utf-8",
    )
    overfitting_payload = {
        **overfitting,
        "generated_at": generated_at,
        "production_promoted": False,
        "model_activated": False,
        "response_automation_allowed": False,
    }
    overfitting_path.write_text(
        json.dumps(overfitting_payload, indent=2, default=str),
        encoding="utf-8",
    )
    overfitting_path.with_suffix(".md").write_text(
        _render_overfitting(overfitting_payload),
        encoding="utf-8",
    )
    report["paths"] = {
        "json": str(report_path),
        "markdown": str(report_path.with_suffix(".md")),
        "overfitting_json": str(overfitting_path),
        "overfitting_markdown": str(overfitting_path.with_suffix(".md")),
    }
    return report


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Validate the v1.5 internal candidate on a separate external CSV "
            "or fixed safe unseen holdout."
        )
    )
    parser.add_argument("--input-csv", default=None)
    parser.add_argument("--mapping-config", default=None)
    parser.add_argument("--label-config", default=None)
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument(
        "--sample-strategy",
        choices=["balanced", "random", "time"],
        default="balanced",
    )
    parser.add_argument("--holdout-from-current-data", action="store_true")
    parser.add_argument("--reviewed-benchmark-csv", default=None)
    parser.add_argument("--output-dir", default=None)
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()
    result = run_external_benchmark_validation(
        input_csv=Path(args.input_csv) if args.input_csv else None,
        mapping_config=Path(args.mapping_config) if args.mapping_config else None,
        label_config=Path(args.label_config) if args.label_config else None,
        limit=args.limit,
        sample_strategy=args.sample_strategy,
        holdout_from_current_data=args.holdout_from_current_data,
        reviewed_benchmark_csv=(
            Path(args.reviewed_benchmark_csv)
            if args.reviewed_benchmark_csv
            else None
        ),
        output_dir=Path(args.output_dir) if args.output_dir else FINAL_OUTPUT_DIR,
    )
    print(json.dumps(result, indent=2 if args.pretty else None, default=str))
    raise SystemExit(0 if result.get("ok") else 1)


if __name__ == "__main__":
    main()
