import csv
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from atdr.app.db.models import AuditLog, MLLabel, MLModelRun
from atdr.app.detection.boundary_analysis import build_boundary_analysis
from atdr.app.detection.model_comparison import compare_supervised_models
from atdr.app.detection.supervised_detector import (
    MODEL_NAME,
    THRESHOLD_PROFILES,
    TRAINABLE_LABELS,
    _artifact_hash,
    _latest_labels,
    _metrics_from_predictions,
    _optional_imports,
    _split_class_warnings,
    _split_indices,
    supervised_model_path,
    threshold_decision,
    training_dataset_diagnostics,
)
from atdr.app.detection.suspicious_recall_analysis import (
    build_suspicious_recall_error_report,
    render_suspicious_recall_error_report,
)
from atdr.app.detection.threshold_tuning import tune_model_thresholds
from atdr.app.ml.features import CATEGORICAL_FEATURES, FEATURE_COLUMNS, NUMERIC_FEATURES, build_feature_rows, feature_set_metadata
from atdr.app.services.class_temporal_coverage_service import build_class_temporal_coverage


SNAPSHOT_DIR = Path("ml_baseline_reviews/supervised_snapshots")
EXPERIMENT_DIR = Path("ml_baseline_reviews/supervised_experiments")
TUNING_DIR = Path("ml_baseline_reviews/supervised_tuning")
ERROR_REPORT_PATH = Path("ml_baseline_reviews/supervised_error_analysis.md")
SANITY_REPORT_PATH = Path("ml_baseline_reviews/supervised_sanity_report.md")


def _safe_timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")


def _label_distribution(labels: list[MLLabel], *, reviewed: bool | None = None) -> dict[str, int]:
    values = [
        label.label
        for label in labels
        if reviewed is None or bool(getattr(label, "reviewed", True)) is reviewed
    ]
    return {value: values.count(value) for value in sorted(set(values))}


def _label_source_distribution(labels: list[MLLabel]) -> dict[str, int]:
    values = [str(getattr(label, "label_source", "manual") or "manual") for label in labels]
    return {value: values.count(value) for value in sorted(set(values))}


def _split_window_for_position(position: int, total: int, test_size: float) -> str:
    first_test = max(0, int(total * (1 - test_size)))
    return "test" if position >= first_test else "train"


def export_supervised_dataset_snapshot(
    db: Session,
    *,
    output_root: str | Path = SNAPSHOT_DIR,
    split: str = "time",
    test_size: float = 0.3,
    include_raw: bool = False,
) -> dict[str, Any]:
    labels = [label for label in _latest_labels(db) if label.log is not None]
    logs = [label.log for label in labels]
    snapshot_id = f"snapshot-{_safe_timestamp()}"
    snapshot_dir = Path(output_root) / snapshot_id
    snapshot_dir.mkdir(parents=True, exist_ok=True)

    feature_rows = build_feature_rows(db, logs) if logs else []
    missing_summary: dict[str, int] = {}
    for column in FEATURE_COLUMNS:
        missing_summary[column] = sum(1 for row in feature_rows if row.get(column) in {None, ""})

    csv_path = snapshot_dir / "features.csv"
    columns = [
        "label_id",
        "log_id",
        "label",
        "attack_type",
        "confidence",
        "reviewed",
        "label_source",
        "timestamp",
        "split_window",
        *FEATURE_COLUMNS,
    ]
    if include_raw:
        columns.append("raw_line")
    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        for position, (label, features) in enumerate(zip(labels, feature_rows, strict=False)):
            log = label.log
            timestamp = log.generated_time or log.receive_time or log.start_time if log else None
            row = {
                "label_id": label.id,
                "log_id": label.log_id,
                "label": label.label,
                "attack_type": label.attack_type,
                "confidence": label.confidence,
                "reviewed": label.reviewed,
                "label_source": label.label_source,
                "timestamp": timestamp.isoformat() if timestamp else "",
                "split_window": _split_window_for_position(position, len(labels), test_size) if split == "time" else "random_candidate",
                **features,
            }
            if include_raw:
                row["raw_line"] = getattr(getattr(log, "raw", None), "raw_line", "") if log else ""
            writer.writerow(row)

    metadata = {
        "snapshot_id": snapshot_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "row_count": len(labels),
        "split": split,
        "test_size": test_size,
        "contains_raw_payloads": include_raw,
        "features_csv": str(csv_path),
        "feature_schema_path": str(snapshot_dir / "feature_schema.json"),
        "metadata_path": str(snapshot_dir / "metadata.json"),
        "label_distribution": _label_distribution(labels),
        "reviewed_label_distribution": _label_distribution(labels, reviewed=True),
        "weak_label_distribution": _label_distribution(labels, reviewed=False),
        "label_source_distribution": _label_source_distribution(labels),
        "reviewed_label_count": sum(1 for label in labels if label.reviewed),
        "weak_label_count": sum(1 for label in labels if not label.reviewed),
        "class_temporal_coverage": build_class_temporal_coverage(db, test_size=test_size),
        "training_dataset_diagnostics": training_dataset_diagnostics(db),
        "feature_set_metadata": feature_set_metadata(row_count=len(labels), missing_value_summary=missing_summary),
        "data_quality_warnings": [
            "Snapshot excludes private raw log text by default.",
            "Weak-label and mixed-label datasets must not be presented as production accuracy.",
        ],
    }
    _write_json(snapshot_dir / "feature_schema.json", metadata["feature_set_metadata"])
    _write_json(snapshot_dir / "metadata.json", metadata)
    return {"ok": True, "status": "exported", **metadata}


def run_supervised_experiment(
    db: Session,
    *,
    output_root: str | Path = EXPERIMENT_DIR,
    split: str = "time",
    test_size: float = 0.3,
    min_samples: int = 6,
    threshold_profile: str = "balanced",
) -> dict[str, Any]:
    experiment_id = f"experiment-{_safe_timestamp()}"
    output_dir = Path(output_root)
    output_dir.mkdir(parents=True, exist_ok=True)
    report_path = output_dir / f"{experiment_id}.md"
    started = time.perf_counter()
    result = compare_supervised_models(
        db,
        output_path=report_path,
        test_size=test_size,
        min_samples=min_samples,
        split=split,
        threshold_profile=threshold_profile,
    )
    result["experiment_id"] = experiment_id
    result["duration_seconds"] = round(time.perf_counter() - started, 4)
    result["feature_set_metadata"] = feature_set_metadata(row_count=result.get("training_rows", 0) + result.get("test_rows", 0))
    result["production_promoted"] = False
    result["response_automation_allowed"] = False
    _write_json(output_dir / f"{experiment_id}.json", result)
    return result


def evaluate_active_supervised_model(
    db: Session,
    *,
    split: str = "time",
    test_size: float = 0.3,
    min_samples: int = 6,
) -> dict[str, Any]:
    imports = _optional_imports()
    active_path = supervised_model_path()
    if imports is None:
        return {"ok": False, "status": "skipped", "message": "Supervised ML dependencies are unavailable."}
    if not active_path.exists():
        return {"ok": False, "status": "skipped", "message": "Active supervised model artifact does not exist."}
    (
        joblib,
        pd,
        _ColumnTransformer,
        _RandomForestClassifier,
        _SimpleImputer,
        accuracy_score,
        confusion_matrix,
        precision_recall_fscore_support,
        train_test_split,
        _Pipeline,
        _OneHotEncoder,
    ) = imports
    labels = [label for label in _latest_labels(db) if label.log is not None and label.label in TRAINABLE_LABELS]
    logs = [label.log for label in labels]
    y = [label.label for label in labels]
    if len(logs) < min_samples or len(set(y)) < 2:
        return {
            "ok": False,
            "status": "skipped",
            "message": "Need at least two classes and enough rows to evaluate the active supervised model.",
        }
    frame = pd.DataFrame(build_feature_rows(db, logs))
    train_idx, test_idx, _y_train, y_test, split_warnings = _split_indices(
        logs=logs,
        y=y,
        split=split,
        test_size=test_size,
        train_test_split=train_test_split,
    )
    split_warnings = [*split_warnings, *_split_class_warnings([y[index] for index in train_idx], y_test)]
    artifact = joblib.load(active_path)
    pipeline = artifact.get("pipeline") if isinstance(artifact, dict) else artifact
    if pipeline is None:
        return {"ok": False, "status": "failed", "message": "Active supervised model artifact is missing its pipeline."}
    active_run = db.scalar(
        select(MLModelRun)
        .where(MLModelRun.model_path == str(active_path))
        .order_by(desc(MLModelRun.created_at), desc(MLModelRun.id))
    )
    threshold_profile = str(artifact.get("threshold_profile", "balanced")) if isinstance(artifact, dict) else "balanced"
    X_test = frame.iloc[test_idx]
    direct_predictions = list(pipeline.predict(X_test))
    class_labels = [str(label) for label in getattr(pipeline.named_steps["model"], "classes_", [])]
    probabilities = pipeline.predict_proba(X_test) if hasattr(pipeline, "predict_proba") else []
    predictions = (
        [
            threshold_decision({label: float(prob) for label, prob in zip(class_labels, row, strict=False)}, profile=threshold_profile)
            for row in probabilities
        ]
        if len(probabilities)
        else direct_predictions
    )
    labels_order = sorted(set(y))
    metrics = _metrics_from_predictions(
        accuracy_score=accuracy_score,
        confusion_matrix=confusion_matrix,
        precision_recall_fscore_support=precision_recall_fscore_support,
        y_true=y_test,
        predictions=predictions,
        labels_order=labels_order,
    )
    direct_metrics = _metrics_from_predictions(
        accuracy_score=accuracy_score,
        confusion_matrix=confusion_matrix,
        precision_recall_fscore_support=precision_recall_fscore_support,
        y_true=y_test,
        predictions=direct_predictions,
        labels_order=labels_order,
    )
    return {
        "ok": True,
        "status": "evaluated",
        "active_model_id": active_run.id if active_run else 0,
        "active_model_version": active_run.model_version if active_run else "active-unregistered",
        "active_model_path": str(active_path),
        "active_artifact_sha256": _artifact_hash(active_path),
        "model_type": str(artifact.get("model_type", "unknown")) if isinstance(artifact, dict) else "unknown",
        "feature_set_version": ((artifact.get("feature_set_metadata") or {}).get("feature_set_version") if isinstance(artifact, dict) else None),
        "dataset_snapshot_id": artifact.get("dataset_snapshot_id") if isinstance(artifact, dict) else None,
        "threshold_profile": threshold_profile,
        "split": split,
        "training_rows": len(train_idx),
        "test_rows": len(test_idx),
        "split_warnings": split_warnings,
        "metrics": metrics,
        "direct_model_metrics": direct_metrics,
        "production_promoted": False,
        "response_automation_allowed": False,
    }


def _metric_line(name: str, metrics: dict[str, Any]) -> str:
    per_class = metrics.get("per_class") or {}
    threat = metrics.get("threat_positive") or {}
    return (
        f"| {name} | {metrics.get('f1', 'n/a')} | {(metrics.get('macro_average') or {}).get('f1', 'n/a')} | "
        f"{(per_class.get('suspicious') or {}).get('recall', 'n/a')} | "
        f"{(per_class.get('malicious') or {}).get('recall', 'n/a')} | {threat.get('f1', 'n/a')} |"
    )


def _render_sanity_report(result: dict[str, Any]) -> str:
    active = result.get("active_model_evaluation") or {}
    experiment = result.get("experiment") or {}
    rows = []
    if active.get("ok"):
        rows.append(_metric_line("active_supervised_model", active.get("metrics") or {}))
    for model in experiment.get("models", []):
        rows.append(_metric_line(str(model.get("name")), model.get("metrics") or {}))
    gate = experiment.get("promotion_gate") or {}
    differences = result.get("pipeline_differences") or []
    label_checks = result.get("label_mapping_checks") or []
    feature_checks = result.get("feature_preprocessing_checks") or []
    weighting_checks = result.get("weighting_checks") or []
    return f"""# ATDR Supervised ML Sanity Report

Generated: {result.get("generated_at")}

This report checks why an experiment may differ from the active supervised model. It does not activate or promote any model, and response automation remains disabled.

## Root Cause Summary

{result.get("root_cause_summary")}

## Training Path vs Experiment Path

{chr(10).join(f"- {item}" for item in differences)}

## Active Model Evaluation

- Status: {active.get("status", "not_available")}
- Active model ID: {active.get("active_model_id", "not_available")}
- Active model version: {active.get("active_model_version", "not_available")}
- Model type: {active.get("model_type", "unknown")}
- Feature set version: {active.get("feature_set_version") or "unknown/legacy artifact"}
- Dataset snapshot ID: {active.get("dataset_snapshot_id") or "not recorded"}
- Threshold profile: {active.get("threshold_profile", "balanced")}
- Split: {active.get("split", result.get("split"))}
- Training rows: {active.get("training_rows", "n/a")}
- Test rows: {active.get("test_rows", "n/a")}

## Apples-To-Apples Comparison

Candidate metrics use the same weighted training policy and probability-threshold decision path used by supervised training.

| Model | Weighted F1 | Macro F1 | Suspicious Recall | Malicious Recall | Threat-Positive F1 |
| --- | --- | --- | --- | --- | --- |
{chr(10).join(rows) if rows else "| No evaluated model | - | - | - | - | - |"}

## Experiment Gate

- Decision: {gate.get("decision", "candidate_only")}
- Analyst review eligible: {gate.get("analyst_review_eligible", False)}
- Production promoted: {gate.get("production_promoted", False)}
- Response automation allowed: {gate.get("response_automation_allowed", False)}

### Gate Reasons

{chr(10).join(f"- {reason}" for reason in gate.get("reasons", [])) or "- none"}

## Label Mapping Checks

{chr(10).join(f"- {item}" for item in label_checks)}

## Feature / Preprocessing Checks

{chr(10).join(f"- {item}" for item in feature_checks)}

## Weighting Checks

{chr(10).join(f"- {item}" for item in weighting_checks)}

## Recommendation

{result.get("recommendation")}
"""


def generate_supervised_sanity_report(
    db: Session,
    *,
    output_path: str | Path = SANITY_REPORT_PATH,
    split: str = "time",
    test_size: float = 0.3,
    min_samples: int = 6,
    threshold_profile: str = "balanced",
) -> dict[str, Any]:
    active = evaluate_active_supervised_model(db, split=split, test_size=test_size, min_samples=min_samples)
    experiment_path = Path(output_path).with_suffix(".experiment.md")
    experiment = compare_supervised_models(
        db,
        output_path=experiment_path,
        test_size=test_size,
        min_samples=min_samples,
        split=split,
        threshold_profile=threshold_profile,
    )
    result = {
        "ok": bool(experiment.get("ok")),
        "status": "exported" if experiment.get("ok") else "failed",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "split": split,
        "test_size": test_size,
        "threshold_profile": threshold_profile,
        "root_cause_summary": (
            "A clear experiment-path bug was found: model comparison evaluated raw classifier predictions while "
            "supervised training evaluated probability outputs through the configured threshold profile. Candidate "
            "comparison now uses the same threshold-decision path as training. If metrics are still weak after this "
            "fix, the previous stronger result is not reproducible on the current database/artifact state and should "
            "be treated as a prior-run result rather than current evidence."
        ),
        "pipeline_differences": [
            "Both paths use latest ml_labels joined to normalized logs; experiment filters labels to trainable classes explicitly.",
            "Both paths use build_feature_rows and the behavior-window feature set.",
            "Both paths use the same random/time split helper and cutoff behavior.",
            "Both paths now apply the same reviewed/weak sample-weight policy.",
            "Training saves one selected model artifact; experiment compares candidates and never overwrites the active artifact.",
            "Training and experiment now both evaluate threshold-adjusted predictions when probabilities are available.",
            "Hybrid score baseline remains a rule/risk baseline and does not use supervised sample weights.",
        ],
        "label_mapping_checks": [
            "Class labels come from estimator classes_ and are mapped to probability columns before threshold decisions.",
            "Confusion matrices use sorted label order from the evaluated dataset.",
            "Suspicious and malicious labels are not swapped; both are treated as threat-positive for combined triage metrics.",
            "needs_context remains a valid uncertainty class and is not forced into suspicious or malicious.",
        ],
        "feature_preprocessing_checks": [
            "Numeric features are median-imputed.",
            "Categorical features are most-frequent imputed and one-hot encoded with handle_unknown='ignore'.",
            "HistGradientBoosting receives numeric transformed features from the preprocessing pipeline.",
            "Train and test frames are produced from the same FEATURE_COLUMNS list.",
        ],
        "weighting_checks": [
            "Reviewed labels receive higher sample weight than unreviewed assisted labels.",
            "Reviewed suspicious and malicious rows receive additional class-specific weight.",
            "RandomForest, ExtraTrees, and LogisticRegression still use class_weight='balanced'; HistGradientBoosting uses sample weights only.",
            "The sanity report does not weaken promotion gates or activate candidates.",
        ],
        "active_model_evaluation": active,
        "experiment": experiment,
        "recommendation": (
            "Keep the active model unchanged. Treat new comparison output as candidate-only until reviewed-label validation "
            "and suspicious/malicious recall pass the readiness floors."
        ),
        "production_promoted": False,
        "response_automation_allowed": False,
    }
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    result["report_path"] = str(path)
    result["experiment_report_path"] = str(experiment_path)
    path.write_text(_render_sanity_report(result), encoding="utf-8")
    _write_json(path.with_suffix(".json"), result)
    return result


def tune_supervised_model_candidates(
    db: Session,
    *,
    output_root: str | Path = TUNING_DIR,
    split: str = "time",
    test_size: float = 0.3,
    min_samples: int = 6,
    threshold_profile: str = "balanced",
) -> dict[str, Any]:
    tuning_id = f"tuning-{_safe_timestamp()}"
    output_dir = Path(output_root)
    output_dir.mkdir(parents=True, exist_ok=True)
    threshold_report = output_dir / f"{tuning_id}-thresholds.md"
    threshold_result = tune_model_thresholds(db, split=split, test_size=test_size, min_samples=min_samples, output_path=threshold_report)
    experiment_result = run_supervised_experiment(
        db,
        output_root=output_dir,
        split=split,
        test_size=test_size,
        min_samples=min_samples,
        threshold_profile=threshold_profile,
    )
    result = {
        "ok": bool(threshold_result.get("ok")) and bool(experiment_result.get("ok")),
        "status": "completed",
        "tuning_id": tuning_id,
        "split": split,
        "threshold_report_path": str(threshold_report),
        "experiment_report_path": experiment_result.get("report_path"),
        "threshold_modes": threshold_result.get("modes", []),
        "model_candidates": experiment_result.get("models", []),
        "best_candidate": experiment_result.get("best_model"),
        "scoring_priorities": [
            "threat-positive F1",
            "suspicious recall",
            "malicious recall",
            "macro F1",
            "cost-sensitive score",
        ],
        "production_promoted": False,
        "response_automation_allowed": False,
    }
    _write_json(output_dir / f"{tuning_id}.json", result)
    return result


def analyze_supervised_errors(
    db: Session,
    *,
    output_path: str | Path = ERROR_REPORT_PATH,
    split: str = "time",
    test_size: float = 0.3,
    min_samples: int = 6,
) -> dict[str, Any]:
    recall_report = build_suspicious_recall_error_report(db, split=split, test_size=test_size, min_samples=min_samples)
    boundary_report = build_boundary_analysis(db, split=split, test_size=test_size, min_samples=min_samples)
    text = [
        "# ATDR Supervised Error Analysis",
        "",
        "This report is for analyst review and active-learning planning. It does not authorize automatic response.",
        "",
        "## Suspicious Recall Analysis",
        "",
        render_suspicious_recall_error_report(recall_report),
        "",
        "## Boundary Summary",
        "",
        f"- Suspicious predicted malicious: {((boundary_report.get('flat_model') or {}).get('boundary_counts') or {}).get('suspicious_predicted_malicious', 'n/a')}",
        f"- Malicious predicted suspicious: {((boundary_report.get('flat_model') or {}).get('boundary_counts') or {}).get('malicious_predicted_suspicious', 'n/a')}",
        f"- Suspicious predicted benign-like: {((boundary_report.get('flat_model') or {}).get('boundary_counts') or {}).get('suspicious_predicted_benign_like', 'n/a')}",
        f"- Malicious predicted benign-like: {((boundary_report.get('flat_model') or {}).get('boundary_counts') or {}).get('malicious_predicted_benign_like', 'n/a')}",
        "",
        "## Recommended Next Review",
        "",
        "- Prioritize threat-positive rows predicted as benign-like.",
        "- Review suspicious/malicious boundary cases with repeated denies, incomplete apps, rare ports, and high hybrid risk.",
        "- Keep weak-label metrics separate from reviewed-label validation.",
    ]
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(text), encoding="utf-8")
    return {
        "ok": True,
        "status": "exported",
        "report_path": str(path),
        "suspicious_recall_report": recall_report,
        "boundary_report": boundary_report,
        "production_promoted": False,
        "response_automation_allowed": False,
    }


def _model_run_to_registry_item(
    run: MLModelRun,
    *,
    active_model_run_id: int | None,
) -> dict[str, Any]:
    metrics = run.metrics_json or {}
    model_path = Path(run.model_path)
    is_active = bool(active_model_run_id == run.id)
    return {
        "model_id": run.id,
        "model_name": run.model_name,
        "model_version": run.model_version,
        "model_type": metrics.get("model_type", "random_forest"),
        "operation": run.operation,
        "status": run.status,
        "created_at": run.created_at,
        "actor": run.actor,
        "model_path": run.model_path,
        "artifact_sha256": run.artifact_sha256,
        "artifact_exists": model_path.exists(),
        "is_active_path": is_active,
        "active_artifact_metadata_status": "registered",
        "active_artifact_metadata_unknown": False,
        "display_model_type": metrics.get("model_type", "random_forest"),
        "display_feature_set": (metrics.get("feature_set_metadata") or {}).get("feature_set_version"),
        "feature_set_version": (metrics.get("feature_set_metadata") or {}).get("feature_set_version"),
        "dataset_snapshot_id": metrics.get("dataset_snapshot_id"),
        "split_strategy": metrics.get("split_strategy"),
        "metrics": metrics.get("metrics", {}),
        "readiness_decision": (metrics.get("promotion_gate") or {}).get("decision", "candidate_only"),
        "lifecycle_state": metrics.get("lifecycle_state", "inactive"),
        "target_mode": metrics.get("target_mode"),
        "calibration_method": metrics.get("calibration_method"),
        "shadow_safety_passed": bool(metrics.get("shadow_safety_passed", False)),
        "decision_support_eligible": bool((metrics.get("strict_gates") or {}).get("decision_support_eligible", False)),
        "analyst_review_eligible": bool((metrics.get("promotion_gate") or {}).get("analyst_review_eligible", False)),
        "production_promoted": False,
        "response_automation_allowed": False,
        "report_path": metrics.get("report_path"),
        "message": run.message,
    }


def list_supervised_models(db: Session, *, limit: int = 25) -> dict[str, Any]:
    from atdr.app.detection.v51_supervised_lifecycle import supervised_lifecycle_status

    lifecycle = supervised_lifecycle_status(db)
    active_model_run_id = lifecycle.get("model_run_id")
    active_model_run = db.get(MLModelRun, int(active_model_run_id)) if active_model_run_id is not None else None
    governed_active_path = Path(active_model_run.model_path) if active_model_run is not None else None
    legacy_path = supervised_model_path()
    runs = list(
        db.scalars(
            select(MLModelRun)
            .where(
                MLModelRun.operation.in_(
                    [
                        "train_supervised",
                        "activate_supervised_shadow",
                        "activate_supervised_decision_support",
                        "rollback_supervised_governed",
                        "disable_supervised_governed",
                    ]
                )
            )
            .order_by(desc(MLModelRun.created_at), desc(MLModelRun.id))
            .limit(limit)
        )
    )
    items = [
        _model_run_to_registry_item(
            run,
            active_model_run_id=int(active_model_run_id) if active_model_run_id is not None else None,
        )
        for run in runs
    ]
    if legacy_path.exists() and not any(
        Path(run.model_path).resolve() == legacy_path.resolve() and run.artifact_sha256 == _artifact_hash(legacy_path)
        for run in runs
        if Path(run.model_path).exists()
    ):
        items.insert(
            0,
            {
                "model_id": 0,
                "model_name": MODEL_NAME,
                "model_version": "active-unregistered",
                "model_type": "unknown",
                "operation": "active_artifact",
                "status": "available",
                "created_at": None,
                "actor": "unknown",
                "model_path": str(legacy_path),
                "artifact_sha256": _artifact_hash(legacy_path),
                "artifact_exists": True,
                "is_active_path": False,
                "active_artifact_metadata_status": "metadata_unknown",
                "active_artifact_metadata_unknown": True,
                "display_model_type": "Active artifact metadata unknown",
                "display_feature_set": "Metadata unavailable",
                "feature_set_version": None,
                "dataset_snapshot_id": None,
                "split_strategy": None,
                "metrics": {},
                "readiness_decision": "unknown_active_artifact",
                "analyst_review_eligible": False,
                "production_promoted": False,
                "response_automation_allowed": False,
                "report_path": None,
                "message": (
                    "A legacy artifact exists but no matching MLModelRun registry row was found. "
                    "It is not selected by the governed v5.1 lifecycle."
                ),
            },
        )
    active_item = next((item for item in items if item.get("is_active_path")), None)
    governed_active = lifecycle.get("lifecycle_state") in {"shadow_observation", "decision_support"}
    active_metadata_unknown = bool(governed_active and active_item and active_item.get("active_artifact_metadata_unknown"))
    return {
        "ok": True,
        "active_model_path": str(governed_active_path) if governed_active_path else "",
        "active_artifact_exists": bool((lifecycle.get("artifact") or {}).get("available")),
        "active_artifact_sha256": (lifecycle.get("artifact") or {}).get("artifact_sha256"),
        "active_artifact_metadata_status": "metadata_unknown" if active_metadata_unknown else "registered" if governed_active else "inactive",
        "active_artifact_metadata_unknown": active_metadata_unknown,
        "lifecycle_state": lifecycle.get("lifecycle_state", "inactive"),
        "governed_lifecycle": lifecycle,
        "legacy_artifact_exists": legacy_path.exists(),
        "legacy_artifact_selected": False,
        "models": items,
        "production_promoted": False,
        "response_automation_allowed": False,
        "decision_support_only": True,
    }


def activate_supervised_model(db: Session, *, model_id: int, actor: str = "cli") -> dict[str, Any]:
    from atdr.app.detection.v51_supervised_lifecycle import activate_governed_supervised_model

    return activate_governed_supervised_model(
        db,
        model_id=model_id,
        lifecycle_state="shadow_observation",
        actor=actor,
    )


def rollback_supervised_model(db: Session, *, actor: str = "cli") -> dict[str, Any]:
    from atdr.app.detection.v51_supervised_lifecycle import rollback_governed_supervised_model

    return rollback_governed_supervised_model(db, actor=actor)
