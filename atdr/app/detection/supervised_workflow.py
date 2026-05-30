import csv
import json
import shutil
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
    _artifact_hash,
    _latest_labels,
    supervised_model_path,
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
) -> dict[str, Any]:
    experiment_id = f"experiment-{_safe_timestamp()}"
    output_dir = Path(output_root)
    output_dir.mkdir(parents=True, exist_ok=True)
    report_path = output_dir / f"{experiment_id}.md"
    started = time.perf_counter()
    result = compare_supervised_models(db, output_path=report_path, test_size=test_size, min_samples=min_samples, split=split)
    result["experiment_id"] = experiment_id
    result["duration_seconds"] = round(time.perf_counter() - started, 4)
    result["feature_set_metadata"] = feature_set_metadata(row_count=result.get("training_rows", 0) + result.get("test_rows", 0))
    result["production_promoted"] = False
    result["response_automation_allowed"] = False
    _write_json(output_dir / f"{experiment_id}.json", result)
    return result


def tune_supervised_model_candidates(
    db: Session,
    *,
    output_root: str | Path = TUNING_DIR,
    split: str = "time",
    test_size: float = 0.3,
    min_samples: int = 6,
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


def _model_run_to_registry_item(run: MLModelRun, *, active_path: Path) -> dict[str, Any]:
    metrics = run.metrics_json or {}
    model_path = Path(run.model_path)
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
        "is_active_path": model_path.resolve() == active_path.resolve() if model_path.exists() and active_path.exists() else False,
        "feature_set_version": (metrics.get("feature_set_metadata") or {}).get("feature_set_version"),
        "dataset_snapshot_id": metrics.get("dataset_snapshot_id"),
        "split_strategy": metrics.get("split_strategy"),
        "metrics": metrics.get("metrics", {}),
        "readiness_decision": (metrics.get("promotion_gate") or {}).get("decision", "candidate_only"),
        "analyst_review_eligible": bool((metrics.get("promotion_gate") or {}).get("analyst_review_eligible", False)),
        "production_promoted": False,
        "response_automation_allowed": False,
        "report_path": metrics.get("report_path"),
        "message": run.message,
    }


def list_supervised_models(db: Session, *, limit: int = 25) -> dict[str, Any]:
    active_path = supervised_model_path()
    runs = list(
        db.scalars(
            select(MLModelRun)
            .where(MLModelRun.operation.in_(["train_supervised", "activate_supervised", "rollback_supervised"]))
            .order_by(desc(MLModelRun.created_at), desc(MLModelRun.id))
            .limit(limit)
        )
    )
    items = [_model_run_to_registry_item(run, active_path=active_path) for run in runs]
    if active_path.exists() and not any(item["is_active_path"] for item in items):
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
                "model_path": str(active_path),
                "artifact_sha256": _artifact_hash(active_path),
                "artifact_exists": True,
                "is_active_path": True,
                "feature_set_version": None,
                "dataset_snapshot_id": None,
                "split_strategy": None,
                "metrics": {},
                "readiness_decision": "unknown_active_artifact",
                "analyst_review_eligible": False,
                "production_promoted": False,
                "response_automation_allowed": False,
                "report_path": None,
                "message": "Active artifact exists but no matching MLModelRun registry row was found.",
            },
        )
    return {
        "ok": True,
        "active_model_path": str(active_path),
        "active_artifact_exists": active_path.exists(),
        "active_artifact_sha256": _artifact_hash(active_path),
        "models": items,
        "production_promoted": False,
        "response_automation_allowed": False,
        "decision_support_only": True,
    }


def activate_supervised_model(db: Session, *, model_id: int, actor: str = "cli") -> dict[str, Any]:
    run = db.get(MLModelRun, model_id)
    if run is None or run.operation != "train_supervised":
        return {"ok": False, "status": "failed", "message": "Training model run not found."}
    source = Path(run.model_path)
    if not source.exists():
        return {"ok": False, "status": "failed", "message": "Model artifact is missing."}
    active_path = supervised_model_path()
    active_path.parent.mkdir(parents=True, exist_ok=True)
    backup_path = None
    if active_path.exists():
        backup_path = active_path.with_suffix(f".backup-{_safe_timestamp()}.joblib")
        shutil.copy2(active_path, backup_path)
    shutil.copy2(source, active_path)
    result = {
        "ok": True,
        "status": "activated",
        "activated_model_id": model_id,
        "active_model_path": str(active_path),
        "active_artifact_sha256": _artifact_hash(active_path),
        "previous_active_backup_path": str(backup_path) if backup_path else None,
        "production_promoted": False,
        "response_automation_allowed": False,
        "message": "Model artifact activated for analyst decision support only.",
    }
    db.add(
        MLModelRun(
            model_name=MODEL_NAME,
            model_version=run.model_version,
            operation="activate_supervised",
            status="activated",
            actor=actor,
            model_path=str(active_path),
            artifact_sha256=result["active_artifact_sha256"],
            artifact_size_bytes=active_path.stat().st_size if active_path.exists() else None,
            training_log_count=run.training_log_count,
            feature_columns_json=run.feature_columns_json,
            metrics_json={
                "activated_model_run_id": model_id,
                "previous_active_backup_path": result["previous_active_backup_path"],
                "production_promoted": False,
                "response_automation_allowed": False,
            },
            message=result["message"],
        )
    )
    db.add(
        AuditLog(
            actor=actor,
            action="activate_supervised_model",
            target_type="ml_model",
            target_value=str(model_id),
            details=result,
        )
    )
    db.commit()
    return result


def rollback_supervised_model(db: Session, *, actor: str = "cli") -> dict[str, Any]:
    activation = db.scalar(
        select(MLModelRun)
        .where(MLModelRun.operation == "activate_supervised")
        .order_by(desc(MLModelRun.created_at), desc(MLModelRun.id))
        .limit(1)
    )
    backup_value = ((activation.metrics_json or {}) if activation else {}).get("previous_active_backup_path")
    backup_path = Path(str(backup_value)) if backup_value else None
    if activation is None or backup_path is None or not backup_path.exists():
        return {"ok": False, "status": "failed", "message": "No rollback backup artifact is available."}
    active_path = supervised_model_path()
    shutil.copy2(backup_path, active_path)
    result = {
        "ok": True,
        "status": "rolled_back",
        "active_model_path": str(active_path),
        "restored_from": str(backup_path),
        "active_artifact_sha256": _artifact_hash(active_path),
        "production_promoted": False,
        "response_automation_allowed": False,
    }
    db.add(
        MLModelRun(
            model_name=MODEL_NAME,
            model_version=activation.model_version,
            operation="rollback_supervised",
            status="rolled_back",
            actor=actor,
            model_path=str(active_path),
            artifact_sha256=result["active_artifact_sha256"],
            artifact_size_bytes=active_path.stat().st_size if active_path.exists() else None,
            feature_columns_json=activation.feature_columns_json,
            metrics_json=result,
            message="Rolled back active supervised model artifact for analyst decision support.",
        )
    )
    db.add(
        AuditLog(
            actor=actor,
            action="rollback_supervised_model",
            target_type="ml_model",
            target_value=str(activation.id),
            details=result,
        )
    )
    db.commit()
    return result
