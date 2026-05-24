import hashlib
import math
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from atdr.app.core.config import get_settings
from atdr.app.db.models import AuditLog, MLLabel, MLModelRun, NormalizedLog
from atdr.app.detection.hybrid_scoring import hybrid_risk_score
from atdr.app.ml.features import CATEGORICAL_FEATURES, FEATURE_COLUMNS, NUMERIC_FEATURES, build_feature_rows, build_log_features


MODEL_NAME = "supervised_random_forest"
TRAINABLE_LABELS = {"benign", "benign_unusual", "suspicious", "malicious"}
POSITIVE_LABELS = {"suspicious", "malicious"}


def _optional_imports():
    try:
        import joblib
        import pandas as pd
        from sklearn.compose import ColumnTransformer
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.impute import SimpleImputer
        from sklearn.metrics import accuracy_score, confusion_matrix, precision_recall_fscore_support
        from sklearn.model_selection import train_test_split
        from sklearn.pipeline import Pipeline
        from sklearn.preprocessing import OneHotEncoder
    except ImportError:
        return None
    return (
        joblib,
        pd,
        ColumnTransformer,
        RandomForestClassifier,
        SimpleImputer,
        accuracy_score,
        confusion_matrix,
        precision_recall_fscore_support,
        train_test_split,
        Pipeline,
        OneHotEncoder,
    )


def supervised_model_path(path: str | Path | None = None) -> Path:
    if path is not None:
        model_path = Path(path)
        return model_path if model_path.is_absolute() else Path(get_settings().resolved_model_path).parent / model_path
    settings = get_settings()
    return settings.resolved_supervised_model_path


def _artifact_hash(path: Path) -> str | None:
    if not path.exists():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _report_path_for_model(path: Path) -> Path:
    return path.with_suffix(".report.md")


def _render_supervised_report(result: dict) -> str:
    metrics = result.get("metrics") or {}
    labels = metrics.get("labels") or sorted((result.get("label_distribution") or {}).keys())
    matrix = metrics.get("confusion_matrix") or []
    matrix_lines = ["| Actual \\ Predicted | " + " | ".join(str(label) for label in labels) + " |"]
    matrix_lines.append("| --- | " + " | ".join("---" for _ in labels) + " |")
    for label, row in zip(labels, matrix, strict=False):
        matrix_lines.append("| " + str(label) + " | " + " | ".join(str(value) for value in row) + " |")
    feature_lines = "\n".join(f"- `{column}`" for column in result.get("feature_columns", []))
    distribution_lines = "\n".join(f"- {label}: {count}" for label, count in (result.get("label_distribution") or {}).items())
    source_lines = "\n".join(f"- {source}: {count}" for source, count in (result.get("label_source_distribution") or {}).items())
    return f"""# ATDR Supervised AI Model Evaluation

## Model

- Model name: {result.get("model_name", MODEL_NAME)}
- Model version: {result.get("model_version", "not_trained")}
- Status: {result.get("status", "unknown")}
- Model path: {result.get("model_path", "")}
- Artifact SHA-256: {result.get("artifact_sha256") or "not_available"}

## Dataset

- Training rows: {result.get("training_rows", 0)}
- Test rows: {result.get("test_rows", 0)}

## Label Distribution

{distribution_lines or "- No labels available"}

## Label Provenance

{source_lines or "- No label-source distribution available"}

- Reviewed label rows: {result.get("reviewed_label_count", "not_available")}
- Unreviewed assisted label rows: {result.get("unreviewed_assisted_label_count", "not_available")}

## Metrics

- Accuracy: {metrics.get("accuracy", "not_available")}
- Precision: {metrics.get("precision", "not_available")}
- Recall: {metrics.get("recall", "not_available")}
- F1: {metrics.get("f1", "not_available")}

## Confusion Matrix

{chr(10).join(matrix_lines) if matrix else "No confusion matrix available."}

## Feature Columns

{feature_lines or "- No feature columns available"}

## Limitations

- This model is decision support only. Rule evidence and analyst review remain authoritative.
- Metrics are only meaningful when labels are representative of the small office environment being monitored.
- The model can miss novel activity and can overfit small or synthetic label sets.
- Response actions must remain simulated or analyst-approved until firewall integration is formally authorized and tested.
"""


def _write_supervised_report(path: Path, result: dict) -> Path:
    report_path = _report_path_for_model(path)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(_render_supervised_report(result), encoding="utf-8")
    return report_path


def _latest_labels(db: Session) -> list[MLLabel]:
    labels = list(
        db.scalars(
            select(MLLabel)
            .join(MLLabel.log)
            .where(MLLabel.label.in_(TRAINABLE_LABELS))
            .order_by(MLLabel.log_id, desc(MLLabel.created_at), desc(MLLabel.id))
        )
    )
    latest: dict[int, MLLabel] = {}
    for label in labels:
        latest.setdefault(label.log_id, label)
    return list(latest.values())


def _label_distribution(labels: list[str]) -> dict[str, int]:
    return {label: labels.count(label) for label in sorted(set(labels))}


def _label_source_distribution(labels: list[MLLabel]) -> dict[str, int]:
    sources = [getattr(label, "label_source", "manual") for label in labels]
    return {source: sources.count(source) for source in sorted(set(sources))}


def _build_pipeline(imports):
    _, _, ColumnTransformer, RandomForestClassifier, SimpleImputer, *_rest, Pipeline, OneHotEncoder = imports
    preprocessor = ColumnTransformer(
        transformers=[
            ("numeric", SimpleImputer(strategy="median"), NUMERIC_FEATURES),
            (
                "categorical",
                Pipeline(
                    steps=[
                        ("imputer", SimpleImputer(strategy="most_frequent")),
                        ("onehot", OneHotEncoder(handle_unknown="ignore")),
                    ]
                ),
                CATEGORICAL_FEATURES,
            ),
        ]
    )
    return Pipeline(
        steps=[
            ("preprocess", preprocessor),
            ("model", RandomForestClassifier(n_estimators=150, random_state=42, class_weight="balanced")),
        ]
    )


def _feature_importances(pipeline, limit: int = 10) -> list[dict[str, Any]]:
    model = pipeline.named_steps.get("model")
    preprocessor = pipeline.named_steps.get("preprocess")
    if model is None or preprocessor is None or not hasattr(model, "feature_importances_"):
        return []
    try:
        names = preprocessor.get_feature_names_out()
    except Exception:
        names = FEATURE_COLUMNS
    pairs = sorted(zip(names, model.feature_importances_, strict=False), key=lambda item: float(item[1]), reverse=True)
    return [{"feature": str(name), "importance": round(float(value), 6)} for name, value in pairs[:limit]]


def train_supervised_classifier(
    db: Session,
    *,
    actor: str = "cli",
    model_path: str | Path | None = None,
    test_size: float = 0.3,
    min_samples: int = 6,
) -> dict:
    imports = _optional_imports()
    if imports is None:
        return {"trained": False, "status": "skipped", "message": "Supervised ML dependencies are unavailable."}
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

    labels = _latest_labels(db)
    logs = [label.log for label in labels if label.log is not None]
    y = [label.label for label in labels if label.log is not None]
    source_distribution = _label_source_distribution(labels)
    reviewed_count = sum(1 for label in labels if getattr(label, "reviewed", True))
    unreviewed_assisted_count = sum(
        1 for label in labels if not getattr(label, "reviewed", True) and getattr(label, "label_source", "").startswith("assisted")
    )
    if len(logs) < min_samples or len(set(y)) < 2:
        result = {
            "trained": False,
            "status": "skipped",
            "message": "Need at least two label classes and enough reviewed rows to train supervised model.",
            "training_rows": len(logs),
            "label_distribution": _label_distribution(y),
            "label_source_distribution": source_distribution,
            "reviewed_label_count": reviewed_count,
            "unreviewed_assisted_label_count": unreviewed_assisted_count,
        }
        _record_run(db, result, actor=actor, model_path=supervised_model_path(model_path))
        return result

    X = pd.DataFrame(build_feature_rows(db, logs))
    distribution = _label_distribution(y)
    estimated_test_rows = max(1, math.ceil(len(y) * test_size))
    stratify = y if min(distribution.values()) >= 2 and estimated_test_rows >= len(distribution) else None
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=test_size, random_state=42, stratify=stratify)
    pipeline = _build_pipeline(imports)
    pipeline.fit(X_train, y_train)
    predictions = pipeline.predict(X_test)
    labels_order = sorted(set(y))
    precision, recall, f1, _support = precision_recall_fscore_support(
        y_test,
        predictions,
        labels=labels_order,
        average="weighted",
        zero_division=0,
    )
    path = supervised_model_path(model_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    artifact = {
        "pipeline": pipeline,
        "feature_columns": FEATURE_COLUMNS,
        "label_classes": labels_order,
        "positive_labels": sorted(POSITIVE_LABELS),
        "trained_at": datetime.now(timezone.utc).isoformat(),
    }
    joblib.dump(artifact, path)
    result = {
        "trained": True,
        "status": "trained",
        "model_name": MODEL_NAME,
        "model_path": str(path),
        "model_version": f"rf-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}",
        "training_rows": len(X_train),
        "test_rows": len(X_test),
        "metrics": {
            "accuracy": round(float(accuracy_score(y_test, predictions)), 4),
            "precision": round(float(precision), 4),
            "recall": round(float(recall), 4),
            "f1": round(float(f1), 4),
            "confusion_matrix": confusion_matrix(y_test, predictions, labels=labels_order).tolist(),
            "labels": labels_order,
        },
        "label_distribution": _label_distribution(y),
        "label_source_distribution": source_distribution,
        "reviewed_label_count": reviewed_count,
        "unreviewed_assisted_label_count": unreviewed_assisted_count,
        "feature_columns": FEATURE_COLUMNS,
        "top_features": _feature_importances(pipeline),
        "artifact_sha256": _artifact_hash(path),
        "message": f"Trained supervised classifier on {len(X_train)} rows and tested on {len(X_test)} rows.",
    }
    report_path = _write_supervised_report(path, result)
    result["report_path"] = str(report_path)
    _record_run(db, result, actor=actor, model_path=path)
    return result


def _record_run(db: Session, result: dict, *, actor: str, model_path: Path) -> None:
    run = MLModelRun(
        model_name=MODEL_NAME,
        model_version=result.get("model_version"),
        operation="train_supervised",
        status=result.get("status", "skipped"),
        actor=actor,
        model_path=str(model_path),
        artifact_sha256=result.get("artifact_sha256"),
        artifact_size_bytes=model_path.stat().st_size if model_path.exists() else None,
        training_log_count=result.get("training_rows"),
        feature_columns_json=result.get("feature_columns", FEATURE_COLUMNS),
        metrics_json={
            "metrics": result.get("metrics", {}),
            "label_distribution": result.get("label_distribution", {}),
            "test_rows": result.get("test_rows", 0),
            "top_features": result.get("top_features", []),
            "report_path": result.get("report_path"),
            "label_source_distribution": result.get("label_source_distribution", {}),
            "reviewed_label_count": result.get("reviewed_label_count"),
            "unreviewed_assisted_label_count": result.get("unreviewed_assisted_label_count"),
        },
        message=result.get("message", ""),
    )
    db.add(run)
    db.add(
        AuditLog(
            actor=actor,
            action="train_supervised_model",
            target_type="ml_model",
            target_value=str(model_path),
            details={"status": run.status, "training_rows": run.training_log_count, "metrics": result.get("metrics", {})},
        )
    )
    db.commit()


def supervised_model_report(db: Session) -> dict:
    path = supervised_model_path()
    latest = db.scalar(
        select(MLModelRun)
        .where(MLModelRun.model_name == MODEL_NAME, MLModelRun.operation == "train_supervised")
        .order_by(desc(MLModelRun.created_at), desc(MLModelRun.id))
        .limit(1)
    )
    label_rows = db.execute(select(MLLabel.label, func.count()).group_by(MLLabel.label)).all()
    source_rows = db.execute(select(MLLabel.label_source, func.count()).group_by(MLLabel.label_source)).all()
    reviewed_count = int(db.scalar(select(func.count(MLLabel.id)).where(MLLabel.reviewed.is_(True))) or 0)
    unreviewed_assisted_count = int(
        db.scalar(select(func.count(MLLabel.id)).where(MLLabel.reviewed.is_(False), MLLabel.label_source.like("assisted%"))) or 0
    )
    return {
        "model_name": MODEL_NAME,
        "model_path": str(path),
        "artifact_exists": path.exists(),
        "artifact_sha256": _artifact_hash(path),
        "latest_run": _run_to_report(latest) if latest else None,
        "label_count": int(db.scalar(select(func.count(MLLabel.id))) or 0),
        "label_distribution": {str(label): int(count) for label, count in label_rows},
        "label_source_distribution": {str(source): int(count) for source, count in source_rows},
        "reviewed_label_count": reviewed_count,
        "unreviewed_assisted_label_count": unreviewed_assisted_count,
        "decision_support_only": True,
    }


def _run_to_report(run: MLModelRun) -> dict:
    metrics = run.metrics_json or {}
    return {
        "id": run.id,
        "model_version": run.model_version,
        "status": run.status,
        "actor": run.actor,
        "training_rows": run.training_log_count,
        "test_rows": metrics.get("test_rows", 0),
        "metrics": metrics.get("metrics", {}),
        "label_distribution": metrics.get("label_distribution", {}),
        "label_source_distribution": metrics.get("label_source_distribution", {}),
        "reviewed_label_count": metrics.get("reviewed_label_count"),
        "unreviewed_assisted_label_count": metrics.get("unreviewed_assisted_label_count"),
        "top_features": metrics.get("top_features", []),
        "report_path": metrics.get("report_path"),
        "created_at": run.created_at,
        "message": run.message,
    }


def supervised_report_markdown(db: Session) -> str:
    latest = db.scalar(
        select(MLModelRun)
        .where(MLModelRun.model_name == MODEL_NAME, MLModelRun.operation == "train_supervised")
        .order_by(desc(MLModelRun.created_at), desc(MLModelRun.id))
        .limit(1)
    )
    if latest is None:
        return _render_supervised_report(
            {
                "status": "not_trained",
                "model_name": MODEL_NAME,
                "model_path": str(supervised_model_path()),
                "label_distribution": {},
                "feature_columns": FEATURE_COLUMNS,
                "message": "No supervised training run has been recorded yet.",
            }
        )
    metrics_json = latest.metrics_json or {}
    report_path = metrics_json.get("report_path")
    if report_path and Path(report_path).exists():
        return Path(report_path).read_text(encoding="utf-8")
    result = {
        "model_name": latest.model_name,
        "model_version": latest.model_version,
        "status": latest.status,
        "model_path": latest.model_path,
        "artifact_sha256": latest.artifact_sha256,
        "training_rows": latest.training_log_count,
        "test_rows": metrics_json.get("test_rows", 0),
        "metrics": metrics_json.get("metrics", {}),
        "label_distribution": metrics_json.get("label_distribution", {}),
        "label_source_distribution": metrics_json.get("label_source_distribution", {}),
        "reviewed_label_count": metrics_json.get("reviewed_label_count"),
        "unreviewed_assisted_label_count": metrics_json.get("unreviewed_assisted_label_count"),
        "feature_columns": latest.feature_columns_json or FEATURE_COLUMNS,
        "message": latest.message,
    }
    return _render_supervised_report(result)


def predict_supervised_log(db: Session, log_id: int, *, rule_score: int = 0, asset_context_weight: int = 0) -> dict:
    imports = _optional_imports()
    if imports is None:
        return {"predicted_label": None, "malicious_probability": 0.0, "confidence": 0.0, "top_contributing_features": []}
    joblib, pd, *_ = imports
    path = supervised_model_path()
    if not path.exists():
        return {"predicted_label": None, "malicious_probability": 0.0, "confidence": 0.0, "top_contributing_features": []}
    log = db.get(NormalizedLog, log_id)
    if log is None:
        return {"predicted_label": None, "malicious_probability": 0.0, "confidence": 0.0, "top_contributing_features": []}
    artifact = joblib.load(path)
    pipeline = artifact["pipeline"]
    frame = pd.DataFrame([build_log_features(db, log)])
    predicted = str(pipeline.predict(frame)[0])
    classes = list(getattr(pipeline.named_steps["model"], "classes_", []))
    probabilities = pipeline.predict_proba(frame)[0] if hasattr(pipeline, "predict_proba") else []
    class_probs = {str(label): float(prob) for label, prob in zip(classes, probabilities, strict=False)}
    malicious_probability = round(sum(class_probs.get(label, 0.0) for label in POSITIVE_LABELS), 4)
    confidence = round(max(class_probs.values()) if class_probs else 0.0, 4)
    hybrid = hybrid_risk_score(
        rule_score=rule_score,
        isolation_anomaly_score=log.anomaly_score,
        isolation_is_anomaly=log.is_anomaly,
        supervised_malicious_probability=malicious_probability,
        asset_context_weight=asset_context_weight,
    )
    return {
        "predicted_label": predicted,
        "malicious_probability": malicious_probability,
        "confidence": confidence,
        "top_contributing_features": _feature_importances(pipeline),
        "class_probabilities": class_probs,
        "hybrid_risk": hybrid,
        "decision_support_only": True,
    }
