import logging
from pathlib import Path
from typing import Iterable

from sqlalchemy import select
from sqlalchemy.orm import Session

from atdr.app.core.config import get_settings
from atdr.app.db.models import NormalizedLog

logger = logging.getLogger(__name__)

NUMERIC_FEATURES = [
    "src_port",
    "dst_port",
    "bytes",
    "bytes_sent",
    "bytes_received",
    "packets",
    "elapsed_time",
    "app_risk",
]
CATEGORICAL_FEATURES = ["protocol", "action", "app", "src_zone", "dst_zone"]
FEATURE_COLUMNS = [*NUMERIC_FEATURES, *CATEGORICAL_FEATURES]


def _optional_ml_imports():
    try:
        import joblib
        import pandas as pd
        from sklearn.compose import ColumnTransformer
        from sklearn.ensemble import IsolationForest
        from sklearn.impute import SimpleImputer
        from sklearn.pipeline import Pipeline
        from sklearn.preprocessing import OneHotEncoder
    except ImportError as exc:
        logger.warning("ML dependencies are unavailable: %s", exc)
        return None
    return joblib, pd, ColumnTransformer, IsolationForest, SimpleImputer, Pipeline, OneHotEncoder


def logs_to_records(logs: Iterable[NormalizedLog]) -> list[dict]:
    records: list[dict] = []
    for log in logs:
        record = {feature: getattr(log, feature) for feature in NUMERIC_FEATURES}
        record.update({feature: getattr(log, feature) for feature in CATEGORICAL_FEATURES})
        record["id"] = log.id
        records.append(record)
    return records


def build_feature_summary(records: list[dict]) -> dict:
    imports = _optional_ml_imports()
    if imports is None or not records:
        return {}

    _, pd, *_ = imports
    df = pd.DataFrame(records)
    summary: dict = {
        "row_count": int(len(df)),
        "numeric": {},
        "categorical": {},
    }
    for feature in NUMERIC_FEATURES:
        if feature not in df.columns:
            continue
        series = pd.to_numeric(df[feature], errors="coerce")
        summary["numeric"][feature] = {
            "missing": int(series.isna().sum()),
            "min": None if series.dropna().empty else float(series.min()),
            "max": None if series.dropna().empty else float(series.max()),
            "median": None if series.dropna().empty else float(series.median()),
        }
    for feature in CATEGORICAL_FEATURES:
        if feature not in df.columns:
            continue
        series = df[feature].fillna("unknown").astype(str)
        top_values = series.value_counts().head(8)
        summary["categorical"][feature] = {
            "missing": int(df[feature].isna().sum()),
            "unique": int(series.nunique()),
            "top_values": [{"value": str(name), "count": int(count)} for name, count in top_values.items()],
        }
    return summary


def train_model(
    db: Session,
    model_path: Path | None = None,
    limit: int | None = None,
    logs: list[NormalizedLog] | None = None,
) -> dict:
    imports = _optional_ml_imports()
    if imports is None:
        return {"trained": False, "message": "ML dependencies are not installed."}

    joblib, pd, ColumnTransformer, IsolationForest, SimpleImputer, Pipeline, OneHotEncoder = imports
    settings = get_settings()
    model_path = model_path or settings.resolved_model_path
    if logs is None:
        statement = select(NormalizedLog).order_by(NormalizedLog.id.desc())
        if limit:
            statement = statement.limit(limit)
        logs = list(db.scalars(statement))
    if len(logs) < 20:
        return {
            "trained": False,
            "message": "Need at least 20 parsed logs to train a useful prototype model.",
            "model_path": str(model_path),
            "training_log_count": len(logs),
            "contamination": settings.ml_contamination,
            "feature_columns": FEATURE_COLUMNS,
            "feature_summary": build_feature_summary(logs_to_records(logs)),
        }

    records = logs_to_records(logs)
    feature_summary = build_feature_summary(records)
    df = pd.DataFrame(records).drop(columns=["id"])
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
    pipeline = Pipeline(
        steps=[
            ("preprocess", preprocessor),
            (
                "model",
                IsolationForest(
                    contamination=settings.ml_contamination,
                    random_state=42,
                    n_estimators=150,
                ),
            ),
        ]
    )
    pipeline.fit(df)
    model_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(pipeline, model_path)
    return {
        "trained": True,
        "message": f"Trained IsolationForest on {len(logs)} logs.",
        "model_path": str(model_path),
        "training_log_count": len(logs),
        "contamination": settings.ml_contamination,
        "feature_columns": FEATURE_COLUMNS,
        "feature_summary": feature_summary,
    }


def apply_model_to_db(db: Session, model_path: Path | None = None, limit: int | None = None) -> dict[int, dict]:
    imports = _optional_ml_imports()
    if imports is None:
        return {}

    joblib, pd, *_ = imports
    settings = get_settings()
    model_path = model_path or settings.resolved_model_path
    if not model_path.exists():
        logger.info("ML model does not exist yet at %s", model_path)
        return {}

    statement = select(NormalizedLog).order_by(NormalizedLog.id.desc())
    if limit:
        statement = statement.limit(limit)
    logs = list(db.scalars(statement))
    if not logs:
        return {}

    model = joblib.load(model_path)
    df = pd.DataFrame(logs_to_records(logs))
    ids = df["id"].tolist()
    feature_df = df.drop(columns=["id"])
    labels = model.predict(feature_df)
    scores = model.decision_function(feature_df)

    result: dict[int, dict] = {}
    for log, label, score in zip(logs, labels, scores, strict=False):
        log.is_anomaly = bool(label == -1)
        log.anomaly_score = float(score)
        result[log.id] = {"is_anomaly": log.is_anomaly, "anomaly_score": log.anomaly_score}
    db.flush()
    return result
