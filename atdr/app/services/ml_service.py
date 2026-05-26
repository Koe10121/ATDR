import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import case, desc, func, or_, select
from sqlalchemy.orm import Session

from atdr.app.core.config import get_settings
from atdr.app.db.models import AuditLog, IngestionRun, MLModelRun, NormalizedLog, RawLog
from atdr.app.detection.ml_detector import FEATURE_COLUMNS, apply_model_to_db, train_model


MODEL_NAME = "isolation_forest"
UNKNOWN_APPS = ["unknown-tcp", "unknown-udp", "unknown-p2p", "incomplete", "not-applicable"]
_ARTIFACT_CACHE: dict[str, dict[str, Any]] = {}
EXACT_JSON_QUALITY_LIMIT = 50_000


def _artifact_metadata(path: Path) -> dict:
    if not path.exists():
        return {"exists": False, "sha256": None, "size_bytes": None}
    stat = path.stat()
    cache_key = f"{path.resolve()}:{stat.st_mtime_ns}:{stat.st_size}"
    cached = _ARTIFACT_CACHE.get(cache_key)
    if cached:
        return dict(cached)
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    metadata = {"exists": True, "sha256": digest.hexdigest(), "size_bytes": stat.st_size}
    _ARTIFACT_CACHE.clear()
    _ARTIFACT_CACHE[cache_key] = metadata
    return dict(metadata)


def _model_version() -> str:
    return f"iforest-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"


def _anomaly_rate(anomalies: int, total: int) -> float:
    return round((anomalies / total) * 100, 2) if total else 0.0


def _known_or_missing_app_filter():
    return or_(NormalizedLog.app.is_(None), func.lower(NormalizedLog.app).not_in(UNKNOWN_APPS))


def _baseline_filters(max_app_risk: int = 3, exclude_unknown_apps: bool = True, exclude_existing_anomalies: bool = True) -> list:
    filters = [
        func.lower(NormalizedLog.action) == "allow",
        or_(NormalizedLog.app_risk.is_(None), NormalizedLog.app_risk <= max_app_risk),
    ]
    if exclude_unknown_apps:
        filters.append(_known_or_missing_app_filter())
    if exclude_existing_anomalies:
        filters.append(NormalizedLog.is_anomaly.is_(False))
    return filters


def _training_logs(
    db: Session,
    *,
    limit: int | None,
    baseline_only: bool,
    max_app_risk: int,
    exclude_unknown_apps: bool,
    exclude_existing_anomalies: bool,
) -> list[NormalizedLog] | None:
    if not baseline_only:
        return None
    statement = select(NormalizedLog).order_by(NormalizedLog.id.desc())
    for filter_clause in _baseline_filters(max_app_risk, exclude_unknown_apps, exclude_existing_anomalies):
        statement = statement.where(filter_clause)
    if limit:
        statement = statement.limit(limit)
    return list(db.scalars(statement))


def train_anomaly_model(
    db: Session,
    *,
    limit: int | None = None,
    actor: str = "system",
    baseline_only: bool = False,
    max_app_risk: int = 3,
    exclude_unknown_apps: bool = True,
    exclude_existing_anomalies: bool = True,
) -> dict:
    settings = get_settings()
    logs = _training_logs(
        db,
        limit=limit,
        baseline_only=baseline_only,
        max_app_risk=max_app_risk,
        exclude_unknown_apps=exclude_unknown_apps,
        exclude_existing_anomalies=exclude_existing_anomalies,
    )
    result = train_model(db, limit=limit, logs=logs)
    artifact = _artifact_metadata(settings.resolved_model_path)
    status = "trained" if result.get("trained") else "skipped"
    model_version = _model_version() if result.get("trained") else None
    training_filter = {
        "baseline_only": baseline_only,
        "max_app_risk": max_app_risk if baseline_only else None,
        "exclude_unknown_apps": exclude_unknown_apps if baseline_only else None,
        "exclude_existing_anomalies": exclude_existing_anomalies if baseline_only else None,
        "limit": limit,
    }

    run = MLModelRun(
        model_name=MODEL_NAME,
        model_version=model_version,
        operation="train",
        status=status,
        actor=actor,
        model_path=str(settings.resolved_model_path),
        artifact_sha256=artifact["sha256"],
        artifact_size_bytes=artifact["size_bytes"],
        training_log_count=result.get("training_log_count"),
        contamination=result.get("contamination", settings.ml_contamination),
        feature_columns_json=result.get("feature_columns", FEATURE_COLUMNS),
        feature_summary_json=result.get("feature_summary", {}),
        metrics_json={"artifact_exists": artifact["exists"], "training_filter": training_filter},
        message=result.get("message", ""),
    )
    db.add(run)
    db.add(
        AuditLog(
            actor=actor,
            action="train_ml_model",
            target_type="ml_model",
            target_value=settings.ml_model_path,
            details={
                "status": status,
                "model_version": model_version,
                "training_log_count": result.get("training_log_count"),
                "artifact_sha256": artifact["sha256"],
                "training_filter": training_filter,
            },
        )
    )
    db.commit()
    db.refresh(run)
    return {**result, "status": status, "model_version": model_version, "run_id": run.id, "training_filter": training_filter}


def apply_anomaly_scoring(db: Session, *, limit: int | None = None, actor: str = "system") -> dict:
    settings = get_settings()
    result = apply_model_to_db(db, limit=limit)
    anomalies = sum(1 for item in result.values() if item["is_anomaly"])
    scored = len(result)
    artifact = _artifact_metadata(settings.resolved_model_path)
    latest_train = latest_model_run(db, operation="train", status="trained")

    run = MLModelRun(
        model_name=MODEL_NAME,
        model_version=latest_train.model_version if latest_train else None,
        operation="score",
        status="scored" if scored else "skipped",
        actor=actor,
        model_path=str(settings.resolved_model_path),
        artifact_sha256=artifact["sha256"],
        artifact_size_bytes=artifact["size_bytes"],
        scored_log_count=scored,
        anomaly_count=anomalies,
        anomaly_rate=_anomaly_rate(anomalies, scored),
        contamination=settings.ml_contamination,
        feature_columns_json=FEATURE_COLUMNS,
        metrics_json={"artifact_exists": artifact["exists"], "limit": limit},
        message=f"Scored {scored} logs and flagged {anomalies} anomalies." if scored else "No logs were scored.",
    )
    db.add(run)
    db.add(
        AuditLog(
            actor=actor,
            action="apply_ml_scoring",
            target_type="normalized_logs",
            target_value="latest_batch",
            details={
                "scored": scored,
                "anomalies": anomalies,
                "anomaly_rate": _anomaly_rate(anomalies, scored),
                "limit": limit,
            },
        )
    )
    db.commit()
    db.refresh(run)
    return {"scored": scored, "anomalies": anomalies, "anomaly_rate": run.anomaly_rate, "run_id": run.id}


def latest_model_run(db: Session, *, operation: str | None = None, status: str | None = None) -> MLModelRun | None:
    statement = select(MLModelRun).order_by(MLModelRun.created_at.desc(), MLModelRun.id.desc())
    if operation:
        statement = statement.where(MLModelRun.operation == operation)
    if status:
        statement = statement.where(MLModelRun.status == status)
    return db.scalar(statement.limit(1))


def list_model_runs(db: Session, limit: int = 20) -> list[MLModelRun]:
    return list(db.scalars(select(MLModelRun).order_by(desc(MLModelRun.created_at), desc(MLModelRun.id)).limit(limit)))


def model_status(db: Session) -> dict:
    settings = get_settings()
    artifact = _artifact_metadata(settings.resolved_model_path)
    latest_train = latest_model_run(db, operation="train")
    latest_score = latest_model_run(db, operation="score")
    total_logs = int(db.scalar(select(func.count(NormalizedLog.id))) or 0)
    anomaly_logs = int(db.scalar(select(func.count(NormalizedLog.id)).where(NormalizedLog.is_anomaly.is_(True))) or 0)
    return {
        "model_name": MODEL_NAME,
        "model_path": str(settings.resolved_model_path),
        "artifact_exists": artifact["exists"],
        "artifact_sha256": artifact["sha256"],
        "artifact_size_bytes": artifact["size_bytes"],
        "contamination": settings.ml_contamination,
        "feature_columns": FEATURE_COLUMNS,
        "latest_training": run_to_dict(latest_train) if latest_train else None,
        "latest_scoring": run_to_dict(latest_score) if latest_score else None,
        "total_logs": total_logs,
        "current_anomaly_logs": anomaly_logs,
        "current_anomaly_rate": _anomaly_rate(anomaly_logs, total_logs),
    }


def _count_group(db: Session, column, limit: int = 10) -> list[dict]:
    rows = db.execute(
        select(column, func.count())
        .where(column.is_not(None))
        .group_by(column)
        .order_by(desc(func.count()))
        .limit(limit)
    ).all()
    return [{"name": str(name), "count": int(count)} for name, count in rows]


def _count_where(db: Session, *filters) -> int:
    statement = select(func.count(NormalizedLog.id))
    for filter_clause in filters:
        statement = statement.where(filter_clause)
    return int(db.scalar(statement) or 0)


def _sum_if(condition):
    return func.coalesce(func.sum(case((condition, 1), else_=0)), 0)


def _traffic_aggregate(db: Session, *, baseline_max_app_risk: int = 3) -> dict:
    lower_action = func.lower(NormalizedLog.action)
    lower_app = func.lower(NormalizedLog.app)
    unknown_app_condition = lower_app.in_(UNKNOWN_APPS)
    baseline_candidate_condition = (
        (lower_action == "allow")
        & (or_(NormalizedLog.app_risk.is_(None), NormalizedLog.app_risk <= baseline_max_app_risk))
        & (or_(NormalizedLog.app.is_(None), lower_app.not_in(UNKNOWN_APPS)))
        & (NormalizedLog.is_anomaly.is_(False))
    )
    row = db.execute(
        select(
            func.count(NormalizedLog.id).label("total_logs"),
            func.min(NormalizedLog.generated_time).label("generated_time_min"),
            func.max(NormalizedLog.generated_time).label("generated_time_max"),
            _sum_if(NormalizedLog.is_anomaly.is_(True)).label("anomaly_logs"),
            _sum_if(lower_action.in_(["deny", "drop"])).label("deny_drop_logs"),
            _sum_if(lower_action.in_(["deny", "drop", "reset-both", "reset-client", "reset-server"])).label(
                "deny_drop_reset_logs"
            ),
            _sum_if(NormalizedLog.app_risk >= 4).label("high_risk_logs"),
            _sum_if(unknown_app_condition).label("unknown_app_logs"),
            _sum_if(baseline_candidate_condition).label("baseline_candidate_count"),
        )
    ).mappings().one()
    return {key: int(value or 0) if key.endswith(("_logs", "_count")) or key == "total_logs" else value for key, value in row.items()}


def _quality_aggregate(db: Session) -> dict:
    lower_app = func.lower(NormalizedLog.app)
    row = db.execute(
        select(
            _sum_if(NormalizedLog.generated_time.is_(None) & NormalizedLog.receive_time.is_(None)).label("missing_timestamp"),
            _sum_if(or_(NormalizedLog.src_ip.is_(None), NormalizedLog.src_ip == "")).label("missing_source_ip"),
            _sum_if(or_(NormalizedLog.dst_ip.is_(None), NormalizedLog.dst_ip == "")).label("missing_destination_ip"),
            _sum_if(or_(NormalizedLog.action.is_(None), NormalizedLog.action == "")).label("missing_action"),
            _sum_if(lower_app.in_(UNKNOWN_APPS)).label("unknown_app_count"),
        )
    ).mappings().one()
    return {key: int(value or 0) for key, value in row.items()}


def _duplicate_raw_logs_from_runs(db: Session) -> int:
    return int(db.scalar(select(func.coalesce(func.sum(IngestionRun.duplicate_raw_logs), 0))) or 0)


def _parser_error_count(db: Session, *, total_logs: int, parser_error_filter) -> int:
    if total_logs <= EXACT_JSON_QUALITY_LIMIT:
        return _count_where(db, parser_error_filter)
    return int(db.scalar(select(func.coalesce(func.sum(IngestionRun.parse_failures), 0))) or 0)


def dataset_profile(db: Session, *, baseline_max_app_risk: int = 3) -> dict:
    aggregate = _traffic_aggregate(db, baseline_max_app_risk=baseline_max_app_risk)
    total_logs = int(aggregate["total_logs"])
    anomaly_logs = int(aggregate["anomaly_logs"])
    deny_drop_logs = int(aggregate["deny_drop_logs"])
    high_risk_logs = int(aggregate["high_risk_logs"])
    unknown_app_logs = int(aggregate["unknown_app_logs"])
    baseline_candidate_count = int(aggregate["baseline_candidate_count"])

    recommendations: list[str] = []
    if total_logs < 1000:
        recommendations.append("Collect more logs before relying on anomaly-rate conclusions.")
    if baseline_candidate_count < 20:
        recommendations.append("Baseline training is not recommended yet because fewer than 20 candidate logs match the safe baseline filter.")
    else:
        recommendations.append("Use baseline-only training first, then score the broader dataset and review anomaly rate.")
    if high_risk_logs:
        recommendations.append("Keep app risk 4-5 traffic out of baseline training unless it is reviewed and accepted as normal.")
    if deny_drop_logs:
        recommendations.append("Keep deny/drop policy events out of baseline training; they are response signals, not normal behavior.")
    if anomaly_logs:
        recommendations.append("Exclude existing anomaly-flagged logs from the next baseline training pass.")

    return {
        "total_logs": total_logs,
        "generated_time_min": aggregate["generated_time_min"],
        "generated_time_max": aggregate["generated_time_max"],
        "current_anomaly_logs": anomaly_logs,
        "current_anomaly_rate": _anomaly_rate(anomaly_logs, total_logs),
        "deny_drop_logs": deny_drop_logs,
        "deny_drop_rate": _anomaly_rate(deny_drop_logs, total_logs),
        "high_risk_logs": high_risk_logs,
        "high_risk_rate": _anomaly_rate(high_risk_logs, total_logs),
        "unknown_app_logs": unknown_app_logs,
        "unknown_app_rate": _anomaly_rate(unknown_app_logs, total_logs),
        "baseline_max_app_risk": baseline_max_app_risk,
        "baseline_candidate_count": baseline_candidate_count,
        "baseline_candidate_rate": _anomaly_rate(baseline_candidate_count, total_logs),
        "action_distribution": _count_group(db, NormalizedLog.action),
        "app_risk_distribution": _count_group(db, NormalizedLog.app_risk),
        "protocol_distribution": _count_group(db, NormalizedLog.protocol),
        "top_apps": _count_group(db, NormalizedLog.app),
        "top_src_zones": _count_group(db, NormalizedLog.src_zone),
        "top_dst_zones": _count_group(db, NormalizedLog.dst_zone),
        "recommendations": recommendations,
    }


def data_quality_profile(db: Session) -> dict:
    total_raw = int(db.scalar(select(func.count(RawLog.id))) or 0)
    total_normalized = int(db.scalar(select(func.count(NormalizedLog.id))) or 0)
    parser_error_filter = NormalizedLog.parsed_json["parser_error"].as_string().is_not(None)
    parse_errors = _parser_error_count(db, total_logs=total_normalized, parser_error_filter=parser_error_filter)
    parsed_successfully = max(0, total_normalized - parse_errors)
    time_range = db.execute(select(func.min(NormalizedLog.generated_time), func.max(NormalizedLog.generated_time))).one()
    latest_ingestion_time = db.scalar(select(func.max(RawLog.imported_at)))
    quality = _quality_aggregate(db)
    parser_error_examples = []
    if parse_errors and total_normalized <= EXACT_JSON_QUALITY_LIMIT:
        parser_error_examples = [
            {
                "raw_log_id": row.raw_log_id,
                "normalized_log_id": row.id,
                "parser_error": row.parsed_json.get("parser_error"),
                "raw_line_excerpt": row.raw_log.raw_line[:240] if row.raw_log else None,
            }
            for row in db.scalars(select(NormalizedLog).where(parser_error_filter).order_by(NormalizedLog.id.desc()).limit(5))
        ]
    return {
        "total_imported_logs": total_raw,
        "parsed_successfully": parsed_successfully,
        "parse_errors": parse_errors,
        "parse_success_rate": round((parsed_successfully / total_raw) * 100, 2) if total_raw else 0.0,
        "missing_timestamp": quality["missing_timestamp"],
        "missing_source_ip": quality["missing_source_ip"],
        "missing_destination_ip": quality["missing_destination_ip"],
        "missing_action": quality["missing_action"],
        "unknown_app_count": quality["unknown_app_count"],
        "duplicate_raw_line_groups": _duplicate_raw_logs_from_runs(db),
        "dataset_time_min": time_range[0],
        "dataset_time_max": time_range[1],
        "latest_ingestion_time": latest_ingestion_time,
        "parser_error_examples": parser_error_examples,
    }


def _anomalous_group(db: Session, column, limit: int = 10) -> list[dict]:
    rows = db.execute(
        select(column, func.count())
        .where(NormalizedLog.is_anomaly.is_(True), column.is_not(None))
        .group_by(column)
        .order_by(desc(func.count()))
        .limit(limit)
    ).all()
    return [{"name": str(name), "count": int(count)} for name, count in rows]


def baseline_drift_report(db: Session) -> dict:
    aggregate = _traffic_aggregate(db)
    total_logs = int(aggregate["total_logs"])
    anomaly_logs = int(aggregate["anomaly_logs"])
    deny_drop_reset_logs = int(aggregate["deny_drop_reset_logs"])
    unknown_app_logs = int(aggregate["unknown_app_logs"])
    scoring_runs = _latest_scoring_runs(db)
    comparison = _run_comparison(scoring_runs)
    return {
        "total_logs": total_logs,
        "unknown_app_count": unknown_app_logs,
        "unknown_app_rate": _anomaly_rate(unknown_app_logs, total_logs),
        "deny_drop_reset_count": deny_drop_reset_logs,
        "deny_drop_reset_rate": _anomaly_rate(deny_drop_reset_logs, total_logs),
        "anomaly_count": anomaly_logs,
        "anomaly_rate": _anomaly_rate(anomaly_logs, total_logs),
        "app_distribution": _count_group(db, NormalizedLog.app),
        "action_distribution": _count_group(db, NormalizedLog.action),
        "top_source_ips": _count_group(db, NormalizedLog.src_ip),
        "top_destination_ports": _count_group(db, NormalizedLog.dst_port),
        "top_destination_ips": _count_group(db, NormalizedLog.dst_ip),
        "run_comparison": comparison,
        "interpretation": comparison.get("interpretation")
        or "Use this snapshot to compare current traffic shape against reviewed baseline and scoring runs.",
    }


def _score_stats(db: Session, anomalous_only: bool = False) -> dict:
    statement = select(
        func.count(NormalizedLog.id),
        func.min(NormalizedLog.anomaly_score),
        func.avg(NormalizedLog.anomaly_score),
        func.max(NormalizedLog.anomaly_score),
    ).where(NormalizedLog.anomaly_score.is_not(None))
    if anomalous_only:
        statement = statement.where(NormalizedLog.is_anomaly.is_(True))
    count, min_score, avg_score, max_score = db.execute(statement).one()
    return {
        "count": int(count or 0),
        "min": None if min_score is None else round(float(min_score), 6),
        "avg": None if avg_score is None else round(float(avg_score), 6),
        "max": None if max_score is None else round(float(max_score), 6),
    }


def _latest_scoring_runs(db: Session, limit: int = 2) -> list[MLModelRun]:
    return list(
        db.scalars(
            select(MLModelRun)
            .where(MLModelRun.operation == "score", MLModelRun.status == "scored")
            .order_by(desc(MLModelRun.created_at), desc(MLModelRun.id))
            .limit(limit)
        )
    )


def _sample_anomalies(db: Session, limit: int = 20) -> list[dict]:
    rows = db.scalars(
        select(NormalizedLog)
        .where(NormalizedLog.is_anomaly.is_(True))
        .order_by(NormalizedLog.anomaly_score.asc(), NormalizedLog.id.desc())
        .limit(limit)
    ).all()
    return [
        {
            "id": log.id,
            "generated_time": log.generated_time,
            "src_ip": log.src_ip,
            "dst_ip": log.dst_ip,
            "app": log.app,
            "action": log.action,
            "protocol": log.protocol,
            "dst_port": log.dst_port,
            "bytes": log.bytes,
            "packets": log.packets,
            "app_risk": log.app_risk,
            "anomaly_score": log.anomaly_score,
        }
        for log in rows
    ]


def _run_comparison(runs: list[MLModelRun]) -> dict:
    latest = runs[0] if runs else None
    previous = runs[1] if len(runs) > 1 else None
    delta = None
    interpretation = "No scored ML runs are available yet."
    if latest and previous and latest.anomaly_rate is not None and previous.anomaly_rate is not None:
        delta = round(float(latest.anomaly_rate - previous.anomaly_rate), 2)
        if abs(delta) < 1:
            interpretation = "Latest anomaly rate is stable compared with the previous scoring run."
        elif delta > 0:
            interpretation = "Latest anomaly rate increased; review whether the model became noisier or the traffic changed."
        else:
            interpretation = "Latest anomaly rate decreased; review whether the model became stricter or traffic normalized."
    elif latest:
        interpretation = "Only one scored ML run is available; compare after another scoring cycle."
    return {
        "latest": run_to_dict(latest) if latest else None,
        "previous": run_to_dict(previous) if previous else None,
        "anomaly_rate_delta": delta,
        "interpretation": interpretation,
    }


def _top_training_values(feature_summary: dict, feature: str) -> set[str]:
    categorical = feature_summary.get("categorical", {}) if isinstance(feature_summary, dict) else {}
    feature_data = categorical.get(feature, {})
    return {str(item.get("value")) for item in feature_data.get("top_values", []) if item.get("value") is not None}


def _top_profile_names(profile: dict, key: str) -> set[str]:
    return {str(item.get("name")) for item in profile.get(key, [])[:8] if item.get("name") is not None}


def _drift_signals(status: dict, profile: dict, run_comparison: dict) -> list[dict]:
    latest_training = status.get("latest_training")
    if not latest_training:
        return [
            {
                "metric": "training_baseline",
                "level": "unknown",
                "training_value": None,
                "current_value": profile.get("total_logs", 0),
                "message": "No successful training baseline is available yet.",
            }
        ]

    signals: list[dict] = []
    feature_summary = latest_training.get("feature_summary") or {}
    training_rows = int(feature_summary.get("row_count") or latest_training.get("training_log_count") or 0)
    current_baseline = int(profile.get("baseline_candidate_count") or 0)
    if training_rows:
        delta_pct = round(((current_baseline - training_rows) / training_rows) * 100, 2)
        if abs(delta_pct) >= 75:
            level = "high"
        elif abs(delta_pct) >= 35:
            level = "medium"
        else:
            level = "low"
        signals.append(
            {
                "metric": "baseline_pool_delta",
                "level": level,
                "training_value": training_rows,
                "current_value": current_baseline,
                "delta_pct": delta_pct,
                "message": "Current baseline candidate volume compared with the latest training set.",
            }
        )

    expected_rate = float(status.get("contamination") or 0) * 100
    current_rate = float(profile.get("current_anomaly_rate") or 0)
    if expected_rate:
        ratio = current_rate / expected_rate
        level = "high" if ratio >= 3 else "medium" if ratio >= 2 else "low"
        signals.append(
            {
                "metric": "anomaly_rate_vs_expected",
                "level": level,
                "training_value": round(expected_rate, 2),
                "current_value": current_rate,
                "message": "Current anomaly rate compared with configured model contamination.",
            }
        )

    for feature, profile_key in [("app", "top_apps"), ("action", "action_distribution"), ("src_zone", "top_src_zones")]:
        training_values = _top_training_values(feature_summary, feature)
        current_values = _top_profile_names(profile, profile_key)
        new_values = sorted(current_values - training_values)
        if training_values and new_values:
            signals.append(
                {
                    "metric": f"{feature}_top_value_shift",
                    "level": "medium" if len(new_values) <= 3 else "high",
                    "training_value": sorted(training_values)[:8],
                    "current_value": sorted(current_values)[:8],
                    "message": f"Current top {feature} values include values not seen in the latest training top list.",
                    "new_values": new_values[:8],
                }
            )

    anomaly_delta = run_comparison.get("anomaly_rate_delta")
    if anomaly_delta is not None and abs(float(anomaly_delta)) >= 2:
        signals.append(
            {
                "metric": "scoring_run_delta",
                "level": "high" if abs(float(anomaly_delta)) >= 5 else "medium",
                "training_value": run_comparison.get("previous", {}).get("anomaly_rate") if run_comparison.get("previous") else None,
                "current_value": run_comparison.get("latest", {}).get("anomaly_rate") if run_comparison.get("latest") else None,
                "message": "Latest scoring anomaly rate moved materially from the previous scoring run.",
            }
        )

    if not signals:
        signals.append(
            {
                "metric": "baseline_drift",
                "level": "low",
                "training_value": training_rows,
                "current_value": current_baseline,
                "message": "No major baseline drift signals were found with the current prototype checks.",
            }
        )
    return signals


def evaluation_report(db: Session) -> dict:
    status = model_status(db)
    profile = dataset_profile(db)
    scoring_runs = _latest_scoring_runs(db)
    run_comparison = _run_comparison(scoring_runs)
    scored_logs = _score_stats(db)["count"]
    anomaly_count = status["current_anomaly_logs"]
    anomaly_rate = status["current_anomaly_rate"]

    recommendations: list[str] = []
    if not status["artifact_exists"]:
        recommendations.append("Train a baseline model before relying on ML-assisted anomaly scoring.")
    if scored_logs == 0:
        recommendations.append("Apply ML scoring after training so anomaly evidence appears in logs and dashboards.")
    if anomaly_rate > 10:
        recommendations.append("Current anomaly rate is high; review baseline filter, contamination setting, and top anomalous apps/IPs.")
    elif 0 < anomaly_rate < 0.5:
        recommendations.append("Current anomaly rate is very low; verify that scoring covered enough logs and the model is not too strict.")
    elif anomaly_count:
        recommendations.append("Review top anomalous sources, apps, and ports before turning findings into response actions.")
    recommendations.extend(profile.get("recommendations", [])[:2])

    return {
        "model_status": status,
        "dataset_profile": profile,
        "data_quality": data_quality_profile(db),
        "scored_log_count": scored_logs,
        "anomaly_count": anomaly_count,
        "anomaly_rate": anomaly_rate,
        "score_stats_all": _score_stats(db),
        "score_stats_anomalies": _score_stats(db, anomalous_only=True),
        "run_comparison": run_comparison,
        "drift_signals": _drift_signals(status, profile, run_comparison),
        "baseline_drift_report": baseline_drift_report(db),
        "top_anomalous_src_ips": _anomalous_group(db, NormalizedLog.src_ip),
        "top_anomalous_dst_ips": _anomalous_group(db, NormalizedLog.dst_ip),
        "top_anomalous_apps": _anomalous_group(db, NormalizedLog.app),
        "top_anomalous_dst_ports": _anomalous_group(db, NormalizedLog.dst_port),
        "top_anomalous_protocols": _anomalous_group(db, NormalizedLog.protocol),
        "sample_anomalies": _sample_anomalies(db),
        "recommendations": list(dict.fromkeys(recommendations)),
    }


def run_to_dict(run: MLModelRun) -> dict:
    return {
        "id": run.id,
        "model_name": run.model_name,
        "model_version": run.model_version,
        "operation": run.operation,
        "status": run.status,
        "actor": run.actor,
        "model_path": run.model_path,
        "artifact_sha256": run.artifact_sha256,
        "artifact_size_bytes": run.artifact_size_bytes,
        "training_log_count": run.training_log_count,
        "scored_log_count": run.scored_log_count,
        "anomaly_count": run.anomaly_count,
        "anomaly_rate": run.anomaly_rate,
        "contamination": run.contamination,
        "feature_columns": run.feature_columns_json,
        "feature_summary": run.feature_summary_json,
        "metrics": run.metrics_json,
        "message": run.message,
        "created_at": run.created_at,
    }
