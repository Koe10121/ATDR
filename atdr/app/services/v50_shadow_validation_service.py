from __future__ import annotations

from collections import Counter
from contextlib import contextmanager
import csv
from datetime import datetime, timedelta, timezone
import gc
import json
import math
import os
from pathlib import Path
import shutil
import time
from typing import Any, Iterator
from unittest.mock import patch
from uuid import uuid4

from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session, joinedload, selectinload

from atdr.app.core.config import PROJECT_ROOT, Settings, get_settings
from atdr.app.db.database import Base
from atdr.app.db.models import (
    Alert,
    AlertEvidence,
    AuditLog,
    DetectionRun,
    IngestionRun,
    LogSource,
    MLLabel,
    MLModelRun,
    NormalizedLog,
    OperationJob,
    RawLog,
    ResponseAction,
)
from atdr.app.detection.attack_mapping import infer_attack_type_from_rules
from atdr.app.detection import v398_independent_holdout_validation as frozen_validation
from atdr.app.detection.explanations import (
    alert_explanation_completeness,
    build_alert_detection_summary,
)
from atdr.app.detection.hybrid_scoring import hybrid_risk_score
from atdr.app.detection.ml_detector import logs_to_records
from atdr.app.detection.rules import build_detection_context, evaluate_rules
from atdr.app.detection.scoring import clamp_score
from atdr.app.detection.supervised_detector import (
    POSITIVE_LABELS,
    supervised_model_path,
    threshold_decision,
)
from atdr.app.detection.v331_noise_reduction import _classes as supervised_classes
from atdr.app.ml.features import FEATURE_COLUMNS, build_feature_rows
from atdr.app.services.assistant_service import answer_assistant_question
from atdr.app.services.case_service import ACTIVE_CASE_STATUSES
from atdr.app.services.detection_service import run_detection
from atdr.app.services.job_service import enqueue_job
from atdr.app.services.operation_worker import run_worker_once
from atdr.app.services.private_log_preflight_service import (
    configured_database_marker,
    preflight_private_paloalto_file,
)
from atdr.app.services.source_service import create_source, source_health, source_quality
from atdr.app.services.staging_service import (
    cleanup_staged_payload,
    stage_upload_for_job,
    staged_payload_fields,
)


DEFAULT_SOURCE_NAME = "real-paloalto-shadow-1"
DEFAULT_OUTPUT_DIR = PROJECT_ROOT / "demo_exports" / "v5_0_shadow_validation"
DEFAULT_REVIEW_SAMPLE = PROJECT_ROOT / "ml_baseline_reviews" / "v5_0_real_log_review_sample.csv"
DEFAULT_ML_SAMPLE_LIMIT = 2_000
DETECTION_WINDOW_MINUTES = 5
HYBRID_QUEUE_THRESHOLD = 50.0
UNKNOWN_APPS = {"", "unknown", "unknown-tcp", "unknown-udp", "unknown-p2p", "incomplete", "not-applicable"}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _stamp() -> str:
    return _now().strftime("%Y%m%dT%H%M%SZ")


def _safe_rate(numerator: int, denominator: int) -> float:
    return round((numerator / denominator) * 100, 4) if denominator else 0.0


def _top(counter: Counter[Any], *, limit: int = 20) -> list[dict[str, Any]]:
    return [
        {"value": str(value), "count": int(count)}
        for value, count in counter.most_common(limit)
    ]


def _quantiles(values: list[float]) -> dict[str, float | int | None]:
    if not values:
        return {
            "count": 0,
            "minimum": None,
            "p25": None,
            "median": None,
            "p75": None,
            "p95": None,
            "maximum": None,
        }
    ordered = sorted(float(value) for value in values)

    def percentile(fraction: float) -> float:
        position = (len(ordered) - 1) * fraction
        lower = math.floor(position)
        upper = math.ceil(position)
        if lower == upper:
            return ordered[lower]
        weight = position - lower
        return ordered[lower] * (1 - weight) + ordered[upper] * weight

    return {
        "count": len(ordered),
        "minimum": round(ordered[0], 6),
        "p25": round(percentile(0.25), 6),
        "median": round(percentile(0.5), 6),
        "p75": round(percentile(0.75), 6),
        "p95": round(percentile(0.95), 6),
        "maximum": round(ordered[-1], 6),
    }


def _artifact_marker(path: Path) -> tuple[int, int] | None:
    if not path.exists():
        return None
    stat = path.stat()
    return int(stat.st_size), int(stat.st_mtime_ns)


@contextmanager
def _shadow_runtime_settings(
    staging_root: Path,
    *,
    input_size_bytes: int,
    chunk_size: int,
) -> Iterator[Settings]:
    storage_limit = max(input_size_bytes + (256 * 1024 * 1024), input_size_bytes * 2)
    values = {
        "OPERATION_STAGING_ROOT": str(staging_root.resolve()),
        "OPERATION_STAGING_MIN_FREE_BYTES": "0",
        "OPERATION_STAGING_MAX_TOTAL_BYTES": str(storage_limit),
        "OPERATION_JOB_MAX_INPUT_BYTES": str(input_size_bytes + (64 * 1024 * 1024)),
        "OPERATION_STAGING_STORAGE_ID": "v50-shadow-temp",
        "INGESTION_CHUNK_SIZE": str(max(1, chunk_size)),
        "INGESTION_PROGRESS_UPDATE_INTERVAL": str(max(1, chunk_size)),
        "OPERATION_WORKER_LEASE_SECONDS": "3600",
        "RESPONSE_SIMULATION": "true",
        "RESPONSE_PROVIDER": "simulation",
        "ASSISTANT_LLM_ENABLED": "false",
        "ASSISTANT_LLM_PROVIDER": "disabled",
        "ASSISTANT_ALLOW_RAW_LOG_CONTEXT": "false",
        "ASSISTANT_REDACT_IPS": "true",
    }
    with patch.dict(os.environ, values, clear=False):
        get_settings.cache_clear()
        try:
            yield get_settings()
        finally:
            get_settings.cache_clear()


def _enqueue_shadow_import(
    db: Session,
    *,
    staged: Any,
    source_id: int,
    line_limit: int | None,
) -> OperationJob:
    target = staged.available_lines if line_limit is None else min(staged.available_lines, max(0, int(line_limit)))
    payload = {
        **staged_payload_fields(staged),
        "input_name": "real-paloalto-shadow.log",
        "input_bytes": staged.byte_count,
        "input_fingerprint": staged.fingerprint,
        "available_lines": staged.available_lines,
        "source_type": "firewall",
        "parser_profile": "palo_alto",
        "limit": line_limit,
        "source_id": source_id,
    }
    job, _created = enqueue_job(
        db,
        job_type="import_logs",
        requested_by="v5.0-shadow-validator",
        payload=payload,
        details={
            "input_name": "real-paloalto-shadow.log",
            "available_lines": staged.available_lines,
            "parser_profile": "palo_alto",
            "source_id": source_id,
            "validation_scope": "disposable_shadow_sqlite",
            "private_path_stored": False,
        },
        progress_total=target,
        input_size_bytes=staged.byte_count,
        input_fingerprint=staged.fingerprint,
        resume_expires_at=_now() + timedelta(hours=2),
        staging_storage_id=staged.storage_id,
    )
    return job


def _normalized_quality(db: Session, source_id: int) -> dict[str, Any]:
    rows = db.scalars(
        select(NormalizedLog)
        .join(RawLog, RawLog.id == NormalizedLog.raw_log_id)
        .where(RawLog.source_id == source_id)
        .execution_options(yield_per=5_000)
    )
    total = 0
    missing = Counter()
    log_types = Counter()
    subtypes = Counter()
    field_counts = Counter()
    parser_warnings = Counter()
    actions = Counter()
    apps = Counter()
    destination_ports = Counter()
    app_risks = Counter()
    threat_severities = Counter()
    unknown_apps = 0
    parser_errors = 0
    for row in rows:
        total += 1
        parsed = row.parsed_json if isinstance(row.parsed_json, dict) else {}
        log_type = str(row.log_type or "missing").upper()
        log_types[log_type] += 1
        subtypes[str(row.subtype or "missing").lower()] += 1
        field_counts[(log_type, int(parsed.get("field_count") or 0))] += 1
        parser_warnings.update(str(item) for item in parsed.get("parser_warnings", []))
        parser_errors += int(bool(parsed.get("parser_error")))
        if row.action:
            actions[str(row.action).lower()] += 1
        if row.app:
            apps[str(row.app).lower()] += 1
        if row.dst_port is not None:
            destination_ports[int(row.dst_port)] += 1
        if row.app_risk is not None:
            app_risks[int(row.app_risk)] += 1
        if parsed.get("parsed_threat_severity"):
            threat_severities[str(parsed["parsed_threat_severity"]).lower()] += 1
        if str(row.app or "").strip().lower() in UNKNOWN_APPS:
            unknown_apps += 1
        for field in (
            "generated_time",
            "src_ip",
            "dst_ip",
            "src_port",
            "dst_port",
            "action",
            "app",
            "src_zone",
            "dst_zone",
            "bytes",
            "packets",
            "app_risk",
        ):
            value = getattr(row, field)
            if value is None or (isinstance(value, str) and not value.strip()):
                missing[field] += 1
    return {
        "normalized_rows": total,
        "parser_error_rows": parser_errors,
        "parser_error_rate_percent": _safe_rate(parser_errors, total),
        "unknown_app_rows": unknown_apps,
        "unknown_app_rate_percent": _safe_rate(unknown_apps, total),
        "log_types": _top(log_types),
        "subtypes": _top(subtypes),
        "schema_variants": [
            {"log_type": log_type, "field_count": field_count, "count": count}
            for (log_type, field_count), count in sorted(field_counts.items())
        ],
        "missing_fields": {key: int(value) for key, value in sorted(missing.items())},
        "parser_warnings": _top(parser_warnings),
        "safe_aggregates": {
            "actions": _top(actions),
            "applications": _top(apps),
            "destination_ports": _top(destination_ports),
            "application_risks": _top(app_risks),
            "threat_severities": _top(threat_severities),
        },
        "raw_evidence_returned": False,
        "private_identifiers_returned": False,
    }


def _group_metadata(alert: Alert) -> dict[str, Any]:
    return next(
        (
            item
            for item in (alert.matched_rules_json or [])
            if isinstance(item, dict) and item.get("code") == "group_metadata"
        ),
        {},
    )


def _alert_noise_audit(db: Session, source_id: int) -> dict[str, Any]:
    alerts = list(
        db.scalars(
            select(Alert)
            .where(
                Alert.id.in_(
                    select(AlertEvidence.alert_id)
                    .join(NormalizedLog, NormalizedLog.id == AlertEvidence.normalized_log_id)
                    .join(RawLog, RawLog.id == NormalizedLog.raw_log_id)
                    .where(RawLog.source_id == source_id)
                )
            )
            .order_by(Alert.id)
        )
    )
    alert_ids = [int(alert.id) for alert in alerts if alert.id is not None]
    evidence_counts: dict[int, int] = {}
    primary_log_ids: dict[int, int] = {}
    if alert_ids:
        evidence_rows = db.execute(
            select(
                AlertEvidence.alert_id,
                func.count(AlertEvidence.id),
                func.min(AlertEvidence.normalized_log_id),
            )
            .where(AlertEvidence.alert_id.in_(alert_ids))
            .group_by(AlertEvidence.alert_id)
        ).all()
        evidence_counts = {
            int(alert_id): int(count)
            for alert_id, count, _primary_log_id in evidence_rows
        }
        primary_log_ids = {
            int(alert_id): int(primary_log_id)
            for alert_id, _count, primary_log_id in evidence_rows
            if primary_log_id is not None
        }
    primary_logs = {
        int(log.id): log
        for log in db.scalars(
            select(NormalizedLog).where(
                NormalizedLog.id.in_(set(primary_log_ids.values()))
            )
        )
    }
    alert_types = Counter()
    attack_types = Counter()
    severities = Counter()
    confidences = Counter()
    event_windows = Counter()
    safe_patterns = Counter()
    completeness_scores: list[float] = []
    occurrence_total = 0
    related_log_total = 0
    case_keys: set[tuple[str, str, str, datetime]] = set()
    for alert in alerts:
        alert_types[alert.alert_type] += 1
        attack_types[infer_attack_type_from_rules(alert.matched_rules_json or [])] += 1
        severities[alert.severity] += 1
        rules = [
            item
            for item in (alert.matched_rules_json or [])
            if isinstance(item, dict) and item.get("code") != "group_metadata"
        ]
        confidences.update(str(item.get("confidence") or "unknown") for item in rules)
        metadata = _group_metadata(alert)
        evidence_count = evidence_counts.get(int(alert.id), 0)
        occurrence_total += int(
            metadata.get("occurrence_count")
            or metadata.get("evidence_count")
            or evidence_count
        )
        related_log_total += int(
            metadata.get("related_log_count")
            or metadata.get("evidence_count")
            or evidence_count
        )
        completeness_scores.append(
            float(
                alert_explanation_completeness(
                    alert,
                    {"evidence_count": evidence_count},
                )["score"]
            )
        )
        primary_log = primary_logs.get(primary_log_ids.get(int(alert.id), -1))
        if primary_log is not None:
            event_time = (
                primary_log.generated_time
                or primary_log.receive_time
                or primary_log.high_res_timestamp
            )
            if event_time is not None:
                event_windows[event_time.replace(second=0, microsecond=0).isoformat()] += 1
            safe_patterns[
                (
                    alert.alert_type,
                    str(primary_log.app or "missing").lower(),
                    str(primary_log.action or "missing").lower(),
                    int(primary_log.dst_port) if primary_log.dst_port is not None else -1,
                )
            ] += 1
        if alert.status in ACTIVE_CASE_STATUSES:
            created_at = alert.created_at
            if created_at.tzinfo is None:
                created_at = created_at.replace(tzinfo=timezone.utc)
            else:
                created_at = created_at.astimezone(timezone.utc)
            case_keys.add(
                (
                    alert.src_ip or "unknown-source",
                    alert.dst_ip or "any-destination",
                    infer_attack_type_from_rules(alert.matched_rules_json or []),
                    created_at.replace(hour=0, minute=0, second=0, microsecond=0),
                )
            )
    return {
        "alerts": len(alerts),
        "computed_cases": len(case_keys),
        "by_alert_type": _top(alert_types),
        "by_attack_type": _top(attack_types),
        "by_severity": _top(severities),
        "rule_confidence_mentions": _top(confidences),
        "top_event_windows": _top(event_windows, limit=10),
        "top_safe_noise_patterns": [
            {
                "alert_type": key[0],
                "application": key[1],
                "action": key[2],
                "destination_port": None if key[3] == -1 else key[3],
                "count": int(count),
            }
            for key, count in safe_patterns.most_common(20)
        ],
        "deduplication": {
            "occurrence_count_total": occurrence_total,
            "related_log_count_total": related_log_total,
            "occurrences_collapsed": max(0, occurrence_total - len(alerts)),
            "grouped_related_logs_beyond_first": max(
                0, related_log_total - len(alerts)
            ),
            "reobserved_occurrences": max(0, occurrence_total - related_log_total),
            "occurrence_to_alert_ratio": round(occurrence_total / len(alerts), 4)
            if alerts
            else 0.0,
            "collapse_rate_percent": _safe_rate(
                max(0, occurrence_total - len(alerts)), occurrence_total
            ),
        },
        "explanation_completeness": {
            "alerts_checked": len(completeness_scores),
            "average_score": round(sum(completeness_scores) / len(completeness_scores), 4)
            if completeness_scores
            else 0.0,
            "complete_alerts": sum(1 for score in completeness_scores if score >= 1.0),
        },
        "ground_truth_available": False,
        "false_positive_rate_reported": False,
        "precision_recall_reported": False,
        "claim_boundary": "Noise patterns are triage-volume observations, not false-positive labels.",
    }


def _source_log_sample(
    db: Session,
    source_id: int,
    *,
    limit: int,
) -> tuple[int, list[NormalizedLog]]:
    source_ids = set(db.scalars(select(LogSource.id)))
    source_isolated_database = source_ids == {source_id}
    count_statement = select(
        func.min(NormalizedLog.id),
        func.max(NormalizedLog.id),
        func.count(NormalizedLog.id),
    )
    if not source_isolated_database:
        count_statement = (
            count_statement.join(RawLog, RawLog.id == NormalizedLog.raw_log_id)
            .where(RawLog.source_id == source_id)
        )
    minimum_id, maximum_id, row_count = db.execute(count_statement).one()
    full_count = int(row_count or 0)
    if not full_count or minimum_id is None or maximum_id is None:
        return 0, []
    sample_size = min(full_count, max(1, int(limit)))
    if sample_size == full_count:
        statement = select(NormalizedLog)
        if not source_isolated_database:
            statement = (
                statement.join(RawLog, RawLog.id == NormalizedLog.raw_log_id)
                .where(RawLog.source_id == source_id)
            )
        statement = statement.options(joinedload(NormalizedLog.raw_log)).order_by(
            NormalizedLog.id
        )
    else:
        span = int(maximum_id) - int(minimum_id)
        target_ids = (
            {int(maximum_id)}
            if sample_size == 1
            else {
                int(minimum_id) + round(index * span / (sample_size - 1))
                for index in range(sample_size)
            }
        )
        statement = select(NormalizedLog).where(NormalizedLog.id.in_(target_ids))
        if not source_isolated_database:
            statement = (
                statement.join(RawLog, RawLog.id == NormalizedLog.raw_log_id)
                .where(RawLog.source_id == source_id)
            )
        statement = statement.options(joinedload(NormalizedLog.raw_log)).order_by(
            NormalizedLog.id
        )
    return full_count, list(db.scalars(statement))


def _isolation_sample(
    logs: list[NormalizedLog],
    *,
    settings: Settings,
) -> tuple[dict[str, Any], dict[int, dict[str, Any]]]:
    model_path = settings.resolved_model_path
    if not model_path.exists() or not logs:
        return (
            {
                "status": "active_artifact_unavailable",
                "sample_rows": len(logs),
                "queue_rows": 0,
                "active_artifact_written": False,
            },
            {},
        )
    try:
        import joblib
        import pandas as pd

        model = joblib.load(model_path)
        frame = pd.DataFrame(logs_to_records(logs))
        ids = [int(value) for value in frame.pop("id").tolist()]
        labels = model.predict(frame)
        scores = model.decision_function(frame)
        rows = {
            log_id: {
                "is_anomaly": bool(label == -1),
                "anomaly_score": float(score),
            }
            for log_id, label, score in zip(ids, labels, scores, strict=False)
        }
        queue_rows = sum(1 for row in rows.values() if row["is_anomaly"])
        return (
            {
                "status": "scored_with_existing_active_artifact",
                "sample_rows": len(rows),
                "queue_rows": queue_rows,
                "queue_rate_percent": _safe_rate(queue_rows, len(rows)),
                "score_distribution": _quantiles(
                    [float(row["anomaly_score"]) for row in rows.values()]
                ),
                "active_artifact_written": False,
            },
            rows,
        )
    except Exception as exc:
        return (
            {
                "status": "active_artifact_incompatible_or_unavailable",
                "error_type": exc.__class__.__name__,
                "sample_rows": len(logs),
                "queue_rows": 0,
                "active_artifact_written": False,
            },
            {},
        )


def _supervised_sample(
    db: Session,
    logs: list[NormalizedLog],
    *,
    governed_artifact_path: Path | None = None,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    path = governed_artifact_path or supervised_model_path()
    if not path.exists() or not logs:
        return (
            {
                "status": "active_artifact_unavailable",
                "sample_rows": len(logs),
                "queue_rows": 0,
                "queue_rate_percent": 0.0,
                "active_artifact_written": False,
            },
            [],
        )
    try:
        import joblib
        import pandas as pd

        artifact = joblib.load(path)
        if isinstance(artifact, dict) and str(artifact.get("schema_version") or "").startswith("v5.1-"):
            model = artifact.get("model")
            if model is None:
                raise ValueError("Governed supervised artifact has no model.")
            feature_rows = build_feature_rows(db, logs)
            frame, _feature_meta = frozen_validation._local_evidence_frame(pd.DataFrame(feature_rows), logs)
            classes = supervised_classes(model)
            positive_class = str(artifact.get("positive_class") or "needs_review")
            if positive_class not in classes:
                raise ValueError("Governed supervised artifact has no review-queue probability.")
            positive_index = classes.index(positive_class)
            probabilities = model.predict_proba(frame)
            threshold = float(artifact.get("threshold", 0.5))
            expected_columns = [
                *(artifact.get("feature_schema") or {}).get("numeric", []),
                *(artifact.get("feature_schema") or {}).get("categorical", []),
            ]
            missing_counts = Counter()
            for column in expected_columns:
                if column not in frame.columns:
                    missing_counts[column] = len(frame)
                else:
                    missing_counts[column] = int(frame[column].isna().sum())
            rows = []
            queue_scores = []
            decisions = Counter()
            for index, log in enumerate(logs):
                queue_probability = float(probabilities[index][positive_index])
                decision = "needs_review" if queue_probability >= threshold else "benign_like"
                decisions[decision] += 1
                queue_scores.append(queue_probability)
                rows.append(
                    {
                        "log_id": int(log.id),
                        "predicted_label": decision,
                        "direct_predicted_label": decision,
                        "threat_probability": queue_probability,
                        "queue_probability": queue_probability,
                        "threshold": threshold,
                        "model_version": artifact.get("model_version"),
                        "lifecycle_state": "shadow_observation",
                        "used_for_hybrid": False,
                    }
                )
            queue_rows = sum(1 for row in rows if row["predicted_label"] == "needs_review")
            return (
                {
                    "status": "scored_with_governed_shadow_artifact",
                    "model_version": artifact.get("model_version"),
                    "model_type": artifact.get("model_type"),
                    "feature_set_version": artifact.get("feature_set_version"),
                    "sample_rows": len(rows),
                    "queue_rows": queue_rows,
                    "queue_rate_percent": _safe_rate(queue_rows, len(rows)),
                    "predicted_labels": _top(decisions),
                    "threat_probability_distribution": _quantiles(queue_scores),
                    "threshold": threshold,
                    "calibration_method": artifact.get("calibration_method"),
                    "feature_columns_expected": len(expected_columns),
                    "feature_missingness_top": [
                        {
                            "feature": feature,
                            "missing_rows": int(count),
                            "missing_rate_percent": _safe_rate(int(count), len(rows)),
                        }
                        for feature, count in missing_counts.most_common(15)
                    ],
                    "decision_support_only": True,
                    "shadow_observation_only": True,
                    "used_for_alert_creation": False,
                    "used_for_hybrid": False,
                    "active_artifact_written": False,
                    "accuracy_metrics_reported": False,
                },
                rows,
            )
        pipeline = artifact.get("pipeline") if isinstance(artifact, dict) else artifact
        threshold_profile = (
            str(artifact.get("threshold_profile") or "balanced")
            if isinstance(artifact, dict)
            else "balanced"
        )
        if pipeline is None:
            raise ValueError("Supervised artifact has no pipeline.")
        feature_rows = build_feature_rows(db, logs)
        frame = pd.DataFrame(feature_rows)
        direct_predictions = [str(value) for value in pipeline.predict(frame)]
        model = getattr(pipeline, "named_steps", {}).get("model")
        classes = [str(value) for value in getattr(model, "classes_", [])]
        raw_probabilities = (
            pipeline.predict_proba(frame) if hasattr(pipeline, "predict_proba") else []
        )
        rows: list[dict[str, Any]] = []
        threat_probabilities: list[float] = []
        confidences: list[float] = []
        predicted_labels = Counter()
        missing_counts = Counter()
        for feature_row in feature_rows:
            for column in FEATURE_COLUMNS:
                value = feature_row.get(column)
                if value is None or (isinstance(value, float) and math.isnan(value)):
                    missing_counts[column] += 1
        for index, log in enumerate(logs):
            class_probabilities = (
                {
                    label: float(probability)
                    for label, probability in zip(
                        classes,
                        raw_probabilities[index],
                        strict=False,
                    )
                }
                if len(raw_probabilities)
                else {}
            )
            direct = direct_predictions[index]
            predicted = (
                threshold_decision(class_probabilities, profile=threshold_profile)
                if class_probabilities
                else direct
            )
            threat_probability = sum(
                class_probabilities.get(label, 0.0) for label in POSITIVE_LABELS
            )
            confidence = max(class_probabilities.values()) if class_probabilities else 0.0
            predicted_labels[predicted] += 1
            threat_probabilities.append(float(threat_probability))
            confidences.append(float(confidence))
            rows.append(
                {
                    "log_id": int(log.id),
                    "predicted_label": predicted,
                    "direct_predicted_label": direct,
                    "threat_probability": float(threat_probability),
                    "confidence": float(confidence),
                }
            )
        queue_rows = sum(
            1 for row in rows if row["predicted_label"] in POSITIVE_LABELS
        )
        return (
            {
                "status": "scored_with_existing_active_artifact",
                "sample_rows": len(rows),
                "queue_rows": queue_rows,
                "queue_rate_percent": _safe_rate(queue_rows, len(rows)),
                "predicted_labels": _top(predicted_labels),
                "threat_probability_distribution": _quantiles(threat_probabilities),
                "confidence_distribution": _quantiles(confidences),
                "threshold_profile": threshold_profile,
                "feature_columns_expected": len(FEATURE_COLUMNS),
                "feature_missingness_top": [
                    {
                        "feature": feature,
                        "missing_rows": int(count),
                        "missing_rate_percent": _safe_rate(int(count), len(rows)),
                    }
                    for feature, count in missing_counts.most_common(15)
                ],
                "decision_support_only": True,
                "active_artifact_written": False,
                "accuracy_metrics_reported": False,
            },
            rows,
        )
    except Exception as exc:
        return (
            {
                "status": "active_artifact_incompatible_or_unavailable",
                "error_type": exc.__class__.__name__,
                "sample_rows": len(logs),
                "queue_rows": 0,
                "active_artifact_written": False,
                "accuracy_metrics_reported": False,
            },
            [],
        )


def _ml_queue_diagnostics(
    db: Session,
    source_id: int,
    *,
    sample_limit: int,
    settings: Settings,
    exact_rule_queue_rows: int | None = None,
    governed_artifact_path: Path | None = None,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    started = time.perf_counter()
    full_count, sample = _source_log_sample(
        db,
        source_id,
        limit=max(1, sample_limit),
    )
    isolation_started = time.perf_counter()
    isolation_public, isolation_rows = _isolation_sample(sample, settings=settings)
    isolation_seconds = time.perf_counter() - isolation_started

    context_started = time.perf_counter()
    context = build_detection_context(sample)
    rule_scores: dict[int, float] = {}
    rule_codes: dict[int, list[str]] = {}
    for log in sample:
        matches = [
            item for item in evaluate_rules(log, context) if item.code != "ml_anomaly_detected"
        ]
        rule_scores[int(log.id)] = float(clamp_score(sum(item.score for item in matches)))
        rule_codes[int(log.id)] = [item.code for item in matches]
    context_seconds = time.perf_counter() - context_started

    supervised_started = time.perf_counter()
    supervised_public, supervised_rows = _supervised_sample(
        db,
        sample,
        governed_artifact_path=governed_artifact_path,
    )
    supervised_seconds = time.perf_counter() - supervised_started
    supervised_by_id = {int(row["log_id"]): row for row in supervised_rows}

    sample_rows: list[dict[str, Any]] = []
    hybrid_scores: list[float] = []
    rule_queue_count = 0
    anomaly_sample_count = 0
    supervised_queue_count = 0
    hybrid_queue_count = 0
    rule_supervised_disagreements = 0
    rule_anomaly_disagreements = 0
    for log in sample:
        log_id = int(log.id)
        rule_score = float(rule_scores.get(log_id, 0.0))
        rule_queue = rule_score >= float(settings.min_alert_score)
        isolation = isolation_rows.get(log_id, {})
        anomaly_queue = bool(isolation.get("is_anomaly", False))
        supervised = supervised_by_id.get(log_id, {})
        supervised_queue = supervised.get("predicted_label") in {*POSITIVE_LABELS, "needs_review"}
        hybrid = hybrid_risk_score(
            rule_score=rule_score,
            isolation_anomaly_score=isolation.get("anomaly_score"),
            isolation_is_anomaly=anomaly_queue,
            supervised_malicious_probability=(
                float(supervised.get("threat_probability") or 0.0)
                if supervised.get("used_for_hybrid", True)
                else 0.0
            ),
        )
        hybrid_score = float(hybrid["final_risk_score"])
        hybrid_queue = hybrid_score >= HYBRID_QUEUE_THRESHOLD
        hybrid_scores.append(hybrid_score)
        rule_queue_count += int(rule_queue)
        anomaly_sample_count += int(anomaly_queue)
        supervised_queue_count += int(supervised_queue)
        hybrid_queue_count += int(hybrid_queue)
        rule_supervised_disagreements += int(rule_queue != supervised_queue)
        rule_anomaly_disagreements += int(rule_queue != anomaly_queue)
        sample_rows.append(
            {
                "log_id": log_id,
                "rule_score": rule_score,
                "rule_codes": rule_codes.get(log_id, []),
                "rule_queue": rule_queue,
                "isolation_is_anomaly": anomaly_queue,
                "isolation_score": isolation.get("anomaly_score"),
                "supervised_predicted_label": supervised.get("predicted_label"),
                "supervised_threat_probability": supervised.get(
                    "threat_probability", 0.0
                ),
                "supervised_confidence": supervised.get("confidence", 0.0),
                "supervised_queue": supervised_queue,
                "hybrid_score": hybrid_score,
                "hybrid_queue": hybrid_queue,
            }
        )

    sample_count = len(sample_rows)

    def estimate(sample_queue_count: int) -> int:
        return round((sample_queue_count / sample_count) * full_count) if sample_count else 0

    public = {
        "scope": "diagnostic_shadow_only",
        "ground_truth_available": False,
        "accuracy_metrics_reported": False,
        "full_rows": full_count,
        "sample_policy": "deterministic even time-ordered sample",
        "sample_rows": sample_count,
        "sample_coverage_percent": _safe_rate(sample_count, full_count),
        "rule_only": {
            "sample_queue_rows": rule_queue_count,
            "sample_queue_rate_percent": _safe_rate(rule_queue_count, sample_count),
            "exact_detection_candidate_rows": exact_rule_queue_rows,
            "estimated_full_queue_rows_from_sample": estimate(rule_queue_count),
            "threshold": float(settings.min_alert_score),
            "estimate_not_accuracy_metric": True,
        },
        "isolation_forest": {
            **isolation_public,
            "estimated_full_queue_rows": estimate(
                int(isolation_public.get("queue_rows") or 0)
            ),
            "estimate_not_accuracy_metric": True,
        },
        "supervised_queue": {
            **supervised_public,
            "estimated_full_queue_rows": estimate(supervised_queue_count),
            "estimate_not_accuracy_metric": True,
        },
        "hybrid_queue": {
            "sample_queue_rows": hybrid_queue_count,
            "sample_queue_rate_percent": _safe_rate(hybrid_queue_count, sample_count),
            "estimated_full_queue_rows": estimate(hybrid_queue_count),
            "threshold": HYBRID_QUEUE_THRESHOLD,
            "score_distribution": _quantiles(hybrid_scores),
            "estimate_not_accuracy_metric": True,
        },
        "disagreements": {
            "rule_vs_supervised": rule_supervised_disagreements,
            "rule_vs_anomaly": rule_anomaly_disagreements,
            "sample_rows": sample_count,
        },
        "latency_seconds": {
            "isolation_forest": round(isolation_seconds, 4),
            "rule_context_and_sample_scores": round(context_seconds, 4),
            "supervised_sample": round(supervised_seconds, 4),
            "total": round(time.perf_counter() - started, 4),
        },
        "decision_support_only": True,
        "model_activated": False,
        "model_promoted": False,
        "active_artifact_written": False,
    }
    return public, sample_rows


def _review_priority(row: dict[str, Any], log: NormalizedLog) -> tuple[int, str]:
    parsed = log.parsed_json if isinstance(log.parsed_json, dict) else {}
    parser_limited = bool(parsed.get("parser_error") or parsed.get("parser_warnings"))
    if row["rule_queue"] != row["supervised_queue"]:
        return 100, "rule_supervised_disagreement"
    if row["isolation_is_anomaly"] and not row["rule_queue"]:
        return 90, "anomaly_without_rule_queue"
    if row["supervised_queue"] and not row["rule_queue"]:
        return 85, "supervised_threat_without_rule_queue"
    if parser_limited:
        return 75, "parser_limited_context"
    if set(row["rule_codes"]) & {
        "unknown_or_incomplete_app",
        "app_risk_4",
        "app_risk_5",
        "deny_drop_action",
    }:
        return 65, "potential_rule_noise_pattern"
    if row["hybrid_queue"]:
        return 50, "hybrid_queue_boundary"
    return 0, "low_priority"


def _write_review_sample(
    db: Session,
    sample_rows: list[dict[str, Any]],
    *,
    output_path: Path,
    maximum_rows: int = 200,
) -> dict[str, Any]:
    if not sample_rows:
        return {
            "status": "not_generated_no_diagnostic_rows",
            "rows": 0,
            "import_ready": False,
        }
    log_ids = [int(row["log_id"]) for row in sample_rows]
    logs = {
        int(log.id): log
        for log in db.scalars(
            select(NormalizedLog)
            .where(NormalizedLog.id.in_(log_ids))
            .order_by(NormalizedLog.id)
        )
    }
    ranked = []
    for row in sample_rows:
        log = logs.get(int(row["log_id"]))
        if log is None:
            continue
        priority, reason = _review_priority(row, log)
        if priority:
            ranked.append((priority, float(row.get("hybrid_score") or 0.0), reason, row, log))
    ranked.sort(key=lambda item: (item[0], item[1]), reverse=True)
    selected = ranked[: max(0, min(int(maximum_rows), 200))]
    if not selected:
        return {
            "status": "not_generated_no_useful_boundary_rows",
            "rows": 0,
            "import_ready": False,
        }

    src_aliases: dict[str, str] = {}
    dst_aliases: dict[str, str] = {}

    def alias(mapping: dict[str, str], value: str | None, prefix: str) -> str:
        key = str(value or "missing")
        mapping.setdefault(key, f"{prefix}-{len(mapping) + 1:04d}")
        return mapping[key]

    fieldnames = [
        "shadow_log_id",
        "source_alias",
        "destination_alias",
        "log_type",
        "subtype",
        "application",
        "action",
        "protocol",
        "destination_port",
        "app_risk",
        "rule_codes",
        "rule_score",
        "isolation_is_anomaly",
        "isolation_score",
        "supervised_predicted_label",
        "supervised_threat_probability",
        "supervised_confidence",
        "hybrid_score",
        "review_reason",
        "codex_suggested_decision",
        "codex_reason",
        "label_source",
        "reviewed",
        "human_review_decision",
        "human_attack_type",
        "human_review_notes",
        "human_must_confirm",
        "import_ready",
    ]
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for _priority, _hybrid, reason, row, log in selected:
            suggested = "needs_context"
            if log.log_type == "THREAT" and row["rule_queue"]:
                suggested = "suspicious"
            writer.writerow(
                {
                    "shadow_log_id": int(log.id),
                    "source_alias": alias(src_aliases, log.src_ip, "src"),
                    "destination_alias": alias(dst_aliases, log.dst_ip, "dst"),
                    "log_type": log.log_type or "",
                    "subtype": log.subtype or "",
                    "application": log.app or "",
                    "action": log.action or "",
                    "protocol": log.protocol or "",
                    "destination_port": log.dst_port if log.dst_port is not None else "",
                    "app_risk": log.app_risk if log.app_risk is not None else "",
                    "rule_codes": "|".join(row["rule_codes"]),
                    "rule_score": row["rule_score"],
                    "isolation_is_anomaly": str(bool(row["isolation_is_anomaly"])).lower(),
                    "isolation_score": row["isolation_score"],
                    "supervised_predicted_label": row["supervised_predicted_label"] or "",
                    "supervised_threat_probability": round(float(row["supervised_threat_probability"] or 0), 6),
                    "supervised_confidence": round(float(row["supervised_confidence"] or 0), 6),
                    "hybrid_score": row["hybrid_score"],
                    "review_reason": reason,
                    "codex_suggested_decision": suggested,
                    "codex_reason": "AI-assisted triage suggestion based on redacted rule/model disagreement; human confirmation is required.",
                    "label_source": "ai_assisted",
                    "reviewed": "false",
                    "human_review_decision": "",
                    "human_attack_type": "",
                    "human_review_notes": "",
                    "human_must_confirm": "true",
                    "import_ready": "false",
                }
            )
    return {
        "status": "generated_ai_assisted_unreviewed",
        "rows": len(selected),
        "file_name": output_path.name,
        "redacted_identifiers": True,
        "raw_logs_included": False,
        "label_source": "ai_assisted",
        "reviewed": False,
        "human_decision_fields_blank": True,
        "import_ready": False,
        "automatically_imported": False,
    }


def _floor_detection_window(value: datetime) -> datetime:
    minute = (value.minute // DETECTION_WINDOW_MINUTES) * DETECTION_WINDOW_MINUTES
    return value.replace(minute=minute, second=0, microsecond=0)


def _run_windowed_source_detection(
    db: Session,
    *,
    source_id: int,
    source_name: str,
    source_type: str,
) -> dict[str, Any]:
    minimum_time, maximum_time, missing_time_rows = db.execute(
        select(
            func.min(NormalizedLog.generated_time),
            func.max(NormalizedLog.generated_time),
            func.count(NormalizedLog.id).filter(NormalizedLog.generated_time.is_(None)),
        )
        .join(RawLog, RawLog.id == NormalizedLog.raw_log_id)
        .where(RawLog.source_id == source_id)
    ).one()
    if minimum_time is None or maximum_time is None:
        return {
            "evaluated": 0,
            "candidate_logs": 0,
            "created_alerts": 0,
            "deduplicated_alert_updates": 0,
            "suppressed_low_groups": 0,
            "suppressed_by_rules": 0,
            "watchlist_matches": 0,
            "top_attack_types": [],
            "window_count": 0,
            "logs_without_generated_time": int(missing_time_rows or 0),
            "source_scoped": True,
            "windowed_for_bounded_memory": True,
        }

    current = _floor_detection_window(minimum_time)
    last = _floor_detection_window(maximum_time)
    totals: Counter[str] = Counter()
    attack_types: Counter[str] = Counter()
    windows: list[dict[str, Any]] = []
    dedup_alert_cache: list[Alert] = []
    dedup_evidence_id_cache: dict[int, set[int]] = {}
    while current <= last:
        end = current + timedelta(minutes=DETECTION_WINDOW_MINUTES)
        result = run_detection(
            db,
            limit=None,
            use_ml=False,
            actor="v5.0-shadow-validator",
            source_id=source_id,
            source_name=source_name,
            source_type=source_type,
            event_time_start=current,
            event_time_end=end,
            dedup_alert_cache=dedup_alert_cache,
            dedup_evidence_id_cache=dedup_evidence_id_cache,
        )
        for key in (
            "evaluated",
            "candidate_logs",
            "created_alerts",
            "deduplicated_alert_updates",
            "suppressed_low_groups",
            "suppressed_by_rules",
            "watchlist_matches",
        ):
            totals[key] += int(result.get(key) or 0)
        for item in result.get("top_attack_types") or []:
            attack_types[str(item.get("name") or "unknown_anomaly")] += int(
                item.get("count") or 0
            )
        windows.append(
            {
                "start": current.isoformat(),
                "end_exclusive": end.isoformat(),
                "evaluated": int(result.get("evaluated") or 0),
                "candidate_logs": int(result.get("candidate_logs") or 0),
                "created_alerts": int(result.get("created_alerts") or 0),
                "deduplicated_alert_updates": int(
                    result.get("deduplicated_alert_updates") or 0
                ),
                "detection_run_id": result.get("detection_run_id"),
            }
        )
        gc.collect()
        current = end

    return {
        **{key: int(value) for key, value in totals.items()},
        "top_attack_types": [
            {"name": name, "count": int(count)}
            for name, count in attack_types.most_common(10)
        ],
        "window_count": len(windows),
        "window_minutes": DETECTION_WINDOW_MINUTES,
        "windows": windows,
        "logs_without_generated_time": int(missing_time_rows or 0),
        "source_scoped": True,
        "windowed_for_bounded_memory": True,
        "window_boundary_effect_possible": True,
        "semantic_note": (
            "Bounded slices use the rule engine's nominal five-minute duration and "
            "cross-window alert deduplication remains active; correlations spanning a "
            "slice boundary can be split in this shadow audit."
        ),
    }


def _table_counts(db: Session) -> dict[str, int]:
    return {
        "raw_logs": int(db.scalar(select(func.count(RawLog.id))) or 0),
        "normalized_logs": int(db.scalar(select(func.count(NormalizedLog.id))) or 0),
        "alerts": int(db.scalar(select(func.count(Alert.id))) or 0),
        "detection_runs": int(db.scalar(select(func.count(DetectionRun.id))) or 0),
        "labels": int(db.scalar(select(func.count(MLLabel.id))) or 0),
        "model_runs": int(db.scalar(select(func.count(MLModelRun.id))) or 0),
        "response_actions": int(db.scalar(select(func.count(ResponseAction.id))) or 0),
    }


def _assistant_and_explanation_audit(db: Session) -> dict[str, Any]:
    alert = db.scalar(
        select(Alert)
        .options(selectinload(Alert.evidence).joinedload(AlertEvidence.normalized_log))
        .order_by(Alert.threat_score.desc(), Alert.id.desc())
        .limit(1)
    )
    if alert is None:
        return {
            "status": "not_run_no_alerts",
            "explanation_sections": {},
            "assistant_question_run": False,
            "mutations": {},
            "response_actions_created": 0,
        }
    explanation = build_alert_detection_summary(db, alert)
    before = _table_counts(db)
    settings = get_settings()
    response = answer_assistant_question(
        db,
        question=f"Why was alert {alert.id} flagged and what should an analyst check next?",
        actor="v5.0-shadow-validator",
        settings=settings,
        alert_id=int(alert.id),
        conversation_id="v50-shadow-validation",
        reset_context=True,
    )
    after = _table_counts(db)
    mutable_tables = (
        "raw_logs",
        "normalized_logs",
        "alerts",
        "detection_runs",
        "labels",
        "model_runs",
        "response_actions",
    )
    mutations = {
        key: after[key] - before[key]
        for key in mutable_tables
    }
    answer = str(response.get("answer") or "")
    citations = response.get("citations") or []
    sections = {
        "observations": bool(explanation.get("observed_evidence")),
        "rules": bool(explanation.get("rule_inferences")),
        "anomaly_score": "anomaly_evidence" in explanation,
        "supervised_score": "ml_evidence" in explanation,
        "missing_context": "missing_context" in explanation,
        "confidence": bool(explanation.get("evidence_confidence")),
        "related_logs": bool(alert.evidence),
        "analyst_checks": bool(explanation.get("analyst_next_steps")),
    }
    return {
        "status": "completed",
        "alert_reference_used": True,
        "alert_id_returned": int(alert.id),
        "explanation_sections": sections,
        "explanation_complete": all(sections.values()),
        "assistant_question_run": True,
        "assistant_mode": response.get("mode"),
        "assistant_answer_words": len(answer.split()),
        "assistant_citation_count": len(citations),
        "assistant_cited": bool(citations),
        "external_provider_used": bool(response.get("external_provider_used")),
        "raw_log_context_included": bool(response.get("raw_log_context_included")),
        "redaction_applied": bool(response.get("redaction_applied")),
        "mutations": mutations,
        "operational_mutations_created": any(value != 0 for value in mutations.values()),
        "response_actions_created": mutations["response_actions"],
        "assistant_audit_logged": int(
            db.scalar(
                select(func.count(AuditLog.id)).where(
                    AuditLog.action == "assistant_question"
                )
            )
            or 0
        )
        > 0,
        "answer_returned": False,
        "private_identifiers_returned": False,
        "decision_support_only": True,
        "response_automation_allowed": False,
    }


def _render_markdown(result: dict[str, Any]) -> str:
    preflight = result.get("preflight") or {}
    overlap = preflight.get("current_database_overlap") or {}
    ingestion = result.get("shadow_ingestion") or {}
    detection = result.get("rule_detection") or {}
    noise = result.get("alert_noise") or {}
    ml = result.get("ml_diagnostics") or {}
    assistant = result.get("assistant_and_explanations") or {}
    review = result.get("review_sample") or {}
    return "\n".join(
        [
            "# ATDR v5.0 Real Palo Alto Shadow Validation",
            "",
            f"- Generated: {result.get('generated_at')}",
            "- Evidence: private local Palo Alto file; raw content and identifiers omitted",
            "- Database: disposable SQLite shadow database",
            f"- Current database modified: {result.get('current_database_modified')}",
            f"- Model activated/promoted: {result.get('model_activated')}/{result.get('model_promoted')}",
            f"- Response actions: {result.get('response_actions_created')}",
            "",
            "## Preflight",
            "",
            f"- File size bytes: {preflight.get('file_size_bytes')}",
            f"- Nonblank lines: {preflight.get('nonblank_lines')}",
            f"- Format: {preflight.get('format')}",
            f"- Parser errors: {(preflight.get('parser') or {}).get('errors')}",
            f"- Exact duplicate rows: {(preflight.get('duplicates') or {}).get('exact_duplicate_rows')}",
            f"- Current DB fingerprint overlap: {overlap.get('file_row_overlap_percent')}%",
            f"- Already imported by fingerprint multiplicity: {overlap.get('already_imported_by_fingerprint')}",
            "",
            "## Shadow Ingestion",
            "",
            f"- Raw rows: {ingestion.get('raw_logs')}",
            f"- Normalized rows: {ingestion.get('normalized_logs')}",
            f"- Parse successes/failures: {ingestion.get('parse_successes')}/{ingestion.get('parse_failures')}",
            f"- Exact duplicate observations: {ingestion.get('duplicate_raw_logs')}",
            f"- Throughput rows/second: {ingestion.get('rows_per_second')}",
            f"- Source health: {ingestion.get('source_health')}",
            "",
            "## Detection And Noise",
            "",
            f"- Logs evaluated: {detection.get('evaluated')}",
            f"- Alerts created: {detection.get('created_alerts')}",
            f"- Deduplicated updates: {detection.get('deduplicated_alert_updates')}",
            f"- Alerts/cases: {noise.get('alerts')}/{noise.get('computed_cases')}",
            f"- Occurrences collapsed: {(noise.get('deduplication') or {}).get('occurrences_collapsed')}",
            "- Alert/noise counts are triage-volume observations. No FPR, precision, recall, or accuracy is claimed without ground truth.",
            "",
            "## Diagnostic ML Queues",
            "",
            f"- Rule-only sample queue: {(ml.get('rule_only') or {}).get('sample_queue_rows')}",
            f"- IsolationForest full queue: {(ml.get('isolation_forest') or {}).get('exact_full_queue_rows')}",
            f"- Supervised sample queue: {(ml.get('supervised_queue') or {}).get('queue_rows')}",
            f"- Hybrid sample queue: {(ml.get('hybrid_queue') or {}).get('sample_queue_rows')}",
            "- Existing artifacts were read only. No model was activated, promoted, trained, or written.",
            "",
            "## Explanation And Assistant Safety",
            "",
            f"- Explanation complete: {assistant.get('explanation_complete')}",
            f"- Assistant cited/read-only/redacted: {assistant.get('assistant_cited')}/"
            f"{not assistant.get('operational_mutations_created', True)}/{assistant.get('redaction_applied')}",
            f"- Raw log context included: {assistant.get('raw_log_context_included')}",
            f"- Review sample: {review.get('status')} ({review.get('rows', 0)} rows, import_ready=false)",
            "",
            "## Claim Boundary",
            "",
            "This is a private-file shadow validation of parser coverage, queue volume, and evidence quality. It is not independently labeled accuracy evidence and does not establish production readiness.",
        ]
    )


def _write_local_reports(
    result: dict[str, Any],
    *,
    output_dir: Path,
) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    stamp = _stamp()
    json_path = output_dir / f"v5_0_shadow_validation_{stamp}.json"
    markdown_path = output_dir / f"v5_0_shadow_validation_{stamp}.md"
    json_path.write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")
    markdown_path.write_text(_render_markdown(result), encoding="utf-8")
    return {
        "written": True,
        "json_file_name": json_path.name,
        "markdown_file_name": markdown_path.name,
        "ignored_output": True,
        "private_path_returned": False,
    }


def run_v50_real_paloalto_shadow_validation(
    *,
    evidence_path: Path,
    use_temp_db: bool,
    current_database_url: str | None = None,
    line_limit: int | None = None,
    chunk_size: int = 1_000,
    ml_sample_limit: int = DEFAULT_ML_SAMPLE_LIMIT,
    write_review_sample: bool = True,
    review_sample_path: Path = DEFAULT_REVIEW_SAMPLE,
    write_reports: bool = True,
    output_dir: Path = DEFAULT_OUTPUT_DIR,
    run_ml: bool = True,
    run_assistant_audit: bool = True,
    governed_supervised_artifact_path: Path | None = None,
) -> dict[str, Any]:
    if not use_temp_db:
        return {
            "ok": False,
            "status": "explicit_temp_database_required",
            "message": "Re-run with --use-temp-db. Configured databases are never shadow-validation targets.",
            "current_database_modified": False,
            "model_activated": False,
            "response_actions_created": 0,
        }
    if line_limit is not None and line_limit <= 0:
        return {
            "ok": False,
            "status": "invalid_line_limit",
            "current_database_modified": False,
            "model_activated": False,
            "response_actions_created": 0,
        }

    started = time.perf_counter()
    database_marker_before = configured_database_marker(current_database_url)
    isolation_path = get_settings().resolved_model_path
    supervised_path = supervised_model_path()
    model_markers_before = {
        "isolation_forest": _artifact_marker(isolation_path),
        "supervised": _artifact_marker(supervised_path),
        "governed_supervised": _artifact_marker(governed_supervised_artifact_path)
        if governed_supervised_artifact_path
        else None,
    }
    preflight = preflight_private_paloalto_file(
        evidence_path,
        current_database_url=current_database_url,
        max_lines=line_limit,
    )
    if not preflight.get("ok"):
        return {
            "ok": False,
            "status": "preflight_failed",
            "preflight": preflight,
            "current_database_modified": False,
            "model_activated": False,
            "response_actions_created": 0,
        }

    run_id = uuid4().hex[:12]
    temp_root = PROJECT_ROOT / ".tmp" / f"v50-shadow-{run_id}"
    database_path = temp_root / "shadow.sqlite3"
    staging_root = temp_root / "staging"
    temp_root.mkdir(parents=True, exist_ok=False)
    engine = None
    staged_payload: dict[str, Any] | None = None
    try:
        with _shadow_runtime_settings(
            staging_root,
            input_size_bytes=int(preflight["file_size_bytes"]),
            chunk_size=chunk_size,
        ) as settings:
            staging_started = time.perf_counter()
            with evidence_path.open("rb") as stream:
                staged = stage_upload_for_job(
                    stream,
                    filename="real-paloalto-shadow.log",
                )
            staging_seconds = time.perf_counter() - staging_started
            staged_payload = {
                **staged_payload_fields(staged),
                "input_bytes": staged.byte_count,
                "input_fingerprint": staged.fingerprint,
            }
            engine = create_engine(
                f"sqlite:///{database_path}",
                connect_args={"check_same_thread": False, "timeout": 60.0},
                future=True,
            )
            Base.metadata.create_all(engine)
            with Session(engine, expire_on_commit=False) as db:
                source = create_source(
                    db,
                    name=DEFAULT_SOURCE_NAME,
                    source_type="firewall",
                    parser_profile="palo_alto",
                )
                job = _enqueue_shadow_import(
                    db,
                    staged=staged,
                    source_id=int(source.id),
                    line_limit=line_limit,
                )
                ingestion_started = time.perf_counter()
                worker_result = run_worker_once(
                    db,
                    worker_id="v50-shadow-import-worker",
                )
                ingestion_seconds = time.perf_counter() - ingestion_started
                db.expire_all()
                completed_job = db.get(OperationJob, int(job.id))
                ingestion_run = (
                    db.get(IngestionRun, int(completed_job.related_ingestion_run_id))
                    if completed_job is not None and completed_job.related_ingestion_run_id
                    else None
                )
                source = db.get(type(source), int(source.id))
                if (
                    not worker_result.get("ok")
                    or completed_job is None
                    or completed_job.status != "completed"
                    or ingestion_run is None
                    or source is None
                ):
                    raise RuntimeError("Disposable shadow ingestion did not complete.")

                raw_count = int(db.scalar(select(func.count(RawLog.id))) or 0)
                normalized_count = int(
                    db.scalar(select(func.count(NormalizedLog.id))) or 0
                )
                ingestion_summary = {
                    "status": completed_job.status,
                    "source_name": source.name,
                    "source_type": source.source_type,
                    "parser_profile": source.parser_profile,
                    "raw_logs": raw_count,
                    "normalized_logs": normalized_count,
                    "parse_successes": int(ingestion_run.parsed_successfully),
                    "parse_failures": int(ingestion_run.parse_failures),
                    "duplicate_raw_logs": int(ingestion_run.duplicate_raw_logs),
                    "chunk_commits": int(completed_job.chunk_commits),
                    "checkpoint_line": int(completed_job.checkpoint_line),
                    "staging_seconds": round(staging_seconds, 4),
                    "ingestion_seconds": round(ingestion_seconds, 4),
                    "rows_per_second": round(raw_count / ingestion_seconds, 2)
                    if ingestion_seconds
                    else None,
                    "source_health": source_health(source).get("status"),
                    "source_quality_warnings": source_quality(db, int(source.id)).get(
                        "warnings", []
                    ),
                    "resumable_worker_path_used": True,
                    "private_path_stored": False,
                    "temporary_database_used": True,
                }
                parser_quality = _normalized_quality(db, int(source.id))

                detection_started = time.perf_counter()
                detection_result = _run_windowed_source_detection(
                    db,
                    source_id=int(source.id),
                    source_name=source.name,
                    source_type=source.source_type,
                )
                detection_seconds = time.perf_counter() - detection_started
                detection_summary = {
                    **detection_result,
                    "runtime_seconds_observed": round(detection_seconds, 4),
                    "source_scoped": True,
                    "response_actions_created": int(
                        db.scalar(select(func.count(ResponseAction.id))) or 0
                    ),
                }
                gc.collect()
                noise_audit = _alert_noise_audit(db, int(source.id))

                if run_ml:
                    ml_diagnostics, diagnostic_rows = _ml_queue_diagnostics(
                        db,
                        int(source.id),
                        sample_limit=ml_sample_limit,
                        settings=settings,
                        exact_rule_queue_rows=int(
                            detection_summary.get("candidate_logs") or 0
                        ),
                        governed_artifact_path=governed_supervised_artifact_path,
                    )
                else:
                    ml_diagnostics = {
                        "scope": "skipped_by_caller",
                        "ground_truth_available": False,
                        "accuracy_metrics_reported": False,
                        "model_activated": False,
                        "active_artifact_written": False,
                    }
                    diagnostic_rows = []

                review_sample = (
                    _write_review_sample(
                        db,
                        diagnostic_rows,
                        output_path=review_sample_path,
                    )
                    if write_review_sample
                    else {
                        "status": "disabled_by_caller",
                        "rows": 0,
                        "import_ready": False,
                    }
                )
                assistant_audit = (
                    _assistant_and_explanation_audit(db)
                    if run_assistant_audit
                    else {
                        "status": "skipped_by_caller",
                        "operational_mutations_created": False,
                        "response_actions_created": 0,
                    }
                )
                final_counts = _table_counts(db)

        database_marker_after = configured_database_marker(current_database_url)
        model_markers_after = {
            "isolation_forest": _artifact_marker(isolation_path),
            "supervised": _artifact_marker(supervised_path),
            "governed_supervised": _artifact_marker(governed_supervised_artifact_path)
            if governed_supervised_artifact_path
            else None,
        }
        current_database_unchanged = database_marker_before == database_marker_after
        model_artifacts_unchanged = model_markers_before == model_markers_after
        response_actions_created = int(final_counts["response_actions"])
        result = {
            "ok": bool(
                current_database_unchanged
                and model_artifacts_unchanged
                and response_actions_created == 0
                and not assistant_audit.get("operational_mutations_created", False)
                and ingestion_summary["raw_logs"] == ingestion_summary["normalized_logs"]
            ),
            "status": "shadow_validation_complete",
            "generated_at": _now().isoformat(),
            "preflight": preflight,
            "shadow_ingestion": ingestion_summary,
            "parser_quality": parser_quality,
            "rule_detection": detection_summary,
            "alert_noise": noise_audit,
            "ml_diagnostics": ml_diagnostics,
            "review_sample": review_sample,
            "assistant_and_explanations": assistant_audit,
            "temporary_database_counts": final_counts,
            "current_database_marker_checked": database_marker_before is not None,
            "current_database_unchanged": current_database_unchanged,
            "current_database_modified": not current_database_unchanged,
            "model_artifacts_unchanged": model_artifacts_unchanged,
            "model_activated": False,
            "model_promoted": False,
            "active_model_artifact_written": False,
            "response_actions_created": response_actions_created,
            "response_automation_allowed": False,
            "real_firewall_blocking_enabled": False,
            "human_reviewed_labels_created": 0,
            "ai_labels_imported": 0,
            "ground_truth_available": False,
            "accuracy_metrics_reported": False,
            "private_path_returned": False,
            "raw_evidence_returned": False,
            "secrets_exposed": False,
            "runtime_seconds": round(time.perf_counter() - started, 4),
        }
        result["reports"] = (
            _write_local_reports(result, output_dir=output_dir)
            if write_reports
            else {"written": False, "ignored_output": True}
        )
        return result
    except Exception as exc:
        database_marker_after = configured_database_marker(current_database_url)
        return {
            "ok": False,
            "status": "shadow_validation_error",
            "error_type": exc.__class__.__name__,
            "preflight": preflight,
            "current_database_modified": database_marker_before
            != database_marker_after,
            "model_activated": False,
            "model_promoted": False,
            "response_actions_created": 0,
            "response_automation_allowed": False,
            "real_firewall_blocking_enabled": False,
            "private_path_returned": False,
            "raw_evidence_returned": False,
            "secrets_exposed": False,
        }
    finally:
        if staged_payload is not None:
            cleanup_staged_payload(staged_payload)
        if engine is not None:
            engine.dispose()
        shutil.rmtree(temp_root, ignore_errors=True)
        get_settings.cache_clear()
