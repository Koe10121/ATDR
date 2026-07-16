from __future__ import annotations

from datetime import datetime
import hashlib
import json
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from atdr.app.detection.supervised_workflow import list_supervised_models
from atdr.app.services.ml_service import model_status


PROJECT_ROOT = Path(__file__).resolve().parents[3]
CANONICAL_EVIDENCE_PATH = PROJECT_ROOT / "ml_baseline_reviews" / "v4_1_schema_aware_soc_queue_latest.json"
CANONICAL_VERSION = "v4.1"


def _iso(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def _metric_ranges(payload: dict[str, Any]) -> dict[str, dict[str, float | None]]:
    expected = (
        "queue_precision",
        "queue_recall",
        "queue_f1",
        "benign_like_false_positive_rate",
        "suspicious_recall",
        "malicious_recall",
        "macro_f1",
        "weighted_f1",
        "review_queue_rate",
    )
    source = payload.get("metric_ranges") or {}
    return {
        name: {
            "min": source.get(name, {}).get("min"),
            "max": source.get(name, {}).get("max"),
        }
        for name in expected
    }


def _canonical_evidence() -> dict[str, Any]:
    if not CANONICAL_EVIDENCE_PATH.exists():
        return {
            "available": False,
            "status": "not_available",
            "reason": "Canonical v4.1 evidence snapshot has not been generated on this installation.",
            "expected_report_name": CANONICAL_EVIDENCE_PATH.name,
            "metrics": None,
        }

    try:
        raw = CANONICAL_EVIDENCE_PATH.read_bytes()
        report = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return {
            "available": False,
            "status": "invalid",
            "reason": "Canonical v4.1 evidence exists but could not be validated.",
            "expected_report_name": CANONICAL_EVIDENCE_PATH.name,
            "metrics": None,
        }

    if report.get("version") != CANONICAL_VERSION or not isinstance(report.get("diagnostic_selection"), dict):
        return {
            "available": False,
            "status": "version_mismatch",
            "reason": "Canonical evidence does not match the required v4.1 schema.",
            "expected_report_name": CANONICAL_EVIDENCE_PATH.name,
            "metrics": None,
        }

    selection = (report["diagnostic_selection"].get("best_overall_development_diagnostic") or {})
    development = report.get("development_evidence") or {}
    dataset = development.get("dataset") or {}
    sample = report.get("development_sample") or {}
    worst = report.get("worst_cross_schema_split") or {}
    calibration = worst.get("calibration") or {}
    readiness = report.get("readiness") or {}
    safety = report.get("safety") or {}

    return {
        "available": True,
        "snapshot_id": f"v41-{hashlib.sha256(raw).hexdigest()[:16]}",
        "generated_at": report.get("generated_at"),
        "version": report.get("version"),
        "evidence_type": "controlled_development_validation",
        "status": report.get("status"),
        "readiness_decision": readiness.get("decision", "candidate_only"),
        "selected_strategy": selection.get("name"),
        "selection_scope": selection.get("selection_scope"),
        "evaluated_splits": selection.get("evaluated_splits"),
        "calibration_passed_splits": selection.get("calibration_passed_splits"),
        "dataset": {
            "dataset_id": dataset.get("dataset_id"),
            "title": dataset.get("title"),
            "publisher": dataset.get("publisher"),
            "role": dataset.get("role"),
            "accepted_rows": sample.get("accepted_rows"),
            "sample_sha256": sample.get("sample_sha256"),
            "provider_ground_truth": (sample.get("label_integrity") or {}).get("provider_ground_truth"),
            "human_reviewed": dataset.get("human_reviewed"),
        },
        "provenance": {
            "report_name": CANONICAL_EVIDENCE_PATH.name,
            "development_manifest_hash": development.get("manifest_hash"),
            "source_file_count": len(development.get("files") or []),
        },
        "metric_ranges": _metric_ranges(selection),
        "worst_split": {
            "split_mode": worst.get("split_mode"),
            "metrics": {
                key: (worst.get("metrics") or {}).get(key)
                for key in (
                    "queue_precision",
                    "queue_recall",
                    "queue_f1",
                    "benign_like_false_positive_rate",
                    "suspicious_recall",
                    "malicious_recall",
                    "macro_f1",
                    "weighted_f1",
                    "review_queue_rate",
                    "review_queue_size",
                )
            },
        },
        "calibration": {
            "status": calibration.get("status", "unknown"),
            "passed": bool(calibration.get("passed", False)),
            "brier_score": calibration.get("brier_score"),
            "expected_calibration_error": calibration.get("expected_calibration_error"),
            "max_confidence_accuracy_gap": calibration.get("max_confidence_accuracy_gap"),
        },
        "safety": {
            "development_only": bool(development.get("development_only", True)),
            "model_activated": bool(readiness.get("model_activated", False)),
            "model_artifact_written": bool(readiness.get("model_artifact_written", False)),
            "production_promoted": bool(readiness.get("production_promoted", False)),
            "response_automation_allowed": bool(readiness.get("response_automation_allowed", False)),
            "real_firewall_blocking_enabled": bool(readiness.get("real_firewall_blocking_enabled", False)),
            "database_counts_unchanged": bool(safety.get("database_counts_unchanged", False)),
        },
        "limitations": [
            "Development-only evidence; it is not an independent final benchmark.",
            "Calibration failed on the evaluated development splits.",
            "The selected strategy is diagnostic-only and was not activated.",
        ],
    }


def build_ml_evidence_snapshot(db: Session) -> dict[str, Any]:
    isolation = model_status(db)
    registry = list_supervised_models(db, limit=25)
    active = next((item for item in registry.get("models", []) if item.get("is_active_path")), None)
    latest_candidate = next(
        (item for item in registry.get("models", []) if item.get("operation") == "train_supervised"),
        None,
    )
    latest_training = isolation.get("latest_training") or {}
    latest_scoring = isolation.get("latest_scoring") or {}

    return {
        "schema_version": "1.0",
        "canonical_evidence": _canonical_evidence(),
        "operational_models": {
            "isolation_forest": {
                "role": "assistive_anomaly_signal",
                "artifact_exists": bool(isolation.get("artifact_exists")),
                "model_type": "IsolationForest",
                "last_trained_at": _iso(latest_training.get("created_at")),
                "last_scored_at": _iso(latest_scoring.get("created_at")),
                "scored_log_count": latest_scoring.get("scored_log_count"),
                "anomaly_count": isolation.get("current_anomaly_logs"),
                "anomaly_rate_percent": isolation.get("current_anomaly_rate"),
                "decision_support_only": True,
            },
            "active_supervised_artifact": {
                "artifact_exists": bool(registry.get("active_artifact_exists")),
                "metadata_status": registry.get("active_artifact_metadata_status"),
                "metadata_unknown": bool(registry.get("active_artifact_metadata_unknown")),
                "model_type": None if not active or active.get("active_artifact_metadata_unknown") else active.get("display_model_type"),
                "feature_set": None if not active or active.get("active_artifact_metadata_unknown") else active.get("display_feature_set"),
                "message": active.get("message") if active else "No active supervised artifact is present.",
                "production_promoted": False,
                "response_automation_allowed": False,
            },
            "diagnostic_candidates": {
                "registry_entry_count": len(registry.get("models") or []),
                "latest_candidate": {
                    "model_id": latest_candidate.get("model_id"),
                    "model_type": latest_candidate.get("display_model_type"),
                    "created_at": _iso(latest_candidate.get("created_at")),
                    "readiness_decision": latest_candidate.get("readiness_decision"),
                    "is_active": bool(latest_candidate.get("is_active_path")),
                }
                if latest_candidate
                else None,
                "canonical_candidate_is_active": False,
            },
        },
        "safety": {
            "decision_support_only": True,
            "production_promoted": False,
            "response_automation_allowed": False,
            "real_firewall_blocking_enabled": False,
            "secrets_exposed": False,
            "local_paths_exposed": False,
        },
    }
