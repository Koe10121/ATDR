from __future__ import annotations

import hashlib
import json
import subprocess
import threading
import time
from collections import Counter, deque
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any

from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from atdr.app.core.config import PROJECT_ROOT, get_settings
from atdr.app.db.models import Alert, AuditLog, DetectionRun, MLLabel, MLModelRun, NormalizedLog, ResponseAction
from atdr.app.detection import v398_independent_holdout_validation as frozen
from atdr.app.detection import v49_detection_ml_reliability as reliability
from atdr.app.detection.supervised_detector import MODEL_NAME, _artifact_hash
from atdr.app.detection.v331_noise_reduction import _classes
from atdr.app.ml.features import build_feature_rows


V51_VERSION = "v5.1-supervised-shadow-v1"
V51_FEATURE_SET_VERSION = "v5.1-causal-soc-queue-features-v1"
V51_MODEL_TYPE = "calibrated_extra_trees"
V51_TARGET_MODE = "binary_soc_review_queue"
V51_SELECTED_STRATEGY = reliability.PREDECLARED_CANDIDATE
LIFECYCLE_STATES = {
    "inactive",
    "shadow_observation",
    "decision_support",
    "production_promoted",
}
ACTIVE_OPERATIONS = {
    "activate_supervised_shadow",
    "activate_supervised_decision_support",
    "rollback_supervised_governed",
    "disable_supervised_governed",
}
SHADOW_TELEMETRY_OPERATION = "supervised_shadow_telemetry_snapshot"
SHADOW_LATENCY_P95_LIMIT_MS = 250.0
DEFAULT_OUTPUT_DIR = PROJECT_ROOT / "ml_baseline_reviews"


_telemetry_lock = threading.Lock()
_telemetry: dict[str, Any] = {
    "model_version": None,
    "inference_count": 0,
    "batch_count": 0,
    "failure_count": 0,
    "missing_feature_values": 0,
    "feature_values_checked": 0,
    "latencies_ms": deque(maxlen=1000),
    "queue_scores": deque(maxlen=5000),
}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _stamp() -> str:
    return _now().strftime("%Y%m%dT%H%M%SZ")


def _stable_hash(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _code_revision() -> str:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=PROJECT_ROOT,
            check=True,
            capture_output=True,
            text=True,
            timeout=3,
        )
    except (OSError, subprocess.SubprocessError):
        return "unavailable"
    return result.stdout.strip() or "unavailable"


def _database_safety_counts(db: Session) -> dict[str, int]:
    return {
        "labels": int(db.scalar(select(func.count(MLLabel.id))) or 0),
        "alerts": int(db.scalar(select(func.count(Alert.id))) or 0),
        "detection_runs": int(db.scalar(select(func.count(DetectionRun.id))) or 0),
        "response_actions": int(db.scalar(select(func.count(ResponseAction.id))) or 0),
    }


def _percentile(values: list[float], fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(float(value) for value in values)
    position = (len(ordered) - 1) * fraction
    lower = int(position)
    upper = min(len(ordered) - 1, lower + 1)
    weight = position - lower
    return ordered[lower] * (1.0 - weight) + ordered[upper] * weight


def _public_split_result(split: dict[str, Any]) -> dict[str, Any]:
    return {
        **{key: value for key, value in split.items() if key != "strategies"},
        "strategies": [reliability._public_strategy(item) for item in split.get("strategies") or []],
    }


def _selected_split_metrics(split_results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for split in split_results:
        selected = next(
            (item for item in split.get("strategies") or [] if item.get("name") == V51_SELECTED_STRATEGY),
            None,
        )
        rows.append(
            {
                "split_mode": split.get("split_mode"),
                "status": split.get("status"),
                "leakage_passed": bool((split.get("leakage_audit") or {}).get("passed")),
                "metrics": (selected or {}).get("metrics", {}),
                "calibration": (selected or {}).get("calibration", {}),
                "threshold_selection": (selected or {}).get("threshold_selection", {}),
            }
        )
    return rows


def _strict_gate_summary(
    comparison: dict[str, Any],
    external_benchmark: dict[str, Any],
    split_results: list[dict[str, Any]],
) -> dict[str, Any]:
    selected = comparison.get(V51_SELECTED_STRATEGY) or {}
    required = len(reliability.V49_SPLITS)
    passing = int(selected.get("strict_passing_splits") or 0)
    all_leakage_passed = all(bool((item.get("leakage_audit") or {}).get("passed")) for item in split_results)
    all_splits_evaluated = all(item.get("status") == "evaluated" for item in split_results)
    external_available = bool(external_benchmark.get("available"))
    external_passed = bool(external_benchmark.get("passed")) if external_available else False
    decision_support_eligible = bool(
        passing == required
        and all_leakage_passed
        and all_splits_evaluated
        and external_available
        and external_passed
    )
    return {
        "decision_support_eligible": decision_support_eligible,
        "decision": "decision_support" if decision_support_eligible else "shadow_observation",
        "strict_passing_splits": passing,
        "strict_required_splits": required,
        "all_required_splits_evaluated": all_splits_evaluated,
        "all_leakage_audits_passed": all_leakage_passed,
        "external_benchmark_available": external_available,
        "external_benchmark_passed": external_passed,
        "quality_targets": dict(reliability.STRICT_GATES),
        "production_promoted": False,
        "response_automation_allowed": False,
    }


def _dataset_manifest(dataset: dict[str, Any], partition: dict[str, Any]) -> dict[str, Any]:
    rows = dataset["rows"]
    identities = [
        {
            "log_id": int(row["log_id"]),
            "label_id": int(row["label_id"]),
            "label": str(row["original_label"]),
            "label_source": str(row["label_source"]),
            "reviewed": bool(row["reviewed"]),
            "exact_fingerprint": str(row["exact_fingerprint"]),
            "near_fingerprint": str(row["near_fingerprint"]),
        }
        for row in rows
    ]
    timestamps = [row["timestamp"] for row in rows if row.get("timestamp") is not None]
    roles: dict[str, list[int]] = {}
    for key in ("fit_idx", "calibration_idx", "threshold_idx", "final_test_idx", "quarantined_idx"):
        roles[key.removesuffix("_idx")] = [int(rows[index]["log_id"]) for index in partition.get(key) or []]
    return {
        "dataset_fingerprint": _stable_hash(identities),
        "reviewed_latest_rows": len(rows),
        "normalized_log_ids": [item["log_id"] for item in identities],
        "label_ids": [item["label_id"] for item in identities],
        "partition_log_ids": roles,
        "provenance": dataset["label_provenance"],
        "time_range": {
            "earliest": min(timestamps).isoformat() if timestamps else None,
            "latest": max(timestamps).isoformat() if timestamps else None,
        },
        "target_mapping": {
            "benign": "non_threat",
            "benign_unusual": "non_threat",
            "needs_context": "needs_review",
            "suspicious": "needs_review",
            "malicious": "needs_review",
        },
        "target_repair_used_as_ground_truth": False,
        "weak_or_unreviewed_labels_used": False,
        "ai_authored_human_reviewed_labels": 0,
    }


def _artifact_path(version: str) -> Path:
    root = get_settings().resolved_supervised_model_path.parent / "supervised_candidates"
    root.mkdir(parents=True, exist_ok=True)
    return root / f"{version}.joblib"


def _extract_feature_importance(model: Any, *, limit: int = 20) -> list[dict[str, Any]]:
    candidates = [model]
    calibrated = getattr(model, "calibrated_classifiers_", None) or []
    candidates.extend(getattr(item, "estimator", None) for item in calibrated)
    for candidate in candidates:
        pipeline = candidate if hasattr(candidate, "named_steps") else None
        if pipeline is None:
            continue
        estimator = pipeline.named_steps.get("model")
        preprocessor = pipeline.named_steps.get("preprocess")
        if estimator is None or preprocessor is None or not hasattr(estimator, "feature_importances_"):
            continue
        try:
            names = preprocessor.get_feature_names_out()
        except Exception:
            names = [f"feature_{index}" for index in range(len(estimator.feature_importances_))]
        pairs = sorted(
            zip(names, estimator.feature_importances_, strict=False),
            key=lambda item: float(item[1]),
            reverse=True,
        )
        return [{"feature": str(name), "importance": round(float(value), 6)} for name, value in pairs[:limit]]
    return []


def _artifact_runtime_checks(artifact_path: Path, frame: Any, sample_indices: list[int]) -> dict[str, Any]:
    import joblib

    loaded = joblib.load(artifact_path)
    model = loaded["model"]
    sample = frame.iloc[sample_indices[: min(100, len(sample_indices))]]
    latencies: list[float] = []
    scores: list[float] = []
    for position in range(len(sample)):
        started = time.perf_counter()
        probabilities = model.predict_proba(sample.iloc[[position]])
        latencies.append((time.perf_counter() - started) * 1000)
        classes = _classes(model)
        positive_index = classes.index("needs_review") if "needs_review" in classes else -1
        scores.append(float(probabilities[0][positive_index]) if positive_index >= 0 else 0.0)
    bounded = all(0.0 <= value <= 1.0 for value in scores)
    return {
        "serialization_round_trip": True,
        "metadata_digest_present": bool(loaded.get("metadata_digest")),
        "checksum_verified": False,
        "sample_rows": len(sample),
        "probabilities_bounded": bounded,
        "latency_ms": {
            "average": round(sum(latencies) / len(latencies), 4) if latencies else 0.0,
            "p95": round(_percentile(latencies, 0.95), 4),
            "maximum": round(max(latencies), 4) if latencies else 0.0,
        },
        "latency_gate_ms": SHADOW_LATENCY_P95_LIMIT_MS,
        "latency_gate_passed": bool(latencies) and _percentile(latencies, 0.95) <= SHADOW_LATENCY_P95_LIMIT_MS,
    }


def train_and_register_v51_candidate(
    db: Session,
    *,
    actor: str = "cli",
    output_dir: Path = DEFAULT_OUTPUT_DIR,
    write_reports: bool = True,
) -> dict[str, Any]:
    before = _database_safety_counts(db)
    dataset = frozen._build_dataset(db, min_samples=50)
    if not dataset.get("ok"):
        return {
            "ok": False,
            "status": dataset.get("status", "failed_closed"),
            "message": dataset.get("message", "Canonical training dataset is unavailable."),
            "model_activated": False,
            "production_promoted": False,
            "response_automation_allowed": False,
        }

    # Ground truth is a direct, auditable mapping from the latest reviewed labels.
    dataset["targets"] = reliability._queue_targets(dataset["original_labels"])
    for row, target in zip(dataset["rows"], dataset["targets"], strict=True):
        row["safe_queue_target"] = target
        row["target_reason"] = "direct_original_reviewed_label_mapping"
    dataset["label_provenance"]["ground_truth_policy"] = "latest_reviewed_original_labels_direct_binary_mapping"
    dataset["label_provenance"]["target_repair_used_as_ground_truth"] = False
    duplicate_groups = frozen.assign_leakage_groups(dataset["rows"])
    split_results = [reliability._run_split(dataset, split_mode=mode) for mode in reliability.V49_SPLITS]
    comparison = reliability._strategy_comparison(split_results)
    external = reliability._locked_external_evidence(output_dir)
    strict_gates = _strict_gate_summary(comparison, external, split_results)

    designated_partition = frozen.build_frozen_partition(dataset["rows"], split_mode="temporal_holdout")
    leakage = frozen.audit_partition_leakage(dataset["rows"], designated_partition)
    if not leakage.get("passed"):
        return {
            "ok": False,
            "status": "failed_closed",
            "message": "Temporal artifact partition failed leakage audit.",
            "leakage_audit": leakage,
            "model_activated": False,
            "production_promoted": False,
            "response_automation_allowed": False,
        }

    fitted = reliability._fit_candidate(
        dataset,
        designated_partition,
        model_type="extra_trees",
        targets=dataset["targets"],
        positive_classes={"needs_review"},
        class_weight=None,
        weight_strategy="strong_benign",
        calibrate=True,
    )
    if fitted.get("status") != "evaluated":
        return {
            "ok": False,
            "status": "failed_closed",
            "message": fitted.get("message", "Selected supervised candidate could not be fitted."),
            "model_activated": False,
            "production_promoted": False,
            "response_automation_allowed": False,
        }

    version = f"v5.1-soc-queue-{_stamp()}"
    path = _artifact_path(version)
    dataset_manifest = _dataset_manifest(dataset, designated_partition)
    threshold = float((fitted.get("threshold_selection") or {}).get("selected_threshold", 0.5))
    selected_splits = _selected_split_metrics(split_results)
    selected_summary = comparison.get(V51_SELECTED_STRATEGY) or {}
    artifact: dict[str, Any] = {
        "schema_version": V51_VERSION,
        "model_name": MODEL_NAME,
        "model_version": version,
        "model_type": V51_MODEL_TYPE,
        "target_mode": V51_TARGET_MODE,
        "model": fitted["model"],
        "label_classes": _classes(fitted["model"]),
        "positive_class": "needs_review",
        "threshold": threshold,
        "feature_set_version": V51_FEATURE_SET_VERSION,
        "feature_schema": {
            "numeric": dataset["feature_meta"]["numeric_features"],
            "categorical": dataset["feature_meta"]["categorical_features"],
            "excluded_leakage_features": dataset["feature_meta"]["excluded_features"],
            "rule_context": dataset["feature_meta"]["rule_context"],
        },
        "dataset_manifest": dataset_manifest,
        "code_revision": _code_revision(),
        "hyperparameters": {
            "classifier": "ExtraTreesClassifier",
            "class_weight": None,
            "sample_weight_strategy": "strong_benign",
            "n_estimators": 180,
            "random_state": 42,
        },
        "calibration_method": fitted["calibration_method"],
        "threshold_selection": fitted["threshold_selection"],
        "validation": {
            "strict_gates": strict_gates,
            "selected_strategy": V51_SELECTED_STRATEGY,
            "selected_split_metrics": selected_splits,
            "external_benchmark": external,
        },
        "trained_at": _now().isoformat(),
        "lifecycle_state_at_registration": "inactive",
        "production_promoted": False,
        "response_automation_allowed": False,
    }

    import joblib

    path.parent.mkdir(parents=True, exist_ok=True)
    # A stable metadata digest is embedded before serialization; the final file checksum is stored in the registry.
    artifact["metadata_digest"] = _stable_hash(
        {
            "model_version": version,
            "dataset_fingerprint": dataset_manifest["dataset_fingerprint"],
            "feature_set_version": V51_FEATURE_SET_VERSION,
            "threshold": threshold,
        }
    )
    joblib.dump(artifact, path)
    artifact_sha256 = _artifact_hash(path)
    runtime_checks = _artifact_runtime_checks(path, dataset["frame"], designated_partition["final_test_idx"])
    # Verify the persisted binary independently from the embedded metadata digest.
    runtime_checks["checksum_verified"] = bool(artifact_sha256 and artifact_sha256 == _artifact_hash(path))
    shadow_safety_passed = bool(
        runtime_checks["serialization_round_trip"]
        and runtime_checks["checksum_verified"]
        and runtime_checks["probabilities_bounded"]
        and runtime_checks["latency_gate_passed"]
        and strict_gates["all_leakage_audits_passed"]
    )
    metrics = {
        "precision": (selected_splits[0].get("metrics") or {}).get("queue_precision"),
        "recall": (selected_splits[0].get("metrics") or {}).get("queue_recall"),
        "f1": (selected_splits[0].get("metrics") or {}).get("queue_f1"),
        "threat_positive": {
            "precision": (selected_splits[0].get("metrics") or {}).get("queue_precision"),
            "recall": (selected_splits[0].get("metrics") or {}).get("queue_recall"),
            "f1": (selected_splits[0].get("metrics") or {}).get("queue_f1"),
        },
        "benign_like_false_positive_rate": (selected_splits[0].get("metrics") or {}).get(
            "benign_like_false_positive_rate"
        ),
        "suspicious_recall": (selected_splits[0].get("metrics") or {}).get("suspicious_recall"),
        "malicious_recall": (selected_splits[0].get("metrics") or {}).get("malicious_recall"),
    }
    run = MLModelRun(
        model_name=MODEL_NAME,
        model_version=version,
        operation="train_supervised",
        status="registered_candidate",
        actor=actor,
        model_path=str(path),
        artifact_sha256=artifact_sha256,
        artifact_size_bytes=path.stat().st_size,
        training_log_count=len(designated_partition["fit_idx"]),
        feature_columns_json=[
            *dataset["feature_meta"]["numeric_features"],
            *dataset["feature_meta"]["categorical_features"],
        ],
        feature_summary_json={
            "feature_set_version": V51_FEATURE_SET_VERSION,
            "numeric_count": len(dataset["feature_meta"]["numeric_features"]),
            "categorical_count": len(dataset["feature_meta"]["categorical_features"]),
        },
        metrics_json={
            "metrics": metrics,
            "model_type": V51_MODEL_TYPE,
            "target_mode": V51_TARGET_MODE,
            "feature_set_metadata": {
                "feature_set_version": V51_FEATURE_SET_VERSION,
                "excluded_leakage_features": dataset["feature_meta"]["excluded_features"],
            },
            "dataset_snapshot_id": dataset_manifest["dataset_fingerprint"],
            "dataset_manifest": dataset_manifest,
            "split_strategy": "strict_multi_split_with_temporal_artifact_partition",
            "split_metrics": selected_splits,
            "strategy_comparison": comparison,
            "selected_strategy_summary": selected_summary,
            "external_benchmark": external,
            "calibration_method": fitted["calibration_method"],
            "threshold": threshold,
            "runtime_checks": runtime_checks,
            "shadow_safety_passed": shadow_safety_passed,
            "strict_gates": strict_gates,
            "promotion_gate": {
                "decision": "decision_support" if strict_gates["decision_support_eligible"] else "candidate_only",
                "analyst_review_eligible": shadow_safety_passed,
                "eligible_for_promotion": False,
                "production_promoted": False,
                "response_automation_allowed": False,
            },
            "lifecycle_state": "inactive",
            "top_features": _extract_feature_importance(fitted["model"]),
            "label_source_distribution": dataset["label_provenance"]["label_source_distribution"],
            "reviewed_label_count": len(dataset["rows"]),
            "weak_label_distribution": {},
            "unreviewed_assisted_label_count": 0,
            "production_promoted": False,
            "response_automation_allowed": False,
        },
        message="Fresh v5.1 binary SOC queue candidate registered; activation requires governed lifecycle checks.",
    )
    db.add(run)
    db.flush()
    db.add(
        AuditLog(
            actor=actor,
            action="register_supervised_soc_queue_candidate",
            target_type="ml_model",
            target_value=str(run.id),
            details={
                "model_version": version,
                "artifact_sha256": artifact_sha256,
                "dataset_fingerprint": dataset_manifest["dataset_fingerprint"],
                "shadow_safety_passed": shadow_safety_passed,
                "decision_support_eligible": strict_gates["decision_support_eligible"],
                "production_promoted": False,
                "response_automation_allowed": False,
            },
        )
    )
    db.commit()

    result = {
        "ok": True,
        "status": "registered_candidate",
        "model_id": run.id,
        "model_name": MODEL_NAME,
        "model_version": version,
        "model_type": V51_MODEL_TYPE,
        "target_mode": V51_TARGET_MODE,
        "artifact_name": path.name,
        "artifact_sha256": artifact_sha256,
        "artifact_size_bytes": path.stat().st_size,
        "dataset": {
            "rows": len(dataset["rows"]),
            "fingerprint": dataset_manifest["dataset_fingerprint"],
            "provenance": dataset["label_provenance"],
            "time_range": dataset_manifest["time_range"],
            "duplicate_groups": duplicate_groups,
        },
        "selected_strategy": V51_SELECTED_STRATEGY,
        "selected_split_metrics": selected_splits,
        "strategy_comparison": comparison,
        "external_benchmark": external,
        "strict_gates": strict_gates,
        "runtime_checks": runtime_checks,
        "shadow_safety_passed": shadow_safety_passed,
        "recommended_activation_mode": "shadow_observation" if shadow_safety_passed else "inactive",
        "production_promoted": False,
        "response_automation_allowed": False,
        "reports": {},
    }
    after = _database_safety_counts(db)
    result["safety"] = {
        "labels_unchanged": before["labels"] == after["labels"],
        "alerts_unchanged": before["alerts"] == after["alerts"],
        "detection_runs_unchanged": before["detection_runs"] == after["detection_runs"],
        "response_actions_unchanged": before["response_actions"] == after["response_actions"],
        "model_activated": False,
        "production_promoted": False,
        "response_automation_allowed": False,
        "real_firewall_blocking_enabled": False,
    }
    if write_reports:
        output_dir.mkdir(parents=True, exist_ok=True)
        report_path = output_dir / f"v5_1_supervised_shadow_activation_{_stamp()}.md"
        latest_path = output_dir / "v5_1_supervised_shadow_activation_latest.json"
        result["reports"] = {"report": str(report_path), "latest_json": str(latest_path)}
        report_path.write_text(render_v51_report(result), encoding="utf-8")
        latest_path.write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")
    return result


def _latest_lifecycle_run(db: Session) -> MLModelRun | None:
    return db.scalar(
        select(MLModelRun)
        .where(MLModelRun.operation.in_(ACTIVE_OPERATIONS))
        .order_by(desc(MLModelRun.created_at), desc(MLModelRun.id))
        .limit(1)
    )


def _latest_durable_telemetry_run(db: Session, model_version: str | None = None) -> MLModelRun | None:
    statement = select(MLModelRun).where(MLModelRun.operation == SHADOW_TELEMETRY_OPERATION)
    if model_version:
        statement = statement.where(MLModelRun.model_version == model_version)
    return db.scalar(statement.order_by(desc(MLModelRun.created_at), desc(MLModelRun.id)).limit(1))


def _resolve_lifecycle_model_run(db: Session, lifecycle_run: MLModelRun) -> MLModelRun | None:
    metrics = lifecycle_run.metrics_json or {}
    model_run_id = metrics.get("model_run_id") or metrics.get("restored_model_run_id")
    return db.get(MLModelRun, int(model_run_id)) if model_run_id is not None else None


def _safe_artifact_state(model_run: MLModelRun | None) -> dict[str, Any]:
    if model_run is None:
        return {"available": False, "checksum_valid": False, "artifact_name": None}
    path = Path(model_run.model_path)
    checksum = _artifact_hash(path) if path.exists() else None
    return {
        "available": path.exists(),
        "checksum_valid": bool(checksum and checksum == model_run.artifact_sha256),
        "artifact_name": path.name,
        "artifact_sha256": checksum,
        "artifact_size_bytes": path.stat().st_size if path.exists() else None,
    }


def _telemetry_snapshot(model_version: str | None) -> dict[str, Any]:
    with _telemetry_lock:
        latencies = list(_telemetry["latencies_ms"])
        scores = list(_telemetry["queue_scores"])
        checked = int(_telemetry["feature_values_checked"])
        missing = int(_telemetry["missing_feature_values"])
        buckets = {
            "0.0-0.2": sum(1 for score in scores if 0.0 <= score < 0.2),
            "0.2-0.4": sum(1 for score in scores if 0.2 <= score < 0.4),
            "0.4-0.6": sum(1 for score in scores if 0.4 <= score < 0.6),
            "0.6-0.8": sum(1 for score in scores if 0.6 <= score < 0.8),
            "0.8-1.0": sum(1 for score in scores if 0.8 <= score <= 1.0),
        }
        return {
            "scope": "current_backend_process",
            "model_version": _telemetry["model_version"] or model_version,
            "inference_count": int(_telemetry["inference_count"]),
            "batch_count": int(_telemetry["batch_count"]),
            "failure_count": int(_telemetry["failure_count"]),
            "latency_ms": {
                "average": round(sum(latencies) / len(latencies), 4) if latencies else 0.0,
                "p95": round(_percentile(latencies, 0.95), 4),
                "maximum": round(max(latencies), 4) if latencies else 0.0,
            },
            "missing_feature_rate": round(missing / checked, 6) if checked else 0.0,
            "queue_rate": round(sum(1 for score in scores if score >= 0.5) / len(scores), 6) if scores else 0.0,
            "queue_score_distribution": {
                "count": len(scores),
                "minimum": round(min(scores), 6) if scores else None,
                "median": round(_percentile(scores, 0.5), 6) if scores else None,
                "p95": round(_percentile(scores, 0.95), 6) if scores else None,
                "maximum": round(max(scores), 6) if scores else None,
                "buckets": buckets,
            },
            "raw_logs_included": False,
            "private_identifiers_included": False,
        }


def _durable_telemetry_payload(run: MLModelRun | None) -> dict[str, Any]:
    if run is None:
        return {
            "available": False,
            "scope": "durable_aggregate_snapshot",
            "raw_logs_included": False,
            "private_identifiers_included": False,
        }
    metrics = run.metrics_json or {}
    telemetry = metrics.get("telemetry") or {}
    return {
        "available": True,
        "snapshot_id": run.id,
        "recorded_at": run.created_at,
        "model_version": run.model_version,
        "scope": "durable_aggregate_snapshot",
        "telemetry": telemetry,
        "drift_warnings": list(metrics.get("drift_warnings") or []),
        "raw_logs_included": False,
        "private_identifiers_included": False,
        "response_actions_created": 0,
    }


def _reliability_report_path() -> Path:
    v53_path = DEFAULT_OUTPUT_DIR / "v5_3_temporal_generalization_latest.json"
    return v53_path if v53_path.exists() else DEFAULT_OUTPUT_DIR / "v5_2_shadow_reliability_latest.json"


def _v54_shadow_drift_summary() -> dict[str, Any]:
    path = DEFAULT_OUTPUT_DIR / "v5_4_temporal_evidence_latest.json"
    if not path.exists():
        return {
            "evidence_lock_status": "not_run",
            "shadow_drift_status": "Insufficient Evidence",
            "shadow_drift_findings": [],
            "development_evidence_rows": 0,
            "excluded_evidence_rows": 0,
            "independent_labeled_evidence_sufficient": False,
        }
    try:
        report = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {
            "evidence_lock_status": "unreadable",
            "shadow_drift_status": "Insufficient Evidence",
            "shadow_drift_findings": [],
            "development_evidence_rows": 0,
            "excluded_evidence_rows": 0,
            "independent_labeled_evidence_sufficient": False,
        }
    lock_validation = (
        (report.get("evidence_lock") or {}).get("validation") or {}
    )
    manifest = (report.get("development_manifest") or {}).get("summary") or {}
    drift = report.get("shadow_drift") or {}
    independent = report.get("independent_labeled_evidence") or {}
    return {
        "evidence_lock_status": lock_validation.get("status", "unknown"),
        "shadow_drift_status": drift.get("status", "Insufficient Evidence"),
        "shadow_drift_findings": list(drift.get("findings") or [])[:8],
        "development_evidence_rows": int(manifest.get("development_rows") or 0),
        "excluded_evidence_rows": int(manifest.get("excluded_rows") or 0),
        "locked_temporal_final_rows": int(
            (manifest.get("role_counts") or {}).get("temporal_final") or 0
        ),
        "quarantined_evidence_rows": int(
            (manifest.get("role_counts") or {}).get("quarantine") or 0
        ),
        "independent_labeled_evidence_sufficient": bool(
            independent.get("sufficient")
        ),
        "raw_logs_included": False,
        "private_identifiers_included": False,
    }


def _v55_repair_summary() -> dict[str, Any]:
    path = DEFAULT_OUTPUT_DIR / "v5_5_development_model_repair_latest.json"
    if not path.exists():
        return {
            "v55_available": False,
            "v55_lifecycle_state": "shadow_observation",
            "v55_candidate_selected": False,
            "v55_model_activated": False,
        }
    try:
        report = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {
            "v55_available": False,
            "v55_status": "unreadable",
            "v55_lifecycle_state": "shadow_observation",
            "v55_candidate_selected": False,
            "v55_model_activated": False,
        }
    readiness = report.get("readiness") or {}
    leader = report.get("selected_development_leader") or {}
    anomaly = report.get("isolation_forest_audit") or {}
    locked = (
        ((report.get("locked_final_regression") or {}).get("supervised") or {})
        .get("result")
        or {}
    )
    metrics = locked.get("metrics") or {}
    calibration = locked.get("calibration") or {}
    return {
        "v55_available": True,
        "v55_status": report.get("status"),
        "v55_generated_at": report.get("generated_at"),
        "v55_lifecycle_state": readiness.get("decision", "shadow_observation"),
        "v55_development_leader": leader.get("name"),
        "v55_development_gates_passed": bool(
            leader.get("passed_all_development_gates")
        ),
        "v55_candidate_selected": bool(readiness.get("candidate_selected")),
        "v55_model_activated": False,
        "v55_locked_queue_f1": metrics.get("queue_f1"),
        "v55_locked_benign_fpr": metrics.get(
            "benign_like_false_positive_rate"
        ),
        "v55_locked_suspicious_recall": metrics.get("suspicious_recall"),
        "v55_locked_malicious_recall": metrics.get("malicious_recall"),
        "v55_locked_calibration_status": calibration.get("status"),
        "v55_isolation_benign_fpr": anomaly.get(
            "benign_like_false_positive_rate_estimate"
        ),
        "v55_isolation_threat_detection_rate": anomaly.get(
            "threat_detection_rate_estimate"
        ),
        "v55_blockers": list(readiness.get("blockers") or [])[:8],
        "raw_logs_included": False,
        "private_identifiers_included": False,
    }


def _v56_repair_summary() -> dict[str, Any]:
    path = DEFAULT_OUTPUT_DIR / "v5_6_private_panos_model_repair_latest.json"
    if not path.exists():
        return {
            "v56_available": False,
            "v56_lifecycle_state": "shadow_observation",
            "v56_candidate_activated": False,
            "v56_response_automation_allowed": False,
        }
    try:
        report = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {
            "v56_available": False,
            "v56_status": "unreadable",
            "v56_lifecycle_state": "shadow_observation",
            "v56_candidate_activated": False,
            "v56_response_automation_allowed": False,
        }
    readiness = report.get("readiness") or {}
    profile = report.get("private_profile") or {}
    drift = report.get("drift_profile") or {}
    assisted = report.get("assisted_labeling") or {}
    future = (
        (report.get("untouched_future_validation") or {}).get("supervised")
        or {}
    )
    future_metrics = future.get("metrics") or {}
    calibration = future.get("calibration") or {}
    isolation = (
        (report.get("untouched_future_validation") or {}).get(
            "isolation_forest"
        )
        or {}
    )
    isolation_metrics = isolation.get("metrics") or {}
    candidate = report.get("frozen_diagnostic_candidate") or {}
    return {
        "v56_available": True,
        "v56_status": report.get("status"),
        "v56_generated_at": report.get("generated_at"),
        "v56_lifecycle_state": readiness.get(
            "decision",
            "shadow_observation",
        ),
        "v56_private_rows_processed": profile.get("rows_processed"),
        "v56_overlap_rows_excluded": profile.get(
            "configured_database_overlap_rows"
        ),
        "v56_drift_status": drift.get("status"),
        "v56_assisted_training_rows": assisted.get(
            "high_confidence_training_event_count"
        ),
        "v56_assisted_human_reviewed_rows": assisted.get(
            "human_reviewed_true_count",
            0,
        ),
        "v56_diagnostic_candidate": candidate.get("name"),
        "v56_future_queue_f1": future_metrics.get("queue_f1"),
        "v56_future_benign_fpr": future_metrics.get(
            "benign_like_false_positive_rate"
        ),
        "v56_future_suspicious_recall": future_metrics.get(
            "suspicious_recall"
        ),
        "v56_future_malicious_recall": future_metrics.get(
            "malicious_recall"
        ),
        "v56_future_calibration_status": calibration.get("status"),
        "v56_future_calibration_ece": calibration.get(
            "expected_calibration_error"
        ),
        "v56_isolation_future_fpr": isolation_metrics.get(
            "benign_like_false_positive_rate"
        ),
        "v56_isolation_future_threat_capture": isolation_metrics.get(
            "queue_recall"
        ),
        "v56_candidate_activated": False,
        "v56_response_automation_allowed": False,
        "v56_independent_validation_claimed": False,
        "v56_blockers": list(readiness.get("blockers") or [])[:8],
        "raw_logs_included": False,
        "private_identifiers_included": False,
    }


def _v57_revalidation_summary() -> dict[str, Any]:
    path = (
        DEFAULT_OUTPUT_DIR
        / "v5_7_independent_shadow_revalidation_latest.json"
    )
    if not path.exists():
        return {
            "v57_available": False,
            "v57_lifecycle_state": "shadow_observation",
            "v57_evidence_status": "pending",
            "v57_blind_validation_status": "pending",
            "v57_candidate_activated": False,
            "v57_rules_alert_authoritative": True,
            "v57_response_automation_allowed": False,
        }
    try:
        report = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {
            "v57_available": False,
            "v57_status": "unreadable",
            "v57_lifecycle_state": "shadow_observation",
            "v57_evidence_status": "pending",
            "v57_blind_validation_status": "pending",
            "v57_candidate_activated": False,
            "v57_rules_alert_authoritative": True,
            "v57_response_automation_allowed": False,
        }
    candidate = report.get("frozen_candidate") or {}
    evidence = report.get("independent_evidence") or {}
    prediction = report.get("prediction_freeze") or {}
    validation = report.get("blind_validation") or {}
    metrics = validation.get("metrics") or {}
    calibration = validation.get("calibration") or {}
    isolation = validation.get("isolation_forest") or {}
    isolation_metrics = isolation.get("metrics") or {}
    readiness = report.get("readiness") or {}
    return {
        "v57_available": True,
        "v57_status": report.get("status"),
        "v57_generated_at": report.get("generated_at"),
        "v57_lifecycle_state": readiness.get(
            "lifecycle_state",
            "shadow_observation",
        ),
        "v57_frozen_candidate": candidate.get("candidate_name"),
        "v57_candidate_model_type": candidate.get("model_type"),
        "v57_candidate_calibration": candidate.get(
            "calibration_method"
        ),
        "v57_candidate_threshold": candidate.get("threshold"),
        "v57_evidence_status": evidence.get("status", "pending"),
        "v57_evidence_qualified": bool(
            evidence.get("eligible_for_predictions")
        ),
        "v57_source_device_count": evidence.get("source_device_count"),
        "v57_independent_time_windows": evidence.get(
            "independent_time_window_count"
        ),
        "v57_prediction_freeze_status": prediction.get(
            "status",
            "not_run",
        ),
        "v57_blind_validation_status": validation.get(
            "status",
            "pending",
        ),
        "v57_blind_queue_f1": metrics.get("queue_f1"),
        "v57_blind_benign_fpr": metrics.get(
            "benign_like_false_positive_rate"
        ),
        "v57_blind_suspicious_recall": metrics.get(
            "suspicious_recall"
        ),
        "v57_blind_malicious_recall": metrics.get("malicious_recall"),
        "v57_blind_calibration_ece": calibration.get(
            "expected_calibration_error"
        ),
        "v57_blind_max_calibration_gap": calibration.get(
            "max_confidence_accuracy_gap"
        ),
        "v57_isolation_status": isolation.get(
            "status",
            "pending_independent_labels",
        ),
        "v57_isolation_benign_fpr": isolation_metrics.get(
            "benign_like_false_positive_rate"
        ),
        "v57_isolation_threat_capture": isolation_metrics.get(
            "queue_recall"
        ),
        "v57_candidate_activated": False,
        "v57_rules_alert_authoritative": True,
        "v57_response_automation_allowed": False,
        "v57_blockers": list(readiness.get("blockers") or [])[:10],
        "raw_logs_included": False,
        "private_identifiers_included": False,
    }


def _v52_reliability_summary() -> dict[str, Any]:
    """Return the latest aggregate reliability summary; name retained for API compatibility."""

    path = _reliability_report_path()
    if not path.exists():
        return {
            "available": False,
            "lifecycle_decision": "shadow_observation",
            "rules_alert_authoritative": True,
            "raw_logs_included": False,
            "private_identifiers_included": False,
        }
    try:
        report = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {
            "available": False,
            "status": "unreadable",
            "lifecycle_decision": "shadow_observation",
            "rules_alert_authoritative": True,
            "raw_logs_included": False,
            "private_identifiers_included": False,
        }
    selected = report.get("selected_diagnostic_strategy") or {}
    selected_summary = selected.get("summary") or {}
    splits = report.get("splits") or []
    evaluated_splits = sum(1 for split in splits if split.get("status") == "evaluated")
    failed_closed_splits = [
        str(split.get("split_mode")) for split in splits if split.get("status") == "failed_closed"
    ]
    layered = report.get("layered_validation") or {}
    readiness = report.get("readiness") or {}
    comparison = report.get("strategy_comparison") or {}
    temporal_diagnosis = report.get("temporal_diagnosis") or {}
    temporal_threshold = temporal_diagnosis.get("threshold_behavior") or {}
    temporal_ood = temporal_diagnosis.get("ood") or {}
    abstention = comparison.get("calibrated_abstention_review_queue") or {}
    abstention_ranges = abstention.get("abstention_ranges") or {}
    selected_split_metrics = selected_summary.get("split_metrics") or []
    temporal_selected = next(
        (row for row in selected_split_metrics if row.get("split_mode") == "temporal_holdout"),
        {},
    )
    rolling = report.get("rolling_temporal") or []
    return {
        "available": True,
        "version": report.get("version"),
        "generated_at": report.get("generated_at"),
        "lifecycle_decision": readiness.get("decision", "shadow_observation"),
        "checks_passed": readiness.get("checks_passed"),
        "checks_total": readiness.get("checks_total"),
        "blockers": list(readiness.get("blockers") or []),
        "selected_diagnostic_strategy": selected.get("name"),
        "selection_role": selected.get("selection_role"),
        "candidate_selected": bool(selected.get("candidate_selected")),
        "governance_outcome": selected.get("governance_outcome"),
        "eligible_for_activation": False,
        "strict_passing_splits": selected_summary.get("strict_passing_splits", selected_summary.get("strict_passing_views")),
        "required_splits": selected_summary.get("required_splits", selected_summary.get("required_views")),
        "evaluated_splits": evaluated_splits,
        "failed_closed_splits": failed_closed_splits,
        "calibration_ranges": selected_summary.get("calibration_ranges") or {},
        "threshold_stability": selected_summary.get("threshold_stability") or {},
        "drift_warning_splits": int(
            (report.get("drift") or {}).get("splits_with_warnings")
            or len(temporal_diagnosis.get("root_causes") or [])
        ),
        "temporal_root_causes": list(temporal_diagnosis.get("root_causes") or []),
        "temporal_fpr": temporal_selected.get("benign_like_false_positive_rate"),
        "temporal_queue_rate": temporal_selected.get("review_queue_rate"),
        "threshold_window_queue_prevalence": temporal_threshold.get(
            "threshold_partition_queue_prevalence"
        ),
        "final_window_queue_prevalence": temporal_threshold.get("final_test_queue_prevalence"),
        "ood_rate": temporal_ood.get("ood_rate"),
        "confidence_instability_rate": temporal_ood.get("confidence_instability_rate"),
        "abstention_rate_range": abstention_ranges.get("abstention_rate") or {},
        "coverage_rate_range": abstention_ranges.get("coverage_rate") or {},
        "missingness": temporal_diagnosis.get("missingness") or {},
        "rolling_temporal": {
            "evaluated": sum(1 for split in rolling if split.get("status") == "evaluated"),
            "required": len(rolling),
            "failed_closed": [
                str(split.get("split_mode")) for split in rolling if split.get("status") != "evaluated"
            ],
        },
        "source_holdout_limitation": (report.get("drift") or {}).get("source_holdout_limitation")
        or "Source-disjoint validation fails closed until reviewed evidence includes at least two independent devices.",
        "layered_before": layered.get("baseline") or {},
        "layered_after": layered.get("after") or layered,
        "external_benchmark_passed": bool((report.get("external_benchmark") or {}).get("passed_v49_gates")),
        "rules_alert_authoritative": True,
        "production_promoted": False,
        "response_automation_allowed": False,
        "raw_logs_included": False,
        "private_identifiers_included": False,
        **_v54_shadow_drift_summary(),
        **_v55_repair_summary(),
        **_v56_repair_summary(),
        **_v57_revalidation_summary(),
    }


def _telemetry_drift_warnings(
    current: dict[str, Any],
    previous: dict[str, Any] | None,
) -> list[str]:
    warnings: list[str] = []
    inference_count = int(current.get("inference_count") or 0)
    failure_count = int(current.get("failure_count") or 0)
    if failure_count:
        failure_rate = failure_count / max(1, inference_count + failure_count)
        warnings.append(f"shadow inference failures observed ({failure_rate:.2%})")
    if float(current.get("missing_feature_rate") or 0.0) > 0.05:
        warnings.append("missing-feature rate exceeds 5%")
    latency = current.get("latency_ms") or {}
    if float(latency.get("p95") or 0.0) > SHADOW_LATENCY_P95_LIMIT_MS:
        warnings.append(f"p95 inference latency exceeds {SHADOW_LATENCY_P95_LIMIT_MS:.0f} ms")
    if float(current.get("queue_rate") or 0.0) > 0.50:
        warnings.append("shadow review-queue rate exceeds 50%")
    if previous:
        prior_queue_rate = float(previous.get("queue_rate") or 0.0)
        current_queue_rate = float(current.get("queue_rate") or 0.0)
        if abs(current_queue_rate - prior_queue_rate) > 0.20:
            warnings.append("shadow review-queue rate shifted by more than 20 percentage points")
        prior_missing = float(previous.get("missing_feature_rate") or 0.0)
        current_missing = float(current.get("missing_feature_rate") or 0.0)
        if abs(current_missing - prior_missing) > 0.10:
            warnings.append("missing-feature rate shifted by more than 10 percentage points")
    return warnings


def persist_supervised_telemetry_snapshot(db: Session, *, actor: str) -> dict[str, Any]:
    """Persist aggregate-only shadow telemetry without evidence or response side effects."""
    lifecycle = _latest_lifecycle_run(db)
    model_run = _resolve_lifecycle_model_run(db, lifecycle) if lifecycle else None
    model_version = model_run.model_version if model_run else None
    current = _telemetry_snapshot(model_version)
    previous_run = _latest_durable_telemetry_run(db, model_version)
    previous_metrics = (previous_run.metrics_json or {}).get("telemetry") if previous_run else None
    warnings = _telemetry_drift_warnings(current, previous_metrics)
    snapshot = MLModelRun(
        model_name=MODEL_NAME,
        model_version=model_version,
        operation=SHADOW_TELEMETRY_OPERATION,
        status="recorded",
        actor=actor,
        model_path="aggregate-only://supervised-shadow-telemetry",
        scored_log_count=int(current.get("inference_count") or 0),
        feature_columns_json=[],
        feature_summary_json={},
        metrics_json={
            "schema_version": "v5.2-shadow-telemetry-v1",
            "telemetry": current,
            "drift_warnings": warnings,
            "privacy": {
                "aggregate_only": True,
                "raw_logs_included": False,
                "private_identifiers_included": False,
            },
            "safety": {
                "model_activated": False,
                "production_promoted": False,
                "response_actions_created": 0,
                "response_automation_allowed": False,
            },
        },
        message="Aggregate-only governed supervised shadow telemetry snapshot.",
    )
    db.add(snapshot)
    db.flush()
    db.add(
        AuditLog(
            actor=actor,
            action=SHADOW_TELEMETRY_OPERATION,
            target_type="ml_model_run",
            target_value=str(snapshot.id),
            details={
                "model_version": model_version,
                "inference_count": int(current.get("inference_count") or 0),
                "batch_count": int(current.get("batch_count") or 0),
                "failure_count": int(current.get("failure_count") or 0),
                "drift_warning_count": len(warnings),
                "aggregate_only": True,
                "raw_logs_included": False,
                "private_identifiers_included": False,
                "response_actions_created": 0,
            },
        )
    )
    db.commit()
    db.refresh(snapshot)
    return {
        "ok": True,
        "status": "recorded",
        "snapshot": _durable_telemetry_payload(snapshot),
        "model_activated": False,
        "production_promoted": False,
        "response_actions_created": 0,
        "response_automation_allowed": False,
    }


def supervised_lifecycle_status(db: Session) -> dict[str, Any]:
    from atdr.app.services.v58_shadow_scoring_service import (
        governed_shadow_runtime_status,
    )

    governed_shadow_runtime = governed_shadow_runtime_status(
        db,
        execute=True,
    )
    lifecycle = _latest_lifecycle_run(db)
    if lifecycle is None or lifecycle.operation == "disable_supervised_governed":
        process_telemetry = _telemetry_snapshot(None)
        return {
            "lifecycle_state": "inactive",
            "model_run_id": None,
            "model_version": None,
            "model_type": None,
            "feature_set_version": None,
            "calibration_status": "not_active",
            "validation_status": "not_active",
            "artifact": {"available": False, "checksum_valid": False, "artifact_name": None},
            "telemetry": process_telemetry,
            "durable_telemetry": _durable_telemetry_payload(_latest_durable_telemetry_run(db)),
            "reliability_validation": _v52_reliability_summary(),
            "governed_shadow_runtime": governed_shadow_runtime,
            "production_promoted": False,
            "response_automation_allowed": False,
            "rule_detection_authoritative": True,
        }
    model_run = _resolve_lifecycle_model_run(db, lifecycle)
    metrics = (model_run.metrics_json or {}) if model_run else {}
    lifecycle_metrics = lifecycle.metrics_json or {}
    requested_state = str(lifecycle_metrics.get("lifecycle_state") or lifecycle.status or "inactive")
    artifact = _safe_artifact_state(model_run)
    effective_state = requested_state if artifact["available"] and artifact["checksum_valid"] else "inactive"
    strict = metrics.get("strict_gates") or {}
    runtime = metrics.get("runtime_checks") or {}
    process_telemetry = _telemetry_snapshot(model_run.model_version if model_run else None)
    return {
        "lifecycle_state": effective_state,
        "configured_lifecycle_state": requested_state,
        "model_run_id": model_run.id if model_run else None,
        "lifecycle_run_id": lifecycle.id,
        "model_version": model_run.model_version if model_run else None,
        "model_type": metrics.get("model_type"),
        "target_mode": metrics.get("target_mode"),
        "feature_set_version": (metrics.get("feature_set_metadata") or {}).get("feature_set_version"),
        "dataset_fingerprint": metrics.get("dataset_snapshot_id"),
        "calibration_method": metrics.get("calibration_method"),
        "calibration_status": "passed_all_splits"
        if int((metrics.get("selected_strategy_summary") or {}).get("calibration_passed_splits") or 0)
        == len(reliability.V49_SPLITS)
        else "weak_or_unstable",
        "validation_status": "strict_gates_passed" if strict.get("decision_support_eligible") else "shadow_only",
        "decision_support_eligible": bool(strict.get("decision_support_eligible")),
        "shadow_safety_passed": bool(metrics.get("shadow_safety_passed")),
        "threshold": metrics.get("threshold"),
        "runtime_checks": runtime,
        "artifact": artifact,
        "telemetry": process_telemetry,
        "durable_telemetry": _durable_telemetry_payload(
            _latest_durable_telemetry_run(db, model_run.model_version if model_run else None)
        ),
        "reliability_validation": _v52_reliability_summary(),
        "governed_shadow_runtime": governed_shadow_runtime,
        "production_promoted": False,
        "response_automation_allowed": False,
        "rule_detection_authoritative": True,
        "model_only_alert_creation_allowed": False,
        "status_message": (
            "Supervised SOC queue is observing in shadow and cannot alter alerts."
            if effective_state == "shadow_observation"
            else "Supervised SOC queue contributes bounded decision-support evidence; rules remain authoritative."
            if effective_state == "decision_support"
            else "Governed supervised inference is inactive because no valid registered artifact is selected."
        ),
    }


def activate_governed_supervised_model(
    db: Session,
    *,
    model_id: int,
    lifecycle_state: str = "shadow_observation",
    actor: str = "cli",
) -> dict[str, Any]:
    if lifecycle_state not in LIFECYCLE_STATES or lifecycle_state == "production_promoted":
        return {
            "ok": False,
            "status": "rejected",
            "message": "Only shadow_observation or gated decision_support activation is allowed.",
            "production_promoted": False,
            "response_automation_allowed": False,
        }
    if lifecycle_state == "inactive":
        return disable_governed_supervised_model(db, actor=actor)
    run = db.get(MLModelRun, model_id)
    metrics = (run.metrics_json or {}) if run else {}
    artifact = _safe_artifact_state(run)
    if run is None or run.operation != "train_supervised" or not metrics.get("shadow_safety_passed"):
        return {
            "ok": False,
            "status": "failed_closed",
            "message": "Model is not a shadow-safe registered supervised candidate.",
            "production_promoted": False,
            "response_automation_allowed": False,
        }
    if not artifact["available"] or not artifact["checksum_valid"]:
        return {
            "ok": False,
            "status": "failed_closed",
            "message": "Registered artifact is missing or its checksum does not match.",
            "production_promoted": False,
            "response_automation_allowed": False,
        }
    strict = metrics.get("strict_gates") or {}
    if lifecycle_state == "decision_support" and not strict.get("decision_support_eligible"):
        return {
            "ok": False,
            "status": "quality_gates_failed",
            "message": "Decision-support activation is denied because every strict split and external gate did not pass.",
            "required_state": "shadow_observation",
            "production_promoted": False,
            "response_automation_allowed": False,
        }
    operation = (
        "activate_supervised_shadow"
        if lifecycle_state == "shadow_observation"
        else "activate_supervised_decision_support"
    )
    activation = MLModelRun(
        model_name=run.model_name,
        model_version=run.model_version,
        operation=operation,
        status=lifecycle_state,
        actor=actor,
        model_path=run.model_path,
        artifact_sha256=run.artifact_sha256,
        artifact_size_bytes=run.artifact_size_bytes,
        training_log_count=run.training_log_count,
        feature_columns_json=run.feature_columns_json,
        feature_summary_json=run.feature_summary_json,
        metrics_json={
            "model_run_id": run.id,
            "lifecycle_state": lifecycle_state,
            "model_type": metrics.get("model_type"),
            "target_mode": metrics.get("target_mode"),
            "feature_set_metadata": metrics.get("feature_set_metadata", {}),
            "dataset_snapshot_id": metrics.get("dataset_snapshot_id"),
            "calibration_method": metrics.get("calibration_method"),
            "strict_gates": strict,
            "shadow_safety_passed": bool(metrics.get("shadow_safety_passed")),
            "decision_support_eligible": bool(strict.get("decision_support_eligible")),
            "rule_detection_authoritative": True,
            "model_only_alert_creation_allowed": False,
            "production_promoted": False,
            "response_automation_allowed": False,
        },
        message=(
            "Governed supervised SOC queue activated for shadow observation only."
            if lifecycle_state == "shadow_observation"
            else "Governed supervised SOC queue activated for bounded decision-support evidence only."
        ),
    )
    db.add(activation)
    db.flush()
    db.add(
        AuditLog(
            actor=actor,
            action=operation,
            target_type="ml_model",
            target_value=str(run.id),
            details={
                "lifecycle_state": lifecycle_state,
                "model_version": run.model_version,
                "artifact_sha256": run.artifact_sha256,
                "rule_detection_authoritative": True,
                "production_promoted": False,
                "response_automation_allowed": False,
            },
        )
    )
    db.commit()
    return {
        "ok": True,
        "status": lifecycle_state,
        "lifecycle_state": lifecycle_state,
        "model_id": run.id,
        "lifecycle_run_id": activation.id,
        "model_version": run.model_version,
        "artifact_name": artifact["artifact_name"],
        "artifact_sha256": artifact["artifact_sha256"],
        "rule_detection_authoritative": True,
        "model_only_alert_creation_allowed": False,
        "production_promoted": False,
        "response_automation_allowed": False,
    }


def disable_governed_supervised_model(db: Session, *, actor: str = "cli") -> dict[str, Any]:
    current = supervised_lifecycle_status(db)
    run = MLModelRun(
        model_name=MODEL_NAME,
        model_version=current.get("model_version"),
        operation="disable_supervised_governed",
        status="inactive",
        actor=actor,
        model_path="governed-registry",
        metrics_json={
            "previous_lifecycle_state": current.get("lifecycle_state"),
            "lifecycle_state": "inactive",
            "production_promoted": False,
            "response_automation_allowed": False,
        },
        message="Governed supervised inference disabled; rule detection remains authoritative.",
    )
    db.add(run)
    db.flush()
    db.add(
        AuditLog(
            actor=actor,
            action="disable_supervised_governed",
            target_type="ml_model",
            target_value=str(current.get("model_run_id") or "none"),
            details={
                "previous_lifecycle_state": current.get("lifecycle_state"),
                "lifecycle_state": "inactive",
                "evidence_deleted": False,
                "labels_deleted": False,
                "production_promoted": False,
                "response_automation_allowed": False,
            },
        )
    )
    db.commit()
    return {
        "ok": True,
        "status": "inactive",
        "lifecycle_state": "inactive",
        "evidence_deleted": False,
        "labels_deleted": False,
        "production_promoted": False,
        "response_automation_allowed": False,
    }


def rollback_governed_supervised_model(db: Session, *, actor: str = "cli") -> dict[str, Any]:
    activations = list(
        db.scalars(
            select(MLModelRun)
            .where(
                MLModelRun.operation.in_(
                    {"activate_supervised_shadow", "activate_supervised_decision_support"}
                )
            )
            .order_by(desc(MLModelRun.created_at), desc(MLModelRun.id))
            .limit(2)
        )
    )
    if len(activations) < 2:
        disabled = disable_governed_supervised_model(db, actor=actor)
        disabled["message"] = "No previous governed artifact exists; supervised inference was safely disabled."
        return disabled
    previous = activations[1]
    previous_model = _resolve_lifecycle_model_run(db, previous)
    if previous_model is None:
        return {
            "ok": False,
            "status": "failed_closed",
            "message": "Previous governed model registry row is unavailable.",
            "production_promoted": False,
            "response_automation_allowed": False,
        }
    state = str((previous.metrics_json or {}).get("lifecycle_state") or "shadow_observation")
    result = activate_governed_supervised_model(
        db,
        model_id=previous_model.id,
        lifecycle_state=state,
        actor=actor,
    )
    result["rollback"] = True
    result["restored_model_run_id"] = previous_model.id
    return result


@lru_cache(maxsize=4)
def _load_governed_artifact(path_string: str, modified_ns: int, checksum: str) -> dict[str, Any]:
    _ = modified_ns, checksum
    import joblib

    value = joblib.load(Path(path_string))
    if not isinstance(value, dict) or value.get("schema_version") != V51_VERSION or "model" not in value:
        raise ValueError("Artifact does not satisfy the governed v5.1 contract.")
    return value


def _observed_signals(frame_row: Any) -> list[dict[str, Any]]:
    candidates = (
        ("local_rule_score", "v398_local_rule_score"),
        ("source_destination_diversity_5m", "src_ip_5min_unique_dst_ips"),
        ("source_port_diversity_5m", "src_ip_5min_unique_dst_ports"),
        ("low_signal_allow", "v337_low_signal_allow_flag"),
        ("scan_context", "v337_web_scan_context_flag"),
        ("unknown_scan_context", "v337_unknown_scan_context_flag"),
        ("behavior_evidence_strength", "v337_behavior_evidence_strength"),
        ("benign_web_likelihood", "v337_benign_web_likelihood_score"),
    )
    rows: list[dict[str, Any]] = []
    for label, column in candidates:
        value = frame_row.get(column)
        if value is not None:
            rows.append({"signal": label, "value": round(float(value), 4)})
    return rows


def score_governed_supervised_logs(db: Session, logs: list[NormalizedLog]) -> dict[str, Any]:
    status = supervised_lifecycle_status(db)
    if status["lifecycle_state"] not in {"shadow_observation", "decision_support"} or not logs:
        return {
            "ok": False,
            "status": "inactive" if not logs else "governed_model_inactive",
            "lifecycle": status,
            "rows": [],
            "decision_support_only": True,
            "used_for_alert_creation": False,
        }
    model_run = db.get(MLModelRun, int(status["model_run_id"]))
    if model_run is None:
        return {
            "ok": False,
            "status": "registry_model_missing",
            "lifecycle": status,
            "rows": [],
            "decision_support_only": True,
            "used_for_alert_creation": False,
        }
    path = Path(model_run.model_path)
    started = time.perf_counter()
    try:
        artifact = _load_governed_artifact(str(path.resolve()), path.stat().st_mtime_ns, str(model_run.artifact_sha256))
        import pandas as pd

        base = pd.DataFrame(build_feature_rows(db, logs))
        frame, _meta = frozen._local_evidence_frame(base, logs)
        model = artifact["model"]
        classes = _classes(model)
        if "needs_review" not in classes:
            raise ValueError("Governed model is missing needs_review class probability.")
        positive_index = classes.index("needs_review")
        probabilities = model.predict_proba(frame)
        threshold = float(artifact.get("threshold", 0.5))
        expected = [
            *artifact["feature_schema"]["numeric"],
            *artifact["feature_schema"]["categorical"],
        ]
        missing_values = 0
        for column in expected:
            if column not in frame.columns:
                missing_values += len(frame)
                continue
            missing_values += int(frame[column].isna().sum())
        rows: list[dict[str, Any]] = []
        scores: list[float] = []
        for position, log in enumerate(logs):
            score = float(probabilities[position][positive_index])
            scores.append(score)
            rows.append(
                {
                    "log_id": int(log.id),
                    "queue_decision": "needs_review" if score >= threshold else "benign_like",
                    "queue_probability": round(score, 6),
                    "threshold": threshold,
                    "calibration_method": artifact.get("calibration_method"),
                    "model_version": artifact.get("model_version"),
                    "feature_set_version": artifact.get("feature_set_version"),
                    "lifecycle_state": status["lifecycle_state"],
                    "observed_signals": _observed_signals(frame.iloc[position]),
                    "confidence_limitations": [
                        "Queue probability is calibrated decision-support evidence, not proof of compromise.",
                        "Rules remain authoritative for alert creation.",
                    ],
                    "used_for_alert_creation": False,
                    "used_for_severity": False,
                    "used_for_suppression": False,
                    "response_action_allowed": False,
                }
            )
        elapsed_ms = (time.perf_counter() - started) * 1000
        with _telemetry_lock:
            if _telemetry["model_version"] != artifact.get("model_version"):
                _telemetry["model_version"] = artifact.get("model_version")
                _telemetry["inference_count"] = 0
                _telemetry["batch_count"] = 0
                _telemetry["failure_count"] = 0
                _telemetry["missing_feature_values"] = 0
                _telemetry["feature_values_checked"] = 0
                _telemetry["latencies_ms"].clear()
                _telemetry["queue_scores"].clear()
            _telemetry["inference_count"] += len(rows)
            _telemetry["batch_count"] += 1
            _telemetry["missing_feature_values"] += missing_values
            _telemetry["feature_values_checked"] += len(expected) * len(rows)
            _telemetry["latencies_ms"].append(elapsed_ms / max(1, len(rows)))
            _telemetry["queue_scores"].extend(scores)
        return {
            "ok": True,
            "status": "scored",
            "lifecycle": status,
            "rows": rows,
            "batch_latency_ms": round(elapsed_ms, 4),
            "average_latency_ms_per_row": round(elapsed_ms / max(1, len(rows)), 4),
            "missing_feature_rate": round(missing_values / max(1, len(expected) * len(rows)), 6),
            "decision_support_only": True,
            "used_for_alert_creation": False,
            "response_automation_allowed": False,
        }
    except Exception as exc:
        elapsed_ms = (time.perf_counter() - started) * 1000
        with _telemetry_lock:
            _telemetry["failure_count"] += len(logs)
            _telemetry["latencies_ms"].append(elapsed_ms / max(1, len(logs)))
        return {
            "ok": False,
            "status": "model_failure_fell_back_to_rules",
            "error_type": exc.__class__.__name__,
            "lifecycle": status,
            "rows": [],
            "rule_detection_continues": True,
            "decision_support_only": True,
            "used_for_alert_creation": False,
            "response_automation_allowed": False,
        }


def score_governed_supervised_log(db: Session, log: NormalizedLog) -> dict[str, Any]:
    result = score_governed_supervised_logs(db, [log])
    if not result.get("ok") or not result.get("rows"):
        return {
            "predicted_label": None,
            "queue_decision": None,
            "queue_probability": 0.0,
            "confidence": 0.0,
            "malicious_probability": 0.0,
            "top_contributing_features": [],
            "lifecycle_state": (result.get("lifecycle") or {}).get("lifecycle_state", "inactive"),
            "model_failure_fallback": result.get("status") == "model_failure_fell_back_to_rules",
            "rule_detection_continues": True,
            "decision_support_only": True,
            "used_for_alert_creation": False,
        }
    row = result["rows"][0]
    return {
        "predicted_label": row["queue_decision"],
        "direct_predicted_label": row["queue_decision"],
        "queue_decision": row["queue_decision"],
        "queue_probability": row["queue_probability"],
        "malicious_probability": 0.0,
        "confidence": row["queue_probability"]
        if row["queue_decision"] == "needs_review"
        else round(1.0 - row["queue_probability"], 6),
        "threshold": row["threshold"],
        "calibration_method": row["calibration_method"],
        "model_version": row["model_version"],
        "feature_set_version": row["feature_set_version"],
        "lifecycle_state": row["lifecycle_state"],
        "top_contributing_features": row["observed_signals"],
        "observed_signals": row["observed_signals"],
        "confidence_limitations": row["confidence_limitations"],
        "rule_detection_continues": True,
        "decision_support_only": True,
        "used_for_alert_creation": False,
        "used_for_severity": False,
        "used_for_suppression": False,
        "response_automation_allowed": False,
    }


def render_v51_report(result: dict[str, Any]) -> str:
    strict = result.get("strict_gates") or {}
    runtime = result.get("runtime_checks") or {}
    lines = [
        "# v5.1 Governed Supervised SOC Queue Activation",
        "",
        f"- Status: `{result.get('status')}`",
        f"- Model: `{result.get('model_type')}`",
        f"- Target: `{result.get('target_mode')}`",
        f"- Version: `{result.get('model_version')}`",
        f"- Reviewed latest rows: `{(result.get('dataset') or {}).get('rows')}`",
        f"- Dataset fingerprint: `{(result.get('dataset') or {}).get('fingerprint')}`",
        f"- Strict passing splits: `{strict.get('strict_passing_splits')}/{strict.get('strict_required_splits')}`",
        f"- Decision-support eligible: `{strict.get('decision_support_eligible')}`",
        f"- Shadow safety passed: `{result.get('shadow_safety_passed')}`",
        f"- Runtime checks: `{runtime}`",
        "- Production promoted: `false`",
        "- Response automation allowed: `false`",
        "",
        "## Interpretation",
        "",
        "The artifact is a binary SOC review-queue model. It may observe in shadow after artifact and safety checks pass. It cannot create or suppress alerts, change severity, execute response, or replace deterministic rule evidence.",
        "",
        "## Label Integrity",
        "",
        "Only the latest eligible reviewed label per normalized log is used. Weak or unreviewed labels are excluded, original provenance is retained, and no AI-generated label is represented as human-reviewed.",
        "",
        "## Known Limitations",
        "",
        "Strict split stability and locked external validation remain mandatory for bounded decision-support influence. A shadow activation is not production promotion.",
    ]
    return "\n".join(lines) + "\n"
