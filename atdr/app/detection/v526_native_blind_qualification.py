from __future__ import annotations

import csv
import json
import sqlite3
import tempfile
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from statistics import mean
from typing import Any

from sqlalchemy.orm import Session

from atdr.app.core.config import PROJECT_ROOT
from atdr.app.detection import hybrid_scoring
from atdr.app.detection import v398_independent_holdout_validation as frozen
from atdr.app.detection import v52_shadow_reliability as v52
from atdr.app.detection import v54_temporal_evidence as v54
from atdr.app.detection import v55_development_model_repair as v55
from atdr.app.detection import v56_private_panos_model_repair as v56
from atdr.app.detection import v521_native_panos_evidence as v521
from atdr.app.detection import v522_supervised_model_rebuild as v522


V526_VERSION = "v5.26-native-panos-blind-qualification-v1"
V526_OUTPUT_DIR = PROJECT_ROOT / "ml_baseline_reviews"
V526_LATEST = "v5_26_native_blind_qualification_latest.json"
V526_REPORT_PREFIX = "v5_26_native_blind_qualification_"
V526_PREDICTION_LOCK = "v5_26_native_blind_prediction_lock.json"
V526_PRELOCK_RECORD = "v5_26_initial_prelock_protocol_record.json"
MIN_HUMAN_BLIND_LABELS = 20
VALID_DECISIONS = {
    "benign",
    "benign_unusual",
    "needs_context",
    "suspicious",
    "malicious",
}
LABEL_FIELDS = {
    "human_decision",
    "human_attack_type",
    "human_confidence",
    "human_notes",
    "human_reviewer",
    "human_reviewed_at",
    "human_reviewed",
}
ASSISTED_FIELDS = {
    "assisted_suggestion",
    "assisted_attack_type",
    "assisted_confidence",
    "assisted_reason",
    "assisted_provenance",
    "rule_codes",
    "rule_score",
}


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _safe_failure(status: str, message: str) -> dict[str, Any]:
    return {
        "ok": False,
        "status": status,
        "message": message,
        "version": V526_VERSION,
        "lifecycle_state": "shadow_observation",
        "path_returned": False,
        "raw_evidence_returned": False,
        "private_identifiers_returned": False,
        "fingerprints_returned": False,
        "blind_labels_used_for_selection": False,
        "model_activated": False,
        "model_promoted": False,
        "response_automation_allowed": False,
    }


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def _boolean(value: Any) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes"}


def _integer(value: Any, default: int = 0) -> int:
    try:
        return int(float(str(value)))
    except (TypeError, ValueError):
        return default


def _number(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _nullable_integer(value: Any) -> int | None:
    return None if str(value or "").strip() == "" else _integer(value)


def _external_to_internal(source_zone: str, destination_zone: str) -> int:
    source = source_zone.strip().lower()
    destination = destination_zone.strip().lower()
    outside = {"outside", "untrust", "external", "internet", "wan"}
    inside = {"inside", "trust", "internal", "lan", "dmz"}
    return int(source in outside and destination in inside)


def _internal_to_external(source_zone: str, destination_zone: str) -> int:
    return _external_to_internal(destination_zone, source_zone)


def _blind_feature_projection(row: dict[str, str], position: int) -> dict[str, Any]:
    source_zone = str(row.get("source_zone") or "unknown")
    destination_zone = str(row.get("destination_zone") or "unknown")
    application = str(row.get("application") or "unknown")
    event_time = str(row.get("event_time_utc") or "")
    minute_bucket = event_time[:16] if event_time else "missing"
    group_size = max(1, _integer(row.get("group_size"), 1))
    action = str(row.get("action") or "unknown")
    return {
        "id": position + 1,
        "review_token": str(row.get("review_token") or ""),
        "evidence_role": str(row.get("evidence_role") or ""),
        "evidence_role_is_blind": _boolean(row.get("evidence_role_is_blind")),
        "pattern": str(row.get("pattern") or "unknown"),
        "event_time": event_time,
        "minute_bucket": minute_bucket,
        "role_rank": 3,
        "log_type": str(row.get("log_type") or "unknown"),
        "subtype": str(row.get("subtype") or "unknown"),
        "app": application,
        "action": action,
        "protocol": str(row.get("protocol") or "unknown"),
        "src_port": _nullable_integer(row.get("source_port")),
        "dst_port": _nullable_integer(row.get("destination_port")),
        "src_zone": source_zone,
        "dst_zone": destination_zone,
        "bytes": _nullable_integer(row.get("bytes")),
        "bytes_sent": None,
        "bytes_received": None,
        "packets": _nullable_integer(row.get("packets")),
        "elapsed_time": _nullable_integer(row.get("elapsed_time")),
        "app_risk": _nullable_integer(row.get("application_risk")),
        "repeat_count": group_size,
        "parser_error": _boolean(row.get("parser_error")),
        "parser_warning_count": _integer(row.get("parser_warning_count")),
        "required_missing_count": _integer(row.get("required_missing_count")),
        "field_count": 0,
        "schema_bucket": str(row.get("schema_bucket") or "unrecognized"),
        "threat_severity": str(row.get("threat_severity") or ""),
        "app_characteristic": "",
        "session_end_reason": str(row.get("session_end_reason") or ""),
        "deny_flag": int(action.strip().lower() in {"deny", "drop", "reset"}),
        "unknown_app_flag": int(application.strip().lower() in {"", "unknown", "incomplete"}),
        "external_to_internal_flag": _external_to_internal(source_zone, destination_zone),
        "internal_to_external_flag": _internal_to_external(source_zone, destination_zone),
        "group_size": group_size,
        "propagation_hash": str(row.get("review_token") or ""),
        "source_event_count": _integer(row.get("source_event_count")),
        "source_deny_count": _integer(row.get("source_deny_count")),
        "source_auth_deny_count": 0,
        "source_unique_destinations": _integer(row.get("source_unique_destinations")),
        "source_unique_ports": _integer(row.get("source_unique_ports")),
        "source_total_bytes": 0,
        "source_average_packets": 0.0,
        "source_unknown_app_count": _integer(row.get("source_unknown_app_count")),
        "source_high_risk_app_count": _integer(row.get("source_high_risk_app_count")),
        "destination_repeat_count": _integer(row.get("destination_repeat_count")),
    }


def load_blind_features_before_labels(pack_path: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Read only prediction features; human decision fields are not retained."""

    with pack_path.open(encoding="utf-8", newline="") as stream:
        reader = csv.DictReader(stream)
        fields = set(reader.fieldnames or [])
        missing = {
            "review_token",
            "evidence_role",
            "evidence_role_is_blind",
            "pattern",
        } - fields
        rows = [dict(row) for row in reader]
    projected = [_blind_feature_projection(row, index) for index, row in enumerate(rows)]
    tokens = [str(row["review_token"]) for row in projected]
    role_valid = all(
        row["evidence_role"] == "untouched_future_validation"
        and row["evidence_role_is_blind"]
        for row in projected
    )
    suggestions_absent = all(
        not str(row.get(field) or "").strip()
        for row in rows
        for field in ASSISTED_FIELDS
    )
    return projected, {
        "rows": len(projected),
        "required_columns_present": not missing,
        "missing_required_columns": sorted(missing),
        "unique_review_tokens": len(tokens) == len(set(tokens)),
        "all_rows_in_blind_role": role_valid,
        "blind_suggestions_absent": suggestions_absent,
        "label_fields_retained_for_prediction": False,
        "raw_logs_included": False,
        "ip_addresses_included": False,
    }


def audit_blind_eligibility(
    manifest: dict[str, Any],
    feature_rows: list[dict[str, Any]],
    feature_audit: dict[str, Any],
) -> dict[str, Any]:
    pack_projection = [
        {
            "review_token": row["review_token"],
            "evidence_role": row["evidence_role"],
            "pattern": row["pattern"],
        }
        for row in feature_rows
    ]
    checks = {
        "v521_manifest_version": manifest.get("version") == v521.V521_MANIFEST_VERSION,
        "manifest_blind_decisions_unopened": manifest.get("blind_decisions_opened") is False,
        "manifest_blind_suggestions_absent": manifest.get("blind_suggestions_generated") is False,
        "manifest_no_human_labels_created": int(manifest.get("human_reviewed_rows_created") or 0) == 0,
        "manifest_configured_database_not_used": manifest.get("configured_database_accessed") is False,
        "pack_columns_complete": bool(feature_audit.get("required_columns_present")),
        "pack_tokens_unique": bool(feature_audit.get("unique_review_tokens")),
        "pack_roles_blind": bool(feature_audit.get("all_rows_in_blind_role")),
        "pack_suggestions_absent": bool(feature_audit.get("blind_suggestions_absent")),
        "pack_fingerprint_matches_lock": bool(
            manifest.get("blind_pack_fingerprint")
            and v521._pack_fingerprint(pack_projection) == manifest.get("blind_pack_fingerprint")
        ),
        "pack_nonempty": bool(feature_rows),
    }
    return {
        "passed": all(checks.values()),
        "status": "blind_evidence_eligible" if all(checks.values()) else "blind_evidence_ineligible",
        "checks": checks,
        "rows": len(feature_rows),
        "duplicate_containment_preserved": int(manifest.get("exact_family_cross_role_count") or 0) == 0
        and int(manifest.get("near_family_cross_role_count") or 0) == 0,
        "fingerprints_compared_privately": True,
        "fingerprints_returned": False,
        "private_identifiers_returned": False,
    }


def _candidate_contract(evidence_dir: Path) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    payload = _read_json(evidence_dir / v522.V522_LATEST)
    if not payload:
        return None, {
            "passed": False,
            "status": "v522_candidate_record_missing",
        }
    candidate = payload.get("frozen_shadow_candidate") or {}
    checks = {
        "v522_completed": payload.get("ok") is True,
        "lifecycle_shadow_observation": payload.get("lifecycle_state") == "shadow_observation",
        "candidate_present": bool(candidate),
        "candidate_frozen_before_blind": candidate.get("frozen_before_blind_label_access") is True,
        "blind_labels_not_used_for_selection": candidate.get("blind_labels_used_for_selection") is False,
        "candidate_not_activation_eligible": candidate.get("eligible_for_activation") is False,
        "artifact_not_written": candidate.get("active_artifact_written") is False,
        "model_not_activated": candidate.get("model_activated") is False,
        "model_not_promoted": candidate.get("model_promoted") is False,
    }
    public = {
        key: candidate.get(key)
        for key in (
            "name",
            "selection_basis",
            "target_mode",
            "model_type",
            "threshold",
            "calibration_method",
        )
    }
    return candidate, {
        "passed": all(checks.values()),
        "status": "v522_frozen_candidate_contract_valid" if all(checks.values()) else "v522_candidate_contract_invalid",
        "checks": checks,
        "candidate": public,
        "candidate_reconstructed_in_memory": True,
        "active_artifact_loaded_or_written": False,
    }


def _blind_bundle(imports: Any, rows: list[dict[str, Any]]) -> dict[str, Any]:
    pd = imports[1]
    metadata = [
        {
            "timestamp": datetime.fromisoformat(str(row["event_time"])) if row.get("event_time") else None,
            "app": row.get("app") or "unknown",
            "action": row.get("action") or "unknown",
            "dst_port": row.get("dst_port"),
            "schema": row.get("schema_bucket") or "unknown",
            "pattern": row.get("pattern") or "unknown",
            "log_type": row.get("log_type") or "unknown",
            "provenance": "sealed_blind_unlabeled",
            "human_reviewed": False,
            "group_size": row.get("group_size") or 1,
            "original_label": "unopened",
        }
        for row in rows
    ]
    return {
        "frame": pd.DataFrame([v56._private_feature_row(row) for row in rows]).reindex(
            columns=[*v56.V56_NUMERIC_FEATURES, *v56.V56_CATEGORICAL_FEATURES]
        ),
        "rows": metadata,
        "original_labels": ["unopened"] * len(rows),
        "targets": ["unopened"] * len(rows),
        "base_weights": [0.0] * len(rows),
    }


def _apply_feature_defaults(bundle: dict[str, Any], stability: dict[str, Any]) -> None:
    for field in stability.get("all_null_numeric_defaults") or []:
        if field in bundle["frame"]:
            bundle["frame"][field] = bundle["frame"][field].astype("float64").fillna(0.0)
    for field in stability.get("all_null_categorical_defaults") or []:
        if field in bundle["frame"]:
            bundle["frame"][field] = bundle["frame"][field].fillna("missing")


def _top(counter: Counter[str], limit: int = 8) -> list[dict[str, Any]]:
    return [
        {"value": value, "rows": int(count)}
        for value, count in counter.most_common(limit)
    ]


def _prediction_summary(rows: list[dict[str, Any]], layer: str) -> dict[str, Any]:
    queue_key = f"{layer}_queue"
    score_key = f"{layer}_score"
    queued = [row for row in rows if row.get(queue_key) == "needs_review"]
    scores = [float(row[score_key]) for row in rows if row.get(score_key) is not None]
    return {
        "rows": len(rows),
        "needs_review_rows": len(queued),
        "non_threat_rows": len(rows) - len(queued),
        "review_queue_rate": round(len(queued) / max(1, len(rows)), 4),
        "score_distribution": {
            "minimum": round(min(scores), 6) if scores else None,
            "maximum": round(max(scores), 6) if scores else None,
            "mean": round(mean(scores), 6) if scores else None,
        },
        "queued_patterns": _top(Counter(str(row["pattern"]) for row in queued)),
        "queued_applications": _top(Counter(str(row["app"]) for row in queued)),
        "queued_actions": _top(Counter(str(row["action"]) for row in queued)),
        "queued_destination_ports": _top(Counter(str(row["dst_port"]) for row in queued)),
        "private_identifiers_included": False,
    }


def _agreement_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    pairs = (
        ("rule", "supervised"),
        ("rule", "isolation"),
        ("rule", "hybrid"),
        ("supervised", "isolation"),
        ("supervised", "hybrid"),
    )
    output: dict[str, Any] = {}
    for left, right in pairs:
        matches = sum(
            1
            for row in rows
            if row[f"{left}_queue"] == row[f"{right}_queue"]
        )
        output[f"{left}_vs_{right}"] = {
            "matching_rows": matches,
            "agreement_rate": round(matches / max(1, len(rows)), 4),
        }
    output["all_layers_agree_rows"] = sum(
        1
        for row in rows
        if len(
            {
                row["rule_queue"],
                row["isolation_queue"],
                row["supervised_queue"],
                row["hybrid_queue"],
            }
        )
        == 1
    )
    return output


def _open_human_labels_after_prediction(pack_path: Path) -> tuple[dict[str, str], dict[str, Any]]:
    with pack_path.open(encoding="utf-8", newline="") as stream:
        rows = list(csv.DictReader(stream))
    labels: dict[str, str] = {}
    invalid_reasons: Counter[str] = Counter()
    decision_distribution: Counter[str] = Counter()
    for row in rows:
        decision = str(row.get("human_decision") or "").strip().lower()
        reviewed = _boolean(row.get("human_reviewed"))
        reviewer = str(row.get("human_reviewer") or "").strip()
        reviewed_at = str(row.get("human_reviewed_at") or "").strip()
        if not decision and not reviewed:
            invalid_reasons["not_reviewed"] += 1
            continue
        if not reviewed:
            invalid_reasons["review_flag_false"] += 1
            continue
        if decision not in VALID_DECISIONS:
            invalid_reasons["invalid_or_missing_decision"] += 1
            continue
        if not reviewer:
            invalid_reasons["reviewer_missing"] += 1
            continue
        if not reviewed_at:
            invalid_reasons["review_timestamp_missing"] += 1
            continue
        token = str(row.get("review_token") or "")
        if not token:
            invalid_reasons["review_token_missing"] += 1
            continue
        labels[token] = decision
        decision_distribution[decision] += 1
    queue_targets = {
        "needs_review" if value in {"needs_context", "suspicious", "malicious"} else "non_threat"
        for value in labels.values()
    }
    return labels, {
        "rows_in_pack": len(rows),
        "genuine_human_labels": len(labels),
        "excluded_rows": len(rows) - len(labels),
        "excluded_reasons": dict(sorted(invalid_reasons.items())),
        "decision_distribution": dict(sorted(decision_distribution.items())),
        "binary_class_support": len(queue_targets),
        "minimum_required": MIN_HUMAN_BLIND_LABELS,
        "enough_for_metrics": len(labels) >= MIN_HUMAN_BLIND_LABELS and len(queue_targets) == 2,
        "assisted_or_weak_labels_counted_as_human": 0,
        "labels_fabricated": 0,
        "labels_written": 0,
    }


def _error_patterns(
    rows: list[dict[str, Any]],
    labels: dict[str, str],
    layer: str,
) -> dict[str, Any]:
    false_positives: list[dict[str, Any]] = []
    false_negatives: list[dict[str, Any]] = []
    for row in rows:
        decision = labels.get(str(row["review_token"]))
        if not decision:
            continue
        actual = "needs_review" if decision in {"needs_context", "suspicious", "malicious"} else "non_threat"
        predicted = str(row[f"{layer}_queue"])
        if actual == predicted:
            continue
        item = {
            "pattern": str(row["pattern"]),
            "application": str(row["app"]),
            "action": str(row["action"]),
            "destination_port": str(row["dst_port"]),
            "schema": str(row["schema"]),
            "log_type": str(row["log_type"]),
            "human_decision": decision,
        }
        (false_positives if actual == "non_threat" else false_negatives).append(item)

    def summarize(items: list[dict[str, Any]]) -> dict[str, Any]:
        return {
            "rows": len(items),
            "patterns": _top(Counter(item["pattern"] for item in items)),
            "applications": _top(Counter(item["application"] for item in items)),
            "actions": _top(Counter(item["action"] for item in items)),
            "destination_ports": _top(Counter(item["destination_port"] for item in items)),
            "schemas": _top(Counter(item["schema"] for item in items)),
            "log_types": _top(Counter(item["log_type"] for item in items)),
            "human_decisions": _top(Counter(item["human_decision"] for item in items)),
        }

    return {
        "false_positives": summarize(false_positives),
        "false_negatives": summarize(false_negatives),
        "private_identifiers_included": False,
    }


def evaluate_predictions_after_label_open(
    predictions: list[dict[str, Any]],
    labels: dict[str, str],
    label_audit: dict[str, Any],
) -> dict[str, Any]:
    if not label_audit.get("enough_for_metrics"):
        return {
            "status": "insufficient_independent_human_labels",
            "metrics_calculated": False,
            "reason": (
                "The sealed blind pack does not contain enough genuine human decisions with both queue classes. "
                "Precision, recall, F1, false-positive rate, and false-negative analysis are unavailable."
            ),
            "layers": {},
            "error_analysis": {
                "status": "unavailable_without_legitimate_blind_labels",
                "false_positive_claims_made": False,
                "false_negative_claims_made": False,
            },
        }
    evaluation_rows = [row for row in predictions if row["review_token"] in labels]
    y_true = [
        "needs_review"
        if labels[row["review_token"]] in {"needs_context", "suspicious", "malicious"}
        else "non_threat"
        for row in evaluation_rows
    ]
    layers: dict[str, Any] = {}
    for layer in ("rule", "isolation", "supervised", "hybrid"):
        predicted = [str(row[f"{layer}_queue"]) for row in evaluation_rows]
        metrics = frozen._binary_metrics(y_true, predicted)
        for decision in ("suspicious", "malicious"):
            positions = [
                index
                for index, row in enumerate(evaluation_rows)
                if labels[row["review_token"]] == decision
            ]
            metrics[f"{decision}_recall"] = (
                round(
                    sum(1 for index in positions if predicted[index] == "needs_review")
                    / len(positions),
                    4,
                )
                if positions
                else None
            )
        scores = [float(row[f"{layer}_score"]) for row in evaluation_rows]
        calibration = (
            frozen._calibration_report(y_true, scores)
            if layer in {"supervised", "hybrid"}
            else {"status": "not_probability_calibrated_layer"}
        )
        layers[layer] = {
            "rows": len(evaluation_rows),
            "metrics": metrics,
            "calibration": calibration,
            "error_patterns": _error_patterns(evaluation_rows, labels, layer),
        }
    return {
        "status": "blind_metrics_calculated_once",
        "metrics_calculated": True,
        "rows": len(evaluation_rows),
        "layers": layers,
        "error_analysis": {
            "status": "available",
            "private_identifiers_included": False,
        },
    }


def _run_prediction_phase(
    db: Session,
    *,
    sample_path: Path,
    manifest: dict[str, Any],
    candidate_contract: dict[str, Any],
    blind_rows: list[dict[str, Any]],
    min_samples: int,
    chunk_size: int,
    max_fit_rows: int,
    max_calibration_rows: int,
    max_threshold_rows: int,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    imports = v56._optional_imports()
    if imports is None:
        raise RuntimeError("Required supervised-learning dependencies are unavailable.")
    dataset = v52._prepare_dataset(db, min_samples=min_samples)
    if not dataset.get("ok"):
        raise RuntimeError(str(dataset.get("message") or "Governed evidence is unavailable."))
    partition = frozen.build_frozen_partition(dataset["rows"], split_mode="temporal_holdout")
    leakage = frozen.audit_partition_leakage(dataset["rows"], partition)
    if not leakage.get("passed"):
        raise RuntimeError("Governed development partition failed leakage checks.")
    evidence_lock = v54.build_evidence_lock(dataset, output_dir=V526_OUTPUT_DIR)
    governed_lock = v54.validate_evidence_lock(evidence_lock)
    if not governed_lock.get("passed"):
        raise RuntimeError("Governed development evidence lock changed.")

    with tempfile.TemporaryDirectory(prefix="atdr-v526-") as directory:
        disposable_path = Path(directory) / "blind-qualification.sqlite3"
        connection = sqlite3.connect(disposable_path)
        try:
            profile = v56.stream_private_file_to_disposable_index(
                sample_path,
                connection,
                database_url="sqlite:///:memory:",
                chunk_size=chunk_size,
            )
            if not profile.get("ok"):
                raise RuntimeError("Private PAN-OS evidence streaming failed.")
            roles = v56.predeclare_chronological_roles(connection)
            if not roles.get("ok"):
                raise RuntimeError("Native chronological role partitioning failed.")
            role_lock = v522._validate_rebuilt_roles(manifest, connection)
            if not role_lock.get("passed"):
                raise RuntimeError("The rebuilt native evidence roles no longer match v5.21.")
            v56.build_disposable_behavior_aggregates(connection)
            policy = v522.apply_development_only_assisted_policy(connection)
            if int(policy.get("future_role_rows_labeled") or 0) != 0:
                raise RuntimeError("Development policy attempted to label the blind role.")
            governed, provenance = v522._governed_bundles_with_provenance(dataset, partition)
            private: dict[str, dict[str, Any]] = {}
            selection: dict[str, Any] = {}
            for role_rank, role_name, cap in (
                (0, "development_fit", max_fit_rows),
                (1, "calibration", max_calibration_rows),
                (2, "threshold", max_threshold_rows),
            ):
                private[role_name], selection[role_name] = v56.load_private_role_bundle(
                    connection,
                    imports,
                    role_rank=role_rank,
                    max_rows=cap,
                )
        finally:
            connection.close()

    fit = v56._concat_bundles(imports, governed["development_fit"], private["development_fit"])
    calibration = v56._concat_bundles(imports, governed["calibration"], private["calibration"])
    threshold = v56._concat_bundles(imports, governed["threshold"], private["threshold"])
    blind = _blind_bundle(imports, blind_rows)
    stabilized, stability = v522._stabilize_view(
        {
            "name": "v526_frozen_candidate_reconstruction",
            "fit": fit,
            "calibration": calibration,
            "threshold": threshold,
            "evaluation": threshold,
        }
    )
    _apply_feature_defaults(blind, stability)
    candidate_name = str(candidate_contract.get("name") or "")
    spec = next(
        (item for item in v56.V56_CANDIDATE_SPECS if item["name"] == candidate_name),
        None,
    )
    if spec is None:
        raise RuntimeError("The frozen v5.22 candidate specification is unavailable.")
    fitted = v56._fit_candidate(
        imports,
        fit=stabilized["fit"],
        calibration=stabilized["calibration"],
        threshold=stabilized["threshold"],
        evaluation=stabilized["evaluation"],
        spec=spec,
    )
    if fitted.get("status") != "evaluated" or fitted.get("_model") is None:
        raise RuntimeError("The frozen v5.22 candidate could not be reconstructed in memory.")
    supervised_scores = v56.reliability._queue_scores(
        fitted["_model"],
        blind["frame"],
        list(range(len(blind_rows))),
        set(fitted.get("_positive_classes") or {"needs_review"}),
    )
    frozen_threshold = _number(candidate_contract.get("threshold"), 0.5)
    supervised_queue = [
        "needs_review" if score >= frozen_threshold else "non_threat"
        for score in supervised_scores
    ]
    isolation_report, isolation_candidate = v56.run_isolation_forest_diagnostics(
        imports,
        fit=stabilized["fit"],
        development_evaluation=stabilized["threshold"],
    )
    if not isolation_candidate:
        raise RuntimeError("No development-only IsolationForest diagnostic candidate was available.")
    isolation_queue, isolation_scores = v56._isolation_predictions(
        isolation_candidate["_pipeline"],
        blind,
    )

    predictions: list[dict[str, Any]] = []
    rule_codes: Counter[str] = Counter()
    for index, row in enumerate(blind_rows):
        codes, rule_score = v56._rule_evidence(row)
        rule_codes.update(codes)
        rule_queue = "needs_review" if codes else "non_threat"
        isolation_is_anomaly = isolation_queue[index] == "needs_review"
        hybrid = hybrid_scoring.hybrid_risk_score(
            rule_score=rule_score,
            isolation_anomaly_score=isolation_scores[index],
            isolation_is_anomaly=isolation_is_anomaly,
            supervised_malicious_probability=supervised_scores[index],
        )
        hybrid_value = float(hybrid["final_risk_score"]) / 100.0
        predictions.append(
            {
                "review_token": row["review_token"],
                "pattern": row["pattern"],
                "app": row["app"],
                "action": row["action"],
                "dst_port": row["dst_port"],
                "schema": row["schema_bucket"],
                "log_type": row["log_type"],
                "rule_queue": rule_queue,
                "rule_score": float(rule_score) / 100.0,
                "isolation_queue": isolation_queue[index],
                "isolation_score": max(0.0, min(1.0, hybrid_scoring.isolation_score_to_risk(
                    isolation_scores[index],
                    is_anomaly=isolation_is_anomaly,
                ) / 100.0)),
                "supervised_queue": supervised_queue[index],
                "supervised_score": float(supervised_scores[index]),
                "hybrid_queue": "needs_review" if hybrid_value >= 0.55 else "non_threat",
                "hybrid_score": hybrid_value,
            }
        )
    summaries = {
        layer: _prediction_summary(predictions, layer)
        for layer in ("rule", "isolation", "supervised", "hybrid")
    }
    summaries["rule"]["top_rule_codes"] = _top(rule_codes)
    return predictions, {
        "status": "predictions_frozen_before_human_label_access",
        "rows": len(predictions),
        "candidate": {
            "name": candidate_name,
            "model_type": candidate_contract.get("model_type"),
            "target_mode": candidate_contract.get("target_mode"),
            "threshold": frozen_threshold,
            "calibration_method": candidate_contract.get("calibration_method"),
            "contract_reconstructed_in_memory": True,
        },
        "development_evidence": {
            "governed_rows": len(dataset["rows"]),
            "genuinely_human_reviewed_rows": provenance.get("genuinely_human_reviewed_rows"),
            "assisted_or_weak_rows": provenance.get("assisted_or_weak_rows"),
            "private_role_selection": selection,
            "blind_role_used_for_fit_calibration_or_threshold": False,
        },
        "native_stream": {
            "rows_processed": int(profile.get("rows_processed") or 0),
            "parser_successes": int(profile.get("parser_successes") or 0),
            "parser_failures": int(profile.get("parser_failures") or 0),
            "role_lock_reproduced": True,
            "temporary_storage_disposed": True,
        },
        "layers": summaries,
        "agreement": _agreement_summary(predictions),
        "isolation_development_status": isolation_report.get("status"),
        "labels_accessed": False,
        "prediction_lock_created": True,
        "prediction_lock_fingerprint_returned": False,
        "private_identifiers_returned": False,
    }


def _readiness(
    *,
    eligibility: dict[str, Any],
    candidate_audit: dict[str, Any],
    label_audit: dict[str, Any],
    evaluation: dict[str, Any],
    safety: dict[str, Any],
) -> dict[str, Any]:
    checks = {
        "blind_evidence_eligible": bool(eligibility.get("passed")),
        "v522_candidate_contract_valid": bool(candidate_audit.get("passed")),
        "predictions_frozen_before_label_access": True,
        "minimum_genuine_human_blind_labels": bool(label_audit.get("enough_for_metrics")),
        "blind_metrics_available": bool(evaluation.get("metrics_calculated")),
        "database_unchanged": bool(safety.get("database_counts_unchanged")),
        "model_artifacts_unchanged": bool(safety.get("model_artifacts_unchanged")),
        "authoritative_side_effects_absent": all(
            int(safety.get(field) or 0) == 0
            for field in (
                "labels_created",
                "model_runs_created",
                "detection_runs_created",
                "alerts_created",
                "response_actions_created",
            )
        ),
    }
    blockers = [name for name, passed in checks.items() if not passed]
    return {
        "decision": "shadow_observation",
        "candidate_only": True,
        "production_promoted": False,
        "response_automation_allowed": False,
        "checks": checks,
        "checks_passed": sum(1 for value in checks.values() if value),
        "checks_total": len(checks),
        "blockers": blockers,
        "message": (
            "The native blind qualification remains in shadow observation. "
            "Independent human-confirmed blind labels and another real source are still required before lifecycle advancement."
        ),
    }


def _render_report(result: dict[str, Any]) -> str:
    labels = result.get("label_audit") or {}
    readiness = result.get("readiness") or {}
    evaluation = result.get("blind_evaluation") or {}
    layers = (result.get("prediction_phase") or {}).get("layers") or {}
    lines = [
        "# v5.26 Native PAN-OS Blind Detection Qualification",
        "",
        f"Generated: `{result.get('generated_at')}`",
        "",
        "## Outcome",
        "",
        f"- Status: `{result.get('status')}`",
        f"- Blind rows scored: `{(result.get('prediction_phase') or {}).get('rows', 0)}`",
        f"- Genuine human blind labels: `{labels.get('genuine_human_labels', 0)}`",
        f"- Promotion metrics calculated: `{evaluation.get('metrics_calculated', False)}`",
        f"- Lifecycle: `{result.get('lifecycle_state')}`",
        f"- Readiness blockers: `{', '.join(readiness.get('blockers') or []) or 'none'}`",
        "",
        "## Prediction Layers",
        "",
    ]
    for layer in ("rule", "isolation", "supervised", "hybrid"):
        summary = layers.get(layer) or {}
        lines.append(
            f"- {layer.title()}: `{summary.get('needs_review_rows', 0)}` queued "
            f"(`{summary.get('review_queue_rate')}` rate)."
        )
    lines.extend(
        [
            "",
            "## Evidence Integrity",
            "",
            "- Predictions were frozen before human decision fields were opened.",
            "- Blind labels were not used for fitting, calibration, thresholds, or candidate selection.",
            "- AI/rule-assisted values were not treated as human-reviewed labels.",
            "- Private paths, raw logs, IP addresses, row tokens, and fingerprints are not included.",
            "",
            "## Interpretation",
            "",
            str(evaluation.get("reason") or "Legitimate blind metrics were calculated once after candidate freeze."),
            "",
            "The result is diagnostic decision support only. Deterministic rules remain alert-authoritative; "
            "automatic response and real firewall blocking remain disabled.",
        ]
    )
    return "\n".join(lines) + "\n"


def _write_private_prediction_lock(
    path: Path,
    predictions: list[dict[str, Any]],
) -> None:
    """Persist the sealed prediction side without raw evidence or identifiers."""

    rows = [
        {
            key: row.get(key)
            for key in (
                "review_token",
                "pattern",
                "app",
                "action",
                "dst_port",
                "schema",
                "log_type",
                "rule_queue",
                "rule_score",
                "isolation_queue",
                "isolation_score",
                "supervised_queue",
                "supervised_score",
                "hybrid_queue",
                "hybrid_score",
            )
        }
        for row in predictions
    ]
    payload = {
        "version": V526_VERSION,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "prediction_rows": rows,
        "predictions_created_before_label_access": True,
        "human_label_fields_included": False,
        "raw_logs_included": False,
        "ip_addresses_included": False,
        "source_path_included": False,
        "secret_values_included": False,
        "configured_database_written": False,
        "model_artifact_written": False,
        "response_actions_created": 0,
        "private_file": True,
        "commit_allowed": False,
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def run_v526_native_blind_qualification(
    db: Session | None,
    *,
    sample_path: str | Path,
    use_temp_db: bool,
    evidence_dir: str | Path = V526_OUTPUT_DIR,
    output_dir: str | Path = V526_OUTPUT_DIR,
    min_samples: int = 100,
    chunk_size: int = 2000,
    max_fit_rows: int = 8000,
    max_calibration_rows: int = 3000,
    max_threshold_rows: int = 3500,
    preflight_only: bool = False,
    write_output: bool = True,
) -> dict[str, Any]:
    started = time.perf_counter()
    path = Path(sample_path)
    evidence = Path(evidence_dir)
    output = Path(output_dir)
    if not use_temp_db:
        return _safe_failure(
            "failed_closed_temp_db_acknowledgement_required",
            "Re-run with --use-temp-db.",
        )
    if not path.is_file():
        return _safe_failure(
            "private_evidence_unavailable",
            "The private PAN-OS evidence file is unavailable.",
        )
    manifest, manifest_validation = v522._load_v521_manifest(path, evidence_dir=evidence)
    if not manifest or not manifest_validation.get("passed"):
        return {
            **_safe_failure(
                "failed_closed_v521_manifest_validation",
                "The v5.21 native evidence lock did not validate.",
            ),
            "manifest_validation": manifest_validation,
        }
    pack_path = evidence / v521.V521_BLIND_PACK
    if not pack_path.is_file():
        return _safe_failure(
            "failed_closed_blind_pack_missing",
            "The sealed v5.21 blind verification pack is unavailable.",
        )
    blind_rows, feature_audit = load_blind_features_before_labels(pack_path)
    eligibility = audit_blind_eligibility(manifest, blind_rows, feature_audit)
    candidate, candidate_audit = _candidate_contract(evidence)
    if not eligibility.get("passed") or not candidate or not candidate_audit.get("passed"):
        return {
            **_safe_failure(
                "failed_closed_blind_or_candidate_contract",
                "Blind evidence or the frozen v5.22 candidate contract is ineligible.",
            ),
            "blind_eligibility": eligibility,
            "candidate_audit": candidate_audit,
        }
    if preflight_only:
        return {
            "ok": True,
            "status": "native_blind_preflight_complete",
            "version": V526_VERSION,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "lifecycle_state": "shadow_observation",
            "blind_eligibility": eligibility,
            "candidate_audit": candidate_audit,
            "prediction_executed": False,
            "blind_label_fields_opened": False,
            "model_activated": False,
            "model_promoted": False,
            "response_automation_allowed": False,
            "path_returned": False,
            "raw_evidence_returned": False,
            "private_identifiers_returned": False,
            "fingerprints_returned": False,
        }
    if not write_output:
        return _safe_failure(
            "failed_closed_prediction_lock_required",
            "A full blind qualification must persist its ignored prediction lock.",
        )
    if db is None:
        return _safe_failure(
            "failed_closed_database_session_required",
            "A read-only governed-evidence database session is required for full qualification.",
        )
    previous = _read_json(output / V526_LATEST)
    lock_path = output / V526_PREDICTION_LOCK
    repairing_prelock_protocol = False
    if previous and previous.get("blind_label_fields_opened") is True:
        prior_label_audit = previous.get("label_audit") or {}
        prior_evaluation = previous.get("blind_evaluation") or {}
        repair_is_safe = bool(
            not lock_path.exists()
            and int(prior_label_audit.get("genuine_human_labels") or 0) == 0
            and prior_evaluation.get("metrics_calculated") is False
        )
        if not repair_is_safe:
            return _safe_failure(
                "failed_closed_blind_qualification_already_consumed",
                "The one-time v5.26 blind qualification has already been consumed.",
            )
        repairing_prelock_protocol = True
        output.mkdir(parents=True, exist_ok=True)
        (output / V526_PRELOCK_RECORD).write_text(
            json.dumps(previous, indent=2, default=str),
            encoding="utf-8",
        )

    counts_before = frozen._database_counts(db)
    artifacts_before = v55._model_artifact_states()
    try:
        predictions, prediction_phase = _run_prediction_phase(
            db,
            sample_path=path,
            manifest=manifest,
            candidate_contract=candidate,
            blind_rows=blind_rows,
            min_samples=min_samples,
            chunk_size=chunk_size,
            max_fit_rows=max_fit_rows,
            max_calibration_rows=max_calibration_rows,
            max_threshold_rows=max_threshold_rows,
        )
    except (OSError, RuntimeError, sqlite3.Error, ValueError) as exc:
        return {
            **_safe_failure(
                "failed_closed_prediction_phase",
                "The prediction phase failed closed before blind labels were opened.",
            ),
            "error_type": exc.__class__.__name__,
            "blind_label_fields_opened": False,
        }

    # This order is the core blind protocol: the ignored prediction side is
    # persisted before the CSV human-decision projection is opened.
    output.mkdir(parents=True, exist_ok=True)
    _write_private_prediction_lock(lock_path, predictions)
    labels, label_audit = _open_human_labels_after_prediction(pack_path)
    evaluation = evaluate_predictions_after_label_open(predictions, labels, label_audit)
    counts_after = frozen._database_counts(db)
    artifacts_after = v55._model_artifact_states()
    safety = {
        "database_counts_unchanged": counts_before == counts_after,
        "model_artifacts_unchanged": artifacts_before == artifacts_after,
        "labels_created": counts_after["ml_labels"] - counts_before["ml_labels"],
        "model_runs_created": counts_after["ml_model_runs"] - counts_before["ml_model_runs"],
        "detection_runs_created": counts_after["detection_runs"] - counts_before["detection_runs"],
        "alerts_created": counts_after["alerts"] - counts_before["alerts"],
        "response_actions_created": counts_after["response_actions"] - counts_before["response_actions"],
        "private_file_imported_into_configured_database": False,
        "temporary_storage_disposed": True,
        "active_model_artifact_written": False,
        "model_activated": False,
        "model_promoted": False,
        "rules_alert_authoritative": True,
        "ml_alert_authority": False,
        "automatic_response_enabled": False,
        "real_firewall_blocking_enabled": False,
    }
    readiness = _readiness(
        eligibility=eligibility,
        candidate_audit=candidate_audit,
        label_audit=label_audit,
        evaluation=evaluation,
        safety=safety,
    )
    side_effect_free = all(
        int(safety[field]) == 0
        for field in (
            "labels_created",
            "model_runs_created",
            "detection_runs_created",
            "alerts_created",
            "response_actions_created",
        )
    )
    result = {
        "ok": bool(
            eligibility.get("passed")
            and candidate_audit.get("passed")
            and safety["database_counts_unchanged"]
            and safety["model_artifacts_unchanged"]
            and side_effect_free
        ),
        "status": (
            "blind_qualification_complete"
            if evaluation.get("metrics_calculated")
            else "blind_predictions_complete_insufficient_human_labels"
        ),
        "version": V526_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "lifecycle_state": "shadow_observation",
        "blind_eligibility": eligibility,
        "candidate_audit": candidate_audit,
        "prediction_phase": prediction_phase,
        "prediction_frozen_before_label_access": True,
        "prediction_lock_persisted_privately": True,
        "prediction_lock_path_returned": False,
        "prelock_protocol_repair": repairing_prelock_protocol,
        "prelock_protocol_repair_ground_truth_observed": False,
        "blind_label_fields_opened": True,
        "blind_labels_used_for_fit": False,
        "blind_labels_used_for_calibration": False,
        "blind_labels_used_for_threshold_selection": False,
        "blind_labels_used_for_candidate_selection": False,
        "label_audit": label_audit,
        "blind_evaluation": evaluation,
        "development_repair_plan": {
            "status": "development_only_plan",
            "blind_role_reuse_for_tuning": False,
            "actions": (
                [
                    "Obtain independent human decisions for the sealed blind pack without model or rule suggestions.",
                    "Keep the current prediction lock sealed; do not rerun v5.26 after labels are supplied.",
                    "Collect a second real PAN-OS source for source-holdout evidence.",
                ]
                if not evaluation.get("metrics_calculated")
                else [
                    "Use only development roles to repair dominant aggregate error patterns.",
                    "Reserve a newly declared blind corpus for any later one-shot qualification.",
                    "Do not tune or relabel against the consumed v5.26 blind role.",
                ]
            ),
        },
        "readiness": readiness,
        "safety": safety,
        "duration_seconds": round(time.perf_counter() - started, 4),
        "path_returned": False,
        "raw_evidence_returned": False,
        "private_identifiers_returned": False,
        "fingerprints_returned": False,
        "report_written": bool(write_output),
    }
    if write_output:
        output.mkdir(parents=True, exist_ok=True)
        stamp = _stamp()
        (output / V526_LATEST).write_text(
            json.dumps(result, indent=2, default=str),
            encoding="utf-8",
        )
        (output / f"{V526_REPORT_PREFIX}{stamp}.md").write_text(
            _render_report(result),
            encoding="utf-8",
        )
    return result
