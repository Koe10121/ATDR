from __future__ import annotations

import json
import os
import sqlite3
import tempfile
import time
import warnings
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from statistics import mean
from typing import Any, Callable

os.environ.setdefault(
    "LOKY_MAX_CPU_COUNT",
    str(max(1, int(os.cpu_count() or 1))),
)

from sqlalchemy.orm import Session

from atdr.app.core.config import PROJECT_ROOT
from atdr.app.detection import v398_independent_holdout_validation as frozen
from atdr.app.detection import v52_shadow_reliability as v52
from atdr.app.detection import v54_temporal_evidence as v54
from atdr.app.detection import v55_development_model_repair as v55
from atdr.app.detection import v56_private_panos_model_repair as v56
from atdr.app.detection import v521_native_panos_evidence as v521


V522_VERSION = "v5.22-native-panos-supervised-rebuild-v1"
V522_OUTPUT_DIR = PROJECT_ROOT / "ml_baseline_reviews"
V522_LATEST = "v5_22_supervised_model_rebuild_latest.json"
V522_REPORT_PREFIX = "v5_22_supervised_model_rebuild_"
HUMAN_PROVENANCE = {"manual", "reviewed_import"}
DEVELOPMENT_ROLE_RANKS = (0, 1, 2)


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _safe_failure(status: str, message: str) -> dict[str, Any]:
    return {
        "ok": False,
        "status": status,
        "message": message,
        "version": V522_VERSION,
        "lifecycle_state": "shadow_observation",
        "path_returned": False,
        "raw_evidence_returned": False,
        "private_identifiers_returned": False,
        "fingerprints_returned": False,
        "model_activated": False,
        "model_promoted": False,
        "response_automation_allowed": False,
    }


def _load_v521_manifest(
    sample_path: Path,
    *,
    evidence_dir: Path,
) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    manifest_path = evidence_dir / v521.V521_MANIFEST_LATEST
    if not manifest_path.is_file():
        return None, {
            "passed": False,
            "status": "v521_manifest_missing",
            "message": "Run the complete v5.21 evidence lock before v5.22.",
        }
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None, {
            "passed": False,
            "status": "v521_manifest_unreadable",
            "message": "The v5.21 evidence lock is unavailable or invalid.",
        }
    required_roles = {
        "development_fit",
        "calibration",
        "threshold",
        "untouched_future_validation",
        "quarantine",
    }
    role_locks = manifest.get("role_locks") or {}
    source_matches = bool(manifest.get("source_file_sha256") and manifest.get("source_file_sha256") == v521._file_sha256(sample_path))
    checks = {
        "manifest_version": manifest.get("version") == v521.V521_MANIFEST_VERSION,
        "source_evidence_matches": source_matches,
        "all_roles_present": required_roles.issubset(role_locks),
        "blind_suggestions_absent": manifest.get("blind_suggestions_generated") is False,
        "blind_decisions_unopened": manifest.get("blind_decisions_opened") is False,
        "no_human_labels_created": int(manifest.get("human_reviewed_rows_created") or 0) == 0,
        "configured_database_not_used_by_v521": manifest.get("configured_database_accessed") is False,
    }
    return manifest, {
        "passed": all(checks.values()),
        "status": "v521_manifest_matched" if all(checks.values()) else "v521_manifest_mismatch",
        "checks": checks,
        "fingerprints_returned": False,
        "source_path_returned": False,
    }


def _validate_rebuilt_roles(
    manifest: dict[str, Any],
    connection: sqlite3.Connection,
) -> dict[str, Any]:
    current = v521._role_locks(connection)
    expected = manifest.get("role_locks") or {}
    role_checks = {
        role: bool(current.get(role) == expected.get(role))
        for role in (
            "development_fit",
            "calibration",
            "threshold",
            "untouched_future_validation",
            "quarantine",
        )
    }
    return {
        "passed": all(role_checks.values()),
        "status": "v521_role_lock_reproduced" if all(role_checks.values()) else "v521_role_lock_mismatch",
        "role_checks": role_checks,
        "role_rows": {role: int((current.get(role) or {}).get("rows") or 0) for role in role_checks},
        "fingerprints_compared_privately": True,
        "fingerprints_returned": False,
    }


def apply_development_only_assisted_policy(
    connection: sqlite3.Connection,
) -> dict[str, Any]:
    """Create weak labels only for fit/calibration/threshold representatives."""

    connection.executescript(
        """
        DROP TABLE IF EXISTS assisted_groups;
        CREATE TABLE assisted_groups (
            representative_id INTEGER PRIMARY KEY,
            propagation_hash TEXT NOT NULL,
            role_rank INTEGER NOT NULL,
            group_size INTEGER NOT NULL,
            decision TEXT NOT NULL,
            provenance TEXT NOT NULL,
            confidence REAL NOT NULL,
            evidence_summary TEXT NOT NULL,
            rule_codes_json TEXT NOT NULL,
            rule_score INTEGER NOT NULL,
            policy_version TEXT NOT NULL,
            human_reviewed INTEGER NOT NULL,
            training_eligible INTEGER NOT NULL,
            ambiguous INTEGER NOT NULL
        );
        """
    )
    query = v56.REPRESENTATIVE_QUERY.replace(
        "ORDER BY e.id",
        "WHERE e.role_rank IN (0, 1, 2) ORDER BY e.id",
    )
    decisions: Counter[str] = Counter()
    provenance: Counter[str] = Counter()
    training_rows = 0
    ambiguous_rows = 0
    batch: list[tuple[Any, ...]] = []
    for values in connection.execute(query):
        row = v56._row_mapping(values)
        codes, score = v56._rule_evidence(row)
        suggestion = v56.assisted_decision(
            row,
            rule_codes=codes,
            rule_score=score,
        )
        group_size = v56._integer(row.get("group_size"), 1)
        decisions[str(suggestion["decision"])] += group_size
        provenance[str(suggestion["provenance"])] += group_size
        if suggestion["training_eligible"]:
            training_rows += group_size
        else:
            ambiguous_rows += group_size
        batch.append(
            (
                int(row["id"]),
                str(row["propagation_hash"]),
                int(row["role_rank"]),
                group_size,
                suggestion["decision"],
                suggestion["provenance"],
                suggestion["confidence"],
                suggestion["evidence_summary"],
                json.dumps(suggestion["rule_codes"], separators=(",", ":")),
                suggestion["rule_score"],
                suggestion["policy_version"],
                0,
                int(suggestion["training_eligible"]),
                int(suggestion["ambiguous"]),
            )
        )
        if len(batch) >= 2000:
            connection.executemany(
                "INSERT INTO assisted_groups VALUES " "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                batch,
            )
            connection.commit()
            batch.clear()
    if batch:
        connection.executemany(
            "INSERT INTO assisted_groups VALUES " "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            batch,
        )
    connection.executescript(
        """
        CREATE INDEX ix_v522_assisted_role
            ON assisted_groups(role_rank, training_eligible);
        CREATE INDEX ix_v522_assisted_decision
            ON assisted_groups(decision, provenance);
        """
    )
    connection.commit()
    future_rows = int(connection.execute("SELECT COUNT(*) FROM assisted_groups WHERE role_rank=3").fetchone()[0])
    return {
        "status": "development_only_assisted_policy_applied",
        "policy_version": v56.V56_POLICY_VERSION,
        "decisions_by_event_count": dict(sorted(decisions.items())),
        "provenance_by_event_count": dict(sorted(provenance.items())),
        "training_event_count": training_rows,
        "ambiguous_event_count": ambiguous_rows,
        "representative_group_count": int(connection.execute("SELECT COUNT(*) FROM assisted_groups").fetchone()[0]),
        "human_reviewed_true_count": 0,
        "future_role_rows_labeled": future_rows,
        "future_role_opened": False,
        "blind_pack_opened": False,
        "configured_database_labels_written": 0,
        "import_ready_file_created": False,
    }


def _governed_bundles_with_provenance(
    dataset: dict[str, Any],
    partition: dict[str, Any],
) -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    bundles = v56.build_human_role_bundles(dataset, partition)
    counts: Counter[str] = Counter()
    human_rows = 0
    assisted_rows = 0
    for role_name, index_key in v56.ROLE_KEYS.items():
        indices = [int(value) for value in partition.get(index_key, [])]
        bundle = bundles[role_name]
        adjusted_weights: list[float] = []
        for position, index in enumerate(indices):
            source = dataset["rows"][index]
            source_name = str(source.get("source_name") or "unknown_source")
            label_source = str(source.get("label_source") or "unknown")
            is_human = bool(source.get("reviewed")) and (label_source in HUMAN_PROVENANCE)
            row = bundle["rows"][position]
            row["human_reviewed"] = is_human
            row["review_state"] = "human_reviewed" if is_human else "assisted_or_weak"
            row["source_identity"] = v54._source_token(source_name)
            counts[label_source] += 1
            if is_human:
                human_rows += 1
                adjusted_weights.append(1.0)
            else:
                assisted_rows += 1
                adjusted_weights.append(min(0.55, v56.ASSISTED_WEIGHTS.get(label_source, 0.30)))
        bundle["base_weights"] = adjusted_weights
    return bundles, {
        "provenance_distribution": dict(sorted(counts.items())),
        "genuinely_human_reviewed_rows": human_rows,
        "assisted_or_weak_rows": assisted_rows,
        "reviewed_flag_not_treated_as_human_authorship": True,
    }


def _filtered_bundle(
    imports: Any,
    bundle: dict[str, Any],
    predicate: Callable[[dict[str, Any]], bool],
) -> dict[str, Any]:
    indices = [index for index, row in enumerate(bundle["rows"]) if predicate(row)]
    return v56._slice_bundle(imports, bundle, indices)


def _supports_binary_evaluation(bundle: dict[str, Any], minimum: int = 20) -> bool:
    return len(bundle["rows"]) >= minimum and len(set(bundle["targets"])) >= 2


def _add_provenance_holdout_view(
    imports: Any,
    views: list[dict[str, Any]],
    *,
    governed: dict[str, dict[str, Any]],
    private: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    manual = _filtered_bundle(
        imports,
        governed["threshold"],
        lambda row: bool(row.get("human_reviewed")),
    )
    ordered = sorted(
        range(len(manual["rows"])),
        key=lambda index: (
            manual["rows"][index].get("timestamp") or datetime.min.replace(tzinfo=timezone.utc),
            index,
        ),
    )
    split = max(1, len(ordered) // 2)
    threshold_manual = v56._slice_bundle(imports, manual, ordered[:split])
    evaluation = v56._slice_bundle(imports, manual, ordered[split:])
    if not _supports_binary_evaluation(evaluation):
        return {
            "available": False,
            "status": "insufficient_manual_provenance_holdout",
            "human_rows_available": len(manual["rows"]),
        }
    views.append(
        {
            "name": "manual_provenance_holdout",
            "fit": v56._concat_bundles(
                imports,
                governed["development_fit"],
                private["development_fit"],
            ),
            "calibration": v56._concat_bundles(
                imports,
                governed["calibration"],
                private["calibration"],
            ),
            "threshold": v56._concat_bundles(
                imports,
                private["threshold"],
                threshold_manual,
            ),
            "evaluation": evaluation,
            "uses_future_validation": False,
            "uses_locked_v53": False,
            "evaluation_provenance": "human_reviewed_only",
        }
    )
    return {
        "available": True,
        "status": "manual_provenance_holdout_added",
        "threshold_rows": len(threshold_manual["rows"]),
        "evaluation_rows": len(evaluation["rows"]),
    }


def _add_source_holdout_view(
    imports: Any,
    views: list[dict[str, Any]],
    *,
    governed: dict[str, dict[str, Any]],
    private: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    all_rows = [row for bundle in governed.values() for row in bundle["rows"] if row.get("source_identity")]
    source_counts = Counter(str(row["source_identity"]) for row in all_rows)
    viable: list[tuple[int, str]] = []
    for source_identity in source_counts:
        evaluation = _filtered_bundle(
            imports,
            governed["threshold"],
            lambda row, source_identity=source_identity: (row.get("source_identity") == source_identity),
        )
        if _supports_binary_evaluation(evaluation):
            viable.append((len(evaluation["rows"]), source_identity))
    if len(source_counts) < 2 or not viable:
        return {
            "available": False,
            "status": "fewer_than_two_usable_source_identities",
            "source_identity_count": len(source_counts),
            "real_device_independence_proven": False,
        }
    _, held_source = max(viable)
    filtered = {
        role: _filtered_bundle(
            imports,
            bundle,
            lambda row, held_source=held_source: (row.get("source_identity") != held_source),
        )
        for role, bundle in governed.items()
    }
    evaluation = _filtered_bundle(
        imports,
        governed["threshold"],
        lambda row: row.get("source_identity") == held_source,
    )
    if not _supports_binary_evaluation(evaluation):
        return {
            "available": False,
            "status": "source_holdout_lost_target_support",
            "source_identity_count": len(source_counts),
            "real_device_independence_proven": False,
        }
    views.append(
        {
            "name": "source_identity_holdout",
            "fit": v56._concat_bundles(
                imports,
                filtered["development_fit"],
                private["development_fit"],
            ),
            "calibration": v56._concat_bundles(
                imports,
                filtered["calibration"],
                private["calibration"],
            ),
            "threshold": v56._concat_bundles(
                imports,
                filtered["threshold"],
                private["threshold"],
            ),
            "evaluation": evaluation,
            "uses_future_validation": False,
            "uses_locked_v53": False,
            "source_identity_held_out": True,
        }
    )
    return {
        "available": True,
        "status": "source_identity_holdout_added",
        "source_identity_count": len(source_counts),
        "evaluation_rows": len(evaluation["rows"]),
        "real_device_independence_proven": False,
    }


def _clone_bundle(bundle: dict[str, Any]) -> dict[str, Any]:
    return {
        "frame": bundle["frame"].copy(),
        "rows": list(bundle["rows"]),
        "original_labels": list(bundle["original_labels"]),
        "targets": list(bundle["targets"]),
        "base_weights": list(bundle["base_weights"]),
    }


def _stabilize_view(view: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    stabilized = {
        key: _clone_bundle(view[key]) if key in {"fit", "calibration", "threshold", "evaluation"} else value for key, value in view.items()
    }
    fit_frame = stabilized["fit"]["frame"]
    all_null_numeric = [field for field in v56.V56_NUMERIC_FEATURES if field in fit_frame and fit_frame[field].isna().all()]
    all_null_categorical = [field for field in v56.V56_CATEGORICAL_FEATURES if field in fit_frame and fit_frame[field].isna().all()]
    for role in ("fit", "calibration", "threshold", "evaluation"):
        frame = stabilized[role]["frame"]
        for field in all_null_numeric:
            frame[field] = frame[field].astype("float64").fillna(0.0)
        for field in all_null_categorical:
            frame[field] = frame[field].fillna("missing")
    return stabilized, {
        "view": view["name"],
        "all_null_numeric_defaults": all_null_numeric,
        "all_null_categorical_defaults": all_null_categorical,
        "feature_count": len(v56.V56_NUMERIC_FEATURES) + len(v56.V56_CATEGORICAL_FEATURES),
        "feature_columns_dropped": [],
    }


def _warning_summary(captured: list[warnings.WarningMessage]) -> dict[str, Any]:
    counts: Counter[str] = Counter()
    for item in captured:
        message = " ".join(str(item.message).split())
        counts[f"{item.category.__name__}: {message}"] += 1
    informational = {key for key in counts if "could not find the number of physical cores" in key.lower()}
    quality_count = sum(value for key, value in counts.items() if key not in informational)
    return {
        "count": sum(counts.values()),
        "quality_count": quality_count,
        "informational_count": sum(value for key, value in counts.items() if key in informational),
        "unique": len(counts),
        "items": [{"warning": key, "count": value} for key, value in counts.most_common(12)],
        "all_null_feature_warning_present": any("missing values" in key.lower() and "skipping" in key.lower() for key in counts),
        "sample_weight_routing_warning_present": any("sample_weight" in key.lower() for key in counts),
    }


def _select_stability_leader(comparison: dict[str, Any]) -> dict[str, Any] | None:
    summaries = comparison.get("candidate_summaries") or {}
    views = comparison.get("views") or []
    ranked: list[tuple[Any, ...]] = []
    for name, summary in summaries.items():
        metrics = summary.get("metric_ranges") or {}
        calibration = summary.get("calibration_ranges") or {}

        def minimum(field: str, default: float = 0.0) -> float:
            return float((metrics.get(field) or {}).get("minimum", default))

        def maximum(field: str, default: float = 1.0) -> float:
            return float((metrics.get(field) or {}).get("maximum", default))

        def calibration_maximum(field: str, default: float = 1.0) -> float:
            return float((calibration.get(field) or {}).get("maximum", default))

        aggregate_checks = {
            "minimum_queue_f1": minimum("queue_f1") >= v56.DEVELOPMENT_GATES["queue_f1_min"],
            "maximum_benign_fpr": maximum("benign_like_false_positive_rate")
            <= v56.DEVELOPMENT_GATES["benign_like_false_positive_rate_max"],
            "minimum_suspicious_recall": minimum("suspicious_recall") >= v56.DEVELOPMENT_GATES["suspicious_recall_min"],
            "minimum_malicious_recall": minimum("malicious_recall") >= v56.DEVELOPMENT_GATES["malicious_recall_min"],
            "maximum_ece": calibration_maximum("expected_calibration_error") <= v56.DEVELOPMENT_GATES["expected_calibration_error_max"],
            "maximum_confidence_gap": calibration_maximum("max_confidence_accuracy_gap")
            <= v56.DEVELOPMENT_GATES["max_confidence_accuracy_gap_max"],
        }
        checks_passed = sum(1 for value in aggregate_checks.values() if value)
        risk_score = (
            minimum("queue_f1")
            + (0.25 * minimum("suspicious_recall"))
            + (0.20 * minimum("malicious_recall"))
            - (1.25 * maximum("benign_like_false_positive_rate"))
            - (0.30 * calibration_maximum("expected_calibration_error"))
        )
        ranked.append(
            (
                checks_passed,
                int(aggregate_checks["maximum_benign_fpr"]),
                int(aggregate_checks["minimum_queue_f1"]),
                round(risk_score, 8),
                name,
                aggregate_checks,
            )
        )
    if not ranked:
        return None
    selected = max(ranked, key=lambda item: item[:5])
    name = str(selected[4])
    configuration = None
    for view in reversed(views):
        for strategy in view.get("strategies") or []:
            if strategy.get("name") == name and strategy.get("status") == "evaluated":
                configuration = strategy
                break
        if configuration:
            break
    if configuration is None:
        return None
    return {
        "name": name,
        "selection_basis": ("predeclared_cross_view_stability_gates_with_manual_provenance"),
        "summary": summaries[name],
        "aggregate_checks": selected[5],
        "aggregate_checks_passed": int(selected[0]),
        "passed_all_development_gates": all(selected[5].values()),
        "configuration": configuration,
    }


def _candidate_public(
    leader: dict[str, Any] | None,
    *,
    warning_report: dict[str, Any],
) -> dict[str, Any] | None:
    if not leader:
        return None
    fitted = leader.get("_latest_fitted") or leader.get("configuration") or {}
    if fitted.get("status") != "evaluated":
        return None
    threshold = fitted.get("_threshold")
    if threshold is None:
        threshold = (fitted.get("threshold_selection") or {}).get("selected_threshold")
    return {
        "name": leader["name"],
        "selection_basis": leader.get("selection_basis"),
        "target_mode": fitted.get("target_mode"),
        "model_type": fitted.get("model_type"),
        "threshold": threshold,
        "calibration_method": fitted.get("calibration_method"),
        "summary": leader.get("summary"),
        "aggregate_checks": leader.get("aggregate_checks") or {},
        "aggregate_checks_passed": leader.get("aggregate_checks_passed"),
        "feature_contract": {
            "numeric_features": list(v56.V56_NUMERIC_FEATURES),
            "categorical_features": list(v56.V56_CATEGORICAL_FEATURES),
            "feature_count": len(v56.V56_NUMERIC_FEATURES) + len(v56.V56_CATEGORICAL_FEATURES),
        },
        "training_warning_count": warning_report["quality_count"],
        "frozen_before_blind_label_access": True,
        "blind_labels_used_for_selection": False,
        "locked_final_labels_used_for_selection": False,
        "eligible_for_activation": False,
        "active_artifact_written": False,
        "model_activated": False,
        "model_promoted": False,
    }


def _readiness(
    *,
    role_lock: dict[str, Any],
    comparison: dict[str, Any],
    candidate: dict[str, Any] | None,
    provenance_holdout: dict[str, Any],
    source_holdout: dict[str, Any],
    warning_report: dict[str, Any],
    safety: dict[str, Any],
) -> dict[str, Any]:
    summaries = comparison.get("candidate_summaries") or {}
    selected_summary = summaries.get((candidate or {}).get("name"), {})
    checks = {
        "v521_role_lock_reproduced": bool(role_lock.get("passed")),
        "candidate_frozen": candidate is not None,
        "all_development_views_passed": bool(selected_summary.get("all_views_passed")),
        "manual_provenance_holdout_available": bool(provenance_holdout.get("available")),
        "source_holdout_available": bool(source_holdout.get("available")),
        "training_warnings_clear": warning_report.get("quality_count") == 0,
        "independent_human_blind_labels_available": False,
        "database_unchanged": bool(safety.get("database_counts_unchanged")),
        "artifacts_unchanged": bool(safety.get("model_artifacts_unchanged")),
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
            "The selected candidate is diagnostic shadow evidence only. "
            "Independent human-confirmed native labels and a second real "
            "source remain mandatory before lifecycle advancement."
        ),
    }


def _render_report(result: dict[str, Any]) -> str:
    candidate = result.get("frozen_shadow_candidate") or {}
    readiness = result.get("readiness") or {}
    evidence = result.get("native_evidence") or {}
    provenance = result.get("label_provenance") or {}
    lines = [
        "# v5.22 Supervised Model Rebuild",
        "",
        f"Generated: `{result.get('generated_at')}`",
        "",
        "## Evidence Lock",
        "",
        f"- v5.21 lock reproduced: `{evidence.get('role_lock_reproduced')}`",
        f"- Development rows: `{evidence.get('development_rows')}`",
        f"- Calibration rows: `{evidence.get('calibration_rows')}`",
        f"- Threshold rows: `{evidence.get('threshold_rows')}`",
        "- Untouched future labels opened: `false`",
        "- Blind pack opened: `false`",
        "",
        "## Provenance",
        "",
        f"- Human-reviewed governed rows: `{provenance.get('genuinely_human_reviewed_rows')}`",
        f"- Assisted/weak governed rows: `{provenance.get('assisted_or_weak_rows')}`",
        "- Private development suggestions are weak labels, not human ground truth.",
        "",
        "## Frozen Shadow Candidate",
        "",
        f"- Candidate: `{candidate.get('name')}`",
        f"- Model: `{candidate.get('model_type')}`",
        f"- Target mode: `{candidate.get('target_mode')}`",
        f"- Calibration: `{candidate.get('calibration_method')}`",
        f"- Threshold: `{candidate.get('threshold')}`",
        f"- Development views all passed: `{(candidate.get('summary') or {}).get('all_views_passed')}`",
        "- Artifact written: `false`",
        "- Activated/promoted: `false/false`",
        "",
        "## Readiness",
        "",
        f"- Decision: `{readiness.get('decision')}`",
        f"- Checks: `{readiness.get('checks_passed')}/{readiness.get('checks_total')}`",
        f"- Blockers: `{readiness.get('blockers')}`",
        "",
        "Rules remain alert-authoritative. Automatic response and real firewall " "blocking remain disabled.",
    ]
    return "\n".join(lines) + "\n"


def run_v522_supervised_model_rebuild(
    db: Session,
    *,
    sample_path: str | Path,
    use_temp_db: bool,
    evidence_dir: str | Path = V522_OUTPUT_DIR,
    output_dir: str | Path = V522_OUTPUT_DIR,
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
            "The private evidence file is unavailable.",
        )
    imports = v56._optional_imports()
    if imports is None:
        return _safe_failure(
            "dependencies_unavailable",
            "Required supervised-learning dependencies are unavailable.",
        )
    manifest, manifest_validation = _load_v521_manifest(
        path,
        evidence_dir=evidence,
    )
    if not manifest or not manifest_validation.get("passed"):
        return {
            **_safe_failure(
                "failed_closed_v521_manifest_validation",
                "The v5.21 native evidence lock did not validate.",
            ),
            "manifest_validation": manifest_validation,
        }

    counts_before = frozen._database_counts(db)
    artifacts_before = v55._model_artifact_states()
    dataset = v52._prepare_dataset(db, min_samples=min_samples)
    if not dataset.get("ok"):
        return {
            **_safe_failure(
                "failed_closed_governed_evidence_unavailable",
                str(dataset.get("message") or "Governed evidence is unavailable."),
            ),
            "governed_status": dataset.get("status"),
        }
    partition = frozen.build_frozen_partition(
        dataset["rows"],
        split_mode="temporal_holdout",
    )
    leakage = frozen.audit_partition_leakage(dataset["rows"], partition)
    if not leakage.get("passed"):
        return _safe_failure(
            "failed_closed_governed_partition_leakage",
            "The governed development partition failed leakage checks.",
        )
    evidence_lock = v54.build_evidence_lock(dataset, output_dir=output)
    governed_lock = v54.validate_evidence_lock(evidence_lock)
    if not governed_lock.get("passed"):
        return {
            **_safe_failure(
                "failed_closed_governed_lock_mismatch",
                "The governed development lock changed; model rebuilding stopped.",
            ),
            "governed_lock": governed_lock,
        }

    comparison: dict[str, Any] = {
        "status": "not_run_preflight_only",
        "views": [],
        "candidate_summaries": {},
    }
    candidate: dict[str, Any] | None = None
    provenance_holdout = {"available": False, "status": "not_run"}
    source_holdout = {"available": False, "status": "not_run"}
    warning_report = _warning_summary([])
    policy: dict[str, Any] = {
        "status": "not_run_preflight_only",
        "future_role_rows_labeled": 0,
        "blind_pack_opened": False,
    }
    role_lock: dict[str, Any]
    roles: dict[str, Any]
    feature_stability: list[dict[str, Any]] = []

    with tempfile.TemporaryDirectory(prefix="atdr-v522-") as directory:
        disposable_path = Path(directory) / "derived-evidence.sqlite3"
        connection = sqlite3.connect(disposable_path)
        try:
            profile = v56.stream_private_file_to_disposable_index(
                path,
                connection,
                database_url="sqlite:///:memory:",
                chunk_size=chunk_size,
            )
            if not profile.get("ok"):
                return {
                    **_safe_failure(
                        str(profile.get("status") or "private_stream_failed"),
                        "Private evidence streaming failed.",
                    ),
                    "private_profile": {
                        key: value
                        for key, value in profile.items()
                        if key
                        in {
                            "ok",
                            "status",
                            "rows_processed",
                            "parser_successes",
                            "parser_failures",
                        }
                    },
                }
            roles = v56.predeclare_chronological_roles(connection)
            if not roles.get("ok"):
                return _safe_failure(
                    str(roles.get("status") or "role_partition_failed"),
                    "Native chronological role partitioning failed.",
                )
            role_lock = _validate_rebuilt_roles(manifest, connection)
            if not role_lock.get("passed"):
                return {
                    **_safe_failure(
                        "failed_closed_v521_role_lock_mismatch",
                        "The rebuilt native evidence roles do not match v5.21.",
                    ),
                    "role_lock": role_lock,
                }
            v56.build_disposable_behavior_aggregates(connection)
            if not preflight_only:
                policy = apply_development_only_assisted_policy(connection)
                governed, provenance_summary = _governed_bundles_with_provenance(
                    dataset,
                    partition,
                )
                private: dict[str, dict[str, Any]] = {}
                private_selection: dict[str, Any] = {}
                for role_rank, role_name, cap in (
                    (0, "development_fit", max_fit_rows),
                    (1, "calibration", max_calibration_rows),
                    (2, "threshold", max_threshold_rows),
                ):
                    private[role_name], private_selection[role_name] = v56.load_private_role_bundle(
                        connection,
                        imports,
                        role_rank=role_rank,
                        max_rows=cap,
                    )
                views = v56.build_development_views(
                    imports,
                    human=governed,
                    private=private,
                )
                provenance_holdout = _add_provenance_holdout_view(
                    imports,
                    views,
                    governed=governed,
                    private=private,
                )
                source_holdout = _add_source_holdout_view(
                    imports,
                    views,
                    governed=governed,
                    private=private,
                )
                stabilized_views = []
                for view in views:
                    stabilized, stability = _stabilize_view(view)
                    stabilized_views.append(stabilized)
                    feature_stability.append(stability)
                with warnings.catch_warnings(record=True) as captured:
                    warnings.simplefilter("always")
                    comparison, _legacy_leader = v56.run_supervised_development_comparison(
                        imports,
                        stabilized_views,
                    )
                warning_report = _warning_summary(captured)
                leader = _select_stability_leader(comparison)
                comparison["v522_selection"] = {key: value for key, value in (leader or {}).items() if key != "configuration"}
                candidate = _candidate_public(
                    leader,
                    warning_report=warning_report,
                )
            else:
                provenance_summary = {
                    "genuinely_human_reviewed_rows": 0,
                    "assisted_or_weak_rows": 0,
                    "preflight_only": True,
                }
                private_selection = {}
        finally:
            connection.close()

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
        "blind_pack_opened": False,
        "future_role_labels_opened": False,
        "active_model_artifact_written": False,
        "model_activated": False,
        "model_promoted": False,
        "rules_alert_authoritative": True,
        "ml_alert_authority": False,
        "automatic_response_enabled": False,
        "real_firewall_blocking_enabled": False,
    }
    readiness = _readiness(
        role_lock=role_lock,
        comparison=comparison,
        candidate=candidate,
        provenance_holdout=provenance_holdout,
        source_holdout=source_holdout,
        warning_report=warning_report,
        safety=safety,
    )
    role_rows = role_lock.get("role_rows") or {}
    result = {
        "ok": bool(
            manifest_validation.get("passed")
            and governed_lock.get("passed")
            and role_lock.get("passed")
            and safety["database_counts_unchanged"]
            and safety["model_artifacts_unchanged"]
            and safety["labels_created"] == 0
            and safety["model_runs_created"] == 0
            and safety["detection_runs_created"] == 0
            and safety["alerts_created"] == 0
            and safety["response_actions_created"] == 0
            and policy.get("future_role_rows_labeled") == 0
        ),
        "status": "preflight_complete" if preflight_only else "diagnostic_shadow_candidate_frozen",
        "version": V522_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "lifecycle_state": "shadow_observation",
        "manifest_validation": manifest_validation,
        "governed_lock": {
            "passed": bool(governed_lock.get("passed")),
            "status": governed_lock.get("status"),
            "fingerprints_returned": False,
        },
        "native_evidence": {
            "role_lock_reproduced": bool(role_lock.get("passed")),
            "development_rows": int(role_rows.get("development_fit") or 0),
            "calibration_rows": int(role_rows.get("calibration") or 0),
            "threshold_rows": int(role_rows.get("threshold") or 0),
            "untouched_future_rows": int(role_rows.get("untouched_future_validation") or 0),
            "quarantine_rows": int(role_rows.get("quarantine") or 0),
            "exact_family_cross_role_count": int(roles.get("exact_family_cross_role_count") or 0),
            "near_family_cross_role_count": int(roles.get("near_family_cross_role_count") or 0),
            "blind_pack_opened": False,
            "blind_decisions_opened": False,
            "fingerprints_returned": False,
        },
        "label_provenance": {
            **provenance_summary,
            "private_policy": policy,
            "ai_or_rule_suggestions_marked_human_reviewed": 0,
            "human_labels_fabricated": 0,
        },
        "sampling": {
            "development_roles": private_selection,
            "future_role_sampled": False,
            "ambiguous_private_rows_used_for_training": False,
        },
        "validation_views": {
            "count": len(comparison.get("views") or []),
            "manual_provenance_holdout": provenance_holdout,
            "source_holdout": source_holdout,
            "uses_locked_final_or_blind_evidence": False,
            "duplicate_family_isolation": True,
        },
        "feature_contract_stability": feature_stability,
        "training_warnings": warning_report,
        "supervised_development_comparison": comparison,
        "frozen_shadow_candidate": candidate,
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
        (output / V522_LATEST).write_text(
            json.dumps(result, indent=2, default=str),
            encoding="utf-8",
        )
        (output / f"{V522_REPORT_PREFIX}{stamp}.md").write_text(
            _render_report(result),
            encoding="utf-8",
        )
    return result
