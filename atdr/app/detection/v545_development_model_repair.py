from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import tempfile
import time
from collections import Counter, defaultdict
from datetime import UTC, datetime, timezone
from pathlib import Path
from statistics import mean
from typing import Any, Iterable

from sqlalchemy.orm import Session

from atdr.app.core.config import PROJECT_ROOT, get_settings
from atdr.app.detection import v398_independent_holdout_validation as frozen
from atdr.app.detection import v49_detection_ml_reliability as reliability
from atdr.app.detection import v540_development_supervised_repair as v540
from atdr.app.detection import v541_governed_blind_evidence as v541
from atdr.app.detection import v542_development_candidate_freeze as v542
from atdr.app.detection import v543_temporal_stability_repair as v543
from atdr.app.detection import v544_chronological_evidence as v544
from atdr.app.detection import v55_development_model_repair as v55
from atdr.app.detection import v56_private_panos_model_repair as v56
from atdr.app.detection.supervised_detector import _optional_imports
from atdr.app.detection.v331_noise_reduction import _build_pipeline_for_columns


V545_VERSION = "v5.45-development-only-supervised-repair-v1"
V545_OUTPUT_DIR = PROJECT_ROOT / "ml_baseline_reviews" / "v5_45_model_repair"
V545_LATEST = "v5_45_development_model_repair_latest.json"
V545_FREEZE_MANIFEST = "v5_45_diagnostic_candidate_manifest.json"
V545_REPORT_PREFIX = "v5_45_development_model_repair"

FIXED_FREEZE_GATES = dict(v542.FIXED_FREEZE_GATES)
MANUAL_PROVENANCE = frozenset({"manual", "reviewed_import"})
ASSISTED_SOURCE_WEIGHTS = {
    "assisted_rule": 0.55,
    "assisted_ml": 0.35,
    "assisted_hybrid": 0.40,
    "vendor_threat_assisted": 0.55,
    "rule_assisted": 0.45,
    "codex_assisted": 0.30,
    "weak_supervision": 0.20,
}
DEFAULT_MAX_ROWS = {
    "development_fit": 8000,
    "calibration": 3000,
    "threshold": 3500,
}

STRATEGY_SPECS = (
    {
        "name": "calibrated_extra_trees_flat_5class",
        "model_type": "extra_trees",
        "target_mode": "flat_5class",
        "class_weight": "balanced",
        "calibration_method": "sigmoid",
        "assisted_weight_cap": 0.50,
    },
    {
        "name": "calibrated_hist_gradient_boosting_flat_5class",
        "model_type": "hist_gradient_boosting",
        "target_mode": "flat_5class",
        "class_weight": None,
        "calibration_method": "sigmoid",
        "assisted_weight_cap": 0.50,
    },
    {
        "name": "calibrated_logistic_regression_flat_5class",
        "model_type": "logistic_regression",
        "target_mode": "flat_5class",
        "class_weight": "balanced",
        "calibration_method": "sigmoid",
        "assisted_weight_cap": 0.50,
    },
    {
        "name": "binary_threat_positive_extra_trees",
        "model_type": "extra_trees",
        "target_mode": "binary_threat_positive",
        "class_weight": "balanced",
        "calibration_method": "sigmoid",
        "assisted_weight_cap": 0.50,
    },
    {
        "name": "three_class_soc_queue_extra_trees",
        "model_type": "extra_trees",
        "target_mode": "three_class_soc_queue",
        "class_weight": "balanced",
        "calibration_method": "sigmoid",
        "assisted_weight_cap": 0.50,
    },
    {
        "name": "hierarchical_two_stage_extra_trees",
        "model_type": "extra_trees",
        "target_mode": "hierarchical_two_stage",
        "class_weight": "balanced",
        "calibration_method": "sigmoid",
        "assisted_weight_cap": 0.50,
    },
    {
        "name": "binary_threat_positive_anchor_strict",
        "model_type": "extra_trees",
        "target_mode": "binary_threat_positive",
        "class_weight": "balanced",
        "calibration_method": "sigmoid",
        "assisted_weight_cap": 0.25,
    },
    {
        "name": "binary_threat_positive_anchor_max",
        "model_type": "extra_trees",
        "target_mode": "binary_threat_positive",
        "class_weight": "balanced",
        "calibration_method": "sigmoid",
        "assisted_weight_cap": 0.75,
    },
)

PATTERN_ORDER = (
    "benign_quic_443",
    "incomplete_allow_80",
    "unknown_udp_tcp",
    "scan_like_behavior",
    "denied_high_risk_service",
    "vendor_threat_record",
    "suspicious_malicious_boundary",
    "routine_known_application",
    "other",
)


class V545RepairError(RuntimeError):
    pass


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _stamp() -> str:
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")


def _number(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _integer(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _stable_hash(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        ).encode("utf-8")
    ).hexdigest()


def _atomic_write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(
        json.dumps(value, indent=2, sort_keys=True, default=str),
        encoding="utf-8",
    )
    os.replace(temporary, path)


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError) as exc:
        raise V545RepairError("A required development lock is unreadable.") from exc
    if not isinstance(value, dict):
        raise V545RepairError("A required development lock is malformed.")
    return value


def _v544_lock_status(output_dir: Path) -> dict[str, Any]:
    state_path = output_dir / v544.V544_PRIVATE_STATE
    lock_path = output_dir / v544.V544_PRIVATE_LOCK
    latest_path = output_dir / v544.V544_LATEST
    if not state_path.is_file() or not lock_path.is_file() or not latest_path.is_file():
        raise V545RepairError("The complete v5.44 private development lock is required.")
    state = _read_json(state_path)
    latest = _read_json(latest_path)
    checks = {
        "state_schema_valid": state.get("schema_version") == v544.V544_VERSION,
        "state_status_valid": state.get("status") == "development_evidence_locked",
        "latest_schema_valid": latest.get("version") == v544.V544_VERSION,
        "latest_safety_valid": bool((latest.get("safety") or {}).get("all_invariants_passed")),
        "future_labels_sealed": not bool(
            (latest.get("cohort_manifest") or {}).get("reserved_future_labels_opened")
        ),
        "lock_file_present": lock_path.stat().st_size > 0,
    }
    if not all(checks.values()):
        raise V545RepairError("The v5.44 private development lock failed validation.")
    return {
        "checks": checks,
        "all_checks_passed": True,
        "state_path": state_path,
        "lock_path": lock_path,
        "latest": latest,
    }


def _protected_state(
    *,
    v544_output_dir: Path,
    state_path: Path,
    pack_path: Path,
    blind_output_dir: Path,
    v542_output_dir: Path,
    v543_output_dir: Path,
) -> dict[str, Any]:
    return {
        "earlier": v544._protected_workspace_state(
            state_path=state_path,
            pack_path=pack_path,
            blind_output_dir=blind_output_dir,
            v542_output_dir=v542_output_dir,
            v543_output_dir=v543_output_dir,
        ),
        "v544_state": v55._file_state(v544_output_dir / v544.V544_PRIVATE_STATE),
        "v544_lock": v55._file_state(v544_output_dir / v544.V544_PRIVATE_LOCK),
        "v544_latest": v55._file_state(v544_output_dir / v544.V544_LATEST),
    }


def revalidate_v545_custody(
    db: Session,
    *,
    min_samples: int = 100,
    v544_output_dir: Path = v544.V544_OUTPUT_DIR,
    state_path: Path = v540.V539_STATE_PATH,
    pack_path: Path = v540.DEFAULT_PACK_PATH,
    blind_output_dir: Path = v541.V541_OUTPUT_DIR,
    v542_output_dir: Path = v542.V542_OUTPUT_DIR,
    v543_output_dir: Path = v543.V543_OUTPUT_DIR,
) -> dict[str, Any]:
    custody = v544.revalidate_v544_custody(
        db,
        min_samples=min_samples,
        state_path=state_path,
        pack_path=pack_path,
        blind_output_dir=blind_output_dir,
        v542_output_dir=v542_output_dir,
        v543_output_dir=v543_output_dir,
    )
    lock = _v544_lock_status(v544_output_dir)
    checks = {
        "v544_custody_valid": bool(custody.get("all_checks_passed")),
        "v544_lock_valid": bool(lock.get("all_checks_passed")),
        "fixed_v542_gates_unchanged": FIXED_FREEZE_GATES == v542.FIXED_FREEZE_GATES,
        "v544_development_repair_ready": bool(
            ((lock.get("latest") or {}).get("sufficiency") or {}).get(
                "development_only_model_repair_ready"
            )
        ),
        "v544_future_labels_sealed": not bool(
            ((lock.get("latest") or {}).get("cohort_manifest") or {}).get(
                "reserved_future_labels_opened"
            )
        ),
    }
    if not all(checks.values()):
        raise V545RepairError("The v5.44 development boundary is not eligible for repair.")
    return {
        "custody": custody,
        "private_lock": lock,
        "checks": checks,
        "all_checks_passed": True,
    }


def _public_custody(state: dict[str, Any]) -> dict[str, Any]:
    latest = state["private_lock"]["latest"]
    cohorts = latest.get("cohort_manifest") or {}
    return {
        "status": "v5_44_development_boundary_revalidated",
        "checks": dict(state["checks"]),
        "all_checks_passed": bool(state["all_checks_passed"]),
        "existing_anchor_rows": int(state["custody"].get("development_rows") or 0),
        "cohort_rows": {
            name: int(values.get("rows") or 0)
            for name, values in (cohorts.get("cohorts") or {}).items()
        },
        "future_labels_opened": False,
        "private_paths_returned": False,
        "private_digests_returned": False,
        "private_identifiers_returned": False,
    }


def _empty_bundle(imports: Any) -> dict[str, Any]:
    return v56._empty_bundle(imports)


def _slice_bundle(imports: Any, bundle: dict[str, Any], indices: Iterable[int]) -> dict[str, Any]:
    return v56._slice_bundle(imports, bundle, [int(value) for value in indices])


def _concat_bundles(imports: Any, *bundles: dict[str, Any]) -> dict[str, Any]:
    return v56._concat_bundles(imports, *bundles)


def _human_role_bundles(
    development: dict[str, Any],
    canonical: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    imports = development["imports"]
    pd = imports[1]
    governed_to_development = {
        int(row["governed_index"]): index
        for index, row in enumerate(development["rows"])
        if row.get("governed_index") is not None
    }
    output: dict[str, dict[str, Any]] = {}
    for role_name, key in v56.ROLE_KEYS.items():
        indices = [
            governed_to_development[int(value)]
            for value in canonical.get(key, [])
            if int(value) in governed_to_development
        ]
        feature_rows = [
            v56._human_feature_row(
                development["frame"].iloc[index],
                development["logs"][index],
            )
            for index in indices
        ]
        metadata: list[dict[str, Any]] = []
        base_weights: list[float] = []
        labels = [development["original_labels"][index] for index in indices]
        for index in indices:
            row = development["rows"][index]
            provenance = str(row.get("label_source") or "unknown")
            manual = provenance in MANUAL_PROVENANCE
            metadata.append(
                {
                    "timestamp": row.get("timestamp"),
                    "app": row.get("app"),
                    "action": row.get("action"),
                    "dst_port": row.get("dst_port"),
                    "schema": "governed_database",
                    "provenance": provenance,
                    "human_reviewed": manual,
                    "group_size": 1,
                    "evidence_role": role_name,
                    "original_label": development["original_labels"][index],
                    "private_source": False,
                    "_duplicate_family": str(
                        row.get("leakage_group")
                        or row.get("near_fingerprint")
                        or f"governed-{row.get('log_id')}-{index}"
                    ),
                }
            )
            base_weights.append(
                1.0 if manual else ASSISTED_SOURCE_WEIGHTS.get(provenance, 0.35)
            )
        output[role_name] = {
            "frame": pd.DataFrame(feature_rows).reindex(
                columns=[*v56.V56_NUMERIC_FEATURES, *v56.V56_CATEGORICAL_FEATURES]
            ),
            "rows": metadata,
            "original_labels": labels,
            "targets": [v56._queue_target(value) for value in labels],
            "base_weights": base_weights,
        }
    return output


_PRIVATE_MODEL_QUERY = v56.MODEL_ROW_QUERY.replace(
    "    e.id, e.event_time,",
    "    e.id, e.candidate_near_hash, e.event_time,",
    1,
)
_PRIVATE_MODEL_COLUMNS = [
    "id",
    "candidate_near_hash",
    *v56.MODEL_ROW_COLUMNS[1:],
]


def _load_private_role_bundle(
    connection: sqlite3.Connection,
    imports: Any,
    *,
    role_rank: int,
    max_rows: int,
) -> tuple[dict[str, Any], dict[str, Any]]:
    if role_rank not in v544.DEVELOPMENT_ROLE_RANKS:
        raise V545RepairError("Only v5.44 development roles may be opened.")
    connection.execute("DROP TABLE IF EXISTS selected_representatives")
    connection.execute(
        "CREATE TEMP TABLE selected_representatives("
        "representative_id INTEGER PRIMARY KEY)"
    )
    labels = ("benign", "benign_unusual", "suspicious", "malicious")
    quota = max(1, int(max_rows) // len(labels))
    selected: list[int] = []
    available: dict[str, int] = {}
    for label in labels:
        available[label] = int(
            connection.execute(
                "SELECT COUNT(*) FROM assisted_groups WHERE role_rank=? "
                "AND training_eligible=1 AND decision=?",
                (role_rank, label),
            ).fetchone()[0]
        )
        selected.extend(
            int(row[0])
            for row in connection.execute(
                "SELECT representative_id FROM assisted_groups WHERE role_rank=? "
                "AND training_eligible=1 AND decision=? "
                "ORDER BY propagation_hash LIMIT ?",
                (role_rank, label, quota),
            )
        )
    connection.executemany(
        "INSERT OR IGNORE INTO selected_representatives VALUES (?)",
        [(value,) for value in selected],
    )
    rows = [
        dict(zip(_PRIVATE_MODEL_COLUMNS, values, strict=True))
        for values in connection.execute(_PRIVATE_MODEL_QUERY)
    ]
    bundle = v56._bundle_from_private_rows(imports, rows)
    for metadata, row in zip(bundle["rows"], rows, strict=True):
        rule_codes, _ = v56._rule_evidence(row)
        metadata.update(
            {
                "_duplicate_family": str(row["candidate_near_hash"]),
                "pattern": v544._pattern_for_row(row, rule_codes),
                "log_type": str(row.get("log_type") or "missing"),
                "threat_severity": str(row.get("threat_severity") or "none"),
            }
        )
    return bundle, {
        "role": v56.ROLE_NAMES[role_rank],
        "available_training_groups_by_label": available,
        "selected_representative_rows": len(rows),
        "selection_cap": int(max_rows),
        "selection": "deterministic_stratified_duplicate_representatives",
        "duplicate_rows_replicated": False,
        "future_labels_opened": False,
        "private_identifiers_returned": False,
    }


def _contain_candidate_near_families(
    connection: sqlite3.Connection,
) -> dict[str, Any]:
    connection.executescript(
        """
        DROP TABLE IF EXISTS v545_cross_role_candidate_families;
        CREATE TEMP TABLE v545_cross_role_candidate_families AS
        SELECT candidate_near_hash
        FROM events
        WHERE quarantine_reason IS NULL
        GROUP BY candidate_near_hash
        HAVING COUNT(DISTINCT role_rank) > 1;
        CREATE INDEX ix_v545_cross_role_candidate_families
            ON v545_cross_role_candidate_families(candidate_near_hash);
        """
    )
    family_count = int(
        connection.execute(
            "SELECT COUNT(*) FROM v545_cross_role_candidate_families"
        ).fetchone()[0]
    )
    event_count = int(
        connection.execute(
            "SELECT COUNT(*) FROM events WHERE candidate_near_hash IN "
            "(SELECT candidate_near_hash FROM v545_cross_role_candidate_families)"
        ).fetchone()[0]
    )
    future_event_count = int(
        connection.execute(
            "SELECT COUNT(*) FROM events WHERE role_rank=3 AND "
            "candidate_near_hash IN (SELECT candidate_near_hash FROM "
            "v545_cross_role_candidate_families)"
        ).fetchone()[0]
    )
    connection.execute(
        "UPDATE events SET role_rank=4, "
        "quarantine_reason='v545_candidate_near_cross_role' "
        "WHERE candidate_near_hash IN (SELECT candidate_near_hash FROM "
        "v545_cross_role_candidate_families)"
    )
    connection.commit()
    remaining_cross_role = int(
        connection.execute(
            "SELECT COUNT(*) FROM (SELECT candidate_near_hash FROM events "
            "WHERE role_rank IN (0,1,2,3) AND quarantine_reason IS NULL "
            "GROUP BY candidate_near_hash HAVING COUNT(DISTINCT role_rank)>1)"
        ).fetchone()[0]
    )
    return {
        "status": "candidate_near_cross_role_families_quarantined",
        "quarantined_candidate_families": family_count,
        "quarantined_event_rows": event_count,
        "quarantined_reserved_future_rows": future_event_count,
        "remaining_candidate_family_cross_role_count": remaining_cross_role,
        "passed": remaining_cross_role == 0,
        "labels_inspected": False,
        "future_labels_opened": False,
        "family_identifiers_returned": False,
    }


def _timestamp(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value
    return datetime.min.replace(tzinfo=timezone.utc)


def _split_temporal_families(
    imports: Any,
    bundle: dict[str, Any],
    *,
    segments: int,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if segments < 2:
        raise ValueError("At least two temporal segments are required.")
    windows = sorted(
        {
            _timestamp(row.get("timestamp")).replace(second=0, microsecond=0)
            for row in bundle["rows"]
            if row.get("timestamp") is not None
        }
    )
    if len(windows) < segments:
        return [], {
            "status": "insufficient_time_windows",
            "time_windows": len(windows),
            "segments": segments,
            "duplicate_family_cross_segment_count": 0,
        }
    boundaries = [
        windows[min(len(windows) - 1, (len(windows) * index) // segments)]
        for index in range(1, segments)
    ]

    def segment_for(row: dict[str, Any]) -> int:
        value = _timestamp(row.get("timestamp"))
        return sum(value >= boundary for boundary in boundaries)

    representative_by_family: dict[str, int] = {}
    for index, row in enumerate(bundle["rows"]):
        family = str(row.get("_duplicate_family"))
        current = representative_by_family.get(family)
        if current is None:
            representative_by_family[family] = index
            continue
        current_row = bundle["rows"][current]
        candidate_key = (
            not bool(row.get("human_reviewed")),
            _timestamp(row.get("timestamp")),
            index,
        )
        current_key = (
            not bool(current_row.get("human_reviewed")),
            _timestamp(current_row.get("timestamp")),
            current,
        )
        if candidate_key < current_key:
            representative_by_family[family] = index
    indices: list[list[int]] = [[] for _ in range(segments)]
    for index in sorted(representative_by_family.values()):
        row = bundle["rows"][index]
        indices[segment_for(row)].append(index)
    slices = [_slice_bundle(imports, bundle, values) for values in indices]
    return slices, {
        "status": "partitioned" if all(len(value["rows"]) for value in slices) else "empty_segment",
        "time_windows": len(windows),
        "segments": segments,
        "segment_rows": [len(value["rows"]) for value in slices],
        "duplicate_representative_rows_collapsed": (
            len(bundle["rows"]) - len(representative_by_family)
        ),
        "quarantined_crossing_family_rows": 0,
        "duplicate_family_cross_segment_count": 0,
        "exact_time_boundaries_returned": False,
        "family_identifiers_returned": False,
    }


def _manual_only(imports: Any, bundle: dict[str, Any]) -> dict[str, Any]:
    return _slice_bundle(
        imports,
        bundle,
        [
            index
            for index, row in enumerate(bundle["rows"])
            if bool(row.get("human_reviewed"))
        ],
    )


def _cap_assisted_rows(
    imports: Any,
    bundle: dict[str, Any],
    *,
    assisted_to_manual_ratio: float = 1.0,
) -> tuple[dict[str, Any], dict[str, Any]]:
    manual = [
        index
        for index, row in enumerate(bundle["rows"])
        if bool(row.get("human_reviewed"))
    ]
    assisted = [
        index
        for index, row in enumerate(bundle["rows"])
        if not bool(row.get("human_reviewed"))
    ]
    if not manual:
        return bundle, {
            "manual_rows": 0,
            "assisted_rows": len(assisted),
            "assisted_row_cap_applied": False,
        }
    cap = max(1, int(len(manual) * max(0.0, assisted_to_manual_ratio)))
    selected_assisted = sorted(
        assisted,
        key=lambda index: (
            str(bundle["rows"][index].get("provenance") or "unknown"),
            str(bundle["rows"][index].get("pattern") or "unknown"),
            str(bundle["rows"][index].get("_duplicate_family") or ""),
        ),
    )[:cap]
    result = _slice_bundle(imports, bundle, [*manual, *selected_assisted])
    return result, {
        "manual_rows": len(manual),
        "assisted_rows_available": len(assisted),
        "assisted_rows_selected": len(selected_assisted),
        "assisted_row_cap_applied": len(selected_assisted) < len(assisted),
        "assisted_to_manual_ratio_max": assisted_to_manual_ratio,
    }


def _family_leakage(view: dict[str, Any]) -> dict[str, Any]:
    roles = {
        name: {
            str(row.get("_duplicate_family"))
            for row in view[name]["rows"]
            if row.get("_duplicate_family")
        }
        for name in ("fit", "calibration", "threshold", "evaluation")
    }
    pairs: dict[str, int] = {}
    names = list(roles)
    for left_index, left in enumerate(names):
        for right in names[left_index + 1 :]:
            pairs[f"{left}_vs_{right}"] = len(roles[left] & roles[right])
    return {
        "passed": all(value == 0 for value in pairs.values()),
        "pair_overlap_counts": pairs,
        "family_identifiers_returned": False,
    }


def _provenance_profile(bundle: dict[str, Any]) -> dict[str, Any]:
    provenance = Counter(str(row.get("provenance") or "unknown") for row in bundle["rows"])
    labels = Counter(str(value) for value in bundle["original_labels"])
    return {
        "rows": len(bundle["rows"]),
        "manual_or_reviewed_rows": sum(
            1 for row in bundle["rows"] if bool(row.get("human_reviewed"))
        ),
        "assisted_rows": sum(
            1 for row in bundle["rows"] if not bool(row.get("human_reviewed"))
        ),
        "provenance_counts": dict(sorted(provenance.items())),
        "label_counts": dict(sorted(labels.items())),
    }


def _view_gate_support(view: dict[str, Any]) -> dict[str, Any]:
    partition_support: dict[str, Any] = {}
    for name in ("fit", "calibration", "threshold", "evaluation"):
        bundle = view[name]
        queue_counts = Counter(str(value) for value in bundle.get("targets") or [])
        partition_support[name] = {
            "non_threat_rows": int(queue_counts.get("non_threat", 0)),
            "needs_review_rows": int(queue_counts.get("needs_review", 0)),
            "binary_queue_support": bool(
                queue_counts.get("non_threat", 0)
                and queue_counts.get("needs_review", 0)
            ),
        }

    evaluation_labels = Counter(
        str(value) for value in view["evaluation"].get("original_labels") or []
    )
    evaluation_support = {
        "benign_like_rows": int(
            evaluation_labels.get("benign", 0)
            + evaluation_labels.get("benign_unusual", 0)
        ),
        "suspicious_rows": int(evaluation_labels.get("suspicious", 0)),
        "malicious_rows": int(evaluation_labels.get("malicious", 0)),
    }
    passed = bool(
        all(value["binary_queue_support"] for value in partition_support.values())
        and all(evaluation_support.values())
    )
    return {
        "passed": passed,
        "partition_support": partition_support,
        "evaluation_support": evaluation_support,
        "labels_returned": False,
        "private_identifiers_returned": False,
    }


def build_development_views(
    imports: Any,
    *,
    human: dict[str, dict[str, Any]],
    private: dict[str, dict[str, Any]],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    views: list[dict[str, Any]] = []
    optional_view_audits: list[dict[str, Any]] = []
    manual_calibration = _manual_only(imports, human["calibration"])
    manual_threshold = _manual_only(imports, human["threshold"])
    fit = _concat_bundles(
        imports,
        human["development_fit"],
        private["development_fit"],
    )

    if (
        len(fit["rows"])
        and len(manual_calibration["rows"])
        and len(manual_threshold["rows"])
        and len(private["calibration"]["rows"])
    ):
        views.append(
            {
                "name": "calibration_cohort_holdout",
                "evaluation_cohort": "calibration",
                "fit": fit,
                "calibration": manual_calibration,
                "threshold": manual_threshold,
                "evaluation": private["calibration"],
                "partition_audit": {
                    "status": "predeclared_v5_44_role_holdout",
                    "fit_role": "development_fit",
                    "evaluation_role": "calibration",
                    "duplicate_family_cross_segment_count": 0,
                    "exact_time_boundaries_returned": False,
                    "family_identifiers_returned": False,
                },
            }
        )

    mixed_calibration, mixed_calibration_cap = _cap_assisted_rows(
        imports,
        _concat_bundles(imports, manual_calibration, private["calibration"]),
    )
    if (
        len(fit["rows"])
        and len(mixed_calibration["rows"])
        and len(manual_threshold["rows"])
        and len(private["threshold"]["rows"])
    ):
        views.append(
            {
                "name": "threshold_cohort_holdout",
                "evaluation_cohort": "threshold",
                "fit": fit,
                "calibration": mixed_calibration,
                "threshold": manual_threshold,
                "evaluation": private["threshold"],
                "partition_audit": {
                    "status": "predeclared_v5_44_role_holdout",
                    "fit_role": "development_fit",
                    "calibration_role": "calibration",
                    "evaluation_role": "threshold",
                    "duplicate_family_cross_segment_count": 0,
                    "exact_time_boundaries_returned": False,
                    "family_identifiers_returned": False,
                },
                "calibration_provenance_cap": mixed_calibration_cap,
            }
        )

    private_threshold_capped = _slice_bundle(
        imports,
        private["threshold"],
        range(min(len(private["threshold"]["rows"]), len(manual_threshold["rows"]))),
    )
    if (
        len(fit["rows"])
        and len(mixed_calibration["rows"])
        and len(private_threshold_capped["rows"])
        and len(manual_threshold["rows"])
    ):
        views.append(
            {
                "name": "manual_anchor_holdout",
                "evaluation_cohort": "manual_reviewed_threshold",
                "fit": fit,
                "calibration": mixed_calibration,
                "threshold": private_threshold_capped,
                "evaluation": manual_threshold,
                "partition_audit": {
                    "status": "predeclared_cross_source_holdout",
                    "manual_evaluation_rows": len(manual_threshold["rows"]),
                    "private_threshold_rows": len(private_threshold_capped["rows"]),
                    "duplicate_family_cross_segment_count": 0,
                    "exact_time_boundaries_returned": False,
                    "family_identifiers_returned": False,
                },
                "calibration_provenance_cap": mixed_calibration_cap,
            }
        )

    # This optional nested view is retained only when broad near-families can
    # be represented without emptying a temporal segment.
    partition_a, audit_a = _split_temporal_families(
        imports,
        private["development_fit"],
        segments=4,
    )
    if len(partition_a) == 4 and audit_a["status"] == "partitioned":
        nested_view = {
            "name": "development_fit_nested_holdout",
            "evaluation_cohort": "development_fit",
            "fit": _concat_bundles(imports, human["development_fit"], partition_a[0]),
            "calibration": partition_a[1],
            "threshold": partition_a[2],
            "evaluation": partition_a[3],
            "partition_audit": audit_a,
        }
        support_audit = _view_gate_support(nested_view)
        optional_view_audits.append(
            {
                "name": nested_view["name"],
                "included": support_audit["passed"],
                "reason": (
                    "full_gate_support"
                    if support_audit["passed"]
                    else "insufficient_class_support_for_fixed_gates"
                ),
                "support": support_audit,
            }
        )
        if support_audit["passed"]:
            nested_view["partition_audit"] = {
                **audit_a,
                "gate_support": support_audit,
            }
            views.append(nested_view)

    public_views: list[dict[str, Any]] = []
    valid_views: list[dict[str, Any]] = []
    for view in views:
        leakage = _family_leakage(view)
        view["leakage_audit"] = leakage
        valid = bool(
            leakage["passed"]
            and all(len(view[key]["rows"]) for key in ("fit", "calibration", "threshold", "evaluation"))
        )
        if valid:
            valid_views.append(view)
        public_views.append(
            {
                "name": view["name"],
                "evaluation_cohort": view["evaluation_cohort"],
                "valid": valid,
                "partition_sizes": {
                    key: len(view[key]["rows"])
                    for key in ("fit", "calibration", "threshold", "evaluation")
                },
                "provenance": {
                    key: _provenance_profile(view[key])
                    for key in ("fit", "calibration", "threshold", "evaluation")
                },
                "partition_audit": view.get("partition_audit"),
                "leakage_audit": leakage,
            }
        )
    return valid_views, {
        "status": "ready" if len(valid_views) >= 3 else "insufficient_valid_views",
        "required_views": 3,
        "valid_views": len(valid_views),
        "views": public_views,
        "optional_view_audits": optional_view_audits,
        "future_labels_opened": False,
        "private_identifiers_returned": False,
        "family_identifiers_returned": False,
    }


def _targets_for_mode(bundle: dict[str, Any], mode: str) -> list[str]:
    if mode == "flat_5class":
        return list(bundle["original_labels"])
    if mode == "three_class_soc_queue":
        return v56._three_class_targets(bundle["original_labels"])
    return list(bundle["targets"])


def _positive_classes(mode: str) -> set[str]:
    if mode == "flat_5class":
        return {"needs_context", "suspicious", "malicious"}
    if mode == "three_class_soc_queue":
        return {"suspicious", "malicious"}
    return {"needs_review"}


def _filter_for_mode(imports: Any, bundle: dict[str, Any], mode: str) -> dict[str, Any]:
    if mode != "binary_threat_positive":
        return bundle
    return _slice_bundle(
        imports,
        bundle,
        [
            index
            for index, label in enumerate(bundle["original_labels"])
            if label != "needs_context"
        ],
    )


def _anchor_capped_weights(
    bundle: dict[str, Any],
    targets: list[str],
    *,
    assisted_cap: float,
) -> tuple[list[float], dict[str, Any]]:
    target_counts = Counter(targets)
    total = max(1, len(targets))
    classes = max(1, len(target_counts))
    weights: list[float] = []
    manual_indices: list[int] = []
    assisted_indices: list[int] = []
    for index, target in enumerate(targets):
        class_factor = min(
            3.0,
            max(0.50, total / (classes * max(1, target_counts[target]))),
        )
        manual = bool(bundle["rows"][index].get("human_reviewed"))
        if manual:
            value = min(4.0, max(1.0, class_factor))
            manual_indices.append(index)
        else:
            value = min(
                0.65,
                max(0.02, float(bundle["base_weights"][index]) * class_factor),
            )
            assisted_indices.append(index)
        weights.append(value)
    manual_total = sum(weights[index] for index in manual_indices)
    assisted_total = sum(weights[index] for index in assisted_indices)
    allowed_assisted = manual_total * max(0.0, min(0.75, assisted_cap))
    scale = 1.0
    if assisted_indices and manual_total > 0 and assisted_total > allowed_assisted:
        scale = allowed_assisted / assisted_total
        for index in assisted_indices:
            weights[index] *= scale
    assisted_total_after = sum(weights[index] for index in assisted_indices)
    return weights, {
        "strategy": "class_balance_with_manual_anchor_aggregate_cap",
        "target_distribution": dict(sorted(target_counts.items())),
        "manual_or_reviewed_rows": len(manual_indices),
        "assisted_rows": len(assisted_indices),
        "manual_effective_weight": round(manual_total, 6),
        "assisted_effective_weight": round(assisted_total_after, 6),
        "assisted_to_manual_weight_ratio": (
            round(assisted_total_after / manual_total, 6) if manual_total else None
        ),
        "assisted_weight_cap": assisted_cap,
        "assisted_scale_applied": round(scale, 8),
        "assisted_labels_dominate_manual_anchors": bool(
            manual_total <= 0 or assisted_total_after > manual_total
        ),
        "labels_rewritten": False,
    }


def _pattern_for_error(row: dict[str, Any], frame_row: Any) -> str:
    if row.get("pattern") in PATTERN_ORDER:
        return str(row["pattern"])
    app = str(row.get("app") or "unknown").casefold()
    action = str(row.get("action") or "unknown").casefold()
    port = _integer(row.get("dst_port"))
    if app == "quic-base" and action == "allow" and port == 443:
        return "benign_quic_443"
    if app == "incomplete" and action == "allow" and port == 80:
        return "incomplete_allow_80"
    if app.startswith("unknown"):
        return "unknown_udp_tcp"
    if _number(frame_row.get("v56_scan_pressure")) >= 0.70:
        return "scan_like_behavior"
    if action in {"deny", "drop", "reset", "block"} and port in v56.AUTH_PORTS:
        return "denied_high_risk_service"
    if str(row.get("log_type") or "").upper() == "THREAT":
        return "vendor_threat_record"
    if row.get("original_label") in {"suspicious", "malicious"}:
        return "suspicious_malicious_boundary"
    if app not in v56.UNKNOWN_APPS:
        return "routine_known_application"
    return "other"


def _residual_error_audit(
    bundle: dict[str, Any],
    actual: list[str],
    predicted: list[str],
) -> dict[str, Any]:
    false_positive: Counter[str] = Counter()
    false_negative: Counter[str] = Counter()
    provenance_fp: Counter[str] = Counter()
    provenance_fn: Counter[str] = Counter()
    for index, (truth, decision) in enumerate(zip(actual, predicted, strict=True)):
        if truth == decision:
            continue
        pattern = _pattern_for_error(bundle["rows"][index], bundle["frame"].iloc[index])
        provenance = str(bundle["rows"][index].get("provenance") or "unknown")
        if truth == "non_threat":
            false_positive[pattern] += 1
            provenance_fp[provenance] += 1
        else:
            false_negative[pattern] += 1
            provenance_fn[provenance] += 1
    return {
        "false_positive_count": sum(false_positive.values()),
        "false_negative_count": sum(false_negative.values()),
        "false_positive_patterns": dict(false_positive.most_common()),
        "false_negative_patterns": dict(false_negative.most_common()),
        "false_positive_provenance": dict(provenance_fp.most_common()),
        "false_negative_provenance": dict(provenance_fn.most_common()),
        "row_predictions_returned": False,
        "private_identifiers_returned": False,
        "exact_timestamps_returned": False,
    }


def _fit_strategy(
    imports: Any,
    *,
    view: dict[str, Any],
    spec: dict[str, Any],
) -> dict[str, Any]:
    mode = str(spec["target_mode"])
    fit = _filter_for_mode(imports, view["fit"], mode)
    calibration = _filter_for_mode(imports, view["calibration"], mode)
    threshold = _filter_for_mode(imports, view["threshold"], mode)
    evaluation = _filter_for_mode(imports, view["evaluation"], mode)
    if any(
        len(bundle["rows"]) < 10
        for bundle in (fit, calibration, threshold, evaluation)
    ):
        return {
            "status": "failed_closed",
            "name": spec["name"],
            "reason": "a dedicated development partition has insufficient rows",
        }
    targets = _targets_for_mode(fit, mode)
    if len(set(targets)) < 2:
        return {
            "status": "failed_closed",
            "name": spec["name"],
            "reason": "fit target support is insufficient",
        }
    pipeline = _build_pipeline_for_columns(
        imports,
        model_type=str(spec["model_type"]),
        class_weight=spec.get("class_weight"),
        numeric_features=v56.V56_NUMERIC_FEATURES,
        categorical_features=v56.V56_CATEGORICAL_FEATURES,
    )
    weights, weighting = _anchor_capped_weights(
        fit,
        targets,
        assisted_cap=float(spec["assisted_weight_cap"]),
    )
    if weighting["assisted_labels_dominate_manual_anchors"]:
        return {
            "status": "failed_closed",
            "name": spec["name"],
            "reason": "assisted effective weight exceeds manual anchor weight",
            "sample_weighting": weighting,
        }
    started = time.perf_counter()
    try:
        pipeline.fit(fit["frame"], targets, model__sample_weight=weights)
        combined = _concat_bundles(imports, fit, calibration)
        combined_targets = _targets_for_mode(combined, mode)
        calibration_indices = list(range(len(fit["rows"]), len(combined["rows"])))
        model, calibration_method = reliability._fit_frozen_calibrator(
            pipeline,
            combined["frame"],
            calibration_indices,
            combined_targets,
            method=str(spec["calibration_method"]),
        )
        positive_classes = _positive_classes(mode)
        threshold_scores = reliability._queue_scores(
            model,
            threshold["frame"],
            list(range(len(threshold["rows"]))),
            positive_classes,
        )
        threshold_selection = reliability.select_v49_threshold(
            threshold["targets"],
            threshold_scores,
        )
        selected_threshold = _number(threshold_selection.get("selected_threshold"), 0.5)
        evaluation_scores = reliability._queue_scores(
            model,
            evaluation["frame"],
            list(range(len(evaluation["rows"]))),
            positive_classes,
        )
    except (ValueError, TypeError, IndexError, AttributeError) as exc:
        return {
            "status": "failed_closed",
            "name": spec["name"],
            "reason": f"model evaluation failed: {exc.__class__.__name__}",
            "sample_weighting": weighting,
        }
    predictions = [
        "needs_review" if score >= selected_threshold else "non_threat"
        for score in evaluation_scores
    ]
    metrics = frozen._binary_metrics(evaluation["targets"], predictions)
    metrics.update(
        frozen._diagnostic_original_recall(
            evaluation["rows"],
            list(range(len(evaluation["rows"]))),
            predictions,
        )
    )
    metrics.update(
        {
            "threat_positive_precision": metrics.get("queue_precision"),
            "threat_positive_recall": metrics.get("queue_recall"),
            "threat_positive_f1": metrics.get("queue_f1"),
        }
    )
    calibration_report = frozen._calibration_report(
        evaluation["targets"],
        evaluation_scores,
    )
    classification = None
    severity_model = None
    if mode in {"flat_5class", "three_class_soc_queue"}:
        direct = [str(value) for value in model.predict(evaluation["frame"])]
        actual = (
            evaluation["original_labels"]
            if mode == "flat_5class"
            else v56._three_class_targets(evaluation["original_labels"])
        )
        classification = reliability._classification_diagnostics(actual, direct)
    elif mode == "hierarchical_two_stage":
        severity_indices = [
            index
            for index, label in enumerate(fit["original_labels"])
            if label in {"suspicious", "malicious"}
        ]
        severity_targets = [fit["original_labels"][index] for index in severity_indices]
        if len(set(severity_targets)) >= 2:
            severity_fit = _slice_bundle(imports, fit, severity_indices)
            severity_model = _build_pipeline_for_columns(
                imports,
                model_type="extra_trees",
                class_weight="balanced",
                numeric_features=v56.V56_NUMERIC_FEATURES,
                categorical_features=v56.V56_CATEGORICAL_FEATURES,
            )
            severity_weights, _ = _anchor_capped_weights(
                severity_fit,
                severity_targets,
                assisted_cap=float(spec["assisted_weight_cap"]),
            )
            severity_model.fit(
                severity_fit["frame"],
                severity_targets,
                model__sample_weight=severity_weights,
            )
            severity_predictions = [
                str(value) for value in severity_model.predict(evaluation["frame"])
            ]
            combined_predictions = [
                severity if queue == "needs_review" else "benign_like"
                for queue, severity in zip(predictions, severity_predictions, strict=True)
            ]
            classification = reliability._classification_diagnostics(
                v56._three_class_targets(evaluation["original_labels"]),
                combined_predictions,
            )
    result = {
        "status": "evaluated",
        "name": spec["name"],
        "model_type": spec["model_type"],
        "target_mode": mode,
        "assisted_weight_cap": spec["assisted_weight_cap"],
        "fit_rows": len(fit["rows"]),
        "calibration_rows": len(calibration["rows"]),
        "threshold_rows": len(threshold["rows"]),
        "evaluation_rows": len(evaluation["rows"]),
        "evaluation_provenance": _provenance_profile(evaluation),
        "metrics": metrics,
        "calibration": calibration_report,
        "applied_calibration_method": calibration_method,
        "threshold_selection": threshold_selection,
        "sample_weighting": weighting,
        "classification_diagnostics": classification,
        "residual_errors": _residual_error_audit(
            evaluation,
            evaluation["targets"],
            predictions,
        ),
        "post_prediction_guard_used": False,
        "future_labels_used": False,
        "active_artifact_written": False,
        "model_activated": False,
        "model_promoted": False,
        "training_seconds": round(time.perf_counter() - started, 4),
        "_model": model,
        "_severity_model": severity_model,
        "_threshold": selected_threshold,
        "_positive_classes": positive_classes,
    }
    result["fixed_freeze_gate"] = v542._fixed_fold_gate(
        result,
        leakage_passed=bool(view["leakage_audit"]["passed"]),
    )
    return result


def _range(values: list[float]) -> dict[str, float | None]:
    return {
        "minimum": round(min(values), 4) if values else None,
        "maximum": round(max(values), 4) if values else None,
        "mean": round(mean(values), 4) if values else None,
    }


def _public_strategy(result: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in result.items() if not key.startswith("_")}


def run_model_comparison(
    imports: Any,
    views: list[dict[str, Any]],
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    public_views: list[dict[str, Any]] = []
    by_strategy: dict[str, list[dict[str, Any]]] = defaultdict(list)
    internal_latest: dict[str, dict[str, Any]] = {}
    for view in views:
        strategies: list[dict[str, Any]] = []
        for spec in STRATEGY_SPECS:
            result = _fit_strategy(imports, view=view, spec=spec)
            public = _public_strategy(result)
            strategies.append(public)
            if result.get("status") == "evaluated":
                by_strategy[str(spec["name"])].append(
                    {"view": view["name"], **public}
                )
                internal_latest[str(spec["name"])] = result
        public_views.append(
            {
                "name": view["name"],
                "evaluation_cohort": view["evaluation_cohort"],
                "leakage_audit": view["leakage_audit"],
                "strategies": strategies,
            }
        )

    summaries: dict[str, Any] = {}
    ranking: list[tuple[Any, ...]] = []
    for name, evaluations in by_strategy.items():
        metric_ranges: dict[str, Any] = {}
        for field in v542.METRIC_FIELDS:
            values = [
                float((row.get("metrics") or {})[field])
                for row in evaluations
                if (row.get("metrics") or {}).get(field) is not None
            ]
            if values:
                metric_ranges[field] = _range(values)
        calibration_ranges: dict[str, Any] = {}
        for field in v542.CALIBRATION_FIELDS:
            values = [
                float((row.get("calibration") or {})[field])
                for row in evaluations
                if (row.get("calibration") or {}).get(field) is not None
            ]
            if values:
                calibration_ranges[field] = _range(values)
        passing = sum(
            1 for row in evaluations if (row.get("fixed_freeze_gate") or {}).get("passed")
        )
        queue_values = [
            float((row.get("metrics") or {}).get("review_queue_rate") or 0.0)
            for row in evaluations
        ]
        queue_spread = max(queue_values) - min(queue_values) if queue_values else 1.0
        all_views = len(evaluations) == len(views)
        all_fold_gates = bool(all_views and passing == len(views))
        stability_passed = queue_spread <= FIXED_FREEZE_GATES["review_queue_rate_spread_max"]
        weight_integrity = all(
            not bool((row.get("sample_weighting") or {}).get("assisted_labels_dominate_manual_anchors"))
            for row in evaluations
        )
        summary = {
            "evaluated_views": len(evaluations),
            "required_views": len(views),
            "passing_views": passing,
            "all_views_passed": all_fold_gates,
            "review_queue_rate_spread": round(queue_spread, 4),
            "review_queue_stability_passed": stability_passed,
            "assisted_weight_integrity_passed": weight_integrity,
            "metric_ranges": metric_ranges,
            "calibration_ranges": calibration_ranges,
            "candidate_freeze_eligible": bool(
                all_fold_gates and stability_passed and weight_integrity
            ),
        }
        manual = next(
            (row for row in evaluations if row["view"] == "manual_anchor_holdout"),
            None,
        )
        assisted = next(
            (row for row in evaluations if row["view"] == "threshold_cohort_holdout"),
            None,
        )
        summary["assisted_label_sensitivity"] = {
            "manual_holdout_available": manual is not None,
            "assisted_holdout_available": assisted is not None,
            "queue_f1_absolute_gap": (
                round(
                    abs(
                        _number((manual or {}).get("metrics", {}).get("queue_f1"))
                        - _number((assisted or {}).get("metrics", {}).get("queue_f1"))
                    ),
                    4,
                )
                if manual and assisted
                else None
            ),
            "fpr_absolute_gap": (
                round(
                    abs(
                        _number(
                            (manual or {}).get("metrics", {}).get(
                                "benign_like_false_positive_rate"
                            )
                        )
                        - _number(
                            (assisted or {}).get("metrics", {}).get(
                                "benign_like_false_positive_rate"
                            )
                        )
                    ),
                    4,
                )
                if manual and assisted
                else None
            ),
        }
        summaries[name] = summary
        f1_min = _number((metric_ranges.get("queue_f1") or {}).get("minimum"))
        fpr_max = _number(
            (metric_ranges.get("benign_like_false_positive_rate") or {}).get("maximum"),
            1.0,
        )
        ece_max = _number(
            (calibration_ranges.get("expected_calibration_error") or {}).get("maximum"),
            1.0,
        )
        ranking.append(
            (
                int(summary["candidate_freeze_eligible"]),
                passing,
                f1_min - fpr_max - (0.20 * ece_max),
                -fpr_max,
                f1_min,
                name,
            )
        )
    leader = None
    if ranking:
        selected = max(ranking)
        name = str(selected[-1])
        leader = {
            "name": name,
            "selection_basis": "v5_44_development_roles_only_unchanged_v5_42_gates",
            "summary": summaries[name],
            "candidate_freeze_eligible": bool(summaries[name]["candidate_freeze_eligible"]),
            "future_labels_used": False,
            "_latest_fitted": internal_latest[name],
        }
    return {
        "status": "evaluated" if views else "failed_closed_no_views",
        "strategies_compared": len(STRATEGY_SPECS),
        "views": public_views,
        "strategy_summaries": summaries,
        "fixed_freeze_gates": FIXED_FREEZE_GATES,
        "future_labels_used_for_fit": False,
        "future_labels_used_for_calibration": False,
        "future_labels_used_for_threshold_selection": False,
        "future_labels_used_for_candidate_ranking": False,
        "post_prediction_guard_used": False,
    }, leader


def _aggregate_residuals(comparison: dict[str, Any], leader_name: str | None) -> dict[str, Any]:
    fp: Counter[str] = Counter()
    fn: Counter[str] = Counter()
    fp_provenance: Counter[str] = Counter()
    fn_provenance: Counter[str] = Counter()
    evaluated_views = 0
    if leader_name:
        for view in comparison.get("views") or []:
            strategy = next(
                (
                    row
                    for row in view.get("strategies") or []
                    if row.get("name") == leader_name and row.get("status") == "evaluated"
                ),
                None,
            )
            if not strategy:
                continue
            evaluated_views += 1
            residual = strategy.get("residual_errors") or {}
            fp.update(residual.get("false_positive_patterns") or {})
            fn.update(residual.get("false_negative_patterns") or {})
            fp_provenance.update(residual.get("false_positive_provenance") or {})
            fn_provenance.update(residual.get("false_negative_provenance") or {})
    return {
        "leader": leader_name,
        "evaluated_views": evaluated_views,
        "false_positive_patterns": dict(fp.most_common()),
        "false_negative_patterns": dict(fn.most_common()),
        "false_positive_provenance": dict(fp_provenance.most_common()),
        "false_negative_provenance": dict(fn_provenance.most_common()),
        "row_predictions_returned": False,
        "private_identifiers_returned": False,
    }


def _isolation_audit(
    imports: Any,
    *,
    fit: dict[str, Any],
    evaluations: list[tuple[str, dict[str, Any]]],
) -> dict[str, Any]:
    results: list[dict[str, Any]] = []
    for name, evaluation in evaluations:
        diagnostics, _candidate = v56.run_isolation_forest_diagnostics(
            imports,
            fit=fit,
            development_evaluation=evaluation,
        )
        public = dict(diagnostics)
        for strategy in public.get("strategies") or []:
            regime = strategy.get("regime_summary") or {}
            regime.pop("time_window", None)
            strategy["regime_summary"] = regime
        results.append(
            {
                "evaluation_cohort": name,
                "diagnostics": public,
            }
        )
    passing = []
    for item in results:
        selected = (item["diagnostics"] or {}).get("selected_development_strategy") or {}
        metrics = selected.get("metrics") or {}
        passing.append(
            bool(
                _number(metrics.get("benign_like_false_positive_rate"), 1.0)
                <= FIXED_FREEZE_GATES["benign_like_false_positive_rate_max"]
                and _number(metrics.get("suspicious_recall"))
                >= FIXED_FREEZE_GATES["suspicious_recall_min"]
                and _number(metrics.get("malicious_recall"))
                >= FIXED_FREEZE_GATES["malicious_recall_min"]
            )
        )
    return {
        "status": "evaluated" if results else "not_evaluated",
        "cohorts": results,
        "advisory_only": True,
        "authoritative_alerts_allowed": False,
        "reliability_passed": bool(passing and all(passing)),
        "candidate_frozen": False,
        "active_artifact_written": False,
        "future_labels_used": False,
        "exact_time_windows_returned": False,
        "private_identifiers_returned": False,
    }


def _freeze_manifest(
    leader: dict[str, Any] | None,
    *,
    output_dir: Path,
    custody: dict[str, Any],
    write_output: bool,
) -> dict[str, Any]:
    if not leader or not leader.get("candidate_freeze_eligible"):
        return {
            "candidate_frozen": False,
            "candidate_freeze_ready": False,
            "reason": "no strategy passed every unchanged development gate",
            "manifest_written": False,
            "active_artifact_written": False,
            "future_labels_opened": False,
        }
    fitted = leader.get("_latest_fitted") or {}
    recipe = {
        "schema_version": V545_VERSION,
        "status": "diagnostic_candidate_recipe_frozen",
        "candidate_name": leader["name"],
        "selection_basis": leader["selection_basis"],
        "model_type": fitted.get("model_type"),
        "target_mode": fitted.get("target_mode"),
        "assisted_weight_cap": fitted.get("assisted_weight_cap"),
        "calibration_method": fitted.get("applied_calibration_method"),
        "selected_threshold": fitted.get("_threshold"),
        "fixed_freeze_gates": FIXED_FREEZE_GATES,
        "development_summary": leader["summary"],
        "v544_lock_contract": _stable_hash(
            {
                "cohorts": (_public_custody(custody).get("cohort_rows") or {}),
                "policy": v56.V56_POLICY_VERSION,
                "gates": FIXED_FREEZE_GATES,
            }
        ),
        "future_labels_opened": False,
        "eligible_for_activation": False,
        "active_artifact_written": False,
        "model_artifact_written": False,
    }
    path = output_dir / V545_FREEZE_MANIFEST
    status = "not_written_by_request"
    if write_output:
        if path.is_file():
            existing = _read_json(path)
            if existing != recipe:
                raise V545RepairError("A different v5.45 diagnostic freeze already exists.")
            status = "existing_manifest_reused"
        else:
            _atomic_write_json(path, recipe)
            status = "manifest_written"
    return {
        "candidate_frozen": True,
        "candidate_freeze_ready": True,
        "candidate_name": leader["name"],
        "selection_basis": leader["selection_basis"],
        "manifest_status": status,
        "manifest_written": bool(write_output),
        "manifest_fingerprint_returned": False,
        "model_artifact_written": False,
        "active_artifact_written": False,
        "eligible_for_activation": False,
        "future_labels_opened": False,
    }


def _readiness(
    *,
    view_protocol: dict[str, Any],
    leader: dict[str, Any] | None,
    freeze: dict[str, Any],
    isolation: dict[str, Any],
) -> dict[str, Any]:
    checks = {
        "three_or_more_valid_development_views": int(view_protocol.get("valid_views") or 0) >= 3,
        "all_candidate_gates_passed": bool(
            leader and leader.get("candidate_freeze_eligible")
        ),
        "diagnostic_recipe_frozen": bool(freeze.get("candidate_frozen")),
        "future_labels_remain_sealed": not bool(freeze.get("future_labels_opened")),
        "isolation_forest_reliable": bool(isolation.get("reliability_passed")),
    }
    blockers: list[str] = []
    if not checks["all_candidate_gates_passed"]:
        blockers.append("No supervised strategy passed every unchanged development gate.")
    if not checks["isolation_forest_reliable"]:
        blockers.append("IsolationForest remains advisory because its development sensitivity gates failed.")
    blockers.extend(
        [
            "Only one genuine private device source is available.",
            "Private cohort decisions are assisted evidence, not independent human ground truth.",
            "Untouched future and independent evidence remain sealed and unavailable for selection.",
        ]
    )
    return {
        "status": (
            "diagnostic_candidate_frozen"
            if freeze.get("candidate_frozen")
            else "development_repair_incomplete"
        ),
        "checks": checks,
        "candidate_freeze_ready": bool(freeze.get("candidate_freeze_ready")),
        "independent_validation_ready": False,
        "shadow_activation_ready": False,
        "production_promotion_ready": False,
        "response_automation_allowed": False,
        "lifecycle_state": "shadow_observation",
        "blockers": blockers,
        "supervised_phases_remaining": 4 if freeze.get("candidate_frozen") else 5,
    }


def _render_report(result: dict[str, Any]) -> str:
    leader = result.get("diagnostic_leader") or {}
    summary = leader.get("summary") or {}
    freeze = result.get("candidate_freeze") or {}
    residual = result.get("residual_error_audit") or {}
    return "\n".join(
        [
            "# v5.45 Development-Only Supervised Model Repair",
            "",
            f"Generated: `{result.get('generated_at')}`",
            "",
            "## Decision",
            "",
            f"- Status: `{result.get('status')}`",
            f"- Diagnostic leader: `{leader.get('name') or 'none'}`",
            f"- Candidate frozen: `{freeze.get('candidate_frozen')}`",
            f"- Lifecycle: `{result.get('lifecycle_state')}`",
            "- Future labels opened: `false`",
            "- Active model artifact written: `false`",
            "",
            "## Stability",
            "",
            f"- Passing views: `{summary.get('passing_views')}` / `{summary.get('required_views')}`",
            f"- Queue-rate spread: `{summary.get('review_queue_rate_spread')}`",
            f"- Metric ranges: `{summary.get('metric_ranges')}`",
            f"- Calibration ranges: `{summary.get('calibration_ranges')}`",
            "",
            "## Residual Patterns",
            "",
            f"- False positives: `{residual.get('false_positive_patterns')}`",
            f"- False negatives: `{residual.get('false_negative_patterns')}`",
            "",
            "This report contains aggregate development-only diagnostics. It contains no raw logs, IP addresses, private paths, identities, row predictions, or model artifact.",
            "",
        ]
    )


def _safe_failure(
    status: str,
    *,
    error_type: str | None = None,
    failure_stage: str | None = None,
    diagnostics: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "ok": False,
        "version": V545_VERSION,
        "status": status,
        "generated_at": _now(),
        "error_type": error_type,
        "failure_stage": failure_stage,
        "diagnostics": diagnostics or {},
        "message": "The v5.45 repair failed closed. Review local diagnostics without exposing private evidence.",
        "lifecycle_state": "shadow_observation",
        "rules_alert_authoritative": True,
        "model_activated": False,
        "model_promoted": False,
        "active_model_artifact_written": False,
        "response_automation_allowed": False,
        "real_firewall_blocking_enabled": False,
        "future_labels_opened": False,
        "private_paths_returned": False,
        "raw_logs_returned": False,
        "ip_addresses_returned": False,
        "source_identities_returned": False,
        "fingerprints_returned": False,
        "row_predictions_returned": False,
        "secrets_exposed": False,
    }


def run_v545_development_model_repair(
    db: Session,
    *,
    sample_path: Path | None,
    use_temp_db: bool = False,
    preflight_only: bool = False,
    min_samples: int = 100,
    max_fit_rows: int = DEFAULT_MAX_ROWS["development_fit"],
    max_calibration_rows: int = DEFAULT_MAX_ROWS["calibration"],
    max_threshold_rows: int = DEFAULT_MAX_ROWS["threshold"],
    output_dir: Path = V545_OUTPUT_DIR,
    write_output: bool = True,
    v544_output_dir: Path = v544.V544_OUTPUT_DIR,
    state_path: Path = v540.V539_STATE_PATH,
    pack_path: Path = v540.DEFAULT_PACK_PATH,
    blind_output_dir: Path = v541.V541_OUTPUT_DIR,
    v542_output_dir: Path = v542.V542_OUTPUT_DIR,
    v543_output_dir: Path = v543.V543_OUTPUT_DIR,
) -> dict[str, Any]:
    started = time.perf_counter()
    counts_before = frozen._database_counts(db)
    artifacts_before = v55._model_artifact_states()
    protected_before = _protected_state(
        v544_output_dir=v544_output_dir,
        state_path=state_path,
        pack_path=pack_path,
        blind_output_dir=blind_output_dir,
        v542_output_dir=v542_output_dir,
        v543_output_dir=v543_output_dir,
    )
    stage = "custody_revalidation"
    failure_diagnostics: dict[str, Any] = {}
    try:
        custody = revalidate_v545_custody(
            db,
            min_samples=min_samples,
            v544_output_dir=v544_output_dir,
            state_path=state_path,
            pack_path=pack_path,
            blind_output_dir=blind_output_dir,
            v542_output_dir=v542_output_dir,
            v543_output_dir=v543_output_dir,
        )
    except (
        V545RepairError,
        v544.V544EvidenceError,
        v543.V543RepairError,
        v542.V542FreezeError,
        v541.V541EvidenceError,
        v540.V540EvidenceBoundaryError,
    ) as exc:
        return _safe_failure(
            "failed_closed_custody",
            error_type=exc.__class__.__name__,
            failure_stage=stage,
        )

    available = bool(sample_path and sample_path.is_file())
    if preflight_only:
        counts_after = frozen._database_counts(db)
        artifacts_after = v55._model_artifact_states()
        protected_after = _protected_state(
            v544_output_dir=v544_output_dir,
            state_path=state_path,
            pack_path=pack_path,
            blind_output_dir=blind_output_dir,
            v542_output_dir=v542_output_dir,
            v543_output_dir=v543_output_dir,
        )
        safe = bool(
            available
            and counts_before == counts_after
            and artifacts_before == artifacts_after
            and protected_before == protected_after
        )
        return {
            "ok": safe,
            "version": V545_VERSION,
            "status": "preflight_complete" if safe else "private_file_unavailable",
            "generated_at": _now(),
            "preflight_only": True,
            "custody": _public_custody(custody),
            "private_file": {
                "supplied": sample_path is not None,
                "available": available,
                "path_returned": False,
                "file_name_returned": False,
                "digest_returned": False,
            },
            "safety": {
                "configured_database_counts_unchanged": counts_before == counts_after,
                "active_model_artifacts_unchanged": artifacts_before == artifacts_after,
                "protected_workspaces_unchanged": protected_before == protected_after,
                "all_invariants_passed": safe,
            },
            "future_labels_opened": False,
            "lifecycle_state": "shadow_observation",
            "rules_alert_authoritative": True,
            "model_activated": False,
            "model_promoted": False,
            "active_model_artifact_written": False,
            "response_automation_allowed": False,
            "real_firewall_blocking_enabled": False,
            "private_paths_returned": False,
            "raw_logs_returned": False,
            "ip_addresses_returned": False,
            "source_identities_returned": False,
            "fingerprints_returned": False,
            "secrets_exposed": False,
        }
    if not available:
        return _safe_failure("private_file_unavailable")
    if not use_temp_db:
        return _safe_failure("temporary_storage_acknowledgement_required")
    imports = _optional_imports()
    if imports is None:
        return _safe_failure("ml_dependencies_unavailable")

    stage = "disposable_stream"
    try:
        with tempfile.TemporaryDirectory(prefix="atdr-v545-") as directory:
            connection = sqlite3.connect(Path(directory) / "development.sqlite3")
            try:
                profile = v56.stream_private_file_to_disposable_index(
                    sample_path,
                    connection,
                    database_url=get_settings().database_url,
                )
                if not profile.get("ok"):
                    raise V545RepairError("Private evidence parsing failed.")
                stage = "protected_boundary_install"
                boundary = v544._install_protected_boundaries(
                    connection,
                    custody=custody["custody"],
                    blind_output_dir=blind_output_dir,
                )
                stage = "chronological_role_reconstruction"
                roles = v56.predeclare_chronological_roles(connection)
                if not roles.get("ok"):
                    raise V545RepairError("Chronological role reconstruction failed.")
                stage = "behavior_aggregate_build"
                v56.build_disposable_behavior_aggregates(connection)
                stage = "assisted_policy_reconstruction"
                assisted = v544._apply_development_assisted_policy(
                    connection,
                    review_limit=0,
                )
                assisted.pop("_review_rows", None)
                stage = "v544_private_lock_revalidation"
                private_lock = v544._write_private_lock(
                    connection,
                    output_dir=v544_output_dir,
                    custody=custody["custody"],
                )
                if private_lock.get("status") != "existing_private_lock_reused":
                    raise V545RepairError("v5.44 lock reconstruction was not reused.")

                stage = "v545_candidate_near_containment"
                candidate_near_containment = _contain_candidate_near_families(
                    connection
                )
                failure_diagnostics["candidate_near_containment"] = (
                    candidate_near_containment
                )
                if not candidate_near_containment["passed"]:
                    raise V545RepairError(
                        "Candidate-near families remain across development roles."
                    )
                stage = "v545_contained_aggregate_rebuild"
                v56.build_disposable_behavior_aggregates(connection)
                assisted = v544._apply_development_assisted_policy(
                    connection,
                    review_limit=0,
                )
                assisted.pop("_review_rows", None)

                stage = "human_anchor_projection"
                human = _human_role_bundles(
                    custody["custody"]["state"]["development"],
                    custody["custody"]["state"]["canonical"],
                )
                private: dict[str, dict[str, Any]] = {}
                private_selection: dict[str, Any] = {}
                stage = "private_development_sampling"
                for role_rank, role_name, maximum in (
                    (0, "development_fit", max_fit_rows),
                    (1, "calibration", max_calibration_rows),
                    (2, "threshold", max_threshold_rows),
                ):
                    private[role_name], private_selection[role_name] = _load_private_role_bundle(
                        connection,
                        imports,
                        role_rank=role_rank,
                        max_rows=maximum,
                    )
                failure_diagnostics["private_selection"] = private_selection
                stage = "development_view_construction"
                views, view_protocol = build_development_views(
                    imports,
                    human=human,
                    private=private,
                )
                failure_diagnostics["view_protocol"] = view_protocol
                if view_protocol["status"] != "ready":
                    raise V545RepairError("Fewer than three leakage-safe development views exist.")
                stage = "supervised_strategy_comparison"
                comparison, leader = run_model_comparison(imports, views)
                residual = _aggregate_residuals(
                    comparison,
                    str(leader["name"]) if leader else None,
                )
                stage = "isolation_forest_audit"
                isolation = _isolation_audit(
                    imports,
                    fit=_concat_bundles(
                        imports,
                        human["development_fit"],
                        private["development_fit"],
                    ),
                    evaluations=[
                        (view["evaluation_cohort"], view["evaluation"])
                        for view in views
                        if view["name"] in {
                            "threshold_cohort_holdout",
                            "manual_anchor_holdout",
                        }
                    ],
                )
                stage = "candidate_freeze_decision"
                freeze = _freeze_manifest(
                    leader,
                    output_dir=output_dir,
                    custody=custody,
                    write_output=write_output,
                )
                stage = "readiness_decision"
                readiness = _readiness(
                    view_protocol=view_protocol,
                    leader=leader,
                    freeze=freeze,
                    isolation=isolation,
                )
            finally:
                connection.close()
    except (
        V545RepairError,
        v544.V544EvidenceError,
        sqlite3.Error,
        OSError,
        ValueError,
        TypeError,
        IndexError,
    ) as exc:
        return _safe_failure(
            "failed_closed_development_repair",
            error_type=exc.__class__.__name__,
            failure_stage=stage,
            diagnostics=failure_diagnostics,
        )

    counts_after = frozen._database_counts(db)
    artifacts_after = v55._model_artifact_states()
    protected_after = _protected_state(
        v544_output_dir=v544_output_dir,
        state_path=state_path,
        pack_path=pack_path,
        blind_output_dir=blind_output_dir,
        v542_output_dir=v542_output_dir,
        v543_output_dir=v543_output_dir,
    )
    deltas = {
        key: int(counts_after[key]) - int(counts_before[key])
        for key in counts_before
    }
    safety = {
        "configured_database_counts_unchanged": counts_before == counts_after,
        "active_model_artifacts_unchanged": artifacts_before == artifacts_after,
        "protected_workspaces_unchanged": protected_before == protected_after,
        "labels_created": deltas.get("ml_labels", 0),
        "model_runs_created": deltas.get("ml_model_runs", 0),
        "detection_runs_created": deltas.get("detection_runs", 0),
        "alerts_created": deltas.get("alerts", 0),
        "response_actions_created": deltas.get("response_actions", 0),
        "future_labels_opened": False,
        "active_model_artifact_written": False,
        "model_activated": False,
        "model_promoted": False,
        "rules_alert_authoritative": True,
        "automatic_response_enabled": False,
        "real_firewall_blocking_enabled": False,
        "human_reviewed_labels_created": 0,
    }
    safety_passed = bool(
        safety["configured_database_counts_unchanged"]
        and safety["active_model_artifacts_unchanged"]
        and safety["protected_workspaces_unchanged"]
        and all(value == 0 for value in deltas.values())
    )
    public_leader = None
    if leader:
        public_leader = {key: value for key, value in leader.items() if not key.startswith("_")}
    result = {
        "ok": safety_passed,
        "version": V545_VERSION,
        "status": readiness["status"],
        "generated_at": _now(),
        "preflight_only": False,
        "custody": _public_custody(custody),
        "private_reconstruction": {
            "status": "v5_44_private_lock_reconstructed_and_reused",
            "parsed_rows": int(profile.get("rows") or 0),
            "parser_success_rows": int(profile.get("parser_success_rows") or 0),
            "parser_failure_rows": int(profile.get("parser_failure_rows") or 0),
            "boundary_quarantine_rows": sum(
                int(value)
                for key, value in boundary.items()
                if key.endswith("_rows") and isinstance(value, int)
            ),
            "candidate_near_containment": candidate_near_containment,
            "future_labels_opened": False,
            "private_paths_returned": False,
            "private_identifiers_returned": False,
            "fingerprints_returned": False,
        },
        "development_dataset": {
            "human_anchor_roles": {
                name: _provenance_profile(bundle) for name, bundle in human.items()
            },
            "private_selection": private_selection,
            "assisted_policy": {
                key: value
                for key, value in assisted.items()
                if key
                in {
                    "status",
                    "policy_version",
                    "decision_group_counts",
                    "provenance_group_counts",
                    "pattern_group_counts",
                    "high_confidence_training_group_count",
                    "ambiguous_or_quarantined_event_count",
                    "human_reviewed_true_count",
                    "reserved_future_labels_opened",
                }
            },
            "view_protocol": view_protocol,
            "future_labels_opened": False,
            "labels_rewritten": False,
        },
        "model_comparison": comparison,
        "diagnostic_leader": public_leader,
        "assisted_label_sensitivity": (
            (public_leader or {}).get("summary", {}).get("assisted_label_sensitivity")
            if public_leader
            else None
        ),
        "residual_error_audit": residual,
        "isolation_forest_audit": isolation,
        "candidate_freeze": freeze,
        "readiness": readiness,
        "safety": {**safety, "all_invariants_passed": safety_passed},
        "runtime_seconds": round(time.perf_counter() - started, 4),
        "lifecycle_state": "shadow_observation",
        "rules_alert_authoritative": True,
        "model_activated": False,
        "model_promoted": False,
        "active_model_artifact_written": False,
        "response_automation_allowed": False,
        "real_firewall_blocking_enabled": False,
        "future_labels_opened": False,
        "private_paths_returned": False,
        "raw_logs_returned": False,
        "ip_addresses_returned": False,
        "source_identities_returned": False,
        "fingerprints_returned": False,
        "row_predictions_returned": False,
        "secrets_exposed": False,
    }
    if write_output:
        output_dir.mkdir(parents=True, exist_ok=True)
        _atomic_write_json(output_dir / V545_LATEST, result)
        (output_dir / f"{V545_REPORT_PREFIX}_{_stamp()}.md").write_text(
            _render_report(result),
            encoding="utf-8",
        )
        result["reports"] = {
            "written": True,
            "file_names_returned": False,
            "private_paths_returned": False,
        }
    else:
        result["reports"] = {
            "written": False,
            "file_names_returned": False,
            "private_paths_returned": False,
        }
    return result


def get_public_v545_status(output_dir: Path = V545_OUTPUT_DIR) -> dict[str, Any]:
    path = output_dir / V545_LATEST
    if not path.is_file():
        return {
            "version": V545_VERSION,
            "status": "not_run",
            "generated_at": None,
            "diagnostic_leader": None,
            "passing_views": 0,
            "required_views": 3,
            "candidate_frozen": False,
            "isolation_forest_reliable": False,
            "supervised_phases_remaining": 5,
            "blockers": ["Development-only model repair has not been run."],
            "lifecycle_state": "shadow_observation",
            "candidate_freeze_ready": False,
            "model_activated": False,
            "model_promoted": False,
            "response_automation_allowed": False,
            "future_labels_opened": False,
            "private_paths_returned": False,
            "fingerprints_returned": False,
            "secrets_exposed": False,
        }
    value = _read_json(path)
    readiness = value.get("readiness") or {}
    return {
        "version": value.get("version") or V545_VERSION,
        "status": value.get("status"),
        "generated_at": value.get("generated_at"),
        "diagnostic_leader": (value.get("diagnostic_leader") or {}).get("name"),
        "candidate_freeze_ready": bool(
            (value.get("candidate_freeze") or {}).get("candidate_freeze_ready")
        ),
        "candidate_frozen": bool(
            (value.get("candidate_freeze") or {}).get("candidate_frozen")
        ),
        "passing_views": (
            ((value.get("diagnostic_leader") or {}).get("summary") or {}).get(
                "passing_views"
            )
        ),
        "required_views": (
            ((value.get("diagnostic_leader") or {}).get("summary") or {}).get(
                "required_views"
            )
        ),
        "isolation_forest_reliable": bool(
            (value.get("isolation_forest_audit") or {}).get("reliability_passed")
        ),
        "supervised_phases_remaining": int(
            readiness.get("supervised_phases_remaining") or 5
        ),
        "blockers": [str(value) for value in readiness.get("blockers") or []],
        "lifecycle_state": "shadow_observation",
        "model_activated": False,
        "model_promoted": False,
        "response_automation_allowed": False,
        "future_labels_opened": False,
        "private_paths_returned": False,
        "fingerprints_returned": False,
        "secrets_exposed": False,
    }
