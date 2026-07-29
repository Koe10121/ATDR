from __future__ import annotations

import hashlib
import json
import math
import random
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from atdr.app.core.log_fingerprint import raw_line_fingerprint
from atdr.app.db.models import Alert, DetectionRun, LogSource, MLLabel, MLModelRun, NormalizedLog, RawLog, ResponseAction
from atdr.app.detection.rules import build_detection_context, evaluate_rules
from atdr.app.detection.supervised_detector import (
    TRAINABLE_LABELS,
    _latest_labels,
    _optional_imports,
    supervised_model_path,
)
from atdr.app.detection.v330_detection_ml_quality import OUTPUT_DIR
from atdr.app.detection.v331_noise_reduction import (
    _build_pipeline_for_columns,
    _classes,
    _noise_reduced_weights,
)
from atdr.app.detection.v332_guard_validation import _safe_float
from atdr.app.detection.v337_evidence_feature_enrichment import _enrichment_values
from atdr.app.detection.v342_label_policy_reframing import behavior_aware_soc_target
from atdr.app.detection.v344_two_stage_soc_queue import _queue_target
from atdr.app.detection.v347_queue_target_repair_proposal import propose_queue_target
from atdr.app.ml.features import CATEGORICAL_FEATURES, NUMERIC_FEATURES, build_feature_rows


V398_LATEST = "v3_98_validation_latest.json"
V398_SPLITS = (
    "temporal_holdout",
    "source_holdout",
    "random_seed_7",
    "random_seed_17",
    "random_seed_42",
)
PRIMARY_CANDIDATE = "v362_repaired_queue_extra_trees_sigmoid"
RULE_QUEUE_THRESHOLD = 0.30
THRESHOLD_GRID = tuple(round(value / 100, 2) for value in range(10, 96, 5))
LEAKAGE_UNSAFE_FEATURES = {"rare_dst_port_flag", "rare_app_flag"}
QUEUE_LABELS = ("non_threat", "needs_review")


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _stable_hash(payload: Any) -> str:
    encoded = json.dumps(payload, sort_keys=True, default=str, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _timestamp(log: Any) -> datetime | None:
    value = getattr(log, "generated_time", None) or getattr(log, "receive_time", None) or getattr(log, "start_time", None)
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _magnitude_bucket(value: Any) -> int:
    numeric = abs(_safe_float(value))
    return 0 if numeric < 1 else int(math.log10(numeric)) + 1


def _raw_fingerprint(log: Any) -> str:
    raw = getattr(log, "raw_log", None)
    existing = str(getattr(raw, "raw_line_hash", "") or "")
    if len(existing) == 64:
        return existing
    raw_line = getattr(raw, "raw_line", None)
    if raw_line is not None:
        return raw_line_fingerprint(str(raw_line))
    return _stable_hash(
        {
            "log_id": getattr(log, "id", None),
            "timestamp": _timestamp(log),
            "app": getattr(log, "app", None),
            "action": getattr(log, "action", None),
            "protocol": getattr(log, "protocol", None),
            "dst_port": getattr(log, "dst_port", None),
        }
    )


def _near_fingerprint(log: Any) -> str:
    """Hash a normalized behavior pattern without retaining raw evidence or IP values."""

    return _stable_hash(
        {
            "log_type": getattr(log, "log_type", None),
            "subtype": getattr(log, "subtype", None),
            "app": str(getattr(log, "app", None) or "").lower(),
            "action": str(getattr(log, "action", None) or "").lower(),
            "protocol": str(getattr(log, "protocol", None) or "").lower(),
            "src_port": getattr(log, "src_port", None),
            "dst_port": getattr(log, "dst_port", None),
            "src_zone": str(getattr(log, "src_zone", None) or "").lower(),
            "dst_zone": str(getattr(log, "dst_zone", None) or "").lower(),
            "app_risk": getattr(log, "app_risk", None),
            "bytes_bucket": _magnitude_bucket(getattr(log, "bytes", None)),
            "packets_bucket": _magnitude_bucket(getattr(log, "packets", None)),
        }
    )


def _feature_fingerprint(frame: Any, index: int, columns: list[str]) -> str:
    row = frame.iloc[index]
    values: dict[str, Any] = {}
    for column in columns:
        value = row.get(column)
        if value is None or (isinstance(value, float) and math.isnan(value)):
            values[column] = None
        elif isinstance(value, float):
            values[column] = round(value, 6)
        else:
            values[column] = str(value)
    return _stable_hash(values)


def _feature_fingerprints(frame: Any, columns: list[str]) -> list[str]:
    fingerprints: list[str] = []
    for record in frame.loc[:, columns].to_dict(orient="records"):
        values: dict[str, Any] = {}
        for column, value in record.items():
            if value is None or (isinstance(value, float) and math.isnan(value)):
                values[column] = None
            elif isinstance(value, float):
                values[column] = round(value, 6)
            else:
                values[column] = str(value)
        fingerprints.append(_stable_hash(values))
    return fingerprints


def _local_evidence_frame(frame: Any, logs: list[Any]) -> tuple[Any, dict[str, Any]]:
    """Build candidate evidence features without whole-dataset rule context.

    Historical v3.31-v3.37 helpers calculated rule context across every labeled
    row. That is useful for diagnostics but leaks holdout batch frequencies into
    training features. v3.98 uses row-local rules plus causal window features.
    """

    safe_frame = frame.copy()
    rule_scores: list[float] = []
    enriched: list[dict[str, Any]] = []
    for position, log in enumerate(logs):
        matches = [match for match in evaluate_rules(log, build_detection_context([log])) if match.code != "ml_anomaly_detected"]
        codes = {match.code for match in matches}
        score = min(100, sum(match.score for match in matches))
        safe_frame.at[position, "v398_local_rule_score"] = float(score)
        # _enrichment_values reads the historical rule-score key. Populate it
        # only with the row-local score so batch membership cannot leak.
        safe_frame.at[position, "v331_rule_score"] = float(score)
        rule_scores.append(float(score))
        enriched.append(_enrichment_values(safe_frame.iloc[position], log, rule_codes=codes))

    enrichment_numeric = [
        "v337_web_like_allow_flag",
        "v337_utility_like_allow_flag",
        "v337_low_signal_allow_flag",
        "v337_web_low_signal_flag",
        "v337_web_scan_context_flag",
        "v337_utility_low_signal_flag",
        "v337_incomplete_scan_context_flag",
        "v337_unknown_scan_context_flag",
        "v337_rule_backed_allow_flag",
        "v337_anomaly_signal_flag",
        "v337_repeated_service_flag",
        "v337_source_diversity_pressure",
        "v337_behavior_evidence_strength",
        "v337_benign_web_likelihood_score",
    ]
    for column in enrichment_numeric:
        safe_frame[column] = [row[column] for row in enriched]
    safe_frame["v337_traffic_family"] = [row["v337_traffic_family"] for row in enriched]

    numeric = [column for column in NUMERIC_FEATURES if column not in LEAKAGE_UNSAFE_FEATURES]
    numeric.extend(["v398_local_rule_score", *enrichment_numeric])
    return safe_frame, {
        "numeric_features": numeric,
        "categorical_features": [*CATEGORICAL_FEATURES, "v337_traffic_family"],
        "excluded_features": sorted(LEAKAGE_UNSAFE_FEATURES),
        "rule_context": "row_local_only",
        "full_dataset_rule_context_used": False,
        "rule_scores": rule_scores,
    }


def _safe_queue_target(label: str, frame_row: Any) -> tuple[str, str]:
    behavior_target = behavior_aware_soc_target(label, frame_row)
    target, reason = propose_queue_target(_queue_target(behavior_target), frame_row)
    return (target if target in QUEUE_LABELS else "needs_review"), reason


def _original_queue_target(label: str) -> str:
    return "needs_review" if label in {"needs_context", "suspicious", "malicious"} else "non_threat"


def _raw_metadata(db: Session, logs: list[Any]) -> dict[int, dict[str, Any]]:
    raw_ids = {int(log.raw_log_id) for log in logs if getattr(log, "raw_log_id", None) is not None}
    if not raw_ids:
        return {}
    rows = db.execute(
        select(
            RawLog.id,
            RawLog.source_id,
            RawLog.raw_line_hash,
            RawLog.raw_line,
            LogSource.name,
        )
        .outerjoin(LogSource, RawLog.source_id == LogSource.id)
        .where(RawLog.id.in_(raw_ids))
    )
    metadata: dict[int, dict[str, Any]] = {}
    for raw_id, source_id, raw_hash, raw_line, source_name in rows:
        fingerprint = str(raw_hash or "")
        if len(fingerprint) != 64:
            fingerprint = raw_line_fingerprint(str(raw_line or ""))
        metadata[int(raw_id)] = {
            "source_id": int(source_id) if source_id is not None else None,
            "source_name": str(source_name or "unknown_source"),
            "raw_fingerprint": fingerprint,
        }
    return metadata


def _build_dataset(db: Session, *, min_samples: int) -> dict[str, Any]:
    imports = _optional_imports()
    if imports is None:
        return {"ok": False, "status": "skipped", "message": "Supervised ML dependencies are unavailable."}

    all_latest = [label for label in _latest_labels(db) if label.log is not None and label.label in TRAINABLE_LABELS]
    labels = [label for label in all_latest if bool(label.reviewed)]
    duplicate_latest_log_ids = len(labels) - len({int(label.log_id) for label in labels})
    if duplicate_latest_log_ids:
        return {
            "ok": False,
            "status": "failed_closed",
            "message": "Latest reviewed-label selection returned duplicate normalized-log identities.",
            "reviewed_latest_rows": len(labels),
            "duplicate_normalized_log_ids": duplicate_latest_log_ids,
        }
    if len(labels) < min_samples or len({label.label for label in labels}) < 2:
        return {
            "ok": False,
            "status": "skipped",
            "message": "Not enough reviewed latest labels for leakage-controlled validation.",
            "reviewed_latest_rows": len(labels),
        }

    pd = imports[1]
    logs = [label.log for label in labels]
    raw_metadata = _raw_metadata(db, logs)
    started = time.perf_counter()
    base_frame = pd.DataFrame(build_feature_rows(db, logs))
    frame, feature_meta = _local_evidence_frame(base_frame, logs)
    feature_seconds = round(time.perf_counter() - started, 4)
    used_columns = [*feature_meta["numeric_features"], *feature_meta["categorical_features"]]
    feature_fingerprints = _feature_fingerprints(frame, used_columns)

    safe_targets: list[str] = []
    target_reasons: Counter[str] = Counter()
    rows: list[dict[str, Any]] = []
    for index, (label, log) in enumerate(zip(labels, logs, strict=True)):
        target, reason = _safe_queue_target(label.label, frame.iloc[index])
        safe_targets.append(target)
        target_reasons[reason] += 1
        raw = raw_metadata.get(int(log.raw_log_id), {}) if log.raw_log_id is not None else {}
        network_zone_group = "zone:{src}->{dst}".format(
            src=str(log.src_zone or "unknown").strip().lower(),
            dst=str(log.dst_zone or "unknown").strip().lower(),
        )
        rows.append(
            {
                "index": index,
                "label_id": int(label.id),
                "log_id": int(log.id),
                "original_label": label.label,
                "safe_queue_target": target,
                "original_queue_target": _original_queue_target(label.label),
                "reviewed": bool(label.reviewed),
                "label_source": str(label.label_source or ""),
                "source_id": raw.get("source_id"),
                "source_name": raw.get("source_name", "unknown_source"),
                "network_zone_group": network_zone_group,
                "timestamp": _timestamp(log),
                "app": str(log.app or "unknown"),
                "action": str(log.action or "unknown"),
                "dst_port": log.dst_port,
                "exact_fingerprint": raw.get("raw_fingerprint") or _raw_fingerprint(log),
                "near_fingerprint": _near_fingerprint(log),
                "feature_fingerprint": feature_fingerprints[index],
                "target_reason": reason,
            }
        )

    total_label_rows = int(db.scalar(select(func.count(MLLabel.id))) or 0)
    trainable_label_rows = int(
        db.scalar(select(func.count(MLLabel.id)).where(MLLabel.label.in_(TRAINABLE_LABELS))) or 0
    )
    return {
        "ok": True,
        "imports": imports,
        "labels": labels,
        "logs": logs,
        "frame": frame,
        "rows": rows,
        "targets": safe_targets,
        "original_labels": [label.label for label in labels],
        "feature_meta": feature_meta,
        "feature_generation_seconds": feature_seconds,
        "label_provenance": {
            "total_label_rows": total_label_rows,
            "latest_trainable_rows": len(all_latest),
            "reviewed_latest_rows": len(labels),
            "weak_or_unreviewed_latest_rows_excluded": len(all_latest) - len(labels),
            "superseded_label_rows_excluded": max(0, trainable_label_rows - len(all_latest)),
            "duplicate_normalized_log_ids_in_evaluation": duplicate_latest_log_ids,
            "label_source_distribution": dict(Counter(str(label.label_source or "") for label in labels)),
            "target_distribution": dict(Counter(safe_targets)),
            "original_label_distribution": dict(Counter(label.label for label in labels)),
            "target_repair_reasons": target_reasons.most_common(20),
        },
    }


class _UnionFind:
    def __init__(self, size: int) -> None:
        self.parent = list(range(size))

    def find(self, value: int) -> int:
        while self.parent[value] != value:
            self.parent[value] = self.parent[self.parent[value]]
            value = self.parent[value]
        return value

    def union(self, left: int, right: int) -> None:
        left_root = self.find(left)
        right_root = self.find(right)
        if left_root != right_root:
            self.parent[right_root] = left_root


def assign_leakage_groups(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Join rows sharing exact, near-pattern, or used-feature fingerprints."""

    union = _UnionFind(len(rows))
    first_seen: dict[tuple[str, str], int] = {}
    for index, row in enumerate(rows):
        for kind in ("exact_fingerprint", "near_fingerprint", "feature_fingerprint"):
            token = (kind, str(row[kind]))
            previous = first_seen.setdefault(token, index)
            union.union(index, previous)

    roots = [union.find(index) for index in range(len(rows))]
    canonical: dict[int, str] = {}
    for root in sorted(set(roots)):
        members = [rows[index]["log_id"] for index, item_root in enumerate(roots) if item_root == root]
        canonical[root] = _stable_hash(sorted(members))[:16]
    for index, root in enumerate(roots):
        rows[index]["leakage_group"] = canonical[root]

    counts = Counter(row["leakage_group"] for row in rows)
    fingerprint_counts = {
        kind: Counter(str(row[kind]) for row in rows)
        for kind in ("exact_fingerprint", "near_fingerprint", "feature_fingerprint")
    }
    return {
        "group_count": len(counts),
        "largest_group_rows": max(counts.values(), default=0),
        "multirow_groups": sum(1 for count in counts.values() if count > 1),
        "rows_in_multirow_groups": sum(count for count in counts.values() if count > 1),
        "duplicate_exact_fingerprint_groups": sum(
            1 for count in fingerprint_counts["exact_fingerprint"].values() if count > 1
        ),
        "duplicate_near_fingerprint_groups": sum(
            1 for count in fingerprint_counts["near_fingerprint"].values() if count > 1
        ),
        "duplicate_feature_fingerprint_groups": sum(
            1 for count in fingerprint_counts["feature_fingerprint"].values() if count > 1
        ),
    }


def _distribution(values: Iterable[str]) -> dict[str, int]:
    return dict(sorted(Counter(values).items()))


def _choose_group_subset(
    indices: list[int],
    rows: list[dict[str, Any]],
    *,
    group_field: str,
    desired_rows: int,
    seed: int,
) -> tuple[list[int], list[int], dict[str, Any]]:
    groups: dict[str, list[int]] = defaultdict(list)
    for index in indices:
        groups[str(rows[index][group_field])].append(index)
    if len(groups) < 2:
        return [], indices, {"ok": False, "reason": f"fewer than two {group_field} groups"}

    desired = max(1, min(desired_rows, len(indices) - 1))
    overall_targets = Counter(rows[index]["safe_queue_target"] for index in indices)
    overall_total = max(1, len(indices))
    best: tuple[float, list[int], list[int]] | None = None
    keys = sorted(groups)
    for attempt in range(250):
        shuffled = list(keys)
        random.Random(seed + attempt).shuffle(shuffled)
        selected_keys: list[str] = []
        selected_size = 0
        for key in shuffled:
            if selected_size >= desired:
                break
            selected_keys.append(key)
            selected_size += len(groups[key])
        subset = sorted(index for key in selected_keys for index in groups[key])
        subset_set = set(subset)
        remainder = [index for index in indices if index not in subset_set]
        if not subset or not remainder:
            continue
        subset_targets = Counter(rows[index]["safe_queue_target"] for index in subset)
        remainder_targets = Counter(rows[index]["safe_queue_target"] for index in remainder)
        missing_penalty = 0.0
        for label in overall_targets:
            if overall_targets[label] >= 4 and (not subset_targets[label] or not remainder_targets[label]):
                missing_penalty += 10.0
        size_error = abs(len(subset) - desired) / overall_total
        drift = sum(
            abs((subset_targets[label] / len(subset)) - (overall_targets[label] / overall_total))
            for label in overall_targets
        )
        score = missing_penalty + size_error + drift
        if best is None or score < best[0]:
            best = (score, subset, remainder)
    if best is None:
        return [], indices, {"ok": False, "reason": f"unable to partition {group_field} groups"}
    return best[1], best[2], {
        "ok": True,
        "group_field": group_field,
        "selected_rows": len(best[1]),
        "remaining_rows": len(best[2]),
        "selected_groups": len({str(rows[index][group_field]) for index in best[1]}),
        "remaining_groups": len({str(rows[index][group_field]) for index in best[2]}),
        "selection_score": round(best[0], 6),
    }


def _temporal_partitions(
    rows: list[dict[str, Any]],
    *,
    final_test_size: float,
    calibration_size: float,
    threshold_size: float,
) -> dict[str, Any]:
    timestamped = sorted(
        (row["timestamp"], index)
        for index, row in enumerate(rows)
        if row.get("timestamp") is not None
    )
    if len(timestamped) < 4:
        return {"status": "failed", "reason": "fewer than four timestamped rows"}

    total = len(timestamped)
    fit_share = 1.0 - final_test_size - calibration_size - threshold_size
    boundary_positions = [
        max(1, min(total - 1, int(total * fit_share))),
        max(1, min(total - 1, int(total * (fit_share + calibration_size)))),
        max(1, min(total - 1, int(total * (fit_share + calibration_size + threshold_size)))),
    ]
    fit_end, calibration_end, threshold_end = [timestamped[position][0] for position in boundary_positions]
    grouped: dict[str, list[int]] = defaultdict(list)
    for index, row in enumerate(rows):
        grouped[str(row["leakage_group"])].append(index)

    partitions = {"fit_idx": [], "calibration_idx": [], "threshold_idx": [], "final_test_idx": []}
    quarantined: list[int] = []
    for members in grouped.values():
        member_times = [rows[index].get("timestamp") for index in members]
        if any(value is None for value in member_times):
            quarantined.extend(members)
            continue
        minimum = min(member_times)
        maximum = max(member_times)
        if maximum < fit_end:
            partitions["fit_idx"].extend(members)
        elif minimum >= fit_end and maximum < calibration_end:
            partitions["calibration_idx"].extend(members)
        elif minimum >= calibration_end and maximum < threshold_end:
            partitions["threshold_idx"].extend(members)
        elif minimum >= threshold_end:
            partitions["final_test_idx"].extend(members)
        else:
            quarantined.extend(members)

    return {
        "status": "partitioned",
        **{key: sorted(values) for key, values in partitions.items()},
        "quarantined_idx": sorted(quarantined),
        "partition_method": "strict_chronological_components_with_boundary_quarantine",
        "time_boundaries": {
            "fit_end": fit_end.isoformat(),
            "calibration_end": calibration_end.isoformat(),
            "threshold_end": threshold_end.isoformat(),
        },
    }


def build_frozen_partition(
    rows: list[dict[str, Any]],
    *,
    split_mode: str,
    final_test_size: float = 0.25,
    calibration_size: float = 0.15,
    threshold_size: float = 0.15,
) -> dict[str, Any]:
    if not 0 < final_test_size < 0.5:
        raise ValueError("final_test_size must be between 0 and 0.5")
    if calibration_size <= 0 or threshold_size <= 0 or final_test_size + calibration_size + threshold_size >= 0.8:
        raise ValueError("fit, calibration, threshold, and final-test partitions need nonzero capacity")
    supported_splits = {*V398_SPLITS, "network_zone_holdout"}
    if split_mode not in supported_splits:
        raise ValueError(f"Unknown v3.98 split mode: {split_mode}")

    if split_mode == "temporal_holdout":
        partition = _temporal_partitions(
            rows,
            final_test_size=final_test_size,
            calibration_size=calibration_size,
            threshold_size=threshold_size,
        )
    else:
        indices = list(range(len(rows)))
        if split_mode == "source_holdout":
            final_group = "source_name"
            seed = 398
        elif split_mode == "network_zone_holdout":
            final_group = "network_zone_group"
            seed = 499
        else:
            final_group = "leakage_group"
            seed = int(split_mode.rsplit("_", 1)[-1])
        final_idx, development_idx, final_meta = _choose_group_subset(
            indices,
            rows,
            group_field=final_group,
            desired_rows=round(len(rows) * final_test_size),
            seed=seed,
        )
        if not final_meta.get("ok"):
            return {"status": "failed", "reason": final_meta.get("reason"), "split_mode": split_mode}
        calibration_idx, remaining_idx, calibration_meta = _choose_group_subset(
            development_idx,
            rows,
            group_field="leakage_group",
            desired_rows=round(len(rows) * calibration_size),
            seed=seed + 1000,
        )
        threshold_idx, fit_idx, threshold_meta = _choose_group_subset(
            remaining_idx,
            rows,
            group_field="leakage_group",
            desired_rows=round(len(rows) * threshold_size),
            seed=seed + 2000,
        )
        if not calibration_meta.get("ok") or not threshold_meta.get("ok"):
            return {
                "status": "failed",
                "reason": calibration_meta.get("reason") or threshold_meta.get("reason"),
                "split_mode": split_mode,
            }
        partition = {
            "status": "partitioned",
            "fit_idx": fit_idx,
            "calibration_idx": calibration_idx,
            "threshold_idx": threshold_idx,
            "final_test_idx": final_idx,
            "quarantined_idx": [],
            "partition_method": (
                "source_disjoint_final_then_fingerprint_grouped_internal"
                if split_mode == "source_holdout"
                else "network_zone_disjoint_final_then_fingerprint_grouped_internal"
                if split_mode == "network_zone_holdout"
                else "fingerprint_component_grouped_random"
            ),
            "selection_metadata": {
                "final": final_meta,
                "calibration": calibration_meta,
                "threshold": threshold_meta,
            },
        }

    partition["split_mode"] = split_mode
    partition["final_test_labels_used_for_training"] = False
    partition["final_test_labels_used_for_calibration"] = False
    partition["final_test_labels_used_for_threshold_selection"] = False
    partition["fractions"] = {
        "final_test": final_test_size,
        "calibration": calibration_size,
        "threshold_selection": threshold_size,
        "fit": round(1.0 - final_test_size - calibration_size - threshold_size, 4),
    }
    for key in ("fit_idx", "calibration_idx", "threshold_idx", "final_test_idx", "quarantined_idx"):
        partition[key] = sorted(set(partition.get(key) or []))

    # A source split can still contain the same near-pattern component in a
    # test source and a development source. Quarantine the entire component.
    if split_mode == "source_holdout":
        owners: dict[str, set[str]] = defaultdict(set)
        for key in ("fit_idx", "calibration_idx", "threshold_idx", "final_test_idx"):
            for index in partition[key]:
                owners[str(rows[index]["leakage_group"])].add(key)
        crossing = {group for group, locations in owners.items() if len(locations) > 1}
        if crossing:
            quarantined = set(partition["quarantined_idx"])
            for key in ("fit_idx", "calibration_idx", "threshold_idx", "final_test_idx"):
                kept = []
                for index in partition[key]:
                    if str(rows[index]["leakage_group"]) in crossing:
                        quarantined.add(index)
                    else:
                        kept.append(index)
                partition[key] = kept
            partition["quarantined_idx"] = sorted(quarantined)
            partition["cross_source_fingerprint_groups_quarantined"] = len(crossing)

    partition["partition_id"] = _stable_hash(
        {
            "protocol": "v3.98-frozen-holdout-v1",
            "split_mode": split_mode,
            "fit": [rows[index]["log_id"] for index in partition["fit_idx"]],
            "calibration": [rows[index]["log_id"] for index in partition["calibration_idx"]],
            "threshold": [rows[index]["log_id"] for index in partition["threshold_idx"]],
            "final": [rows[index]["log_id"] for index in partition["final_test_idx"]],
        }
    )
    return partition


def _overlap(rows: list[dict[str, Any]], left: list[int], right: list[int], field: str) -> int:
    left_values = {str(rows[index][field]) for index in left}
    right_values = {str(rows[index][field]) for index in right}
    return len(left_values & right_values)


def _time_bucket_overlap(rows: list[dict[str, Any]], left: list[int], right: list[int]) -> int:
    def buckets(indices: list[int]) -> set[str]:
        return {
            value.replace(minute=0, second=0, microsecond=0).isoformat()
            for index in indices
            if (value := rows[index].get("timestamp")) is not None
        }

    return len(buckets(left) & buckets(right))


def audit_partition_leakage(rows: list[dict[str, Any]], partition: dict[str, Any]) -> dict[str, Any]:
    if partition.get("status") != "partitioned":
        return {"passed": False, "status": "partition_unavailable", "reason": partition.get("reason")}
    keys = ("fit_idx", "calibration_idx", "threshold_idx", "final_test_idx")
    pairwise: list[dict[str, Any]] = []
    unacceptable = 0
    for left_position, left_key in enumerate(keys):
        for right_key in keys[left_position + 1 :]:
            row = {"left": left_key, "right": right_key}
            for field in ("exact_fingerprint", "near_fingerprint", "feature_fingerprint", "log_id", "leakage_group"):
                count = _overlap(rows, partition[left_key], partition[right_key], field)
                row[f"{field}_overlap"] = count
                unacceptable += count
            row["source_name_overlap"] = _overlap(rows, partition[left_key], partition[right_key], "source_name")
            row["utc_hour_bucket_overlap"] = _time_bucket_overlap(
                rows,
                partition[left_key],
                partition[right_key],
            )
            pairwise.append(row)

    source_overlap = 0
    group_overlap = 0
    if partition["split_mode"] == "source_holdout":
        development = partition["fit_idx"] + partition["calibration_idx"] + partition["threshold_idx"]
        source_overlap = _overlap(rows, development, partition["final_test_idx"], "source_name")
        unacceptable += source_overlap
    elif partition["split_mode"] == "network_zone_holdout":
        development = partition["fit_idx"] + partition["calibration_idx"] + partition["threshold_idx"]
        group_overlap = _overlap(rows, development, partition["final_test_idx"], "network_zone_group")
        unacceptable += group_overlap

    temporal_overlap = False
    if partition["split_mode"] == "temporal_holdout":
        development_times = [rows[index]["timestamp"] for key in keys[:-1] for index in partition[key]]
        final_times = [rows[index]["timestamp"] for index in partition["final_test_idx"]]
        temporal_overlap = bool(development_times and final_times and max(development_times) >= min(final_times))
        unacceptable += int(temporal_overlap)

    partition_sizes = {key.removesuffix("_idx"): len(partition[key]) for key in (*keys, "quarantined_idx")}
    target_distributions = {
        key.removesuffix("_idx"): _distribution(rows[index]["safe_queue_target"] for index in partition[key])
        for key in keys
    }
    missing_required_partition = any(not partition[key] for key in keys)
    class_diversity_failure = any(len(target_distributions[key.removesuffix("_idx")]) < 2 for key in keys)
    passed = unacceptable == 0 and not missing_required_partition and not class_diversity_failure
    return {
        "passed": passed,
        "status": "passed" if passed else "failed_closed",
        "unacceptable_overlap_count": unacceptable,
        "pairwise": pairwise,
        "diagnostic_source_overlap_count": sum(int(row["source_name_overlap"]) for row in pairwise),
        "diagnostic_utc_hour_overlap_count": sum(int(row["utc_hour_bucket_overlap"]) for row in pairwise),
        "source_time_policy": (
            "source identity is fatal only across development/final in source holdout; "
            "chronological overlap is fatal in temporal holdout; random splits report both as diagnostics"
        ),
        "source_overlap_with_final_test": source_overlap,
        "network_zone_group_overlap_with_final_test": group_overlap,
        "temporal_window_overlap": temporal_overlap,
        "missing_required_partition": missing_required_partition,
        "class_diversity_failure": class_diversity_failure,
        "partition_sizes": partition_sizes,
        "target_distributions": target_distributions,
        "quarantined_rows": len(partition["quarantined_idx"]),
    }


def _binary_metrics(y_true: list[str], predictions: list[str]) -> dict[str, Any]:
    tp = fp = fn = tn = 0
    for actual, predicted in zip(y_true, predictions, strict=True):
        actual_positive = actual == "needs_review"
        predicted_positive = predicted == "needs_review"
        if actual_positive and predicted_positive:
            tp += 1
        elif not actual_positive and predicted_positive:
            fp += 1
        elif actual_positive:
            fn += 1
        else:
            tn += 1
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0

    class_metrics = []
    for label in QUEUE_LABELS:
        label_tp = sum(1 for actual, predicted in zip(y_true, predictions, strict=True) if actual == label and predicted == label)
        label_fp = sum(1 for actual, predicted in zip(y_true, predictions, strict=True) if actual != label and predicted == label)
        label_fn = sum(1 for actual, predicted in zip(y_true, predictions, strict=True) if actual == label and predicted != label)
        support = sum(1 for actual in y_true if actual == label)
        label_precision = label_tp / (label_tp + label_fp) if label_tp + label_fp else 0.0
        label_recall = label_tp / (label_tp + label_fn) if label_tp + label_fn else 0.0
        label_f1 = (
            2 * label_precision * label_recall / (label_precision + label_recall)
            if label_precision + label_recall
            else 0.0
        )
        class_metrics.append((label, label_precision, label_recall, label_f1, support))
    total = max(1, len(y_true))
    macro_f1 = sum(item[3] for item in class_metrics) / len(class_metrics)
    weighted_f1 = sum(item[3] * item[4] for item in class_metrics) / total
    return {
        "queue_precision": round(precision, 4),
        "queue_recall": round(recall, 4),
        "queue_f1": round(f1, 4),
        "benign_like_false_positive_rate": round(fpr, 4),
        "macro_f1": round(macro_f1, 4),
        "weighted_f1": round(weighted_f1, 4),
        "true_positive": tp,
        "false_positive": fp,
        "false_negative": fn,
        "true_negative": tn,
        "review_queue_size": tp + fp,
        "review_queue_rate": round((tp + fp) / total, 4),
        "per_class": {
            label: {
                "precision": round(label_precision, 4),
                "recall": round(label_recall, 4),
                "f1": round(label_f1, 4),
                "support": support,
            }
            for label, label_precision, label_recall, label_f1, support in class_metrics
        },
    }


def _diagnostic_original_recall(
    rows: list[dict[str, Any]],
    indices: list[int],
    predictions: list[str],
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for label in ("suspicious", "malicious"):
        positions = [position for position, index in enumerate(indices) if rows[index]["original_label"] == label]
        caught = sum(1 for position in positions if predictions[position] == "needs_review")
        result[f"{label}_recall"] = round(caught / len(positions), 4) if positions else None
        result[f"{label}_support"] = len(positions)
    return result


def _calibration_report(y_true: list[str], scores: list[float], *, bins: int = 10) -> dict[str, Any]:
    if not y_true or len(y_true) != len(scores):
        return {"status": "missing", "passed": False, "confidence_buckets": []}
    binary = [1 if value == "needs_review" else 0 for value in y_true]
    bounded = [max(0.0, min(1.0, float(score))) for score in scores]
    brier = sum((score - actual) ** 2 for score, actual in zip(bounded, binary, strict=True)) / len(binary)
    bucket_rows = []
    ece = 0.0
    max_gap = 0.0
    for bucket in range(bins):
        lower = bucket / bins
        upper = (bucket + 1) / bins
        positions = [
            index
            for index, score in enumerate(bounded)
            if lower <= score < upper or (bucket == bins - 1 and score == 1.0)
        ]
        if not positions:
            continue
        confidence = sum(bounded[index] for index in positions) / len(positions)
        accuracy = sum(binary[index] for index in positions) / len(positions)
        gap = abs(confidence - accuracy)
        ece += (len(positions) / len(binary)) * gap
        max_gap = max(max_gap, gap)
        bucket_rows.append(
            {
                "range": f"{lower:.1f}-{upper:.1f}",
                "rows": len(positions),
                "average_confidence": round(confidence, 4),
                "observed_positive_rate": round(accuracy, 4),
                "gap": round(gap, 4),
            }
        )
    passed = brier <= 0.20 and ece <= 0.15 and max_gap <= 0.20
    return {
        "status": "passed" if passed else "weak",
        "passed": passed,
        "brier_score": round(brier, 4),
        "expected_calibration_error": round(ece, 4),
        "max_confidence_accuracy_gap": round(max_gap, 4),
        "confidence_buckets": bucket_rows,
    }


def _bootstrap_intervals(
    y_true: list[str],
    predictions: list[str],
    *,
    seed: int,
    iterations: int = 300,
) -> dict[str, Any]:
    if len(y_true) < 2:
        return {"status": "insufficient_rows", "iterations": 0}
    rng = random.Random(seed)
    values: dict[str, list[float]] = defaultdict(list)
    for _ in range(iterations):
        positions = [rng.randrange(len(y_true)) for _row in y_true]
        sample_true = [y_true[position] for position in positions]
        sample_predictions = [predictions[position] for position in positions]
        metrics = _binary_metrics(sample_true, sample_predictions)
        for key in ("queue_precision", "queue_recall", "queue_f1", "benign_like_false_positive_rate"):
            values[key].append(float(metrics[key]))

    def interval(items: list[float]) -> dict[str, float]:
        ordered = sorted(items)
        lower = ordered[max(0, int(len(ordered) * 0.025) - 1)]
        upper = ordered[min(len(ordered) - 1, int(len(ordered) * 0.975))]
        return {"lower": round(lower, 4), "upper": round(upper, 4)}

    return {
        "status": "computed",
        "method": "deterministic_nonparametric_bootstrap",
        "iterations": iterations,
        "confidence_level": 0.95,
        "intervals": {key: interval(items) for key, items in values.items()},
    }


def _error_patterns(
    rows: list[dict[str, Any]],
    indices: list[int],
    y_true: list[str],
    predictions: list[str],
) -> dict[str, Any]:
    false_positive_rows = []
    false_negative_rows = []
    for position, index in enumerate(indices):
        if y_true[position] == predictions[position]:
            continue
        item = {
            "source": rows[index]["source_name"],
            "app": rows[index]["app"],
            "action": rows[index]["action"],
            "dst_port": rows[index]["dst_port"],
            "original_label": rows[index]["original_label"],
        }
        if y_true[position] == "non_threat":
            false_positive_rows.append(item)
        else:
            false_negative_rows.append(item)

    def summarize(items: list[dict[str, Any]]) -> dict[str, Any]:
        return {
            "rows": len(items),
            "top_sources": Counter(str(item["source"]) for item in items).most_common(10),
            "top_apps": Counter(str(item["app"]) for item in items).most_common(10),
            "top_actions": Counter(str(item["action"]) for item in items).most_common(10),
            "top_ports": Counter(str(item["dst_port"]) for item in items).most_common(10),
            "top_original_labels": Counter(str(item["original_label"]) for item in items).most_common(10),
        }

    return {"false_positives": summarize(false_positive_rows), "false_negatives": summarize(false_negative_rows)}


def select_threshold(y_threshold: list[str], scores: list[float]) -> dict[str, Any]:
    """Select a queue threshold from the dedicated threshold partition only."""

    if not y_threshold or len(y_threshold) != len(scores):
        return {
            "status": "failed",
            "selected_threshold": 0.5,
            "selected_on": "threshold_selection_partition_only",
            "threshold_rows": len(y_threshold),
            "used_final_test_labels": False,
        }
    candidates = []
    for threshold in THRESHOLD_GRID:
        predictions = ["needs_review" if score >= threshold else "non_threat" for score in scores]
        metrics = _binary_metrics(y_threshold, predictions)
        recall = float(metrics["queue_recall"])
        fpr = float(metrics["benign_like_false_positive_rate"])
        f1 = float(metrics["queue_f1"])
        precision = float(metrics["queue_precision"])
        score = f1 + (0.10 * precision) + (0.10 * recall) - (0.35 * fpr)
        if recall < 0.75:
            score -= 1.0
        candidates.append({"threshold": threshold, "selection_score": round(score, 6), "metrics": metrics})
    selected = max(candidates, key=lambda item: (item["selection_score"], -item["threshold"]))
    return {
        "status": "selected",
        "selected_threshold": selected["threshold"],
        "selected_on": "threshold_selection_partition_only",
        "threshold_rows": len(y_threshold),
        "used_final_test_labels": False,
        "selected_metrics": selected["metrics"],
        "candidate_count": len(candidates),
    }


def _positive_scores(model: Any, frame: Any, indices: list[int]) -> list[float]:
    classes = _classes(model)
    if "needs_review" not in classes:
        return [0.0 for _ in indices]
    position = classes.index("needs_review")
    probabilities = model.predict_proba(frame.iloc[indices])
    return [float(row[position]) for row in probabilities]


def _fit_supervised_candidate(
    dataset: dict[str, Any],
    partition: dict[str, Any],
    *,
    model_type: str,
    calibrate: bool,
) -> dict[str, Any]:
    frame = dataset["frame"]
    targets = dataset["targets"]
    fit_idx = partition["fit_idx"]
    calibration_idx = partition["calibration_idx"]
    threshold_idx = partition["threshold_idx"]
    final_idx = partition["final_test_idx"]
    y_fit = [targets[index] for index in fit_idx]
    pipeline = _build_pipeline_for_columns(
        dataset["imports"],
        model_type=model_type,
        class_weight="balanced" if model_type == "logistic_regression" else None,
        numeric_features=dataset["feature_meta"]["numeric_features"],
        categorical_features=dataset["feature_meta"]["categorical_features"],
    )
    weights, weight_meta = _noise_reduced_weights(dataset["labels"], "strong_benign")
    fit_kwargs: dict[str, Any] = {}
    if model_type != "logistic_regression":
        fit_kwargs["model__sample_weight"] = [weights[index] for index in fit_idx]
    started = time.perf_counter()
    pipeline.fit(frame.iloc[fit_idx], y_fit, **fit_kwargs)
    model: Any = pipeline
    calibration_method = "none"
    if calibrate:
        from sklearn.calibration import CalibratedClassifierCV

        y_calibration = [targets[index] for index in calibration_idx]
        try:
            from sklearn.frozen import FrozenEstimator

            model = CalibratedClassifierCV(FrozenEstimator(pipeline), method="sigmoid")
        except ImportError:  # pragma: no cover - compatibility with older sklearn
            model = CalibratedClassifierCV(pipeline, method="sigmoid", cv="prefit")
        model.fit(frame.iloc[calibration_idx], y_calibration)
        calibration_method = "sigmoid_on_dedicated_calibration_partition"

    threshold_scores = _positive_scores(model, frame, threshold_idx)
    threshold = select_threshold([targets[index] for index in threshold_idx], threshold_scores)
    final_scores = _positive_scores(model, frame, final_idx)
    return {
        "model": model,
        "threshold_selection": threshold,
        "threshold_scores": threshold_scores,
        "final_scores": final_scores,
        "training_seconds": round(time.perf_counter() - started, 4),
        "calibration_method": calibration_method,
        "weighting": weight_meta,
    }


def _rule_scores(logs: list[Any], indices: list[int]) -> list[float]:
    selected_logs = [logs[index] for index in indices]
    context = build_detection_context(selected_logs)
    scores = []
    for log in selected_logs:
        matches = [match for match in evaluate_rules(log, context) if match.code != "ml_anomaly_detected"]
        scores.append(min(100, sum(match.score for match in matches)) / 100.0)
    return scores


def _fit_anomaly_candidate(dataset: dict[str, Any], partition: dict[str, Any]) -> dict[str, Any]:
    from sklearn.compose import ColumnTransformer
    from sklearn.ensemble import IsolationForest
    from sklearn.impute import SimpleImputer
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import OneHotEncoder

    numeric = dataset["feature_meta"]["numeric_features"]
    categorical = dataset["feature_meta"]["categorical_features"]
    preprocess = ColumnTransformer(
        transformers=[
            ("numeric", SimpleImputer(strategy="median"), numeric),
            (
                "categorical",
                Pipeline(
                    steps=[
                        ("imputer", SimpleImputer(strategy="most_frequent")),
                        ("onehot", OneHotEncoder(handle_unknown="ignore")),
                    ]
                ),
                categorical,
            ),
        ]
    )
    model = Pipeline(
        steps=[
            ("preprocess", preprocess),
            ("model", IsolationForest(n_estimators=150, contamination="auto", random_state=398, n_jobs=-1)),
        ]
    )
    frame = dataset["frame"]
    model.fit(frame.iloc[partition["fit_idx"]])
    calibration_raw = [-float(value) for value in model.decision_function(frame.iloc[partition["calibration_idx"]])]

    def percentiles(values: list[float]) -> list[float]:
        if not calibration_raw:
            return [0.5 for _ in values]
        reference = sorted(calibration_raw)
        return [sum(1 for item in reference if item <= value) / len(reference) for value in values]

    threshold_raw = [-float(value) for value in model.decision_function(frame.iloc[partition["threshold_idx"]])]
    final_raw = [-float(value) for value in model.decision_function(frame.iloc[partition["final_test_idx"]])]
    threshold_scores = percentiles(threshold_raw)
    return {
        "threshold_selection": select_threshold(
            [dataset["targets"][index] for index in partition["threshold_idx"]],
            threshold_scores,
        ),
        "threshold_scores": threshold_scores,
        "final_scores": percentiles(final_raw),
        "scaling": "empirical_percentile_from_calibration_partition_without_labels",
    }


def _evaluate_scores(
    dataset: dict[str, Any],
    partition: dict[str, Any],
    *,
    name: str,
    scores: list[float],
    threshold_selection: dict[str, Any],
    seed: int,
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    final_idx = partition["final_test_idx"]
    y_true = [dataset["targets"][index] for index in final_idx]
    threshold = float(threshold_selection.get("selected_threshold", 0.5))
    predictions = ["needs_review" if score >= threshold else "non_threat" for score in scores]
    metrics = _binary_metrics(y_true, predictions)
    metrics.update(_diagnostic_original_recall(dataset["rows"], final_idx, predictions))
    return {
        "name": name,
        "status": "evaluated",
        "threshold_selection": threshold_selection,
        "metrics": metrics,
        "calibration": _calibration_report(y_true, scores),
        "bootstrap_95_percent": _bootstrap_intervals(y_true, predictions, seed=seed),
        "error_patterns": _error_patterns(dataset["rows"], final_idx, y_true, predictions),
        "details": details or {},
        "_scores": scores,
        "_predictions": predictions,
    }


def _fixed_threshold(value: float, *, policy: str) -> dict[str, Any]:
    return {
        "status": "fixed",
        "selected_threshold": value,
        "selected_on": policy,
        "used_final_test_labels": False,
    }


def _run_split(dataset: dict[str, Any], *, split_mode: str) -> dict[str, Any]:
    partition = build_frozen_partition(dataset["rows"], split_mode=split_mode)
    leakage = audit_partition_leakage(dataset["rows"], partition)
    if not leakage.get("passed"):
        return {
            "split_mode": split_mode,
            "status": "failed_closed",
            "partition": partition,
            "leakage_audit": leakage,
            "strategies": [],
        }

    seed = 398 if split_mode in {"temporal_holdout", "source_holdout"} else int(split_mode.rsplit("_", 1)[-1])
    primary = _fit_supervised_candidate(dataset, partition, model_type="extra_trees", calibrate=True)
    logistic = _fit_supervised_candidate(dataset, partition, model_type="logistic_regression", calibrate=False)
    anomaly = _fit_anomaly_candidate(dataset, partition)

    final_idx = partition["final_test_idx"]
    threshold_idx = partition["threshold_idx"]
    final_rule_scores = _rule_scores(dataset["logs"], final_idx)
    threshold_rule_scores = _rule_scores(dataset["logs"], threshold_idx)

    primary_result = _evaluate_scores(
        dataset,
        partition,
        name=PRIMARY_CANDIDATE,
        scores=primary["final_scores"],
        threshold_selection=primary["threshold_selection"],
        seed=seed,
        details={
            "model_type": "extra_trees",
            "calibration_method": primary["calibration_method"],
            "training_seconds": primary["training_seconds"],
            "sample_weighting": primary["weighting"],
        },
    )
    logistic_result = _evaluate_scores(
        dataset,
        partition,
        name="balanced_logistic_regression_baseline",
        scores=logistic["final_scores"],
        threshold_selection=logistic["threshold_selection"],
        seed=seed + 1,
        details={
            "model_type": "logistic_regression",
            "calibration_method": logistic["calibration_method"],
            "training_seconds": logistic["training_seconds"],
        },
    )
    rule_result = _evaluate_scores(
        dataset,
        partition,
        name="deterministic_rules_baseline",
        scores=final_rule_scores,
        threshold_selection=_fixed_threshold(RULE_QUEUE_THRESHOLD, policy="existing_minimum_rule_alert_score"),
        seed=seed + 2,
        details={"ml_anomaly_rule_excluded": True, "context_scope": "final_partition_batch_only"},
    )
    anomaly_result = _evaluate_scores(
        dataset,
        partition,
        name="isolation_forest_baseline",
        scores=anomaly["final_scores"],
        threshold_selection=anomaly["threshold_selection"],
        seed=seed + 3,
        details={"scaling": anomaly["scaling"], "model_artifact_written": False},
    )

    threshold_hybrid_scores = [
        (0.55 * rule_score) + (0.20 * anomaly_score) + (0.20 * supervised_score)
        for rule_score, anomaly_score, supervised_score in zip(
            threshold_rule_scores,
            anomaly["threshold_scores"],
            primary["threshold_scores"],
            strict=True,
        )
    ]
    final_hybrid_scores = [
        (0.55 * rule_score) + (0.20 * anomaly_score) + (0.20 * supervised_score)
        for rule_score, anomaly_score, supervised_score in zip(
            final_rule_scores,
            anomaly["final_scores"],
            primary["final_scores"],
            strict=True,
        )
    ]
    hybrid_threshold = select_threshold(
        [dataset["targets"][index] for index in threshold_idx],
        threshold_hybrid_scores,
    )
    hybrid_result = _evaluate_scores(
        dataset,
        partition,
        name="hybrid_rule_anomaly_supervised_decision_support",
        scores=final_hybrid_scores,
        threshold_selection=hybrid_threshold,
        seed=seed + 4,
        details={
            "weights": {"rule": 0.55, "anomaly": 0.20, "supervised_queue": 0.20, "asset_context": 0.05},
            "asset_context_value": 0.0,
            "decision_support_only": True,
        },
    )

    fit_targets = [dataset["targets"][index] for index in partition["fit_idx"]]
    majority = Counter(fit_targets).most_common(1)[0][0]
    majority_scores = [1.0 if majority == "needs_review" else 0.0 for _ in final_idx]
    majority_result = _evaluate_scores(
        dataset,
        partition,
        name="majority_class_baseline",
        scores=majority_scores,
        threshold_selection=_fixed_threshold(0.5, policy="fit_partition_majority_only"),
        seed=seed + 5,
        details={"fit_majority_class": majority},
    )

    return {
        "split_mode": split_mode,
        "status": "evaluated",
        "partition": {
            key: value
            for key, value in partition.items()
            if key not in {"fit_idx", "calibration_idx", "threshold_idx", "final_test_idx", "quarantined_idx"}
        },
        "partition_sizes": leakage["partition_sizes"],
        "partition_target_distributions": leakage["target_distributions"],
        "leakage_audit": leakage,
        "strategies": [
            primary_result,
            logistic_result,
            rule_result,
            anomaly_result,
            hybrid_result,
            majority_result,
        ],
    }


def _public_strategy(strategy: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in strategy.items() if not key.startswith("_")}


def _strategy_comparison(split_results: list[dict[str, Any]]) -> dict[str, Any]:
    names = sorted(
        {
            strategy["name"]
            for split in split_results
            for strategy in split.get("strategies") or []
            if strategy.get("status") == "evaluated"
        }
    )
    comparison: dict[str, Any] = {}
    for name in names:
        rows = []
        for split in split_results:
            for strategy in split.get("strategies") or []:
                if strategy.get("name") == name and strategy.get("status") == "evaluated":
                    rows.append({"split_mode": split["split_mode"], **strategy["metrics"], "calibration": strategy["calibration"]})
        metric_ranges = {}
        for metric in (
            "queue_precision",
            "queue_recall",
            "queue_f1",
            "benign_like_false_positive_rate",
            "macro_f1",
            "weighted_f1",
            "suspicious_recall",
            "malicious_recall",
            "review_queue_rate",
        ):
            values = [float(row[metric]) for row in rows if row.get(metric) is not None]
            metric_ranges[metric] = {
                "min": round(min(values), 4) if values else None,
                "max": round(max(values), 4) if values else None,
            }
        comparison[name] = {
            "evaluated_splits": len(rows),
            "metric_ranges": metric_ranges,
            "calibration_passed_splits": sum(1 for row in rows if (row.get("calibration") or {}).get("passed")),
            "split_metrics": rows,
        }
    return comparison


def _readiness(split_results: list[dict[str, Any]], comparison: dict[str, Any]) -> dict[str, Any]:
    evaluated = [split for split in split_results if split.get("status") == "evaluated"]
    primary_rows = []
    for split in evaluated:
        primary_rows.extend(
            strategy
            for strategy in split.get("strategies") or []
            if strategy.get("name") == PRIMARY_CANDIDATE and strategy.get("status") == "evaluated"
        )
    checks = [
        {
            "name": "all required splits evaluated",
            "passed": len(evaluated) == len(V398_SPLITS),
            "value": f"{len(evaluated)}/{len(V398_SPLITS)}",
            "target": "5/5",
        },
        {
            "name": "all partition leakage audits passed",
            "passed": len(evaluated) == len(V398_SPLITS) and all(split["leakage_audit"]["passed"] for split in evaluated),
            "value": sum(1 for split in evaluated if split["leakage_audit"]["passed"]),
            "target": len(V398_SPLITS),
        },
        {
            "name": "final labels never used for fit calibration or threshold selection",
            "passed": all(
                not bool((strategy.get("threshold_selection") or {}).get("used_final_test_labels"))
                for split in evaluated
                for strategy in split.get("strategies") or []
            ),
            "value": False,
            "target": False,
        },
        {
            "name": "primary queue F1 stable",
            "passed": bool(primary_rows) and min(float(row["metrics"]["queue_f1"]) for row in primary_rows) >= 0.80,
            "value": min((float(row["metrics"]["queue_f1"]) for row in primary_rows), default=None),
            "target": ">= 0.80 every split",
        },
        {
            "name": "primary benign-like FPR controlled",
            "passed": bool(primary_rows)
            and max(float(row["metrics"]["benign_like_false_positive_rate"]) for row in primary_rows) <= 0.15,
            "value": max((float(row["metrics"]["benign_like_false_positive_rate"]) for row in primary_rows), default=None),
            "target": "<= 0.15 every split",
        },
        {
            "name": "primary queue recall stable",
            "passed": bool(primary_rows) and min(float(row["metrics"]["queue_recall"]) for row in primary_rows) >= 0.80,
            "value": min((float(row["metrics"]["queue_recall"]) for row in primary_rows), default=None),
            "target": ">= 0.80 every split",
        },
        {
            "name": "primary confidence calibration acceptable",
            "passed": bool(primary_rows) and all(bool(row["calibration"]["passed"]) for row in primary_rows),
            "value": sum(1 for row in primary_rows if row["calibration"]["passed"]),
            "target": len(V398_SPLITS),
        },
        {
            "name": "external independent benchmark available",
            "passed": False,
            "value": "not performed in v3.98",
            "target": "provider-blinded or real-source external dataset",
        },
    ]
    internal_passed = all(item["passed"] for item in checks if item["name"] != "external independent benchmark available")
    return {
        "decision": "candidate_only",
        "internal_holdout_gates_passed": internal_passed,
        "external_independent_validation_passed": False,
        "checks_passed": sum(1 for item in checks if item["passed"]),
        "checks_total": len(checks),
        "checks": checks,
        "blockers": [item["name"] for item in checks if not item["passed"]],
        "production_promoted": False,
        "model_activated": False,
        "model_artifact_written": False,
        "response_automation_allowed": False,
        "real_firewall_blocking_enabled": False,
        "primary_candidate": comparison.get(PRIMARY_CANDIDATE) or {},
    }


def _worst_primary_split(split_results: list[dict[str, Any]]) -> dict[str, Any] | None:
    rows = []
    for split in split_results:
        for strategy in split.get("strategies") or []:
            if strategy.get("name") == PRIMARY_CANDIDATE and strategy.get("status") == "evaluated":
                rows.append(
                    {
                        "split_mode": split["split_mode"],
                        "metrics": strategy["metrics"],
                        "calibration": strategy["calibration"],
                    }
                )
    if not rows:
        return None
    return min(
        rows,
        key=lambda row: (
            float(row["metrics"]["queue_f1"]),
            -float(row["metrics"]["benign_like_false_positive_rate"]),
        ),
    )


def _database_counts(db: Session) -> dict[str, int]:
    return {
        "raw_logs": int(db.scalar(select(func.count(RawLog.id))) or 0),
        "normalized_logs": int(db.scalar(select(func.count(NormalizedLog.id))) or 0),
        "alerts": int(db.scalar(select(func.count(Alert.id))) or 0),
        "ml_labels": int(db.scalar(select(func.count(MLLabel.id))) or 0),
        "ml_model_runs": int(db.scalar(select(func.count(MLModelRun.id))) or 0),
        "detection_runs": int(db.scalar(select(func.count(DetectionRun.id))) or 0),
        "response_actions": int(db.scalar(select(func.count(ResponseAction.id))) or 0),
    }


def _artifact_state() -> dict[str, Any]:
    path = supervised_model_path()
    if not path.exists():
        return {"exists": False, "name": path.name, "size_bytes": None, "modified_ns": None}
    stat = path.stat()
    return {
        "exists": True,
        "name": path.name,
        "size_bytes": int(stat.st_size),
        "modified_ns": int(stat.st_mtime_ns),
    }


def _render_validation_report(result: dict[str, Any]) -> str:
    readiness = result.get("readiness") or {}
    worst = result.get("worst_primary_split") or {}
    lines = [
        "# v3.98 Independent Detection/ML Holdout Validation",
        "",
        f"Generated: {result.get('generated_at')}",
        "",
        "This is an internal leakage-controlled holdout. It is not an external independent benchmark and is not production accuracy.",
        "",
        "## Scope",
        "",
        f"- Evaluated reviewed latest labels: `{result.get('dataset', {}).get('rows')}`",
        f"- Primary frozen candidate: `{PRIMARY_CANDIDATE}`",
        f"- Feature generation seconds: `{result.get('dataset', {}).get('feature_generation_seconds')}`",
        f"- Leakage groups: `{result.get('leakage_group_summary')}`",
        f"- Readiness: `{readiness.get('decision')}`",
        f"- Internal gates passed: `{readiness.get('internal_holdout_gates_passed')}`",
        f"- External independent validation: `{readiness.get('external_independent_validation_passed')}`",
        "",
        "## Split Results",
        "",
        "| Split | Status | Precision | Recall | F1 | Benign FPR | Suspicious Recall | Malicious Recall | ECE |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for split in result.get("splits") or []:
        primary = next(
            (item for item in split.get("strategies") or [] if item.get("name") == PRIMARY_CANDIDATE),
            {},
        )
        metrics = primary.get("metrics") or {}
        calibration = primary.get("calibration") or {}
        lines.append(
            "| {split} | {status} | {precision} | {recall} | {f1} | {fpr} | {suspicious} | {malicious} | {ece} |".format(
                split=split.get("split_mode"),
                status=split.get("status"),
                precision=metrics.get("queue_precision", "-"),
                recall=metrics.get("queue_recall", "-"),
                f1=metrics.get("queue_f1", "-"),
                fpr=metrics.get("benign_like_false_positive_rate", "-"),
                suspicious=metrics.get("suspicious_recall", "-"),
                malicious=metrics.get("malicious_recall", "-"),
                ece=calibration.get("expected_calibration_error", "-"),
            )
        )
    lines.extend(
        [
            "",
            "## Worst Primary Split",
            "",
            f"- Split: `{worst.get('split_mode')}`",
            f"- Metrics: `{worst.get('metrics')}`",
            f"- Calibration: `{worst.get('calibration')}`",
            "",
            "## Strategy Comparison",
            "",
        ]
    )
    for name, item in (result.get("strategy_comparison") or {}).items():
        lines.append(f"- `{name}`: `{item.get('metric_ranges')}`")
    lines.extend(
        [
            "",
            "## Safety And Interpretation",
            "",
            "- Fit, probability calibration, threshold selection, and final test are separate partitions.",
            "- Exact raw fingerprints, normalized near-patterns, and used-feature fingerprints are grouped before splitting.",
            "- Weak/unreviewed latest labels are excluded from this evaluation.",
            "- Final-test labels are not used for fitting, probability calibration, or threshold selection.",
            "- No active model artifact is written or activated.",
            "- No labels, detection runs, alerts, or response actions are created.",
            "- The supervised output remains SOC review prioritization only.",
            "- Real firewall blocking and response automation remain disabled.",
            "",
            f"Safety evidence: `{result.get('safety')}`",
        ]
    )
    return "\n".join(lines) + "\n"


def _render_leakage_report(result: dict[str, Any]) -> str:
    lines = [
        "# v3.98 Leakage Audit",
        "",
        f"Generated: {result.get('generated_at')}",
        "",
        "The audit fails a split closed when exact fingerprints, near-pattern fingerprints, used-feature fingerprints, normalized-log IDs, or leakage components cross partitions. Source overlap is additionally forbidden for the source holdout; time-window overlap is forbidden for the temporal holdout.",
        "",
        f"Label provenance: `{result.get('dataset', {}).get('label_provenance')}`",
        f"Leakage groups: `{result.get('leakage_group_summary')}`",
        "",
        "## Split Audits",
        "",
    ]
    for split in result.get("splits") or []:
        audit = split.get("leakage_audit") or {}
        lines.extend(
            [
                f"### {split.get('split_mode')}",
                "",
                f"- Status: `{split.get('status')}`",
                f"- Audit passed: `{audit.get('passed')}`",
                f"- Unacceptable overlap count: `{audit.get('unacceptable_overlap_count')}`",
                f"- Source overlap with final test: `{audit.get('source_overlap_with_final_test')}`",
                f"- Temporal window overlap: `{audit.get('temporal_window_overlap')}`",
                f"- Partition sizes: `{audit.get('partition_sizes')}`",
                f"- Quarantined rows: `{audit.get('quarantined_rows')}`",
                f"- Pairwise evidence: `{audit.get('pairwise')}`",
                "",
            ]
        )
    lines.extend(
        [
            "## Known Boundary",
            "",
            "This audit controls row and feature-pattern leakage inside the current reviewed dataset. It cannot prove independence from the process that produced those labels. A provider-blinded or real-source external benchmark is still required.",
        ]
    )
    return "\n".join(lines) + "\n"


def run_v398_independent_holdout_validation(
    db: Session,
    *,
    output_dir: str | Path = OUTPUT_DIR,
    min_samples: int = 100,
    write_output: bool = True,
) -> dict[str, Any]:
    started = time.perf_counter()
    before_counts = _database_counts(db)
    before_artifact = _artifact_state()
    dataset = _build_dataset(db, min_samples=min_samples)
    if not dataset.get("ok"):
        return {
            "ok": False,
            "status": dataset.get("status", "skipped"),
            "phase": "v3.98",
            "message": dataset.get("message"),
            "readiness": {"decision": "candidate_only"},
            "safety": {
                "production_promoted": False,
                "model_activated": False,
                "model_artifact_written": False,
                "labels_written": False,
                "response_automation_allowed": False,
            },
        }

    leakage_group_summary = assign_leakage_groups(dataset["rows"])
    split_results = [_run_split(dataset, split_mode=split_mode) for split_mode in V398_SPLITS]
    comparison = _strategy_comparison(split_results)
    readiness = _readiness(split_results, comparison)
    after_counts = _database_counts(db)
    after_artifact = _artifact_state()
    counts_unchanged = before_counts == after_counts
    artifact_unchanged = before_artifact == after_artifact

    public_splits = []
    for split in split_results:
        public_splits.append(
            {
                **{key: value for key, value in split.items() if key != "strategies"},
                "strategies": [_public_strategy(strategy) for strategy in split.get("strategies") or []],
            }
        )
    generated_at = datetime.now(timezone.utc).isoformat()
    result = {
        "ok": counts_unchanged and artifact_unchanged,
        "status": "completed" if counts_unchanged and artifact_unchanged else "safety_failure",
        "phase": "v3.98",
        "generated_at": generated_at,
        "validation_scope": "internal_reviewed_label_leakage_controlled_holdout",
        "independence_claim": "unseen_within_each_frozen_split_not_external_independence",
        "external_independent_benchmark": {
            "performed": False,
            "reason": "No provider-blinded or real-source external labeled dataset was supplied for v3.98.",
            "existing_synthetic_benchmarks": "reference evidence only; not external real-world independence",
        },
        "frozen_protocol": {
            "version": "v3.98-frozen-holdout-v1",
            "primary_candidate_selected_before_final_test": PRIMARY_CANDIDATE,
            "partitions": ["fit", "calibration", "threshold_selection", "final_test"],
            "split_modes": list(V398_SPLITS),
            "reviewed_labels_only": True,
            "exact_fingerprint_grouping": True,
            "near_pattern_grouping": True,
            "used_feature_fingerprint_grouping": True,
            "final_test_reuse_for_tuning": False,
            "excluded_future_context_features": dataset["feature_meta"]["excluded_features"],
            "batch_rule_context_used_as_model_feature": False,
        },
        "dataset": {
            "rows": len(dataset["rows"]),
            "feature_generation_seconds": dataset["feature_generation_seconds"],
            "feature_count": len(dataset["feature_meta"]["numeric_features"])
            + len(dataset["feature_meta"]["categorical_features"]),
            "label_provenance": dataset["label_provenance"],
            "raw_logs_included_in_reports": False,
        },
        "leakage_group_summary": leakage_group_summary,
        "splits": public_splits,
        "strategy_comparison": comparison,
        "worst_primary_split": _worst_primary_split(split_results),
        "readiness": readiness,
        "review_sample": {
            "generated": False,
            "reason": "v3.98 validates frozen behavior and does not author or auto-approve labels.",
            "import_ready": False,
        },
        "safety": {
            "database_counts_before": before_counts,
            "database_counts_after": after_counts,
            "database_counts_unchanged": counts_unchanged,
            "active_artifact_before": before_artifact,
            "active_artifact_after": after_artifact,
            "active_artifact_unchanged": artifact_unchanged,
            "session_new_objects": len(db.new),
            "session_dirty_objects": len(db.dirty),
            "session_deleted_objects": len(db.deleted),
            "labels_written": False,
            "model_activated": False,
            "model_artifact_written": False,
            "production_promoted": False,
            "response_automation_allowed": False,
            "real_firewall_blocking_enabled": False,
            "raw_logs_written_to_reports": False,
        },
        "runtime_seconds": round(time.perf_counter() - started, 4),
    }

    if write_output:
        output = Path(output_dir)
        output.mkdir(parents=True, exist_ok=True)
        stamp = _stamp()
        validation_path = output / f"v3_98_holdout_validation_{stamp}.md"
        leakage_path = output / f"v3_98_leakage_audit_{stamp}.md"
        latest_path = output / V398_LATEST
        result["reports"] = {
            "holdout_validation": str(validation_path),
            "leakage_audit": str(leakage_path),
            "latest_json": str(latest_path),
        }
        validation_path.write_text(_render_validation_report(result), encoding="utf-8")
        leakage_path.write_text(_render_leakage_report(result), encoding="utf-8")
        latest_path.write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")
    return result
