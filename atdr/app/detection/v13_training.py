import csv
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session, joinedload

from atdr.app.benchmarks.adapter import load_prepared_benchmark_snapshot
from atdr.app.benchmarks.readiness import readiness_gate_v3
from atdr.app.db.models import MLLabel, NormalizedLog, RawLog
from atdr.app.detection.boundary_analysis import build_boundary_analysis
from atdr.app.detection.model_comparison import compare_supervised_models
from atdr.app.detection.supervised_detector import _latest_labels, predict_supervised_log
from atdr.app.detection.supervised_recovery import (
    build_current_supervised_dataset_audit,
    build_supervised_label_target_plan,
    write_soc_triage_model_strategy_report,
)
from atdr.app.detection.suspicious_recall_analysis import build_suspicious_recall_error_report
from atdr.app.services.active_learning_service import (
    build_balanced_recovery_review_sample,
    build_large_pool_active_learning_sample,
    build_stage1_threat_recall_review_sample,
)
from atdr.app.services.class_temporal_coverage_service import build_class_temporal_coverage, classify_log_time_window


OUTPUT_DIR = Path("ml_baseline_reviews")
V13_REVIEW_PATH = OUTPUT_DIR / "v1_3_ai_training_review_sample.csv"
V13_LABEL_TARGET_PATH = OUTPUT_DIR / "v1_3_label_target_plan.md"
MINIMUM_TARGETS = {
    "benign": 300,
    "benign_unusual": 300,
    "suspicious": 300,
    "malicious": 150,
    "needs_context": 50,
}
BETTER_TARGETS = {
    "benign": 500,
    "benign_unusual": 500,
    "suspicious": 500,
    "malicious": 250,
    "needs_context": 100,
}
V13_REVIEW_FIELDS = [
    "log_id",
    "timestamp",
    "split_window",
    "source",
    "source_name",
    "src_ip",
    "dst_ip",
    "dst_port",
    "protocol",
    "app",
    "action",
    "bytes",
    "bytes_sent",
    "bytes_received",
    "packets",
    "current_label",
    "reviewed_status",
    "attack_type",
    "rule_evidence",
    "anomaly_score",
    "supervised_prediction",
    "threat_positive_score",
    "hybrid_risk",
    "reason_selected",
    "evidence_summary",
    "human_review_decision",
    "human_review_attack_type",
    "human_review_confidence",
    "human_review_note",
]


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")


def _latest_trainable_labels(db: Session) -> list[MLLabel]:
    return [label for label in _latest_labels(db) if label.log is not None]


def _source_name(log: NormalizedLog) -> str:
    source = getattr(getattr(log, "raw_log", None), "source", None)
    return str(source.name if source else "unknown_source")


def _signature(log: NormalizedLog, *, include_time: bool) -> tuple[Any, ...]:
    values: list[Any] = [
        log.src_ip,
        log.dst_ip,
        log.src_port,
        log.dst_port,
        log.protocol,
        log.app,
        log.action,
        log.bytes,
        log.packets,
    ]
    if include_time:
        values.append(log.generated_time or log.receive_time or log.start_time)
    return tuple(values)


def _duplicate_summary(labels: list[MLLabel]) -> dict[str, Any]:
    exact = Counter(_signature(label.log, include_time=True) for label in labels)
    near = Counter(_signature(label.log, include_time=False) for label in labels)
    return {
        "exact_duplicate_rows": sum(count - 1 for count in exact.values() if count > 1),
        "exact_duplicate_groups": sum(1 for count in exact.values() if count > 1),
        "near_duplicate_rows": sum(count - 1 for count in near.values() if count > 1),
        "near_duplicate_groups": sum(1 for count in near.values() if count > 1),
        "largest_near_duplicate_group": max(near.values(), default=0),
    }


def _label_overlap(labels: list[MLLabel], class_names: set[str]) -> list[dict[str, Any]]:
    patterns: dict[tuple[Any, ...], set[str]] = defaultdict(set)
    counts: Counter[tuple[Any, ...]] = Counter()
    for label in labels:
        if label.label not in class_names:
            continue
        key = (
            label.log.app or "missing",
            label.log.action or "missing",
            label.log.dst_port if label.log.dst_port is not None else "missing",
            label.log.protocol or "missing",
        )
        patterns[key].add(label.label)
        counts[key] += 1
    return [
        {
            "app": key[0],
            "action": key[1],
            "dst_port": key[2],
            "protocol": key[3],
            "labels": sorted(values),
            "rows": counts[key],
        }
        for key, values in patterns.items()
        if len(values) > 1
    ][:20]


def render_training_data_audit(report: dict[str, Any]) -> str:
    quality = report["training_readiness"]
    return f"""# v1.3 Training Data Quality Audit

Generated: {report['generated_at']}

This audit describes supervised training evidence only. It excludes private raw payloads and does not claim production accuracy.

## Counts

- Total labeled rows: {report['total_supervised_rows']}
- Reviewed labels: {report['reviewed_label_count']}
- Weak labels: {report['weak_label_count']}
- Training rows: {report['training_rows']}
- Test rows: {report['test_rows']}
- Split: {report['split']}

## Distributions

- Labels: {report['label_distribution']}
- Reviewed labels: {report['reviewed_label_distribution']}
- Weak labels: {report['weak_label_distribution']}
- Attack types: {report['attack_type_distribution']}
- Label sources: {report['label_source_distribution']}

## Coverage and Quality

- Time coverage: {report['time_coverage']}
- Source distribution: {report['source_breakdown']}
- Duplicate summary: {report['duplicate_summary']}
- Missing feature rates: {report['missing_feature_rates']}
- Suspicious/malicious overlap patterns: {len(report['suspicious_malicious_overlap'])}
- Benign-family overlap patterns: {len(report['benign_family_overlap'])}

## Training Readiness

- Enough for strong supervised validation: {quality['enough_for_strong_supervised_validation']}
- Minimum reviewed target classes met: {quality['minimum_target_classes_met']} / {quality['minimum_target_class_count']}
- Assessment: {quality['assessment']}

## Warnings

{chr(10).join(f"- {item}" for item in report['warnings'])}

## Safety

- Production promoted: false
- Response automation allowed: false
"""


def audit_training_data_quality(
    db: Session,
    *,
    output_path: str | Path | None = None,
    split: str = "time",
    test_size: float = 0.3,
) -> dict[str, Any]:
    output = Path(output_path) if output_path else OUTPUT_DIR / f"training_data_quality_audit_{_stamp()}.md"
    base = build_current_supervised_dataset_audit(db, output_path=output, split=split, test_size=test_size)
    if not base.get("ok"):
        return base
    labels = _latest_trainable_labels(db)
    reviewed = Counter(label.label for label in labels if label.reviewed)
    weak = Counter(label.label for label in labels if not label.reviewed)
    timestamps = [
        label.log.generated_time or label.log.receive_time or label.log.start_time
        for label in labels
        if label.log is not None
    ]
    valid_timestamps = [value for value in timestamps if value is not None]
    missing_counts = base.get("missing_feature_summary") or {}
    total = max(1, len(labels))
    minimum_met = sum(int(reviewed.get(label) or 0) >= target for label, target in MINIMUM_TARGETS.items())
    report = {
        **base,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "report_path": str(output),
        "reviewed_label_distribution": dict(sorted(reviewed.items())),
        "weak_label_distribution": dict(sorted(weak.items())),
        "attack_type_distribution": dict(sorted(Counter(label.attack_type or "unknown" for label in labels).items())),
        "time_coverage": {
            "earliest": min(valid_timestamps).isoformat() if valid_timestamps else None,
            "latest": max(valid_timestamps).isoformat() if valid_timestamps else None,
            "missing_timestamp_rows": len(timestamps) - len(valid_timestamps),
        },
        "duplicate_summary": _duplicate_summary(labels),
        "missing_feature_rates": {
            key: round(int(value) / total, 4)
            for key, value in sorted(missing_counts.items())
        },
        "suspicious_malicious_overlap": _label_overlap(labels, {"suspicious", "malicious"}),
        "benign_family_overlap": _label_overlap(labels, {"benign", "benign_unusual", "needs_context"}),
        "training_readiness": {
            "minimum_target_classes_met": minimum_met,
            "minimum_target_class_count": len(MINIMUM_TARGETS),
            "enough_for_strong_supervised_validation": minimum_met == len(MINIMUM_TARGETS),
            "assessment": (
                "Reviewed class targets are met; candidate evaluation is meaningful but still lab-only."
                if minimum_met == len(MINIMUM_TARGETS)
                else "More reviewed labels and temporal class coverage are required before strong supervised claims."
            ),
        },
        "production_promoted": False,
        "response_automation_allowed": False,
    }
    report["warnings"] = list(
        dict.fromkeys(
            [
                *base.get("warnings", []),
                "Duplicate and near-duplicate rows can inflate random-split metrics.",
                "Time-split and reviewed-only metrics remain the primary validation evidence.",
            ]
        )
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(render_training_data_audit(report), encoding="utf-8")
    _write_json(output.with_suffix(".json"), report)
    return report


def render_label_target_plan(plan: dict[str, Any]) -> str:
    rows = "\n".join(
        "| {label} | {current} | {minimum} | {minimum_gap} | {better} | {better_gap} | {reviewed_train} | {reviewed_test} |".format(
            **row
        )
        for row in plan["class_rows"]
    )
    return f"""# v1.3 Label Target Plan

Generated: {plan['generated_at']}

| Class | Reviewed | Minimum | Minimum Gap | Better | Better Gap | Reviewed Train | Reviewed Test |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
{rows}

## Recommended Next Review Focus

{chr(10).join(f"- {item}" for item in plan['recommendations'])}

## Safety

- These are review targets, not production certification thresholds.
- Production promoted: false
- Response automation allowed: false
"""


def write_v13_label_target_plan(
    db: Session,
    *,
    output_path: str | Path = V13_LABEL_TARGET_PATH,
    split: str = "time",
    test_size: float = 0.3,
) -> dict[str, Any]:
    base = build_supervised_label_target_plan(
        db,
        split=split,
        test_size=test_size,
        targets=MINIMUM_TARGETS,
    )
    rows = []
    for row in base.get("class_rows", []):
        label = row["label"]
        current = int(row["reviewed"])
        rows.append(
            {
                "label": label,
                "current": current,
                "minimum": MINIMUM_TARGETS[label],
                "minimum_gap": max(0, MINIMUM_TARGETS[label] - current),
                "better": BETTER_TARGETS[label],
                "better_gap": max(0, BETTER_TARGETS[label] - current),
                "train": int(row["train"]),
                "test": int(row["test"]),
                "reviewed_train": int(row["reviewed_train"]),
                "reviewed_test": int(row["reviewed_test"]),
            }
        )
    ranked = sorted(rows, key=lambda item: (item["minimum_gap"], item["better_gap"]), reverse=True)
    recommendations = [
        f"Prioritize {row['label']}: minimum gap {row['minimum_gap']}, better-target gap {row['better_gap']}."
        for row in ranked
        if row["minimum_gap"] > 0
    ]
    if not recommendations:
        recommendations.append("Minimum reviewed-label targets are met; focus on temporal gaps and model error boundaries.")
    for row in rows:
        if row["reviewed_train"] == 0 or row["reviewed_test"] == 0:
            recommendations.append(
                f"{row['label']} lacks reviewed coverage in one time window (train={row['reviewed_train']}, test={row['reviewed_test']})."
            )
    plan = {
        "ok": True,
        "status": "exported",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "split": split,
        "reviewed_total": base.get("reviewed_total", 0),
        "weak_total": base.get("weak_total", 0),
        "class_rows": rows,
        "recommendations": recommendations,
        "report_path": str(output_path),
        "production_promoted": False,
        "response_automation_allowed": False,
    }
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_label_target_plan(plan), encoding="utf-8")
    _write_json(path.with_suffix(".json"), plan)
    return plan


def _candidate_rows(db: Session, *, limit: int, focus: str) -> list[dict[str, Any]]:
    pool_limit = max(limit, min(limit * 2, 1000))
    rows: list[dict[str, Any]] = []
    if focus in {"balanced", "benchmark", "boundary", "threat_positive"}:
        rows.extend(build_large_pool_active_learning_sample(db, limit=pool_limit, candidate_pool_limit=max(1000, pool_limit * 4)))
    if focus in {"balanced", "benign_gap", "boundary"}:
        rows.extend(build_balanced_recovery_review_sample(db, limit=pool_limit))
    if focus in {"threat_positive", "boundary"}:
        rows.extend(build_stage1_threat_recall_review_sample(db, limit=pool_limit))
    by_log: dict[int, dict[str, Any]] = {}
    for row in rows:
        log_id = int(row.get("log_id") or 0)
        if log_id:
            existing = by_log.get(log_id)
            if existing is None or int(row.get("selection_score") or 0) > int(existing.get("selection_score") or 0):
                by_log[log_id] = row
    return list(by_log.values())


def export_v13_ai_training_review_sample(
    db: Session,
    *,
    limit: int = 500,
    focus: str = "balanced",
    output_path: str | Path = V13_REVIEW_PATH,
) -> dict[str, Any]:
    allowed_focus = {"balanced", "threat_positive", "benign_gap", "boundary", "benchmark"}
    if focus not in allowed_focus:
        raise ValueError(f"Unsupported focus {focus!r}; choose from {sorted(allowed_focus)}.")
    candidates = _candidate_rows(db, limit=limit, focus=focus)
    ids = [int(row["log_id"]) for row in candidates]
    logs = list(
        db.scalars(
            select(NormalizedLog)
            .options(joinedload(NormalizedLog.raw_log).joinedload(RawLog.source))
            .where(NormalizedLog.id.in_(ids))
        )
    ) if ids else []
    logs_by_id = {log.id: log for log in logs}
    labels_by_id = {label.log_id: label for label in _latest_trainable_labels(db)}
    temporal = build_class_temporal_coverage(db)
    prepared: list[dict[str, Any]] = []
    for candidate in candidates:
        log = logs_by_id.get(int(candidate["log_id"]))
        if log is None:
            continue
        label = labels_by_id.get(log.id)
        try:
            prediction = predict_supervised_log(db, log.id)
        except Exception:
            prediction = {}
        probabilities = prediction.get("class_probabilities") or {}
        threat_score = float(probabilities.get("suspicious") or 0) + float(probabilities.get("malicious") or 0)
        current_label = str(candidate.get("current_label") or (label.label if label else ""))
        predicted = str(candidate.get("model_prediction") or prediction.get("predicted_label") or "")
        priority = int(candidate.get("selection_score") or candidate.get("hybrid_risk") or 0)
        if focus == "threat_positive" and predicted in {"suspicious", "malicious"}:
            priority += 50
        if focus == "benign_gap" and current_label in {"", "benign", "benign_unusual"}:
            priority += 50
        if focus == "boundary" and current_label and predicted and current_label != predicted:
            priority += 60
        prepared.append(
            {
                "_priority": priority,
                "log_id": log.id,
                "timestamp": log.generated_time or log.receive_time or log.start_time,
                "split_window": classify_log_time_window(log, temporal),
                "source": _source_name(log),
                "source_name": _source_name(log),
                "src_ip": log.src_ip or "",
                "dst_ip": log.dst_ip or "",
                "dst_port": log.dst_port or "",
                "protocol": log.protocol or "",
                "app": log.app or "",
                "action": log.action or "",
                "bytes": log.bytes or "",
                "bytes_sent": log.bytes_sent or "",
                "bytes_received": log.bytes_received or "",
                "packets": log.packets or "",
                "current_label": current_label,
                "reviewed_status": bool(label.reviewed) if label else False,
                "attack_type": label.attack_type if label else "unknown_anomaly",
                "rule_evidence": candidate.get("rule_evidence") or "",
                "anomaly_score": candidate.get("anomaly_score") if candidate.get("anomaly_score") != "" else log.anomaly_score or "",
                "supervised_prediction": predicted,
                "threat_positive_score": round(threat_score, 4),
                "hybrid_risk": candidate.get("hybrid_risk") or 0,
                "reason_selected": candidate.get("reason_selected") or "",
                "evidence_summary": candidate.get("evidence_summary") or "",
                "human_review_decision": "",
                "human_review_attack_type": label.attack_type if label else "unknown_anomaly",
                "human_review_confidence": label.confidence if label else 3,
                "human_review_note": "",
            }
        )
    prepared.sort(key=lambda row: (int(row["_priority"]), float(row["threat_positive_score"]), int(row["log_id"])), reverse=True)
    selected: list[dict[str, Any]] = []
    source_counts: Counter[str] = Counter()
    app_counts: Counter[str] = Counter()
    max_per_dimension = max(5, limit // 8)
    for row in prepared:
        if source_counts[row["source"]] >= max_per_dimension and app_counts[str(row["app"])] >= max_per_dimension:
            continue
        selected.append(row)
        source_counts[row["source"]] += 1
        app_counts[str(row["app"])] += 1
        if len(selected) >= limit:
            break
    if len(selected) < limit:
        selected_ids = {row["log_id"] for row in selected}
        selected.extend(row for row in prepared if row["log_id"] not in selected_ids)
    selected = selected[:limit]
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=V13_REVIEW_FIELDS)
        writer.writeheader()
        for row in selected:
            serialized = {field: row.get(field, "") for field in V13_REVIEW_FIELDS}
            if hasattr(serialized["timestamp"], "isoformat"):
                serialized["timestamp"] = serialized["timestamp"].isoformat()
            writer.writerow(serialized)
    return {
        "ok": True,
        "status": "exported",
        "path": str(path),
        "rows": len(selected),
        "focus": focus,
        "current_label_distribution": dict(Counter(str(row["current_label"] or "unlabeled") for row in selected)),
        "prediction_distribution": dict(Counter(str(row["supervised_prediction"] or "unavailable") for row in selected)),
        "split_distribution": dict(Counter(str(row["split_window"] or "unknown") for row in selected)),
        "source_count": len({row["source"] for row in selected}),
        "production_promoted": False,
        "response_automation_allowed": False,
    }


def _best_flat_model(comparison: dict[str, Any]) -> dict[str, Any] | None:
    evaluated = [
        item
        for item in comparison.get("models", [])
        if item.get("name") != "hybrid_score_baseline" and item.get("metrics")
    ]
    return max(
        evaluated,
        key=lambda item: (
            float(((item.get("metrics") or {}).get("threat_positive") or {}).get("f1") or 0),
            float(((item.get("metrics") or {}).get("macro_average") or {}).get("f1") or 0),
        ),
        default=None,
    )


def _benchmark_count(snapshot_path: str | Path | None) -> int:
    if not snapshot_path:
        return 0
    try:
        records, _summary = load_prepared_benchmark_snapshot(Path(snapshot_path))
        return len(records)
    except (OSError, ValueError, json.JSONDecodeError):
        return 0


def render_candidate_report(report: dict[str, Any]) -> str:
    rows = "\n".join(
        "| {name} | {weighted} | {macro} | {threat} | {suspicious} | {malicious} | {fpr} |".format(
            name=item.get("name"),
            weighted=(item.get("metrics") or {}).get("f1"),
            macro=((item.get("metrics") or {}).get("macro_average") or {}).get("f1"),
            threat=((item.get("metrics") or {}).get("threat_positive") or {}).get("f1"),
            suspicious=(((item.get("metrics") or {}).get("per_class") or {}).get("suspicious") or {}).get("recall"),
            malicious=(((item.get("metrics") or {}).get("per_class") or {}).get("malicious") or {}).get("recall"),
            fpr=(item.get("metrics") or {}).get("false_positive_rate"),
        )
        for item in report["flat_candidates"]
        if item.get("metrics")
    )
    gate = report["readiness_gate_v3"]
    return f"""# v1.3 Supervised Candidate Report

Generated: {report['generated_at']}

No model artifact was written, activated, or promoted.

| Candidate | Weighted F1 | Macro F1 | Threat+ F1 | Suspicious Recall | Malicious Recall | Benign-like FPR |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
{rows}

## SOC Triage Strategies

```json
{json.dumps(report['soc_triage_strategies'], indent=2, default=str)}
```

## Readiness Gate v3

- Decision: {gate['decision']}
- Checks passed: {gate['passed']} / {gate['total']}
- Production status: {gate['production_status']}
- Response automation allowed: false

## Limitations

- Time split is the primary validation evidence.
- Reviewed-label and benchmark coverage remain explicit gate inputs.
- This report does not activate a model.
"""


def train_v13_supervised_candidates(
    db: Session,
    *,
    output_path: str | Path | None = None,
    split: str = "time",
    test_size: float = 0.3,
    min_samples: int = 6,
    benchmark_snapshot: str | Path | None = None,
) -> dict[str, Any]:
    path = Path(output_path) if output_path else OUTPUT_DIR / f"v1_3_supervised_candidate_report_{_stamp()}.md"
    flat_path = path.with_name(f"{path.stem}_flat_comparison.md")
    strategy_path = path.with_name(f"{path.stem}_soc_strategy.md")
    comparison = compare_supervised_models(
        db,
        output_path=flat_path,
        test_size=test_size,
        min_samples=min_samples,
        split=split,
        threshold_profile="balanced",
    )
    strategy = write_soc_triage_model_strategy_report(
        db,
        output_path=strategy_path,
        split=split,
        test_size=test_size,
        min_samples=min_samples,
    )
    best = _best_flat_model(comparison)
    metrics = (best or {}).get("metrics") or {}
    temporal = build_class_temporal_coverage(db, test_size=test_size)
    reviewed_distribution = comparison.get("reviewed_label_distribution") or {}
    reviewed_count = sum(int(value) for value in reviewed_distribution.values())
    gate = readiness_gate_v3(
        reviewed_label_count=reviewed_count,
        reviewed_label_distribution=reviewed_distribution,
        temporal_class_coverage=temporal,
        metrics=metrics,
        benchmark_label_count=_benchmark_count(benchmark_snapshot),
        calibration_buckets=[],
        drift_warnings=[],
        response_automation_allowed=False,
    )
    report = {
        "ok": True,
        "status": "completed",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "split": split,
        "test_size": test_size,
        "training_rows": comparison.get("training_rows"),
        "test_rows": comparison.get("test_rows"),
        "reviewed_label_count": reviewed_count,
        "reviewed_label_distribution": reviewed_distribution,
        "weak_label_distribution": comparison.get("weak_label_distribution") or {},
        "flat_candidates": comparison.get("models") or [],
        "best_flat_candidate": best,
        "soc_triage_strategies": strategy.get("strategies") or {},
        "benchmark_snapshot": str(benchmark_snapshot) if benchmark_snapshot else None,
        "benchmark_label_count": _benchmark_count(benchmark_snapshot),
        "readiness_gate_v3": gate,
        "report_path": str(path),
        "safety": {
            "model_artifact_written": False,
            "model_activated": False,
            "production_promoted": False,
            "automatic_response_enabled": False,
            "real_firewall_blocking_enabled": False,
        },
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_candidate_report(report), encoding="utf-8")
    _write_json(path.with_suffix(".json"), report)
    return report


def _confusion_summary(metrics: dict[str, Any]) -> dict[str, int]:
    labels = metrics.get("labels") or []
    matrix = metrics.get("confusion_matrix") or []
    counts: Counter[str] = Counter()
    for row_index, actual in enumerate(labels):
        for column_index, predicted in enumerate(labels):
            if actual == predicted:
                continue
            value = int(matrix[row_index][column_index]) if row_index < len(matrix) and column_index < len(matrix[row_index]) else 0
            counts[f"{actual}_predicted_{predicted}"] += value
    return dict(counts)


def analyze_v13_ml_errors(
    db: Session,
    *,
    output_path: str | Path | None = None,
    split: str = "time",
    test_size: float = 0.3,
    min_samples: int = 6,
) -> dict[str, Any]:
    path = Path(output_path) if output_path else OUTPUT_DIR / f"v1_3_ml_error_analysis_{_stamp()}.md"
    recall = build_suspicious_recall_error_report(db, split=split, test_size=test_size, min_samples=min_samples)
    boundary = build_boundary_analysis(db, split=split, test_size=test_size, min_samples=min_samples)
    balanced = next(
        (item for item in recall.get("threshold_profiles", []) if item.get("profile") == "balanced"),
        {},
    )
    metrics = balanced.get("metrics") or {}
    confusion = _confusion_summary(metrics)
    threat_false_negatives = sum(
        count
        for key, count in confusion.items()
        if key.startswith(("suspicious_predicted_", "malicious_predicted_"))
        and not key.endswith(("suspicious", "malicious"))
    )
    benign_false_positives = sum(
        count
        for key, count in confusion.items()
        if key.startswith(("benign_predicted_", "benign_unusual_predicted_", "needs_context_predicted_"))
        and key.endswith(("suspicious", "malicious"))
    )
    recommendations = []
    if threat_false_negatives:
        recommendations.append("Focus the next review sample on threat-positive rows predicted benign-like.")
    if confusion.get("malicious_predicted_suspicious", 0):
        recommendations.append("Review malicious/suspicious boundary rows with shared app/action/port patterns.")
    if benign_false_positives:
        recommendations.append("Add reviewed benign and benign_unusual false-positive examples.")
    if confusion.get("needs_context_predicted_suspicious", 0) or confusion.get("needs_context_predicted_malicious", 0):
        recommendations.append("Preserve needs_context for ambiguous evidence instead of forcing a threat label.")
    if not recommendations:
        recommendations.append("Maintain balanced review and expand source/time diversity.")
    report = {
        "ok": True,
        "status": "completed",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "split": split,
        "confusion_counts": confusion,
        "false_negatives": threat_false_negatives,
        "false_positives": benign_false_positives,
        "suspicious_predicted_benign_like": sum(
            confusion.get(f"suspicious_predicted_{label}", 0)
            for label in ("benign", "benign_unusual", "needs_context")
        ),
        "malicious_predicted_suspicious": confusion.get("malicious_predicted_suspicious", 0),
        "benign_predicted_threat_like": sum(
            confusion.get(f"{actual}_predicted_{predicted}", 0)
            for actual in ("benign", "benign_unusual")
            for predicted in ("suspicious", "malicious")
        ),
        "needs_context_confusion": sum(
            value for key, value in confusion.items() if key.startswith("needs_context_predicted_")
        ),
        "weak_vs_reviewed_error_breakdown": recall.get("suspicious_error_source_distribution") or {},
        "common_patterns": recall.get("common_error_patterns") or {},
        "boundary_summary": boundary.get("flat_model") or boundary.get("hierarchical_candidate") or {},
        "recommended_next_label_focus": recommendations,
        "report_path": str(path),
        "production_promoted": False,
        "response_automation_allowed": False,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "\n".join(
            [
                "# v1.3 ML Error Analysis",
                "",
                f"Generated: {report['generated_at']}",
                "",
                f"- False negatives: {report['false_negatives']}",
                f"- False positives: {report['false_positives']}",
                f"- Suspicious predicted benign-like: {report['suspicious_predicted_benign_like']}",
                f"- Malicious predicted suspicious: {report['malicious_predicted_suspicious']}",
                f"- Benign predicted threat-like: {report['benign_predicted_threat_like']}",
                f"- Needs-context confusion: {report['needs_context_confusion']}",
                "",
                "## Confusion Counts",
                "",
                f"```json\n{json.dumps(confusion, indent=2)}\n```",
                "",
                "## Recommended Next Label Focus",
                "",
                *[f"- {item}" for item in recommendations],
                "",
                "## Safety",
                "",
                "- Decision support only.",
                "- Production promoted: false",
                "- Response automation allowed: false",
            ]
        ),
        encoding="utf-8",
    )
    _write_json(path.with_suffix(".json"), report)
    return report
