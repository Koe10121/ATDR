import json
import math
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from atdr.app.db.models import MLLabel, MLModelRun, ResponseAction
from atdr.app.detection.supervised_detector import training_dataset_diagnostics
from atdr.app.detection.v330_detection_ml_quality import OUTPUT_DIR, _source_name
from atdr.app.detection.v332_guard_validation import _load_base_dataset, _prepared_for_split, _safe_float
from atdr.app.detection.v335_split_stability_repair import V335_SPLITS
from atdr.app.detection.v337_evidence_feature_enrichment import enrich_v337_features
from atdr.app.detection.v341_label_semantics_audit import _evidence_bucket
from atdr.app.detection.v342_label_policy_reframing import behavior_aware_soc_target
from atdr.app.detection.v344_two_stage_soc_queue import REVIEW_TARGETS, _queue_target


V346_LATEST = "v3_46_queue_target_separability_latest.json"
QUEUE_LABELS = ["non_threat", "needs_review"]


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _pattern(log: Any) -> str:
    return f"app={getattr(log, 'app', None) or '-'}|action={getattr(log, 'action', None) or '-'}|port={getattr(log, 'dst_port', None) or '-'}"


def _target_values(prepared: dict[str, Any], frame: Any) -> list[str]:
    return [behavior_aware_soc_target(label, frame.iloc[index]) for index, label in enumerate(prepared["y"])]


def _queue_values(target_values: list[str]) -> list[str]:
    return [_queue_target(target) for target in target_values]


def _safe_number(value: Any) -> float | None:
    try:
        if value is None:
            return None
        number = float(value)
    except (TypeError, ValueError):
        return None
    return None if math.isnan(number) or math.isinf(number) else number


def _mean(values: list[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def _std(values: list[float]) -> float:
    if len(values) < 2:
        return 0.0
    avg = _mean(values)
    return math.sqrt(sum((value - avg) ** 2 for value in values) / (len(values) - 1))


def _label_status(label: MLLabel) -> str:
    source = str(getattr(label, "label_source", "") or "unknown")
    reviewed = bool(getattr(label, "reviewed", False))
    return f"{source}|reviewed={reviewed}"


def _analysis_rows(prepared: dict[str, Any], frame: Any, target_values: list[str], queue_values: list[str]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for index, label in enumerate(prepared["labels"]):
        log = prepared["logs"][index]
        frame_row = frame.iloc[index]
        rows.append(
            {
                "index": index,
                "label": label.label,
                "label_status": _label_status(label),
                "soc_target": target_values[index],
                "queue_target": queue_values[index],
                "pattern": _pattern(log),
                "traffic_family": str(frame_row.get("v337_traffic_family") or "unknown"),
                "evidence_bucket": _evidence_bucket(frame_row),
                "source_name": _source_name(log),
                "timestamp": getattr(log, "generated_time", None) or getattr(log, "receive_time", None),
            }
        )
    return rows


def _distribution(values: list[str]) -> dict[str, int]:
    return {key: count for key, count in sorted(Counter(values).items())}


def _categorical_mix(rows: list[dict[str, Any]], key: str, *, min_count: int = 4) -> list[dict[str, Any]]:
    grouped: dict[str, Counter] = defaultdict(Counter)
    for row in rows:
        grouped[str(row.get(key) or "unknown")][row["queue_target"]] += 1
    mixed = []
    for value, counts in grouped.items():
        total = sum(counts.values())
        if total < min_count or len(counts) < 2:
            continue
        review = int(counts.get("needs_review", 0))
        non_threat = int(counts.get("non_threat", 0))
        majority, majority_count = counts.most_common(1)[0]
        mixed.append(
            {
                "field": key,
                "value": value,
                "total": total,
                "non_threat": non_threat,
                "needs_review": review,
                "majority": majority,
                "purity": round(majority_count / total, 4),
                "conflict_ratio": round(min(review, non_threat) / total, 4),
            }
        )
    return sorted(mixed, key=lambda item: (item["conflict_ratio"], item["total"]), reverse=True)


def _mixed_row_share(mixed_groups: list[dict[str, Any]], total_rows: int) -> float:
    if not total_rows:
        return 0.0
    return round(sum(int(row["total"]) for row in mixed_groups) / total_rows, 4)


def _numeric_separability(frame: Any, rows: list[dict[str, Any]], numeric_features: list[str]) -> list[dict[str, Any]]:
    by_target = {target: {feature: [] for feature in numeric_features} for target in QUEUE_LABELS}
    for row in rows:
        target = row["queue_target"]
        if target not in by_target:
            continue
        frame_row = frame.iloc[row["index"]]
        for feature in numeric_features:
            value = _safe_number(frame_row.get(feature))
            if value is not None:
                by_target[target][feature].append(value)
    results = []
    for feature in numeric_features:
        non_values = by_target["non_threat"][feature]
        review_values = by_target["needs_review"][feature]
        if len(non_values) < 3 or len(review_values) < 3:
            continue
        non_mean = _mean(non_values)
        review_mean = _mean(review_values)
        pooled = math.sqrt((_std(non_values) ** 2 + _std(review_values) ** 2) / 2)
        effect = abs(review_mean - non_mean) / pooled if pooled else 0.0
        results.append(
            {
                "feature": feature,
                "non_threat_mean": round(non_mean, 4),
                "needs_review_mean": round(review_mean, 4),
                "absolute_mean_delta": round(abs(review_mean - non_mean), 4),
                "effect_size": round(effect, 4),
                "non_threat_rows": len(non_values),
                "needs_review_rows": len(review_values),
            }
        )
    return sorted(results, key=lambda item: (item["effect_size"], item["absolute_mean_delta"]), reverse=True)


def _source_concentration(rows: list[dict[str, Any]]) -> dict[str, Any]:
    sources = Counter(str(row["source_name"]) for row in rows)
    review_sources = Counter(str(row["source_name"]) for row in rows if row["queue_target"] == "needs_review")
    non_sources = Counter(str(row["source_name"]) for row in rows if row["queue_target"] == "non_threat")
    return {
        "top_sources": sources.most_common(10),
        "top_needs_review_sources": review_sources.most_common(10),
        "top_non_threat_sources": non_sources.most_common(10),
    }


def _split_drift(base: dict[str, Any], *, target_values: list[str], queue_values: list[str], test_size: float) -> list[dict[str, Any]]:
    drift_rows = []
    for split_mode in V335_SPLITS:
        prepared = _prepared_for_split(base, split_mode=split_mode, test_size=test_size)
        train_queue = [queue_values[index] for index in prepared["train_idx"]]
        test_queue = [queue_values[index] for index in prepared["test_idx"]]
        train_review_rate = train_queue.count("needs_review") / len(train_queue) if train_queue else 0.0
        test_review_rate = test_queue.count("needs_review") / len(test_queue) if test_queue else 0.0
        train_soc = [target_values[index] for index in prepared["train_idx"]]
        test_soc = [target_values[index] for index in prepared["test_idx"]]
        drift_rows.append(
            {
                "split_mode": split_mode,
                "training_rows": len(train_queue),
                "test_rows": len(test_queue),
                "train_needs_review_rate": round(train_review_rate, 4),
                "test_needs_review_rate": round(test_review_rate, 4),
                "absolute_rate_shift": round(abs(test_review_rate - train_review_rate), 4),
                "train_queue_distribution": _distribution(train_queue),
                "test_queue_distribution": _distribution(test_queue),
                "train_soc_distribution": _distribution(train_soc),
                "test_soc_distribution": _distribution(test_soc),
                "split_warnings": prepared.get("split_warnings") or [],
            }
        )
    return sorted(drift_rows, key=lambda item: item["absolute_rate_shift"], reverse=True)


def _label_status_mix(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped = []
    for key in ["label", "label_status", "soc_target", "evidence_bucket", "traffic_family"]:
        grouped.extend(_categorical_mix(rows, key, min_count=3)[:8])
    return grouped[:25]


def _assessment(
    *,
    rows: list[dict[str, Any]],
    pattern_mix: list[dict[str, Any]],
    family_mix: list[dict[str, Any]],
    numeric: list[dict[str, Any]],
    drift: list[dict[str, Any]],
) -> dict[str, Any]:
    total = len(rows)
    ambiguous_pattern_share = _mixed_row_share(pattern_mix, total)
    ambiguous_family_share = _mixed_row_share(family_mix, total)
    max_shift = max((row["absolute_rate_shift"] for row in drift), default=0.0)
    top_effect = numeric[0]["effect_size"] if numeric else 0.0
    checks = [
        {
            "name": "ambiguous pattern share acceptable",
            "passed": ambiguous_pattern_share <= 0.35,
            "value": ambiguous_pattern_share,
            "target": "<= 0.35",
        },
        {
            "name": "traffic family ambiguity acceptable",
            "passed": ambiguous_family_share <= 0.45,
            "value": ambiguous_family_share,
            "target": "<= 0.45",
        },
        {
            "name": "queue target split drift acceptable",
            "passed": max_shift <= 0.2,
            "value": max_shift,
            "target": "<= 0.2 max needs-review-rate shift",
        },
        {
            "name": "at least one strong numeric separator exists",
            "passed": top_effect >= 0.75,
            "value": top_effect,
            "target": ">= 0.75 effect size",
        },
        {"name": "no labels written", "passed": True, "value": True, "target": "required"},
        {"name": "model activation disabled", "passed": True, "value": False, "target": "required"},
        {"name": "response automation disabled", "passed": True, "value": False, "target": "required"},
    ]
    return {
        "decision": "diagnostic_only",
        "passed": sum(1 for row in checks if row["passed"]),
        "total": len(checks),
        "blockers": [row["name"] for row in checks if not row["passed"]],
        "checks": checks,
        "recommendation": (
            "Improve queue target definitions and benchmark/source split coverage before another activation candidate."
            if any(not row["passed"] for row in checks[:4])
            else "Queue target separability looks acceptable enough for another diagnostic model pass."
        ),
    }


def _render_report(result: dict[str, Any]) -> str:
    assessment = result.get("assessment") or {}
    return f"""# v3.46 Queue Target Separability And Training Signal Audit

Generated: {result.get("generated_at")}

This report is diagnostic only. It audits whether the current behavior-aware SOC queue target is separable enough for stable supervised learning. No labels were written, no model was activated, no artifact was written, and response automation stayed disabled.

## Summary

- Rows audited: {result.get("rows_audited")}
- Queue target distribution: `{result.get("queue_target_distribution")}`
- SOC target distribution: `{result.get("soc_target_distribution")}`
- Assessment: {assessment.get("decision")}
- Checks passed: {assessment.get("passed")} / {assessment.get("total")}
- Blockers: {assessment.get("blockers")}
- Recommendation: {assessment.get("recommendation")}

## Top Numeric Separators

```json
{json.dumps(result.get("top_numeric_separators", [])[:10], indent=2, default=str)}
```

## Top Ambiguous Patterns

```json
{json.dumps(result.get("ambiguous_patterns", [])[:10], indent=2, default=str)}
```

## Split Drift

```json
{json.dumps(result.get("split_drift", [])[:5], indent=2, default=str)}
```

## Safety

```json
{json.dumps(result.get("safety"), indent=2, default=str)}
```
"""


def run_v346_queue_target_separability(
    db: Session,
    *,
    test_size: float = 0.3,
    min_samples: int = 6,
    output_dir: str | Path = OUTPUT_DIR,
) -> dict[str, Any]:
    before_labels = int(db.scalar(select(func.count(MLLabel.id))) or 0)
    before_runs = int(db.scalar(select(func.count(MLModelRun.id))) or 0)
    before_responses = int(db.scalar(select(func.count(ResponseAction.id))) or 0)
    started = time.perf_counter()
    base = _load_base_dataset(db, min_samples=min_samples)
    if not base.get("ok"):
        return base
    prepared = _prepared_for_split(base, split_mode="time", test_size=test_size)
    frame, meta = enrich_v337_features(prepared)
    target_values = _target_values(prepared, frame)
    queue_values = _queue_values(target_values)
    rows = _analysis_rows(prepared, frame, target_values, queue_values)
    numeric = _numeric_separability(frame, rows, meta["numeric_features"])
    pattern_mix = _categorical_mix(rows, "pattern", min_count=4)
    family_mix = _categorical_mix(rows, "traffic_family", min_count=4)
    evidence_mix = _categorical_mix(rows, "evidence_bucket", min_count=4)
    source_mix = _categorical_mix(rows, "source_name", min_count=4)
    split_drift = _split_drift(base, target_values=target_values, queue_values=queue_values, test_size=test_size)
    assessment = _assessment(
        rows=rows,
        pattern_mix=pattern_mix,
        family_mix=family_mix,
        numeric=numeric,
        drift=split_drift,
    )
    after_labels = int(db.scalar(select(func.count(MLLabel.id))) or 0)
    after_runs = int(db.scalar(select(func.count(MLModelRun.id))) or 0)
    after_responses = int(db.scalar(select(func.count(ResponseAction.id))) or 0)
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    stamp = _stamp()
    report_path = output_path / f"v3_46_queue_target_separability_{stamp}.md"
    latest_path = output_path / V346_LATEST
    result = {
        "ok": True,
        "status": "completed",
        "phase": "v3.46",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "runtime_seconds": round(time.perf_counter() - started, 4),
        "rows_audited": len(rows),
        "target_mode": "behavior_aware_soc_queue_separability",
        "queue_target_distribution": _distribution(queue_values),
        "soc_target_distribution": _distribution(target_values),
        "top_numeric_separators": numeric[:25],
        "ambiguous_patterns": pattern_mix[:25],
        "ambiguous_traffic_families": family_mix[:25],
        "ambiguous_evidence_buckets": evidence_mix[:25],
        "ambiguous_sources": source_mix[:25],
        "label_status_mix": _label_status_mix(rows),
        "source_concentration": _source_concentration(rows),
        "split_drift": split_drift,
        "assessment": assessment,
        "training_dataset": training_dataset_diagnostics(db),
        "safety": {
            "production_promoted": False,
            "model_activated": False,
            "model_artifact_written": False,
            "response_automation_allowed": False,
            "real_firewall_blocking_enabled": False,
            "labels_written": False,
            "ml_labels_before": before_labels,
            "ml_labels_after": after_labels,
            "ml_model_runs_before": before_runs,
            "ml_model_runs_after": after_runs,
            "response_actions_before": before_responses,
            "response_actions_after": after_responses,
        },
        "report_path": str(report_path),
        "latest_summary_path": str(latest_path),
    }
    report_path.write_text(_render_report(result), encoding="utf-8")
    latest_path.write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")
    return result
