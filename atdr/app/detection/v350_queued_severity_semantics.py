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
from atdr.app.detection.v341_label_semantics_audit import _evidence_bucket, classify_semantic_issue
from atdr.app.detection.v342_label_policy_reframing import SOC_REVIEW_TARGETS, behavior_aware_soc_target
from atdr.app.detection.v348_repaired_queue_target_model import queue_targets_for_mode


V350_LATEST = "v3_50_queued_severity_semantics_latest.json"
SEVERITY_TARGETS = [
    "unusual_needs_review",
    "evidence_backed_suspicious",
    "malicious_high_confidence",
]


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _pattern(log: Any) -> str:
    return f"app={getattr(log, 'app', None) or '-'}|action={getattr(log, 'action', None) or '-'}|port={getattr(log, 'dst_port', None) or '-'}"


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


def _distribution(values: list[str]) -> dict[str, int]:
    return {key: count for key, count in sorted(Counter(values).items())}


def _label_status(label: MLLabel) -> str:
    source = str(getattr(label, "label_source", None) or "unknown")
    reviewed = bool(getattr(label, "reviewed", False))
    return f"{source}|reviewed={reviewed}"


def _severity_targets(prepared: dict[str, Any], frame: Any) -> list[str]:
    return [behavior_aware_soc_target(label, frame.iloc[index]) for index, label in enumerate(prepared["y"])]


def _analysis_rows(prepared: dict[str, Any], frame: Any) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    severity_targets = _severity_targets(prepared, frame)
    queue_targets, queue_meta = queue_targets_for_mode(prepared, frame, target_mode="repaired_queue_target")
    rows: list[dict[str, Any]] = []
    for index, label in enumerate(prepared["labels"]):
        if queue_targets[index] != "needs_review":
            continue
        log = prepared["logs"][index]
        row = frame.iloc[index]
        semantic = classify_semantic_issue(label.label, row)
        rows.append(
            {
                "index": index,
                "label": label.label,
                "label_status": _label_status(label),
                "label_source": str(getattr(label, "label_source", None) or "unknown"),
                "reviewed": bool(getattr(label, "reviewed", False)),
                "severity_target": severity_targets[index],
                "queue_target": queue_targets[index],
                "pattern": _pattern(log),
                "traffic_family": str(row.get("v337_traffic_family") or "unknown"),
                "evidence_bucket": _evidence_bucket(row),
                "semantic_issue": semantic["issue"],
                "semantic_severity": int(semantic["severity"]),
                "source_name": _source_name(log),
                "timestamp": getattr(log, "generated_time", None) or getattr(log, "receive_time", None),
            }
        )
    return rows, {
        "severity_targets": severity_targets,
        "queue_targets": queue_targets,
        "queue_repair": queue_meta,
    }


def _categorical_ambiguity(rows: list[dict[str, Any]], key: str, *, min_count: int = 4) -> list[dict[str, Any]]:
    grouped: dict[str, Counter[str]] = defaultdict(Counter)
    status_grouped: dict[str, Counter[str]] = defaultdict(Counter)
    for row in rows:
        value = str(row.get(key) or "unknown")
        grouped[value][row["severity_target"]] += 1
        status_grouped[value][row["label_status"]] += 1

    ambiguous = []
    for value, counts in grouped.items():
        total = sum(counts.values())
        if total < min_count or len(counts) < 2:
            continue
        majority, majority_count = counts.most_common(1)[0]
        ambiguous.append(
            {
                "field": key,
                "value": value,
                "total": total,
                "target_counts": dict(counts),
                "label_status_counts": dict(status_grouped[value]),
                "majority": majority,
                "purity": round(majority_count / total, 4),
                "conflict_ratio": round(1 - majority_count / total, 4),
            }
        )
    return sorted(ambiguous, key=lambda item: (item["conflict_ratio"], item["total"]), reverse=True)


def _ambiguous_row_share(groups: list[dict[str, Any]], total_rows: int) -> float:
    if not total_rows:
        return 0.0
    return round(sum(int(row["total"]) for row in groups) / total_rows, 4)


def _feature_value(frame: Any, row: dict[str, Any], feature: str) -> float | None:
    return _safe_number(frame.iloc[row["index"]].get(feature))


def _numeric_separability(frame: Any, rows: list[dict[str, Any]], numeric_features: list[str]) -> list[dict[str, Any]]:
    by_target = {target: {feature: [] for feature in numeric_features} for target in SEVERITY_TARGETS}
    for row in rows:
        target = row["severity_target"]
        if target not in by_target:
            continue
        for feature in numeric_features:
            value = _feature_value(frame, row, feature)
            if value is not None:
                by_target[target][feature].append(value)

    results = []
    for feature in numeric_features:
        class_stats: dict[str, dict[str, Any]] = {}
        for target in SEVERITY_TARGETS:
            values = by_target[target][feature]
            if values:
                class_stats[target] = {
                    "rows": len(values),
                    "mean": round(_mean(values), 4),
                    "std": round(_std(values), 4),
                }
        if len(class_stats) < 2:
            continue

        pairwise = []
        for left_index, left in enumerate(SEVERITY_TARGETS):
            for right in SEVERITY_TARGETS[left_index + 1 :]:
                left_values = by_target[left][feature]
                right_values = by_target[right][feature]
                if len(left_values) < 3 or len(right_values) < 3:
                    continue
                pooled = math.sqrt((_std(left_values) ** 2 + _std(right_values) ** 2) / 2)
                effect = abs(_mean(left_values) - _mean(right_values)) / pooled if pooled else 0.0
                pairwise.append(
                    {
                        "pair": f"{left} vs {right}",
                        "effect_size": round(effect, 4),
                        "absolute_mean_delta": round(abs(_mean(left_values) - _mean(right_values)), 4),
                        "left_rows": len(left_values),
                        "right_rows": len(right_values),
                    }
                )
        if not pairwise:
            continue
        results.append(
            {
                "feature": feature,
                "classes_covered": sorted(class_stats),
                "class_stats": class_stats,
                "minimum_pairwise_effect_size": round(min(item["effect_size"] for item in pairwise), 4),
                "maximum_pairwise_effect_size": round(max(item["effect_size"] for item in pairwise), 4),
                "pairwise": sorted(pairwise, key=lambda item: item["effect_size"]),
            }
        )
    return sorted(
        results,
        key=lambda item: (
            len(item["classes_covered"]),
            item["minimum_pairwise_effect_size"],
            item["maximum_pairwise_effect_size"],
        ),
        reverse=True,
    )


def _label_support(rows: list[dict[str, Any]]) -> dict[str, Any]:
    by_target: dict[str, Counter[str]] = defaultdict(Counter)
    source_by_target: dict[str, Counter[str]] = defaultdict(Counter)
    reviewed_by_target = Counter()
    manual_by_target = Counter()
    for row in rows:
        target = row["severity_target"]
        by_target[target][row["label_status"]] += 1
        source_by_target[target][row["label_source"]] += 1
        if row["reviewed"]:
            reviewed_by_target[target] += 1
        if row["label_source"] == "manual":
            manual_by_target[target] += 1
    return {
        target: {
            "total": sum(by_target[target].values()),
            "reviewed": reviewed_by_target[target],
            "manual": manual_by_target[target],
            "label_status_counts": dict(by_target[target]),
            "label_source_counts": dict(source_by_target[target]),
        }
        for target in SEVERITY_TARGETS
    }


def _evidence_support(rows: list[dict[str, Any]]) -> dict[str, Any]:
    bucket_by_target: dict[str, Counter[str]] = defaultdict(Counter)
    family_by_target: dict[str, Counter[str]] = defaultdict(Counter)
    issue_by_target: dict[str, Counter[str]] = defaultdict(Counter)
    for row in rows:
        target = row["severity_target"]
        bucket_by_target[target][row["evidence_bucket"]] += 1
        family_by_target[target][row["traffic_family"]] += 1
        issue_by_target[target][row["semantic_issue"]] += 1
    return {
        target: {
            "evidence_buckets": bucket_by_target[target].most_common(12),
            "traffic_families": family_by_target[target].most_common(12),
            "semantic_issues": issue_by_target[target].most_common(12),
        }
        for target in SEVERITY_TARGETS
    }


def _split_support(
    base: dict[str, Any],
    *,
    severity_targets: list[str],
    queue_targets: list[str],
    test_size: float,
) -> list[dict[str, Any]]:
    support = []
    for split_mode in V335_SPLITS:
        prepared = _prepared_for_split(base, split_mode=split_mode, test_size=test_size)
        train_targets = [
            severity_targets[index]
            for index in prepared["train_idx"]
            if queue_targets[index] == "needs_review" and severity_targets[index] in SOC_REVIEW_TARGETS
        ]
        test_targets = [
            severity_targets[index]
            for index in prepared["test_idx"]
            if queue_targets[index] == "needs_review" and severity_targets[index] in SOC_REVIEW_TARGETS
        ]
        train_counts = Counter(train_targets)
        test_counts = Counter(test_targets)
        rate_shift: dict[str, float] = {}
        for target in SEVERITY_TARGETS:
            train_rate = train_counts[target] / len(train_targets) if train_targets else 0.0
            test_rate = test_counts[target] / len(test_targets) if test_targets else 0.0
            rate_shift[target] = round(abs(train_rate - test_rate), 4)
        support.append(
            {
                "split_mode": split_mode,
                "training_queue_rows": len(train_targets),
                "test_queue_rows": len(test_targets),
                "train_distribution": _distribution(train_targets),
                "test_distribution": _distribution(test_targets),
                "min_train_support": min((train_counts[target] for target in SEVERITY_TARGETS), default=0),
                "min_test_support": min((test_counts[target] for target in SEVERITY_TARGETS), default=0),
                "max_rate_shift": max(rate_shift.values(), default=0.0),
                "rate_shift_by_target": rate_shift,
                "split_warnings": prepared.get("split_warnings") or [],
            }
        )
    return sorted(support, key=lambda row: (row["max_rate_shift"], -row["min_test_support"]), reverse=True)


def _assessment(
    *,
    rows: list[dict[str, Any]],
    pattern_ambiguity: list[dict[str, Any]],
    family_ambiguity: list[dict[str, Any]],
    evidence_ambiguity: list[dict[str, Any]],
    numeric: list[dict[str, Any]],
    split_support: list[dict[str, Any]],
    label_support: dict[str, Any],
) -> dict[str, Any]:
    total = len(rows)
    queued_non_threat = sum(1 for row in rows if row["severity_target"] == "non_threat")
    queued_non_threat_share = round(queued_non_threat / total, 4) if total else 0.0
    pattern_share = _ambiguous_row_share(pattern_ambiguity, total)
    family_share = _ambiguous_row_share(family_ambiguity, total)
    evidence_share = _ambiguous_row_share(evidence_ambiguity, total)
    strong_feature_count = sum(1 for item in numeric if item["minimum_pairwise_effect_size"] >= 0.5)
    max_split_shift = max((row["max_rate_shift"] for row in split_support), default=0.0)
    min_train_support = min((row["min_train_support"] for row in split_support), default=0)
    min_test_support = min((row["min_test_support"] for row in split_support), default=0)
    min_reviewed_support = min((int(label_support.get(target, {}).get("reviewed") or 0) for target in SEVERITY_TARGETS), default=0)
    checks = [
        {
            "name": "severity classes all present",
            "passed": all(int(label_support.get(target, {}).get("total") or 0) > 0 for target in SEVERITY_TARGETS),
            "value": {target: label_support.get(target, {}).get("total", 0) for target in SEVERITY_TARGETS},
            "target": "all severity targets present",
        },
        {
            "name": "queued non-threat target mismatch acceptable",
            "passed": queued_non_threat_share <= 0.05,
            "value": {"rows": queued_non_threat, "share": queued_non_threat_share},
            "target": "<=5% of repaired-queue rows still map to non_threat severity target",
        },
        {
            "name": "minimum train/test support acceptable",
            "passed": min_train_support >= 30 and min_test_support >= 15,
            "value": {"min_train_support": min_train_support, "min_test_support": min_test_support},
            "target": ">=30 train and >=15 test rows per severity class across splits",
        },
        {
            "name": "reviewed support acceptable",
            "passed": min_reviewed_support >= 20,
            "value": min_reviewed_support,
            "target": ">=20 reviewed rows per severity class",
        },
        {
            "name": "pattern ambiguity acceptable",
            "passed": pattern_share <= 0.45,
            "value": pattern_share,
            "target": "<=0.45 ambiguous pattern row share",
        },
        {
            "name": "traffic-family ambiguity acceptable",
            "passed": family_share <= 0.60,
            "value": family_share,
            "target": "<=0.60 ambiguous traffic-family row share",
        },
        {
            "name": "evidence-bucket ambiguity acceptable",
            "passed": evidence_share <= 0.65,
            "value": evidence_share,
            "target": "<=0.65 ambiguous evidence-bucket row share",
        },
        {
            "name": "feature support acceptable",
            "passed": strong_feature_count >= 3,
            "value": strong_feature_count,
            "target": ">=3 numeric features with minimum pairwise effect size >=0.5",
        },
        {
            "name": "split drift acceptable",
            "passed": max_split_shift <= 0.25,
            "value": max_split_shift,
            "target": "<=0.25 max severity-rate shift",
        },
        {"name": "no labels written", "passed": True, "value": True, "target": "required"},
        {"name": "model activation disabled", "passed": True, "value": False, "target": "required"},
        {"name": "response automation disabled", "passed": True, "value": False, "target": "required"},
    ]
    blockers = [row["name"] for row in checks if not row["passed"]]
    return {
        "decision": "diagnostic_only",
        "passed": sum(1 for row in checks if row["passed"]),
        "total": len(checks),
        "blockers": blockers,
        "checks": checks,
        "recommendation": (
            "Repair queued severity target semantics and evidence features before another downstream severity model pass."
            if blockers
            else "Queued severity support looks strong enough for another diagnostic severity model pass."
        ),
    }


def _render_report(result: dict[str, Any]) -> str:
    assessment = result.get("assessment") or {}
    return f"""# v3.50 Queued Severity Target Semantics And Feature Support Audit

Generated: {result.get("generated_at")}

This report is diagnostic only. It audits why rows admitted by the repaired queue are difficult to classify into unusual, suspicious, and malicious severity levels. No labels were written, no model was activated, no artifact was written, and response automation stayed disabled.

## Summary

- Rows audited: {result.get("queued_rows_audited")}
- Severity distribution: `{result.get("severity_distribution")}`
- Queued rows still mapped to `non_threat`: {result.get("queued_non_threat_count")} ({result.get("queued_non_threat_share")})
- Assessment: {assessment.get("decision")}
- Checks passed: {assessment.get("passed")} / {assessment.get("total")}
- Blockers: {assessment.get("blockers")}
- Recommendation: {assessment.get("recommendation")}

## Label Support

```json
{json.dumps(result.get("label_support"), indent=2, default=str)}
```

## Split Support

```json
{json.dumps(result.get("split_support", [])[:5], indent=2, default=str)}
```

## Top Numeric Separators

```json
{json.dumps(result.get("numeric_separability", [])[:12], indent=2, default=str)}
```

## Ambiguous Patterns

```json
{json.dumps(result.get("ambiguous_patterns", [])[:12], indent=2, default=str)}
```

## Safety

```json
{json.dumps(result.get("safety"), indent=2, default=str)}
```
"""


def run_v350_queued_severity_semantics(
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
    rows, target_meta = _analysis_rows(prepared, frame)
    numeric = _numeric_separability(frame, rows, meta["numeric_features"])
    pattern_ambiguity = _categorical_ambiguity(rows, "pattern", min_count=4)
    family_ambiguity = _categorical_ambiguity(rows, "traffic_family", min_count=4)
    evidence_ambiguity = _categorical_ambiguity(rows, "evidence_bucket", min_count=4)
    source_ambiguity = _categorical_ambiguity(rows, "source_name", min_count=4)
    label_support = _label_support(rows)
    split_support = _split_support(
        base,
        severity_targets=target_meta["severity_targets"],
        queue_targets=target_meta["queue_targets"],
        test_size=test_size,
    )
    assessment = _assessment(
        rows=rows,
        pattern_ambiguity=pattern_ambiguity,
        family_ambiguity=family_ambiguity,
        evidence_ambiguity=evidence_ambiguity,
        numeric=numeric,
        split_support=split_support,
        label_support=label_support,
    )

    after_labels = int(db.scalar(select(func.count(MLLabel.id))) or 0)
    after_runs = int(db.scalar(select(func.count(MLModelRun.id))) or 0)
    after_responses = int(db.scalar(select(func.count(ResponseAction.id))) or 0)
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    stamp = _stamp()
    report_path = output_path / f"v3_50_queued_severity_semantics_{stamp}.md"
    latest_path = output_path / V350_LATEST
    result = {
        "ok": True,
        "status": "completed",
        "phase": "v3.50",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "runtime_seconds": round(time.perf_counter() - started, 4),
        "feature_generation_seconds": base.get("feature_generation_seconds"),
        "queued_rows_audited": len(rows),
        "target_mode": "repaired_queue_downstream_severity_semantics",
        "severity_distribution": _distribution([row["severity_target"] for row in rows]),
        "queued_non_threat_count": sum(1 for row in rows if row["severity_target"] == "non_threat"),
        "queued_non_threat_share": round(
            sum(1 for row in rows if row["severity_target"] == "non_threat") / len(rows), 4
        )
        if rows
        else 0.0,
        "label_support": label_support,
        "evidence_support": _evidence_support(rows),
        "split_support": split_support,
        "numeric_separability": numeric[:30],
        "ambiguous_patterns": pattern_ambiguity[:30],
        "ambiguous_traffic_families": family_ambiguity[:20],
        "ambiguous_evidence_buckets": evidence_ambiguity[:20],
        "ambiguous_sources": source_ambiguity[:20],
        "queue_repair": target_meta["queue_repair"],
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
