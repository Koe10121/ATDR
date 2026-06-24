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
from atdr.app.detection.v342_label_policy_reframing import behavior_aware_soc_target
from atdr.app.detection.v348_repaired_queue_target_model import queue_targets_for_mode


V351_LATEST = "v3_51_queue_severity_interface_latest.json"
BASE_SEVERITY_TARGETS = [
    "unusual_needs_review",
    "evidence_backed_suspicious",
    "malicious_high_confidence",
]
LOW_CONFIDENCE_TARGET = "queue_low_confidence_review"
VARIANT_NAMES = [
    "baseline_current_interface",
    "low_confidence_review_class",
    "map_non_threat_to_unusual",
    "demote_non_threat_from_queue",
    "evidence_promote_or_demote",
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


def _base_rows(prepared: dict[str, Any], frame: Any) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    severity_targets = [behavior_aware_soc_target(label, frame.iloc[index]) for index, label in enumerate(prepared["y"])]
    queue_targets, queue_meta = queue_targets_for_mode(prepared, frame, target_mode="repaired_queue_target")
    rows: list[dict[str, Any]] = []
    for index, label in enumerate(prepared["labels"]):
        if queue_targets[index] != "needs_review":
            continue
        log = prepared["logs"][index]
        frame_row = frame.iloc[index]
        semantic = classify_semantic_issue(label.label, frame_row)
        evidence = _evidence_bucket(frame_row)
        rows.append(
            {
                "index": index,
                "label": label.label,
                "label_status": _label_status(label),
                "label_source": str(getattr(label, "label_source", None) or "unknown"),
                "reviewed": bool(getattr(label, "reviewed", False)),
                "base_severity_target": severity_targets[index],
                "severity_target": severity_targets[index],
                "queue_target": queue_targets[index],
                "pattern": _pattern(log),
                "traffic_family": str(frame_row.get("v337_traffic_family") or "unknown"),
                "evidence_bucket": evidence,
                "evidence_strength": _safe_float(frame_row.get("v337_behavior_evidence_strength")),
                "rule_backed": bool(frame_row.get("v337_rule_backed_allow_flag")),
                "anomaly_signal": bool(frame_row.get("v337_anomaly_signal_flag")),
                "scan_context": evidence in {"web_scan_context", "incomplete_scan_context", "unknown_scan_context"},
                "semantic_issue": semantic["issue"],
                "semantic_severity": int(semantic["severity"]),
                "source_name": _source_name(log),
            }
        )
    return rows, {
        "severity_targets": severity_targets,
        "queue_targets": queue_targets,
        "queue_repair": queue_meta,
    }


def _has_review_worthy_evidence(row: dict[str, Any]) -> bool:
    return (
        row["rule_backed"]
        or row["anomaly_signal"]
        or row["scan_context"]
        or _safe_float(row.get("evidence_strength")) >= 3.0
        or row["evidence_bucket"] in {"rule_backed", "anomaly_backed", "incomplete_scan_context", "unknown_scan_context"}
    )


def repair_interface_target(base_target: str, row: dict[str, Any], *, variant: str) -> str | None:
    if variant == "baseline_current_interface":
        return base_target
    if base_target != "non_threat":
        return base_target
    if variant == "low_confidence_review_class":
        return LOW_CONFIDENCE_TARGET
    if variant == "map_non_threat_to_unusual":
        return "unusual_needs_review"
    if variant == "demote_non_threat_from_queue":
        return None
    if variant == "evidence_promote_or_demote":
        return "unusual_needs_review" if _has_review_worthy_evidence(row) else None
    raise ValueError(f"Unknown v3.51 interface variant: {variant}")  # pragma: no cover


def _variant_rows(base_rows: list[dict[str, Any]], *, variant: str) -> list[dict[str, Any]]:
    rows = []
    for row in base_rows:
        repaired = repair_interface_target(row["base_severity_target"], row, variant=variant)
        if repaired is None:
            continue
        rows.append({**row, "severity_target": repaired})
    return rows


def _categorical_ambiguity(rows: list[dict[str, Any]], key: str, *, min_count: int = 4) -> list[dict[str, Any]]:
    grouped: dict[str, Counter[str]] = defaultdict(Counter)
    for row in rows:
        grouped[str(row.get(key) or "unknown")][row["severity_target"]] += 1
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


def _numeric_separability(
    frame: Any,
    rows: list[dict[str, Any]],
    numeric_features: list[str],
    targets: list[str],
) -> list[dict[str, Any]]:
    by_target = {target: {feature: [] for feature in numeric_features} for target in targets}
    for row in rows:
        target = row["severity_target"]
        if target not in by_target:
            continue
        frame_row = frame.iloc[row["index"]]
        for feature in numeric_features:
            value = _safe_number(frame_row.get(feature))
            if value is not None:
                by_target[target][feature].append(value)
    results = []
    for feature in numeric_features:
        class_stats = {
            target: {"rows": len(values), "mean": round(_mean(values), 4), "std": round(_std(values), 4)}
            for target in targets
            if (values := by_target[target][feature])
        }
        if len(class_stats) < 2:
            continue
        pairwise = []
        covered = [target for target in targets if target in class_stats]
        for left_index, left in enumerate(covered):
            for right in covered[left_index + 1 :]:
                left_values = by_target[left][feature]
                right_values = by_target[right][feature]
                if len(left_values) < 3 or len(right_values) < 3:
                    continue
                pooled = math.sqrt((_std(left_values) ** 2 + _std(right_values) ** 2) / 2)
                effect = abs(_mean(left_values) - _mean(right_values)) / pooled if pooled else 0.0
                pairwise.append({"pair": f"{left} vs {right}", "effect_size": round(effect, 4)})
        if pairwise:
            results.append(
                {
                    "feature": feature,
                    "classes_covered": covered,
                    "class_stats": class_stats,
                    "minimum_pairwise_effect_size": round(min(item["effect_size"] for item in pairwise), 4),
                    "maximum_pairwise_effect_size": round(max(item["effect_size"] for item in pairwise), 4),
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


def _split_support(
    base: dict[str, Any],
    *,
    target_by_index: dict[int, str],
    test_size: float,
    targets: list[str],
) -> list[dict[str, Any]]:
    rows = []
    for split_mode in V335_SPLITS:
        prepared = _prepared_for_split(base, split_mode=split_mode, test_size=test_size)
        train_targets = [target_by_index[index] for index in prepared["train_idx"] if index in target_by_index]
        test_targets = [target_by_index[index] for index in prepared["test_idx"] if index in target_by_index]
        train_counts = Counter(train_targets)
        test_counts = Counter(test_targets)
        rate_shift = {}
        for target in targets:
            train_rate = train_counts[target] / len(train_targets) if train_targets else 0.0
            test_rate = test_counts[target] / len(test_targets) if test_targets else 0.0
            rate_shift[target] = round(abs(train_rate - test_rate), 4)
        rows.append(
            {
                "split_mode": split_mode,
                "training_queue_rows": len(train_targets),
                "test_queue_rows": len(test_targets),
                "train_distribution": _distribution(train_targets),
                "test_distribution": _distribution(test_targets),
                "min_train_support": min((train_counts[target] for target in targets), default=0),
                "min_test_support": min((test_counts[target] for target in targets), default=0),
                "max_rate_shift": max(rate_shift.values(), default=0.0),
                "rate_shift_by_target": rate_shift,
                "split_warnings": prepared.get("split_warnings") or [],
            }
        )
    return sorted(rows, key=lambda row: (row["max_rate_shift"], -row["min_test_support"]), reverse=True)


def _label_support(rows: list[dict[str, Any]], targets: list[str]) -> dict[str, Any]:
    grouped: dict[str, Counter[str]] = defaultdict(Counter)
    reviewed = Counter()
    manual = Counter()
    for row in rows:
        target = row["severity_target"]
        grouped[target][row["label_status"]] += 1
        reviewed[target] += int(row["reviewed"])
        manual[target] += int(row["label_source"] == "manual")
    return {
        target: {
            "total": sum(grouped[target].values()),
            "reviewed": reviewed[target],
            "manual": manual[target],
            "label_status_counts": dict(grouped[target]),
        }
        for target in targets
    }


def _variant_summary(
    base: dict[str, Any],
    frame: Any,
    base_rows: list[dict[str, Any]],
    *,
    variant: str,
    numeric_features: list[str],
    test_size: float,
) -> dict[str, Any]:
    rows = _variant_rows(base_rows, variant=variant)
    targets = list(BASE_SEVERITY_TARGETS)
    if any(row["severity_target"] == LOW_CONFIDENCE_TARGET for row in rows):
        targets = [LOW_CONFIDENCE_TARGET, *targets]
    target_by_index = {row["index"]: row["severity_target"] for row in rows}
    dropped = len(base_rows) - len(rows)
    non_threat_mismatch = sum(1 for row in rows if row["severity_target"] == "non_threat")
    pattern_mix = _categorical_ambiguity(rows, "pattern", min_count=4)
    family_mix = _categorical_ambiguity(rows, "traffic_family", min_count=4)
    evidence_mix = _categorical_ambiguity(rows, "evidence_bucket", min_count=4)
    split_support = _split_support(base, target_by_index=target_by_index, test_size=test_size, targets=targets)
    numeric = _numeric_separability(frame, rows, numeric_features, targets)
    label_support = _label_support(rows, targets)
    max_split_shift = max((row["max_rate_shift"] for row in split_support), default=0.0)
    total = len(rows)
    checks = [
        {
            "name": "target mismatch removed",
            "passed": non_threat_mismatch == 0,
            "value": non_threat_mismatch,
            "target": "0 retained queued rows with non_threat severity target",
        },
        {
            "name": "queue retention acceptable",
            "passed": (dropped / len(base_rows) if base_rows else 0.0) <= 0.25,
            "value": round(dropped / len(base_rows), 4) if base_rows else 0.0,
            "target": "<=0.25 dropped queued rows",
        },
        {
            "name": "support acceptable",
            "passed": min((row["min_test_support"] for row in split_support), default=0) >= 15,
            "value": min((row["min_test_support"] for row in split_support), default=0),
            "target": ">=15 test rows per retained target across splits",
        },
        {
            "name": "pattern ambiguity improved",
            "passed": _ambiguous_row_share(pattern_mix, total) <= 0.65,
            "value": _ambiguous_row_share(pattern_mix, total),
            "target": "<=0.65 ambiguous pattern row share",
        },
        {
            "name": "split drift acceptable",
            "passed": max_split_shift <= 0.25,
            "value": max_split_shift,
            "target": "<=0.25 max retained-target rate shift",
        },
    ]
    return {
        "variant": variant,
        "retained_rows": len(rows),
        "dropped_rows": dropped,
        "dropped_share": round(dropped / len(base_rows), 4) if base_rows else 0.0,
        "target_distribution": _distribution([row["severity_target"] for row in rows]),
        "non_threat_mismatch_rows": non_threat_mismatch,
        "pattern_ambiguity_share": _ambiguous_row_share(pattern_mix, total),
        "traffic_family_ambiguity_share": _ambiguous_row_share(family_mix, total),
        "evidence_bucket_ambiguity_share": _ambiguous_row_share(evidence_mix, total),
        "split_support": split_support,
        "label_support": label_support,
        "numeric_separability": numeric[:15],
        "top_ambiguous_patterns": pattern_mix[:12],
        "top_ambiguous_traffic_families": family_mix[:10],
        "top_ambiguous_evidence_buckets": evidence_mix[:10],
        "checks": checks,
        "passed": sum(1 for row in checks if row["passed"]),
        "total": len(checks),
        "blockers": [row["name"] for row in checks if not row["passed"]],
    }


def _score_variant(summary: dict[str, Any]) -> tuple[Any, ...]:
    split_shift = max((row["max_rate_shift"] for row in summary.get("split_support", [])), default=1.0)
    return (
        int(summary.get("passed") or 0),
        -int(summary.get("non_threat_mismatch_rows") or 0),
        -_safe_float(summary.get("pattern_ambiguity_share"), 1.0),
        -split_shift,
        -_safe_float(summary.get("dropped_share"), 1.0),
        int(summary.get("retained_rows") or 0),
    )


def _select_best(variants: list[dict[str, Any]]) -> str | None:
    if not variants:
        return None
    return max(variants, key=_score_variant)["variant"]


def _assessment(best: dict[str, Any] | None) -> dict[str, Any]:
    if not best:
        return {
            "decision": "diagnostic_only",
            "passed": 0,
            "total": 0,
            "blockers": ["no interface variants evaluated"],
            "checks": [],
            "recommendation": "No v3.51 interface recommendation is available.",
        }
    checks = [
        *best.get("checks", []),
        {"name": "proposal is diagnostic-only", "passed": True, "value": True, "target": "required"},
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
            "Use the best interface only as the next diagnostic target candidate; do not write labels or activate a model."
        ),
    }


def _render_report(result: dict[str, Any]) -> str:
    rows = []
    for item in result.get("variant_comparison", []):
        rows.append(
            "| {variant} | {passed}/{total} | {retained} | {dropped} | {mismatch} | {pattern} | {split} |".format(
                variant=item["variant"],
                passed=item["passed"],
                total=item["total"],
                retained=item["retained_rows"],
                dropped=item["dropped_rows"],
                mismatch=item["non_threat_mismatch_rows"],
                pattern=item["pattern_ambiguity_share"],
                split=max((row["max_rate_shift"] for row in item.get("split_support", [])), default=None),
            )
        )
    return f"""# v3.51 Queue / Severity Target Interface Repair

Generated: {result.get("generated_at")}

This report is diagnostic only. It compares target-interface variants for rows admitted by the repaired queue. No labels were written, no model was activated, no artifact was written, and response automation stayed disabled.

## Summary

- Rows audited: {result.get("base_queued_rows")}
- Best diagnostic interface: {result.get("best_variant")}
- Assessment: {result.get("assessment", {}).get("decision")}
- Checks passed: {result.get("assessment", {}).get("passed")} / {result.get("assessment", {}).get("total")}
- Blockers: {result.get("assessment", {}).get("blockers")}

## Variant Comparison

| Variant | Checks | Retained Rows | Dropped Rows | Non-Threat Mismatch | Pattern Ambiguity | Max Split Drift |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
{chr(10).join(rows)}

## Safety

```json
{json.dumps(result.get("safety"), indent=2, default=str)}
```
"""


def run_v351_queue_severity_interface(
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
    base_rows, target_meta = _base_rows(prepared, frame)
    variants = [
        _variant_summary(
            base,
            frame,
            base_rows,
            variant=variant,
            numeric_features=meta["numeric_features"],
            test_size=test_size,
        )
        for variant in VARIANT_NAMES
    ]
    best_variant = _select_best(variants)
    best = next((item for item in variants if item["variant"] == best_variant), None)
    assessment = _assessment(best)
    after_labels = int(db.scalar(select(func.count(MLLabel.id))) or 0)
    after_runs = int(db.scalar(select(func.count(MLModelRun.id))) or 0)
    after_responses = int(db.scalar(select(func.count(ResponseAction.id))) or 0)
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    stamp = _stamp()
    report_path = output_path / f"v3_51_queue_severity_interface_{stamp}.md"
    latest_path = output_path / V351_LATEST
    result = {
        "ok": True,
        "status": "completed",
        "phase": "v3.51",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "runtime_seconds": round(time.perf_counter() - started, 4),
        "feature_generation_seconds": base.get("feature_generation_seconds"),
        "base_queued_rows": len(base_rows),
        "base_distribution": _distribution([row["base_severity_target"] for row in base_rows]),
        "queue_repair": target_meta["queue_repair"],
        "variant_comparison": variants,
        "best_variant": best_variant,
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
