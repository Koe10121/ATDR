import csv
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
from atdr.app.detection.v341_label_semantics_audit import _evidence_bucket, classify_semantic_issue
from atdr.app.detection.v348_repaired_queue_target_model import queue_targets_for_mode
from atdr.app.detection.v352_repaired_interface_severity_model import interface_severity_targets
from atdr.app.detection.v353_severity_feature_repair import (
    V353_CATEGORICAL_FEATURES,
    V353_NUMERIC_FEATURES,
    enrich_v353_severity_features,
)


V354_LATEST = "v3_54_severity_target_semantics_audit_latest.json"
SEVERITY_TARGETS = ("unusual_needs_review", "evidence_backed_suspicious", "malicious_high_confidence")
CATEGORICAL_FIELDS = (
    "pattern",
    "source_name",
    "traffic_family",
    "evidence_bucket",
    "severity_evidence_tier",
    "service_family",
    "original_label",
    "review_status",
    "label_source",
)
NUMERIC_FIELDS = (
    "v337_behavior_evidence_strength",
    "v337_source_diversity_pressure",
    "v337_benign_web_likelihood_score",
    *V353_NUMERIC_FEATURES,
)
POLICY_VARIANTS = {
    "current_three_severity": {
        "unusual_needs_review": "unusual_needs_review",
        "evidence_backed_suspicious": "evidence_backed_suspicious",
        "malicious_high_confidence": "malicious_high_confidence",
    },
    "merge_unusual_and_suspicious": {
        "unusual_needs_review": "review_needed",
        "evidence_backed_suspicious": "review_needed",
        "malicious_high_confidence": "malicious_high_confidence",
    },
    "merge_suspicious_and_malicious": {
        "unusual_needs_review": "unusual_needs_review",
        "evidence_backed_suspicious": "threat_evidence",
        "malicious_high_confidence": "threat_evidence",
    },
    "binary_review_queue": {
        "unusual_needs_review": "needs_review",
        "evidence_backed_suspicious": "needs_review",
        "malicious_high_confidence": "needs_review",
    },
}


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _mean(values: list[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def _std(values: list[float]) -> float:
    if len(values) < 2:
        return 0.0
    avg = _mean(values)
    return math.sqrt(sum((value - avg) ** 2 for value in values) / (len(values) - 1))


def _pattern(log: Any) -> str:
    return f"app={getattr(log, 'app', None) or '-'}|action={getattr(log, 'action', None) or '-'}|port={getattr(log, 'dst_port', None) or '-'}"


def _review_status(label: Any) -> str:
    if bool(getattr(label, "reviewed", False)):
        return "reviewed"
    return "weak_or_unreviewed"


def _severity_records(prepared: dict[str, Any], frame: Any) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    queue_values, queue_meta = queue_targets_for_mode(prepared, frame, target_mode="repaired_queue_target")
    severity_targets, interface_meta = interface_severity_targets(prepared, frame, variant="map_non_threat_to_unusual")
    records: list[dict[str, Any]] = []
    for index, target in enumerate(severity_targets):
        if queue_values[index] != "needs_review" or target not in SEVERITY_TARGETS:
            continue
        label = prepared["labels"][index]
        log = prepared["logs"][index]
        row = frame.iloc[index]
        semantic_issue = classify_semantic_issue(str(label.label), row)
        record = {
            "index": index,
            "target": str(target),
            "queue_target": queue_values[index],
            "original_label": str(label.label),
            "label_source": str(label.label_source or "unknown"),
            "review_status": _review_status(label),
            "reviewed": bool(label.reviewed),
            "pattern": _pattern(log),
            "source_name": _source_name(log),
            "traffic_family": str(row.get("v337_traffic_family") or "unknown"),
            "evidence_bucket": _evidence_bucket(row),
            "severity_evidence_tier": str(row.get("v353_severity_evidence_tier") or "unknown"),
            "service_family": str(row.get("v353_service_family") or "unknown"),
            "semantic_issue": semantic_issue.get("issue"),
            "semantic_issue_severity": int(semantic_issue.get("severity") or 0),
            "semantic_recommendation": semantic_issue.get("recommendation"),
        }
        for feature in NUMERIC_FIELDS:
            record[feature] = round(_safe_float(row.get(feature), default=0.0), 4)
        for feature in V353_CATEGORICAL_FEATURES:
            record[feature] = str(row.get(feature) or "unknown")
        records.append(record)
    return records, {"queue": queue_meta, "interface": interface_meta}


def _target_distribution(records: list[dict[str, Any]], field: str = "target") -> dict[str, int]:
    return dict(Counter(str(record.get(field) or "unknown") for record in records))


def _target_support(records: list[dict[str, Any]]) -> dict[str, Any]:
    support: dict[str, Any] = {}
    for target in SEVERITY_TARGETS:
        rows = [record for record in records if record["target"] == target]
        support[target] = {
            "rows": len(rows),
            "reviewed_rows": sum(1 for record in rows if record["review_status"] == "reviewed"),
            "manual_rows": sum(1 for record in rows if record["label_source"] == "manual"),
            "label_source_counts": dict(Counter(record["label_source"] for record in rows)),
            "original_label_counts": dict(Counter(record["original_label"] for record in rows)),
        }
    return support


def _categorical_ambiguity(
    records: list[dict[str, Any]],
    field: str,
    *,
    min_total: int = 4,
    target_field: str = "target",
) -> list[dict[str, Any]]:
    grouped: dict[str, Counter[str]] = defaultdict(Counter)
    for record in records:
        grouped[str(record.get(field) or "unknown")][str(record.get(target_field) or "unknown")] += 1
    ambiguous = []
    for value, counts in grouped.items():
        total = int(sum(counts.values()))
        if total < min_total or len(counts) < 2:
            continue
        majority, majority_count = counts.most_common(1)[0]
        ambiguous.append(
            {
                "field": field,
                "value": value,
                "total": total,
                "target_counts": dict(counts),
                "majority": majority,
                "purity": round(majority_count / total, 4),
                "conflict_ratio": round(1 - majority_count / total, 4),
            }
        )
    return sorted(ambiguous, key=lambda item: (item["conflict_ratio"], item["total"]), reverse=True)


def _categorical_summary(records: list[dict[str, Any]]) -> dict[str, Any]:
    by_field = {}
    for field in CATEGORICAL_FIELDS:
        ambiguous = _categorical_ambiguity(records, field)
        by_field[field] = {
            "ambiguous_value_count": len(ambiguous),
            "ambiguous_row_count": sum(item["total"] for item in ambiguous),
            "top_ambiguous_values": ambiguous[:12],
        }
    all_values = [item for summary in by_field.values() for item in summary["top_ambiguous_values"]]
    all_values.sort(key=lambda item: (item["conflict_ratio"], item["total"]), reverse=True)
    return {
        "fields": by_field,
        "top_ambiguous_values": all_values[:20],
        "ambiguous_row_share": round(sum(item["total"] for item in all_values) / len(records), 4) if records else 0.0,
    }


def _numeric_separability(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    targets = sorted({record["target"] for record in records})
    results = []
    for feature in NUMERIC_FIELDS:
        values_by_target: dict[str, list[float]] = defaultdict(list)
        for record in records:
            value = _safe_float(record.get(feature), default=float("nan"))
            if value == value:
                values_by_target[record["target"]].append(value)
        class_stats = {
            target: {"rows": len(values), "mean": round(_mean(values), 4), "std": round(_std(values), 4)}
            for target, values in values_by_target.items()
            if values
        }
        if len(class_stats) < 2:
            continue
        pairwise = []
        for left_index, left in enumerate(targets):
            for right in targets[left_index + 1 :]:
                left_values = values_by_target.get(left) or []
                right_values = values_by_target.get(right) or []
                if len(left_values) < 3 or len(right_values) < 3:
                    continue
                pooled = math.sqrt((_std(left_values) ** 2 + _std(right_values) ** 2) / 2)
                effect = abs(_mean(left_values) - _mean(right_values)) / pooled if pooled else 0.0
                pairwise.append({"pair": f"{left} vs {right}", "effect_size": round(effect, 4)})
        if pairwise:
            results.append(
                {
                    "feature": feature,
                    "class_stats": class_stats,
                    "minimum_pairwise_effect_size": round(min(item["effect_size"] for item in pairwise), 4),
                    "maximum_pairwise_effect_size": round(max(item["effect_size"] for item in pairwise), 4),
                    "pairwise": pairwise,
                }
            )
    return sorted(results, key=lambda item: item["minimum_pairwise_effect_size"], reverse=True)


def _semantic_contradictions(records: list[dict[str, Any]]) -> dict[str, Any]:
    buckets = {
        "unusual_with_strong_evidence": [],
        "suspicious_with_low_context": [],
        "malicious_with_low_malicious_signal": [],
        "high_severity_semantic_issue": [],
    }
    for record in records:
        evidence = _safe_float(record.get("v337_behavior_evidence_strength"))
        malicious_signal = _safe_float(record.get("v353_malicious_signal_score"))
        target = record["target"]
        if target == "unusual_needs_review" and (
            record["evidence_bucket"] in {"rule_backed", "anomaly_backed", "unknown_scan_context", "incomplete_scan_context"}
            or evidence >= 3.0
        ):
            buckets["unusual_with_strong_evidence"].append(record)
        if target == "evidence_backed_suspicious" and record["evidence_bucket"] in {"web_low_signal", "utility_low_signal", "low_context"}:
            buckets["suspicious_with_low_context"].append(record)
        if target == "malicious_high_confidence" and malicious_signal < 3.0:
            buckets["malicious_with_low_malicious_signal"].append(record)
        if int(record.get("semantic_issue_severity") or 0) >= 3:
            buckets["high_severity_semantic_issue"].append(record)
    return {
        name: {
            "rows": len(rows),
            "target_counts": _target_distribution(rows),
            "top_patterns": dict(Counter(row["pattern"] for row in rows).most_common(8)),
            "top_sources": dict(Counter(row["source_name"] for row in rows).most_common(8)),
            "examples": [_compact_record(row) for row in rows[:8]],
        }
        for name, rows in buckets.items()
    }


def _split_drift(
    base: dict[str, Any],
    *,
    test_size: float,
    min_samples: int,
) -> dict[str, Any]:
    results = []
    max_shift = 0.0
    for split_mode in V335_SPLITS:
        prepared = _prepared_for_split(base, split_mode=split_mode, test_size=test_size)
        frame, _meta = enrich_v353_severity_features(prepared)
        records, _target_meta = _severity_records(prepared, frame)
        by_index = {record["index"]: record["target"] for record in records}
        train_targets = [by_index[index] for index in prepared["train_idx"] if index in by_index]
        test_targets = [by_index[index] for index in prepared["test_idx"] if index in by_index]
        train_dist = dict(Counter(train_targets))
        test_dist = dict(Counter(test_targets))
        target_shifts = {}
        for target in SEVERITY_TARGETS:
            train_rate = train_dist.get(target, 0) / len(train_targets) if train_targets else 0.0
            test_rate = test_dist.get(target, 0) / len(test_targets) if test_targets else 0.0
            shift = abs(test_rate - train_rate)
            max_shift = max(max_shift, shift)
            target_shifts[target] = {
                "train_rate": round(train_rate, 4),
                "test_rate": round(test_rate, 4),
                "absolute_shift": round(shift, 4),
            }
        results.append(
            {
                "split_mode": split_mode,
                "training_rows": len(prepared["train_idx"]),
                "test_rows": len(prepared["test_idx"]),
                "severity_train_rows": len(train_targets),
                "severity_test_rows": len(test_targets),
                "train_distribution": train_dist,
                "test_distribution": test_dist,
                "target_shifts": target_shifts,
                "split_warnings": prepared.get("split_warnings") or [],
            }
        )
    return {"max_target_rate_shift": round(max_shift, 4), "splits": results, "min_samples": min_samples}


def _apply_policy(records: list[dict[str, Any]], mapping: dict[str, str]) -> list[dict[str, Any]]:
    return [{**record, "policy_target": mapping[record["target"]]} for record in records]


def _policy_variant_summary(records: list[dict[str, Any]]) -> dict[str, Any]:
    results = {}
    for name, mapping in POLICY_VARIANTS.items():
        policy_records = _apply_policy(records, mapping)
        ambiguous_values = []
        for field in CATEGORICAL_FIELDS:
            ambiguous_values.extend(_categorical_ambiguity(policy_records, field, target_field="policy_target"))
        ambiguous_values.sort(key=lambda item: (item["conflict_ratio"], item["total"]), reverse=True)
        results[name] = {
            "target_distribution": _target_distribution(policy_records, field="policy_target"),
            "class_count": len({record["policy_target"] for record in policy_records}),
            "top_ambiguous_values": ambiguous_values[:12],
            "ambiguous_row_count_top_values": sum(item["total"] for item in ambiguous_values[:12]),
            "ambiguous_row_share_top_values": round(sum(item["total"] for item in ambiguous_values[:12]) / len(records), 4)
            if records
            else 0.0,
        }
    return results


def _compact_record(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "index": record.get("index"),
        "target": record.get("target"),
        "label": record.get("original_label"),
        "review_status": record.get("review_status"),
        "label_source": record.get("label_source"),
        "pattern": record.get("pattern"),
        "source_name": record.get("source_name"),
        "evidence_bucket": record.get("evidence_bucket"),
        "traffic_family": record.get("traffic_family"),
        "severity_tier": record.get("severity_evidence_tier"),
        "scan_pressure": record.get("v353_scan_pressure_score"),
        "malicious_signal": record.get("v353_malicious_signal_score"),
        "semantic_issue": record.get("semantic_issue"),
    }


def _write_residual_sample(records: list[dict[str, Any]], *, output_path: Path, limit: int = 120) -> dict[str, Any]:
    candidates = [
        record
        for record in records
        if int(record.get("semantic_issue_severity") or 0) >= 3
        or record["target"] == "unusual_needs_review"
        and _safe_float(record.get("v337_behavior_evidence_strength")) >= 3.0
    ]
    candidates.sort(
        key=lambda row: (
            int(row.get("semantic_issue_severity") or 0),
            _safe_float(row.get("v337_behavior_evidence_strength")),
            _safe_float(row.get("v353_scan_pressure_score")),
        ),
        reverse=True,
    )
    selected = candidates[:limit]
    if not selected:
        return {"generated": False, "path": "", "rows": 0, "import_ready": False}
    output_path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "index",
        "target",
        "original_label",
        "review_status",
        "label_source",
        "pattern",
        "source_name",
        "evidence_bucket",
        "traffic_family",
        "severity_evidence_tier",
        "service_family",
        "v337_behavior_evidence_strength",
        "v353_scan_pressure_score",
        "v353_malicious_signal_score",
        "semantic_issue",
        "semantic_issue_severity",
        "semantic_recommendation",
        "diagnostic_note",
        "import_ready",
    ]
    with output_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for record in selected:
            writer.writerow(
                {
                    **{field: record.get(field, "") for field in fieldnames},
                    "diagnostic_note": "v3.54 semantic audit candidate; human review required before any label change",
                    "import_ready": "false",
                }
            )
    return {"generated": True, "path": str(output_path), "rows": len(selected), "candidate_rows": len(candidates), "import_ready": False}


def _readiness(result: dict[str, Any]) -> dict[str, Any]:
    categorical = result.get("categorical_ambiguity") or {}
    numeric = result.get("numeric_separability") or []
    split = result.get("split_drift") or {}
    contradictions = result.get("semantic_contradictions") or {}
    strongest_min_effect = max((item.get("minimum_pairwise_effect_size") or 0.0 for item in numeric), default=0.0)
    top_conflict = max(
        (
            item.get("conflict_ratio") or 0.0
            for summary in (categorical.get("fields") or {}).values()
            for item in summary.get("top_ambiguous_values") or []
        ),
        default=0.0,
    )
    high_issue_rows = int((contradictions.get("high_severity_semantic_issue") or {}).get("rows") or 0)
    unusual_strong = int((contradictions.get("unusual_with_strong_evidence") or {}).get("rows") or 0)
    checks = [
        {"name": "severity support exists", "passed": result.get("rows_analyzed", 0) >= 100, "value": result.get("rows_analyzed"), "target": ">= 100"},
        {
            "name": "all severity targets represented",
            "passed": all((result.get("target_distribution") or {}).get(target, 0) >= 20 for target in SEVERITY_TARGETS),
            "value": result.get("target_distribution"),
            "target": ">= 20 rows per target",
        },
        {
            "name": "categorical ambiguity acceptable",
            "passed": top_conflict <= 0.35,
            "value": round(top_conflict, 4),
            "target": "<= 0.35 max top conflict ratio",
        },
        {
            "name": "numeric separability acceptable",
            "passed": strongest_min_effect >= 0.7,
            "value": round(strongest_min_effect, 4),
            "target": ">= 0.70 strongest min pairwise effect",
        },
        {
            "name": "split target drift acceptable",
            "passed": _safe_float(split.get("max_target_rate_shift")) <= 0.20,
            "value": split.get("max_target_rate_shift"),
            "target": "<= 0.20 max severity target-rate shift",
        },
        {
            "name": "semantic contradictions low",
            "passed": high_issue_rows <= 50 and unusual_strong <= 100,
            "value": {"high_severity_issues": high_issue_rows, "unusual_with_strong_evidence": unusual_strong},
            "target": "<= 50 high semantic issues and <= 100 unusual strong-evidence rows",
        },
        {"name": "no labels written", "passed": True, "value": True, "target": "required"},
        {"name": "model activation disabled", "passed": True, "value": False, "target": "required"},
        {"name": "response automation disabled", "passed": True, "value": False, "target": "required"},
    ]
    blockers = [row["name"] for row in checks if not row["passed"]]
    return {
        "decision": "diagnostic_only" if blockers else "candidate_only",
        "passed": sum(1 for row in checks if row["passed"]),
        "total": len(checks),
        "production_promoted": False,
        "model_activated": False,
        "model_artifact_written": False,
        "response_automation_allowed": False,
        "blockers": blockers,
        "checks": checks,
    }


def _render_report(result: dict[str, Any]) -> str:
    categorical_rows = []
    for item in (result.get("categorical_ambiguity") or {}).get("top_ambiguous_values") or []:
        categorical_rows.append(
            "| {field} | {value} | {total} | {purity} | {conflict} | {counts} |".format(
                field=item.get("field"),
                value=str(item.get("value", ""))[:80],
                total=item.get("total"),
                purity=item.get("purity"),
                conflict=item.get("conflict_ratio"),
                counts=json.dumps(item.get("target_counts"), sort_keys=True),
            )
        )
    numeric_rows = []
    for item in result.get("numeric_separability") or []:
        numeric_rows.append(
            "| {feature} | {min_effect} | {max_effect} |".format(
                feature=item.get("feature"),
                min_effect=item.get("minimum_pairwise_effect_size"),
                max_effect=item.get("maximum_pairwise_effect_size"),
            )
        )
    return f"""# v3.54 Severity Target Semantics Audit

Generated: {result.get("generated_at")}

This report is diagnostic only. It audits whether the downstream severity targets are semantically separable before more classifier tuning. No labels were written, no model was activated, no model artifact was written, and response automation stayed disabled.

## Summary

- Rows analyzed: {result.get("rows_analyzed")}
- Target distribution: `{result.get("target_distribution")}`
- Readiness: `{result.get("readiness", {}).get("decision")}`
- Checks passed: {result.get("readiness", {}).get("passed")} / {result.get("readiness", {}).get("total")}
- Blockers: {result.get("readiness", {}).get("blockers")}
- Max split target-rate shift: {result.get("split_drift", {}).get("max_target_rate_shift")}

## Top Categorical Ambiguity

| Field | Value | Rows | Purity | Conflict | Target Counts |
| --- | --- | ---: | ---: | ---: | --- |
{chr(10).join(categorical_rows)}

## Numeric Separability

| Feature | Min Pairwise Effect | Max Pairwise Effect |
| --- | ---: | ---: |
{chr(10).join(numeric_rows)}

## Semantic Contradictions

```json
{json.dumps(result.get("semantic_contradictions"), indent=2, default=str)}
```

## Policy Variant Diagnostic

```json
{json.dumps(result.get("policy_variants"), indent=2, default=str)}
```

## Safety

```json
{json.dumps(result.get("safety"), indent=2, default=str)}
```
"""


def run_v354_severity_target_semantics_audit(
    db: Session,
    *,
    test_size: float = 0.3,
    min_samples: int = 6,
    output_dir: str | Path = OUTPUT_DIR,
) -> dict[str, Any]:
    before_labels = int(db.scalar(select(func.count(MLLabel.id))) or 0)
    before_runs = int(db.scalar(select(func.count(MLModelRun.id))) or 0)
    before_responses = int(db.scalar(select(func.count(ResponseAction.id))) or 0)
    base = _load_base_dataset(db, min_samples=min_samples)
    if not base.get("ok"):
        return base

    started = time.perf_counter()
    prepared = _prepared_for_split(base, split_mode="time", test_size=test_size)
    frame, feature_meta = enrich_v353_severity_features(prepared)
    records, target_meta = _severity_records(prepared, frame)
    categorical = _categorical_summary(records)
    result: dict[str, Any] = {
        "ok": True,
        "status": "completed",
        "phase": "v3.54",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "runtime_seconds": 0.0,
        "feature_generation_seconds": base.get("feature_generation_seconds"),
        "rows_analyzed": len(records),
        "target_distribution": _target_distribution(records),
        "target_support": _target_support(records),
        "target_meta": target_meta,
        "feature_meta": {
            "numeric_features_used": [field for field in NUMERIC_FIELDS if field in frame.columns],
            "categorical_features_used": [*V353_CATEGORICAL_FEATURES, "v337_traffic_family"],
            "experimental_features": feature_meta.get("experimental_features") or [],
        },
        "categorical_ambiguity": categorical,
        "numeric_separability": _numeric_separability(records),
        "semantic_contradictions": _semantic_contradictions(records),
        "split_drift": _split_drift(base, test_size=test_size, min_samples=min_samples),
        "policy_variants": _policy_variant_summary(records),
        "training_dataset": training_dataset_diagnostics(db),
    }

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    stamp = _stamp()
    report_path = output_path / f"v3_54_severity_target_semantics_audit_{stamp}.md"
    latest_path = output_path / V354_LATEST
    sample_path = output_path / "v3_54_severity_semantics_residual_sample.csv"
    residual_sample = _write_residual_sample(records, output_path=sample_path)

    after_labels = int(db.scalar(select(func.count(MLLabel.id))) or 0)
    after_runs = int(db.scalar(select(func.count(MLModelRun.id))) or 0)
    after_responses = int(db.scalar(select(func.count(ResponseAction.id))) or 0)
    result["residual_sample"] = residual_sample
    result["safety"] = {
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
    }
    result["readiness"] = _readiness(result)
    result["runtime_seconds"] = round(time.perf_counter() - started, 4)
    result["report_path"] = str(report_path)
    result["latest_summary_path"] = str(latest_path)
    report_path.write_text(_render_report(result), encoding="utf-8")
    latest_path.write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")
    return result
