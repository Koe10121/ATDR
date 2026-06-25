import json
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
from atdr.app.detection.v344_two_stage_soc_queue import _queue_target
from atdr.app.detection.v347_queue_target_repair_proposal import propose_queue_target


V362_LATEST = "v3_62_supervised_training_target_contract_latest.json"
SAFE_QUEUE_TARGETS = {"non_threat", "needs_review"}
BLOCKED_TRAINING_TARGETS = {
    "flat_5class_exact_label",
    "exact_suspicious_vs_malicious_production_classifier",
    "ai_generated_human_review_label",
}


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _pattern(log: Any) -> str:
    return f"app={getattr(log, 'app', None) or '-'}|action={getattr(log, 'action', None) or '-'}|port={getattr(log, 'dst_port', None) or '-'}"


def _review_status(label: Any) -> str:
    return "reviewed" if bool(getattr(label, "reviewed", False)) else "weak_or_unreviewed"


def _top_counter(counter: Counter[str], limit: int = 12) -> list[list[Any]]:
    return [[key, value] for key, value in counter.most_common(limit)]


def build_safe_training_target_adapter(prepared: dict[str, Any], frame: Any) -> dict[str, Any]:
    """Map unstable exact labels to a safe binary SOC review-queue target.

    The adapter is diagnostic infrastructure only. It does not mutate labels,
    write model artifacts, or decide exact suspicious/malicious classes.
    """

    rows: list[dict[str, Any]] = []
    target_counts: Counter[str] = Counter()
    original_counts: Counter[str] = Counter()
    original_to_target: Counter[str] = Counter()
    issue_to_target: Counter[str] = Counter()
    evidence_to_target: Counter[str] = Counter()
    reason_counts: Counter[str] = Counter()
    review_status_by_target: Counter[str] = Counter()
    semantic_issue_counts: Counter[str] = Counter()
    semantic_issue_review_counts: Counter[str] = Counter()
    pattern_targets: dict[tuple[str, str], Counter[str]] = defaultdict(Counter)
    source_targets: dict[str, Counter[str]] = defaultdict(Counter)

    for index, original_label in enumerate(prepared["y"]):
        label_obj = prepared["labels"][index]
        log = prepared["logs"][index]
        frame_row = frame.iloc[index]
        behavior_target = behavior_aware_soc_target(original_label, frame_row)
        base_queue_target = _queue_target(behavior_target)
        safe_target, repair_reason = propose_queue_target(base_queue_target, frame_row)
        if safe_target not in SAFE_QUEUE_TARGETS:
            safe_target = "needs_review"
            repair_reason = "forced_safe_fallback_unknown_target"

        issue = classify_semantic_issue(original_label, frame_row)
        evidence_bucket = _evidence_bucket(frame_row)
        pattern = _pattern(log)
        source_name = _source_name(log)
        reviewed = _review_status(label_obj)
        row = {
            "index": index,
            "label_id": getattr(label_obj, "id", None),
            "log_id": getattr(log, "id", None),
            "source_name": source_name,
            "pattern": pattern,
            "original_label": original_label,
            "review_status": reviewed,
            "label_source": str(getattr(label_obj, "label_source", "") or ""),
            "behavior_target": behavior_target,
            "base_queue_target": base_queue_target,
            "safe_queue_target": safe_target,
            "target_repair_reason": repair_reason,
            "exact_label_policy": "explanation_or_ranking_only",
            "semantic_issue": issue["issue"],
            "semantic_issue_severity": int(issue["severity"]),
            "semantic_recommendation": issue["recommendation"],
            "evidence_bucket": evidence_bucket,
            "traffic_family": issue["traffic_family"],
            "evidence_strength": issue["evidence_strength"],
            "raw_log_included": False,
            "human_review_written": False,
        }
        rows.append(row)

        target_counts[safe_target] += 1
        original_counts[original_label] += 1
        original_to_target[f"{original_label}->{safe_target}"] += 1
        issue_to_target[f"{issue['issue']}->{safe_target}"] += 1
        evidence_to_target[f"{evidence_bucket}->{safe_target}"] += 1
        reason_counts[repair_reason] += 1
        review_status_by_target[f"{reviewed}->{safe_target}"] += 1
        semantic_issue_counts[issue["issue"]] += 1
        if int(issue["severity"]) >= 3:
            semantic_issue_review_counts[f"{reviewed}->{issue['issue']}"] += 1
        pattern_targets[(pattern, evidence_bucket)][safe_target] += 1
        source_targets[source_name][safe_target] += 1

    mixed_patterns = []
    for (pattern, evidence), targets in pattern_targets.items():
        if len(targets) < 2:
            continue
        total = sum(targets.values())
        mixed_patterns.append(
            {
                "pattern": pattern,
                "evidence_bucket": evidence,
                "total": total,
                "target_counts": dict(targets),
                "needs_review_share": round(targets.get("needs_review", 0) / total, 4) if total else 0.0,
            }
        )
    mixed_patterns.sort(key=lambda item: (item["total"], abs(0.5 - item["needs_review_share"])), reverse=True)

    mixed_sources = []
    for source_name, targets in source_targets.items():
        if len(targets) < 2:
            continue
        total = sum(targets.values())
        mixed_sources.append(
            {
                "source_name": source_name,
                "total": total,
                "target_counts": dict(targets),
                "needs_review_share": round(targets.get("needs_review", 0) / total, 4) if total else 0.0,
            }
        )
    mixed_sources.sort(key=lambda item: item["total"], reverse=True)

    high_severity_issue_rows = [row for row in rows if int(row["semantic_issue_severity"]) >= 3]
    weak_high_severity_issue_rows = [
        row for row in high_severity_issue_rows if row["review_status"] == "weak_or_unreviewed"
    ]
    return {
        "status": "completed",
        "rows_audited": len(rows),
        "safe_queue_targets": sorted(SAFE_QUEUE_TARGETS),
        "all_rows_mapped_to_safe_targets": set(target_counts).issubset(SAFE_QUEUE_TARGETS),
        "target_distribution": dict(target_counts),
        "original_label_distribution": dict(original_counts),
        "original_label_to_safe_target": _top_counter(original_to_target, 20),
        "semantic_issue_to_safe_target": _top_counter(issue_to_target, 20),
        "evidence_bucket_to_safe_target": _top_counter(evidence_to_target, 20),
        "target_repair_reasons": _top_counter(reason_counts, 20),
        "review_status_by_safe_target": _top_counter(review_status_by_target, 12),
        "semantic_issue_counts": dict(semantic_issue_counts),
        "high_severity_semantic_issue_count": len(high_severity_issue_rows),
        "weak_high_severity_semantic_issue_count": len(weak_high_severity_issue_rows),
        "high_severity_semantic_issue_review_counts": _top_counter(semantic_issue_review_counts, 20),
        "top_mixed_target_patterns": mixed_patterns[:20],
        "top_mixed_target_sources": mixed_sources[:12],
        "row_sample": rows[:12],
        "row_sample_policy": "sanitized_feature_summary_only_no_raw_logs",
    }


def _split_target_drift(base: dict[str, Any], targets: list[str], *, test_size: float) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for split_mode in V335_SPLITS:
        try:
            split = _prepared_for_split(base, split_mode=split_mode, test_size=test_size)
        except Exception as exc:  # pragma: no cover - split helpers are covered elsewhere
            rows.append({"split_mode": split_mode, "status": "failed", "error": str(exc)})
            continue
        train_targets = [targets[index] for index in split["train_idx"]]
        test_targets = [targets[index] for index in split["test_idx"]]
        train_counts = Counter(train_targets)
        test_counts = Counter(test_targets)
        train_total = max(1, len(train_targets))
        test_total = max(1, len(test_targets))
        train_review_rate = train_counts.get("needs_review", 0) / train_total
        test_review_rate = test_counts.get("needs_review", 0) / test_total
        rows.append(
            {
                "split_mode": split_mode,
                "status": "evaluated",
                "train_rows": len(train_targets),
                "test_rows": len(test_targets),
                "train_target_distribution": dict(train_counts),
                "test_target_distribution": dict(test_counts),
                "train_needs_review_rate": round(train_review_rate, 4),
                "test_needs_review_rate": round(test_review_rate, 4),
                "absolute_rate_shift": round(abs(train_review_rate - test_review_rate), 4),
                "warnings": split.get("split_warnings") or [],
            }
        )
    return rows


def build_supervised_training_target_contract(
    *,
    adapter: dict[str, Any],
    split_drift: list[dict[str, Any]],
    training_diagnostics: dict[str, Any] | None = None,
) -> dict[str, Any]:
    evaluated_splits = [row for row in split_drift if row.get("status") == "evaluated"]
    max_drift = max((_safe_float(row.get("absolute_rate_shift")) for row in evaluated_splits), default=0.0)
    high_issue_count = int(adapter.get("high_severity_semantic_issue_count") or 0)
    weak_high_issue_count = int(adapter.get("weak_high_severity_semantic_issue_count") or 0)
    safety_checks = [
        {
            "name": "all labels map to safe queue targets",
            "passed": bool(adapter.get("all_rows_mapped_to_safe_targets")),
            "value": adapter.get("target_distribution"),
            "target": sorted(SAFE_QUEUE_TARGETS),
        },
        {
            "name": "exact labels are blocked as active training targets",
            "passed": True,
            "value": sorted(BLOCKED_TRAINING_TARGETS),
            "target": "blocked",
        },
        {
            "name": "adapter writes no human-reviewed labels",
            "passed": True,
            "value": False,
            "target": "required",
        },
        {
            "name": "adapter writes no model artifacts",
            "passed": True,
            "value": False,
            "target": "required",
        },
        {
            "name": "adapter cannot trigger response actions",
            "passed": True,
            "value": False,
            "target": "required",
        },
    ]
    quality_warnings = []
    if high_issue_count:
        quality_warnings.append(
            f"{high_issue_count} rows have high-severity label/evidence semantic issues; use queue target only."
        )
    if weak_high_issue_count:
        quality_warnings.append(
            f"{weak_high_issue_count} high-severity semantic issue rows are weak/unreviewed; do not treat as ground truth."
        )
    if max_drift > 0.20:
        quality_warnings.append(
            f"Safe queue target distribution shifts by up to {max_drift:.4f} across validation splits."
        )

    passed = sum(1 for item in safety_checks if item["passed"])
    decision = "safe_queue_target_adapter_ready" if passed == len(safety_checks) else "diagnostic_only"
    return {
        "decision": decision,
        "recommended_training_target": "binary_soc_review_queue",
        "allowed_training_targets": {
            "binary_soc_review_queue": {
                "status": "diagnostic_training_allowed",
                "classes": sorted(SAFE_QUEUE_TARGETS),
                "meaning": "Predict whether evidence should enter SOC analyst review.",
            }
        },
        "blocked_training_targets": {
            target: {
                "status": "blocked",
                "reason": "Exact label semantics are not stable enough for active production classification.",
            }
            for target in sorted(BLOCKED_TRAINING_TARGETS)
        },
        "exact_label_policy": "explanation_or_ranking_only",
        "runtime_activation_allowed": False,
        "production_promotion_allowed": False,
        "response_automation_allowed": False,
        "adapter": adapter,
        "split_target_drift": split_drift,
        "max_safe_target_rate_shift": round(max_drift, 4),
        "quality_warnings": quality_warnings,
        "checks": safety_checks,
        "checks_passed": passed,
        "checks_total": len(safety_checks),
        "blockers": [item["name"] for item in safety_checks if not item["passed"]],
        "training_diagnostics": training_diagnostics or {},
    }


def _render_report(result: dict[str, Any]) -> str:
    contract = result.get("contract") or {}
    adapter = contract.get("adapter") or {}
    lines = [
        "# v3.62 Supervised Training Target Contract",
        "",
        f"Generated: {result.get('generated_at')}",
        "",
        "This diagnostic turns unstable exact labels into a safe binary SOC review-queue target. It does not train, activate, promote, write labels, or trigger response actions.",
        "",
        "## Decision",
        "",
        f"- Decision: `{contract.get('decision')}`",
        f"- Recommended target: `{contract.get('recommended_training_target')}`",
        f"- Exact label policy: `{contract.get('exact_label_policy')}`",
        f"- Checks: `{contract.get('checks_passed')} / {contract.get('checks_total')}`",
        f"- Runtime activation allowed: `{contract.get('runtime_activation_allowed')}`",
        f"- Response automation allowed: `{contract.get('response_automation_allowed')}`",
        "",
        "## Target Mapping",
        "",
        f"- Rows audited: `{adapter.get('rows_audited')}`",
        f"- Safe target distribution: `{adapter.get('target_distribution')}`",
        f"- Original labels: `{adapter.get('original_label_distribution')}`",
        f"- Original-to-safe target: `{adapter.get('original_label_to_safe_target')}`",
        f"- Target repair reasons: `{adapter.get('target_repair_reasons')}`",
        "",
        "## Semantic Warnings",
        "",
        f"- High-severity semantic issue rows: `{adapter.get('high_severity_semantic_issue_count')}`",
        f"- Weak high-severity semantic issue rows: `{adapter.get('weak_high_severity_semantic_issue_count')}`",
        f"- Quality warnings: `{contract.get('quality_warnings')}`",
        "",
        "## Split Target Drift",
        "",
    ]
    for row in contract.get("split_target_drift") or []:
        lines.append(
            f"- `{row.get('split_mode')}`: status `{row.get('status')}`, "
            f"train review rate `{row.get('train_needs_review_rate')}`, "
            f"test review rate `{row.get('test_needs_review_rate')}`, "
            f"shift `{row.get('absolute_rate_shift')}`"
        )
    lines.extend(
        [
            "",
            "## Blocked Uses",
            "",
            "- Exact five-class labels as active production classifier target.",
            "- AI-generated labels as human-reviewed labels.",
            "- Supervised output triggering automatic response or real firewall blocking.",
            "",
            "## Safety",
            "",
            f"```json\n{json.dumps(result.get('safety') or {}, indent=2, default=str)}\n```",
        ]
    )
    return "\n".join(lines) + "\n"


def run_v362_supervised_training_target_contract(
    db: Session,
    *,
    output_dir: str | Path = OUTPUT_DIR,
    test_size: float = 0.3,
    min_samples: int = 6,
) -> dict[str, Any]:
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    before_labels = int(db.scalar(select(func.count(MLLabel.id))) or 0)
    before_runs = int(db.scalar(select(func.count(MLModelRun.id))) or 0)
    before_responses = int(db.scalar(select(func.count(ResponseAction.id))) or 0)

    base = _load_base_dataset(db, min_samples=min_samples)
    if not base.get("ok"):
        return {
            "ok": False,
            "status": base.get("status", "skipped"),
            "phase": "v3.62",
            "message": base.get("message", "Dataset unavailable."),
            "safety": {
                "production_promoted": False,
                "model_activated": False,
                "model_artifact_written": False,
                "labels_written": False,
                "response_automation_allowed": False,
            },
        }

    prepared = _prepared_for_split(base, split_mode="time", test_size=test_size)
    frame, enrichment_meta = enrich_v337_features(prepared)
    adapter = build_safe_training_target_adapter(prepared, frame)
    safe_targets = [row["safe_queue_target"] for row in adapter.get("row_sample", [])]
    if len(safe_targets) != adapter.get("rows_audited"):
        # Row samples are intentionally limited; recompute full target list from counters' source rows.
        full_targets = []
        for index, original_label in enumerate(prepared["y"]):
            frame_row = frame.iloc[index]
            behavior_target = behavior_aware_soc_target(original_label, frame_row)
            safe_target, _reason = propose_queue_target(_queue_target(behavior_target), frame_row)
            full_targets.append(safe_target if safe_target in SAFE_QUEUE_TARGETS else "needs_review")
    else:
        full_targets = safe_targets

    split_drift = _split_target_drift(base, full_targets, test_size=test_size)
    diagnostics = training_dataset_diagnostics(db)
    contract = build_supervised_training_target_contract(
        adapter=adapter,
        split_drift=split_drift,
        training_diagnostics={
            "total_label_rows": diagnostics.get("total_label_rows"),
            "trainable_latest_rows": diagnostics.get("trainable_latest_rows"),
            "excluded_from_training": diagnostics.get("excluded_from_training"),
            "superseded_label_rows": diagnostics.get("superseded_label_rows"),
            "missing_log_rows": diagnostics.get("missing_log_rows"),
            "non_trainable_label_rows": diagnostics.get("non_trainable_label_rows"),
            "missing_timestamp_latest_rows": diagnostics.get("missing_timestamp_latest_rows"),
            "feature_excluded_rows": diagnostics.get("feature_excluded_rows"),
        },
    )

    after_labels = int(db.scalar(select(func.count(MLLabel.id))) or 0)
    after_runs = int(db.scalar(select(func.count(MLModelRun.id))) or 0)
    after_responses = int(db.scalar(select(func.count(ResponseAction.id))) or 0)
    stamp = _stamp()
    result = {
        "ok": True,
        "status": "completed",
        "phase": "v3.62",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "contract": contract,
        "feature_enrichment": {
            "experimental_features": enrichment_meta.get("experimental_features") or [],
            "raw_logs_included": False,
        },
        "safety": {
            "production_promoted": False,
            "model_activated": False,
            "model_artifact_written": False,
            "labels_written": before_labels != after_labels,
            "raw_logs_included": False,
            "response_automation_allowed": False,
            "real_firewall_blocking_enabled": False,
            "ml_labels_before": before_labels,
            "ml_labels_after": after_labels,
            "ml_model_runs_before": before_runs,
            "ml_model_runs_after": after_runs,
            "response_actions_before": before_responses,
            "response_actions_after": after_responses,
        },
    }
    report_path = output / f"v3_62_supervised_training_target_contract_{stamp}.md"
    latest_path = output / V362_LATEST
    result["report_path"] = str(report_path)
    result["latest_summary_path"] = str(latest_path)
    report_path.write_text(_render_report(result), encoding="utf-8")
    latest_path.write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")
    return result
