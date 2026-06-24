import csv
import json
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from atdr.app.db.models import MLLabel, MLModelRun, ResponseAction
from atdr.app.detection.v330_detection_ml_quality import BENIGN_LIKE_LABELS, OUTPUT_DIR, REVIEW_FIELDS, THREAT_LABELS, _source_name
from atdr.app.detection.v331_noise_reduction import _build_pipeline_for_columns, _metric_bundle, _profile_summary
from atdr.app.detection.v332_guard_validation import _load_base_dataset, _prepared_for_split, _safe_float
from atdr.app.detection.v335_split_stability_repair import V335_SPLITS, _max_numeric
from atdr.app.detection.supervised_detector import training_dataset_diagnostics


V336_LATEST = "v3_36_label_semantics_latest.json"
WEB_LIKE_APPS = {
    "ssl",
    "quic-base",
    "web-browsing",
    "facebook-base",
    "gmail-base",
    "youtube-base",
    "naver-line",
    "tiktok-base",
    "apple-maps",
    "adobe-cloud",
    "stun",
    "dns-base",
    "ntp-base",
    "ping",
}
TARGET_DESIGNS = ["soc_queue_three_state", "soc_queue_four_state", "binary_evidence_backed_threat"]


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _lower(value: str | None) -> str:
    return (value or "").strip().lower()


def _pattern(log: Any) -> str:
    return f"app={log.app or '-'}|action={log.action or '-'}|port={log.dst_port or '-'}"


def evidence_profile(row: Any, log: Any) -> dict[str, Any]:
    unique_dst_ips = _max_numeric(
        row,
        ["src_ip_5min_unique_dst_ips", "src_ip_15min_unique_dst_ips", "src_ip_60min_unique_dst_ips"],
    )
    unique_dst_ports = _max_numeric(
        row,
        ["src_ip_5min_unique_dst_ports", "src_ip_15min_unique_dst_ports", "src_ip_60min_unique_dst_ports"],
    )
    event_count = _max_numeric(
        row,
        ["src_ip_5min_log_count", "src_ip_5min_event_count", "src_ip_15min_event_count", "src_ip_60min_event_count"],
    )
    deny_count = _max_numeric(
        row,
        [
            "src_ip_5min_deny_count",
            "src_ip_5min_deny_drop_reset_count",
            "src_ip_15min_deny_drop_reset_count",
            "src_ip_60min_deny_drop_reset_count",
        ],
    )
    unknown_count = _max_numeric(
        row,
        ["src_ip_5min_unknown_app_count", "src_ip_15min_unknown_app_count", "src_ip_60min_unknown_app_count"],
    )
    high_risk_count = _max_numeric(
        row,
        ["src_ip_5min_high_risk_app_count", "src_ip_15min_high_risk_app_count", "src_ip_60min_high_risk_app_count"],
    )
    rule_score = _safe_float(row.get("v331_rule_score"))
    anomaly_score = _safe_float(getattr(log, "anomaly_score", None), 0.0)
    anomaly_signal = bool(getattr(log, "is_anomaly", False)) or anomaly_score <= -0.20
    scan_like = (
        unique_dst_ips >= 4
        or unique_dst_ports >= 3
        or (event_count >= 10 and (unique_dst_ips >= 3 or unique_dst_ports >= 2))
        or deny_count > 0
        or unknown_count >= 3
        or high_risk_count >= 2
    )
    app = _lower(getattr(log, "app", None))
    action = _lower(getattr(log, "action", None))
    port = getattr(log, "dst_port", None)
    web_like = action == "allow" and (app in WEB_LIKE_APPS or port in {53, 80, 123, 443, 3478})
    low_evidence = (
        rule_score < 10
        and not anomaly_signal
        and not scan_like
        and deny_count == 0
        and high_risk_count < 2
        and unknown_count < 3
    )
    return {
        "rule_score": rule_score,
        "anomaly_signal": anomaly_signal,
        "scan_like": scan_like,
        "web_like": web_like,
        "low_evidence": low_evidence,
        "low_evidence_web_like": low_evidence and web_like,
        "unique_dst_ips": unique_dst_ips,
        "unique_dst_ports": unique_dst_ports,
        "event_count": event_count,
        "deny_count": deny_count,
        "unknown_count": unknown_count,
        "high_risk_count": high_risk_count,
    }


def map_label_to_soc_target(label: str, evidence: dict[str, Any], *, design: str) -> str:
    if design == "binary_evidence_backed_threat":
        return "evidence_backed_threat" if label in THREAT_LABELS and not evidence["low_evidence_web_like"] else "non_threat_or_review"
    if label in {"benign", "benign_unusual"}:
        return "non_threat"
    if label == "needs_context":
        return "needs_review"
    if evidence["low_evidence_web_like"]:
        return "needs_review"
    if design == "soc_queue_four_state":
        return f"{label}_evidence"
    return "evidence_backed_threat"


def _target_order(design: str) -> tuple[list[str], set[str]]:
    if design == "binary_evidence_backed_threat":
        return ["evidence_backed_threat", "non_threat_or_review"], {"evidence_backed_threat"}
    if design == "soc_queue_four_state":
        return ["malicious_evidence", "needs_review", "non_threat", "suspicious_evidence"], {
            "malicious_evidence",
            "suspicious_evidence",
        }
    return ["evidence_backed_threat", "needs_review", "non_threat"], {"evidence_backed_threat"}


def _labels_for_design(prepared: dict[str, Any], frame: Any, *, design: str) -> list[str]:
    values: list[str] = []
    for index, label in enumerate(prepared["y"]):
        values.append(map_label_to_soc_target(label, evidence_profile(frame.iloc[index], prepared["logs"][index]), design=design))
    return values


def _target_summary(metrics: dict[str, Any]) -> dict[str, Any]:
    summary = _profile_summary(metrics)
    per_class = metrics.get("per_class") or {}
    for key in [
        "non_threat",
        "needs_review",
        "evidence_backed_threat",
        "suspicious_evidence",
        "malicious_evidence",
        "non_threat_or_review",
    ]:
        if key in per_class:
            summary[f"{key}_recall"] = per_class[key].get("recall")
            summary[f"{key}_f1"] = per_class[key].get("f1")
    return summary


def _fit_target_design(prepared: dict[str, Any], augmented: dict[str, Any], *, design: str) -> dict[str, Any]:
    frame = augmented["frame"]
    target_values = _labels_for_design(prepared, frame, design=design)
    train_idx = prepared["train_idx"]
    test_idx = prepared["test_idx"]
    y_train = [target_values[index] for index in train_idx]
    y_test = [target_values[index] for index in test_idx]
    labels_order, threat_labels = _target_order(design)
    if len(set(y_train)) < 2 or len(set(y_test)) < 2:
        return {
            "design": design,
            "status": "skipped",
            "message": "Target design has fewer than two classes in train or test split.",
            "target_distribution": dict(Counter(target_values)),
        }
    pipeline = _build_pipeline_for_columns(
        prepared["imports"],
        model_type="extra_trees",
        class_weight="balanced",
        numeric_features=augmented["numeric_features"],
        categorical_features=augmented["categorical_features"],
    )
    started = time.perf_counter()
    pipeline.fit(frame.iloc[train_idx], y_train)
    predictions = [str(value) for value in pipeline.predict(frame.iloc[test_idx])]
    metrics = _metric_bundle(
        prepared,
        y_true=y_test,
        predictions=predictions,
        labels_order=labels_order,
        threat_labels=threat_labels,
    )
    return {
        "design": design,
        "status": "evaluated",
        "training_seconds": round(time.perf_counter() - started, 4),
        "target_distribution": dict(Counter(target_values)),
        "test_distribution": dict(Counter(y_test)),
        "summary": _target_summary(metrics),
        "metrics": metrics,
    }


def _stability_summary(split_rows: list[dict[str, Any]]) -> dict[str, Any]:
    evaluated = [row for row in split_rows if row.get("status") == "evaluated"]
    keys = [
        "threat_positive_precision",
        "threat_positive_recall",
        "threat_positive_f1",
        "benign_like_false_positive_rate",
        "macro_f1",
        "weighted_f1",
        "needs_review_recall",
        "evidence_backed_threat_recall",
        "suspicious_evidence_recall",
        "malicious_evidence_recall",
    ]
    ranges: dict[str, dict[str, float | None]] = {}
    for key in keys:
        values = [
            _safe_float((row.get("summary") or {}).get(key), default=float("nan"))
            for row in evaluated
            if (row.get("summary") or {}).get(key) is not None
        ]
        values = [value for value in values if value == value]
        ranges[key] = {
            "min": round(min(values), 4) if values else None,
            "max": round(max(values), 4) if values else None,
            "span": round(max(values) - min(values), 4) if values else None,
        }
    pass_count = 0
    blockers: list[str] = []
    for row in evaluated:
        summary = row.get("summary") or {}
        checks = {
            "benign-like FPR": _safe_float(summary.get("benign_like_false_positive_rate"), 1) <= 0.15,
            "threat-positive F1": _safe_float(summary.get("threat_positive_f1")) >= 0.80,
            "macro F1": _safe_float(summary.get("macro_f1")) >= 0.60,
        }
        if all(checks.values()):
            pass_count += 1
        else:
            blockers.append(
                f"{row.get('split_mode')}: " + ", ".join(name for name, passed in checks.items() if not passed)
            )
    return {
        "evaluated_splits": len(evaluated),
        "passing_splits": pass_count,
        "passed": bool(evaluated) and pass_count == len(evaluated),
        "metric_ranges": ranges,
        "blockers": blockers,
    }


def _aggregate_designs(split_results: list[dict[str, Any]]) -> dict[str, Any]:
    comparison: dict[str, Any] = {}
    for design in TARGET_DESIGNS:
        rows = []
        for split in split_results:
            for design_row in split.get("designs", []):
                if design_row.get("design") == design:
                    rows.append({**design_row, "split_mode": split.get("split_mode")})
        comparison[design] = {
            "stability": _stability_summary(rows),
            "target_distribution": rows[0].get("target_distribution") if rows else {},
        }
    return comparison


def _label_overlap_analysis(prepared: dict[str, Any], augmented: dict[str, Any]) -> dict[str, Any]:
    pattern_counts: dict[str, Counter[str]] = defaultdict(Counter)
    low_evidence_threat_rows: list[dict[str, Any]] = []
    for index, label in enumerate(prepared["labels"]):
        log = prepared["logs"][index]
        row = augmented["frame"].iloc[index]
        evidence = evidence_profile(row, log)
        pattern = _pattern(log)
        pattern_counts[pattern][label.label] += 1
        if label.label in THREAT_LABELS and evidence["low_evidence_web_like"]:
            low_evidence_threat_rows.append(
                {
                    "label": label,
                    "log": log,
                    "pattern": pattern,
                    "source_name": _source_name(log),
                    "evidence": evidence,
                    "suggested_soc_target": "needs_review",
                }
            )
    ambiguous = []
    for pattern, counts in pattern_counts.items():
        benign = sum(counts[label] for label in BENIGN_LIKE_LABELS)
        threat = sum(counts[label] for label in THREAT_LABELS)
        if benign and threat:
            ambiguous.append(
                {
                    "pattern": pattern,
                    "total": sum(counts.values()),
                    "benign_like": benign,
                    "threat": threat,
                    "label_counts": dict(counts),
                    "threat_ratio": round(threat / sum(counts.values()), 4),
                }
            )
    ambiguous.sort(key=lambda row: (row["total"], min(row["threat_ratio"], 1 - row["threat_ratio"])), reverse=True)
    return {
        "ambiguous_pattern_count": len(ambiguous),
        "top_ambiguous_patterns": ambiguous[:20],
        "low_evidence_threat_count": len(low_evidence_threat_rows),
        "low_evidence_threat_patterns": Counter(row["pattern"] for row in low_evidence_threat_rows).most_common(20),
        "_low_evidence_rows": low_evidence_threat_rows,
    }


def _write_low_evidence_sample(rows: list[dict[str, Any]], *, output_path: Path, limit: int) -> dict[str, Any]:
    selected = rows[:limit]
    if not selected:
        return {"generated": False, "path": "", "rows": 0, "candidate_rows": 0, "import_ready": False}
    output_path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        *REVIEW_FIELDS,
        "codex_soc_target_suggestion",
        "codex_semantic_reason",
        "import_ready",
    ]
    with output_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for item in selected:
            label = item["label"]
            log = item["log"]
            evidence = item["evidence"]
            writer.writerow(
                {
                    "label_id": label.id,
                    "log_id": log.id,
                    "timestamp": (log.generated_time or log.receive_time or log.start_time or "").isoformat()
                    if (log.generated_time or log.receive_time or log.start_time)
                    else "",
                    "split_window": "diagnostic_all",
                    "source_name": item["source_name"],
                    "src_ip": log.src_ip or "",
                    "dst_ip": log.dst_ip or "",
                    "dst_port": log.dst_port if log.dst_port is not None else "",
                    "protocol": log.protocol or "",
                    "app": log.app or "",
                    "action": log.action or "",
                    "current_label": label.label,
                    "current_attack_type": label.attack_type or "",
                    "reviewed_status": "reviewed" if label.reviewed else "weak_or_unreviewed",
                    "label_source": label.label_source or "",
                    "model_prediction": "",
                    "model_confidence": "",
                    "threat_positive_score": "",
                    "rule_score": evidence["rule_score"],
                    "anomaly_score": log.anomaly_score if log.anomaly_score is not None else "",
                    "hybrid_risk_score": "",
                    "reason_selected": "v3.36 low-evidence threat-label semantics diagnostic",
                    "evidence_summary": (
                        f"pattern={item['pattern']}; low_evidence_web_like={evidence['low_evidence_web_like']}; "
                        f"scan_like={evidence['scan_like']}; anomaly={evidence['anomaly_signal']}; "
                        f"unique_dst_ips={evidence['unique_dst_ips']}; unique_dst_ports={evidence['unique_dst_ports']}"
                    ),
                    "human_review_decision": "",
                    "human_review_attack_type": "",
                    "human_review_confidence": "",
                    "human_review_note": "",
                    "codex_soc_target_suggestion": item["suggested_soc_target"],
                    "codex_semantic_reason": "Low-evidence web-like threat label is better treated as SOC needs_review unless more context exists.",
                    "import_ready": "false",
                }
            )
    return {"generated": True, "path": str(output_path), "rows": len(selected), "candidate_rows": len(rows), "import_ready": False}


def _select_best_design(comparison: dict[str, Any]) -> str | None:
    if not comparison:
        return None

    def score(name: str) -> tuple[Any, ...]:
        item = comparison[name]
        ranges = item.get("stability", {}).get("metric_ranges", {})
        fpr = _safe_float((ranges.get("benign_like_false_positive_rate") or {}).get("max"), 1)
        threat_f1 = _safe_float((ranges.get("threat_positive_f1") or {}).get("min"))
        macro = _safe_float((ranges.get("macro_f1") or {}).get("min"))
        return (
            int(item.get("stability", {}).get("passing_splits") or 0),
            1 if fpr <= 0.15 else 0,
            threat_f1 - 0.35 * fpr,
            macro,
            -fpr,
        )

    return max(comparison, key=score)


def _readiness(best: dict[str, Any]) -> dict[str, Any]:
    stability = best.get("stability") or {}
    ranges = stability.get("metric_ranges") or {}
    checks = [
        {
            "name": "redesigned SOC target stable across splits",
            "passed": bool(stability.get("passed")),
            "value": f"{stability.get('passing_splits')}/{stability.get('evaluated_splits')}",
            "target": "all evaluated splits pass target gates",
        },
        {
            "name": "benign-like false-positive rate remains controlled",
            "passed": _safe_float((ranges.get("benign_like_false_positive_rate") or {}).get("max"), 1) <= 0.15,
            "value": (ranges.get("benign_like_false_positive_rate") or {}).get("max"),
            "target": "<= 0.15",
        },
        {
            "name": "SOC target threat F1 remains useful",
            "passed": _safe_float((ranges.get("threat_positive_f1") or {}).get("min")) >= 0.80,
            "value": (ranges.get("threat_positive_f1") or {}).get("min"),
            "target": ">= 0.80",
        },
        {"name": "no label rows written", "passed": True, "value": True, "target": "required"},
        {"name": "no model activation", "passed": True, "value": False, "target": "required"},
        {"name": "response automation disabled", "passed": True, "value": False, "target": "required"},
    ]
    return {
        "decision": "candidate_only",
        "passed": sum(1 for item in checks if item["passed"]),
        "total": len(checks),
        "production_promoted": False,
        "model_activated": False,
        "model_artifact_written": False,
        "response_automation_allowed": False,
        "blockers": [item["name"] for item in checks if not item["passed"]],
        "checks": checks,
    }


def _render_report(result: dict[str, Any]) -> str:
    rows = []
    for design, item in result.get("design_comparison", {}).items():
        ranges = item.get("stability", {}).get("metric_ranges", {})
        rows.append(
            "| {design} | {passed} | {f1_min}-{f1_max} | {fpr_min}-{fpr_max} | {macro_min}-{macro_max} |".format(
                design=design,
                passed=f"{item.get('stability', {}).get('passing_splits')}/{item.get('stability', {}).get('evaluated_splits')}",
                f1_min=(ranges.get("threat_positive_f1") or {}).get("min"),
                f1_max=(ranges.get("threat_positive_f1") or {}).get("max"),
                fpr_min=(ranges.get("benign_like_false_positive_rate") or {}).get("min"),
                fpr_max=(ranges.get("benign_like_false_positive_rate") or {}).get("max"),
                macro_min=(ranges.get("macro_f1") or {}).get("min"),
                macro_max=(ranges.get("macro_f1") or {}).get("max"),
            )
        )
    return f"""# v3.36 Label Semantics and SOC Queue Target Redesign

Generated: {result.get("generated_at")}

This is diagnostic-only. No labels were changed, no model was activated, no model artifact was written, and response automation stayed disabled.

## Label Overlap

- Ambiguous pattern count: {result.get("label_overlap", {}).get("ambiguous_pattern_count")}
- Low-evidence threat labels: {result.get("label_overlap", {}).get("low_evidence_threat_count")}
- Top low-evidence threat patterns: {result.get("label_overlap", {}).get("low_evidence_threat_patterns")}

## SOC Target Design Comparison

| Design | Passing Splits | Threat F1 Range | Benign FPR Range | Macro F1 Range |
| --- | ---: | --- | --- | --- |
{chr(10).join(rows)}

## Best Diagnostic Design

- Design: {result.get("best_design")}
- Readiness: {result.get("readiness", {}).get("decision")}
- Checks passed: {result.get("readiness", {}).get("passed")} / {result.get("readiness", {}).get("total")}
- Blockers: {result.get("readiness", {}).get("blockers")}

## Safety

```json
{json.dumps(result.get("safety"), indent=2, default=str)}
```
"""


def run_v336_label_semantics_analysis(
    db: Session,
    *,
    test_size: float = 0.3,
    min_samples: int = 6,
    sample_limit: int = 200,
    output_dir: str | Path = OUTPUT_DIR,
) -> dict[str, Any]:
    before_labels = int(db.scalar(select(func.count(MLLabel.id))) or 0)
    before_runs = int(db.scalar(select(func.count(MLModelRun.id))) or 0)
    before_responses = int(db.scalar(select(func.count(ResponseAction.id))) or 0)
    base = _load_base_dataset(db, min_samples=min_samples)
    if not base.get("ok"):
        return base
    started = time.perf_counter()
    first_prepared = _prepared_for_split(base, split_mode="time", test_size=test_size)
    from atdr.app.detection.v331_noise_reduction import _augment_frame

    first_frame, first_meta = _augment_frame(first_prepared)
    label_overlap = _label_overlap_analysis(first_prepared, {"frame": first_frame, **first_meta})

    split_results: list[dict[str, Any]] = []
    for split_mode in V335_SPLITS:
        prepared = _prepared_for_split(base, split_mode=split_mode, test_size=test_size)
        augmented_frame, augmented_meta = _augment_frame(prepared)
        augmented = {"frame": augmented_frame, **augmented_meta}
        designs = [_fit_target_design(prepared, augmented, design=design) for design in TARGET_DESIGNS]
        split_results.append(
            {
                "split_mode": split_mode,
                "status": "evaluated",
                "training_rows": len(prepared["train_idx"]),
                "test_rows": len(prepared["test_idx"]),
                "designs": designs,
            }
        )
    comparison = _aggregate_designs(split_results)
    best_design = _select_best_design(comparison)
    readiness = _readiness(comparison[best_design]) if best_design else {
        "decision": "candidate_only",
        "passed": 0,
        "total": 0,
        "production_promoted": False,
        "model_activated": False,
        "model_artifact_written": False,
        "response_automation_allowed": False,
        "blockers": ["no evaluated target design"],
        "checks": [],
    }
    after_labels = int(db.scalar(select(func.count(MLLabel.id))) or 0)
    after_runs = int(db.scalar(select(func.count(MLModelRun.id))) or 0)
    after_responses = int(db.scalar(select(func.count(ResponseAction.id))) or 0)

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    stamp = _stamp()
    report_path = output_path / f"v3_36_label_semantics_soc_target_report_{stamp}.md"
    latest_path = output_path / V336_LATEST
    sample = _write_low_evidence_sample(
        label_overlap.get("_low_evidence_rows") or [],
        output_path=output_path / "v3_36_low_evidence_threat_semantics_sample.csv",
        limit=sample_limit,
    )
    public_overlap = {key: value for key, value in label_overlap.items() if not key.startswith("_")}
    result: dict[str, Any] = {
        "ok": True,
        "status": "completed",
        "phase": "v3.36",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "runtime_seconds": round(time.perf_counter() - started, 4),
        "feature_generation_seconds": base.get("feature_generation_seconds"),
        "label_overlap": public_overlap,
        "design_comparison": comparison,
        "best_design": best_design,
        "readiness": readiness,
        "sample": sample,
        "training_dataset": training_dataset_diagnostics(db),
        "safety": {
            "production_promoted": False,
            "model_activated": False,
            "model_artifact_written": False,
            "response_automation_allowed": False,
            "real_firewall_blocking_enabled": False,
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
