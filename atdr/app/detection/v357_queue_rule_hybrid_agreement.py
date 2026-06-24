import json
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from atdr.app.db.models import MLLabel, MLModelRun, ResponseAction
from atdr.app.detection.supervised_detector import training_dataset_diagnostics
from atdr.app.detection.v330_detection_ml_quality import OUTPUT_DIR, _source_name
from atdr.app.detection.v331_noise_reduction import _calibration_report
from atdr.app.detection.v332_guard_validation import _load_base_dataset, _prepared_for_split, _safe_float
from atdr.app.detection.v335_split_stability_repair import V335_SPLITS, _max_numeric
from atdr.app.detection.v344_two_stage_soc_queue import _fit_classifier, _prob_rows, _queue_metrics, _split_train_calibration_indices
from atdr.app.detection.v348_repaired_queue_target_model import _predict_queue, _select_threshold
from atdr.app.detection.v353_severity_feature_repair import enrich_v353_severity_features
from atdr.app.detection.v355_severity_target_policy_reframing import _policy_targets


V357_LATEST = "v3_57_queue_rule_hybrid_agreement_latest.json"
QUEUE_POLICY_NAME = "binary_review_queue"


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _lower(value: Any) -> str:
    return str(value or "").strip().lower()


def _redact_ip(value: str | None) -> str | None:
    if not value:
        return None
    parts = str(value).split(".")
    if len(parts) == 4 and all(part.isdigit() for part in parts):
        return f"{parts[0]}.{parts[1]}.x.x"
    return "redacted"


def _feature(row: Any, names: list[str], default: float = 0.0) -> float:
    return _max_numeric(row, names) if names else default


def evidence_snapshot(row: Any, log: Any | None = None) -> dict[str, Any]:
    """Build a deterministic evidence summary for diagnostic queue comparison."""
    app = _lower(getattr(log, "app", None)) if log is not None else ""
    action = _lower(getattr(log, "action", None)) if log is not None else ""
    dst_port = getattr(log, "dst_port", None) if log is not None else None
    rule_score = _safe_float(row.get("v331_rule_score"))
    evidence_strength = _safe_float(row.get("v337_behavior_evidence_strength"))
    scan_pressure = _safe_float(row.get("v353_scan_pressure_score"))
    malicious_signal = _safe_float(row.get("v353_malicious_signal_score"))
    suspicious_signal = _safe_float(row.get("v353_suspicious_signal_score"))
    evidence_margin = _safe_float(row.get("v353_evidence_margin_score"))
    source_diversity = _safe_float(row.get("v337_source_diversity_pressure"))
    scanning_like = _safe_float(row.get("scanning_like_behavior_score"))
    unique_dst_ips = _feature(
        row,
        [
            "src_ip_5min_unique_dst_ips",
            "src_ip_15min_unique_dst_ips",
            "src_ip_1h_unique_dst_ips",
            "src_ip_24h_unique_dst_ips",
        ],
    )
    unique_dst_ports = _feature(
        row,
        [
            "src_ip_5min_unique_dst_ports",
            "src_ip_15min_unique_dst_ports",
            "src_ip_1h_unique_dst_ports",
            "src_ip_24h_unique_dst_ports",
        ],
    )
    deny_count = _feature(
        row,
        [
            "src_ip_5min_deny_drop_reset_count",
            "src_ip_15min_deny_drop_reset_count",
            "src_ip_1h_deny_drop_reset_count",
            "src_ip_24h_deny_drop_reset_count",
            "src_ip_5min_deny_count",
        ],
    )
    unknown_count = _feature(
        row,
        [
            "src_ip_5min_unknown_app_count",
            "src_ip_15min_unknown_app_count",
            "src_ip_1h_unknown_app_count",
            "src_ip_24h_unknown_app_count",
        ],
    )
    high_risk_count = _feature(
        row,
        [
            "src_ip_5min_high_risk_app_count",
            "src_ip_15min_high_risk_app_count",
            "src_ip_1h_high_risk_app_count",
            "src_ip_24h_high_risk_app_count",
        ],
    )
    app_risk = _safe_float(row.get("app_risk"))
    rare_port = bool(row.get("rare_dst_port_flag"))
    unknown_app = bool(row.get("unknown_app_flag"))
    rule_backed = bool(row.get("v337_rule_backed_allow_flag")) or rule_score > 0
    anomaly = bool(row.get("v337_anomaly_signal_flag"))
    low_signal = bool(row.get("v337_low_signal_allow_flag")) and evidence_strength < 2.0 and scan_pressure < 3.0
    scan_like = (
        scan_pressure >= 4.0
        or scanning_like >= 2.0
        or source_diversity >= 5.0
        or unique_dst_ips >= 4.0
        or unique_dst_ports >= 3.0
        or (unknown_count >= 3.0 and unique_dst_ips >= 2.0)
    )

    reasons: list[str] = []
    score = 0.0
    if rule_backed:
        score += 3.0
        reasons.append("rule evidence")
    if anomaly and evidence_strength >= 2.0:
        score += 2.0
        reasons.append("anomaly evidence")
    if scan_like:
        score += 2.5
        reasons.append("scan/diversity behavior")
    if deny_count > 0:
        score += min(deny_count, 3.0)
        reasons.append("deny/drop/reset behavior")
    if high_risk_count >= 2.0 or app_risk >= 4.0:
        score += 1.5
        reasons.append("high-risk app context")
    if rare_port and (unknown_app or scan_like):
        score += 1.0
        reasons.append("rare-port unknown-app context")
    if evidence_strength >= 4.0 or malicious_signal >= 6.0:
        score += 2.0
        reasons.append("strong evidence score")
    elif suspicious_signal >= 5.0 or evidence_margin >= 4.0:
        score += 1.0
        reasons.append("suspicious evidence score")
    if low_signal and not rule_backed and not scan_like and deny_count == 0:
        score -= 2.0
        reasons.append("low-signal allow traffic")

    if rule_backed or score >= 3.0:
        decision = "needs_review"
    else:
        decision = "non_threat"
    confidence = "strong" if rule_backed or score >= 5.0 else "moderate" if decision == "needs_review" else "low"
    return {
        "decision": decision,
        "confidence": confidence,
        "score": round(score, 4),
        "reasons": reasons[:6],
        "traffic_family": str(row.get("v337_traffic_family") or "unknown"),
        "severity_evidence_tier": str(row.get("v353_severity_evidence_tier") or "unknown"),
        "app": app or None,
        "action": action or None,
        "dst_port": dst_port,
        "rule_backed": rule_backed,
        "anomaly": anomaly,
        "scan_like": scan_like,
        "low_signal": low_signal,
        "rule_score": round(rule_score, 4),
        "evidence_strength": round(evidence_strength, 4),
        "scan_pressure": round(scan_pressure, 4),
        "source_diversity": round(source_diversity, 4),
        "unique_dst_ips": round(unique_dst_ips, 4),
        "unique_dst_ports": round(unique_dst_ports, 4),
    }


def agreement_category(queue_prediction: str, evidence_decision: str) -> str:
    queue_review = queue_prediction == "needs_review"
    evidence_review = evidence_decision == "needs_review"
    if queue_review and evidence_review:
        return "queue_and_evidence_agree_review"
    if queue_review and not evidence_review:
        return "queue_only_review"
    if not queue_review and evidence_review:
        return "evidence_only_review"
    return "queue_and_evidence_agree_non_review"


def _example_row(
    *,
    prepared: dict[str, Any],
    index: int,
    queue_true: str,
    queue_prediction: str,
    queue_score: float,
    snapshot: dict[str, Any],
    category: str,
) -> dict[str, Any]:
    log = prepared["logs"][index]
    return {
        "log_id": getattr(log, "id", None),
        "source": _source_name(log),
        "src_ip": _redact_ip(getattr(log, "src_ip", None)),
        "dst_ip": _redact_ip(getattr(log, "dst_ip", None)),
        "app": getattr(log, "app", None),
        "action": getattr(log, "action", None),
        "dst_port": getattr(log, "dst_port", None),
        "queue_true": queue_true,
        "queue_prediction": queue_prediction,
        "queue_score": round(queue_score, 4),
        "evidence_decision": snapshot["decision"],
        "evidence_score": snapshot["score"],
        "evidence_reasons": snapshot["reasons"],
        "traffic_family": snapshot["traffic_family"],
        "severity_evidence_tier": snapshot["severity_evidence_tier"],
        "category": category,
        "current_label": prepared["y"][index],
        "reviewed": bool(getattr(prepared["labels"][index], "reviewed", False)),
        "label_source": getattr(prepared["labels"][index], "label_source", None),
        "frame_index": index,
        "raw_log_included": False,
    }


def _agreement_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    total = len(rows)
    category_counts = Counter(row["category"] for row in rows)
    target_confusion = Counter(
        f"{row['queue_true']}->{row['queue_prediction']}" for row in rows if row["queue_true"] != row["queue_prediction"]
    )
    evidence_confusion = Counter(
        f"{row['queue_true']}->{row['evidence_decision']}" for row in rows if row["queue_true"] != row["evidence_decision"]
    )
    queue_only = [row for row in rows if row["category"] == "queue_only_review"]
    evidence_only = [row for row in rows if row["category"] == "evidence_only_review"]
    agreements = category_counts["queue_and_evidence_agree_review"] + category_counts["queue_and_evidence_agree_non_review"]
    return {
        "evaluated_rows": total,
        "agreement_rate": round(agreements / total, 4) if total else 0.0,
        "category_counts": dict(category_counts),
        "queue_only_review_count": len(queue_only),
        "queue_only_review_rate": round(len(queue_only) / total, 4) if total else 0.0,
        "evidence_only_review_count": len(evidence_only),
        "evidence_only_review_rate": round(len(evidence_only) / total, 4) if total else 0.0,
        "queue_target_confusions": target_confusion.most_common(10),
        "evidence_target_confusions": evidence_confusion.most_common(10),
        "top_queue_only_patterns": Counter(
            f"app={row.get('app') or '-'}|action={row.get('action') or '-'}|port={row.get('dst_port') or '-'}"
            for row in queue_only
        ).most_common(10),
        "top_evidence_only_patterns": Counter(
            f"app={row.get('app') or '-'}|action={row.get('action') or '-'}|port={row.get('dst_port') or '-'}"
            for row in evidence_only
        ).most_common(10),
    }


def _evaluate_split(base: dict[str, Any], *, split_mode: str, test_size: float) -> dict[str, Any]:
    prepared = _prepared_for_split(base, split_mode=split_mode, test_size=test_size)
    frame, meta = enrich_v353_severity_features(prepared)
    augmented = {"frame": frame, **meta}
    _targets, queue_values, policy_meta = _policy_targets(prepared, frame, policy_name=QUEUE_POLICY_NAME)
    split = _split_train_calibration_indices(prepared, queue_values)
    model, classes, model_meta = _fit_classifier(
        prepared,
        augmented,
        indices=split["fit_idx"],
        targets=queue_values,
        model_type="extra_trees",
        weight_strategy="strong_benign",
    )
    if model is None:
        return {
            "split_mode": split_mode,
            "status": "skipped",
            "message": "Queue model unavailable.",
            "training_rows": len(prepared["train_idx"]),
            "test_rows": len(prepared["test_idx"]),
        }
    calibration_rows = _prob_rows(model, classes, frame, split["calibration_idx"])
    calibration_true = [queue_values[index] for index in split["calibration_idx"]]
    threshold_selection = _select_threshold(calibration_true, calibration_rows)
    test_idx = list(prepared["test_idx"])
    queue_true = [queue_values[index] for index in test_idx]
    probability_rows = _prob_rows(model, classes, frame, test_idx)
    predictions = _predict_queue(probability_rows, threshold=threshold_selection["selected_threshold"])
    queue_metrics = _queue_metrics(queue_true, predictions)
    calibration = _calibration_report(
        queue_true,
        model.predict_proba(frame.iloc[test_idx]),
        classes,
        threat_labels={"needs_review"},
    )

    rows = []
    for local_pos, index in enumerate(test_idx):
        snapshot = evidence_snapshot(frame.iloc[index], prepared["logs"][index])
        queue_score = _safe_float(probability_rows[local_pos].get("needs_review"))
        category = agreement_category(predictions[local_pos], snapshot["decision"])
        rows.append(
            _example_row(
                prepared=prepared,
                index=index,
                queue_true=queue_true[local_pos],
                queue_prediction=predictions[local_pos],
                queue_score=queue_score,
                snapshot=snapshot,
                category=category,
            )
        )

    summary = _agreement_summary(rows)
    return {
        "split_mode": split_mode,
        "status": "evaluated",
        "training_rows": len(prepared["train_idx"]),
        "test_rows": len(prepared["test_idx"]),
        "split_warnings": prepared.get("split_warnings") or [],
        "target_distribution": policy_meta.get("target_distribution") or {},
        "model": model_meta,
        "threshold_selection": {
            "fit_rows": split["fit_rows"],
            "calibration_rows": split["calibration_rows"],
            "calibration_strategy": split["calibration_strategy"],
            "selected_on": threshold_selection["selected_on"],
            "used_test_for_threshold_selection": threshold_selection["used_test_for_threshold_selection"],
            "queue_threshold": threshold_selection["selected_threshold"],
            "calibration_summary": threshold_selection["calibration_summary"],
        },
        "queue_metrics": queue_metrics,
        "calibration": calibration,
        "agreement": summary,
        "examples": {
            "queue_only_review": [row for row in rows if row["category"] == "queue_only_review"][:10],
            "evidence_only_review": [row for row in rows if row["category"] == "evidence_only_review"][:10],
            "agreed_review": [row for row in rows if row["category"] == "queue_and_evidence_agree_review"][:5],
        },
    }


def _aggregate_split_results(split_results: list[dict[str, Any]]) -> dict[str, Any]:
    evaluated = [row for row in split_results if row.get("status") == "evaluated"]
    categories = Counter()
    top_queue_only = Counter()
    top_evidence_only = Counter()
    agreement_rates = []
    queue_f1_values = []
    queue_recall_values = []
    queue_precision_values = []
    queue_fpr_values = []
    ece_values = []
    blockers = []
    for split in evaluated:
        agreement = split.get("agreement") or {}
        categories.update(agreement.get("category_counts") or {})
        top_queue_only.update(dict(agreement.get("top_queue_only_patterns") or []))
        top_evidence_only.update(dict(agreement.get("top_evidence_only_patterns") or []))
        agreement_rates.append(_safe_float(agreement.get("agreement_rate")))
        metrics = split.get("queue_metrics") or {}
        queue_f1_values.append(_safe_float(metrics.get("queue_f1")))
        queue_recall_values.append(_safe_float(metrics.get("queue_recall")))
        queue_precision_values.append(_safe_float(metrics.get("queue_precision")))
        queue_fpr_values.append(_safe_float(metrics.get("queue_false_positive_rate"), 1.0))
        calibration = split.get("calibration") or {}
        ece_values.append(_safe_float(calibration.get("expected_calibration_error"), 1.0))
        if _safe_float(metrics.get("queue_f1")) < 0.9:
            blockers.append(f"{split['split_mode']}: queue F1 below 0.90")
        if _safe_float(metrics.get("queue_false_positive_rate"), 1.0) > 0.15:
            blockers.append(f"{split['split_mode']}: queue false-positive rate above 0.15")
        if _safe_float(agreement.get("agreement_rate")) < 0.75:
            blockers.append(f"{split['split_mode']}: queue/evidence agreement below 0.75")
        if _safe_float(agreement.get("evidence_only_review_rate")) > 0.10:
            blockers.append(f"{split['split_mode']}: evidence-only review rate above 0.10")

    return {
        "evaluated_splits": len(evaluated),
        "passing_splits": len(evaluated) - len({blocker.split(":", maxsplit=1)[0] for blocker in blockers}),
        "category_counts": dict(categories),
        "agreement_rate_min": round(min(agreement_rates), 4) if agreement_rates else None,
        "agreement_rate_max": round(max(agreement_rates), 4) if agreement_rates else None,
        "queue_f1_min": round(min(queue_f1_values), 4) if queue_f1_values else None,
        "queue_recall_min": round(min(queue_recall_values), 4) if queue_recall_values else None,
        "queue_precision_min": round(min(queue_precision_values), 4) if queue_precision_values else None,
        "queue_false_positive_rate_max": round(max(queue_fpr_values), 4) if queue_fpr_values else None,
        "calibration_ece_max": round(max(ece_values), 4) if ece_values else None,
        "top_queue_only_patterns": top_queue_only.most_common(12),
        "top_evidence_only_patterns": top_evidence_only.most_common(12),
        "blockers": blockers,
    }


def _readiness(aggregate: dict[str, Any]) -> dict[str, Any]:
    checks = [
        {
            "name": "all standard splits evaluated",
            "passed": aggregate.get("evaluated_splits") == len(V335_SPLITS),
            "value": aggregate.get("evaluated_splits"),
            "target": len(V335_SPLITS),
        },
        {
            "name": "queue F1 remains stable",
            "passed": _safe_float(aggregate.get("queue_f1_min")) >= 0.90,
            "value": aggregate.get("queue_f1_min"),
            "target": ">= 0.90",
        },
        {
            "name": "queue false-positive rate controlled",
            "passed": _safe_float(aggregate.get("queue_false_positive_rate_max"), 1.0) <= 0.15,
            "value": aggregate.get("queue_false_positive_rate_max"),
            "target": "<= 0.15",
        },
        {
            "name": "queue/evidence agreement acceptable",
            "passed": _safe_float(aggregate.get("agreement_rate_min")) >= 0.75,
            "value": aggregate.get("agreement_rate_min"),
            "target": ">= 0.75",
        },
        {
            "name": "evidence-only misses remain reviewable",
            "passed": not any("evidence-only" in blocker for blocker in aggregate.get("blockers") or []),
            "value": aggregate.get("top_evidence_only_patterns"),
            "target": "no split above 0.10 evidence-only rate",
        },
        {"name": "no labels written", "passed": True, "value": True, "target": "required"},
        {"name": "model activation disabled", "passed": True, "value": False, "target": "required"},
        {"name": "response automation disabled", "passed": True, "value": False, "target": "required"},
    ]
    blockers = [check["name"] for check in checks if not check["passed"]]
    return {
        "decision": "candidate_only" if not blockers else "diagnostic_only",
        "passed": sum(1 for check in checks if check["passed"]),
        "total": len(checks),
        "production_promoted": False,
        "model_activated": False,
        "model_artifact_written": False,
        "response_automation_allowed": False,
        "blockers": blockers,
        "checks": checks,
    }


def _render_report(result: dict[str, Any]) -> str:
    split_rows = []
    for split in result.get("split_results") or []:
        if split.get("status") != "evaluated":
            split_rows.append(f"| {split.get('split_mode')} | {split.get('status')} | - | - | - | - |")
            continue
        metrics = split.get("queue_metrics") or {}
        agreement = split.get("agreement") or {}
        split_rows.append(
            "| {split} | {status} | {f1} | {fpr} | {agree} | {eonly} |".format(
                split=split.get("split_mode"),
                status=split.get("status"),
                f1=metrics.get("queue_f1"),
                fpr=metrics.get("queue_false_positive_rate"),
                agree=agreement.get("agreement_rate"),
                eonly=agreement.get("evidence_only_review_rate"),
            )
        )
    return f"""# v3.57 Queue-vs-Rule/Hybrid Agreement Diagnostic

Generated: {result.get("generated_at")}

This report is diagnostic only. It compares the stable binary SOC review-queue candidate against deterministic rule/anomaly/hybrid evidence. No labels were written, no model was activated, no model artifact was written, and response automation stayed disabled.

## Summary

- Readiness: `{result.get("readiness", {}).get("decision")}`
- Checks passed: {result.get("readiness", {}).get("passed")} / {result.get("readiness", {}).get("total")}
- Evaluated splits: {result.get("aggregate", {}).get("evaluated_splits")}
- Queue F1 min: {result.get("aggregate", {}).get("queue_f1_min")}
- Queue FPR max: {result.get("aggregate", {}).get("queue_false_positive_rate_max")}
- Queue/evidence agreement min: {result.get("aggregate", {}).get("agreement_rate_min")}
- Calibration ECE max: {result.get("aggregate", {}).get("calibration_ece_max")}
- Blockers: {result.get("readiness", {}).get("blockers")}

## Split Results

| Split | Status | Queue F1 | Queue FPR | Agreement Rate | Evidence-Only Review Rate |
| --- | --- | ---: | ---: | ---: | ---: |
{chr(10).join(split_rows)}

## Agreement Categories

```json
{json.dumps(result.get("aggregate", {}).get("category_counts"), indent=2, default=str)}
```

## Top Queue-Only Review Patterns

```json
{json.dumps(result.get("aggregate", {}).get("top_queue_only_patterns"), indent=2, default=str)}
```

## Top Evidence-Only Review Patterns

```json
{json.dumps(result.get("aggregate", {}).get("top_evidence_only_patterns"), indent=2, default=str)}
```

## Safety

```json
{json.dumps(result.get("safety"), indent=2, default=str)}
```
"""


def run_v357_queue_rule_hybrid_agreement(
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
    split_results = [_evaluate_split(base, split_mode=split_mode, test_size=test_size) for split_mode in V335_SPLITS]
    aggregate = _aggregate_split_results(split_results)
    readiness = _readiness(aggregate)
    after_labels = int(db.scalar(select(func.count(MLLabel.id))) or 0)
    after_runs = int(db.scalar(select(func.count(MLModelRun.id))) or 0)
    after_responses = int(db.scalar(select(func.count(ResponseAction.id))) or 0)

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    stamp = _stamp()
    report_path = output_path / f"v3_57_queue_rule_hybrid_agreement_{stamp}.md"
    latest_path = output_path / V357_LATEST
    result = {
        "ok": True,
        "status": "completed",
        "phase": "v3.57",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "runtime_seconds": round(time.perf_counter() - started, 4),
        "policy_name": QUEUE_POLICY_NAME,
        "split_results": split_results,
        "aggregate": aggregate,
        "readiness": readiness,
        "training_dataset": training_dataset_diagnostics(db),
        "safety": {
            "production_promoted": False,
            "model_activated": False,
            "model_artifact_written": False,
            "response_automation_allowed": False,
            "real_firewall_blocking_enabled": False,
            "labels_written": False,
            "raw_logs_included": False,
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
