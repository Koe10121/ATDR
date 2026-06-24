import csv
import json
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from atdr.app.db.models import MLLabel, MLModelRun, ResponseAction
from atdr.app.detection.v330_detection_ml_quality import (
    BENIGN_LIKE_LABELS,
    OUTPUT_DIR,
    REVIEW_FIELDS,
    THREAT_LABELS,
    _log_timestamp,
    _source_name,
)
from atdr.app.detection.v331_noise_reduction import (
    _apply_low_signal_benign_guard,
    _calibration_report,
    _metric_bundle,
    _profile_summary,
)
from atdr.app.detection.v332_guard_validation import (
    V332_PROFILE,
    V332_STRATEGY,
    _aggregate_guard_safety,
    _false_positive_patterns,
    _fit_candidate,
    _load_base_dataset,
    _prepared_for_split,
    _profile_predictions,
    _safe_float,
    _stability_summary,
    _threshold_sweep,
)
from atdr.app.detection.supervised_detector import training_dataset_diagnostics


V333_STRATEGY = "flat_5class_extra_trees_current_with_evidence_aware_low_signal_guard"
V333_OUTPUT_LATEST = "v3_33_guard_refinement_latest.json"
V333_SPLITS = ["time", "grouped_stratified", "random_seed_7", "random_seed_17", "random_seed_42"]


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _max_numeric(row: Any, names: list[str]) -> float:
    return max((_safe_float(row.get(name)) for name in names), default=0.0)


def _evidence_summary(row: Any, log: Any, rule_codes: set[str], probabilities: dict[str, float]) -> dict[str, Any]:
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
    threat_score = _safe_float(probabilities.get("suspicious")) + _safe_float(probabilities.get("malicious"))
    malicious_score = _safe_float(probabilities.get("malicious"))
    anomaly_score = _safe_float(getattr(log, "anomaly_score", None), 0.0)
    anomaly_signal = bool(getattr(log, "is_anomaly", False)) or anomaly_score <= -0.20
    scan_like = (
        unique_dst_ips >= 4
        or unique_dst_ports >= 3
        or (event_count >= 12 and (unique_dst_ips >= 3 or unique_dst_ports >= 2))
        or deny_count > 0
        or unknown_count >= 3
        or high_risk_count >= 2
    )
    high_model_confidence = threat_score >= 0.75 or malicious_score >= 0.45
    strong_evidence = (
        bool(rule_codes)
        or rule_score >= 15
        or anomaly_signal
        or scan_like
        or high_model_confidence
    )
    return {
        "unique_dst_ips": unique_dst_ips,
        "unique_dst_ports": unique_dst_ports,
        "event_count": event_count,
        "deny_count": deny_count,
        "unknown_count": unknown_count,
        "high_risk_count": high_risk_count,
        "rule_score": rule_score,
        "threat_score": round(threat_score, 4),
        "malicious_score": round(malicious_score, 4),
        "high_model_confidence": high_model_confidence,
        "anomaly_signal": anomaly_signal,
        "scan_like": scan_like,
        "strong_evidence": strong_evidence,
    }


def _apply_evidence_aware_low_signal_guard(
    prepared: dict[str, Any],
    augmented: dict[str, Any],
    predictions: list[str],
    probability_rows: list[dict[str, float]],
) -> list[str]:
    guarded: list[str] = []
    frame = augmented["frame"]
    for position, prediction in enumerate(predictions):
        if prediction not in THREAT_LABELS:
            guarded.append(prediction)
            continue
        absolute_index = prepared["test_idx"][position]
        row = frame.iloc[absolute_index]
        log = prepared["test_logs"][position]
        rule_codes = set(augmented["rule_code_rows"][absolute_index])
        low_signal_candidate = bool(row.get("v331_quic_443_allow_no_rule_flag")) or bool(
            row.get("v331_benign_network_utility_no_rule_flag")
        )
        if not low_signal_candidate:
            guarded.append(prediction)
            continue
        if bool(row.get("v331_quic_443_allow_with_rule_flag")) or rule_codes:
            guarded.append(prediction)
            continue
        evidence = _evidence_summary(row, log, rule_codes, probability_rows[position])
        if evidence["strong_evidence"]:
            guarded.append(prediction)
            continue
        guarded.append("benign")
    return guarded


def _suppression_report(
    prepared: dict[str, Any],
    augmented: dict[str, Any],
    before: list[str],
    after: list[str],
    probability_rows: list[dict[str, float]],
) -> dict[str, Any]:
    frame = augmented["frame"]
    rows: list[dict[str, Any]] = []
    for position, (actual, predicted_before, predicted_after) in enumerate(
        zip(prepared["y_test"], before, after, strict=False)
    ):
        if predicted_before not in THREAT_LABELS or predicted_after in THREAT_LABELS:
            continue
        absolute_index = prepared["test_idx"][position]
        row = frame.iloc[absolute_index]
        log = prepared["test_logs"][position]
        rule_codes = set(augmented["rule_code_rows"][absolute_index])
        evidence = _evidence_summary(row, log, rule_codes, probability_rows[position])
        rows.append(
            {
                "actual": actual,
                "before": predicted_before,
                "after": predicted_after,
                "pattern": f"app={log.app or '-'}|action={log.action or '-'}|port={log.dst_port or '-'}",
                "source_name": _source_name(log),
                "rule_codes": sorted(rule_codes),
                "quic_no_rule": bool(row.get("v331_quic_443_allow_no_rule_flag")),
                "quic_with_rule": bool(row.get("v331_quic_443_allow_with_rule_flag")),
                "network_utility_no_rule": bool(row.get("v331_benign_network_utility_no_rule_flag")),
                "evidence": evidence,
            }
        )
    actual_threat = [row for row in rows if row["actual"] in THREAT_LABELS]
    return {
        "suppressed_total": len(rows),
        "suppressed_actual_threat": len(actual_threat),
        "suppressed_actual_threat_examples": actual_threat[:20],
        "suppressed_rule_bearing_quic": sum(1 for row in rows if row["quic_with_rule"]),
        "suppressed_quic_no_rule_threat_rows": sum(1 for row in actual_threat if row["quic_no_rule"]),
        "suppressed_ping_no_rule_threat_rows": sum(1 for row in actual_threat if row["network_utility_no_rule"]),
        "top_suppressed_patterns": Counter(row["pattern"] for row in rows).most_common(10),
    }


def _evaluate_variant(
    prepared: dict[str, Any],
    augmented: dict[str, Any],
    *,
    variant_name: str,
    predictions: list[str],
    unguarded_predictions: list[str],
    probability_rows: list[dict[str, float]],
    calibration: dict[str, Any],
) -> dict[str, Any]:
    metrics = _metric_bundle(
        prepared,
        y_true=prepared["y_test"],
        predictions=predictions,
        labels_order=prepared["labels_order"],
        threat_labels=set(THREAT_LABELS),
    )
    false_positive_patterns = _false_positive_patterns(prepared, augmented, predictions)
    return {
        "variant": variant_name,
        "summary": _profile_summary(metrics),
        "metrics": metrics,
        "calibration": calibration,
        "false_positive_patterns": {key: value for key, value in false_positive_patterns.items() if not key.startswith("_")},
        "guard_safety": _suppression_report(
            prepared,
            augmented,
            unguarded_predictions,
            predictions,
            probability_rows,
        ),
        "_residual_rows": false_positive_patterns.get("_rows") or [],
    }


def _variant_readiness(stability: dict[str, Any], guard_safety: dict[str, Any], calibration: dict[str, Any]) -> dict[str, Any]:
    checks = [
        {
            "name": "independent split stability acceptable",
            "passed": bool(stability.get("passed")),
            "value": f"{stability.get('passing_splits')}/{stability.get('evaluated_splits')}",
            "target": "all evaluated splits pass FPR/F1/recall gates",
        },
        {
            "name": "benign-like false-positive rate stable",
            "passed": _safe_float((stability.get("metric_ranges") or {}).get("benign_like_false_positive_rate", {}).get("max"), 1)
            <= 0.15,
            "value": (stability.get("metric_ranges") or {}).get("benign_like_false_positive_rate", {}).get("max"),
            "target": "<= 0.15 across splits",
        },
        {
            "name": "confidence calibration acceptable",
            "passed": bool(calibration.get("passed")),
            "value": calibration.get("status"),
            "target": "passed",
        },
        {
            "name": "guard suppresses zero actual threats",
            "passed": int(guard_safety.get("suppressed_actual_threat") or 0) == 0,
            "value": guard_safety.get("suppressed_actual_threat"),
            "target": "0",
        },
        {
            "name": "guard suppresses zero rule-bearing threats",
            "passed": int(guard_safety.get("suppressed_rule_bearing_quic") or 0) == 0,
            "value": guard_safety.get("suppressed_rule_bearing_quic"),
            "target": "0",
        },
        {"name": "model activation disabled", "passed": True, "value": False, "target": "required"},
        {"name": "response automation disabled", "passed": True, "value": False, "target": "required"},
    ]
    return {
        "decision": "candidate_only",
        "passed": sum(1 for item in checks if item["passed"]),
        "total": len(checks),
        "production_promoted": False,
        "model_activated": False,
        "response_automation_allowed": False,
        "blockers": [item["name"] for item in checks if not item["passed"]],
        "checks": checks,
    }


def _aggregate_variant_split_results(split_results: list[dict[str, Any]]) -> dict[str, Any]:
    variant_names = sorted(
        {
            variant["variant"]
            for split in split_results
            for variant in split.get("variants", [])
            if split.get("status") == "evaluated"
        }
    )
    comparison: dict[str, Any] = {}
    for variant_name in variant_names:
        variant_splits = []
        guard_splits = []
        calibrations = []
        for split in split_results:
            if split.get("status") != "evaluated":
                continue
            for variant in split.get("variants", []):
                if variant["variant"] != variant_name:
                    continue
                variant_splits.append(
                    {
                        "split_mode": split["split_mode"],
                        "status": "evaluated",
                        "training_rows": split["training_rows"],
                        "test_rows": split["test_rows"],
                        "summary": variant["summary"],
                        "guard_safety": variant["guard_safety"],
                    }
                )
                guard_splits.append({"guard_safety": variant["guard_safety"]})
                calibrations.append(variant.get("calibration") or {})
        stability = _stability_summary(variant_splits)
        guard_safety = _aggregate_guard_safety(guard_splits)
        best_calibration = max(
            calibrations,
            key=lambda item: (
                1 if item.get("passed") else 0,
                -_safe_float(item.get("expected_calibration_error"), 1),
                -_safe_float(item.get("max_confidence_accuracy_gap"), 1),
            ),
            default={},
        )
        comparison[variant_name] = {
            "stability": stability,
            "guard_safety": guard_safety,
            "best_calibration": best_calibration,
            "readiness": _variant_readiness(stability, guard_safety, best_calibration),
        }
    return comparison


def _select_best_variant(comparison: dict[str, Any]) -> str:
    def score(name: str) -> tuple:
        item = comparison[name]
        ranges = item["stability"].get("metric_ranges") or {}
        max_fpr = _safe_float((ranges.get("benign_like_false_positive_rate") or {}).get("max"), 1)
        min_f1 = _safe_float((ranges.get("threat_positive_f1") or {}).get("min"))
        min_suspicious = _safe_float((ranges.get("suspicious_recall") or {}).get("min"))
        min_malicious = _safe_float((ranges.get("malicious_recall") or {}).get("min"))
        suppressed = int(item["guard_safety"].get("suppressed_actual_threat") or 0)
        return (
            1 if max_fpr <= 0.15 else 0,
            item["stability"].get("passing_splits") or 0,
            -max_fpr,
            min_f1,
            min_suspicious,
            min_malicious,
            -suppressed,
            item["readiness"]["passed"],
        )

    return max(
        comparison,
        key=score,
    )


def _write_residual_review_sample(rows: list[dict[str, Any]], *, output_path: Path, limit: int) -> dict[str, Any]:
    selected = rows[:limit]
    if not selected:
        return {"generated": False, "path": "", "rows": 0, "candidate_rows": 0, "import_ready": False}
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=REVIEW_FIELDS)
        writer.writeheader()
        for row in selected:
            log = row["log"]
            label = row["label"]
            timestamp = _log_timestamp(log)
            writer.writerow(
                {
                    "label_id": label.id,
                    "log_id": log.id,
                    "timestamp": timestamp.isoformat() if timestamp else "",
                    "split_window": "diagnostic_test",
                    "source_name": _source_name(log),
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
                    "model_prediction": row["predicted"],
                    "model_confidence": "",
                    "threat_positive_score": "",
                    "rule_score": "",
                    "anomaly_score": log.anomaly_score if log.anomaly_score is not None else "",
                    "hybrid_risk_score": "",
                    "reason_selected": "v3.33 residual false positive after evidence-aware guard refinement",
                    "evidence_summary": (
                        f"actual={row['actual']}; predicted={row['predicted']}; "
                        f"pattern={row['pattern']}; rules={','.join(row['rule_codes']) or 'none'}"
                    ),
                    "human_review_decision": "",
                    "human_review_attack_type": "",
                    "human_review_confidence": "",
                    "human_review_note": "",
                }
            )
    return {
        "generated": True,
        "path": str(output_path),
        "rows": len(selected),
        "candidate_rows": len(rows),
        "import_ready": False,
    }


def _load_v332_suppression_context(output_dir: str | Path) -> dict[str, Any]:
    latest = Path(output_dir) / "v3_32_guard_validation_latest.json"
    if not latest.exists():
        return {"available": False, "message": "v3.32 latest summary not found."}
    data = json.loads(latest.read_text(encoding="utf-8"))
    guard = data.get("guard_safety") or {}
    examples = guard.get("suppressed_actual_threat_examples") or []
    return {
        "available": True,
        "suppressed_actual_threat": guard.get("suppressed_actual_threat"),
        "suppressed_rule_bearing_quic": guard.get("suppressed_rule_bearing_quic"),
        "top_patterns": guard.get("top_suppressed_patterns"),
        "example_pattern_counts": Counter(row.get("pattern", "unknown") for row in examples).most_common(10),
        "example_labels": Counter(row.get("actual", "unknown") for row in examples).most_common(),
        "examples": examples[:10],
    }


def _render_guard_report(result: dict[str, Any]) -> str:
    variant_rows = []
    for name, item in result.get("variant_comparison", {}).items():
        ranges = item.get("stability", {}).get("metric_ranges", {})
        variant_rows.append(
            "| {name} | {passed} | {f1_min}-{f1_max} | {fpr_min}-{fpr_max} | {susp_min}-{susp_max} | {mal_min}-{mal_max} | {suppressed} | {cal} |".format(
                name=name,
                passed=f"{item.get('stability', {}).get('passing_splits')}/{item.get('stability', {}).get('evaluated_splits')}",
                f1_min=(ranges.get("threat_positive_f1") or {}).get("min"),
                f1_max=(ranges.get("threat_positive_f1") or {}).get("max"),
                fpr_min=(ranges.get("benign_like_false_positive_rate") or {}).get("min"),
                fpr_max=(ranges.get("benign_like_false_positive_rate") or {}).get("max"),
                susp_min=(ranges.get("suspicious_recall") or {}).get("min"),
                susp_max=(ranges.get("suspicious_recall") or {}).get("max"),
                mal_min=(ranges.get("malicious_recall") or {}).get("min"),
                mal_max=(ranges.get("malicious_recall") or {}).get("max"),
                suppressed=item.get("guard_safety", {}).get("suppressed_actual_threat"),
                cal=item.get("best_calibration", {}).get("status"),
            )
        )
    return f"""# v3.33 Evidence-Aware Low-Signal Guard Refinement

Generated: {result.get("generated_at")}

This is diagnostic-only work. No model was activated, no model artifact was written, and response automation stayed disabled.

## v3.32 Suppression Root Cause

```json
{json.dumps(result.get("v3_32_suppression_context"), indent=2, default=str)}
```

## Variant Comparison

| Variant | Passing Splits | Threat F1 Range | Benign FPR Range | Suspicious Recall Range | Malicious Recall Range | Suppressed Actual Threats | Best Calibration |
| --- | ---: | --- | --- | --- | --- | ---: | --- |
{chr(10).join(variant_rows)}

## Best Diagnostic Variant

- Variant: {result.get("best_variant")}
- Readiness: {result.get("readiness", {}).get("decision")}
- Checks passed: {result.get("readiness", {}).get("passed")} / {result.get("readiness", {}).get("total")}
- Blockers: {result.get("readiness", {}).get("blockers")}

## Refined Guard Behavior

The refined guard only suppresses no-rule QUIC/443 or network-utility traffic when rule evidence, scan-like diversity, anomaly evidence, and high model threat confidence are all absent.

```json
{json.dumps((result.get("variant_comparison") or {}).get("refined_evidence_guard", {}).get("guard_safety", {}), indent=2, default=str)}
```

## Safety

```json
{json.dumps(result.get("safety"), indent=2, default=str)}
```
"""


def _render_split_stability_report(result: dict[str, Any]) -> str:
    rows = []
    for split in result.get("split_results", []):
        for variant in split.get("variants", []):
            summary = variant.get("summary") or {}
            rows.append(
                "| {split} | {variant} | {precision} | {recall} | {f1} | {fpr} | {suspicious} | {malicious} | {macro} | {weighted} | {fp} | {fn} | {queue} | {suppressed} |".format(
                    split=split.get("split_mode"),
                    variant=variant.get("variant"),
                    precision=summary.get("threat_positive_precision"),
                    recall=summary.get("threat_positive_recall"),
                    f1=summary.get("threat_positive_f1"),
                    fpr=summary.get("benign_like_false_positive_rate"),
                    suspicious=summary.get("suspicious_recall"),
                    malicious=summary.get("malicious_recall"),
                    macro=summary.get("macro_f1"),
                    weighted=summary.get("weighted_f1"),
                    fp=summary.get("false_positives"),
                    fn=summary.get("false_negatives"),
                    queue=summary.get("review_queue_size_estimate"),
                    suppressed=variant.get("guard_safety", {}).get("suppressed_actual_threat"),
                )
            )
    return f"""# v3.33 Split Stability Report

Generated: {result.get("generated_at")}

| Split | Variant | Threat Precision | Threat Recall | Threat F1 | Benign FPR | Suspicious Recall | Malicious Recall | Macro F1 | Weighted F1 | FP | FN | Queue | Suppressed Threats |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
{chr(10).join(rows)}

## Calibration

```json
{json.dumps(result.get("calibration"), indent=2, default=str)}
```
"""


def run_v333_guard_refinement(
    db: Session,
    *,
    test_size: float = 0.3,
    min_samples: int = 6,
    review_limit: int = 100,
    output_dir: str | Path = OUTPUT_DIR,
) -> dict[str, Any]:
    before_runs = int(db.scalar(select(func.count(MLModelRun.id))) or 0)
    before_responses = int(db.scalar(select(func.count(ResponseAction.id))) or 0)
    base = _load_base_dataset(db, min_samples=min_samples)
    if not base.get("ok"):
        return base

    split_results: list[dict[str, Any]] = []
    residual_rows_for_best: list[dict[str, Any]] = []
    calibration_by_variant: dict[str, list[dict[str, Any]]] = {}
    started = time.perf_counter()
    for split_mode in V333_SPLITS:
        prepared = _prepared_for_split(base, split_mode=split_mode, test_size=test_size)
        from atdr.app.detection.v331_noise_reduction import _augment_frame

        augmented_frame, augmented_meta = _augment_frame(prepared)
        augmented = {"frame": augmented_frame, **augmented_meta}
        uncalibrated = _fit_candidate(prepared, augmented)
        sigmoid = _fit_candidate(prepared, augmented, calibration_method="sigmoid")
        isotonic = _fit_candidate(prepared, augmented, calibration_method="isotonic") if split_mode == "time" else None
        if uncalibrated.get("status") != "evaluated":
            split_results.append({"split_mode": split_mode, "status": uncalibrated.get("status"), "message": uncalibrated.get("message")})
            continue

        unguarded = uncalibrated["_unguarded_predictions"]
        current_guard = _apply_low_signal_benign_guard(prepared, augmented, unguarded)
        refined_guard = _apply_evidence_aware_low_signal_guard(
            prepared,
            augmented,
            unguarded,
            uncalibrated["_probability_rows"],
        )
        variants = [
            _evaluate_variant(
                prepared,
                augmented,
                variant_name="threshold_only_no_guard",
                predictions=unguarded,
                unguarded_predictions=unguarded,
                probability_rows=uncalibrated["_probability_rows"],
                calibration=uncalibrated["calibration"],
            ),
            _evaluate_variant(
                prepared,
                augmented,
                variant_name="current_v331_guard",
                predictions=current_guard,
                unguarded_predictions=unguarded,
                probability_rows=uncalibrated["_probability_rows"],
                calibration=uncalibrated["calibration"],
            ),
            _evaluate_variant(
                prepared,
                augmented,
                variant_name="refined_evidence_guard",
                predictions=refined_guard,
                unguarded_predictions=unguarded,
                probability_rows=uncalibrated["_probability_rows"],
                calibration=uncalibrated["calibration"],
            ),
        ]
        if sigmoid.get("status") == "evaluated":
            sigmoid_unguarded = sigmoid["_unguarded_predictions"]
            sigmoid_refined = _apply_evidence_aware_low_signal_guard(
                prepared,
                augmented,
                sigmoid_unguarded,
                sigmoid["_probability_rows"],
            )
            variants.extend(
                [
                    _evaluate_variant(
                        prepared,
                        augmented,
                        variant_name="calibrated_threshold_only_no_guard",
                        predictions=sigmoid_unguarded,
                        unguarded_predictions=sigmoid_unguarded,
                        probability_rows=sigmoid["_probability_rows"],
                        calibration=sigmoid["calibration"],
                    ),
                    _evaluate_variant(
                        prepared,
                        augmented,
                        variant_name="refined_evidence_guard_sigmoid_calibrated",
                        predictions=sigmoid_refined,
                        unguarded_predictions=sigmoid_unguarded,
                        probability_rows=sigmoid["_probability_rows"],
                        calibration=sigmoid["calibration"],
                    ),
                ]
            )
        if isotonic and isotonic.get("status") == "evaluated":
            calibration_by_variant.setdefault("isotonic_time_split", []).append(isotonic["calibration"])
        for variant in variants:
            calibration_by_variant.setdefault(variant["variant"], []).append(variant.get("calibration") or {})
        split_results.append(
            {
                "split_mode": split_mode,
                "status": "evaluated",
                "training_rows": len(prepared["train_idx"]),
                "test_rows": len(prepared["test_idx"]),
                "split_warnings": prepared["split_warnings"],
                "feature_generation_seconds": prepared["feature_generation_seconds"],
                "variants": [
                    {
                        key: value
                        for key, value in variant.items()
                        if key not in {"metrics", "_residual_rows"}
                    }
                    for variant in variants
                ],
            }
        )
    variant_comparison = _aggregate_variant_split_results(split_results)
    best_variant = _select_best_variant(variant_comparison)
    for split in split_results:
        if split.get("split_mode") != "time":
            continue
        for variant in split.get("variants", []):
            if variant.get("variant") == best_variant:
                # Recompute residual rows for the concrete best variant from the time split.
                prepared = _prepared_for_split(base, split_mode="time", test_size=test_size)
                from atdr.app.detection.v331_noise_reduction import _augment_frame

                augmented_frame, augmented_meta = _augment_frame(prepared)
                augmented = {"frame": augmented_frame, **augmented_meta}
                uncalibrated = _fit_candidate(prepared, augmented)
                predictions = uncalibrated["_unguarded_predictions"]
                if best_variant == "current_v331_guard":
                    predictions = _apply_low_signal_benign_guard(prepared, augmented, predictions)
                elif best_variant == "refined_evidence_guard":
                    predictions = _apply_evidence_aware_low_signal_guard(
                        prepared,
                        augmented,
                        predictions,
                        uncalibrated["_probability_rows"],
                    )
                elif best_variant in {"calibrated_threshold_only_no_guard", "refined_evidence_guard_sigmoid_calibrated"}:
                    sigmoid = _fit_candidate(prepared, augmented, calibration_method="sigmoid")
                    predictions = sigmoid["_unguarded_predictions"]
                    if best_variant == "refined_evidence_guard_sigmoid_calibrated":
                        predictions = _apply_evidence_aware_low_signal_guard(
                            prepared,
                            augmented,
                            predictions,
                            sigmoid["_probability_rows"],
                        )
                residual_rows_for_best = _false_positive_patterns(prepared, augmented, predictions).get("_rows") or []
                break

    best_comparison = variant_comparison[best_variant]
    readiness = best_comparison["readiness"]
    output_path = Path(output_dir)
    stamp = _stamp()
    guard_report_path = output_path / f"v3_33_guard_refinement_report_{stamp}.md"
    stability_report_path = output_path / f"v3_33_split_stability_report_{stamp}.md"
    summary_path = output_path / f"v3_33_guard_refinement_{stamp}.json"
    latest_path = output_path / V333_OUTPUT_LATEST
    review_sample = _write_residual_review_sample(
        residual_rows_for_best,
        output_path=output_path / "v3_33_residual_error_review_sample.csv",
        limit=review_limit,
    )
    calibration = {
        "by_variant": {
            name: max(
                values,
                key=lambda item: (
                    1 if item.get("passed") else 0,
                    -_safe_float(item.get("expected_calibration_error"), 1),
                    -_safe_float(item.get("max_confidence_accuracy_gap"), 1),
                ),
            )
            for name, values in calibration_by_variant.items()
            if values
        }
    }
    result: dict[str, Any] = {
        "ok": True,
        "status": "completed",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "strategy_under_test": V332_STRATEGY,
        "refined_strategy": V333_STRATEGY,
        "profile": V332_PROFILE,
        "test_size": test_size,
        "total_label_rows": int(db.scalar(select(func.count(MLLabel.id))) or 0),
        "latest_trainable_rows": len(base["labels"]),
        "reviewed_labels": sum(1 for label in base["labels"] if label.reviewed),
        "runtime_seconds": round(time.perf_counter() - started, 4),
        "v3_32_suppression_context": _load_v332_suppression_context(output_dir),
        "split_results": split_results,
        "variant_comparison": variant_comparison,
        "best_variant": best_variant,
        "calibration": calibration,
        "readiness": readiness,
        "review_sample": review_sample,
        "training_dataset_diagnostics": training_dataset_diagnostics(db),
        "safety": {
            "ml_model_runs_before": before_runs,
            "ml_model_runs_after": int(db.scalar(select(func.count(MLModelRun.id))) or 0),
            "response_actions_before": before_responses,
            "response_actions_after": int(db.scalar(select(func.count(ResponseAction.id))) or 0),
            "production_promoted": False,
            "model_activated": False,
            "model_artifact_written": False,
            "response_automation_allowed": False,
            "real_firewall_blocking_enabled": False,
        },
    }
    output_path.mkdir(parents=True, exist_ok=True)
    guard_report_path.write_text(_render_guard_report(result), encoding="utf-8")
    stability_report_path.write_text(_render_split_stability_report(result), encoding="utf-8")
    summary = {key: value for key, value in result.items() if key != "training_dataset_diagnostics"}
    summary["guard_report_path"] = str(guard_report_path)
    summary["stability_report_path"] = str(stability_report_path)
    summary["summary_path"] = str(summary_path)
    summary["latest_summary_path"] = str(latest_path)
    summary_path.write_text(json.dumps(summary, indent=2, default=str), encoding="utf-8")
    latest_path.write_text(json.dumps(summary, indent=2, default=str), encoding="utf-8")
    result["guard_report_path"] = str(guard_report_path)
    result["stability_report_path"] = str(stability_report_path)
    result["summary_path"] = str(summary_path)
    result["latest_summary_path"] = str(latest_path)
    return result
