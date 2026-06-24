import csv
import json
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from atdr.app.core.config import get_settings
from atdr.app.db.models import MLLabel, MLModelRun, NormalizedLog, ResponseAction
from atdr.app.detection.hybrid_scoring import hybrid_risk_score
from atdr.app.detection.rules import build_detection_context, evaluate_rules
from atdr.app.detection.scoring import clamp_score
from atdr.app.detection.supervised_detector import (
    TRAINABLE_LABELS,
    _build_pipeline,
    _label_distribution,
    _latest_labels,
    _metrics_from_predictions,
    _optional_imports,
    _reviewed_distribution,
    _sample_weights,
    _split_class_warnings,
    _split_indices,
    _weak_distribution,
    threshold_decision,
    training_dataset_diagnostics,
)
from atdr.app.detection.v14_false_positive import _calibration_report
from atdr.app.ml.features import build_feature_rows
from atdr.app.services.class_temporal_coverage_service import build_class_temporal_coverage


OUTPUT_DIR = Path("ml_baseline_reviews")
THREAT_LABELS = {"suspicious", "malicious"}
BENIGN_LIKE_LABELS = {"benign", "benign_unusual", "needs_context"}
V330_PROFILE_ORDER = [
    "conservative",
    "balanced",
    "low_noise_soc_queue",
    "threat_recall",
    "precision_focused",
]
V330_CUSTOM_PROFILES = {
    "low_noise_soc_queue": {"malicious": 0.82, "threat_positive": 0.88, "needs_context": 0.55},
    "threat_recall": {"malicious": 0.24, "threat_positive": 0.34, "needs_context": 0.45},
    "precision_focused": {"malicious": 0.72, "threat_positive": 0.78, "needs_context": 0.55},
}
REVIEW_FIELDS = [
    "label_id",
    "log_id",
    "timestamp",
    "split_window",
    "source_name",
    "src_ip",
    "dst_ip",
    "dst_port",
    "protocol",
    "app",
    "action",
    "current_label",
    "current_attack_type",
    "reviewed_status",
    "label_source",
    "model_prediction",
    "model_confidence",
    "threat_positive_score",
    "rule_score",
    "anomaly_score",
    "hybrid_risk_score",
    "reason_selected",
    "evidence_summary",
    "human_review_decision",
    "human_review_attack_type",
    "human_review_confidence",
    "human_review_note",
]


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _log_timestamp(log: NormalizedLog) -> datetime | None:
    return log.generated_time or log.receive_time or log.start_time


def _source_name(log: NormalizedLog) -> str:
    source = getattr(getattr(log, "raw_log", None), "source", None)
    return str(source.name if source else "unknown_source")


def _confidence(row: dict[str, float]) -> float:
    return round(max(row.values(), default=0.0), 4)


def _threat_score(row: dict[str, float]) -> float:
    return round(float(row.get("suspicious", 0.0)) + float(row.get("malicious", 0.0)), 4)


def _custom_profile_decision(class_probs: dict[str, float], *, profile: str) -> str:
    thresholds = V330_CUSTOM_PROFILES[profile]
    malicious = float(class_probs.get("malicious", 0.0))
    suspicious = float(class_probs.get("suspicious", 0.0))
    threat = malicious + suspicious
    needs_context = float(class_probs.get("needs_context", 0.0))
    if malicious >= thresholds["malicious"]:
        return "malicious"
    if threat >= thresholds["threat_positive"]:
        return "malicious" if malicious > suspicious else "suspicious"
    if needs_context >= thresholds["needs_context"]:
        return "needs_context"
    benign_fallback = {
        "benign": float(class_probs.get("benign", 0.0)),
        "benign_unusual": float(class_probs.get("benign_unusual", 0.0)),
        "needs_context": needs_context,
    }
    return max(benign_fallback.items(), key=lambda item: item[1])[0]


def _profile_decision(class_probs: dict[str, float], *, profile: str) -> str:
    if profile in V330_CUSTOM_PROFILES:
        return _custom_profile_decision(class_probs, profile=profile)
    return threshold_decision(class_probs, profile=profile)


def _threat_binary_metrics(y_true: list[str], predictions: list[str]) -> dict[str, Any]:
    tp = fp = fn = tn = 0
    for actual, predicted in zip(y_true, predictions, strict=False):
        actual_threat = actual in THREAT_LABELS
        predicted_threat = predicted in THREAT_LABELS
        if actual_threat and predicted_threat:
            tp += 1
        elif not actual_threat and predicted_threat:
            fp += 1
        elif actual_threat and not predicted_threat:
            fn += 1
        else:
            tn += 1
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "true_positive": tp,
        "false_positive": fp,
        "false_negative": fn,
        "true_negative": tn,
        "support": tp + fn,
        "review_queue_size_estimate": tp + fp,
        "benign_like_false_positive_rate": round(fp / (fp + tn), 4) if fp + tn else 0.0,
    }


def _metrics_bundle(prepared: dict[str, Any], predictions: list[str]) -> dict[str, Any]:
    imports = prepared["imports"]
    metrics = _metrics_from_predictions(
        accuracy_score=imports[5],
        confusion_matrix=imports[6],
        precision_recall_fscore_support=imports[7],
        y_true=prepared["y_test"],
        predictions=predictions,
        labels_order=prepared["labels_order"],
    )
    threat = _threat_binary_metrics(prepared["y_test"], predictions)
    metrics["threat_positive"] = threat
    metrics["benign_like_false_positive_rate"] = threat["benign_like_false_positive_rate"]
    metrics["false_positives"] = threat["false_positive"]
    metrics["false_negatives"] = threat["false_negative"]
    metrics["review_queue_size_estimate"] = threat["review_queue_size_estimate"]
    return metrics


def _profile_summary(metrics: dict[str, Any]) -> dict[str, Any]:
    threat = metrics.get("threat_positive") or {}
    per_class = metrics.get("per_class") or {}
    return {
        "threat_positive_precision": threat.get("precision"),
        "threat_positive_recall": threat.get("recall"),
        "threat_positive_f1": threat.get("f1"),
        "benign_like_false_positive_rate": metrics.get("benign_like_false_positive_rate"),
        "suspicious_recall": (per_class.get("suspicious") or {}).get("recall"),
        "malicious_recall": (per_class.get("malicious") or {}).get("recall"),
        "macro_f1": (metrics.get("macro_average") or {}).get("f1"),
        "weighted_f1": (metrics.get("weighted_average") or {}).get("f1"),
        "false_positives": metrics.get("false_positives"),
        "false_negatives": metrics.get("false_negatives"),
        "review_queue_size_estimate": metrics.get("review_queue_size_estimate"),
    }


def _best_profile(profile_results: list[dict[str, Any]]) -> dict[str, Any]:
    return max(
        profile_results,
        key=lambda item: (
            float((item["summary"].get("threat_positive_f1") or 0)) - 0.65 * float(item["summary"].get("benign_like_false_positive_rate") or 1),
            -float(item["summary"].get("benign_like_false_positive_rate") or 1),
            float(item["summary"].get("threat_positive_recall") or 0),
        ),
    )


def _prepare_dataset(
    db: Session,
    *,
    split: str,
    test_size: float,
    min_samples: int,
    model_type: str,
    class_weight: str | None,
) -> dict[str, Any]:
    imports = _optional_imports()
    if imports is None:
        return {"ok": False, "status": "skipped", "message": "Supervised ML dependencies are unavailable."}
    labels = [label for label in _latest_labels(db) if label.log is not None and label.label in TRAINABLE_LABELS]
    if len(labels) < min_samples or len({label.label for label in labels}) < 2:
        return {"ok": False, "status": "skipped", "message": "Not enough labeled rows for v3.30 evaluation."}
    pd = imports[1]
    train_test_split = imports[8]
    logs = [label.log for label in labels]
    y = [label.label for label in labels]
    started = time.perf_counter()
    frame = pd.DataFrame(build_feature_rows(db, logs))
    feature_seconds = time.perf_counter() - started
    train_idx, test_idx, y_train, y_test, split_warnings = _split_indices(
        logs=logs,
        y=y,
        split=split,
        test_size=test_size,
        train_test_split=train_test_split,
    )
    pipeline = _build_pipeline(imports, model_type=model_type, class_weight=class_weight)
    weights, weight_summary = _sample_weights(labels)
    pipeline.fit(frame.iloc[train_idx], y_train, model__sample_weight=[weights[index] for index in train_idx])
    probabilities = pipeline.predict_proba(frame.iloc[test_idx]) if hasattr(pipeline, "predict_proba") else []
    classes = [str(label) for label in getattr(pipeline.named_steps["model"], "classes_", [])]
    probability_rows = [
        {label: float(value) for label, value in zip(classes, row, strict=False)}
        for row in probabilities
    ]
    return {
        "ok": True,
        "imports": imports,
        "labels": labels,
        "logs": logs,
        "y": y,
        "frame": frame,
        "train_idx": train_idx,
        "test_idx": test_idx,
        "y_train": y_train,
        "y_test": y_test,
        "test_labels": [labels[index] for index in test_idx],
        "test_logs": [logs[index] for index in test_idx],
        "labels_order": sorted(set(y)),
        "pipeline": pipeline,
        "probabilities": probabilities,
        "probability_rows": probability_rows,
        "classes": classes,
        "split_warnings": [*split_warnings, *_split_class_warnings(y_train, y_test)],
        "feature_generation_seconds": round(feature_seconds, 4),
        "sample_weighting": weight_summary,
    }


def _error_bucket(actual: str, predicted: str) -> str | None:
    if actual in BENIGN_LIKE_LABELS and predicted in THREAT_LABELS:
        return f"{actual}_predicted_threat"
    if actual in THREAT_LABELS and predicted in BENIGN_LIKE_LABELS:
        return f"{actual}_predicted_benign_like"
    if actual == "suspicious" and predicted == "malicious":
        return "suspicious_predicted_malicious"
    if actual == "malicious" and predicted == "suspicious":
        return "malicious_predicted_suspicious"
    return None


def _row_pattern(log: NormalizedLog) -> str:
    return f"app={log.app or '-'}|action={log.action or '-'}|port={log.dst_port or '-'}"


def _safe_time_bucket(log: NormalizedLog) -> str:
    timestamp = _log_timestamp(log)
    if timestamp is None:
        return "unknown_time"
    return timestamp.replace(minute=0, second=0, microsecond=0).isoformat()


def _error_analysis(prepared: dict[str, Any], predictions: list[str], probability_rows: list[dict[str, float]]) -> dict[str, Any]:
    errors: list[dict[str, Any]] = []
    bucket_counts: Counter[str] = Counter()
    app_counts: Counter[str] = Counter()
    action_counts: Counter[str] = Counter()
    port_counts: Counter[str] = Counter()
    source_counts: Counter[str] = Counter()
    pattern_counts: Counter[str] = Counter()
    time_counts: Counter[str] = Counter()
    reviewed_counts: Counter[str] = Counter()
    label_source_counts: Counter[str] = Counter()
    for label, log, actual, predicted, probs in zip(
        prepared["test_labels"],
        prepared["test_logs"],
        prepared["y_test"],
        predictions,
        probability_rows,
        strict=False,
    ):
        bucket = _error_bucket(actual, predicted)
        if bucket is None:
            continue
        confidence = _confidence(probs)
        source_name = _source_name(log)
        row = {
            "label_id": label.id,
            "log_id": log.id,
            "actual": actual,
            "predicted": predicted,
            "confidence": confidence,
            "threat_positive_score": _threat_score(probs),
            "bucket": bucket,
            "reviewed": bool(label.reviewed),
            "label_source": label.label_source or "unknown",
            "source_name": source_name,
            "app": log.app or "-",
            "action": log.action or "-",
            "dst_port": log.dst_port,
            "src_ip": log.src_ip,
            "dst_ip": log.dst_ip,
            "time_bucket": _safe_time_bucket(log),
            "pattern": _row_pattern(log),
        }
        errors.append(row)
        bucket_counts[bucket] += 1
        app_counts[str(log.app or "-")] += 1
        action_counts[str(log.action or "-")] += 1
        port_counts[str(log.dst_port or "-")] += 1
        source_counts[source_name] += 1
        pattern_counts[row["pattern"]] += 1
        time_counts[row["time_bucket"]] += 1
        reviewed_counts["reviewed" if label.reviewed else "weak_or_unreviewed"] += 1
        label_source_counts[str(label.label_source or "unknown")] += 1
    return {
        "total_errors_analyzed": len(errors),
        "bucket_counts": dict(bucket_counts),
        "top_apps": app_counts.most_common(10),
        "top_actions": action_counts.most_common(10),
        "top_ports": port_counts.most_common(10),
        "top_sources": source_counts.most_common(10),
        "top_patterns": pattern_counts.most_common(10),
        "top_time_windows": time_counts.most_common(10),
        "reviewed_vs_weak": dict(reviewed_counts),
        "label_source_counts": dict(label_source_counts),
        "high_confidence_wrong": [row for row in errors if float(row["confidence"]) >= 0.75][:25],
        "examples": errors[:25],
    }


def _rule_ml_disagreement(prepared: dict[str, Any], predictions: list[str], probability_rows: list[dict[str, float]]) -> dict[str, Any]:
    settings = get_settings()
    logs = prepared["test_logs"]
    context = build_detection_context(logs)
    counts: Counter[str] = Counter()
    rule_codes: Counter[str] = Counter()
    examples: list[dict[str, Any]] = []
    for label, log, actual, predicted, probs in zip(
        prepared["test_labels"],
        logs,
        prepared["y_test"],
        predictions,
        probability_rows,
        strict=False,
    ):
        matches = evaluate_rules(log, context)
        rule_score = clamp_score(sum(match.score for match in matches))
        rule_threat = bool(matches and rule_score >= settings.min_alert_score)
        anomaly_threat = bool(log.is_anomaly)
        supervised_threat = predicted in THREAT_LABELS
        actual_threat = actual in THREAT_LABELS
        malicious_probability = float(probs.get("malicious", 0.0))
        hybrid = hybrid_risk_score(
            rule_score=rule_score,
            isolation_anomaly_score=log.anomaly_score,
            isolation_is_anomaly=bool(log.is_anomaly),
            supervised_malicious_probability=malicious_probability,
        )
        hybrid_threat = float(hybrid["final_risk_score"]) >= settings.min_alert_score
        for match in matches:
            rule_codes[match.code] += 1
        if rule_threat and not supervised_threat:
            counts["rule_only_threat"] += 1
        if supervised_threat and not rule_threat:
            counts["supervised_only_threat"] += 1
        if anomaly_threat and not rule_threat and not supervised_threat:
            counts["anomaly_only_risky_rows"] += 1
        if rule_threat and supervised_threat and hybrid_threat:
            counts["hybrid_agreement_threat"] += 1
        if len({rule_threat, supervised_threat, hybrid_threat}) > 1:
            counts["hybrid_disagreement_cases"] += 1
        if rule_threat == actual_threat and supervised_threat != actual_threat:
            counts["rules_look_correct_ml_disagrees"] += 1
        if supervised_threat and not rule_threat:
            counts["ml_risky_rules_quiet"] += 1
        if not rule_threat and not supervised_threat and not hybrid_threat:
            counts["quiet_agreement"] += 1
        if len(examples) < 30 and (rule_threat != supervised_threat or hybrid_threat != supervised_threat):
            examples.append(
                {
                    "label_id": label.id,
                    "log_id": log.id,
                    "actual": actual,
                    "predicted": predicted,
                    "source_name": _source_name(log),
                    "app": log.app,
                    "action": log.action,
                    "dst_port": log.dst_port,
                    "rule_score": rule_score,
                    "rule_codes": [match.code for match in matches],
                    "is_anomaly": bool(log.is_anomaly),
                    "anomaly_score": log.anomaly_score,
                    "threat_positive_score": _threat_score(probs),
                    "hybrid_risk_score": hybrid["final_risk_score"],
                }
            )
    return {
        "counts": dict(counts),
        "top_rule_codes": rule_codes.most_common(10),
        "examples": examples,
    }


def _review_reason(actual: str, predicted: str, rule_score: float, hybrid_score: float, confidence: float) -> str:
    if actual in BENIGN_LIKE_LABELS and predicted in THREAT_LABELS and confidence >= 0.75:
        return "high-confidence false positive"
    if actual in BENIGN_LIKE_LABELS and predicted in THREAT_LABELS:
        return "benign-like row predicted threat-positive"
    if actual in THREAT_LABELS and predicted in BENIGN_LIKE_LABELS:
        return "threat-positive row predicted benign-like"
    if actual in THREAT_LABELS and predicted in THREAT_LABELS and actual != predicted:
        return "suspicious/malicious boundary case"
    if rule_score >= get_settings().min_alert_score and predicted not in THREAT_LABELS:
        return "rule evidence disagrees with supervised model"
    if hybrid_score >= get_settings().min_alert_score and predicted not in THREAT_LABELS:
        return "hybrid risk disagrees with supervised model"
    return "label quality review candidate"


def _write_review_sample(
    prepared: dict[str, Any],
    predictions: list[str],
    probability_rows: list[dict[str, float]],
    *,
    path: Path,
    limit: int,
) -> dict[str, Any]:
    context = build_detection_context(prepared["test_logs"])
    rows: list[dict[str, Any]] = []
    for label, log, actual, predicted, probs in zip(
        prepared["test_labels"],
        prepared["test_logs"],
        prepared["y_test"],
        predictions,
        probability_rows,
        strict=False,
    ):
        matches = evaluate_rules(log, context)
        rule_score = clamp_score(sum(match.score for match in matches))
        threat_score = _threat_score(probs)
        confidence = _confidence(probs)
        hybrid = hybrid_risk_score(
            rule_score=rule_score,
            isolation_anomaly_score=log.anomaly_score,
            isolation_is_anomaly=bool(log.is_anomaly),
            supervised_malicious_probability=float(probs.get("malicious", 0.0)),
        )
        hybrid_score = float(hybrid["final_risk_score"])
        reason = _review_reason(actual, predicted, rule_score, hybrid_score, confidence)
        if reason == "label quality review candidate" and confidence < 0.65 and rule_score < get_settings().min_alert_score:
            continue
        priority = (
            30 if actual in BENIGN_LIKE_LABELS and predicted in THREAT_LABELS else 0
        ) + (
            25 if actual in THREAT_LABELS and predicted in BENIGN_LIKE_LABELS else 0
        ) + (
            15 if actual in THREAT_LABELS and predicted in THREAT_LABELS and actual != predicted else 0
        ) + int(confidence * 10) + int(threat_score * 10) + int(hybrid_score / 10)
        rows.append(
            {
                "_priority": priority,
                "label_id": label.id,
                "log_id": log.id,
                "timestamp": (_log_timestamp(log).isoformat() if _log_timestamp(log) else ""),
                "split_window": "test",
                "source_name": _source_name(log),
                "src_ip": log.src_ip or "",
                "dst_ip": log.dst_ip or "",
                "dst_port": log.dst_port or "",
                "protocol": log.protocol or "",
                "app": log.app or "",
                "action": log.action or "",
                "current_label": actual,
                "current_attack_type": label.attack_type or "",
                "reviewed_status": "reviewed" if label.reviewed else "weak_or_unreviewed",
                "label_source": label.label_source or "",
                "model_prediction": predicted,
                "model_confidence": confidence,
                "threat_positive_score": threat_score,
                "rule_score": rule_score,
                "anomaly_score": log.anomaly_score if log.anomaly_score is not None else "",
                "hybrid_risk_score": hybrid_score,
                "reason_selected": reason,
                "evidence_summary": (
                    f"{log.action or 'unknown'} {log.app or 'unknown'} traffic to port {log.dst_port or 'unknown'}; "
                    f"rules={','.join(match.code for match in matches[:4]) or 'none'}; "
                    f"source={_source_name(log)}"
                ),
                "human_review_decision": "",
                "human_review_attack_type": "",
                "human_review_confidence": "",
                "human_review_note": "",
            }
        )
    rows.sort(key=lambda item: int(item["_priority"]), reverse=True)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=REVIEW_FIELDS)
        writer.writeheader()
        for row in rows[:limit]:
            writer.writerow({field: row.get(field, "") for field in REVIEW_FIELDS})
    return {
        "generated": True,
        "path": str(path),
        "rows": min(len(rows), limit),
        "candidate_rows": len(rows),
        "fields": REVIEW_FIELDS,
    }


def _render_analysis_markdown(result: dict[str, Any]) -> str:
    baseline = result.get("baseline") or {}
    baseline_metrics = baseline.get("metrics") or {}
    per_class = baseline_metrics.get("per_class") or {}
    threat = baseline_metrics.get("threat_positive") or {}
    analysis = result.get("error_analysis") or {}
    disagreement = result.get("detection_signal_comparison") or {}
    profile_rows = []
    for profile in result.get("threshold_profiles", []):
        summary = profile.get("summary") or {}
        profile_rows.append(
            "| {name} | {precision} | {recall} | {f1} | {fpr} | {suspicious} | {malicious} | {macro} | {weighted} | {queue} |".format(
                name=profile.get("profile"),
                precision=summary.get("threat_positive_precision"),
                recall=summary.get("threat_positive_recall"),
                f1=summary.get("threat_positive_f1"),
                fpr=summary.get("benign_like_false_positive_rate"),
                suspicious=summary.get("suspicious_recall"),
                malicious=summary.get("malicious_recall"),
                macro=summary.get("macro_f1"),
                weighted=summary.get("weighted_f1"),
                queue=summary.get("review_queue_size_estimate"),
            )
        )
    calibration = result.get("calibration") or {}
    bucket_lines = [
        f"| {bucket.get('range')} | {bucket.get('rows')} | {bucket.get('average_confidence')} | {bucket.get('accuracy')} | {bucket.get('gap')} |"
        for bucket in calibration.get("buckets", [])
    ]
    return f"""# v3.30 Detection and ML Quality Revalidation

Generated: {result.get("generated_at")}

This is a diagnostic SOC-triage report. It does not activate a model, promote a model, enable response automation, or claim production readiness.

## Baseline

- Total label rows: {result.get("label_state", {}).get("total_label_rows")}
- Latest trainable labels: {result.get("label_state", {}).get("latest_trainable_rows")}
- Reviewed labels: {result.get("label_state", {}).get("reviewed_labels")}
- Weak/unreviewed assisted labels: {result.get("label_state", {}).get("weak_unreviewed_assisted_labels")}
- Train/test rows: {baseline.get("training_rows")} / {baseline.get("test_rows")}
- Weighted F1: {(baseline_metrics.get("weighted_average") or {}).get("f1")}
- Macro F1: {(baseline_metrics.get("macro_average") or {}).get("f1")}
- Suspicious precision/recall/F1: {(per_class.get("suspicious") or {}).get("precision")} / {(per_class.get("suspicious") or {}).get("recall")} / {(per_class.get("suspicious") or {}).get("f1")}
- Malicious precision/recall/F1: {(per_class.get("malicious") or {}).get("precision")} / {(per_class.get("malicious") or {}).get("recall")} / {(per_class.get("malicious") or {}).get("f1")}
- Threat-positive precision/recall/F1: {threat.get("precision")} / {threat.get("recall")} / {threat.get("f1")}
- Benign-like false-positive rate: {baseline_metrics.get("benign_like_false_positive_rate")}
- Readiness decision: {result.get("readiness", {}).get("decision")}

## Threshold Profile Comparison

| Profile | Threat Precision | Threat Recall | Threat F1 | Benign FPR | Suspicious Recall | Malicious Recall | Macro F1 | Weighted F1 | Queue Estimate |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
{chr(10).join(profile_rows) if profile_rows else "| none | - | - | - | - | - | - | - | - | - |"}

Best diagnostic profile: `{(result.get("best_profile") or {}).get("profile")}`. This is not activated automatically.

## Confidence Calibration

- Status: {calibration.get("status")}
- Brier score threat-positive: {calibration.get("brier_score_threat_positive")}
- Expected calibration error: {calibration.get("expected_calibration_error")}
- Maximum confidence/accuracy gap: {calibration.get("max_confidence_accuracy_gap")}

| Bucket | Rows | Avg Confidence | Accuracy | Gap |
| --- | --- | --- | --- | --- |
{chr(10).join(bucket_lines) if bucket_lines else "| none | - | - | - | - |"}

## False-Positive / False-Negative Root Causes

- Error buckets: {json.dumps(analysis.get("bucket_counts", {}), default=str)}
- Top apps: {analysis.get("top_apps")}
- Top actions: {analysis.get("top_actions")}
- Top ports: {analysis.get("top_ports")}
- Top sources: {analysis.get("top_sources")}
- Top source/action/app/port patterns: {analysis.get("top_patterns")}
- Time-window concentration: {analysis.get("top_time_windows")}
- Reviewed vs weak error split: {analysis.get("reviewed_vs_weak")}

## Rule / Anomaly / Supervised / Hybrid Comparison

- Counts: {json.dumps(disagreement.get("counts", {}), default=str)}
- Top rule codes: {disagreement.get("top_rule_codes")}

## Review Sample

- Generated: {result.get("review_sample", {}).get("generated")}
- Rows: {result.get("review_sample", {}).get("rows")}
- Path: `{result.get("review_sample", {}).get("path")}`

## Safety

- Production promoted: false
- Model activated: false
- Model artifact written: false
- Response automation allowed: false
- Real firewall blocking enabled: false
"""


def _summary_payload(result: dict[str, Any]) -> dict[str, Any]:
    baseline = result.get("baseline") or {}
    baseline_metrics = baseline.get("metrics") or {}
    calibration = result.get("calibration") or {}
    error_analysis = result.get("error_analysis") or {}
    signal_comparison = result.get("detection_signal_comparison") or {}
    readiness = result.get("readiness") or {}
    return {
        "available": True,
        "ok": bool(result.get("ok")),
        "generated_at": result.get("generated_at"),
        "split": result.get("split"),
        "test_size": result.get("test_size"),
        "model_type": result.get("model_type"),
        "class_weight": result.get("class_weight"),
        "label_state": result.get("label_state"),
        "baseline": {
            "profile": baseline.get("profile"),
            "training_rows": baseline.get("training_rows"),
            "test_rows": baseline.get("test_rows"),
            "weighted_f1": (baseline_metrics.get("weighted_average") or {}).get("f1"),
            "macro_f1": (baseline_metrics.get("macro_average") or {}).get("f1"),
            "threat_positive": baseline_metrics.get("threat_positive"),
            "benign_like_false_positive_rate": baseline_metrics.get("benign_like_false_positive_rate"),
            "suspicious": (baseline_metrics.get("per_class") or {}).get("suspicious"),
            "malicious": (baseline_metrics.get("per_class") or {}).get("malicious"),
            "false_positives": baseline_metrics.get("false_positives"),
            "false_negatives": baseline_metrics.get("false_negatives"),
        },
        "threshold_profiles": [
            {"profile": item.get("profile"), **(item.get("summary") or {})}
            for item in result.get("threshold_profiles", [])
        ],
        "best_profile": result.get("best_profile"),
        "calibration": {
            "status": calibration.get("status"),
            "brier_score_threat_positive": calibration.get("brier_score_threat_positive"),
            "expected_calibration_error": calibration.get("expected_calibration_error"),
            "max_confidence_accuracy_gap": calibration.get("max_confidence_accuracy_gap"),
        },
        "error_analysis": {
            "bucket_counts": error_analysis.get("bucket_counts"),
            "top_apps": error_analysis.get("top_apps"),
            "top_actions": error_analysis.get("top_actions"),
            "top_ports": error_analysis.get("top_ports"),
            "top_sources": error_analysis.get("top_sources"),
            "top_patterns": error_analysis.get("top_patterns"),
            "top_time_windows": error_analysis.get("top_time_windows"),
            "reviewed_vs_weak": error_analysis.get("reviewed_vs_weak"),
        },
        "detection_signal_comparison": {
            "counts": signal_comparison.get("counts"),
            "top_rule_codes": signal_comparison.get("top_rule_codes"),
        },
        "review_sample": result.get("review_sample"),
        "readiness": readiness,
        "safety": {
            **(result.get("safety") or {}),
            "production_promoted": False,
            "model_activated": False,
            "model_artifact_written": False,
            "response_automation_allowed": False,
            "real_firewall_blocking_enabled": False,
        },
    }


def _readiness(metrics: dict[str, Any], calibration: dict[str, Any]) -> dict[str, Any]:
    threat = metrics.get("threat_positive") or {}
    per_class = metrics.get("per_class") or {}
    checks = [
        {
            "name": "benign-like false-positive rate within target",
            "passed": float(metrics.get("benign_like_false_positive_rate") or 1) <= 0.15,
            "value": metrics.get("benign_like_false_positive_rate"),
            "target": "<= 0.15",
        },
        {
            "name": "threat-positive F1 within target",
            "passed": float(threat.get("f1") or 0) >= 0.85,
            "value": threat.get("f1"),
            "target": ">= 0.85",
        },
        {
            "name": "suspicious recall within target",
            "passed": float((per_class.get("suspicious") or {}).get("recall") or 0) >= 0.8,
            "value": (per_class.get("suspicious") or {}).get("recall"),
            "target": ">= 0.8",
        },
        {
            "name": "malicious recall above zero",
            "passed": float((per_class.get("malicious") or {}).get("recall") or 0) > 0,
            "value": (per_class.get("malicious") or {}).get("recall"),
            "target": "> 0",
        },
        {
            "name": "confidence calibration acceptable",
            "passed": bool(calibration.get("passed")),
            "value": calibration.get("status"),
            "target": "passed",
        },
        {
            "name": "response automation disabled",
            "passed": True,
            "value": False,
            "target": "required",
        },
    ]
    passed = sum(1 for item in checks if item["passed"])
    blockers = [item["name"] for item in checks if not item["passed"]]
    decision = "analyst_review_eligible" if passed >= 4 else "candidate_only"
    return {
        "decision": decision,
        "passed": passed,
        "total": len(checks),
        "production_promoted": False,
        "response_automation_allowed": False,
        "blockers": blockers,
        "checks": checks,
    }


def run_v330_detection_ml_quality_revalidation(
    db: Session,
    *,
    split: str = "time",
    test_size: float = 0.3,
    min_samples: int = 6,
    review_limit: int = 200,
    output_dir: str | Path = OUTPUT_DIR,
    model_type: str = "random_forest",
    class_weight: str | None = "balanced",
) -> dict[str, Any]:
    before_runs = int(db.scalar(select(func.count(MLModelRun.id))) or 0)
    before_responses = int(db.scalar(select(func.count(ResponseAction.id))) or 0)
    prepared = _prepare_dataset(
        db,
        split=split,
        test_size=test_size,
        min_samples=min_samples,
        model_type=model_type,
        class_weight=class_weight,
    )
    if not prepared.get("ok"):
        return prepared
    probability_rows = prepared["probability_rows"]
    profile_results: list[dict[str, Any]] = []
    predictions_by_profile: dict[str, list[str]] = {}
    for profile in V330_PROFILE_ORDER:
        predictions = [_profile_decision(probs, profile=profile) for probs in probability_rows]
        predictions_by_profile[profile] = predictions
        metrics = _metrics_bundle(prepared, predictions)
        profile_results.append(
            {
                "profile": profile,
                "metrics": metrics,
                "summary": _profile_summary(metrics),
            }
        )
    baseline_predictions = predictions_by_profile["balanced"]
    baseline_metrics = _metrics_bundle(prepared, baseline_predictions)
    calibration = _calibration_report(prepared["y_test"], prepared["probabilities"], prepared["classes"])
    analysis = _error_analysis(prepared, baseline_predictions, probability_rows)
    disagreement = _rule_ml_disagreement(prepared, baseline_predictions, probability_rows)
    best = _best_profile(profile_results)
    output_path = Path(output_dir)
    stamp = _stamp()
    review_path = output_path / "v3_30_detection_quality_review_sample.csv"
    review_sample = _write_review_sample(
        prepared,
        baseline_predictions,
        probability_rows,
        path=review_path,
        limit=review_limit,
    )
    latest_labels = prepared["labels"]
    all_label_rows = int(db.scalar(select(func.count(MLLabel.id))) or 0)
    reviewed_count = sum(1 for label in latest_labels if bool(label.reviewed))
    weak_count = sum(
        1 for label in latest_labels if not bool(label.reviewed) and str(label.label_source or "").startswith("assisted")
    )
    result: dict[str, Any] = {
        "ok": True,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "split": split,
        "test_size": test_size,
        "model_type": model_type,
        "class_weight": class_weight or "none",
        "decision_support_only": True,
        "production_promoted": False,
        "model_activated": False,
        "model_artifact_written": False,
        "response_automation_allowed": False,
        "label_state": {
            "total_label_rows": all_label_rows,
            "latest_trainable_rows": len(latest_labels),
            "reviewed_labels": reviewed_count,
            "weak_unreviewed_assisted_labels": weak_count,
            "class_distribution": _label_distribution(prepared["y"]),
            "reviewed_distribution": _reviewed_distribution(latest_labels),
            "weak_distribution": _weak_distribution(latest_labels),
            "train_support": _label_distribution(prepared["y_train"]),
            "test_support": _label_distribution(prepared["y_test"]),
        },
        "baseline": {
            "profile": "balanced",
            "training_rows": len(prepared["train_idx"]),
            "test_rows": len(prepared["test_idx"]),
            "metrics": baseline_metrics,
            "confusion_matrix": baseline_metrics.get("confusion_matrix"),
            "labels": baseline_metrics.get("labels"),
        },
        "threshold_profiles": profile_results,
        "best_profile": {"profile": best["profile"], "summary": best["summary"]},
        "calibration": calibration,
        "error_analysis": analysis,
        "detection_signal_comparison": disagreement,
        "class_temporal_coverage": build_class_temporal_coverage(db, test_size=test_size),
        "training_dataset_diagnostics": training_dataset_diagnostics(db),
        "split_warnings": prepared["split_warnings"],
        "feature_generation_seconds": prepared["feature_generation_seconds"],
        "sample_weighting": prepared["sample_weighting"],
        "review_sample": review_sample,
        "safety": {
            "ml_model_runs_before": before_runs,
            "ml_model_runs_after": int(db.scalar(select(func.count(MLModelRun.id))) or 0),
            "response_actions_before": before_responses,
            "response_actions_after": int(db.scalar(select(func.count(ResponseAction.id))) or 0),
            "external_llm_used": False,
            "raw_logs_exported": False,
            "current_database_reset": False,
        },
    }
    result["readiness"] = _readiness(baseline_metrics, calibration)
    analysis_path = output_path / f"v3_30_detection_ml_quality_analysis_{stamp}.md"
    analysis_path.parent.mkdir(parents=True, exist_ok=True)
    analysis_path.write_text(_render_analysis_markdown(result), encoding="utf-8")
    result["analysis_report_path"] = str(analysis_path)
    summary_payload = _summary_payload(result)
    summary_path = output_path / f"v3_30_detection_ml_quality_{stamp}.json"
    latest_summary_path = output_path / "v3_30_detection_ml_quality_latest.json"
    summary_path.write_text(json.dumps(summary_payload, indent=2, default=str), encoding="utf-8")
    latest_summary_path.write_text(json.dumps(summary_payload, indent=2, default=str), encoding="utf-8")
    result["summary_report_path"] = str(summary_path)
    result["latest_summary_report_path"] = str(latest_summary_path)
    return result
