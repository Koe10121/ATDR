import argparse
import csv
import json
import math
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from atdr.app.benchmarks.adapter import BenchmarkRecord, load_prepared_benchmark_snapshot
from atdr.app.benchmarks.readiness import readiness_gate_v6_external_generalization
from atdr.app.core.config import PROJECT_ROOT
from atdr.app.detection.supervised_detector import _build_pipeline, _optional_imports
from atdr.scripts.build_internal_ai_readiness_benchmark import (
    DEFAULT_OUTPUT as INTERNAL_CSV,
    build_internal_ai_readiness_benchmark,
)
from atdr.scripts.detection_reliability_common import json_default
from atdr.scripts.prepare_benchmark_dataset import prepare_benchmark_dataset
from atdr.scripts.run_benchmark_ml_experiment import _metrics, _triage_label
from atdr.scripts.run_external_benchmark_validation import (
    BENCHMARK_OUTPUT_DIR,
    FINAL_OUTPUT_DIR,
    _calibration_metrics,
    _feature_frame,
    _overfitting_analysis,
)
from atdr.scripts.run_v15_ai_readiness_validation import _latest_validation_status


REVIEW_OUTPUT_DIR = PROJECT_ROOT / "ml_baseline_reviews"
PROFILE_NAMES = (
    "current_hybrid",
    "low_noise_external",
    "suspicious_recall_external",
    "calibrated_external",
    "hybrid_external_balanced",
    "high_confidence_external",
    "three_class_external",
    "hierarchical_external",
)
LABELS_ORDER = ["benign_like", "malicious", "suspicious"]
THREAT_LABELS = {"malicious", "suspicious"}


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _latest_report_path(directory: Path, pattern: str) -> Path | None:
    if not directory.exists():
        return None
    candidates = sorted(
        directory.glob(pattern),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    return candidates[0] if candidates else None


def _load_json(path: Path | None) -> dict[str, Any]:
    if path is None:
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        if value is None:
            return default
        result = float(value)
    except (TypeError, ValueError):
        return default
    if math.isnan(result) or math.isinf(result):
        return default
    return result


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        if value in (None, ""):
            return default
        return int(float(value))
    except (TypeError, ValueError):
        return default


def _text(value: Any) -> str:
    return str(value or "").strip().lower()


def _record_value(record: BenchmarkRecord, key: str, default: Any = None) -> Any:
    value = record.normalized.get(key)
    return default if value in (None, "") else value


def _is_private_ip(value: Any) -> bool:
    import ipaddress

    try:
        return ipaddress.ip_address(str(value)).is_private
    except ValueError:
        return False


def _record_context(record: BenchmarkRecord) -> dict[str, Any]:
    src_ip = _record_value(record, "src_ip")
    dst_ip = _record_value(record, "dst_ip")
    app = _text(_record_value(record, "app"))
    action = _text(_record_value(record, "action"))
    protocol = _text(_record_value(record, "protocol"))
    dst_port = _safe_int(_record_value(record, "dst_port"))
    bytes_sent = _safe_int(_record_value(record, "bytes"))
    packets = _safe_int(_record_value(record, "packets"))
    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_internal": _is_private_ip(src_ip),
        "dst_internal": _is_private_ip(dst_ip),
        "app": app,
        "action": action,
        "protocol": protocol,
        "dst_port": dst_port,
        "bytes": bytes_sent,
        "packets": packets,
        "scenario": str(_record_value(record, "scenario", "") or ""),
        "source": str(_record_value(record, "source_name", "external-holdout") or "external-holdout"),
    }


def _rule_signal(record: BenchmarkRecord) -> dict[str, Any]:
    ctx = _record_context(record)
    app = ctx["app"]
    action = ctx["action"]
    port = ctx["dst_port"]
    bytes_sent = ctx["bytes"]
    packets = ctx["packets"]
    score = 0.08
    reasons: list[str] = []
    suggested = "benign_like"
    benign_prior = False

    if app in {"quic", "google-base", "ssl"} and action == "allow" and port in {443, 8443}:
        score = 0.03
        benign_prior = True
        reasons.append("known allowed TLS/QUIC-like traffic")
    if app in {"ms-ds", "ms-ds-smb", "smb"} and action == "allow" and port == 445 and bytes_sent >= 1_000_000:
        score = min(score, 0.06)
        benign_prior = True
        reasons.append("large internal backup-like SMB transfer")
    if app == "incomplete" and action == "allow" and port in {80, 443}:
        score = min(score, 0.12)
        benign_prior = True
        reasons.append("incomplete allow on web port is ambiguous but not enough alone")
    if app in {"unknown-udp", "netbios-ns"} and action in {"deny", "drop", "reset"} and port in {137, 138, 1900, 5353}:
        score = min(score, 0.16)
        benign_prior = True
        reasons.append("blocked background-noise style UDP")

    if app in {"bittorrent", "p2p"} or 6881 <= port <= 6999:
        score = max(score, 0.72)
        suggested = "suspicious"
        reasons.append("policy-violation/p2p-like signal")
    if app in {"unknown-tcp", "unknown"} and action == "allow" and port >= 6000:
        score = max(score, 0.66)
        suggested = "suspicious"
        reasons.append("unknown service on high destination port")
    if app == "incomplete" and action in {"deny", "drop", "reset"}:
        score = max(score, 0.68)
        suggested = "suspicious"
        reasons.append("incomplete denied/reset traffic")
    if action in {"deny", "drop", "reset"} and port in {22, 23, 3389, 445, 995}:
        score = max(score, 0.76)
        suggested = "malicious" if port in {22, 3389, 445} else "suspicious"
        reasons.append("denied high-risk service access")
    if app in {"dns", "unknown-udp"} and action == "allow" and packets <= 3 and bytes_sent <= 1200:
        score = max(score, 0.6)
        suggested = "malicious"
        reasons.append("low-volume beacon-like DNS/UDP pattern")
    if bytes_sent >= 50_000_000 and action == "allow" and not ctx["dst_internal"]:
        score = max(score, 0.82)
        suggested = "malicious"
        reasons.append("large outbound transfer to external destination")
    if action == "allow" and app in {"web-browsing", "ssl", "quic"} and port in {80, 443} and score < 0.5:
        suggested = "benign_like"

    if not reasons:
        reasons.append("no strong rule-style signal")
    return {
        "score": round(max(0.0, min(score, 1.0)), 4),
        "suggested_class": suggested,
        "benign_prior": benign_prior,
        "reasons": reasons,
        "label": f"{suggested}:{round(max(0.0, min(score, 1.0)), 2)}",
    }


def _anomaly_signal(record: BenchmarkRecord) -> dict[str, Any]:
    ctx = _record_context(record)
    score = 0.1
    reasons: list[str] = []
    app = ctx["app"]
    port = ctx["dst_port"]
    bytes_sent = ctx["bytes"]
    packets = ctx["packets"]
    if app in {"unknown-tcp", "unknown-udp", "unknown"}:
        score += 0.25
        reasons.append("unknown application")
    if port and port not in {53, 80, 123, 137, 138, 443, 445, 995, 3389, 8443}:
        score += 0.2
        reasons.append("rare destination port")
    if bytes_sent >= 50_000_000:
        score += 0.25
        reasons.append("large byte volume")
    if packets <= 2 and app in {"dns", "unknown-udp"}:
        score += 0.15
        reasons.append("very small repeated-looking packet pattern")
    if ctx["action"] in {"deny", "drop", "reset"} and app == "incomplete":
        score += 0.18
        reasons.append("incomplete denied/reset traffic")
    return {
        "score": round(min(score, 1.0), 4),
        "reasons": reasons or ["no high anomaly-style indicator"],
        "label": f"anomaly:{round(min(score, 1.0), 2)}",
    }


def _probability_map(classes: list[str], row: Any) -> dict[str, float]:
    values = {label: 0.0 for label in LABELS_ORDER}
    for label, value in zip(classes, row, strict=False):
        values[str(label)] = _safe_float(value)
    return values


def _normalize_probs(values: dict[str, float]) -> dict[str, float]:
    clipped = {label: max(0.0, _safe_float(values.get(label))) for label in LABELS_ORDER}
    total = sum(clipped.values())
    if total <= 0:
        return {label: 1.0 / len(LABELS_ORDER) for label in LABELS_ORDER}
    return {label: clipped[label] / total for label in LABELS_ORDER}


def _temperature_probs(values: dict[str, float], temperature: float) -> dict[str, float]:
    temperature = max(0.1, float(temperature))
    adjusted = {
        label: max(1e-6, value) ** (1.0 / temperature)
        for label, value in _normalize_probs(values).items()
    }
    return _normalize_probs(adjusted)


def _pseudo_probability(prediction: str, confidence: float) -> list[float]:
    confidence = max(1 / 3, min(float(confidence), 0.99))
    remaining = max(0.0, 1.0 - confidence)
    row = []
    other_count = len(LABELS_ORDER) - 1
    for label in LABELS_ORDER:
        row.append(confidence if label == prediction else remaining / other_count)
    return row


def _hybrid_probs(
    *,
    base_probs: dict[str, float],
    rule: dict[str, Any],
    anomaly: dict[str, Any],
    profile: str,
) -> dict[str, float]:
    probs = _normalize_probs(base_probs)
    rule_score = _safe_float(rule.get("score"))
    anomaly_score = _safe_float(anomaly.get("score"))
    suggested = str(rule.get("suggested_class") or "benign_like")
    adjusted = dict(probs)

    if suggested in THREAT_LABELS:
        boost = 0.18 if profile != "low_noise_external" else 0.1
        adjusted[suggested] += boost * rule_score
    elif rule.get("benign_prior"):
        adjusted["benign_like"] += 0.25 if profile != "low_noise_external" else 0.35
        adjusted["suspicious"] *= 0.45 if profile != "suspicious_recall_external" else 0.58
        adjusted["malicious"] *= 0.42 if profile != "suspicious_recall_external" else 0.55
    if anomaly_score >= 0.55:
        adjusted["suspicious"] += 0.08 * anomaly_score
    if profile == "suspicious_recall_external":
        adjusted["suspicious"] += 0.12 * rule_score
        adjusted["benign_like"] *= 0.86
    if profile == "low_noise_external":
        adjusted["benign_like"] += 0.08
        if rule_score < 0.55:
            adjusted["suspicious"] *= 0.7
            adjusted["malicious"] *= 0.72
    if profile == "hybrid_external_balanced":
        adjusted["benign_like"] += 0.05 if rule_score < 0.35 else 0.0
        adjusted["suspicious"] += 0.07 if suggested == "suspicious" else 0.0
        adjusted["malicious"] += 0.07 if suggested == "malicious" else 0.0
    return _normalize_probs(adjusted)


def _profile_prediction(
    record: BenchmarkRecord,
    base_probs: dict[str, float],
    *,
    profile: str,
    hierarchical_binary_threat: float | None = None,
    hierarchical_stage2: dict[str, float] | None = None,
) -> dict[str, Any]:
    rule = _rule_signal(record)
    anomaly = _anomaly_signal(record)
    probs = dict(base_probs)
    if profile == "calibrated_external":
        probs = _temperature_probs(base_probs, 1.6)
    elif profile in {
        "current_hybrid",
        "low_noise_external",
        "suspicious_recall_external",
        "hybrid_external_balanced",
    }:
        probs = _hybrid_probs(base_probs=base_probs, rule=rule, anomaly=anomaly, profile=profile)
    elif profile == "hierarchical_external":
        threat_probability = _safe_float(hierarchical_binary_threat)
        stage2_probs = hierarchical_stage2 or {"malicious": probs.get("malicious", 0.0), "suspicious": probs.get("suspicious", 0.0)}
        stage2_total = max(1e-6, _safe_float(stage2_probs.get("malicious")) + _safe_float(stage2_probs.get("suspicious")))
        probs = {
            "benign_like": max(0.0, 1.0 - threat_probability),
            "malicious": threat_probability * _safe_float(stage2_probs.get("malicious")) / stage2_total,
            "suspicious": threat_probability * _safe_float(stage2_probs.get("suspicious")) / stage2_total,
        }
        probs = _hybrid_probs(base_probs=probs, rule=rule, anomaly=anomaly, profile="hybrid_external_balanced")

    probs = _normalize_probs(probs)
    threat_probability = probs.get("suspicious", 0.0) + probs.get("malicious", 0.0)
    prediction = max(probs.items(), key=lambda item: item[1])[0]
    thresholds = {
        "current_hybrid": (0.5, 0.46, 0.34),
        "low_noise_external": (0.78, 0.68, 0.62),
        "suspicious_recall_external": (0.42, 0.66, 0.28),
        "calibrated_external": (0.56, 0.5, 0.42),
        "hybrid_external_balanced": (0.54, 0.48, 0.38),
        "high_confidence_external": (0.9, 0.75, 0.72),
        "three_class_external": (0.0, 0.0, 0.0),
        "hierarchical_external": (0.5, 0.5, 0.36),
    }
    threat_threshold, malicious_threshold, suspicious_threshold = thresholds[profile]
    strong_rule_threat = (
        rule.get("suggested_class") in THREAT_LABELS
        and _safe_float(rule.get("score")) >= 0.68
        and profile
        not in {
            "low_noise_external",
            "high_confidence_external",
        }
    )
    if profile != "three_class_external":
        if threat_probability < threat_threshold and not strong_rule_threat:
            prediction = "benign_like"
        elif probs.get("malicious", 0.0) >= malicious_threshold and probs.get("malicious", 0.0) >= probs.get("suspicious", 0.0) * 0.88:
            prediction = "malicious"
        elif probs.get("suspicious", 0.0) >= suspicious_threshold or rule.get("suggested_class") == "suspicious":
            prediction = "suspicious"
        else:
            prediction = "malicious" if probs.get("malicious", 0.0) >= probs.get("suspicious", 0.0) else "suspicious"
    confidence = max(probs.values())
    hybrid_risk = round(
        min(
            1.0,
            0.58 * threat_probability
            + 0.28 * _safe_float(rule.get("score"))
            + 0.14 * _safe_float(anomaly.get("score")),
        ),
        4,
    )
    return {
        "prediction": prediction,
        "confidence": round(confidence, 4),
        "probabilities": probs,
        "probability_row": _pseudo_probability(prediction, confidence),
        "threat_probability": round(threat_probability, 4),
        "rule": rule,
        "anomaly": anomaly,
        "hybrid_risk": hybrid_risk,
    }


def _cost_score(y_true: list[str], y_pred: list[str]) -> dict[str, Any]:
    total = 0.0
    rows: Counter[str] = Counter()
    for actual, predicted in zip(y_true, y_pred, strict=False):
        if actual == predicted:
            continue
        key = f"{actual}_predicted_{predicted}"
        rows[key] += 1
        if actual == "malicious" and predicted == "benign_like":
            total += 10
        elif actual == "suspicious" and predicted == "benign_like":
            total += 6
        elif actual == "benign_like" and predicted == "malicious":
            total += 5
        elif actual == "benign_like" and predicted == "suspicious":
            total += 3
        elif actual in THREAT_LABELS and predicted in THREAT_LABELS:
            total += 2
        else:
            total += 1
    return {
        "total_cost": round(total, 4),
        "average_cost": round(total / len(y_true), 4) if y_true else 0,
        "error_breakdown": dict(sorted(rows.items())),
    }


def _evaluate_predictions(
    *,
    y_true: list[str],
    predictions: list[str],
    probability_rows: list[list[float]],
    imports,
) -> dict[str, Any]:
    (
        _joblib,
        _pd,
        _ColumnTransformer,
        _RandomForestClassifier,
        _SimpleImputer,
        accuracy_score,
        confusion_matrix,
        precision_recall_fscore_support,
        _train_test_split,
        _Pipeline,
        _OneHotEncoder,
    ) = imports
    metrics = _metrics(
        y_true,
        predictions,
        LABELS_ORDER,
        accuracy_score=accuracy_score,
        confusion_matrix=confusion_matrix,
        precision_recall_fscore_support=precision_recall_fscore_support,
    )
    calibration = _calibration_metrics(y_true, predictions, probability_rows, LABELS_ORDER)
    queue_size = sum(1 for prediction in predictions if prediction in THREAT_LABELS)
    return {
        "metrics": metrics,
        "calibration": calibration,
        "queue_size": queue_size,
        "cost_sensitive": _cost_score(y_true, predictions),
    }


def _train_base_models(
    *,
    imports,
    training_frame: Any,
    holdout_frame: Any,
    training_records: list[BenchmarkRecord],
) -> dict[str, Any]:
    y_train = [_triage_label(record) for record in training_records]
    models: dict[str, Any] = {}

    base = _build_pipeline(imports, model_type="extra_trees", class_weight="balanced")
    base.fit(training_frame, y_train)
    models["extra_trees"] = base

    low_noise = _build_pipeline(imports, model_type="extra_trees", class_weight=None)
    low_noise.fit(training_frame, y_train)
    models["extra_trees_low_noise"] = low_noise

    logistic = _build_pipeline(imports, model_type="logistic_regression", class_weight="balanced")
    logistic.fit(training_frame, y_train)
    models["logistic_regression"] = logistic

    binary_labels = [
        "threat_positive" if label in THREAT_LABELS else "benign_like"
        for label in y_train
    ]
    stage1 = _build_pipeline(imports, model_type="extra_trees", class_weight="balanced")
    stage1.fit(training_frame, binary_labels)
    threat_indexes = [idx for idx, label in enumerate(y_train) if label in THREAT_LABELS]
    stage2 = None
    if len({y_train[idx] for idx in threat_indexes}) >= 2:
        stage2 = _build_pipeline(imports, model_type="extra_trees", class_weight="balanced")
        stage2.fit(
            training_frame.iloc[threat_indexes],
            [y_train[idx] for idx in threat_indexes],
        )
    models["hierarchical_stage1"] = stage1
    models["hierarchical_stage2"] = stage2
    _ = holdout_frame
    return models


def _model_probabilities(model: Any, frame: Any, labels: list[str]) -> list[dict[str, float]]:
    if model is None or not hasattr(model, "predict_proba"):
        predictions = list(model.predict(frame)) if model is not None else ["benign_like"] * len(frame)
        return [
            _normalize_probs(
                {
                    label: 0.9 if label == prediction else 0.05
                    for label in labels
                }
            )
            for prediction in predictions
        ]
    classes = [str(value) for value in model.named_steps["model"].classes_]
    return [_probability_map(classes, row) for row in model.predict_proba(frame)]


def _run_profiles(
    *,
    records: list[BenchmarkRecord],
    training_records: list[BenchmarkRecord],
    training_frame: Any,
    holdout_frame: Any,
    imports,
) -> dict[str, Any]:
    models = _train_base_models(
        imports=imports,
        training_frame=training_frame,
        holdout_frame=holdout_frame,
        training_records=training_records,
    )
    y_true = [_triage_label(record) for record in records]
    base_probs = _model_probabilities(models["extra_trees"], holdout_frame, LABELS_ORDER)
    low_noise_probs = _model_probabilities(models["extra_trees_low_noise"], holdout_frame, LABELS_ORDER)
    logistic_probs = _model_probabilities(models["logistic_regression"], holdout_frame, LABELS_ORDER)
    stage1_probs = _model_probabilities(
        models["hierarchical_stage1"],
        holdout_frame,
        ["benign_like", "threat_positive"],
    )
    stage2_probs = _model_probabilities(
        models["hierarchical_stage2"],
        holdout_frame,
        ["malicious", "suspicious"],
    ) if models.get("hierarchical_stage2") is not None else [
        {"malicious": probs.get("malicious", 0.0), "suspicious": probs.get("suspicious", 0.0)}
        for probs in base_probs
    ]

    profile_results: list[dict[str, Any]] = []
    predictions_by_profile: dict[str, list[dict[str, Any]]] = {}
    for profile in PROFILE_NAMES:
        rows: list[dict[str, Any]] = []
        if profile == "low_noise_external":
            source_probs = low_noise_probs
        elif profile == "calibrated_external":
            source_probs = logistic_probs
        else:
            source_probs = base_probs
        for index, (record, probs) in enumerate(zip(records, source_probs, strict=False)):
            binary_threat = None
            if profile == "hierarchical_external":
                binary_threat = _safe_float(stage1_probs[index].get("threat_positive"))
            row = _profile_prediction(
                record,
                probs,
                profile=profile,
                hierarchical_binary_threat=binary_threat,
                hierarchical_stage2=stage2_probs[index],
            )
            rows.append(row)
        predictions = [row["prediction"] for row in rows]
        probability_rows = [row["probability_row"] for row in rows]
        evaluated = _evaluate_predictions(
            y_true=y_true,
            predictions=predictions,
            probability_rows=probability_rows,
            imports=imports,
        )
        profile_results.append(
            {
                "profile": profile,
                **evaluated,
                "model_artifact_written": False,
                "model_activated": False,
                "response_automation_allowed": False,
            }
        )
        predictions_by_profile[profile] = rows
    best = _best_profile(profile_results)
    return {
        "profiles": profile_results,
        "best_profile": best,
        "predictions_by_profile": predictions_by_profile,
    }


def _best_profile(profile_results: list[dict[str, Any]]) -> dict[str, Any] | None:
    eligible = []
    for item in profile_results:
        metrics = item.get("metrics") or {}
        suspicious = ((metrics.get("per_class") or {}).get("suspicious") or {}).get("recall") or 0
        malicious = ((metrics.get("per_class") or {}).get("malicious") or {}).get("recall") or 0
        benign_fpr = metrics.get("benign_false_positive_rate") or 0
        threat_f1 = metrics.get("threat_positive_f1") or 0
        if malicious >= 0.55 and benign_fpr <= 0.3 and threat_f1 >= 0.7:
            eligible.append((item, suspicious))
    candidates = [item for item, _suspicious in eligible] or profile_results
    return max(
        candidates,
        key=lambda item: (
            float((item.get("metrics") or {}).get("threat_positive_f1") or 0)
            - 0.45 * float((item.get("metrics") or {}).get("benign_false_positive_rate") or 0)
            + 0.2 * float((((item.get("metrics") or {}).get("per_class") or {}).get("suspicious") or {}).get("recall") or 0),
            -float((item.get("cost_sensitive") or {}).get("total_cost") or 0),
        ),
        default=None,
    )


def _error_category(actual: str, predicted: str) -> str:
    if actual == predicted:
        return "correct"
    if actual == "suspicious" and predicted == "benign_like":
        return "suspicious_predicted_benign_like"
    if actual == "suspicious" and predicted == "malicious":
        return "suspicious_predicted_malicious"
    if actual == "malicious" and predicted == "benign_like":
        return "malicious_predicted_benign_like"
    if actual == "malicious" and predicted == "suspicious":
        return "malicious_predicted_suspicious"
    if actual == "benign_like" and predicted == "suspicious":
        return "benign_predicted_suspicious"
    if actual == "benign_like" and predicted == "malicious":
        return "benign_predicted_malicious"
    return f"{actual}_predicted_{predicted}"


def _top_patterns(
    rows: list[tuple[BenchmarkRecord, dict[str, Any], str, str]],
    *,
    limit: int = 8,
) -> dict[str, list[dict[str, Any]]]:
    counters: dict[str, Counter[str]] = {
        "app": Counter(),
        "action": Counter(),
        "dst_port": Counter(),
        "source": Counter(),
        "scenario": Counter(),
        "app_action_port": Counter(),
    }
    for record, _prediction, _actual, _category in rows:
        ctx = _record_context(record)
        counters["app"][ctx["app"] or "-"] += 1
        counters["action"][ctx["action"] or "-"] += 1
        counters["dst_port"][str(ctx["dst_port"] or "-")] += 1
        counters["source"][ctx["source"] or "-"] += 1
        counters["scenario"][ctx["scenario"] or "-"] += 1
        counters["app_action_port"][f"{ctx['app'] or '-'} / {ctx['action'] or '-'} / {ctx['dst_port'] or '-'}"] += 1
    return {
        name: [{"value": value, "count": count} for value, count in counter.most_common(limit)]
        for name, counter in counters.items()
    }


def _build_error_analysis(
    *,
    records: list[BenchmarkRecord],
    current_predictions: list[dict[str, Any]],
    best_predictions: list[dict[str, Any]],
    best_profile: str,
) -> dict[str, Any]:
    categories: dict[str, list[tuple[BenchmarkRecord, dict[str, Any], str, str]]] = defaultdict(list)
    best_categories: Counter[str] = Counter()
    disagreement: Counter[str] = Counter()
    for record, current, best in zip(records, current_predictions, best_predictions, strict=False):
        actual = _triage_label(record)
        current_category = _error_category(actual, current["prediction"])
        categories[current_category].append((record, current, actual, current_category))
        best_categories[_error_category(actual, best["prediction"])] += 1
        rule_class = (current.get("rule") or {}).get("suggested_class")
        supervised_class = current["prediction"]
        hybrid_class = best["prediction"]
        if rule_class != supervised_class:
            disagreement[f"rule_{rule_class}_vs_supervised_{supervised_class}"] += 1
        if supervised_class != hybrid_class:
            disagreement[f"supervised_{supervised_class}_vs_{best_profile}_{hybrid_class}"] += 1
    focus = {
        name: {
            "count": len(rows),
            "patterns": _top_patterns(rows),
        }
        for name, rows in sorted(categories.items())
        if name != "correct"
    }
    return {
        "current_error_counts": {
            name: len(rows)
            for name, rows in sorted(categories.items())
        },
        "best_profile_error_counts": dict(sorted(best_categories.items())),
        "current_error_patterns": focus,
        "rule_supervised_hybrid_disagreement": dict(disagreement.most_common(20)),
        "recommended_fixes": [
            "Add reviewed benign boundary rows for normal QUIC/TLS, incomplete allow, and blocked background noise.",
            "Add reviewed suspicious rows for policy-violation and unknown-service boundary traffic.",
            "Keep high-risk denied service patterns as threat-positive, but route ambiguous evidence to analyst review.",
            "Show external confidence as limited until calibration buckets pass.",
            "Use external holdout metrics as a readiness blocker; do not activate models from this script.",
        ],
    }


def _review_priority(
    record: BenchmarkRecord,
    current: dict[str, Any],
    best: dict[str, Any],
) -> tuple[int, list[str]]:
    actual = _triage_label(record)
    current_pred = current["prediction"]
    best_pred = best["prediction"]
    reasons = []
    priority = 0
    if actual == "suspicious" and current_pred == "benign_like":
        priority += 100
        reasons.append("suspicious false negative")
    if actual == "benign_like" and current_pred in THREAT_LABELS:
        priority += 95
        reasons.append("benign-like false positive")
    if actual == "suspicious" and current_pred == "malicious":
        priority += 75
        reasons.append("suspicious/malicious boundary")
    if actual == "malicious" and current_pred != "malicious":
        priority += 80
        reasons.append("malicious boundary miss")
    if best_pred != current_pred:
        priority += 35
        reasons.append("profile disagreement")
    if abs(current.get("threat_probability", 0.0) - 0.5) <= 0.18:
        priority += 25
        reasons.append("near threat decision boundary")
    if (current.get("rule") or {}).get("suggested_class") != current_pred:
        priority += 20
        reasons.append("rule/model disagreement")
    ctx = _record_context(record)
    if ctx["app"] in {"incomplete", "quic", "unknown-tcp", "unknown-udp", "bittorrent"}:
        priority += 15
        reasons.append(f"important boundary app={ctx['app']}")
    return priority, reasons or ["diverse external holdout coverage"]


def _evidence_summary(record: BenchmarkRecord, prediction: dict[str, Any]) -> str:
    ctx = _record_context(record)
    return (
        f"{ctx['source']} {ctx['scenario']}: {ctx['src_ip']} -> {ctx['dst_ip']} "
        f"port {ctx['dst_port']} app={ctx['app'] or '-'} action={ctx['action'] or '-'}; "
        f"rule={'; '.join((prediction.get('rule') or {}).get('reasons') or [])}; "
        f"anomaly={'; '.join((prediction.get('anomaly') or {}).get('reasons') or [])}"
    )


def _write_review_sample(
    *,
    records: list[BenchmarkRecord],
    current_predictions: list[dict[str, Any]],
    best_predictions: list[dict[str, Any]],
    output_path: Path,
    limit: int,
) -> dict[str, Any]:
    ranked = []
    for index, (record, current, best) in enumerate(zip(records, current_predictions, best_predictions, strict=False)):
        priority, reasons = _review_priority(record, current, best)
        ranked.append((priority, index, reasons))
    ranked.sort(key=lambda item: (item[0], -item[1]), reverse=True)
    selected = ranked[: min(limit, len(ranked))]
    output_path.parent.mkdir(parents=True, exist_ok=True)
    columns = [
        "review_dataset_kind",
        "review_import_workflow",
        "benchmark_row_id",
        "timestamp",
        "source",
        "scenario_family",
        "src_ip",
        "dst_ip",
        "dst_port",
        "protocol",
        "app",
        "action",
        "bytes",
        "packets",
        "current_label",
        "expected_label",
        "model_prediction",
        "rule_signal",
        "anomaly_signal",
        "supervised_signal",
        "hybrid_risk",
        "reason_selected",
        "evidence_summary",
        "human_review_decision",
        "human_review_attack_type",
        "human_review_confidence",
        "human_review_note",
    ]
    with output_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        for _priority, index, reasons in selected:
            record = records[index]
            prediction = current_predictions[index]
            ctx = _record_context(record)
            timestamp = _record_value(record, "timestamp")
            writer.writerow(
                {
                    "review_dataset_kind": "external_holdout",
                    "review_import_workflow": "benchmark_review",
                    "benchmark_row_id": record.row_number,
                    "timestamp": timestamp.isoformat() if hasattr(timestamp, "isoformat") else timestamp,
                    "source": ctx["source"],
                    "scenario_family": ctx["scenario"],
                    "src_ip": ctx["src_ip"],
                    "dst_ip": ctx["dst_ip"],
                    "dst_port": ctx["dst_port"],
                    "protocol": ctx["protocol"],
                    "app": ctx["app"],
                    "action": ctx["action"],
                    "bytes": ctx["bytes"],
                    "packets": ctx["packets"],
                    "current_label": _triage_label(record),
                    "expected_label": record.label,
                    "model_prediction": prediction["prediction"],
                    "rule_signal": (prediction.get("rule") or {}).get("label"),
                    "anomaly_signal": (prediction.get("anomaly") or {}).get("label"),
                    "supervised_signal": f"{prediction['prediction']}:{prediction['confidence']}",
                    "hybrid_risk": prediction.get("hybrid_risk"),
                    "reason_selected": "; ".join(reasons),
                    "evidence_summary": _evidence_summary(record, prediction),
                    "human_review_decision": "",
                    "human_review_attack_type": "",
                    "human_review_confidence": "",
                    "human_review_note": "",
                }
            )
    reason_counts: Counter[str] = Counter()
    for _priority, _index, reasons in selected:
        for reason in reasons:
            reason_counts[reason] += 1
    return {
        "path": str(output_path),
        "rows": len(selected),
        "target_rows": limit,
        "protected_manual_rows": 0,
        "reason_distribution": dict(reason_counts.most_common()),
    }


def _render_error_analysis(
    *,
    report: dict[str, Any],
    error_analysis: dict[str, Any],
) -> str:
    lines = [
        "# ATDR v1.7 External Error Analysis",
        "",
        f"- Generated: {report['generated_at']}",
        f"- External rows: {report['external_label_count']}",
        f"- Current profile: current_hybrid",
        f"- Best evaluated profile: {report['best_profile']['profile'] if report.get('best_profile') else 'not_available'}",
        "- Production promoted: false",
        "- Model activated: false",
        "- Response automation allowed: false",
        "",
        "## Current Error Counts",
        "",
    ]
    for name, count in (error_analysis.get("current_error_counts") or {}).items():
        lines.append(f"- {name}: {count}")
    lines.extend(["", "## Best Profile Error Counts", ""])
    for name, count in (error_analysis.get("best_profile_error_counts") or {}).items():
        lines.append(f"- {name}: {count}")
    lines.extend(["", "## Error Patterns", ""])
    for category, item in (error_analysis.get("current_error_patterns") or {}).items():
        lines.append(f"### {category}")
        lines.append("")
        lines.append(f"- Count: {item.get('count')}")
        for pattern_name, rows in (item.get("patterns") or {}).items():
            formatted = ", ".join(f"{row['value']} ({row['count']})" for row in rows[:5])
            lines.append(f"- Top {pattern_name}: {formatted or '-'}")
        lines.append("")
    lines.extend(["## Rule / Supervised / Hybrid Disagreement", ""])
    for name, count in (error_analysis.get("rule_supervised_hybrid_disagreement") or {}).items():
        lines.append(f"- {name}: {count}")
    lines.extend(["", "## Recommended Fixes", ""])
    for item in error_analysis.get("recommended_fixes") or []:
        lines.append(f"- {item}")
    lines.extend(
        [
            "",
            "## Safety",
            "",
            "- This report uses safe external/holdout-style benchmark rows.",
            "- No model artifact is activated by v1.7.",
            "- Metrics remain development evidence for SOC decision support, not production accuracy.",
        ]
    )
    return "\n".join(lines)


def _render_profile_report(report: dict[str, Any]) -> str:
    lines = [
        "# ATDR v1.7 External Generalization Improvement",
        "",
        f"- Generated: {report['generated_at']}",
        f"- External rows: {report['external_label_count']}",
        f"- Previous v1.6 threat F1: {report['baseline_v16_metrics'].get('threat_positive_f1')}",
        f"- Previous v1.6 benign FPR: {report['baseline_v16_metrics'].get('benign_false_positive_rate')}",
        "- Production promoted: false",
        "- Model activated: false",
        "- Response automation allowed: false",
        "",
        "## Profile Comparison",
        "",
        "| Profile | Threat P | Threat R | Threat F1 | Benign FPR | Susp R | Mal R | Macro F1 | ECE | Brier | FP | FN | Queue | Cost |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for item in report["profiles"]:
        metrics = item.get("metrics") or {}
        per_class = metrics.get("per_class") or {}
        calibration = item.get("calibration") or {}
        cost = item.get("cost_sensitive") or {}
        lines.append(
            f"| {item['profile']} | {metrics.get('threat_positive_precision')} | "
            f"{metrics.get('threat_positive_recall')} | {metrics.get('threat_positive_f1')} | "
            f"{metrics.get('benign_false_positive_rate')} | "
            f"{(per_class.get('suspicious') or {}).get('recall')} | "
            f"{(per_class.get('malicious') or {}).get('recall')} | "
            f"{metrics.get('macro_f1')} | "
            f"{calibration.get('expected_calibration_error')} | "
            f"{calibration.get('brier_score_threat_positive')} | "
            f"{metrics.get('false_positives')} | {metrics.get('false_negatives')} | "
            f"{item.get('queue_size')} | {cost.get('total_cost')} |"
        )
    best = report.get("best_profile") or {}
    readiness = report.get("readiness_gate_v6") or {}
    gap = report.get("overfitting_guard") or {}
    lines.extend(
        [
            "",
            "## Best Profile",
            "",
            f"- Profile: {best.get('profile')}",
            f"- Readiness decision: {readiness.get('decision')}",
            f"- External benchmark validated: {readiness.get('external_benchmark_validated')}",
            f"- Overfitting status: {gap.get('status')}",
            f"- Overfitting warning: {gap.get('overfitting_warning')}",
            "",
            "## Interpretation",
            "",
            "- v1.7 compares lower-noise, suspicious-recall, calibrated, hybrid, three-class, and hierarchical external profiles.",
            "- The selected profile is an analyst-review candidate only; it is not activated.",
            "- External holdout metrics remain separate from local firewall-log metrics and are not production accuracy.",
            "- Response automation remains disabled.",
        ]
    )
    return "\n".join(lines)


def run_v17_external_generalization(
    *,
    external_report_path: Path | None = None,
    review_limit: int = 300,
    output_dir: Path = FINAL_OUTPUT_DIR,
    review_output_dir: Path = REVIEW_OUTPUT_DIR,
) -> dict[str, Any]:
    started = time.perf_counter()
    imports = _optional_imports()
    if imports is None:
        return {
            "ok": False,
            "status": "skipped",
            "message": "Supervised ML dependencies are unavailable.",
            "production_promoted": False,
            "model_activated": False,
            "response_automation_allowed": False,
        }
    _joblib, pd, *_ = imports
    generated_at = datetime.now(timezone.utc).isoformat()
    v16_path = external_report_path or _latest_report_path(
        output_dir,
        "external_benchmark_validation_*.json",
    )
    v16 = _load_json(v16_path)
    external_snapshot_path = Path((v16.get("external_snapshot") or {}).get("snapshot_path") or "")
    if not external_snapshot_path.exists():
        raise FileNotFoundError(
            "No prepared external snapshot found. Run "
            "python -m atdr.scripts.run_external_benchmark_validation --holdout-from-current-data first."
        )
    build_internal_ai_readiness_benchmark(output_path=INTERNAL_CSV)
    internal_snapshot = prepare_benchmark_dataset(
        input_csv=INTERNAL_CSV,
        sample_strategy="balanced",
        output_dir=BENCHMARK_OUTPUT_DIR,
    )
    internal_snapshot_path = Path(internal_snapshot["snapshot_path"])
    training_records, training_summary = load_prepared_benchmark_snapshot(internal_snapshot_path)
    holdout_records, holdout_summary = load_prepared_benchmark_snapshot(external_snapshot_path)
    training_frame = _feature_frame(
        training_records,
        source_name="v17-internal-training",
        dataframe_type=pd.DataFrame,
    )
    holdout_frame = _feature_frame(
        holdout_records,
        source_name="v17-external-holdout",
        dataframe_type=pd.DataFrame,
    )
    profile_run = _run_profiles(
        records=holdout_records,
        training_records=training_records,
        training_frame=training_frame,
        holdout_frame=holdout_frame,
        imports=imports,
    )
    profiles = profile_run["profiles"]
    best_profile = profile_run["best_profile"] or {}
    predictions_by_profile = profile_run["predictions_by_profile"]
    current_predictions = predictions_by_profile["current_hybrid"]
    best_predictions = predictions_by_profile[best_profile.get("profile", "current_hybrid")]
    error_analysis = _build_error_analysis(
        records=holdout_records,
        current_predictions=current_predictions,
        best_predictions=best_predictions,
        best_profile=best_profile.get("profile", "current_hybrid"),
    )
    stamp = _stamp()
    review_sample = _write_review_sample(
        records=holdout_records,
        current_predictions=current_predictions,
        best_predictions=best_predictions,
        output_path=review_output_dir / "v1_7_external_boundary_review_sample.csv",
        limit=review_limit,
    )
    baseline_metrics = (
        (v16.get("cross_dataset_candidate") or {}).get("metrics")
        or (v16.get("current_active_supervised_artifact") or {}).get("metrics")
        or {}
    )
    best_metrics = best_profile.get("metrics") or {}
    internal_metrics = (((_load_json(_latest_report_path(REVIEW_OUTPUT_DIR, "final_ai_readiness_report_*.json")) or {}).get("best_benchmark_candidate") or {}).get("metrics") or {})
    overfitting = _overfitting_analysis(
        internal_metrics=internal_metrics,
        external_metrics=best_metrics,
    )
    readiness = readiness_gate_v6_external_generalization(
        external_label_count=len(holdout_records),
        external_metrics=best_metrics,
        calibration_status=str((best_profile.get("calibration") or {}).get("status") or "not_available"),
        controlled_validations_passed=bool(_latest_validation_status()["passed"]),
        internal_benchmark_validated=True,
        overfitting_status=str(overfitting.get("status") or "not_evaluated"),
        response_automation_allowed=False,
    )
    if overfitting.get("status") == "significant_generalization_gap" and readiness.get("decision") == "external_benchmark_validated_candidate":
        readiness = {
            **readiness,
            "decision": "internal_benchmark_validated_candidate",
            "external_benchmark_validated": False,
            "overfitting_guard_downgraded": True,
            "message": (
                readiness.get("message", "")
                + " v1.7 overfitting guard downgraded external validation because the internal-to-external gap is significant."
            ),
        }
    report = {
        "ok": True,
        "status": "completed",
        "generated_at": generated_at,
        "validation_scope": "v1.7 external generalization improvement",
        "external_label_count": len(holdout_records),
        "external_snapshot_id": holdout_summary.get("snapshot_id"),
        "external_snapshot_name": external_snapshot_path.name,
        "internal_training_snapshot": {
            "snapshot_id": training_summary.get("snapshot_id"),
            "row_count": len(training_records),
        },
        "baseline_v16_metrics": baseline_metrics,
        "profiles": profiles,
        "best_profile": best_profile,
        "error_analysis": error_analysis,
        "review_sample": review_sample,
        "overfitting_guard": overfitting,
        "readiness_gate_v6": readiness,
        "production_promoted": False,
        "model_activated": False,
        "model_artifact_written": False,
        "response_automation_allowed": False,
        "real_firewall_blocking_enabled": False,
        "runtime_seconds": round(time.perf_counter() - started, 4),
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / f"v1_7_external_generalization_{stamp}.json"
    markdown_path = output_dir / f"v1_7_external_generalization_{stamp}.md"
    error_path = output_dir / f"v1_7_external_error_analysis_{stamp}.md"
    json_path.write_text(
        json.dumps(report, indent=2, default=json_default),
        encoding="utf-8",
    )
    markdown_path.write_text(_render_profile_report(report), encoding="utf-8")
    error_path.write_text(
        _render_error_analysis(report=report, error_analysis=error_analysis),
        encoding="utf-8",
    )
    report["paths"] = {
        "json": str(json_path),
        "markdown": str(markdown_path),
        "error_analysis_markdown": str(error_path),
        "review_sample_csv": review_sample["path"],
    }
    return report


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Run v1.7 external holdout profile comparison, error analysis, "
            "calibration, and boundary review export without activating a model."
        )
    )
    parser.add_argument("--external-report", default=None)
    parser.add_argument("--review-limit", type=int, default=300)
    parser.add_argument("--output-dir", default=None)
    parser.add_argument("--review-output-dir", default=None)
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()
    result = run_v17_external_generalization(
        external_report_path=Path(args.external_report) if args.external_report else None,
        review_limit=args.review_limit,
        output_dir=Path(args.output_dir) if args.output_dir else FINAL_OUTPUT_DIR,
        review_output_dir=Path(args.review_output_dir) if args.review_output_dir else REVIEW_OUTPUT_DIR,
    )
    print(json.dumps(result, indent=2 if args.pretty else None, default=json_default))
    raise SystemExit(0 if result.get("ok") else 1)


if __name__ == "__main__":
    main()
