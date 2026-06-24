import csv
import json
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from atdr.app.db.models import MLLabel, MLModelRun, NormalizedLog, ResponseAction
from atdr.app.detection.rules import build_detection_context, evaluate_rules
from atdr.app.detection.scoring import clamp_score
from atdr.app.detection.supervised_detector import (
    TRAINABLE_LABELS,
    _latest_labels,
    _metrics_from_predictions,
    _model_for_type,
    _optional_imports,
    _sample_weights,
    _split_class_warnings,
    _split_indices,
    training_dataset_diagnostics,
)
from atdr.app.detection.v330_detection_ml_quality import (
    BENIGN_LIKE_LABELS,
    OUTPUT_DIR,
    REVIEW_FIELDS,
    THREAT_LABELS,
    _best_profile as _v330_best_profile,
    _metrics_bundle as _v330_metrics_bundle,
    _prepare_dataset,
    _profile_decision,
    _profile_summary as _v330_profile_summary,
    _source_name,
    _stamp,
    _threat_score,
)
from atdr.app.ml.features import CATEGORICAL_FEATURES, NUMERIC_FEATURES
from atdr.app.services.class_temporal_coverage_service import build_class_temporal_coverage


V331_PROFILES = {
    "balanced": {"malicious": 0.45, "threat_positive": 0.55, "needs_context": 0.50},
    "precision_focused": {"malicious": 0.72, "threat_positive": 0.78, "needs_context": 0.55},
    "low_noise_soc_queue": {"malicious": 0.82, "threat_positive": 0.88, "needs_context": 0.55},
    "calibrated_low_noise": {"malicious": 0.78, "threat_positive": 0.83, "needs_context": 0.55},
    "threat_recall": {"malicious": 0.28, "threat_positive": 0.38, "needs_context": 0.45},
}
V331_PROFILE_ORDER = [
    "balanced",
    "precision_focused",
    "low_noise_soc_queue",
    "calibrated_low_noise",
    "threat_recall",
]


def _log_timestamp(log: NormalizedLog) -> datetime | None:
    return log.generated_time or log.receive_time or log.start_time


def _lower(value: str | None) -> str:
    return (value or "").strip().lower()


def _is_quic_443_allow(log: NormalizedLog) -> bool:
    return _lower(log.app) == "quic-base" and _lower(log.action) == "allow" and log.dst_port == 443


def _is_incomplete_allow_80(log: NormalizedLog) -> bool:
    return _lower(log.app) == "incomplete" and _lower(log.action) == "allow" and log.dst_port == 80


def _is_unknown_udp(log: NormalizedLog) -> bool:
    return _lower(log.app) == "unknown-udp" or (_lower(log.protocol) == "udp" and _lower(log.app).startswith("unknown"))


def _is_app_risk_only(rule_codes: set[str]) -> bool:
    if not rule_codes:
        return False
    allowed = {"app_risk_4", "app_risk_5", "suspicious_app_characteristic"}
    return bool(rule_codes) and rule_codes.issubset(allowed)


def _build_pipeline_for_columns(
    imports,
    *,
    model_type: str,
    class_weight: str | None,
    numeric_features: list[str],
    categorical_features: list[str],
):
    _, _, ColumnTransformer, RandomForestClassifier, SimpleImputer, *_rest, Pipeline, OneHotEncoder = imports
    preprocessor = ColumnTransformer(
        transformers=[
            ("numeric", SimpleImputer(strategy="median"), numeric_features),
            (
                "categorical",
                Pipeline(
                    steps=[
                        ("imputer", SimpleImputer(strategy="most_frequent")),
                        ("onehot", OneHotEncoder(handle_unknown="ignore")),
                    ]
                ),
                categorical_features,
            ),
        ]
    )
    return Pipeline(
        steps=[
            ("preprocess", preprocessor),
            ("model", _model_for_type(model_type, RandomForestClassifier, class_weight=class_weight)),
        ]
    )


def _augment_frame(prepared: dict[str, Any]) -> tuple[Any, dict[str, Any]]:
    frame = prepared["frame"].copy()
    logs = prepared["logs"]
    context = build_detection_context(logs)
    rule_code_rows: list[set[str]] = []
    rule_scores: list[float] = []
    quic_no_rule: list[int] = []
    quic_any_rule: list[int] = []
    incomplete_allow_80: list[int] = []
    unknown_udp_scan_context: list[int] = []
    app_risk_only: list[int] = []
    benign_web_allow_no_rule: list[int] = []
    benign_network_utility_no_rule: list[int] = []

    for position, log in enumerate(logs):
        matches = evaluate_rules(log, context)
        codes = {match.code for match in matches}
        rule_code_rows.append(codes)
        rule_score = clamp_score(sum(match.score for match in matches))
        rule_scores.append(float(rule_score))
        is_quic = _is_quic_443_allow(log)
        is_incomplete_80 = _is_incomplete_allow_80(log)
        unique_dst_ips = int(frame.iloc[position].get("src_ip_5min_unique_dst_ips") or 0)
        unique_dst_ports = int(frame.iloc[position].get("src_ip_5min_unique_dst_ports") or 0)
        is_unknown_scan = _is_unknown_udp(log) and unique_dst_ips >= 8 and unique_dst_ports >= 4
        has_no_rule = len(codes) == 0
        app_risk_only_value = _is_app_risk_only(codes)
        quic_no_rule.append(int(is_quic and has_no_rule))
        quic_any_rule.append(int(is_quic and not has_no_rule))
        incomplete_allow_80.append(int(is_incomplete_80))
        unknown_udp_scan_context.append(int(is_unknown_scan))
        app_risk_only.append(int(app_risk_only_value))
        benign_web_allow_no_rule.append(
            int(
                has_no_rule
                and _lower(log.action) == "allow"
                and log.dst_port in {80, 443}
                and _lower(log.app) in {"ssl", "web-browsing", "quic-base"}
            )
        )
        benign_network_utility_no_rule.append(
            int(has_no_rule and _lower(log.action) == "allow" and _lower(log.app) in {"ping", "icmp"})
        )

    frame["v331_quic_443_allow_no_rule_flag"] = quic_no_rule
    frame["v331_quic_443_allow_with_rule_flag"] = quic_any_rule
    frame["v331_incomplete_allow_80_flag"] = incomplete_allow_80
    frame["v331_unknown_udp_scan_context_flag"] = unknown_udp_scan_context
    frame["v331_app_risk_only_flag"] = app_risk_only
    frame["v331_benign_web_allow_no_rule_flag"] = benign_web_allow_no_rule
    frame["v331_benign_network_utility_no_rule_flag"] = benign_network_utility_no_rule
    frame["v331_rule_score"] = rule_scores

    numeric = [
        *NUMERIC_FEATURES,
        "v331_quic_443_allow_no_rule_flag",
        "v331_quic_443_allow_with_rule_flag",
        "v331_incomplete_allow_80_flag",
        "v331_unknown_udp_scan_context_flag",
        "v331_app_risk_only_flag",
        "v331_benign_web_allow_no_rule_flag",
        "v331_benign_network_utility_no_rule_flag",
        "v331_rule_score",
    ]
    return frame, {
        "numeric_features": numeric,
        "categorical_features": list(CATEGORICAL_FEATURES),
        "rule_code_rows": rule_code_rows,
        "experimental_features": [
            "v331_quic_443_allow_no_rule_flag",
            "v331_quic_443_allow_with_rule_flag",
            "v331_incomplete_allow_80_flag",
            "v331_unknown_udp_scan_context_flag",
            "v331_app_risk_only_flag",
            "v331_benign_web_allow_no_rule_flag",
            "v331_benign_network_utility_no_rule_flag",
            "v331_rule_score",
        ],
    }


def _apply_low_signal_benign_guard(
    prepared: dict[str, Any],
    augmented: dict[str, Any],
    predictions: list[str],
) -> list[str]:
    guarded: list[str] = []
    frame = augmented["frame"]
    for position, prediction in enumerate(predictions):
        if prediction not in THREAT_LABELS:
            guarded.append(prediction)
            continue
        absolute_index = prepared["test_idx"][position]
        row = frame.iloc[absolute_index]
        if bool(row.get("v331_quic_443_allow_no_rule_flag")) or bool(
            row.get("v331_benign_network_utility_no_rule_flag")
        ):
            guarded.append("benign")
        else:
            guarded.append(prediction)
    return guarded


def _noise_reduced_weights(labels: list[MLLabel], strategy: str) -> tuple[list[float] | None, dict[str, Any]]:
    if strategy == "current":
        return _sample_weights(labels)
    if strategy == "none":
        return None, {"enabled": False, "strategy": strategy}
    multipliers_by_strategy = {
        "lower_threat": {
            "benign": 2.5,
            "benign_unusual": 2.0,
            "needs_context": 1.6,
            "suspicious": 0.95,
            "malicious": 1.1,
        },
        "strong_benign": {
            "benign": 4.5,
            "benign_unusual": 3.4,
            "needs_context": 2.2,
            "suspicious": 0.75,
            "malicious": 1.0,
        },
    }
    multipliers = multipliers_by_strategy[strategy]
    values: list[float] = []
    grouped: dict[str, list[float]] = defaultdict(list)
    for label in labels:
        source = str(label.label_source or "manual")
        reviewed = bool(label.reviewed)
        weight = 2.0 if reviewed else 0.6
        if source.startswith("assisted") and not reviewed:
            weight *= 0.75
        weight *= multipliers.get(label.label, 1.0)
        if label.confidence >= 4:
            weight *= 1.15
        elif label.confidence <= 2:
            weight *= 0.8
        value = round(min(weight, 20.0), 4)
        values.append(value)
        grouped[label.label].append(value)
    return values, {
        "enabled": True,
        "strategy": strategy,
        "min_weight": min(values, default=0),
        "max_weight": max(values, default=0),
        "average_weight": round(sum(values) / len(values), 4) if values else 0,
        "average_weight_by_label": {
            label: round(sum(items) / len(items), 4) for label, items in sorted(grouped.items())
        },
    }


def _classes(model: Any) -> list[str]:
    if hasattr(model, "classes_"):
        return [str(value) for value in model.classes_]
    nested = getattr(model, "named_steps", {}).get("model")
    return [str(value) for value in getattr(nested, "classes_", [])]


def _hard_gate_decision(class_probs: dict[str, float], *, profile: str, mode: str) -> str:
    thresholds = V331_PROFILES[profile]
    if mode == "binary":
        return (
            "threat_positive"
            if float(class_probs.get("threat_positive", 0.0)) >= thresholds["threat_positive"]
            else "benign_like"
        )
    malicious = float(class_probs.get("malicious", 0.0))
    suspicious = float(class_probs.get("suspicious", 0.0))
    threat = malicious + suspicious
    if malicious >= thresholds["malicious"]:
        return "malicious"
    if threat >= thresholds["threat_positive"]:
        return "malicious" if malicious > suspicious else "suspicious"
    if mode == "three_class":
        return "benign_like"
    needs_context = float(class_probs.get("needs_context", 0.0))
    if needs_context >= thresholds["needs_context"]:
        return "needs_context"
    fallback = {
        "benign": float(class_probs.get("benign", 0.0)),
        "benign_unusual": float(class_probs.get("benign_unusual", 0.0)),
        "needs_context": needs_context,
    }
    return max(fallback.items(), key=lambda item: item[1])[0]


def _probability_rows(probabilities: Any, classes: list[str]) -> list[dict[str, float]]:
    return [{label: float(value) for label, value in zip(classes, row, strict=False)} for row in probabilities]


def _mapped_labels(labels: list[str], mode: str) -> list[str]:
    if mode == "binary":
        return ["threat_positive" if label in THREAT_LABELS else "benign_like" for label in labels]
    if mode == "three_class":
        return [label if label in THREAT_LABELS else "benign_like" for label in labels]
    return labels


def _threat_binary_metrics(y_true: list[str], predictions: list[str], *, threat_labels: set[str]) -> dict[str, Any]:
    tp = fp = fn = tn = 0
    for actual, predicted in zip(y_true, predictions, strict=False):
        actual_threat = actual in threat_labels
        predicted_threat = predicted in threat_labels
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


def _metric_bundle(
    prepared: dict[str, Any],
    *,
    y_true: list[str],
    predictions: list[str],
    labels_order: list[str],
    threat_labels: set[str],
) -> dict[str, Any]:
    imports = prepared["imports"]
    metrics = _metrics_from_predictions(
        accuracy_score=imports[5],
        confusion_matrix=imports[6],
        precision_recall_fscore_support=imports[7],
        y_true=y_true,
        predictions=predictions,
        labels_order=labels_order,
    )
    threat = _threat_binary_metrics(y_true, predictions, threat_labels=threat_labels)
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


def _calibration_report(y_true: list[str], probabilities: Any, classes: list[str], *, threat_labels: set[str]) -> dict[str, Any]:
    if not len(probabilities):
        return {"status": "unavailable", "passed": False, "buckets": []}
    rows: list[tuple[float, bool]] = []
    brier_total = 0.0
    for actual, row in zip(y_true, probabilities, strict=False):
        values = [float(value) for value in row]
        predicted_index = max(range(len(values)), key=values.__getitem__)
        confidence = values[predicted_index]
        predicted = classes[predicted_index]
        rows.append((confidence, predicted == actual))
        threat_probability = sum(value for label, value in zip(classes, values, strict=False) if label in threat_labels)
        actual_threat = 1.0 if actual in threat_labels else 0.0
        brier_total += (threat_probability - actual_threat) ** 2
    minimum_bucket_rows = max(10, int(len(rows) * 0.02 + 0.999))
    buckets: list[dict[str, Any]] = []
    for lower in (0.0, 0.2, 0.4, 0.6, 0.8):
        upper = lower + 0.2
        selected = [
            (confidence, correct)
            for confidence, correct in rows
            if confidence >= lower and (confidence < upper or upper >= 1.0)
        ]
        if not selected:
            continue
        average_confidence = sum(item[0] for item in selected) / len(selected)
        accuracy = sum(1 for _confidence, correct in selected if correct) / len(selected)
        buckets.append(
            {
                "range": f"{lower:.1f}-{min(upper, 1.0):.1f}",
                "rows": len(selected),
                "average_confidence": round(average_confidence, 4),
                "accuracy": round(accuracy, 4),
                "gap": round(abs(average_confidence - accuracy), 4),
                "reliable": len(selected) >= minimum_bucket_rows,
            }
        )
    total = len(rows)
    expected_calibration_error = sum(item["rows"] / total * item["gap"] for item in buckets) if total else 1.0
    reliable = [item for item in buckets if item["reliable"]]
    max_gap = max((float(item["gap"]) for item in reliable), default=1.0)
    passed = bool(reliable) and max_gap <= 0.2 and expected_calibration_error <= 0.15
    return {
        "status": "passed" if passed else "weak",
        "passed": passed,
        "rows": total,
        "brier_score_threat_positive": round(brier_total / total, 4) if total else None,
        "expected_calibration_error": round(expected_calibration_error, 4),
        "max_confidence_accuracy_gap": round(max_gap, 4),
        "minimum_reliable_bucket_rows": minimum_bucket_rows,
        "buckets": buckets,
        "readiness_buckets": reliable,
    }


def _profile_predictions(probabilities: Any, classes: list[str], *, mode: str) -> dict[str, list[str]]:
    prob_rows = _probability_rows(probabilities, classes)
    return {
        profile: [_hard_gate_decision(row, profile=profile, mode=mode) for row in prob_rows]
        for profile in V331_PROFILE_ORDER
    }


def _fit_strategy(
    prepared: dict[str, Any],
    augmented: dict[str, Any],
    *,
    name: str,
    model_type: str,
    target_mode: str,
    class_weight: str | None,
    weight_strategy: str,
    use_augmented_features: bool,
    calibrated: bool = False,
    postprocess_low_signal_guard: bool = False,
) -> dict[str, Any]:
    frame = augmented["frame"] if use_augmented_features else prepared["frame"]
    numeric = augmented["numeric_features"] if use_augmented_features else list(NUMERIC_FEATURES)
    categorical = augmented["categorical_features"] if use_augmented_features else list(CATEGORICAL_FEATURES)
    labels = prepared["labels"]
    train_idx = prepared["train_idx"]
    test_idx = prepared["test_idx"]
    y = _mapped_labels(prepared["y"], target_mode)
    y_train = [y[index] for index in train_idx]
    y_test = [y[index] for index in test_idx]
    pipeline = _build_pipeline_for_columns(
        prepared["imports"],
        model_type=model_type,
        class_weight=class_weight,
        numeric_features=numeric,
        categorical_features=categorical,
    )
    weights, weight_summary = _noise_reduced_weights(labels, weight_strategy)
    started = time.perf_counter()
    if calibrated:
        from sklearn.calibration import CalibratedClassifierCV

        min_train_support = min(Counter(y_train).values(), default=0)
        if min_train_support < 3:
            return {
                "name": name,
                "status": "skipped",
                "message": "Not enough per-class support for 3-fold calibration.",
                "profiles": {},
            }
        model = CalibratedClassifierCV(estimator=pipeline, method="sigmoid", cv=3)
        model.fit(frame.iloc[train_idx], y_train)
    else:
        model = pipeline
        fit_kwargs = {}
        if weights is not None:
            fit_kwargs["model__sample_weight"] = [weights[index] for index in train_idx]
        model.fit(frame.iloc[train_idx], y_train, **fit_kwargs)
    training_seconds = time.perf_counter() - started
    probabilities = model.predict_proba(frame.iloc[test_idx])
    classes = _classes(model)
    mode_for_decision = "binary" if target_mode == "binary" else "three_class" if target_mode == "three_class" else "flat"
    predictions_by_profile = _profile_predictions(probabilities, classes, mode=mode_for_decision)
    if postprocess_low_signal_guard and target_mode == "flat":
        predictions_by_profile = {
            profile: _apply_low_signal_benign_guard(prepared, augmented, predictions)
            for profile, predictions in predictions_by_profile.items()
        }
    if target_mode == "binary":
        labels_order = ["benign_like", "threat_positive"]
        threat_labels = {"threat_positive"}
    elif target_mode == "three_class":
        labels_order = ["benign_like", "malicious", "suspicious"]
        threat_labels = set(THREAT_LABELS)
    else:
        labels_order = sorted(set(prepared["y"]))
        threat_labels = set(THREAT_LABELS)
    profiles = {
        profile: _metric_bundle(
            prepared,
            y_true=y_test,
            predictions=predictions,
            labels_order=labels_order,
            threat_labels=threat_labels,
        )
        for profile, predictions in predictions_by_profile.items()
    }
    return {
        "name": name,
        "status": "evaluated",
        "model_type": model_type,
        "target_mode": target_mode,
        "class_weight": class_weight or "none",
        "sample_weighting": weight_summary,
        "use_augmented_features": use_augmented_features,
        "calibrated": calibrated,
        "postprocess_low_signal_guard": postprocess_low_signal_guard,
        "training_seconds": round(training_seconds, 4),
        "profiles": profiles,
        "calibration": _calibration_report(y_test, probabilities, classes, threat_labels=threat_labels),
        "_probabilities": probabilities,
        "_classes": classes,
        "_predictions": predictions_by_profile,
        "_y_test": y_test,
    }


def _fit_hierarchical_strategy(prepared: dict[str, Any], augmented: dict[str, Any]) -> dict[str, Any]:
    frame = augmented["frame"]
    labels = prepared["labels"]
    train_idx = prepared["train_idx"]
    test_idx = prepared["test_idx"]
    y = prepared["y"]
    stage1_y = ["threat_positive" if label in THREAT_LABELS else "benign_like" for label in y]
    weights, weight_summary = _noise_reduced_weights(labels, "strong_benign")
    started = time.perf_counter()
    stage1 = _build_pipeline_for_columns(
        prepared["imports"],
        model_type="extra_trees",
        class_weight=None,
        numeric_features=augmented["numeric_features"],
        categorical_features=augmented["categorical_features"],
    )
    stage1.fit(
        frame.iloc[train_idx],
        [stage1_y[index] for index in train_idx],
        model__sample_weight=[weights[index] for index in train_idx],
    )
    threat_train_idx = [index for index in train_idx if y[index] in THREAT_LABELS]
    if len(threat_train_idx) < 3 or len({y[index] for index in threat_train_idx}) < 2:
        return {
            "name": "hierarchical_two_stage_augmented",
            "status": "skipped",
            "message": "Not enough threat-class support for stage 2.",
            "profiles": {},
        }
    stage2 = _build_pipeline_for_columns(
        prepared["imports"],
        model_type="extra_trees",
        class_weight="balanced",
        numeric_features=augmented["numeric_features"],
        categorical_features=augmented["categorical_features"],
    )
    stage2.fit(
        frame.iloc[threat_train_idx],
        [y[index] for index in threat_train_idx],
        model__sample_weight=[weights[index] for index in threat_train_idx],
    )
    stage1_probabilities = stage1.predict_proba(frame.iloc[test_idx])
    stage1_classes = _classes(stage1)
    stage2_probabilities = stage2.predict_proba(frame.iloc[test_idx])
    stage2_classes = _classes(stage2)
    y_test = [value if value in THREAT_LABELS else "benign_like" for value in prepared["y_test"]]
    profiles: dict[str, Any] = {}
    for profile, thresholds in V331_PROFILES.items():
        predictions: list[str] = []
        for stage1_row, stage2_row in zip(stage1_probabilities, stage2_probabilities, strict=False):
            stage1_probs = {
                label: float(value) for label, value in zip(stage1_classes, stage1_row, strict=False)
            }
            if float(stage1_probs.get("threat_positive", 0.0)) < thresholds["threat_positive"]:
                predictions.append("benign_like")
                continue
            stage2_probs = {
                label: float(value) for label, value in zip(stage2_classes, stage2_row, strict=False)
            }
            predictions.append(
                "malicious"
                if float(stage2_probs.get("malicious", 0.0)) >= float(stage2_probs.get("suspicious", 0.0))
                else "suspicious"
            )
        profiles[profile] = _metric_bundle(
            prepared,
            y_true=y_test,
            predictions=predictions,
            labels_order=["benign_like", "malicious", "suspicious"],
            threat_labels=set(THREAT_LABELS),
        )
    return {
        "name": "hierarchical_two_stage_augmented",
        "status": "evaluated",
        "model_type": "extra_trees_two_stage",
        "target_mode": "hierarchical",
        "class_weight": "mixed",
        "sample_weighting": weight_summary,
        "use_augmented_features": True,
        "calibrated": False,
        "training_seconds": round(time.perf_counter() - started, 4),
        "profiles": profiles,
        "calibration": _calibration_report(
            [stage1_y[index] for index in test_idx],
            stage1_probabilities,
            stage1_classes,
            threat_labels={"threat_positive"},
        ),
    }


def _strategy_best_profile(strategy: dict[str, Any]) -> str | None:
    if not strategy.get("profiles"):
        return None
    candidates = []
    for profile, metrics in strategy["profiles"].items():
        summary = _profile_summary(metrics)
        fpr = float(summary.get("benign_like_false_positive_rate") if summary.get("benign_like_false_positive_rate") is not None else 1)
        threat_f1 = float(summary.get("threat_positive_f1") or 0)
        threat_recall = float(summary.get("threat_positive_recall") or 0)
        suspicious = summary.get("suspicious_recall")
        suspicious_score = float(suspicious) if suspicious is not None else threat_recall
        malicious = summary.get("malicious_recall")
        malicious_score = float(malicious) if malicious is not None else threat_recall
        candidates.append((profile, fpr, threat_f1, threat_recall, suspicious_score, malicious_score))
    viable = [item for item in candidates if item[1] <= 0.15 and item[2] >= 0.70 and item[3] >= 0.55]
    ranked = viable or candidates
    return max(
        ranked,
        key=lambda item: (
            item[2] - 0.45 * item[1],
            -item[1],
            item[3],
            item[4],
            item[5],
        ),
    )[0]


def _select_best_strategy(strategies: list[dict[str, Any]]) -> tuple[dict[str, Any] | None, str | None]:
    candidates = []
    for strategy in strategies:
        profile = strategy.get("recommended_profile")
        if not profile:
            continue
        summary = strategy.get("recommended_metrics") or {}
        fpr = float(summary.get("benign_like_false_positive_rate") if summary.get("benign_like_false_positive_rate") is not None else 1)
        threat_f1 = float(summary.get("threat_positive_f1") or 0)
        threat_recall = float(summary.get("threat_positive_recall") or 0)
        suspicious = summary.get("suspicious_recall")
        suspicious_score = float(suspicious) if suspicious is not None else threat_recall
        malicious = summary.get("malicious_recall")
        malicious_score = float(malicious) if malicious is not None else threat_recall
        candidates.append((strategy, profile, fpr, threat_f1, threat_recall, suspicious_score, malicious_score))
    viable = [item for item in candidates if item[2] <= 0.15 and item[3] >= 0.70 and item[4] >= 0.55]
    ranked = viable or candidates
    winner = max(
        ranked,
        key=lambda item: (
            item[3] - 0.45 * item[2],
            -item[2],
            item[4],
            item[5],
            item[6],
        ),
        default=None,
    )
    return (winner[0], winner[1]) if winner else (None, None)


def _false_positive_pattern_report(
    prepared: dict[str, Any],
    predictions: list[str],
    *,
    augmented: dict[str, Any],
) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    frame = augmented["frame"]
    test_idx = prepared["test_idx"]
    for position, (actual, predicted) in enumerate(zip(prepared["y_test"], predictions, strict=False)):
        if actual not in BENIGN_LIKE_LABELS or predicted not in THREAT_LABELS:
            continue
        log = prepared["test_logs"][position]
        absolute_index = test_idx[position]
        rule_codes = augmented["rule_code_rows"][absolute_index]
        rows.append(
            {
                "label": prepared["test_labels"][position],
                "log": log,
                "actual": actual,
                "predicted": predicted,
                "rule_codes": rule_codes,
                "quic_no_rule": bool(frame.iloc[absolute_index].get("v331_quic_443_allow_no_rule_flag")),
                "quic_with_rule": bool(frame.iloc[absolute_index].get("v331_quic_443_allow_with_rule_flag")),
                "incomplete_allow_80": bool(frame.iloc[absolute_index].get("v331_incomplete_allow_80_flag")),
                "unknown_udp_scan_context": bool(frame.iloc[absolute_index].get("v331_unknown_udp_scan_context_flag")),
                "app_risk_only": bool(frame.iloc[absolute_index].get("v331_app_risk_only_flag")),
                "benign_network_utility_no_rule": bool(
                    frame.iloc[absolute_index].get("v331_benign_network_utility_no_rule_flag")
                ),
            }
        )
    pattern_counts = Counter(
        f"app={row['log'].app or '-'}|action={row['log'].action or '-'}|port={row['log'].dst_port or '-'}"
        for row in rows
    )
    return {
        "false_positive_count": len(rows),
        "top_patterns": pattern_counts.most_common(12),
        "top_apps": Counter(str(row["log"].app or "-") for row in rows).most_common(10),
        "top_ports": Counter(str(row["log"].dst_port or "-") for row in rows).most_common(10),
        "quic_443_no_rule_false_positives": sum(1 for row in rows if row["quic_no_rule"]),
        "quic_443_with_rule_false_positives": sum(1 for row in rows if row["quic_with_rule"]),
        "incomplete_allow_80_false_positives": sum(1 for row in rows if row["incomplete_allow_80"]),
        "unknown_udp_scan_context_false_positives": sum(1 for row in rows if row["unknown_udp_scan_context"]),
        "app_risk_only_false_positives": sum(1 for row in rows if row["app_risk_only"]),
        "benign_network_utility_no_rule_false_positives": sum(
            1 for row in rows if row["benign_network_utility_no_rule"]
        ),
        "reviewed_vs_weak": dict(Counter("reviewed" if row["label"].reviewed else "weak" for row in rows)),
        "label_sources": dict(Counter(str(row["label"].label_source or "unknown") for row in rows)),
        "_rows": rows,
    }


def _write_review_sample(rows: list[dict[str, Any]], *, output_path: Path, limit: int) -> dict[str, Any]:
    selected = rows[:limit]
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
                    "split_window": "test",
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
                    "reason_selected": "residual v3.31 false positive after noise-reduction strategy",
                    "evidence_summary": (
                        f"actual={row['actual']}; predicted={row['predicted']}; "
                        f"app={log.app}; action={log.action}; dst_port={log.dst_port}; "
                        f"rules={','.join(sorted(row['rule_codes'])) or 'none'}; source={_source_name(log)}"
                    ),
                    "human_review_decision": "",
                    "human_review_attack_type": "",
                    "human_review_confidence": "",
                    "human_review_note": "",
                }
            )
    return {
        "generated": bool(selected),
        "path": str(output_path),
        "rows": len(selected),
        "candidate_rows": len(rows),
        "import_ready": False,
    }


def _strip_strategy(strategy: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in strategy.items() if not key.startswith("_")}


def _readiness(best_summary: dict[str, Any], calibration: dict[str, Any]) -> dict[str, Any]:
    checks = [
        {
            "name": "benign-like false-positive rate within target",
            "passed": float(best_summary.get("benign_like_false_positive_rate") or 1) <= 0.15,
            "value": best_summary.get("benign_like_false_positive_rate"),
            "target": "<= 0.15",
        },
        {
            "name": "threat-positive F1 within target",
            "passed": float(best_summary.get("threat_positive_f1") or 0) >= 0.85,
            "value": best_summary.get("threat_positive_f1"),
            "target": ">= 0.85",
        },
        {
            "name": "suspicious recall within target",
            "passed": best_summary.get("suspicious_recall") is not None
            and float(best_summary.get("suspicious_recall") or 0) >= 0.8,
            "value": best_summary.get("suspicious_recall"),
            "target": ">= 0.8",
        },
        {
            "name": "malicious recall acceptable",
            "passed": best_summary.get("malicious_recall") is not None
            and float(best_summary.get("malicious_recall") or 0) >= 0.5,
            "value": best_summary.get("malicious_recall"),
            "target": ">= 0.5",
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
    return {
        "decision": "candidate_only",
        "passed": passed,
        "total": len(checks),
        "production_promoted": False,
        "response_automation_allowed": False,
        "blockers": [item["name"] for item in checks if not item["passed"]],
        "checks": checks,
    }


def _root_cause_notes(baseline_patterns: dict[str, Any], best_patterns: dict[str, Any]) -> list[str]:
    notes = [
        "The balanced baseline is still noisy because benign-like web/QUIC traffic can be assigned to threat classes.",
        "Most baseline false positives are human-reviewed labels, so this is primarily a model/threshold/feature issue, not a missing-label issue.",
    ]
    if baseline_patterns.get("quic_443_no_rule_false_positives"):
        notes.append(
            "QUIC/443 allow traffic with no rule evidence remains the largest false-positive pattern and needs explicit benign handling."
        )
    if baseline_patterns.get("incomplete_allow_80_false_positives"):
        notes.append(
            "Incomplete/allow/80 traffic is a secondary boundary pattern and should be separated from true scan behavior using source-diversity features."
        )
    if baseline_patterns.get("app_risk_only_false_positives"):
        notes.append(
            "App-risk-only rows such as SSL or BitTorrent should be treated as policy/unusual evidence, not automatically malicious."
        )
    if best_patterns.get("false_positive_count", 0) < baseline_patterns.get("false_positive_count", 0):
        notes.append(
            "Hard-gated low-noise profiles reduce false positives substantially, but recall and calibration must be checked before use."
        )
    return notes


def _render_markdown(result: dict[str, Any]) -> str:
    baseline = result["baseline"]
    best = result["best_candidate"]
    rows = []
    for strategy in result["strategies"]:
        if strategy.get("status") != "evaluated":
            rows.append(f"| {strategy.get('name')} | skipped | - | - | - | - | - | - | - | - |")
            continue
        summary = strategy.get("recommended_metrics") or {}
        rows.append(
            "| {name} | {mode} | {profile} | {precision} | {recall} | {f1} | {fpr} | {suspicious} | {malicious} | {queue} |".format(
                name=strategy.get("name"),
                mode=strategy.get("target_mode"),
                profile=strategy.get("recommended_profile"),
                precision=summary.get("threat_positive_precision"),
                recall=summary.get("threat_positive_recall"),
                f1=summary.get("threat_positive_f1"),
                fpr=summary.get("benign_like_false_positive_rate"),
                suspicious=summary.get("suspicious_recall"),
                malicious=summary.get("malicious_recall"),
                queue=summary.get("review_queue_size_estimate"),
            )
        )
    profile_rows = []
    for profile in result["profile_comparison"]:
        profile_rows.append(
            "| {profile} | {precision} | {recall} | {f1} | {fpr} | {suspicious} | {malicious} | {queue} |".format(
                profile=profile.get("profile"),
                precision=profile.get("threat_positive_precision"),
                recall=profile.get("threat_positive_recall"),
                f1=profile.get("threat_positive_f1"),
                fpr=profile.get("benign_like_false_positive_rate"),
                suspicious=profile.get("suspicious_recall"),
                malicious=profile.get("malicious_recall"),
                queue=profile.get("review_queue_size_estimate"),
            )
        )
    return f"""# v3.31 Model/Feature/Threshold Noise Reduction

Generated: {result['generated_at']}

This is a diagnostic evaluation only. No model was activated, no model artifact was written, and response automation stayed disabled.

## Before / Baseline

- Strategy: {baseline['strategy']}
- Threat-positive precision/recall/F1: {baseline['threat_positive_precision']} / {baseline['threat_positive_recall']} / {baseline['threat_positive_f1']}
- Benign-like false-positive rate: {baseline['benign_like_false_positive_rate']}
- Suspicious recall: {baseline['suspicious_recall']}
- Malicious recall: {baseline['malicious_recall']}
- Macro F1: {baseline['macro_f1']}
- Weighted F1: {baseline['weighted_f1']}
- False positives: {baseline['false_positives']}
- Review queue estimate: {baseline['review_queue_size_estimate']}

## Best Diagnostic Candidate

- Strategy: {best['strategy']}
- Profile: {best['profile']}
- Threat-positive precision/recall/F1: {best['metrics'].get('threat_positive_precision')} / {best['metrics'].get('threat_positive_recall')} / {best['metrics'].get('threat_positive_f1')}
- Benign-like false-positive rate: {best['metrics'].get('benign_like_false_positive_rate')}
- Suspicious recall: {best['metrics'].get('suspicious_recall')}
- Malicious recall: {best['metrics'].get('malicious_recall')}
- Macro F1: {best['metrics'].get('macro_f1')}
- Weighted F1: {best['metrics'].get('weighted_f1')}
- Review queue estimate: {best['metrics'].get('review_queue_size_estimate')}
- Calibration: {best['calibration'].get('status')}

## Strategy Comparison

| Strategy | Mode | Profile | Threat Precision | Threat Recall | Threat F1 | Benign FPR | Suspicious Recall | Malicious Recall | Queue |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
{chr(10).join(rows)}

## Profile Comparison For Best Strategy

| Profile | Threat Precision | Threat Recall | Threat F1 | Benign FPR | Suspicious Recall | Malicious Recall | Queue |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
{chr(10).join(profile_rows)}

## False-Positive Root Cause

{chr(10).join(f"- {item}" for item in result['root_cause_notes'])}

### Baseline False-Positive Patterns

```json
{json.dumps(result['baseline_false_positive_patterns'], indent=2, default=str)}
```

### Best Candidate Residual False-Positive Patterns

```json
{json.dumps(result['best_false_positive_patterns'], indent=2, default=str)}
```

## Calibration

```json
{json.dumps(best['calibration'], indent=2, default=str)}
```

## Readiness

- Decision: {result['readiness']['decision']}
- Checks passed: {result['readiness']['passed']} / {result['readiness']['total']}
- Blockers: {result['readiness']['blockers']}

## Safety

- Production promoted: false
- Model activated: false
- Model artifact written: false
- Response automation allowed: false
- Real firewall blocking enabled: false
"""


def run_v331_noise_reduction_evaluation(
    db: Session,
    *,
    split: str = "time",
    test_size: float = 0.3,
    min_samples: int = 6,
    review_limit: int = 100,
    output_dir: str | Path = OUTPUT_DIR,
) -> dict[str, Any]:
    before_runs = int(db.scalar(select(func.count(MLModelRun.id))) or 0)
    before_responses = int(db.scalar(select(func.count(ResponseAction.id))) or 0)
    prepared = _prepare_dataset(
        db,
        split=split,
        test_size=test_size,
        min_samples=min_samples,
        model_type="extra_trees",
        class_weight="balanced",
    )
    if not prepared.get("ok"):
        return prepared
    augmented_frame, augmented_meta = _augment_frame(prepared)
    augmented = {"frame": augmented_frame, **augmented_meta}

    baseline_predictions = [_profile_decision(row, profile="balanced") for row in prepared["probability_rows"]]
    baseline_metrics = _v330_metrics_bundle(prepared, baseline_predictions)
    baseline_summary = _v330_profile_summary(baseline_metrics)
    baseline_patterns = _false_positive_pattern_report(prepared, baseline_predictions, augmented=augmented)

    strategies = [
        _fit_strategy(
            prepared,
            augmented,
            name="flat_5class_extra_trees_current_features_current_weights",
            model_type="extra_trees",
            target_mode="flat",
            class_weight="balanced",
            weight_strategy="current",
            use_augmented_features=False,
        ),
        _fit_strategy(
            prepared,
            augmented,
            name="flat_5class_extra_trees_current_with_low_signal_guard",
            model_type="extra_trees",
            target_mode="flat",
            class_weight="balanced",
            weight_strategy="current",
            use_augmented_features=False,
            postprocess_low_signal_guard=True,
        ),
        _fit_strategy(
            prepared,
            augmented,
            name="flat_5class_extra_trees_augmented_lower_threat",
            model_type="extra_trees",
            target_mode="flat",
            class_weight=None,
            weight_strategy="lower_threat",
            use_augmented_features=True,
        ),
        _fit_strategy(
            prepared,
            augmented,
            name="flat_5class_extra_trees_augmented_strong_benign",
            model_type="extra_trees",
            target_mode="flat",
            class_weight=None,
            weight_strategy="strong_benign",
            use_augmented_features=True,
        ),
        _fit_strategy(
            prepared,
            augmented,
            name="binary_benign_like_vs_threat_positive",
            model_type="extra_trees",
            target_mode="binary",
            class_weight=None,
            weight_strategy="strong_benign",
            use_augmented_features=True,
        ),
        _fit_strategy(
            prepared,
            augmented,
            name="three_class_soc_triage",
            model_type="extra_trees",
            target_mode="three_class",
            class_weight=None,
            weight_strategy="strong_benign",
            use_augmented_features=True,
        ),
        _fit_strategy(
            prepared,
            augmented,
            name="calibrated_logistic_regression_augmented",
            model_type="logistic_regression",
            target_mode="flat",
            class_weight="balanced",
            weight_strategy="none",
            use_augmented_features=True,
            calibrated=True,
        ),
        _fit_strategy(
            prepared,
            augmented,
            name="calibrated_logistic_regression_augmented_low_signal_guard",
            model_type="logistic_regression",
            target_mode="flat",
            class_weight="balanced",
            weight_strategy="none",
            use_augmented_features=True,
            calibrated=True,
            postprocess_low_signal_guard=True,
        ),
        _fit_hierarchical_strategy(prepared, augmented),
    ]
    evaluated_strategies = []
    for strategy in strategies:
        if strategy.get("status") == "evaluated":
            profile = _strategy_best_profile(strategy)
            strategy["recommended_profile"] = profile
            strategy["recommended_metrics"] = _profile_summary(strategy["profiles"][profile]) if profile else {}
        evaluated_strategies.append(strategy)

    best_strategy, best_profile = _select_best_strategy(evaluated_strategies)
    if best_strategy is None or best_profile is None:
        return {"ok": False, "status": "failed", "message": "No v3.31 strategy could be evaluated."}
    best_metrics_full = best_strategy["profiles"][best_profile]
    best_summary = _profile_summary(best_metrics_full)
    best_predictions = (best_strategy.get("_predictions") or {}).get(best_profile) or []
    best_patterns = _false_positive_pattern_report(prepared, best_predictions, augmented=augmented)
    best_calibration = best_strategy.get("calibration") or {}
    readiness = _readiness(best_summary, best_calibration)

    profile_comparison = []
    for profile in V331_PROFILE_ORDER:
        metrics = best_strategy["profiles"].get(profile)
        if not metrics:
            continue
        summary = _profile_summary(metrics)
        profile_comparison.append({"profile": profile, **summary})

    output_path = Path(output_dir)
    stamp = _stamp()
    report_path = output_path / f"v3_31_noise_reduction_analysis_{stamp}.md"
    summary_path = output_path / f"v3_31_noise_reduction_{stamp}.json"
    latest_path = output_path / "v3_31_noise_reduction_latest.json"
    review_sample = {"generated": False, "path": "", "rows": 0, "candidate_rows": 0, "import_ready": False}
    residual_rows = best_patterns.get("_rows") or []
    if residual_rows:
        review_sample = _write_review_sample(
            residual_rows,
            output_path=output_path / "v3_31_noise_reduction_review_sample.csv",
            limit=review_limit,
        )
    root_cause_notes = _root_cause_notes(baseline_patterns, best_patterns)
    label_count = int(db.scalar(select(func.count(MLLabel.id))) or 0)
    result: dict[str, Any] = {
        "ok": True,
        "status": "completed",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "split": split,
        "test_size": test_size,
        "training_rows": len(prepared["train_idx"]),
        "test_rows": len(prepared["test_idx"]),
        "total_label_rows": label_count,
        "latest_trainable_rows": len(prepared["labels"]),
        "reviewed_labels": sum(1 for label in prepared["labels"] if label.reviewed),
        "experimental_features": augmented["experimental_features"],
        "feature_generation_seconds": prepared["feature_generation_seconds"],
        "class_temporal_coverage": build_class_temporal_coverage(db, test_size=test_size),
        "training_dataset_diagnostics": training_dataset_diagnostics(db),
        "baseline": {
            "strategy": "v3_30_extra_trees_balanced_threshold",
            **baseline_summary,
        },
        "baseline_false_positive_patterns": {
            key: value for key, value in baseline_patterns.items() if not key.startswith("_")
        },
        "strategies": [_strip_strategy(strategy) for strategy in evaluated_strategies],
        "best_candidate": {
            "strategy": best_strategy["name"],
            "profile": best_profile,
            "metrics": best_summary,
            "calibration": best_calibration,
            "target_mode": best_strategy.get("target_mode"),
            "model_type": best_strategy.get("model_type"),
        },
        "profile_comparison": profile_comparison,
        "best_false_positive_patterns": {
            key: value for key, value in best_patterns.items() if not key.startswith("_")
        },
        "calibration": best_calibration,
        "root_cause_notes": root_cause_notes,
        "review_sample": review_sample,
        "readiness": readiness,
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
    report_path.write_text(_render_markdown(result), encoding="utf-8")
    summary = {
        key: value
        for key, value in result.items()
        if key not in {"class_temporal_coverage", "training_dataset_diagnostics"}
    }
    summary["report_path"] = str(report_path)
    summary["summary_path"] = str(summary_path)
    summary["latest_summary_path"] = str(latest_path)
    summary_path.write_text(json.dumps(summary, indent=2, default=str), encoding="utf-8")
    latest_path.write_text(json.dumps(summary, indent=2, default=str), encoding="utf-8")
    result["report_path"] = str(report_path)
    result["summary_path"] = str(summary_path)
    result["latest_summary_path"] = str(latest_path)
    return result
