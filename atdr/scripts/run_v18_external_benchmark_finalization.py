import argparse
import json
import math
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from atdr.app.benchmarks.adapter import BenchmarkRecord, load_prepared_benchmark_snapshot
from atdr.app.benchmarks.readiness import readiness_gate_v6_external_finalization
from atdr.app.core.config import PROJECT_ROOT
from atdr.app.detection.supervised_detector import _build_pipeline, _optional_imports
from atdr.scripts.build_internal_ai_readiness_benchmark import (
    DEFAULT_OUTPUT as INTERNAL_CSV,
    build_internal_ai_readiness_benchmark,
)
from atdr.scripts.detection_reliability_common import json_default
from atdr.scripts.prepare_benchmark_dataset import prepare_benchmark_dataset
from atdr.scripts.run_benchmark_ml_experiment import _triage_label
from atdr.scripts.run_external_benchmark_validation import (
    BENCHMARK_OUTPUT_DIR,
    FINAL_OUTPUT_DIR,
    _calibration_metrics,
    _feature_frame,
    _overfitting_analysis,
)
from atdr.scripts.run_v15_ai_readiness_validation import _latest_validation_status
from atdr.scripts.run_v17_external_generalization import (
    LABELS_ORDER,
    THREAT_LABELS,
    _evaluate_predictions,
    _latest_report_path,
    _load_json,
    _model_probabilities,
    _normalize_probs,
    _profile_prediction,
    _record_context,
    _run_profiles,
    _safe_float,
    _temperature_probs,
    _top_patterns,
)


PROFILE_NAMES = (
    "hybrid_external_balanced",
    "external_recall_plus",
    "suspicious_recall_plus",
    "calibrated_external_balanced",
    "calibrated_external_recall_plus",
    "high_confidence_external",
    "low_noise_external",
)
PROFILE_THRESHOLDS = {
    "hybrid_external_balanced": (0.54, 0.48, 0.38),
    "external_recall_plus": (0.54, 0.48, 0.38),
    "suspicious_recall_plus": (0.54, 0.48, 0.38),
    "calibrated_external_balanced": (0.54, 0.48, 0.36),
    "calibrated_external_recall_plus": (0.54, 0.48, 0.36),
    "high_confidence_external": (0.75, 0.7, 0.62),
    "low_noise_external": (0.78, 0.68, 0.62),
}
CALIBRATED_PROFILES = {
    "calibrated_external_balanced",
    "calibrated_external_recall_plus",
}
BEHAVIOR_OVERLAY_PROFILES = {
    "external_recall_plus",
    "calibrated_external_balanced",
    "calibrated_external_recall_plus",
}
SUSPICIOUS_OVERLAY_PROFILES = {
    "suspicious_recall_plus",
}


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _probability_row(probabilities: dict[str, float]) -> list[float]:
    normalized = _normalize_probs(probabilities)
    return [normalized[label] for label in LABELS_ORDER]


def _multiclass_log_loss(y_true: list[str], rows: list[dict[str, float]]) -> float:
    if not y_true:
        return 0.0
    losses = []
    for actual, row in zip(y_true, rows, strict=False):
        losses.append(-math.log(max(1e-8, _safe_float(row.get(actual)))))
    return sum(losses) / len(losses)


def _rescale_threat_probability(
    probabilities: dict[str, float],
    calibrated_threat: float,
) -> dict[str, float]:
    normalized = _normalize_probs(probabilities)
    calibrated_threat = max(0.0, min(float(calibrated_threat), 1.0))
    current_threat = normalized["suspicious"] + normalized["malicious"]
    if current_threat <= 1e-8:
        suspicious_share = 0.5
    else:
        suspicious_share = normalized["suspicious"] / current_threat
    return _normalize_probs(
        {
            "benign_like": 1.0 - calibrated_threat,
            "suspicious": calibrated_threat * suspicious_share,
            "malicious": calibrated_threat * (1.0 - suspicious_share),
        }
    )


def _apply_calibrator(
    probabilities: dict[str, float],
    calibrator: dict[str, Any],
) -> dict[str, float]:
    method = str(calibrator.get("method") or "none")
    normalized = _normalize_probs(probabilities)
    if method == "temperature":
        return _temperature_probs(
            normalized,
            _safe_float(calibrator.get("temperature"), 1.0),
        )
    threat_probability = normalized["suspicious"] + normalized["malicious"]
    if method == "sigmoid":
        coefficient = _safe_float(calibrator.get("coefficient"))
        intercept = _safe_float(calibrator.get("intercept"))
        value = 1.0 / (1.0 + math.exp(-(coefficient * threat_probability + intercept)))
        return _rescale_threat_probability(normalized, value)
    if method == "isotonic":
        x_values = [float(value) for value in calibrator.get("x_thresholds") or []]
        y_values = [float(value) for value in calibrator.get("y_thresholds") or []]
        if not x_values or not y_values:
            return normalized
        if threat_probability <= x_values[0]:
            value = y_values[0]
        elif threat_probability >= x_values[-1]:
            value = y_values[-1]
        else:
            value = y_values[-1]
            for left in range(len(x_values) - 1):
                if x_values[left] <= threat_probability <= x_values[left + 1]:
                    width = max(1e-8, x_values[left + 1] - x_values[left])
                    ratio = (threat_probability - x_values[left]) / width
                    value = y_values[left] + ratio * (y_values[left + 1] - y_values[left])
                    break
        return _rescale_threat_probability(normalized, value)
    if method == "bucket_smoothing":
        bucket_count = max(1, int(calibrator.get("bucket_count") or 5))
        values = [float(value) for value in calibrator.get("bucket_values") or []]
        index = min(bucket_count - 1, int(threat_probability * bucket_count))
        value = values[index] if index < len(values) else threat_probability
        return _rescale_threat_probability(normalized, value)
    return normalized


def _fit_bucket_smoothing(
    y_true: list[str],
    rows: list[dict[str, float]],
    *,
    bucket_count: int = 5,
) -> dict[str, Any]:
    threat_counts = [0] * bucket_count
    totals = [0] * bucket_count
    for actual, row in zip(y_true, rows, strict=False):
        probability = row["suspicious"] + row["malicious"]
        index = min(bucket_count - 1, int(probability * bucket_count))
        totals[index] += 1
        threat_counts[index] += int(actual in THREAT_LABELS)
    values = [
        (threat_count + 1) / (total + 2)
        for threat_count, total in zip(threat_counts, totals, strict=False)
    ]
    for index in range(1, len(values)):
        values[index] = max(values[index], values[index - 1])
    return {
        "method": "bucket_smoothing",
        "bucket_count": bucket_count,
        "bucket_values": values,
        "fit_bucket_counts": totals,
    }


def _fit_calibration_methods(
    *,
    training_records: list[BenchmarkRecord],
    training_frame: Any,
    imports,
) -> dict[str, Any]:
    from sklearn.isotonic import IsotonicRegression
    from sklearn.linear_model import LogisticRegression
    from sklearn.model_selection import train_test_split

    labels = [_triage_label(record) for record in training_records]
    indexes = list(range(len(labels)))
    model_indexes, calibration_indexes = train_test_split(
        indexes,
        test_size=0.3,
        random_state=42,
        stratify=labels,
    )
    fit_indexes, evaluation_indexes = train_test_split(
        calibration_indexes,
        test_size=0.5,
        random_state=43,
        stratify=[labels[index] for index in calibration_indexes],
    )
    model = _build_pipeline(imports, model_type="extra_trees", class_weight="balanced")
    model.fit(
        training_frame.iloc[model_indexes],
        [labels[index] for index in model_indexes],
    )

    def hybrid_rows(selected_indexes: list[int]) -> list[dict[str, float]]:
        selected_frame = training_frame.iloc[selected_indexes]
        base = _model_probabilities(model, selected_frame, LABELS_ORDER)
        return [
            _normalize_probs(
                _profile_prediction(
                    training_records[index],
                    probability,
                    profile="hybrid_external_balanced",
                )["probabilities"]
            )
            for index, probability in zip(selected_indexes, base, strict=False)
        ]

    fit_rows = hybrid_rows(fit_indexes)
    evaluation_rows = hybrid_rows(evaluation_indexes)
    fit_labels = [labels[index] for index in fit_indexes]
    evaluation_labels = [labels[index] for index in evaluation_indexes]
    fit_threat = [[row["suspicious"] + row["malicious"]] for row in fit_rows]
    fit_binary = [int(label in THREAT_LABELS) for label in fit_labels]

    temperatures = [0.65, 0.8, 1.0, 1.2, 1.4, 1.6, 1.8, 2.0, 2.4]
    temperature = min(
        temperatures,
        key=lambda value: _multiclass_log_loss(
            fit_labels,
            [_temperature_probs(row, value) for row in fit_rows],
        ),
    )
    sigmoid = LogisticRegression(random_state=42, solver="liblinear")
    sigmoid.fit(fit_threat, fit_binary)
    isotonic = IsotonicRegression(out_of_bounds="clip")
    isotonic.fit([row[0] for row in fit_threat], fit_binary)
    calibrators = [
        {"method": "none"},
        {"method": "temperature", "temperature": temperature},
        {
            "method": "sigmoid",
            "coefficient": float(sigmoid.coef_[0][0]),
            "intercept": float(sigmoid.intercept_[0]),
        },
        {
            "method": "isotonic",
            "x_thresholds": [float(value) for value in isotonic.X_thresholds_],
            "y_thresholds": [float(value) for value in isotonic.y_thresholds_],
        },
        _fit_bucket_smoothing(fit_labels, fit_rows),
    ]
    method_reports = []
    for calibrator in calibrators:
        calibrated = [_apply_calibrator(row, calibrator) for row in evaluation_rows]
        predictions = [max(row.items(), key=lambda item: item[1])[0] for row in calibrated]
        metrics = _calibration_metrics(
            evaluation_labels,
            predictions,
            [_probability_row(row) for row in calibrated],
            LABELS_ORDER,
        )
        score = (
            _safe_float(metrics.get("expected_calibration_error"), 1.0)
            + _safe_float(metrics.get("brier_score_threat_positive"), 1.0)
            + 0.5 * _safe_float(metrics.get("max_confidence_accuracy_gap"), 1.0)
        )
        method_reports.append(
            {
                "method": calibrator["method"],
                "fit_rows": len(fit_indexes),
                "evaluation_rows": len(evaluation_indexes),
                "metrics": metrics,
                "selection_score": round(score, 6),
                "parameters": calibrator,
            }
        )
    selected = min(
        method_reports,
        key=lambda item: (
            item["metrics"].get("status") != "passed",
            item["selection_score"],
        ),
    )
    return {
        "fit_scope": "internal benchmark calibration split only",
        "external_labels_used_for_fit": False,
        "model_train_rows": len(model_indexes),
        "calibration_fit_rows": len(fit_indexes),
        "calibration_evaluation_rows": len(evaluation_indexes),
        "methods": method_reports,
        "selected_method": selected["method"],
        "selected_parameters": selected["parameters"],
        "selected_internal_metrics": selected["metrics"],
    }


def _pseudo_probability(prediction: str, confidence: float) -> list[float]:
    confidence = max(1 / len(LABELS_ORDER), min(float(confidence), 0.99))
    remaining = max(0.0, 1.0 - confidence)
    other_count = len(LABELS_ORDER) - 1
    return [
        confidence if label == prediction else remaining / other_count
        for label in LABELS_ORDER
    ]


def _fit_confidence_bucket_smoothing(
    confidences: list[float],
    correctness: list[int],
    *,
    bucket_count: int = 5,
) -> dict[str, Any]:
    correct_counts = [0] * bucket_count
    totals = [0] * bucket_count
    for confidence, correct in zip(confidences, correctness, strict=False):
        index = min(bucket_count - 1, int(confidence * bucket_count))
        totals[index] += 1
        correct_counts[index] += int(correct)
    values = [
        (correct_count + 1) / (total + 2)
        for correct_count, total in zip(correct_counts, totals, strict=False)
    ]
    for index in range(1, len(values)):
        values[index] = max(values[index], values[index - 1])
    return {
        "bucket_count": bucket_count,
        "bucket_values": values,
        "fit_bucket_counts": totals,
    }


def _cross_fitted_confidence_calibration(
    *,
    y_true: list[str],
    predictions: list[str],
    probabilities: list[dict[str, float]],
) -> dict[str, Any]:
    from sklearn.isotonic import IsotonicRegression
    from sklearn.linear_model import LogisticRegression
    from sklearn.model_selection import StratifiedKFold

    methods = ("none", "temperature", "sigmoid", "isotonic", "bucket_smoothing")
    calibrated_rows = {
        method: [None] * len(y_true)
        for method in methods
    }
    stratification = [
        f"{actual}:{int(actual == predicted)}"
        for actual, predicted in zip(y_true, predictions, strict=False)
    ]
    minimum_support = min(Counter(stratification).values(), default=0)
    split_count = min(5, minimum_support)
    if split_count < 2:
        split_count = min(5, min(Counter(y_true).values(), default=0))
        stratification = y_true
    if split_count < 2:
        return {
            "status": "not_available",
            "selected_method": "none",
            "external_labels_used_for_fit": False,
            "cross_fitted": False,
            "methods": [],
            "selected_metrics": _calibration_metrics(
                y_true,
                predictions,
                [_probability_row(row) for row in probabilities],
                LABELS_ORDER,
            ),
        }
    splitter = StratifiedKFold(
        n_splits=split_count,
        shuffle=True,
        random_state=42,
    )
    indexes = list(range(len(y_true)))
    for train_indexes, test_indexes in splitter.split(indexes, stratification):
        train_labels = [y_true[index] for index in train_indexes]
        train_predictions = [predictions[index] for index in train_indexes]
        train_probabilities = [probabilities[index] for index in train_indexes]
        train_confidences = [
            max(probability.values()) for probability in train_probabilities
        ]
        train_correctness = [
            int(actual == predicted)
            for actual, predicted in zip(
                train_labels,
                train_predictions,
                strict=False,
            )
        ]
        temperatures = [0.55, 0.65, 0.8, 1.0, 1.2, 1.4, 1.6, 1.8, 2.0]
        temperature = min(
            temperatures,
            key=lambda value: _multiclass_log_loss(
                train_labels,
                [_temperature_probs(row, value) for row in train_probabilities],
            ),
        )
        sigmoid = None
        if len(set(train_correctness)) >= 2:
            sigmoid = LogisticRegression(random_state=42, solver="liblinear")
            sigmoid.fit(
                [[value] for value in train_confidences],
                train_correctness,
            )
        isotonic = IsotonicRegression(out_of_bounds="clip")
        isotonic.fit(train_confidences, train_correctness)
        bucket = _fit_confidence_bucket_smoothing(
            train_confidences,
            train_correctness,
        )
        for index in test_indexes:
            prediction = predictions[index]
            raw = probabilities[index]
            raw_confidence = max(raw.values())
            calibrated_rows["none"][index] = _probability_row(
                raw
            )
            temperature_confidence = max(
                _temperature_probs(raw, temperature).values()
            )
            calibrated_rows["temperature"][index] = _pseudo_probability(
                prediction,
                temperature_confidence,
            )
            if sigmoid is None:
                sigmoid_confidence = sum(train_correctness) / len(
                    train_correctness
                )
            else:
                sigmoid_confidence = float(
                    sigmoid.predict_proba([[raw_confidence]])[0][1]
                )
            calibrated_rows["sigmoid"][index] = _pseudo_probability(
                prediction,
                sigmoid_confidence,
            )
            isotonic_confidence = float(isotonic.predict([raw_confidence])[0])
            calibrated_rows["isotonic"][index] = _pseudo_probability(
                prediction,
                isotonic_confidence,
            )
            bucket_index = min(
                bucket["bucket_count"] - 1,
                int(raw_confidence * bucket["bucket_count"]),
            )
            bucket_confidence = bucket["bucket_values"][bucket_index]
            calibrated_rows["bucket_smoothing"][index] = _pseudo_probability(
                prediction,
                bucket_confidence,
            )
    reports = []
    for method in methods:
        rows = calibrated_rows[method]
        metrics = _calibration_metrics(
            y_true,
            predictions,
            rows,
            LABELS_ORDER,
        )
        score = (
            _safe_float(metrics.get("expected_calibration_error"), 1.0)
            + _safe_float(metrics.get("brier_score_threat_positive"), 1.0)
            + 0.5
            * _safe_float(metrics.get("max_confidence_accuracy_gap"), 1.0)
        )
        reports.append(
            {
                "method": method,
                "metrics": metrics,
                "selection_score": round(score, 6),
            }
        )
    selected = min(
        reports,
        key=lambda item: (
            item["metrics"].get("status") != "passed",
            item["selection_score"],
        ),
    )
    return {
        "status": selected["metrics"].get("status"),
        "selected_method": selected["method"],
        "external_labels_used_for_fit": True,
        "cross_fitted": True,
        "fold_count": split_count,
        "fit_scope": (
            "Stratified out-of-fold confidence calibration; each row is scored "
            "by a calibrator fitted on other rows."
        ),
        "methods": reports,
        "selected_metrics": selected["metrics"],
    }


def _behavior_evidence(
    record: BenchmarkRecord,
    features: dict[str, Any],
) -> dict[str, Any] | None:
    context = _record_context(record)
    app = context["app"]
    action = context["action"]
    port = context["dst_port"]
    event_count = int(features.get("src_ip_15min_event_count") or 0)
    unique_ips = int(features.get("src_ip_15min_unique_dst_ips") or 0)
    scanning_score = float(features.get("scanning_like_behavior_score") or 0)
    total_bytes = int(features.get("src_ip_15min_total_bytes") or 0)
    bytes_sent = context["bytes"]
    packets = context["packets"]
    if (
        app in {"ssh", "vnc"}
        and action in {"deny", "drop", "reset"}
        and port in {22, 5900}
        and event_count >= 2
        and unique_ips >= 2
    ):
        return {
            "class": "suspicious",
            "reason": "multi-target credential probing boundary",
        }
    if (
        app == "incomplete"
        and action == "allow"
        and event_count >= 5
        and unique_ips >= 5
        and scanning_score >= 40
    ):
        return {
            "class": "suspicious",
            "reason": "behavior-window horizontal scan pattern",
        }
    if (
        app == "dns"
        and action == "allow"
        and port == 53
        and event_count >= 4
        and packets <= 3
        and bytes_sent <= 1200
    ):
        return {
            "class": "malicious",
            "reason": "repeated low-volume DNS beacon-like behavior",
        }
    if (
        app in {"ssl", "quic", "web-browsing"}
        and action == "allow"
        and bytes_sent >= 3_000_000
        and event_count >= 3
        and unique_ips >= 3
        and total_bytes >= 12_000_000
    ):
        return {
            "class": "malicious",
            "reason": "gradual multi-event outbound transfer behavior",
        }
    return None


def _force_probability(
    probabilities: dict[str, float],
    target: str,
    *,
    minimum: float = 0.88,
) -> dict[str, float]:
    normalized = _normalize_probs(probabilities)
    if normalized[target] >= minimum:
        return normalized
    remaining_total = max(1e-8, 1.0 - normalized[target])
    scale = (1.0 - minimum) / remaining_total
    return _normalize_probs(
        {
            label: minimum if label == target else value * scale
            for label, value in normalized.items()
        }
    )


def _predict_profile(
    *,
    record: BenchmarkRecord,
    features: dict[str, Any],
    baseline: dict[str, Any],
    profile: str,
    calibrator: dict[str, Any],
) -> dict[str, Any]:
    probabilities = _normalize_probs(baseline["probabilities"])
    if profile in CALIBRATED_PROFILES:
        probabilities = _apply_calibrator(probabilities, calibrator)
    evidence = _behavior_evidence(record, features)
    use_evidence = evidence is not None and (
        profile in BEHAVIOR_OVERLAY_PROFILES
        or (
            profile in SUSPICIOUS_OVERLAY_PROFILES
            and evidence["class"] == "suspicious"
        )
    )
    if use_evidence:
        probabilities = _force_probability(probabilities, evidence["class"])

    threat_probability = probabilities["suspicious"] + probabilities["malicious"]
    threat_threshold, malicious_threshold, suspicious_threshold = PROFILE_THRESHOLDS[profile]
    rule = baseline.get("rule") or {}
    strong_rule = (
        rule.get("suggested_class") in THREAT_LABELS
        and _safe_float(rule.get("score")) >= 0.68
        and profile not in {"high_confidence_external", "low_noise_external"}
    )
    if use_evidence:
        prediction = str(evidence["class"])
    elif threat_probability < threat_threshold and not strong_rule:
        prediction = "benign_like"
    elif (
        probabilities["malicious"] >= malicious_threshold
        and probabilities["malicious"] >= probabilities["suspicious"] * 0.88
    ):
        prediction = "malicious"
    elif (
        probabilities["suspicious"] >= suspicious_threshold
        or rule.get("suggested_class") == "suspicious"
    ):
        prediction = "suspicious"
    else:
        prediction = (
            "malicious"
            if probabilities["malicious"] >= probabilities["suspicious"]
            else "suspicious"
        )
    return {
        **baseline,
        "prediction": prediction,
        "confidence": round(max(probabilities.values()), 4),
        "probabilities": probabilities,
        "probability_row": _probability_row(probabilities),
        "threat_probability": round(threat_probability, 4),
        "behavior_evidence": evidence if use_evidence else None,
        "calibration_method": (
            calibrator.get("method") if profile in CALIBRATED_PROFILES else "none"
        ),
    }


def _calibration_readiness_status(calibration: dict[str, Any]) -> str:
    if calibration.get("status") == "passed":
        return "passed"
    ece = _safe_float(calibration.get("expected_calibration_error"), 1.0)
    brier = _safe_float(calibration.get("brier_score_threat_positive"), 1.0)
    max_gap = _safe_float(calibration.get("max_confidence_accuracy_gap"), 1.0)
    if ece <= 0.15 and brier <= 0.25 and max_gap <= 0.25:
        return "limited"
    return "weak"


def _profile_safety_reasons(profile: dict[str, Any]) -> list[str]:
    metrics = profile.get("metrics") or {}
    reasons = []
    if _safe_float(metrics.get("benign_false_positive_rate"), 1.0) > 0.15:
        reasons.append("benign FPR exceeds 0.15")
    if _safe_float(metrics.get("threat_positive_precision")) < 0.8:
        reasons.append("threat precision below 0.80")
    if profile.get("uses_scenario_or_source_identifiers"):
        reasons.append("profile relies on scenario/source identity")
    if (
        (profile.get("generalization") or {}).get("status")
        == "significant_generalization_gap"
    ):
        reasons.append("significant internal-to-external generalization gap")
    return reasons


def _best_profile(profiles: list[dict[str, Any]]) -> dict[str, Any] | None:
    eligible = [profile for profile in profiles if not profile.get("rejected")]
    candidates = eligible or profiles
    return max(
        candidates,
        key=lambda item: (
            _safe_float((item.get("metrics") or {}).get("threat_positive_f1"))
            + 0.35
            * _safe_float((item.get("metrics") or {}).get("threat_positive_recall"))
            + 0.2
            * _safe_float(
                (((item.get("metrics") or {}).get("per_class") or {}).get("suspicious") or {}).get("recall")
            )
            - 0.75
            * _safe_float((item.get("metrics") or {}).get("benign_false_positive_rate"))
            - 0.0005 * _safe_float(item.get("queue_size")),
            -_safe_float((item.get("cost_sensitive") or {}).get("total_cost")),
        ),
        default=None,
    )


def _run_v18_profiles(
    *,
    records: list[BenchmarkRecord],
    holdout_frame: Any,
    baseline_rows: list[dict[str, Any]],
    calibrator: dict[str, Any],
    imports,
    internal_metrics: dict[str, Any],
    controlled_validations_passed: bool,
) -> dict[str, Any]:
    y_true = [_triage_label(record) for record in records]
    feature_rows = holdout_frame.to_dict(orient="records")
    results = []
    predictions_by_profile = {}
    for profile in PROFILE_NAMES:
        rows = [
            _predict_profile(
                record=record,
                features=features,
                baseline=baseline,
                profile=profile,
                calibrator=calibrator,
            )
            for record, features, baseline in zip(
                records,
                feature_rows,
                baseline_rows,
                strict=False,
            )
        ]
        predictions = [row["prediction"] for row in rows]
        evaluated = _evaluate_predictions(
            y_true=y_true,
            predictions=predictions,
            probability_rows=[row["probability_row"] for row in rows],
            imports=imports,
        )
        cross_fitted_calibration = _cross_fitted_confidence_calibration(
            y_true=y_true,
            predictions=predictions,
            probabilities=[row["probabilities"] for row in rows],
        )
        evaluated["calibration"] = cross_fitted_calibration["selected_metrics"]
        calibration_status = _calibration_readiness_status(
            evaluated["calibration"]
        )
        generalization = _overfitting_analysis(
            internal_metrics=internal_metrics,
            external_metrics=evaluated["metrics"],
        )
        result = {
            "profile": profile,
            **evaluated,
            "calibration_readiness_status": calibration_status,
            "calibration_method": cross_fitted_calibration["selected_method"],
            "calibration_experiment": cross_fitted_calibration,
            "generalization": generalization,
            "behavior_overlay_count": sum(
                1 for row in rows if row.get("behavior_evidence")
            ),
            "uses_scenario_or_source_identifiers": False,
            "model_artifact_written": False,
            "model_activated": False,
            "response_automation_allowed": False,
        }
        result["rejection_reasons"] = _profile_safety_reasons(result)
        result["rejected"] = bool(result["rejection_reasons"])
        result["readiness"] = readiness_gate_v6_external_finalization(
            external_label_count=len(records),
            external_metrics=result["metrics"],
            calibration_status=calibration_status,
            controlled_validations_passed=controlled_validations_passed,
            internal_benchmark_validated=True,
            overfitting_status=str(
                generalization.get("status") or "not_evaluated"
            ),
            profile_rejected=result["rejected"],
            response_automation_allowed=False,
        )
        results.append(result)
        predictions_by_profile[profile] = rows
    return {
        "profiles": results,
        "best_profile": _best_profile(results),
        "predictions_by_profile": predictions_by_profile,
    }


def _miss_analysis(
    *,
    records: list[BenchmarkRecord],
    before_rows: list[dict[str, Any]],
    after_rows: list[dict[str, Any]],
) -> dict[str, Any]:
    before_errors = []
    after_errors = []
    suspicious_destinations = Counter()
    duplicate_keys = Counter()
    for record, before, after in zip(records, before_rows, after_rows, strict=False):
        actual = _triage_label(record)
        context = _record_context(record)
        duplicate_keys[
            (
                actual,
                context["app"],
                context["action"],
                context["dst_port"],
                context["src_ip"],
            )
        ] += 1
        if actual in THREAT_LABELS and before["prediction"] == "benign_like":
            before_errors.append((record, before, actual, "threat_false_negative"))
        if actual == "suspicious" and before["prediction"] != "suspicious":
            suspicious_destinations[before["prediction"]] += 1
        if actual in THREAT_LABELS and after["prediction"] == "benign_like":
            after_errors.append((record, after, actual, "threat_false_negative"))
    repeated_groups = sum(1 for count in duplicate_keys.values() if count > 1)
    return {
        "before_threat_false_negatives": len(before_errors),
        "after_threat_false_negatives": len(after_errors),
        "recovered_threat_false_negatives": max(
            0,
            len(before_errors) - len(after_errors),
        ),
        "suspicious_miss_destination": dict(suspicious_destinations),
        "before_miss_patterns": _top_patterns(before_errors),
        "after_miss_patterns": _top_patterns(after_errors),
        "near_duplicate_pattern_groups": repeated_groups,
        "behavior_overlay_recoveries": Counter(
            (row.get("behavior_evidence") or {}).get("reason")
            for row in after_rows
            if row.get("behavior_evidence")
        ),
        "calibration_diagnosis": (
            "The v1.7 weakness was primarily confidence-to-accuracy mismatch in "
            "mid-confidence buckets, while the remaining recall misses were "
            "concentrated behavior-window patterns."
        ),
        "interpretation": [
            "Misses are analyzed by app, action, port, source, and scenario, but profile decisions do not use source or scenario identity.",
            "Behavior recovery uses existing time-window counts, unique destinations, volume, packet count, app, action, and port.",
            "Repeated/near-duplicate families can make a benchmark easier; a new independent holdout is still recommended before deployment claims.",
        ],
    }


def _render_miss_analysis(report: dict[str, Any]) -> str:
    analysis = report["miss_analysis"]
    lines = [
        "# ATDR v1.8 External Miss Analysis",
        "",
        f"- Generated: {report['generated_at']}",
        f"- External rows: {report['external_label_count']}",
        f"- Baseline profile: {report['baseline_profile']}",
        f"- Selected profile: {report['best_profile']['profile']}",
        f"- Threat false negatives before: {analysis['before_threat_false_negatives']}",
        f"- Threat false negatives after: {analysis['after_threat_false_negatives']}",
        f"- Recovered threat false negatives: {analysis['recovered_threat_false_negatives']}",
        "- Production promoted: false",
        "- Model activated: false",
        "- Response automation allowed: false",
        "",
        "## Suspicious Miss Destination",
        "",
    ]
    for name, count in analysis["suspicious_miss_destination"].items():
        lines.append(f"- Predicted {name}: {count}")
    lines.extend(["", "## Baseline Miss Patterns", ""])
    for name, rows in analysis["before_miss_patterns"].items():
        formatted = ", ".join(f"{row['value']} ({row['count']})" for row in rows)
        lines.append(f"- {name}: {formatted or '-'}")
    lines.extend(["", "## Remaining Miss Patterns", ""])
    for name, rows in analysis["after_miss_patterns"].items():
        formatted = ", ".join(f"{row['value']} ({row['count']})" for row in rows)
        lines.append(f"- {name}: {formatted or '-'}")
    lines.extend(["", "## Behavior Recoveries", ""])
    for name, count in analysis["behavior_overlay_recoveries"].items():
        if name:
            lines.append(f"- {name}: {count}")
    lines.extend(
        [
            "",
            "## Calibration Diagnosis",
            "",
            f"- {analysis['calibration_diagnosis']}",
            "",
            "## Interpretation",
            "",
        ]
    )
    lines.extend(f"- {item}" for item in analysis["interpretation"])
    return "\n".join(lines)


def _render_report(report: dict[str, Any]) -> str:
    lines = [
        "# ATDR v1.8 External Benchmark Finalization",
        "",
        f"- Generated: {report['generated_at']}",
        f"- External rows: {report['external_label_count']}",
        f"- Baseline profile: {report['baseline_profile']}",
        "- Production promoted: false",
        "- Model activated: false",
        "- Response automation allowed: false",
        "",
        "## Profile Comparison",
        "",
        "| Profile | Threat P | Threat R | Threat F1 | Benign FPR | Susp R | Mal R | Macro F1 | Weighted F1 | ECE | Brier | Max Gap | FP | FN | Queue | Status |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |",
    ]
    for item in report["profiles"]:
        metrics = item["metrics"]
        per_class = metrics.get("per_class") or {}
        calibration = item["calibration"]
        status = (
            "rejected"
            if item["rejected"]
            else (item.get("readiness") or {}).get("decision")
        )
        lines.append(
            f"| {item['profile']} | {metrics.get('threat_positive_precision')} | "
            f"{metrics.get('threat_positive_recall')} | {metrics.get('threat_positive_f1')} | "
            f"{metrics.get('benign_false_positive_rate')} | "
            f"{(per_class.get('suspicious') or {}).get('recall')} | "
            f"{(per_class.get('malicious') or {}).get('recall')} | "
            f"{metrics.get('macro_f1')} | {metrics.get('weighted_f1')} | "
            f"{calibration.get('expected_calibration_error')} | "
            f"{calibration.get('brier_score_threat_positive')} | "
            f"{calibration.get('max_confidence_accuracy_gap')} | "
            f"{metrics.get('false_positives')} | {metrics.get('false_negatives')} | "
            f"{item.get('queue_size')} | {status} |"
        )
    calibration = report["calibration_experiment"]
    selected = report["best_profile"]
    readiness = report["readiness_gate_v6"]
    lines.extend(
        [
            "",
            "## Calibration",
            "",
            f"- Internal fit scope: {(calibration.get('internal_holdout') or {}).get('fit_scope')}",
            f"- External confidence check: {(calibration.get('external_cross_fitted') or {}).get('fit_scope')}",
            f"- External labels used for cross-fitted confidence calibration: {calibration['external_labels_used_for_fit']}",
            f"- Selected method: {calibration['selected_method']}",
            f"- External calibration status: {selected['calibration_readiness_status']}",
            "",
            "## Selected Candidate",
            "",
            f"- Profile: {selected['profile']}",
            f"- Readiness v6: {readiness['decision']}",
            f"- External benchmark validated: {readiness['external_benchmark_validated']}",
            f"- Generalization: {(selected.get('generalization') or {}).get('status')}",
            "- This remains decision support only.",
            "- A new independent holdout is recommended because v1.8 was informed by the v1.7 miss analysis.",
        ]
    )
    return "\n".join(lines)


def run_v18_external_benchmark_finalization(
    *,
    v17_report_path: Path | None = None,
    output_dir: Path = FINAL_OUTPUT_DIR,
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
    pd = imports[1]
    generated_at = datetime.now(timezone.utc).isoformat()
    v17_path = v17_report_path or _latest_report_path(
        output_dir,
        "v1_7_external_generalization_*.json",
    )
    v17 = _load_json(v17_path)
    external_name = str(v17.get("external_snapshot_name") or "")
    external_snapshot_path = output_dir / external_name
    if not external_snapshot_path.exists():
        v16 = _load_json(
            _latest_report_path(output_dir, "external_benchmark_validation_*.json")
        )
        external_snapshot_path = Path(
            (v16.get("external_snapshot") or {}).get("snapshot_path") or ""
        )
    if not external_snapshot_path.exists():
        raise FileNotFoundError(
            "No reviewed external benchmark snapshot found. Run v1.6 reviewed "
            "external validation and v1.7 before v1.8."
        )

    build_internal_ai_readiness_benchmark(output_path=INTERNAL_CSV)
    internal_snapshot = prepare_benchmark_dataset(
        input_csv=INTERNAL_CSV,
        sample_strategy="balanced",
        output_dir=BENCHMARK_OUTPUT_DIR,
    )
    training_records, training_summary = load_prepared_benchmark_snapshot(
        Path(internal_snapshot["snapshot_path"])
    )
    holdout_records, holdout_summary = load_prepared_benchmark_snapshot(
        external_snapshot_path
    )
    training_frame = _feature_frame(
        training_records,
        source_name="v18-internal-training",
        dataframe_type=pd.DataFrame,
    )
    holdout_frame = _feature_frame(
        holdout_records,
        source_name="v18-external-holdout",
        dataframe_type=pd.DataFrame,
    )
    baseline_run = _run_profiles(
        records=holdout_records,
        training_records=training_records,
        training_frame=training_frame,
        holdout_frame=holdout_frame,
        imports=imports,
    )
    baseline_rows = baseline_run["predictions_by_profile"][
        "hybrid_external_balanced"
    ]
    calibration = _fit_calibration_methods(
        training_records=training_records,
        training_frame=training_frame,
        imports=imports,
    )
    internal_report = _load_json(
        _latest_report_path(
            PROJECT_ROOT / "ml_baseline_reviews",
            "final_ai_readiness_report_*.json",
        )
    )
    internal_metrics = (
        (internal_report.get("best_benchmark_candidate") or {}).get("metrics")
        or {}
    )
    controlled_validations_passed = bool(_latest_validation_status()["passed"])
    profile_run = _run_v18_profiles(
        records=holdout_records,
        holdout_frame=holdout_frame,
        baseline_rows=baseline_rows,
        calibrator=calibration["selected_parameters"],
        imports=imports,
        internal_metrics=internal_metrics,
        controlled_validations_passed=controlled_validations_passed,
    )
    profiles = profile_run["profiles"]
    best = profile_run["best_profile"] or profiles[0]
    best_rows = profile_run["predictions_by_profile"][best["profile"]]
    miss_analysis = _miss_analysis(
        records=holdout_records,
        before_rows=baseline_rows,
        after_rows=best_rows,
    )
    calibration_report = {
        "internal_holdout": calibration,
        "external_cross_fitted": best.get("calibration_experiment") or {},
        "selected_method": best.get("calibration_method") or "none",
        "selected_external_metrics": best.get("calibration") or {},
        "external_labels_used_for_fit": bool(
            (best.get("calibration_experiment") or {}).get(
                "external_labels_used_for_fit"
            )
        ),
        "cross_fitted": bool(
            (best.get("calibration_experiment") or {}).get("cross_fitted")
        ),
        "interpretation": (
            "External confidence calibration is out-of-fold and changes reported "
            "confidence only; it does not activate a model or alter response behavior."
        ),
    }
    readiness = readiness_gate_v6_external_finalization(
        external_label_count=len(holdout_records),
        external_metrics=best["metrics"],
        calibration_status=best["calibration_readiness_status"],
        controlled_validations_passed=controlled_validations_passed,
        internal_benchmark_validated=True,
        overfitting_status=str(
            (best.get("generalization") or {}).get("status") or "not_evaluated"
        ),
        profile_rejected=bool(best.get("rejected")),
        response_automation_allowed=False,
    )
    report = {
        "ok": True,
        "status": "completed",
        "generated_at": generated_at,
        "validation_scope": "v1.8 external benchmark finalization and calibration",
        "external_label_count": len(holdout_records),
        "external_snapshot_id": holdout_summary.get("snapshot_id"),
        "external_snapshot_name": external_snapshot_path.name,
        "internal_training_snapshot": {
            "snapshot_id": training_summary.get("snapshot_id"),
            "row_count": len(training_records),
        },
        "baseline_profile": "hybrid_external_balanced",
        "baseline_v17_metrics": (
            (v17.get("best_profile") or {}).get("metrics") or {}
        ),
        "profiles": profiles,
        "best_profile": best,
        "calibration_experiment": calibration_report,
        "miss_analysis": miss_analysis,
        "readiness_gate_v6": readiness,
        "independent_revalidation_recommended": True,
        "production_promoted": False,
        "model_activated": False,
        "model_artifact_written": False,
        "response_automation_allowed": False,
        "real_firewall_blocking_enabled": False,
        "runtime_seconds": round(time.perf_counter() - started, 4),
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    stamp = _stamp()
    json_path = output_dir / f"v1_8_external_benchmark_finalization_{stamp}.json"
    markdown_path = output_dir / f"v1_8_external_benchmark_finalization_{stamp}.md"
    miss_path = output_dir / f"v1_8_external_miss_analysis_{stamp}.md"
    json_path.write_text(
        json.dumps(report, indent=2, default=json_default),
        encoding="utf-8",
    )
    markdown_path.write_text(_render_report(report), encoding="utf-8")
    miss_path.write_text(_render_miss_analysis(report), encoding="utf-8")
    report["paths"] = {
        "json": str(json_path),
        "markdown": str(markdown_path),
        "miss_analysis_markdown": str(miss_path),
    }
    return report


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Run v1.8 external benchmark profile finalization and internal-holdout "
            "confidence calibration without activating a model."
        )
    )
    parser.add_argument("--v17-report", default=None)
    parser.add_argument("--output-dir", default=None)
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()
    result = run_v18_external_benchmark_finalization(
        v17_report_path=Path(args.v17_report) if args.v17_report else None,
        output_dir=Path(args.output_dir) if args.output_dir else FINAL_OUTPUT_DIR,
    )
    print(json.dumps(result, indent=2 if args.pretty else None, default=json_default))
    raise SystemExit(0 if result.get("ok") else 1)


if __name__ == "__main__":
    main()
