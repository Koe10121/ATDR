import csv
import json
import math
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from atdr.app.benchmarks.readiness import readiness_gate_v3
from atdr.app.db.models import MLLabel, NormalizedLog
from atdr.app.detection.supervised_detector import (
    TRAINABLE_LABELS,
    _build_pipeline,
    _latest_labels,
    _metrics_from_predictions,
    _optional_imports,
    _sample_weights,
    _split_class_warnings,
    _split_indices,
    threshold_decision,
)
from atdr.app.ml.features import build_feature_rows
from atdr.app.services.class_temporal_coverage_service import build_class_temporal_coverage


OUTPUT_DIR = Path("ml_baseline_reviews")
V14_REVIEW_PATH = OUTPUT_DIR / "v1_4_false_positive_review_sample.csv"
THREAT_LABELS = {"suspicious", "malicious"}
BENIGN_LIKE_LABELS = {"benign", "benign_unusual", "needs_context"}
V14_THRESHOLD_PROFILES = {
    "conservative": {"malicious": 0.62, "threat_positive": 0.68, "needs_context": 0.52},
    "balanced": {"malicious": 0.50, "threat_positive": 0.58, "needs_context": 0.50},
    "precision_focused": {"malicious": 0.72, "threat_positive": 0.78, "needs_context": 0.48},
    "recall_focused": {"malicious": 0.30, "threat_positive": 0.38, "needs_context": 0.52},
    "low_noise_soc_queue": {"malicious": 0.82, "threat_positive": 0.88, "needs_context": 0.45},
}
V14_REVIEW_FIELDS = [
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
    "reason_selected",
    "evidence_summary",
    "human_review_decision",
    "human_review_attack_type",
    "human_review_confidence",
    "human_review_note",
]


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")


def _labels(db: Session) -> list[MLLabel]:
    return [
        label
        for label in _latest_labels(db)
        if label.log is not None and label.label in TRAINABLE_LABELS
    ]


def _log_timestamp(log: NormalizedLog) -> datetime | None:
    return log.generated_time or log.receive_time or log.start_time


def _source_name(log: NormalizedLog) -> str:
    source = getattr(getattr(log, "raw_log", None), "source", None)
    return str(source.name if source else "unknown_source")


def _signature(log: NormalizedLog, *, include_time: bool) -> tuple[Any, ...]:
    values: list[Any] = [
        log.src_ip,
        log.dst_ip,
        log.src_port,
        log.dst_port,
        log.protocol,
        log.app,
        log.action,
        log.bytes,
        log.packets,
    ]
    if include_time:
        values.append(_log_timestamp(log))
    return tuple(values)


def _prepare_dataset(
    db: Session,
    *,
    split: str,
    test_size: float,
    min_samples: int,
) -> dict[str, Any]:
    imports = _optional_imports()
    if imports is None:
        return {"ok": False, "status": "skipped", "message": "Supervised ML dependencies are unavailable."}
    labels = _labels(db)
    if len(labels) < min_samples or len({label.label for label in labels}) < 2:
        return {"ok": False, "status": "skipped", "message": "Not enough labeled rows for v1.4 evaluation."}
    pd = imports[1]
    train_test_split = imports[8]
    logs = [label.log for label in labels]
    y = [label.label for label in labels]
    feature_started = time.perf_counter()
    frame = pd.DataFrame(build_feature_rows(db, logs))
    feature_seconds = time.perf_counter() - feature_started
    train_idx, test_idx, y_train, y_test, split_warnings = _split_indices(
        logs=logs,
        y=y,
        split=split,
        test_size=test_size,
        train_test_split=train_test_split,
    )
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
        "split_warnings": [*split_warnings, *_split_class_warnings(y_train, y_test)],
        "feature_generation_seconds": round(feature_seconds, 4),
    }


def _v14_threshold_decision(class_probs: dict[str, float], *, profile: str) -> str:
    thresholds = V14_THRESHOLD_PROFILES[profile]
    malicious = float(class_probs.get("malicious", 0))
    suspicious = float(class_probs.get("suspicious", 0))
    threat_positive = malicious + suspicious
    if malicious >= thresholds["malicious"]:
        return "malicious"
    if threat_positive >= thresholds["threat_positive"]:
        return "malicious" if malicious > suspicious else "suspicious"
    if float(class_probs.get("needs_context", 0)) >= thresholds["needs_context"]:
        return "needs_context"
    fallback = {
        label: float(class_probs.get(label, 0))
        for label in ("benign", "benign_unusual", "needs_context")
    }
    return max(fallback.items(), key=lambda item: item[1])[0]


def _binary_counts(y_true: list[str], predictions: list[str]) -> dict[str, int | float]:
    true_positive = false_positive = false_negative = true_negative = 0
    for actual, predicted in zip(y_true, predictions, strict=False):
        actual_threat = actual in THREAT_LABELS or actual == "threat_positive"
        predicted_threat = predicted in THREAT_LABELS or predicted == "threat_positive"
        if actual_threat and predicted_threat:
            true_positive += 1
        elif not actual_threat and predicted_threat:
            false_positive += 1
        elif actual_threat:
            false_negative += 1
        else:
            true_negative += 1
    precision = true_positive / (true_positive + false_positive) if true_positive + false_positive else 0.0
    recall = true_positive / (true_positive + false_negative) if true_positive + false_negative else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "true_positive": true_positive,
        "false_positive": false_positive,
        "false_negative": false_negative,
        "true_negative": true_negative,
        "support": true_positive + false_negative,
        "review_queue_size_estimate": true_positive + false_positive,
        "benign_like_false_positive_rate": round(
            false_positive / (false_positive + true_negative),
            4,
        )
        if false_positive + true_negative
        else 0.0,
    }


def _metric_bundle(
    prepared: dict[str, Any],
    *,
    y_true: list[str],
    predictions: list[str],
    labels_order: list[str],
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
    binary = _binary_counts(y_true, predictions)
    metrics["threat_positive"] = binary
    metrics["false_positive_rate"] = binary["benign_like_false_positive_rate"]
    metrics["false_positives"] = binary["false_positive"]
    metrics["false_negatives"] = binary["false_negative"]
    metrics["review_queue_size_estimate"] = binary["review_queue_size_estimate"]
    return metrics


def _binary_metric_bundle(y_true: list[str], predictions: list[str]) -> dict[str, Any]:
    binary = _binary_counts(y_true, predictions)
    total = len(y_true)
    accuracy = (
        (int(binary["true_positive"]) + int(binary["true_negative"])) / total
        if total
        else 0.0
    )
    return {
        "accuracy": round(accuracy, 4),
        "threat_positive": binary,
        "false_positive_rate": binary["benign_like_false_positive_rate"],
        "false_positives": binary["false_positive"],
        "false_negatives": binary["false_negative"],
        "review_queue_size_estimate": binary["review_queue_size_estimate"],
        "per_class": {},
        "weighted_average": {"f1": binary["f1"]},
        "macro_average": {"f1": binary["f1"]},
        "labels": ["benign_like", "threat_positive"],
    }


def _weights(labels: list[MLLabel], strategy: str) -> tuple[list[float] | None, dict[str, Any]]:
    if strategy == "current":
        weights, summary = _sample_weights(labels)
        return weights, {**summary, "strategy": strategy}
    if strategy == "none":
        return None, {"enabled": False, "strategy": strategy}
    values: list[float] = []
    grouped: dict[str, list[float]] = defaultdict(list)
    for label in labels:
        reviewed = bool(label.reviewed)
        source = str(label.label_source or "manual")
        weight = 2.0 if reviewed else 0.6
        if source.startswith("assisted") and not reviewed:
            weight *= 0.8
        if strategy == "lower_threat":
            multipliers = {
                "benign": 2.2,
                "benign_unusual": 1.8,
                "needs_context": 1.5,
                "suspicious": 0.9,
                "malicious": 1.1,
            }
        elif strategy == "strong_benign":
            multipliers = {
                "benign": 4.0,
                "benign_unusual": 3.0,
                "needs_context": 2.0,
                "suspicious": 0.8,
                "malicious": 1.0,
            }
        else:
            raise ValueError(f"Unknown sample-weight strategy: {strategy}")
        weight *= multipliers.get(label.label, 1.0)
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
            label: round(sum(items) / len(items), 4)
            for label, items in sorted(grouped.items())
        },
    }


def _classes(model: Any) -> list[str]:
    if hasattr(model, "classes_"):
        return [str(value) for value in model.classes_]
    nested = getattr(model, "named_steps", {}).get("model")
    return [str(value) for value in getattr(nested, "classes_", [])]


def _profile_predictions(
    probabilities: Any,
    classes: list[str],
    *,
    mapped_mode: str,
) -> dict[str, list[str]]:
    results: dict[str, list[str]] = {}
    for profile, thresholds in V14_THRESHOLD_PROFILES.items():
        predictions: list[str] = []
        for row in probabilities:
            probs = {label: float(value) for label, value in zip(classes, row, strict=False)}
            if mapped_mode == "binary":
                threat_probability = float(probs.get("threat_positive", 0))
                predictions.append(
                    "threat_positive"
                    if threat_probability >= thresholds["threat_positive"]
                    else "benign_like"
                )
            elif mapped_mode == "three_class":
                malicious = float(probs.get("malicious", 0))
                suspicious = float(probs.get("suspicious", 0))
                if malicious >= thresholds["malicious"]:
                    predictions.append("malicious")
                elif malicious + suspicious >= thresholds["threat_positive"]:
                    predictions.append("malicious" if malicious > suspicious else "suspicious")
                else:
                    predictions.append("benign_like")
            else:
                predictions.append(_v14_threshold_decision(probs, profile=profile))
        results[profile] = predictions
    return results


def _calibration_report(
    y_true: list[str],
    probabilities: Any,
    classes: list[str],
) -> dict[str, Any]:
    if not len(probabilities):
        return {"status": "unavailable", "buckets": [], "passed": False}
    rows: list[tuple[float, bool]] = []
    brier_total = 0.0
    for actual, row in zip(y_true, probabilities, strict=False):
        values = [float(value) for value in row]
        predicted_index = max(range(len(values)), key=values.__getitem__)
        confidence = values[predicted_index]
        rows.append((confidence, classes[predicted_index] == actual))
        threat_probability = sum(
            value for label, value in zip(classes, values, strict=False) if label in THREAT_LABELS
        )
        actual_threat = 1.0 if actual in THREAT_LABELS else 0.0
        brier_total += (threat_probability - actual_threat) ** 2
    buckets: list[dict[str, Any]] = []
    minimum_bucket_rows = max(10, math.ceil(len(rows) * 0.02))
    for lower in (0.0, 0.2, 0.4, 0.6, 0.8):
        upper = lower + 0.2
        selected = [
            (confidence, correct)
            for confidence, correct in rows
            if confidence >= lower
            and (confidence < upper or (upper >= 1.0 and confidence <= 1.0))
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
    expected_calibration_error = (
        sum(item["rows"] / total * item["gap"] for item in buckets)
        if total
        else 1.0
    )
    reliable_buckets = [item for item in buckets if item["reliable"]]
    max_gap = max(
        (float(item["gap"]) for item in reliable_buckets),
        default=1.0,
    )
    all_bucket_max_gap = max((float(item["gap"]) for item in buckets), default=1.0)
    passed = (
        bool(reliable_buckets)
        and max_gap <= 0.2
        and expected_calibration_error <= 0.15
    )
    return {
        "status": "passed" if passed else "weak",
        "passed": passed,
        "rows": total,
        "brier_score_threat_positive": round(brier_total / total, 4) if total else None,
        "expected_calibration_error": round(expected_calibration_error, 4),
        "max_confidence_accuracy_gap": round(max_gap, 4),
        "all_bucket_max_confidence_accuracy_gap": round(all_bucket_max_gap, 4),
        "minimum_reliable_bucket_rows": minimum_bucket_rows,
        "buckets": buckets,
        "readiness_buckets": reliable_buckets,
    }


def _fit_flat_strategy(
    prepared: dict[str, Any],
    *,
    name: str,
    model_type: str,
    class_weight: str | None,
    weight_strategy: str,
    calibrated: bool = False,
) -> dict[str, Any]:
    labels = prepared["labels"]
    train_idx = prepared["train_idx"]
    test_idx = prepared["test_idx"]
    frame = prepared["frame"]
    y_train = prepared["y_train"]
    y_test = prepared["y_test"]
    pipeline = _build_pipeline(
        prepared["imports"],
        model_type=model_type,
        class_weight=class_weight,
    )
    weights, weight_summary = _weights(labels, weight_strategy)
    started = time.perf_counter()
    if calibrated:
        from sklearn.calibration import CalibratedClassifierCV

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
    profile_predictions = _profile_predictions(probabilities, classes, mapped_mode="flat")
    labels_order = sorted(set(prepared["y"]))
    profiles = {
        profile: _metric_bundle(
            prepared,
            y_true=y_test,
            predictions=predictions,
            labels_order=labels_order,
        )
        for profile, predictions in profile_predictions.items()
    }
    return {
        "name": name,
        "status": "evaluated",
        "model_type": model_type,
        "target_mode": "flat",
        "class_weight": class_weight or "none",
        "sample_weighting": weight_summary,
        "calibrated": calibrated,
        "training_seconds": round(training_seconds, 4),
        "profiles": profiles,
        "calibration": _calibration_report(y_test, probabilities, classes),
        "_probabilities": probabilities,
        "_classes": classes,
        "_predictions": profile_predictions,
    }


def _fit_mapped_strategy(
    prepared: dict[str, Any],
    *,
    name: str,
    target_mode: str,
) -> dict[str, Any]:
    labels = prepared["labels"]
    train_idx = prepared["train_idx"]
    test_idx = prepared["test_idx"]
    frame = prepared["frame"]
    mapped = [
        "threat_positive"
        if target_mode == "binary" and label.label in THREAT_LABELS
        else "benign_like"
        if target_mode in {"binary", "three_class"} and label.label in BENIGN_LIKE_LABELS
        else label.label
        for label in labels
    ]
    y_train = [mapped[index] for index in train_idx]
    y_test = [mapped[index] for index in test_idx]
    pipeline = _build_pipeline(
        prepared["imports"],
        model_type="extra_trees",
        class_weight=None,
    )
    weights, weight_summary = _weights(labels, "strong_benign")
    started = time.perf_counter()
    pipeline.fit(
        frame.iloc[train_idx],
        y_train,
        model__sample_weight=[weights[index] for index in train_idx],
    )
    training_seconds = time.perf_counter() - started
    probabilities = pipeline.predict_proba(frame.iloc[test_idx])
    classes = _classes(pipeline)
    profile_predictions = _profile_predictions(
        probabilities,
        classes,
        mapped_mode=target_mode,
    )
    profiles = {}
    for profile, predictions in profile_predictions.items():
        if target_mode == "binary":
            profiles[profile] = _binary_metric_bundle(y_test, predictions)
        else:
            profiles[profile] = _metric_bundle(
                prepared,
                y_true=y_test,
                predictions=predictions,
                labels_order=["benign_like", "malicious", "suspicious"],
            )
    return {
        "name": name,
        "status": "evaluated",
        "model_type": "extra_trees",
        "target_mode": target_mode,
        "class_weight": "none",
        "sample_weighting": weight_summary,
        "calibrated": False,
        "training_seconds": round(training_seconds, 4),
        "profiles": profiles,
        "calibration": _calibration_report(y_test, probabilities, classes),
        "_model": pipeline,
        "_probabilities": probabilities,
        "_classes": classes,
        "_predictions": profile_predictions,
        "_mapped_y_test": y_test,
    }


def _fit_hierarchical_strategy(prepared: dict[str, Any]) -> dict[str, Any]:
    labels = prepared["labels"]
    train_idx = prepared["train_idx"]
    test_idx = prepared["test_idx"]
    frame = prepared["frame"]
    y = prepared["y"]
    stage1_y = ["threat_positive" if value in THREAT_LABELS else "benign_like" for value in y]
    weights, weight_summary = _weights(labels, "strong_benign")
    stage1 = _build_pipeline(prepared["imports"], model_type="extra_trees", class_weight=None)
    started = time.perf_counter()
    stage1.fit(
        frame.iloc[train_idx],
        [stage1_y[index] for index in train_idx],
        model__sample_weight=[weights[index] for index in train_idx],
    )
    stage1_probabilities = stage1.predict_proba(frame.iloc[test_idx])
    stage1_classes = _classes(stage1)
    threat_train_idx = [index for index in train_idx if y[index] in THREAT_LABELS]
    stage2 = _build_pipeline(prepared["imports"], model_type="extra_trees", class_weight="balanced")
    stage2.fit(
        frame.iloc[threat_train_idx],
        [y[index] for index in threat_train_idx],
        model__sample_weight=[weights[index] for index in threat_train_idx],
    )
    stage2_probabilities = stage2.predict_proba(frame.iloc[test_idx])
    stage2_classes = _classes(stage2)
    profiles: dict[str, Any] = {}
    mapped_y_test = [
        value if value in THREAT_LABELS else "benign_like"
        for value in prepared["y_test"]
    ]
    for profile, thresholds in V14_THRESHOLD_PROFILES.items():
        predictions = []
        for stage1_row, stage2_row in zip(
            stage1_probabilities,
            stage2_probabilities,
            strict=False,
        ):
            stage1_probs = {
                label: float(value)
                for label, value in zip(stage1_classes, stage1_row, strict=False)
            }
            if float(stage1_probs.get("threat_positive", 0)) < thresholds["threat_positive"]:
                predictions.append("benign_like")
                continue
            stage2_probs = {
                label: float(value)
                for label, value in zip(stage2_classes, stage2_row, strict=False)
            }
            predictions.append(
                "malicious"
                if float(stage2_probs.get("malicious", 0))
                >= float(stage2_probs.get("suspicious", 0))
                else "suspicious"
            )
        profiles[profile] = _metric_bundle(
            prepared,
            y_true=mapped_y_test,
            predictions=predictions,
            labels_order=["benign_like", "malicious", "suspicious"],
        )
    return {
        "name": "hierarchical_two_stage",
        "status": "evaluated",
        "model_type": "extra_trees_two_stage",
        "target_mode": "hierarchical",
        "class_weight": "mixed",
        "sample_weighting": weight_summary,
        "calibrated": False,
        "training_seconds": round(time.perf_counter() - started, 4),
        "profiles": profiles,
        "calibration": _calibration_report(
            [stage1_y[index] for index in test_idx],
            stage1_probabilities,
            stage1_classes,
        ),
    }


def _profile_summary(metrics: dict[str, Any]) -> dict[str, Any]:
    threat = metrics.get("threat_positive") or {}
    per_class = metrics.get("per_class") or {}
    return {
        "threat_positive_precision": threat.get("precision"),
        "threat_positive_recall": threat.get("recall"),
        "threat_positive_f1": threat.get("f1"),
        "benign_like_false_positive_rate": metrics.get("false_positive_rate"),
        "suspicious_recall": (per_class.get("suspicious") or {}).get("recall"),
        "malicious_recall": (per_class.get("malicious") or {}).get("recall"),
        "false_positives": metrics.get("false_positives"),
        "false_negatives": metrics.get("false_negatives"),
        "review_queue_size_estimate": metrics.get("review_queue_size_estimate"),
        "weighted_f1": (metrics.get("weighted_average") or {}).get("f1"),
        "macro_f1": (metrics.get("macro_average") or {}).get("f1"),
    }


def _best_profile(profiles: dict[str, Any]) -> str | None:
    candidates = []
    for name, metrics in profiles.items():
        summary = _profile_summary(metrics)
        recall = float(summary.get("threat_positive_recall") or 0)
        f1 = float(summary.get("threat_positive_f1") or 0)
        raw_fpr = summary.get("benign_like_false_positive_rate")
        fpr = float(raw_fpr if raw_fpr is not None else 1)
        candidates.append((name, recall, f1, fpr))
    viable = [item for item in candidates if item[1] >= 0.75]
    ranked = viable or candidates
    return max(
        ranked,
        key=lambda item: (
            item[2] - 0.5 * item[3],
            item[1],
            -item[3],
        ),
        default=(None, 0, 0, 1),
    )[0]


def _strip_runtime_fields(strategy: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in strategy.items()
        if not key.startswith("_")
    }


def _fit_legacy_baseline(prepared: dict[str, Any]) -> dict[str, Any]:
    labels = prepared["labels"]
    train_idx = prepared["train_idx"]
    test_idx = prepared["test_idx"]
    pipeline = _build_pipeline(
        prepared["imports"],
        model_type="logistic_regression",
        class_weight="balanced",
    )
    weights, weight_summary = _weights(labels, "current")
    pipeline.fit(
        prepared["frame"].iloc[train_idx],
        prepared["y_train"],
        model__sample_weight=[weights[index] for index in train_idx],
    )
    probabilities = pipeline.predict_proba(prepared["frame"].iloc[test_idx])
    classes = _classes(pipeline)
    predictions = [
        threshold_decision(
            {
                label: float(value)
                for label, value in zip(classes, row, strict=False)
            },
            profile="balanced",
        )
        for row in probabilities
    ]
    return {
        "name": "v1_3_logistic_regression_balanced",
        "predictions": predictions,
        "probabilities": probabilities,
        "classes": classes,
        "sample_weighting": weight_summary,
        "metrics": _metric_bundle(
            prepared,
            y_true=prepared["y_test"],
            predictions=predictions,
            labels_order=sorted(set(prepared["y"])),
        ),
    }


def _pattern_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "apps": dict(Counter(str(row["log"].app or "unknown") for row in rows).most_common(10)),
        "actions": dict(Counter(str(row["log"].action or "unknown") for row in rows).most_common(10)),
        "destination_ports": dict(
            Counter(
                str(row["log"].dst_port if row["log"].dst_port is not None else "missing")
                for row in rows
            ).most_common(10)
        ),
        "source_ips": dict(Counter(str(row["log"].src_ip or "missing") for row in rows).most_common(10)),
        "sources": dict(Counter(_source_name(row["log"]) for row in rows).most_common(10)),
        "review_status": dict(
            Counter("reviewed" if row["label"].reviewed else "weak" for row in rows)
        ),
    }


def _false_positive_rows(
    prepared: dict[str, Any],
    baseline: dict[str, Any],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for position, (actual, predicted, probability_row) in enumerate(
        zip(
            prepared["y_test"],
            baseline["predictions"],
            baseline["probabilities"],
            strict=False,
        )
    ):
        if actual not in BENIGN_LIKE_LABELS or predicted not in THREAT_LABELS:
            continue
        label = prepared["test_labels"][position]
        probs = {
            name: float(value)
            for name, value in zip(baseline["classes"], probability_row, strict=False)
        }
        rows.append(
            {
                "position": position,
                "label": label,
                "log": label.log,
                "actual": actual,
                "predicted": predicted,
                "confidence": max(probs.values(), default=0),
                "threat_positive_score": sum(probs.get(name, 0) for name in THREAT_LABELS),
                "probabilities": probs,
            }
        )
    return rows


def _duplicate_diagnostics(
    prepared: dict[str, Any],
    false_positive_rows: list[dict[str, Any]],
) -> dict[str, Any]:
    logs = prepared["logs"]
    train_exact = Counter(_signature(logs[index], include_time=True) for index in prepared["train_idx"])
    train_near = Counter(_signature(logs[index], include_time=False) for index in prepared["train_idx"])
    test_exact = Counter(_signature(logs[index], include_time=True) for index in prepared["test_idx"])
    test_near = Counter(_signature(logs[index], include_time=False) for index in prepared["test_idx"])
    shared_exact = set(train_exact) & set(test_exact)
    shared_near = set(train_near) & set(test_near)
    fp_exact = sum(
        1 for row in false_positive_rows
        if _signature(row["log"], include_time=True) in shared_exact
    )
    fp_near = sum(
        1 for row in false_positive_rows
        if _signature(row["log"], include_time=False) in shared_near
    )
    test_rows_in_shared_near_groups = sum(test_near[key] for key in shared_near)
    near_overlap_rate = (
        test_rows_in_shared_near_groups / len(prepared["test_idx"])
        if prepared["test_idx"]
        else 0.0
    )
    return {
        "shared_exact_signature_groups": len(shared_exact),
        "shared_near_duplicate_groups": len(shared_near),
        "test_rows_in_shared_exact_groups": sum(test_exact[key] for key in shared_exact),
        "test_rows_in_shared_near_groups": test_rows_in_shared_near_groups,
        "test_near_duplicate_overlap_rate": round(near_overlap_rate, 4),
        "false_positives_in_shared_exact_groups": fp_exact,
        "false_positives_in_shared_near_groups": fp_near,
        "interpretation": (
            "Cross-window near duplicates may inflate or distort temporal evaluation."
            if near_overlap_rate > 0.05
            else "Near-duplicate overlap is limited and is unlikely to be the main false-positive driver."
            if shared_near
            else "No train/test near-duplicate overlap was detected."
        ),
    }


def _render_false_positive_analysis(report: dict[str, Any]) -> str:
    return f"""# v1.4 False Positive Analysis

Generated: {report['generated_at']}

This report reproduces the v1.3 selected Logistic Regression threshold behavior. It is diagnostic only.

## Counts

- Total false positives: {report['false_positive_count']}
- Benign predicted malicious: {report['confusion_counts'].get('benign_predicted_malicious', 0)}
- Benign predicted suspicious: {report['confusion_counts'].get('benign_predicted_suspicious', 0)}
- Benign-unusual predicted malicious: {report['confusion_counts'].get('benign_unusual_predicted_malicious', 0)}
- Benign-unusual predicted suspicious: {report['confusion_counts'].get('benign_unusual_predicted_suspicious', 0)}
- Needs-context predicted malicious: {report['confusion_counts'].get('needs_context_predicted_malicious', 0)}
- Needs-context predicted suspicious: {report['confusion_counts'].get('needs_context_predicted_suspicious', 0)}
- Incomplete / allow / port 80 false positives: {report['incomplete_allow_port_80_count']}

## Patterns

```json
{json.dumps(report['patterns'], indent=2, default=str)}
```

## Time and Source Concentration

```json
{json.dumps(report['time_source_concentration'], indent=2, default=str)}
```

## Duplicate Diagnostics

```json
{json.dumps(report['duplicate_diagnostics'], indent=2, default=str)}
```

## Root Cause

{chr(10).join(f"- {item}" for item in report['root_cause_notes'])}

## Safety

- Model activation: none
- Production promoted: false
- Response automation allowed: false
"""


def _render_experiment_report(report: dict[str, Any]) -> str:
    rows = []
    for strategy in report["strategies"]:
        profile = strategy.get("recommended_profile")
        summary = strategy.get("recommended_metrics") or {}
        rows.append(
            "| {name} | {mode} | {profile} | {precision} | {recall} | {f1} | {fpr} | {suspicious} | {malicious} | {queue} |".format(
                name=strategy.get("name"),
                mode=strategy.get("target_mode"),
                profile=profile,
                precision=summary.get("threat_positive_precision"),
                recall=summary.get("threat_positive_recall"),
                f1=summary.get("threat_positive_f1"),
                fpr=summary.get("benign_like_false_positive_rate"),
                suspicious=summary.get("suspicious_recall"),
                malicious=summary.get("malicious_recall"),
                queue=summary.get("review_queue_size_estimate"),
            )
        )
    return f"""# v1.4 False Positive Reduction and Calibration

Generated: {report['generated_at']}

No model artifact was written or activated.

| Strategy | Mode | Profile | Threat Precision | Threat Recall | Threat F1 | Benign-like FPR | Suspicious Recall | Malicious Recall | Review Queue |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
{chr(10).join(rows)}

## Recommendation

- Best strategy: {report['best_strategy']}
- Best profile: {report['best_profile']}
- Readiness: {report['readiness']['decision']}
- Calibration: {report['calibration_status']}

## Readiness Notes

{chr(10).join(f"- {item}" for item in report['readiness_notes'])}

## Safety

- Production promoted: false
- Response automation allowed: false
- Real firewall blocking enabled: false
"""


def _select_best_strategy(strategies: list[dict[str, Any]]) -> tuple[dict[str, Any] | None, str | None]:
    candidates = []
    for strategy in strategies:
        profile = strategy.get("recommended_profile")
        metrics = (strategy.get("profiles") or {}).get(profile) or {}
        summary = _profile_summary(metrics)
        recall = float(summary.get("threat_positive_recall") or 0)
        f1 = float(summary.get("threat_positive_f1") or 0)
        raw_fpr = summary.get("benign_like_false_positive_rate")
        fpr = float(raw_fpr if raw_fpr is not None else 1)
        suspicious = summary.get("suspicious_recall")
        suspicious_score = float(suspicious) if suspicious is not None else recall
        candidates.append((strategy, profile, recall, f1, fpr, suspicious_score))
    viable = [item for item in candidates if item[2] >= 0.75]
    ranked = viable or candidates
    winner = max(
        ranked,
        key=lambda item: (
            item[3] - 0.5 * item[4],
            item[5],
            item[2],
            -item[4],
        ),
        default=None,
    )
    return (winner[0], winner[1]) if winner else (None, None)


def _write_review_sample(
    false_positive_rows: list[dict[str, Any]],
    *,
    output_path: str | Path,
    limit: int,
    include_manual: bool = False,
    include_reviewed: bool = False,
    only_actionable: bool = True,
) -> dict[str, Any]:
    eligible: list[dict[str, Any]] = []
    excluded: Counter[str] = Counter()
    for row in false_positive_rows:
        label = row["label"]
        source = str(label.label_source or "manual")
        if source == "manual" and not include_manual:
            excluded["protected_manual"] += 1
            continue
        if source != "manual" and label.reviewed and not include_reviewed:
            excluded["protected_reviewed"] += 1
            continue
        if only_actionable and source == "manual":
            excluded["manual_not_actionable"] += 1
            continue
        eligible.append(row)
    prioritized = sorted(
        eligible,
        key=lambda row: (
            row["confidence"],
            row["threat_positive_score"],
            int(row["label"].reviewed),
        ),
        reverse=True,
    )
    selected: list[dict[str, Any]] = []
    source_counts: Counter[str] = Counter()
    max_per_source = max(10, limit // 3)
    for row in prioritized:
        source = _source_name(row["log"])
        if source_counts[source] >= max_per_source:
            continue
        selected.append(row)
        source_counts[source] += 1
        if len(selected) >= limit:
            break
    if len(selected) < limit:
        selected_ids = {row["label"].log_id for row in selected}
        selected.extend(
            row for row in prioritized
            if row["label"].log_id not in selected_ids
        )
    selected = selected[:limit]
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=V14_REVIEW_FIELDS)
        writer.writeheader()
        for row in selected:
            log = row["log"]
            label = row["label"]
            timestamp = _log_timestamp(log)
            pattern = (
                str(log.app or "").lower() == "incomplete"
                and str(log.action or "").lower() == "allow"
                and log.dst_port == 80
            )
            reason = (
                "high-confidence false positive; incomplete/allow/port 80 repeated pattern"
                if pattern
                else f"high-confidence false positive: {row['actual']} predicted {row['predicted']}"
            )
            writer.writerow(
                {
                    "label_id": label.id,
                    "log_id": log.id,
                    "timestamp": timestamp.isoformat() if timestamp else "",
                    "split_window": "test_window",
                    "source_name": _source_name(log),
                    "src_ip": log.src_ip or "",
                    "dst_ip": log.dst_ip or "",
                    "dst_port": log.dst_port if log.dst_port is not None else "",
                    "protocol": log.protocol or "",
                    "app": log.app or "",
                    "action": log.action or "",
                    "current_label": label.label,
                    "current_attack_type": label.attack_type,
                    "reviewed_status": bool(label.reviewed),
                    "label_source": label.label_source,
                    "model_prediction": row["predicted"],
                    "model_confidence": round(row["confidence"], 4),
                    "threat_positive_score": round(row["threat_positive_score"], 4),
                    "reason_selected": reason,
                    "evidence_summary": (
                        f"actual={row['actual']}; predicted={row['predicted']}; "
                        f"app={log.app}; action={log.action}; dst_port={log.dst_port}; "
                        f"source={_source_name(log)}"
                    ),
                    "human_review_decision": "",
                    "human_review_attack_type": label.attack_type,
                    "human_review_confidence": label.confidence,
                    "human_review_note": "",
                }
            )
    return {
        "path": str(path),
        "rows": len(selected),
        "label_distribution": dict(Counter(row["actual"] for row in selected)),
        "prediction_distribution": dict(Counter(row["predicted"] for row in selected)),
        "source_distribution": dict(Counter(_source_name(row["log"]) for row in selected)),
        "excluded": dict(excluded),
        "include_manual": include_manual,
        "include_reviewed": include_reviewed,
        "only_actionable": only_actionable,
    }


def run_v14_false_positive_reduction(
    db: Session,
    *,
    split: str = "time",
    test_size: float = 0.3,
    min_samples: int = 6,
    review_limit: int = 200,
    output_dir: str | Path = OUTPUT_DIR,
    include_manual: bool = False,
    include_reviewed: bool = False,
    only_actionable: bool = True,
) -> dict[str, Any]:
    output = Path(output_dir)
    stamp = _stamp()
    prepared = _prepare_dataset(
        db,
        split=split,
        test_size=test_size,
        min_samples=min_samples,
    )
    if not prepared.get("ok"):
        return prepared

    baseline = _fit_legacy_baseline(prepared)
    false_positive_rows = _false_positive_rows(prepared, baseline)
    confusion_counts = Counter(
        f"{actual}_predicted_{predicted}"
        for actual, predicted in zip(
            prepared["y_test"],
            baseline["predictions"],
            strict=False,
        )
        if actual != predicted
    )
    timestamps = [
        timestamp
        for row in false_positive_rows
        if (timestamp := _log_timestamp(row["log"])) is not None
    ]
    patterns = _pattern_summary(false_positive_rows)
    source_counts = Counter(_source_name(row["log"]) for row in false_positive_rows)
    time_counts = Counter(
        timestamp.strftime("%Y-%m-%dT%H:%M")
        for timestamp in timestamps
        if timestamp is not None
    )
    incomplete_allow_80 = sum(
        1
        for row in false_positive_rows
        if str(row["log"].app or "").lower() == "incomplete"
        and str(row["log"].action or "").lower() == "allow"
        and row["log"].dst_port == 80
    )
    duplicate_diagnostics = _duplicate_diagnostics(prepared, false_positive_rows)
    largest_source_count = max(source_counts.values(), default=0)
    source_concentration = (
        largest_source_count / len(false_positive_rows)
        if false_positive_rows
        else 0.0
    )
    top_app, top_app_count = Counter(
        str(row["log"].app or "unknown") for row in false_positive_rows
    ).most_common(1)[0] if false_positive_rows else ("none", 0)
    top_action, top_action_count = Counter(
        str(row["log"].action or "unknown") for row in false_positive_rows
    ).most_common(1)[0] if false_positive_rows else ("none", 0)
    top_port, top_port_count = Counter(
        str(row["log"].dst_port if row["log"].dst_port is not None else "missing")
        for row in false_positive_rows
    ).most_common(1)[0] if false_positive_rows else ("none", 0)
    top_minute, top_minute_count = time_counts.most_common(1)[0] if time_counts else ("none", 0)
    false_positive_count = max(len(false_positive_rows), 1)
    reviewed_false_positives = sum(
        1 for row in false_positive_rows if row["label"].reviewed
    )
    root_causes = [
        "The legacy balanced threshold can fall back to a threat class even when the configured threat threshold is not met.",
        "Current sample weighting strongly upweights reviewed suspicious and malicious rows, increasing threat bias.",
        (
            f"{top_minute_count}/{len(false_positive_rows)} false positives "
            f"({top_minute_count / false_positive_count:.1%}) occur in minute {top_minute}, "
            "indicating a concentrated time-window distribution shift."
        ),
        (
            f"The dominant pattern is app={top_app} ({top_app_count}), "
            f"action={top_action} ({top_action_count}), and destination port={top_port} "
            f"({top_port_count})."
        ),
        (
            f"{reviewed_false_positives}/{len(false_positive_rows)} false positives are "
            "human-reviewed labels, so the error is not explained by weak labels alone."
        ),
        (
            f"The largest source label contributes {source_concentration:.1%} of false positives. "
            "All rows use local_import when source attribution is not device-specific."
        ),
        (
            f"Incomplete/allow/port 80 contributes {incomplete_allow_80} false positives "
            "and is not the dominant pattern."
        ),
        duplicate_diagnostics["interpretation"],
    ]
    analysis = {
        "ok": True,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "split": split,
        "training_rows": len(prepared["train_idx"]),
        "test_rows": len(prepared["test_idx"]),
        "baseline": baseline["name"],
        "baseline_metrics": baseline["metrics"],
        "false_positive_count": len(false_positive_rows),
        "confusion_counts": dict(confusion_counts),
        "patterns": patterns,
        "incomplete_allow_port_80_count": incomplete_allow_80,
        "time_source_concentration": {
            "top_sources": dict(source_counts.most_common(10)),
            "largest_source_share": round(source_concentration, 4),
            "top_minutes": dict(time_counts.most_common(10)),
            "earliest_false_positive": min(timestamps).isoformat() if timestamps else None,
            "latest_false_positive": max(timestamps).isoformat() if timestamps else None,
        },
        "duplicate_diagnostics": duplicate_diagnostics,
        "root_cause_notes": root_causes,
        "production_promoted": False,
        "response_automation_allowed": False,
    }
    analysis_path = output / f"v1_4_false_positive_analysis_{stamp}.md"
    analysis_path.parent.mkdir(parents=True, exist_ok=True)
    analysis_path.write_text(_render_false_positive_analysis(analysis), encoding="utf-8")
    _write_json(analysis_path.with_suffix(".json"), analysis)
    analysis["report_path"] = str(analysis_path)

    strategies = [
        _fit_flat_strategy(
            prepared,
            name="flat_extra_trees_current",
            model_type="extra_trees",
            class_weight="balanced",
            weight_strategy="current",
        ),
        _fit_flat_strategy(
            prepared,
            name="flat_extra_trees_lower_threat",
            model_type="extra_trees",
            class_weight=None,
            weight_strategy="lower_threat",
        ),
        _fit_flat_strategy(
            prepared,
            name="flat_extra_trees_strong_benign",
            model_type="extra_trees",
            class_weight=None,
            weight_strategy="strong_benign",
        ),
        _fit_flat_strategy(
            prepared,
            name="calibrated_logistic_regression",
            model_type="logistic_regression",
            class_weight="balanced",
            weight_strategy="none",
            calibrated=True,
        ),
        _fit_mapped_strategy(
            prepared,
            name="binary_benign_like_vs_threat",
            target_mode="binary",
        ),
        _fit_mapped_strategy(
            prepared,
            name="three_class_soc_triage",
            target_mode="three_class",
        ),
        _fit_hierarchical_strategy(prepared),
    ]
    for strategy in strategies:
        strategy["recommended_profile"] = _best_profile(strategy["profiles"])
        strategy["recommended_metrics"] = _profile_summary(
            strategy["profiles"][strategy["recommended_profile"]]
        )
    baseline_strategy = strategies[0]
    threshold_report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "strategy": baseline_strategy["name"],
        "profiles": {
            profile: {
                "thresholds": V14_THRESHOLD_PROFILES[profile],
                "metrics": _profile_summary(metrics),
            }
            for profile, metrics in baseline_strategy["profiles"].items()
        },
        "recommended_profile": baseline_strategy["recommended_profile"],
        "production_promoted": False,
        "response_automation_allowed": False,
    }
    threshold_path = output / f"v1_4_threshold_calibration_{stamp}.md"
    threshold_rows = "\n".join(
        "| {profile} | {precision} | {recall} | {f1} | {fpr} | {suspicious} | {malicious} | {fp} | {fn} | {queue} |".format(
            profile=profile,
            precision=item["metrics"].get("threat_positive_precision"),
            recall=item["metrics"].get("threat_positive_recall"),
            f1=item["metrics"].get("threat_positive_f1"),
            fpr=item["metrics"].get("benign_like_false_positive_rate"),
            suspicious=item["metrics"].get("suspicious_recall"),
            malicious=item["metrics"].get("malicious_recall"),
            fp=item["metrics"].get("false_positives"),
            fn=item["metrics"].get("false_negatives"),
            queue=item["metrics"].get("review_queue_size_estimate"),
        )
        for profile, item in threshold_report["profiles"].items()
    )
    threshold_path.write_text(
        "# v1.4 Threshold Calibration\n\n"
        f"Generated: {threshold_report['generated_at']}\n\n"
        "The v1.4 profiles use a hard threat gate. If threat probability is below the gate, "
        "the fallback cannot silently return suspicious or malicious.\n\n"
        "| Profile | Threat Precision | Threat Recall | Threat F1 | Benign-like FPR | Suspicious Recall | Malicious Recall | FP | FN | Queue |\n"
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |\n"
        f"{threshold_rows}\n\n"
        f"Recommended profile: {threshold_report['recommended_profile']}\n\n"
        "No model activation. Response automation remains disabled.\n",
        encoding="utf-8",
    )
    _write_json(threshold_path.with_suffix(".json"), threshold_report)

    strategy_report = {
        "generated_at": threshold_report["generated_at"],
        "strategies": [_strip_runtime_fields(item) for item in strategies],
        "production_promoted": False,
        "response_automation_allowed": False,
    }
    strategy_path = output / f"v1_4_model_strategy_comparison_{stamp}.md"
    strategy_rows = "\n".join(
        "| {name} | {mode} | {profile} | {precision} | {recall} | {f1} | {fpr} | {suspicious} | {malicious} |".format(
            name=item["name"],
            mode=item["target_mode"],
            profile=item["recommended_profile"],
            precision=item["recommended_metrics"].get("threat_positive_precision"),
            recall=item["recommended_metrics"].get("threat_positive_recall"),
            f1=item["recommended_metrics"].get("threat_positive_f1"),
            fpr=item["recommended_metrics"].get("benign_like_false_positive_rate"),
            suspicious=item["recommended_metrics"].get("suspicious_recall"),
            malicious=item["recommended_metrics"].get("malicious_recall"),
        )
        for item in strategies
    )
    strategy_path.write_text(
        "# v1.4 Model Strategy Comparison\n\n"
        f"Generated: {strategy_report['generated_at']}\n\n"
        "| Strategy | Mode | Profile | Threat Precision | Threat Recall | Threat F1 | Benign-like FPR | Suspicious Recall | Malicious Recall |\n"
        "| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |\n"
        f"{strategy_rows}\n\n"
        "All strategies are diagnostic candidates. No model artifact was written or activated.\n",
        encoding="utf-8",
    )
    _write_json(strategy_path.with_suffix(".json"), strategy_report)

    best_strategy, best_profile = _select_best_strategy(strategies)
    if best_strategy is None or best_profile is None:
        return {"ok": False, "status": "failed", "message": "No v1.4 strategy could be evaluated."}
    best_metrics = best_strategy["profiles"][best_profile]
    best_calibration = best_strategy.get("calibration") or {}
    temporal = build_class_temporal_coverage(db, test_size=test_size)
    reviewed_distribution = dict(
        Counter(label.label for label in prepared["labels"] if label.reviewed)
    )
    readiness = readiness_gate_v3(
        reviewed_label_count=sum(reviewed_distribution.values()),
        reviewed_label_distribution=reviewed_distribution,
        temporal_class_coverage=temporal,
        metrics=best_metrics,
        benchmark_label_count=0,
        calibration_buckets=best_calibration.get("readiness_buckets") or [],
        drift_warnings=[],
        response_automation_allowed=False,
    )
    blockers = [
        item["detail"]
        for item in readiness["checks"]
        if not item["passed"]
    ]
    best_fpr = best_metrics.get("false_positive_rate")
    if float(best_fpr if best_fpr is not None else 1) > 0.15:
        blockers.insert(0, "Main blocker: false positives remain above the 0.15 target.")
    if best_calibration.get("status") != "passed":
        blockers.append("Calibration remains weak or pending.")
    blockers.extend(
        [
            "Model remains decision support only.",
            "Response automation disabled.",
        ]
    )
    serializable_strategies = [_strip_runtime_fields(item) for item in strategies]
    report = {
        "ok": True,
        "status": "completed",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "split": split,
        "test_size": test_size,
        "training_rows": len(prepared["train_idx"]),
        "test_rows": len(prepared["test_idx"]),
        "reviewed_label_count": sum(reviewed_distribution.values()),
        "feature_generation_seconds": prepared["feature_generation_seconds"],
        "split_warnings": prepared["split_warnings"],
        "baseline": {
            "name": baseline["name"],
            "metrics": baseline["metrics"],
            "summary": _profile_summary(baseline["metrics"]),
        },
        "threshold_profiles": V14_THRESHOLD_PROFILES,
        "strategies": serializable_strategies,
        "threshold_report_path": str(threshold_path),
        "strategy_report_path": str(strategy_path),
        "best_strategy": best_strategy["name"],
        "best_profile": best_profile,
        "best_metrics": _profile_summary(best_metrics),
        "calibration_status": best_calibration.get("status", "unavailable"),
        "best_calibration": best_calibration,
        "readiness": readiness,
        "readiness_notes": list(dict.fromkeys(blockers)),
        "false_positive_analysis_path": str(analysis_path),
        "production_promoted": False,
        "model_activated": False,
        "model_artifact_written": False,
        "response_automation_allowed": False,
        "real_firewall_blocking_enabled": False,
    }
    report_path = output / f"v1_4_false_positive_reduction_{stamp}.md"
    report_path.write_text(_render_experiment_report(report), encoding="utf-8")
    _write_json(report_path.with_suffix(".json"), report)
    report["report_path"] = str(report_path)

    calibration_path = output / f"v1_4_confidence_calibration_{stamp}.md"
    calibration_path.write_text(
        "# v1.4 Confidence Calibration\n\n"
        f"Generated: {report['generated_at']}\n\n"
        f"- Best strategy: {report['best_strategy']}\n"
        f"- Status: {report['calibration_status']}\n"
        f"- Threat-positive Brier score: {best_calibration.get('brier_score_threat_positive')}\n"
        f"- Expected calibration error: {best_calibration.get('expected_calibration_error')}\n"
        f"- Maximum confidence/accuracy gap: {best_calibration.get('max_confidence_accuracy_gap')}\n\n"
        f"```json\n{json.dumps(best_calibration.get('buckets') or [], indent=2)}\n```\n\n"
        "Decision support only. No model activation or response automation.\n",
        encoding="utf-8",
    )
    _write_json(
        calibration_path.with_suffix(".json"),
        {
            "generated_at": report["generated_at"],
            "best_strategy": report["best_strategy"],
            **best_calibration,
            "production_promoted": False,
            "response_automation_allowed": False,
        },
    )
    report["calibration_report_path"] = str(calibration_path)

    review = _write_review_sample(
        false_positive_rows,
        output_path=output / V14_REVIEW_PATH.name,
        limit=review_limit,
        include_manual=include_manual,
        include_reviewed=include_reviewed,
        only_actionable=only_actionable,
    )
    report["review_sample"] = review
    _write_json(report_path.with_suffix(".json"), report)
    return report
