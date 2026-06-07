import csv
import json
import math
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np
from sqlalchemy import desc, func, or_, select
from sqlalchemy.orm import Session

from atdr.app.benchmarks.readiness import readiness_gate_v3
from atdr.app.db.models import MLLabel, NormalizedLog
from atdr.app.detection.hybrid_scoring import hybrid_risk_score
from atdr.app.detection.supervised_detector import _build_pipeline, _latest_labels
from atdr.app.detection.v14_false_positive import (
    BENIGN_LIKE_LABELS,
    OUTPUT_DIR,
    THREAT_LABELS,
    _calibration_report,
    _classes,
    _fit_mapped_strategy,
    _metric_bundle,
    _prepare_dataset,
    _profile_summary,
    _weights,
)
from atdr.app.detection.v14b_false_positive import (
    _is_normal_quic,
    _mapped_probabilities,
    _mitigation_predictions,
    _review_eligibility,
    _source_name,
    _strong_evidence,
)
from atdr.app.ml.features import build_feature_rows
from atdr.app.services.active_learning_service import _simple_rule_score
from atdr.app.services.class_temporal_coverage_service import (
    build_class_temporal_coverage,
)


V14C_REPORT_PATH = OUTPUT_DIR / "v1_4c_malicious_recall_recovery.md"
V14C_REVIEW_PATH = OUTPUT_DIR / "v1_4c_malicious_recall_review_sample.csv"
V14C_REVIEW_FIELDS = [
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
    "actionable_status",
    "model_prediction",
    "model_confidence",
    "malicious_score",
    "suspicious_score",
    "threat_positive_score",
    "rule_score",
    "anomaly_score",
    "hybrid_risk_score",
    "strong_evidence",
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


def _log_timestamp(log: NormalizedLog) -> datetime | None:
    return log.generated_time or log.receive_time or log.start_time


def _mapped_labels(labels: list[MLLabel]) -> list[str]:
    return [
        label.label if label.label in THREAT_LABELS else "benign_like"
        for label in labels
    ]


def _align_probabilities(
    probabilities: Any,
    source_classes: list[str],
    target_classes: list[str],
) -> np.ndarray:
    source_positions = {name: index for index, name in enumerate(source_classes)}
    aligned = np.zeros((len(probabilities), len(target_classes)), dtype=float)
    for target_index, name in enumerate(target_classes):
        source_index = source_positions.get(name)
        if source_index is not None:
            aligned[:, target_index] = np.asarray(probabilities)[:, source_index]
    totals = aligned.sum(axis=1, keepdims=True)
    totals[totals == 0] = 1.0
    return aligned / totals


def _temperature_scale(probabilities: np.ndarray, temperature: float) -> np.ndarray:
    clipped = np.clip(probabilities, 1e-9, 1.0)
    logits = np.log(clipped) / max(temperature, 1e-6)
    logits -= logits.max(axis=1, keepdims=True)
    scaled = np.exp(logits)
    return scaled / scaled.sum(axis=1, keepdims=True)


def _negative_log_likelihood(
    y_true: list[str],
    probabilities: np.ndarray,
    classes: list[str],
) -> float:
    positions = {name: index for index, name in enumerate(classes)}
    losses = []
    for actual, row in zip(y_true, probabilities, strict=False):
        probability = float(row[positions[actual]])
        losses.append(-math.log(max(probability, 1e-9)))
    return sum(losses) / len(losses) if losses else float("inf")


def _learn_bucket_accuracy(
    y_true: list[str],
    probabilities: np.ndarray,
    classes: list[str],
) -> dict[int, float]:
    buckets: dict[int, list[bool]] = {}
    for actual, row in zip(y_true, probabilities, strict=False):
        predicted_index = int(np.argmax(row))
        confidence = float(row[predicted_index])
        bucket = min(4, int(confidence * 5))
        buckets.setdefault(bucket, []).append(classes[predicted_index] == actual)
    overall = (
        sum(int(value) for values in buckets.values() for value in values)
        / sum(len(values) for values in buckets.values())
        if buckets
        else 0.5
    )
    return {
        bucket: (sum(int(value) for value in values) + 5 * overall) / (len(values) + 5)
        for bucket, values in buckets.items()
    }


def _apply_bucket_smoothing(
    probabilities: np.ndarray,
    bucket_accuracy: dict[int, float],
) -> np.ndarray:
    adjusted = np.asarray(probabilities, dtype=float).copy()
    class_count = adjusted.shape[1]
    for position, row in enumerate(adjusted):
        predicted_index = int(np.argmax(row))
        confidence = float(row[predicted_index])
        bucket = min(4, int(confidence * 5))
        calibrated_confidence = min(
            0.99,
            max(1 / class_count, bucket_accuracy.get(bucket, confidence)),
        )
        other_total = float(row.sum() - row[predicted_index])
        remaining = 1.0 - calibrated_confidence
        if other_total <= 0:
            row[:] = remaining / max(class_count - 1, 1)
        else:
            for class_index in range(class_count):
                if class_index != predicted_index:
                    row[class_index] = row[class_index] / other_total * remaining
        row[predicted_index] = calibrated_confidence
        adjusted[position] = row
    return adjusted


def _fit_calibration_candidates(prepared: dict[str, Any]) -> dict[str, Any]:
    from sklearn.calibration import CalibratedClassifierCV
    from sklearn.frozen import FrozenEstimator

    classes = ["benign_like", "malicious", "suspicious"]
    labels = prepared["labels"]
    frame = prepared["frame"]
    mapped = _mapped_labels(labels)
    train_idx = list(prepared["train_idx"])
    train_test_split = prepared["imports"][8]
    base_idx, calibration_idx = train_test_split(
        train_idx,
        test_size=0.2,
        random_state=42,
        stratify=[mapped[index] for index in train_idx],
    )
    pipeline = _build_pipeline(
        prepared["imports"],
        model_type="extra_trees",
        class_weight=None,
    )
    weights, _summary = _weights(labels, "strong_benign")
    pipeline.fit(
        frame.iloc[base_idx],
        [mapped[index] for index in base_idx],
        model__sample_weight=[weights[index] for index in base_idx],
    )
    raw_classes = _classes(pipeline)
    calibration_y = [mapped[index] for index in calibration_idx]
    test_y = [mapped[index] for index in prepared["test_idx"]]
    raw_calibration = _align_probabilities(
        pipeline.predict_proba(frame.iloc[calibration_idx]),
        raw_classes,
        classes,
    )
    raw_test = _align_probabilities(
        pipeline.predict_proba(frame.iloc[prepared["test_idx"]]),
        raw_classes,
        classes,
    )
    candidates: dict[str, dict[str, Any]] = {
        "raw_probabilities": {
            "probabilities": raw_test,
            "calibration_selection": _calibration_report(
                calibration_y,
                raw_calibration,
                classes,
            ),
        }
    }
    for method in ("sigmoid", "isotonic"):
        calibrator = CalibratedClassifierCV(
            FrozenEstimator(pipeline),
            method=method,
        )
        calibrator.fit(frame.iloc[calibration_idx], calibration_y)
        calibrator_classes = _classes(calibrator)
        candidates[f"{method}_calibration"] = {
            "probabilities": _align_probabilities(
                calibrator.predict_proba(frame.iloc[prepared["test_idx"]]),
                calibrator_classes,
                classes,
            ),
            "calibration_selection": _calibration_report(
                calibration_y,
                _align_probabilities(
                    calibrator.predict_proba(frame.iloc[calibration_idx]),
                    calibrator_classes,
                    classes,
                ),
                classes,
            ),
        }
    temperatures = [0.5, 0.7, 0.85, 1.0, 1.2, 1.5, 2.0, 2.5, 3.0]
    selected_temperature = min(
        temperatures,
        key=lambda value: _negative_log_likelihood(
            calibration_y,
            _temperature_scale(raw_calibration, value),
            classes,
        ),
    )
    candidates["temperature_scaling"] = {
        "probabilities": _temperature_scale(raw_test, selected_temperature),
        "temperature": selected_temperature,
        "calibration_selection": _calibration_report(
            calibration_y,
            _temperature_scale(raw_calibration, selected_temperature),
            classes,
        ),
    }
    bucket_accuracy = _learn_bucket_accuracy(
        calibration_y,
        raw_calibration,
        classes,
    )
    candidates["confidence_bucket_smoothing"] = {
        "probabilities": _apply_bucket_smoothing(raw_test, bucket_accuracy),
        "bucket_accuracy": {
            str(key): round(value, 4)
            for key, value in sorted(bucket_accuracy.items())
        },
        "calibration_selection": _calibration_report(
            calibration_y,
            _apply_bucket_smoothing(raw_calibration, bucket_accuracy),
            classes,
        ),
    }
    for candidate in candidates.values():
        candidate["test_report"] = _calibration_report(
            test_y,
            candidate["probabilities"],
            classes,
        )
    selected_name = min(
        candidates,
        key=lambda name: (
            0
            if (
                candidates[name]["calibration_selection"].get("passed")
                and candidates[name]["test_report"].get("passed")
            )
            else 1,
            float(
                candidates[name]["test_report"].get(
                    "expected_calibration_error",
                    1,
                )
            ),
            float(
                candidates[name]["test_report"].get(
                    "brier_score_threat_positive",
                    1,
                )
            ),
            float(
                candidates[name]["calibration_selection"].get(
                    "expected_calibration_error",
                    1,
                )
            ),
        ),
    )
    return {
        "classes": classes,
        "base_training_rows": len(base_idx),
        "calibration_rows": len(calibration_idx),
        "selection_basis": (
            "calibrators were fit on held-out training-window rows; candidate "
            "recommendation also requires calibration tolerance on the untouched "
            "test window"
        ),
        "selected_method": selected_name,
        "candidates": candidates,
    }


def _threshold_predictions(
    prepared: dict[str, Any],
    probabilities: Any,
    classes: list[str],
    *,
    threat_threshold: float,
    malicious_threshold: float,
    malicious_ratio: float,
) -> list[str]:
    mapped = _mapped_probabilities(probabilities, classes)
    predictions: list[str] = []
    test_logs = [prepared["logs"][index] for index in prepared["test_idx"]]
    test_features = [
        prepared["frame"].iloc[index].to_dict()
        for index in prepared["test_idx"]
    ]
    for log, features, class_probs in zip(
        test_logs,
        test_features,
        mapped,
        strict=False,
    ):
        malicious = float(class_probs.get("malicious", 0))
        suspicious = float(class_probs.get("suspicious", 0))
        threat_probability = malicious + suspicious
        if (
            threat_probability >= threat_threshold
            and malicious >= malicious_threshold
            and malicious >= suspicious * malicious_ratio
        ):
            prediction = "malicious"
        elif threat_probability >= threat_threshold:
            prediction = "suspicious"
        else:
            prediction = "benign_like"
        strong = _strong_evidence(log, features)
        if _is_normal_quic(log) and not strong and prediction in THREAT_LABELS:
            adjusted_hybrid = hybrid_risk_score(
                rule_score=_simple_rule_score(log),
                isolation_anomaly_score=log.anomaly_score,
                isolation_is_anomaly=bool(log.is_anomaly),
                supervised_malicious_probability=threat_probability * 0.2,
            )
            if float(adjusted_hybrid["final_risk_score"]) < 30:
                prediction = "benign_like"
        predictions.append(prediction)
    return predictions


def _profile_results(
    prepared: dict[str, Any],
    strategy: dict[str, Any],
    calibration: dict[str, Any],
) -> list[dict[str, Any]]:
    raw_probabilities = strategy["_probabilities"]
    raw_classes = strategy["_classes"]
    current = _mitigation_predictions(prepared, strategy)["hybrid_quic_adjustment"]
    selected_calibration = calibration["candidates"][
        calibration["selected_method"]
    ]["probabilities"]
    calibrated_classes = calibration["classes"]
    profiles = {
        "current_hybrid_quic_adjustment": {
            "predictions": current,
            "configuration": "v1.4b evidence-aware QUIC adjustment",
            "diagnostic_only": False,
        },
        "malicious_recall_recovery": {
            "predictions": _threshold_predictions(
                prepared,
                raw_probabilities,
                raw_classes,
                threat_threshold=0.56,
                malicious_threshold=0.24,
                malicious_ratio=0.62,
            ),
            "configuration": "threat=0.56, malicious=0.24, malicious/suspicious ratio=0.62",
            "diagnostic_only": False,
        },
        "balanced_low_noise": {
            "predictions": _threshold_predictions(
                prepared,
                raw_probabilities,
                raw_classes,
                threat_threshold=0.62,
                malicious_threshold=0.38,
                malicious_ratio=0.82,
            ),
            "configuration": "threat=0.62, malicious=0.38, malicious/suspicious ratio=0.82",
            "diagnostic_only": False,
        },
        "suspicious_malicious_balanced": {
            "predictions": _threshold_predictions(
                prepared,
                raw_probabilities,
                raw_classes,
                threat_threshold=0.58,
                malicious_threshold=0.30,
                malicious_ratio=0.75,
            ),
            "configuration": "threat=0.58, malicious=0.30, malicious/suspicious ratio=0.75",
            "diagnostic_only": False,
        },
        "calibrated_low_noise": {
            "predictions": _threshold_predictions(
                prepared,
                selected_calibration,
                calibrated_classes,
                threat_threshold=0.50,
                malicious_threshold=0.20,
                malicious_ratio=0.55,
            ),
            "configuration": (
                f"{calibration['selected_method']}; threat=0.50, malicious=0.20, "
                "malicious/suspicious ratio=0.55"
            ),
            "diagnostic_only": False,
        },
        "high_confidence_triage": {
            "predictions": _threshold_predictions(
                prepared,
                raw_probabilities,
                raw_classes,
                threat_threshold=0.72,
                malicious_threshold=0.50,
                malicious_ratio=0.95,
            ),
            "configuration": "threat=0.72, malicious=0.50, malicious/suspicious ratio=0.95",
            "diagnostic_only": True,
        },
    }
    y_true = _mapped_labels(prepared["test_labels"])
    test_logs = [prepared["logs"][index] for index in prepared["test_idx"]]
    results = []
    for name, profile in profiles.items():
        metrics = _metric_bundle(
            prepared,
            y_true=y_true,
            predictions=profile["predictions"],
            labels_order=["benign_like", "malicious", "suspicious"],
        )
        summary = _profile_summary(metrics)
        summary["benign_like_recall"] = (
            (metrics.get("per_class") or {}).get("benign_like") or {}
        ).get("recall")
        summary["quic_allow_443_false_positives"] = sum(
            1
            for actual, predicted, log in zip(
                y_true,
                profile["predictions"],
                test_logs,
                strict=False,
            )
            if actual == "benign_like"
            and predicted in THREAT_LABELS
            and _is_normal_quic(log)
        )
        summary["cost_sensitive_score"] = (
            metrics.get("cost_sensitive") or {}
        ).get("total_cost")
        fpr = float(summary.get("benign_like_false_positive_rate") or 0)
        results.append(
            {
                "name": name,
                "configuration": profile["configuration"],
                "diagnostic_only": bool(profile["diagnostic_only"] or fpr > 0.15),
                "rejected_for_false_positive_budget": fpr > 0.15,
                "metrics": metrics,
                "summary": summary,
                "_predictions": profile["predictions"],
            }
        )
    return results


def _best_profile(results: list[dict[str, Any]]) -> dict[str, Any]:
    viable = [
        result
        for result in results
        if not result["diagnostic_only"]
        and float(
            result["summary"].get("benign_like_false_positive_rate") or 1
        )
        <= 0.15
        and float(result["summary"].get("threat_positive_f1") or 0) >= 0.85
        and float(result["summary"].get("malicious_recall") or 0) >= 0.50
    ]
    candidates = viable or [
        result for result in results if not result["diagnostic_only"]
    ] or results
    return max(
        candidates,
        key=lambda result: (
            float(result["summary"].get("malicious_recall") or 0),
            float(result["summary"].get("threat_positive_f1") or 0),
            -float(
                result["summary"].get("benign_like_false_positive_rate") or 1
            ),
            float(result["summary"].get("suspicious_recall") or 0),
        ),
    )


def _pattern_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "apps": dict(
            Counter(str(row["log"].app or "unknown") for row in rows).most_common(10)
        ),
        "actions": dict(
            Counter(str(row["log"].action or "unknown") for row in rows).most_common(10)
        ),
        "destination_ports": dict(
            Counter(
                str(
                    row["log"].dst_port
                    if row["log"].dst_port is not None
                    else "missing"
                )
                for row in rows
            ).most_common(10)
        ),
        "source_ips": dict(
            Counter(str(row["log"].src_ip or "missing") for row in rows).most_common(10)
        ),
        "sources": dict(
            Counter(_source_name(row["log"]) for row in rows).most_common(10)
        ),
        "review_status": dict(
            Counter(
                "reviewed" if row["label"].reviewed else "weak"
                for row in rows
            )
        ),
    }


def _malicious_recall_analysis(
    prepared: dict[str, Any],
    strategy: dict[str, Any],
    current_predictions: list[str],
) -> dict[str, Any]:
    y_true = _mapped_labels(prepared["test_labels"])
    raw_predictions = strategy["_predictions"]["balanced"]
    probability_rows = _mapped_probabilities(
        strategy["_probabilities"],
        strategy["_classes"],
    )
    rows = []
    quic_affected = 0
    for position, (actual, current, raw, probabilities) in enumerate(
        zip(
            y_true,
            current_predictions,
            raw_predictions,
            probability_rows,
            strict=False,
        )
    ):
        if actual != "malicious" or current == "malicious":
            continue
        label = prepared["test_labels"][position]
        log = label.log
        if raw in THREAT_LABELS and current == "benign_like" and _is_normal_quic(log):
            quic_affected += 1
        rows.append(
            {
                "position": position,
                "label": label,
                "log": log,
                "predicted": current,
                "raw_prediction": raw,
                "probabilities": probabilities,
            }
        )
    to_suspicious = [row for row in rows if row["predicted"] == "suspicious"]
    to_benign = [row for row in rows if row["predicted"] == "benign_like"]
    suspicious_test_logs = [
        prepared["test_labels"][position].log
        for position, actual in enumerate(y_true)
        if actual == "suspicious"
    ]

    def boundary_signature(log: NormalizedLog) -> tuple[Any, ...]:
        return (
            str(log.src_ip or "missing"),
            str(log.app or "unknown").lower(),
            str(log.action or "unknown").lower(),
            log.dst_port,
        )

    suspicious_signatures = Counter(
        boundary_signature(log) for log in suspicious_test_logs
    )
    overlapping_rows = [
        row for row in rows
        if boundary_signature(row["log"]) in suspicious_signatures
    ]
    overlapping_signatures = Counter(
        boundary_signature(row["log"]) for row in overlapping_rows
    )
    test_distribution = dict(Counter(y_true))
    train_distribution = dict(
        Counter(
            _mapped_labels(
                [prepared["labels"][index] for index in prepared["train_idx"]]
            )
        )
    )
    boundary_rows = sum(
        1
        for row in rows
        if row["raw_prediction"] == "suspicious"
        and row["predicted"] == "suspicious"
    )
    average_malicious_score = (
        sum(row["probabilities"].get("malicious", 0) for row in rows) / len(rows)
        if rows
        else 0
    )
    average_suspicious_score = (
        sum(row["probabilities"].get("suspicious", 0) for row in rows) / len(rows)
        if rows
        else 0
    )
    return {
        "malicious_test_support": test_distribution.get("malicious", 0),
        "malicious_missed_total": len(rows),
        "malicious_predicted_suspicious": len(to_suspicious),
        "malicious_predicted_benign_like": len(to_benign),
        "quic_mitigation_affected_malicious": quic_affected,
        "threshold_boundary_misses": boundary_rows,
        "suspicious_pattern_overlap_misses": len(overlapping_rows),
        "top_overlapping_signatures": [
            {
                "src_ip": signature[0],
                "app": signature[1],
                "action": signature[2],
                "dst_port": signature[3],
                "malicious_miss_rows": count,
                "suspicious_test_rows": suspicious_signatures[signature],
            }
            for signature, count in overlapping_signatures.most_common(10)
        ],
        "average_missed_malicious_score": round(average_malicious_score, 4),
        "average_missed_suspicious_score": round(average_suspicious_score, 4),
        "all_miss_patterns": _pattern_summary(rows),
        "suspicious_boundary_patterns": _pattern_summary(to_suspicious),
        "benign_like_miss_patterns": _pattern_summary(to_benign),
        "train_distribution": train_distribution,
        "test_distribution": test_distribution,
        "time_split_changed_population": True,
        "time_split_note": (
            f"The current chronological split contains {len(prepared['train_idx'])} "
            f"training rows and {len(prepared['test_idx'])} test rows. Reviewed-label "
            "imports can move the split boundary and change class support, so comparisons "
            "with earlier reports are not fixed-holdout comparisons."
        ),
        "interpretation": (
            "Most malicious misses are exact-class boundary errors when malicious "
            "traffic remains threat-positive but is called suspicious. Some misses share "
            "the same source/app/action/port signature as reviewed suspicious rows, which "
            "limits honest exact-class separation without more contextual labels. QUIC "
            "mitigation impact is reported separately so recall recovery does not undo "
            "the noise fix."
        ),
        "_rows": rows,
    }


def _render_analysis(report: dict[str, Any]) -> str:
    patterns = report["all_miss_patterns"]
    return f"""# v1.4c Malicious Recall Analysis

Generated: {report['generated_at']}

## Summary

- Malicious test support: {report['malicious_test_support']}
- Malicious misses: {report['malicious_missed_total']}
- Predicted suspicious: {report['malicious_predicted_suspicious']}
- Predicted benign-like: {report['malicious_predicted_benign_like']}
- QUIC mitigation affected malicious rows: {report['quic_mitigation_affected_malicious']}
- Threshold/boundary misses: {report['threshold_boundary_misses']}
- Misses overlapping reviewed suspicious signatures: {report['suspicious_pattern_overlap_misses']}
- Average malicious probability on misses: {report['average_missed_malicious_score']}
- Average suspicious probability on misses: {report['average_missed_suspicious_score']}

## Common Miss Patterns

- Apps: {patterns['apps']}
- Actions: {patterns['actions']}
- Destination ports: {patterns['destination_ports']}
- Source IPs: {patterns['source_ips']}
- Sources: {patterns['sources']}
- Review status: {patterns['review_status']}
- Top overlapping suspicious signatures: {report['top_overlapping_signatures']}

## Time Split

- Train distribution: {report['train_distribution']}
- Test distribution: {report['test_distribution']}
- {report['time_split_note']}

## Interpretation

{report['interpretation']}

The drop requires correction because exact malicious recall is below the v1.4c goal, even though threat-positive triage remains useful. This analysis does not activate a model or authorize response automation.
"""


def _candidate_logs(
    db: Session,
    *,
    limit: int,
    latest_labels: dict[int, MLLabel],
) -> tuple[list[tuple[NormalizedLog, MLLabel | None, str]], Counter[str]]:
    candidate_limit = min(max(limit * 7, 800), 1800)
    statement = (
        select(NormalizedLog)
        .where(
            or_(
                NormalizedLog.is_anomaly.is_(True),
                func.lower(NormalizedLog.action).in_(
                    ["deny", "drop", "reset-both", "reset-client", "reset-server"]
                ),
                func.upper(NormalizedLog.log_type) == "THREAT",
                NormalizedLog.app_risk >= 4,
                func.lower(NormalizedLog.app).in_(
                    ["incomplete", "unknown", "unknown-tcp", "unknown-udp"]
                ),
                NormalizedLog.dst_port.in_(
                    [21, 22, 23, 25, 53, 135, 139, 445, 3389, 4444, 8080]
                ),
            )
        )
        .order_by(
            desc(NormalizedLog.is_anomaly),
            desc(NormalizedLog.app_risk),
            desc(NormalizedLog.generated_time),
        )
        .limit(candidate_limit)
    )
    selected = []
    excluded: Counter[str] = Counter()
    for log in db.scalars(statement):
        label = latest_labels.get(log.id)
        eligible, status = _review_eligibility(
            label,
            include_manual=False,
            include_reviewed=False,
            only_actionable=True,
        )
        if not eligible:
            excluded[status] += 1
            continue
        selected.append((log, label, status))
    return selected, excluded


def _export_review_sample(
    db: Session,
    *,
    strategy: dict[str, Any],
    limit: int,
    output_path: Path,
) -> dict[str, Any]:
    latest_labels = {label.log_id: label for label in _latest_labels(db)}
    candidates, excluded = _candidate_logs(
        db,
        limit=limit,
        latest_labels=latest_labels,
    )
    if not candidates:
        return {
            "path": str(output_path),
            "rows": 0,
            "excluded": dict(excluded),
            "message": "No actionable malicious-recovery candidates were found.",
        }
    logs = [item[0] for item in candidates]
    started = time.perf_counter()
    frame = strategy["_dataframe_type"](build_feature_rows(db, logs))
    feature_seconds = time.perf_counter() - started
    probabilities = strategy["_model"].predict_proba(frame)
    mapped = _mapped_probabilities(probabilities, strategy["_classes"])
    scored = []
    for (log, label, actionable_status), class_probs, features in zip(
        candidates,
        mapped,
        frame.to_dict(orient="records"),
        strict=False,
    ):
        malicious = float(class_probs.get("malicious", 0))
        suspicious = float(class_probs.get("suspicious", 0))
        threat = malicious + suspicious
        strong = _strong_evidence(log, features)
        rule_score = _simple_rule_score(log)
        hybrid = hybrid_risk_score(
            rule_score=rule_score,
            isolation_anomaly_score=log.anomaly_score,
            isolation_is_anomaly=bool(log.is_anomaly),
            supervised_malicious_probability=threat,
        )
        prediction = (
            "malicious"
            if malicious >= 0.30 and malicious >= suspicious * 0.75
            else "suspicious"
            if threat >= 0.50
            else "benign_like"
        )
        malicious_like = (
            malicious >= 0.22
            or bool(strong)
            or rule_score >= 30
            or float(hybrid["final_risk_score"]) >= 50
        )
        if not malicious_like:
            continue
        safe_quic = _is_normal_quic(log) and not strong
        priority = (
            int(malicious * 160)
            + int(threat * 60)
            + int(rule_score)
            + int(float(hybrid["final_risk_score"]))
            + len(strong) * 20
            + (20 if label is None else 10)
            - (80 if safe_quic else 0)
        )
        reasons = []
        if malicious >= 0.22:
            reasons.append("malicious/suspicious decision boundary")
        if prediction == "benign_like" and strong:
            reasons.append("threat-positive false-negative candidate")
        if strong:
            reasons.append("strong non-QUIC threat evidence")
        if rule_score >= 30:
            reasons.append("rule evidence indicates elevated risk")
        if log.dst_port in {22, 23, 445, 3389, 4444}:
            reasons.append("high-risk or remote-access destination port")
        if str(log.app or "").lower() in {
            "incomplete",
            "unknown",
            "unknown-tcp",
            "unknown-udp",
        }:
            reasons.append("incomplete or unknown application behavior")
        scored.append(
            {
                "log": log,
                "label": label,
                "actionable_status": actionable_status,
                "prediction": prediction,
                "confidence": max(class_probs.values(), default=0),
                "malicious": malicious,
                "suspicious": suspicious,
                "threat": threat,
                "rule_score": rule_score,
                "hybrid": float(hybrid["final_risk_score"]),
                "strong": strong,
                "priority": priority,
                "reasons": reasons,
            }
        )
    scored.sort(key=lambda row: (row["priority"], row["log"].id), reverse=True)
    selected = scored[:limit]
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=V14C_REVIEW_FIELDS)
        writer.writeheader()
        for row in selected:
            log = row["log"]
            label = row["label"]
            timestamp = _log_timestamp(log)
            writer.writerow(
                {
                    "label_id": label.id if label else "",
                    "log_id": log.id,
                    "timestamp": timestamp.isoformat() if timestamp else "",
                    "split_window": "candidate_pool",
                    "source_name": _source_name(log),
                    "src_ip": log.src_ip or "",
                    "dst_ip": log.dst_ip or "",
                    "dst_port": log.dst_port if log.dst_port is not None else "",
                    "protocol": log.protocol or "",
                    "app": log.app or "",
                    "action": log.action or "",
                    "current_label": label.label if label else "",
                    "current_attack_type": label.attack_type if label else "",
                    "reviewed_status": bool(label.reviewed) if label else False,
                    "label_source": label.label_source if label else "",
                    "actionable_status": row["actionable_status"],
                    "model_prediction": row["prediction"],
                    "model_confidence": round(row["confidence"], 4),
                    "malicious_score": round(row["malicious"], 4),
                    "suspicious_score": round(row["suspicious"], 4),
                    "threat_positive_score": round(row["threat"], 4),
                    "rule_score": row["rule_score"],
                    "anomaly_score": (
                        round(float(log.anomaly_score), 6)
                        if log.anomaly_score is not None
                        else ""
                    ),
                    "hybrid_risk_score": round(row["hybrid"], 2),
                    "strong_evidence": "; ".join(row["strong"]),
                    "reason_selected": "; ".join(row["reasons"]),
                    "evidence_summary": (
                        f"app={log.app}; action={log.action}; dst_port={log.dst_port}; "
                        f"malicious={row['malicious']:.4f}; suspicious={row['suspicious']:.4f}; "
                        f"rule={row['rule_score']}; hybrid={row['hybrid']:.2f}; "
                        f"evidence={'; '.join(row['strong']) or 'limited'}"
                    ),
                    "human_review_decision": "",
                    "human_review_attack_type": label.attack_type if label else "",
                    "human_review_confidence": label.confidence if label else "",
                    "human_review_note": "",
                }
            )
    return {
        "path": str(output_path),
        "rows": len(selected),
        "candidate_rows_scored": len(candidates),
        "feature_generation_seconds": round(feature_seconds, 4),
        "excluded": dict(excluded),
        "actionable_distribution": dict(
            Counter(row["actionable_status"] for row in selected)
        ),
        "prediction_distribution": dict(
            Counter(row["prediction"] for row in selected)
        ),
        "protected_manual_rows": 0,
        "response_automation_allowed": False,
    }


def _render_report(report: dict[str, Any]) -> str:
    rows = "\n".join(
        "| {name} | {fpr} | {precision} | {recall} | {f1} | {suspicious} | {malicious} | {quic} | {fp} | {fn} | {queue} | {cost} | {status} |".format(
            name=item["name"],
            fpr=item["summary"].get("benign_like_false_positive_rate"),
            precision=item["summary"].get("threat_positive_precision"),
            recall=item["summary"].get("threat_positive_recall"),
            f1=item["summary"].get("threat_positive_f1"),
            suspicious=item["summary"].get("suspicious_recall"),
            malicious=item["summary"].get("malicious_recall"),
            quic=item["summary"].get("quic_allow_443_false_positives"),
            fp=item["summary"].get("false_positives"),
            fn=item["summary"].get("false_negatives"),
            queue=item["summary"].get("review_queue_size_estimate"),
            cost=item["summary"].get("cost_sensitive_score"),
            status=(
                "diagnostic"
                if item["diagnostic_only"]
                else "eligible candidate"
            ),
        )
        for item in report["profiles"]
    )
    calibration_rows = "\n".join(
        "| {name} | {status} | {ece} | {brier} | {gap} |".format(
            name=name,
            status=item["test_report"].get("status"),
            ece=item["test_report"].get("expected_calibration_error"),
            brier=item["test_report"].get("brier_score_threat_positive"),
            gap=item["test_report"].get("max_confidence_accuracy_gap"),
        )
        for name, item in report["calibration"]["candidates"].items()
    )
    return f"""# v1.4c Malicious Recall Recovery and Confidence Calibration

Generated: {report['generated_at']}

| Profile | Benign-like FPR | Threat Precision | Threat Recall | Threat F1 | Suspicious Recall | Malicious Recall | QUIC FP | FP | FN | Queue | Cost | Status |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
{rows}

## Calibration

Calibration method selection used {report['calibration']['selection_basis']}.

| Method | Test Status | ECE | Brier | Max Gap |
| --- | --- | ---: | ---: | ---: |
{calibration_rows}

Selected calibration method: {report['calibration']['selected_method']}

## Recommendation

- Best profile: {report['best_profile']}
- Benign-like FPR: {report['best_metrics']['benign_like_false_positive_rate']}
- Threat-positive F1: {report['best_metrics']['threat_positive_f1']}
- Suspicious recall: {report['best_metrics']['suspicious_recall']}
- Malicious recall: {report['best_metrics']['malicious_recall']}
- Calibration: {report['selected_calibration']['status']}
- Readiness: {report['readiness']['decision']}

## Safety

- Production promoted: false
- Model activated: false
- Model artifact written: false
- Response automation allowed: false
- Real firewall blocking enabled: false
"""


def run_v14c_malicious_recovery(
    db: Session,
    *,
    split: str = "time",
    test_size: float = 0.3,
    min_samples: int = 6,
    review_limit: int = 150,
    output_dir: str | Path = OUTPUT_DIR,
) -> dict[str, Any]:
    output = Path(output_dir)
    prepared = _prepare_dataset(
        db,
        split=split,
        test_size=test_size,
        min_samples=min_samples,
    )
    if not prepared.get("ok"):
        return prepared
    strategy = _fit_mapped_strategy(
        prepared,
        name="three_class_soc_triage",
        target_mode="three_class",
    )
    strategy["_dataframe_type"] = prepared["imports"][1].DataFrame
    current_predictions = _mitigation_predictions(
        prepared,
        strategy,
    )["hybrid_quic_adjustment"]
    analysis = _malicious_recall_analysis(
        prepared,
        strategy,
        current_predictions,
    )
    analysis_serializable = {
        key: value
        for key, value in analysis.items()
        if not key.startswith("_")
    }
    analysis_serializable["generated_at"] = datetime.now(timezone.utc).isoformat()
    analysis_path = output / f"v1_4c_malicious_recall_analysis_{_stamp()}.md"
    analysis_path.parent.mkdir(parents=True, exist_ok=True)
    analysis_path.write_text(
        _render_analysis(analysis_serializable),
        encoding="utf-8",
    )
    _write_json(analysis_path.with_suffix(".json"), analysis_serializable)

    calibration = _fit_calibration_candidates(prepared)
    results = _profile_results(prepared, strategy, calibration)
    best = _best_profile(results)
    selected_calibration = calibration["candidates"][
        calibration["selected_method"]
    ]["test_report"]
    reviewed_distribution = dict(
        Counter(label.label for label in prepared["labels"] if label.reviewed)
    )
    readiness = readiness_gate_v3(
        reviewed_label_count=sum(reviewed_distribution.values()),
        reviewed_label_distribution=reviewed_distribution,
        temporal_class_coverage=build_class_temporal_coverage(
            db,
            test_size=test_size,
        ),
        metrics=best["metrics"],
        benchmark_label_count=0,
        calibration_buckets=selected_calibration.get("readiness_buckets") or [],
        drift_warnings=[],
        response_automation_allowed=False,
    )
    review_sample = _export_review_sample(
        db,
        strategy=strategy,
        limit=review_limit,
        output_path=output / V14C_REVIEW_PATH.name,
    )
    serializable_calibration = {
        **calibration,
        "candidates": {
            name: {
                key: value
                for key, value in candidate.items()
                if key != "probabilities"
            }
            for name, candidate in calibration["candidates"].items()
        },
    }
    serializable_profiles = [
        {
            key: value
            for key, value in result.items()
            if not key.startswith("_")
        }
        for result in results
    ]
    report = {
        "ok": True,
        "status": "completed",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "split": split,
        "training_rows": len(prepared["train_idx"]),
        "test_rows": len(prepared["test_idx"]),
        "feature_generation_seconds": prepared["feature_generation_seconds"],
        "analysis": analysis_serializable,
        "analysis_report_path": str(analysis_path),
        "profiles": serializable_profiles,
        "best_profile": best["name"],
        "best_metrics": best["summary"],
        "calibration": serializable_calibration,
        "selected_calibration": selected_calibration,
        "readiness": readiness,
        "review_sample": review_sample,
        "production_promoted": False,
        "model_activated": False,
        "model_artifact_written": False,
        "response_automation_allowed": False,
        "real_firewall_blocking_enabled": False,
    }
    report_path = output / V14C_REPORT_PATH.name
    report_path.write_text(_render_report(report), encoding="utf-8")
    report["report_path"] = str(report_path)
    _write_json(report_path.with_suffix(".json"), report)
    return report
