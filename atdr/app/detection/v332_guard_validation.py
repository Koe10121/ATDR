import csv
import json
import math
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from atdr.app.db.models import MLLabel, MLModelRun, NormalizedLog, ResponseAction
from atdr.app.detection.supervised_detector import (
    TRAINABLE_LABELS,
    _latest_labels,
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
    _log_timestamp,
    _source_name,
)
from atdr.app.detection.v331_noise_reduction import (
    V331_PROFILES,
    _apply_low_signal_benign_guard,
    _augment_frame,
    _build_pipeline_for_columns,
    _classes,
    _calibration_report,
    _metric_bundle,
    _probability_rows,
    _profile_summary,
)
from atdr.app.ml.features import CATEGORICAL_FEATURES, NUMERIC_FEATURES, build_feature_rows


V332_PROFILE = "threat_recall"
V332_STRATEGY = "flat_5class_extra_trees_current_with_low_signal_guard"
V332_OUTPUT_LATEST = "v3_32_guard_validation_latest.json"


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _label_distribution(labels: list[str]) -> dict[str, int]:
    return {label: labels.count(label) for label in sorted(set(labels))}


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        if value is None:
            return default
        return float(value)
    except (TypeError, ValueError):
        return default


def _random_split_indices(
    *,
    y: list[str],
    test_size: float,
    train_test_split,
    random_state: int,
) -> tuple[list[int], list[int], list[str], list[str], list[str]]:
    indices = list(range(len(y)))
    distribution = _label_distribution(y)
    estimated_test_rows = max(1, math.ceil(len(y) * test_size))
    stratify = y if min(distribution.values()) >= 2 and estimated_test_rows >= len(distribution) else None
    train_idx, test_idx, y_train, y_test = train_test_split(
        indices,
        y,
        test_size=test_size,
        random_state=random_state,
        stratify=stratify,
    )
    return list(train_idx), list(test_idx), list(y_train), list(y_test), [
        f"Random diagnostic split used seed {random_state}."
    ]


def _split_for_mode(
    *,
    logs: list[NormalizedLog],
    y: list[str],
    split_mode: str,
    test_size: float,
    train_test_split,
) -> tuple[list[int], list[int], list[str], list[str], list[str]]:
    if split_mode.startswith("random_seed_"):
        try:
            seed = int(split_mode.rsplit("_", 1)[-1])
        except ValueError:
            seed = 42
        return _random_split_indices(
            y=y,
            test_size=test_size,
            train_test_split=train_test_split,
            random_state=seed,
        )
    return _split_indices(
        logs=logs,
        y=y,
        split=split_mode,
        test_size=test_size,
        train_test_split=train_test_split,
    )


def _load_base_dataset(
    db: Session,
    *,
    min_samples: int,
) -> dict[str, Any]:
    imports = _optional_imports()
    if imports is None:
        return {"ok": False, "status": "skipped", "message": "Supervised ML dependencies are unavailable."}
    labels = [label for label in _latest_labels(db) if label.log is not None and label.label in TRAINABLE_LABELS]
    if len(labels) < min_samples or len({label.label for label in labels}) < 2:
        return {"ok": False, "status": "skipped", "message": "Not enough labeled rows for v3.32 validation."}
    pd = imports[1]
    train_test_split = imports[8]
    logs = [label.log for label in labels]
    y = [label.label for label in labels]
    started = time.perf_counter()
    frame = pd.DataFrame(build_feature_rows(db, logs))
    feature_seconds = time.perf_counter() - started
    return {
        "ok": True,
        "imports": imports,
        "labels": labels,
        "logs": logs,
        "y": y,
        "frame": frame,
        "feature_generation_seconds": round(feature_seconds, 4),
    }


def _prepared_for_split(
    base: dict[str, Any],
    *,
    split_mode: str,
    test_size: float,
) -> dict[str, Any]:
    train_test_split = base["imports"][8]
    logs = base["logs"]
    y = base["y"]
    train_idx, test_idx, y_train, y_test, split_warnings = _split_for_mode(
        logs=logs,
        y=y,
        split_mode=split_mode,
        test_size=test_size,
        train_test_split=train_test_split,
    )
    return {
        "ok": True,
        "imports": base["imports"],
        "labels": base["labels"],
        "logs": logs,
        "y": y,
        "frame": base["frame"],
        "train_idx": train_idx,
        "test_idx": test_idx,
        "y_train": y_train,
        "y_test": y_test,
        "test_labels": [base["labels"][index] for index in test_idx],
        "test_logs": [logs[index] for index in test_idx],
        "labels_order": sorted(set(y)),
        "split_mode": split_mode,
        "split_warnings": [*split_warnings, *_split_class_warnings(y_train, y_test)],
        "feature_generation_seconds": base["feature_generation_seconds"],
    }


def _load_dataset(
    db: Session,
    *,
    split_mode: str,
    test_size: float,
    min_samples: int,
) -> dict[str, Any]:
    base = _load_base_dataset(db, min_samples=min_samples)
    if not base.get("ok"):
        return base
    return _prepared_for_split(base, split_mode=split_mode, test_size=test_size)


def _profile_predictions(probability_rows: list[dict[str, float]], *, profile: str) -> list[str]:
    thresholds = V331_PROFILES[profile]
    predictions: list[str] = []
    for row in probability_rows:
        malicious = _safe_float(row.get("malicious"))
        suspicious = _safe_float(row.get("suspicious"))
        threat = malicious + suspicious
        if malicious >= thresholds["malicious"]:
            predictions.append("malicious")
        elif threat >= thresholds["threat_positive"]:
            predictions.append("malicious" if malicious > suspicious else "suspicious")
        elif _safe_float(row.get("needs_context")) >= thresholds["needs_context"]:
            predictions.append("needs_context")
        else:
            fallback = {
                "benign": _safe_float(row.get("benign")),
                "benign_unusual": _safe_float(row.get("benign_unusual")),
                "needs_context": _safe_float(row.get("needs_context")),
            }
            predictions.append(max(fallback.items(), key=lambda item: item[1])[0])
    return predictions


def _fit_candidate(
    prepared: dict[str, Any],
    augmented: dict[str, Any],
    *,
    calibration_method: str | None = None,
) -> dict[str, Any]:
    imports = prepared["imports"]
    frame = prepared["frame"]
    train_idx = prepared["train_idx"]
    test_idx = prepared["test_idx"]
    y_train = prepared["y_train"]
    pipeline = _build_pipeline_for_columns(
        imports,
        model_type="extra_trees",
        class_weight="balanced",
        numeric_features=list(NUMERIC_FEATURES),
        categorical_features=list(CATEGORICAL_FEATURES),
    )
    weights, weight_summary = _sample_weights(prepared["labels"])
    started = time.perf_counter()
    if calibration_method:
        from sklearn.calibration import CalibratedClassifierCV

        min_train_support = min(Counter(y_train).values(), default=0)
        if min_train_support < 3:
            return {
                "status": "skipped",
                "message": "Not enough per-class support for 3-fold calibration.",
                "calibration_method": calibration_method,
            }
        model = CalibratedClassifierCV(estimator=pipeline, method=calibration_method, cv=3)
        try:
            model.fit(frame.iloc[train_idx], y_train, sample_weight=[weights[index] for index in train_idx])
        except TypeError:
            model.fit(frame.iloc[train_idx], y_train)
    else:
        model = pipeline
        model.fit(frame.iloc[train_idx], y_train, model__sample_weight=[weights[index] for index in train_idx])
    probabilities = model.predict_proba(frame.iloc[test_idx])
    classes = _classes(model)
    rows = _probability_rows(probabilities, classes)
    unguarded_predictions = _profile_predictions(rows, profile=V332_PROFILE)
    guarded_predictions = _apply_low_signal_benign_guard(prepared, augmented, unguarded_predictions)
    metrics = _metric_bundle(
        prepared,
        y_true=prepared["y_test"],
        predictions=guarded_predictions,
        labels_order=prepared["labels_order"],
        threat_labels=set(THREAT_LABELS),
    )
    return {
        "status": "evaluated",
        "strategy": V332_STRATEGY,
        "profile": V332_PROFILE,
        "calibration_method": calibration_method or "none",
        "training_seconds": round(time.perf_counter() - started, 4),
        "sample_weighting": weight_summary,
        "metrics": metrics,
        "summary": _profile_summary(metrics),
        "calibration": _calibration_report(
            prepared["y_test"],
            probabilities,
            classes,
            threat_labels=set(THREAT_LABELS),
        ),
        "_classes": classes,
        "_probabilities": probabilities,
        "_probability_rows": rows,
        "_unguarded_predictions": unguarded_predictions,
        "_guarded_predictions": guarded_predictions,
    }


def _pattern_for_row(log: NormalizedLog) -> str:
    return f"app={log.app or '-'}|action={log.action or '-'}|port={log.dst_port or '-'}"


def _false_positive_patterns(
    prepared: dict[str, Any],
    augmented: dict[str, Any],
    predictions: list[str],
) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    frame = augmented["frame"]
    for position, (actual, predicted) in enumerate(zip(prepared["y_test"], predictions, strict=False)):
        if actual not in BENIGN_LIKE_LABELS or predicted not in THREAT_LABELS:
            continue
        index = prepared["test_idx"][position]
        log = prepared["test_logs"][position]
        label = prepared["test_labels"][position]
        row = frame.iloc[index]
        rows.append(
            {
                "label": label,
                "log": log,
                "actual": actual,
                "predicted": predicted,
                "pattern": _pattern_for_row(log),
                "source_name": _source_name(log),
                "quic_no_rule": bool(row.get("v331_quic_443_allow_no_rule_flag")),
                "quic_with_rule": bool(row.get("v331_quic_443_allow_with_rule_flag")),
                "incomplete_allow_80": bool(row.get("v331_incomplete_allow_80_flag")),
                "unknown_udp_scan_context": bool(row.get("v331_unknown_udp_scan_context_flag")),
                "app_risk_only": bool(row.get("v331_app_risk_only_flag")),
                "network_utility_no_rule": bool(row.get("v331_benign_network_utility_no_rule_flag")),
                "rule_codes": sorted(augmented["rule_code_rows"][index]),
            }
        )
    return {
        "false_positive_count": len(rows),
        "top_patterns": Counter(row["pattern"] for row in rows).most_common(12),
        "top_sources": Counter(row["source_name"] for row in rows).most_common(10),
        "top_apps": Counter(str(row["log"].app or "-") for row in rows).most_common(10),
        "top_ports": Counter(str(row["log"].dst_port or "-") for row in rows).most_common(10),
        "quic_443_no_rule_false_positives": sum(1 for row in rows if row["quic_no_rule"]),
        "quic_443_with_rule_false_positives": sum(1 for row in rows if row["quic_with_rule"]),
        "incomplete_allow_80_false_positives": sum(1 for row in rows if row["incomplete_allow_80"]),
        "unknown_udp_scan_context_false_positives": sum(1 for row in rows if row["unknown_udp_scan_context"]),
        "app_risk_only_false_positives": sum(1 for row in rows if row["app_risk_only"]),
        "network_utility_no_rule_false_positives": sum(1 for row in rows if row["network_utility_no_rule"]),
        "reviewed_vs_weak": dict(Counter("reviewed" if row["label"].reviewed else "weak" for row in rows)),
        "_rows": rows,
    }


def _guard_suppression_report(
    prepared: dict[str, Any],
    augmented: dict[str, Any],
    unguarded: list[str],
    guarded: list[str],
) -> dict[str, Any]:
    frame = augmented["frame"]
    rows: list[dict[str, Any]] = []
    for position, (actual, before, after) in enumerate(zip(prepared["y_test"], unguarded, guarded, strict=False)):
        if before not in THREAT_LABELS or after in THREAT_LABELS:
            continue
        index = prepared["test_idx"][position]
        row = frame.iloc[index]
        log = prepared["test_logs"][position]
        rows.append(
            {
                "actual": actual,
                "before": before,
                "after": after,
                "log": log,
                "pattern": _pattern_for_row(log),
                "rule_codes": sorted(augmented["rule_code_rows"][index]),
                "quic_no_rule": bool(row.get("v331_quic_443_allow_no_rule_flag")),
                "quic_with_rule": bool(row.get("v331_quic_443_allow_with_rule_flag")),
                "unknown_udp_scan_context": bool(row.get("v331_unknown_udp_scan_context_flag")),
                "app_risk_only": bool(row.get("v331_app_risk_only_flag")),
                "network_utility_no_rule": bool(row.get("v331_benign_network_utility_no_rule_flag")),
            }
        )
    actual_threat = [row for row in rows if row["actual"] in THREAT_LABELS]
    return {
        "suppressed_total": len(rows),
        "suppressed_actual_threat": len(actual_threat),
        "suppressed_actual_threat_examples": [
            {
                "actual": row["actual"],
                "before": row["before"],
                "after": row["after"],
                "pattern": row["pattern"],
                "rule_codes": row["rule_codes"],
                "source_name": _source_name(row["log"]),
            }
            for row in actual_threat[:20]
        ],
        "suppressed_rule_bearing_quic": sum(1 for row in rows if row["quic_with_rule"]),
        "suppressed_quic_no_rule_threat_rows": sum(
            1 for row in actual_threat if row["quic_no_rule"] and row["actual"] in THREAT_LABELS
        ),
        "suppressed_ping_no_rule_threat_rows": sum(
            1 for row in actual_threat if row["network_utility_no_rule"] and row["actual"] in THREAT_LABELS
        ),
        "suppressed_unknown_udp_scan_context": sum(1 for row in rows if row["unknown_udp_scan_context"]),
        "suppressed_app_risk_only": sum(1 for row in rows if row["app_risk_only"]),
        "top_suppressed_patterns": Counter(row["pattern"] for row in rows).most_common(10),
    }


def _threshold_sweep(
    prepared: dict[str, Any],
    augmented: dict[str, Any],
    probability_rows: list[dict[str, float]],
) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    threshold_values = [round(value / 100, 2) for value in range(30, 91, 5)]
    malicious_values = [0.24, 0.28, 0.35, 0.45, 0.6]
    for threat_threshold in threshold_values:
        for malicious_threshold in malicious_values:
            predictions: list[str] = []
            for row in probability_rows:
                malicious = _safe_float(row.get("malicious"))
                suspicious = _safe_float(row.get("suspicious"))
                threat = malicious + suspicious
                if malicious >= malicious_threshold:
                    predictions.append("malicious")
                elif threat >= threat_threshold:
                    predictions.append("malicious" if malicious > suspicious else "suspicious")
                elif _safe_float(row.get("needs_context")) >= 0.45:
                    predictions.append("needs_context")
                else:
                    fallback = {
                        "benign": _safe_float(row.get("benign")),
                        "benign_unusual": _safe_float(row.get("benign_unusual")),
                        "needs_context": _safe_float(row.get("needs_context")),
                    }
                    predictions.append(max(fallback.items(), key=lambda item: item[1])[0])
            guarded = _apply_low_signal_benign_guard(prepared, augmented, predictions)
            metrics = _metric_bundle(
                prepared,
                y_true=prepared["y_test"],
                predictions=guarded,
                labels_order=prepared["labels_order"],
                threat_labels=set(THREAT_LABELS),
            )
            summary = _profile_summary(metrics)
            candidates.append(
                {
                    "threat_positive_threshold": threat_threshold,
                    "malicious_threshold": malicious_threshold,
                    **summary,
                }
            )
    viable = [
        item
        for item in candidates
        if _safe_float(item.get("benign_like_false_positive_rate"), 1) <= 0.15
        and _safe_float(item.get("threat_positive_f1")) >= 0.85
        and _safe_float(item.get("suspicious_recall")) >= 0.8
        and _safe_float(item.get("malicious_recall")) >= 0.5
    ]
    ranked = viable or candidates
    ranked.sort(
        key=lambda item: (
            _safe_float(item.get("threat_positive_f1")) - 0.4 * _safe_float(item.get("benign_like_false_positive_rate"), 1),
            _safe_float(item.get("threat_positive_recall")),
            _safe_float(item.get("malicious_recall")),
        ),
        reverse=True,
    )
    return ranked[:12]


def _stability_summary(split_results: list[dict[str, Any]]) -> dict[str, Any]:
    evaluated = [item for item in split_results if item.get("status") == "evaluated"]
    metric_keys = [
        "threat_positive_precision",
        "threat_positive_recall",
        "threat_positive_f1",
        "benign_like_false_positive_rate",
        "suspicious_recall",
        "malicious_recall",
        "macro_f1",
        "weighted_f1",
    ]
    ranges: dict[str, Any] = {}
    for key in metric_keys:
        values = [_safe_float((item.get("summary") or {}).get(key), default=float("nan")) for item in evaluated]
        values = [value for value in values if not math.isnan(value)]
        if not values:
            ranges[key] = {"min": None, "max": None, "span": None}
            continue
        ranges[key] = {
            "min": round(min(values), 4),
            "max": round(max(values), 4),
            "span": round(max(values) - min(values), 4),
        }
    pass_count = 0
    blockers: list[str] = []
    for item in evaluated:
        summary = item.get("summary") or {}
        mode = item.get("split_mode")
        checks = {
            "benign-like FPR": _safe_float(summary.get("benign_like_false_positive_rate"), 1) <= 0.15,
            "threat-positive F1": _safe_float(summary.get("threat_positive_f1")) >= 0.85,
            "suspicious recall": _safe_float(summary.get("suspicious_recall")) >= 0.8,
            "malicious recall": _safe_float(summary.get("malicious_recall")) >= 0.5,
        }
        if all(checks.values()):
            pass_count += 1
        else:
            failed = ", ".join(name for name, passed in checks.items() if not passed)
            blockers.append(f"{mode}: {failed}")
    return {
        "evaluated_splits": len(evaluated),
        "passing_splits": pass_count,
        "passed": bool(evaluated) and pass_count == len(evaluated),
        "metric_ranges": ranges,
        "blockers": blockers,
    }


def _readiness(
    *,
    stability: dict[str, Any],
    calibration: dict[str, Any],
    guard_report: dict[str, Any],
) -> dict[str, Any]:
    checks = [
        {
            "name": "independent split stability acceptable",
            "passed": bool(stability.get("passed")),
            "value": f"{stability.get('passing_splits')}/{stability.get('evaluated_splits')}",
            "target": "all evaluated splits pass FPR/F1/recall gates",
        },
        {
            "name": "confidence calibration acceptable",
            "passed": bool(calibration.get("passed")),
            "value": calibration.get("status"),
            "target": "passed",
        },
        {
            "name": "low-signal guard does not suppress rule-bearing QUIC threats",
            "passed": int(guard_report.get("suppressed_rule_bearing_quic") or 0) == 0,
            "value": guard_report.get("suppressed_rule_bearing_quic"),
            "target": "0",
        },
        {
            "name": "low-signal guard does not suppress actual threats",
            "passed": int(guard_report.get("suppressed_actual_threat") or 0) == 0,
            "value": guard_report.get("suppressed_actual_threat"),
            "target": "0",
        },
        {
            "name": "model activation disabled",
            "passed": True,
            "value": False,
            "target": "required",
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
        "model_activated": False,
        "response_automation_allowed": False,
        "blockers": [item["name"] for item in checks if not item["passed"]],
        "checks": checks,
    }


def _aggregate_guard_safety(split_results: list[dict[str, Any]]) -> dict[str, Any]:
    safety_rows = [item.get("guard_safety") or {} for item in split_results if item.get("guard_safety")]
    top_patterns: Counter[str] = Counter()
    examples: list[dict[str, Any]] = []
    for safety in safety_rows:
        for pattern, count in safety.get("top_suppressed_patterns") or []:
            top_patterns[str(pattern)] += int(count)
        examples.extend(safety.get("suppressed_actual_threat_examples") or [])
    return {
        "evaluated_splits": len(safety_rows),
        "suppressed_total": sum(int(item.get("suppressed_total") or 0) for item in safety_rows),
        "suppressed_actual_threat": sum(int(item.get("suppressed_actual_threat") or 0) for item in safety_rows),
        "suppressed_actual_threat_examples": examples[:20],
        "suppressed_rule_bearing_quic": sum(int(item.get("suppressed_rule_bearing_quic") or 0) for item in safety_rows),
        "suppressed_quic_no_rule_threat_rows": sum(
            int(item.get("suppressed_quic_no_rule_threat_rows") or 0) for item in safety_rows
        ),
        "suppressed_ping_no_rule_threat_rows": sum(
            int(item.get("suppressed_ping_no_rule_threat_rows") or 0) for item in safety_rows
        ),
        "suppressed_unknown_udp_scan_context": sum(
            int(item.get("suppressed_unknown_udp_scan_context") or 0) for item in safety_rows
        ),
        "suppressed_app_risk_only": sum(int(item.get("suppressed_app_risk_only") or 0) for item in safety_rows),
        "top_suppressed_patterns": top_patterns.most_common(10),
    }


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
                    "reason_selected": "v3.32 residual false positive after low-signal guard validation",
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


def _strip_private(value: dict[str, Any]) -> dict[str, Any]:
    return {key: item for key, item in value.items() if not key.startswith("_")}


def _render_validation_report(result: dict[str, Any]) -> str:
    split_rows = []
    for split in result.get("split_results", []):
        summary = split.get("summary") or {}
        split_rows.append(
            "| {mode} | {status} | {train} / {test} | {precision} | {recall} | {f1} | {fpr} | {suspicious} | {malicious} | {macro} | {weighted} | {queue} |".format(
                mode=split.get("split_mode"),
                status=split.get("status"),
                train=split.get("training_rows"),
                test=split.get("test_rows"),
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
    return f"""# v3.32 Low-Signal Guard Independent Validation

Generated: {result.get("generated_at")}

This is diagnostic validation only. No active model artifact was written, no model was promoted, and response automation stayed disabled.

## Candidate Under Test

- Strategy: {V332_STRATEGY}
- Profile: {V332_PROFILE}
- Model activation: false
- Production promoted: false
- Response automation allowed: false

## Split Stability

| Split | Status | Train / Test | Threat Precision | Threat Recall | Threat F1 | Benign FPR | Suspicious Recall | Malicious Recall | Macro F1 | Weighted F1 | Queue |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
{chr(10).join(split_rows)}

```json
{json.dumps(result.get("stability"), indent=2, default=str)}
```

## Low-Signal Guard Safety

```json
{json.dumps(result.get("guard_safety"), indent=2, default=str)}
```

## Residual False Positives

```json
{json.dumps(result.get("residual_false_positive_patterns"), indent=2, default=str)}
```

## Readiness

- Decision: {result.get("readiness", {}).get("decision")}
- Checks passed: {result.get("readiness", {}).get("passed")} / {result.get("readiness", {}).get("total")}
- Blockers: {result.get("readiness", {}).get("blockers")}

## Safety

```json
{json.dumps(result.get("safety"), indent=2, default=str)}
```
"""


def _render_calibration_report(result: dict[str, Any]) -> str:
    experiment_rows = []
    for experiment in result.get("calibration_experiments", []):
        summary = experiment.get("summary") or {}
        calibration = experiment.get("calibration") or {}
        experiment_rows.append(
            "| {method} | {status} | {precision} | {recall} | {f1} | {fpr} | {brier} | {ece} | {gap} | {cal_status} |".format(
                method=experiment.get("calibration_method"),
                status=experiment.get("status"),
                precision=summary.get("threat_positive_precision"),
                recall=summary.get("threat_positive_recall"),
                f1=summary.get("threat_positive_f1"),
                fpr=summary.get("benign_like_false_positive_rate"),
                brier=calibration.get("brier_score_threat_positive"),
                ece=calibration.get("expected_calibration_error"),
                gap=calibration.get("max_confidence_accuracy_gap"),
                cal_status=calibration.get("status"),
            )
        )
    sweep_rows = []
    for row in result.get("calibrated_threshold_selection", [])[:10]:
        sweep_rows.append(
            "| {threat} | {malicious} | {precision} | {recall} | {f1} | {fpr} | {suspicious} | {malicious_recall} |".format(
                threat=row.get("threat_positive_threshold"),
                malicious=row.get("malicious_threshold"),
                precision=row.get("threat_positive_precision"),
                recall=row.get("threat_positive_recall"),
                f1=row.get("threat_positive_f1"),
                fpr=row.get("benign_like_false_positive_rate"),
                suspicious=row.get("suspicious_recall"),
                malicious_recall=row.get("malicious_recall"),
            )
        )
    return f"""# v3.32 Calibration Report

Generated: {result.get("generated_at")}

Calibration is evaluated for confidence trustworthiness only. No model was activated or promoted.

## Calibration Experiments

| Method | Status | Threat Precision | Threat Recall | Threat F1 | Benign FPR | Brier | ECE | Max Gap | Calibration Status |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
{chr(10).join(experiment_rows)}

## Best Calibration

```json
{json.dumps(result.get("best_calibration"), indent=2, default=str)}
```

## Threshold Sweep

| Threat Threshold | Malicious Threshold | Threat Precision | Threat Recall | Threat F1 | Benign FPR | Suspicious Recall | Malicious Recall |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
{chr(10).join(sweep_rows)}

## Confidence Buckets

```json
{json.dumps((result.get("best_calibration") or {}).get("buckets", []), indent=2, default=str)}
```
"""


def run_v332_guard_validation(
    db: Session,
    *,
    test_size: float = 0.3,
    min_samples: int = 6,
    review_limit: int = 100,
    output_dir: str | Path = OUTPUT_DIR,
) -> dict[str, Any]:
    before_runs = int(db.scalar(select(func.count(MLModelRun.id))) or 0)
    before_responses = int(db.scalar(select(func.count(ResponseAction.id))) or 0)
    split_modes = ["time", "grouped_stratified", "random_seed_7", "random_seed_17", "random_seed_42"]
    split_results: list[dict[str, Any]] = []
    first_evaluated: tuple[dict[str, Any], dict[str, Any], dict[str, Any]] | None = None
    base = _load_base_dataset(db, min_samples=min_samples)
    if not base.get("ok"):
        return base
    for split_mode in split_modes:
        prepared = _prepared_for_split(base, split_mode=split_mode, test_size=test_size)
        if not prepared.get("ok"):
            split_results.append({"split_mode": split_mode, "status": prepared.get("status"), "message": prepared.get("message")})
            continue
        augmented_frame, augmented_meta = _augment_frame(prepared)
        augmented = {"frame": augmented_frame, **augmented_meta}
        candidate = _fit_candidate(prepared, augmented)
        if candidate.get("status") != "evaluated":
            split_results.append(
                {"split_mode": split_mode, "status": candidate.get("status"), "message": candidate.get("message")}
            )
            continue
        false_positive_patterns = _false_positive_patterns(
            prepared,
            augmented,
            candidate["_guarded_predictions"],
        )
        guard_safety = _guard_suppression_report(
            prepared,
            augmented,
            candidate["_unguarded_predictions"],
            candidate["_guarded_predictions"],
        )
        split_results.append(
            {
                "split_mode": split_mode,
                "status": "evaluated",
                "training_rows": len(prepared["train_idx"]),
                "test_rows": len(prepared["test_idx"]),
                "split_warnings": prepared["split_warnings"],
                "feature_generation_seconds": prepared["feature_generation_seconds"],
                "training_seconds": candidate["training_seconds"],
                "summary": candidate["summary"],
                "calibration": candidate["calibration"],
                "false_positive_patterns": _strip_private(false_positive_patterns),
                "guard_safety": guard_safety,
            }
        )
        if first_evaluated is None:
            first_evaluated = (prepared, augmented, candidate)
    if first_evaluated is None:
        return {"ok": False, "status": "failed", "message": "No v3.32 validation split could be evaluated."}

    prepared, augmented, candidate = first_evaluated
    calibration_experiments: list[dict[str, Any]] = []
    for method in (None, "sigmoid", "isotonic"):
        experiment = _fit_candidate(prepared, augmented, calibration_method=method)
        if experiment.get("status") == "evaluated":
            calibration_experiments.append(
                {
                    "status": "evaluated",
                    "calibration_method": experiment["calibration_method"],
                    "summary": experiment["summary"],
                    "calibration": experiment["calibration"],
                    "training_seconds": experiment["training_seconds"],
                }
            )
        else:
            calibration_experiments.append(
                {
                    "status": experiment.get("status"),
                    "calibration_method": method or "none",
                    "message": experiment.get("message"),
                }
            )
    evaluated_calibrations = [item for item in calibration_experiments if item.get("status") == "evaluated"]
    best_calibration = max(
        evaluated_calibrations,
        key=lambda item: (
            1 if (item.get("calibration") or {}).get("passed") else 0,
            -_safe_float((item.get("calibration") or {}).get("expected_calibration_error"), 1),
            -_safe_float((item.get("calibration") or {}).get("max_confidence_accuracy_gap"), 1),
            _safe_float((item.get("summary") or {}).get("threat_positive_f1")),
        ),
        default={},
    )
    threshold_selection = _threshold_sweep(prepared, augmented, candidate["_probability_rows"])
    stability = _stability_summary(split_results)
    time_guard_safety = (split_results[0].get("guard_safety") if split_results else {}) or {}
    aggregate_guard_safety = _aggregate_guard_safety(split_results)
    readiness = _readiness(
        stability=stability,
        calibration=best_calibration.get("calibration") or {},
        guard_report=aggregate_guard_safety,
    )
    primary_patterns = (split_results[0].get("false_positive_patterns") if split_results else {}) or {}
    review_sample = {"generated": False, "path": "", "rows": 0, "candidate_rows": 0, "import_ready": False}
    residual_rows = _false_positive_patterns(prepared, augmented, candidate["_guarded_predictions"]).get("_rows") or []
    if residual_rows:
        review_sample = _write_residual_review_sample(
            residual_rows,
            output_path=Path(output_dir) / "v3_32_residual_error_review_sample.csv",
            limit=review_limit,
        )

    output_path = Path(output_dir)
    stamp = _stamp()
    validation_report_path = output_path / f"v3_32_low_signal_guard_validation_{stamp}.md"
    calibration_report_path = output_path / f"v3_32_calibration_report_{stamp}.md"
    summary_path = output_path / f"v3_32_guard_validation_{stamp}.json"
    latest_path = output_path / V332_OUTPUT_LATEST
    label_count = int(db.scalar(select(func.count(MLLabel.id))) or 0)
    result: dict[str, Any] = {
        "ok": True,
        "status": "completed",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "strategy": V332_STRATEGY,
        "profile": V332_PROFILE,
        "test_size": test_size,
        "total_label_rows": label_count,
        "latest_trainable_rows": len(prepared["labels"]),
        "reviewed_labels": sum(1 for label in prepared["labels"] if label.reviewed),
        "split_results": split_results,
        "stability": stability,
        "calibration_experiments": calibration_experiments,
        "best_calibration": best_calibration.get("calibration") or {},
        "best_calibration_method": best_calibration.get("calibration_method"),
        "calibrated_threshold_selection": threshold_selection,
        "guard_safety": aggregate_guard_safety,
        "time_split_guard_safety": time_guard_safety,
        "residual_false_positive_patterns": primary_patterns,
        "review_sample": review_sample,
        "readiness": readiness,
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
    validation_report_path.write_text(_render_validation_report(result), encoding="utf-8")
    calibration_report_path.write_text(_render_calibration_report(result), encoding="utf-8")
    summary = {key: value for key, value in result.items() if key != "training_dataset_diagnostics"}
    summary["validation_report_path"] = str(validation_report_path)
    summary["calibration_report_path"] = str(calibration_report_path)
    summary["summary_path"] = str(summary_path)
    summary["latest_summary_path"] = str(latest_path)
    summary_path.write_text(json.dumps(summary, indent=2, default=str), encoding="utf-8")
    latest_path.write_text(json.dumps(summary, indent=2, default=str), encoding="utf-8")
    result["validation_report_path"] = str(validation_report_path)
    result["calibration_report_path"] = str(calibration_report_path)
    result["summary_path"] = str(summary_path)
    result["latest_summary_path"] = str(latest_path)
    return result
