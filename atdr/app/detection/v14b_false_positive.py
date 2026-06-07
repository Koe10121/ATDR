import csv
import json
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import desc, func, or_, select
from sqlalchemy.orm import Session

from atdr.app.benchmarks.readiness import readiness_gate_v3
from atdr.app.db.models import MLLabel, NormalizedLog
from atdr.app.detection.hybrid_scoring import hybrid_risk_score
from atdr.app.detection.supervised_detector import _latest_labels
from atdr.app.detection.v14_false_positive import (
    BENIGN_LIKE_LABELS,
    OUTPUT_DIR,
    THREAT_LABELS,
    _calibration_report,
    _fit_mapped_strategy,
    _metric_bundle,
    _prepare_dataset,
    _profile_predictions,
    _profile_summary,
)
from atdr.app.ml.features import build_feature_rows
from atdr.app.services.active_learning_service import _simple_rule_score
from atdr.app.services.class_temporal_coverage_service import (
    build_class_temporal_coverage,
)


V14B_REVIEW_PATH = OUTPUT_DIR / "v1_4b_actionable_false_positive_review_sample.csv"
V14B_REVIEW_FIELDS = [
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


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")


def _log_timestamp(log: NormalizedLog) -> datetime | None:
    return log.generated_time or log.receive_time or log.start_time


def _source_name(log: NormalizedLog) -> str:
    source = getattr(getattr(log, "raw_log", None), "source", None)
    return str(source.name if source else "unknown_source")


def _is_normal_quic(log: NormalizedLog) -> bool:
    return (
        str(log.app or "").lower() == "quic-base"
        and str(log.action or "").lower() == "allow"
        and log.dst_port == 443
    )


def _strong_evidence(log: NormalizedLog, features: dict[str, Any]) -> list[str]:
    reasons: list[str] = []
    action = str(log.action or "").lower()
    if any(token in action for token in ("deny", "drop", "reset")):
        reasons.append(f"action={action}")
    if str(log.log_type or "").upper() == "THREAT":
        reasons.append("firewall threat log")
    if int(log.app_risk or 0) >= 4:
        reasons.append(f"app_risk={log.app_risk}")
    if bool(log.is_anomaly) and (
        log.anomaly_score is None or abs(float(log.anomaly_score)) >= 0.05
    ):
        reasons.append("strong anomaly evidence")
    unique_ports = int(features.get("src_ip_15min_unique_dst_ports") or 0)
    unique_ips = int(features.get("src_ip_15min_unique_dst_ips") or 0)
    deny_count = int(features.get("src_ip_5min_deny_count") or 0)
    external_to_internal = int(features.get("external_to_internal_flag") or 0)
    if (
        int(features.get("scanning_like_behavior_score") or 0) >= 60
        and (unique_ports >= 5 or deny_count >= 3 or external_to_internal)
    ):
        reasons.append("scanning-like behavior")
    if unique_ports >= 10:
        reasons.append("many destination ports")
    if external_to_internal and unique_ips >= 15:
        reasons.append("external-to-internal destination sweep")
    if (
        int(features.get("external_to_internal_flag") or 0)
        and int(features.get("repeated_connection_attempts") or 0) >= 5
    ):
        reasons.append("repeated external-to-internal attempts")
    if deny_count >= 5:
        reasons.append("repeated denied traffic")
    if int(log.bytes_sent or 0) >= 20_000_000:
        reasons.append("high outbound bytes")
    return reasons


def _review_eligibility(
    label: MLLabel | None,
    *,
    include_manual: bool,
    include_reviewed: bool,
    only_actionable: bool,
) -> tuple[bool, str]:
    if label is None:
        return True, "unlabeled"
    source = str(label.label_source or "manual")
    if source == "manual":
        if include_manual:
            return True, "protected_manual_explicitly_included"
        return False, "protected_manual"
    if bool(label.reviewed):
        if include_reviewed:
            return True, "reviewed_non_manual_requires_correction_mode"
        return False, "protected_reviewed"
    if source.startswith("assisted"):
        return True, "unreviewed_assisted"
    return (not only_actionable, "non_manual_label")


def _mapped_probabilities(
    probabilities: Any,
    classes: list[str],
) -> list[dict[str, float]]:
    return [
        {
            label: float(value)
            for label, value in zip(classes, row, strict=False)
        }
        for row in probabilities
    ]


def _single_three_class_decision(
    probabilities: dict[str, float],
    *,
    profile: str,
) -> str:
    classes = list(probabilities)
    row = [[probabilities[label] for label in classes]]
    return _profile_predictions(
        row,
        classes,
        mapped_mode="three_class",
    )[profile][0]


def _mitigation_predictions(
    prepared: dict[str, Any],
    strategy: dict[str, Any],
) -> dict[str, list[str]]:
    probabilities = _mapped_probabilities(
        strategy["_probabilities"],
        strategy["_classes"],
    )
    test_logs = [prepared["logs"][index] for index in prepared["test_idx"]]
    test_features = [
        prepared["frame"].iloc[index].to_dict()
        for index in prepared["test_idx"]
    ]
    current_balanced = list(strategy["_predictions"]["balanced"])
    low_noise = list(strategy["_predictions"]["low_noise_soc_queue"])
    benign_prior: list[str] = []
    hybrid_adjusted: list[str] = []
    stronger_threshold: list[str] = []

    for log, features, class_probs, current in zip(
        test_logs,
        test_features,
        probabilities,
        current_balanced,
        strict=False,
    ):
        strong = _strong_evidence(log, features)
        safe_quic = _is_normal_quic(log) and not strong
        threat_probability = sum(class_probs.get(label, 0) for label in THREAT_LABELS)

        prior_probs = dict(class_probs)
        if safe_quic:
            for label in THREAT_LABELS:
                prior_probs[label] = prior_probs.get(label, 0) * 0.2
            total = sum(prior_probs.values()) or 1.0
            prior_probs = {label: value / total for label, value in prior_probs.items()}
        benign_prior.append(
            _single_three_class_decision(prior_probs, profile="balanced")
        )

        adjusted_prediction = current
        if safe_quic and current in THREAT_LABELS:
            adjusted_hybrid = hybrid_risk_score(
                rule_score=_simple_rule_score(log),
                isolation_anomaly_score=log.anomaly_score,
                isolation_is_anomaly=bool(log.is_anomaly),
                supervised_malicious_probability=threat_probability * 0.2,
            )
            if float(adjusted_hybrid["final_risk_score"]) < 30:
                adjusted_prediction = "benign_like"
        hybrid_adjusted.append(adjusted_prediction)

        stronger_prediction = current
        if safe_quic and current in THREAT_LABELS and threat_probability < 0.9:
            stronger_prediction = "benign_like"
        stronger_threshold.append(stronger_prediction)

    return {
        "current_v1_4_balanced": current_balanced,
        "low_noise_profile": low_noise,
        "three_class_quic_benign_prior": benign_prior,
        "hybrid_quic_adjustment": hybrid_adjusted,
        "quic_stronger_evidence_threshold": stronger_threshold,
    }


def _strategy_metrics(
    prepared: dict[str, Any],
    predictions_by_strategy: dict[str, list[str]],
) -> list[dict[str, Any]]:
    y_true = [
        value if value in THREAT_LABELS else "benign_like"
        for value in prepared["y_test"]
    ]
    test_logs = [prepared["logs"][index] for index in prepared["test_idx"]]
    results: list[dict[str, Any]] = []
    for name, predictions in predictions_by_strategy.items():
        metrics = _metric_bundle(
            prepared,
            y_true=y_true,
            predictions=predictions,
            labels_order=["benign_like", "malicious", "suspicious"],
        )
        quic_false_positives = sum(
            1
            for actual, predicted, log in zip(
                y_true,
                predictions,
                test_logs,
                strict=False,
            )
            if actual == "benign_like"
            and predicted in THREAT_LABELS
            and _is_normal_quic(log)
        )
        summary = _profile_summary(metrics)
        summary["benign_like_recall"] = (
            (metrics.get("per_class") or {}).get("benign_like") or {}
        ).get("recall")
        summary["quic_allow_443_false_positives"] = quic_false_positives
        results.append(
            {
                "name": name,
                "metrics": metrics,
                "summary": summary,
            }
        )
    return results


def _best_mitigation(results: list[dict[str, Any]]) -> dict[str, Any]:
    viable = [
        result
        for result in results
        if float(result["summary"].get("threat_positive_recall") or 0) >= 0.8
        and float(result["summary"].get("malicious_recall") or 0) >= 0.5
    ]
    candidates = viable or results
    return max(
        candidates,
        key=lambda result: (
            float(result["summary"].get("threat_positive_f1") or 0)
            - 0.65
            * float(
                result["summary"].get("benign_like_false_positive_rate")
                if result["summary"].get("benign_like_false_positive_rate")
                is not None
                else 1
            ),
            float(result["summary"].get("suspicious_recall") or 0),
        ),
    )


def _candidate_logs(
    db: Session,
    *,
    limit: int,
    latest_labels: dict[int, MLLabel],
    include_manual: bool,
    include_reviewed: bool,
    only_actionable: bool,
) -> tuple[list[tuple[NormalizedLog, MLLabel | None, str]], Counter[str]]:
    candidate_limit = min(max(limit * 5, 600), 1600)
    queries = [
        select(NormalizedLog)
        .where(
            func.lower(NormalizedLog.app) == "quic-base",
            func.lower(NormalizedLog.action) == "allow",
            NormalizedLog.dst_port == 443,
        )
        .order_by(desc(NormalizedLog.is_anomaly), desc(NormalizedLog.generated_time))
        .limit(candidate_limit),
        select(NormalizedLog)
        .where(
            or_(
                NormalizedLog.is_anomaly.is_(True),
                NormalizedLog.app.in_(
                    ["incomplete", "unknown", "unknown-tcp", "unknown-udp"]
                ),
            )
        )
        .order_by(desc(NormalizedLog.generated_time))
        .limit(max(limit * 2, 300)),
        select(NormalizedLog)
        .where(
            func.lower(NormalizedLog.app) == "incomplete",
            func.lower(NormalizedLog.action) == "allow",
            NormalizedLog.dst_port == 80,
        )
        .order_by(desc(NormalizedLog.generated_time))
        .limit(max(limit, 200)),
    ]
    selected: list[tuple[NormalizedLog, MLLabel | None, str]] = []
    excluded: Counter[str] = Counter()
    seen: set[int] = set()
    for statement in queries:
        for log in db.scalars(statement):
            if log.id in seen:
                continue
            seen.add(log.id)
            label = latest_labels.get(log.id)
            eligible, status = _review_eligibility(
                label,
                include_manual=include_manual,
                include_reviewed=include_reviewed,
                only_actionable=only_actionable,
            )
            if not eligible:
                excluded[status] += 1
                continue
            selected.append((log, label, status))
            if len(selected) >= candidate_limit:
                return selected, excluded
    return selected, excluded


def export_v14b_actionable_review_sample(
    db: Session,
    *,
    prepared: dict[str, Any],
    strategy: dict[str, Any],
    limit: int = 200,
    output_path: str | Path = V14B_REVIEW_PATH,
    include_manual: bool = False,
    include_reviewed: bool = False,
    only_actionable: bool = True,
) -> dict[str, Any]:
    latest_labels = {label.log_id: label for label in _latest_labels(db)}
    candidates, excluded = _candidate_logs(
        db,
        limit=limit,
        latest_labels=latest_labels,
        include_manual=include_manual,
        include_reviewed=include_reviewed,
        only_actionable=only_actionable,
    )
    if not candidates:
        return {
            "path": str(output_path),
            "rows": 0,
            "excluded": dict(excluded),
            "message": "No actionable candidate rows were found.",
        }
    logs = [item[0] for item in candidates]
    feature_started = time.perf_counter()
    frame = prepared["imports"][1].DataFrame(build_feature_rows(db, logs))
    feature_seconds = time.perf_counter() - feature_started
    probabilities = strategy["_model"].predict_proba(frame)
    classes = strategy["_classes"]
    predictions = _profile_predictions(
        probabilities,
        classes,
        mapped_mode="three_class",
    )["balanced"]
    scored: list[dict[str, Any]] = []
    for position, (log, label, actionable_status) in enumerate(candidates):
        class_probs = {
            name: float(value)
            for name, value in zip(classes, probabilities[position], strict=False)
        }
        threat_probability = sum(
            class_probs.get(name, 0) for name in THREAT_LABELS
        )
        prediction = predictions[position]
        features = frame.iloc[position].to_dict()
        strong = _strong_evidence(log, features)
        rule_score = _simple_rule_score(log)
        hybrid = hybrid_risk_score(
            rule_score=rule_score,
            isolation_anomaly_score=log.anomaly_score,
            isolation_is_anomaly=bool(log.is_anomaly),
            supervised_malicious_probability=threat_probability,
        )
        boundary = 1 - abs(threat_probability - 0.58)
        priority = (
            (50 if _is_normal_quic(log) else 0)
            + (35 if label is None else 15)
            + int(threat_probability * 100)
            + (20 if prediction in THREAT_LABELS else 0)
            + int(max(0, boundary) * 20)
            + (10 if log.is_anomaly else 0)
        )
        if prediction not in THREAT_LABELS and threat_probability < 0.45:
            continue
        scored.append(
            {
                "log": log,
                "label": label,
                "actionable_status": actionable_status,
                "prediction": prediction,
                "confidence": max(class_probs.values(), default=0),
                "threat_probability": threat_probability,
                "rule_score": rule_score,
                "hybrid_score": hybrid["final_risk_score"],
                "strong_evidence": strong,
                "priority": priority,
            }
        )
    scored.sort(key=lambda row: (row["priority"], row["log"].id), reverse=True)
    selected = scored[:limit]
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=V14B_REVIEW_FIELDS)
        writer.writeheader()
        for row in selected:
            log = row["log"]
            label = row["label"]
            timestamp = _log_timestamp(log)
            reasons = []
            if _is_normal_quic(log):
                reasons.append("normal QUIC/443 false-positive pattern")
            if label is None:
                reasons.append("unlabeled row")
            elif not label.reviewed:
                reasons.append("unreviewed assisted label")
            if row["prediction"] in THREAT_LABELS:
                reasons.append(f"model predicted {row['prediction']}")
            if row["threat_probability"] >= 0.7:
                reasons.append("high threat-positive confidence")
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
                    "threat_positive_score": round(row["threat_probability"], 4),
                    "rule_score": row["rule_score"],
                    "anomaly_score": (
                        round(float(log.anomaly_score), 6)
                        if log.anomaly_score is not None
                        else ""
                    ),
                    "hybrid_risk_score": row["hybrid_score"],
                    "strong_evidence": "; ".join(row["strong_evidence"]),
                    "reason_selected": "; ".join(reasons),
                    "evidence_summary": (
                        f"app={log.app}; action={log.action}; dst_port={log.dst_port}; "
                        f"threat_score={row['threat_probability']:.4f}; "
                        f"strong_evidence={'; '.join(row['strong_evidence']) or 'none'}"
                    ),
                    "human_review_decision": "",
                    "human_review_attack_type": label.attack_type if label else "",
                    "human_review_confidence": label.confidence if label else "",
                    "human_review_note": "",
                }
            )
    return {
        "path": str(path),
        "rows": len(selected),
        "candidate_rows_scored": len(candidates),
        "feature_generation_seconds": round(feature_seconds, 4),
        "excluded": dict(excluded),
        "include_manual": include_manual,
        "include_reviewed": include_reviewed,
        "only_actionable": only_actionable,
        "actionable_distribution": dict(
            Counter(row["actionable_status"] for row in selected)
        ),
        "prediction_distribution": dict(
            Counter(row["prediction"] for row in selected)
        ),
        "pattern_distribution": {
            "quic_base_allow_443": sum(
                1 for row in selected if _is_normal_quic(row["log"])
            ),
            "incomplete_allow_80": sum(
                1
                for row in selected
                if str(row["log"].app or "").lower() == "incomplete"
                and str(row["log"].action or "").lower() == "allow"
                and row["log"].dst_port == 80
            ),
        },
        "protected_manual_rows": sum(
            1
            for row in selected
            if row["label"] is not None
            and str(row["label"].label_source or "manual") == "manual"
        ),
        "response_automation_allowed": False,
    }


def _render_mitigation_report(report: dict[str, Any]) -> str:
    rows = "\n".join(
        "| {name} | {precision} | {recall} | {f1} | {fpr} | {benign} | {suspicious} | {malicious} | {quic_fp} | {fp} | {fn} | {queue} |".format(
            name=item["name"],
            precision=item["summary"].get("threat_positive_precision"),
            recall=item["summary"].get("threat_positive_recall"),
            f1=item["summary"].get("threat_positive_f1"),
            fpr=item["summary"].get("benign_like_false_positive_rate"),
            benign=item["summary"].get("benign_like_recall"),
            suspicious=item["summary"].get("suspicious_recall"),
            malicious=item["summary"].get("malicious_recall"),
            quic_fp=item["summary"].get("quic_allow_443_false_positives"),
            fp=item["summary"].get("false_positives"),
            fn=item["summary"].get("false_negatives"),
            queue=item["summary"].get("review_queue_size_estimate"),
        )
        for item in report["strategies"]
    )
    return f"""# v1.4b QUIC False Positive Mitigation

Generated: {report['generated_at']}

## Confirmed Pattern

- QUIC/allow/443 false positives in the current balanced test result: {report['analysis']['quic_false_positive_count']}
- Manual benign or benign-unusual QUIC false positives: {report['analysis']['manual_benign_quic_false_positive_count']}
- Dominant source: {report['analysis']['dominant_source']}
- Dominant minute: {report['analysis']['dominant_minute']}
- Rule-driven rows: {report['analysis']['rule_driven_count']}
- Anomaly-driven rows: {report['analysis']['anomaly_driven_count']}
- Supervised threat-driven rows: {report['analysis']['supervised_driven_count']}
- Hybrid risk at least 50: {report['analysis']['hybrid_high_count']}

| Strategy | Threat Precision | Threat Recall | Threat F1 | Benign-like FPR | Benign-like Recall | Suspicious Recall | Malicious Recall | QUIC FP | FP | FN | Queue |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
{rows}

## Recommendation

- Best candidate: {report['best_strategy']}
- Readiness: {report['readiness']['decision']}
- Production promoted: false
- Model activated: false
- Response automation allowed: false

The QUIC prior is applied only when stronger scan, deny, anomaly, external-to-internal, exfiltration, policy, or high-risk application evidence is absent.
"""


def run_v14b_false_positive_mitigation(
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
    predictions = _mitigation_predictions(prepared, strategy)
    results = _strategy_metrics(prepared, predictions)
    current_predictions = predictions["current_v1_4_balanced"]
    y_true = [
        value if value in THREAT_LABELS else "benign_like"
        for value in prepared["y_test"]
    ]
    test_logs = [prepared["logs"][index] for index in prepared["test_idx"]]
    test_labels = prepared["test_labels"]
    test_features = [
        prepared["frame"].iloc[index].to_dict()
        for index in prepared["test_idx"]
    ]
    class_probabilities = _mapped_probabilities(
        strategy["_probabilities"],
        strategy["_classes"],
    )
    quic_rows: list[dict[str, Any]] = []
    for actual, predicted, log, label, features, probs in zip(
        y_true,
        current_predictions,
        test_logs,
        test_labels,
        test_features,
        class_probabilities,
        strict=False,
    ):
        if (
            actual != "benign_like"
            or predicted not in THREAT_LABELS
            or not _is_normal_quic(log)
        ):
            continue
        threat_probability = sum(probs.get(name, 0) for name in THREAT_LABELS)
        rule_score = _simple_rule_score(log)
        hybrid = hybrid_risk_score(
            rule_score=rule_score,
            isolation_anomaly_score=log.anomaly_score,
            isolation_is_anomaly=bool(log.is_anomaly),
            supervised_malicious_probability=threat_probability,
        )
        quic_rows.append(
            {
                "log": log,
                "label": label,
                "rule_score": rule_score,
                "is_anomaly": bool(log.is_anomaly),
                "threat_probability": threat_probability,
                "hybrid_score": float(hybrid["final_risk_score"]),
                "strong_evidence": _strong_evidence(log, features),
            }
        )
    source_counts = Counter(_source_name(row["log"]) for row in quic_rows)
    minute_counts = Counter(
        timestamp.strftime("%Y-%m-%dT%H:%M")
        for row in quic_rows
        if (timestamp := _log_timestamp(row["log"])) is not None
    )
    analysis = {
        "quic_false_positive_count": len(quic_rows),
        "manual_benign_quic_false_positive_count": sum(
            1
            for row in quic_rows
            if str(row["label"].label_source or "manual") == "manual"
            and row["label"].label in BENIGN_LIKE_LABELS
        ),
        "dominant_source": source_counts.most_common(1)[0][0]
        if source_counts
        else None,
        "source_distribution": dict(source_counts),
        "dominant_minute": minute_counts.most_common(1)[0][0]
        if minute_counts
        else None,
        "minute_distribution": dict(minute_counts.most_common(10)),
        "rule_driven_count": sum(
            1 for row in quic_rows if row["rule_score"] >= 30
        ),
        "anomaly_driven_count": sum(
            1 for row in quic_rows if row["is_anomaly"]
        ),
        "supervised_driven_count": sum(
            1 for row in quic_rows if row["threat_probability"] >= 0.58
        ),
        "hybrid_high_count": sum(
            1 for row in quic_rows if row["hybrid_score"] >= 50
        ),
        "strong_evidence_count": sum(
            1 for row in quic_rows if row["strong_evidence"]
        ),
        "interpretation": (
            "The current supervised threat gate is the main driver when rule, "
            "anomaly, and hybrid evidence remain low."
        ),
    }
    best = _best_mitigation(results)
    best_calibration = _calibration_report(
        y_true,
        strategy["_probabilities"],
        strategy["_classes"],
    )
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
        calibration_buckets=best_calibration.get("readiness_buckets") or [],
        drift_warnings=[],
        response_automation_allowed=False,
    )
    review_sample = export_v14b_actionable_review_sample(
        db,
        prepared=prepared,
        strategy=strategy,
        limit=review_limit,
        output_path=output / V14B_REVIEW_PATH.name,
        include_manual=include_manual,
        include_reviewed=include_reviewed,
        only_actionable=only_actionable,
    )
    report = {
        "ok": True,
        "status": "completed",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "split": split,
        "training_rows": len(prepared["train_idx"]),
        "test_rows": len(prepared["test_idx"]),
        "feature_generation_seconds": prepared["feature_generation_seconds"],
        "analysis": analysis,
        "strategies": results,
        "best_strategy": best["name"],
        "best_metrics": best["summary"],
        "calibration": best_calibration,
        "readiness": readiness,
        "review_sample": review_sample,
        "production_promoted": False,
        "model_activated": False,
        "model_artifact_written": False,
        "response_automation_allowed": False,
        "real_firewall_blocking_enabled": False,
    }
    report_path = output / "v1_4b_quic_false_positive_mitigation.md"
    report_path.write_text(_render_mitigation_report(report), encoding="utf-8")
    _write_json(report_path.with_suffix(".json"), report)
    report["report_path"] = str(report_path)
    _write_json(report_path.with_suffix(".json"), report)
    return report
