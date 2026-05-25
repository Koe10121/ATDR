import csv
from io import StringIO
from pathlib import Path
from typing import Any

from sqlalchemy import desc, func, or_, select
from sqlalchemy.orm import Session, joinedload

from atdr.app.db.models import MLLabel, NormalizedLog
from atdr.app.detection.hybrid_scoring import hybrid_risk_score
from atdr.app.detection.rules import build_detection_context, evaluate_rules
from atdr.app.detection.supervised_detector import MIN_CLASS_SUPPORT, predict_supervised_log
from atdr.app.ml.features import build_log_features
from atdr.app.services.class_temporal_coverage_service import build_class_temporal_coverage, classify_log_time_window


DEFAULT_ACTIVE_LEARNING_PATH = Path("ml_baseline_reviews/active_learning_review_sample.csv")
DEFAULT_ACTIVE_LEARNING_ROUND2_PATH = Path("ml_baseline_reviews/active_learning_round2.csv")
DEFAULT_ACTIVE_LEARNING_ROUND3_MALICIOUS_PATH = Path("ml_baseline_reviews/active_learning_round3_malicious_focus.csv")
DEFAULT_ACTIVE_LEARNING_ROUND4_BOUNDARY_PATH = Path("ml_baseline_reviews/active_learning_round4_boundary_cases.csv")
DEFAULT_ACTIVE_LEARNING_ROUND5_BOUNDARY_PATH = Path(
    "ml_baseline_reviews/active_learning_round5_suspicious_malicious_boundary.csv"
)
DEFAULT_TRAINING_WINDOW_THREAT_REVIEW_PATH = Path("ml_baseline_reviews/training_window_threat_review_sample.csv")
DEFAULT_SUSPICIOUS_RECALL_REVIEW_PATH = Path("ml_baseline_reviews/suspicious_recall_review_sample.csv")

ACTIVE_LEARNING_FIELDNAMES = [
    "label_id",
    "log_id",
    "generated_time",
    "src_ip",
    "dst_ip",
    "app",
    "dst_port",
    "action",
    "current_label",
    "current_attack_type",
    "label_source",
    "reviewed",
    "time_window",
    "model_prediction",
    "label_confidence",
    "confidence",
    "malicious_probability",
    "hybrid_risk_score",
    "rule_score",
    "is_anomaly",
    "anomaly_score",
    "reason_selected_for_review",
    "top_evidence",
    "human_review_decision",
    "human_review_note",
]

TRAINING_WINDOW_THREAT_FIELDNAMES = [
    "label_id",
    "log_id",
    "timestamp",
    "split_window",
    "current_label",
    "current_attack_type",
    "current_reviewed_status",
    "model_prediction",
    "confidence",
    "rule_evidence",
    "anomaly_evidence",
    "hybrid_risk_score",
    "reason_selected_for_review",
    "evidence_summary",
    "human_review_decision",
    "human_review_attack_type",
    "human_review_confidence",
    "human_review_note",
]

SUSPICIOUS_RECALL_FIELDNAMES = [
    "label_id",
    "log_id",
    "timestamp",
    "split_window",
    "current_label",
    "current_attack_type",
    "reviewed_status",
    "model_prediction",
    "model_confidence",
    "threat_positive_score",
    "rule_evidence",
    "anomaly_evidence",
    "hybrid_risk",
    "reason_selected",
    "evidence_summary",
    "human_review_decision",
    "human_review_attack_type",
    "human_review_confidence",
    "human_review_note",
]


def _parse_focus(focus: str | list[str] | tuple[str, ...] | set[str] | None) -> set[str]:
    if focus is None:
        return set()
    if isinstance(focus, str):
        raw_items = focus.split(",")
    else:
        raw_items = list(focus)
    allowed = {"malicious", "suspicious", "needs_context"}
    return {item.strip().lower() for item in raw_items if item and item.strip().lower() in allowed}


def _latest_labels_by_log(db: Session) -> dict[int, MLLabel]:
    labels = list(
        db.scalars(
            select(MLLabel)
            .options(joinedload(MLLabel.log))
            .order_by(MLLabel.log_id, desc(MLLabel.created_at), desc(MLLabel.id))
        )
    )
    latest: dict[int, MLLabel] = {}
    for label in labels:
        latest.setdefault(label.log_id, label)
    return latest


def _count_value(db: Session, column, value: Any) -> int:
    if value is None or value == "":
        return 0
    return int(db.scalar(select(func.count(NormalizedLog.id)).where(column == value)) or 0)


def _rule_score_for_log(db: Session, log: NormalizedLog) -> int:
    rules = evaluate_rules(log, build_detection_context([log]))
    return min(100, sum(rule.score for rule in rules))


def _simple_rule_score(log: NormalizedLog) -> int:
    score = 0
    action = (log.action or "").lower()
    app = (log.app or "").lower()
    if any(token in action for token in ["deny", "drop", "reset"]):
        score += 30
    if log.is_anomaly:
        score += 25
    if (log.app_risk or 0) >= 5:
        score += 25
    elif (log.app_risk or 0) >= 4:
        score += 15
    if app in {"unknown", "unknown-tcp", "unknown-udp", "incomplete"}:
        score += 15
    return min(score, 100)


def _risky_filter():
    return or_(
        NormalizedLog.is_anomaly.is_(True),
        NormalizedLog.app_risk >= 4,
        NormalizedLog.action.in_(["deny", "drop", "reset-both", "reset-client", "reset-server"]),
        NormalizedLog.app.in_(["unknown", "unknown-tcp", "unknown-udp", "incomplete"]),
    )


def _base_candidates(
    db: Session,
    limit: int,
    *,
    focus: set[str] | None = None,
    temporal_coverage: dict[str, Any] | None = None,
) -> dict[int, dict[str, Any]]:
    latest_labels = _latest_labels_by_log(db)
    focus = focus or set()
    candidate_limit = min(max(limit * (8 if focus else 4), 300 if focus else 200), 3000 if focus else 500)
    logs = list(
        db.scalars(
            select(NormalizedLog)
            .where(_risky_filter())
            .order_by(desc(NormalizedLog.generated_time), desc(NormalizedLog.id))
            .limit(candidate_limit)
        )
    )
    if focus:
        logs.extend(
            list(
                db.scalars(
                    select(NormalizedLog)
                    .where(_risky_filter())
                    .order_by(NormalizedLog.generated_time.asc(), NormalizedLog.id.asc())
                    .limit(candidate_limit)
                )
            )
        )
    candidates: dict[int, dict[str, Any]] = {}
    for log in logs:
        rule_score = _simple_rule_score(log)
        hybrid = hybrid_risk_score(
            rule_score=rule_score,
            isolation_anomaly_score=log.anomaly_score,
            isolation_is_anomaly=log.is_anomaly,
            supervised_malicious_probability=0,
        )
        priority_reasons = []
        if log.is_anomaly:
            priority_reasons.append("IsolationForest anomaly")
        if rule_score >= 60:
            priority_reasons.append("high rule evidence")
        if (log.app_risk or 0) >= 4:
            priority_reasons.append(f"app risk {log.app_risk}")
        if (log.action or "").lower() in {"deny", "drop", "reset-both", "reset-client", "reset-server"}:
            priority_reasons.append(f"action={log.action}")
        candidates[log.id] = {
            "log_id": log.id,
            "generated_time": log.generated_time,
            "src_ip": log.src_ip,
            "dst_ip": log.dst_ip,
            "app": log.app,
            "dst_port": log.dst_port,
            "action": log.action,
            "app_risk": log.app_risk,
            "is_anomaly": log.is_anomaly,
            "anomaly_score": log.anomaly_score,
            "rule_score": rule_score,
            "supervised_prediction": None,
            "malicious_probability": 0,
            "hybrid_risk_score": int(hybrid.get("final_risk_score", 0)),
            "priority_score": int(hybrid.get("final_risk_score", 0)),
            "priority_reasons": priority_reasons or ["recent suspicious log"],
            "time_window": classify_log_time_window(log, temporal_coverage),
            "existing_label": None,
        }
    for label in latest_labels.values():
        if not label.log:
            continue
        if label.label != "needs_context" and label.label != "malicious" and label.attack_type not in {"malware_c2", "data_exfiltration_suspicion"}:
            continue
        if label.log_id in candidates:
            continue
        prediction = predict_supervised_log(db, label.log_id)
        rule_score = _rule_score_for_log(db, label.log)
        malicious_probability = float(prediction.get("malicious_probability") or 0)
        hybrid = prediction.get("hybrid_risk") or hybrid_risk_score(
            rule_score=rule_score,
            isolation_anomaly_score=label.log.anomaly_score,
            isolation_is_anomaly=label.log.is_anomaly,
            supervised_malicious_probability=malicious_probability,
        )
        candidates[label.log_id] = {
            "log_id": label.log_id,
            "generated_time": label.log.generated_time,
            "src_ip": label.log.src_ip,
            "dst_ip": label.log.dst_ip,
            "app": label.log.app,
            "action": label.log.action,
            "app_risk": label.log.app_risk,
            "is_anomaly": label.log.is_anomaly,
            "anomaly_score": label.log.anomaly_score,
            "rule_score": rule_score,
            "supervised_prediction": prediction.get("predicted_label"),
            "malicious_probability": malicious_probability,
            "hybrid_risk_score": int(hybrid.get("final_risk_score", 0)),
            "priority_score": int(hybrid.get("final_risk_score", 0)),
            "priority_reasons": ["needs_context or rare high-risk label"],
            "time_window": classify_log_time_window(label.log, temporal_coverage),
            "existing_label": {
                "id": label.id,
                "label": label.label,
                "attack_type": label.attack_type,
                "label_source": label.label_source,
                "reviewed": label.reviewed,
            },
        }
    return candidates


def _selection_reasons(
    db: Session,
    item: dict[str, Any],
    label: MLLabel | None,
    prediction: dict[str, Any],
    label_distribution: dict[str, int],
    *,
    focus: set[str] | None = None,
    temporal_coverage: dict[str, Any] | None = None,
    strategy: str = "general",
) -> tuple[int, list[str]]:
    reasons: list[str] = []
    score = 0
    focus = focus or set()
    predicted_label = prediction.get("predicted_label") or item.get("supervised_prediction")
    class_probabilities = prediction.get("class_probabilities") or {}
    confidence = float(prediction.get("confidence") or 0)
    hybrid_score = int(item.get("hybrid_risk_score") or 0)
    rule_score = int(item.get("rule_score") or 0)
    time_window = str(item.get("time_window") or "unknown_timestamp")
    malicious_probability = float(class_probabilities.get("malicious") or 0)
    suspicious_probability = float(class_probabilities.get("suspicious") or 0)
    boundary_gap = abs(malicious_probability - suspicious_probability)
    evidence_threat_like = bool(rule_score >= 45 or item.get("is_anomaly") or hybrid_score >= 55)
    boundary_mode = strategy in {"boundary", "threat_boundary", "training_threat", "suspicious_recall"}
    if boundary_mode:
        if time_window == "training_window":
            score += 30
            reasons.append("training-window threat-boundary candidate")
        if strategy in {"threat_boundary", "training_threat"} and time_window == "training_window":
            score += 15
            reasons.append("reviewer-consistency training sample")
        if boundary_gap <= 0.15 and (malicious_probability or suspicious_probability):
            score += 30
            reasons.append("model boundary case between suspicious and malicious")
        if label and label.label in {"malicious", "suspicious", "needs_context"} and predicted_label in {"benign", "benign_unusual"}:
            score += 35
            reasons.append("possible threat false negative for human review")
        if strategy in {"threat_boundary", "training_threat"} and label and label.label in {"malicious", "suspicious"}:
            if predicted_label in {"suspicious", "malicious"} and label.label != predicted_label:
                score += 35
                reasons.append("suspicious/malicious label disagrees with model boundary")
            if predicted_label in {"benign", "benign_unusual"}:
                score += 40
                reasons.append("threat-positive row predicted benign-like")
        if predicted_label in {"malicious", "suspicious"} and not evidence_threat_like:
            score += 18
            reasons.append("model threat prediction with weak rule/anomaly evidence")
        if label and label.label == "suspicious" and evidence_threat_like:
            score += 18
            reasons.append("suspicious row may deserve malicious review")
    if strategy == "suspicious_recall":
        if label and label.label == "suspicious" and predicted_label != "suspicious":
            score += 45
            reasons.append(f"suspicious exact-class error predicted={predicted_label or 'unknown'}")
        if label and label.label == "suspicious" and predicted_label == "malicious":
            score += 25
            reasons.append("suspicious/malicious boundary confusion")
        if label and label.label == "suspicious" and predicted_label in {"benign", "benign_unusual", "needs_context"}:
            score += 35
            reasons.append("suspicious row predicted non-threat/uncertain")
        if label and label.label == "suspicious" and not getattr(label, "reviewed", True):
            score += 16
            reasons.append("weak suspicious label needs validation")
        if label and label.label == "suspicious" and time_window == "training_window":
            score += 20
            reasons.append("training-window suspicious example can improve recall")
        if item.get("app") == "incomplete" and item.get("action") == "allow" and item.get("dst_port") == 995:
            score += 18
            reasons.append("app=incomplete/action=allow/port=995 boundary pattern")
        threat_positive_score = malicious_probability + suspicious_probability
        if label and label.label == "suspicious" and predicted_label != "suspicious" and threat_positive_score >= 0.65:
            score += 18
            reasons.append("high threat-positive confidence but wrong exact class")
    if focus and time_window == "training_window":
        score += 25
        reasons.append("training-window sample useful for time-split learning")
    if "malicious" in focus and time_window == "training_window":
        malicious_train_count = int((temporal_coverage or {}).get("malicious_train_count") or 0)
        if malicious_train_count < MIN_CLASS_SUPPORT and (hybrid_score >= 55 or rule_score >= 45 or item.get("is_anomaly")):
            score += 35
            reasons.append("underrepresented malicious training-window candidate")
    if "malicious" in focus and (label and label.label in {"suspicious", "needs_context"} or predicted_label in {"suspicious", "malicious"}):
        score += 20
        reasons.append("candidate may refine suspicious versus malicious boundary")
    if "suspicious" in focus and predicted_label in {"benign", "benign_unusual"} and (rule_score >= 45 or item.get("is_anomaly")):
        score += 20
        reasons.append("risky row predicted benign-like")
    if "needs_context" in focus and (confidence < 0.7 or label and label.label == "needs_context"):
        score += 15
        reasons.append("uncertain row useful for needs_context coverage")
    if confidence and confidence < 0.65:
        score += 30
        reasons.append("low-confidence model prediction")
    if label and predicted_label and label.label != predicted_label:
        score += 25
        reasons.append("current label disagrees with supervised prediction")
    if predicted_label in {"benign", "benign_unusual"} and (rule_score >= 60 or hybrid_score >= 70 or item.get("is_anomaly")):
        score += 25
        reasons.append("rule/anomaly/hybrid evidence disagrees with benign prediction")
    if predicted_label in {"suspicious", "malicious"} and rule_score < 30 and hybrid_score < 40:
        score += 15
        reasons.append("supervised model flags risk with low rule evidence")
    if hybrid_score >= 70:
        score += 20
        reasons.append("high hybrid risk")
    if item.get("is_anomaly"):
        score += 15
        reasons.append("IsolationForest anomaly")
    if label and label.label == "needs_context":
        score += 20
        reasons.append("needs_context label")
    if label and int(label_distribution.get(label.label, 0)) < MIN_CLASS_SUPPORT:
        score += 20
        reasons.append(f"underrepresented class: {label.label}")
    if label and label.attack_type in {"malware_c2", "data_exfiltration_suspicion", "unknown_anomaly"}:
        score += 12
        reasons.append(f"rare/high-interest attack type: {label.attack_type}")
    app_count = _count_value(db, NormalizedLog.app, item.get("app"))
    port_count = _count_value(db, NormalizedLog.dst_port, item.get("dst_port"))
    if item.get("app") and app_count and app_count <= 3:
        score += 10
        reasons.append("rare application")
    if item.get("dst_port") and port_count and port_count <= 3:
        score += 10
        reasons.append("rare destination port")
    log = db.get(NormalizedLog, int(item["log_id"]))
    if log is not None:
        try:
            features = build_log_features(db, log)
        except Exception:
            features = {}
        scanning_score = int(features.get("scanning_like_behavior_score") or 0)
        repeated_attempts = int(features.get("repeated_connection_attempts") or 0)
        external_to_internal = bool(features.get("external_to_internal_flag"))
        unknown_app = bool(features.get("unknown_app_flag"))
        total_bytes_1h = int(features.get("src_ip_1h_total_bytes") or 0)
        unique_ports_15m = int(features.get("src_ip_15min_unique_dst_ports") or 0)
        deny_ratio_15m = float(features.get("src_ip_15min_deny_ratio") or 0)
        if scanning_score >= 60 or unique_ports_15m >= 20:
            score += 25
            reasons.append("possible scanning behavior")
        if repeated_attempts >= 5 and deny_ratio_15m >= 0.4:
            score += 18
            reasons.append("possible brute-force/repeated denied attempts")
        if external_to_internal and unknown_app:
            score += 15
            reasons.append("repeated external-to-internal unknown/incomplete traffic")
        if total_bytes_1h >= 50_000_000 and predicted_label in {"benign", "benign_unusual"}:
            score += 15
            reasons.append("possible exfiltration/large transfer behavior")
    if not reasons:
        score += 5
        reasons.append("diversity sample")
    return score, reasons


def build_active_learning_review_sample(
    db: Session,
    *,
    limit: int = 100,
    focus: str | list[str] | tuple[str, ...] | set[str] | None = None,
    strategy: str = "general",
) -> list[dict[str, Any]]:
    focus_set = _parse_focus(focus)
    temporal_coverage = build_class_temporal_coverage(db) if focus_set else None
    latest_labels = _latest_labels_by_log(db)
    label_values = [label.label for label in latest_labels.values()]
    label_distribution = {label: label_values.count(label) for label in sorted(set(label_values))}
    candidates = _base_candidates(db, limit, focus=focus_set, temporal_coverage=temporal_coverage)
    rows: list[dict[str, Any]] = []
    candidate_pool = sorted(
        candidates.values(),
        key=lambda item: (int(item.get("priority_score") or 0), int(item.get("hybrid_risk_score") or 0), int(item["log_id"])),
        reverse=True,
    )[: min(max(limit * (4 if focus_set else 2), 100 if focus_set else 50), 500 if focus_set else 200)]
    for item in candidate_pool:
        label = latest_labels.get(int(item["log_id"]))
        prediction = predict_supervised_log(db, int(item["log_id"]), rule_score=int(item.get("rule_score") or 0))
        score, reasons = _selection_reasons(
            db,
            item,
            label,
            prediction,
            label_distribution,
            focus=focus_set,
            temporal_coverage=temporal_coverage,
            strategy=strategy,
        )
        rows.append(
            {
                "selection_score": score,
                "label_id": label.id if label else "",
                "log_id": item["log_id"],
                "generated_time": item.get("generated_time"),
                "src_ip": item.get("src_ip") or "",
                "dst_ip": item.get("dst_ip") or "",
                "app": item.get("app") or "",
                "dst_port": item.get("dst_port") or "",
                "action": item.get("action") or "",
                "current_label": label.label if label else "",
                "current_attack_type": label.attack_type if label else "unknown_anomaly",
                "label_source": label.label_source if label else "",
                "reviewed": label.reviewed if label else False,
                "time_window": item.get("time_window") or "unknown_timestamp",
                "model_prediction": prediction.get("predicted_label") or item.get("supervised_prediction") or "",
                "label_confidence": 3,
                "confidence": prediction.get("confidence") or 0,
                "malicious_probability": prediction.get("malicious_probability") or item.get("malicious_probability") or 0,
                "hybrid_risk_score": item.get("hybrid_risk_score") or 0,
                "rule_score": item.get("rule_score") or 0,
                "is_anomaly": item.get("is_anomaly"),
                "anomaly_score": item.get("anomaly_score") or "",
                "reason_selected_for_review": "; ".join(reasons),
                "top_evidence": "; ".join([*reasons[:3], *[str(reason) for reason in item.get("priority_reasons", [])[:2]]]),
                "human_review_decision": "",
                "human_review_note": "",
            }
        )
    rows.sort(key=lambda row: (int(row["selection_score"]), int(row.get("hybrid_risk_score") or 0), int(row["log_id"])), reverse=True)
    selected: list[dict[str, Any]] = []
    seen_src: set[str] = set()
    seen_app: set[str] = set()
    for row in rows:
        src = str(row.get("src_ip") or "")
        app = str(row.get("app") or "")
        if len(selected) < max(1, limit // 2) and (src in seen_src and app in seen_app):
            continue
        selected.append(row)
        if src:
            seen_src.add(src)
        if app:
            seen_app.add(app)
        if len(selected) >= limit:
            break
    if len(selected) < limit:
        selected_ids = {row["log_id"] for row in selected}
        remaining = [row for row in rows if row["log_id"] not in selected_ids]
        selected.extend(remaining[: limit - len(selected)])
    return selected[:limit]


def export_active_learning_review_sample_csv(
    db: Session,
    *,
    limit: int = 100,
    focus: str | list[str] | tuple[str, ...] | set[str] | None = None,
    strategy: str = "general",
) -> str:
    output = StringIO()
    writer = csv.DictWriter(output, fieldnames=ACTIVE_LEARNING_FIELDNAMES)
    writer.writeheader()
    for row in build_active_learning_review_sample(db, limit=limit, focus=focus, strategy=strategy):
        serialized = {field: row.get(field, "") for field in ACTIVE_LEARNING_FIELDNAMES}
        generated_time = serialized.get("generated_time")
        if hasattr(generated_time, "isoformat"):
            serialized["generated_time"] = generated_time.isoformat()
        writer.writerow(serialized)
    return output.getvalue()


def write_active_learning_review_sample(
    db: Session,
    *,
    limit: int = 100,
    output_path: str | Path = DEFAULT_ACTIVE_LEARNING_PATH,
    focus: str | list[str] | tuple[str, ...] | set[str] | None = None,
    strategy: str = "general",
) -> dict[str, Any]:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    csv_text = export_active_learning_review_sample_csv(db, limit=limit, focus=focus, strategy=strategy)
    path.write_text(csv_text, encoding="utf-8")
    rows = max(0, len(csv_text.splitlines()) - 1)
    return {"status": "exported", "path": str(path), "rows": rows, "focus": sorted(_parse_focus(focus)), "strategy": strategy}


def build_training_window_threat_review_sample(db: Session, *, limit: int = 150) -> list[dict[str, Any]]:
    rows = build_active_learning_review_sample(
        db,
        limit=max(limit * 3, 300),
        focus="malicious,suspicious,needs_context",
        strategy="training_threat",
    )
    training_rows = [row for row in rows if row.get("time_window") == "training_window"]
    if len(training_rows) < limit:
        selected_ids = {row["log_id"] for row in training_rows}
        training_rows.extend(row for row in rows if row["log_id"] not in selected_ids)
    return training_rows[:limit]


def export_training_window_threat_review_sample_csv(db: Session, *, limit: int = 150) -> str:
    output = StringIO()
    writer = csv.DictWriter(output, fieldnames=TRAINING_WINDOW_THREAT_FIELDNAMES)
    writer.writeheader()
    for row in build_training_window_threat_review_sample(db, limit=limit):
        timestamp = row.get("generated_time")
        if hasattr(timestamp, "isoformat"):
            timestamp = timestamp.isoformat()
        writer.writerow(
            {
                "label_id": row.get("label_id", ""),
                "log_id": row.get("log_id", ""),
                "timestamp": timestamp or "",
                "split_window": row.get("time_window", ""),
                "current_label": row.get("current_label", ""),
                "current_attack_type": row.get("current_attack_type", ""),
                "current_reviewed_status": row.get("reviewed", ""),
                "model_prediction": row.get("model_prediction", ""),
                "confidence": row.get("confidence", ""),
                "rule_evidence": f"rule_score={row.get('rule_score', 0)}",
                "anomaly_evidence": f"is_anomaly={row.get('is_anomaly')}; anomaly_score={row.get('anomaly_score', '')}",
                "hybrid_risk_score": row.get("hybrid_risk_score", 0),
                "reason_selected_for_review": row.get("reason_selected_for_review", ""),
                "evidence_summary": row.get("top_evidence", ""),
                "human_review_decision": "",
                "human_review_attack_type": row.get("current_attack_type") or "unknown_anomaly",
                "human_review_confidence": row.get("label_confidence", 3),
                "human_review_note": "",
            }
        )
    return output.getvalue()


def write_training_window_threat_review_sample(
    db: Session,
    *,
    limit: int = 150,
    output_path: str | Path = DEFAULT_TRAINING_WINDOW_THREAT_REVIEW_PATH,
) -> dict[str, Any]:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    csv_text = export_training_window_threat_review_sample_csv(db, limit=limit)
    path.write_text(csv_text, encoding="utf-8")
    rows = max(0, len(csv_text.splitlines()) - 1)
    return {"status": "exported", "path": str(path), "rows": rows, "strategy": "training_threat"}


def build_suspicious_recall_review_sample(db: Session, *, limit: int = 150) -> list[dict[str, Any]]:
    temporal_coverage = build_class_temporal_coverage(db)
    latest_labels = _latest_labels_by_log(db)
    suspicious_logs = [
        label.log
        for label in latest_labels.values()
        if label.log is not None and label.label in {"suspicious", "malicious", "benign_unusual", "needs_context"}
    ]
    candidates: dict[int, dict[str, Any]] = _base_candidates(
        db,
        max(limit * 2, 300),
        focus={"suspicious", "malicious", "needs_context"},
        temporal_coverage=temporal_coverage,
    )
    for log in suspicious_logs:
        if log is None or log.id in candidates:
            continue
        label = latest_labels.get(log.id)
        rule_score = _simple_rule_score(log)
        prediction = predict_supervised_log(db, log.id, rule_score=rule_score)
        malicious_probability = float(prediction.get("malicious_probability") or 0)
        hybrid = prediction.get("hybrid_risk") or hybrid_risk_score(
            rule_score=rule_score,
            isolation_anomaly_score=log.anomaly_score,
            isolation_is_anomaly=log.is_anomaly,
            supervised_malicious_probability=malicious_probability,
        )
        candidates[log.id] = {
            "log_id": log.id,
            "generated_time": log.generated_time,
            "src_ip": log.src_ip,
            "dst_ip": log.dst_ip,
            "app": log.app,
            "dst_port": log.dst_port,
            "action": log.action,
            "app_risk": log.app_risk,
            "is_anomaly": log.is_anomaly,
            "anomaly_score": log.anomaly_score,
            "rule_score": rule_score,
            "supervised_prediction": prediction.get("predicted_label"),
            "malicious_probability": malicious_probability,
            "hybrid_risk_score": int((hybrid or {}).get("final_risk_score", 0)),
            "priority_score": int((hybrid or {}).get("final_risk_score", 0)),
            "priority_reasons": ["current label selected for suspicious-recall review"],
            "time_window": classify_log_time_window(log, temporal_coverage),
            "existing_label": {
                "id": label.id,
                "label": label.label,
                "attack_type": label.attack_type,
                "label_source": label.label_source,
                "reviewed": label.reviewed,
            }
            if label
            else None,
        }
    label_values = [label.label for label in latest_labels.values()]
    label_distribution = {label: label_values.count(label) for label in sorted(set(label_values))}
    rows: list[dict[str, Any]] = []
    for item in candidates.values():
        label = latest_labels.get(int(item["log_id"]))
        if label is None:
            continue
        prediction = predict_supervised_log(db, int(item["log_id"]), rule_score=int(item.get("rule_score") or 0))
        score, reasons = _selection_reasons(
            db,
            item,
            label,
            prediction,
            label_distribution,
            focus={"suspicious", "malicious", "needs_context"},
            temporal_coverage=temporal_coverage,
            strategy="suspicious_recall",
        )
        if label.label == "suspicious" or score >= 55:
            rows.append(
                {
                    "selection_score": score,
                    "label_id": label.id,
                    "log_id": item["log_id"],
                    "generated_time": item.get("generated_time"),
                    "src_ip": item.get("src_ip") or "",
                    "dst_ip": item.get("dst_ip") or "",
                    "app": item.get("app") or "",
                    "dst_port": item.get("dst_port") or "",
                    "action": item.get("action") or "",
                    "current_label": label.label,
                    "current_attack_type": label.attack_type,
                    "label_source": label.label_source,
                    "reviewed": label.reviewed,
                    "time_window": item.get("time_window") or "unknown_timestamp",
                    "model_prediction": prediction.get("predicted_label") or item.get("supervised_prediction") or "",
                    "confidence": prediction.get("confidence") or 0,
                    "threat_positive_score": round(
                        float((prediction.get("class_probabilities") or {}).get("suspicious") or 0)
                        + float((prediction.get("class_probabilities") or {}).get("malicious") or 0),
                        4,
                    ),
                    "hybrid_risk_score": item.get("hybrid_risk_score") or 0,
                    "rule_score": item.get("rule_score") or 0,
                    "is_anomaly": item.get("is_anomaly"),
                    "anomaly_score": item.get("anomaly_score") or "",
                    "reason_selected_for_review": "; ".join(reasons),
                    "top_evidence": "; ".join([*reasons[:3], *[str(reason) for reason in item.get("priority_reasons", [])[:2]]]),
                    "label_confidence": label.confidence or 3,
                }
            )
    rows.sort(
        key=lambda row: (
            row.get("current_label") == "suspicious",
            int(row.get("selection_score") or 0),
            row.get("time_window") == "training_window",
            int(row.get("hybrid_risk_score") or 0),
            int(row.get("log_id") or 0),
        ),
        reverse=True,
    )
    return rows[:limit]


def export_suspicious_recall_review_sample_csv(db: Session, *, limit: int = 150) -> str:
    output = StringIO()
    writer = csv.DictWriter(output, fieldnames=SUSPICIOUS_RECALL_FIELDNAMES)
    writer.writeheader()
    for row in build_suspicious_recall_review_sample(db, limit=limit):
        timestamp = row.get("generated_time")
        if hasattr(timestamp, "isoformat"):
            timestamp = timestamp.isoformat()
        writer.writerow(
            {
                "label_id": row.get("label_id", ""),
                "log_id": row.get("log_id", ""),
                "timestamp": timestamp or "",
                "split_window": row.get("time_window", ""),
                "current_label": row.get("current_label", ""),
                "current_attack_type": row.get("current_attack_type", ""),
                "reviewed_status": row.get("reviewed", ""),
                "model_prediction": row.get("model_prediction", ""),
                "model_confidence": row.get("confidence", ""),
                "threat_positive_score": row.get("threat_positive_score", ""),
                "rule_evidence": f"rule_score={row.get('rule_score', 0)}",
                "anomaly_evidence": f"is_anomaly={row.get('is_anomaly')}; anomaly_score={row.get('anomaly_score', '')}",
                "hybrid_risk": row.get("hybrid_risk_score", 0),
                "reason_selected": row.get("reason_selected_for_review", ""),
                "evidence_summary": row.get("top_evidence", ""),
                "human_review_decision": "",
                "human_review_attack_type": row.get("current_attack_type") or "unknown_anomaly",
                "human_review_confidence": row.get("label_confidence", 3),
                "human_review_note": "",
            }
        )
    return output.getvalue()


def write_suspicious_recall_review_sample(
    db: Session,
    *,
    limit: int = 150,
    output_path: str | Path = DEFAULT_SUSPICIOUS_RECALL_REVIEW_PATH,
) -> dict[str, Any]:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    csv_text = export_suspicious_recall_review_sample_csv(db, limit=limit)
    path.write_text(csv_text, encoding="utf-8")
    rows = max(0, len(csv_text.splitlines()) - 1)
    return {"status": "exported", "path": str(path), "rows": rows, "strategy": "suspicious_recall"}
