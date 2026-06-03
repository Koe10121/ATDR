import csv
from collections import Counter
from io import StringIO
from pathlib import Path
from typing import Any

from sqlalchemy import desc, func, or_, select
from sqlalchemy.orm import Session, joinedload

from atdr.app.db.models import MLLabel, NormalizedLog, RawLog
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
DEFAULT_LARGE_POOL_ACTIVE_LEARNING_PATH = Path("ml_baseline_reviews/large_pool_active_learning_sample.csv")
DEFAULT_BALANCED_RECOVERY_REVIEW_PATH = Path("ml_baseline_reviews/balanced_recovery_review_sample.csv")
DEFAULT_STAGE1_THREAT_RECALL_REVIEW_PATH = Path("ml_baseline_reviews/stage1_threat_recall_review_sample.csv")
DEFAULT_BENIGN_NEEDS_CONTEXT_FINAL_GAP_PATH = Path("ml_baseline_reviews/benign_needs_context_final_gap_sample.csv")
DEFAULT_FINAL_SMALL_LABEL_GAP_PATH = Path("ml_baseline_reviews/final_small_label_gap_sample.csv")

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

LARGE_POOL_ACTIVE_LEARNING_FIELDNAMES = [
    "log_id",
    "timestamp",
    "source",
    "src_ip",
    "dst_ip",
    "dst_port",
    "app",
    "action",
    "current_label",
    "reviewed_status",
    "rule_evidence",
    "anomaly_score",
    "hybrid_risk",
    "model_prediction",
    "reason_selected",
    "evidence_summary",
    "human_review_decision",
    "human_review_attack_type",
    "human_review_confidence",
    "human_review_note",
]

BALANCED_RECOVERY_FIELDNAMES = LARGE_POOL_ACTIVE_LEARNING_FIELDNAMES

STAGE1_THREAT_RECALL_FIELDNAMES = [
    "log_id",
    "timestamp",
    "source",
    "src_ip",
    "dst_ip",
    "dst_port",
    "app",
    "action",
    "current_label",
    "reviewed_status",
    "model_prediction",
    "threat_positive_score",
    "rule_evidence",
    "anomaly_score",
    "hybrid_risk",
    "reason_selected",
    "evidence_summary",
    "human_review_decision",
    "human_review_attack_type",
    "human_review_confidence",
    "human_review_note",
]

BENIGN_NEEDS_CONTEXT_FINAL_GAP_FIELDNAMES = [
    "log_id",
    "timestamp",
    "source",
    "src_ip",
    "dst_ip",
    "dst_port",
    "app",
    "action",
    "current_label",
    "reviewed_status",
    "model_prediction",
    "benign_probability",
    "threat_positive_probability",
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


def _append_candidate_logs(candidates: dict[int, NormalizedLog], logs: list[NormalizedLog], *, cap: int) -> None:
    for log in logs:
        candidates.setdefault(log.id, log)
        if len(candidates) >= cap:
            break


def _source_name(log: NormalizedLog) -> str:
    raw = getattr(log, "raw_log", None)
    source = getattr(raw, "source", None)
    if source is None:
        return "unknown_source"
    return str(source.name or f"source-{source.id}")


def _large_pool_candidate_logs(db: Session, *, limit: int, candidate_pool_limit: int | None = None) -> list[NormalizedLog]:
    pool_limit = candidate_pool_limit or min(max(limit * 10, 1000), 5000)
    candidates: dict[int, NormalizedLog] = {}
    load_options = [joinedload(NormalizedLog.raw_log).joinedload(RawLog.source)]
    per_query = max(50, min(pool_limit // 5, 1000))
    risky_actions = ["deny", "drop", "reset-both", "reset-client", "reset-server"]
    unknown_apps = ["unknown", "unknown-tcp", "unknown-udp", "incomplete"]

    _append_candidate_logs(
        candidates,
        list(
            db.scalars(
                select(NormalizedLog)
                .options(*load_options)
                .where(NormalizedLog.is_anomaly.is_(True))
                .order_by(NormalizedLog.anomaly_score.asc(), desc(NormalizedLog.generated_time), desc(NormalizedLog.id))
                .limit(per_query)
            )
        ),
        cap=pool_limit,
    )
    _append_candidate_logs(
        candidates,
        list(
            db.scalars(
                select(NormalizedLog)
                .options(*load_options)
                .where(_risky_filter())
                .order_by(desc(NormalizedLog.generated_time), desc(NormalizedLog.id))
                .limit(per_query)
            )
        ),
        cap=pool_limit,
    )
    _append_candidate_logs(
        candidates,
        list(
            db.scalars(
                select(NormalizedLog)
                .options(*load_options)
                .where(NormalizedLog.action.in_(risky_actions))
                .order_by(desc(NormalizedLog.generated_time), desc(NormalizedLog.id))
                .limit(per_query)
            )
        ),
        cap=pool_limit,
    )
    _append_candidate_logs(
        candidates,
        list(
            db.scalars(
                select(NormalizedLog)
                .options(*load_options)
                .where(NormalizedLog.app.in_(unknown_apps))
                .order_by(desc(NormalizedLog.generated_time), desc(NormalizedLog.id))
                .limit(per_query)
            )
        ),
        cap=pool_limit,
    )
    _append_candidate_logs(
        candidates,
        list(
            db.scalars(
                select(NormalizedLog)
                .options(*load_options)
                .where(
                    NormalizedLog.app.in_(["ssl", "quic-base"]),
                    NormalizedLog.action == "allow",
                    NormalizedLog.dst_port == 443,
                )
                .order_by(desc(NormalizedLog.generated_time), desc(NormalizedLog.id))
                .limit(per_query)
            )
        ),
        cap=pool_limit,
    )

    rare_apps = [
        value
        for value in db.scalars(
            select(NormalizedLog.app)
            .where(NormalizedLog.app.is_not(None), NormalizedLog.app != "")
            .group_by(NormalizedLog.app)
            .having(func.count(NormalizedLog.id) <= 5)
            .limit(25)
        )
    ]
    if rare_apps:
        _append_candidate_logs(
            candidates,
            list(
                db.scalars(
                    select(NormalizedLog)
                    .options(*load_options)
                    .where(NormalizedLog.app.in_(rare_apps))
                    .order_by(desc(NormalizedLog.generated_time), desc(NormalizedLog.id))
                    .limit(per_query)
                )
            ),
            cap=pool_limit,
        )
    rare_ports = [
        value
        for value in db.scalars(
            select(NormalizedLog.dst_port)
            .where(NormalizedLog.dst_port.is_not(None))
            .group_by(NormalizedLog.dst_port)
            .having(func.count(NormalizedLog.id) <= 5)
            .limit(25)
        )
    ]
    if rare_ports:
        _append_candidate_logs(
            candidates,
            list(
                db.scalars(
                    select(NormalizedLog)
                    .options(*load_options)
                    .where(NormalizedLog.dst_port.in_(rare_ports))
                    .order_by(desc(NormalizedLog.generated_time), desc(NormalizedLog.id))
                    .limit(per_query)
                )
            ),
            cap=pool_limit,
        )
    _append_candidate_logs(
        candidates,
        list(
            db.scalars(
                select(NormalizedLog).options(*load_options).order_by(desc(NormalizedLog.generated_time), desc(NormalizedLog.id)).limit(per_query)
            )
        ),
        cap=pool_limit,
    )
    return list(candidates.values())


def _large_pool_score(
    db: Session,
    log: NormalizedLog,
    label: MLLabel | None,
    prediction: dict[str, Any],
    temporal_coverage: dict[str, Any],
) -> tuple[int, list[str], dict[str, Any]]:
    rule_score = _simple_rule_score(log)
    class_probabilities = prediction.get("class_probabilities") or {}
    predicted_label = str(prediction.get("predicted_label") or "")
    malicious_probability = float(class_probabilities.get("malicious") or 0)
    suspicious_probability = float(class_probabilities.get("suspicious") or 0)
    hybrid = prediction.get("hybrid_risk") or hybrid_risk_score(
        rule_score=rule_score,
        isolation_anomaly_score=log.anomaly_score,
        isolation_is_anomaly=log.is_anomaly,
        supervised_malicious_probability=malicious_probability,
    )
    hybrid_score = int(hybrid.get("final_risk_score", 0))
    reasons: list[str] = []
    score = hybrid_score
    if label is None:
        score += 30
        reasons.append("unlabeled row from large log pool")
    elif not bool(getattr(label, "reviewed", True)):
        score += 20
        reasons.append("weak label needs human review")
    if log.is_anomaly:
        score += 25
        reasons.append("high anomaly signal")
    if rule_score >= 45:
        score += 20
        reasons.append(f"rule evidence score={rule_score}")
    if hybrid_score >= 60:
        score += 20
        reasons.append(f"high hybrid risk={hybrid_score}")
    if predicted_label in {"suspicious", "malicious"} and not label:
        score += 20
        reasons.append("threat-positive model prediction without reviewed label")
    if predicted_label in {"benign", "benign_unusual"} and (rule_score >= 45 or log.is_anomaly or hybrid_score >= 60):
        score += 22
        reasons.append("model benign prediction disagrees with rule/anomaly risk")
    if predicted_label in {"suspicious", "malicious"} and rule_score < 25 and not log.is_anomaly:
        score += 12
        reasons.append("model flags risk with weak rule evidence")
    if malicious_probability and suspicious_probability and abs(malicious_probability - suspicious_probability) <= 0.15:
        score += 18
        reasons.append("suspicious/malicious boundary case")
    if log.dst_port and _count_value(db, NormalizedLog.dst_port, log.dst_port) <= 5:
        score += 10
        reasons.append("rare destination port")
    if log.app and _count_value(db, NormalizedLog.app, log.app) <= 5:
        score += 10
        reasons.append("rare app")
    if log.app in {"ssl", "quic-base"} and log.action == "allow" and log.dst_port == 443:
        score += 12
        reasons.append("ssl/quic-base allow 443 confusion pattern")
    split_window = classify_log_time_window(log, temporal_coverage)
    if split_window == "training_window" and (rule_score >= 45 or log.is_anomaly or predicted_label in {"suspicious", "malicious"}):
        score += 15
        reasons.append("training-window candidate for class coverage")
    try:
        features = build_log_features(db, log)
    except Exception:
        features = {}
    if int(features.get("scanning_like_behavior_score") or 0) >= 50:
        score += 20
        reasons.append("scanning-like behavior window")
    if bool(features.get("external_to_internal_flag")) and (log.app in {"unknown", "unknown-tcp", "unknown-udp", "incomplete"}):
        score += 18
        reasons.append("external-to-internal unknown/incomplete behavior")
    if int(features.get("src_ip_15min_unique_dst_ports") or 0) >= 20:
        score += 14
        reasons.append("many destination ports from source")
    if int(features.get("src_ip_15min_unique_dst_ips") or 0) >= 20:
        score += 14
        reasons.append("many destination IPs from source")
    if not reasons:
        reasons.append("diversity sample from large log pool")
    evidence = {
        "rule_score": rule_score,
        "hybrid_score": hybrid_score,
        "predicted_label": predicted_label,
        "split_window": split_window,
    }
    return score, reasons, evidence


def build_large_pool_active_learning_sample(db: Session, *, limit: int = 300, candidate_pool_limit: int | None = None) -> list[dict[str, Any]]:
    temporal_coverage = build_class_temporal_coverage(db)
    labels_by_log = _latest_labels_by_log(db)
    candidates = _large_pool_candidate_logs(db, limit=limit, candidate_pool_limit=candidate_pool_limit)
    scored_rows: list[dict[str, Any]] = []
    for log in candidates:
        label = labels_by_log.get(log.id)
        rule_score = _simple_rule_score(log)
        try:
            prediction = predict_supervised_log(db, log.id, rule_score=rule_score)
        except Exception:
            prediction = {"predicted_label": "", "confidence": 0, "class_probabilities": {}}
        score, reasons, evidence = _large_pool_score(db, log, label, prediction, temporal_coverage)
        timestamp = log.generated_time or log.receive_time or log.start_time
        anomaly_text = "" if log.anomaly_score is None else round(float(log.anomaly_score), 6)
        scored_rows.append(
            {
                "selection_score": score,
                "log_id": log.id,
                "timestamp": timestamp,
                "source": _source_name(log),
                "src_ip": log.src_ip or "",
                "dst_ip": log.dst_ip or "",
                "dst_port": log.dst_port or "",
                "app": log.app or "",
                "action": log.action or "",
                "current_label": label.label if label else "",
                "reviewed_status": bool(label.reviewed) if label else False,
                "rule_evidence": f"rule_score={evidence['rule_score']}",
                "anomaly_score": anomaly_text,
                "hybrid_risk": evidence["hybrid_score"],
                "model_prediction": evidence["predicted_label"],
                "reason_selected": "; ".join(reasons),
                "evidence_summary": "; ".join(reasons[:5]),
                "human_review_decision": "",
                "human_review_attack_type": label.attack_type if label else "unknown_anomaly",
                "human_review_confidence": label.confidence if label else 3,
                "human_review_note": "",
            }
        )
    scored_rows.sort(key=lambda row: (int(row["selection_score"]), int(row["hybrid_risk"]), int(row["log_id"])), reverse=True)
    selected: list[dict[str, Any]] = []
    source_counts: Counter[str] = Counter()
    app_counts: Counter[str] = Counter()
    port_counts: Counter[str] = Counter()
    max_per_dimension = max(3, limit // 8)
    for row in scored_rows:
        source = str(row.get("source") or "unknown_source")
        app = str(row.get("app") or "missing")
        port = str(row.get("dst_port") or "missing")
        if (
            len(selected) < int(limit * 0.75)
            and source_counts[source] >= max_per_dimension
            and app_counts[app] >= max_per_dimension
            and port_counts[port] >= max_per_dimension
        ):
            continue
        selected.append(row)
        source_counts[source] += 1
        app_counts[app] += 1
        port_counts[port] += 1
        if len(selected) >= limit:
            break
    if len(selected) < limit:
        selected_ids = {row["log_id"] for row in selected}
        selected.extend(row for row in scored_rows if row["log_id"] not in selected_ids)
    return selected[:limit]


def export_large_pool_active_learning_sample_csv(db: Session, *, limit: int = 300, candidate_pool_limit: int | None = None) -> str:
    output = StringIO()
    writer = csv.DictWriter(output, fieldnames=LARGE_POOL_ACTIVE_LEARNING_FIELDNAMES)
    writer.writeheader()
    for row in build_large_pool_active_learning_sample(db, limit=limit, candidate_pool_limit=candidate_pool_limit):
        serialized = {field: row.get(field, "") for field in LARGE_POOL_ACTIVE_LEARNING_FIELDNAMES}
        timestamp = serialized.get("timestamp")
        if hasattr(timestamp, "isoformat"):
            serialized["timestamp"] = timestamp.isoformat()
        writer.writerow(serialized)
    return output.getvalue()


def write_large_pool_active_learning_sample(
    db: Session,
    *,
    limit: int = 300,
    output_path: str | Path = DEFAULT_LARGE_POOL_ACTIVE_LEARNING_PATH,
    candidate_pool_limit: int | None = None,
) -> dict[str, Any]:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    csv_text = export_large_pool_active_learning_sample_csv(db, limit=limit, candidate_pool_limit=candidate_pool_limit)
    path.write_text(csv_text, encoding="utf-8")
    rows = max(0, len(csv_text.splitlines()) - 1)
    return {
        "status": "exported",
        "path": str(path),
        "rows": rows,
        "strategy": "large_pool_active_learning",
        "production_promoted": False,
        "response_automation_allowed": False,
    }


def _normal_traffic_candidates(db: Session, *, limit: int) -> list[NormalizedLog]:
    normal_apps = ["ssl", "quic-base", "dns-base", "web-browsing"]
    normal_ports = [443, 80, 53]
    return list(
        db.scalars(
            select(NormalizedLog)
            .options(joinedload(NormalizedLog.raw_log).joinedload(RawLog.source))
            .where(
                NormalizedLog.action == "allow",
                or_(NormalizedLog.is_anomaly.is_(False), NormalizedLog.is_anomaly.is_(None)),
                NormalizedLog.app.in_(normal_apps),
                NormalizedLog.dst_port.in_(normal_ports),
                NormalizedLog.app_risk <= 3,
            )
            .order_by(desc(NormalizedLog.generated_time), desc(NormalizedLog.id))
            .limit(limit)
        )
    )


def _needs_context_candidates(db: Session, *, limit: int) -> list[NormalizedLog]:
    latest_labels = _latest_labels_by_log(db)
    label_logs = [
        label.log
        for label in latest_labels.values()
        if label.log is not None and label.label == "needs_context"
    ]
    queried = list(
        db.scalars(
            select(NormalizedLog)
            .options(joinedload(NormalizedLog.raw_log).joinedload(RawLog.source))
            .where(
                or_(
                    NormalizedLog.app.in_(["unknown", "unknown-tcp", "unknown-udp", "incomplete"]),
                    NormalizedLog.dst_port == 0,
                    NormalizedLog.src_ip.is_(None),
                    NormalizedLog.dst_ip.is_(None),
                    NormalizedLog.action.is_(None),
                )
            )
            .order_by(desc(NormalizedLog.generated_time), desc(NormalizedLog.id))
            .limit(limit)
        )
    )
    by_id = {log.id: log for log in [*label_logs, *queried] if log is not None}
    return list(by_id.values())[:limit]


def _suspicious_boundary_candidates(db: Session, *, limit: int) -> list[NormalizedLog]:
    latest_labels = _latest_labels_by_log(db)
    label_logs = [
        label.log
        for label in latest_labels.values()
        if label.log is not None and label.label in {"suspicious", "benign", "benign_unusual"}
    ]
    queried = list(
        db.scalars(
            select(NormalizedLog)
            .options(joinedload(NormalizedLog.raw_log).joinedload(RawLog.source))
            .where(
                or_(
                    _risky_filter(),
                    NormalizedLog.app.in_(["ssl", "quic-base"]),
                    NormalizedLog.dst_port == 443,
                )
            )
            .order_by(desc(NormalizedLog.generated_time), desc(NormalizedLog.id))
            .limit(limit)
        )
    )
    by_id = {log.id: log for log in [*label_logs, *queried] if log is not None}
    return list(by_id.values())[:limit]


def _balanced_review_row(
    db: Session,
    log: NormalizedLog,
    label: MLLabel | None,
    *,
    bucket: str,
    bucket_reason: str,
    temporal_coverage: dict[str, Any],
) -> dict[str, Any]:
    rule_score = _simple_rule_score(log)
    try:
        prediction = predict_supervised_log(db, log.id, rule_score=rule_score)
    except Exception:
        prediction = {"predicted_label": "", "confidence": 0, "class_probabilities": {}}
    score, reasons, evidence = _large_pool_score(db, log, label, prediction, temporal_coverage)
    predicted_label = str(evidence.get("predicted_label") or "")
    if bucket == "benign_candidate":
        score += 60
        if predicted_label in {"suspicious", "malicious"}:
            score += 35
            reasons.insert(0, "possible binary threat-positive false positive")
        reasons.insert(0, bucket_reason)
    elif bucket == "needs_context_candidate":
        score += 45
        reasons.insert(0, bucket_reason)
    elif bucket == "suspicious_boundary_candidate":
        score += 35
        if predicted_label in {"benign", "benign_unusual"}:
            score += 25
            reasons.insert(0, "suspicious row predicted benign-like")
        reasons.insert(0, bucket_reason)
    else:
        score += 20
        reasons.insert(0, bucket_reason)
    timestamp = log.generated_time or log.receive_time or log.start_time
    return {
        "selection_score": score,
        "bucket": bucket,
        "log_id": log.id,
        "timestamp": timestamp,
        "source": _source_name(log),
        "src_ip": log.src_ip or "",
        "dst_ip": log.dst_ip or "",
        "dst_port": log.dst_port or "",
        "app": log.app or "",
        "action": log.action or "",
        "current_label": label.label if label else "",
        "reviewed_status": bool(label.reviewed) if label else False,
        "rule_evidence": f"rule_score={evidence['rule_score']}",
        "anomaly_score": "" if log.anomaly_score is None else round(float(log.anomaly_score), 6),
        "hybrid_risk": evidence["hybrid_score"],
        "model_prediction": predicted_label,
        "reason_selected": "; ".join(dict.fromkeys(reasons)),
        "evidence_summary": "; ".join(list(dict.fromkeys(reasons))[:5]),
        "human_review_decision": "",
        "human_review_attack_type": label.attack_type if label else "unknown_anomaly",
        "human_review_confidence": label.confidence if label else 3,
        "human_review_note": "",
    }


def build_balanced_recovery_review_sample(db: Session, *, limit: int = 300) -> list[dict[str, Any]]:
    target_plan = [("benign_candidate", 150), ("needs_context_candidate", 50), ("suspicious_boundary_candidate", 75), ("misc_disagreement", 25)]
    if limit != 300:
        scale = limit / 300
        target_plan = [(bucket, max(1, round(count * scale))) for bucket, count in target_plan]
    target_by_bucket = dict(target_plan)
    latest_labels = _latest_labels_by_log(db)
    temporal_coverage = build_class_temporal_coverage(db)
    pools = {
        "benign_candidate": _normal_traffic_candidates(db, limit=max(target_by_bucket.get("benign_candidate", 1) * 3, 200)),
        "needs_context_candidate": _needs_context_candidates(db, limit=max(target_by_bucket.get("needs_context_candidate", 1) * 3, 120)),
        "suspicious_boundary_candidate": _suspicious_boundary_candidates(
            db, limit=max(target_by_bucket.get("suspicious_boundary_candidate", 1) * 3, 180)
        ),
        "misc_disagreement": _large_pool_candidate_logs(
            db,
            limit=max(target_by_bucket.get("misc_disagreement", 1) * 3, 80),
            candidate_pool_limit=max(target_by_bucket.get("misc_disagreement", 1) * 8, 200),
        ),
    }
    reasons = {
        "benign_candidate": "benign gap recovery: normal allowed SSL/QUIC/DNS/web traffic",
        "needs_context_candidate": "needs_context gap recovery: ambiguous or limited evidence",
        "suspicious_boundary_candidate": "suspicious boundary cleanup without malicious-heavy sampling",
        "misc_disagreement": "miscellaneous model/rule/anomaly disagreement",
    }
    selected: list[dict[str, Any]] = []
    used_log_ids: set[int] = set()
    for bucket, target in target_plan:
        rows: list[dict[str, Any]] = []
        for log in pools[bucket]:
            if log.id in used_log_ids:
                continue
            label = latest_labels.get(log.id)
            if label and label.label == "malicious":
                continue
            row = _balanced_review_row(
                db,
                log,
                label,
                bucket=bucket,
                bucket_reason=reasons[bucket],
                temporal_coverage=temporal_coverage,
            )
            if bucket == "benign_candidate" and row["current_label"] not in {"", "benign", "benign_unusual"}:
                continue
            if bucket == "needs_context_candidate" and row["current_label"] == "malicious":
                continue
            rows.append(row)
            if len(rows) >= max(target * 3, target + 20):
                break
        rows.sort(key=lambda row: (int(row["selection_score"]), int(row["hybrid_risk"]), int(row["log_id"])), reverse=True)
        for row in rows[:target]:
            selected.append(row)
            used_log_ids.add(int(row["log_id"]))
    if len(selected) < limit:
        fallback = [
            _balanced_review_row(
                db,
                log,
                latest_labels.get(log.id),
                bucket="fallback_balanced",
                bucket_reason="fallback balanced recovery candidate",
                temporal_coverage=temporal_coverage,
            )
            for log in _normal_traffic_candidates(db, limit=max(limit * 3, 500))
            if log.id not in used_log_ids and (latest_labels.get(log.id) is None or latest_labels[log.id].label != "malicious")
        ]
        fallback.sort(key=lambda row: (int(row["selection_score"]), int(row["log_id"])), reverse=True)
        selected.extend(fallback[: limit - len(selected)])
    return selected[:limit]


def export_balanced_recovery_review_sample_csv(db: Session, *, limit: int = 300) -> str:
    return _balanced_recovery_rows_to_csv(build_balanced_recovery_review_sample(db, limit=limit))


def _balanced_recovery_rows_to_csv(rows: list[dict[str, Any]]) -> str:
    output = StringIO()
    writer = csv.DictWriter(output, fieldnames=BALANCED_RECOVERY_FIELDNAMES)
    writer.writeheader()
    for row in rows:
        serialized = {field: row.get(field, "") for field in BALANCED_RECOVERY_FIELDNAMES}
        timestamp = serialized.get("timestamp")
        if hasattr(timestamp, "isoformat"):
            serialized["timestamp"] = timestamp.isoformat()
        writer.writerow(serialized)
    return output.getvalue()


def write_balanced_recovery_review_sample(
    db: Session,
    *,
    limit: int = 300,
    output_path: str | Path = DEFAULT_BALANCED_RECOVERY_REVIEW_PATH,
) -> dict[str, Any]:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    selected = build_balanced_recovery_review_sample(db, limit=limit)
    csv_text = _balanced_recovery_rows_to_csv(selected)
    path.write_text(csv_text, encoding="utf-8")
    rows = max(0, len(csv_text.splitlines()) - 1)
    bucket_distribution = dict(Counter(str(row.get("bucket") or "unknown") for row in selected))
    return {
        "status": "exported",
        "path": str(path),
        "rows": rows,
        "bucket_distribution": bucket_distribution,
        "strategy": "balanced_recovery",
        "production_promoted": False,
        "response_automation_allowed": False,
    }


def _benign_boundary_candidates(db: Session, *, limit: int) -> list[NormalizedLog]:
    latest_labels = _latest_labels_by_log(db)
    label_logs = [
        label.log
        for label in latest_labels.values()
        if label.log is not None and label.label in {"benign", "benign_unusual"}
    ]
    queried = list(
        db.scalars(
            select(NormalizedLog)
            .options(joinedload(NormalizedLog.raw_log).joinedload(RawLog.source))
            .where(
                NormalizedLog.action == "allow",
                or_(NormalizedLog.app.in_(["ssl", "quic-base", "dns-base", "web-browsing"]), NormalizedLog.dst_port.in_([443, 80, 53])),
            )
            .order_by(desc(NormalizedLog.generated_time), desc(NormalizedLog.id))
            .limit(limit)
        )
    )
    by_id = {log.id: log for log in [*label_logs, *queried] if log is not None}
    return list(by_id.values())[:limit]


def _stage1_review_row(
    db: Session,
    log: NormalizedLog,
    label: MLLabel | None,
    *,
    bucket: str,
    bucket_reason: str,
    temporal_coverage: dict[str, Any],
) -> dict[str, Any]:
    rule_score = _simple_rule_score(log)
    try:
        prediction = predict_supervised_log(db, log.id, rule_score=rule_score)
    except Exception:
        prediction = {"predicted_label": "", "confidence": 0, "class_probabilities": {}, "malicious_probability": 0}
    score, reasons, evidence = _large_pool_score(db, log, label, prediction, temporal_coverage)
    predicted_label = str(evidence.get("predicted_label") or prediction.get("predicted_label") or "")
    class_probabilities = prediction.get("class_probabilities") or {}
    threat_positive_score = float(
        prediction.get("malicious_probability")
        or class_probabilities.get("suspicious", 0) + class_probabilities.get("malicious", 0)
        or 0
    )
    reasons.insert(0, bucket_reason)
    if bucket == "threat_positive_false_negative":
        score += 80
        if label and label.label == "suspicious":
            score += 20
        if predicted_label in {"benign", "benign_unusual", "needs_context"}:
            reasons.insert(0, "Stage 1 false negative: threat-positive label predicted benign-like")
        elif threat_positive_score < 0.5:
            reasons.insert(0, "Stage 1 false negative: low threat-positive score")
    elif bucket == "benign_candidate":
        score += 55
        if predicted_label in {"suspicious", "malicious"}:
            score += 25
            reasons.insert(0, "possible Stage 1 false positive on normal traffic")
    elif bucket == "benign_boundary":
        score += 45
        reasons.insert(0, "benign vs benign_unusual boundary case")
    elif bucket == "needs_context_candidate":
        score += 45
        reasons.insert(0, "needs_context target recovery: ambiguous evidence")
    else:
        score += 20
    timestamp = log.generated_time or log.receive_time or log.start_time
    unique_reasons = list(dict.fromkeys(reasons))
    return {
        "selection_score": int(score),
        "bucket": bucket,
        "log_id": log.id,
        "timestamp": timestamp,
        "source": _source_name(log),
        "src_ip": log.src_ip or "",
        "dst_ip": log.dst_ip or "",
        "dst_port": log.dst_port or "",
        "app": log.app or "",
        "action": log.action or "",
        "current_label": label.label if label else "",
        "reviewed_status": bool(label.reviewed) if label else False,
        "model_prediction": predicted_label,
        "threat_positive_score": round(threat_positive_score, 4),
        "rule_evidence": f"rule_score={evidence['rule_score']}",
        "anomaly_score": "" if log.anomaly_score is None else round(float(log.anomaly_score), 6),
        "hybrid_risk": evidence["hybrid_score"],
        "reason_selected": "; ".join(unique_reasons),
        "evidence_summary": "; ".join(unique_reasons[:5]),
        "human_review_decision": "",
        "human_review_attack_type": label.attack_type if label else "unknown_anomaly",
        "human_review_confidence": label.confidence if label else 3,
        "human_review_note": "",
    }


def build_stage1_threat_recall_review_sample(db: Session, *, limit: int = 300) -> list[dict[str, Any]]:
    target_plan = [
        ("threat_positive_false_negative", 120),
        ("benign_candidate", 80),
        ("benign_boundary", 50),
        ("needs_context_candidate", 30),
        ("misc_disagreement", 20),
    ]
    if limit != 300:
        scale = limit / 300
        target_plan = [(bucket, max(1, round(count * scale))) for bucket, count in target_plan]
    target_by_bucket = dict(target_plan)
    latest_labels = _latest_labels_by_log(db)
    temporal_coverage = build_class_temporal_coverage(db)
    threat_logs = [
        label.log
        for label in latest_labels.values()
        if label.log is not None and label.label in {"suspicious", "malicious"}
    ]
    pools = {
        "threat_positive_false_negative": threat_logs,
        "benign_candidate": _normal_traffic_candidates(db, limit=max(target_by_bucket.get("benign_candidate", 1) * 3, 160)),
        "benign_boundary": _benign_boundary_candidates(db, limit=max(target_by_bucket.get("benign_boundary", 1) * 3, 120)),
        "needs_context_candidate": _needs_context_candidates(db, limit=max(target_by_bucket.get("needs_context_candidate", 1) * 3, 90)),
        "misc_disagreement": _large_pool_candidate_logs(
            db,
            limit=max(target_by_bucket.get("misc_disagreement", 1) * 3, 60),
            candidate_pool_limit=max(target_by_bucket.get("misc_disagreement", 1) * 8, 160),
        ),
    }
    reasons = {
        "threat_positive_false_negative": "Stage 1 recall recovery: current threat-positive row predicted benign-like or low threat-positive",
        "benign_candidate": "benign target recovery: normal SSL/QUIC/DNS/web traffic",
        "benign_boundary": "benign versus benign_unusual boundary review",
        "needs_context_candidate": "needs_context target recovery: ambiguous source/profile or limited parser evidence",
        "misc_disagreement": "miscellaneous Stage 1 rule/anomaly/model disagreement",
    }
    selected: list[dict[str, Any]] = []
    used_log_ids: set[int] = set()
    malicious_cap = max(5, round(limit * 0.18))
    malicious_selected = 0
    for bucket, target in target_plan:
        rows: list[dict[str, Any]] = []
        for log in pools[bucket]:
            if log is None or log.id in used_log_ids:
                continue
            label = latest_labels.get(log.id)
            row = _stage1_review_row(
                db,
                log,
                label,
                bucket=bucket,
                bucket_reason=reasons[bucket],
                temporal_coverage=temporal_coverage,
            )
            current_label = str(row.get("current_label") or "")
            predicted_label = str(row.get("model_prediction") or "")
            threat_positive_score = float(row.get("threat_positive_score") or 0)
            if bucket == "threat_positive_false_negative":
                if current_label not in {"suspicious", "malicious"}:
                    continue
                if predicted_label not in {"benign", "benign_unusual", "needs_context", ""} and threat_positive_score >= 0.5:
                    continue
            elif bucket in {"benign_candidate", "benign_boundary"} and current_label not in {"", "benign", "benign_unusual"}:
                continue
            elif bucket == "needs_context_candidate" and current_label == "malicious":
                continue
            elif bucket == "misc_disagreement" and current_label == "malicious":
                continue
            if current_label == "malicious" and malicious_selected >= malicious_cap:
                continue
            rows.append(row)
            if len(rows) >= max(target * 3, target + 20):
                break
        rows.sort(
            key=lambda row: (
                row.get("current_label") == "suspicious",
                int(row.get("selection_score") or 0),
                int(row.get("hybrid_risk") or 0),
                int(row.get("log_id") or 0),
            ),
            reverse=True,
        )
        for row in rows[:target]:
            selected.append(row)
            used_log_ids.add(int(row["log_id"]))
            if row.get("current_label") == "malicious":
                malicious_selected += 1
    if len(selected) < limit:
        fallback = [
            _stage1_review_row(
                db,
                log,
                latest_labels.get(log.id),
                bucket="fallback_stage1_balanced",
                bucket_reason="fallback Stage 1 balanced recovery candidate",
                temporal_coverage=temporal_coverage,
            )
            for log in _normal_traffic_candidates(db, limit=max(limit * 2, 300))
            if log.id not in used_log_ids and (latest_labels.get(log.id) is None or latest_labels[log.id].label != "malicious")
        ]
        fallback.sort(key=lambda row: (int(row["selection_score"]), int(row["log_id"])), reverse=True)
        selected.extend(fallback[: limit - len(selected)])
    return selected[:limit]


def _stage1_rows_to_csv(rows: list[dict[str, Any]]) -> str:
    output = StringIO()
    writer = csv.DictWriter(output, fieldnames=STAGE1_THREAT_RECALL_FIELDNAMES)
    writer.writeheader()
    for row in rows:
        serialized = {field: row.get(field, "") for field in STAGE1_THREAT_RECALL_FIELDNAMES}
        timestamp = serialized.get("timestamp")
        if hasattr(timestamp, "isoformat"):
            serialized["timestamp"] = timestamp.isoformat()
        writer.writerow(serialized)
    return output.getvalue()


def export_stage1_threat_recall_review_sample_csv(db: Session, *, limit: int = 300) -> str:
    return _stage1_rows_to_csv(build_stage1_threat_recall_review_sample(db, limit=limit))


def write_stage1_threat_recall_review_sample(
    db: Session,
    *,
    limit: int = 300,
    output_path: str | Path = DEFAULT_STAGE1_THREAT_RECALL_REVIEW_PATH,
) -> dict[str, Any]:
    selected = build_stage1_threat_recall_review_sample(db, limit=limit)
    csv_text = _stage1_rows_to_csv(selected)
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(csv_text, encoding="utf-8")
    return {
        "status": "exported",
        "path": str(path),
        "rows": max(0, len(csv_text.splitlines()) - 1),
        "bucket_distribution": dict(Counter(str(row.get("bucket") or "unknown") for row in selected)),
        "label_distribution": dict(Counter(str(row.get("current_label") or "unlabeled") for row in selected)),
        "strategy": "stage1_threat_recall",
        "production_promoted": False,
        "response_automation_allowed": False,
    }


def _benign_gap_row(
    db: Session,
    log: NormalizedLog,
    label: MLLabel | None,
    *,
    bucket: str,
    bucket_reason: str,
    temporal_coverage: dict[str, Any],
) -> dict[str, Any]:
    rule_score = _simple_rule_score(log)
    try:
        prediction = predict_supervised_log(db, log.id, rule_score=rule_score)
    except Exception:
        prediction = {"predicted_label": "", "confidence": 0, "class_probabilities": {}}
    score, reasons, evidence = _large_pool_score(db, log, label, prediction, temporal_coverage)
    class_probabilities = prediction.get("class_probabilities") or {}
    predicted_label = str(evidence.get("predicted_label") or prediction.get("predicted_label") or "")
    benign_probability = float(class_probabilities.get("benign") or 0)
    threat_positive_probability = float(class_probabilities.get("suspicious") or 0) + float(class_probabilities.get("malicious") or 0)
    reasons.insert(0, bucket_reason)
    if bucket == "benign_training_candidate":
        score += 65
        if classify_log_time_window(log, temporal_coverage) == "training_window":
            score += 25
            reasons.insert(0, "training-window benign candidate")
        if predicted_label in {"suspicious", "malicious"}:
            score += 35
            reasons.insert(0, "benign row predicted threat-positive")
    elif bucket == "needs_context_candidate":
        score += 45
        reasons.insert(0, "needs_context target gap")
    elif bucket == "benign_unusual_boundary":
        score += 35
        reasons.insert(0, "benign versus benign_unusual calibration case")
    elif bucket == "benign_suspicious_boundary":
        score += 50
        reasons.insert(0, "benign/suspicious boundary confusion")
    else:
        score += 15
    timestamp = log.generated_time or log.receive_time or log.start_time
    unique_reasons = list(dict.fromkeys(reasons))
    return {
        "selection_score": int(score),
        "bucket": bucket,
        "log_id": log.id,
        "timestamp": timestamp,
        "source": _source_name(log),
        "src_ip": log.src_ip or "",
        "dst_ip": log.dst_ip or "",
        "dst_port": log.dst_port or "",
        "app": log.app or "",
        "action": log.action or "",
        "current_label": label.label if label else "",
        "reviewed_status": bool(label.reviewed) if label else False,
        "model_prediction": predicted_label,
        "benign_probability": round(benign_probability, 4),
        "threat_positive_probability": round(threat_positive_probability, 4),
        "reason_selected": "; ".join(unique_reasons),
        "evidence_summary": "; ".join(unique_reasons[:5]),
        "human_review_decision": "",
        "human_review_attack_type": label.attack_type if label else "normal",
        "human_review_confidence": label.confidence if label else 3,
        "human_review_note": "",
    }


def build_benign_needs_context_final_gap_sample(db: Session, *, limit: int = 100) -> list[dict[str, Any]]:
    target_plan = [
        ("benign_training_candidate", 40),
        ("needs_context_candidate", 20),
        ("benign_unusual_boundary", 20),
        ("benign_suspicious_boundary", 20),
    ]
    if limit != 100:
        scale = limit / 100
        target_plan = [(bucket, max(1, round(count * scale))) for bucket, count in target_plan]
    target_by_bucket = dict(target_plan)
    latest_labels = _latest_labels_by_log(db)
    temporal_coverage = build_class_temporal_coverage(db)
    labeled_logs = [label.log for label in latest_labels.values() if label.log is not None]
    benign_training_pool = [
        log
        for log in [
            *[label.log for label in latest_labels.values() if label.log is not None and label.label in {"benign", "benign_unusual"}],
            *_normal_traffic_candidates(db, limit=max(target_by_bucket.get("benign_training_candidate", 1) * 5, 250)),
        ]
        if log is not None and classify_log_time_window(log, temporal_coverage) == "training_window"
    ]
    benign_suspicious_pool = [
        log
        for log in [
            *[
                label.log
                for label in latest_labels.values()
                if label.log is not None and label.label in {"benign", "benign_unusual", "suspicious"}
            ],
            *_suspicious_boundary_candidates(db, limit=max(target_by_bucket.get("benign_suspicious_boundary", 1) * 5, 160)),
        ]
        if log is not None
    ]
    pools = {
        "benign_training_candidate": benign_training_pool,
        "needs_context_candidate": _needs_context_candidates(db, limit=max(target_by_bucket.get("needs_context_candidate", 1) * 4, 100)),
        "benign_unusual_boundary": [
            log for log in labeled_logs if latest_labels.get(log.id) and latest_labels[log.id].label in {"benign", "benign_unusual"}
        ],
        "benign_suspicious_boundary": benign_suspicious_pool,
    }
    reasons = {
        "benign_training_candidate": "benign target gap: review normal-looking training-window traffic",
        "needs_context_candidate": "needs_context target gap: preserve uncertainty instead of forcing threat labels",
        "benign_unusual_boundary": "benign versus benign_unusual final calibration",
        "benign_suspicious_boundary": "benign-like versus suspicious boundary cleanup",
    }
    selected: list[dict[str, Any]] = []
    used_log_ids: set[int] = set()
    for bucket, target in target_plan:
        rows: list[dict[str, Any]] = []
        for log in pools[bucket]:
            if log is None or log.id in used_log_ids:
                continue
            label = latest_labels.get(log.id)
            current_label = label.label if label else ""
            if current_label == "malicious":
                continue
            if bucket in {"benign_training_candidate", "benign_unusual_boundary"} and current_label not in {"", "benign", "benign_unusual"}:
                continue
            if bucket == "needs_context_candidate" and current_label in {"malicious", "suspicious"}:
                continue
            if bucket == "benign_suspicious_boundary" and current_label not in {"", "benign", "benign_unusual", "suspicious"}:
                continue
            row = _benign_gap_row(
                db,
                log,
                label,
                bucket=bucket,
                bucket_reason=reasons[bucket],
                temporal_coverage=temporal_coverage,
            )
            predicted_label = str(row.get("model_prediction") or "")
            if bucket == "benign_suspicious_boundary" and current_label in {"benign", "benign_unusual"} and predicted_label not in {"suspicious", "malicious"}:
                continue
            if bucket == "benign_suspicious_boundary" and current_label == "suspicious" and predicted_label not in {"benign", "benign_unusual"}:
                continue
            rows.append(row)
            if len(rows) >= max(target * 3, target + 20):
                break
        rows.sort(
            key=lambda row: (
                row.get("current_label") == "benign",
                int(row.get("selection_score") or 0),
                float(row.get("threat_positive_probability") or 0),
                int(row.get("log_id") or 0),
            ),
            reverse=True,
        )
        for row in rows[:target]:
            selected.append(row)
            used_log_ids.add(int(row["log_id"]))
    if len(selected) < limit:
        fallback = [
            _benign_gap_row(
                db,
                log,
                latest_labels.get(log.id),
                bucket="fallback_benign_gap",
                bucket_reason="fallback benign/needs_context final-gap candidate",
                temporal_coverage=temporal_coverage,
            )
            for log in _normal_traffic_candidates(db, limit=max(limit * 4, 300))
            if log.id not in used_log_ids and (latest_labels.get(log.id) is None or latest_labels[log.id].label != "malicious")
        ]
        fallback.sort(key=lambda row: (int(row["selection_score"]), int(row["log_id"])), reverse=True)
        selected.extend(fallback[: limit - len(selected)])
    return selected[:limit]


def _benign_gap_rows_to_csv(rows: list[dict[str, Any]]) -> str:
    output = StringIO()
    writer = csv.DictWriter(output, fieldnames=BENIGN_NEEDS_CONTEXT_FINAL_GAP_FIELDNAMES)
    writer.writeheader()
    for row in rows:
        serialized = {field: row.get(field, "") for field in BENIGN_NEEDS_CONTEXT_FINAL_GAP_FIELDNAMES}
        timestamp = serialized.get("timestamp")
        if hasattr(timestamp, "isoformat"):
            serialized["timestamp"] = timestamp.isoformat()
        writer.writerow(serialized)
    return output.getvalue()


def export_benign_needs_context_final_gap_sample_csv(db: Session, *, limit: int = 100) -> str:
    return _benign_gap_rows_to_csv(build_benign_needs_context_final_gap_sample(db, limit=limit))


def write_benign_needs_context_final_gap_sample(
    db: Session,
    *,
    limit: int = 100,
    output_path: str | Path = DEFAULT_BENIGN_NEEDS_CONTEXT_FINAL_GAP_PATH,
) -> dict[str, Any]:
    selected = build_benign_needs_context_final_gap_sample(db, limit=limit)
    csv_text = _benign_gap_rows_to_csv(selected)
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(csv_text, encoding="utf-8")
    return {
        "status": "exported",
        "path": str(path),
        "rows": max(0, len(csv_text.splitlines()) - 1),
        "bucket_distribution": dict(Counter(str(row.get("bucket") or "unknown") for row in selected)),
        "label_distribution": dict(Counter(str(row.get("current_label") or "unlabeled") for row in selected)),
        "strategy": "benign_needs_context_final_gap",
        "production_promoted": False,
        "response_automation_allowed": False,
    }


def build_final_small_label_gap_sample(db: Session, *, limit: int = 64) -> list[dict[str, Any]]:
    """Build a final small review sample for the remaining benign/needs_context gaps."""
    target_plan = [
        ("benign_training_candidate", 34),
        ("needs_context_candidate", 10),
        ("benign_suspicious_boundary", 20),
    ]
    if limit != 64:
        scale = limit / 64
        target_plan = [(bucket, max(1, round(count * scale))) for bucket, count in target_plan]
    target_by_bucket = dict(target_plan)
    latest_labels = _latest_labels_by_log(db)
    temporal_coverage = build_class_temporal_coverage(db)
    labeled_logs = [label.log for label in latest_labels.values() if label.log is not None]
    pools = {
        "benign_training_candidate": [
            log
            for log in [
                *[label.log for label in latest_labels.values() if label.log is not None and label.label == "benign"],
                *_normal_traffic_candidates(db, limit=max(target_by_bucket.get("benign_training_candidate", 1) * 5, 250)),
            ]
            if log is not None and classify_log_time_window(log, temporal_coverage) == "training_window"
        ],
        "needs_context_candidate": _needs_context_candidates(db, limit=max(target_by_bucket.get("needs_context_candidate", 1) * 5, 120)),
        "benign_suspicious_boundary": [
            *[
                log
                for log in labeled_logs
                if log is not None
                and latest_labels.get(log.id)
                and latest_labels[log.id].label in {"benign", "benign_unusual", "suspicious"}
            ],
            *_suspicious_boundary_candidates(db, limit=max(target_by_bucket.get("benign_suspicious_boundary", 1) * 5, 160)),
        ],
    }
    reasons = {
        "benign_training_candidate": "final benign gap: review normal-looking training-window traffic",
        "needs_context_candidate": "final needs_context gap: preserve uncertainty where evidence is ambiguous",
        "benign_suspicious_boundary": "final benign/suspicious boundary check without malicious-heavy sampling",
    }
    selected: list[dict[str, Any]] = []
    used_log_ids: set[int] = set()
    for bucket, target in target_plan:
        rows: list[dict[str, Any]] = []
        for log in pools[bucket]:
            if log is None or log.id in used_log_ids:
                continue
            label = latest_labels.get(log.id)
            current_label = label.label if label else ""
            if current_label == "malicious":
                continue
            if bucket == "benign_training_candidate" and current_label not in {"", "benign"}:
                continue
            if bucket == "needs_context_candidate" and current_label in {"malicious", "suspicious"}:
                continue
            if bucket == "benign_suspicious_boundary" and current_label not in {"", "benign", "benign_unusual", "suspicious"}:
                continue
            row = _benign_gap_row(
                db,
                log,
                label,
                bucket=bucket,
                bucket_reason=reasons[bucket],
                temporal_coverage=temporal_coverage,
            )
            rows.append(row)
            if len(rows) >= max(target * 3, target + 20):
                break
        rows.sort(
            key=lambda row: (
                row.get("current_label") in {"benign", "needs_context"},
                int(row.get("selection_score") or 0),
                float(row.get("threat_positive_probability") or 0),
                int(row.get("log_id") or 0),
            ),
            reverse=True,
        )
        for row in rows[:target]:
            selected.append(row)
            used_log_ids.add(int(row["log_id"]))
    if len(selected) < limit:
        fallback = [
            _benign_gap_row(
                db,
                log,
                latest_labels.get(log.id),
                bucket="fallback_final_small_gap",
                bucket_reason="fallback final benign/needs_context review candidate",
                temporal_coverage=temporal_coverage,
            )
            for log in _normal_traffic_candidates(db, limit=max(limit * 4, 300))
            if log.id not in used_log_ids and (latest_labels.get(log.id) is None or latest_labels[log.id].label != "malicious")
        ]
        fallback.sort(key=lambda row: (int(row["selection_score"]), int(row["log_id"])), reverse=True)
        selected.extend(fallback[: limit - len(selected)])
    return selected[:limit]


def export_final_small_label_gap_sample_csv(db: Session, *, limit: int = 64) -> str:
    return _benign_gap_rows_to_csv(build_final_small_label_gap_sample(db, limit=limit))


def write_final_small_label_gap_sample(
    db: Session,
    *,
    limit: int = 64,
    output_path: str | Path = DEFAULT_FINAL_SMALL_LABEL_GAP_PATH,
) -> dict[str, Any]:
    selected = build_final_small_label_gap_sample(db, limit=limit)
    csv_text = _benign_gap_rows_to_csv(selected)
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(csv_text, encoding="utf-8")
    return {
        "status": "exported",
        "path": str(path),
        "rows": max(0, len(csv_text.splitlines()) - 1),
        "bucket_distribution": dict(Counter(str(row.get("bucket") or "unknown") for row in selected)),
        "label_distribution": dict(Counter(str(row.get("current_label") or "unlabeled") for row in selected)),
        "strategy": "final_small_label_gap",
        "production_promoted": False,
        "response_automation_allowed": False,
    }


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
