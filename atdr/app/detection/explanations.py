from typing import Any

from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from atdr.app.db.models import Alert, MLLabel, NormalizedLog
from atdr.app.detection.attack_mapping import attack_mapping_for_type, infer_attack_type_from_rules
from atdr.app.detection.hybrid_scoring import hybrid_risk_score
from atdr.app.detection.supervised_detector import predict_supervised_log
from atdr.app.ml.features import build_log_features


BEHAVIOR_EXPLANATION_FEATURES = [
    "src_ip_5min_log_count",
    "src_ip_5min_deny_count",
    "src_ip_5min_unique_dst_ports",
    "src_ip_5min_unique_dst_ips",
    "deny_rate_5min",
    "src_ip_15min_event_count",
    "src_ip_1h_event_count",
    "src_ip_24h_event_count",
    "dst_ip_5min_event_count",
    "rare_dst_port_flag",
    "rare_app_flag",
    "unknown_app_flag",
    "external_to_internal_flag",
    "internal_to_external_flag",
    "first_seen_src_ip_flag",
    "first_seen_app_flag",
    "repeated_connection_attempts",
    "scanning_like_behavior_score",
]


def compact_behavior_features(db: Session, log: NormalizedLog) -> dict[str, Any]:
    try:
        features = build_log_features(db, log)
    except Exception as exc:
        return {"available": False, "error": str(exc)}
    return {"available": True, **{key: features.get(key) for key in BEHAVIOR_EXPLANATION_FEATURES}}


def _latest_label_by_log(db: Session, log_ids: list[int]) -> dict[int, MLLabel]:
    if not log_ids:
        return {}
    rows = db.scalars(
        select(MLLabel)
        .where(MLLabel.log_id.in_(log_ids))
        .order_by(MLLabel.log_id, desc(MLLabel.created_at), desc(MLLabel.id))
    ).all()
    latest: dict[int, MLLabel] = {}
    for row in rows:
        latest.setdefault(row.log_id, row)
    return latest


def _primary_attack_type(alert: Alert, labels: dict[int, MLLabel]) -> str:
    for label in labels.values():
        if label.attack_type and label.attack_type != "normal":
            return label.attack_type
    return infer_attack_type_from_rules(alert.matched_rules_json or [])


def build_alert_detection_summary(db: Session, alert: Alert) -> dict[str, Any]:
    evidence_logs = [item.normalized_log for item in alert.evidence if item.normalized_log is not None]
    if not evidence_logs:
        evidence_logs = [db.get(NormalizedLog, item.normalized_log_id) for item in alert.evidence]
        evidence_logs = [item for item in evidence_logs if item is not None]
    evidence_logs = evidence_logs[:25]
    primary_log = evidence_logs[0] if evidence_logs else None
    evidence_ids = [log.id for log in evidence_logs]
    labels = _latest_label_by_log(db, evidence_ids)
    attack_type = _primary_attack_type(alert, labels)
    mapping = attack_mapping_for_type(attack_type)
    rule_matches = [rule for rule in (alert.matched_rules_json or []) if rule.get("code") != "group_metadata"]
    anomaly_logs = [log for log in evidence_logs if log.is_anomaly]
    anomaly_scores = [float(log.anomaly_score) for log in evidence_logs if log.anomaly_score is not None]
    supervised: dict[str, Any] = {"predicted_label": None, "malicious_probability": 0.0, "confidence": 0.0}
    if primary_log is not None:
        try:
            supervised = predict_supervised_log(db, primary_log.id, rule_score=alert.threat_score)
        except Exception:
            supervised = {"predicted_label": None, "malicious_probability": 0.0, "confidence": 0.0}
    hybrid = supervised.get("hybrid_risk") if supervised.get("hybrid_risk") else hybrid_risk_score(
        rule_score=alert.threat_score,
        isolation_anomaly_score=primary_log.anomaly_score if primary_log else None,
        isolation_is_anomaly=bool(primary_log and primary_log.is_anomaly),
        supervised_malicious_probability=float(supervised.get("malicious_probability") or 0),
    )
    behavior = compact_behavior_features(db, primary_log) if primary_log is not None else {"available": False}

    detection_sources: list[str] = []
    if any(rule.get("code") not in {"ml_anomaly_detected", "group_metadata"} for rule in rule_matches):
        detection_sources.append("rule")
    if anomaly_logs or any(rule.get("code") == "ml_anomaly_detected" for rule in rule_matches):
        detection_sources.append("anomaly")
    if supervised.get("predicted_label"):
        detection_sources.append("supervised")
    detection_sources.append("hybrid")
    detection_sources = list(dict.fromkeys(detection_sources))

    evidence_points: list[str] = []
    for rule in rule_matches[:4]:
        title = rule.get("title") or rule.get("code")
        explanation = rule.get("explanation")
        evidence_points.append(f"{title}: {explanation}" if explanation else str(title))
    if behavior.get("src_ip_5min_deny_count"):
        evidence_points.append(f"Source had {behavior['src_ip_5min_deny_count']} deny/drop/reset events in 5 minutes.")
    if behavior.get("src_ip_5min_unique_dst_ports"):
        evidence_points.append(f"Source touched {behavior['src_ip_5min_unique_dst_ports']} unique destination ports in 5 minutes.")
    if behavior.get("src_ip_5min_unique_dst_ips"):
        evidence_points.append(f"Source reached {behavior['src_ip_5min_unique_dst_ips']} unique destination IPs in 5 minutes.")
    if behavior.get("repeated_connection_attempts"):
        evidence_points.append(f"Repeated connection attempts observed: {behavior['repeated_connection_attempts']}.")
    if behavior.get("scanning_like_behavior_score"):
        evidence_points.append(f"Scanning-like behavior score is {behavior['scanning_like_behavior_score']}.")
    if behavior.get("rare_dst_port_flag"):
        evidence_points.append("Destination port is rare for the current dataset.")
    if behavior.get("rare_app_flag"):
        evidence_points.append("Application is rare for the current dataset.")
    if behavior.get("unknown_app_flag"):
        evidence_points.append("Application is unknown or incomplete.")
    if behavior.get("external_to_internal_flag"):
        evidence_points.append("Traffic direction is external to internal.")
    elif behavior.get("internal_to_external_flag"):
        evidence_points.append("Traffic direction is internal to external.")
    if anomaly_scores:
        evidence_points.append(f"IsolationForest anomaly score range: {round(min(anomaly_scores), 6)} to {round(max(anomaly_scores), 6)}.")
    if supervised.get("predicted_label"):
        evidence_points.append(
            f"Supervised triage predicted {supervised.get('predicted_label')} with confidence {supervised.get('confidence', 0.0)}."
        )

    why = "Flagged for analyst review because "
    if evidence_points:
        why += "; ".join(evidence_points[:4])
    else:
        why += alert.explanation
    if not why.endswith("."):
        why += "."

    return {
        "detection_source": detection_sources,
        "attack_type": attack_type,
        "attack_mapping": mapping,
        "matched_rule_names": [str(rule.get("title") or rule.get("code")) for rule in rule_matches],
        "anomaly": {
            "present": bool(anomaly_logs),
            "count": len(anomaly_logs),
            "min_score": round(min(anomaly_scores), 6) if anomaly_scores else None,
            "max_score": round(max(anomaly_scores), 6) if anomaly_scores else None,
        },
        "supervised": {
            "predicted_label": supervised.get("predicted_label"),
            "malicious_probability": supervised.get("malicious_probability", 0.0),
            "confidence": supervised.get("confidence", 0.0),
            "decision_support_only": True,
        },
        "hybrid_risk": hybrid,
        "behavior_window": behavior,
        "top_evidence_points": evidence_points[:8],
        "why_flagged": why,
    }
