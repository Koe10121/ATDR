import csv
from dataclasses import dataclass
from io import StringIO
from typing import Any

from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session, joinedload

from atdr.app.db.models import Alert, AlertEvidence, AuditLog, MLLabel, NormalizedLog
from atdr.app.detection.hybrid_scoring import hybrid_risk_score
from atdr.app.ml.features import build_log_features

NORMAL_PORTS = {53, 80, 123, 443, 853, 993, 995}
NORMAL_APPS = {
    "ssl",
    "web-browsing",
    "dns",
    "dns-base",
    "quic-base",
    "ping",
    "gmail-base",
    "google-base",
    "facebook-base",
    "tiktok-base",
    "naver-line",
    "apple-maps",
}
UNKNOWN_APPS = {"unknown", "unknown-tcp", "unknown-udp", "incomplete", "not-applicable"}
DENY_ACTIONS = {"deny", "drop", "reset-both", "reset-client", "reset-server"}


@dataclass(slots=True)
class AssistedDecision:
    log_id: int
    label: str
    attack_type: str
    confidence: int
    label_source: str
    reviewed: bool
    review_note: str
    rule_score: int
    hybrid_risk_score: float
    anomaly_score: float | None
    is_anomaly: bool
    src_ip: str | None
    dst_ip: str | None
    app: str | None
    action: str | None
    app_risk: int | None
    applied: bool = False
    skipped_reason: str | None = None


def _latest_labels_by_log(db: Session) -> dict[int, MLLabel]:
    labels = list(db.scalars(select(MLLabel).order_by(MLLabel.log_id, desc(MLLabel.created_at), desc(MLLabel.id))))
    latest: dict[int, MLLabel] = {}
    for label in labels:
        latest.setdefault(label.log_id, label)
    return latest


def _alert_context(db: Session, log_ids: list[int]) -> dict[int, dict[str, Any]]:
    if not log_ids:
        return {}
    rows = db.execute(
        select(AlertEvidence.normalized_log_id, Alert.id, Alert.threat_score, Alert.alert_type, Alert.severity)
        .join(Alert, Alert.id == AlertEvidence.alert_id)
        .where(AlertEvidence.normalized_log_id.in_(log_ids))
    ).all()
    context: dict[int, dict[str, Any]] = {}
    for log_id, alert_id, threat_score, alert_type, severity in rows:
        item = context.setdefault(int(log_id), {"rule_score": 0, "alert_ids": [], "alert_types": set(), "severities": set()})
        item["rule_score"] = max(int(item["rule_score"]), int(threat_score or 0))
        item["alert_ids"].append(int(alert_id))
        item["alert_types"].add(str(alert_type))
        item["severities"].add(str(severity))
    return context


def _choose_attack_type(log: NormalizedLog, features: dict[str, Any], rule_score: int) -> str:
    app = (log.app or "").lower()
    action = (log.action or "").lower()
    dst_port = int(log.dst_port or 0)
    unique_ports = int(features.get("src_ip_5min_unique_dst_ports") or 0)
    deny_count = int(features.get("src_ip_5min_deny_count") or 0)
    total_bytes = int(features.get("src_ip_5min_total_bytes") or 0)
    if unique_ports >= 12:
        return "port_scan"
    if action in DENY_ACTIONS and dst_port in {22, 23, 3389, 445, 1433, 3306} and deny_count >= 3:
        return "brute_force"
    if features.get("dst_ip_5min_connection_count", 0) >= 200 or deny_count >= 100:
        return "dos_ddos"
    if app in UNKNOWN_APPS and log.is_anomaly and rule_score >= 60:
        return "malware_c2"
    if total_bytes >= 50_000_000 and action == "allow":
        return "data_exfiltration_suspicion"
    if action in DENY_ACTIONS or (log.app_risk or 0) >= 4:
        return "policy_violation"
    if log.is_anomaly:
        return "unknown_anomaly"
    return "normal"


def _decision_for_log(log: NormalizedLog, features: dict[str, Any], alert_info: dict[str, Any] | None) -> AssistedDecision:
    action = (log.action or "").lower()
    app = (log.app or "").lower()
    app_risk = int(log.app_risk or 0)
    rule_score = int((alert_info or {}).get("rule_score", 0))
    hybrid = hybrid_risk_score(
        rule_score=rule_score,
        isolation_anomaly_score=log.anomaly_score,
        isolation_is_anomaly=log.is_anomaly,
        supervised_malicious_probability=0,
    )
    hybrid_score = float(hybrid["final_risk_score"])
    unique_ports = int(features.get("src_ip_5min_unique_dst_ports") or 0)
    deny_count = int(features.get("src_ip_5min_deny_count") or 0)
    unknown_count = int(features.get("src_ip_5min_unknown_app_count") or 0)
    high_risk_count = int(features.get("src_ip_5min_high_risk_app_count") or 0)
    total_bytes = int(features.get("src_ip_5min_total_bytes") or 0)
    dst_port = int(log.dst_port or 0)
    reasons: list[str] = []

    strong_repeated = unique_ports >= 20 or deny_count >= 20 or high_risk_count >= 10
    very_high_evidence = rule_score >= 80 and log.is_anomaly and strong_repeated
    if very_high_evidence:
        label = "malicious"
        confidence = 5
        label_source = "assisted_hybrid"
        reasons.append("rule alert plus anomaly plus repeated suspicious window behavior")
    elif rule_score >= 60 or action in DENY_ACTIONS or app_risk >= 4 or unknown_count >= 2 or unique_ports >= 8 or log.is_anomaly:
        label = "suspicious"
        confidence = 4 if rule_score >= 60 or (log.is_anomaly and (app_risk >= 4 or unique_ports >= 8)) else 3
        rule_like_signal = bool(rule_score or action in DENY_ACTIONS or app_risk >= 4 or unknown_count >= 2 or unique_ports >= 8)
        label_source = "assisted_hybrid" if log.is_anomaly and rule_like_signal else "assisted_rule" if rule_like_signal else "assisted_ml"
        if rule_score:
            reasons.append(f"rule_score={rule_score}")
        if action in DENY_ACTIONS:
            reasons.append(f"action={action}")
        if app_risk >= 4:
            reasons.append(f"app_risk={app_risk}")
        if app in UNKNOWN_APPS:
            reasons.append(f"app={app}")
        if unknown_count >= 2:
            reasons.append(f"{unknown_count} unknown/incomplete app events in 5 minutes")
        if high_risk_count >= 2:
            reasons.append(f"{high_risk_count} high-risk app events in 5 minutes")
        if log.is_anomaly:
            reasons.append("anomaly=true")
        if unique_ports >= 8:
            reasons.append(f"src_ip touched {unique_ports} unique destination ports in 5 minutes")
        if deny_count:
            reasons.append(f"{deny_count} deny/drop/reset events in 5 minutes")
    elif action == "allow" and app_risk <= 3 and not log.is_anomaly and dst_port in NORMAL_PORTS and (not app or app in NORMAL_APPS):
        label = "benign"
        confidence = 4 if hybrid_score < 15 else 3
        label_source = "assisted_rule"
        reasons.append("allowed low-risk common application/port with no anomaly or alert evidence")
    elif action == "allow" and (total_bytes >= 20_000_000 or dst_port not in NORMAL_PORTS or app not in NORMAL_APPS or hybrid_score >= 20):
        label = "benign_unusual"
        confidence = 3
        label_source = "assisted_hybrid" if hybrid_score >= 20 else "assisted_rule"
        if total_bytes >= 20_000_000:
            reasons.append(f"high 5-minute byte volume={total_bytes}")
        if dst_port not in NORMAL_PORTS:
            reasons.append(f"unusual destination port={dst_port}")
        if app not in NORMAL_APPS:
            reasons.append(f"less-common app={app or 'unknown'}")
        if hybrid_score >= 20:
            reasons.append(f"moderate hybrid risk={hybrid_score}")
    else:
        label = "needs_context"
        confidence = 2
        label_source = "assisted_hybrid"
        reasons.append("evidence is not strong enough for a reliable assisted label")

    attack_type = "normal" if label in {"benign", "benign_unusual"} else _choose_attack_type(log, features, rule_score)
    note = (
        f"Assisted label: {label} because {', '.join(reasons)}. "
        f"hybrid_risk={hybrid_score}, anomaly={log.is_anomaly}, anomaly_score={log.anomaly_score}. "
        "Weak label: review before treating as ground truth."
    )
    return AssistedDecision(
        log_id=log.id,
        label=label,
        attack_type=attack_type,
        confidence=confidence,
        label_source=label_source,
        reviewed=False,
        review_note=note,
        rule_score=rule_score,
        hybrid_risk_score=hybrid_score,
        anomaly_score=log.anomaly_score,
        is_anomaly=log.is_anomaly,
        src_ip=log.src_ip,
        dst_ip=log.dst_ip,
        app=log.app,
        action=log.action,
        app_risk=log.app_risk,
    )


def _decision_to_dict(decision: AssistedDecision) -> dict[str, Any]:
    return {
        "log_id": decision.log_id,
        "label": decision.label,
        "attack_type": decision.attack_type,
        "confidence": decision.confidence,
        "label_source": decision.label_source,
        "reviewed": decision.reviewed,
        "review_note": decision.review_note,
        "rule_score": decision.rule_score,
        "hybrid_risk_score": decision.hybrid_risk_score,
        "anomaly_score": decision.anomaly_score,
        "is_anomaly": decision.is_anomaly,
        "src_ip": decision.src_ip,
        "dst_ip": decision.dst_ip,
        "app": decision.app,
        "action": decision.action,
        "app_risk": decision.app_risk,
        "applied": decision.applied,
        "skipped_reason": decision.skipped_reason,
    }


def export_assisted_preview_csv(decisions: list[AssistedDecision]) -> str:
    output = StringIO()
    fieldnames = [
        "log_id",
        "label",
        "attack_type",
        "confidence",
        "label_source",
        "reviewed",
        "rule_score",
        "hybrid_risk_score",
        "is_anomaly",
        "anomaly_score",
        "src_ip",
        "dst_ip",
        "app",
        "action",
        "app_risk",
        "applied",
        "skipped_reason",
        "review_note",
    ]
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    for decision in decisions:
        writer.writerow(_decision_to_dict(decision))
    return output.getvalue()


def generate_assisted_labels(
    db: Session,
    *,
    limit: int = 1000,
    apply: bool = False,
    reviewer: str = "codex_assisted",
    min_confidence: int = 3,
    overwrite: bool = False,
    only_unlabeled: bool = True,
) -> dict:
    statement = select(NormalizedLog).options(joinedload(NormalizedLog.raw_log)).order_by(desc(NormalizedLog.id)).limit(limit)
    logs = list(db.scalars(statement))
    latest_labels = _latest_labels_by_log(db)
    alert_context = _alert_context(db, [log.id for log in logs])
    decisions: list[AssistedDecision] = []
    created = 0
    updated = 0
    skipped = 0

    for log in logs:
        existing = latest_labels.get(log.id)
        if only_unlabeled and existing is not None:
            skipped += 1
            decision = _decision_for_log(log, build_log_features(db, log), alert_context.get(log.id))
            decision.skipped_reason = "already_labeled"
            decisions.append(decision)
            continue
        decision = _decision_for_log(log, build_log_features(db, log), alert_context.get(log.id))
        if decision.confidence < min_confidence:
            skipped += 1
            decision.skipped_reason = f"confidence_below_{min_confidence}"
            decisions.append(decision)
            continue
        if apply:
            if existing is not None and overwrite:
                existing.label = decision.label
                existing.attack_type = decision.attack_type
                existing.confidence = decision.confidence
                existing.reviewer = reviewer
                existing.review_note = decision.review_note
                existing.label_source = decision.label_source
                existing.reviewed = False
                updated += 1
                decision.applied = True
            elif existing is None:
                db.add(
                    MLLabel(
                        log_id=log.id,
                        label=decision.label,
                        attack_type=decision.attack_type,
                        confidence=decision.confidence,
                        reviewer=reviewer,
                        review_note=decision.review_note,
                        label_source=decision.label_source,
                        reviewed=False,
                    )
                )
                created += 1
                decision.applied = True
            else:
                skipped += 1
                decision.skipped_reason = "existing_label_not_overwritten"
        decisions.append(decision)

    if apply:
        db.add(
            AuditLog(
                actor=reviewer,
                action="generate_assisted_labels",
                target_type="ml_labels",
                target_value="latest_logs",
                details={
                    "limit": limit,
                    "created": created,
                    "updated": updated,
                    "skipped": skipped,
                    "min_confidence": min_confidence,
                    "overwrite": overwrite,
                    "only_unlabeled": only_unlabeled,
                    "warning": "Assisted labels are weak labels and require human review before final model-performance claims.",
                },
            )
        )
        db.commit()

    distribution: dict[str, int] = {}
    for decision in decisions:
        if decision.applied or not apply:
            distribution[decision.label] = distribution.get(decision.label, 0) + 1

    return {
        "mode": "apply" if apply else "dry_run",
        "created": created,
        "updated": updated,
        "skipped": skipped,
        "candidate_count": len(decisions),
        "distribution": distribution,
        "min_confidence": min_confidence,
        "overwrite": overwrite,
        "only_unlabeled": only_unlabeled,
        "reviewer": reviewer,
        "warning": "Assisted labels are weak labels. Review a sample before claiming supervised model performance.",
        "decisions": [_decision_to_dict(decision) for decision in decisions],
        "csv": export_assisted_preview_csv(decisions),
    }


def export_label_review_sample(db: Session, *, output_per_label: dict[str, int] | None = None) -> str:
    quotas = output_per_label or {"benign": 15, "benign_unusual": 10, "suspicious": 15, "malicious": 5, "needs_context": 5}
    output = StringIO()
    fieldnames = [
        "label_id",
        "log_id",
        "label",
        "attack_type",
        "confidence",
        "label_source",
        "reviewed",
        "reviewer",
        "src_ip",
        "dst_ip",
        "app",
        "action",
        "app_risk",
        "is_anomaly",
        "anomaly_score",
        "human_review_decision",
        "human_review_note",
        "assisted_review_note",
        "raw_evidence_excerpt",
    ]
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    for label, quota in quotas.items():
        rows = list(
            db.scalars(
                select(MLLabel)
                .options(joinedload(MLLabel.log).joinedload(NormalizedLog.raw_log))
                .where(MLLabel.label == label)
                .order_by(MLLabel.reviewed.asc(), desc(MLLabel.confidence), desc(MLLabel.created_at))
                .limit(quota)
            )
        )
        for item in rows:
            log = item.log
            writer.writerow(
                {
                    "label_id": item.id,
                    "log_id": item.log_id,
                    "label": item.label,
                    "attack_type": item.attack_type,
                    "confidence": item.confidence,
                    "label_source": item.label_source,
                    "reviewed": item.reviewed,
                    "reviewer": item.reviewer,
                    "src_ip": log.src_ip if log else "",
                    "dst_ip": log.dst_ip if log else "",
                    "app": log.app if log else "",
                    "action": log.action if log else "",
                    "app_risk": log.app_risk if log else "",
                    "is_anomaly": log.is_anomaly if log else "",
                    "anomaly_score": log.anomaly_score if log else "",
                    "human_review_decision": "",
                    "human_review_note": "",
                    "assisted_review_note": item.review_note or "",
                    "raw_evidence_excerpt": (log.raw_log.raw_line[:500] if log and log.raw_log else ""),
                }
            )
    return output.getvalue()
