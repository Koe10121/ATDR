import csv
from io import StringIO
from pathlib import Path
from typing import Any

from sqlalchemy import desc, select
from sqlalchemy.orm import Session, joinedload

from atdr.app.db.models import MLLabel
from atdr.app.ml.features import build_log_features


DEFAULT_LABEL_QUALITY_PATH = Path("ml_baseline_reviews/label_quality_issues.csv")

FIELDNAMES = [
    "issue_group",
    "issue_type",
    "severity",
    "label_id",
    "log_id",
    "src_ip",
    "dst_ip",
    "app",
    "dst_port",
    "action",
    "current_label",
    "current_attack_type",
    "reviewed",
    "label_source",
    "issue_reason",
    "evidence_summary",
    "suggested_review_focus",
    "human_review_decision",
    "human_review_attack_type",
    "human_review_confidence",
    "human_review_note",
]


def _latest_labels(db: Session) -> list[MLLabel]:
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
    return list(latest.values())


def _basic_risk_evidence(label: MLLabel) -> tuple[int, list[str]]:
    log = label.log
    if log is None:
        return 0, ["missing normalized log"]
    score = 0
    evidence: list[str] = []
    action = (log.action or "").lower()
    app = (log.app or "").lower()
    if any(token in action for token in ["deny", "drop", "reset"]):
        score += 25
        evidence.append(f"action={log.action}")
    if log.is_anomaly:
        score += 25
        evidence.append("IsolationForest anomaly")
    if (log.app_risk or 0) >= 4:
        score += 20
        evidence.append(f"app risk {log.app_risk}")
    if app in {"unknown", "unknown-tcp", "unknown-udp", "incomplete"}:
        score += 15
        evidence.append("unknown/incomplete app")
    return min(score, 100), evidence


def build_label_quality_issues(db: Session, *, limit: int = 500) -> list[dict[str, Any]]:
    labels = _latest_labels(db)
    issues: list[dict[str, Any]] = []
    action_app_port_map: dict[tuple[Any, ...], list[MLLabel]] = {}
    src_ip_map: dict[str, list[MLLabel]] = {}
    dst_port_map: dict[Any, list[MLLabel]] = {}
    scan_pattern_map: dict[tuple[Any, ...], list[MLLabel]] = {}
    for label in labels:
        log = label.log
        if log is None:
            continue
        action_app_port_pattern = (log.src_ip, log.app, log.action, log.dst_port)
        action_app_port_map.setdefault(action_app_port_pattern, []).append(label)
        if log.src_ip:
            src_ip_map.setdefault(str(log.src_ip), []).append(label)
        if log.dst_port is not None:
            dst_port_map.setdefault(log.dst_port, []).append(label)
        risk_score, evidence = _basic_risk_evidence(label)
        if label.label == "malicious" and risk_score < 35:
            issues.append(
                _issue(
                    "malicious_without_strong_evidence",
                    "malicious_without_strong_evidence",
                    "high",
                    label,
                    "Label says malicious, but rule/anomaly/app-risk evidence is weak.",
                    evidence or ["low rule/anomaly/app-risk evidence"],
                    "Recheck this malicious label; confirm evidence before using it for model validation.",
                )
            )
        if label.label in {"benign", "benign_unusual"} and risk_score >= 45:
            issues.append(
                _issue(
                    "benign_despite_strong_risk_evidence",
                    "benign_despite_high_risk_evidence",
                    "medium",
                    label,
                    "Label says benign/benign_unusual, but detection evidence is high risk.",
                    evidence,
                    "Recheck whether this is truly benign or should be suspicious/needs_context.",
                )
            )
        try:
            features = build_log_features(db, log)
        except Exception:
            features = {}
        if int(features.get("scanning_like_behavior_score") or 0) >= 60 and label.label not in {"suspicious", "malicious", "needs_context"}:
            scan_pattern_map.setdefault((log.src_ip, log.action, log.app), []).append(label)
            issues.append(
                _issue(
                    "scan_like_behavior_inconsistent",
                    "scan_pattern_labeled_low_risk",
                    "medium",
                    label,
                    "Behavior-window features look scanning-like, but label is low risk.",
                    [f"scanning_like_behavior_score={features.get('scanning_like_behavior_score')}"],
                    "Review repeated destination-port behavior and consider suspicious/needs_context.",
                )
            )
    issues.extend(
        _group_inconsistency_issues(
            action_app_port_map,
            issue_group="action_app_port_pattern",
            issue_type="inconsistent_same_action_app_port_pattern",
            pattern_label="src/app/action/port",
            recommendation="Review labels for this repeated source/app/action/port pattern.",
        )
    )
    issues.extend(
        _group_inconsistency_issues(
            src_ip_map,
            issue_group="same_source_ip_inconsistent_labels",
            issue_type="same_source_ip_inconsistent_labels",
            pattern_label="src_ip",
            recommendation="Review whether this source IP has mixed behavior or inconsistent labels.",
        )
    )
    issues.extend(
        _group_inconsistency_issues(
            dst_port_map,
            issue_group="same_destination_port_inconsistent_labels",
            issue_type="same_destination_port_inconsistent_labels",
            pattern_label="dst_port",
            recommendation="Review whether destination-port labels are consistent for this traffic pattern.",
        )
    )
    issues.extend(
        _group_inconsistency_issues(
            scan_pattern_map,
            issue_group="scan_like_behavior_inconsistent",
            issue_type="scan_like_behavior_inconsistently_labeled",
            pattern_label="src/action/app",
            recommendation="Review scan-like behavior and align labels across repeated attempts.",
        )
    )
    issues.sort(key=lambda row: {"high": 3, "medium": 2, "low": 1}.get(str(row["severity"]), 0), reverse=True)
    return issues[:limit]


def _group_inconsistency_issues(
    grouped_items: dict[Any, list[MLLabel]],
    *,
    issue_group: str,
    issue_type: str,
    pattern_label: str,
    recommendation: str,
) -> list[dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    for pattern, grouped in grouped_items.items():
        if len(grouped) < 2:
            continue
        grouped_labels = sorted({label.label for label in grouped})
        if len(grouped_labels) < 2:
            continue
        reviewed_count = sum(1 for label in grouped if label.reviewed)
        evidence = [f"{pattern_label}={pattern}", f"labels={','.join(grouped_labels)}", f"group_count={len(grouped)}"]
        for label in grouped[:5]:
            issues.append(
                _issue(
                    issue_group,
                    issue_type,
                    "medium" if reviewed_count else "low",
                    label,
                    "Same pattern has multiple labels.",
                    evidence,
                    recommendation,
                )
            )
    return issues


def _issue(
    issue_group: str,
    issue_type: str,
    severity: str,
    label: MLLabel,
    issue_reason: str,
    evidence: list[str],
    recommendation: str,
) -> dict[str, Any]:
    log = label.log
    return {
        "issue_group": issue_group,
        "issue_type": issue_type,
        "severity": severity,
        "label_id": label.id,
        "log_id": label.log_id,
        "src_ip": getattr(log, "src_ip", None),
        "dst_ip": getattr(log, "dst_ip", None),
        "app": getattr(log, "app", None),
        "dst_port": getattr(log, "dst_port", None),
        "action": getattr(log, "action", None),
        "current_label": label.label,
        "current_attack_type": label.attack_type,
        "reviewed": label.reviewed,
        "label_source": label.label_source,
        "issue_reason": issue_reason,
        "evidence_summary": "; ".join(evidence),
        "suggested_review_focus": recommendation,
        "human_review_decision": "",
        "human_review_attack_type": "",
        "human_review_confidence": "",
        "human_review_note": "",
    }


def export_label_quality_issues_csv(db: Session, *, limit: int = 500) -> str:
    output = StringIO()
    writer = csv.DictWriter(output, fieldnames=FIELDNAMES)
    writer.writeheader()
    for row in build_label_quality_issues(db, limit=limit):
        writer.writerow(row)
    return output.getvalue()


def write_label_quality_issues(db: Session, *, limit: int = 500, output_path: str | Path = DEFAULT_LABEL_QUALITY_PATH) -> dict[str, Any]:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    csv_text = export_label_quality_issues_csv(db, limit=limit)
    path.write_text(csv_text, encoding="utf-8")
    rows = max(0, len(csv_text.splitlines()) - 1)
    return {"status": "exported", "path": str(path), "rows": rows}
