import csv
from io import StringIO
from typing import Any

from sqlalchemy import desc, or_, select
from sqlalchemy.orm import Session, joinedload

from atdr.app.db.models import Alert, AlertEvidence, AuditLog, MLLabel, NormalizedLog
from atdr.app.detection.hybrid_scoring import hybrid_risk_score
from atdr.app.detection.supervised_detector import predict_supervised_log
from atdr.app.schemas.ml import MLLabelCreate, MLLabelUpdate

CSV_FIELDNAMES = [
    "id",
    "log_id",
    "label",
    "attack_type",
    "confidence",
    "reviewer",
    "label_source",
    "reviewed",
    "review_note",
    "created_at",
]
CSV_TEMPLATE_FIELDNAMES = ["log_id", "label", "attack_type", "confidence", "review_note"]
VALID_LABELS = {"benign", "benign_unusual", "suspicious", "malicious", "needs_context"}
VALID_ATTACK_TYPES = {
    "normal",
    "port_scan",
    "brute_force",
    "dos_ddos",
    "malware_c2",
    "policy_violation",
    "data_exfiltration_suspicion",
    "unknown_anomaly",
}
VALID_LABEL_SOURCES = {"manual", "assisted_rule", "assisted_ml", "assisted_hybrid"}


def _label_to_dict(label: MLLabel) -> dict:
    return {
        "id": label.id,
        "log_id": label.log_id,
        "label": label.label,
        "attack_type": label.attack_type,
        "confidence": label.confidence,
        "reviewer": label.reviewer,
        "label_source": getattr(label, "label_source", "manual"),
        "reviewed": getattr(label, "reviewed", True),
        "review_note": label.review_note,
        "created_at": label.created_at,
    }


def create_ml_label(db: Session, request: MLLabelCreate, *, reviewer: str) -> MLLabel | None:
    log = db.get(NormalizedLog, request.log_id)
    if log is None:
        return None
    label = MLLabel(
        log_id=request.log_id,
        label=request.label,
        attack_type=request.attack_type,
        confidence=request.confidence,
        reviewer=reviewer,
        review_note=request.review_note,
        label_source=request.label_source,
        reviewed=request.reviewed,
    )
    db.add(label)
    db.add(
        AuditLog(
            actor=reviewer,
            action="ml_label_created",
            target_type="normalized_log",
            target_value=str(request.log_id),
            details={
                "label": request.label,
                "attack_type": request.attack_type,
                "confidence": request.confidence,
                "label_source": request.label_source,
                "reviewed": request.reviewed,
            },
        )
    )
    db.commit()
    db.refresh(label)
    return label


def _latest_label_for_log(db: Session, log_id: int) -> MLLabel | None:
    return db.scalar(
        select(MLLabel)
        .where(MLLabel.log_id == log_id)
        .order_by(desc(MLLabel.created_at), desc(MLLabel.id))
        .limit(1)
    )


def update_ml_label(db: Session, label_id: int, request: MLLabelUpdate, *, reviewer: str) -> MLLabel | None:
    label = db.get(MLLabel, label_id)
    if label is None:
        return None
    changes: dict = {}
    for field in ["label", "attack_type", "confidence", "review_note", "label_source", "reviewed"]:
        value = getattr(request, field)
        if value is not None:
            setattr(label, field, value)
            changes[field] = value
    label.reviewer = reviewer
    db.add(
        AuditLog(
            actor=reviewer,
            action="ml_label_updated",
            target_type="ml_label",
            target_value=str(label_id),
            details={"log_id": label.log_id, "changes": changes},
        )
    )
    db.commit()
    db.refresh(label)
    return label


def list_ml_labels(
    db: Session,
    *,
    label: str | None = None,
    attack_type: str | None = None,
    log_id: int | None = None,
    reviewer: str | None = None,
    limit: int = 200,
    offset: int = 0,
) -> list[MLLabel]:
    statement = select(MLLabel).order_by(MLLabel.created_at.desc(), MLLabel.id.desc())
    if label:
        statement = statement.where(MLLabel.label == label)
    if attack_type:
        statement = statement.where(MLLabel.attack_type == attack_type)
    if log_id:
        statement = statement.where(MLLabel.log_id == log_id)
    if reviewer:
        statement = statement.where(MLLabel.reviewer.ilike(f"%{reviewer}%"))
    return list(db.scalars(statement.limit(limit).offset(offset)))


def ml_label_csv_template() -> str:
    output = StringIO()
    writer = csv.DictWriter(output, fieldnames=CSV_TEMPLATE_FIELDNAMES)
    writer.writeheader()
    writer.writerow(
        {
            "log_id": "1",
            "label": "suspicious",
            "attack_type": "port_scan",
            "confidence": "4",
            "review_note": "Example analyst note. Replace this row before importing.",
        }
    )
    return output.getvalue()


def export_ml_labels_csv(labels: list[MLLabel]) -> str:
    output = StringIO()
    writer = csv.DictWriter(output, fieldnames=CSV_FIELDNAMES)
    writer.writeheader()
    for label in labels:
        row = _label_to_dict(label)
        row["created_at"] = label.created_at.isoformat() if label.created_at else ""
        writer.writerow(row)
    return output.getvalue()


def _parse_int(value: Any, *, field: str, row_number: int) -> int:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError) as exc:
        raise ValueError(f"row {row_number}: invalid {field}") from exc


def _parse_optional_int(value: Any, *, field: str, row_number: int) -> int | None:
    if value is None or str(value).strip() == "":
        return None
    return _parse_int(value, field=field, row_number=row_number)


def _parse_bool(value: Any, *, default: bool) -> bool:
    if value is None or str(value).strip() == "":
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "y"}


def _validate_import_row(row: dict[str, Any], row_number: int) -> dict[str, Any]:
    label_id = _parse_optional_int(row.get("id") or row.get("label_id"), field="label_id", row_number=row_number)
    log_id = _parse_optional_int(row.get("log_id"), field="log_id", row_number=row_number)
    has_human_review_columns = "human_review_decision" in row or "human_review_note" in row
    has_human_review_input = bool(str(row.get("human_review_decision") or "").strip() or str(row.get("human_review_note") or "").strip())
    label = str(row.get("human_review_decision") or row.get("label", "")).strip()
    attack_type = str(row.get("attack_type", "unknown_anomaly")).strip() or "unknown_anomaly"
    confidence = _parse_int(row.get("confidence", 3), field="confidence", row_number=row_number)
    if log_id is None and label_id is None:
        raise ValueError(f"row {row_number}: log_id or label_id is required")
    if label not in VALID_LABELS:
        raise ValueError(f"row {row_number}: label must be one of {sorted(VALID_LABELS)}")
    if attack_type not in VALID_ATTACK_TYPES:
        raise ValueError(f"row {row_number}: attack_type must be one of {sorted(VALID_ATTACK_TYPES)}")
    if not 1 <= confidence <= 5:
        raise ValueError(f"row {row_number}: confidence must be 1-5")
    label_source = str(row.get("label_source", "manual") or "manual").strip()
    if label_source not in VALID_LABEL_SOURCES:
        raise ValueError(f"row {row_number}: label_source must be manual or assisted_*")
    review_note = str(row.get("human_review_note") or row.get("review_note") or "").strip() or None
    return {
        "id": label_id,
        "log_id": log_id,
        "label": label,
        "attack_type": attack_type,
        "confidence": confidence,
        "review_note": review_note,
        "label_source": label_source,
        "reviewed": _parse_bool(row.get("reviewed"), default=True),
        "has_human_review_columns": has_human_review_columns,
        "has_human_review_input": has_human_review_input,
    }


def _merge_human_review_note(existing_note: str | None, imported_note: str | None, *, reviewer: str) -> str:
    human_note = (
        f"Human review by {reviewer}: {imported_note}"
        if imported_note
        else f"Human review by {reviewer}: CSV review confirmed this label."
    )
    if existing_note and human_note in existing_note:
        return existing_note
    return f"{existing_note}\n\n{human_note}" if existing_note else human_note


def import_ml_labels_csv(
    db: Session,
    csv_content: str,
    *,
    reviewer: str,
    mark_reviewed: bool = True,
    overwrite_manual: bool = False,
    preserve_label_source: bool = True,
) -> dict:
    reader = csv.DictReader(StringIO(csv_content))
    created = 0
    updated = 0
    skipped = 0
    protected_manual = 0
    failed = 0
    errors: list[dict[str, Any]] = []

    for row_number, row in enumerate(reader, start=2):
        try:
            parsed = _validate_import_row(row, row_number)
            if mark_reviewed and parsed["has_human_review_columns"] and not parsed["has_human_review_input"]:
                skipped += 1
                continue
            label = db.get(MLLabel, parsed["id"]) if parsed["id"] else None
            if label is not None and parsed["log_id"] is not None and label.log_id != parsed["log_id"]:
                raise ValueError(f"row {row_number}: label_id does not belong to log_id {parsed['log_id']}")
            if label is not None and parsed["log_id"] is None:
                parsed["log_id"] = label.log_id
            if parsed["log_id"] is None:
                raise ValueError(f"row {row_number}: log_id is required when label_id is not found")
            log = db.get(NormalizedLog, parsed["log_id"])
            if log is None:
                raise ValueError(f"row {row_number}: normalized log {parsed['log_id']} not found")
            if label is None:
                label = _latest_label_for_log(db, parsed["log_id"])
            if label is None:
                label = MLLabel(
                    log_id=parsed["log_id"],
                    label=parsed["label"],
                    attack_type=parsed["attack_type"],
                    confidence=parsed["confidence"],
                    reviewer=reviewer,
                    review_note=parsed["review_note"],
                    label_source=parsed["label_source"],
                    reviewed=True if mark_reviewed else parsed["reviewed"],
                )
                db.add(label)
                created += 1
            else:
                existing_source = getattr(label, "label_source", "manual") or "manual"
                if existing_source == "manual" and not overwrite_manual:
                    skipped += 1
                    protected_manual += 1
                    continue
                label.label = parsed["label"]
                label.attack_type = parsed["attack_type"]
                label.confidence = parsed["confidence"]
                label.review_note = _merge_human_review_note(label.review_note, parsed["review_note"], reviewer=reviewer)
                if not preserve_label_source:
                    label.label_source = parsed["label_source"]
                label.reviewed = True if mark_reviewed else parsed["reviewed"]
                updated += 1
        except ValueError as exc:
            failed += 1
            errors.append({"row": row_number, "error": str(exc)})

    db.add(
        AuditLog(
            actor=reviewer,
            action="ml_labels_imported",
            target_type="ml_labels",
            target_value="csv",
            details={
                "created": created,
                "updated": updated,
                "skipped": skipped,
                "protected_manual": protected_manual,
                "failed": failed,
                "mark_reviewed": mark_reviewed,
                "overwrite_manual": overwrite_manual,
                "preserve_label_source": preserve_label_source,
                "errors": errors[:20],
            },
        )
    )
    db.commit()
    return {
        "created": created,
        "updated": updated,
        "skipped": skipped,
        "protected_manual": protected_manual,
        "failed": failed,
        "errors": errors,
    }


def _alert_scores_by_log(db: Session) -> dict[int, dict[str, Any]]:
    rows = db.execute(
        select(AlertEvidence.normalized_log_id, Alert.id, Alert.threat_score, Alert.severity, Alert.status, Alert.alert_type)
        .join(Alert, Alert.id == AlertEvidence.alert_id)
        .where(Alert.status.notin_(["resolved", "false_positive"]))
    ).all()
    scores: dict[int, dict[str, Any]] = {}
    for log_id, alert_id, threat_score, severity, status, alert_type in rows:
        entry = scores.setdefault(
            int(log_id),
            {"rule_score": 0, "alert_ids": [], "severities": set(), "statuses": set(), "alert_types": set()},
        )
        entry["rule_score"] = max(int(entry["rule_score"]), int(threat_score or 0))
        entry["alert_ids"].append(int(alert_id))
        entry["severities"].add(str(severity))
        entry["statuses"].add(str(status))
        entry["alert_types"].add(str(alert_type))
    return scores


def _latest_labels_by_log(db: Session) -> dict[int, MLLabel]:
    labels = list(db.scalars(select(MLLabel).order_by(MLLabel.log_id, desc(MLLabel.created_at), desc(MLLabel.id))))
    latest: dict[int, MLLabel] = {}
    for label in labels:
        latest.setdefault(label.log_id, label)
    return latest


def _review_priority(log: NormalizedLog, *, rule_score: int, prediction: dict, existing_label: MLLabel | None) -> tuple[int, list[str]]:
    score = 0
    reasons: list[str] = []
    malicious_probability = float(prediction.get("malicious_probability") or 0)
    predicted_label = prediction.get("predicted_label")

    if existing_label is None:
        score += 25
        reasons.append("unlabeled")
    if log.is_anomaly:
        score += 25
        reasons.append("IsolationForest anomaly")
    if rule_score >= 80:
        score += 30
        reasons.append("critical rule evidence")
    elif rule_score >= 60:
        score += 20
        reasons.append("high rule evidence")
    elif rule_score >= 30:
        score += 10
        reasons.append("medium rule evidence")
    if log.action in {"deny", "drop", "reset-both", "reset-client", "reset-server"}:
        score += 12
        reasons.append(f"action={log.action}")
    if (log.app_risk or 0) >= 4:
        score += 12
        reasons.append(f"app risk {log.app_risk}")
    if log.app in {"unknown-tcp", "unknown-udp", "incomplete", "unknown"}:
        score += 10
        reasons.append("unknown/incomplete app")
    if malicious_probability >= 0.7:
        score += 18
        reasons.append("supervised model predicts malicious/suspicious")
    if predicted_label in {"benign", "benign_unusual"} and rule_score >= 60:
        score += 16
        reasons.append("rule/ML disagreement")
    if predicted_label in {"suspicious", "malicious"} and rule_score < 30:
        score += 16
        reasons.append("ML/rule disagreement")
    if not reasons:
        reasons.append("recent log sample")
    return min(score, 100), reasons


def build_label_review_queue(db: Session, *, limit: int = 100, include_labeled: bool = False) -> list[dict]:
    alert_scores = _alert_scores_by_log(db)
    latest_labels = _latest_labels_by_log(db)
    active_alert_evidence_filter = NormalizedLog.alert_evidence.any(
        AlertEvidence.alert.has(Alert.status.notin_(["resolved", "false_positive"]))
    )
    statement = (
        select(NormalizedLog)
        .options(joinedload(NormalizedLog.raw_log), joinedload(NormalizedLog.alert_evidence))
        .where(
            or_(
                active_alert_evidence_filter,
                NormalizedLog.is_anomaly.is_(True),
                NormalizedLog.app_risk >= 4,
                NormalizedLog.action.in_(["deny", "drop", "reset-both", "reset-client", "reset-server"]),
                NormalizedLog.app.in_(["unknown", "unknown-tcp", "unknown-udp", "incomplete"]),
            )
        )
        .order_by(desc(NormalizedLog.generated_time), desc(NormalizedLog.id))
        .limit(max(limit * 5, 200))
    )
    logs = list(db.scalars(statement).unique())
    queue: list[dict] = []
    for log in logs:
        existing_label = latest_labels.get(log.id)
        if existing_label is not None and not include_labeled:
            continue
        alert_info = alert_scores.get(log.id, {})
        rule_score = int(alert_info.get("rule_score", 0))
        prediction = predict_supervised_log(db, log.id, rule_score=rule_score)
        malicious_probability = float(prediction.get("malicious_probability") or 0)
        hybrid = prediction.get("hybrid_risk") or hybrid_risk_score(
            rule_score=rule_score,
            isolation_anomaly_score=log.anomaly_score,
            isolation_is_anomaly=log.is_anomaly,
            supervised_malicious_probability=malicious_probability,
        )
        priority_score, reasons = _review_priority(log, rule_score=rule_score, prediction=prediction, existing_label=existing_label)
        queue.append(
            {
                "log_id": log.id,
                "generated_time": log.generated_time,
                "src_ip": log.src_ip,
                "dst_ip": log.dst_ip,
                "app": log.app,
                "action": log.action,
                "protocol": log.protocol,
                "src_zone": log.src_zone,
                "dst_zone": log.dst_zone,
                "app_risk": log.app_risk,
                "is_anomaly": log.is_anomaly,
                "anomaly_score": log.anomaly_score,
                "rule_score": rule_score,
                "supervised_prediction": prediction.get("predicted_label"),
                "malicious_probability": malicious_probability,
                "hybrid_risk_score": int(hybrid.get("final_risk_score", 0)),
                "priority_score": priority_score,
                "priority_reasons": reasons,
                "existing_label": _label_to_dict(existing_label) if existing_label else None,
                "alert_ids": sorted({int(value) for value in alert_info.get("alert_ids", [])}),
            }
        )
    queue.sort(key=lambda item: (int(item["priority_score"]), int(item["hybrid_risk_score"]), item["log_id"]), reverse=True)
    return queue[:limit]


def export_review_queue_csv(queue: list[dict]) -> str:
    output = StringIO()
    fieldnames = [
        "log_id",
        "generated_time",
        "src_ip",
        "dst_ip",
        "app",
        "action",
        "app_risk",
        "is_anomaly",
        "anomaly_score",
        "rule_score",
        "supervised_prediction",
        "malicious_probability",
        "hybrid_risk_score",
        "priority_score",
        "priority_reasons",
        "label",
        "attack_type",
        "confidence",
        "review_note",
    ]
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    for item in queue:
        writer.writerow(
            {
                "log_id": item["log_id"],
                "generated_time": item["generated_time"].isoformat() if item.get("generated_time") else "",
                "src_ip": item.get("src_ip") or "",
                "dst_ip": item.get("dst_ip") or "",
                "app": item.get("app") or "",
                "action": item.get("action") or "",
                "app_risk": item.get("app_risk") or "",
                "is_anomaly": item.get("is_anomaly"),
                "anomaly_score": item.get("anomaly_score") or "",
                "rule_score": item.get("rule_score") or 0,
                "supervised_prediction": item.get("supervised_prediction") or "",
                "malicious_probability": item.get("malicious_probability") or 0,
                "hybrid_risk_score": item.get("hybrid_risk_score") or 0,
                "priority_score": item.get("priority_score") or 0,
                "priority_reasons": "; ".join(item.get("priority_reasons") or []),
                "label": "",
                "attack_type": "unknown_anomaly",
                "confidence": "",
                "review_note": "",
            }
        )
    return output.getvalue()


def label_to_dict(label: MLLabel) -> dict:
    return _label_to_dict(label)
