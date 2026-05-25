from collections import Counter
import csv
from datetime import datetime, timedelta, timezone
from html import escape
from io import StringIO

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session, joinedload

from atdr.app.db.models import Alert, AlertEvidence, AlertNote, AuditLog, NormalizedLog, ResponseAction, User
from atdr.app.detection.explanations import build_alert_detection_summary, compact_behavior_features
from atdr.app.detection.rules import DetectionResult
from atdr.app.detection.scoring import recommended_response, severity_from_score


ALERT_STATUSES = {"open", "investigating", "contained", "resolved", "false_positive"}
SLA_TARGETS = {
    "Critical": ("Immediate", timedelta(hours=1)),
    "High": ("Same day", timedelta(hours=24)),
    "Medium": ("Review", timedelta(hours=72)),
    "Low": ("Backlog", timedelta(days=7)),
}
SLA_CLOSED_STATUSES = {"resolved", "false_positive"}


def _ensure_aware(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def alert_sla(alert: Alert, *, now: datetime | None = None) -> dict:
    current = _ensure_aware(now or datetime.now(timezone.utc))
    created_at = _ensure_aware(alert.created_at)
    label, target_delta = SLA_TARGETS.get(alert.severity, ("Backlog", timedelta(days=7)))
    due_at = created_at + target_delta
    age_minutes = max(0, int((current - created_at).total_seconds() // 60))
    minutes_remaining = int((due_at - current).total_seconds() // 60)
    if alert.status in SLA_CLOSED_STATUSES:
        state = "closed"
    elif alert.assigned_to is None and alert.status in {"open", "investigating", "contained"}:
        state = "needs_owner"
    elif minutes_remaining < 0:
        state = "overdue"
    elif minutes_remaining <= 60 and alert.severity in {"Critical", "High"}:
        state = "due_soon"
    else:
        state = "on_track"
    return {
        "label": label,
        "state": state,
        "due_at": due_at,
        "age_minutes": age_minutes,
        "minutes_remaining": minutes_remaining,
        "target_minutes": int(target_delta.total_seconds() // 60),
    }


def create_alert_from_detection(db: Session, log: NormalizedLog, result: DetectionResult) -> Alert:
    matched_rules = [
        {
            "code": rule.code,
            "title": rule.title,
            "score": rule.score,
            "explanation": rule.explanation,
        }
        for rule in result.matched_rules
    ]
    top_rule = matched_rules[0]["title"] if matched_rules else "Suspicious activity"
    alert = Alert(
        title=f"{result.severity}: {top_rule}",
        alert_type=matched_rules[0]["code"] if matched_rules else "suspicious_activity",
        src_ip=log.src_ip,
        dst_ip=log.dst_ip,
        threat_score=result.threat_score,
        severity=result.severity,
        explanation=result.explanation,
        matched_rules_json=matched_rules,
        recommended_response=recommended_response(result.severity, log.src_ip),
    )
    alert.evidence.append(AlertEvidence(normalized_log_id=log.id))
    db.add(alert)
    return alert


def create_grouped_alert_from_detections(
    db: Session,
    detections: list[tuple[NormalizedLog, DetectionResult]],
    primary_rule_code: str | None = None,
) -> Alert:
    if not detections:
        raise ValueError("detections must not be empty")

    logs = [log for log, _ in detections]
    results = [result for _, result in detections]
    primary_result = max(results, key=lambda item: item.threat_score)
    primary_log = logs[results.index(primary_result)]
    evidence_count = len(logs)
    max_score = max(result.threat_score for result in results)
    severity = severity_from_score(max_score)

    rule_by_code: dict[str, dict] = {}
    rule_counts: Counter[str] = Counter()
    for result in results:
        for rule in result.matched_rules:
            rule_counts[rule.code] += 1
            existing = rule_by_code.get(rule.code)
            if existing is None or rule.score > existing["score"]:
                rule_by_code[rule.code] = {
                    "code": rule.code,
                    "title": rule.title,
                    "score": rule.score,
                    "explanation": rule.explanation,
                }

    matched_rules = []
    for code, rule in sorted(rule_by_code.items(), key=lambda item: (-item[1]["score"], item[1]["code"])):
        rule["matched_log_count"] = rule_counts[code]
        matched_rules.append(rule)

    event_times = [_event_time(log) for log in logs]
    event_times = [item for item in event_times if item is not None]
    first_seen = min(event_times).isoformat() if event_times else None
    last_seen = max(event_times).isoformat() if event_times else None
    src_ips = sorted({log.src_ip for log in logs if log.src_ip})[:10]
    unique_src_count = len({log.src_ip for log in logs if log.src_ip})
    dst_ips = sorted({log.dst_ip for log in logs if log.dst_ip})[:10]
    unique_dst_count = len({log.dst_ip for log in logs if log.dst_ip})
    dst_ports = sorted({log.dst_port for log in logs if log.dst_port is not None})[:10]
    actions = sorted({log.action for log in logs if log.action})
    protocols = sorted({log.protocol for log in logs if log.protocol})

    top_rule = next((rule for rule in matched_rules if rule["code"] == primary_rule_code), None)
    if top_rule is None:
        top_rule = matched_rules[0] if matched_rules else {"code": "suspicious_activity", "title": "Suspicious activity"}
    source_label = primary_log.src_ip or "unknown source"
    if unique_src_count > 1:
        source_label = f"{unique_src_count} sources"
    title = f"{severity}: {top_rule['title']} from {source_label}"
    if evidence_count > 1:
        title = f"{title} ({evidence_count} events)"

    explanation_parts = [
        f"Grouped {evidence_count} matching log event{'s' if evidence_count != 1 else ''}.",
        f"Highest threat score in group is {max_score}.",
    ]
    if first_seen and last_seen:
        explanation_parts.append(f"Observed from {first_seen} to {last_seen}.")
    if src_ips:
        explanation_parts.append(f"Sample sources: {', '.join(src_ips)}.")
    if dst_ips:
        explanation_parts.append(f"Sample destinations: {', '.join(dst_ips)}.")
    if dst_ports:
        explanation_parts.append(f"Destination ports observed: {', '.join(str(port) for port in dst_ports)}.")
    explanation_parts.append(primary_result.explanation)

    alert = Alert(
        title=title,
        alert_type=top_rule["code"],
        src_ip=primary_log.src_ip if unique_src_count <= 1 else None,
        dst_ip=primary_log.dst_ip if unique_dst_count <= 1 else None,
        threat_score=max_score,
        severity=severity,
        explanation=" ".join(explanation_parts),
        matched_rules_json=[
            *matched_rules,
            {
                "code": "group_metadata",
                "title": "Grouped alert metadata",
                "score": 0,
                "explanation": "Alert groups related evidence logs to reduce analyst noise.",
                "evidence_count": evidence_count,
                "first_seen": first_seen,
                "last_seen": last_seen,
                "unique_src_count": unique_src_count,
                "sample_src_ips": src_ips,
                "unique_dst_count": unique_dst_count,
                "sample_dst_ips": dst_ips,
                "sample_dst_ports": dst_ports,
                "actions": actions,
                "protocols": protocols,
            },
        ],
        recommended_response=recommended_response(severity, primary_log.src_ip),
    )
    for log in logs:
        alert.evidence.append(AlertEvidence(normalized_log_id=log.id))
    db.add(alert)
    return alert


def _event_time(log: NormalizedLog) -> datetime | None:
    return log.generated_time or log.receive_time or log.high_res_timestamp or log.start_time


def list_alerts(
    db: Session,
    *,
    search: str | None = None,
    severity: str | None = None,
    status: str | None = None,
    src_ip: str | None = None,
    dst_ip: str | None = None,
    alert_type: str | None = None,
    assigned_to: str | None = None,
    unassigned: bool = False,
    sort_by: str = "created",
    limit: int = 100,
    offset: int = 0,
) -> list[Alert]:
    statement = build_alert_query(
        search=search,
        severity=severity,
        status=status,
        src_ip=src_ip,
        dst_ip=dst_ip,
        alert_type=alert_type,
        assigned_to=assigned_to,
        unassigned=unassigned,
        sort_by=sort_by,
    )
    return list(db.scalars(statement.limit(limit).offset(offset)).unique())


def build_alert_query(
    *,
    search: str | None = None,
    severity: str | None = None,
    status: str | None = None,
    src_ip: str | None = None,
    dst_ip: str | None = None,
    alert_type: str | None = None,
    assigned_to: str | None = None,
    unassigned: bool = False,
    sort_by: str = "created",
):
    sort_columns = {
        "updated": Alert.updated_at,
        "created": Alert.created_at,
        "score": Alert.threat_score,
        "severity": Alert.severity,
    }
    order_column = sort_columns.get(sort_by, Alert.created_at)
    statement = select(Alert).options(joinedload(Alert.evidence)).order_by(order_column.desc(), Alert.id.desc())
    if search:
        pattern = f"%{search}%"
        statement = statement.where(
            or_(
                Alert.title.ilike(pattern),
                Alert.alert_type.ilike(pattern),
                Alert.src_ip.ilike(pattern),
                Alert.dst_ip.ilike(pattern),
                Alert.explanation.ilike(pattern),
            )
        )
    if severity:
        statement = statement.where(Alert.severity == severity)
    if status:
        statement = statement.where(Alert.status == status)
    if src_ip:
        statement = statement.where(Alert.src_ip == src_ip)
    if dst_ip:
        statement = statement.where(Alert.dst_ip == dst_ip)
    if alert_type:
        statement = statement.where(Alert.alert_type.ilike(f"%{alert_type}%"))
    if assigned_to:
        statement = statement.where(Alert.assigned_to == assigned_to)
    if unassigned:
        statement = statement.where(Alert.assigned_to.is_(None))
    return statement


def count_alerts(db: Session, **filters) -> int:
    statement = build_alert_query(**filters).order_by(None)
    return int(db.scalar(select(func.count()).select_from(statement.subquery())) or 0)


def get_alert(db: Session, alert_id: int) -> Alert | None:
    statement = select(Alert).options(joinedload(Alert.evidence), joinedload(Alert.notes)).where(Alert.id == alert_id)
    return db.scalars(statement).unique().first()


def escalate_alert(
    db: Session,
    alert_id: int,
    *,
    priority_owner: str,
    escalation_reason: str,
    ticket_reference: str | None,
    actor: str,
) -> Alert | None:
    alert = get_alert(db, alert_id)
    if alert is None:
        return None
    alert.priority_owner = priority_owner
    alert.escalation_reason = escalation_reason
    alert.ticket_reference = ticket_reference
    alert.escalated_at = datetime.now(timezone.utc)
    db.add(
        AuditLog(
            actor=actor,
            action="alert_escalated",
            target_type="alert",
            target_value=str(alert_id),
            details={
                "priority_owner": priority_owner,
                "ticket_reference": ticket_reference,
                "escalation_reason": escalation_reason,
            },
        )
    )
    db.commit()
    db.refresh(alert)
    return alert


def update_alert_status(db: Session, alert_id: int, status: str, actor: str = "analyst") -> Alert | None:
    if status not in ALERT_STATUSES:
        raise ValueError(f"Unsupported alert status: {status}")
    alert = get_alert(db, alert_id)
    if alert is None:
        return None
    alert.status = status
    db.add(
        AuditLog(
            actor=actor,
            action=f"alert_{status}",
            target_type="alert",
            target_value=str(alert_id),
            details={"src_ip": alert.src_ip, "dst_ip": alert.dst_ip, "severity": alert.severity},
        )
    )
    db.commit()
    db.refresh(alert)
    return alert


def assign_alert(
    db: Session,
    alert_id: int,
    *,
    assigned_to: str,
    actor: str,
) -> Alert | None:
    alert = get_alert(db, alert_id)
    if alert is None:
        return None
    user = db.scalar(select(User).where(User.username == assigned_to, User.is_active.is_(True)))
    if user is None:
        raise ValueError(f"Active user not found: {assigned_to}")

    alert.assigned_to = assigned_to
    alert.assigned_at = datetime.now(timezone.utc)
    db.add(
        AuditLog(
            actor=actor,
            action="alert_assigned",
            target_type="alert",
            target_value=str(alert_id),
            details={"assigned_to": assigned_to, "severity": alert.severity, "status": alert.status},
        )
    )
    db.commit()
    db.refresh(alert)
    return alert


def add_alert_note(db: Session, alert_id: int, *, author: str, note: str) -> AlertNote | None:
    alert = get_alert(db, alert_id)
    if alert is None:
        return None
    alert_note = AlertNote(alert_id=alert_id, author=author, note=note.strip())
    db.add(alert_note)
    db.add(
        AuditLog(
            actor=author,
            action="alert_note_added",
            target_type="alert",
            target_value=str(alert_id),
            details={"note_preview": note.strip()[:160]},
        )
    )
    db.commit()
    db.refresh(alert_note)
    return alert_note


def list_alert_notes(db: Session, alert_id: int) -> list[AlertNote] | None:
    alert_exists = db.scalar(select(Alert.id).where(Alert.id == alert_id))
    if alert_exists is None:
        return None
    statement = select(AlertNote).where(AlertNote.alert_id == alert_id).order_by(AlertNote.created_at.asc(), AlertNote.id.asc())
    return list(db.scalars(statement))


def alert_timeline(db: Session, alert_id: int) -> list[dict] | None:
    alert = get_alert(db, alert_id)
    if alert is None:
        return None

    events: list[dict] = [
        {
            "event_time": alert.created_at,
            "event_type": "created",
            "actor": "system",
            "summary": f"Alert created with severity {alert.severity}.",
            "details": {"status": alert.status, "threat_score": alert.threat_score},
        }
    ]
    audit_rows = db.scalars(
        select(AuditLog)
        .where(AuditLog.target_type == "alert", AuditLog.target_value == str(alert_id))
        .order_by(AuditLog.created_at.asc(), AuditLog.id.asc())
    ).all()
    for audit in audit_rows:
        events.append(
            {
                "event_time": audit.created_at,
                "event_type": audit.action,
                "actor": audit.actor,
                "summary": _audit_summary(audit),
                "details": audit.details,
            }
        )

    response_rows = db.scalars(
        select(ResponseAction)
        .where(ResponseAction.alert_id == alert_id)
        .order_by(ResponseAction.executed_at.asc(), ResponseAction.id.asc())
    ).all()
    for action in response_rows:
        events.append(
            {
                "event_time": action.executed_at,
                "event_type": action.action_type,
                "actor": action.executed_by,
                "summary": f"{action.action_type.replace('_', ' ').title()} {action.target_ip}: {action.status}.",
                "details": {"target_ip": action.target_ip, "result_message": action.result_message},
            }
        )

    events.sort(key=lambda item: item["event_time"])
    return events


def alert_report(db: Session, alert_id: int) -> dict | None:
    alert = get_alert(db, alert_id)
    if alert is None:
        return None
    evidence_logs = []
    for evidence in alert.evidence:
        log = db.get(NormalizedLog, evidence.normalized_log_id)
        if log is None:
            continue
        raw_line = log.raw_log.raw_line if log.raw_log else None
        evidence_logs.append(
            {
                "id": log.id,
                "raw_log_id": log.raw_log_id,
                "generated_time": log.generated_time,
                "receive_time": log.receive_time,
                "src_ip": log.src_ip,
                "dst_ip": log.dst_ip,
                "app": log.app,
                "action": log.action,
                "protocol": log.protocol,
                "dst_port": log.dst_port,
                "bytes": log.bytes,
                "app_risk": log.app_risk,
                "is_anomaly": log.is_anomaly,
                "anomaly_score": log.anomaly_score,
                "behavior_window": compact_behavior_features(db, log),
                "raw_line_excerpt": raw_line[:500] if raw_line else None,
            }
        )
    response_actions = db.scalars(
        select(ResponseAction)
        .where(ResponseAction.alert_id == alert_id)
        .order_by(ResponseAction.executed_at.asc(), ResponseAction.id.asc())
    ).all()
    evidence_count = len(evidence_logs)
    matched_rule_titles = [rule.get("title") for rule in alert.matched_rules_json if rule.get("code") != "group_metadata"]
    ai_assistive = any(rule.get("code") == "ml_anomaly_detected" for rule in alert.matched_rules_json)
    watchlist_matched = any(rule.get("code") == "watchlist_match" for rule in alert.matched_rules_json)
    impact = "High" if alert.severity in {"High", "Critical"} else "Moderate" if alert.severity == "Medium" else "Low"
    likelihood = "Elevated" if alert.threat_score >= 61 else "Moderate" if alert.threat_score >= 31 else "Low"
    recommended_next_steps = [
        "Confirm ownership and record the investigation decision in alert notes.",
        "Review linked raw evidence before performing response actions.",
    ]
    if alert.severity in {"Critical", "High"}:
        recommended_next_steps.append("Escalate to the priority owner and contain affected source or destination if validated.")
    if watchlist_matched:
        recommended_next_steps.append("Validate why the watchlisted indicator appeared and update the watchlist disposition.")
    if ai_assistive:
        recommended_next_steps.append("Treat ML evidence as assistive and confirm with rule evidence or network context.")
    return {
        "generated_at": datetime.now(timezone.utc),
        "executive_summary": (
            f"Alert {alert.id} is a {alert.severity} {alert.alert_type} finding with score {alert.threat_score}. "
            f"It contains {evidence_count} linked evidence log{'s' if evidence_count != 1 else ''} and is currently {alert.status}."
        ),
        "risk_assessment": {
            "impact": impact,
            "likelihood": likelihood,
            "ai_assistive": ai_assistive,
            "watchlist_matched": watchlist_matched,
            "primary_reasons": matched_rule_titles[:5],
        },
        "recommended_next_steps": recommended_next_steps,
        "alert": {
            "id": alert.id,
            "title": alert.title,
            "alert_type": alert.alert_type,
            "src_ip": alert.src_ip,
            "dst_ip": alert.dst_ip,
            "threat_score": alert.threat_score,
            "severity": alert.severity,
            "status": alert.status,
            "assigned_to": alert.assigned_to,
            "priority_owner": alert.priority_owner,
            "ticket_reference": alert.ticket_reference,
            "escalation_reason": alert.escalation_reason,
            "created_at": alert.created_at,
            "updated_at": alert.updated_at,
        },
        "sla": alert_sla(alert),
        "matched_rules": alert.matched_rules_json,
        "detection_summary": build_alert_detection_summary(db, alert),
        "evidence_logs": evidence_logs,
        "timeline": alert_timeline(db, alert_id) or [],
        "notes": [
            {"id": note.id, "alert_id": note.alert_id, "author": note.author, "note": note.note, "created_at": note.created_at}
            for note in (list_alert_notes(db, alert_id) or [])
        ],
        "response_actions": [
            {
                "id": action.id,
                "action_type": action.action_type,
                "target_ip": action.target_ip,
                "status": action.status,
                "result_message": action.result_message,
                "executed_by": action.executed_by,
                "executed_at": action.executed_at,
            }
            for action in response_actions
        ],
    }


def _safe_report_value(value) -> str:
    if value is None:
        return "-"
    return escape(str(value))


def _report_table(rows: list[dict], columns: list[str]) -> str:
    if not rows:
        return '<p class="muted">No records.</p>'
    header = "".join(f"<th>{_safe_report_value(column.replace('_', ' ').title())}</th>" for column in columns)
    body_rows = []
    for row in rows:
        cells = "".join(f"<td>{_safe_report_value(row.get(column))}</td>" for column in columns)
        body_rows.append(f"<tr>{cells}</tr>")
    return f"<table><thead><tr>{header}</tr></thead><tbody>{''.join(body_rows)}</tbody></table>"


def render_alert_report_html(report: dict) -> str:
    alert = report["alert"]
    risk = report.get("risk_assessment", {})
    evidence_columns = ["id", "generated_time", "src_ip", "dst_ip", "app", "action", "protocol", "dst_port", "is_anomaly"]
    rule_columns = ["code", "title", "score", "matched_log_count", "explanation"]
    timeline_columns = ["event_time", "event_type", "actor", "summary"]
    response_columns = ["action_type", "target_ip", "status", "executed_by", "executed_at"]
    return f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>ATDR Alert {alert["id"]} Report</title>
  <style>
    body {{ font-family: Arial, sans-serif; color: #172033; margin: 32px; }}
    h1 {{ margin-bottom: 4px; }}
    h2 {{ margin-top: 28px; border-bottom: 1px solid #d8dee9; padding-bottom: 6px; }}
    .muted {{ color: #64748b; }}
    .summary {{ border: 1px solid #d8dee9; border-radius: 8px; padding: 16px; background: #f8fafc; }}
    .grid {{ display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px; margin-top: 16px; }}
    .card {{ border: 1px solid #d8dee9; border-radius: 8px; padding: 12px; }}
    .label {{ color: #64748b; font-size: 12px; text-transform: uppercase; font-weight: bold; }}
    .value {{ font-size: 20px; font-weight: bold; margin-top: 4px; }}
    table {{ border-collapse: collapse; width: 100%; font-size: 13px; }}
    th, td {{ border: 1px solid #d8dee9; padding: 8px; vertical-align: top; }}
    th {{ background: #f1f5f9; text-align: left; }}
  </style>
</head>
<body>
  <h1>ATDR Incident Report</h1>
  <p class="muted">Generated at {_safe_report_value(report.get("generated_at"))} by {_safe_report_value(report.get("generated_by"))}</p>
  <div class="summary">
    <strong>{_safe_report_value(alert.get("title"))}</strong>
    <p>{_safe_report_value(report.get("executive_summary"))}</p>
  </div>
  <div class="grid">
    <div class="card"><div class="label">Severity</div><div class="value">{_safe_report_value(alert.get("severity"))}</div></div>
    <div class="card"><div class="label">Score</div><div class="value">{_safe_report_value(alert.get("threat_score"))}</div></div>
    <div class="card"><div class="label">Status</div><div class="value">{_safe_report_value(alert.get("status"))}</div></div>
    <div class="card"><div class="label">Ticket</div><div class="value">{_safe_report_value(alert.get("ticket_reference"))}</div></div>
  </div>
  <h2>Risk Assessment</h2>
  <p>Impact: <strong>{_safe_report_value(risk.get("impact"))}</strong> | Likelihood: <strong>{_safe_report_value(risk.get("likelihood"))}</strong> | ML Assistive: <strong>{_safe_report_value(risk.get("ai_assistive"))}</strong></p>
  <h2>Recommended Next Steps</h2>
  <ul>{"".join(f"<li>{_safe_report_value(step)}</li>" for step in report.get("recommended_next_steps", []))}</ul>
  <h2>Matched Rules</h2>
  {_report_table(report.get("matched_rules", []), rule_columns)}
  <h2>Evidence Logs</h2>
  {_report_table(report.get("evidence_logs", []), evidence_columns)}
  <h2>Timeline</h2>
  {_report_table(report.get("timeline", []), timeline_columns)}
  <h2>Response Actions</h2>
  {_report_table(report.get("response_actions", []), response_columns)}
</body>
</html>"""


def render_alert_report_csv(report: dict) -> str:
    output = StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=[
            "alert_id",
            "severity",
            "status",
            "threat_score",
            "evidence_log_id",
            "generated_time",
            "src_ip",
            "dst_ip",
            "app",
            "action",
            "protocol",
            "dst_port",
            "is_anomaly",
            "anomaly_score",
        ],
    )
    writer.writeheader()
    alert_data = report["alert"]
    for log in report["evidence_logs"]:
        writer.writerow(
            {
                "alert_id": alert_data["id"],
                "severity": alert_data["severity"],
                "status": alert_data["status"],
                "threat_score": alert_data["threat_score"],
                "evidence_log_id": log["id"],
                "generated_time": log["generated_time"],
                "src_ip": log["src_ip"],
                "dst_ip": log["dst_ip"],
                "app": log["app"],
                "action": log["action"],
                "protocol": log["protocol"],
                "dst_port": log["dst_port"],
                "is_anomaly": log["is_anomaly"],
                "anomaly_score": log["anomaly_score"],
            }
        )
    return output.getvalue()


def _pdf_escape(value) -> str:
    text = "-" if value is None else str(value)
    return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _pdf_lines(report: dict) -> list[str]:
    alert = report["alert"]
    sla = report.get("sla", {})
    lines = [
        "ATDR Incident Report",
        f"Generated: {report.get('generated_at')} by {report.get('generated_by', '-')}",
        "",
        f"Alert #{alert.get('id')}: {alert.get('title')}",
        f"Severity: {alert.get('severity')} | Score: {alert.get('threat_score')} | Status: {alert.get('status')}",
        f"SLA: {sla.get('label', '-')} | State: {sla.get('state', '-')} | Due: {sla.get('due_at', '-')}",
        f"Source: {alert.get('src_ip', '-')} | Destination: {alert.get('dst_ip', '-')}",
        "",
        "Executive Summary",
        str(report.get("executive_summary", "-")),
        "",
        "Recommended Next Steps",
    ]
    lines.extend(f"- {step}" for step in report.get("recommended_next_steps", []))
    lines.extend(["", "Matched Rules"])
    for rule in report.get("matched_rules", [])[:10]:
        lines.append(f"- {rule.get('code', '-')}: {rule.get('title', '-')} (+{rule.get('score', '-')})")
    lines.extend(["", "Evidence Logs"])
    for log in report.get("evidence_logs", [])[:10]:
        lines.append(
            f"- Log {log.get('id')}: {log.get('src_ip', '-')} -> {log.get('dst_ip', '-')} "
            f"{log.get('app', '-')} {log.get('action', '-')}"
        )
        if log.get("raw_line_excerpt"):
            lines.append(f"  Raw: {str(log.get('raw_line_excerpt'))[:180]}")
    lines.extend(["", "Timeline"])
    for event in report.get("timeline", [])[:12]:
        lines.append(f"- {event.get('event_time', '-')}: {event.get('event_type', '-')} by {event.get('actor', '-')}")
        lines.append(f"  {event.get('summary', '-')}")
    lines.extend(["", "Response Actions"])
    for action in report.get("response_actions", [])[:10]:
        lines.append(
            f"- {action.get('action_type', '-')} {action.get('target_ip', '-')} "
            f"{action.get('status', '-')} by {action.get('executed_by', '-')}"
        )
    lines.extend(["", "Analyst Notes"])
    for note in report.get("notes", [])[:10]:
        lines.append(f"- {note.get('created_at', '-')}: {note.get('author', '-')} - {note.get('note', '-')}")
    return lines


def _pdf_page_stream(lines: list[str]) -> str:
    y = 760
    commands = ["BT", "/F1 10 Tf", "14 TL"]
    first = True
    for line in lines:
        escaped = _pdf_escape(line[:110])
        if first:
            commands.append(f"72 {y} Td ({escaped}) Tj")
            first = False
        else:
            commands.append(f"T* ({escaped}) Tj")
    commands.append("ET")
    return "\n".join(commands)


def render_alert_report_pdf(report: dict) -> bytes:
    lines = _pdf_lines(report)
    pages = [lines[index : index + 44] for index in range(0, len(lines), 44)] or [["ATDR Incident Report"]]
    objects: list[bytes] = []
    page_object_ids: list[int] = []
    content_object_ids: list[int] = []

    objects.append(b"<< /Type /Catalog /Pages 2 0 R >>")
    objects.append(b"")
    objects.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
    for page_lines in pages:
        content = _pdf_page_stream(page_lines).encode("latin-1", errors="replace")
        content_id = len(objects) + 1
        content_object_ids.append(content_id)
        objects.append(b"<< /Length " + str(len(content)).encode("ascii") + b" >>\nstream\n" + content + b"\nendstream")
        page_id = len(objects) + 1
        page_object_ids.append(page_id)
        objects.append(
            (
                f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
                f"/Resources << /Font << /F1 3 0 R >> >> /Contents {content_id} 0 R >>"
            ).encode("ascii")
        )
    kids = " ".join(f"{page_id} 0 R" for page_id in page_object_ids)
    objects[1] = f"<< /Type /Pages /Kids [{kids}] /Count {len(page_object_ids)} >>".encode("ascii")

    output = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for object_id, payload in enumerate(objects, start=1):
        offsets.append(len(output))
        output.extend(f"{object_id} 0 obj\n".encode("ascii"))
        output.extend(payload)
        output.extend(b"\nendobj\n")
    xref_offset = len(output)
    output.extend(f"xref\n0 {len(objects) + 1}\n".encode("ascii"))
    output.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        output.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    output.extend(
        (
            f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\n"
            f"startxref\n{xref_offset}\n%%EOF\n"
        ).encode("ascii")
    )
    return bytes(output)


def _audit_summary(audit: AuditLog) -> str:
    action = audit.action.replace("_", " ").title()
    if audit.action == "alert_assigned":
        return f"Assigned alert to {audit.details.get('assigned_to', 'unknown')}."
    if audit.action == "alert_note_added":
        return f"Added note: {audit.details.get('note_preview', '')}"
    if audit.action.startswith("alert_"):
        return action.replace("Alert ", "Alert marked ")
    return action


def existing_evidence_log_ids(db: Session) -> set[int]:
    return set(db.scalars(select(AlertEvidence.normalized_log_id)).all())


def alert_counts_by_severity(db: Session) -> dict[str, int]:
    rows = db.execute(select(Alert.severity, func.count(Alert.id)).group_by(Alert.severity)).all()
    return {severity: int(count) for severity, count in rows}
