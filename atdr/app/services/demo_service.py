import json
from pathlib import Path
from datetime import datetime, timezone

from sqlalchemy import delete, desc, select
from sqlalchemy.orm import Session

from atdr.app.core.config import PROJECT_ROOT, get_settings
from atdr.app.db.models import (
    Alert,
    AlertEvidence,
    AlertNote,
    AuditLog,
    BlockedIP,
    MLModelRun,
    NormalizedLog,
    RawLog,
    ResponseAction,
    SuppressionRule,
    WatchlistItem,
)
from atdr.app.services.alert_service import alert_report, render_alert_report_csv, render_alert_report_html, render_alert_report_pdf
from atdr.app.services.dashboard_service import build_dashboard_summary
from atdr.app.services.detection_service import run_detection
from atdr.app.services.log_service import import_log_file
from atdr.app.services.ml_service import apply_anomaly_scoring, evaluation_report, train_anomaly_model
from atdr.app.services.user_service import ensure_demo_users


DELETE_ORDER = [
    ResponseAction,
    BlockedIP,
    AlertEvidence,
    AlertNote,
    Alert,
    AuditLog,
    MLModelRun,
    SuppressionRule,
    WatchlistItem,
    NormalizedLog,
    RawLog,
]


def clear_demo_data(db: Session) -> dict:
    deleted: dict[str, int] = {}
    for model in DELETE_ORDER:
        result = db.execute(delete(model))
        deleted[model.__tablename__] = int(result.rowcount or 0)
    db.commit()
    return deleted


def reset_and_seed_demo(
    db: Session,
    *,
    sample_path: str | Path | None = None,
    limit: int | None = 5000,
    use_ml: bool = False,
    actor: str = "reset_demo",
) -> dict:
    path = resolve_demo_sample_path(sample_path)
    deleted = clear_demo_data(db)
    users = ensure_demo_users(db)
    import_result = import_log_file(db, path, limit=limit, actor=actor)
    detection_result = run_detection(db, limit=limit, use_ml=use_ml, actor=actor)
    return {
        "deleted": deleted,
        "users": users,
        "import": import_result,
        "detection": detection_result,
    }


def resolve_demo_sample_path(sample_path: str | Path | None = None) -> Path:
    settings = get_settings()
    path = Path(sample_path or settings.demo_sample_log_path)
    if not path.is_absolute():
        path = PROJECT_ROOT / path
    return path


def import_demo_sample_logs(
    db: Session,
    *,
    sample_path: str | Path | None = None,
    limit: int | None = None,
    actor: str,
) -> dict:
    settings = get_settings()
    import_limit = settings.demo_import_limit if limit is None else limit
    if import_limit is not None and import_limit <= 0:
        import_limit = None
    path = resolve_demo_sample_path(sample_path)
    return import_log_file(db, path, limit=import_limit, actor=actor)


def run_demo_detection(
    db: Session,
    *,
    limit: int | None = None,
    use_ml: bool = False,
    actor: str,
) -> dict:
    settings = get_settings()
    detection_limit = settings.demo_import_limit if limit is None else limit
    if detection_limit is not None and detection_limit <= 0:
        detection_limit = None
    return run_detection(db, limit=detection_limit, use_ml=use_ml, actor=actor)


def train_demo_ml_model(db: Session, *, limit: int | None = None, actor: str) -> dict:
    settings = get_settings()
    train_limit = settings.demo_import_limit if limit is None else limit
    if train_limit is not None and train_limit <= 0:
        train_limit = None
    return train_anomaly_model(db, limit=train_limit, actor=actor)


def apply_demo_ml_scoring(db: Session, *, limit: int | None = None, actor: str) -> dict:
    settings = get_settings()
    score_limit = settings.demo_import_limit if limit is None else limit
    if score_limit is not None and score_limit <= 0:
        score_limit = None
    return apply_anomaly_scoring(db, limit=score_limit, actor=actor)


def _json_default(value):
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def _write_json(path: Path, payload: dict | list) -> None:
    path.write_text(json.dumps(payload, default=_json_default, indent=2), encoding="utf-8")


def _top_alert_rows(db: Session, limit: int) -> list[dict]:
    alerts = db.scalars(select(Alert).order_by(desc(Alert.threat_score), desc(Alert.updated_at), desc(Alert.id)).limit(limit)).all()
    return [
        {
            "id": alert.id,
            "title": alert.title,
            "alert_type": alert.alert_type,
            "severity": alert.severity,
            "status": alert.status,
            "threat_score": alert.threat_score,
            "src_ip": alert.src_ip,
            "dst_ip": alert.dst_ip,
            "assigned_to": alert.assigned_to,
            "ticket_reference": alert.ticket_reference,
            "evidence_count": len(alert.evidence),
            "created_at": alert.created_at,
            "updated_at": alert.updated_at,
        }
        for alert in alerts
    ]


def _recent_audit_rows(db: Session, limit: int) -> list[dict]:
    rows = db.scalars(select(AuditLog).order_by(desc(AuditLog.created_at), desc(AuditLog.id)).limit(limit)).all()
    return [
        {
            "id": row.id,
            "actor": row.actor,
            "action": row.action,
            "target_type": row.target_type,
            "target_value": row.target_value,
            "details": row.details,
            "created_at": row.created_at,
        }
        for row in rows
    ]


def _markdown_summary(
    *,
    generated_at: datetime,
    actor: str,
    summary: dict,
    top_alerts: list[dict],
    ml_report: dict,
    selected_alert_id: int | None,
) -> str:
    top_alert = top_alerts[0] if top_alerts else {}
    return f"""# MFU ATDR Demo Evidence Summary

Generated at: {generated_at.isoformat()}
Generated by: {actor}

## Current Stage

- Senior project prototype: complete
- Lab pilot readiness: mostly ready
- Production deployment: requires PostgreSQL/Docker validation, HTTPS, backup jobs, real baseline tuning, and approved firewall integration

## Operational Snapshot

- Logs ingested: {summary.get("total_logs", 0)}
- Total alerts: {summary.get("total_alerts", 0)}
- Active alerts: {summary.get("active_alerts", 0)}
- Critical open alerts: {summary.get("critical_open_alerts", 0)}
- ML anomaly rate: {summary.get("anomaly_rate", 0)}%
- Active suppressions: {summary.get("active_suppressions", 0)}
- Watchlist hits: {summary.get("watchlist_hits", 0)}

## Supervisor Talking Points

- Raw logs are preserved before parsing so every alert has evidence.
- Rules are primary because they are explainable and easier to defend.
- IsolationForest is assistive; it highlights unusual traffic but does not prove malicious activity by itself.
- Response actions are simulated by default to avoid changing real firewall devices.
- Real enforcement requires PostgreSQL deployment, HTTPS, backups, baseline tuning, approvals, allowlists, and rollback.

## Highest Priority Alert

- Alert ID: {top_alert.get("id", "-")}
- Severity: {top_alert.get("severity", "-")}
- Score: {top_alert.get("threat_score", "-")}
- Title: {top_alert.get("title", "-")}

## Exported Incident Report

Selected alert ID: {selected_alert_id or "-"}

## ML Governance

- Model artifact ready: {ml_report.get("model_status", {}).get("artifact_exists", False)}
- Scored logs: {ml_report.get("scored_log_count", 0)}
- Current anomalies: {ml_report.get("anomaly_count", 0)}
- Drift signals: {len(ml_report.get("drift_signals", []))}
"""


def export_demo_bundle(
    db: Session,
    *,
    actor: str,
    alert_id: int | None = None,
    output_dir: str | Path | None = None,
    top_alert_limit: int = 10,
    audit_limit: int = 50,
) -> dict:
    generated_at = datetime.now(timezone.utc)
    root = Path(output_dir) if output_dir else PROJECT_ROOT / "demo_exports"
    if not root.is_absolute():
        root = PROJECT_ROOT / root
    bundle_dir = root / f"atdr_demo_bundle_{generated_at.strftime('%Y%m%d_%H%M%S')}"
    bundle_dir.mkdir(parents=True, exist_ok=True)

    summary = build_dashboard_summary(db)
    top_alerts = _top_alert_rows(db, top_alert_limit)
    recent_audit = _recent_audit_rows(db, audit_limit)
    ml_report = evaluation_report(db)
    selected_alert_id = alert_id or (top_alerts[0]["id"] if top_alerts else None)

    files: dict[str, str] = {}
    file_payloads: list[tuple[str, dict | list]] = [
        ("dashboard_summary.json", summary),
        ("top_alerts.json", top_alerts),
        ("recent_audit.json", recent_audit),
        ("ml_evaluation.json", ml_report),
    ]
    for filename, payload in file_payloads:
        path = bundle_dir / filename
        _write_json(path, payload)
        files[filename] = str(path)

    incident_report = None
    if selected_alert_id is not None:
        incident_report = alert_report(db, selected_alert_id)
        if incident_report is not None:
            incident_report["generated_by"] = actor
            json_path = bundle_dir / f"alert_{selected_alert_id}_report.json"
            csv_path = bundle_dir / f"alert_{selected_alert_id}_report.csv"
            html_path = bundle_dir / f"alert_{selected_alert_id}_report.html"
            pdf_path = bundle_dir / f"alert_{selected_alert_id}_report.pdf"
            _write_json(json_path, incident_report)
            csv_path.write_text(render_alert_report_csv(incident_report), encoding="utf-8")
            html_path.write_text(render_alert_report_html(incident_report), encoding="utf-8")
            pdf_path.write_bytes(render_alert_report_pdf(incident_report))
            files[json_path.name] = str(json_path)
            files[csv_path.name] = str(csv_path)
            files[html_path.name] = str(html_path)
            files[pdf_path.name] = str(pdf_path)

    markdown = _markdown_summary(
        generated_at=generated_at,
        actor=actor,
        summary=summary,
        top_alerts=top_alerts,
        ml_report=ml_report,
        selected_alert_id=selected_alert_id if incident_report is not None else None,
    )
    markdown_path = bundle_dir / "demo_summary.md"
    markdown_path.write_text(markdown, encoding="utf-8")
    files[markdown_path.name] = str(markdown_path)

    db.add(
        AuditLog(
            actor=actor,
            action="demo_bundle_exported",
            target_type="demo_bundle",
            target_value=str(bundle_dir),
            details={
                "selected_alert_id": selected_alert_id,
                "file_count": len(files),
                "total_logs": summary.get("total_logs", 0),
                "total_alerts": summary.get("total_alerts", 0),
            },
        )
    )
    db.commit()

    return {
        "generated_at": generated_at,
        "export_dir": str(bundle_dir),
        "selected_alert_id": selected_alert_id if incident_report is not None else None,
        "files": files,
        "counts": {
            "total_logs": summary.get("total_logs", 0),
            "total_alerts": summary.get("total_alerts", 0),
            "top_alerts": len(top_alerts),
            "audit_events": len(recent_audit),
            "ml_drift_signals": len(ml_report.get("drift_signals", [])),
        },
    }
