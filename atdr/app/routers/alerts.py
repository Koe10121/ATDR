from fastapi import APIRouter, Depends, HTTPException, Query, Response
from fastapi.responses import HTMLResponse, StreamingResponse
from sqlalchemy.orm import Session

from atdr.app.core.security import require_analyst_or_admin
from atdr.app.db.database import get_db
from atdr.app.db.models import User
from atdr.app.schemas.alerts import (
    ALLOWED_ALERT_STATUSES,
    AlertAssignRequest,
    AlertEscalateRequest,
    AlertNoteCreate,
    AlertNoteRead,
    AlertRead,
    AlertStatusResponse,
    AlertStatusUpdate,
    AlertTimelineEvent,
)
from atdr.app.detection.explanations import build_alert_detection_summary
from atdr.app.services.alert_service import (
    add_alert_note,
    alert_report,
    alert_sla,
    alert_timeline,
    assign_alert,
    count_alerts,
    escalate_alert,
    get_alert,
    list_alert_notes,
    list_alerts,
    render_alert_report_csv,
    render_alert_report_html,
    render_alert_report_pdf,
    update_alert_status,
)

router = APIRouter(prefix="/api/alerts", tags=["alerts"])


def _alert_to_dict(alert, db: Session | None = None, *, include_detection_summary: bool = False) -> dict:
    payload = {
        "id": alert.id,
        "title": alert.title,
        "alert_type": alert.alert_type,
        "src_ip": alert.src_ip,
        "dst_ip": alert.dst_ip,
        "threat_score": alert.threat_score,
        "severity": alert.severity,
        "status": alert.status,
        "assigned_to": alert.assigned_to,
        "assigned_at": alert.assigned_at,
        "priority_owner": alert.priority_owner,
        "escalation_reason": alert.escalation_reason,
        "ticket_reference": alert.ticket_reference,
        "escalated_at": alert.escalated_at,
        "explanation": alert.explanation,
        "matched_rules_json": alert.matched_rules_json,
        "recommended_response": alert.recommended_response,
        "created_at": alert.created_at,
        "updated_at": alert.updated_at,
        "evidence_count": len(alert.evidence),
        "evidence_log_ids": [item.normalized_log_id for item in alert.evidence],
        "sla": alert_sla(alert),
    }
    if include_detection_summary and db is not None:
        payload["detection_summary"] = build_alert_detection_summary(db, alert)
    return payload

@router.get("", response_model=list[AlertRead])
def api_list_alerts(
    response: Response,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
    search: str | None = None,
    severity: str | None = None,
    status: str | None = None,
    src_ip: str | None = None,
    dst_ip: str | None = None,
    alert_type: str | None = None,
    assigned_to: str | None = None,
    mine: bool = False,
    unassigned: bool = False,
    sort_by: str = "created",
    limit: int = 100,
    offset: int = 0,
) -> list[dict]:
    owner = current_user.username if mine else assigned_to
    filters = {
        "search": search,
        "severity": severity,
        "status": status,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "alert_type": alert_type,
        "assigned_to": owner,
        "unassigned": unassigned,
        "sort_by": sort_by,
    }
    response.headers["X-Total-Count"] = str(count_alerts(db, **filters))
    return [
        _alert_to_dict(alert)
        for alert in list_alerts(
            db,
            **filters,
            limit=limit,
            offset=offset,
        )
    ]


@router.get("/{alert_id}", response_model=AlertRead)
def api_get_alert(
    alert_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
) -> dict:
    alert = get_alert(db, alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found.")
    return _alert_to_dict(alert, db, include_detection_summary=True)


@router.post("/{alert_id}/assign", response_model=AlertRead)
def assign_alert_endpoint(
    alert_id: int,
    request: AlertAssignRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
) -> dict:
    assigned_to = request.username or current_user.username
    if assigned_to != current_user.username and current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Only admins can assign alerts to another user.")
    try:
        alert = assign_alert(db, alert_id, assigned_to=assigned_to, actor=current_user.username)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found.")
    return _alert_to_dict(alert)


@router.post("/{alert_id}/assign/me", response_model=AlertRead)
def assign_alert_to_self(
    alert_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
) -> dict:
    alert = assign_alert(db, alert_id, assigned_to=current_user.username, actor=current_user.username)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found.")
    return _alert_to_dict(alert)


@router.post("/{alert_id}/escalate", response_model=AlertRead)
def escalate_alert_endpoint(
    alert_id: int,
    request: AlertEscalateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
) -> dict:
    alert = escalate_alert(
        db,
        alert_id,
        priority_owner=request.priority_owner,
        escalation_reason=request.escalation_reason,
        ticket_reference=request.ticket_reference,
        actor=current_user.username,
    )
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found.")
    return _alert_to_dict(alert)


def _set_alert_status(db: Session, alert_id: int, status: str, username: str) -> dict:
    normalized = status.strip().lower().replace("-", "_")
    if normalized not in ALLOWED_ALERT_STATUSES:
        raise HTTPException(status_code=400, detail=f"Unsupported alert status: {status}")
    try:
        alert = update_alert_status(db, alert_id, normalized, actor=username)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found.")
    return {"id": alert.id, "status": alert.status, "updated_at": alert.updated_at}


@router.post("/{alert_id}/status", response_model=AlertStatusResponse)
def update_status(
    alert_id: int,
    request: AlertStatusUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
) -> dict:
    return _set_alert_status(db, alert_id, request.normalized_status(), current_user.username)


@router.post("/{alert_id}/investigate", response_model=AlertStatusResponse)
def investigate_alert(
    alert_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
) -> dict:
    return _set_alert_status(db, alert_id, "investigating", current_user.username)


@router.post("/{alert_id}/contain", response_model=AlertStatusResponse)
def contain_alert(
    alert_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
) -> dict:
    return _set_alert_status(db, alert_id, "contained", current_user.username)


@router.post("/{alert_id}/resolve", response_model=AlertStatusResponse)
def resolve_alert(
    alert_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
) -> dict:
    return _set_alert_status(db, alert_id, "resolved", current_user.username)


@router.post("/{alert_id}/false-positive", response_model=AlertStatusResponse)
def false_positive_alert(
    alert_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
) -> dict:
    return _set_alert_status(db, alert_id, "false_positive", current_user.username)


@router.post("/{alert_id}/notes", response_model=AlertNoteRead)
def create_alert_note(
    alert_id: int,
    request: AlertNoteCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
):
    note = add_alert_note(db, alert_id, author=current_user.username, note=request.note)
    if note is None:
        raise HTTPException(status_code=404, detail="Alert not found.")
    return note


@router.get("/{alert_id}/notes", response_model=list[AlertNoteRead])
def get_alert_notes(
    alert_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
):
    notes = list_alert_notes(db, alert_id)
    if notes is None:
        raise HTTPException(status_code=404, detail="Alert not found.")
    return notes


@router.get("/{alert_id}/timeline", response_model=list[AlertTimelineEvent])
def get_alert_timeline(
    alert_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
):
    timeline = alert_timeline(db, alert_id)
    if timeline is None:
        raise HTTPException(status_code=404, detail="Alert not found.")
    return timeline


@router.get("/{alert_id}/report")
def get_alert_report(
    alert_id: int,
    format: str = Query(default="json", pattern="^(json|csv|html|pdf)$"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
):
    report = alert_report(db, alert_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Alert not found.")
    report["generated_by"] = current_user.username
    if format == "json":
        return report
    if format == "html":
        return HTMLResponse(
            content=render_alert_report_html(report),
            headers={"Content-Disposition": f'attachment; filename="alert-{alert_id}-report.html"'},
        )
    if format == "pdf":
        return Response(
            content=render_alert_report_pdf(report),
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="alert-{alert_id}-report.pdf"'},
        )

    return StreamingResponse(
        iter([render_alert_report_csv(report)]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="alert-{alert_id}-report.csv"'},
    )
