import argparse
import json
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from atdr.app.core.config import PROJECT_ROOT
from atdr.app.db.database import SessionLocal, init_db
from atdr.app.db.models import Alert, AuditLog, LogSource, ResponseAction
from atdr.app.services.alert_service import list_alerts
from atdr.app.services.case_service import list_alert_cases
from atdr.app.services.source_service import source_to_dict

DEFAULT_REPORT_DIR = PROJECT_ROOT / "demo_exports" / "lab_validation_reports"


def _json_default(value: Any) -> str:
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def _timed(label: str, fn: Callable[[], Any]) -> tuple[str, Any, float]:
    started = time.perf_counter()
    result = fn()
    return label, result, round(time.perf_counter() - started, 4)


def _safe_filename(value: str) -> str:
    clean = re.sub(r"[^A-Za-z0-9_.-]+", "_", value.strip())[:80].strip("._")
    return clean or "source"


def _alert_summary(alert: Alert) -> dict[str, Any]:
    metadata = next((item for item in (alert.matched_rules_json or []) if item.get("code") == "group_metadata"), {})
    return {
        "alert_id": alert.id,
        "title": alert.title,
        "alert_type": alert.alert_type,
        "severity": alert.severity,
        "status": alert.status,
        "threat_score": alert.threat_score,
        "source_ip": alert.src_ip,
        "destination_ip": alert.dst_ip,
        "evidence_count": len(alert.evidence),
        "occurrence_count": metadata.get("occurrence_count", metadata.get("evidence_count", len(alert.evidence))),
        "related_log_count": metadata.get("related_log_count", len(alert.evidence)),
        "why_flagged": alert.explanation,
        "recommended_response": alert.recommended_response,
        "created_at": alert.created_at,
        "updated_at": alert.updated_at,
    }


def _latest_run_summary(runs: list[dict[str, Any]]) -> dict[str, Any]:
    return runs[0] if runs else {}


def _response_and_audit_summary(db: Session, alerts: list[Alert]) -> dict[str, Any]:
    alert_ids = [alert.id for alert in alerts]
    source_response_count = 0
    source_response_statuses: dict[str, int] = {}
    if alert_ids:
        rows = db.execute(
            select(ResponseAction.status, func.count(ResponseAction.id))
            .where(ResponseAction.alert_id.in_(alert_ids))
            .group_by(ResponseAction.status)
        ).all()
        source_response_statuses = {str(status): int(count) for status, count in rows}
        source_response_count = sum(source_response_statuses.values())

    source_audit_count = 0
    recent_source_audit: list[dict[str, Any]] = []
    if alert_ids:
        target_values = [str(alert_id) for alert_id in alert_ids]
        audits = db.scalars(
            select(AuditLog)
            .where(AuditLog.target_type == "alert", AuditLog.target_value.in_(target_values))
            .order_by(AuditLog.created_at.desc(), AuditLog.id.desc())
            .limit(20)
        ).all()
        source_audit_count = int(
            db.scalar(
                select(func.count(AuditLog.id)).where(AuditLog.target_type == "alert", AuditLog.target_value.in_(target_values))
            )
            or 0
        )
        recent_source_audit = [
            {
                "audit_id": audit.id,
                "actor": audit.actor,
                "action": audit.action,
                "target_type": audit.target_type,
                "target_value": audit.target_value,
                "created_at": audit.created_at,
            }
            for audit in audits
        ]

    return {
        "source_alert_response_actions": source_response_count,
        "source_alert_response_statuses": source_response_statuses,
        "recent_source_alert_audit": recent_source_audit,
        "source_alert_audit_count": source_audit_count,
        "total_response_actions": int(db.scalar(select(func.count(ResponseAction.id))) or 0),
        "total_audit_events": int(db.scalar(select(func.count(AuditLog.id))) or 0),
        "safety": {
            "simulated_response_only": True,
            "automatic_response_enabled": False,
            "analyst_approval_required": True,
        },
    }


def build_lab_validation_report(db: Session, *, source_name: str) -> dict[str, Any]:
    timings: dict[str, float] = {}
    _, source, seconds = _timed(
        "source_detail",
        lambda: db.scalar(select(LogSource).where(LogSource.name == source_name).limit(1)),
    )
    if source is None:
        raise ValueError(f"Source not found: {source_name}")
    timings["source_detail_seconds"] = seconds
    db.refresh(source)

    _, source_detail, seconds = _timed("source_quality", lambda: source_to_dict(source, include_quality=True, db=db))
    timings["source_quality_seconds"] = seconds
    _, alerts, seconds = _timed("source_alerts", lambda: list_alerts(db, source_id=source.id, limit=50))
    timings["source_alert_query_seconds"] = seconds
    _, cases, seconds = _timed("source_cases", lambda: list_alert_cases(db, source_id=source.id, limit=20))
    timings["source_case_query_seconds"] = seconds
    _, response_audit, seconds = _timed("response_audit", lambda: _response_and_audit_summary(db, alerts))
    timings["response_audit_query_seconds"] = seconds

    warnings = []
    health = source_detail.get("health") or {}
    if health.get("status") in {"idle", "warning", "error"}:
        warnings.append(f"Source health is {health.get('status')}; review parser profile, forwarding, and latest errors.")
    if not source_detail.get("quality", {}).get("raw_logs"):
        warnings.append("No raw logs are currently linked to this source.")

    return {
        "ok": True,
        "generated_at": datetime.now(timezone.utc),
        "validation_mode": "controlled_simulation_replay",
        "real_hardware_validation": "not_performed",
        "source_name": source.name,
        "source_id": source.id,
        "source": source_detail,
        "ingestion_runs": source_detail.get("recent_ingestion_runs", []),
        "parser_quality": source_detail.get("quality", {}),
        "detection_runs": source_detail.get("recent_detection_runs", []),
        "alerts": [_alert_summary(alert) for alert in alerts],
        "alert_summary": {
            "count": len(alerts),
            "severe_count": sum(1 for alert in alerts if alert.severity in {"High", "Critical"}),
            "deduplicated_count": sum(
                1
                for alert in alerts
                if any(rule.get("code") == "group_metadata" and rule.get("deduplicated") for rule in (alert.matched_rules_json or []))
            ),
        },
        "advisor_summary": {
            "scenario_or_source": source.name,
            "ingestion_result": _latest_run_summary(source_detail.get("recent_ingestion_runs", [])),
            "parser_result": source_detail.get("quality", {}),
            "detection_result": _latest_run_summary(source_detail.get("recent_detection_runs", [])),
            "ai_status": "Decision support only",
            "response_status": "Simulated response only; manual approval required",
            "hardware_status": "Real router/firewall validation has not been performed yet",
        },
        "cases": cases,
        "response_and_audit": response_audit,
        "performance_timings": timings,
        "warnings": warnings,
        "limitations": [
            "This report is for controlled simulation/replay validation, not production certification.",
            "Response actions remain simulated and analyst-approved.",
            "ML outputs remain SOC triage decision support only.",
            "Real router/firewall hardware forwarding validation has not been performed yet.",
        ],
    }


def render_lab_validation_markdown(report: dict[str, Any]) -> str:
    source = report.get("source", {})
    health = source.get("health", {})
    quality = report.get("parser_quality", {})
    latest_ingestion = _latest_run_summary(report.get("ingestion_runs", []))
    latest_detection = _latest_run_summary(report.get("detection_runs", []))
    response = report.get("response_and_audit", {})
    alerts = report.get("alerts", [])[:8]
    cases = report.get("cases", [])[:5]
    warnings = report.get("warnings", [])
    limitations = report.get("limitations", [])

    lines = [
        "# ATDR Simulation Validation Report",
        "",
        f"- Generated at: {report.get('generated_at')}",
        f"- Validation mode: {report.get('validation_mode')}",
        f"- Source/scenario: {report.get('source_name')}",
        f"- Real hardware validation: {report.get('real_hardware_validation')}",
        "",
        "## Source Health",
        "",
        f"- Source type: {source.get('source_type', '-')}",
        f"- Parser profile: {source.get('parser_profile', '-')}",
        f"- Status: {health.get('status', '-')}",
        f"- Logs received: {source.get('logs_received_count', 0)}",
        f"- Parse success/failure: {source.get('parse_success_count', 0)} / {source.get('parse_failure_count', 0)}",
        f"- Last log received: {source.get('last_log_received_at', '-')}",
        "",
        "## Ingestion And Parser Result",
        "",
        f"- Latest ingestion run: {latest_ingestion.get('run_id', '-')}",
        f"- Lines received: {latest_ingestion.get('total_lines_received', '-')}",
        f"- Raw logs created: {latest_ingestion.get('raw_logs_created', '-')}",
        f"- Parsed successfully: {latest_ingestion.get('parsed_successfully', '-')}",
        f"- Parse failures: {latest_ingestion.get('parse_failures', '-')}",
        f"- Duplicate raw logs: {latest_ingestion.get('duplicate_raw_logs', '-')}",
        f"- Source-linked raw logs: {quality.get('raw_logs', 0)}",
        f"- Source-linked normalized logs: {quality.get('normalized_logs', 0)}",
        f"- Unknown app rate: {quality.get('unknown_app_rate', 0)}%",
        "",
        "## Detection And Alerts",
        "",
        f"- Latest detection run: {latest_detection.get('run_id', '-')}",
        f"- Logs evaluated: {latest_detection.get('logs_evaluated', '-')}",
        f"- Alerts created: {latest_detection.get('alerts_created', '-')}",
        f"- Alerts deduplicated: {latest_detection.get('alerts_deduplicated', '-')}",
        f"- Alert count in report: {report.get('alert_summary', {}).get('count', 0)}",
        f"- Severe alert count: {report.get('alert_summary', {}).get('severe_count', 0)}",
        "",
        "## Evidence Examples",
        "",
    ]
    if alerts:
        for alert in alerts:
            lines.extend(
                [
                    f"- Alert {alert.get('alert_id')}: {alert.get('title')}",
                    f"  - Severity/score: {alert.get('severity')} / {alert.get('threat_score')}",
                    f"  - Evidence logs: {alert.get('evidence_count')}",
                    f"  - Occurrences: {alert.get('occurrence_count')}",
                    f"  - Why flagged: {alert.get('why_flagged')}",
                ]
            )
    else:
        lines.append("- No source-linked alerts found in this report.")
    lines.extend(["", "## Case Summary", ""])
    if cases:
        for case in cases:
            lines.append(
                f"- {case.get('title', 'Case')}: {case.get('related_alert_count', 0)} alert(s), "
                f"{case.get('total_related_logs', 0)} related log(s)."
            )
    else:
        lines.append("- No source-linked cases found in this report.")
    lines.extend(
        [
            "",
            "## Response And Audit Safety",
            "",
            f"- Source alert response actions: {response.get('source_alert_response_actions', 0)}",
            f"- Total audit events: {response.get('total_audit_events', 0)}",
            "- Simulated response only: yes",
            "- Manual approval required: yes",
            "- Automatic response enabled: no",
            "",
            "## Performance Timings",
            "",
        ]
    )
    for key, value in (report.get("performance_timings") or {}).items():
        lines.append(f"- {key}: {value}s")
    lines.extend(["", "## Warnings", ""])
    lines.extend([f"- {warning}" for warning in warnings] or ["- No warnings."])
    lines.extend(["", "## Limitations", ""])
    lines.extend(f"- {item}" for item in limitations)
    lines.append("")
    return "\n".join(lines)


def export_lab_validation_report(
    *,
    source_name: str,
    output_dir: Path | None = None,
    output_format: str = "both",
    db: Session | None = None,
) -> dict[str, Any]:
    owns_session = db is None
    if owns_session:
        init_db()
        db = SessionLocal()
    try:
        try:
            report = build_lab_validation_report(db, source_name=source_name)
        except ValueError as exc:
            return {"ok": False, "error": str(exc), "source_name": source_name}
        target_dir = output_dir or DEFAULT_REPORT_DIR
        target_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        stem = f"{_safe_filename(source_name)}_{timestamp}"
        paths: dict[str, str] = {}
        normalized_format = output_format if output_format in {"json", "markdown", "both"} else "both"
        path = target_dir / f"{stem}.json"
        if normalized_format in {"json", "both"}:
            path.write_text(json.dumps(report, default=_json_default, indent=2), encoding="utf-8")
            paths["json"] = str(path)
        markdown_path = target_dir / f"{stem}.md"
        if normalized_format in {"markdown", "both"}:
            markdown_path.write_text(render_lab_validation_markdown(report), encoding="utf-8")
            paths["markdown"] = str(markdown_path)
        return {
            "ok": True,
            "path": paths.get("json") or paths.get("markdown"),
            "paths": paths,
            "source_name": report["source_name"],
            "source_id": report["source_id"],
            "alert_count": report["alert_summary"]["count"],
            "severe_alert_count": report["alert_summary"]["severe_count"],
            "warnings": report["warnings"],
            "report": report,
        }
    finally:
        if owns_session and db is not None:
            db.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Export a safe ATDR lab validation report for one log source.")
    parser.add_argument("--source-name", required=True)
    parser.add_argument("--output-dir", default=None)
    parser.add_argument("--format", choices=["json", "markdown", "both"], default="both")
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()

    output_dir = Path(args.output_dir) if args.output_dir else None
    result = export_lab_validation_report(source_name=args.source_name, output_dir=output_dir, output_format=args.format)
    print(json.dumps(result, default=_json_default, indent=2 if args.pretty else None))
    raise SystemExit(0 if result.get("ok") else 1)


if __name__ == "__main__":
    main()
