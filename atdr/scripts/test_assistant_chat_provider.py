from __future__ import annotations

import argparse
import json
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from atdr.app.core.config import get_settings
from atdr.app.db.database import Base
from atdr.app.db.models import (
    Alert,
    AlertEvidence,
    AuditLog,
    DetectionRun,
    LogSource,
    MLLabel,
    MLModelRun,
    NormalizedLog,
    RawLog,
    ResponseAction,
)
from atdr.app.services.assistant_service import answer_assistant_question, assistant_status


SYNTHETIC_RAW_LINE = "synthetic provider probe raw line - should never be sent or returned"


@contextmanager
def _temp_session() -> Iterator[Session]:
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
    db = SessionLocal()
    try:
        _seed_probe_data(db)
        yield db
    finally:
        db.close()
        engine.dispose()


def _seed_probe_data(db: Session) -> None:
    now = datetime(2026, 6, 27, 12, 0, tzinfo=UTC)
    source = LogSource(
        name="assistant-provider-probe-firewall",
        source_type="firewall",
        parser_profile="palo_alto",
        enabled=True,
        logs_received_count=1,
        parse_success_count=1,
        parse_failure_count=0,
        last_seen=now,
        last_log_received_at=now,
    )
    db.add(source)
    db.flush()
    raw = RawLog(
        raw_line=SYNTHETIC_RAW_LINE,
        source_id=source.id,
        imported_at=now,
    )
    db.add(raw)
    db.flush()
    log = NormalizedLog(
        raw_log_id=raw.id,
        receive_time=now,
        generated_time=now,
        log_type="TRAFFIC",
        subtype="end",
        src_ip="203.0.113.77",
        dst_ip="198.51.100.88",
        app="incomplete",
        action="deny",
        src_zone="untrust",
        dst_zone="trust",
        src_port=55122,
        dst_port=22,
        protocol="tcp",
        bytes=240,
        packets=5,
        app_risk=4,
        parsed_json={"probe": "assistant_provider_chat"},
    )
    db.add(log)
    db.flush()
    alert = Alert(
        id=1,
        title="Critical: Assistant provider probe alert",
        alert_type="possible_port_scan",
        src_ip="203.0.113.77",
        dst_ip="198.51.100.88",
        threat_score=91,
        severity="Critical",
        status="open",
        explanation="Synthetic denied SSH-like traffic used to validate the assistant provider path.",
        matched_rules_json=[
            {
                "code": "possible_port_scan",
                "title": "Possible port scan",
                "score": 80,
                "explanation": "Scanning-like denied traffic.",
            }
        ],
        recommended_response="Review related logs before simulated containment.",
        created_at=now,
        updated_at=now,
    )
    db.add(alert)
    db.flush()
    db.add(AlertEvidence(alert_id=alert.id, normalized_log_id=log.id))
    db.commit()


def _side_effect_counts(db: Session) -> dict[str, int]:
    return {
        "response_actions": db.scalar(select(func.count(ResponseAction.id))) or 0,
        "detection_runs": db.scalar(select(func.count(DetectionRun.id))) or 0,
        "model_runs": db.scalar(select(func.count(MLModelRun.id))) or 0,
        "labels": db.scalar(select(func.count(MLLabel.id))) or 0,
        "audit_logs": db.scalar(select(func.count(AuditLog.id))) or 0,
    }


def _safe_excerpt(value: str, *, limit: int = 260) -> str:
    compact = " ".join(value.split())
    return compact[:limit] + ("..." if len(compact) > limit else "")


def build_report(*, execute: bool, question: str = "Why was alert 1 flagged?") -> dict[str, Any]:
    settings = get_settings()
    status = assistant_status(settings)
    report: dict[str, Any] = {
        "ok": True,
        "executed_chat_call": False,
        "llm_enabled": status["llm_enabled"],
        "provider_configured": status["llm_provider_configured"],
        "provider": status["llm_provider_name"] or "disabled",
        "model_configured": status["llm_model_configured"],
        "api_key_configured": status["llm_secret_configured"],
        "raw_log_context_allowed": status["raw_log_context_allowed"],
        "redaction_enabled": status["redaction_enabled"],
        "secrets_exposed": False,
        "raw_log_context_included": False,
        "message": "Assistant chat was not executed. Pass --execute to test the full assistant service with a synthetic temporary database.",
    }
    if not execute:
        return report

    with _temp_session() as db:
        before = _side_effect_counts(db)
        response = answer_assistant_question(
            db,
            question=question,
            actor="assistant-provider-probe",
            settings=settings,
            alert_id=1,
            include_recent_context=True,
        )
        after = _side_effect_counts(db)

    serialized = json.dumps(response, default=str)
    api_key = settings.assistant_llm_api_key.strip()
    raw_line_exposed = SYNTHETIC_RAW_LINE in serialized
    api_key_exposed = bool(api_key and api_key in serialized)
    llm_details = response.get("details", {}).get("llm", {}) if isinstance(response.get("details"), dict) else {}
    mutating_side_effects = {
        key: after[key] - before[key]
        for key in ("response_actions", "detection_runs", "model_runs", "labels")
    }
    report.update(
        {
            "executed_chat_call": True,
            "external_provider_used": bool(response.get("external_provider_used")),
            "mode": response.get("mode"),
            "provider": llm_details.get("provider") or report["provider"],
            "provider_called": bool(llm_details.get("provider_called")),
            "provider_answer_used": bool(llm_details.get("answer_used")),
            "provider_guard_reason": llm_details.get("answer_guard_reason"),
            "fallback_reason": llm_details.get("fallback_reason"),
            "structured_output_valid": bool(llm_details.get("structured_output_valid")),
            "structured_validation_error": llm_details.get("validation_error"),
            "provider_latency_ms": llm_details.get("latency_ms"),
            "provider_attempts": llm_details.get("attempts"),
            "provider_usage": llm_details.get("usage", {}),
            "context_used": response.get("context_used", []),
            "citation_count": len(response.get("citations", [])),
            "suggested_followup_count": len(response.get("suggested_followups", [])),
            "raw_log_context_included": bool(response.get("raw_log_context_included")),
            "raw_line_exposed": raw_line_exposed,
            "secrets_exposed": api_key_exposed or bool(llm_details.get("secrets_exposed")),
            "redaction_applied": bool(response.get("redaction_applied")),
            "assistant_audit_created": after["audit_logs"] - before["audit_logs"] == 1,
            "mutating_side_effects": mutating_side_effects,
            "answer_excerpt": _safe_excerpt(str(response.get("answer", ""))),
        }
    )
    report["ok"] = (
        report["executed_chat_call"]
        and not report["raw_log_context_included"]
        and not report["raw_line_exposed"]
        and not report["secrets_exposed"]
        and all(delta == 0 for delta in mutating_side_effects.values())
        and report["assistant_audit_created"]
    )
    report["message"] = (
        "Full assistant chat provider path completed safely."
        if report["ok"]
        else "Assistant chat provider path completed with safety warnings."
    )
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description="Safely test the full ATDR assistant chat path with a synthetic temporary database.")
    parser.add_argument("--execute", action="store_true", help="Call the assistant service. External LLM is used only if enabled in private config.")
    parser.add_argument("--question", default="Why was alert 1 flagged?", help="Synthetic assistant question to ask.")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON output.")
    args = parser.parse_args()
    report = build_report(execute=args.execute, question=args.question)
    print(json.dumps(report, indent=2 if args.pretty else None, sort_keys=True))


if __name__ == "__main__":
    main()
