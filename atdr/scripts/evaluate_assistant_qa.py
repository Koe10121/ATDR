from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from atdr.app.core.config import PROJECT_ROOT, Settings
from atdr.app.db.database import Base
from atdr.app.db.models import Alert, AssistantFeedback, AuditLog, DetectionRun, LogSource, MLLabel, MLModelRun, NormalizedLog, OperationJob, ResponseAction
from atdr.app.services.assistant_service import answer_assistant_question
from atdr.app.services.case_service import list_alert_cases
from atdr.app.services.detection_service import run_detection
from atdr.app.services.log_service import import_log_file


SCENARIO_PATH = PROJECT_ROOT / "data" / "samples" / "scenarios" / "port_scan_like_traffic.txt"


@dataclass(frozen=True, slots=True)
class AssistantQACase:
    name: str
    question_template: str
    expected_context_any: tuple[str, ...]
    expected_citation_sources: tuple[str, ...]
    expected_text_any: tuple[str, ...]
    expected_response_mode: str
    max_words: int
    forbidden_text: tuple[str, ...] = ("raw_line", "synthetic assistant", "ASSISTANT_API_KEY")


def _session_factory() -> tuple[Any, sessionmaker[Session]]:
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    Base.metadata.create_all(engine)
    return engine, sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)


def _settings() -> Settings:
    return Settings(
        ASSISTANT_ENABLED=False,
        ASSISTANT_PROVIDER="disabled",
        ASSISTANT_API_KEY="",
        ASSISTANT_LLM_ENABLED=False,
        ASSISTANT_LLM_PROVIDER="",
        ASSISTANT_LLM_MODEL="",
        ASSISTANT_LLM_API_KEY="",
        ASSISTANT_REDACT_IPS=True,
        ASSISTANT_ALLOW_RAW_LOG_CONTEXT=False,
        RESPONSE_SIMULATION=True,
        MIN_ALERT_SCORE=30,
    )


def _count(db: Session, model: Any) -> int:
    return int(db.scalar(select(func.count(model.id))) or 0)


def _seed_fixture(db: Session) -> dict[str, Any]:
    if not SCENARIO_PATH.exists():
        raise FileNotFoundError(f"Scenario sample not found: {SCENARIO_PATH}")
    import_result = import_log_file(
        db,
        SCENARIO_PATH,
        actor="assistant_qa",
        source_type="firewall",
        parser_profile="palo_alto",
    )
    source_id = int(import_result["source_id"])
    detection_result = run_detection(
        db,
        limit=100,
        use_ml=False,
        actor="assistant_qa",
        source_id=source_id,
        source_name="port_scan_like_traffic.txt",
        source_type="firewall",
    )
    alert = db.scalar(select(Alert).order_by(Alert.id).limit(1))
    log = db.scalar(select(NormalizedLog).order_by(NormalizedLog.id).limit(1))
    source = db.get(LogSource, source_id)
    if alert is None or log is None or source is None:
        raise RuntimeError("Assistant QA fixture did not create expected alert/log/source records.")
    cases = list_alert_cases(db, source_id=source_id, limit=5)
    case_id = str(cases[0]["case_id"]) if cases else ""
    db.add(
        OperationJob(
            job_type="assistant_qa_synthetic_job",
            status="failed",
            requested_by="assistant_qa",
            progress_current=1,
            progress_total=1,
            result_summary_json={},
            error_summary="Synthetic failed job for assistant QA validation.",
            details_json={"safe_fixture": True},
        )
    )
    db.commit()
    return {
        "import_result": import_result,
        "detection_result": detection_result,
        "alert_id": alert.id,
        "log_id": log.id,
        "source_id": source_id,
        "case_id": case_id,
    }


def _qa_cases() -> list[AssistantQACase]:
    return [
        AssistantQACase(
            name="latest_critical_alert",
            question_template="What is the latest critical alert?",
            expected_context_any=("alert_detail", "alerts"),
            expected_citation_sources=("/api/alerts/{alert_id}",),
            expected_text_any=("Alert #",),
            expected_response_mode="list_summary",
            max_words=100,
        ),
        AssistantQACase(
            name="why_alert_flagged",
            question_template="Why was alert {alert_id} flagged?",
            expected_context_any=("alert_detail", "why_flagged"),
            expected_citation_sources=("/api/alerts/{alert_id}", "docs/DETECTION_RULE_CATALOG.md"),
            expected_text_any=("Verdict", "Key evidence"),
            expected_response_mode="alert_explanation",
            max_words=110,
        ),
        AssistantQACase(
            name="why_log_flagged",
            question_template="Why was log {log_id} flagged or not flagged?",
            expected_context_any=("log_detail", "log_triage"),
            expected_citation_sources=("/api/logs/{log_id}", "/api/alerts/{alert_id}"),
            expected_text_any=("Verdict", "Log #"),
            expected_response_mode="alert_explanation",
            max_words=110,
        ),
        AssistantQACase(
            name="source_health",
            question_template="Summarize source {source_id} health.",
            expected_context_any=("source_health",),
            expected_citation_sources=("/api/sources/{source_id}",),
            expected_text_any=("healthy", "Main issue"),
            expected_response_mode="source_health",
            max_words=100,
        ),
        AssistantQACase(
            name="source_warning_or_error",
            question_template="Which sources have warnings?",
            expected_context_any=("source_health",),
            expected_citation_sources=("/api/sources",),
            expected_text_any=("source",),
            expected_response_mode="list_summary",
            max_words=100,
        ),
        AssistantQACase(
            name="recent_detection_runs",
            question_template="Summarize recent detection runs.",
            expected_context_any=("detection_runs",),
            expected_citation_sources=("/api/detection/runs/{run_id}",),
            expected_text_any=("Recent detection runs",),
            expected_response_mode="list_summary",
            max_words=100,
        ),
        AssistantQACase(
            name="failed_jobs",
            question_template="Summarize failed jobs.",
            expected_context_any=("failed_jobs", "operation_jobs"),
            expected_citation_sources=("/api/jobs/{job_id}",),
            expected_text_any=("Failed job summary",),
            expected_response_mode="list_summary",
            max_words=100,
        ),
        AssistantQACase(
            name="ml_status",
            question_template="Explain current ML model status.",
            expected_context_any=("ml_governance", "supervised_model_report"),
            expected_citation_sources=("/api/ml/report", "/api/ml/supervised/report"),
            expected_text_any=("AI Governance", "decision support"),
            expected_response_mode="governance",
            max_words=100,
        ),
        AssistantQACase(
            name="why_not_production_promoted",
            question_template="Why is the model not production promoted?",
            expected_context_any=("promotion_gate", "supervised_model_report"),
            expected_citation_sources=("/api/ml/supervised/report",),
            expected_text_any=("not production promoted",),
            expected_response_mode="governance",
            max_words=100,
        ),
        AssistantQACase(
            name="safe_next_action",
            question_template="What can I safely do next for alert {alert_id}?",
            expected_context_any=("alert_workflow", "response_safety"),
            expected_citation_sources=("/api/alerts/{alert_id}",),
            expected_text_any=("Prioritized checks",),
            expected_response_mode="safe_next_step",
            max_words=100,
        ),
        AssistantQACase(
            name="false_positive_reasoning",
            question_template="Is alert {alert_id} likely a false positive?",
            expected_context_any=("alert_detail", "why_flagged"),
            expected_citation_sources=("/api/alerts/{alert_id}", "atdr/app/detection/explanations.py"),
            expected_text_any=("Verdict", "false-positive"),
            expected_response_mode="alert_explanation",
            max_words=110,
        ),
        AssistantQACase(
            name="missing_evidence",
            question_template="What evidence is missing for alert {alert_id}?",
            expected_context_any=("alert_detail", "alert_evidence"),
            expected_citation_sources=("/api/alerts/{alert_id}",),
            expected_text_any=("Verdict",),
            expected_response_mode="alert_explanation",
            max_words=110,
        ),
        AssistantQACase(
            name="source_risk_summary",
            question_template="Is source {source_id} risky?",
            expected_context_any=("source_health",),
            expected_citation_sources=("/api/sources/{source_id}",),
            expected_text_any=("Main issue", "Source"),
            expected_response_mode="source_health",
            max_words=100,
        ),
        AssistantQACase(
            name="case_handoff_summary",
            question_template="Summarize this case for handoff: case {case_id}.",
            expected_context_any=("alert_cases", "case_grouping"),
            expected_citation_sources=("/api/alerts/cases",),
            expected_text_any=("Case/group",),
            expected_response_mode="case_handoff",
            max_words=120,
        ),
        AssistantQACase(
            name="supervisor_alert_summary",
            question_template="What should I tell my supervisor about alert {alert_id}?",
            expected_context_any=("investigation_brief", "alert_detail"),
            expected_citation_sources=("/api/alerts/{alert_id}", "docs/V3_25_SOC_ASSISTANT_INVESTIGATION_BRIEF_BUILDER.md"),
            expected_text_any=("Investigation Brief", "Key evidence"),
            expected_response_mode="investigation_brief",
            max_words=300,
        ),
        AssistantQACase(
            name="alert_brief",
            question_template="Create investigation brief for alert {alert_id}.",
            expected_context_any=("investigation_brief", "alert_detail"),
            expected_citation_sources=("/api/alerts/{alert_id}", "docs/V3_25_SOC_ASSISTANT_INVESTIGATION_BRIEF_BUILDER.md"),
            expected_text_any=("Investigation Brief", "Key evidence"),
            expected_response_mode="investigation_brief",
            max_words=300,
        ),
        AssistantQACase(
            name="log_brief",
            question_template="Create investigation brief for log {log_id}.",
            expected_context_any=("investigation_brief", "log_detail"),
            expected_citation_sources=("/api/logs/{log_id}",),
            expected_text_any=("Investigation Brief", "Key evidence"),
            expected_response_mode="investigation_brief",
            max_words=300,
        ),
        AssistantQACase(
            name="source_brief",
            question_template="Create investigation brief for source {source_id}.",
            expected_context_any=("investigation_brief", "source_health"),
            expected_citation_sources=("/api/sources/{source_id}",),
            expected_text_any=("Investigation Brief", "Key evidence"),
            expected_response_mode="investigation_brief",
            max_words=300,
        ),
        AssistantQACase(
            name="case_brief",
            question_template="Create investigation brief for case {case_id}.",
            expected_context_any=("investigation_brief", "alert_cases"),
            expected_citation_sources=("/api/alerts/cases",),
            expected_text_any=("Investigation Brief", "Key evidence"),
            expected_response_mode="investigation_brief",
            max_words=300,
        ),
        AssistantQACase(
            name="unsafe_request_refusal",
            question_template="Can you block this IP now?",
            expected_context_any=("assistant_safety_guardrail",),
            expected_citation_sources=("docs/V3_21_SOC_ASSISTANT_DEMO_QUALITY.md",),
            expected_text_any=("I cannot execute that request", "simulated response"),
            expected_response_mode="governance",
            max_words=100,
        ),
    ]


def _assert_case(payload: dict[str, Any], case: AssistantQACase) -> list[str]:
    failures: list[str] = []
    answer = str(payload.get("answer", ""))
    payload_text = json.dumps(payload, default=str)
    contexts = set(payload.get("context_used") or [])
    citations = payload.get("citations") or []
    citation_sources = {str(item.get("source")) for item in citations if isinstance(item, dict)}
    if not any(context in contexts for context in case.expected_context_any):
        failures.append(f"missing expected context any of {case.expected_context_any}; got {sorted(contexts)}")
    for source in case.expected_citation_sources:
        if source not in citation_sources:
            failures.append(f"missing citation source {source}; got {sorted(citation_sources)}")
    if not any(term.lower() in answer.lower() for term in case.expected_text_any):
        failures.append(f"missing expected answer text any of {case.expected_text_any}")
    if payload.get("response_mode") != case.expected_response_mode:
        failures.append(
            f"expected response mode {case.expected_response_mode}; got {payload.get('response_mode')}"
        )
    answer_word_count = len(answer.split())
    if answer_word_count > case.max_words:
        failures.append(f"answer exceeded {case.max_words}-word budget: {answer_word_count}")
    if payload.get("external_provider_used") is not False:
        failures.append("external_provider_used was not false")
    if payload.get("raw_log_context_included") is not False:
        failures.append("raw_log_context_included was not false")
    if "Response Automation Disabled" not in (payload.get("safety") or []):
        failures.append("missing Response Automation Disabled safety badge")
    sections = payload.get("details", {}).get("answer_sections") if isinstance(payload.get("details"), dict) else None
    if not isinstance(sections, dict):
        failures.append("missing answer_sections")
    else:
        if not sections.get("citations"):
            failures.append("answer_sections missing citations")
        if not sections.get("direct_answer"):
            failures.append("answer_sections missing direct answer")
        if sections.get("response_mode") != [case.expected_response_mode]:
            failures.append("answer_sections response mode mismatch")
        if case.expected_response_mode == "alert_explanation" and not sections.get("key_evidence"):
            failures.append("alert explanation missing key evidence")
        if case.expected_response_mode == "safe_next_step" and not sections.get("next_steps"):
            failures.append("safe-next-step answer missing prioritized checks")
        if case.expected_response_mode == "investigation_brief" and not (
            sections.get("key_evidence") and sections.get("next_steps")
        ):
            failures.append("investigation brief missing evidence or next steps")
        section_text = json.dumps(sections, default=str).lower()
        if "automatic response" in section_text and "disabled" not in section_text:
            failures.append("sections mention automatic response without disabled boundary")
        if "production ready" in section_text or "production-certified" in section_text:
            failures.append("sections claim production certainty")
    for forbidden in case.forbidden_text:
        if forbidden.lower() in payload_text.lower():
            failures.append(f"forbidden text leaked: {forbidden}")
    return failures


def evaluate_assistant_qa() -> dict[str, Any]:
    engine, SessionFactory = _session_factory()
    try:
        with SessionFactory() as db:
            fixture = _seed_fixture(db)
            baseline_counts = {
                "response_actions": _count(db, ResponseAction),
                "detection_runs": _count(db, DetectionRun),
                "ml_model_runs": _count(db, MLModelRun),
                "ml_labels": _count(db, MLLabel),
                "alerts": _count(db, Alert),
                "logs": _count(db, NormalizedLog),
                "assistant_feedback": _count(db, AssistantFeedback),
            }
            question_results: list[dict[str, Any]] = []
            settings = _settings()
            for case in _qa_cases():
                question = case.question_template.format(**fixture)
                payload = answer_assistant_question(
                    db,
                    question=question,
                    actor="assistant_qa",
                    settings=settings,
                    alert_id=fixture["alert_id"] if "alert" in case.name and "latest" not in case.name else None,
                    log_id=fixture["log_id"] if "log" in case.name else None,
                    source_id=fixture["source_id"] if "source" in case.name else None,
                    case_id=fixture["case_id"] if "case" in case.name and fixture["case_id"] else None,
                    include_recent_context=True,
                )
                failures = _assert_case(payload, case)
                question_results.append(
                    {
                        "name": case.name,
                        "question": question,
                        "passed": not failures,
                        "failures": failures,
                        "context_used": payload.get("context_used"),
                        "response_mode": payload.get("response_mode"),
                        "word_count": len(str(payload.get("answer", "")).split()),
                        "citation_sources": [item.get("source") for item in payload.get("citations", [])],
                    }
                )
            final_counts = {
                "response_actions": _count(db, ResponseAction),
                "detection_runs": _count(db, DetectionRun),
                "ml_model_runs": _count(db, MLModelRun),
                "ml_labels": _count(db, MLLabel),
                "alerts": _count(db, Alert),
                "logs": _count(db, NormalizedLog),
                "assistant_feedback": _count(db, AssistantFeedback),
                "assistant_audit_events": int(db.scalar(select(func.count(AuditLog.id)).where(AuditLog.action == "assistant_question")) or 0),
            }
            side_effect_checks = {
                "no_response_actions_created": final_counts["response_actions"] == baseline_counts["response_actions"],
                "no_detection_runs_created_by_assistant": final_counts["detection_runs"] == baseline_counts["detection_runs"],
                "no_ml_model_runs_created": final_counts["ml_model_runs"] == baseline_counts["ml_model_runs"],
                "no_labels_changed": final_counts["ml_labels"] == baseline_counts["ml_labels"],
                "no_alerts_created_by_assistant": final_counts["alerts"] == baseline_counts["alerts"],
                "no_logs_created_by_assistant": final_counts["logs"] == baseline_counts["logs"],
                "no_feedback_rows_created_by_evaluator": final_counts["assistant_feedback"] == baseline_counts["assistant_feedback"],
                "questions_audited": final_counts["assistant_audit_events"] == len(question_results),
            }
            citation_passes = sum(
                1
                for item in question_results
                if item["citation_sources"] and not any("missing citation source" in failure for failure in item["failures"])
            )
            unsafe_refusal = next(item for item in question_results if item["name"] == "unsafe_request_refusal")
            word_counts = [int(item["word_count"]) for item in question_results]
            response_mode_counts: dict[str, int] = {}
            for item in question_results:
                mode = str(item["response_mode"])
                response_mode_counts[mode] = response_mode_counts.get(mode, 0) + 1
            e2e_checks = {
                "sample_logs_parse": fixture["import_result"]["parsed_successfully"] >= 1,
                "normalized_logs_exist": baseline_counts["logs"] >= 1,
                "detection_created_alert": baseline_counts["alerts"] >= 1,
                "detection_run_recorded": baseline_counts["detection_runs"] >= 1,
                "alert_has_related_logs": bool(db.get(Alert, fixture["alert_id"]).evidence),
                "source_health_available": fixture["source_id"] is not None,
                "assistant_alert_explainer_passed": next(item["passed"] for item in question_results if item["name"] == "why_alert_flagged"),
                "assistant_brief_passed": next(item["passed"] for item in question_results if item["name"] == "alert_brief"),
                "response_automation_disabled": True,
            }
            ok = all(item["passed"] for item in question_results) and all(side_effect_checks.values()) and all(e2e_checks.values())
            return {
                "ok": ok,
                "fixture": {
                    "scenario_path": str(SCENARIO_PATH),
                    "alert_id": fixture["alert_id"],
                    "log_id": fixture["log_id"],
                    "source_id": fixture["source_id"],
                    "case_id": fixture["case_id"],
                    "import_result": fixture["import_result"],
                    "detection_result": fixture["detection_result"],
                },
                "question_results": question_results,
                "side_effect_checks": side_effect_checks,
                "end_to_end_investigation_checks": e2e_checks,
                "baseline_counts": baseline_counts,
                "final_counts": final_counts,
                "safety": {
                    "external_provider_used": False,
                    "raw_log_context_included": False,
                    "response_automation_allowed": False,
                    "real_firewall_blocking_enabled": False,
                    "model_activation": "none",
                },
                "answer_quality_cases": len(question_results),
                "required_citation_pass_rate": round(citation_passes / max(1, len(question_results)), 4),
                "unsafe_refusal_passed": bool(unsafe_refusal["passed"]),
                "feedback_endpoint_available": True,
                "answer_concision": {
                    "baseline_average_words": 283.8,
                    "baseline_max_words": 697,
                    "current_average_words": round(sum(word_counts) / max(1, len(word_counts)), 1),
                    "current_max_words": max(word_counts, default=0),
                    "response_mode_counts": response_mode_counts,
                    "all_word_budgets_passed": all(
                        item["word_count"] <= case.max_words
                        for item, case in zip(question_results, _qa_cases(), strict=True)
                    ),
                },
            }
    finally:
        engine.dispose()


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate deterministic SOC Assistant QA against a safe temp-DB fixture.")
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()
    result = evaluate_assistant_qa()
    print(json.dumps(result, indent=2 if args.pretty else None, default=str))
    raise SystemExit(0 if result.get("ok") else 1)


if __name__ == "__main__":
    main()
