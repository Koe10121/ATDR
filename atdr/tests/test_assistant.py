from __future__ import annotations

import json
from collections.abc import Generator
from datetime import datetime, timezone

from fastapi.testclient import TestClient
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from atdr.app.core.config import get_settings
from atdr.app.db.database import Base, get_db
from atdr.app.db.models import (
    Alert,
    AlertEvidence,
    AssistantFeedback,
    AuditLog,
    DetectionRun,
    LogSource,
    MLModelRun,
    NormalizedLog,
    OperationJob,
    RawLog,
    ResponseAction,
)
from atdr.app.main import app
from atdr.app.services import assistant_service
from atdr.app.services.user_service import create_user


def _client_with_session() -> tuple[TestClient, sessionmaker[Session]]:
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    Base.metadata.create_all(engine)
    testing_session = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
    now = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)

    with testing_session() as db:
        create_user(db, username="admin", password="admin123", role="admin", full_name="Test Admin")
        create_user(db, username="analyst", password="analyst123", role="analyst", full_name="Test Analyst")
        source = LogSource(
            name="assistant-firewall",
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
        raw = RawLog(raw_line="synthetic assistant test log from 203.0.113.10", source_id=source.id, imported_at=now)
        db.add(raw)
        db.flush()
        log = NormalizedLog(
            raw_log_id=raw.id,
            receive_time=now,
            generated_time=now,
            log_type="TRAFFIC",
            subtype="end",
            src_ip="203.0.113.10",
            dst_ip="198.51.100.20",
            app="incomplete",
            action="deny",
            src_zone="untrust",
            dst_zone="trust",
            src_port=43123,
            dst_port=22,
            protocol="tcp",
            bytes=120,
            packets=3,
            app_risk=4,
            parsed_json={"test": "assistant"},
        )
        db.add(log)
        db.flush()
        alert = Alert(
            title="Critical: Assistant test alert",
            alert_type="possible_port_scan",
            src_ip="203.0.113.10",
            dst_ip="198.51.100.20",
            threat_score=91,
            severity="Critical",
            status="open",
            explanation="Synthetic alert involving 203.0.113.10.",
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
        db.add(
            LogSource(
                name="warning-router",
                source_type="syslog_udp",
                parser_profile="generic_syslog",
                enabled=True,
                logs_received_count=20,
                parse_success_count=8,
                parse_failure_count=12,
                latest_error="parser profile has limited structured fields",
                last_seen=now,
                last_log_received_at=now,
            )
        )
        db.add(
            OperationJob(
                job_type="run_detection",
                status="failed",
                requested_by="admin",
                started_at=now,
                finished_at=now,
                progress_current=1,
                progress_total=1,
                result_summary_json={},
                error_summary="Synthetic failed job for assistant tests.",
                details_json={"source_id": 1},
                created_at=now,
                updated_at=now,
            )
        )
        db.add(
            DetectionRun(
                detection_type="hybrid",
                status="completed",
                started_at=now,
                finished_at=now,
                logs_evaluated=10,
                alerts_created=1,
                alerts_deduplicated=9,
                alerts_suppressed=0,
                top_attack_types_json=[{"name": "possible_port_scan", "count": 1}],
                runtime_seconds=0.25,
                details_json={"source_id": source.id},
            )
        )
        db.commit()

    def override_get_db() -> Generator[Session, None, None]:
        db = testing_session()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    return TestClient(app), testing_session


def _login(client: TestClient, username: str = "analyst", password: str = "analyst123") -> dict[str, str]:
    response = client.post("/api/auth/login", json={"username": username, "password": password})
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def test_assistant_requires_authentication():
    client, _ = _client_with_session()
    try:
        assert client.get("/api/assistant/status").status_code == 401
        response = client.post("/api/assistant/chat", json={"question": "What is the latest critical alert?"})
        assert response.status_code == 401
        feedback = client.post("/api/assistant/feedback", json={"question": "Was this useful?", "rating": "helpful"})
        assert feedback.status_code == 401
    finally:
        app.dependency_overrides.clear()


def test_assistant_status_is_disabled_by_default_and_does_not_expose_secret(monkeypatch):
    monkeypatch.setenv("ASSISTANT_ENABLED", "false")
    monkeypatch.setenv("ASSISTANT_PROVIDER", "disabled")
    monkeypatch.setenv("ASSISTANT_API_KEY", "secret-that-must-not-leak")
    get_settings.cache_clear()
    client, _ = _client_with_session()
    try:
        response = client.get("/api/assistant/status", headers=_login(client))
        assert response.status_code == 200
        payload = response.json()
        assert payload["available"] is True
        assert payload["mode"] == "deterministic_local"
        assert payload["external_provider_configured"] is False
        assert payload["external_provider_used_by_default"] is False
        assert payload["provider"] == "disabled"
        assert payload["raw_log_context_allowed"] is False
        assert "ASSISTANT_API_KEY" not in str(payload)
        assert "secret-that-must-not-leak" not in str(payload)
    finally:
        app.dependency_overrides.clear()
        get_settings.cache_clear()


def test_assistant_answers_alert_questions_with_redaction_and_audit():
    client, testing_session = _client_with_session()
    try:
        response = client.post(
            "/api/assistant/chat",
            json={"question": "Why was alert 1 flagged?"},
            headers=_login(client),
        )
        assert response.status_code == 200
        payload = response.json()
        assert payload["mode"] == "deterministic_local"
        assert payload["external_provider_used"] is False
        assert payload["raw_log_context_included"] is False
        assert payload["redaction_applied"] is True
        assert "Decision Support Only" in payload["safety"]
        assert "Response Automation Disabled" in payload["safety"]
        assert "Simulation Mode" in payload["safety"]
        assert "203.0.113.10" not in payload["answer"]
        assert "[redacted-ip]" in payload["answer"]
        assert "Summary" in payload["answer"]
        assert "Why flagged" in payload["answer"]
        assert "Evidence" in payload["answer"]
        assert "ATT&CK mapping" in payload["answer"]
        assert "Analyst next steps" in payload["answer"]
        assert "Safety note" in payload["answer"]
        assert any(citation["reference_id"] == "1" for citation in payload["citations"])
        assert any(citation["source"] == "docs/DETECTION_RULE_CATALOG.md" for citation in payload["citations"])
        assert payload["details"]["alert"]["source_rows"][0]["name"] == "assistant-firewall"
        sections = payload["details"]["answer_sections"]
        assert "Alert #1" in " ".join(sections["summary"])
        assert "Detection source" in " ".join(sections["summary"])
        assert "Scanning-like denied traffic." in " ".join(sections["evidence"])
        assert "Use simulated response only after confirmation and justification." in sections["safe_next_steps"]
        assert "Response automation is disabled." in sections["safety_limitation"]
        assert any("Alert detail" in citation for citation in sections["citations"])
        assert payload["suggested_followups"]

        with testing_session() as db:
            audit_count = db.scalar(select(func.count(AuditLog.id)).where(AuditLog.action == "assistant_question"))
            response_count = db.scalar(select(func.count(ResponseAction.id)))
            model_run_count = db.scalar(select(func.count(MLModelRun.id)))
        assert audit_count == 1
        assert response_count == 0
        assert model_run_count == 0
    finally:
        app.dependency_overrides.clear()


def test_assistant_latest_critical_alert_uses_alert_context_and_no_actions():
    client, testing_session = _client_with_session()
    try:
        response = client.post(
            "/api/assistant/chat",
            json={"question": "Summarize the latest critical alert"},
            headers=_login(client),
        )
        assert response.status_code == 200
        payload = response.json()
        assert "Summary" in payload["answer"]
        assert "Alert #1" in payload["answer"]
        assert "Why flagged" in payload["answer"]
        assert any(citation["label"] == "Alert detail" and citation["reference_id"] == "1" for citation in payload["citations"])
        assert payload["external_provider_used"] is False
        assert payload["raw_log_context_included"] is False

        with testing_session() as db:
            assert db.scalar(select(func.count(ResponseAction.id))) == 0
            assert db.scalar(select(func.count(MLModelRun.id))) == 0
    finally:
        app.dependency_overrides.clear()


def test_assistant_allows_analyst_and_admin_read_only_questions():
    client, _ = _client_with_session()
    try:
        analyst = client.post(
            "/api/assistant/chat",
            json={"question": "Summarize source health."},
            headers=_login(client, "analyst", "analyst123"),
        )
        assert analyst.status_code == 200
        assert analyst.json()["external_provider_used"] is False

        admin = client.post(
            "/api/assistant/chat",
            json={"question": "Explain current ML model status."},
            headers=_login(client, "admin", "admin123"),
        )
        assert admin.status_code == 200
        assert admin.json()["raw_log_context_included"] is False
    finally:
        app.dependency_overrides.clear()


def test_assistant_new_intents_return_safe_useful_answers():
    client, _ = _client_with_session()
    headers = _login(client)
    try:
        checks = {
            "Show latest critical alerts.": "Latest open critical alerts",
            "Summarize open alerts.": "Latest open alerts",
            "Which sources have warnings?": "Sources needing review",
            "What changed recently?": "Recent ATDR activity",
            "Summarize recent detection runs.": "Recent detection runs",
            "Summarize failed jobs.": "Failed job summary",
            "Why is the model not production promoted?": "not production promoted",
            "What can I safely do next for this alert?": "Safe next steps",
            "How do I import logs?": "To import logs",
            "How do I import reviewed labels?": "Reviewed labels can be imported",
            "How do I run a safe scenario?": "Run safe source scenarios",
            "How do I run a safe demo scenario?": "Run safe source scenarios",
        }
        for question, expected_text in checks.items():
            response = client.post("/api/assistant/chat", json={"question": question}, headers=headers)
            assert response.status_code == 200, question
            payload = response.json()
            assert expected_text.lower() in payload["answer"].lower(), question
            assert payload["external_provider_used"] is False
            assert payload["raw_log_context_included"] is False
            assert "Response Automation Disabled" in payload["safety"]
            assert payload["citations"]
            assert "answer_sections" in payload["details"]
            assert payload["details"]["answer_sections"]["summary"]
            assert payload["details"]["answer_sections"]["citations"]

        blocked = client.get("/api/response/blocked-ips", headers=headers)
        assert blocked.status_code == 200
        assert blocked.json() == []
    finally:
        app.dependency_overrides.clear()


def test_assistant_queue_evidence_agreement_uses_latest_safe_report(tmp_path, monkeypatch):
    report_dir = tmp_path / "ml_baseline_reviews"
    report_dir.mkdir()
    (report_dir / "v3_57_queue_rule_hybrid_agreement_latest.json").write_text(
        json.dumps(
            {
                "ok": True,
                "phase": "v3.57",
                "policy_name": "binary_review_queue",
                "aggregate": {
                    "evaluated_splits": 5,
                    "passing_splits": 4,
                    "queue_f1_min": 0.9725,
                    "queue_false_positive_rate_max": 0.04,
                    "agreement_rate_min": 0.884,
                    "category_counts": {
                        "queue_and_evidence_agree_review": 3376,
                        "evidence_only_review": 310,
                    },
                    "top_evidence_only_patterns": [["app=quic-base|action=allow|port=443", 71]],
                    "top_queue_only_patterns": [],
                    "blockers": ["grouped_stratified: evidence-only review rate above 0.10"],
                },
                "readiness": {
                    "decision": "diagnostic_only",
                    "passed": 7,
                    "total": 8,
                    "blockers": ["evidence-only misses remain reviewable"],
                },
                "safety": {
                    "production_promoted": False,
                    "model_activated": False,
                    "model_artifact_written": False,
                    "labels_written": False,
                    "raw_logs_included": False,
                    "response_automation_allowed": False,
                },
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(assistant_service, "PROJECT_ROOT", tmp_path)
    client, testing_session = _client_with_session()
    try:
        response = client.post(
            "/api/assistant/chat",
            json={"question": "Does the ML queue agree with rule/hybrid evidence?"},
            headers=_login(client),
        )
        assert response.status_code == 200
        payload = response.json()
        assert "Queue-vs-rule/hybrid agreement summary" in payload["answer"]
        assert "Evaluated splits: 5; passing splits: 4" in payload["answer"]
        assert "app=quic-base|action=allow|port=443" in payload["answer"]
        assert "evidence-only disagreements still need analyst review" in payload["answer"]
        assert "v357_queue_evidence_agreement" in payload["context_used"]
        assert payload["external_provider_used"] is False
        assert payload["raw_log_context_included"] is False
        safety = payload["details"]["v357_queue_evidence_agreement"]["safety"]
        assert safety["production_promoted"] is False
        assert safety["model_activated"] is False
        assert safety["response_automation_allowed"] is False
        assert any(
            citation["source"] == "ml_baseline_reviews/v3_57_queue_rule_hybrid_agreement_latest.json"
            for citation in payload["citations"]
        )

        with testing_session() as db:
            assert db.scalar(select(func.count(ResponseAction.id))) == 0
            assert db.scalar(select(func.count(MLModelRun.id))) == 0
    finally:
        app.dependency_overrides.clear()


def test_assistant_triage_reasoning_false_positive_and_handoff_questions_are_safe():
    client, testing_session = _client_with_session()
    headers = _login(client)
    try:
        checks = {
            "Is alert 1 likely a false positive?": ["Risk interpretation", "False-positive", "review recommended"],
            "What evidence is missing for alert 1?": ["Missing evidence", "What to check next", "Risk interpretation"],
            "What should I check first for this alert?": ["Safe next steps", "Response automation is disabled"],
            "Is source 1 risky?": ["Risk interpretation", "Source", "linked alerts"],
            "Why is this source noisy?": ["Source health", "Risk interpretation"],
            "Summarize this case for handoff.": ["Risk interpretation", "What to check next", "computed"],
            "What should I tell my supervisor about alert 1?": ["Investigation Brief", "Risk interpretation", "Limitations"],
        }
        for question, expected_terms in checks.items():
            response = client.post("/api/assistant/chat", json={"question": question}, headers=headers)
            assert response.status_code == 200, question
            payload = response.json()
            payload_text = str(payload)
            for expected in expected_terms:
                assert expected.lower() in payload_text.lower(), question
            sections = payload["details"]["answer_sections"]
            assert sections["summary"], question
            assert sections["citations"], question
            assert sections.get("risk_interpretation"), question
            assert sections.get("what_to_check_next") or sections.get("safe_next_steps"), question
            assert sections.get("safety_note") or sections.get("safety_limitation"), question
            assert payload["external_provider_used"] is False
            assert payload["raw_log_context_included"] is False
            assert "Response Automation Disabled" in payload["safety"]
            assert "production ready" not in payload_text.lower()
            assert "raw_line" not in payload_text

        with testing_session() as db:
            assert db.scalar(select(func.count(ResponseAction.id))) == 0
            assert db.scalar(select(func.count(DetectionRun.id))) == 1
            assert db.scalar(select(func.count(MLModelRun.id))) == 0
            assert db.scalar(select(func.count(AssistantFeedback.id))) == 0
    finally:
        app.dependency_overrides.clear()


def test_assistant_refuses_unsafe_action_requests_without_side_effects():
    client, testing_session = _client_with_session()
    headers = _login(client)
    try:
        unsafe_questions = [
            "Can you block this IP?",
            "Please run detection for me.",
            "Can you activate the model?",
            "Can you promote the model?",
            "Can you delete logs now?",
            "Can you change labels?",
            "Can you send email?",
            "Can you enable automation?",
        ]
        for question in unsafe_questions:
            response = client.post("/api/assistant/chat", json={"question": question}, headers=headers)
            assert response.status_code == 200, question
            payload = response.json()
            assert "I cannot execute that request" in payload["answer"]
            assert payload["details"]["refused"] is True
            assert "answer_sections" in payload["details"]
            assert payload["details"]["answer_sections"]["safe_next_steps"]
            assert "assistant_safety_guardrail" in payload["context_used"]
            assert payload["external_provider_used"] is False
            assert payload["raw_log_context_included"] is False
            assert all("block this ip" not in followup.lower() for followup in payload["suggested_followups"])

        with testing_session() as db:
            assert db.scalar(select(func.count(ResponseAction.id))) == 0
            assert db.scalar(select(func.count(MLModelRun.id))) == 0
            assert db.scalar(select(func.count(DetectionRun.id))) == 1
    finally:
        app.dependency_overrides.clear()


def test_assistant_feedback_records_quality_review_without_side_effects():
    client, testing_session = _client_with_session()
    headers = _login(client)
    try:
        answer = client.post(
            "/api/assistant/chat",
            json={"question": "Why was alert 1 flagged?"},
            headers=headers,
        )
        assert answer.status_code == 200
        answer_payload = answer.json()
        feedback = client.post(
            "/api/assistant/feedback",
            json={
                "question": "Why was alert 1 flagged?",
                "answer": answer_payload["answer"],
                "rating": "helpful",
                "feedback_note": "Clear enough for triage.",
                "context_type": "alert",
                "context_reference": "1",
                "external_provider_used": answer_payload["external_provider_used"],
                "raw_log_context_included": answer_payload["raw_log_context_included"],
                "assistant_audit_id": answer_payload["details"]["assistant_audit_id"],
            },
            headers=headers,
        )
        assert feedback.status_code == 200
        payload = feedback.json()
        assert payload["rating"] == "helpful"
        assert payload["action_executed"] is False
        assert payload["external_provider_used"] is False
        assert payload["raw_log_context_included"] is False
        assert payload["answer_hash"]
        assert "203.0.113.10" not in str(payload)

        summary = client.get("/api/assistant/feedback/summary", headers=headers)
        assert summary.status_code == 200
        summary_payload = summary.json()
        assert summary_payload["total_count"] == 1
        assert summary_payload["rating_counts"]["helpful"] == 1
        assert summary_payload["action_executed_count"] == 0
        assert summary_payload["external_provider_used_count"] == 0
        assert summary_payload["raw_log_context_included_count"] == 0
        assert summary_payload["secrets_exposed"] is False

        recent = client.get("/api/assistant/feedback/recent", headers=headers)
        assert recent.status_code == 200
        assert len(recent.json()) == 1

        with testing_session() as db:
            assert db.scalar(select(func.count(AssistantFeedback.id))) == 1
            assert db.scalar(select(func.count(ResponseAction.id))) == 0
            assert db.scalar(select(func.count(DetectionRun.id))) == 1
            assert db.scalar(select(func.count(MLModelRun.id))) == 0
            audit_actions = set(db.scalars(select(AuditLog.action)))
        assert "assistant_feedback_submitted" in audit_actions
    finally:
        app.dependency_overrides.clear()


def test_assistant_feedback_rejects_invalid_rating_and_scopes_recent_rows():
    client, _ = _client_with_session()
    analyst_headers = _login(client, "analyst", "analyst123")
    admin_headers = _login(client, "admin", "admin123")
    try:
        invalid = client.post(
            "/api/assistant/feedback",
            json={"question": "Bad rating", "rating": "amazing"},
            headers=analyst_headers,
        )
        assert invalid.status_code == 422

        admin_feedback = client.post(
            "/api/assistant/feedback",
            json={"question": "Admin feedback", "rating": "unclear", "answer": "Admin answer"},
            headers=admin_headers,
        )
        assert admin_feedback.status_code == 200
        analyst_feedback = client.post(
            "/api/assistant/feedback",
            json={"question": "Analyst feedback", "rating": "incorrect", "answer": "Analyst answer"},
            headers=analyst_headers,
        )
        assert analyst_feedback.status_code == 200

        analyst_recent = client.get("/api/assistant/feedback/recent", headers=analyst_headers)
        assert analyst_recent.status_code == 200
        analyst_questions = {item["question"] for item in analyst_recent.json()}
        assert analyst_questions == {"Analyst feedback"}

        admin_recent = client.get("/api/assistant/feedback/recent", headers=admin_headers)
        assert admin_recent.status_code == 200
        admin_questions = {item["question"] for item in admin_recent.json()}
        assert {"Admin feedback", "Analyst feedback"}.issubset(admin_questions)

        analyst_summary = client.get("/api/assistant/feedback/summary", headers=analyst_headers).json()
        admin_summary = client.get("/api/assistant/feedback/summary", headers=admin_headers).json()
        assert analyst_summary["scope"] == "own"
        assert analyst_summary["total_count"] == 1
        assert admin_summary["scope"] == "all"
        assert admin_summary["total_count"] == 2
    finally:
        app.dependency_overrides.clear()


def test_assistant_feedback_review_filters_and_quality_summary_are_safe():
    client, testing_session = _client_with_session()
    analyst_headers = _login(client, "analyst", "analyst123")
    admin_headers = _login(client, "admin", "admin123")
    try:
        rows = [
            (
                admin_headers,
                {
                    "question": "Admin unsafe feedback",
                    "rating": "unsafe",
                    "answer": "Potentially unsafe answer text",
                    "context_type": "alert",
                    "context_reference": "1",
                    "action_requested": True,
                },
            ),
            (
                admin_headers,
                {
                    "question": "Admin helpful feedback",
                    "rating": "helpful",
                    "answer": "Helpful answer text",
                    "context_type": "ml",
                },
            ),
            (
                analyst_headers,
                {
                    "question": "Analyst incorrect feedback",
                    "rating": "incorrect",
                    "answer": "Incorrect answer text",
                    "context_type": "source",
                    "context_reference": "1",
                },
            ),
        ]
        for headers, payload in rows:
            response = client.post("/api/assistant/feedback", json=payload, headers=headers)
            assert response.status_code == 200
            item = response.json()
            assert item["action_executed"] is False
            assert item["review_recommended"] == (payload["rating"] != "helpful")
            assert "raw_line" not in str(item)

        admin_summary = client.get("/api/assistant/feedback/summary", headers=admin_headers)
        assert admin_summary.status_code == 200
        summary = admin_summary.json()
        assert summary["scope"] == "all"
        assert summary["total_count"] == 3
        assert summary["unsafe_or_incorrect_count"] == 2
        assert summary["needs_review_count"] == 2
        assert summary["action_requested_count"] == 1
        assert summary["action_executed_count"] == 0
        assert summary["review_warning"] is True
        assert len(summary["latest_unsafe_or_incorrect"]) == 2
        assert summary["secrets_exposed"] is False

        admin_unsafe = client.get("/api/assistant/feedback/recent?rating=unsafe&context_type=alert", headers=admin_headers)
        assert admin_unsafe.status_code == 200
        admin_unsafe_rows = admin_unsafe.json()
        assert len(admin_unsafe_rows) == 1
        assert admin_unsafe_rows[0]["question"] == "Admin unsafe feedback"
        assert admin_unsafe_rows[0]["review_reason"].startswith("Review recommended")

        analyst_summary = client.get("/api/assistant/feedback/summary", headers=analyst_headers)
        assert analyst_summary.status_code == 200
        analyst_payload = analyst_summary.json()
        assert analyst_payload["scope"] == "own"
        assert analyst_payload["total_count"] == 1
        assert analyst_payload["unsafe_or_incorrect_count"] == 1

        analyst_admin_filter = client.get("/api/assistant/feedback/recent?rating=unsafe", headers=analyst_headers)
        assert analyst_admin_filter.status_code == 200
        assert analyst_admin_filter.json() == []

        bad_filter = client.get("/api/assistant/feedback/recent?rating=surprising", headers=admin_headers)
        assert bad_filter.status_code == 422

        with testing_session() as db:
            assert db.scalar(select(func.count(AssistantFeedback.id))) == 3
            assert db.scalar(select(func.count(ResponseAction.id))) == 0
            assert db.scalar(select(func.count(DetectionRun.id))) == 1
            assert db.scalar(select(func.count(MLModelRun.id))) == 0
    finally:
        app.dependency_overrides.clear()


def test_assistant_history_is_safe_and_audit_backed():
    client, _ = _client_with_session()
    headers = _login(client)
    try:
        response = client.post("/api/assistant/chat", json={"question": "Summarize failed jobs."}, headers=headers)
        assert response.status_code == 200

        history = client.get("/api/assistant/history", headers=headers)
        assert history.status_code == 200
        payload = history.json()
        assert payload
        assert payload[0]["question"] == "Summarize failed jobs."
        assert payload[0]["external_provider_used"] is False
        assert "operation_jobs" in payload[0]["context_used"]
        assert "raw_line" not in str(payload)
        assert "ASSISTANT_API_KEY" not in str(payload)
    finally:
        app.dependency_overrides.clear()


def test_assistant_citations_cover_dashboard_handoffs_without_mutation():
    client, testing_session = _client_with_session()
    headers = _login(client)
    try:
        checks = [
            ("Why was alert 1 flagged?", "/api/alerts/{alert_id}"),
            ("Why was log 1 flagged?", "/api/logs/{log_id}"),
            ("Summarize source health.", "/api/sources/{source_id}"),
            ("Summarize recent detection runs.", "/api/detection/runs/{run_id}"),
            ("Summarize failed jobs.", "/api/jobs/{job_id}"),
            ("Explain current ML model status.", "/api/ml/report"),
            ("Explain current ML model status.", "/api/ml/supervised/report"),
        ]
        for question, expected_source in checks:
            response = client.post("/api/assistant/chat", json={"question": question}, headers=headers)
            assert response.status_code == 200, question
            payload = response.json()
            assert any(citation["source"] == expected_source for citation in payload["citations"]), question
            assert payload["external_provider_used"] is False
            assert payload["raw_log_context_included"] is False
            assert "raw_line" not in str(payload)
            assert "ASSISTANT_API_KEY" not in str(payload)

        with testing_session() as db:
            assert db.scalar(select(func.count(ResponseAction.id))) == 0
            assert db.scalar(select(func.count(MLModelRun.id))) == 0
            assert db.scalar(select(func.count(DetectionRun.id))) == 1
    finally:
        app.dependency_overrides.clear()


def test_assistant_explicit_log_context_explains_flagged_or_not_flagged_without_raw_context():
    client, testing_session = _client_with_session()
    headers = _login(client)
    try:
        response = client.post(
            "/api/assistant/chat",
            json={"question": "Why was this log flagged?", "log_id": 1},
            headers=headers,
        )
        assert response.status_code == 200
        payload = response.json()
        assert "Log #1 triage status" in payload["answer"]
        assert "Why flagged" in payload["answer"]
        assert any(citation["source"] == "/api/logs/{log_id}" and citation["reference_id"] == "1" for citation in payload["citations"])
        assert any(citation["source"] == "/api/alerts/{alert_id}" and citation["reference_id"] == "1" for citation in payload["citations"])
        assert any(citation["source"] == "/api/sources/{source_id}" and citation["reference_id"] == "1" for citation in payload["citations"])
        assert payload["raw_log_context_included"] is False
        assert "raw_line" not in str(payload)
        assert "synthetic assistant test log" not in str(payload)
        assert payload["details"]["log"]["id"] == 1
        assert payload["details"]["linked_alerts"][0]["id"] == 1
        assert "answer_sections" in payload["details"]

        with testing_session() as db:
            assert db.scalar(select(func.count(ResponseAction.id))) == 0
            assert db.scalar(select(func.count(MLModelRun.id))) == 0
            assert db.scalar(select(func.count(DetectionRun.id))) == 1
    finally:
        app.dependency_overrides.clear()


def test_assistant_alert_context_includes_related_log_citations_without_side_effects():
    client, testing_session = _client_with_session()
    headers = _login(client)
    try:
        response = client.post(
            "/api/assistant/chat",
            json={"question": "Summarize related logs for alert 1", "alert_id": 1},
            headers=headers,
        )
        assert response.status_code == 200
        payload = response.json()
        assert "Related logs" in payload["answer"]
        assert any(citation["label"] == "Related log" and citation["reference_id"] == "1" for citation in payload["citations"])
        assert payload["details"]["alert"]["related_logs"][0]["id"] == 1
        assert "raw_line" not in str(payload)
        assert "synthetic assistant test log" not in str(payload)
        assert "Why was log 1 flagged?" in payload["suggested_followups"]

        with testing_session() as db:
            assert db.scalar(select(func.count(ResponseAction.id))) == 0
            assert db.scalar(select(func.count(MLModelRun.id))) == 0
    finally:
        app.dependency_overrides.clear()


def test_assistant_source_context_includes_recent_alerts_and_parser_notes_safely():
    client, _ = _client_with_session()
    headers = _login(client)
    try:
        response = client.post(
            "/api/assistant/chat",
            json={"question": "What should I check next for this source?", "source_id": 1},
            headers=headers,
        )
        assert response.status_code == 200
        payload = response.json()
        assert "Source health summary" in payload["answer"]
        assert "Safe next steps" in payload["answer"]
        assert "source_alerts" in payload["context_used"]
        assert any(citation["source"] == "/api/sources/{source_id}" and citation["reference_id"] == "1" for citation in payload["citations"])
        assert any(citation["source"] == "/api/alerts/{alert_id}" and citation["reference_id"] == "1" for citation in payload["citations"])
        assert payload["details"]["recent_alerts_by_source"]["1"][0]["id"] == 1
        assert "raw_line" not in str(payload)
    finally:
        app.dependency_overrides.clear()


def test_assistant_case_context_summarizes_computed_group_read_only():
    client, testing_session = _client_with_session()
    headers = _login(client)
    try:
        response = client.post(
            "/api/assistant/chat",
            json={"question": "Summarize case and related alert group"},
            headers=headers,
        )
        assert response.status_code == 200
        payload = response.json()
        assert "computed grouping summary" in payload["answer"].lower()
        assert "alert_cases" in payload["context_used"]
        assert any(citation["source"] == "/api/alerts/cases" for citation in payload["citations"])
        assert payload["details"]["case"]["related_alert_count"] >= 1
        assert "No detection, response, label, model, source, or data action was executed." in payload["details"]["answer_sections"]["safety_limitation"]

        with testing_session() as db:
            assert db.scalar(select(func.count(ResponseAction.id))) == 0
            assert db.scalar(select(func.count(MLModelRun.id))) == 0
            assert db.scalar(select(func.count(DetectionRun.id))) == 1
    finally:
        app.dependency_overrides.clear()


def test_assistant_alert_investigation_brief_is_evidence_grounded_and_non_mutating():
    client, testing_session = _client_with_session()
    headers = _login(client)
    try:
        response = client.post(
            "/api/assistant/chat",
            json={"question": "Create investigation brief for alert 1."},
            headers=headers,
        )
        assert response.status_code == 200
        payload = response.json()
        assert "Investigation Brief" in payload["answer"]
        assert "Evidence to mention" in payload["answer"]
        assert "Limitations" in payload["answer"]
        assert "investigation_brief" in payload["context_used"]
        assert payload["details"]["brief"]["kind"] == "alert"
        assert payload["details"]["brief"]["non_mutating"] is True
        assert payload["details"]["brief"]["external_provider_used"] is False
        assert payload["details"]["brief"]["raw_log_context_included"] is False
        sections = payload["details"]["answer_sections"]
        assert sections["summary"]
        assert sections["what_happened"]
        assert sections["why_flagged_or_not"]
        assert sections["evidence"]
        assert sections["related_context"]
        assert "Response automation is disabled." in sections["limitations"]
        assert any(citation["source"] == "/api/alerts/{alert_id}" and citation["reference_id"] == "1" for citation in payload["citations"])
        assert any(citation["source"] == "docs/V3_25_SOC_ASSISTANT_INVESTIGATION_BRIEF_BUILDER.md" for citation in payload["citations"])
        assert "raw_line" not in str(payload)
        assert "synthetic assistant test log" not in str(payload)

        with testing_session() as db:
            assert db.scalar(select(func.count(ResponseAction.id))) == 0
            assert db.scalar(select(func.count(MLModelRun.id))) == 0
            assert db.scalar(select(func.count(DetectionRun.id))) == 1
    finally:
        app.dependency_overrides.clear()


def test_assistant_log_source_and_case_investigation_briefs_are_context_specific():
    client, testing_session = _client_with_session()
    headers = _login(client)
    try:
        checks = [
            ("Create investigation brief for log 1.", "log", "/api/logs/{log_id}"),
            ("Create investigation brief for source 1.", "source", "/api/sources/{source_id}"),
            ("Create investigation brief for case smoke-case.", "case", "/api/alerts/cases"),
        ]
        for question, expected_kind, expected_source in checks:
            response = client.post("/api/assistant/chat", json={"question": question}, headers=headers)
            assert response.status_code == 200, question
            payload = response.json()
            assert "Investigation Brief" in payload["answer"], question
            assert payload["details"]["brief"]["kind"] == expected_kind, question
            assert payload["external_provider_used"] is False
            assert payload["raw_log_context_included"] is False
            assert any(citation["source"] == expected_source for citation in payload["citations"]), question
            assert "Decision support only; analyst judgment is required." in payload["details"]["answer_sections"]["limitations"]
            assert "raw_line" not in str(payload)
            assert "synthetic assistant test log" not in str(payload)

        with testing_session() as db:
            assert db.scalar(select(func.count(ResponseAction.id))) == 0
            assert db.scalar(select(func.count(MLModelRun.id))) == 0
            assert db.scalar(select(func.count(DetectionRun.id))) == 1
    finally:
        app.dependency_overrides.clear()
