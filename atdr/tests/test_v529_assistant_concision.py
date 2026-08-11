from __future__ import annotations

import json

import pytest
from sqlalchemy import select

from atdr.app.core.config import get_settings
from atdr.app.db.models import Alert, AuditLog
from atdr.app.main import app
from atdr.app.services import assistant_llm, assistant_service
from atdr.tests.test_assistant import _client_with_session, _login, _side_effect_counts


@pytest.fixture(autouse=True)
def _safe_assistant_defaults(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("ASSISTANT_LLM_ENABLED", "false")
    monkeypatch.setenv("ASSISTANT_LLM_PROVIDER", "")
    monkeypatch.setenv("ASSISTANT_LLM_MODEL", "")
    monkeypatch.setenv("ASSISTANT_LLM_API_KEY", "")
    monkeypatch.setenv("ASSISTANT_ALLOW_RAW_LOG_CONTEXT", "false")
    get_settings.cache_clear()
    yield
    app.dependency_overrides.clear()
    get_settings.cache_clear()


def test_v529_intents_have_distinct_shapes_and_hard_word_budgets() -> None:
    client, _ = _client_with_session()
    headers = _login(client)
    checks = [
        ("Why was alert 1 flagged?", "alert_explanation", 110, "key_evidence"),
        ("What logs are related to alert 1?", "related_logs", 120, "related_logs"),
        ("What should I check next for alert 1?", "safe_next_step", 100, "next_steps"),
        ("Summarize source 1 health.", "source_health", 100, "key_evidence"),
        ("Show latest critical alerts.", "list_summary", 100, "list_items"),
        ("How do I run a controlled validation scenario?", "how_to", 180, "steps"),
        ("Why is the model not production promoted?", "governance", 100, "blockers"),
        ("Create investigation brief for alert 1.", "investigation_brief", 160, "key_evidence"),
    ]
    section_signatures: set[tuple[str, ...]] = set()
    for question, expected_mode, word_limit, required_section in checks:
        response = client.post("/api/assistant/chat", json={"question": question}, headers=headers)
        assert response.status_code == 200, question
        payload = response.json()
        sections = payload["details"]["answer_sections"]
        assert payload["response_mode"] == expected_mode
        assert len(payload["answer"].split()) <= word_limit
        assert sections["direct_answer"]
        assert sections[required_section], question
        assert sections["citations"]
        assert len(payload["suggested_followups"]) <= 3
        section_signatures.add(tuple(sorted(sections)))
    assert len(section_signatures) >= 6


def test_v529_followups_keep_alert_context_without_repeating_full_answer() -> None:
    client, testing_session = _client_with_session()
    headers = _login(client)
    conversation_id = "v529followup01"
    questions = [
        ("Why was alert 1 flagged?", "alert_explanation"),
        ("What logs are related?", "related_logs"),
        ("What should I check next?", "safe_next_step"),
    ]
    answers: list[str] = []
    with testing_session() as db:
        before = _side_effect_counts(db)
    for question, expected_mode in questions:
        response = client.post(
            "/api/assistant/chat",
            json={"question": question, "conversation_id": conversation_id},
            headers=headers,
        )
        assert response.status_code == 200
        payload = response.json()
        assert payload["response_mode"] == expected_mode
        assert payload["active_context"]["alert_id"] == 1
        assert payload["active_context"]["primary"] == "alert"
        assert all("alert 1" in followup.lower() for followup in payload["suggested_followups"][:2])
        answers.append(payload["answer"])
    assert "Related logs for alert #1" in answers[1]
    assert "Prioritized checks for alert #1" in answers[2]
    assert "Key evidence" not in answers[1]
    assert "Verdict:" not in answers[2]
    assert len(set(answers)) == 3
    with testing_session() as db:
        assert _side_effect_counts(db) == before
        audited = list(
            db.scalars(
                select(AuditLog).where(
                    AuditLog.action == "assistant_question",
                    AuditLog.actor == "analyst",
                )
            )
        )
        assert len(audited) == 3


def test_v529_guard_accepts_short_grounded_answer_and_rejects_unsupported_id() -> None:
    citations = [
        {
            "label": "Alert detail",
            "source": "/api/alerts/{alert_id}",
            "reference_id": "1",
        }
    ]
    structured = {
        "direct_answer": "Alert #1 was flagged by the supplied port-scan evidence.",
        "key_evidence": ["Repeated destination-port probing was observed."],
        "next_steps": ["Review the linked logs."],
        "citation_references": ["Alert detail #1"],
    }
    assert assistant_service._llm_answer_guard_reason(
        deterministic_answer="Long deterministic evidence " * 100,
        provider_answer=structured["direct_answer"],
        context_used=["alert_detail"],
        response_mode="alert_explanation",
        citations=citations,
        structured_answer=structured,
    ) is None
    assert assistant_service._llm_answer_guard_reason(
        deterministic_answer="Alert #1 evidence.",
        provider_answer="Alert #999 was flagged.",
        context_used=["alert_detail"],
        response_mode="alert_explanation",
        citations=citations,
        structured_answer=structured,
    ) == "provider_answer_contains_unsupported_alert_id"


def test_v529_short_gemini_answer_is_used_and_provider_failure_falls_back_concisely(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ASSISTANT_LLM_ENABLED", "true")
    monkeypatch.setenv("ASSISTANT_LLM_PROVIDER", "gemini")
    monkeypatch.setenv("ASSISTANT_LLM_MODEL", "gemini-test")
    monkeypatch.setenv("ASSISTANT_LLM_API_KEY", "private-test-key")
    get_settings.cache_clear()

    grounded = {
        "direct_answer": "Alert #1 was flagged by the supplied port-scan evidence.",
        "key_evidence": ["Scanning-like denied traffic was recorded."],
        "next_steps": ["Review the linked logs."],
        "limitations": [],
        "suggested_followups": ["What logs are related to alert 1?"],
        "citation_references": ["Alert detail #1"],
    }

    def successful_provider(*args, **kwargs):
        return {"candidates": [{"content": {"parts": [{"text": json.dumps(grounded)}]}}]}

    monkeypatch.setattr(assistant_llm, "_post_json", successful_provider)
    client, testing_session = _client_with_session()
    headers = _login(client)
    with testing_session() as db:
        before = _side_effect_counts(db)
    response = client.post("/api/assistant/chat", json={"question": "Why was alert 1 flagged?"}, headers=headers)
    assert response.status_code == 200
    payload = response.json()
    assert payload["external_provider_used"] is True
    assert payload["mode"] == "external_llm_gemini"
    assert payload["details"]["llm"]["answer_guard_reason"] is None
    assert len(payload["answer"].split()) <= 110
    assert "private-test-key" not in str(payload)

    def failed_provider(*args, **kwargs):
        raise assistant_llm.AssistantLLMTransportError("provider_service_unavailable")

    monkeypatch.setattr(assistant_llm, "_post_json", failed_provider)
    fallback = client.post("/api/assistant/chat", json={"question": "Why was alert 1 flagged?"}, headers=headers)
    assert fallback.status_code == 200
    fallback_payload = fallback.json()
    assert fallback_payload["external_provider_used"] is False
    assert fallback_payload["mode"] == "deterministic_local_llm_fallback_gemini"
    assert fallback_payload["response_mode"] == "alert_explanation"
    assert len(fallback_payload["answer"].split()) <= 110
    assert "private-test-key" not in str(fallback_payload)
    with testing_session() as db:
        assert _side_effect_counts(db) == before
        assert db.scalar(select(Alert).where(Alert.id == 1)) is not None
