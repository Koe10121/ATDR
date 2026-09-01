from __future__ import annotations

import json

import pytest

from atdr.app.core.config import get_settings
from atdr.app.main import app
from atdr.app.services import assistant_llm
from atdr.app.services.assistant_response_contracts import (
    RESPONSE_CONTRACTS,
    build_response_presentation,
    infer_response_mode,
)
from atdr.tests.test_assistant import _client_with_session, _login, _side_effect_counts


@pytest.fixture(autouse=True)
def _safe_assistant_defaults(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("ASSISTANT_LLM_ENABLED", "false")
    monkeypatch.setenv("ASSISTANT_LLM_PROVIDER", "")
    monkeypatch.setenv("ASSISTANT_LLM_MODEL", "")
    monkeypatch.setenv("ASSISTANT_LLM_API_KEY", "")
    monkeypatch.setenv("ASSISTANT_ALLOW_RAW_LOG_CONTEXT", "false")
    monkeypatch.setenv("ASSISTANT_REDACT_IPS", "true")
    get_settings.cache_clear()
    yield
    app.dependency_overrides.clear()
    get_settings.cache_clear()


@pytest.mark.parametrize(
    ("reason", "category"),
    [
        ("provider_timeout", "timeout"),
        ("provider_quota_exhausted", "quota"),
        ("provider_rate_limited", "rate_limit"),
        ("malformed_provider_response", "malformed_output"),
        ("provider_answer_lost_primary_alert_citation", "citation_rejection"),
        ("provider_answer_implies_action_execution", "safety_rejection"),
        ("provider_answer_contains_unsupported_alert_id", "grounding_rejection"),
    ],
)
def test_v534_provider_failures_have_safe_stable_categories(reason: str, category: str) -> None:
    assert assistant_llm.classify_assistant_llm_failure(reason) == category


def test_v552_response_contracts_are_concise_and_limit_followups() -> None:
    expected_limits = {
        "direct_fact": 55,
        "alert_explanation": 75,
        "safe_next_step": 70,
        "related_logs": 80,
        "source_health": 70,
        "list_summary": 75,
        "case_handoff": 90,
        "investigation_brief": 110,
        "how_to": 120,
        "governance": 70,
    }
    assert {name: contract.word_limit for name, contract in RESPONSE_CONTRACTS.items()} == expected_limits
    assert all(contract.max_followups == 2 for contract in RESPONSE_CONTRACTS.values())


def test_v534_investigation_presentation_deduplicates_evidence_and_stays_bounded() -> None:
    presentation = build_response_presentation(
        mode="investigation_brief",
        question="Create an investigation brief for alert 1.",
        original_answer="A compact investigation brief.",
        raw_sections={
            "summary": ["Alert #1 requires analyst review."],
            "evidence": [
                "Repeated denied probes targeted multiple destination ports.",
                "Repeated denied probes targeted multiple destination ports.",
                "Multiple destination ports received repeated denied probes.",
            ],
            "risk_interpretation": ["The pattern is consistent with scan-like behavior."],
            "what_to_check_next": ["Verify the linked normalized logs and source history."],
            "limitations": ["No endpoint telemetry is available."],
        },
        active_context={"primary": "alert", "alert_id": 1},
        citation_references=["Alert detail #1"],
    )
    assert presentation.word_limit == 110
    assert presentation.word_count <= 110
    assert presentation.sections["citations"] == ["Alert detail #1"]
    assert len(presentation.sections["key_evidence"]) == 1


def test_v534_case_context_uses_dedicated_handoff_mode() -> None:
    assert infer_response_mode(
        "Summarize this case for analyst handoff.",
        ["alert_cases", "case_grouping"],
    ) == "case_handoff"


def test_v534_gemini_brief_is_compacted_after_provider_rendering_and_read_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ASSISTANT_LLM_ENABLED", "true")
    monkeypatch.setenv("ASSISTANT_LLM_PROVIDER", "gemini")
    monkeypatch.setenv("ASSISTANT_LLM_MODEL", "gemini-test")
    monkeypatch.setenv("ASSISTANT_LLM_API_KEY", "private-test-key")
    get_settings.cache_clear()

    structured = {
        "direct_answer": "Alert #1 shows scan-like denied traffic and requires analyst review.",
        "key_evidence": [
            "Repeated denied probes targeted multiple destination ports.",
            "Repeated denied probes targeted multiple destination ports.",
            "Multiple destination ports received repeated denied probes.",
            "The alert rule and grouped evidence agree on scanning behavior.",
        ],
        "next_steps": [
            "Review the linked normalized logs.",
            "Compare source activity in the same time window.",
            "Confirm the destination scope before any simulated response.",
        ],
        "limitations": ["No endpoint telemetry is available."],
        "safety_notice": "Read-only decision support; response automation remains disabled.",
        "suggested_followups": ["What logs are related to alert 1?"],
        "citation_references": ["Alert detail #1"],
    }

    def successful_provider(*args, **kwargs):
        return {"candidates": [{"content": {"parts": [{"text": json.dumps(structured)}]}}]}

    monkeypatch.setattr(assistant_llm, "_post_json", successful_provider)
    client, testing_session = _client_with_session()
    headers = _login(client)
    with testing_session() as db:
        before = _side_effect_counts(db)

    response = client.post(
        "/api/assistant/chat",
        json={"question": "Create an investigation brief for alert 1."},
        headers=headers,
    )
    assert response.status_code == 200
    payload = response.json()
    sections = payload["details"]["answer_sections"]
    assert payload["external_provider_used"] is True
    assert payload["response_mode"] == "investigation_brief"
    assert len(payload["answer"].split()) <= 110
    assert payload["details"]["response_contract"]["word_limit"] == 110
    assert len(sections["key_evidence"]) == 2
    assert sections["citations"] == ["Alert detail #1"]
    assert payload["raw_log_context_included"] is False
    assert "private-test-key" not in str(payload)
    with testing_session() as db:
        assert _side_effect_counts(db) == before


def test_v534_malformed_provider_output_is_classified_and_falls_back(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ASSISTANT_LLM_ENABLED", "true")
    monkeypatch.setenv("ASSISTANT_LLM_PROVIDER", "gemini")
    monkeypatch.setenv("ASSISTANT_LLM_MODEL", "gemini-test")
    monkeypatch.setenv("ASSISTANT_LLM_API_KEY", "private-test-key")
    get_settings.cache_clear()

    monkeypatch.setattr(
        assistant_llm,
        "_post_json",
        lambda *args, **kwargs: {
            "candidates": [{"content": {"parts": [{"text": "not-json"}]}}]
        },
    )
    client, testing_session = _client_with_session()
    headers = _login(client)
    with testing_session() as db:
        before = _side_effect_counts(db)
    response = client.post(
        "/api/assistant/chat",
        json={"question": "Why was alert 1 flagged?"},
        headers=headers,
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["external_provider_used"] is False
    assert payload["details"]["llm"]["fallback_reason"] == "malformed_provider_response"
    assert payload["details"]["llm"]["failure_category"] == "malformed_output"
    assert payload["raw_log_context_included"] is False
    assert "private-test-key" not in str(payload)
    with testing_session() as db:
        assert _side_effect_counts(db) == before
