from __future__ import annotations

import json

import pytest

from atdr.app.core.config import Settings, validate_runtime_settings
from atdr.app.services import assistant_llm, assistant_service
from atdr.app.services.assistant_response_contracts import build_response_presentation


def _settings(**overrides: object) -> Settings:
    values: dict[str, object] = {
        "ASSISTANT_LLM_ENABLED": True,
        "ASSISTANT_LLM_PROVIDER": "mock",
        "ASSISTANT_LLM_MODEL": "v556-safe-mock",
        "ASSISTANT_LLM_API_KEY": "private-v556-test-key",
        "ASSISTANT_ALLOW_RAW_LOG_CONTEXT": False,
        "ASSISTANT_REDACT_IPS": True,
        "ASSISTANT_LLM_CIRCUIT_BREAKER_FAILURES": 5,
        "ASSISTANT_LLM_USAGE_WARNING_TOKENS": 100,
    }
    values.update(overrides)
    return Settings(_env_file=None, **values)


def _request() -> assistant_llm.AssistantLLMRequest:
    return assistant_llm.AssistantLLMRequest(
        question="Why was alert 42 flagged?",
        deterministic_answer="Alert #42 has bounded deterministic rule evidence.",
        context_used=["alert_detail", "why_flagged"],
        citations=[
            {
                "label": "Alert detail",
                "source": "/api/alerts/{alert_id}",
                "reference_id": "42",
            }
        ],
        suggested_followups=["What logs are related to alert 42?"],
        safety=["Read-only decision support; response automation is disabled."],
        response_mode="alert_explanation",
        word_limit=75,
    )


class _UsageProvider(assistant_llm.AssistantLLMProvider):
    provider_name = "mock"

    def generate(
        self,
        request: assistant_llm.AssistantLLMRequest,
        settings: Settings,
    ) -> assistant_llm.AssistantLLMResult:
        structured = {
            "direct_answer": "Alert #42 was flagged by bounded rule evidence.",
            "key_evidence": ["Repeated denied probing was observed."],
            "next_steps": ["Review the linked normalized evidence."],
            "limitations": [],
            "safety_notice": "",
            "suggested_followups": [],
            "citation_references": ["Alert detail #42"],
        }
        return assistant_llm.AssistantLLMResult(
            used=True,
            provider=self.provider_name,
            model=settings.assistant_llm_model,
            answer=assistant_llm._render_structured_answer(
                structured,
                response_mode=request.response_mode,
                word_limit=request.word_limit,
            ),
            structured_answer=structured,
            usage={"input_tokens": 80, "output_tokens": 30, "total_tokens": 110},
            provider_called=True,
        )


def test_v556_operational_status_has_safe_usage_warning(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _settings()
    assistant_llm.reset_assistant_llm_operational_state(settings)
    monkeypatch.setattr(assistant_llm, "_provider_for", lambda _name: _UsageProvider())

    result = assistant_llm.maybe_generate_external_answer(_request(), settings)
    status = assistant_llm.assistant_llm_operational_status(settings)

    assert result.used is True
    assert status["calls_attempted"] == 1
    assert status["calls_succeeded"] == 1
    assert status["usage_warning"] is True
    assert status["usage_status"] == "threshold_reached"
    assert status["usage_warning_threshold_tokens"] == 100
    assert status["usage_remaining_tokens"] == 0
    assert status["token_usage"]["total_tokens"] == 110
    assert status["last_latency_ms"] >= 0
    assert status["max_latency_ms"] >= status["last_latency_ms"]
    serialized = json.dumps(status)
    assert "private-v556-test-key" not in serialized
    assert "Why was alert" not in serialized
    assert status["prompts_stored"] is False
    assert status["answers_stored"] is False


def test_v556_timeout_and_rate_limit_events_are_explicit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _settings(ASSISTANT_LLM_PROVIDER="gemini")
    assistant_llm.reset_assistant_llm_operational_state(settings)
    reasons = iter(["provider_timeout", "provider_rate_limited"])

    class _FailingProvider(assistant_llm.AssistantLLMProvider):
        provider_name = "gemini"

        def generate(
            self,
            request: assistant_llm.AssistantLLMRequest,
            settings: Settings,
        ) -> assistant_llm.AssistantLLMResult:
            raise assistant_llm.AssistantLLMTransportError(next(reasons))

    monkeypatch.setattr(
        assistant_llm,
        "_provider_for",
        lambda _name: _FailingProvider(),
    )
    assert (
        assistant_llm.maybe_generate_external_answer(_request(), settings).fallback_reason
        == "provider_timeout"
    )
    assert (
        assistant_llm.maybe_generate_external_answer(_request(), settings).fallback_reason
        == "provider_rate_limited"
    )
    status = assistant_llm.assistant_llm_operational_status(settings)
    assert status["calls_failed"] == 2
    assert status["fallbacks"] == 2
    assert status["timeout_events"] == 1
    assert status["rate_limit_events"] == 1
    assert status["quota_events"] == 0


def test_v556_external_provider_requires_ip_redaction() -> None:
    settings = _settings(ASSISTANT_REDACT_IPS=False)
    assistant_llm.reset_assistant_llm_operational_state(settings)
    result = assistant_llm.maybe_generate_external_answer(_request(), settings)
    issues = validate_runtime_settings(settings)
    assert result.used is False
    assert result.provider_called is False
    assert result.fallback_reason == "ip_redaction_required_for_llm"
    assert any("ASSISTANT_REDACT_IPS" in issue for issue in issues)


def test_v556_provider_guard_rejects_unsafe_private_or_unsupported_output() -> None:
    citations = [
        {
            "label": "Alert detail",
            "source": "/api/alerts/{alert_id}",
            "reference_id": "42",
        }
    ]
    assert assistant_service._llm_answer_guard_reason(
        deterministic_answer="Alert #42 has rule evidence.",
        provider_answer="Block the source immediately.",
        context_used=["alert_detail"],
        citations=citations,
    ) == "provider_answer_recommends_unsafe_action"
    assert assistant_service._llm_answer_guard_reason(
        deterministic_answer="Alert #42 has rule evidence.",
        provider_answer="Alert #42 came from 203.0.113.10.",
        context_used=["alert_detail"],
        citations=citations,
    ) == "provider_answer_contains_unredacted_ip"
    assert assistant_service._llm_answer_guard_reason(
        deterministic_answer="Alert #42 has rule evidence.",
        provider_answer="Alert #42 has supplied evidence.",
        context_used=["alert_detail"],
        citations=citations,
        structured_answer={"_unsupported_citation_count": 1},
    ) == "provider_answer_contains_unsupported_citation"


def test_v556_citation_aliases_resolve_only_to_one_allowlisted_reference() -> None:
    payload = json.dumps(
        {
            "direct_answer": "Alert #42 is supported by supplied evidence.",
            "key_evidence": ["The bounded alert record contains rule evidence."],
            "next_steps": ["Review linked normalized evidence."],
            "citation_references": ["/api/alerts/{alert_id} #42"],
        }
    )
    parsed = assistant_llm._parse_structured_answer(
        payload,
        citations=[
            {
                "label": "Alert detail",
                "source": "/api/alerts/{alert_id}",
                "reference_id": "42",
            }
        ],
        response_mode="alert_explanation",
    )
    assert parsed is not None
    assert parsed["citation_references"] == ["Alert detail #42"]
    assert "_unsupported_citation_count" not in parsed

    ambiguous = assistant_llm._parse_structured_answer(
        payload.replace("/api/alerts/{alert_id} #42", "Evidence log"),
        citations=[
            {"label": "Evidence log", "source": "/api/logs/{log_id}", "reference_id": "1"},
            {"label": "Evidence log", "source": "/api/logs/{log_id}", "reference_id": "2"},
        ],
        response_mode="alert_explanation",
    )
    assert ambiguous is not None
    assert ambiguous["_unsupported_citation_count"] == 1


def test_v556_gemini_schema_constrains_citations_to_request_allowlist() -> None:
    citations = [
        {
            "label": "Alert detail",
            "source": "/api/alerts/{alert_id}",
            "reference_id": "42",
        },
        {
            "label": "Detection explanation",
            "source": "atdr/app/detection/explanations.py",
        },
    ]
    schema = assistant_llm._gemini_response_schema(citations)
    citation_schema = schema["properties"]["citation_references"]
    assert citation_schema["items"]["enum"] == [
        "Alert detail #42",
        "Detection explanation",
    ]
    assert citation_schema["maxItems"] == 2
    assert "enum" not in assistant_llm.GEMINI_STRUCTURED_RESPONSE_SCHEMA["properties"]["citation_references"]["items"]


def test_v556_oversized_provider_output_falls_back_and_counts_usage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _settings(ASSISTANT_LLM_USAGE_WARNING_TOKENS=50)
    assistant_llm.reset_assistant_llm_operational_state(settings)

    class _OversizedProvider(assistant_llm.AssistantLLMProvider):
        provider_name = "mock"

        def generate(
            self,
            request: assistant_llm.AssistantLLMRequest,
            settings: Settings,
        ) -> assistant_llm.AssistantLLMResult:
            structured = {
                "direct_answer": "oversized " * 130,
                "key_evidence": ["bounded evidence"],
                "next_steps": ["review evidence"],
                "citation_references": ["Alert detail #42"],
            }
            return assistant_llm.AssistantLLMResult(
                used=True,
                provider="mock",
                answer="temporary",
                structured_answer=structured,
                usage={"input_tokens": 40, "output_tokens": 90, "total_tokens": 130},
                provider_called=True,
            )

    monkeypatch.setattr(
        assistant_llm,
        "_provider_for",
        lambda _name: _OversizedProvider(),
    )
    result = assistant_llm.maybe_generate_external_answer(_request(), settings)
    status = assistant_llm.assistant_llm_operational_status(settings)
    assert result.used is False
    assert result.answer is None
    assert result.fallback_reason == "provider_response_oversized"
    assert status["calls_failed"] == 1
    assert status["fallbacks"] == 1
    assert status["failure_categories"]["oversized_output"] == 1
    assert status["token_usage"]["total_tokens"] == 130
    assert status["usage_warning"] is True


def test_v556_provider_output_within_hard_limit_is_rendered_to_intent_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _settings()
    assistant_llm.reset_assistant_llm_operational_state(settings)

    class _VerboseButValidProvider(assistant_llm.AssistantLLMProvider):
        provider_name = "mock"

        def generate(
            self,
            request: assistant_llm.AssistantLLMRequest,
            settings: Settings,
        ) -> assistant_llm.AssistantLLMResult:
            structured = {
                "direct_answer": " ".join(f"fact{index}" for index in range(70)),
                "key_evidence": ["bounded evidence"],
                "next_steps": ["review evidence"],
                "citation_references": ["Alert detail #42"],
            }
            return assistant_llm.AssistantLLMResult(
                used=True,
                provider="mock",
                answer="unbounded provider rendering must not escape",
                structured_answer=structured,
                usage={"total_tokens": 90},
                provider_called=True,
            )

    monkeypatch.setattr(
        assistant_llm,
        "_provider_for",
        lambda _name: _VerboseButValidProvider(),
    )
    result = assistant_llm.maybe_generate_external_answer(_request(), settings)
    assert result.used is True
    assert result.fallback_reason is None
    assert result.answer is not None
    assert len(result.answer.split()) <= _request().word_limit
    assert "unbounded provider rendering" not in result.answer


def test_v556_related_log_rows_keep_distinct_record_ids() -> None:
    presentation = build_response_presentation(
        mode="related_logs",
        question="What logs are related to alert 42?",
        original_answer="Three related logs are available.",
        raw_sections={
            "summary": ["Evidence logs: 4; related logs: 4."],
            "related_context": [
                "Log 1: deny unknown to port 20001",
                "Log 2: deny unknown to port 20002",
                "Log 3: deny unknown to port 20003",
                "Log 4: deny unknown to port 20004",
            ],
        },
        active_context={"primary": "alert", "alert_id": 42},
        citation_references=["Alert detail #42"],
    )
    assert presentation.sections["related_logs"] == [
        "Log 1: deny unknown to port 20001",
        "Log 2: deny unknown to port 20002",
        "Log 3: deny unknown to port 20003",
    ]
    assert "Log 4" not in presentation.answer


def test_v556_false_positive_and_governance_answers_are_direct() -> None:
    false_positive = build_response_presentation(
        mode="alert_explanation",
        question="Is alert 42 likely a false positive?",
        original_answer="Alert 42 needs review.",
        raw_sections={
            "summary": ["Alert #42 has scan-like evidence."],
            "risk_interpretation": [
                "Evidence strength: high confidence.",
                "False-positive factor: authorized vulnerability scanner.",
            ],
            "what_to_check_next": ["Confirm whether the scanner is authorized."],
        },
        active_context={"primary": "alert", "alert_id": 42},
        citation_references=["Alert detail #42"],
    )
    governance = build_response_presentation(
        mode="governance",
        question="Explain current ML status.",
        original_answer="ML is advisory.",
        raw_sections={
            "summary": ["ML remains advisory; rules are alert-authoritative."],
            "limitations": ["Independent validation is still required."],
            "evidence": ["Anomaly artifact is present."],
            "what_to_check_next": ["Use ML only as supporting context."],
        },
        active_context={},
        citation_references=["ML report"],
    )
    assert false_positive.answer.startswith("Verdict: Do not mark alert #42")
    assert "Independent validation is still required" in governance.answer
    assert "Blocker: Anomaly artifact" not in governance.answer
