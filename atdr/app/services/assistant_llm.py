from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

import requests

from atdr.app.core.config import Settings


IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
PROMPT_CONTRACT_VERSION = "soc_evidence_preserving_v1"

SAFE_SYSTEM_PROMPT = """You are the ATDR SOC Assistant.

You are writing for a professional security analyst using a read-only SOC
triage system. Improve wording and structure, but stay inside the supplied
ATDR evidence. Preserve IDs, uncertainty, counts, citations, and safety
limits. Do not invent facts. Do not request or expose raw logs. Do not execute,
recommend executing, or imply you executed response actions, detection runs,
label changes, model activation, account changes, data deletion, or firewall
changes. ATDR response remains simulated and analyst-approved only.

Return a concise but complete SOC answer. Do not answer with a single sentence
when alert/log/source evidence is available. Use the requested section labels
when possible: Summary, Evidence, Risk interpretation, Analyst checks, Safety,
Sources.
"""


@dataclass(frozen=True)
class AssistantLLMRequest:
    question: str
    deterministic_answer: str
    context_used: list[str]
    citations: list[dict[str, Any]]
    suggested_followups: list[str]
    safety: list[str]


@dataclass(frozen=True)
class AssistantLLMResult:
    used: bool
    provider: str
    model: str | None = None
    answer: str | None = None
    fallback_reason: str | None = None
    raw_log_context_included: bool = False
    secrets_exposed: bool = False
    context_characters: int = 0

    def safe_details(self) -> dict[str, Any]:
        return {
            "used": self.used,
            "provider": self.provider,
            "model_configured": bool(self.model),
            "fallback_reason": self.fallback_reason,
            "raw_log_context_included": self.raw_log_context_included,
            "secrets_exposed": self.secrets_exposed,
            "context_characters": self.context_characters,
            "prompt_contract": PROMPT_CONTRACT_VERSION,
        }


class AssistantLLMProvider:
    provider_name = "disabled"

    def generate(self, request: AssistantLLMRequest, settings: Settings) -> AssistantLLMResult:
        raise NotImplementedError


class MockAssistantLLMProvider(AssistantLLMProvider):
    provider_name = "mock"

    def generate(self, request: AssistantLLMRequest, settings: Settings) -> AssistantLLMResult:
        context = build_safe_context_prompt(request, settings)
        return AssistantLLMResult(
            used=True,
            provider=self.provider_name,
            model=settings.assistant_llm_model.strip() or "mock",
            answer=(
                "LLM-assisted analyst summary (mock provider).\n\n"
                f"{request.deterministic_answer}\n\n"
                "Safety: read-only decision support; response automation remains disabled."
            ),
            context_characters=len(context),
        )


class GeminiAssistantLLMProvider(AssistantLLMProvider):
    provider_name = "gemini"

    def generate(self, request: AssistantLLMRequest, settings: Settings) -> AssistantLLMResult:
        model = settings.assistant_llm_model.strip() or "gemini-1.5-flash"
        base_url = settings.assistant_llm_base_url.strip().rstrip("/") or "https://generativelanguage.googleapis.com/v1beta"
        url = f"{base_url}/models/{model}:generateContent"
        payload = {
            "systemInstruction": {"parts": [{"text": SAFE_SYSTEM_PROMPT}]},
            "contents": [{"role": "user", "parts": [{"text": build_safe_context_prompt(request, settings)}]}],
            "generationConfig": {"temperature": 0.2, "maxOutputTokens": 1200},
        }
        data = _post_json(
            url,
            headers={},
            params={"key": settings.assistant_llm_api_key.strip()},
            payload=payload,
            timeout=settings.assistant_llm_timeout_seconds,
        )
        text = _extract_gemini_text(data)
        return AssistantLLMResult(
            used=True,
            provider=self.provider_name,
            model=model,
            answer=text,
            context_characters=len(payload["contents"][0]["parts"][0]["text"]),
        )


class OpenAICompatibleAssistantLLMProvider(AssistantLLMProvider):
    provider_name = "openai"

    def generate(self, request: AssistantLLMRequest, settings: Settings) -> AssistantLLMResult:
        model = settings.assistant_llm_model.strip() or "gpt-4o-mini"
        base_url = settings.assistant_llm_base_url.strip().rstrip("/") or "https://api.openai.com/v1"
        payload = {
            "model": model,
            "temperature": 0.2,
            "max_tokens": 1200,
            "messages": [
                {"role": "system", "content": SAFE_SYSTEM_PROMPT},
                {"role": "user", "content": build_safe_context_prompt(request, settings)},
            ],
        }
        data = _post_json(
            f"{base_url}/chat/completions",
            headers={"Authorization": f"Bearer {settings.assistant_llm_api_key.strip()}"},
            params=None,
            payload=payload,
            timeout=settings.assistant_llm_timeout_seconds,
        )
        text = _extract_openai_text(data)
        return AssistantLLMResult(
            used=True,
            provider=self.provider_name,
            model=model,
            answer=text,
            context_characters=len(payload["messages"][1]["content"]),
        )


class ClaudeAssistantLLMProvider(AssistantLLMProvider):
    provider_name = "claude"

    def generate(self, request: AssistantLLMRequest, settings: Settings) -> AssistantLLMResult:
        model = settings.assistant_llm_model.strip() or "claude-3-5-sonnet-latest"
        base_url = settings.assistant_llm_base_url.strip().rstrip("/") or "https://api.anthropic.com/v1"
        payload = {
            "model": model,
            "max_tokens": 1200,
            "temperature": 0.2,
            "system": SAFE_SYSTEM_PROMPT,
            "messages": [{"role": "user", "content": build_safe_context_prompt(request, settings)}],
        }
        data = _post_json(
            f"{base_url}/messages",
            headers={
                "x-api-key": settings.assistant_llm_api_key.strip(),
                "anthropic-version": "2023-06-01",
            },
            params=None,
            payload=payload,
            timeout=settings.assistant_llm_timeout_seconds,
        )
        text = _extract_claude_text(data)
        return AssistantLLMResult(
            used=True,
            provider=self.provider_name,
            model=model,
            answer=text,
            context_characters=len(payload["messages"][0]["content"]),
        )


def maybe_generate_external_answer(
    request: AssistantLLMRequest,
    settings: Settings,
) -> AssistantLLMResult:
    if not settings.assistant_llm_enabled:
        return AssistantLLMResult(used=False, provider="disabled", fallback_reason="external_llm_disabled")
    if settings.assistant_allow_raw_log_context:
        return AssistantLLMResult(used=False, provider="disabled", fallback_reason="raw_log_context_not_allowed_for_llm")
    provider_name = settings.assistant_llm_provider.strip().lower()
    if not provider_name:
        return AssistantLLMResult(used=False, provider="disabled", fallback_reason="provider_not_configured")
    if not settings.assistant_llm_api_key.strip() and provider_name != "mock":
        return AssistantLLMResult(used=False, provider=provider_name, fallback_reason="api_key_not_configured")

    provider = _provider_for(provider_name)
    if provider is None:
        return AssistantLLMResult(used=False, provider=provider_name, fallback_reason="provider_not_supported")
    try:
        result = provider.generate(request, settings)
    except Exception:
        return AssistantLLMResult(used=False, provider=provider.provider_name, fallback_reason="provider_request_failed")
    if not result.answer or not result.answer.strip():
        return AssistantLLMResult(used=False, provider=provider.provider_name, fallback_reason="empty_provider_response")
    return result


def build_safe_context_prompt(request: AssistantLLMRequest, settings: Settings) -> str:
    citations = [
        {
            "label": str(item.get("label", ""))[:120],
            "source": str(item.get("source", ""))[:120],
            "reference_id": str(item.get("reference_id", ""))[:120] if item.get("reference_id") is not None else None,
        }
        for item in request.citations[:20]
    ]
    lines = [
        f"Prompt contract: {PROMPT_CONTRACT_VERSION}",
        "",
        "Analyst question:",
        _redact_if_needed(request.question, settings=settings)[:2000],
        "",
        "ATDR deterministic answer to preserve:",
        _redact_if_needed(request.deterministic_answer, settings=settings)[:6000],
        "",
        "Context labels:",
        ", ".join(_redact_if_needed(item, settings=settings)[:120] for item in request.context_used[:20]) or "none",
        "",
        "Citations:",
        str(citations),
        "",
        "Suggested follow-ups:",
        str([_redact_if_needed(item, settings=settings)[:160] for item in request.suggested_followups[:8]]),
        "",
        "Safety rules:",
        "; ".join(request.safety),
        "",
        "Required response format:",
        "- Summary: directly answer the analyst's question in 2-4 sentences.",
        "- Evidence: preserve the important alert/log/source facts, counts, IDs, and why-flagged signals from ATDR.",
        "- Risk interpretation: explain what the evidence suggests and what is uncertain.",
        "- Analyst checks: list safe verification steps an analyst should perform next.",
        "- Safety: state that the assistant is read-only and response automation remains disabled.",
        "- Sources: mention the provided citation labels and reference IDs when useful.",
        "",
        "Quality requirements:",
        "- Use professional SOC wording.",
        "- Keep the same facts and uncertainty as the deterministic answer.",
        "- Do not omit concrete IDs, counts, evidence strength, parser/source warnings, or response-safety limits when they are present.",
        "- Do not add unprovided indicators, IPs, users, filenames, model claims, device actions, or containment actions.",
        "- If evidence is weak, say so clearly and recommend analyst verification.",
        "- If the deterministic answer already says no automatic response occurred, preserve that safety limit.",
        "- Be concise, but do not be so terse that the evidence trail disappears.",
        "",
        "Task:",
        "Rewrite the deterministic answer into the required SOC format. Keep it evidence-grounded and read-only.",
    ]
    return "\n".join(lines)[:10000]


def _provider_for(provider_name: str) -> AssistantLLMProvider | None:
    if provider_name == "mock":
        return MockAssistantLLMProvider()
    if provider_name in {"gemini", "google", "google_gemini"}:
        return GeminiAssistantLLMProvider()
    if provider_name in {"openai", "openai_compatible", "openai-compatible"}:
        return OpenAICompatibleAssistantLLMProvider()
    if provider_name in {"claude", "anthropic"}:
        return ClaudeAssistantLLMProvider()
    return None


def _redact_if_needed(value: str, *, settings: Settings) -> str:
    if not settings.assistant_redact_ips:
        return value
    return IP_PATTERN.sub("[redacted-ip]", value)


def _post_json(
    url: str,
    *,
    headers: dict[str, str],
    params: dict[str, str] | None,
    payload: dict[str, Any],
    timeout: float,
) -> dict[str, Any]:
    safe_headers = {"Content-Type": "application/json", **headers}
    response = requests.post(url, headers=safe_headers, params=params, json=payload, timeout=max(1.0, min(timeout, 60.0)))
    if response.status_code >= 400:
        raise RuntimeError("provider request failed")
    data = response.json()
    if not isinstance(data, dict):
        raise RuntimeError("provider response was not an object")
    return data


def _extract_gemini_text(data: dict[str, Any]) -> str:
    candidates = data.get("candidates")
    if not isinstance(candidates, list) or not candidates:
        return ""
    content = candidates[0].get("content") if isinstance(candidates[0], dict) else None
    parts = content.get("parts") if isinstance(content, dict) else None
    if not isinstance(parts, list):
        return ""
    return "\n".join(str(part.get("text", "")).strip() for part in parts if isinstance(part, dict)).strip()


def _extract_openai_text(data: dict[str, Any]) -> str:
    choices = data.get("choices")
    if not isinstance(choices, list) or not choices:
        return ""
    message = choices[0].get("message") if isinstance(choices[0], dict) else None
    content = message.get("content") if isinstance(message, dict) else None
    return str(content).strip() if content else ""


def _extract_claude_text(data: dict[str, Any]) -> str:
    content = data.get("content")
    if not isinstance(content, list):
        return ""
    return "\n".join(str(item.get("text", "")).strip() for item in content if isinstance(item, dict)).strip()
