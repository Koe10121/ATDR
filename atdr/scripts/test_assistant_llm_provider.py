from __future__ import annotations

import argparse
import json
from typing import Any

from atdr.app.core.config import get_settings
from atdr.app.services.assistant_llm import AssistantLLMRequest, maybe_generate_external_answer
from atdr.app.services.assistant_service import assistant_status


def _build_probe_request() -> AssistantLLMRequest:
    return AssistantLLMRequest(
        question="Summarize ATDR assistant safety mode.",
        deterministic_answer=(
            "ATDR assistant is read-only decision support. It cannot execute response actions, "
            "change labels, run detection, activate models, delete data, or change firewall state."
        ),
        context_used=["assistant_provider_probe", "safety_policy"],
        citations=[
            {
                "label": "Assistant safety contract",
                "source": "docs/security/ATDR_REAL_LLM_ASSISTANT_PLAN.md",
                "reference_id": "assistant-safety",
            }
        ],
        suggested_followups=["What can the assistant do safely?", "What remains disabled?"],
        safety=["Read-only", "Decision Support Only", "Response Automation Disabled"],
    )


def build_report(*, execute: bool) -> dict[str, Any]:
    settings = get_settings()
    status = assistant_status(settings)
    report: dict[str, Any] = {
        "ok": True,
        "executed_provider_call": False,
        "llm_enabled": status["llm_enabled"],
        "provider_configured": status["llm_provider_configured"],
        "provider": status["llm_provider_name"] or "disabled",
        "model_configured": status["llm_model_configured"],
        "api_key_configured": status["llm_secret_configured"],
        "base_url_configured": status["llm_base_url_configured"],
        "raw_log_context_allowed": status["raw_log_context_allowed"],
        "redaction_enabled": status["redaction_enabled"],
        "secrets_exposed": False,
        "message": "External LLM call was not executed. Pass --execute with ASSISTANT_LLM_ENABLED=true to run one minimal probe.",
    }
    if not execute:
        return report
    if not settings.assistant_llm_enabled:
        report["ok"] = False
        report["message"] = "ASSISTANT_LLM_ENABLED is false; no provider call was made."
        return report
    result = maybe_generate_external_answer(_build_probe_request(), settings)
    report["executed_provider_call"] = bool(
        result.used
        or result.fallback_reason in {"provider_request_failed", "empty_provider_response", "malformed_provider_response"}
    )
    report["provider"] = result.provider
    report["model_configured"] = bool(result.model)
    report["fallback_reason"] = result.fallback_reason
    report["raw_log_context_included"] = result.raw_log_context_included
    report["context_characters"] = result.context_characters
    report["structured_output_valid"] = bool(result.structured_answer)
    report["latency_ms"] = result.latency_ms
    report["attempts"] = result.attempts
    report["usage"] = result.usage
    report["secrets_exposed"] = result.secrets_exposed
    report["ok"] = bool(
        result.used
        and result.structured_answer
        and not result.secrets_exposed
        and not result.raw_log_context_included
    )
    report["message"] = "Provider probe completed." if report["ok"] else "Provider probe did not complete successfully."
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description="Safely check ATDR assistant LLM provider readiness.")
    parser.add_argument("--execute", action="store_true", help="Run one minimal provider call if ASSISTANT_LLM_ENABLED=true.")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON output.")
    args = parser.parse_args()
    report = build_report(execute=args.execute)
    print(json.dumps(report, indent=2 if args.pretty else None, sort_keys=True))


if __name__ == "__main__":
    main()
