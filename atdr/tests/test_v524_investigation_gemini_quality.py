from __future__ import annotations

import json

from atdr.app.core.config import Settings
from atdr.app.services import assistant_llm
from atdr.app.services.v524_investigation_gemini_quality_service import (
    RAW_SENTINEL,
    QualityQuestion,
    evaluate_assistant_response,
    run_v524_quality_lock,
)


def _settings(**updates) -> Settings:
    values = {
        "ASSISTANT_ENABLED": True,
        "ASSISTANT_LLM_ENABLED": True,
        "ASSISTANT_LLM_PROVIDER": "mock",
        "ASSISTANT_LLM_MODEL": "v524-mock",
        "ASSISTANT_LLM_API_KEY": "",
        "ASSISTANT_ALLOW_RAW_LOG_CONTEXT": False,
        "ASSISTANT_REDACT_IPS": True,
    }
    values.update(updates)
    return Settings(**values)


def test_v524_mock_quality_lock_is_bounded_private_and_read_only() -> None:
    report = run_v524_quality_lock(
        settings=_settings(),
        execute_provider=True,
        write_reports=False,
    )

    assert report["question_count"] == 6
    assert report["provider"] == "mock"
    assert report["provider_measurements"]["calls_used"] == 6
    assert report["checks"]["provider_failure_fallback_passed"] is True
    assert report["checks"]["privacy_contract_passed"] is True
    assert report["checks"]["read_only_contract_passed"] is True
    assert report["mutation_deltas"] == {
        "raw_logs": 0,
        "normalized_logs": 0,
        "alerts": 0,
        "detection_runs": 0,
        "labels": 0,
        "model_runs": 0,
        "response_actions": 0,
        "users": 0,
    }
    serialized = json.dumps(report)
    assert RAW_SENTINEL not in serialized
    assert "203.0.113.77" not in serialized
    assert "198.51.100.88" not in serialized


def test_v524_preflight_does_not_claim_provider_quality_lock() -> None:
    report = run_v524_quality_lock(
        settings=_settings(),
        execute_provider=False,
        write_reports=False,
    )

    assert report["status"] == "v5_24_provider_evaluation_not_requested"
    assert report["phase_complete"] is False
    assert report["provider_measurements"]["calls_used"] == 0
    assert report["checks"]["read_only_contract_passed"] is True


def test_v524_response_evaluator_rejects_wrong_context_and_hallucinated_id() -> None:
    question = QualityQuestion(
        key="alert_explanation",
        question="Why was alert 1 flagged?",
        expected_primary="alert",
        expected_route="/api/alerts/{alert_id}",
        expected_reference="1",
        expected_terms=("port scan",),
        conversation_id="v524-test",
        alert_id=1,
    )
    response = {
        "answer": "I blocked alert 99 after a port scan.",
        "mode": "external_llm_mock",
        "external_provider_used": True,
        "redaction_applied": True,
        "raw_log_context_included": False,
        "citations": [{"label": "Alert detail", "source": "/api/alerts/{alert_id}", "reference_id": "1"}],
        "active_context": {"primary": "alert", "alert_id": 99},
        "details": {
            "llm": {
                "provider_called": True,
                "answer_used": True,
                "structured_output_valid": True,
                "secrets_exposed": False,
            },
            "answer_sections": {
                "summary": ["I blocked alert 99."],
                "evidence": ["Port scan."],
                "what_to_check_next": ["Review."],
                "limitations": [],
                "citations": ["Alert detail #1"],
            },
        },
    }

    result = evaluate_assistant_response(
        response,
        question=question,
        provider_required=True,
        api_key="",
    )

    assert result["passed"] is False
    assert result["checks"]["primary_context_retained"] is False
    assert result["checks"]["no_unsupported_entity_references"] is False
    assert result["checks"]["no_implied_action_execution"] is False
    assert "alert:99" in result["unsupported_entity_references"]


def test_v524_generated_report_stays_outside_tracked_docs(tmp_path) -> None:
    report = run_v524_quality_lock(
        settings=_settings(),
        execute_provider=False,
        output_dir=tmp_path,
        write_reports=True,
    )

    assert report["phase_complete"] is False
    names = sorted(path.name for path in tmp_path.iterdir())
    assert "v5_24_investigation_gemini_quality_latest.json" in names
    assert any(name.endswith(".md") for name in names)
    assert all(".env" not in name for name in names)


def test_v524_structured_answer_always_attaches_trusted_primary_citation() -> None:
    payload = json.dumps(
        {
            "summary": "The requested alert has deterministic evidence.",
            "evidence": ["A port-scan rule matched."],
            "risk_interpretation": ["Analyst review remains required."],
            "analyst_checks": ["Review related logs."],
            "missing_information": ["Asset ownership is not established."],
            "safety_notice": "Read-only decision support; response automation remains disabled.",
            "suggested_followups": ["What logs are related?"],
            "citation_references": [],
        }
    )

    parsed = assistant_llm._parse_structured_answer(
        payload,
        citations=[
            {"label": "Alert detail", "source": "/api/alerts/{alert_id}", "reference_id": "1"},
            {"label": "Detection rule catalog", "source": "docs/DETECTION_RULE_CATALOG.md", "reference_id": None},
        ],
    )

    assert parsed is not None
    assert parsed["citation_references"][0] == "Alert detail #1"
