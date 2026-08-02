from __future__ import annotations

import json

from atdr.app.core.config import Settings
from atdr.app.services.v525_integrated_acceptance_service import (
    build_v525_report,
    run_v525_integrated_acceptance,
)


def _mock_settings() -> Settings:
    return Settings(
        ASSISTANT_ENABLED=True,
        ASSISTANT_LLM_ENABLED=True,
        ASSISTANT_LLM_PROVIDER="mock",
        ASSISTANT_LLM_MODEL="v525-mock",
        ASSISTANT_LLM_API_KEY="",
        ASSISTANT_ALLOW_RAW_LOG_CONTEXT=False,
        ASSISTANT_REDACT_IPS=True,
    )


def _passing_inputs() -> dict:
    product = {
        "passed": True,
        "attempted": 100,
        "raw_logs_imported": 100,
        "normalized_logs_created": 100,
        "source_links_complete": True,
        "raw_evidence_preserved": True,
        "interruption_recovered": True,
        "cancellation_recovered": True,
        "stale_lease_failed_closed": True,
        "rule_alert_created": True,
        "deduplication_recorded": True,
        "investigation_source_traceable": True,
        "case_available": True,
        "why_flagged_available": True,
        "configured_database_unchanged": True,
        "temporary_artifacts_removed": True,
        "response_actions_created": 0,
        "labels_created": 0,
        "model_runs_created": 0,
        "secrets_exposed": False,
    }
    workflow = {
        "passed": True,
        "rules_alert_authoritative": True,
        "ml_requested_as_decision_support": True,
        "missing_justification_denied": True,
        "protected_target_denied": True,
        "analyst_approved_action_simulated": True,
        "response_audits_recorded": True,
        "simulated_response_records": 3,
        "automatic_response_enabled": False,
        "real_firewall_blocking_enabled": False,
    }
    transport = {
        "passed": True,
        "file_import_passed": True,
        "api_upload_passed": True,
        "resumable_import_passed": True,
        "backpressure_enforced": True,
        "local_udp_transport_passed": True,
        "non_loopback_transport_validated": False,
        "real_device_validated": False,
        "rules_alert_authoritative": True,
        "alert_created": True,
        "deduplication_recorded": True,
        "source_traceable": True,
        "why_flagged_available": True,
        "analyst_next_steps_available": True,
        "configured_database_unchanged": True,
        "temporary_artifacts_removed": True,
        "secrets_exposed": False,
    }
    assistant = {
        "passed": True,
        "rules_remain_alert_authoritative": True,
        "raw_logs_disabled": True,
        "ip_redaction_enabled": True,
        "assistant_read_only": True,
        "model_activated": False,
        "model_promoted": False,
        "response_automation_allowed": False,
        "real_firewall_blocking_enabled": False,
        "mutation_deltas": {"alerts": 0, "responses": 0},
        "secrets_exposed": False,
    }
    repository = {"passed": True, "private_configuration_returned": False}
    return {
        "product": product,
        "workflow": workflow,
        "transport": transport,
        "assistant": assistant,
        "repository": repository,
    }


def test_v525_report_passes_local_closure_with_external_gates_open() -> None:
    report = build_v525_report(**_passing_inputs(), assistant_evidence_mode="fresh_provider")

    assert report["ok"] is True
    assert report["phase_complete"] is True
    assert report["production_ready"] is False
    assert report["status"] == "v5_25_integrated_acceptance_passed_external_gates_open"
    assert report["external_gates"]["non_loopback_sender"]["status"] == "owner_deferred"
    assert report["external_gates"]["real_firewall_or_router"]["satisfied"] is False
    assert report["safety"]["model_activated"] is False
    assert report["safety"]["automatic_response_enabled"] is False


def test_v525_report_fails_closed_without_provider_evidence() -> None:
    report = build_v525_report(**_passing_inputs(), assistant_evidence_mode="unavailable")

    assert report["ok"] is False
    assert report["phase_complete"] is False
    assert report["status"] == "v5_25_gemini_quality_evidence_required"
    assert "gemini_quality_lock_passed" in report["failed_checks"]


def test_v525_report_rejects_unsafe_response_claim() -> None:
    inputs = _passing_inputs()
    inputs["workflow"]["automatic_response_enabled"] = True

    report = build_v525_report(**inputs, assistant_evidence_mode="fresh_provider")

    assert report["ok"] is False
    assert "no_automatic_or_real_response" in report["failed_checks"]
    assert report["production_ready"] is False


def test_v525_report_rejects_private_path_or_address() -> None:
    inputs = _passing_inputs()
    inputs["product"]["unsafe_value"] = "C:/Users/private/evidence.log"

    report = build_v525_report(**inputs, assistant_evidence_mode="fresh_provider")

    assert report["ok"] is False
    assert report["status"] == "v5_25_privacy_contract_failed"
    assert report["privacy"]["private_path_or_address_returned"] is True


def test_v525_requires_disposable_database() -> None:
    report = run_v525_integrated_acceptance(
        settings=_mock_settings(),
        use_temp_db=False,
        execute_provider=True,
        write_reports=False,
    )

    assert report["ok"] is False
    assert report["status"] == "explicit_temp_database_required"
    assert report["configured_database_modified"] is False


def test_v525_mock_integrated_acceptance_is_private_and_safe(tmp_path) -> None:
    report = run_v525_integrated_acceptance(
        settings=_mock_settings(),
        use_temp_db=True,
        execute_provider=True,
        log_count=100,
        temp_parent=tmp_path,
        write_reports=False,
    )

    serialized = json.dumps(report)
    assert report["ok"] is True
    assert report["passed_checks"] == report["total_checks"]
    assert report["collection"]["configured_database_unchanged"] is True
    assert report["live_source"]["configured_database_unchanged"] is True
    assert report["assistant"]["provider"] == "mock"
    assert report["workflow"]["analyst_approved_action_simulated"] is True
    assert report["workflow"]["response_audits_recorded"] is True
    assert report["privacy"]["private_path_or_address_returned"] is False
    assert "raw_line" not in serialized
    assert "api_key" not in serialized.lower()


def test_v525_reports_are_generated_only_in_supplied_output(tmp_path) -> None:
    report = run_v525_integrated_acceptance(
        settings=_mock_settings(),
        use_temp_db=True,
        execute_provider=True,
        log_count=100,
        temp_parent=tmp_path / "runtime",
        output_dir=tmp_path / "reports",
        write_reports=True,
    )

    assert report["ok"] is True
    names = sorted(path.name for path in (tmp_path / "reports").iterdir())
    assert "v5_25_integrated_acceptance_latest.json" in names
    assert any(name.endswith(".md") for name in names)
    assert all(".env" not in name for name in names)
