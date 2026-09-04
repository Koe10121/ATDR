import shutil
from pathlib import Path

from atdr.app.core.config import PROJECT_ROOT
from atdr.scripts.run_e2e_workflow_validation import run_e2e_workflow_validation


def _output_dir(name: str) -> Path:
    path = PROJECT_ROOT / ".tmp" / "tests" / name
    shutil.rmtree(path, ignore_errors=True)
    path.mkdir(parents=True, exist_ok=True)
    return path


def test_e2e_workflow_validation_preserves_evidence_without_automatic_response():
    report = run_e2e_workflow_validation(
        scenarios=["port_scan_like_traffic"],
        simulate_response=False,
        write_output=False,
    )

    assert report["ok"] is True
    scenario = report["scenarios"][0]
    assert scenario["parser_normalization"]["raw_logs"] > 0
    assert scenario["parser_normalization"]["normalized_logs"] > 0
    assert scenario["alert_count"] >= 1
    assert scenario["case_count"] >= 1
    assert scenario["investigation_evidence"]["linked_evidence_count"] > 0
    assert scenario["audit_summary"]["response_actions_created"] == 0
    assert all(item["passed"] for item in scenario["checks"])


def test_e2e_workflow_validation_simulated_response_is_audited_and_safe():
    report = run_e2e_workflow_validation(
        scenarios=["port_scan_like_traffic"],
        simulate_response=True,
        write_output=True,
        output_dir=_output_dir("e2e_validation_reports"),
    )

    assert report["ok"] is True
    scenario = report["scenarios"][0]
    response = scenario["response_safety"]
    assert response["missing_justification_denied"] is True
    assert response["protected_ip_denied"] is True
    assert response["approved_simulated"] is True
    assert response["real_firewall_changed"] is False
    assert scenario["audit_summary"]["response_actions_created"] == 3
    assert Path(report["paths"]["json"]).exists()
    markdown = Path(report["paths"]["markdown"]).read_text(encoding="utf-8")
    assert "ATDR v1.0 End-to-End Workflow Validation" in markdown
    assert "Response actions remain simulated" in markdown


def test_e2e_workflow_validation_preserves_assistant_context_without_side_effects():
    report = run_e2e_workflow_validation(
        scenarios=["port_scan_like_traffic"],
        simulate_response=True,
        exercise_assistant=True,
        write_output=False,
    )

    assert report["ok"] is True
    assert report["exercise_assistant"] is True
    scenario = report["scenarios"][0]
    assistant = scenario["assistant"]
    assert assistant["exercised"] is True
    assert assistant["passed"] is True
    assert assistant["conversation_turns"] == 3
    assert [item["response_mode"] for item in assistant["responses"]] == [
        "alert_explanation",
        "related_logs",
        "safe_next_step",
    ]
    assert len({item["active_context"]["alert_id"] for item in assistant["responses"]}) == 1
    assert all(item["citation_count"] > 0 for item in assistant["responses"])
    assert all(item["external_provider_used"] is False for item in assistant["responses"])
    assert all(item["raw_log_context_included"] is False for item in assistant["responses"])
    assert all(item["redaction_applied"] is True for item in assistant["responses"])
    assert assistant["case_handoff"]["available"] is True
    assert assistant["case_handoff"]["response_mode"] == "case_handoff"
    assert assistant["action_executed"] is False
    assert all(delta == 0 for delta in assistant["authoritative_row_deltas"].values())
    assert scenario["response_safety"]["approved_simulated"] is True
    assert scenario["response_safety"]["real_firewall_changed"] is False
