from atdr.scripts.evaluate_assistant_qa import evaluate_assistant_qa


def test_assistant_qa_evaluator_passes_and_is_non_mutating():
    result = evaluate_assistant_qa()

    assert result["ok"] is True
    assert result["end_to_end_investigation_checks"]["sample_logs_parse"] is True
    assert result["end_to_end_investigation_checks"]["detection_created_alert"] is True
    assert result["end_to_end_investigation_checks"]["assistant_alert_explainer_passed"] is True
    assert result["end_to_end_investigation_checks"]["assistant_brief_passed"] is True
    assert all(item["passed"] for item in result["question_results"])
    assert all(result["side_effect_checks"].values())
    assert result["safety"]["external_provider_used"] is False
    assert result["safety"]["raw_log_context_included"] is False
    assert result["safety"]["response_automation_allowed"] is False
    assert result["safety"]["real_firewall_blocking_enabled"] is False
