from atdr.scripts.run_detection_validation_suite import run_detection_validation_scenario
from atdr.scripts.validate_detection_quality import validate_detection_quality
from atdr.scripts.validate_parser_normalization import validate_parser_normalization


def test_v318_detection_quality_reports_no_false_positive_or_false_negative_scenarios():
    report = validate_detection_quality()

    assert report["ok"] is True
    assert report["scenario_count"] == 23
    assert report["expected_alerts"] == report["actual_alerts"] == 12
    assert report["false_positive_scenario_count"] == 0
    assert report["false_negative_scenario_count"] == 0
    assert report["unexpected_attack_type_count"] == 0
    assert report["parser_warning_count"] >= 1
    assert report["raw_fallback_count"] >= 1
    assert report["response_actions_created"] == 0
    assert report["no_automatic_response_confirmed"] is True


def test_v318_benign_control_scenarios_do_not_create_alerts():
    report = validate_detection_quality(
        scenarios=[
            "benign_dns_web_traffic",
            "benign_incomplete_allow_noise",
            "benign_repeated_internal_service",
            "benign_high_volume_single_service",
        ]
    )

    assert report["ok"] is True
    assert report["benign_no_alert_scenarios"] == 4
    assert report["actual_alerts"] == 0
    assert report["false_positive_scenario_count"] == 0
    assert {item["rule_level_qa"]["source"] for item in report["scenarios"]} <= {"no_alert", "parser_warning_only"}


def test_v318_positive_scenarios_create_expected_attack_types():
    report = validate_detection_quality(
        scenarios=[
            "suspicious_horizontal_scan",
            "suspicious_denied_ssh_burst",
            "suspicious_rare_port_probe",
            "malicious_like_c2_beacon",
            "malicious_like_exfiltration_burst",
        ]
    )

    assert report["ok"] is True
    by_name = {item["scenario"]: item for item in report["scenarios"]}
    assert by_name["suspicious_horizontal_scan"]["attack_types"] == ["port_scan"]
    assert by_name["suspicious_denied_ssh_burst"]["attack_types"] == ["brute_force"]
    assert by_name["suspicious_rare_port_probe"]["attack_types"] == ["policy_violation"]
    assert by_name["malicious_like_c2_beacon"]["attack_types"] == ["malware_c2"]
    assert by_name["malicious_like_exfiltration_burst"]["attack_types"] == ["data_exfiltration_suspicion"]
    assert all(item["rule_level_qa"]["source"] == "rule" for item in by_name.values())


def test_v318_malformed_vendor_mixed_fields_preserve_evidence_without_crashing():
    report = validate_parser_normalization(["malformed_vendor_mixed_fields"])

    assert report["ok"] is True
    assert report["database_mutated"] is False
    assert report["files_checked"] == 1
    file_result = report["files"][0]
    assert file_result["parsed_successfully"] == 3
    assert file_result["parse_failures"] == 0
    assert file_result["missing_action_count"] >= 1
    assert file_result["top_parser_warnings"]


def test_v318_alert_explanations_include_required_evidence_sections():
    result = run_detection_validation_scenario(scenario="suspicious_horizontal_scan")

    assert result["passed"] is True
    alert = result["alerts"][0]
    assert alert["what_happened"]
    assert alert["why_flagged"]
    assert alert["why_suspicious"]
    assert alert["normalized_fields_used"]
    assert alert["rule_evidence"]
    assert alert["anomaly_evidence"] is not None
    assert alert["ml_evidence"]["decision_support_only"] is True
    assert alert["analyst_next_steps"]
    assert alert["safety_note"] == "Decision support only. Response automation remains disabled."
