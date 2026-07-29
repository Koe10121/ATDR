import re
import shutil
from datetime import datetime
from pathlib import Path

from atdr.app.core.config import PROJECT_ROOT
from atdr.scripts.generate_detection_variants import generate_variant_lines
from atdr.scripts.run_detection_validation_suite import (
    _load_expectations,
    run_detection_validation_scenario,
    run_detection_validation_suite,
)
from atdr.scripts.validate_detection_pipeline import validate_detection_pipeline


def _output_dir(name: str) -> Path:
    path = PROJECT_ROOT / ".tmp" / "tests" / name
    shutil.rmtree(path, ignore_errors=True)
    path.mkdir(parents=True, exist_ok=True)
    return path


def test_detection_validation_suite_all_scenarios_passes_in_temp_db():
    result = run_detection_validation_suite(write_output=False)
    expectations = _load_expectations()

    assert result["ok"] is True
    assert result["scenario_count"] == len(expectations)
    assert result["passed_count"] == len(expectations)
    assert {item["scenario"] for item in result["risk_calibration"]} == {item["scenario"] for item in result["scenarios"]}
    assert all(item["safety"]["response_actions_created"] == 0 for item in result["scenarios"])


def test_detection_validation_suite_writes_json_and_markdown_report():
    result = run_detection_validation_suite(
        scenarios=["port_scan_like_traffic", "malformed_raw_fallback"],
        output_dir=_output_dir("detection_validation_report"),
    )

    assert result["ok"] is True
    json_path = Path(result["paths"]["json"])
    markdown_path = Path(result["paths"]["markdown"])
    risk_path = Path(result["paths"]["risk_calibration"])
    assert json_path.exists()
    assert markdown_path.exists()
    assert risk_path.exists()
    markdown = markdown_path.read_text(encoding="utf-8")
    assert "ATDR Controlled Threat Detection Validation" in markdown
    assert "controlled small-subnet" in markdown
    assert "Response mode: simulated and analyst-approved only" in markdown
    risk_markdown = risk_path.read_text(encoding="utf-8")
    assert "ATDR Risk And Severity Calibration" in risk_markdown
    assert "port_scan_like_traffic" in risk_markdown


def test_detection_variants_preserve_cadence_sensitive_beacon_window():
    lines = generate_variant_lines("malicious_like_c2_beacon", variant_index=3)[:6]
    timestamps = []
    for line in lines:
        match = re.match(r"(2026-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\+07:00)", line)
        assert match is not None
        timestamps.append(datetime.fromisoformat(match.group(1)))

    assert (max(timestamps) - min(timestamps)).total_seconds() == 300


def test_validation_scenarios_cover_clean_and_malformed_inputs():
    normal = run_detection_validation_scenario(scenario="normal_allowed_traffic")
    malformed = run_detection_validation_scenario(scenario="malformed_raw_fallback")
    mixed = run_detection_validation_scenario(scenario="mixed_small_subnet_validation")
    negative = run_detection_validation_scenario(scenario="normal_repeated_same_service_traffic")
    policy = run_detection_validation_scenario(scenario="policy_violation_suspicious_app")

    assert normal["passed"] is True
    assert normal["alert_count"] == 0
    assert malformed["passed"] is True
    assert malformed["source"]["quality"]["raw_logs"] == 3
    assert malformed["source"]["parse_failure_count"] == 3
    assert mixed["passed"] is True
    assert mixed["alert_count"] == 3
    assert {"port_scan", "brute_force", "malware_c2"}.issubset({alert["attack_type"] for alert in mixed["alerts"]})
    assert policy["passed"] is True
    assert policy["alert_count"] == 1
    assert {alert["attack_type"] for alert in policy["alerts"]} == {"policy_violation"}
    assert negative["passed"] is True
    assert negative["alert_count"] == 0


def test_repeated_dedup_validation_records_occurrence_update():
    result = run_detection_validation_scenario(scenario="repeated_dedup_traffic")

    assert result["passed"] is True
    checks = {item["name"]: item for item in result["checks"]}
    assert checks["dedup_min"]["passed"] is True
    assert result["alert_count"] == 1
    assert result["detection_result"]["deduplicated_alert_updates"] >= 1


def test_v311_detection_pipeline_validation_reports_explanation_completeness():
    report = validate_detection_pipeline(scenarios=["normal_allowed_traffic", "port_scan_like_traffic"])

    assert report["ok"] is True
    assert report["scenario_count"] == 2
    assert report["logs_parsed"] > 0
    assert report["expected_alerts"] == 1
    assert report["actual_alerts"] >= 1
    assert report["missed_expected_alerts"] == []
    assert report["response_actions_created"] == 0
    assert report["explanation_completeness_score"] >= 0.85
    port_scan = next(item for item in report["scenarios"] if item["scenario"] == "port_scan_like_traffic")
    assert port_scan["explanation_missing_fields"] == []


def test_v312_detection_pipeline_classifies_expected_and_unexpected_alerts():
    report = validate_detection_pipeline()

    assert report["ok"] is True
    assert report["expected_alerts"] == 15
    assert report["actual_alerts"] == 15
    assert report["unexpected_alerts"] == []
    assert all(item["unexpected_attack_types"] == [] for item in report["scenarios"])
    mixed = next(item for item in report["scenarios"] if item["scenario"] == "mixed_small_subnet_validation")
    assert mixed["expected_primary_attack_type"] == "port_scan"
    assert mixed["allowed_secondary_attack_types"] == ["brute_force", "malware_c2"]
    assert mixed["actual_alerts"] == 3
    policy = next(item for item in report["scenarios"] if item["scenario"] == "policy_violation_suspicious_app")
    assert policy["actual_alerts"] == 1
