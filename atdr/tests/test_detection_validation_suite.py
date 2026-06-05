import shutil
from pathlib import Path

from atdr.app.core.config import PROJECT_ROOT
from atdr.scripts.run_detection_validation_suite import (
    run_detection_validation_scenario,
    run_detection_validation_suite,
)


def _output_dir(name: str) -> Path:
    path = PROJECT_ROOT / ".tmp" / "tests" / name
    shutil.rmtree(path, ignore_errors=True)
    path.mkdir(parents=True, exist_ok=True)
    return path


def test_detection_validation_suite_all_scenarios_passes_in_temp_db():
    result = run_detection_validation_suite(write_output=False)

    assert result["ok"] is True
    assert result["scenario_count"] == 14
    assert result["passed_count"] == 14
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


def test_validation_scenarios_cover_clean_and_malformed_inputs():
    normal = run_detection_validation_scenario(scenario="normal_allowed_traffic")
    malformed = run_detection_validation_scenario(scenario="malformed_raw_fallback")
    mixed = run_detection_validation_scenario(scenario="mixed_small_subnet_validation")
    negative = run_detection_validation_scenario(scenario="normal_repeated_same_service_traffic")

    assert normal["passed"] is True
    assert normal["alert_count"] == 0
    assert malformed["passed"] is True
    assert malformed["source"]["quality"]["raw_logs"] == 3
    assert malformed["source"]["parse_failure_count"] == 3
    assert mixed["passed"] is True
    assert {"port_scan", "brute_force", "malware_c2"}.issubset({alert["attack_type"] for alert in mixed["alerts"]})
    assert negative["passed"] is True
    assert negative["alert_count"] == 0


def test_repeated_dedup_validation_records_occurrence_update():
    result = run_detection_validation_scenario(scenario="repeated_dedup_traffic")

    assert result["passed"] is True
    checks = {item["name"]: item for item in result["checks"]}
    assert checks["dedup_min"]["passed"] is True
    assert result["alert_count"] == 1
    assert result["detection_result"]["deduplicated_alert_updates"] >= 1
