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
    assert result["scenario_count"] == 8
    assert result["passed_count"] == 8
    assert all(item["safety"]["response_actions_created"] == 0 for item in result["scenarios"])


def test_detection_validation_suite_writes_json_and_markdown_report():
    result = run_detection_validation_suite(
        scenarios=["port_scan_like_traffic", "malformed_raw_fallback"],
        output_dir=_output_dir("detection_validation_report"),
    )

    assert result["ok"] is True
    json_path = Path(result["paths"]["json"])
    markdown_path = Path(result["paths"]["markdown"])
    assert json_path.exists()
    assert markdown_path.exists()
    markdown = markdown_path.read_text(encoding="utf-8")
    assert "ATDR Controlled Threat Detection Validation" in markdown
    assert "controlled small-subnet" in markdown
    assert "Response mode: simulated and analyst-approved only" in markdown


def test_validation_scenarios_cover_clean_and_malformed_inputs():
    normal = run_detection_validation_scenario(scenario="normal_allowed_traffic")
    malformed = run_detection_validation_scenario(scenario="malformed_raw_fallback")

    assert normal["passed"] is True
    assert normal["alert_count"] == 0
    assert malformed["passed"] is True
    assert malformed["source"]["quality"]["raw_logs"] == 3
    assert malformed["source"]["parse_failure_count"] == 3
