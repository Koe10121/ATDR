import shutil
from pathlib import Path

from atdr.app.core.config import PROJECT_ROOT
from atdr.scripts.run_layered_detection_validation import run_layered_detection_validation


def _output_dir(name: str) -> Path:
    path = PROJECT_ROOT / ".tmp" / "tests" / name
    shutil.rmtree(path, ignore_errors=True)
    path.mkdir(parents=True, exist_ok=True)
    return path


def test_layered_detection_validation_compares_modes_safely():
    report = run_layered_detection_validation(
        scenarios=["port_scan_like_traffic", "normal_web_dns_quic_traffic"],
        variants=1,
        write_output=False,
        variant_output_dir=_output_dir("layered_variants"),
    )

    assert report["ok"] is True
    assert report["mode_run_count"] == 8
    assert report["false_positive_count"] == 0
    assert report["false_negative_count"] == 0
    assert all(item["safety"]["response_actions_created"] == 0 for item in report["results"])

    by_mode_scenario = {(item["mode"], item["scenario"]): item for item in report["results"]}
    assert by_mode_scenario[("rules_only", "port_scan_like_traffic")]["actual_attack_types"] == ["port_scan"]
    assert by_mode_scenario[("hybrid", "port_scan_like_traffic")]["actual_attack_types"] == ["port_scan"]
    assert by_mode_scenario[("rules_only", "normal_web_dns_quic_traffic")]["alerts_created"] == 0
    assert by_mode_scenario[("hybrid", "normal_web_dns_quic_traffic")]["alerts_created"] == 0
    assert by_mode_scenario[("anomaly_only", "port_scan_like_traffic")]["diagnostics"] is not None
    assert by_mode_scenario[("supervised_only", "port_scan_like_traffic")]["diagnostics"]["decision_support_only"] is True


def test_layered_detection_validation_writes_reports():
    output_dir = _output_dir("layered_reports")
    report = run_layered_detection_validation(
        scenarios=["port_scan_like_traffic"],
        variants=1,
        output_dir=output_dir,
        variant_output_dir=_output_dir("layered_report_variants"),
    )

    assert report["ok"] is True
    assert Path(report["paths"]["json"]).exists()
    markdown_path = Path(report["paths"]["markdown"])
    assert markdown_path.exists()
    markdown = markdown_path.read_text(encoding="utf-8")
    assert "ATDR Layered Detection Validation" in markdown
    assert "Rules are the primary source" in markdown
    assert "Response actions remain simulated" in markdown
