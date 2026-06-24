from atdr.app.parsers.paloalto_parser import parse_log_line_for_profile
from atdr.scripts.validate_detection_quality import validate_detection_quality
from atdr.scripts.validate_parser_normalization import validate_parser_normalization


def test_parser_normalization_report_uses_safe_samples_without_db_mutation():
    report = validate_parser_normalization(["normal_allowed_traffic", "generic_syslog_mixed", "malformed_raw_fallback"])

    assert report["ok"] is True
    assert report["read_only"] is True
    assert report["database_mutated"] is False
    assert report["total_sample_lines_checked"] >= 1
    assert report["parsed_successfully"] >= 1
    assert report["raw_fallback_count"] >= 1
    assert report["parse_failures"] >= 1
    assert report["safety"]["response_actions_created"] == 0
    assert "palo_alto" in report["parser_profiles_used"]
    assert "generic_syslog" in report["parser_profiles_used"]
    assert "raw_fallback" in report["parser_profiles_used"]


def test_malformed_and_raw_fallback_parser_profiles_preserve_evidence():
    generic = parse_log_line_for_profile("2026-01-01T00:00:00Z lab-router mixed syslog message", "generic_syslog")
    raw = parse_log_line_for_profile("not a structured firewall line", "raw_fallback")

    assert generic.error is None
    assert generic.parsed_json["parser_profile"] == "generic_syslog"
    assert "message" in generic.parsed_json
    assert raw.error == "raw fallback parser profile"
    assert raw.parsed_json["raw_fallback"] is True
    assert raw.raw_line == "not a structured firewall line"


def test_detection_quality_report_validates_core_scenarios_without_response_actions():
    report = validate_detection_quality(
        scenarios=[
            "normal_allowed_traffic",
            "port_scan_like_traffic",
            "repeated_dedup_traffic",
            "generic_syslog_mixed",
            "malformed_raw_fallback",
        ]
    )

    assert report["ok"] is True
    assert report["uses_temp_db"] is True
    assert report["read_only_current_db"] is True
    assert report["actual_alerts"] >= 2
    assert report["alerts_deduplicated"] >= 1
    assert report["response_actions_created"] == 0
    assert report["no_automatic_response_confirmed"] is True
    assert report["safety"]["real_firewall_blocking_enabled"] is False
    assert report["explanation_completeness_score"] >= 0.875

