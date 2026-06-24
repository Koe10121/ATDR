import argparse
import json
from typing import Any

from atdr.app.core.config import PROJECT_ROOT
from atdr.app.parsers.paloalto_parser import parse_log_line_for_profile
from atdr.scripts.run_source_scenario import SCENARIOS
from atdr.scripts.validate_detection_pipeline import validate_detection_pipeline


DEFAULT_QUALITY_SCENARIOS = [
    "normal_allowed_traffic",
    "normal_web_dns_quic_traffic",
    "benign_dns_web_traffic",
    "benign_incomplete_allow_noise",
    "benign_repeated_internal_service",
    "benign_high_volume_single_service",
    "normal_high_volume_but_allowed_traffic",
    "normal_repeated_same_service_traffic",
    "port_scan_like_traffic",
    "suspicious_horizontal_scan",
    "suspicious_denied_ssh_burst",
    "suspicious_rare_port_probe",
    "repeated_dedup_traffic",
    "malware_c2_like_beaconing",
    "malicious_like_c2_beacon",
    "data_exfiltration_suspicion",
    "malicious_like_exfiltration_burst",
    "brute_force_like_traffic",
    "ddos_or_connection_flood_like",
    "policy_violation_suspicious_app",
    "generic_syslog_mixed",
    "malformed_raw_fallback",
    "malformed_vendor_mixed_fields",
]


def _parser_quality_for_scenario(name: str) -> dict[str, Any]:
    spec = SCENARIOS[name]
    path = PROJECT_ROOT / "data" / "samples" / "scenarios" / spec.filename
    parser_warning_count = 0
    raw_fallback_count = 0
    parse_failures = 0
    parsed_successfully = 0
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        parsed = parse_log_line_for_profile(line, spec.default_parser_profile)
        parsed_json = parsed.parsed_json if isinstance(parsed.parsed_json, dict) else {}
        parser_warning_count += len(parsed_json.get("parser_warnings") or [])
        raw_fallback_count += 1 if parsed_json.get("raw_fallback") or spec.default_parser_profile == "raw_fallback" else 0
        if parsed.error:
            parse_failures += 1
        else:
            parsed_successfully += 1
    return {
        "parser_profile": spec.default_parser_profile,
        "parser_warning_count": parser_warning_count,
        "raw_fallback_count": raw_fallback_count,
        "parse_failures_observed": parse_failures,
        "parsed_successfully_observed": parsed_successfully,
    }


def _rule_level_qa(scenario: dict[str, Any], parser_quality: dict[str, Any], actual_alerts: int) -> dict[str, Any]:
    detection_sources = [str(item) for item in scenario.get("detection_sources", []) if item]
    matched_rule_names = [str(item) for item in scenario.get("matched_rule_names", []) if item]
    if actual_alerts > 0:
        if "rule" in detection_sources:
            source = "rule"
        elif "anomaly" in detection_sources:
            source = "anomaly"
        elif "supervised" in detection_sources:
            source = "supervised"
        elif "hybrid" in detection_sources:
            source = "hybrid"
        else:
            source = "alert_without_source"
    elif parser_quality["parser_warning_count"] or parser_quality["raw_fallback_count"] or parser_quality["parse_failures_observed"]:
        source = "parser_warning_only"
    else:
        source = "no_alert"
    return {
        "source": source,
        "detection_sources": detection_sources,
        "matched_rule_names": matched_rule_names,
        "parser_profile": parser_quality["parser_profile"],
    }


def _scenario_result(scenario: dict[str, Any]) -> dict[str, Any]:
    name = str(scenario.get("scenario") or "")
    parser_quality = _parser_quality_for_scenario(name)
    expected_alert = bool(scenario.get("expected_alert"))
    actual_alerts = int(scenario.get("actual_alerts") or 0)
    attack_types = [str(item) for item in scenario.get("attack_types", [])]
    no_high_critical = True
    if not expected_alert:
        no_high_critical = not bool(scenario.get("unexpected_alert"))
    return {
        "scenario": name,
        "passed": bool(scenario.get("passed"))
        and not scenario.get("missed_expected_alert")
        and not scenario.get("unexpected_alert")
        and int(scenario.get("response_actions_created") or 0) == 0,
        "expected_alerts": int(scenario.get("expected_alerts") or 0),
        "actual_alerts": actual_alerts,
        "attack_types": attack_types,
        "missing_expected_alert": bool(scenario.get("missed_expected_alert")),
        "unexpected_alert": bool(scenario.get("unexpected_alert")),
        "unexpected_attack_types": scenario.get("unexpected_attack_types") or [],
        "false_positive": not expected_alert and actual_alerts > 0,
        "false_negative": expected_alert and (bool(scenario.get("missed_expected_alert")) or actual_alerts == 0),
        "raw_logs_imported": int(scenario.get("logs_imported") or 0),
        "normalized_logs_created": int(scenario.get("logs_parsed") or 0),
        "parse_failures": int(scenario.get("parse_failures") or 0),
        "parser_warning_count": parser_quality["parser_warning_count"],
        "raw_fallback_count": parser_quality["raw_fallback_count"],
        "alerts_created": int(scenario.get("alerts_created") or 0),
        "alerts_deduplicated": int(scenario.get("alerts_deduplicated") or 0),
        "explanation_completeness_score": float(scenario.get("explanation_completeness_score") or 0.0),
        "explanation_missing_fields": scenario.get("explanation_missing_fields") or [],
        "response_actions_created": int(scenario.get("response_actions_created") or 0),
        "rule_level_qa": _rule_level_qa(scenario, parser_quality, actual_alerts),
        "quality_checks": {
            "normal_has_no_high_or_critical_alert": no_high_critical,
            "expected_alert_present": (actual_alerts > 0) if expected_alert else True,
            "raw_evidence_preserved": int(scenario.get("logs_imported") or 0) > 0,
            "explanation_complete": float(scenario.get("explanation_completeness_score") or 0.0) >= 0.875,
            "no_automatic_response": int(scenario.get("response_actions_created") or 0) == 0,
        },
    }


def validate_detection_quality(
    *,
    scenarios: list[str] | None = None,
    use_ml: bool = False,
) -> dict[str, Any]:
    selected = scenarios or DEFAULT_QUALITY_SCENARIOS
    pipeline = validate_detection_pipeline(scenarios=selected, use_ml=use_ml)
    scenario_results = [_scenario_result(item) for item in pipeline["scenarios"]]
    missing = [item["scenario"] for item in scenario_results if item["missing_expected_alert"]]
    unexpected = [item["scenario"] for item in scenario_results if item["unexpected_alert"]]
    false_positives = [item["scenario"] for item in scenario_results if item["false_positive"]]
    false_negatives = [item["scenario"] for item in scenario_results if item["false_negative"]]
    response_actions = sum(item["response_actions_created"] for item in scenario_results)
    report = {
        "ok": all(item["passed"] for item in scenario_results) and response_actions == 0 and not false_positives and not false_negatives,
        "read_only_current_db": True,
        "uses_temp_db": True,
        "validation_scope": "v3.18 controlled detection corpus and false-positive/false-negative QA",
        "use_ml": use_ml,
        "scenario_count": len(scenario_results),
        "passed_count": sum(1 for item in scenario_results if item["passed"]),
        "expected_alerts": sum(item["expected_alerts"] for item in scenario_results),
        "actual_alerts": sum(item["actual_alerts"] for item in scenario_results),
        "benign_no_alert_scenarios": sum(1 for item in scenario_results if item["expected_alerts"] == 0),
        "positive_alert_scenarios": sum(1 for item in scenario_results if item["expected_alerts"] > 0),
        "false_positive_scenario_count": len(false_positives),
        "false_positive_scenarios": false_positives,
        "false_negative_scenario_count": len(false_negatives),
        "false_negative_scenarios": false_negatives,
        "missing_expected_alerts": missing,
        "unexpected_alerts": unexpected,
        "unexpected_attack_type_count": sum(len(item["unexpected_attack_types"]) for item in scenario_results),
        "alerts_created": sum(item["alerts_created"] for item in scenario_results),
        "alerts_deduplicated": sum(item["alerts_deduplicated"] for item in scenario_results),
        "dedup_count": sum(item["alerts_deduplicated"] for item in scenario_results),
        "raw_logs_imported": sum(item["raw_logs_imported"] for item in scenario_results),
        "normalized_logs_created": sum(item["normalized_logs_created"] for item in scenario_results),
        "parse_failures": sum(item["parse_failures"] for item in scenario_results),
        "parser_warning_count": sum(item["parser_warning_count"] for item in scenario_results),
        "raw_fallback_count": sum(item["raw_fallback_count"] for item in scenario_results),
        "explanation_completeness_score": round(
            sum(item["explanation_completeness_score"] for item in scenario_results) / max(len(scenario_results), 1),
            4,
        ),
        "response_actions_created": response_actions,
        "no_automatic_response_confirmed": response_actions == 0,
        "scenarios": scenario_results,
        "safety": {
            "database_mode": "temporary in-memory SQLite",
            "current_database_mutated": False,
            "response_automation_enabled": False,
            "real_firewall_blocking_enabled": False,
            "ml_decision_support_only": True,
        },
    }
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate ATDR controlled detection quality with safe scenarios.")
    parser.add_argument("--scenario", action="append", help="Scenario to validate. Defaults to core quality scenarios.")
    parser.add_argument("--use-ml", action="store_true", help="Include assistive ML scoring when available.")
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()
    report = validate_detection_quality(scenarios=args.scenario, use_ml=args.use_ml)
    print(json.dumps(report, indent=2 if args.pretty else None, default=str))
    raise SystemExit(0 if report["ok"] else 1)


if __name__ == "__main__":
    main()
