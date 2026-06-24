import argparse
import json
from datetime import datetime
from typing import Any

from atdr.scripts.run_detection_validation_suite import SCENARIOS, run_detection_validation_suite


def _json_default(value: Any) -> str:
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def _expected_alert(scenario: dict[str, Any]) -> bool:
    return bool((scenario.get("expected") or {}).get("expected_alert_present"))


def _expected_alert_count(scenario: dict[str, Any]) -> int:
    expected = scenario.get("expected") or {}
    if not _expected_alert(scenario):
        return 0
    if expected.get("expected_alert_count_min") is not None:
        return int(expected["expected_alert_count_min"])
    expected_types = expected.get("expected_attack_types") or []
    if expected_types:
        return len(expected_types)
    return 1


def _allowed_attack_types(expected: dict[str, Any]) -> set[str]:
    values = {str(item) for item in expected.get("expected_attack_types", []) if item}
    if expected.get("expected_attack_type"):
        values.add(str(expected["expected_attack_type"]))
    if expected.get("expected_primary_attack_type"):
        values.add(str(expected["expected_primary_attack_type"]))
    values.update(str(item) for item in expected.get("allowed_secondary_attack_types", []) if item)
    return values


def _unexpected_alert(scenario: dict[str, Any]) -> bool:
    expected = scenario.get("expected") or {}
    actual_attack_types = {
        str((alert.get("detection_summary") or {}).get("attack_type") or alert.get("attack_type") or "")
        for alert in scenario.get("alerts", [])
    }
    actual_attack_types.discard("")
    allowed_attack_types = _allowed_attack_types(expected)
    noisy_types = actual_attack_types - allowed_attack_types if allowed_attack_types else set()
    if _expected_alert(scenario):
        max_count = expected.get("expected_alert_count_max")
        too_many = max_count is not None and int(scenario.get("alert_count") or 0) > int(max_count)
        return too_many or bool(noisy_types)
    severe_failure = any(
        check.get("name") == "no_high_or_critical_alerts" and not check.get("passed")
        for check in scenario.get("checks", [])
    )
    max_count = expected.get("expected_alert_count_max")
    too_many = max_count is not None and int(scenario.get("alert_count") or 0) > int(max_count)
    return severe_failure or too_many


def _scenario_summary(scenario: dict[str, Any]) -> dict[str, Any]:
    alerts = scenario.get("alerts") or []
    expected = scenario.get("expected") or {}
    completeness_scores = [
        float((alert.get("explanation_completeness") or {}).get("score") or 0.0)
        for alert in alerts
    ]
    completeness_missing = {
        str(item)
        for alert in alerts
        for item in ((alert.get("explanation_completeness") or {}).get("missing") or [])
    }
    import_result = scenario.get("import_result") or {}
    detection_result = scenario.get("detection_result") or {}
    missed_expected = _expected_alert(scenario) and not alerts
    unexpected = _unexpected_alert(scenario)
    attack_types = sorted({str(alert.get("attack_type") or "-") for alert in alerts}) if alerts else []
    allowed_attack_types = _allowed_attack_types(expected)
    unexpected_attack_types = sorted(set(attack_types) - allowed_attack_types) if allowed_attack_types else []
    detection_sources = sorted(
        {
            str(source)
            for alert in alerts
            for source in (alert.get("detection_source") or [])
            if source
        }
    )
    matched_rule_names = sorted(
        {
            str(rule)
            for alert in alerts
            for rule in (alert.get("matched_rule_names") or [])
            if rule
        }
    )
    return {
        "scenario": scenario.get("scenario"),
        "passed": bool(scenario.get("passed")),
        "expected_alert": _expected_alert(scenario),
        "expected_primary_attack_type": expected.get("expected_primary_attack_type") or expected.get("expected_attack_type"),
        "allowed_secondary_attack_types": list(expected.get("allowed_secondary_attack_types", [])),
        "logs_attempted": int(import_result.get("available_lines") or import_result.get("requested_limit") or import_result.get("imported") or 0),
        "logs_imported": int(import_result.get("raw_logs_imported") or import_result.get("imported") or 0),
        "logs_parsed": int(import_result.get("parsed_successfully") or import_result.get("parsed") or 0),
        "parse_failures": int(import_result.get("parse_failures") or import_result.get("failed") or 0),
        "expected_alerts": _expected_alert_count(scenario),
        "expected_alert_count_min": expected.get("expected_alert_count_min"),
        "expected_alert_count_max": expected.get("expected_alert_count_max"),
        "actual_alerts": int(scenario.get("alert_count") or 0),
        "missed_expected_alert": missed_expected,
        "unexpected_alert": unexpected,
        "unexpected_attack_types": unexpected_attack_types,
        "alerts_created": int(detection_result.get("created_alerts") or 0),
        "alerts_deduplicated": int(detection_result.get("deduplicated_alert_updates") or 0),
        "dedup_behavior_observed": int(detection_result.get("deduplicated_alert_updates") or 0) > 0,
        "explanation_completeness_score": round(
            sum(completeness_scores) / len(completeness_scores),
            4,
        )
        if completeness_scores
        else 1.0,
        "explanation_missing_fields": sorted(completeness_missing),
        "response_actions_created": int((scenario.get("safety") or {}).get("response_actions_created") or 0),
        "attack_types": attack_types,
        "detection_sources": detection_sources,
        "matched_rule_names": matched_rule_names,
        "rule_level_qa": {
            "source": "rule" if "rule" in detection_sources else "no_alert",
            "detection_sources": detection_sources,
            "matched_rule_names": matched_rule_names,
        },
    }


def validate_detection_pipeline(
    *,
    scenarios: list[str] | None = None,
    use_ml: bool = False,
) -> dict[str, Any]:
    suite = run_detection_validation_suite(
        scenarios=scenarios,
        use_temp_db=True,
        use_ml=use_ml,
        write_output=False,
    )
    summaries = [_scenario_summary(item) for item in suite["scenarios"]]
    total_alerts = sum(item["actual_alerts"] for item in summaries)
    completeness_scores = [item["explanation_completeness_score"] for item in summaries if item["actual_alerts"]]
    missed = [item["scenario"] for item in summaries if item["missed_expected_alert"]]
    unexpected = [item["scenario"] for item in summaries if item["unexpected_alert"]]
    response_actions = sum(item["response_actions_created"] for item in summaries)
    report = {
        "ok": bool(suite["ok"]) and not missed and not unexpected and response_actions == 0,
        "generated_at": suite["generated_at"],
        "validation_scope": "v3.18 parser, detection, deduplication, FP/FN, alert-quality, and explanation completeness validation",
        "use_temp_db": True,
        "use_ml": use_ml,
        "scenario_count": len(summaries),
        "passed_count": sum(1 for item in summaries if item["passed"]),
        "logs_attempted": sum(item["logs_attempted"] for item in summaries),
        "logs_parsed": sum(item["logs_parsed"] for item in summaries),
        "parse_failures": sum(item["parse_failures"] for item in summaries),
        "expected_alerts": sum(item["expected_alerts"] for item in summaries),
        "actual_alerts": total_alerts,
        "missed_expected_alerts": missed,
        "unexpected_alerts": unexpected,
        "alerts_deduplicated": sum(item["alerts_deduplicated"] for item in summaries),
        "explanation_completeness_score": round(sum(completeness_scores) / len(completeness_scores), 4)
        if completeness_scores
        else 1.0,
        "response_actions_created": response_actions,
        "safety": suite["safety"],
        "scenarios": summaries,
    }
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate ATDR parser, detection, and explanation pipeline with safe scenarios.")
    parser.add_argument("--scenario", action="append", choices=sorted(SCENARIOS), help="Scenario to validate. Repeat for multiple.")
    parser.add_argument("--use-ml", action="store_true", help="Include assistive ML scoring when available.")
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()

    report = validate_detection_pipeline(scenarios=args.scenario, use_ml=args.use_ml)
    print(json.dumps(report, default=_json_default, indent=2 if args.pretty else None))
    raise SystemExit(0 if report["ok"] else 1)


if __name__ == "__main__":
    main()
