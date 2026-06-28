import argparse
import ast
import json
import re
from pathlib import Path
from typing import Any

from atdr.app.core.config import PROJECT_ROOT
from atdr.app.detection.attack_mapping import ATTACK_TYPE_MAPPINGS
from atdr.scripts.run_source_scenario import SCENARIOS, SCENARIO_DIR


RULES_PATH = PROJECT_ROOT / "atdr" / "app" / "detection" / "rules.py"
RULE_CONTRACT_PATH = PROJECT_ROOT / "docs" / "detection" / "ATDR_RULE_PACK_CONTRACT.md"
SCENARIO_CONTRACT_PATH = PROJECT_ROOT / "docs" / "detection" / "ATDR_SCENARIO_CORPUS_CONTRACT.md"
EXPECTATIONS_PATH = SCENARIO_DIR / "scenario_expectations.json"

REQUIRED_EXPECTATION_FIELDS = {
    "expected_alert_present",
    "expected_min_severity",
    "expected_parser_success_min",
    "expected_parse_failures_min",
    "expected_raw_preserved",
    "expected_no_response_actions",
    "expected_evidence_keywords",
}
ALLOWED_PARSER_PROFILES = {"palo_alto", "generic_syslog", "raw_fallback"}


def implemented_rule_codes(path: Path = RULES_PATH) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    codes: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func_name = getattr(node.func, "id", None) or getattr(node.func, "attr", None)
        if func_name != "RuleMatch":
            continue
        for keyword in node.keywords:
            if keyword.arg == "code" and isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, str):
                codes.add(keyword.value.value)
    return codes


def documented_backtick_tokens(path: Path) -> set[str]:
    text = path.read_text(encoding="utf-8")
    return {match.strip() for match in re.findall(r"`([^`]+)`", text)}


def _load_expectations(path: Path = EXPECTATIONS_PATH) -> dict[str, dict[str, Any]]:
    return json.loads(path.read_text(encoding="utf-8"))


def _expected_attack_types(expectation: dict[str, Any]) -> set[str]:
    values = set()
    for key in ("expected_attack_type", "expected_primary_attack_type"):
        value = expectation.get(key)
        if value:
            values.add(str(value))
    values.update(str(item) for item in expectation.get("expected_attack_types") or [])
    values.update(str(item) for item in expectation.get("allowed_secondary_attack_types") or [])
    return values


def validate_rule_pack_contract() -> dict[str, Any]:
    issues: list[str] = []
    implemented_rules = implemented_rule_codes()
    documented_rules = documented_backtick_tokens(RULE_CONTRACT_PATH)
    missing_rule_docs = sorted(implemented_rules - documented_rules)
    if missing_rule_docs:
        issues.append(f"Rule contract is missing implemented rule ids: {', '.join(missing_rule_docs)}")

    expectations = _load_expectations()
    scenario_names = set(SCENARIOS)
    expectation_names = set(expectations)
    missing_expectations = sorted(scenario_names - expectation_names)
    orphan_expectations = sorted(expectation_names - scenario_names)
    if missing_expectations:
        issues.append(f"Scenario expectations missing registered scenarios: {', '.join(missing_expectations)}")
    if orphan_expectations:
        issues.append(f"Scenario expectations include unregistered scenarios: {', '.join(orphan_expectations)}")

    documented_scenarios = documented_backtick_tokens(SCENARIO_CONTRACT_PATH)
    missing_scenario_docs = sorted(scenario_names - documented_scenarios)
    if missing_scenario_docs:
        issues.append(f"Scenario contract is missing registered scenarios: {', '.join(missing_scenario_docs)}")

    known_attack_types = set(ATTACK_TYPE_MAPPINGS)
    for name, spec in sorted(SCENARIOS.items()):
        sample_path = SCENARIO_DIR / spec.filename
        expectation = expectations.get(name) or {}
        if not sample_path.exists():
            issues.append(f"{name}: sample file does not exist: {spec.filename}")
        if spec.default_parser_profile not in ALLOWED_PARSER_PROFILES:
            issues.append(f"{name}: unsupported parser profile {spec.default_parser_profile}")
        missing_fields = sorted(REQUIRED_EXPECTATION_FIELDS - set(expectation))
        if missing_fields:
            issues.append(f"{name}: missing required expectation fields: {', '.join(missing_fields)}")
        if "expected_attack_type" not in expectation and "expected_primary_attack_type" not in expectation:
            issues.append(f"{name}: expected_attack_type or expected_primary_attack_type is required")
        if expectation.get("expected_raw_preserved") is not True:
            issues.append(f"{name}: expected_raw_preserved must be true")
        if expectation.get("expected_no_response_actions") is not True:
            issues.append(f"{name}: expected_no_response_actions must be true")
        unknown_attack_types = sorted(_expected_attack_types(expectation) - known_attack_types)
        if unknown_attack_types:
            issues.append(f"{name}: unknown attack type(s): {', '.join(unknown_attack_types)}")
        expected_alert = bool(expectation.get("expected_alert_present"))
        if expected_alert:
            for key in ("expected_alert_count_min", "expected_alert_count_max", "expected_min_risk_score", "expected_max_risk_score"):
                if key not in expectation:
                    issues.append(f"{name}: alert-positive scenario missing {key}")
        else:
            if "expected_alert_count_max" not in expectation:
                issues.append(f"{name}: no-alert scenario missing expected_alert_count_max")
            if float(expectation.get("expected_alert_count_max") or 0) > 0:
                issues.append(f"{name}: no-alert scenario must keep expected_alert_count_max at 0")

    return {
        "ok": not issues,
        "implemented_rule_count": len(implemented_rules),
        "documented_rule_count": len(implemented_rules & documented_rules),
        "scenario_count": len(scenario_names),
        "documented_scenario_count": len(scenario_names & documented_scenarios),
        "expectation_count": len(expectation_names),
        "safety": {
            "mutates_database": False,
            "creates_response_actions": False,
            "activates_models": False,
            "enables_real_firewall_blocking": False,
        },
        "issues": issues,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate ATDR rule-pack and scenario-corpus contracts.")
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()
    report = validate_rule_pack_contract()
    print(json.dumps(report, indent=2 if args.pretty else None, default=str))
    raise SystemExit(0 if report["ok"] else 1)


if __name__ == "__main__":
    main()
