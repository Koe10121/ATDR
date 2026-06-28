from atdr.scripts.validate_rule_pack_contract import implemented_rule_codes, validate_rule_pack_contract


def test_implemented_rule_codes_are_discoverable():
    codes = implemented_rule_codes()

    assert "possible_port_scan" in codes
    assert "brute_force_like_attempts" in codes
    assert "ml_anomaly_detected" in codes


def test_rule_pack_and_scenario_contracts_are_source_aligned():
    report = validate_rule_pack_contract()

    assert report["ok"] is True, report["issues"]
    assert report["implemented_rule_count"] == report["documented_rule_count"]
    assert report["scenario_count"] == report["documented_scenario_count"]
    assert report["scenario_count"] == report["expectation_count"]
    assert report["safety"]["mutates_database"] is False
    assert report["safety"]["creates_response_actions"] is False
    assert report["safety"]["activates_models"] is False
    assert report["safety"]["enables_real_firewall_blocking"] is False
