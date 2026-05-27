from atdr.scripts.run_source_scenario import SCENARIOS, run_source_scenario


def test_source_scenario_samples_parse_in_dry_run():
    for scenario in SCENARIOS:
        result = run_source_scenario(scenario=scenario, dry_run=True)

        assert result["ok"] is True
        assert result["dry_run"] is True
        assert result["read"] == result["available_lines"]


def test_normal_allowed_scenario_does_not_create_high_critical_alerts():
    result = run_source_scenario(
        scenario="normal_allowed_traffic",
        use_temp_db=True,
        run_detection_after=True,
    )

    assert result["ok"] is True
    checks = {item["name"]: item for item in result["expected_outcome"]["checks"]}
    assert checks["no_high_or_critical_alerts"]["passed"] is True
    assert result["expected_outcome"]["source_counts"]["alerts"] == 0


def test_port_scan_scenario_creates_source_scoped_alert():
    result = run_source_scenario(
        scenario="port_scan_like_traffic",
        use_temp_db=True,
        run_detection_after=True,
    )

    assert result["ok"] is True
    assert result["detection_results"][0]["source_id"] == result["source_after"]["source_id"]
    assert result["expected_outcome"]["source_counts"]["alerts"] >= 1
    assert any(alert["alert_type"] == "possible_port_scan" for alert in result["expected_outcome"]["alert_summaries"])


def test_repeated_dedup_scenario_updates_occurrence_count():
    result = run_source_scenario(
        scenario="repeated_dedup_traffic",
        use_temp_db=True,
        run_detection_after=True,
    )

    assert result["ok"] is True
    checks = {item["name"]: item for item in result["expected_outcome"]["checks"]}
    assert checks["alert_deduplicated"]["passed"] is True
    assert checks["dedup_count_recorded"]["passed"] is True
    assert result["expected_outcome"]["alert_summaries"][0]["occurrence_count"] >= 2


def test_generic_and_raw_fallback_scenarios_preserve_evidence():
    generic = run_source_scenario(scenario="generic_syslog_mixed", use_temp_db=True)
    fallback = run_source_scenario(scenario="malformed_raw_fallback", use_temp_db=True)

    assert generic["ok"] is True
    assert generic["source_after"]["health"]["status"] == "warning"
    assert generic["expected_outcome"]["source_counts"]["raw_logs"] == 3
    assert fallback["ok"] is True
    assert fallback["source_after"]["health"]["status"] == "error"
    assert fallback["source_after"]["parse_failure_count"] == 3
    assert fallback["expected_outcome"]["source_counts"]["raw_logs"] == 3


def test_source_scenario_disable_preserves_existing_rows():
    result = run_source_scenario(
        scenario="malformed_raw_fallback",
        use_temp_db=True,
        disable_source_after=True,
    )

    assert result["ok"] is True
    assert result["source_after"]["health"]["status"] == "disabled"
    assert result["disabled_source_check"]["data_preserved"] is True
    assert result["disabled_source_check"]["raw_logs_after_disable"] == 3
