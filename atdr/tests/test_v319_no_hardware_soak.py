from atdr.scripts.run_no_hardware_soak import run_no_hardware_soak


def test_no_hardware_soak_dry_run_does_not_mutate_db():
    result = run_no_hardware_soak(
        dry_run=True,
        iterations=1,
        source_count=3,
        scenario_mix=[
            "normal_allowed_traffic",
            "generic_syslog_mixed",
            "malformed_raw_fallback",
        ],
        run_detection_after=True,
    )

    assert result["ok"] is True
    assert result["dry_run"] is True
    assert result["current_database_mutated"] is False
    assert result["parser_drift"]["logs_attempted"] > 0
    assert result["parser_drift"]["parse_failures"] >= 1
    assert result["safety"]["response_actions_created"] == 0


def test_no_hardware_soak_temp_db_reports_parser_drift_and_source_health():
    result = run_no_hardware_soak(
        use_temp_db=True,
        iterations=1,
        source_count=3,
        scenario_mix=[
            "normal_allowed_traffic",
            "benign_incomplete_allow_noise",
            "generic_syslog_mixed",
            "malformed_raw_fallback",
            "malformed_vendor_mixed_fields",
            "suspicious_horizontal_scan",
        ],
        run_detection_after=True,
    )

    assert result["ok"] is True
    assert result["current_database_mutated"] is False
    assert result["import_summary"]["raw_logs_imported"] > 0
    assert result["import_summary"]["normalized_logs_created"] > 0
    assert result["parser_drift"]["parser_warning_count"] > 0
    assert result["parser_drift"]["raw_fallback_count"] >= 1
    assert result["parser_drift"]["missing_src_ip_count"] >= 1
    assert {source["parser_profile"] for source in result["source_health"]} >= {
        "palo_alto",
        "generic_syslog",
        "raw_fallback",
    }
    assert all(source["status_expected"] for source in result["source_health"])


def test_no_hardware_soak_detects_alerts_deduplicates_and_keeps_explanations_complete():
    result = run_no_hardware_soak(
        use_temp_db=True,
        iterations=2,
        source_count=3,
        scenario_mix=[
            "repeated_dedup_traffic",
            "suspicious_horizontal_scan",
            "malicious_like_c2_beacon",
        ],
        run_detection_after=True,
    )

    assert result["ok"] is True
    assert result["event_summary"]["false_positive_scenario_count"] == 0
    assert result["event_summary"]["false_negative_scenario_count"] == 0
    assert result["import_summary"]["alerts_created"] >= 3
    assert result["import_summary"]["alerts_deduplicated"] >= 1
    assert result["explanation_completeness"]["completeness_score"] == 1.0
    assert result["explanation_completeness"]["missing_field_count"] == 0


def test_no_hardware_soak_never_creates_response_actions_or_model_runs():
    result = run_no_hardware_soak(
        use_temp_db=True,
        iterations=1,
        source_count=3,
        scenario_mix=[
            "repeated_dedup_traffic",
            "suspicious_denied_ssh_burst",
            "malicious_like_c2_beacon",
        ],
        run_detection_after=True,
    )

    assert result["ok"] is True
    assert result["safety"]["response_actions_created"] == 0
    assert result["safety"]["automatic_response_enabled"] is False
    assert result["safety"]["real_firewall_blocking_enabled"] is False
    assert result["safety"]["ml_activated_or_promoted"] is False
    assert result["safety"]["ml_model_runs_created"] == 0
