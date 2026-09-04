import json
import re

from atdr.scripts.run_v557_analyst_workflow_acceptance import run_v557_analyst_workflow_acceptance


def test_v557_disposable_analyst_workflow_is_complete_and_safe():
    report = run_v557_analyst_workflow_acceptance()

    assert report["ok"] is True
    assert report["configured_database_accessed"] is False
    assert all(stage["passed"] is True for stage in report["stages"].values())
    assert report["stages"]["soc_assistant"]["response_modes"] == [
        "alert_explanation",
        "related_logs",
        "safe_next_step",
    ]
    assert all(
        delta == 0
        for delta in report["stages"]["soc_assistant"]["authoritative_row_deltas"].values()
    )
    assert report["stages"]["simulated_response"]["real_firewall_changed"] is False
    assert report["checks"]["failed"] == []
    assert report["safety"]["assistant_read_only"] is True
    assert report["safety"]["automatic_response_enabled"] is False
    assert report["safety"]["model_activated_or_promoted"] is False
    assert report["safety"]["production_readiness_claim"] is False


def test_v557_public_report_contains_no_paths_addresses_logs_or_secrets():
    encoded = json.dumps(run_v557_analyst_workflow_acceptance())

    assert re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", encoded) is None
    assert "raw_line" not in encoded
    assert "src_ip" not in encoded
    assert "dst_ip" not in encoded
    assert "api_key" not in encoded.lower()
    assert "C:\\" not in encoded
    assert "/Users/" not in encoded
