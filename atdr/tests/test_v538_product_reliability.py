from __future__ import annotations

import json
from pathlib import Path
import subprocess

import pytest

from atdr.app.services.v538_product_reliability_service import (
    run_v538_product_reliability_acceptance,
)


@pytest.fixture(scope="module")
def full_acceptance(tmp_path_factory: pytest.TempPathFactory) -> dict:
    parent = tmp_path_factory.mktemp("v538")
    report = run_v538_product_reliability_acceptance(
        use_temp_db=True,
        log_count=64,
        temp_parent=parent,
        output_dir=parent / "reports",
        write_reports=True,
    )
    report["_test_output_dir"] = parent / "reports"
    return report


def test_v538_refuses_configured_database_target() -> None:
    report = run_v538_product_reliability_acceptance(
        use_temp_db=False,
        write_reports=False,
    )

    assert report["ok"] is False
    assert report["status"] == "explicit_temp_database_required"
    assert report["configured_database_modified"] is False
    assert report["real_response_actions"] == 0
    assert report["secrets_exposed"] is False


def test_v538_source_backed_preflight_covers_startup_access_and_ui() -> None:
    report = run_v538_product_reliability_acceptance(
        use_temp_db=True,
        preflight_only=True,
        write_reports=False,
    )

    assert report["ok"] is True
    assert report["status"] == "v5_38_preflight_passed"
    assert report["execution_required"] is True
    assert all(report["contracts"]["startup"].values())
    assert all(report["contracts"]["access"].values())
    assert all(report["contracts"]["ui"].values())


def test_v538_full_workflow_passes_all_gates(full_acceptance: dict) -> None:
    assert full_acceptance["ok"] is True
    assert full_acceptance["status"] == "v5_38_product_reliability_passed"
    assert full_acceptance["passed_gate_count"] == full_acceptance["gate_count"] == 11
    assert all(full_acceptance["gates"].values())
    assert full_acceptance["configured_database_unchanged"] is True
    assert full_acceptance["configured_database_modified"] is False
    assert full_acceptance["temporary_artifacts_removed"] is True


def test_v538_ingestion_detection_and_explanation_are_consistent(full_acceptance: dict) -> None:
    workflow = full_acceptance["workflow"]

    assert workflow["logs_attempted"] == 64
    assert workflow["raw_logs_imported"] == 64
    assert workflow["normalized_logs_created"] == 64
    assert workflow["parse_failures_tracked"] == 3
    assert workflow["duplicates_tracked"] >= 1
    assert workflow["source_links_complete"] is True
    assert workflow["evidence_preserved"] is True
    assert workflow["alert_type"] == "possible_port_scan"
    assert workflow["alerts_created"] == 1
    assert workflow["alerts_deduplicated"] == 1
    assert workflow["occurrence_count"] == workflow["related_log_count"] == 20
    assert workflow["source_traceable"] is True
    assert workflow["case_available"] is True
    assert workflow["why_flagged_available"] is True


def test_v538_failure_modes_and_assistant_fail_closed(full_acceptance: dict) -> None:
    assert all(full_acceptance["failure_modes"].values())
    assert full_acceptance["workflow"]["assistant_context_preserved"] is True
    assert full_acceptance["workflow"]["assistant_citation_grounded"] is True
    assert full_acceptance["workflow"]["assistant_provider_fallback_safe"] is True


def test_v538_response_stays_simulated_and_audited(full_acceptance: dict) -> None:
    safety = full_acceptance["response_safety"]

    assert safety["missing_justification_denied"] is True
    assert safety["protected_target_denied"] is True
    assert safety["approved_action_simulated"] is True
    assert safety["simulated_unblock_recorded"] is True
    assert safety["audit_events_recorded"] is True
    assert safety["real_response_actions"] == 0
    assert full_acceptance["model_activation_performed"] is False
    assert full_acceptance["model_promotion_performed"] is False
    assert full_acceptance["response_automation_allowed"] is False
    assert full_acceptance["real_firewall_blocking_enabled"] is False


def test_v538_report_is_redacted_and_writes_only_named_artifacts(full_acceptance: dict) -> None:
    output_dir = full_acceptance["_test_output_dir"]
    public_report = {
        key: value for key, value in full_acceptance.items() if not key.startswith("_test_")
    }
    rendered = json.dumps(public_report, default=str)

    assert str(Path.home()) not in rendered
    assert "198.51.100.77" not in rendered
    assert "10.0.0.77" not in rendered
    assert "raw_line" not in rendered.lower()
    assert public_report["raw_evidence_returned"] is False
    assert public_report["private_paths_returned"] is False
    assert public_report["secrets_exposed"] is False
    assert sorted(path.name for path in output_dir.iterdir()) == sorted(public_report["artifacts"])
    latest = json.loads((output_dir / "v5_38_product_reliability_latest.json").read_text(encoding="utf-8"))
    assert latest["ok"] is True
    assert latest["artifacts"] == public_report["artifacts"]


def test_stale_pid_helper_requires_matching_process_start_time() -> None:
    root = Path(__file__).resolve().parents[2]
    common = root / "scripts" / "system_common.ps1"
    command = (
        f". '{common}'; "
        "$stale = [pscustomobject]@{ pid = $PID; started_at = '2000-01-01T00:00:00Z' }; "
        "if (Test-TrackedProcessRecordActive $stale) { exit 11 }; "
        "$process = Get-Process -Id $PID; "
        "$current = [pscustomobject]@{ pid = $PID; started_at = $process.StartTime.ToUniversalTime().ToString('o') }; "
        "if (-not (Test-TrackedProcessRecordActive $current)) { exit 12 }; exit 0"
    )
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command],
        cwd=root,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 0, result.stderr
