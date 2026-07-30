from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from atdr.app.services import v515_runtime_soak_service
from atdr.app.services.v515_runtime_soak_service import (
    run_v515_runtime_soak_acceptance,
)


SCENARIO_PATH = (
    Path(__file__).resolve().parents[2]
    / "data"
    / "samples"
    / "scenarios"
    / "port_scan_like_traffic.txt"
)


def test_v515_refuses_configured_database_runtime_target() -> None:
    result = run_v515_runtime_soak_acceptance(
        sample_path=SCENARIO_PATH,
        target_rows=10,
        chunk_size=2,
    )

    assert result["ok"] is False
    assert result["status"] == "explicit_temp_database_required"
    assert result["configured_database_modified"] is False
    assert result["path_returned"] is False
    assert result["secrets_exposed"] is False


def test_v515_fails_closed_when_three_times_storage_gate_fails(
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        v515_runtime_soak_service.shutil,
        "disk_usage",
        lambda _path: SimpleNamespace(total=1_000, used=999, free=1),
    )

    result = run_v515_runtime_soak_acceptance(
        sample_path=SCENARIO_PATH,
        target_rows=10,
        chunk_size=2,
        use_temp_db=True,
    )

    assert result["ok"] is False
    assert result["status"] == "resource_preflight_failed"
    assert result["resource_preflight"]["disk"]["sufficient"] is False
    assert result["configured_database_modified"] is False


def test_v515_combined_recovery_preserves_exact_evidence_and_traceability() -> None:
    result = run_v515_runtime_soak_acceptance(
        sample_path=SCENARIO_PATH,
        target_rows=10,
        chunk_size=1,
        use_temp_db=True,
        fault_plan="combined",
        run_detection_after=True,
    )

    assert result["ok"] is True
    assert result["status"] == "long_duration_runtime_soak_passed"
    assert result["runtime_evidence"] == {
        "rows_selected": 10,
        "rows_processed": 10,
        "stage_count": 1,
        "logical_source_count": 1,
        "logical_sources_are_simulated": True,
        "physical_device_count_claimed": 0,
    }

    ingestion = result["ingestion"]
    assert ingestion["raw_logs"] == ingestion["normalized_logs"] == 10
    assert ingestion["parsed_successfully"] == 10
    assert ingestion["parse_failures"] == 0
    assert ingestion["total_worker_handoffs"] == 3
    assert ingestion["total_cancellations"] == 1
    assert ingestion["total_stale_lease_recoveries"] == 1
    assert all(ingestion["checks"].values())

    stage_import = result["stages"][0]["import"]
    assert stage_import["progress_monotonic"] is True
    assert stage_import["line_checkpoint_monotonic"] is True
    assert stage_import["byte_checkpoint_monotonic"] is True
    assert stage_import["staged_input_cleaned"] is True
    assert {
        transition["event"] for transition in stage_import["transitions"]
    } >= {
        "worker_handoff",
        "cancelled_at_boundary",
        "cancelled_job_resumed",
        "worker_process_lost",
        "stale_lease_failed_closed",
        "stale_job_explicitly_resumed",
        "completed",
    }

    integrity = result["database"]["integrity"]
    assert integrity["ok"] is True
    assert integrity["sqlite_integrity_check"] == "ok"
    assert integrity["foreign_key_violation_count"] == 0
    assert integrity["orphan_normalized_rows"] == 0
    assert integrity["raw_rows_without_normalized"] == 0
    assert integrity["raw_rows_without_source"] == 0
    assert integrity["orphan_alert_evidence_rows"] == 0

    detection = result["detection"]
    assert detection["executed"] is True
    assert detection["rule_detection_authoritative"] is True
    assert detection["ml_advisory_execution"] is False
    assert detection["supervised_lifecycle"] == "shadow_observation"
    assert detection["logs_evaluated"] == 10
    assert detection["alerts_with_source_traceability"] >= 1
    assert detection["alert_to_log_source_traceability"] is True
    assert detection["cases_reconcile_with_alert_groups"] is True
    assert detection["response_actions_created"] == 0
    assert all(
        stage["detection"]["alert_to_log_traceability"]
        for stage in result["stages"]
    )

    assert result["cleanup"]["complete"] is True
    assert result["privacy_findings"] == []
    assert result["safety"]["configured_database_unchanged"] is True
    assert result["safety"]["unsafe_side_effect_counts"] == {
        "response_actions": 0,
        "labels": 0,
        "model_runs": 0,
    }


def test_v515_repeated_evidence_is_preserved_without_checkpoint_replay(
    tmp_path: Path,
) -> None:
    first_line = SCENARIO_PATH.read_text(encoding="utf-8").splitlines()[0]
    private_path = tmp_path / "repeated-private-evidence.log"
    private_path.write_text(
        "\n".join([first_line] * 8) + "\n",
        encoding="utf-8",
    )

    result = run_v515_runtime_soak_acceptance(
        sample_path=private_path,
        target_rows=8,
        chunk_size=1,
        use_temp_db=True,
        fault_plan="combined",
    )

    assert result["ok"] is True
    assert result["ingestion"]["raw_logs"] == 8
    assert result["ingestion"]["normalized_logs"] == 8
    assert result["ingestion"]["exact_duplicates_observed_and_preserved"] == 7
    assert result["ingestion"]["checks"]["no_checkpoint_replay_rows"] is True


def test_v515_output_redacts_private_names_paths_ips_and_fingerprints(
    tmp_path: Path,
) -> None:
    private_path = tmp_path / "private-203.0.113.44-evidence.log"
    private_path.write_bytes(SCENARIO_PATH.read_bytes())

    result = run_v515_runtime_soak_acceptance(
        sample_path=private_path,
        target_rows=10,
        chunk_size=1,
        use_temp_db=True,
        fault_plan="combined",
        run_detection_after=True,
    )
    serialized = json.dumps(result, default=str)

    assert result["ok"] is True
    assert result["privacy_findings"] == []
    assert str(private_path) not in serialized
    assert private_path.name not in serialized
    assert "203.0.113.44" not in serialized
    assert "raw_line" not in serialized
    assert result["safety"]["fingerprints_returned"] is False
    assert result["safety"]["secrets_exposed"] is False


def test_v515_preflight_only_returns_safe_aggregate_resource_status() -> None:
    result = run_v515_runtime_soak_acceptance(
        sample_path=SCENARIO_PATH,
        target_rows=10,
        preflight_only=True,
    )

    assert result["ok"] is True
    assert result["status"] == "resource_preflight_complete"
    assert result["resource_preflight"]["available_rows"] == 10
    assert result["resource_preflight"]["selected_rows"] == 10
    assert result["resource_preflight"]["disk"]["headroom_multiplier"] == 3
    assert result["resource_preflight"]["private_evidence"]["parser_errors"] == 0
    assert result["privacy_findings"] == []


def test_v515_invalid_fault_plan_fails_without_processing() -> None:
    result = run_v515_runtime_soak_acceptance(
        sample_path=SCENARIO_PATH,
        target_rows=10,
        use_temp_db=True,
        fault_plan="not-a-plan",
    )

    assert result["ok"] is False
    assert result["status"] == "invalid_fault_plan"
    assert result["configured_database_modified"] is False
