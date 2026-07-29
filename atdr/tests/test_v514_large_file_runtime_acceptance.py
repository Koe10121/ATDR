from __future__ import annotations

import json
from pathlib import Path

from atdr.app.services.v514_large_file_runtime_service import (
    run_v514_large_file_runtime_acceptance,
)


SCENARIO_PATH = (
    Path(__file__).resolve().parents[2]
    / "data"
    / "samples"
    / "scenarios"
    / "port_scan_like_traffic.txt"
)


def test_v514_requires_disposable_database_for_runtime_processing() -> None:
    result = run_v514_large_file_runtime_acceptance(
        sample_path=SCENARIO_PATH,
        limit=10,
        chunk_size=3,
    )

    assert result["ok"] is False
    assert result["status"] == "explicit_temp_database_required"
    assert result["configured_database_modified"] is False
    assert result["path_returned"] is False
    assert result["secrets_exposed"] is False


def test_v514_resumes_with_source_traceability_and_no_unsafe_side_effects() -> None:
    result = run_v514_large_file_runtime_acceptance(
        sample_path=SCENARIO_PATH,
        limit=10,
        chunk_size=3,
        use_temp_db=True,
        simulate_interruption=True,
        resume=True,
        run_detection_after=True,
    )

    assert result["ok"] is True
    assert result["status"] == "large_file_runtime_acceptance_passed"
    assert result["runtime_evidence"]["rows_processed"] == 10
    assert result["runtime_evidence"]["logical_source_count"] == 2
    assert result["runtime_evidence"]["physical_device_count_claimed"] == 0
    assert result["runtime_evidence"]["logical_sources_are_simulated"] is True

    ingestion = result["ingestion"]
    assert ingestion["raw_logs"] == ingestion["normalized_logs"] == 10
    assert ingestion["parse_failures"] == 0
    assert ingestion["checks"]["progress_monotonic"] is True
    assert ingestion["checks"]["bounded_chunks"] is True
    assert ingestion["checks"]["idempotent_enqueue_reused_existing_job"] is True
    assert ingestion["checks"]["no_extra_rows_after_resume"] is True
    assert ingestion["imports"][0]["interruption_released_at_checkpoint"] is True
    assert ingestion["imports"][0]["staged_input_cleaned"] is True

    assert result["cancellation"]["ok"] is True
    assert result["cancellation"]["cancelled_at_committed_boundary"] is True
    assert result["cancellation"]["resume_eligible"] is True
    assert result["database_lock_handling"]["ok"] is True

    assert len(result["sources"]) == 2
    assert all(source["last_seen_recorded"] for source in result["sources"])
    assert all(source["ingestion_history_count"] == 1 for source in result["sources"])
    assert all(source["detection_history_count"] == 1 for source in result["sources"])

    detection = result["detection"]
    assert detection["executed"] is True
    assert detection["rule_detection_authoritative"] is True
    assert detection["ml_advisory_execution"] is False
    assert detection["logs_evaluated"] == 10
    assert detection["alerts_with_source_traceability"] >= 1
    assert detection["logical_sources_with_alert_evidence"] == 2
    assert detection["alert_to_log_traceability"] is True
    assert detection["response_actions_created"] == 0

    safety = result["safety"]
    assert safety["configured_database_targeted"] is False
    assert safety["configured_database_unchanged"] is True
    assert safety["model_activation_performed"] is False
    assert safety["model_promotion_performed"] is False
    assert safety["response_automation_allowed"] is False
    assert safety["real_firewall_blocking_enabled"] is False
    assert safety["unsafe_side_effect_counts"] == {
        "response_actions": 0,
        "labels": 0,
        "model_runs": 0,
    }


def test_v514_counts_repeated_evidence_without_resume_duplication(
    tmp_path: Path,
) -> None:
    first_line = SCENARIO_PATH.read_text(encoding="utf-8").splitlines()[0]
    repeated_path = tmp_path / "private-repeated-evidence.log"
    repeated_path.write_text(
        "\n".join([first_line] * 8) + "\n",
        encoding="utf-8",
    )

    result = run_v514_large_file_runtime_acceptance(
        sample_path=repeated_path,
        limit=8,
        chunk_size=2,
        use_temp_db=True,
        simulate_interruption=True,
        resume=True,
    )

    assert result["ok"] is True
    assert result["ingestion"]["raw_logs"] == 8
    assert result["ingestion"]["normalized_logs"] == 8
    assert result["ingestion"]["exact_duplicates_observed_and_preserved"] == 7
    assert result["ingestion"]["checks"]["no_extra_rows_after_resume"] is True
    assert "counted and preserved" in result["ingestion"]["duplicate_policy"]


def test_v514_output_redacts_private_path_raw_evidence_and_ips(
    tmp_path: Path,
) -> None:
    private_path = tmp_path / "private-campus-firewall-evidence.log"
    private_path.write_bytes(SCENARIO_PATH.read_bytes())

    result = run_v514_large_file_runtime_acceptance(
        sample_path=private_path,
        limit=10,
        chunk_size=3,
        use_temp_db=True,
        simulate_interruption=True,
        resume=True,
        run_detection_after=True,
    )
    serialized = json.dumps(result, default=str)

    assert result["ok"] is True
    assert result["privacy_findings"] == []
    assert str(private_path) not in serialized
    assert private_path.name not in serialized
    assert "203.0.113.44" not in serialized
    assert "raw_line" not in serialized
    assert result["safety"]["private_path_returned"] is False
    assert result["safety"]["raw_evidence_returned"] is False
    assert result["safety"]["private_identifiers_returned"] is False
    assert result["safety"]["fingerprints_returned"] is False
    assert result["safety"]["secrets_exposed"] is False


def test_v514_preflight_only_returns_aggregate_evidence() -> None:
    result = run_v514_large_file_runtime_acceptance(
        sample_path=SCENARIO_PATH,
        limit=10,
        chunk_size=3,
        preflight_only=True,
    )

    assert result["ok"] is True
    assert result["status"] == "preflight_complete"
    assert result["preflight"]["nonblank_lines"] == 10
    assert result["preflight"]["parser_errors"] == 0
    assert result["preflight"]["path_returned"] is False
    assert result["preflight"]["raw_evidence_returned"] is False
    assert result["privacy_findings"] == []
