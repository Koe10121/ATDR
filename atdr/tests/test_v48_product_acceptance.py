from __future__ import annotations

import json
from pathlib import Path
import shutil
from uuid import uuid4

import pytest

from atdr.scripts.run_v48_product_acceptance import run_v48_product_acceptance


@pytest.fixture(scope="module")
def full_acceptance() -> dict:
    parent = Path(".tmp") / f"pytest-v48-{uuid4().hex[:12]}"
    parent.mkdir(parents=True, exist_ok=False)
    try:
        yield run_v48_product_acceptance(
            use_temp_db=True,
            log_count=64,
            simulate_interruption=True,
            run_detection_enabled=True,
            test_assistant=True,
            test_backup_restore=True,
            temp_parent=parent,
        )
    finally:
        shutil.rmtree(parent, ignore_errors=True)


def test_v48_refuses_configured_database_target() -> None:
    result = run_v48_product_acceptance(use_temp_db=False, log_count=64)

    assert result["ok"] is False
    assert result["status"] == "explicit_temp_database_required"
    assert result["current_database_modified"] is False
    assert result["production_ready"] is False
    assert result["secrets_exposed"] is False


def test_v48_validates_input_contract() -> None:
    too_small = run_v48_product_acceptance(use_temp_db=True, log_count=39)
    assistant_without_detection = run_v48_product_acceptance(
        use_temp_db=True,
        log_count=64,
        test_assistant=True,
    )

    assert too_small["status"] == "invalid_log_count"
    assert assistant_without_detection["status"] == "assistant_requires_detection"
    assert too_small["current_database_modified"] is False
    assert assistant_without_detection["current_database_modified"] is False


def test_v48_full_acceptance_uses_migrated_disposable_database(full_acceptance: dict) -> None:
    assert full_acceptance["ok"] is True
    assert full_acceptance["status"] == "v48_product_acceptance_passed"
    assert full_acceptance["scope"] == "synthetic_disposable_sqlite_only"
    assert full_acceptance["migration"]["at_head"] is True
    assert full_acceptance["current_database_unchanged"] is True
    assert full_acceptance["current_database_modified"] is False
    assert full_acceptance["temp_artifacts_removed"] is True


def test_v48_ingestion_resume_and_failure_recovery_are_exact(full_acceptance: dict) -> None:
    ingestion = full_acceptance["ingestion"]
    recovery = full_acceptance["recovery"]

    assert ingestion["attempted"] == 64
    assert ingestion["raw_logs_imported"] == 64
    assert ingestion["normalized_logs_created"] == 64
    assert ingestion["parse_failures"] == 3
    assert ingestion["duplicate_raw_logs"] >= 10
    assert ingestion["missing_source_links"] == 0
    assert ingestion["empty_raw_evidence"] == 0
    assert recovery["bulk_graceful_interruption"]["resume_completed"] is True
    assert recovery["bulk_graceful_interruption"]["progress_monotonic"] is True
    assert recovery["cancellation_resume"]["ok"] is True
    assert recovery["cancellation_resume"]["resume_status"] == "completed"
    assert recovery["stale_lease"]["ok"] is True
    assert recovery["stale_lease"]["unsafe_retry_performed"] is False


def test_v48_detection_dedup_and_investigation_are_source_scoped(full_acceptance: dict) -> None:
    detection = full_acceptance["detection"]
    investigation = full_acceptance["investigation"]

    assert detection["first_run"]["created_alerts"] == 1
    assert detection["second_run"]["deduplicated_alert_updates"] == 1
    assert detection["source_scoped_alert_count"] == 1
    assert detection["alert_type"] == "possible_port_scan"
    assert detection["occurrence_count"] == 20
    assert detection["related_log_count"] == 20
    assert investigation["source_traceable"] is True
    assert "port_scan" in investigation["case_attack_types"]
    assert investigation["case_related_logs"] == 20
    assert investigation["why_flagged_available"] is True
    assert investigation["decision_support_only"] is True


def test_v48_assistant_is_grounded_read_only_and_fails_safe(full_acceptance: dict) -> None:
    assistant = full_acceptance["assistant"]

    assert assistant["ok"] is True
    assert assistant["conversation_context_preserved"] is True
    assert assistant["citation_references_alert"] is True
    assert assistant["provider_failure_fallback"] is True
    assert assistant["raw_log_context_included"] is False
    assert assistant["redaction_applied"] is True
    assert assistant["mutating_counts_unchanged"] is True
    assert assistant["response_actions_created"] == 0
    assert assistant["secrets_exposed"] is False


def test_v48_backup_restore_and_observability_are_safe(full_acceptance: dict) -> None:
    backup = full_acceptance["backup_restore"]
    observability = full_acceptance["observability"]

    assert backup["ok"] is True
    assert backup["checksum_valid"] is True
    assert backup["active_database_target_refused"] is True
    assert backup["row_counts_match"] is True
    assert backup["migration_revision_match"] is True
    assert backup["current_database_modified"] is False
    assert observability["ok"] is True
    assert observability["raw_evidence_exposed"] is False
    assert observability["secrets_exposed"] is False


def test_v48_never_creates_response_model_or_label_side_effects(full_acceptance: dict) -> None:
    counts = full_acceptance["counts"]

    assert counts["response_actions"] == 0
    assert counts["model_runs"] == 0
    assert counts["labels"] == 0
    assert counts["users"] == 0
    assert full_acceptance["response_automation_allowed"] is False
    assert full_acceptance["real_firewall_blocking_enabled"] is False
    assert full_acceptance["model_activation_performed"] is False
    assert full_acceptance["production_ready"] is False


def test_v48_public_report_contains_no_private_paths_or_raw_evidence(full_acceptance: dict) -> None:
    rendered = json.dumps(full_acceptance, default=str)

    assert str(Path.home()) not in rendered
    assert "raw_line" not in rendered.lower()
    assert "203.0.113.44" not in rendered
    assert "v48-secret-sentinel" not in rendered
    assert full_acceptance["secrets_exposed"] is False


def test_v48_acceptance_report_is_repeatable() -> None:
    parent = Path(".tmp") / f"pytest-v48-repeat-{uuid4().hex[:12]}"
    parent.mkdir(parents=True, exist_ok=False)
    try:
        runs = [
            run_v48_product_acceptance(
                use_temp_db=True,
                log_count=40,
                temp_parent=parent,
            )
            for _ in range(2)
        ]
    finally:
        shutil.rmtree(parent, ignore_errors=True)

    assert all(item["ok"] for item in runs)
    stable_keys = (
        "status",
        "scope",
        "options",
        "ingestion",
        "checks",
        "failed_checks",
        "response_automation_allowed",
        "real_firewall_blocking_enabled",
        "model_activation_performed",
        "production_ready",
        "secrets_exposed",
    )
    assert {key: runs[0][key] for key in stable_keys} == {key: runs[1][key] for key in stable_keys}
