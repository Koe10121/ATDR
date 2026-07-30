from __future__ import annotations

import json
from pathlib import Path

from sqlalchemy.dialects import postgresql, sqlite

from atdr.app.services.source_service import (
    _source_alert_count_statement,
    _source_normalized_quality_statement,
)
from atdr.app.services.v516_memory_query_service import (
    process_memory_snapshot,
    run_v516_memory_query_stabilization,
)


SCENARIO_PATH = (
    Path(__file__).resolve().parents[2]
    / "data"
    / "samples"
    / "scenarios"
    / "port_scan_like_traffic.txt"
)


def test_v516_requires_disposable_database() -> None:
    result = run_v516_memory_query_stabilization(
        sample_path=SCENARIO_PATH,
        target_rows=10,
        chunk_size=2,
        run_detection_after=True,
    )

    assert result["ok"] is False
    assert result["acceptance"]["status"] == "explicit_temp_database_required"
    assert result["safety"]["configured_database_modified"] is False
    assert result["privacy_findings"] == []


def test_v516_bounded_acceptance_preserves_semantics_and_safety() -> None:
    result = run_v516_memory_query_stabilization(
        sample_path=SCENARIO_PATH,
        target_rows=10,
        chunk_size=2,
        use_temp_db=True,
        run_detection_after=True,
    )

    assert result["ok"] is True
    assert result["status"] == "memory_query_stabilization_passed"
    assert all(result["semantic_equivalence"].values())
    assert all(
        result["gates"][key]
        for key in (
            "memory_target_passed",
            "query_latency_targets_passed",
            "query_count_regression_passed",
            "ingestion_throughput_floor_passed",
            "detection_throughput_floor_passed",
            "semantic_equivalence_passed",
        )
    )
    metrics = result["metrics"]
    assert metrics["memory_acceptance_basis"] in {
        "process_peak_rss",
        "traced_python_memory",
    }
    assert metrics["traced_memory_comparison_scope_compatible"] is False
    assert metrics["identity_map"]["profile_count"] == 1
    assert metrics["identity_map"]["peak_identity_map_size"] < 100
    assert metrics["queries"]["overview_cold_query_count"] <= 35
    assert metrics["queries"]["source_detail_query_count"] <= 7
    plan = metrics["queries"]["query_plan_summary"]
    assert plan["dialect"] == "sqlite"
    assert plan["unique_select_plans"] > 0
    assert plan["sql_text_returned"] is False
    assert plan["query_parameters_returned"] is False

    acceptance = result["acceptance"]
    assert acceptance["detection"]["executed"] is True
    assert acceptance["detection"]["rule_detection_authoritative"] is True
    assert acceptance["detection"]["supervised_lifecycle"] == (
        "shadow_observation"
    )
    assert acceptance["safety"]["unsafe_side_effect_counts"] == {
        "response_actions": 0,
        "labels": 0,
        "model_runs": 0,
    }
    assert acceptance["cleanup"]["complete"] is True


def test_v516_profile_only_skips_detection_and_redacts_private_input(
    tmp_path: Path,
) -> None:
    private_path = tmp_path / "private-203.0.113.44-runtime.log"
    private_path.write_bytes(SCENARIO_PATH.read_bytes())

    result = run_v516_memory_query_stabilization(
        sample_path=private_path,
        target_rows=10,
        chunk_size=2,
        use_temp_db=True,
        profile_only=True,
        run_detection_after=True,
    )
    serialized = json.dumps(result, default=str)

    assert result["ok"] is True
    assert result["mode"] == "profile_only"
    assert result["acceptance"]["detection"]["executed"] is False
    assert result["privacy_findings"] == []
    assert str(private_path) not in serialized
    assert private_path.name not in serialized
    assert "203.0.113.44" not in serialized
    assert result["safety"]["secrets_exposed"] is False
    assert result["safety"]["response_automation_allowed"] is False
    assert result["safety"]["real_firewall_blocking_enabled"] is False


def test_process_memory_snapshot_is_aggregate_only() -> None:
    snapshot = process_memory_snapshot()

    assert set(snapshot) == {
        "available",
        "current_rss_mb",
        "peak_rss_mb",
        "source",
    }
    assert "path" not in snapshot


def test_v516_source_aggregate_queries_compile_for_sqlite_and_postgresql() -> None:
    statements = [
        _source_normalized_quality_statement(1),
        _source_alert_count_statement(1),
    ]

    for dialect in (sqlite.dialect(), postgresql.dialect()):
        rendered = "\n".join(
            str(statement.compile(dialect=dialect))
            for statement in statements
        ).lower()
        assert "normalized_logs" in rendered
        assert "raw_logs" in rendered
        assert "json_extract" not in rendered
        assert "pragma" not in rendered
