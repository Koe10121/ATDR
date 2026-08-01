from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from atdr.app.services import v518_postgres_scale_service as v518_service
from atdr.app.services.v518_postgres_scale_service import (
    _slo_evaluation,
    run_v518_postgres_scale_qualification,
)


def _passing_stage(*, target_rows: int, workers: int) -> dict:
    return {
        "ok": True,
        "status": "postgres_multiworker_acceptance_passed",
        "target_rows": target_rows,
        "workers": workers,
    }


def test_v518_missing_environment_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv(
        "ATDR_V518_POSTGRES_DATABASE_URL",
        raising=False,
    )
    monkeypatch.delenv(
        "ATDR_V518_RESTORE_DATABASE_URL",
        raising=False,
    )
    monkeypatch.delenv("ATDR_V518_APPROVED_HOST", raising=False)

    result = run_v518_postgres_scale_qualification()
    rendered = json.dumps(result, default=str)

    assert result["ok"] is False
    assert result["status"] == "blocked_by_environment"
    assert result["executed"] is False
    assert result["configured_database_modified"] is False
    assert result["database_urls_returned"] is False
    assert result["credentials_returned"] is False
    assert result["secrets_exposed"] is False
    assert "postgresql://" not in rendered.lower()
    assert "password" not in rendered.lower()


def test_v518_confirmation_is_required_before_database_preparation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        v518_service,
        "get_settings",
        lambda: SimpleNamespace(database_url="sqlite:///./atdr.db"),
    )
    monkeypatch.setattr(
        v518_service,
        "_configured_database_marker",
        lambda: ("sqlite", (10, 20)),
    )
    monkeypatch.setattr(
        v518_service,
        "_preflight",
        lambda **_kwargs: {"ok": True, "status": "ready"},
    )
    called = False

    def unexpected_stage(**_kwargs):
        nonlocal called
        called = True
        raise AssertionError("Scale stage must not run without confirmation.")

    monkeypatch.setattr(v518_service, "_run_scale_stage", unexpected_stage)
    monkeypatch.setenv(
        "ATDR_V518_POSTGRES_DATABASE_URL",
        "postgresql://user@localhost/atdr_v518_disposable",
    )
    monkeypatch.setenv(
        "ATDR_V518_RESTORE_DATABASE_URL",
        "postgresql://user@localhost/atdr_v518_restore",
    )

    result = run_v518_postgres_scale_qualification(
        execute=True,
        confirmation="wrong",
    )

    assert result["status"] == "confirmation_required"
    assert result["executed"] is False
    assert called is False


def test_v518_does_not_run_250k_when_100k_gate_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        v518_service,
        "get_settings",
        lambda: SimpleNamespace(database_url="sqlite:///./atdr.db"),
    )
    monkeypatch.setattr(
        v518_service,
        "_configured_database_marker",
        lambda: ("sqlite", (10, 20)),
    )
    monkeypatch.setattr(
        v518_service,
        "_preflight",
        lambda **_kwargs: {"ok": True, "status": "ready"},
    )
    monkeypatch.setattr(
        v518_service,
        "_drop_disposable_database",
        lambda _url: True,
    )
    calls: list[tuple[int, int]] = []

    def stage(**kwargs):
        target_rows = int(kwargs["target_rows"])
        workers = int(kwargs["workers"])
        calls.append((target_rows, workers))
        result = _passing_stage(
            target_rows=target_rows,
            workers=workers,
        )
        if workers == 4:
            result["ok"] = False
        return result

    monkeypatch.setattr(v518_service, "_run_scale_stage", stage)
    monkeypatch.setenv(
        "ATDR_V518_POSTGRES_DATABASE_URL",
        "postgresql://user@localhost/atdr_v518_disposable",
    )
    monkeypatch.setenv(
        "ATDR_V518_RESTORE_DATABASE_URL",
        "postgresql://user@localhost/atdr_v518_restore",
    )

    result = run_v518_postgres_scale_qualification(
        execute=True,
        confirmation="APPROVED_DISPOSABLE_V518_SCALE_DATABASES",
    )

    assert calls == [(100_000, 2), (100_000, 4)]
    assert result["hundred_k"]["passed"] is False
    assert result["quarter_million"]["attempted"] is False
    assert (
        result["quarter_million"]["skipped_reason"]
        == "hundred_k_gate_failed"
    )
    assert result["roadmap"]["remaining_major_gates"] == 4
    assert result["configured_database_unchanged"] is True


def test_v518_runs_250k_only_after_both_100k_profiles_pass(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        v518_service,
        "get_settings",
        lambda: SimpleNamespace(database_url="sqlite:///./atdr.db"),
    )
    monkeypatch.setattr(
        v518_service,
        "_configured_database_marker",
        lambda: ("sqlite", (10, 20)),
    )
    monkeypatch.setattr(
        v518_service,
        "_preflight",
        lambda **_kwargs: {"ok": True, "status": "ready"},
    )
    monkeypatch.setattr(
        v518_service,
        "_drop_disposable_database",
        lambda _url: True,
    )
    calls: list[tuple[int, int]] = []

    def stage(**kwargs):
        target_rows = int(kwargs["target_rows"])
        workers = int(kwargs["workers"])
        calls.append((target_rows, workers))
        return _passing_stage(
            target_rows=target_rows,
            workers=workers,
        )

    monkeypatch.setattr(v518_service, "_run_scale_stage", stage)
    monkeypatch.setenv(
        "ATDR_V518_POSTGRES_DATABASE_URL",
        "postgresql://user@localhost/atdr_v518_disposable",
    )
    monkeypatch.setenv(
        "ATDR_V518_RESTORE_DATABASE_URL",
        "postgresql://user@localhost/atdr_v518_restore",
    )

    result = run_v518_postgres_scale_qualification(
        execute=True,
        confirmation="APPROVED_DISPOSABLE_V518_SCALE_DATABASES",
    )

    assert calls == [
        (100_000, 2),
        (100_000, 4),
        (250_000, 2),
        (250_000, 4),
    ]
    assert result["hundred_k"]["passed"] is True
    assert result["quarter_million"]["passed"] is True
    assert result["roadmap"]["postgresql_gate_closed"] is True
    assert result["roadmap"]["remaining_major_gates"] == 3
    assert result["configured_database_unchanged"] is True


def test_v518_slo_evaluation_covers_runtime_memory_queries_and_locks() -> None:
    acceptance = {
        "ok": True,
        "ingestion": {
            "rows_per_second": 500.0,
            "runtime_seconds": 200.0,
            "chunk_commit_interval_seconds": {"p99": 0.5},
        },
        "full_stage_memory": {
            "peak_rss_mb": 250.0,
        },
        "database": {"growth_bytes": 500_000_000},
        "pool": {"timeout_errors": 0},
        "queries": {
            "dashboard": {
                "overview_cold_seconds": 0.5,
                "overview_cached_seconds": 0.02,
                "alert_list_seconds": 1.0,
                "case_summary_seconds": 0.5,
                "source_detail_seconds": 0.5,
            },
            "ungranted_lock_count": 0,
        },
    }

    result = _slo_evaluation(acceptance, target_rows=100_000)

    assert result["ok"] is True
    assert result["passed"] == result["total"]
    assert result["observed_full_stage_peak_rss_mb"] == 250.0


def test_v518_slo_rejects_slow_or_lock_waiting_stage() -> None:
    acceptance = {
        "ok": True,
        "ingestion": {
            "rows_per_second": 10.0,
            "runtime_seconds": 800.0,
            "chunk_commit_interval_seconds": {"p99": 12.0},
        },
        "full_stage_memory": {
            "peak_rss_mb": 5_000.0,
        },
        "database": {"growth_bytes": 2_000_000_000},
        "pool": {"timeout_errors": 1},
        "queries": {
            "dashboard": {
                "overview_cold_seconds": 10.0,
                "overview_cached_seconds": 1.0,
                "alert_list_seconds": 10.0,
                "case_summary_seconds": 10.0,
                "source_detail_seconds": 10.0,
            },
            "ungranted_lock_count": 1,
        },
    }

    result = _slo_evaluation(acceptance, target_rows=100_000)

    assert result["ok"] is False
    assert result["checks"]["ingestion_throughput"] is False
    assert result["checks"]["pool_no_timeout"] is False
    assert result["checks"]["no_lock_waiters"] is False
