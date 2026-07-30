from __future__ import annotations

import json
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from atdr.app.db.database import Base
from atdr.app.services import v517_postgres_multiworker_service as v517_service
from atdr.app.services.detection_coordination_service import (
    DetectionCoordinationTimeout,
    acquire_detection_transaction_lock,
)
from atdr.app.services.job_service import enqueue_job
from atdr.app.services import operation_worker as operation_worker_service
from atdr.app.services.v517_postgres_multiworker_service import (
    _has_distinct_job_claims,
    _safe_postgres_target,
    run_v517_postgres_multiworker_acceptance,
)


def _sqlite_engine():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    Base.metadata.create_all(engine)
    return engine


def test_v517_missing_postgres_environment_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("ATDR_V517_POSTGRES_DATABASE_URL", raising=False)
    monkeypatch.delenv("ATDR_V517_RESTORE_DATABASE_URL", raising=False)

    result = run_v517_postgres_multiworker_acceptance(
        target_rows=100,
        chunk_size=10,
        workers=2,
        synthetic=True,
        preflight_only=True,
    )
    rendered = json.dumps(result, default=str)

    assert result["ok"] is False
    assert result["status"] == "blocked_by_environment"
    assert result["executed"] is False
    assert result["configured_database_modified"] is False
    assert result["secrets_exposed"] is False
    assert "password" not in rendered.lower()
    assert "postgresql://" not in rendered.lower()


@pytest.mark.parametrize(
    ("target", "expected_reason"),
    [
        ("sqlite:///./v517.db", "postgresql_required"),
        (
            "postgresql+psycopg2://user:secret@localhost/postgres",
            "unsafe_database_name",
        ),
        (
            "postgresql+psycopg2://user:secret@localhost/production",
            "unsafe_database_name",
        ),
    ],
)
def test_v517_refuses_unsafe_targets(
    target: str,
    expected_reason: str,
) -> None:
    accepted, reason = _safe_postgres_target(
        target,
        configured_url="sqlite:///./atdr.db",
    )

    assert accepted is False
    assert reason == expected_reason


def test_v517_refuses_configured_database_identity() -> None:
    target = (
        "postgresql+psycopg2://user:secret@localhost/"
        "atdr_v517_disposable"
    )

    accepted, reason = _safe_postgres_target(
        target,
        configured_url=target,
    )

    assert accepted is False
    assert reason == "configured_database_target_refused"


def test_v517_requires_exactly_one_evidence_mode() -> None:
    neither = run_v517_postgres_multiworker_acceptance(
        target_rows=100,
        chunk_size=10,
        workers=2,
        preflight_only=True,
    )
    both = run_v517_postgres_multiworker_acceptance(
        target_rows=100,
        chunk_size=10,
        workers=2,
        synthetic=True,
        sample_path=Path("private.log"),
        preflight_only=True,
    )

    assert neither["status"] == "select_exactly_one_evidence_source"
    assert both["status"] == "select_exactly_one_evidence_source"
    assert neither["configured_database_modified"] is False
    assert both["configured_database_modified"] is False


def test_detection_coordination_is_noop_for_sqlite() -> None:
    engine = _sqlite_engine()
    try:
        with Session(engine) as db:
            assert acquire_detection_transaction_lock(db) == 0.0
    finally:
        engine.dispose()


class _PostgresBind:
    class _Dialect:
        name = "postgresql"

    dialect = _Dialect()


class _LockSession:
    def __init__(self, outcomes: list[bool]) -> None:
        self.outcomes = iter(outcomes)
        self.calls = 0

    def get_bind(self):
        return _PostgresBind()

    def scalar(self, _statement, _parameters):
        self.calls += 1
        return next(self.outcomes)


def test_detection_coordination_retries_then_acquires() -> None:
    db = _LockSession([False, True])

    waited = acquire_detection_transaction_lock(
        db,  # type: ignore[arg-type]
        timeout_seconds=1,
        poll_seconds=0.01,
    )

    assert waited >= 0
    assert db.calls == 2


def test_detection_coordination_timeout_fails_closed() -> None:
    class NeverAcquires(_LockSession):
        def scalar(self, _statement, _parameters):
            self.calls += 1
            return False

    db = NeverAcquires([])

    with pytest.raises(
        DetectionCoordinationTimeout,
        match="Another detection transaction",
    ):
        acquire_detection_transaction_lock(
            db,  # type: ignore[arg-type]
            timeout_seconds=0.02,
            poll_seconds=0.01,
        )


def test_postgres_worker_releases_lock_through_owning_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class PostgresBind:
        class Dialect:
            name = "postgresql"

        dialect = Dialect()

    class WorkSession:
        def get_bind(self):
            return PostgresBind()

    class CoordinationSession:
        closed = False

        def close(self) -> None:
            self.closed = True

    coordination = CoordinationSession()
    acquired_with: list[object] = []
    released_with: list[object] = []

    monkeypatch.setattr(
        operation_worker_service,
        "Session",
        lambda **_kwargs: coordination,
    )
    monkeypatch.setattr(
        operation_worker_service,
        "acquire_worker_operation_lock",
        lambda session: not acquired_with.append(session),
    )
    monkeypatch.setattr(
        operation_worker_service,
        "release_worker_operation_lock",
        lambda session: released_with.append(session),
    )
    monkeypatch.setattr(
        operation_worker_service,
        "_run_worker_once_locked",
        lambda *_args, **_kwargs: {
            "ok": True,
            "processed": False,
            "status": "test_complete",
        },
    )

    result = operation_worker_service.run_worker_once(
        WorkSession(),  # type: ignore[arg-type]
        worker_id="v517-lock-owner",
    )

    assert result["ok"] is True
    assert acquired_with == [coordination]
    assert released_with == [coordination]
    assert coordination.closed is True


def test_v517_distinct_job_claims_uses_public_job_id_contract() -> None:
    distinct = [
        {"processed": True, "job": {"job_id": 101}},
        {"processed": True, "job": {"job_id": 102}},
    ]
    repeated = [
        {"processed": True, "job": {"job_id": 101}},
        {"processed": True, "job": {"job_id": 101}},
    ]

    assert _has_distinct_job_claims(distinct, expected=2) is True
    assert _has_distinct_job_claims(repeated, expected=2) is False


def test_sequential_idempotency_reuses_one_job() -> None:
    engine = _sqlite_engine()
    try:
        with Session(engine) as db:
            first, first_reused = enqueue_job(
                db,
                job_type="validation",
                requested_by="v517-test",
                payload={},
                idempotency_key="v517-test-key",
            )
            second, second_reused = enqueue_job(
                db,
                job_type="validation",
                requested_by="v517-test",
                payload={},
                idempotency_key="v517-test-key",
            )

            assert first.id == second.id
            assert first_reused is False
            assert second_reused is True
    finally:
        engine.dispose()


def test_v517_result_contract_contains_no_action_authority() -> None:
    result = run_v517_postgres_multiworker_acceptance(
        target_rows=100,
        chunk_size=10,
        workers=2,
        synthetic=True,
        preflight_only=True,
    )

    assert result["rules_alert_authoritative"] is True
    assert result["model_activation_performed"] is False
    assert result["model_promotion_performed"] is False
    assert result["response_automation_allowed"] is False
    assert result["real_firewall_blocking_enabled"] is False


def test_v517_migration_failure_cleans_disposable_targets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target_url = (
        "postgresql+psycopg2://user:secret@localhost/"
        "atdr_v517_disposable"
    )
    restore_url = (
        "postgresql+psycopg2://user:secret@localhost/"
        "atdr_v517_restore"
    )
    dropped: list[str] = []

    monkeypatch.setenv("ATDR_V517_POSTGRES_DATABASE_URL", target_url)
    monkeypatch.setenv("ATDR_V517_RESTORE_DATABASE_URL", restore_url)
    monkeypatch.setattr(
        v517_service,
        "_configured_database_marker",
        lambda: ("sqlite", (1, 2)),
    )
    monkeypatch.setattr(
        v517_service,
        "_preflight",
        lambda **_kwargs: {
            "ok": True,
            "status": "ready",
            "database_urls_returned": False,
            "credentials_returned": False,
        },
    )
    monkeypatch.setattr(
        v517_service,
        "_run_migrations",
        lambda _database_url: {
            "ok": False,
            "status": "migration_failed",
            "error_type": "AlembicError",
        },
    )
    monkeypatch.setattr(
        v517_service,
        "_drop_disposable_database",
        lambda database_url: not dropped.append(database_url),
    )

    result = run_v517_postgres_multiworker_acceptance(
        target_rows=100,
        chunk_size=10,
        workers=2,
        synthetic=True,
    )
    rendered = json.dumps(result, default=str)

    assert result["status"] == "migration_failed"
    assert result["executed"] is False
    assert result["configured_database_unchanged"] is True
    assert result["cleanup"]["complete"] is True
    assert dropped == [restore_url, target_url]
    assert "postgresql://" not in rendered.lower()
    assert "user:secret" not in rendered.lower()
