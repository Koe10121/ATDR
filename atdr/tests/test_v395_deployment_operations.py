from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import hashlib
import json

from fastapi import Request
from sqlalchemy import UniqueConstraint, create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool
from starlette.responses import Response

from atdr.app.core.config import PROJECT_ROOT, Settings, get_settings, validate_runtime_settings
from atdr.app.core.middleware import TrustedProxyHeadersMiddleware
from atdr.app.db.database import Base
from atdr.app.db.models import LogSource
from atdr.app.services.load_test_service import run_read_only_load_test
from atdr.app.services.metrics_service import render_prometheus_metrics
from atdr.app.services.persistence_service import verify_database_backup_artifact
from atdr.scripts.run_disaster_recovery_drill import run_disaster_recovery_drill
from atdr.scripts.validate_deployment_operations import validate_deployment_operations
from atdr.scripts.verify_latest_backup import verify_latest_backup


def _engine():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    Base.metadata.create_all(engine)
    return engine


def _request(*, peer: str, headers: list[tuple[bytes, bytes]]) -> Request:
    return Request(
        {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": "GET",
            "scheme": "http",
            "path": "/probe",
            "raw_path": b"/probe",
            "query_string": b"",
            "root_path": "",
            "headers": headers,
            "client": (peer, 12345),
            "server": ("testserver", 80),
        }
    )


def test_trusted_proxy_headers_apply_only_for_allowlisted_direct_peer():
    middleware = TrustedProxyHeadersMiddleware(lambda *_: None, enabled=True, trusted_cidrs=["127.0.0.1/32"])
    captured: list[tuple[str, str, bool]] = []

    async def call_next(request: Request) -> Response:
        captured.append((request.url.scheme, request.client.host, request.state.proxy_headers_trusted))
        return Response("ok")

    trusted = _request(
        peer="127.0.0.1",
        headers=[(b"x-forwarded-proto", b"https"), (b"x-forwarded-for", b"203.0.113.20")],
    )
    untrusted = _request(
        peer="198.51.100.5",
        headers=[(b"x-forwarded-proto", b"https"), (b"x-forwarded-for", b"203.0.113.21")],
    )
    asyncio.run(middleware.dispatch(trusted, call_next))
    asyncio.run(middleware.dispatch(untrusted, call_next))

    assert captured[0] == ("https", "203.0.113.20", True)
    assert captured[1] == ("http", "198.51.100.5", False)


def test_proxy_configuration_rejects_invalid_networks():
    settings = Settings(TRUST_PROXY_HEADERS=True, TRUSTED_PROXY_CIDRS="not-a-network")
    assert any("TRUSTED_PROXY_CIDRS" in issue for issue in validate_runtime_settings(settings))


def test_log_source_metadata_matches_migrated_unique_constraint_and_index():
    name_constraints = [
        constraint
        for constraint in LogSource.__table__.constraints
        if isinstance(constraint, UniqueConstraint)
        and tuple(column.name for column in constraint.columns) == ("name",)
    ]
    name_index = next(index for index in LogSource.__table__.indexes if index.name == "ix_log_sources_name")

    assert len(name_constraints) == 1
    assert name_index.unique is True


def test_ci_pytest_temp_root_uses_runner_managed_directory():
    workflow = (PROJECT_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")

    assert "--basetemp=${{ runner.temp }}/atdr-pytest" in workflow
    assert "--basetemp=.tmp/pytest-ci" not in workflow


def test_metrics_cover_operational_alerts_without_sensitive_dimensions(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "sqlite://")
    monkeypatch.setenv("RESPONSE_SIMULATION", "true")
    monkeypatch.setenv("OPERATION_STAGING_MIN_FREE_BYTES", "0")
    get_settings.cache_clear()
    engine = _engine()
    with Session(engine) as db:
        rendered = render_prometheus_metrics(db, heartbeat_seconds=15)
    get_settings.cache_clear()

    for metric in (
        "atdr_service_ready",
        "atdr_database_ready",
        "atdr_runtime_configuration_issues",
        "atdr_response_simulation_enabled",
        "atdr_operation_recent_failures",
        "atdr_ingestion_recent_failed_runs",
        "atdr_detection_recent_failed_runs",
        "atdr_ingestion_staging_pressure",
        "atdr_database_pool_observable",
        "atdr_database_pool_utilization_ratio",
        "atdr_backup_configured",
        "atdr_backup_fresh",
    ):
        assert metric in rendered
    for forbidden in ("request_id=", "email=", "src_ip=", "raw_log=", "file_path=", "token="):
        assert forbidden not in rendered


def test_read_only_load_test_reports_percentiles_and_never_writes():
    calls: list[tuple[str, dict[str, str]]] = []

    def fake_request(url: str, headers: dict[str, str], _timeout: float) -> tuple[int, float]:
        calls.append((url, headers))
        return 200, 0.025

    def fake_metrics(_url: str, _timeout: float) -> tuple[int, str]:
        return (
            200,
            "\n".join(
                (
                    "atdr_database_pool_observable 1",
                    'atdr_database_pool_connections{state="checked_in"} 3',
                    'atdr_database_pool_connections{state="checked_out"} 2',
                    'atdr_database_pool_connections{state="overflow"} 0',
                    "atdr_database_pool_configured_size 5",
                    "atdr_database_pool_max_overflow 10",
                    "atdr_database_pool_utilization_ratio 0.133333",
                    'atdr_operation_queue_depth{job_type="import",state="queued"} 4',
                )
            ),
        )

    result = run_read_only_load_test(
        base_url="http://127.0.0.1:8000",
        bearer_token="private-test-token",
        requests_per_endpoint=2,
        concurrency=2,
        execute=True,
        request_function=fake_request,
        metrics_url="http://127.0.0.1:8000/metrics",
        metrics_probe_function=fake_metrics,
    )

    assert result["ok"] is True
    assert result["total_requests"] == 16
    assert result["error_rate"] == 0
    assert result["write_requests_allowed"] is False
    assert result["response_bodies_reported"] is False
    assert result["secrets_exposed"] is False
    assert all(row["p95_seconds"] == 0.025 for row in result["results"])
    assert all(url.startswith("http://127.0.0.1:8000/") for url, _ in calls)
    assert result["operational_metrics"]["pool_observable"] is True
    assert result["operational_metrics"]["checked_out"] == 2
    assert result["operational_metrics"]["queue_depth"] == 4
    assert "private-test-token" not in json.dumps(result)


def test_remote_load_test_requires_explicit_confirmation():
    result = run_read_only_load_test(
        base_url="https://atdr.example.invalid",
        bearer_token="private-test-token",
        execute=True,
    )
    assert result["ok"] is False
    assert result["status"] == "remote_confirmation_required"
    assert result["executed"] is False


def test_backup_manifest_verification_is_read_only_and_detects_tampering(tmp_path):
    artifact = tmp_path / "atdr-sqlite-test.sqlite3"
    artifact.write_bytes(b"synthetic-backup")
    manifest = tmp_path / f"{artifact.name}.manifest.json"
    payload = {
        "format_version": 1,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "dialect": "sqlite",
        "artifact_name": artifact.name,
        "artifact_size_bytes": artifact.stat().st_size,
        "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
        "alembic_revision": "test-revision",
        "table_counts": {"raw_logs": 1},
    }
    manifest.write_text(json.dumps(payload), encoding="utf-8")

    valid = verify_database_backup_artifact(backup_path=artifact, manifest_path=manifest, max_age_hours=1)
    latest = verify_latest_backup(backup_dir=tmp_path, max_age_hours=1)
    artifact.write_bytes(b"tampered")
    invalid = verify_database_backup_artifact(backup_path=artifact, manifest_path=manifest, max_age_hours=1)

    assert valid["ok"] is True and latest["ok"] is True
    assert valid["database_modified"] is False
    assert invalid["ok"] is False and invalid["status"] == "checksum_mismatch"
    assert str(tmp_path) not in json.dumps(valid)


def test_disaster_recovery_drill_is_dry_run_by_default():
    result = run_disaster_recovery_drill()
    assert result["ok"] is True
    assert result["status"] == "dry_run"
    assert result["executed"] is False
    assert result["active_database_restore_allowed"] is False
    assert result["current_database_modified"] is False
    assert result["rto_measured"] is False
    assert result["rpo_measured"] is False
    assert result["approved_host_measurement"] is False


def test_deployment_assets_are_safe_and_complete(tmp_path):
    settings = Settings(
        _env_file=None,
        DATABASE_URL=f"sqlite:///{tmp_path / 'safe.db'}",
        RESPONSE_SIMULATION=True,
        MFU_IAM_ENABLED=False,
        OIDC_ENABLED=False,
        ASSISTANT_ENABLED=False,
        ASSISTANT_LLM_ENABLED=False,
        ASSISTANT_ALLOW_RAW_LOG_CONTEXT=False,
        SMTP_ENABLED=False,
        OPERATION_WORKER_CONCURRENCY=1,
        OPERATION_STAGING_MIN_FREE_BYTES=0,
    )
    result = validate_deployment_operations(settings=settings)
    assert result["ok"] is True
    assert result["scheduled_destructive_flags_present"] is False
    assert result["uvicorn_generic_proxy_headers_disabled"] is True
    assert result["response_simulation"] is True
    assert result["secrets_exposed"] is False
