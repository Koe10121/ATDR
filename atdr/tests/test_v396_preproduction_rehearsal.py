from __future__ import annotations

import json

from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from atdr.app.core.config import Settings
from atdr.app.db.database import Base
from atdr.app.db.models import Alert, AlertEvidence, NormalizedLog, RawLog
from atdr.app.services import preproduction_acceptance_service
from atdr.app.services.case_service import list_alert_cases
from atdr.app.services.preproduction_acceptance_service import build_preproduction_acceptance_report
from atdr.scripts import run_disaster_recovery_drill as recovery_drill_module
from atdr.scripts.run_v396_preproduction_preflight import (
    CONFIRMATION,
    run_preproduction_preflight,
)


def _settings(tmp_path, **overrides) -> Settings:
    staging = tmp_path / "staging"
    backup = tmp_path / "backup"
    tls = tmp_path / "tls"
    staging.mkdir()
    backup.mkdir()
    tls.mkdir()
    certificate = tls / "fullchain.pem"
    private_key = tls / "privkey.pem"
    certificate.write_text("synthetic-certificate", encoding="utf-8")
    private_key.write_text("synthetic-private-key", encoding="utf-8")
    staging.chmod(0o770)
    backup.chmod(0o700)
    private_key.chmod(0o600)
    values = {
        "ENVIRONMENT": "preproduction",
        "ATDR_AUTH_MODE": "template_shell",
        "DATABASE_URL": "postgresql+psycopg2://atdr:private-db-value@127.0.0.1:5432/atdr",
        "AUTO_CREATE_TABLES": False,
        "JWT_SECRET_KEY": "v396-private-test-signing-value-with-safe-length",
        "RESPONSE_SIMULATION": True,
        "RESPONSE_PROVIDER": "simulation",
        "CORS_ALLOWED_ORIGINS": "https://atdr.example.test",
        "TRUST_PROXY_HEADERS": True,
        "TRUSTED_PROXY_CIDRS": "127.0.0.1/32,10.20.0.0/24",
        "DEPLOYMENT_REHEARSAL_APPROVED": True,
        "DEPLOYMENT_PUBLIC_BASE_URL": "https://atdr.example.test",
        "DEPLOYMENT_DNS_NAME": "atdr.example.test",
        "DEPLOYMENT_TLS_CERTIFICATE_PATH": str(certificate),
        "DEPLOYMENT_TLS_PRIVATE_KEY_PATH": str(private_key),
        "DEPLOYMENT_PROMETHEUS_URL": "http://127.0.0.1:9090",
        "DEPLOYMENT_SECRET_PROVIDER": "vault",
        "OPERATION_WORKER_ENABLED": True,
        "OPERATION_WORKER_DEPLOYMENT_ID": "preproduction-a",
        "OPERATION_WORKER_CONCURRENCY": 2,
        "OPERATION_STAGING_ROOT": str(staging),
        "OPERATION_STAGING_SHARED": True,
        "OPERATION_STAGING_STORAGE_ID": "preproduction-storage-a",
        "OPERATION_STAGING_MIN_FREE_BYTES": 0,
        "ATDR_BACKUP_DIRECTORY": str(backup),
        "ATDR_BACKUP_MAX_AGE_HOURS": 30,
        "MFU_IAM_ENABLED": True,
        "MFU_IAM_ALLOWED_DOMAINS": "lamduan.mfu.ac.th",
        "MFU_IAM_TEMPLATE_SHELL_ENABLED": True,
        "MFU_IAM_TEMPLATE_SHELL_BASE_URL": "https://shell.example.test",
        "MFU_IAM_TEMPLATE_SHELL_LAUNCH_URL": "https://shell.example.test/#/pages/login",
        "MFU_IAM_HANDOFF_ENABLED": True,
        "MFU_IAM_HANDOFF_SHARED_SECRET": "private-handoff-test-value",
        "MFU_IAM_HANDOFF_FRONTEND_URL": "https://atdr.example.test",
        "MFU_IAM_HANDOFF_ALLOWED_ORIGINS": "https://shell.example.test",
        "MFU_IAM_HANDOFF_COOKIE_SECURE": True,
        "ASSISTANT_LLM_ENABLED": False,
        "ASSISTANT_ALLOW_RAW_LOG_CONTEXT": False,
    }
    values.update(overrides)
    return Settings(_env_file=None, **values)


def _database_at_head(_settings: Settings, *, probe_connection: bool) -> dict:
    return {
        "connection_status": "available" if probe_connection else "not_checked",
        "migration_status": "at_head" if probe_connection else "not_checked",
    }


def _fresh_backup(**_kwargs) -> dict:
    return {"ok": True, "status": "backup_valid", "secrets_exposed": False}


def test_preproduction_report_is_incomplete_and_secret_safe_by_default(tmp_path):
    settings = Settings(
        _env_file=None,
        DATABASE_URL=f"sqlite:///{tmp_path / 'local.db'}",
        JWT_SECRET_KEY="private-local-test-secret-that-must-not-appear",
        RESPONSE_SIMULATION=True,
        ASSISTANT_ALLOW_RAW_LOG_CONTEXT=False,
    )
    result = build_preproduction_acceptance_report(settings, system_name="Windows")
    encoded = json.dumps(result)

    assert result["ok"] is True
    assert result["accepted"] is False
    assert result["status"] == "preproduction_requirements_incomplete"
    assert result["current_database_modified"] is False
    assert result["external_network_calls_made"] is False
    assert result["response_automation_allowed"] is False
    assert result["real_firewall_blocking_enabled"] is False
    assert result["model_activation_performed"] is False
    assert "private-local-test-secret" not in encoded
    assert "production_ready" in result and result["production_ready"] is False
    assert all(
        str(check["detail"]).startswith("Requirement not met:")
        for check in result["checks"]
        if not check["passed"]
    )
    assert len(result["operator_actions"]) == len(result["missing_requirement_ids"])
    assert all("verify that" in str(check["detail"]) for check in result["checks"] if not check["passed"])


def test_approved_synthetic_profile_can_satisfy_source_checks(tmp_path, monkeypatch):
    settings = _settings(tmp_path)
    real_directory_state = preproduction_acceptance_service._directory_state
    monkeypatch.setattr(preproduction_acceptance_service, "inspect_database_runtime", _database_at_head)
    monkeypatch.setattr(
        preproduction_acceptance_service,
        "_private_key_permissions_safe",
        lambda _path, *, system_name: system_name == "Linux",
    )
    monkeypatch.setattr(
        preproduction_acceptance_service,
        "_directory_state",
        lambda value, **kwargs: {
            **real_directory_state(value, **kwargs),
            "owned_by_operator": True,
            "permissions_safe": True,
        },
    )

    result = build_preproduction_acceptance_report(
        settings,
        probe_database=True,
        system_name="Linux",
        command_lookup=lambda name: f"/usr/bin/{name}",
        backup_status_function=_fresh_backup,
    )

    assert result["accepted"] is True, result["missing_requirement_ids"]
    assert result["status"] == "operational_acceptance_passed"
    assert result["missing_requirement_ids"] == []
    assert result["approved_host_evidence"] is True
    assert result["database_connection_probe_performed"] is True
    assert result["external_network_calls_made"] is True
    assert result["secrets_exposed"] is False
    assert "private-db-value" not in json.dumps(result)
    assert "private-handoff-test-value" not in json.dumps(result)


def test_production_profile_and_broad_proxy_scope_are_not_accepted(tmp_path, monkeypatch):
    settings = _settings(
        tmp_path,
        ENVIRONMENT="production",
        TRUSTED_PROXY_CIDRS="0.0.0.0/0",
    )
    monkeypatch.setattr(preproduction_acceptance_service, "inspect_database_runtime", _database_at_head)

    result = build_preproduction_acceptance_report(
        settings,
        probe_database=True,
        system_name="Linux",
        command_lookup=lambda name: f"/usr/bin/{name}",
        backup_status_function=_fresh_backup,
    )

    assert result["accepted"] is False
    assert "shared_environment" in result["missing_requirement_ids"]
    assert "trusted_proxy" in result["missing_requirement_ids"]


def test_assistant_raw_log_context_and_response_provider_fail_acceptance(tmp_path, monkeypatch):
    settings = _settings(
        tmp_path,
        ASSISTANT_ALLOW_RAW_LOG_CONTEXT=True,
        RESPONSE_PROVIDER="manual",
    )
    monkeypatch.setattr(preproduction_acceptance_service, "inspect_database_runtime", _database_at_head)

    result = build_preproduction_acceptance_report(
        settings,
        probe_database=True,
        system_name="Linux",
        command_lookup=lambda name: f"/usr/bin/{name}",
        backup_status_function=_fresh_backup,
    )

    assert result["accepted"] is False
    assert "assistant_raw_logs_disabled" in result["missing_requirement_ids"]
    assert "assistant_provider_safety" in result["missing_requirement_ids"]
    assert "response_simulation" in result["missing_requirement_ids"]


def test_database_probe_requires_exact_confirmation(tmp_path):
    settings = Settings(
        _env_file=None,
        DATABASE_URL=f"sqlite:///{tmp_path / 'local.db'}",
        RESPONSE_SIMULATION=True,
    )

    blocked = run_preproduction_preflight(
        settings=settings,
        probe_database=True,
        confirmation="wrong",
    )
    dry_run = run_preproduction_preflight(settings=settings)

    assert blocked["ok"] is False
    assert blocked["status"] == "database_probe_confirmation_required"
    assert blocked["required_confirmation"] == CONFIRMATION
    assert blocked["database_connection_probe_performed"] is False
    assert dry_run["ok"] is True
    assert dry_run["database_connection_probe_performed"] is False


def test_recovery_drill_reports_only_isolated_rto_measurement(monkeypatch):
    monkeypatch.setattr(
        recovery_drill_module,
        "validate_persistence_profile",
        lambda settings: {
            "ok": True,
            "current_database_unchanged": True,
            "runtime_seconds": 1.25,
            "sqlite_validation": {
                "migration": {"ok": True},
                "backup": {"ok": True, "sha256": "synthetic"},
                "restore": {
                    "ok": True,
                    "integrity_ok": True,
                    "row_counts_match": True,
                    "migration_revision_match": True,
                },
            },
        },
    )

    result = recovery_drill_module.run_disaster_recovery_drill(execute=True, confirmed=True)

    assert result["ok"] is True
    assert result["measurement_scope"] == "isolated_synthetic_sqlite"
    assert result["measured_rehearsal_rto_seconds"] == 1.25
    assert result["rto_measured"] is True
    assert result["rpo_measured"] is False
    assert result["measured_rpo_seconds"] is None
    assert result["approved_host_measurement"] is False
    assert result["current_database_unchanged"] is True


def test_case_summary_eager_loads_evidence_with_bounded_queries():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        for alert_number in range(10):
            alert = Alert(
                title=f"Medium: synthetic case alert {alert_number}",
                alert_type="possible_port_scan",
                src_ip=f"203.0.113.{alert_number + 1}",
                dst_ip="10.0.0.10",
                threat_score=55,
                severity="Medium",
                status="open",
                explanation="Synthetic evidence-loading regression fixture.",
                matched_rules_json=[{"code": "possible_port_scan"}],
                recommended_response="Investigate.",
            )
            for evidence_number in range(4):
                raw = RawLog(raw_line=f"synthetic-{alert_number}-{evidence_number}")
                normalized = NormalizedLog(
                    raw_log=raw,
                    src_ip=alert.src_ip,
                    dst_ip=alert.dst_ip,
                    dst_port=1000 + evidence_number,
                    action="allow",
                )
                alert.evidence.append(AlertEvidence(normalized_log=normalized))
            db.add(alert)
        db.commit()

    query_count = 0

    @event.listens_for(engine, "before_cursor_execute")
    def count_query(*_args):
        nonlocal query_count
        query_count += 1

    with Session(engine) as db:
        cases = list_alert_cases(db, limit=20)

    assert len(cases) == 10
    assert sum(item["total_related_logs"] for item in cases) == 40
    assert query_count <= 3
