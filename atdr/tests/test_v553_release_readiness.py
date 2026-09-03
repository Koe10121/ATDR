from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path

from sqlalchemy import func, select

from atdr.app.core.config import Settings, get_settings, validate_runtime_settings
from atdr.app.core.security import create_access_token
from atdr.app.db.models import DetectionRun, MLModelRun, ResponseAction, User
from atdr.app.main import app
from atdr.app.services import mfu_iam_service
from atdr.app.services.repository_security_service import (
    build_cyclonedx_sbom,
    scan_repository_paths,
)
from atdr.app.services.v553_release_readiness_service import (
    _EVIDENCE_CONTRACTS,
    build_v553_release_readiness_report,
    validate_acceptance_manifest,
)
from atdr.scripts import run_v553_team_runtime_acceptance as team_rehearsal
from atdr.tests.test_mfu_iam_handoff import _client as _handoff_client
from atdr.tests.test_mfu_iam_handoff import _configure_handoff
from atdr.tests.test_v390_durable_operation_jobs import _client_with_session


def _settings(tmp_path: Path, **overrides) -> Settings:
    values = {
        "ENVIRONMENT": "development",
        "ATDR_AUTH_MODE": "template_shell",
        "DATABASE_URL": f"sqlite:///{tmp_path / 'atdr.db'}",
        "JWT_SECRET_KEY": "v553-test-signing-secret-with-safe-length",
        "RESPONSE_SIMULATION": True,
        "RESPONSE_PROVIDER": "simulation",
        "MFU_IAM_ENABLED": True,
        "MFU_IAM_ALLOWED_DOMAINS": "lamduan.mfu.ac.th",
        "MFU_IAM_DEFAULT_ROLE": "analyst",
        "MFU_IAM_ADMIN_GROUPS": "atdr-admin",
        "MFU_IAM_TEMPLATE_SHELL_ENABLED": True,
        "MFU_IAM_TEMPLATE_SHELL_BASE_URL": "http://127.0.0.1:8214",
        "MFU_IAM_TEMPLATE_SHELL_LAUNCH_URL": "http://localhost:8080/#/pages/login",
        "MFU_IAM_HANDOFF_ENABLED": True,
        "MFU_IAM_HANDOFF_SHARED_SECRET": "v553-private-handoff-test-value",
        "MFU_IAM_HANDOFF_FRONTEND_URL": "http://127.0.0.1:5173",
        "MFU_IAM_HANDOFF_ALLOWED_ORIGINS": "http://localhost:8080",
        "MFU_IAM_HANDOFF_ALLOWED_RETURN_PATHS": "/overview,/assistant",
        "ASSISTANT_LLM_ENABLED": False,
        "ASSISTANT_REDACT_IPS": True,
        "ASSISTANT_ALLOW_RAW_LOG_CONTEXT": False,
        "ATDR_ACCEPTANCE_EVIDENCE_ROOT": str(tmp_path / "acceptance"),
    }
    values.update(overrides)
    return Settings(_env_file=None, **values)


def _write_manifest(root: Path, evidence_type: str, *, environment: str = "development", **overrides) -> Path:
    now = datetime.now(timezone.utc)
    contract = _EVIDENCE_CONTRACTS[evidence_type]
    payload = {
        "schema_version": 1,
        "evidence_type": evidence_type,
        "environment": environment,
        "template_only": False,
        "recorded_at": (now - timedelta(minutes=5)).isoformat(),
        "expires_at": (now + timedelta(days=30)).isoformat(),
        "approved_by_role": "authorized-acceptance-owner",
        "checks": {name: True for name in contract["checks"]},
    }
    payload.update(overrides)
    root.mkdir(parents=True, exist_ok=True)
    path = root / str(contract["filename"])
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_acceptance_manifests_are_fail_closed_expiring_and_secret_safe(tmp_path):
    settings = _settings(tmp_path)
    root = tmp_path / "acceptance"

    missing = validate_acceptance_manifest(settings, "mfu_iam")
    assert missing["valid"] is False
    assert missing["status"] == "evidence_root_unavailable"

    path = _write_manifest(root, "mfu_iam")
    valid = validate_acceptance_manifest(settings, "mfu_iam")
    assert valid["valid"] is True
    assert valid["checks_passed"] == valid["checks_total"]

    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["client_secret"] = "private-manifest-value-that-must-not-leak"
    path.write_text(json.dumps(payload), encoding="utf-8")
    unsafe = validate_acceptance_manifest(settings, "mfu_iam")
    assert unsafe["valid"] is False
    assert unsafe["status"] == "evidence_unsafe"
    assert "private-manifest-value" not in json.dumps(unsafe)

    payload.pop("client_secret")
    payload["expires_at"] = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
    path.write_text(json.dumps(payload), encoding="utf-8")
    expired = validate_acceptance_manifest(settings, "mfu_iam")
    assert expired["valid"] is False
    assert expired["expired"] is True


def test_release_readiness_separates_local_controls_from_external_acceptance(tmp_path):
    settings = _settings(tmp_path)
    incomplete = build_v553_release_readiness_report(
        settings,
        preproduction_report={"accepted": False, "status": "preproduction_requirements_incomplete", "missing_requirement_ids": ["host"]},
    )
    assert incomplete["local_controls_ready"] is True
    assert incomplete["shared_lab_ready"] is False
    assert incomplete["production_ready"] is False
    assert incomplete["readiness_states"] == {
        "local_controls": "locally_verified",
        "external_evidence": "unavailable",
        "approved_host": "externally_pending",
        "shared_lab": "unavailable",
    }
    assert incomplete["response_automation_allowed"] is False
    assert incomplete["model_activation_performed"] is False

    evidence_root = tmp_path / "acceptance"
    for evidence_type in _EVIDENCE_CONTRACTS:
        _write_manifest(evidence_root, evidence_type)
    accepted = build_v553_release_readiness_report(
        settings,
        preproduction_report={
            "accepted": True,
            "status": "operational_acceptance_passed",
            "missing_requirement_ids": [],
            "resource_availability": {"postgresql_configured": True},
            "checks": [
                {"id": check_id, "passed": True}
                for check_id in (
                    "database_at_head",
                    "worker_profile",
                    "backup_directory",
                    "backup_permissions",
                    "backup_freshness",
                    "prometheus",
                    "https_public_url",
                    "tls_certificate",
                    "tls_private_key",
                    "tls_private_key_permissions",
                    "managed_secrets",
                )
            ],
        },
    )
    assert accepted["external_evidence_complete"] is True
    assert accepted["approved_host_ready"] is True
    assert accepted["shared_lab_ready"] is True
    assert accepted["production_ready"] is False
    assert accepted["readiness_states"] == {
        "local_controls": "locally_verified",
        "external_evidence": "externally_accepted",
        "approved_host": "externally_accepted",
        "shared_lab": "externally_accepted",
    }
    assert accepted["secrets_exposed"] is False
    deployment = accepted["sections"]["deployment"]
    assert deployment["database_profile"] == "shared PostgreSQL"
    assert deployment["workers_ready"] is True
    assert deployment["backup_ready"] is True
    assert deployment["monitoring_ready"] is True
    assert deployment["https_ready"] is True
    assert deployment["managed_secrets_ready"] is True
    assert deployment["recovery_evidence_ready"] is True


def test_external_admin_group_does_not_fail_local_engineering_controls(tmp_path):
    settings = _settings(tmp_path, MFU_IAM_ADMIN_GROUPS="")
    report = build_v553_release_readiness_report(
        settings,
        preproduction_report={"accepted": False, "checks": [], "resource_availability": {}},
    )
    assert report["local_controls_ready"] is True
    assert report["sections"]["iam"]["ready"] is True
    assert report["sections"]["iam"]["admin_group_mapping_configured"] is False
    assert report["external_evidence_complete"] is False
    assert "MFU provider lifecycle acceptance" in report["remaining_external_actions"]


def test_release_readiness_distinguishes_pending_unavailable_and_failed_evidence(tmp_path):
    settings = _settings(tmp_path)
    root = tmp_path / "acceptance"
    root.mkdir()
    pending = build_v553_release_readiness_report(
        settings,
        preproduction_report={"accepted": False, "checks": [], "resource_availability": {}},
    )
    assert pending["sections"]["iam"]["external_evidence"]["acceptance_state"] == "externally_pending"

    _write_manifest(root, "mfu_iam", expires_at="invalid-timestamp")
    failed = build_v553_release_readiness_report(
        settings,
        preproduction_report={"accepted": False, "checks": [], "resource_availability": {}},
    )
    assert failed["sections"]["iam"]["external_evidence"]["acceptance_state"] == "failed"
    assert failed["readiness_states"]["external_evidence"] == "failed"

    unavailable_settings = _settings(tmp_path, ATDR_ACCEPTANCE_EVIDENCE_ROOT=str(tmp_path / "absent"))
    unavailable = build_v553_release_readiness_report(
        unavailable_settings,
        preproduction_report={"accepted": False, "checks": [], "resource_availability": {}},
    )
    assert unavailable["readiness_states"]["external_evidence"] == "unavailable"


def test_invalid_origins_admin_default_and_relative_evidence_root_fail_runtime_validation(tmp_path):
    settings = _settings(
        tmp_path,
        ENVIRONMENT="preproduction",
        MFU_IAM_TEMPLATE_SHELL_BASE_URL="https://shell.example.test/path",
        MFU_IAM_HANDOFF_FRONTEND_URL="https://atdr.example.test/path",
        MFU_IAM_HANDOFF_ALLOWED_ORIGINS="https://*.example.test,https://shell.example.test/path",
        MFU_IAM_DEFAULT_ROLE="admin",
        MFU_IAM_HANDOFF_COOKIE_SECURE=True,
        ATDR_ACCEPTANCE_EVIDENCE_ROOT="relative/evidence",
    )
    issues = validate_runtime_settings(settings)
    rendered = " ".join(issues)
    assert "valid approved http(s) origin" in rendered
    assert "exact approved origins" in rendered
    assert "admin requires an explicit group mapping" in rendered
    assert "absolute private path" in rendered


def test_cors_contract_is_explicit_and_rejects_wildcards(tmp_path):
    settings = _settings(
        tmp_path,
        CORS_ALLOWED_METHODS="GET,POST,OPTIONS",
        CORS_ALLOWED_HEADERS="Authorization,Content-Type,X-Request-ID",
        CORS_EXPOSED_HEADERS="X-Request-ID,X-Total-Count",
    )
    assert settings.cors_methods == ["GET", "POST", "OPTIONS"]
    assert settings.cors_headers == ["Authorization", "Content-Type", "X-Request-ID"]
    assert settings.cors_expose_headers == ["X-Request-ID", "X-Total-Count"]
    assert not validate_runtime_settings(settings)

    unsafe = _settings(
        tmp_path,
        CORS_ALLOWED_METHODS="*",
        CORS_ALLOWED_HEADERS="*",
    )
    rendered = " ".join(validate_runtime_settings(unsafe))
    assert "CORS_ALLOWED_METHODS must not include '*'" in rendered
    assert "CORS_ALLOWED_HEADERS must be explicit" in rendered


def test_readiness_endpoint_is_admin_only_and_has_no_authoritative_side_effects(monkeypatch):
    monkeypatch.setenv("ATDR_AUTH_MODE", "local_recovery")
    get_settings.cache_clear()
    client, session_factory = _client_with_session()
    try:
        admin_token = create_access_token("admin", "admin")
        analyst_token = create_access_token("analyst", "analyst")
        admin_headers = {"Authorization": f"Bearer {admin_token}"}
        analyst_headers = {"Authorization": f"Bearer {analyst_token}"}
        with session_factory() as db:
            before = (
                db.scalar(select(func.count(DetectionRun.id))) or 0,
                db.scalar(select(func.count(MLModelRun.id))) or 0,
                db.scalar(select(func.count(ResponseAction.id))) or 0,
            )
        assert client.get("/api/operations/release-readiness").status_code == 401
        assert client.get("/api/operations/release-readiness", headers=analyst_headers).status_code == 403
        response = client.get("/api/operations/release-readiness", headers=admin_headers)
        assert response.status_code == 200
        payload = response.json()
        assert payload["production_ready"] is False
        assert payload["secrets_exposed"] is False
        assert "v553-private-handoff-test-value" not in json.dumps(payload)

        logout = client.post("/api/auth/logout", headers=admin_headers)
        assert logout.status_code == 204
        cookie = logout.headers.get("set-cookie", "")
        assert "atdr_session=" in cookie
        assert "Max-Age=0" in cookie
        with session_factory() as db:
            after = (
                db.scalar(select(func.count(DetectionRun.id))) or 0,
                db.scalar(select(func.count(MLModelRun.id))) or 0,
                db.scalar(select(func.count(ResponseAction.id))) or 0,
            )
        assert after == before
    finally:
        app.dependency_overrides.clear()
        get_settings.cache_clear()


def test_expired_session_disabled_user_malformed_and_replayed_handoffs_fail_closed(monkeypatch):
    _configure_handoff(monkeypatch)
    client, session_factory = _handoff_client()
    try:
        expired = create_access_token("admin", "admin", expires_delta=timedelta(seconds=-1))
        assert client.get("/api/auth/me", headers={"Authorization": f"Bearer {expired}"}).status_code == 401

        active = create_access_token("analyst", "analyst")
        with session_factory() as db:
            user = db.scalar(select(User).where(User.username == "analyst"))
            assert user is not None
            user.is_active = False
            db.commit()
        assert client.get("/api/auth/me", headers={"Authorization": f"Bearer {active}"}).status_code == 401

        class MalformedResponse:
            status_code = 200

            @staticmethod
            def json() -> list[str]:
                return ["not", "an", "object"]

        monkeypatch.setattr(mfu_iam_service.requests, "post", lambda *args, **kwargs: MalformedResponse())
        malformed = client.post(
            "/api/auth/mfu-iam/handoff/consume",
            data={"handoff_code": "private-malformed-code"},
            headers={"Origin": "http://template-shell.test"},
            follow_redirects=False,
        )
        assert "handoff_invalid_response" in malformed.headers["location"]
        assert "private-malformed-code" not in malformed.headers["location"]

        class ReplayedResponse:
            status_code = 409

        monkeypatch.setattr(mfu_iam_service.requests, "post", lambda *args, **kwargs: ReplayedResponse())
        replayed = client.post(
            "/api/auth/mfu-iam/handoff/consume",
            data={"handoff_code": "private-replayed-code"},
            headers={"Origin": "http://template-shell.test"},
            follow_redirects=False,
        )
        assert "handoff_expired_or_used" in replayed.headers["location"]
        assert "private-replayed-code" not in replayed.headers["location"]
    finally:
        app.dependency_overrides.clear()
        get_settings.cache_clear()


def test_repository_secret_scan_never_returns_matched_value_and_sbom_is_bounded(tmp_path):
    secret = "AIza" + "A" * 35
    (tmp_path / "safe.py").write_text("print('ok')\n", encoding="utf-8")
    (tmp_path / "unsafe.py").write_text(f"value = '{secret}'\n", encoding="utf-8")
    (tmp_path / "requirements.lock.txt").write_text(
        "fastapi==1.2.3 \\\n    --hash=sha256:" + "a" * 64 + "\n",
        encoding="utf-8",
    )
    frontend = tmp_path / "frontend"
    frontend.mkdir()
    (frontend / "package-lock.json").write_text(
        json.dumps({"packages": {"": {"name": "frontend"}, "node_modules/react": {"name": "react", "version": "19.0.0"}}}),
        encoding="utf-8",
    )

    report = scan_repository_paths(tmp_path, ["safe.py", "unsafe.py"])
    assert report["ok"] is False
    assert report["findings"] == [{"path": "unsafe.py", "rule": "google_api_key"}]
    assert secret not in json.dumps(report)
    sbom = build_cyclonedx_sbom(tmp_path)
    assert sbom["bomFormat"] == "CycloneDX"
    assert {(item["name"], item["version"]) for item in sbom["components"]} == {
        ("fastapi", "1.2.3"),
        ("react", "19.0.0"),
    }


def test_team_rehearsal_preflight_is_path_safe_and_never_executes(monkeypatch, tmp_path):
    root = tmp_path / "ATDR clean clone"
    template = tmp_path / "private MFU shell"
    (root / "config").mkdir(parents=True)
    (root / ".env.shell.example").write_text("RESPONSE_SIMULATION=true\n", encoding="utf-8")
    required = ["backend-node/package.json", "frontend-vue/package.json"]
    (root / "config/mfu-shell-contract.json").write_text(json.dumps({"required_paths": required}), encoding="utf-8")
    for relative in required:
        path = template / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(team_rehearsal, "_command", lambda _name: "available")
    monkeypatch.setattr(team_rehearsal, "_source_clean", lambda _root: True)

    report = team_rehearsal.build_team_runtime_preflight(
        root=root,
        template_root=template,
        shell_package=None,
        private_config_root=None,
    )
    encoded = json.dumps(report)
    assert report["ok"] is True
    assert report["status"] == "ready_for_disposable_rehearsal"
    assert report["configured_database_accessed"] is False
    assert report["configured_shell_modified"] is False
    assert str(template) not in encoded


def test_team_rehearsal_handoff_contract_requires_safe_shell_status():
    report = {
        "ok": True,
        "all_services_ready": True,
        "configuration": {
            "auth_mode": "template_shell",
            "response_simulation": True,
            "secrets_exposed": False,
        },
        "identity_provider": {
            "iam_proxy_configured": True,
            "google_auth_ready": True,
            "acceptance_requires_real_sign_in": True,
            "account_scope_acceptance": "not_validated",
            "secrets_exposed": False,
        },
        "secrets_exposed": False,
    }
    assert team_rehearsal._login_handoff_contract_ready(report) is True
    report["identity_provider"]["account_scope_acceptance"] = "accepted_without_real_sign_in"
    assert team_rehearsal._login_handoff_contract_ready(report) is False


def test_team_rehearsal_start_stage_can_avoid_inherited_capture_handles(monkeypatch, tmp_path):
    recorded: dict[str, object] = {}

    class Result:
        returncode = 0

    def fake_run(*args, **kwargs):
        recorded.update(kwargs)
        return Result()

    monkeypatch.setattr(team_rehearsal.subprocess, "run", fake_run)
    assert team_rehearsal._run_stage(
        "powershell.exe",
        ["-File", "start_system.ps1"],
        cwd=tmp_path,
        timeout=10,
        capture_output=False,
    ) is True
    assert recorded["stdout"] is team_rehearsal.subprocess.DEVNULL
    assert recorded["stderr"] is team_rehearsal.subprocess.DEVNULL
    assert "capture_output" not in recorded
