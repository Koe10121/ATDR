from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

from atdr.app.core.config import get_settings
from atdr.app.main import app
from atdr.app.services import mfu_iam_service
from atdr.app.services.template_shell_auth import build_template_google_auth_status
from atdr.scripts.harden_template_google_auth import harden_template_google_auth
from atdr.tests.test_mfu_iam_handoff import _client, _configure_handoff


def _supported_node_environment(tmp_path: Path) -> dict[str, str]:
    binary_dir = tmp_path / "supported-node"
    binary_dir.mkdir(exist_ok=True)
    (binary_dir / "node.cmd").write_text("@echo off\r\necho v20.19.1\r\n", encoding="utf-8")
    (binary_dir / "npm.cmd").write_text("@echo off\r\nexit /b 0\r\n", encoding="utf-8")
    environment = os.environ.copy()
    environment["PATH"] = f"{binary_dir}{os.pathsep}{environment.get('PATH', '')}"
    return environment


def _write_shell_fixture(root: Path, *, frontend_id: str, backend_id: str, legacy: bool) -> None:
    frontend_env = root / "frontend-vue/.env.localdev"
    backend_env = root / "backend-node/.env.local"
    main_js = root / "frontend-vue/src/main.js"
    account_js = root / "backend-node/server/Project/accounts/service/account.js"
    sign_in = root / "frontend-vue/src/projects/components/dialog/SignIn.vue"
    for path in (frontend_env, backend_env, main_js, account_js, sign_in):
        path.parent.mkdir(parents=True, exist_ok=True)
    frontend_env.write_text(f"VUE_APP_CLIENTID={frontend_id}\n", encoding="utf-8")
    backend_env.write_text(f"GOOGLE_CLIENT_ID={backend_id}\n", encoding="utf-8")
    frontend_expression = (
        "process.env.VUE_APP_CLIENTID || '123456-legacyclient.apps.googleusercontent.com'"
        if legacy
        else "process.env.VUE_APP_CLIENTID"
    )
    backend_expression = (
        "process.env.GOOGLE_CLIENT_ID ||\n"
        "                process.env.VUE_APP_CLIENTID ||\n"
        "                '123456-legacyclient.apps.googleusercontent.com'"
        if legacy
        else "process.env.GOOGLE_CLIENT_ID"
    )
    main_js.write_text(
        "import GAuth from 'vue-google-oauth2'\n"
        "const gauthOption = {\n"
        f"  clientId: {frontend_expression},\n"
        "  scope: 'profile email'\n"
        "}\n",
        encoding="utf-8",
    )
    account_js.write_text(
        "exports.verifyIdTokenGoogle = async function (request, response) {\n"
        f"            const audience = {backend_expression};\n"
        "            const client = new OAuth2Client(audience || undefined);\n"
        "};\n",
        encoding="utf-8",
    )
    sign_in.write_text(
        "<script>\nexport default {\n"
        "        methods: {\n"
        "          async onAuthenGoogle() {\n"
        "            try { await this.$gAuth.signIn() } catch (err) {\n"
        "              this.$store.commit('dialog/showError', {\n"
        "                message: this.$t('auth.signIn.errors.google'),\n"
        "                status: true\n"
        "              })\n"
        "            }\n"
        "          },\n"
        "        },\n"
        "}\n</script>\n",
        encoding="utf-8",
    )


def test_google_auth_status_requires_matching_private_configuration_without_exposure(tmp_path):
    shell = tmp_path / "shell"
    private_frontend_id = "frontend-private-client.apps.googleusercontent.com"
    private_backend_id = "backend-private-client.apps.googleusercontent.com"
    _write_shell_fixture(
        shell,
        frontend_id=private_frontend_id,
        backend_id=private_backend_id,
        legacy=False,
    )

    status = build_template_google_auth_status(shell)
    encoded = json.dumps(status)

    assert status["ready"] is False
    assert status["diagnosis"] == "client_id_mismatch"
    assert status["client_ids_match"] is False
    assert status["secrets_exposed"] is False
    assert private_frontend_id not in encoded
    assert private_backend_id not in encoded


def test_google_auth_hardener_removes_fallbacks_and_preserves_private_env(tmp_path):
    shell = tmp_path / "shell"
    client_id = "approved-client.apps.googleusercontent.com"
    _write_shell_fixture(shell, frontend_id=client_id, backend_id=client_id, legacy=True)
    frontend_env = shell / "frontend-vue/.env.localdev"
    backend_env = shell / "backend-node/.env.local"
    original_frontend_env = frontend_env.read_bytes()
    original_backend_env = backend_env.read_bytes()

    preview = harden_template_google_auth(shell, runtime_root=tmp_path / "runtime", apply=False)
    applied = harden_template_google_auth(shell, runtime_root=tmp_path / "runtime", apply=True)
    status = build_template_google_auth_status(shell)

    assert preview["changes_required"] is True
    assert preview["changed_file_count"] == 0
    assert applied["changed_file_count"] == 3
    assert applied["backup_created"] is True
    assert applied["secrets_exposed"] is False
    assert status["ready"] is True
    assert status["frontend_legacy_fallback_present"] is False
    assert status["backend_legacy_fallback_present"] is False
    assert frontend_env.read_bytes() == original_frontend_env
    assert backend_env.read_bytes() == original_backend_env
    assert "AUTH_GOOGLE_NOT_CONFIGURED" in (shell / "backend-node/server/Project/accounts/service/account.js").read_text(
        encoding="utf-8"
    )
    assert "googleSignInMessage" in (
        shell / "frontend-vue/src/projects/components/dialog/SignIn.vue"
    ).read_text(encoding="utf-8")


def test_expired_handoff_returns_actionable_error_without_code_or_secret(monkeypatch):
    _configure_handoff(monkeypatch)

    class ExpiredResponse:
        status_code = 410

    monkeypatch.setattr(mfu_iam_service.requests, "post", lambda *args, **kwargs: ExpiredResponse())
    client, _ = _client()
    try:
        response = client.post(
            "/api/auth/mfu-iam/handoff/consume",
            data={"handoff_code": "one-time-private-code"},
            headers={"Origin": "http://template-shell.test"},
            follow_redirects=False,
        )

        assert response.status_code == 303
        assert "handoff_error=handoff_expired_or_used" in response.headers["location"]
        assert "one-time-private-code" not in response.headers["location"]
        assert "test-bridge-secret-that-must-not-leak" not in response.headers["location"]
    finally:
        app.dependency_overrides.clear()
        get_settings.cache_clear()


def test_unapproved_school_domain_returns_safe_domain_error(monkeypatch):
    _configure_handoff(monkeypatch)

    class OtherDomainResponse:
        status_code = 200

        @staticmethod
        def json() -> dict:
            return {"data": {"email": "person@example.org", "subject": "external-1", "groups": []}}

    monkeypatch.setattr(mfu_iam_service.requests, "post", lambda *args, **kwargs: OtherDomainResponse())
    client, _ = _client()
    try:
        response = client.post(
            "/api/auth/mfu-iam/handoff/consume",
            data={"handoff_code": "one-time-private-code"},
            headers={"Origin": "http://template-shell.test"},
            follow_redirects=False,
        )

        assert response.status_code == 303
        assert "handoff_error=domain_not_allowed" in response.headers["location"]
        assert "person%40example.org" not in response.headers["location"]
    finally:
        app.dependency_overrides.clear()
        get_settings.cache_clear()


def test_react_login_has_specific_safe_handoff_messages():
    root = Path(__file__).resolve().parents[2]
    content = (root / "frontend/src/pages/LoginPage.tsx").read_text(encoding="utf-8")

    for code in (
        "handoff_origin_not_allowed",
        "handoff_expired_or_used",
        "handoff_backend_unavailable",
        "account_disabled",
        "identity_conflict",
        "domain_not_allowed",
    ):
        assert code in content
    assert "raw provider" not in content.lower()


def test_team_setup_reports_provider_blocker_when_google_client_is_missing(tmp_path):
    root = Path(__file__).resolve().parents[2]
    portable_root = tmp_path / "ATDR copy"
    scripts = portable_root / "scripts"
    scripts.mkdir(parents=True)
    for name in ("system_common.ps1", "setup_team.ps1"):
        shutil.copy2(root / "scripts" / name, scripts / name)
    (portable_root / "config").mkdir()
    shutil.copy2(root / "config/mfu-shell-contract.json", portable_root / "config/mfu-shell-contract.json")
    shutil.copy2(root / ".env.shell.example", portable_root / ".env.shell.example")

    shell = tmp_path / "MFU shell"
    required = (
        "backend-node/package.json",
        "backend-node/server.js",
        "backend-node/server/Project/atdr/atdr_handoff.routes.js",
        "backend-node/server/Project/atdr/service/atdr_handoff.js",
        "frontend-vue/package.json",
        "frontend-vue/src/projects/utils/atdr-handoff.js",
    )
    for relative in required:
        path = shell / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{}" if path.name == "package.json" else "// test fixture", encoding="utf-8")
    (shell / "backend-node/.env.local").write_text(
        "\n".join(
            (
                "MONGODB=mongodb://127.0.0.1:27017/test",
                "IAM_SDK_BASE_URL=https://iam.invalid",
                "IAM_SDK_CLIENT_ID=test-client",
                "IAM_SDK_CLIENT_SECRET=private-value",
                "IAM_SDK_AUDIENCE=test-api",
                "IAM_ADMIN_CLIENT_ID=test-admin",
                "IAM_ADMIN_CLIENT_SECRET=private-admin-value",
                "IAM_ADMIN_AUDIENCE=test-admin-api",
                "PROJECT_PERMISSION_TYPE_TITLE=Test Administration",
                "PROJECT_PERMISSION_GROUP_TITLE=Test Admin",
                "PROJECT_AUTH_REQUIRE_2FA=true",
                "GOOGLE_CLIENT_ID=",
            )
        )
        + "\n",
        encoding="utf-8",
    )
    (shell / "frontend-vue/.env.localdev").parent.mkdir(parents=True, exist_ok=True)
    (shell / "frontend-vue/.env.localdev").write_text("VUE_APP_CLIENTID=\n", encoding="utf-8")

    result = subprocess.run(
        [
            "powershell.exe",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(scripts / "setup_team.ps1"),
            "-TemplateRoot",
            str(shell),
            "-DryRun",
        ],
        cwd=portable_root,
        env=_supported_node_environment(tmp_path),
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    output = result.stdout + result.stderr
    assert result.returncode == 0
    assert "Set VUE_APP_CLIENTID" in output
    assert "Installation can proceed" in output
    assert "VUE_APP_CLIENTID" in output
    assert "Installation can proceed" in output
    assert "private-value" not in output
    assert "private-admin-value" not in output
    assert "FullyQualifiedErrorId" not in output
    assert "At " not in output

    required = subprocess.run(
        [
            "powershell.exe",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(scripts / "setup_team.ps1"),
            "-TemplateRoot",
            str(shell),
            "-DryRun",
            "-RequireProviderReady",
        ],
        cwd=portable_root,
        env=_supported_node_environment(tmp_path),
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    required_output = required.stdout + required.stderr
    assert required.returncode == 1
    assert "identity provider is not ready" in required_output
    assert "private-value" not in required_output
