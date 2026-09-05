from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

from atdr.app.core.config import Settings, get_settings, validate_runtime_settings
from atdr.app.main import app
from atdr.tests.test_api import _client


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _supported_node_environment(tmp_path: Path) -> dict[str, str]:
    binary_dir = tmp_path / "supported-node"
    binary_dir.mkdir(exist_ok=True)
    (binary_dir / "node.cmd").write_text("@echo off\r\necho v20.19.1\r\n", encoding="utf-8")
    (binary_dir / "npm.cmd").write_text("@echo off\r\nexit /b 0\r\n", encoding="utf-8")
    environment = os.environ.copy()
    environment["PATH"] = f"{binary_dir}{os.pathsep}{environment.get('PATH', '')}"
    return environment


def test_template_shell_profile_does_not_require_unrelated_b2b_credentials():
    settings = Settings(
        _env_file=None,
        ATDR_AUTH_MODE="template_shell",
        MFU_IAM_ENABLED=True,
        MFU_IAM_TEMPLATE_SHELL_ENABLED=True,
        MFU_IAM_TEMPLATE_SHELL_BASE_URL="http://127.0.0.1:8214",
        MFU_IAM_TEMPLATE_SHELL_LAUNCH_URL="http://127.0.0.1:8080/#/pages/login",
        MFU_IAM_ALLOWED_DOMAINS="lamduan.mfu.ac.th",
        MFU_IAM_HANDOFF_ENABLED=True,
        MFU_IAM_HANDOFF_SHARED_SECRET="private-test-value",
        MFU_IAM_HANDOFF_ALLOWED_ORIGINS="http://127.0.0.1:8080",
        MFU_IAM_BASE_URL="",
        MFU_IAM_CLIENT_ID="",
        MFU_IAM_CLIENT_SECRET="",
        MFU_IAM_AUDIENCE="",
    )

    issues = validate_runtime_settings(settings)

    assert not any("MFU_IAM_BASE_URL" in issue for issue in issues)
    assert not any("MFU_IAM_CLIENT_ID" in issue for issue in issues)
    assert not any("MFU_IAM_CLIENT_SECRET" in issue for issue in issues)
    assert not any("MFU_IAM_AUDIENCE" in issue for issue in issues)


def test_template_shell_profile_rejects_documentation_secret_placeholders():
    settings = Settings(
        _env_file=None,
        ATDR_AUTH_MODE="template_shell",
        MFU_IAM_ENABLED=True,
        MFU_IAM_TEMPLATE_SHELL_ENABLED=True,
        MFU_IAM_TEMPLATE_SHELL_BASE_URL="http://127.0.0.1:8214",
        MFU_IAM_TEMPLATE_SHELL_LAUNCH_URL="http://127.0.0.1:8080/#/pages/login",
        MFU_IAM_ALLOWED_DOMAINS="lamduan.mfu.ac.th",
        MFU_IAM_HANDOFF_ENABLED=True,
        MFU_IAM_HANDOFF_SHARED_SECRET="replace-during-private-setup",
        MFU_IAM_HANDOFF_ALLOWED_ORIGINS="http://127.0.0.1:8080",
        JWT_SECRET_KEY="replace-during-private-setup",
    )

    issues = validate_runtime_settings(settings)

    assert any("JWT_SECRET_KEY" in issue for issue in issues)
    assert any("MFU_IAM_HANDOFF_SHARED_SECRET" in issue for issue in issues)


def test_portable_shell_example_keeps_external_assistant_disabled_by_default():
    env_example = Path(__file__).resolve().parents[2] / ".env.shell.example"
    content = env_example.read_text(encoding="utf-8")

    assert "ASSISTANT_ENABLED=false" in content
    assert 'ASSISTANT_PROVIDER="disabled"' in content
    assert "ASSISTANT_LLM_ENABLED=false" in content
    assert "ASSISTANT_ALLOW_RAW_LOG_CONTEXT=false" in content


def test_portable_shell_uses_google_compatible_localhost_origin():
    root = Path(__file__).resolve().parents[2]
    env_example = (root / ".env.shell.example").read_text(encoding="utf-8")
    setup_script = (root / "scripts/setup_team.ps1").read_text(encoding="utf-8")
    start_script = (root / "scripts/start_system.ps1").read_text(encoding="utf-8")

    assert 'MFU_IAM_TEMPLATE_SHELL_LAUNCH_URL="http://localhost:8080/#/pages/login"' in env_example
    assert 'MFU_IAM_HANDOFF_ALLOWED_ORIGINS="http://localhost:8080,http://127.0.0.1:8080"' in env_example
    assert 'MFU_IAM_TEMPLATE_SHELL_LAUNCH_URL = "http://localhost:8080/#/pages/login"' in setup_script
    assert 'Start-Process "http://localhost:8080/#/pages/login"' in start_script


def test_template_shell_profile_blocks_local_login_and_reports_safe_mode(monkeypatch):
    monkeypatch.setenv("ATDR_AUTH_MODE", "template_shell")
    monkeypatch.setenv("MFU_IAM_ENABLED", "true")
    monkeypatch.setenv("MFU_IAM_TEMPLATE_SHELL_ENABLED", "true")
    monkeypatch.setenv("MFU_IAM_TEMPLATE_SHELL_BASE_URL", "http://127.0.0.1:8214")
    monkeypatch.setenv("MFU_IAM_TEMPLATE_SHELL_LAUNCH_URL", "http://127.0.0.1:8080/#/pages/login")
    monkeypatch.setenv("MFU_IAM_ALLOWED_DOMAINS", "lamduan.mfu.ac.th")
    monkeypatch.setenv("MFU_IAM_HANDOFF_ENABLED", "true")
    monkeypatch.setenv("MFU_IAM_HANDOFF_SHARED_SECRET", "private-value-that-must-not-leak")
    monkeypatch.setenv("MFU_IAM_HANDOFF_ALLOWED_ORIGINS", "http://127.0.0.1:8080")
    get_settings.cache_clear()
    client = _client()
    try:
        denied = client.post("/api/auth/login", json={"username": "admin", "password": "admin123"})
        assert denied.status_code == 403
        assert "MFU application shell" in denied.json()["detail"]

        public = client.get("/api/auth/mfu-iam/public-status")
        payload = public.json()
        assert payload["auth_mode"] == "template_shell"
        assert payload["template_shell_required"] is True
        assert payload["local_login_enabled"] is False
        assert payload["handoff_ready"] is True
        assert payload["secrets_exposed"] is False
        assert "private-value-that-must-not-leak" not in json.dumps(payload)
    finally:
        app.dependency_overrides.clear()
        get_settings.cache_clear()


def test_local_login_works_only_in_explicit_recovery_profile(monkeypatch):
    monkeypatch.setenv("ATDR_AUTH_MODE", "local_recovery")
    get_settings.cache_clear()
    client = _client()
    try:
        response = client.post("/api/auth/login", json={"username": "analyst", "password": "analyst123"})
        assert response.status_code == 200
        public = client.get("/api/auth/mfu-iam/public-status").json()
        assert public["auth_mode"] == "local_recovery"
        assert public["local_login_enabled"] is True
        assert public["template_shell_required"] is False
    finally:
        app.dependency_overrides.clear()
        get_settings.cache_clear()


def test_incomplete_runtime_configuration_returns_clean_503_without_secret_detail():
    client = _client()
    original = getattr(app.state, "configuration_issues", ())
    app.state.configuration_issues = ("private-value-must-not-be-returned",)
    try:
        response = client.get("/api/alerts")
        assert response.status_code == 503
        payload = response.json()
        assert payload["issue_count"] == 1
        assert payload["secrets_exposed"] is False
        assert "private-value-must-not-be-returned" not in json.dumps(payload)
        assert client.get("/health/live").status_code == 200
        assert client.get("/api/auth/mfu-iam/public-status").status_code == 200
    finally:
        app.state.configuration_issues = original
        app.dependency_overrides.clear()


def test_active_runtime_files_have_no_developer_machine_path():
    root = Path(__file__).resolve().parents[2]
    paths = [
        root / "atdr/app/services/template_bridge_contract.py",
        root / "atdr/scripts/validate_template_bridge_contract.py",
        root / "atdr/scripts/validate_template_shell_runtime.py",
        root / "atdr/scripts/apply_template_atdr_launcher.py",
        root / "scripts/setup_team.ps1",
        root / "scripts/start_system.ps1",
        root / "scripts/check_system.ps1",
        root / "scripts/stop_system.ps1",
        root / "scripts/system_common.ps1",
        root / "scripts/setup_team.cmd",
        root / "scripts/start_system.cmd",
        root / "scripts/check_system.cmd",
        root / "scripts/stop_system.cmd",
        root / ".env.shell.example",
    ]
    corpus = "\n".join(path.read_text(encoding="utf-8") for path in paths)
    assert ("C:" + "\\Users\\" + "User") not in corpus
    assert "Desktop\\ATDR" not in corpus


def test_team_setup_prefers_versioned_python_dependency_lock():
    root = Path(__file__).resolve().parents[2]
    setup_script = (root / "scripts/setup_team.ps1").read_text(encoding="utf-8")
    lock_file = root / "requirements.lock.txt"

    assert lock_file.exists()
    assert "requirements.lock.txt" in setup_script
    assert "requirements.txt" in setup_script
    assert "requirements.lock.txt" in setup_script.split("requirements.txt", maxsplit=1)[0]


def test_team_setup_dry_run_works_from_path_with_spaces_and_preserves_database(tmp_path):
    root = Path(__file__).resolve().parents[2]
    portable_root = tmp_path / "ATDR Team Copy"
    scripts = portable_root / "scripts"
    scripts.mkdir(parents=True)
    for name in ("system_common.ps1", "setup_team.ps1"):
        shutil.copy2(root / "scripts" / name, scripts / name)
    (portable_root / "config").mkdir()
    shutil.copy2(root / "config/mfu-shell-contract.json", portable_root / "config/mfu-shell-contract.json")
    shutil.copy2(root / ".env.shell.example", portable_root / ".env.shell.example")
    database = portable_root / "atdr.db"
    database.write_bytes(b"existing-database-must-not-change")
    before = _sha256(database)

    template = tmp_path / "MFU Shell Copy"
    required = [
        "backend-node/package.json",
        "backend-node/server.js",
        "backend-node/server/Project/atdr/atdr_handoff.routes.js",
        "backend-node/server/Project/atdr/service/atdr_handoff.js",
        "frontend-vue/package.json",
        "frontend-vue/src/projects/utils/atdr-handoff.js",
    ]
    for relative in required:
        path = template / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{}" if path.name == "package.json" else "// safe test fixture", encoding="utf-8")
    (template / "backend-node/.env.local").write_text(
        "\n".join(
            (
                'MONGODB="mongodb://127.0.0.1:27017/test"',
                'IAM_SDK_BASE_URL="https://iam.invalid"',
                'IAM_SDK_CLIENT_ID="test-project-client"',
                'IAM_SDK_CLIENT_SECRET="private-sdk-secret"',
                'IAM_SDK_AUDIENCE="test-api"',
                'IAM_ADMIN_CLIENT_ID="test-admin-client"',
                'IAM_ADMIN_CLIENT_SECRET="private-admin-secret"',
                'IAM_ADMIN_AUDIENCE="test-admin-api"',
                'PROJECT_PERMISSION_TYPE_TITLE="Test Administration"',
                'PROJECT_PERMISSION_GROUP_TITLE="Test Admin"',
                'PROJECT_AUTH_REQUIRE_2FA="true"',
                'KEY="private-test-key"',
                'GOOGLE_CLIENT_ID="approved-test-client.apps.googleusercontent.com"',
            )
        )
        + "\n",
        encoding="utf-8",
    )
    (template / "frontend-vue/.env.localdev").parent.mkdir(parents=True, exist_ok=True)
    (template / "frontend-vue/.env.localdev").write_text(
        'VUE_APP_CLIENTID="approved-test-client.apps.googleusercontent.com"\n',
        encoding="utf-8",
    )
    (template / "frontend-vue/src/main.js").parent.mkdir(parents=True, exist_ok=True)
    (template / "frontend-vue/src/main.js").write_text(
        "import GAuth from 'vue-google-oauth2'\n"
        "const googleClientId = String(process.env.VUE_APP_CLIENTID || '').trim()\n"
        "if (!googleClientId) throw new Error('Google sign-in is not configured')\n"
        "const gauthOption = { clientId: googleClientId }\n",
        encoding="utf-8",
    )
    (template / "backend-node/server/Project/accounts/service/account.js").parent.mkdir(parents=True, exist_ok=True)
    (template / "backend-node/server/Project/accounts/service/account.js").write_text(
        "const audience = String(process.env.GOOGLE_CLIENT_ID || '').trim();\n"
        "if (!audience) return response.status(503).json({ code: 'AUTH_GOOGLE_NOT_CONFIGURED' });\n",
        encoding="utf-8",
    )

    command = [
        "powershell.exe",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        str(scripts / "setup_team.ps1"),
        "-TemplateRoot",
        str(template),
        "-DryRun",
    ]
    result = subprocess.run(
        command,
        cwd=portable_root,
        env=_supported_node_environment(tmp_path),
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert "Dry run passed" in result.stdout
    assert _sha256(database) == before
    assert not (portable_root / ".env").exists()
    assert "private-test-key" not in result.stdout + result.stderr


def test_stop_script_removes_stale_pid_metadata_without_killing_process(tmp_path):
    root = Path(__file__).resolve().parents[2]
    portable_root = tmp_path / "ATDR stop test"
    scripts = portable_root / "scripts"
    runtime = portable_root / ".atdr_runtime"
    scripts.mkdir(parents=True)
    runtime.mkdir(parents=True)
    for name in ("system_common.ps1", "stop_system.ps1"):
        shutil.copy2(root / "scripts" / name, scripts / name)
    (runtime / "system-processes.json").write_text(
        json.dumps({"processes": [{"name": "stale", "pid": 2147483000, "started_at": "2000-01-01T00:00:00Z"}]}),
        encoding="utf-8",
    )

    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(scripts / "stop_system.ps1")],
        cwd=portable_root,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert not (runtime / "system-processes.json").exists()


def test_runtime_classification_distinguishes_healthy_partial_and_stale_states():
    root = Path(__file__).resolve().parents[2]
    common = str(root / "scripts/system_common.ps1").replace("'", "''")
    expected = "@('atdr-backend','atdr-frontend','shell-backend','shell-frontend')"

    def classify(active: str, readiness: str) -> dict[str, object]:
        command = (
            f". '{common}'; "
            f"$result = Get-TrackedSystemRuntimeClassification -TrackedNames {expected} "
            f"-ActiveNames {active} -ServiceReadiness {readiness}; "
            "$result | ConvertTo-Json -Compress"
        )
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        return json.loads(result.stdout)

    all_ready = "@{a=$true;b=$true;c=$true;d=$true}"
    healthy = classify(expected, all_ready)
    partial = classify("@('atdr-backend','atdr-frontend')", all_ready)
    stale = classify("@()", "@{a=$false;b=$false;c=$false;d=$false}")

    assert healthy["state"] == "healthy"
    assert healthy["active_count"] == 4
    assert healthy["ready_count"] == 4
    assert healthy["secrets_exposed"] is False
    assert partial["state"] == "partial"
    assert partial["missing_active"] == ["shell-backend", "shell-frontend"]
    assert stale["state"] == "stale"


def test_startup_diagnostics_use_supported_commands_and_hide_machine_paths(tmp_path):
    root = Path(__file__).resolve().parents[2]
    scripts = tmp_path / "portable startup" / "scripts"
    scripts.mkdir(parents=True)
    for name in ("system_common.ps1", "check_system.ps1"):
        shutil.copy2(root / "scripts" / name, scripts / name)

    result = subprocess.run(
        [
            "powershell.exe",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(scripts / "check_system.ps1"),
            "-Json",
        ],
        cwd=scripts.parent,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode in (0, 1), result.stderr
    assert result.stdout.strip(), result.stderr
    report = json.loads(result.stdout)
    encoded = json.dumps(report)

    assert "project_root" not in report
    assert "template_root" not in report
    assert report["project_root_configured"] is True
    assert report["template_root_configured"] is False
    assert report["secrets_exposed"] is False
    assert str(tmp_path) not in encoded
    assert ".\\scripts\\setup_team.cmd" in report["recommended_action"]

    startup_sources = "\n".join(
        (root / "scripts" / name).read_text(encoding="utf-8")
        for name in ("start_system.ps1", "check_system.ps1", "stop_system.ps1", "setup_team.ps1")
    )
    assert "already running and all four components are healthy" in startup_sources
    assert ".\\scripts\\check_system.cmd" in startup_sources
    assert ".\\scripts\\stop_system.cmd" in startup_sources
    assert "Start: .\\scripts\\start_system.cmd" in startup_sources
