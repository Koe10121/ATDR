from __future__ import annotations

import json
import os
import shutil
import subprocess
import zipfile
from pathlib import Path

import pytest

from atdr.app.services.mfu_shell_package_service import (
    BUILD_CONFIRMATION,
    INSTALL_CONFIRMATION,
    ShellPackageError,
    build_shell_package,
    install_shell_package,
    verify_installed_shell,
    verify_shell_package,
)


def _write(path: Path, content: str | bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, bytes):
        path.write_bytes(content)
    else:
        path.write_text(content, encoding="utf-8")


def _shell_fixture(root: Path) -> None:
    files = {
        "backend-node/package.json": '{"name":"shell-api","version":"1.0.0"}',
        "backend-node/package-lock.json": '{"name":"shell-api","lockfileVersion":3}',
        "backend-node/server.js": "require('./server/routes/app.routes')\n",
        "backend-node/server/routes/app.routes.js": "module.exports = {}\n",
        "backend-node/server/Project/atdr/atdr_handoff.routes.js": "module.exports = {}\n",
        "backend-node/server/Project/atdr/service/atdr_handoff.js": "module.exports = {}\n",
        "backend-node/scripts/bootstrap-mfuaidrivenlogbasedthreatdetectionandresponse-permissions.js": (
            "module.exports = {}\n"
        ),
        "frontend-vue/package.json": '{"name":"shell-ui","version":"1.0.0"}',
        "frontend-vue/package-lock.json": '{"name":"shell-ui","lockfileVersion":3}',
        "frontend-vue/src/main.js": "const clientId = process.env.VUE_APP_CLIENTID\n",
        "frontend-vue/src/projects/utils/atdr-handoff.js": "export const handoff = true\n",
    }
    for relative, content in files.items():
        _write(root / relative, content)
    _write(root / "backend-node/.env.local", "IAM_ADMIN_CLIENT_SECRET=must-never-enter-package\n")
    _write(root / "frontend-vue/.env.localdev", "VUE_APP_CLIENTID=must-never-enter-package\n")
    _write(root / "backend-node/public/account/private-profile.png", b"private-upload")
    _write(root / "frontend-vue/public/models/private-model.bin", b"model-artifact")
    _write(root / "frontend-vue/src/projects/views/Old.vue.bak-20260716", "backup")
    _write(root / "backend-node/test/private-fixture.test.js", "const secret = 'must-not-ship'\n")


def _contract(root: Path) -> Path:
    source = Path(__file__).resolve().parents[2] / "config/mfu-shell-contract.json"
    payload = json.loads(source.read_text(encoding="utf-8"))
    payload["package_release"]["release_version"] = "test-release-1"
    payload["package_release"]["source_template_version"] = "test-template"
    payload["package_release"]["archive_name"] = "test-shell.zip"
    payload["package_release"]["archive_sha256"] = "pending"
    payload["package_release"]["source_fingerprint"] = "pending"
    path = root / "mfu-shell-contract.json"
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return path


def _approved_package(tmp_path: Path) -> tuple[Path, Path, dict]:
    shell = tmp_path / "source shell"
    _shell_fixture(shell)
    contract_path = _contract(tmp_path)
    output = tmp_path / "release output"
    result = build_shell_package(
        source_root=shell,
        contract_path=contract_path,
        output_directory=output,
        confirmation=BUILD_CONFIRMATION,
        write=True,
    )
    contract = json.loads(contract_path.read_text(encoding="utf-8"))
    contract["package_release"]["archive_sha256"] = result["archive_sha256"]
    contract["package_release"]["source_fingerprint"] = result["source_fingerprint"]
    contract_path.write_text(json.dumps(contract, indent=2) + "\n", encoding="utf-8")
    return output / "test-shell.zip", contract_path, result


def test_sanitized_shell_package_is_deterministic_and_excludes_private_artifacts(tmp_path: Path):
    package, contract_path, first = _approved_package(tmp_path)
    shell = tmp_path / "source shell"
    second = build_shell_package(
        source_root=shell,
        contract_path=contract_path,
        output_directory=tmp_path / "second output",
        confirmation=BUILD_CONFIRMATION,
        write=True,
    )

    assert first["archive_sha256"] == second["archive_sha256"]
    assert first["source_fingerprint"] == second["source_fingerprint"]
    assert first["private_configuration_included"] is False
    assert first["secrets_exposed"] is False

    with zipfile.ZipFile(package) as archive:
        names = set(archive.namelist())
        rendered = b"\n".join(archive.read(name) for name in names)
    assert "mfu-shell-release.json" in names
    assert not any(Path(name).name.startswith(".env") for name in names)
    assert not any("/public/account/" in name for name in names)
    assert not any("/public/models/" in name for name in names)
    assert not any(".bak-" in name for name in names)
    assert b"must-never-enter-package" not in rendered
    assert verify_shell_package(package_path=package, contract_path=contract_path)["ok"] is True


def test_shell_package_rejects_hardcoded_provider_client(tmp_path: Path):
    shell = tmp_path / "source"
    _shell_fixture(shell)
    _write(
        shell / "frontend-vue/src/main.js",
        "const clientId = '123456789012-longlegacygoogleclientid.apps.googleusercontent.com'\n",
    )
    with pytest.raises(ShellPackageError, match="safety scan failed"):
        build_shell_package(
            source_root=shell,
            contract_path=_contract(tmp_path),
            output_directory=tmp_path / "output",
            confirmation=None,
            write=False,
        )


def test_shell_package_checksum_and_path_traversal_fail_closed(tmp_path: Path):
    package, contract_path, _ = _approved_package(tmp_path)
    tampered = tmp_path / "tampered.zip"
    shutil.copy2(package, tampered)
    with zipfile.ZipFile(tampered, "a") as archive:
        archive.writestr("unexpected.txt", "tamper")
    with pytest.raises(ShellPackageError, match="checksum"):
        verify_shell_package(package_path=tampered, contract_path=contract_path)

    traversal = tmp_path / "traversal.zip"
    with zipfile.ZipFile(traversal, "w") as archive:
        archive.writestr("../escape.txt", "unsafe")
    with pytest.raises(ShellPackageError, match="unsafe archive path"):
        verify_shell_package(package_path=traversal, contract_path=contract_path, require_contract_hash=False)


def test_shell_package_install_is_verified_idempotent_and_detects_source_drift(tmp_path: Path):
    package, contract_path, _ = _approved_package(tmp_path)
    first = install_shell_package(
        package_path=package,
        contract_path=contract_path,
        install_base=tmp_path / "installed shells",
        confirmation=INSTALL_CONFIRMATION,
    )
    second = install_shell_package(
        package_path=package,
        contract_path=contract_path,
        install_base=tmp_path / "installed shells",
        confirmation=INSTALL_CONFIRMATION,
    )
    installed = Path(first["install_root"])

    assert first["write_performed"] is True
    assert second["reused"] is True
    assert verify_installed_shell(shell_root=installed, contract_path=contract_path)["ok"] is True

    (installed / "backend-node/server.js").write_text("tampered\n", encoding="utf-8")
    with pytest.raises(ShellPackageError, match="integrity failed"):
        verify_installed_shell(shell_root=installed, contract_path=contract_path)


def test_team_setup_package_dry_run_is_path_safe_and_reports_one_provider_blocker(tmp_path: Path):
    root = Path(__file__).resolve().parents[2]
    package, contract_path, _ = _approved_package(tmp_path)
    portable = tmp_path / "ATDR teammate path with spaces"
    for relative in (
        "scripts/system_common.ps1",
        "scripts/setup_team.ps1",
        ".env.shell.example",
        "atdr/__init__.py",
        "atdr/app/__init__.py",
        "atdr/app/services/__init__.py",
        "atdr/app/services/mfu_shell_package_service.py",
        "atdr/scripts/__init__.py",
        "atdr/scripts/mfu_shell_package.py",
    ):
        target = portable / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(root / relative, target)
    (portable / "config").mkdir()
    shutil.copy2(contract_path, portable / "config/mfu-shell-contract.json")

    binary_dir = tmp_path / "supported node"
    binary_dir.mkdir()
    (binary_dir / "node.cmd").write_text("@echo off\r\necho v20.19.1\r\n", encoding="utf-8")
    (binary_dir / "npm.cmd").write_text("@echo off\r\nexit /b 0\r\n", encoding="utf-8")
    environment = os.environ.copy()
    environment["PATH"] = f"{binary_dir}{os.pathsep}{environment.get('PATH', '')}"
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    result = subprocess.run(
        [
            "powershell.exe",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(portable / "scripts/setup_team.ps1"),
            "-ShellPackage",
            str(package),
            "-DryRun",
        ],
        cwd=portable,
        env=environment,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    output = result.stdout + result.stderr

    assert result.returncode == 0, output
    assert "Shell distribution: versioned_package / test-release-1" in output
    assert output.count("Provider acceptance blocker:") == 1
    assert "Dry run passed" in output
    assert "must-never-enter-package" not in output
    assert not (portable / ".env").exists()
    assert not (portable / "atdr.db").exists()
    assert not (portable / ".atdr_runtime").exists()


def test_start_and_check_scripts_enforce_versioned_package_integrity():
    root = Path(__file__).resolve().parents[2]
    start = (root / "scripts/start_system.ps1").read_text(encoding="utf-8")
    check = (root / "scripts/check_system.ps1").read_text(encoding="utf-8")

    assert "Get-InstalledMfuShellPackageStatus" in start
    assert "Versioned MFU shell integrity check failed" in start
    assert "package_integrity_ready" in check
    assert "Provider blocker:" in check
