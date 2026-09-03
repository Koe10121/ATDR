from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from zipfile import ZipFile

from atdr.app.core.config import PROJECT_ROOT
from atdr.app.services.mfu_shell_package_service import verify_shell_package


EXECUTION_CONFIRMATION = "DISPOSABLE_V553_TEAM_RUNTIME"


def _command(name: str) -> str | None:
    candidates = ("powershell.exe", "pwsh", "powershell") if name == "powershell" else (name,)
    for candidate in candidates:
        resolved = shutil.which(candidate)
        if resolved:
            return resolved
    return None


def _source_clean(root: Path) -> bool:
    try:
        result = subprocess.run(
            ["git", "status", "--porcelain", "--untracked-files=all"],
            cwd=root,
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return False
    return result.returncode == 0 and not result.stdout.strip()


def _required_shell_paths(root: Path) -> list[str]:
    contract = json.loads((root / "config/mfu-shell-contract.json").read_text(encoding="utf-8"))
    return [str(value) for value in contract.get("required_paths", [])]


def _template_source_ready(root: Path, template_root: Path) -> bool:
    return template_root.is_dir() and all((template_root / path).is_file() for path in _required_shell_paths(root))


def build_team_runtime_preflight(
    *,
    root: Path,
    template_root: Path | None,
    shell_package: Path | None,
    private_config_root: Path | None,
) -> dict[str, Any]:
    exactly_one_source = (template_root is None) != (shell_package is None)
    shell_source_ready = False
    source_mode = "invalid"
    if exactly_one_source and template_root is not None:
        source_mode = "approved_directory"
        try:
            shell_source_ready = _template_source_ready(root, template_root)
        except (OSError, ValueError, json.JSONDecodeError):
            shell_source_ready = False
    elif exactly_one_source and shell_package is not None:
        source_mode = "versioned_package"
        try:
            shell_source_ready = bool(
                verify_shell_package(
                    package_path=shell_package,
                    contract_path=root / "config/mfu-shell-contract.json",
                )["ok"]
            )
        except (OSError, ValueError):
            shell_source_ready = False

    try:
        response_simulation_contract = "RESPONSE_SIMULATION=true" in (
            root / ".env.shell.example"
        ).read_text(encoding="utf-8")
    except OSError:
        response_simulation_contract = False
    controls = {
        "git_available": bool(_command("git")),
        "powershell_available": bool(_command("powershell")),
        "node_available": bool(_command("node")),
        "python_available": bool(_command("python") or _command("py")),
        "source_clean": _source_clean(root),
        "exactly_one_shell_source": exactly_one_source,
        "shell_source_ready": shell_source_ready,
        "private_config_root_available": private_config_root is None or private_config_root.is_dir(),
        "response_simulation_contract": response_simulation_contract,
    }
    failed = [name for name, passed in controls.items() if not passed]
    return {
        "ok": not failed,
        "status": "ready_for_disposable_rehearsal" if not failed else "rehearsal_preconditions_incomplete",
        "source_mode": source_mode,
        "controls": controls,
        "failed_controls": failed,
        "configured_database_accessed": False,
        "configured_shell_modified": False,
        "private_configuration_copied_to_git": False,
        "secrets_exposed": False,
    }


def _run_stage(
    executable: str,
    arguments: list[str],
    *,
    cwd: Path,
    timeout: int,
    capture_output: bool = True,
) -> bool:
    output_options: dict[str, Any]
    if capture_output:
        output_options = {"capture_output": True, "text": True}
    else:
        # Long-lived processes started by PowerShell can inherit anonymous pipe
        # handles on Windows. DEVNULL avoids waiting for those descendants after
        # the launcher itself has exited successfully.
        output_options = {"stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL}
    result = subprocess.run(
        [executable, "-NoProfile", "-ExecutionPolicy", "Bypass", *arguments],
        cwd=cwd,
        timeout=timeout,
        check=False,
        **output_options,
    )
    return result.returncode == 0


def _read_system_report(powershell: str, clone: Path) -> dict[str, Any] | None:
    try:
        result = subprocess.run(
            [
                powershell,
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(clone / "scripts/check_system.ps1"),
                "-Json",
                "-RequireReady",
            ],
            cwd=clone,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        if result.returncode != 0:
            return None
        payload = json.loads(result.stdout)
        return payload if isinstance(payload, dict) else None
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
        return None


def _login_handoff_contract_ready(report: dict[str, Any] | None) -> bool:
    if not report:
        return False
    configuration = report.get("configuration")
    identity = report.get("identity_provider")
    return bool(
        report.get("ok")
        and report.get("all_services_ready")
        and isinstance(configuration, dict)
        and configuration.get("auth_mode") == "template_shell"
        and configuration.get("response_simulation") is True
        and configuration.get("secrets_exposed") is False
        and isinstance(identity, dict)
        and identity.get("iam_proxy_configured") is True
        and identity.get("google_auth_ready") is True
        and identity.get("acceptance_requires_real_sign_in") is True
        and identity.get("account_scope_acceptance") == "not_validated"
        and identity.get("secrets_exposed") is False
        and report.get("secrets_exposed") is False
    )


def _wait_http(url: str, *, timeout: int = 60) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with urlopen(url, timeout=3) as response:  # noqa: S310 - fixed loopback URL
                if response.status < 400:
                    return True
        except (HTTPError, URLError, TimeoutError, OSError):
            pass
        time.sleep(1)
    return False


def _terminate_process(process: subprocess.Popen[bytes] | None) -> None:
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def _run_disposable_recovery_smoke(clone: Path) -> bool:
    """Prove the explicit local-recovery profile without touching configured data."""

    python = clone / ".venv/Scripts/python.exe"
    node = _command("node")
    vite = clone / "frontend/node_modules/vite/bin/vite.js"
    if not python.is_file() or not node or not vite.is_file():
        return False

    environment = os.environ.copy()
    recovery_password = secrets.token_urlsafe(24)
    environment.update(
        {
            "ATDR_AUTH_MODE": "local_recovery",
            "LOCAL_LOGIN_ENABLED": "true",
            "MFU_IAM_ENABLED": "false",
            "MFU_IAM_TEMPLATE_SHELL_ENABLED": "false",
            "MFU_IAM_HANDOFF_ENABLED": "false",
            "DATABASE_URL": "sqlite:///./atdr.db",
            "RESPONSE_SIMULATION": "true",
            "RESPONSE_PROVIDER": "simulation",
            "ASSISTANT_LLM_ENABLED": "false",
            "ASSISTANT_ALLOW_RAW_LOG_CONTEXT": "false",
            "DEMO_ADMIN_PASSWORD": recovery_password,
        }
    )
    creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    backend: subprocess.Popen[bytes] | None = None
    frontend: subprocess.Popen[bytes] | None = None
    try:
        seeded = subprocess.run(
            [str(python), "-m", "atdr.scripts.seed_users"],
            cwd=clone,
            env=environment,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=60,
            check=False,
            creationflags=creation_flags,
        )
        if seeded.returncode != 0:
            return False
        backend = subprocess.Popen(
            [
                str(python),
                "-m",
                "uvicorn",
                "atdr.app.main:app",
                "--host",
                "127.0.0.1",
                "--port",
                "8000",
            ],
            cwd=clone,
            env=environment,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=creation_flags,
        )
        frontend = subprocess.Popen(
            [str(node), str(vite), "--host", "127.0.0.1", "--port", "5173", "--strictPort"],
            cwd=clone / "frontend",
            env=environment,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=creation_flags,
        )
        if not _wait_http("http://127.0.0.1:8000/health/live") or not _wait_http("http://127.0.0.1:5173"):
            return False
        with urlopen(  # noqa: S310 - fixed loopback URL
            "http://127.0.0.1:8000/api/auth/mfu-iam/public-status",
            timeout=5,
        ) as response:
            status = json.loads(response.read().decode("utf-8"))
        if not (
            isinstance(status, dict)
            and status.get("auth_mode") == "local_recovery"
            and status.get("local_login_enabled") is True
            and status.get("template_shell_required") is False
            and status.get("secrets_exposed") is False
        ):
            return False
        request = Request(  # noqa: S310 - fixed loopback URL
            "http://127.0.0.1:8000/api/auth/login",
            data=json.dumps(
                {"username": "admin", "password": recovery_password}
            ).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(request, timeout=5) as response:  # noqa: S310 - fixed loopback URL
            login = json.loads(response.read().decode("utf-8"))
        return bool(
            isinstance(login, dict)
            and login.get("token_type") == "bearer"
            and login.get("role") == "admin"
        )
    except (HTTPError, URLError, TimeoutError, OSError, ValueError, subprocess.SubprocessError):
        return False
    finally:
        _terminate_process(frontend)
        _terminate_process(backend)


def execute_disposable_team_rehearsal(
    *,
    root: Path,
    template_root: Path | None,
    shell_package: Path | None,
    private_config_root: Path | None,
    keep_workspace: bool = False,
) -> dict[str, Any]:
    preflight = build_team_runtime_preflight(
        root=root,
        template_root=template_root,
        shell_package=shell_package,
        private_config_root=private_config_root,
    )
    if not preflight["ok"]:
        return {**preflight, "executed": False}

    workspace_parent = root / ".tmp"
    workspace_parent.mkdir(parents=True, exist_ok=True)
    workspace = workspace_parent / f"v553-team-{int(time.time() * 1000)}"
    workspace.mkdir()
    archive = workspace / "atdr.zip"
    clone = workspace / "ATDR"
    shell_copy = workspace / "MFU-shell"
    stages = {
        "archive": False,
        "setup": False,
        "start": False,
        "health": False,
        "login_handoff_contract": False,
        "stop": False,
        "restart": False,
        "restart_health": False,
        "restart_login_handoff_contract": False,
        "restart_stop": False,
        "local_recovery": False,
    }
    powershell = _command("powershell")
    try:
        archive_result = subprocess.run(
            ["git", "archive", "--format=zip", "--output", str(archive), "HEAD"],
            cwd=root,
            capture_output=True,
            check=False,
        )
        if archive_result.returncode != 0:
            return _rehearsal_result(stages, status="archive_failed", workspace_retained=keep_workspace)
        with ZipFile(archive) as bundle:
            bundle.extractall(clone)
        stages["archive"] = True

        setup_arguments = ["-File", str(clone / "scripts/setup_team.ps1")]
        if template_root is not None:
            shutil.copytree(
                template_root,
                shell_copy,
                ignore=shutil.ignore_patterns(".git", "node_modules", "logs", "coverage", "dist"),
            )
            setup_arguments.extend(["-TemplateRoot", str(shell_copy)])
        else:
            setup_arguments.extend(["-ShellPackage", str(shell_package)])
            if private_config_root is not None:
                setup_arguments.extend(["-ShellPrivateConfigRoot", str(private_config_root)])
        if not powershell or not _run_stage(powershell, setup_arguments, cwd=clone, timeout=1_800):
            return _rehearsal_result(stages, status="setup_failed", workspace_retained=keep_workspace)
        stages["setup"] = True

        if not _run_stage(
            powershell,
            ["-File", str(clone / "scripts/start_system.ps1"), "-NoBrowser"],
            cwd=clone,
            timeout=420,
            capture_output=False,
        ):
            return _rehearsal_result(stages, status="startup_failed", workspace_retained=keep_workspace)
        stages["start"] = True
        first_report = _read_system_report(powershell, clone)
        stages["health"] = bool(first_report and first_report.get("ok") and first_report.get("all_services_ready"))
        stages["login_handoff_contract"] = _login_handoff_contract_ready(first_report)
        stages["stop"] = _run_stage(
            powershell,
            ["-File", str(clone / "scripts/stop_system.ps1")],
            cwd=clone,
            timeout=60,
        )
        if stages["stop"]:
            stages["restart"] = _run_stage(
                powershell,
                ["-File", str(clone / "scripts/start_system.ps1"), "-NoBrowser"],
                cwd=clone,
                timeout=420,
                capture_output=False,
            )
        if stages["restart"]:
            restart_report = _read_system_report(powershell, clone)
            stages["restart_health"] = bool(
                restart_report and restart_report.get("ok") and restart_report.get("all_services_ready")
            )
            stages["restart_login_handoff_contract"] = _login_handoff_contract_ready(restart_report)
            stages["restart_stop"] = _run_stage(
                powershell,
                ["-File", str(clone / "scripts/stop_system.ps1")],
                cwd=clone,
                timeout=60,
            )
        if stages["restart_stop"]:
            stages["local_recovery"] = _run_disposable_recovery_smoke(clone)
        return _rehearsal_result(
            stages,
            status="disposable_team_runtime_passed" if all(stages.values()) else "disposable_team_runtime_failed",
            workspace_retained=keep_workspace,
        )
    except (OSError, subprocess.SubprocessError, ValueError):
        return _rehearsal_result(
            stages,
            status="disposable_rehearsal_failed_safely",
            workspace_retained=keep_workspace,
        )
    finally:
        normal_runtime_active = (stages["start"] and not stages["stop"]) or (
            stages["restart"] and not stages["restart_stop"]
        )
        if normal_runtime_active and powershell and clone.exists():
            _run_stage(
                powershell,
                ["-File", str(clone / "scripts/stop_system.ps1")],
                cwd=clone,
                timeout=60,
            )
        if not keep_workspace:
            shutil.rmtree(workspace, ignore_errors=True)


def _rehearsal_result(
    stages: dict[str, bool],
    *,
    status: str,
    workspace_retained: bool,
) -> dict[str, Any]:
    return {
        "ok": status == "disposable_team_runtime_passed",
        "status": status,
        "executed": True,
        "stages": stages,
        "configured_database_accessed": False,
        "configured_shell_modified": False,
        "workspace_retained": workspace_retained,
        "acceptance_manifest_created": False,
        "private_paths_exposed": False,
        "secrets_exposed": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Rehearse clean-clone shell-first ATDR startup in disposable storage.")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--template-root")
    source.add_argument("--shell-package")
    parser.add_argument("--shell-private-config-root")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--confirm", default="")
    parser.add_argument("--keep-workspace", action="store_true")
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()

    template_root = Path(args.template_root).expanduser().resolve() if args.template_root else None
    shell_package = Path(args.shell_package).expanduser().resolve() if args.shell_package else None
    private_root = (
        Path(args.shell_private_config_root).expanduser().resolve()
        if args.shell_private_config_root
        else None
    )
    if args.execute and args.confirm != EXECUTION_CONFIRMATION:
        result = {
            "ok": False,
            "status": "execution_confirmation_required",
            "required_confirmation": EXECUTION_CONFIRMATION,
            "executed": False,
            "secrets_exposed": False,
        }
    elif args.execute:
        result = execute_disposable_team_rehearsal(
            root=PROJECT_ROOT,
            template_root=template_root,
            shell_package=shell_package,
            private_config_root=private_root,
            keep_workspace=args.keep_workspace,
        )
    else:
        result = build_team_runtime_preflight(
            root=PROJECT_ROOT,
            template_root=template_root,
            shell_package=shell_package,
            private_config_root=private_root,
        )
        result["executed"] = False
    print(json.dumps(result, indent=2 if args.pretty else None))
    raise SystemExit(0 if result["ok"] else 1)


if __name__ == "__main__":
    main()
