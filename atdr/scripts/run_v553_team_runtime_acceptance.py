from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil
import subprocess
import time
from typing import Any
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
) -> bool:
    result = subprocess.run(
        [executable, "-NoProfile", "-ExecutionPolicy", "Bypass", *arguments],
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    return result.returncode == 0


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
    stages = {"archive": False, "setup": False, "start": False, "health": False, "stop": False}
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
        ):
            return _rehearsal_result(stages, status="startup_failed", workspace_retained=keep_workspace)
        stages["start"] = True
        stages["health"] = _run_stage(
            powershell,
            ["-File", str(clone / "scripts/check_system.ps1"), "-RequireReady"],
            cwd=clone,
            timeout=60,
        )
        stages["stop"] = _run_stage(
            powershell,
            ["-File", str(clone / "scripts/stop_system.ps1")],
            cwd=clone,
            timeout=60,
        )
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
        if stages["start"] and not stages["stop"] and powershell and clone.exists():
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
