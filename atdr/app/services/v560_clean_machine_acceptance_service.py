from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import sqlite3
import stat
import subprocess
import tempfile
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen
import uuid

from atdr.app.services.mfu_shell_package_service import (
    ShellPackageError,
    verify_installed_shell,
    verify_shell_package,
)


VERSION = "v5.60-clean-machine-release-candidate-acceptance-v1"
EXECUTION_CONFIRMATION = "DISPOSABLE_V560_CLEAN_MACHINE"
REQUIRED_PORTS = (8000, 5173, 8214, 8080)
AUTHORITATIVE_TABLES = (
    "alerts",
    "detection_runs",
    "ml_labels",
    "ml_model_runs",
    "response_actions",
)
_WORKSPACE_PREFIX = "atdr-v560-"
_PRIVATE_PATH_RE = re.compile(r"(?i)(?:[a-z]:\\users\\[^\\\s]+|/users/[^/\s]+/)")
_ADDRESS_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


class AcceptanceFailure(RuntimeError):
    def __init__(self, stage: str, code: str) -> None:
        super().__init__(code)
        self.stage = stage
        self.code = code


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out


@dataclass(frozen=True)
class DisposableProviderProfile:
    root: Path
    mongo_uri: str
    mongo_database: str
    secret_values: tuple[str, ...]


def _command(name: str) -> str | None:
    candidates = ("powershell.exe", "pwsh", "powershell") if name == "powershell" else (name,)
    for candidate in candidates:
        result = shutil.which(candidate)
        if result:
            return result
    return None


def _run_command(
    command: list[str],
    *,
    cwd: Path,
    timeout: int,
    environment: dict[str, str] | None = None,
    capture_output: bool = True,
) -> CommandResult:
    output: dict[str, Any]
    if capture_output:
        output = {"capture_output": True, "text": True, "encoding": "utf-8", "errors": "replace"}
    else:
        output = {"stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL}
    try:
        result = subprocess.run(
            command,
            cwd=cwd,
            env=environment,
            timeout=timeout,
            check=False,
            **output,
        )
    except subprocess.TimeoutExpired:
        return CommandResult(returncode=-1, timed_out=True)
    except OSError:
        return CommandResult(returncode=-1)
    return CommandResult(
        returncode=result.returncode,
        stdout=result.stdout if capture_output else "",
        stderr=result.stderr if capture_output else "",
    )


def _git_text(root: Path, arguments: list[str]) -> str | None:
    git = _command("git")
    if not git:
        return None
    result = _run_command([git, *arguments], cwd=root, timeout=60)
    if not result.ok:
        return None
    return result.stdout.strip()


def _parse_version(value: str) -> tuple[int, int, int] | None:
    match = re.search(r"(\d+)\.(\d+)\.(\d+)", value)
    if not match:
        return None
    return tuple(int(match.group(index)) for index in range(1, 4))


def _tool_version(command: list[str], *, cwd: Path) -> tuple[bool, str | None]:
    result = _run_command(command, cwd=cwd, timeout=30)
    rendered = (result.stdout or result.stderr).strip().splitlines()
    return result.ok, rendered[0] if rendered else None


def _python311_command(root: Path) -> tuple[list[str] | None, str | None]:
    launcher = _command("py")
    candidates: list[list[str]] = []
    if launcher:
        candidates.append([launcher, "-3.11"])
    python = _command("python")
    if python:
        candidates.append([python])
    for prefix in candidates:
        ok, version = _tool_version([*prefix, "--version"], cwd=root)
        parsed = _parse_version(version or "")
        if ok and parsed and parsed[:2] == (3, 11):
            return prefix, version
    return None, None


def _node_supported(version: str | None) -> bool:
    parsed = _parse_version(version or "")
    return bool(parsed and (parsed[0] > 20 or (parsed[0] == 20 and parsed[1] >= 19)))


def _tcp_available(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.5):
            return True
    except OSError:
        return False


def _port_is_free(port: int) -> bool:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", port))
        return True
    except OSError:
        return False
    finally:
        listener.close()


def _safe_remote(remote: str | None) -> bool:
    if not remote or _PRIVATE_PATH_RE.search(remote):
        return False
    if remote.startswith("git@"):
        return ":" in remote and "@" in remote
    parsed = urlsplit(remote)
    return parsed.scheme in {"https", "ssh"} and bool(parsed.hostname) and parsed.username is None


def _working_tree_clean(root: Path) -> bool:
    status = _git_text(root, ["status", "--porcelain", "--untracked-files=all"])
    return status == ""


def build_clean_machine_preflight(*, root: Path, shell_package: Path) -> dict[str, Any]:
    root = root.resolve()
    shell_package = shell_package.resolve()
    python_prefix, python_version = _python311_command(root)
    node = _command("node")
    npm = _command("npm.cmd") or _command("npm")
    powershell = _command("powershell")
    git = _command("git")
    node_ok, node_version = _tool_version([node, "--version"], cwd=root) if node else (False, None)
    npm_ok, npm_version = _tool_version([npm, "--version"], cwd=root) if npm else (False, None)
    head = _git_text(root, ["rev-parse", "HEAD"])
    origin_head = _git_text(root, ["rev-parse", "origin/main"])
    remote = _git_text(root, ["remote", "get-url", "origin"])
    try:
        package = verify_shell_package(
            package_path=shell_package,
            contract_path=root / "config/mfu-shell-contract.json",
        )
        package_ready = bool(package["ok"])
        package_release = str(package["release_version"])
    except (OSError, ValueError, ShellPackageError):
        package_ready = False
        package_release = None

    required_controls = {
        "windows_environment": os.name == "nt",
        "git_available": bool(git),
        "powershell_available": bool(powershell),
        "python_3_11_available": bool(python_prefix),
        "node_20_19_or_newer": node_ok and _node_supported(node_version),
        "npm_available": bool(npm and npm_ok),
        "published_main_resolved": bool(head and origin_head and head == origin_head),
        "genuine_remote_configured": _safe_remote(remote),
        "shell_package_verified": package_ready,
        "mongodb_for_shell_reachable": _tcp_available(27017),
        "runtime_ports_free": all(_port_is_free(port) for port in REQUIRED_PORTS),
    }
    failed = [name for name, passed in required_controls.items() if not passed]
    return {
        "version": VERSION,
        "ok": not failed,
        "status": "ready_for_disposable_acceptance" if not failed else "acceptance_preconditions_incomplete",
        "executed": False,
        "controls": required_controls,
        "failed_controls": failed,
        "observations": {
            "authoritative_worktree_clean": _working_tree_clean(root),
            "python_version": python_version,
            "node_version": node_version,
            "npm_version": npm_version,
            "shell_release": package_release,
        },
        "boundaries": {
            "remote_branch": "main",
            "clone_source": "origin/main",
            "database_mode": "disposable_sqlite",
            "shell_distribution": "verified_versioned_companion_archive",
            "private_provider_configuration_used": False,
            "real_mfu_account_acceptance": "not_validated",
        },
        "configured_database_accessed": False,
        "configured_shell_modified": False,
        "private_paths_exposed": False,
        "secrets_exposed": False,
    }


def _verified_temp_workspace(temp_root: Path) -> Path:
    temp_root = temp_root.resolve()
    temp_root.mkdir(parents=True, exist_ok=True)
    workspace = Path(tempfile.mkdtemp(prefix=_WORKSPACE_PREFIX, dir=temp_root)).resolve()
    if workspace.parent != temp_root or not workspace.name.startswith(_WORKSPACE_PREFIX):
        raise AcceptanceFailure("temporary_workspace", "temporary_workspace_boundary_invalid")
    return workspace


def remove_verified_temp_workspace(workspace: Path, *, temp_root: Path) -> bool:
    def clear_readonly_and_retry(function: Any, path: str, _error: Any) -> None:
        try:
            os.chmod(path, stat.S_IWRITE)
            function(path)
        except OSError:
            return

    try:
        resolved_root = temp_root.resolve()
        resolved = workspace.resolve()
        if resolved.parent != resolved_root or not resolved.name.startswith(_WORKSPACE_PREFIX):
            return False
        if resolved.is_symlink():
            return False
        deletion_target: str | Path = resolved
        if os.name == "nt" and not str(resolved).startswith("\\\\?\\"):
            deletion_target = f"\\\\?\\{resolved}"
        for attempt in range(5):
            shutil.rmtree(deletion_target, onerror=clear_readonly_and_retry)
            if not resolved.exists():
                break
            time.sleep(0.5 * (attempt + 1))
        return not resolved.exists()
    except OSError:
        return False


def _clone_hygiene(clone: Path) -> dict[str, bool]:
    forbidden_directories = {
        ".atdr_runtime",
        ".venv",
        "node_modules",
        "ml_baseline_reviews",
        "demo_exports",
        "processed_logs",
    }
    forbidden_files = {".env", ".env.local", ".env.localdev", "atdr.db"}
    forbidden_suffixes = {".db", ".sqlite", ".sqlite3", ".log", ".joblib", ".pkl"}
    private_file_found = False
    generated_directory_found = False
    for path in clone.rglob("*"):
        if ".git" in path.parts:
            continue
        if path.is_dir() and path.name.lower() in forbidden_directories:
            generated_directory_found = True
            continue
        if path.is_file():
            lowered = path.name.lower()
            if lowered in forbidden_files or (path.suffix.lower() in forbidden_suffixes and not lowered.endswith(".example")):
                private_file_found = True
    return {
        "git_worktree_clean": _working_tree_clean(clone),
        "private_file_absent": not private_file_found,
        "generated_directories_absent": not generated_directory_found,
    }


def _dotenv(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.is_file():
        return values
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        clean = line.strip()
        if not clean or clean.startswith("#") or "=" not in clean:
            continue
        key, value = clean.split("=", 1)
        values[key.strip()] = value.strip().strip("\"").strip("'")
    return values


def _write_disposable_provider_profile(workspace: Path) -> DisposableProviderProfile:
    profile_root = workspace / "synthetic-provider"
    backend = profile_root / "backend-node/.env.local"
    frontend = profile_root / "frontend-vue/.env.localdev"
    backend.parent.mkdir(parents=True)
    frontend.parent.mkdir(parents=True)
    mongo_database = f"atdr_v560_{uuid.uuid4().hex[:12]}"
    mongo_uri = f"mongodb://127.0.0.1:27017/{mongo_database}"
    local_key = secrets.token_urlsafe(48)
    iam_secret = secrets.token_urlsafe(48)
    admin_secret = secrets.token_urlsafe(48)
    client_id = f"v560-{uuid.uuid4().hex}.apps.googleusercontent.invalid"
    backend.write_text(
        "\n".join(
            [
                "NODE_ENV=development",
                "PORT=8214",
                "BASE_SERVER_URL=http://127.0.0.1:8214",
                "PROJECT_CODE=atdr-clean-machine-acceptance",
                "PROJECT_NAME=ATDR Clean Machine Acceptance",
                "PROJECT_ENV=disposable",
                "PROJECT_BASE_URL=http://127.0.0.1:8214",
                f"MONGODB={mongo_uri}",
                f"KEY={local_key}",
                "TIMEOUT=30",
                "TOKENLANGTH=6",
                "TOKENEXPIRED=1",
                "TRANSACTIONEXPIRED=5",
                f"GOOGLE_CLIENT_ID={client_id}",
                "IAM_SDK_BASE_URL=https://iam.invalid",
                "IAM_SDK_CLIENT_ID=atdr-clean-machine-client",
                f"IAM_SDK_CLIENT_SECRET={iam_secret}",
                "IAM_SDK_AUDIENCE=atdr-clean-machine-api",
                "IAM_SDK_SCOPE=atdr.clean.read atdr.clean.write",
                "IAM_SDK_TIMEOUT_MS=5000",
                "IAM_SDK_TOKEN_PATH=/api/v1/b2b/token",
                "IAM_SDK_INTROSPECT_PATH=/api/v1/b2b/introspect",
                "IAM_SDK_PROFILE_PATH=/api/v1/b2b/clients/me",
                "IAM_SDK_ADMIN_BASE_PATH=/api/v1/b2b/admin",
                "IAM_ADMIN_CLIENT_ID=atdr-clean-machine-admin",
                f"IAM_ADMIN_CLIENT_SECRET={admin_secret}",
                "IAM_ADMIN_AUDIENCE=atdr-clean-machine-admin-api",
                "IAM_ADMIN_SCOPE=atdr.clean.admin",
                "PROJECT_PERMISSION_TYPE_TITLE=ATDR Clean Machine Administration",
                "PROJECT_PERMISSION_GROUP_TITLE=ATDR Clean Machine Admin",
                "PROJECT_PERMISSION_ROOT_PATH=/atdr-clean-machine/security/permission",
                "PROJECT_PERMISSION_PATHS=/atdr-clean-machine/security/permission,/dashboard",
                "PROJECT_PERMISSION_SOURCE=iam",
                "PROJECT_PERMISSION_BOOTSTRAP_MODE=iam",
                "PROJECT_AUTH_REQUIRE_2FA=true",
                "PROJECT_AUDIT_RETENTION_DAYS=1",
                "",
            ]
        ),
        encoding="utf-8",
    )
    frontend.write_text(
        "\n".join(
            [
                "NODE_ENV=development",
                "VUE_APP_ENV=localdev",
                "VUE_APP_BASE_URL=http://localhost:8080",
                "VUE_APP_API_BASE_URL=http://127.0.0.1:8214",
                "VUE_APP_SOCKET_URL=http://127.0.0.1:8214",
                f"VUE_APP_CLIENTID={client_id}",
                "",
            ]
        ),
        encoding="utf-8",
    )
    return DisposableProviderProfile(
        root=profile_root,
        mongo_uri=mongo_uri,
        mongo_database=mongo_database,
        secret_values=(local_key, iam_secret, admin_secret, client_id),
    )


def _output_contains_generated_secret(result: CommandResult, values: tuple[str, ...]) -> bool:
    output = f"{result.stdout}\n{result.stderr}"
    return any(value and value in output for value in values)


def _powershell_stage(
    powershell: str,
    script: Path,
    arguments: list[str],
    *,
    cwd: Path,
    timeout: int,
    capture_output: bool = True,
) -> CommandResult:
    return _run_command(
        [
            powershell,
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(script),
            *arguments,
        ],
        cwd=cwd,
        timeout=timeout,
        capture_output=capture_output,
    )


def _read_json_output(result: CommandResult) -> dict[str, Any] | None:
    if not result.ok:
        return None
    try:
        value = json.loads(result.stdout.strip())
    except json.JSONDecodeError:
        return None
    return value if isinstance(value, dict) else None


def _system_report(powershell: str, clone: Path, *, require_ready: bool) -> dict[str, Any] | None:
    arguments = ["-Json"]
    if require_ready:
        arguments.append("-RequireReady")
    return _read_json_output(
        _powershell_stage(
            powershell,
            clone / "scripts/check_system.ps1",
            arguments,
            cwd=clone,
            timeout=90,
        )
    )


def _system_contract_ready(report: dict[str, Any] | None) -> bool:
    if not report:
        return False
    configuration = report.get("configuration") or {}
    identity = report.get("identity_provider") or {}
    shell = report.get("shell_distribution") or {}
    services = report.get("services") or {}
    return bool(
        report.get("ok")
        and report.get("all_services_ready")
        and len(services) == 4
        and all(bool((service or {}).get("reachable")) for service in services.values())
        and configuration.get("auth_mode") == "template_shell"
        and configuration.get("database_dialect") == "sqlite"
        and configuration.get("response_simulation") is True
        and configuration.get("gemini_configured") is False
        and configuration.get("secrets_exposed") is False
        and shell.get("mode") == "versioned_package"
        and shell.get("package_integrity_ready") is True
        and identity.get("iam_proxy_configured") is True
        and identity.get("google_auth_ready") is True
        and identity.get("acceptance_requires_real_sign_in") is True
        and identity.get("account_scope_acceptance") == "not_validated"
        and identity.get("secrets_exposed") is False
        and report.get("secrets_exposed") is False
    )


def _http_ready(url: str, *, timeout: int = 20) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with urlopen(url, timeout=3) as response:  # noqa: S310 - fixed loopback acceptance endpoint
                if response.status < 400:
                    return True
        except (HTTPError, URLError, TimeoutError, OSError):
            pass
        time.sleep(0.5)
    return False


def _config_contract(clone: Path, shell_root: Path) -> bool:
    root_env = _dotenv(clone / ".env")
    react_env = _dotenv(clone / "frontend/.env.local")
    shell_backend = _dotenv(shell_root / "backend-node/.env.local")
    shell_frontend = _dotenv(shell_root / "frontend-vue/.env.localdev")
    try:
        team = json.loads((clone / ".atdr_runtime/team-config.json").read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError):
        return False
    return bool(
        root_env.get("DATABASE_URL") == "sqlite:///./atdr.db"
        and root_env.get("ATDR_AUTH_MODE") == "template_shell"
        and root_env.get("RESPONSE_SIMULATION", "").lower() == "true"
        and root_env.get("ASSISTANT_LLM_ENABLED", "").lower() == "false"
        and root_env.get("ASSISTANT_ALLOW_RAW_LOG_CONTEXT", "").lower() == "false"
        and root_env.get("MFU_IAM_TEMPLATE_SHELL_BASE_URL") == "http://127.0.0.1:8214"
        and root_env.get("MFU_IAM_TEMPLATE_SHELL_LAUNCH_URL") == "http://localhost:8080/#/pages/login"
        and react_env.get("VITE_API_BASE_URL") == "http://127.0.0.1:8000"
        and shell_backend.get("PROJECT_BASE_URL") == "http://127.0.0.1:8214"
        and shell_backend.get("GOOGLE_CLIENT_ID")
        and shell_backend.get("GOOGLE_CLIENT_ID") == shell_frontend.get("VUE_APP_CLIENTID")
        and team.get("atdr_backend_url") == "http://127.0.0.1:8000"
        and team.get("atdr_frontend_url") == "http://127.0.0.1:5173"
        and team.get("shell_backend_url") == "http://127.0.0.1:8214"
        and team.get("shell_frontend_url") == "http://localhost:8080"
        and team.get("shell_distribution_mode") == "versioned_package"
        and team.get("shell_package_verified") is True
        and team.get("secrets_stored") is False
        and "MONGODB" not in root_env
    )


def _packaged_handoff_contract(shell_root: Path) -> bool:
    route_path = shell_root / "backend-node/server/Project/atdr/atdr_handoff.routes.js"
    service_path = shell_root / "backend-node/server/Project/atdr/service/atdr_handoff.js"
    try:
        route = route_path.read_text(encoding="utf-8")
        service = service_path.read_text(encoding="utf-8")
    except OSError:
        return False
    route_tokens = (
        "router.post('/start', account.onCheckAuthorization",
        "router.post('/exchange'",
        "handoff.exchange",
        "ATDR handoff request could not be completed.",
    )
    service_tokens = (
        "crypto.timingSafeEqual",
        "consumedAt: null",
        "expiresAt: { $gt: consumedAt }",
        "findOneAndUpdate",
        "allowedDomains",
        "secretsExposed: false",
    )
    return all(token in route for token in route_tokens) and all(token in service for token in service_tokens)


def _authoritative_counts(database: Path) -> dict[str, int] | None:
    if not database.is_file():
        return None
    try:
        with sqlite3.connect(database) as connection:
            return {
                table: int(connection.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0])
                for table in AUTHORITATIVE_TABLES
            }
    except sqlite3.Error:
        return None


def _analyst_workflow_summary(report: dict[str, Any] | None) -> dict[str, Any]:
    if not report or not report.get("ok") or report.get("scenario_count") != 1:
        return {"passed": False}
    scenario = (report.get("scenarios") or [{}])[0]
    assistant = scenario.get("assistant") or {}
    responses = assistant.get("responses") or []
    checks = {str(item.get("name")): bool(item.get("passed")) for item in scenario.get("checks") or []}
    response_safety = scenario.get("response_safety") or {}
    authoritative_deltas = assistant.get("authoritative_row_deltas") or {}
    passed = bool(
        scenario.get("passed")
        and int((scenario.get("parser_normalization") or {}).get("normalized_logs") or 0) > 0
        and int(scenario.get("alert_count") or 0) > 0
        and checks.get("source_health_visible")
        and checks.get("why_flagged_present")
        and checks.get("investigation_evidence_linked")
        and assistant.get("passed")
        and [item.get("response_mode") for item in responses]
        == ["alert_explanation", "related_logs", "safe_next_step"]
        and all(int(item.get("citation_count") or 0) > 0 for item in responses)
        and all(item.get("external_provider_used") is False for item in responses)
        and all(item.get("raw_log_context_included") is False for item in responses)
        and all(item.get("redaction_applied") is True for item in responses)
        and all(int(value) == 0 for value in authoritative_deltas.values())
        and response_safety.get("simulate_response") is False
        and int(response_safety.get("response_actions_created") or 0) == 0
        and int((scenario.get("audit_summary") or {}).get("response_actions_created") or 0) == 0
    )
    return {
        "passed": passed,
        "records_ingested": int((scenario.get("parser_normalization") or {}).get("raw_logs") or 0),
        "records_normalized": int((scenario.get("parser_normalization") or {}).get("normalized_logs") or 0),
        "alerts_created": int(scenario.get("alert_count") or 0),
        "assistant_turns": int(assistant.get("conversation_turns") or 0),
        "citation_counts": [int(item.get("citation_count") or 0) for item in responses],
        "response_actions_created": 0,
        "model_activated_or_promoted": False,
    }


def _terminate_process(process: subprocess.Popen[bytes] | None) -> None:
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def _local_recovery_idempotence(clone: Path) -> bool:
    python = clone / ".venv/Scripts/python.exe"
    node = _command("node")
    vite = clone / "frontend/node_modules/vite/bin/vite.js"
    if not python.is_file() or not node or not vite.is_file():
        return False
    password = secrets.token_urlsafe(32)
    environment = os.environ.copy()
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
            "DEMO_ADMIN_PASSWORD": password,
            "DEMO_ANALYST_PASSWORD": secrets.token_urlsafe(32),
        }
    )
    for _ in range(2):
        result = _run_command(
            [str(python), "-m", "atdr.scripts.seed_users"],
            cwd=clone,
            timeout=90,
            environment=environment,
        )
        if not result.ok or password in f"{result.stdout}\n{result.stderr}":
            return False
    try:
        with sqlite3.connect(clone / "atdr.db") as connection:
            if int(connection.execute("SELECT COUNT(*) FROM users").fetchone()[0]) != 2:
                return False
    except sqlite3.Error:
        return False

    creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    backend: subprocess.Popen[bytes] | None = None
    frontend: subprocess.Popen[bytes] | None = None
    try:
        backend = subprocess.Popen(
            [str(python), "-m", "uvicorn", "atdr.app.main:app", "--host", "127.0.0.1", "--port", "8000"],
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
        if not _http_ready("http://127.0.0.1:8000/health/live", timeout=60) or not _http_ready(
            "http://127.0.0.1:5173", timeout=60
        ):
            return False
        request = Request(  # noqa: S310 - fixed loopback acceptance endpoint
            "http://127.0.0.1:8000/api/auth/login",
            data=json.dumps({"username": "admin", "password": password}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(request, timeout=10) as response:  # noqa: S310 - fixed loopback acceptance endpoint
            payload = json.loads(response.read().decode("utf-8"))
        return bool(payload.get("token_type") == "bearer" and payload.get("role") == "admin")
    except (HTTPError, URLError, TimeoutError, OSError, ValueError, json.JSONDecodeError):
        return False
    finally:
        _terminate_process(frontend)
        _terminate_process(backend)


def _drop_disposable_mongo(shell_root: Path, profile: DisposableProviderProfile) -> bool:
    if not re.fullmatch(r"atdr_v560_[a-f0-9]{12}", profile.mongo_database):
        return False
    node = _command("node")
    if not node or not (shell_root / "backend-node/node_modules/mongoose").exists():
        return False
    environment = os.environ.copy()
    environment["MONGODB"] = profile.mongo_uri
    script = (
        "const mongoose=require('mongoose');"
        "(async()=>{await mongoose.connect(process.env.MONGODB);"
        "await mongoose.connection.db.dropDatabase();await mongoose.disconnect();})()"
        ".catch(()=>process.exit(1));"
    )
    return _run_command(
        [node, "-e", script],
        cwd=shell_root / "backend-node",
        timeout=60,
        environment=environment,
    ).ok


def _public_report_is_redacted(report: dict[str, Any]) -> bool:
    encoded = json.dumps(report, default=str)
    normalized_paths = encoded.replace("\\\\", "\\")
    return not (
        _PRIVATE_PATH_RE.search(normalized_paths)
        or _ADDRESS_RE.search(encoded)
        or "mongodb://" in encoded.lower()
        or "client_secret" in encoded.lower()
        or "api_key" in encoded.lower()
    )


def execute_clean_machine_acceptance(*, root: Path, shell_package: Path) -> dict[str, Any]:
    root = root.resolve()
    shell_package = shell_package.resolve()
    preflight = build_clean_machine_preflight(root=root, shell_package=shell_package)
    if not preflight["ok"]:
        return preflight

    stage_names = (
        "remote_clone",
        "clone_hygiene",
        "setup_without_private_config",
        "provider_missing_fail_closed",
        "synthetic_profile_install",
        "setup_idempotence",
        "dependency_isolation",
        "configuration_contract",
        "shell_handoff_fixtures",
        "system_start",
        "system_health",
        "entry_urls",
        "start_idempotence",
        "system_stop",
        "stop_idempotence",
        "stale_process_recovery",
        "occupied_port_diagnostic",
        "system_restart",
        "restart_health",
        "restart_stop",
        "local_recovery",
        "analyst_workflow",
        "runtime_governance",
        "authoritative_state_unchanged",
        "mongo_cleanup",
        "process_cleanup",
        "temporary_workspace_cleanup",
    )
    stages = {name: False for name in stage_names}
    metrics: dict[str, Any] = {}
    failure_stage: str | None = None
    failure_code: str | None = None
    temp_root = Path(tempfile.gettempdir()).resolve()
    workspace: Path | None = None
    clone: Path | None = None
    shell_root: Path | None = None
    provider: DisposableProviderProfile | None = None
    powershell = _command("powershell")
    expected_commit = _git_text(root, ["rev-parse", "origin/main"])
    remote = _git_text(root, ["remote", "get-url", "origin"])

    try:
        if not powershell or not expected_commit or not _safe_remote(remote):
            raise AcceptanceFailure("remote_clone", "published_remote_unavailable")
        workspace = _verified_temp_workspace(temp_root)
        clone = workspace / "ATDR"
        git = _command("git")
        clone_result = _run_command(
            [
                str(git),
                "clone",
                "--no-local",
                "--single-branch",
                "--branch",
                "main",
                "--quiet",
                str(remote),
                str(clone),
            ],
            cwd=workspace,
            timeout=600,
        )
        clone_head = _git_text(clone, ["rev-parse", "HEAD"]) if clone_result.ok else None
        if not clone_result.ok or clone_head != expected_commit:
            raise AcceptanceFailure("remote_clone", "published_clone_failed")
        stages["remote_clone"] = True

        hygiene = _clone_hygiene(clone)
        if not all(hygiene.values()):
            raise AcceptanceFailure("clone_hygiene", "clean_clone_contains_private_or_generated_state")
        stages["clone_hygiene"] = True

        setup_script = clone / "scripts/setup_team.ps1"
        base_setup_args = ["-ShellPackage", str(shell_package)]
        setup = _powershell_stage(
            powershell,
            setup_script,
            base_setup_args,
            cwd=clone,
            timeout=2_400,
        )
        if not setup.ok:
            raise AcceptanceFailure("setup_without_private_config", "first_time_setup_failed")
        stages["setup_without_private_config"] = True

        unavailable_report = _system_report(powershell, clone, require_ready=False)
        blocked_start = _powershell_stage(
            powershell,
            clone / "scripts/start_system.ps1",
            ["-NoBrowser"],
            cwd=clone,
            timeout=120,
        )
        blocker_text = f"{blocked_start.stdout}\n{blocked_start.stderr}".lower()
        if not (
            unavailable_report
            and unavailable_report.get("installation_ready") is True
            and unavailable_report.get("provider_ready") is False
            and not blocked_start.ok
            and "private provider configuration" in blocker_text
            and not (clone / ".atdr_runtime/system-processes.json").exists()
        ):
            raise AcceptanceFailure("provider_missing_fail_closed", "missing_provider_did_not_fail_closed")
        stages["provider_missing_fail_closed"] = True

        provider = _write_disposable_provider_profile(workspace)
        configured_setup_args = [
            *base_setup_args,
            "-ShellPrivateConfigRoot",
            str(provider.root),
            "-SkipDependencyInstall",
        ]
        configured_setup = _powershell_stage(
            powershell,
            setup_script,
            configured_setup_args,
            cwd=clone,
            timeout=600,
        )
        if not configured_setup.ok or _output_contains_generated_secret(configured_setup, provider.secret_values):
            raise AcceptanceFailure("synthetic_profile_install", "disposable_provider_profile_install_failed")
        stages["synthetic_profile_install"] = True

        root_env_hash_before = hashlib.sha256((clone / ".env").read_bytes()).hexdigest()
        repeated_setup = _powershell_stage(
            powershell,
            setup_script,
            configured_setup_args,
            cwd=clone,
            timeout=600,
        )
        root_env_hash_after = hashlib.sha256((clone / ".env").read_bytes()).hexdigest()
        if not repeated_setup.ok or root_env_hash_before != root_env_hash_after:
            raise AcceptanceFailure("setup_idempotence", "repeated_setup_changed_private_root_configuration")
        stages["setup_idempotence"] = True

        try:
            team = json.loads((clone / ".atdr_runtime/team-config.json").read_text(encoding="utf-8-sig"))
            shell_root = Path(str(team["template_root"])).resolve()
        except (OSError, KeyError, ValueError, json.JSONDecodeError):
            raise AcceptanceFailure("dependency_isolation", "installed_shell_metadata_invalid") from None
        expected_shell_parent = (clone / ".atdr_runtime/shell").resolve()
        try:
            shell_root.relative_to(expected_shell_parent)
        except ValueError:
            raise AcceptanceFailure("dependency_isolation", "installed_shell_outside_disposable_clone") from None
        dependency_ready = all(
            path.exists()
            for path in (
                clone / ".venv/Scripts/python.exe",
                clone / "frontend/node_modules/vite/bin/vite.js",
                shell_root / "backend-node/node_modules/mongoose",
                shell_root / "frontend-vue/node_modules/@vue/cli-service",
                clone / "atdr.db",
            )
        )
        try:
            installed = verify_installed_shell(
                shell_root=shell_root,
                contract_path=clone / "config/mfu-shell-contract.json",
            )
        except (OSError, ValueError, ShellPackageError):
            installed = {"ok": False}
        if not dependency_ready or not installed.get("ok"):
            raise AcceptanceFailure("dependency_isolation", "isolated_dependencies_or_migrations_incomplete")
        stages["dependency_isolation"] = True

        if not _config_contract(clone, shell_root):
            raise AcceptanceFailure("configuration_contract", "component_configuration_disagrees")
        stages["configuration_contract"] = True

        python = clone / ".venv/Scripts/python.exe"
        backend_handoff = _run_command(
            [str(python), "-m", "pytest", "atdr/tests/test_mfu_iam_handoff.py", "-q"],
            cwd=clone,
            timeout=300,
        )
        node = _command("node")
        shell_route = shell_root / "backend-node/server/Project/atdr/atdr_handoff.routes.js"
        shell_service = shell_root / "backend-node/server/Project/atdr/service/atdr_handoff.js"
        route_syntax = (
            _run_command([str(node), "--check", str(shell_route)], cwd=shell_root / "backend-node", timeout=60)
            if node
            else CommandResult(returncode=-1)
        )
        service_syntax = (
            _run_command([str(node), "--check", str(shell_service)], cwd=shell_root / "backend-node", timeout=60)
            if node
            else CommandResult(returncode=-1)
        )
        if not (
            backend_handoff.ok
            and route_syntax.ok
            and service_syntax.ok
            and _packaged_handoff_contract(shell_root)
        ):
            raise AcceptanceFailure("shell_handoff_fixtures", "shell_handoff_contract_fixture_failed")
        stages["shell_handoff_fixtures"] = True

        counts_before = _authoritative_counts(clone / "atdr.db")
        if counts_before is None:
            raise AcceptanceFailure("authoritative_state_unchanged", "disposable_database_count_snapshot_failed")

        start = _powershell_stage(
            powershell,
            clone / "scripts/start_system.ps1",
            ["-NoBrowser"],
            cwd=clone,
            timeout=480,
            capture_output=False,
        )
        if not start.ok:
            raise AcceptanceFailure("system_start", "four_component_start_failed")
        stages["system_start"] = True

        report = _system_report(powershell, clone, require_ready=True)
        if not _system_contract_ready(report):
            raise AcceptanceFailure("system_health", "four_component_health_contract_failed")
        stages["system_health"] = True
        if not _http_ready("http://localhost:8080", timeout=30) or not _http_ready("http://127.0.0.1:5173", timeout=30):
            raise AcceptanceFailure("entry_urls", "published_entry_url_unreachable")
        stages["entry_urls"] = True

        metadata_path = clone / ".atdr_runtime/system-processes.json"
        metadata_before = json.loads(metadata_path.read_text(encoding="utf-8-sig"))
        repeated_start = _powershell_stage(
            powershell,
            clone / "scripts/start_system.ps1",
            ["-NoBrowser"],
            cwd=clone,
            timeout=120,
            capture_output=False,
        )
        metadata_after = json.loads(metadata_path.read_text(encoding="utf-8-sig"))
        before_pids = [int(item["pid"]) for item in metadata_before.get("processes") or []]
        after_pids = [int(item["pid"]) for item in metadata_after.get("processes") or []]
        if not repeated_start.ok or before_pids != after_pids or len(after_pids) != 4:
            raise AcceptanceFailure("start_idempotence", "healthy_start_created_duplicate_processes")
        stages["start_idempotence"] = True

        stop = _powershell_stage(
            powershell,
            clone / "scripts/stop_system.ps1",
            [],
            cwd=clone,
            timeout=90,
        )
        if not stop.ok or metadata_path.exists():
            raise AcceptanceFailure("system_stop", "launcher_stop_failed")
        stages["system_stop"] = True
        repeated_stop = _powershell_stage(
            powershell,
            clone / "scripts/stop_system.ps1",
            [],
            cwd=clone,
            timeout=60,
        )
        if not repeated_stop.ok:
            raise AcceptanceFailure("stop_idempotence", "repeated_stop_failed")
        stages["stop_idempotence"] = True

        metadata_path.write_text(
            json.dumps(
                {
                    "version": 1,
                    "processes": [
                        {
                            "name": "atdr-backend",
                            "pid": 2_147_483_647,
                            "started_at": "2000-01-01T00:00:00Z",
                        }
                    ],
                    "secrets_stored": False,
                }
            ),
            encoding="utf-8",
        )
        stale_stop = _powershell_stage(
            powershell,
            clone / "scripts/stop_system.ps1",
            [],
            cwd=clone,
            timeout=60,
        )
        if not stale_stop.ok or metadata_path.exists():
            raise AcceptanceFailure("stale_process_recovery", "stale_metadata_recovery_failed")
        stages["stale_process_recovery"] = True

        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            listener.bind(("127.0.0.1", 8000))
            listener.listen(1)
            occupied = _powershell_stage(
                powershell,
                clone / "scripts/start_system.ps1",
                ["-NoBrowser"],
                cwd=clone,
                timeout=120,
            )
        finally:
            listener.close()
        occupied_text = f"{occupied.stdout}\n{occupied.stderr}".lower()
        if occupied.ok or "occupied" not in occupied_text or metadata_path.exists():
            raise AcceptanceFailure("occupied_port_diagnostic", "occupied_port_did_not_fail_actionably")
        stages["occupied_port_diagnostic"] = True

        restart = _powershell_stage(
            powershell,
            clone / "scripts/start_system.ps1",
            ["-NoBrowser"],
            cwd=clone,
            timeout=480,
            capture_output=False,
        )
        if not restart.ok:
            raise AcceptanceFailure("system_restart", "clean_restart_failed")
        stages["system_restart"] = True
        restart_report = _system_report(powershell, clone, require_ready=True)
        if not _system_contract_ready(restart_report):
            raise AcceptanceFailure("restart_health", "restart_health_contract_failed")
        stages["restart_health"] = True
        restart_stop = _powershell_stage(
            powershell,
            clone / "scripts/stop_system.ps1",
            [],
            cwd=clone,
            timeout=90,
        )
        if not restart_stop.ok:
            raise AcceptanceFailure("restart_stop", "restart_stop_failed")
        stages["restart_stop"] = True

        if not _local_recovery_idempotence(clone):
            raise AcceptanceFailure("local_recovery", "local_recovery_or_user_bootstrap_failed")
        stages["local_recovery"] = True

        workflow_result = _run_command(
            [
                str(python),
                "-m",
                "atdr.scripts.run_e2e_workflow_validation",
                "--scenario",
                "port_scan_like_traffic",
                "--exercise-assistant",
                "--no-report",
            ],
            cwd=clone,
            timeout=300,
        )
        workflow_summary = _analyst_workflow_summary(_read_json_output(workflow_result))
        if not workflow_summary.get("passed"):
            raise AcceptanceFailure("analyst_workflow", "disposable_analyst_workflow_failed")
        metrics["analyst_workflow"] = workflow_summary
        stages["analyst_workflow"] = True

        runtime_result = _run_command(
            [str(python), "-m", "atdr.scripts.run_v558_governed_hybrid_runtime", "--require-safe"],
            cwd=clone,
            timeout=120,
        )
        runtime = _read_json_output(runtime_result)
        if not (
            runtime
            and runtime.get("status") == "governed_hybrid_runtime_safe"
            and (runtime.get("rules") or {}).get("state") == "active_authoritative"
            and (runtime.get("supervised") or {}).get("state") == "unqualified"
            and (runtime.get("response") or {}).get("state") == "simulation_only"
            and runtime.get("model_activated") is False
            and int(runtime.get("response_actions_created") or 0) == 0
        ):
            raise AcceptanceFailure("runtime_governance", "runtime_governance_contract_failed")
        metrics["runtime_governance"] = {
            "rules": "active_authoritative",
            "anomaly": (runtime.get("anomaly") or {}).get("state"),
            "supervised": "unqualified",
            "hybrid": (runtime.get("hybrid") or {}).get("state"),
            "response": "simulation_only",
        }
        stages["runtime_governance"] = True

        counts_after = _authoritative_counts(clone / "atdr.db")
        if counts_after != counts_before:
            raise AcceptanceFailure("authoritative_state_unchanged", "authoritative_disposable_counts_changed")
        stages["authoritative_state_unchanged"] = True
    except AcceptanceFailure as exc:
        failure_stage = exc.stage
        failure_code = exc.code
    except (OSError, ValueError, KeyError, json.JSONDecodeError, sqlite3.Error):
        failure_stage = "unexpected_failure"
        failure_code = "acceptance_failed_safely"
    finally:
        if clone and powershell and (clone / "scripts/stop_system.ps1").is_file():
            _powershell_stage(
                powershell,
                clone / "scripts/stop_system.ps1",
                [],
                cwd=clone,
                timeout=90,
            )
        stages["process_cleanup"] = all(not _tcp_available(port) for port in REQUIRED_PORTS)
        if shell_root and provider:
            stages["mongo_cleanup"] = _drop_disposable_mongo(shell_root, provider)
        elif provider is None:
            stages["mongo_cleanup"] = True
        if workspace:
            stages["temporary_workspace_cleanup"] = remove_verified_temp_workspace(workspace, temp_root=temp_root)

    required_passed = all(stages.values())
    status = "clean_machine_acceptance_passed" if required_passed else "clean_machine_acceptance_failed"
    result = {
        "version": VERSION,
        "ok": required_passed,
        "status": status,
        "executed": True,
        "published_baseline": "origin/main",
        "stages": stages,
        "stage_summary": {
            "passed": sum(1 for passed in stages.values() if passed),
            "total": len(stages),
            "failed": [name for name, passed in stages.items() if not passed],
        },
        "failure_stage": failure_stage,
        "failure_code": failure_code,
        "metrics": metrics,
        "safety": {
            "authoritative_workspace_accessed": False,
            "configured_database_accessed": False,
            "authoritative_private_configuration_copied": False,
            "synthetic_non_network_provider_profile_used": provider is not None,
            "real_mfu_account_acceptance": "not_validated",
            "deterministic_rules_alert_authoritative": True,
            "supervised_ml_state": "unqualified",
            "model_activated_or_promoted": False,
            "assistant_external_provider_used": False,
            "assistant_raw_log_context_included": False,
            "automatic_response_enabled": False,
            "response_mode": "simulation_only",
            "real_firewall_blocking_enabled": False,
            "private_paths_exposed": False,
            "secrets_exposed": False,
            "production_readiness_claim": False,
        },
        "limitations": [
            "Synthetic provider configuration validates lifecycle wiring, not MFU account acceptance.",
            "Controlled evidence validates reproducibility, not independent field detection accuracy.",
            "The approved shell archive and real provider profile remain separately distributed dependencies.",
        ],
    }
    if not _public_report_is_redacted(result):
        result = {
            "version": VERSION,
            "ok": False,
            "status": "public_report_redaction_failed",
            "executed": True,
            "stages": stages,
            "failure_stage": "report_redaction",
            "failure_code": "public_report_contains_forbidden_value_class",
            "private_paths_exposed": False,
            "secrets_exposed": False,
        }
    return result
