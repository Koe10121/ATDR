import argparse
import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Sequence

from atdr.app.core.config import PROJECT_ROOT


DEFAULT_TIMEOUT_SECONDS = 300.0
EXCERPT_LIMIT = 4000


@dataclass(frozen=True)
class CommandExecution:
    return_code: int
    stdout: str = ""
    stderr: str = ""


CommandRunner = Callable[[Sequence[str], float], CommandExecution]


def _excerpt(value: str, *, limit: int = EXCERPT_LIMIT) -> str:
    if len(value) <= limit:
        return value
    return value[: limit - 3] + "..."


def _default_runner(command: Sequence[str], timeout: float) -> CommandExecution:
    temp_dir = Path(PROJECT_ROOT) / ".tmp" / "release-tmp"
    temp_dir.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env["TMP"] = str(temp_dir)
    env["TEMP"] = str(temp_dir)
    try:
        completed = subprocess.run(
            list(command),
            cwd=PROJECT_ROOT,
            capture_output=True,
            check=False,
            env=env,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError as exc:
        return CommandExecution(return_code=127, stderr=str(exc))
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout if isinstance(exc.stdout, str) else ""
        stderr = exc.stderr if isinstance(exc.stderr, str) else ""
        return CommandExecution(return_code=124, stdout=stdout, stderr=stderr or f"Command timed out after {timeout} seconds.")
    except OSError as exc:
        return CommandExecution(return_code=1, stderr=f"{exc.__class__.__name__}: {exc}")
    return CommandExecution(return_code=completed.returncode, stdout=completed.stdout, stderr=completed.stderr)


def _command_check(
    *,
    name: str,
    command: Sequence[str],
    runner: CommandRunner,
    timeout: float,
    required: bool = True,
) -> tuple[dict, CommandExecution]:
    started = time.perf_counter()
    execution = runner(command, timeout)
    duration = time.perf_counter() - started
    ok = execution.return_code == 0
    return (
        {
            "name": name,
            "ok": ok,
            "required": required,
            "skipped": False,
            "command": list(command),
            "return_code": execution.return_code,
            "duration_seconds": round(duration, 3),
            "stdout_excerpt": _excerpt(execution.stdout),
            "stderr_excerpt": _excerpt(execution.stderr),
        },
        execution,
    )


def _skipped_check(name: str, message: str) -> dict:
    return {
        "name": name,
        "ok": True,
        "required": False,
        "skipped": True,
        "message": message,
    }


def _parse_json_stdout(execution: CommandExecution) -> dict | None:
    text = execution.stdout.strip()
    if not text:
        return None
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return None
    return payload if isinstance(payload, dict) else None


def run_verify_release(
    *,
    include_smoke: bool = False,
    require_docker: bool = False,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    runner: CommandRunner | None = None,
) -> dict:
    runner = runner or _default_runner
    include_smoke = include_smoke or require_docker
    python = sys.executable
    checks: list[dict] = []

    required_commands: list[tuple[str, list[str]]] = [
        ("config_doctor", [python, "-m", "atdr.scripts.config_doctor"]),
        ("compileall", [python, "-m", "compileall", "-q", "atdr", "migrations"]),
        ("pytest", [python, "-m", "pytest", "atdr/tests", "-q", "-o", "cache_dir=.tmp/pytest-cache"]),
        ("alembic_check", [python, "-m", "alembic", "check"]),
    ]

    for name, command in required_commands:
        check, _ = _command_check(name=name, command=command, runner=runner, timeout=timeout, required=True)
        checks.append(check)

    if include_smoke:
        smoke_command = [python, "-m", "atdr.scripts.lab_smoke_check"]
        smoke_check, smoke_execution = _command_check(
            name="lab_smoke_check",
            command=smoke_command,
            runner=runner,
            timeout=timeout,
            required=True,
        )
        smoke_payload = _parse_json_stdout(smoke_execution)
        if smoke_payload is not None:
            smoke_check["details"] = {
                "local_stack_ok": bool(smoke_payload.get("local_stack_ok")),
                "docker_validated": bool(smoke_payload.get("docker_validated")),
            }
            if require_docker and not smoke_payload.get("docker_validated"):
                smoke_check["ok"] = False
                smoke_check["failure_reason"] = "Docker validation is required but docker_compose did not pass."
        elif require_docker:
            smoke_check["ok"] = False
            smoke_check["failure_reason"] = "Docker validation is required but lab smoke output was not parseable JSON."
        checks.append(smoke_check)
    else:
        checks.append(_skipped_check("lab_smoke_check", "Skipped. Pass --include-smoke to verify a running local stack."))

    failed_required = [check["name"] for check in checks if check.get("required") and not check.get("ok")]
    return {
        "ok": not failed_required,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "project_root": str(Path(PROJECT_ROOT)),
        "include_smoke": include_smoke,
        "require_docker": require_docker,
        "python_executable": python,
        "failed_required_checks": failed_required,
        "checks": checks,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the ATDR production-quality release verification gate.")
    parser.add_argument("--include-smoke", action="store_true", help="Also run lab smoke checks against the running API/dashboard.")
    parser.add_argument("--require-docker", action="store_true", help="Fail if Docker Compose validation is not available or does not pass.")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT_SECONDS, help="Per-check timeout in seconds.")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON output.")
    args = parser.parse_args()

    result = run_verify_release(
        include_smoke=args.include_smoke,
        require_docker=args.require_docker,
        timeout=args.timeout,
    )
    print(json.dumps(result, indent=2 if args.pretty else None, default=str))
    raise SystemExit(0 if result["ok"] else 1)


if __name__ == "__main__":
    main()
