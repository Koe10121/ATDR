import json
from pathlib import Path
from typing import Sequence

from atdr.scripts.verify_release import DEFAULT_TIMEOUT_SECONDS, CommandExecution, run_verify_release


def _passing_runner(command: Sequence[str], timeout: float) -> CommandExecution:
    del timeout
    command_text = " ".join(command)
    if "config_doctor" in command_text:
        return CommandExecution(0, stdout='{"ok": true, "critical_count": 0}')
    if "lab_smoke_check" in command_text:
        return CommandExecution(0, stdout='{"local_stack_ok": true, "docker_validated": false}')
    return CommandExecution(0, stdout="ok")


def test_verify_release_json_shape_and_skipped_smoke():
    result = run_verify_release(runner=_passing_runner)
    checks = {check["name"]: check for check in result["checks"]}

    assert result["ok"] is True
    assert result["include_smoke"] is False
    assert result["require_docker"] is False
    assert result["failed_required_checks"] == []
    assert {
        "config_doctor",
        "compileall",
        "pytest",
        "alembic_check",
        "deployment_operations",
        "lab_smoke_check",
    } <= set(checks)
    assert checks["lab_smoke_check"]["skipped"] is True
    assert checks["pytest"]["return_code"] == 0
    pytest_basetemp = next(item for item in checks["pytest"]["command"] if item.startswith("--basetemp="))
    assert pytest_basetemp.startswith("--basetemp=.tmp/pytest-release-tmp-")
    compile_command = checks["compileall"]["command"]
    assert "-x" in compile_command
    assert r"atdr[\\/]data[\\/]processed" in compile_command
    assert "duration_seconds" in checks["compileall"]
    json.dumps(result)


def test_verify_release_default_timeout_allows_full_backend_suite_runtime():
    assert DEFAULT_TIMEOUT_SECONDS >= 900.0


def test_verify_release_required_command_failure_is_reported():
    def runner(command: Sequence[str], timeout: float) -> CommandExecution:
        del timeout
        if "pytest" in " ".join(command):
            return CommandExecution(1, stderr="tests failed")
        return CommandExecution(0, stdout="ok")

    result = run_verify_release(runner=runner)
    checks = {check["name"]: check for check in result["checks"]}

    assert result["ok"] is False
    assert result["failed_required_checks"] == ["pytest"]
    assert checks["pytest"]["ok"] is False
    assert checks["pytest"]["stderr_excerpt"] == "tests failed"


def test_verify_release_include_smoke_does_not_fail_for_missing_docker():
    result = run_verify_release(include_smoke=True, runner=_passing_runner)
    smoke = {check["name"]: check for check in result["checks"]}["lab_smoke_check"]

    assert result["ok"] is True
    assert smoke["ok"] is True
    assert smoke["details"]["local_stack_ok"] is True
    assert smoke["details"]["docker_validated"] is False


def test_verify_release_require_docker_fails_when_docker_is_not_validated():
    result = run_verify_release(require_docker=True, runner=_passing_runner)
    smoke = {check["name"]: check for check in result["checks"]}["lab_smoke_check"]

    assert result["ok"] is False
    assert result["include_smoke"] is True
    assert result["failed_required_checks"] == ["lab_smoke_check"]
    assert smoke["ok"] is False
    assert "Docker validation is required" in smoke["failure_reason"]


def test_release_docs_reference_quality_gate_and_optional_browser_smoke():
    release = Path("docs/RELEASE_CHECKLIST.md").read_text(encoding="utf-8")
    readme = Path("README.md").read_text(encoding="utf-8")

    for text in [release, readme]:
        assert "python -m atdr.scripts.verify_release" in text
        assert "ATDR_RUN_PLAYWRIGHT" in text
    for phrase in [
        "config_doctor",
        "Alembic",
        "backup_postgres --dry-run",
        "lab_smoke_check",
        "Docker/PostgreSQL validation",
        "Rollback",
    ]:
        assert phrase in release
