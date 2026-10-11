"""What the launcher scripts do for a release (scripts/release.cmd, atdr/app/services/release_service.py).

A release stops ATDR's own parts and leaves the MFU sign-in page up, has the watcher start them again, and must
never be undone by a start of the wrong folder: the one ATDR is developed in, or one a release left half changed.
The scripts run here in a folder of their own, where nothing can reach a running ATDR.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"
OWN_PARTS = "atdr-backend,atdr-worker,atdr-syslog,atdr-frontend"
windows_only = pytest.mark.skipif(sys.platform != "win32", reason="runs the Windows launcher scripts")


def _powershell(command: str) -> str:
    result = subprocess.run(["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command],
                            capture_output=True, text=True, timeout=120, check=False)
    assert result.returncode == 0, result.stderr or result.stdout
    return result.stdout


def _script(path: Path, *arguments: str) -> subprocess.CompletedProcess:
    return subprocess.run(["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(path), *arguments],
                          capture_output=True, text=True, timeout=180, check=False, cwd=path.parent.parent)


def _quoted(path: Path) -> str:
    return "'" + str(path).replace("'", "''") + "'"


def _own_folder(tmp_path: Path, *names: str) -> Path:
    """The scripts in a folder of their own: its .atdr_runtime is the only one they can touch."""

    root = tmp_path / "ATDR on its own"
    (root / "scripts").mkdir(parents=True)
    (root / ".atdr_runtime").mkdir()
    for name in ("system_common.ps1", *names):
        shutil.copy2(SCRIPTS / name, root / "scripts" / name)
    return root


def _read(root: Path, name: str) -> dict:
    return json.loads((root / ".atdr_runtime" / name).read_text(encoding="utf-8-sig"))


def _sleeper() -> tuple[subprocess.Popen, str]:
    """A process of our own to stop, and the moment it started as the start script would record it."""

    process = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(300)"])
    started = _powershell(f"(Get-Process -Id {process.pid}).StartTime.ToUniversalTime().ToString('o')").strip()
    return process, started


@windows_only
def test_a_release_stops_atdrs_own_parts_and_leaves_the_sign_in_page_running_and_on_record(tmp_path):
    root = _own_folder(tmp_path, "stop_system.ps1")
    running = {name: _sleeper() for name in ("atdr-backend", "atdr-worker", "shell-backend", "shell-frontend")}
    try:
        (root / ".atdr_runtime" / "system-processes.json").write_text(json.dumps({
            "version": 1, "started_at": "2026-10-10T04:00:00.0000000Z", "secrets_stored": False,
            "processes": [{"name": name, "pid": process.pid, "started_at": started, "working_directory": str(root)}
                          for name, (process, started) in running.items()],
        }), encoding="utf-8")

        partly = _script(root / "scripts" / "stop_system.ps1", "-HoldHours", "2", "-Only", OWN_PARTS)

        assert partly.returncode == 0, partly.stderr
        for name in ("atdr-backend", "atdr-worker"):
            assert running[name][0].wait(timeout=20) is not None, f"{name} was stopped"
        for name in ("shell-backend", "shell-frontend"):
            assert running[name][0].poll() is None, f"{name} was left running"
        left = _read(root, "system-processes.json")
        assert [(record["name"], record["pid"]) for record in left["processes"]] == [
            ("shell-backend", running["shell-backend"][0].pid), ("shell-frontend", running["shell-frontend"][0].pid)]
        assert left["started_at"] and left["secrets_stored"] is False
        assert "Stopped 2 of ATDR's parts; still running: shell-backend, shell-frontend." in partly.stdout
        # ATDR as a whole counts as stopped, and held: the watcher starts nothing until the release asks it to.
        desired = _read(root, "desired-state.json")
        assert desired["state"] == "stopped" and desired["hold_until"]

        # A stop without -Only still stops everything that is left.
        everything = _script(root / "scripts" / "stop_system.ps1")
        assert everything.returncode == 0, everything.stderr
        for name in ("shell-backend", "shell-frontend"):
            assert running[name][0].wait(timeout=20) is not None
        assert not (root / ".atdr_runtime" / "system-processes.json").exists()
        assert "ATDR system stop complete. Processes stopped: 2" in everything.stdout
    finally:
        for process, _started in running.values():
            if process.poll() is None:
                process.kill()


@windows_only
def test_the_folder_atdr_is_developed_in_is_not_started_or_given_the_tasks_by_accident(tmp_path):
    root = _own_folder(tmp_path, "start_system.ps1", "stop_system.ps1")
    common = _quoted(root / "scripts" / "system_common.ps1")
    assert _powershell(f". {common}; [string](Get-AtdrLiveCopy)").strip() == "", "a folder with no live copy is its own"
    (root / ".atdr_runtime" / "live-copy.json").write_text(json.dumps({"root": "C:\\ATDR-live", "since": "2026-10-10T08:00:00+00:00"}), encoding="utf-8")
    assert _powershell(f". {common}; Get-AtdrLiveCopy").strip() == "C:\\ATDR-live"

    refused = _script(root / "scripts" / "start_system.ps1", "-NoBrowser")
    assert refused.returncode == 1
    assert ("ATDR startup failed: This is the folder ATDR is developed in; ATDR runs from C:\\ATDR-live. Start it there "
            "(C:\\ATDR-live\\scripts\\start_system.cmd), or put a new version there with .\\scripts\\release.cmd go. "
            "To start this folder's own copy anyway, add -Development.") in refused.stderr
    assert not (root / ".atdr_runtime" / "start.lock").exists() and not (root / ".atdr_runtime" / "desired-state.json").exists()
    # The watcher's start of one part is refused the same way: it is the same script.
    assert "This is the folder ATDR is developed in" in _script(root / "scripts" / "start_system.ps1", "-NoBrowser", "-Only", "atdr-worker").stderr

    # Asked for on purpose, it gets past that and as far as this folder can go: there is no MFU shell here to start.
    wanted = _script(root / "scripts" / "start_system.ps1", "-NoBrowser", "-Development")
    assert wanted.returncode == 1 and "This is the folder ATDR is developed in" not in wanted.stderr
    assert "ATDR startup failed: MFU supervisor shell path is not configured" in wanted.stderr

    # The sign-in start and the watcher belong to the folder ATDR runs from; here they are neither installed nor
    # removed. Read, not run: run with that refusal broken, this test would take the machine's real tasks away.
    installer = (SCRIPTS / "autostart.ps1").read_text(encoding="utf-8")
    refusal = installer[installer.index("$liveCopy = Get-AtdrLiveCopy"):installer.index("if ($Remove) {")]
    assert "if ($liveCopy) {" in refusal and "exit 1" in refusal and "Run $liveCopy\\scripts\\autostart.cmd instead." in refusal
    assert installer.index("if ($Status) {") < installer.index("$liveCopy = Get-AtdrLiveCopy") < installer.index("if ($Remove) {")
    assert installer.index("if ($Remove) {") < installer.index("Register-ScheduledTask"), "nothing is removed or installed before the refusal"

    stopped = _script(root / "scripts" / "stop_system.ps1")
    assert stopped.returncode == 0 and "ATDR itself runs from C:\\ATDR-live; stop it there." in stopped.stdout

    (root / ".atdr_runtime" / "live-copy.json").write_text("{ not json", encoding="utf-8")
    assert _powershell(f". {common}; [string](Get-AtdrLiveCopy)").strip() == ""


@windows_only
def test_a_folder_a_release_left_half_changed_is_started_by_the_release_alone(tmp_path):
    root = _own_folder(tmp_path, "start_system.ps1")
    common = _quoted(root / "scripts" / "system_common.ps1")
    assert _powershell(f". {common}; $null -eq (Get-AtdrUnfinishedRelease)").strip() == "True"
    began = datetime(2026, 10, 10, 5, 30, tzinfo=timezone.utc)
    (root / ".atdr_runtime" / "release-in-progress.json").write_text(json.dumps(
        {"from": "a" * 40, "to": "b" * 40, "started_at": began.isoformat(), "source": "C:\\Users\\User\\Desktop\\ATDR"}), encoding="utf-8")

    refused = _script(root / "scripts" / "start_system.ps1", "-NoBrowser")
    # The time is said by the machine's own clock, which is PowerShell's and not always this process's.
    local = _powershell("[datetime]::Parse('2026-10-10T05:30:00Z').ToLocalTime().ToString('yyyy-MM-dd HH:mm')").strip()
    assert refused.returncode == 1
    assert (f"ATDR startup failed: A release into this folder did not finish (it began {local}), so its files may be half of one "
            "version and half of another. Run .\\scripts\\release.cmd recover in C:\\Users\\User\\Desktop\\ATDR; it puts back the "
            "version that was running.") in refused.stderr
    assert not (root / ".atdr_runtime" / "start.lock").exists()

    # The release's own start gets past it (and, in this folder, no further than the missing MFU shell).
    release = _script(root / "scripts" / "start_system.ps1", "-NoBrowser", "-DuringRelease")
    assert release.returncode == 1 and "did not finish" not in release.stderr
    assert "ATDR startup failed: MFU supervisor shell path is not configured" in release.stderr

    # While the process that makes the release runs, the release is under way and not cut off. The watcher, which
    # tries to bring back a part that stopped while the new version is being watched, is told so.
    driver, driver_started = _sleeper()
    try:
        (root / ".atdr_runtime" / "release-in-progress.json").write_text(json.dumps(
            {"from": "a" * 40, "started_at": began.isoformat(), "source": "C:\\Users\\User\\Desktop\\ATDR",
             "driver": {"pid": driver.pid, "started_at": driver_started}}), encoding="utf-8")
        under_way = _script(root / "scripts" / "start_system.ps1", "-NoBrowser", "-Only", "atdr-worker")
        assert under_way.returncode == 1 and "did not finish" not in under_way.stderr
        assert (f"ATDR startup failed: A release into this folder is under way (it began {local}). It stops and starts ATDR itself, "
                "and puts the version before back when the new one does not come up; nothing was started.") in under_way.stderr
        assert _powershell(f". {common}; (Get-AtdrUnfinishedRelease).under_way").strip() == "True"
    finally:
        driver.kill()
        driver.wait()
    # The same record once that process is gone: cut off.
    cut_off = _script(root / "scripts" / "start_system.ps1", "-NoBrowser")
    assert cut_off.returncode == 1 and "did not finish" in cut_off.stderr and "under way" not in cut_off.stderr
    assert _powershell(f". {common}; (Get-AtdrUnfinishedRelease).under_way").strip() == "False"

    # A record that cannot be read is still an unfinished release.
    (root / ".atdr_runtime" / "release-in-progress.json").write_text("{ not json", encoding="utf-8")
    unreadable = _script(root / "scripts" / "start_system.ps1", "-NoBrowser")
    assert unreadable.returncode == 1 and "A release into this folder did not finish, so its files" in unreadable.stderr
    assert "recover in the folder ATDR is developed in" in unreadable.stderr

    start = (SCRIPTS / "start_system.ps1").read_text(encoding="utf-8")
    assert start.index("$liveCopy = Get-AtdrLiveCopy") < start.index("$unfinished = Get-AtdrUnfinishedRelease") < start.index("$locked = Enter-AtdrStartLock"), (
        "refused before anything is locked or started")


@windows_only
def test_a_start_that_is_refused_leaves_the_record_of_running_parts_as_it_is(tmp_path):
    # On 11 October 2026, during a release, the new version's worker stopped. The watcher tried to bring it back, the
    # start was refused (a release had not finished), and the refusal removed system-processes.json while four parts
    # ran. Nothing could see, stop or restart them, and the release could not put the version before back.
    root = _own_folder(tmp_path, "start_system.ps1", "stop_system.ps1")
    runtime = root / ".atdr_runtime"
    common = _quoted(root / "scripts" / "system_common.ps1")
    running = {name: _sleeper() for name in ("atdr-backend", "shell-frontend")}
    try:
        (runtime / "system-processes.json").write_text(json.dumps({
            "version": 1, "started_at": "2026-10-11T05:33:38.0000000Z", "secrets_stored": False,
            "processes": [{"name": name, "pid": process.pid, "started_at": started, "working_directory": str(root)}
                          for name, (process, started) in running.items()],
        }), encoding="utf-8")
        before = (runtime / "system-processes.json").read_bytes()
        _powershell(f". {common}; Set-AtdrDesiredState -State running -By 'test'")
        refusals = (
            ("release-in-progress.json", {"from": "a" * 40, "started_at": "2026-10-11T05:33:03+00:00"}, "did not finish"),
            ("live-copy.json", {"root": "C:\\ATDR-live"}, "the folder ATDR is developed in"),
        )
        for name, content, said in refusals:
            (runtime / name).write_text(json.dumps(content), encoding="utf-8")
            # As a person or the sign-in start asks, and as the watcher asks when it brings one part back.
            for arguments in (("-NoBrowser",), ("-NoBrowser", "-Only", "atdr-worker")):
                refused = _script(root / "scripts" / "start_system.ps1", *arguments)
                assert refused.returncode == 1 and said in refused.stderr, refused.stderr
                assert (runtime / "system-processes.json").read_bytes() == before, f"{name}: {arguments}"
                assert all(process.poll() is None for process, _started in running.values())
            (runtime / name).unlink()

        # A start that did look at the record and then failed (here: no MFU shell) keeps on it what was running.
        failed = _script(root / "scripts" / "start_system.ps1", "-NoBrowser", "-Only", "atdr-worker")
        assert failed.returncode == 1 and "MFU supervisor shell path is not configured" in failed.stderr
        kept = _read(root, "system-processes.json")
        assert sorted((record["name"], record["pid"]) for record in kept["processes"]) == sorted(
            (name, process.pid) for name, (process, _started) in running.items())

        # So the stop script still finds every part.
        stopped = _script(root / "scripts" / "stop_system.ps1")
        assert stopped.returncode == 0 and "Processes stopped: 2" in stopped.stdout
        for process, _started in running.values():
            assert process.wait(timeout=20) is not None

        # And a start that looked and found only parts that are gone still clears their record, as it always did:
        # the start of everything, and the watcher's start of one part.
        stale = json.dumps({"processes": [{"name": "atdr-backend", "pid": 2147483000, "started_at": "2000-01-01T00:00:00Z"}]})
        _powershell(f". {common}; Set-AtdrDesiredState -State running -By 'test'")
        for arguments in (("-NoBrowser",), ("-NoBrowser", "-Only", "atdr-worker")):
            (runtime / "system-processes.json").write_text(stale, encoding="utf-8")
            failed = _script(root / "scripts" / "start_system.ps1", *arguments)
            assert failed.returncode == 1 and "MFU supervisor shell path is not configured" in failed.stderr, failed.stderr
            assert not (runtime / "system-processes.json").exists(), arguments
    finally:
        for process, _started in running.values():
            if process.poll() is None:
                process.kill()


@windows_only
def test_the_watcher_starts_atdr_for_a_release_and_says_how_it_went(tmp_path):
    root = _own_folder(tmp_path, "watch_system.ps1", "start_system.ps1", "stop_system.ps1")
    runtime = root / ".atdr_runtime"
    assert _script(root / "scripts" / "stop_system.ps1", "-HoldHours", "2").returncode == 0
    (runtime / "start-request.json").write_text(json.dumps({"id": "release-1", "by": "release", "release": True}), encoding="utf-8")
    # A release that was cut off is on record: only the start the release asked for may pass it.
    (runtime / "release-in-progress.json").write_text(json.dumps({"from": "a" * 40, "started_at": "2026-10-10T05:30:00+00:00"}), encoding="utf-8")

    assert _script(root / "scripts" / "watch_system.ps1", "-Checks", "1").returncode == 0

    result = _read(root, "start-result.json")
    assert (result["id"], result["ok"], result["code"]) == ("release-1", False, 1)
    # In this folder there is no MFU shell, so the start fails; what matters is that it was the release's start that was tried.
    assert result["said"].startswith("ATDR startup failed: MFU supervisor shell path is not configured"), result["said"]
    assert result["asked_for"] == ["atdr-backend", "atdr-frontend", "shell-backend", "shell-frontend"] and result["at"]
    assert not (runtime / "start-request.json").exists() and not list(runtime.glob("*.arriving"))
    desired = _read(root, "desired-state.json")
    assert (desired["state"], desired["by"], desired["hold_until"]) == ("running", "release", None), "the hold the release set is over"
    log = (runtime / "logs" / "watch.log").read_text(encoding="utf-8-sig")
    assert "Starting ATDR, asked by release." in log and "What release asked for did not start (exit code 1)" in log
    status = _read(root, "watch-status.json")
    # The check that followed tried a start of its own, as for any ATDR that is meant to run and does not; that one
    # is refused by the unfinished release, and it is the only one counted as a restart.
    assert len(status["all_restarts"]) == 1 and "did not finish" in status["last_action"]["said"]

    # A request nobody can read is dropped, not answered and not tried for ever.
    (runtime / "start-result.json").unlink()
    (runtime / "start-request.json").write_text("{ not json", encoding="utf-8")
    assert _script(root / "scripts" / "watch_system.ps1", "-Checks", "1").returncode == 0
    assert not (runtime / "start-request.json").exists() and not (runtime / "start-result.json").exists()
    assert "A request to start ATDR could not be read and was dropped." in (runtime / "logs" / "watch.log").read_text(encoding="utf-8-sig")


@windows_only
def test_a_request_to_start_is_answered_within_seconds_not_at_the_next_check(tmp_path):
    root = _own_folder(tmp_path, "watch_system.ps1", "start_system.ps1", "stop_system.ps1")
    runtime = root / ".atdr_runtime"
    assert _script(root / "scripts" / "stop_system.ps1", "-HoldHours", "2").returncode == 0
    began = time.monotonic()
    watcher = subprocess.Popen(
        ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(root / "scripts" / "watch_system.ps1"),
         "-Checks", "2", "-IntervalSeconds", "120"], cwd=root, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        # Its first check has been made (the status is written) and it is waiting for the second.
        deadline = time.monotonic() + 60
        while not (runtime / "watch-status.json").exists() and time.monotonic() < deadline:
            time.sleep(0.5)
        assert (runtime / "watch-status.json").exists()
        (runtime / "start-request.json").write_text(json.dumps({"id": "release-2", "by": "release", "release": True}), encoding="utf-8")
        assert watcher.wait(timeout=90) == 0
    finally:
        if watcher.poll() is None:
            watcher.kill()
    assert time.monotonic() - began < 100, "it did not wait out the two minutes to its next check"
    assert _read(root, "start-result.json")["id"] == "release-2"


@windows_only
def test_the_system_check_says_which_version_runs_and_which_folder_it_is_in(tmp_path):
    root = _own_folder(tmp_path, "check_system.ps1")
    common = _quoted(root / "scripts" / "system_common.ps1")
    assert _powershell(f". {common}; $null -eq (Get-AtdrReleasedVersion)").strip() == "True"

    # In the folder ATDR is developed in: no version of its own, and where to look instead.
    (root / ".atdr_runtime" / "live-copy.json").write_text(json.dumps({"root": "C:\\ATDR-live"}), encoding="utf-8")
    here = _script(root / "scripts" / "check_system.ps1")
    assert "  Version:" not in here.stdout
    assert ("  This is the folder ATDR is developed in. ATDR runs from C:\\ATDR-live; what follows is this folder's own: "
            "check there with C:\\ATDR-live\\scripts\\check_system.cmd") in here.stdout
    assert here.stdout.index("This is the folder ATDR is developed in") < here.stdout.index("  Meant to be:")

    # In a live copy: the version its record names, and when it went live by this machine's clock.
    (root / ".atdr_runtime" / "live-copy.json").unlink()
    (root / ".atdr_runtime" / "release.json").write_text(json.dumps(
        {"commit": "1768cda" + "0" * 33, "short": "1768cda", "released_at": "2026-10-11T04:48:03.123456+00:00", "check": "x"}), encoding="utf-8")
    local = _powershell("[datetime]::Parse('2026-10-11T04:48:03Z').ToLocalTime().ToString('yyyy-MM-dd HH:mm')").strip()
    there = _script(root / "scripts" / "check_system.ps1")
    assert f"  Version: 1768cda, live since {local}" in there.stdout and "the folder ATDR is developed in" not in there.stdout
    assert _powershell(f". {common}; (Get-AtdrReleasedVersion).short").strip() == "1768cda"

    for unusable in ('{"short": " ", "released_at": "2026-10-11T04:48:03+00:00", "check": "x"}', '{"short": "1768cda"}', "{ not json"):
        (root / ".atdr_runtime" / "release.json").write_text(unusable, encoding="utf-8")
        assert _powershell(f". {common}; $null -eq (Get-AtdrReleasedVersion)").strip() == "True"
    assert "  Version:" not in _script(root / "scripts" / "check_system.ps1").stdout


def test_what_the_scripts_promise_a_release():
    common = (SCRIPTS / "system_common.ps1").read_text(encoding="utf-8")
    watcher = (SCRIPTS / "watch_system.ps1").read_text(encoding="utf-8")
    stop = (SCRIPTS / "stop_system.ps1").read_text(encoding="utf-8")
    start = (SCRIPTS / "start_system.ps1").read_text(encoding="utf-8")

    # release_service reads these two texts to know what the folder's scripts can do.
    assert '"start-request.json"' in common and "[string[]]$Only = @()" in stop
    # The watcher is ended by its own process, never by ending its task, which would end the parts it started.
    restart = common[common.index("function Restart-AtdrWatcher"):common.index("# ---- Releases")]
    assert "Stop-AtdrWatcherProcess" in restart and "Start-AtdrWatcherTask" in restart and "Stop-ScheduledTask" not in restart
    # A request is answered before the check, is taken away before it is acted on, and is no restart.
    request = watcher[watcher.index("function Invoke-AtdrStartRequest"):watcher.index("function Invoke-AtdrWatchCheck")]
    assert request.index("Remove-Item -LiteralPath $path") < request.index("Set-AtdrDesiredState") < request.index("Invoke-AtdrStart -")
    assert "Add-AtdrRestart" not in request and "-DuringRelease:$release" in request
    loop = watcher[watcher.index("while ($true) {"):]
    assert loop.index("Invoke-AtdrStartRequest") < loop.index("Invoke-AtdrWatchCheck")
    assert "Test-Path -LiteralPath (Get-AtdrStartRequestPath)" in loop
    # Only what a release asks for passes an unfinished release; a part that is brought back does not.
    assert 'if ($DuringRelease) { $arguments += "-DuringRelease" }' in watcher
    assert watcher.count("-DuringRelease:$release") == 2 and "Invoke-AtdrStart -Only $names\n" in watcher.replace("\r\n", "\n")
    assert "if ($null -ne $unfinished -and -not $DuringRelease) {" in start and "if ($liveCopy -and -not $Development) {" in start
    # With a build to serve, the tools that make one are not needed to start.
    assert "if (-not (Test-Path -LiteralPath $reactCli) -and -not $dashboardBuilt) {" in start


def test_release_cmd_runs_the_release_with_the_development_folders_python():
    wrapper = (SCRIPTS / "release.cmd").read_text(encoding="utf-8")
    assert '".venv\\Scripts\\python.exe" -m atdr.scripts.release %*' in wrapper and 'pushd "%~dp0.."' in wrapper
    assert wrapper.rstrip().endswith("exit /b %ATDR_RELEASE_EXIT%")
    ignored = (ROOT / ".gitignore").read_text(encoding="utf-8").split()
    assert ".venvs/" in ignored and ".python/" in ignored, "a live copy's Python is never taken for a change to its files"
