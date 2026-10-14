"""ATDR brings back a part that stops, and leaves ATDR alone after it was stopped on purpose.

Nothing restarted a part of ATDR that died: the start script launched five processes and recorded them, and after
one of them ended ATDR stayed broken until someone ran stop and start by hand. scripts/watch_system.ps1 now looks
every half minute. These tests run its decisions (scripts/system_common.ps1) and the scripts themselves in a
folder of their own, where nothing can reach a running ATDR.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"
NOW = datetime(2026, 10, 9, 5, 0, tzinfo=timezone.utc)
FOUR = ["atdr-backend", "atdr-frontend", "shell-backend", "shell-frontend"]
ALL = [*FOUR, "atdr-worker"]


def _powershell(command: str, *, cwd: Path | None = None) -> str:
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command],
        capture_output=True, text=True, timeout=120, check=False, cwd=cwd,
    )
    assert result.returncode == 0, result.stderr or result.stdout
    return result.stdout


def _script(path: Path, *arguments: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(path), *arguments],
        capture_output=True, text=True, timeout=180, check=False, cwd=path.parent.parent,
    )


def _quoted(path: Path) -> str:
    return "'" + str(path).replace("'", "''") + "'"


def _time(moment: datetime) -> str:
    return f"([datetime]::Parse('{moment.strftime('%Y-%m-%dT%H:%M:%SZ')}').ToUniversalTime())"


def _names(names: list[str]) -> str:
    return "@(" + ",".join(f"'{name}'" for name in names) + ")"


def _table(values: dict[str, str]) -> str:
    return "@{" + ";".join(f"'{key}'={value}" for key, value in values.items()) + "}"


def _decide(desired: str, alive: list[str], *, expected: list[str] | None = None, hold_until: datetime | None = None,
            unanswered: dict[str, int] | None = None, started_minutes_ago: dict[str, float] | None = None,
            restarted_minutes_ago: dict[str, list[float]] | None = None) -> dict:
    arguments = [f"-DesiredState {desired}", f"-Now {_time(NOW)}", f"-Expected {_names(expected or ALL)}", f"-Alive {_names(alive)}"]
    if hold_until is not None:
        arguments.append(f"-HoldUntil {_time(hold_until)}")
    if unanswered:
        arguments.append("-Unanswered " + _table({name: str(count) for name, count in unanswered.items()}))
    if started_minutes_ago:
        arguments.append("-StartedAt " + _table({name: _time(NOW - timedelta(minutes=ago)) for name, ago in started_minutes_ago.items()}))
    if restarted_minutes_ago:
        arguments.append("-Restarts " + _table({
            name: "@(" + ",".join(_time(NOW - timedelta(minutes=ago)) for ago in times) + ")"
            for name, times in restarted_minutes_ago.items()
        }))
    output = _powershell(f". {_quoted(SCRIPTS / 'system_common.ps1')}; Get-AtdrWatchDecision {' '.join(arguments)} | ConvertTo-Json -Compress -Depth 4")
    decision = json.loads(output)
    return {key: (value if isinstance(value, list) or key in ("action", "resume", "reason") else [value]) for key, value in decision.items()}


def _does(decision: dict) -> tuple[str, list[str], list[str], list[str]]:
    return decision["action"], decision["start"], decision["restart"], decision["waiting"]


def test_a_part_that_stopped_is_started_and_a_healthy_atdr_is_left_alone():
    assert _does(_decide("running", ALL)) == ("none", [], [], [])
    one = _decide("running", [name for name in ALL if name != "atdr-worker"])
    assert _does(one) == ("parts", ["atdr-worker"], [], []) and one["reason"] == "stopped: atdr-worker"
    two = _decide("running", ["atdr-backend", "shell-backend", "shell-frontend"])
    assert _does(two) == ("parts", ["atdr-frontend", "atdr-worker"], [], []), "both in one start"

    # Only what ATDR is set up to run: a worker that is switched off is not started, a stray extra part is ignored.
    assert _does(_decide("running", FOUR, expected=FOUR)) == ("none", [], [], [])
    assert _does(_decide("running", [*ALL, "atdr-syslog"])) == ("none", [], [], [])


def test_nothing_running_means_a_whole_start():
    nothing = _decide("running", [])
    assert _does(nothing) == ("start_all", [], [], []) and nothing["reason"] == "no part is running"
    # A part that is not one of ATDR's own does not count as ATDR running.
    assert _decide("running", ["atdr-syslog"], expected=FOUR)["action"] == "start_all"


def test_atdr_stopped_on_purpose_is_left_stopped():
    stopped = _decide("stopped", [])
    assert _does(stopped) == ("none", [], [], []) and stopped["resume"] is False and stopped["reason"] == "stopped on purpose"
    # Also when a part is still running, or half of them: stop_system is stopping them.
    assert _decide("stopped", ["atdr-backend"])["action"] == "none"
    never = _decide("unknown", [])
    assert never["action"] == "none" and "has not been started" in never["reason"]


def test_a_stop_that_was_to_last_two_hours_ends_by_itself():
    held = _decide("stopped", [], hold_until=NOW + timedelta(minutes=1))
    assert (held["action"], held["resume"]) == ("none", False) and held["reason"].startswith("stopped on purpose until 2026-10-09T05:01:00")
    over = _decide("stopped", [], hold_until=NOW)
    assert (over["action"], over["resume"], over["reason"]) == ("start_all", True, "the time it was to stay stopped has passed")


def test_a_part_that_runs_but_does_not_answer_is_restarted_after_three_minutes():
    old = {"atdr-backend": 120.0}
    assert _decide("running", ALL, unanswered={"atdr-backend": 5}, started_minutes_ago=old)["action"] == "none"
    silent = _decide("running", ALL, unanswered={"atdr-backend": 6}, started_minutes_ago=old)
    assert _does(silent) == ("parts", [], ["atdr-backend"], []) and silent["reason"] == "not answering: atdr-backend"

    # The MFU shell compiles for minutes after it starts: silence then is not a fault.
    assert _decide("running", ALL, unanswered={"shell-frontend": 40}, started_minutes_ago={"shell-frontend": 4.9})["action"] == "none"
    assert _decide("running", ALL, unanswered={"shell-frontend": 40}, started_minutes_ago={"shell-frontend": 5.0})["restart"] == ["shell-frontend"]

    # One part stopped and another silent: one action for both.
    both = _decide("running", [name for name in ALL if name != "atdr-worker"], unanswered={"atdr-frontend": 9},
                   started_minutes_ago={"atdr-frontend": 60.0})
    assert _does(both) == ("parts", ["atdr-worker"], ["atdr-frontend"], [])
    assert both["reason"] == "stopped: atdr-worker; not answering: atdr-frontend"


def test_a_part_that_keeps_dying_is_tried_three_times_in_ten_minutes_then_every_five():
    dead = [name for name in ALL if name != "atdr-worker"]
    assert _decide("running", dead, restarted_minutes_ago={"atdr-worker": [9, 2]})["start"] == ["atdr-worker"]
    waiting = _decide("running", dead, restarted_minutes_ago={"atdr-worker": [9, 6, 2]})
    assert _does(waiting) == ("none", [], [], ["atdr-worker"]) and waiting["reason"].startswith("keeps stopping: atdr-worker")
    assert _decide("running", dead, restarted_minutes_ago={"atdr-worker": [9, 8, 4.9]})["waiting"] == ["atdr-worker"]
    assert _decide("running", dead, restarted_minutes_ago={"atdr-worker": [9, 8, 5]})["start"] == ["atdr-worker"]
    # Restarts of more than ten minutes ago are forgotten, and another part is not held back by this one.
    assert _decide("running", dead, restarted_minutes_ago={"atdr-worker": [30, 20, 11]})["start"] == ["atdr-worker"]
    other = _decide("running", ["atdr-frontend", "shell-backend", "shell-frontend"], restarted_minutes_ago={"atdr-worker": [9, 6, 2]})
    assert _does(other) == ("parts", ["atdr-backend"], [], ["atdr-worker"])

    # The same for a whole start that keeps failing, and for a part that stays silent.
    failing = _decide("running", [], restarted_minutes_ago={"*": [9, 6, 2]})
    assert _does(failing) == ("none", [], [], ["*"]) and "did not start" in failing["reason"]
    assert _decide("running", [], restarted_minutes_ago={"*": [9, 8, 5]})["action"] == "start_all"
    silent = _decide("running", ALL, unanswered={"atdr-backend": 20}, started_minutes_ago={"atdr-backend": 60.0},
                     restarted_minutes_ago={"atdr-backend": [8, 5, 1]})
    assert _does(silent) == ("none", [], [], ["atdr-backend"])


def _reports(told: list[str], waiting: list[str], *, alive: list[str] | None = None, expected: list[str] | None = None,
             meant_to_run: bool = True, started_minutes_ago: dict[str, float] | None = None) -> tuple[list[str], list[str]]:
    arguments = [f"-Told {_names(told)}", f"-Waiting {_names(waiting)}", f"-Expected {_names(expected or ALL)}",
                 f"-Alive {_names(ALL if alive is None else alive)}", f"-Now {_time(NOW)}"]
    if meant_to_run:
        arguments.append("-MeantToRun")
    if started_minutes_ago:
        arguments.append("-StartedAt " + _table({name: _time(NOW - timedelta(minutes=ago)) for name, ago in started_minutes_ago.items()}))
    found = json.loads(_powershell(f". {_quoted(SCRIPTS / 'system_common.ps1')}; Get-AtdrProblemReports {' '.join(arguments)} | ConvertTo-Json -Compress"))

    def listed(value) -> list[str]:
        return value if isinstance(value, list) else ([] if value is None else [value])

    return listed(found["report"]), listed(found["over"])


def test_people_are_told_once_when_a_part_keeps_stopping_and_again_when_it_has_stayed_up():
    # A part that stopped stayed on the System panel as "keeps stopping", for whoever happened to open it.
    assert _reports([], ["atdr-worker"]) == (["atdr-worker"], [])
    assert _reports(["atdr-worker"], ["atdr-worker"]) == ([], []), "told once"

    # Tried again every five minutes, it runs for a moment each time: that is not yet over.
    assert _reports(["atdr-worker"], [], started_minutes_ago={"atdr-worker": 9.9}) == ([], [])
    assert _reports(["atdr-worker"], [], started_minutes_ago={"atdr-worker": 10.0}) == ([], ["atdr-worker"])
    down = [name for name in ALL if name != "atdr-worker"]
    assert _reports(["atdr-worker"], [], alive=down, started_minutes_ago={"atdr-worker": 60.0}) == ([], []), "down between two tries"
    assert _reports(["atdr-worker"], []) == ([], []), "running, but since when is not known"

    # One part over while another begins.
    assert _reports(["atdr-worker"], ["atdr-backend"], started_minutes_ago={"atdr-worker": 30.0}) == (["atdr-backend"], ["atdr-worker"])
    # A part ATDR no longer runs, or ATDR stopped on purpose: no longer a problem.
    assert _reports(["atdr-syslog"], []) == ([], ["atdr-syslog"])
    assert _reports(["atdr-worker", "*"], [], meant_to_run=False, alive=[]) == ([], ["atdr-worker", "*"])


def test_people_are_told_when_atdr_cannot_be_started_and_when_every_part_runs_again():
    assert _reports([], ["*"], alive=[]) == (["*"], [])
    assert _reports(["*"], ["*"], alive=[]) == ([], [])
    assert _reports(["*"], [], alive=FOUR) == ([], []), "the worker is still missing"
    assert _reports(["*"], [], alive=ALL) == ([], ["*"])


def test_the_watcher_tells_people_through_a_command_that_does_not_need_the_worker(tmp_path):
    watch = (SCRIPTS / "watch_system.ps1").read_text(encoding="utf-8")
    assert '@("-m", "atdr.scripts.notify")' in watch and '"--not-starting"' in watch and '@("--part", $Key)' in watch and '"--over"' in watch
    assert watch.index("Move-Item -LiteralPath $arriving") < watch.index("Get-AtdrProblemReports -Told"), (
        "telling takes seconds: the status is written first, or the System panel would call the watcher gone")

    # What was told is in the status, for the watcher that comes after this one.
    root = _own_folder(tmp_path, "watch_system.ps1", "stop_system.ps1")
    assert _script(root / "scripts" / "stop_system.ps1").returncode == 0
    assert _script(root / "scripts" / "watch_system.ps1", "-Checks", "1").returncode == 0
    status = _read(root, "watch-status.json")
    assert status["problems_told"] == []
    # The watcher before this one had told people. This one cannot tell them it is over (this folder has no
    # Python to tell with), so both stay on record to be tried again.
    status["problems_told"] = ["atdr-worker", "*"]
    (root / ".atdr_runtime" / "watch-status.json").write_text(json.dumps(status), encoding="utf-8")
    again = _script(root / "scripts" / "watch_system.ps1", "-Checks", "1")
    assert again.returncode == 0, again.stderr
    assert _read(root, "watch-status.json")["problems_told"] == ["*", "atdr-worker"]

    # A status written before this was added has no such list, and is read without an error.
    del status["problems_told"]
    status["parts"] = [{"name": "atdr-backend", "running": True, "restarts": ["2026-10-09T04:53:16.7393800Z"]}]
    (root / ".atdr_runtime" / "watch-status.json").write_text(json.dumps(status), encoding="utf-8")
    assert _script(root / "scripts" / "watch_system.ps1", "-Checks", "1").returncode == 0
    older = _read(root, "watch-status.json")
    assert older["problems_told"] == []
    assert "A check failed" not in (root / ".atdr_runtime" / "logs" / "watch.log").read_text(encoding="utf-8-sig")


def test_the_parts_atdr_expects_follow_its_settings():
    common = _quoted(SCRIPTS / "system_common.ps1")
    expected = _powershell(
        f". {common}; (Get-AtdrExpectedParts @{{ OPERATION_WORKER_ENABLED = 'true'; SYSLOG_ENABLED = 'TRUE' }}) -join ','; "
        "(Get-AtdrExpectedParts @{ OPERATION_WORKER_ENABLED = 'false' }) -join ','; (Get-AtdrExpectedParts @{}) -join ','"
    ).split()
    assert expected == [",".join([*FOUR, "atdr-worker", "atdr-syslog"]), ",".join(FOUR), ",".join(FOUR)]
    addresses = _powershell(f". {common}; 'atdr-backend','atdr-frontend','shell-backend','shell-frontend','atdr-worker','atdr-syslog' | ForEach-Object {{ \"$_=$(Get-AtdrPartAddress $_)\" }}").split()
    assert addresses == [
        "atdr-backend=http://127.0.0.1:8000/health/live", "atdr-frontend=http://127.0.0.1:5173",
        "shell-backend=http://127.0.0.1:8214/healthz", "shell-frontend=http://localhost:8080", "atdr-worker=", "atdr-syslog=",
    ]


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


def test_stopping_is_put_on_record_before_anything_is_stopped_and_can_be_made_to_last(tmp_path):
    root = _own_folder(tmp_path, "stop_system.ps1")
    (root / ".atdr_runtime" / "system-processes.json").write_text(
        json.dumps({"processes": [{"name": "atdr-backend", "pid": 2147483000, "started_at": "2000-01-01T00:00:00Z"}]}), encoding="utf-8")

    plain = _script(root / "scripts" / "stop_system.ps1")
    assert plain.returncode == 0, plain.stderr
    desired = _read(root, "desired-state.json")
    assert (desired["state"], desired["by"], desired["hold_until"]) == ("stopped", "stop_system", None)
    assert not (root / ".atdr_runtime" / "system-processes.json").exists()
    assert "Restart: .\\scripts\\start_system.cmd" in plain.stdout

    before = datetime.now(timezone.utc)
    held = _script(root / "scripts" / "stop_system.ps1", "-HoldHours", "2")
    assert held.returncode == 0, held.stderr
    until = datetime.fromisoformat(_read(root, "desired-state.json")["hold_until"][:26].rstrip("Z") + "+00:00")
    assert timedelta(hours=1, minutes=59) < until - before < timedelta(hours=2, minutes=1)
    assert "ATDR stays stopped until" in held.stdout and "also across a sign-in" in held.stdout

    script = (SCRIPTS / "stop_system.ps1").read_text(encoding="utf-8")
    assert script.index("Set-AtdrDesiredState -State \"stopped\"") < script.index("Stop-Process -Id $process.Id -Force"), (
        "the watcher must read 'stopped' before a part goes, or it would bring that part back")
    assert "Test-AtdrStartLockHeld" in script, "a start that is under way finishes first"


def test_what_atdr_is_meant_to_be_is_read_back_as_written(tmp_path):
    root = _own_folder(tmp_path)
    common = _quoted(root / "scripts" / "system_common.ps1")
    show = "$d = Read-AtdrDesiredState; \"$($d.state)|$($d.by)|$([bool]$d.hold_until)|$(Test-AtdrHeld $d)\""
    assert _powershell(f". {common}; {show}").strip() == "unknown||False|False"
    assert _powershell(f". {common}; Set-AtdrDesiredState -State running -By 'start_system'; {show}").strip() == "running|start_system|False|False"
    assert _powershell(f". {common}; Set-AtdrDesiredState -State stopped -By 'stop_system' -HoldUntil (Get-Date).AddHours(1); {show}").strip() == "stopped|stop_system|True|True"
    assert _powershell(f". {common}; Set-AtdrDesiredState -State stopped -By 'stop_system' -HoldUntil (Get-Date).AddSeconds(-5); {show}").strip() == "stopped|stop_system|True|False"
    # A time to stay stopped until means nothing for a system that is meant to run.
    assert _powershell(f". {common}; Set-AtdrDesiredState -State running -By 'start_system' -HoldUntil (Get-Date).AddHours(1); {show}").strip() == "running|start_system|False|False"
    (root / ".atdr_runtime" / "desired-state.json").write_text("{ not json", encoding="utf-8")
    assert _powershell(f". {common}; {show}").strip() == "unknown||False|False"


def test_one_check_of_a_stopped_atdr_starts_nothing_and_says_why(tmp_path):
    root = _own_folder(tmp_path, "watch_system.ps1", "stop_system.ps1")
    assert _script(root / "scripts" / "stop_system.ps1").returncode == 0
    check = _script(root / "scripts" / "watch_system.ps1", "-Checks", "1")
    assert check.returncode == 0, check.stderr
    status = _read(root, "watch-status.json")
    assert status["note"] == "stopped on purpose" and status["desired"]["state"] == "stopped" and status["last_action"] is None
    assert [(part["name"], part["running"], part["restarts"]) for part in status["parts"]] == [(name, False, []) for name in FOUR]
    assert status["watcher"]["interval_seconds"] == 30 and status["watcher"]["checked_at"]
    log = (root / ".atdr_runtime" / "logs" / "watch.log").read_text(encoding="utf-8-sig")
    assert "Watching ATDR" in log and "Starting" not in log
    assert not list((root / ".atdr_runtime").glob("*.lock")) and not list((root / ".atdr_runtime").glob("*.arriving"))


@pytest.mark.skipif(sys.platform != "win32", reason="starts the Windows start script")
def test_a_check_with_nothing_running_tries_a_start_and_records_how_it_went(tmp_path):
    root = _own_folder(tmp_path, "watch_system.ps1", "start_system.ps1")
    common = _quoted(root / "scripts" / "system_common.ps1")
    _powershell(f". {common}; Set-AtdrDesiredState -State running -By 'test'")
    for _ in range(2):
        assert _script(root / "scripts" / "watch_system.ps1", "-Checks", "1").returncode == 0
    status = _read(root, "watch-status.json")
    # In this folder there is no MFU shell to start, so the start fails; what matters is that it was tried and told.
    assert (status["last_action"]["ok"], status["last_action"]["all"], status["last_action"]["resumed"]) == (False, True, False)
    assert "ATDR startup failed" in status["last_action"]["said"]
    assert len(status["all_restarts"]) == 2, "the watcher that came after remembers the try of the one before"
    log = (root / ".atdr_runtime" / "logs" / "watch.log").read_text(encoding="utf-8-sig")
    assert log.count("Starting ATDR: no part is running.") == 2 and "ATDR did not start (exit code 1)" in log
    assert not (root / ".atdr_runtime" / "start.lock").exists()


def test_the_start_script_serves_the_built_dashboard_and_can_start_one_part():
    start = (SCRIPTS / "start_system.ps1").read_text(encoding="utf-8")
    assert '"-m", "atdr.scripts.build_dashboard"' in start and '"-m", "atdr.scripts.serve_dashboard", "--host", "127.0.0.1", "--port", "5173"' in start
    assert "node_modules/vite/bin/vite.js\", \"--host\"" not in start, "the development server is no longer what ATDR runs"
    assert start.index("atdr.scripts.build_dashboard") < start.index("atdr.scripts.serve_dashboard"), "built before it is served"
    assert "[string[]]$Only = @()" in start and 'if ("atdr-backend" -in $wanted)' in start
    for part in ("atdr-worker", "atdr-syslog", "atdr-frontend", "shell-backend", "shell-frontend"):
        assert f'"{part}" -in $wanted' in start, part
    assert "processes = @(@($kept) + @($started))" in start, "the parts that were running stay on record"
    assert start.index("Enter-AtdrStartLock") < start.index("Start-TrackedProcess -Name \"atdr-backend\""), "one start at a time"
    assert 'Set-AtdrDesiredState -State "running" -By "start_system"' in start and "Start-AtdrWatcherTask" in start
    assert '(Read-AtdrDesiredState).state -ne "running"' in start, "a part is not brought back after a stop on purpose"


def test_the_installer_keeps_the_watcher_alive_without_launching_anything_while_it_runs():
    installer = (SCRIPTS / "autostart.ps1").read_text(encoding="utf-8")
    assert "watch_system.ps1" in installer and "$AtdrWatcherTaskName" in installer
    assert "New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 1)" in installer
    watch_settings = installer[installer.index("function New-AtdrLongRunningSettings"):installer.index("function Start-AtdrWatcherAfresh")]
    assert "-MultipleInstances IgnoreNew" in watch_settings and "-ExecutionTimeLimit ([TimeSpan]::Zero)" in watch_settings
    assert "-AllowStartIfOnBatteries" in watch_settings and "-DontStopIfGoingOnBatteries" in watch_settings
    # Ending the watcher's task would end every part of ATDR that this watcher had brought back, so the watcher is
    # ended by its own process, after its task is gone.
    assert "Stop-ScheduledTask" not in installer and "Stop-AtdrWatcherProcess" in installer
    removal = installer[installer.index("function Unregister-AtdrTasks"):installer.index("function Register-AtdrSignInTask")]
    assert removal.index("Unregister-ScheduledTask -TaskName $watchTaskName") < removal.index("Stop-AtdrWatcherProcess")

    # No console window at all for a task of the sign-in session. With a hidden window Windows ended the sign-in
    # start seconds after each real sign-in (result 0xC000013A, three sign-ins of three) and once ended the watcher
    # at an unlock.
    assert '-Execute $headless -Argument "--headless powershell.exe $PowerShellArguments"' in installer
    assert 'Join-Path $env:SystemRoot "System32\\conhost.exe"' in installer
    assert "$action = New-HiddenPowerShellAction $arguments" in installer
    for_sign_in = installer[installer.index("function Install-AtdrForSignIn"):installer.index("function Install-AtdrBeforeSignIn")]
    assert ("Register-ScheduledTask -TaskName $watchTaskName -Action (New-HiddenPowerShellAction $watchArguments) "
            "-Trigger (New-AtdrEveryMinuteTrigger) -Settings (New-AtdrLongRunningSettings)") in for_sign_in
    assert "-LogonType Interactive -RunLevel Limited" in for_sign_in and "S4U" not in for_sign_in

    watcher = (SCRIPTS / "watch_system.ps1").read_text(encoding="utf-8")
    assert "Get-AtdrWatchDecision" in watcher and '"-Only", ($Only -join ",")' in watcher
    assert "-RedirectStandardOutput $out" in watcher and "$start.WaitForExit()" in watcher and "-Wait " not in watcher
    assert watcher.count("if ($result.code -eq 3) {") == 2, "a start already under way is left to whoever is making it"
    common = (SCRIPTS / "system_common.ps1").read_text(encoding="utf-8")
    assert '$AtdrWatcherTaskName = "ATDR keep running"' in common
    start = (SCRIPTS / "start_system.ps1").read_text(encoding="utf-8")
    busy = start[start.index("$locked = Enter-AtdrStartLock"):start.index("if ($partial -and (Read-AtdrDesiredState)")]
    assert "exit 3" in busy and "exit 0" not in busy, "a start that finds another under way says so with its exit code"


def test_a_sign_in_start_that_is_cut_short_still_leaves_atdr_looked_after(tmp_path):
    # Windows ended the sign-in script seconds after it began, on every real sign-in. The start it had launched
    # went on, but what the script did after it never happened. So it now does first what must not be lost.
    sign_in = (SCRIPTS / "start_at_sign_in.ps1").read_text(encoding="utf-8")
    held, meant, watching, first_try = (
        sign_in.index("if (Test-AtdrHeld $desired) {"), sign_in.index('Set-AtdrDesiredState -State "running" -By "start_at_sign_in"'),
        sign_in.rindex("\nStart-Watcher\n"), sign_in.index("for ($attempt = 1;"),
    )
    assert held < meant < watching < first_try, "held stop first; then meant to run and the watcher, before any try"
    assert "if ($code -eq 3) {" in sign_in and "Complete-SignInStart" not in sign_in

    root = _own_folder(tmp_path, "start_at_sign_in.ps1", "start_system.ps1", "stop_system.ps1")
    assert _script(root / "scripts" / "stop_system.ps1").returncode == 0
    # One try, no wait: in this folder there is nothing to start, and on a machine where ATDR runs it is found running.
    _script(root / "scripts" / "start_at_sign_in.ps1", "-Attempts", "1", "-WaitSeconds", "1")
    desired = _read(root, "desired-state.json")
    assert (desired["state"], desired["by"], desired["hold_until"]) == ("running", "start_at_sign_in", None), "a sign-in ends a plain stop"
    log = (root / ".atdr_runtime" / "logs" / "autostart.log").read_text(encoding="utf-8-sig")
    assert "Sign-in start requested." in log

    # A stop that was to outlast a sign-in does.
    assert _script(root / "scripts" / "stop_system.ps1", "-HoldHours", "2").returncode == 0
    kept = _script(root / "scripts" / "start_at_sign_in.ps1", "-Attempts", "1", "-WaitSeconds", "1")
    assert kept.returncode == 0, kept.stderr
    desired = _read(root, "desired-state.json")
    assert desired["state"] == "stopped" and desired["hold_until"]
    log = (root / ".atdr_runtime" / "logs" / "autostart.log").read_text(encoding="utf-8-sig")
    assert "ATDR is being kept stopped until" in log and "not started" in log
