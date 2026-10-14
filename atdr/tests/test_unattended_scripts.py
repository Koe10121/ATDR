"""ATDR runs with nobody at the machine (scripts/autostart.cmd -BeforeSignIn).

Installed for a sign-in, ATDR's watcher and everything it starts belong to that sign-in: nothing runs before
someone signs in, and all of it ends when they sign out. Installed to start with the machine, the watcher is a
task Windows runs without a sign-in, every start of ATDR goes through it, and a helper in the sign-in session
shows the Windows notifications that parts without a desktop cannot show.

The scripts run here in a folder of their own. The installer itself is read, not run: run, it would change the
machine's real tasks and its power settings.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from atdr.app.services.notification_channels import helper_at_the_desktop

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"
windows_only = pytest.mark.skipif(sys.platform != "win32", reason="runs the Windows launcher scripts")


def _powershell(command: str) -> str:
    result = subprocess.run(["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command],
                            capture_output=True, text=True, timeout=120, check=False)
    assert result.returncode == 0, result.stderr or result.stdout
    return result.stdout


def _script(path: Path, *arguments: str, timeout: int = 180) -> subprocess.CompletedProcess:
    return subprocess.run(["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(path), *arguments],
                          capture_output=True, text=True, timeout=timeout, check=False, cwd=path.parent.parent)


def _quoted(path: Path) -> str:
    return "'" + str(path).replace("'", "''") + "'"


def _own_folder(tmp_path: Path, *names: str) -> Path:
    root = tmp_path / "ATDR on its own"
    (root / "scripts").mkdir(parents=True)
    (root / ".atdr_runtime").mkdir()
    for name in ("system_common.ps1", *names):
        shutil.copy2(SCRIPTS / name, root / "scripts" / name)
    return root


def _read(root: Path, name: str) -> dict:
    return json.loads((root / ".atdr_runtime" / name).read_text(encoding="utf-8-sig"))


def _installed(root: Path, mode: str) -> None:
    (root / ".atdr_runtime" / "autostart.json").write_text(json.dumps({"mode": mode, "user": "LAPTOP\\someone"}), encoding="utf-8")


def _sleeper() -> tuple[subprocess.Popen, str]:
    process = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(300)"])
    started = _powershell(f"(Get-Process -Id {process.pid}).StartTime.ToUniversalTime().ToString('o')").strip()
    return process, started


def _answer_as_the_watcher(runtime: Path, answer: dict, asked: list[dict]) -> threading.Thread:
    """Plays the watcher for one request: takes it, notes what ATDR was meant to be at that moment, and answers."""

    def run() -> None:
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline and not (runtime / "start-request.json").exists():
            time.sleep(0.2)
        request = json.loads((runtime / "start-request.json").read_text(encoding="utf-8-sig"))
        (runtime / "start-request.json").unlink()
        desired = runtime / "desired-state.json"
        asked.append({**request, "desired_then": json.loads(desired.read_text(encoding="utf-8-sig"))["state"] if desired.exists() else None})
        (runtime / "start-result.json").write_text(json.dumps({"id": request["id"], **answer}), encoding="utf-8")

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return thread


@windows_only
def test_how_a_folder_was_installed_is_read_from_its_own_record(tmp_path):
    root = _own_folder(tmp_path)
    common = _quoted(root / "scripts" / "system_common.ps1")
    ask = f". {common}; \"$(Test-AtdrRunsWithoutSignIn)|$($null -eq (Read-AtdrAutostartRecord))\""
    # Whatever tasks this machine has: a folder nobody installed does not run without a sign-in.
    assert _powershell(ask).strip() == "False|True"
    _installed(root, "at_sign_in")
    assert _powershell(ask).strip() == "False|False"
    _installed(root, "before_sign_in")
    assert _powershell(ask).strip() == "True|False"
    for unusable in ('{"mode": "something else"}', "{ not json"):
        (root / ".atdr_runtime" / "autostart.json").write_text(unusable, encoding="utf-8")
        assert _powershell(ask).strip() == "False|True"
    assert _powershell(f". {common}; \"$(Test-AtdrHasDesktop)|$(Test-AtdrWatcherAlive)\"").strip() == "True|False", (
        "the tests run at a desktop, and this folder has no watcher")


@windows_only
def test_a_start_by_a_person_is_handed_to_the_watcher_where_atdr_runs_without_a_sign_in(tmp_path):
    # Started from a person's window, ATDR's parts belong to that sign-in and end with it. The watcher, which
    # Windows runs without a sign-in, makes the start instead and the person's window waits for its answer.
    root = _own_folder(tmp_path, "start_system.ps1")
    runtime = root / ".atdr_runtime"
    _installed(root, "before_sign_in")
    watcher, watcher_started = _sleeper()
    (runtime / "watch.lock").write_text(json.dumps({"pid": watcher.pid, "started_at": watcher_started}), encoding="utf-8")
    asked: list[dict] = []
    try:
        watching = _answer_as_the_watcher(runtime, {"ok": True, "code": 0, "said": "", "asked_for": ["atdr-backend", "atdr-worker"]}, asked)
        done = _script(root / "scripts" / "start_system.ps1", "-NoBrowser")
        watching.join(timeout=5)
        assert done.returncode == 0, done.stderr
        assert "its watcher makes the start" in done.stdout
        assert "ATDR is running: its watcher started atdr-backend, atdr-worker." in done.stdout
        assert (asked[0]["by"], asked[0]["release"]) == ("start_system", False) and asked[0]["id"]
        assert not (runtime / "start-result.json").exists() and not (runtime / "start.lock").exists()
        assert not (runtime / "system-processes.json").exists(), "nothing was started from the person's window"

        # What the watcher could not start is the person's failure too, in the same words.
        watching = _answer_as_the_watcher(runtime, {"ok": False, "code": 1, "said": "ATDR startup failed: MongoDB is unavailable at 127.0.0.1:27017.", "asked_for": []}, asked)
        failed = _script(root / "scripts" / "start_system.ps1", "-NoBrowser")
        watching.join(timeout=5)
        assert failed.returncode == 1 and "ATDR startup failed: MongoDB is unavailable at 127.0.0.1:27017." in failed.stderr
        assert "ATDR startup failed: ATDR startup failed" not in failed.stderr

        # The watcher's own start does the work (and in this folder gets no further than the missing MFU shell);
        # so does a look that starts nothing.
        own = _script(root / "scripts" / "start_system.ps1", "-NoBrowser", "-ByWatcher", timeout=90)
        assert own.returncode == 1 and "its watcher makes the start" not in own.stdout
        assert "ATDR startup failed: MFU supervisor shell path is not configured" in own.stderr
        dry = _script(root / "scripts" / "start_system.ps1", "-DryRun", timeout=90)
        assert "its watcher makes the start" not in dry.stdout and not (runtime / "start-request.json").exists()

        # Installed for a sign-in, a person's start is the start, as it always was.
        _installed(root, "at_sign_in")
        direct = _script(root / "scripts" / "start_system.ps1", "-NoBrowser", timeout=90)
        assert direct.returncode == 1 and "its watcher makes the start" not in direct.stdout
        assert "ATDR startup failed: MFU supervisor shell path is not configured" in direct.stderr

        # Which watcher is this folder's, and where it runs, is read from the record the watcher keeps of itself.
        common = _quoted(root / "scripts" / "system_common.ps1")
        where = _powershell(f". {common}; \"$(Test-AtdrWatcherAlive)|$(Get-AtdrWatcherSession)|$((Get-Process -Id $PID).SessionId)\"").strip().split("|")
        assert where[0] == "True" and where[1] == where[2] != "0", "at a desktop here; session 0 is the one without"
    finally:
        watcher.kill()
        watcher.wait()
    assert _powershell(f". {common}; \"$(Test-AtdrWatcherAlive)|$(Get-AtdrWatcherSession)|\"").strip() == "False||", "its record outlives it"


@windows_only
def test_a_request_without_an_answer_is_taken_back(tmp_path):
    root = _own_folder(tmp_path)
    common = _quoted(root / "scripts" / "system_common.ps1")
    began = time.monotonic()
    said = _powershell(f". {common}; $answer = Request-AtdrStart -By 'test' -TimeoutSeconds 3; \"$($null -eq $answer)\"").strip()
    assert said == "True" and 2 < time.monotonic() - began < 30
    runtime = root / ".atdr_runtime"
    assert not (runtime / "start-request.json").exists(), "nobody finds it later and starts ATDR unasked"

    # An answer to another request is not this one's, whenever it arrives.
    def answer_another() -> None:
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline and not (runtime / "start-request.json").exists():
            time.sleep(0.1)
        (runtime / "start-result.json").write_text(json.dumps({"id": "another", "ok": True, "code": 0, "said": ""}), encoding="utf-8")

    other = threading.Thread(target=answer_another, daemon=True)
    other.start()
    assert _powershell(f". {common}; $answer = Request-AtdrStart -By 'test' -TimeoutSeconds 4; \"$($null -eq $answer)\"").strip() == "True"
    other.join(timeout=5)


@windows_only
def test_a_sign_in_starts_nothing_itself_where_the_watcher_runs_without_one(tmp_path):
    root = _own_folder(tmp_path, "start_at_sign_in.ps1", "start_system.ps1", "stop_system.ps1")
    _installed(root, "before_sign_in")
    assert _script(root / "scripts" / "stop_system.ps1").returncode == 0
    done = _script(root / "scripts" / "start_at_sign_in.ps1", "-Attempts", "1", "-WaitSeconds", "1")
    assert done.returncode == 0, done.stderr
    desired = _read(root, "desired-state.json")
    assert (desired["state"], desired["by"]) == ("running", "start_at_sign_in"), "a sign-in still ends a plain stop"
    log = (root / ".atdr_runtime" / "logs" / "autostart.log").read_text(encoding="utf-8-sig")
    assert "its watcher does the starting" in log
    assert "Start attempt" not in log and "ATDR startup failed" not in log and "ATDR did not start" not in log
    assert not (root / ".atdr_runtime" / "logs" / "autostart.start.out.log").exists(), "the start script was never run"

    # A stop that was to outlast a sign-in still does.
    assert _script(root / "scripts" / "stop_system.ps1", "-HoldHours", "2").returncode == 0
    assert _script(root / "scripts" / "start_at_sign_in.ps1", "-Attempts", "1", "-WaitSeconds", "1").returncode == 0
    assert _read(root, "desired-state.json")["state"] == "stopped"


def _stub(tmp_path: Path, *, code: int) -> Path:
    """Stands in for scripts/show_notification.ps1: writes down what it was given instead of showing it."""

    stub = tmp_path / f"show_{code}.ps1"
    seen = tmp_path / "seen.jsonl"
    stub.write_text(
        "$line = @{ title = $env:ATDR_NOTIFICATION_TITLE; body = $env:ATDR_NOTIFICATION_BODY; link = $env:ATDR_NOTIFICATION_LINK } | ConvertTo-Json -Compress\n"
        f"Add-Content -LiteralPath '{seen}' -Value $line -Encoding UTF8\n"
        f"exit {code}\n", encoding="utf-8")
    return stub


@windows_only
def test_the_helper_at_the_desktop_shows_what_waits_and_says_how_it_went(tmp_path):
    root = _own_folder(tmp_path, "desktop_agent.ps1")
    queue = root / ".atdr_runtime" / "desktop-notifications"
    queue.mkdir()
    words = {"ATDR_NOTIFICATION_TITLE": "2 new Critical alerts", "ATDR_NOTIFICATION_BODY": "#7 Critical: malware / C2\n#8 Critical: port scan",
             "ATDR_NOTIFICATION_LINK": "http://127.0.0.1:5173/alerts"}
    (queue / "first.json").write_text(json.dumps(words), encoding="utf-8")
    (queue / "second.json").write_text(json.dumps({**words, "ATDR_NOTIFICATION_TITLE": "ATDR could not back up its database"}), encoding="utf-8")
    (queue / "half.arriving").write_text("{", encoding="utf-8")

    shown = _script(root / "scripts" / "desktop_agent.ps1", "-Checks", "1", "-ShowScript", str(_stub(tmp_path, code=0)))
    assert shown.returncode == 0, shown.stderr
    assert sorted(path.name for path in queue.iterdir()) == ["first.shown", "half.arriving", "second.shown"], (
        "each is answered where the part that asked looks; a file still being written is left alone")
    seen = [json.loads(line) for line in (tmp_path / "seen.jsonl").read_text(encoding="utf-8-sig").splitlines() if line.strip()]
    assert sorted(item["title"] for item in seen) == ["2 new Critical alerts", "ATDR could not back up its database"]
    assert seen[0]["body"].splitlines()[0].startswith("#7 Critical") and seen[0]["link"] == "http://127.0.0.1:5173/alerts"
    log = (root / ".atdr_runtime" / "logs" / "desktop.log").read_text(encoding="utf-8-sig")
    assert "At the desktop" in log and not (root / ".atdr_runtime" / "desktop.lock").exists()

    # One that Windows would not show, and one nobody can read: both are answered as failed, and said in the log.
    for path in queue.iterdir():
        path.unlink()
    (queue / "third.json").write_text(json.dumps(words), encoding="utf-8")
    (queue / "fourth.json").write_text("{ not json", encoding="utf-8")
    assert _script(root / "scripts" / "desktop_agent.ps1", "-Checks", "1", "-ShowScript", str(_stub(tmp_path, code=1))).returncode == 0
    assert sorted(path.name for path in queue.iterdir()) == ["fourth.failed", "third.failed"]
    log = (root / ".atdr_runtime" / "logs" / "desktop.log").read_text(encoding="utf-8-sig")
    assert "A notification could not be shown (the script ended with 1)." in log

    # Answers nobody collected are cleared away once they are old; a fresh one stays for the part to read.
    old = time.time() - 3600
    os.utime(queue / "third.failed", (old, old))
    assert _script(root / "scripts" / "desktop_agent.ps1", "-Checks", "1", "-ShowScript", str(_stub(tmp_path, code=0))).returncode == 0
    assert [path.name for path in queue.iterdir()] == ["fourth.failed"]


@windows_only
def test_one_helper_at_a_time(tmp_path):
    root = _own_folder(tmp_path, "desktop_agent.ps1")
    queue = root / ".atdr_runtime" / "desktop-notifications"
    queue.mkdir()
    other, other_started = _sleeper()
    lock = root / ".atdr_runtime" / "desktop.lock"
    try:
        lock.write_text(json.dumps({"pid": other.pid, "started_at": other_started}), encoding="utf-8")
        (queue / "waiting.json").write_text(json.dumps({"ATDR_NOTIFICATION_TITLE": "x"}), encoding="utf-8")
        second = _script(root / "scripts" / "desktop_agent.ps1", "-Checks", "1", "-ShowScript", str(_stub(tmp_path, code=0)))
        assert second.returncode == 0 and [path.name for path in queue.iterdir()] == ["waiting.json"], "left to the helper that is running"
        assert not (tmp_path / "seen.jsonl").exists()
        # The same record tells a part of ATDR whether anyone is signed in to show a notification to.
        assert helper_at_the_desktop(lock) is True
    finally:
        other.kill()
        other.wait()
    assert helper_at_the_desktop(lock) is False, "the record outlives a helper that was ended with its sign-in session"

    # And the record a helper writes of itself is one a part can read: while it runs it is there, afterwards not.
    lock.unlink()
    (queue / "waiting.json").unlink()
    helper = subprocess.Popen(["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(root / "scripts" / "desktop_agent.ps1"),
                               "-IntervalSeconds", "1", "-ShowScript", str(_stub(tmp_path, code=0))], cwd=root)
    try:
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline and not helper_at_the_desktop(lock):
            time.sleep(0.25)
        assert helper_at_the_desktop(lock) is True
    finally:
        helper.kill()
        helper.wait()
    assert helper_at_the_desktop(lock) is False


@windows_only
def test_the_sleep_time_is_read_from_what_windows_says():
    common = _quoted(SCRIPTS / "system_common.ps1")
    printed = ("'  Power Setting GUID: 29f6c1db-86da-48c5-9fdb-f2b67b1f44da  (Sleep after)', '    Current AC Power Setting Index: 0x00000e10', "
               "'    Current DC Power Setting Index: 0x000000b4'")
    assert _powershell(f". {common}; ConvertFrom-AtdrPowerQuery @({printed})").strip() == "3600"
    assert _powershell(f". {common}; ConvertFrom-AtdrPowerQuery @('    Current AC Power Setting Index: 0x00000000')").strip() == "0"
    assert _powershell(f". {common}; $null -eq (ConvertFrom-AtdrPowerQuery @('nothing of the kind'))").strip() == "True"
    assert _powershell(f". {common}; $null -eq (ConvertFrom-AtdrPowerQuery $null)").strip() == "True"
    # Asked of this machine, without changing anything: it has at least one plan, and its plan in use says a time.
    plans = _powershell(f". {common}; (Get-AtdrPowerPlans) -join ','").strip().split(",")
    assert plans and all(len(plan) == 36 for plan in plans), plans
    assert int(_powershell(f". {common}; Get-AtdrMainsSleepSeconds").strip()) >= 0


def test_what_the_installer_registers_and_what_it_leaves_alone():
    installer = (SCRIPTS / "autostart.ps1").read_text(encoding="utf-8")
    before = installer[installer.index("function Install-AtdrBeforeSignIn"):installer.index("function Wait-AtdrWatcherWithoutDesktop")]
    # As the user, without a stored password and without administrator rights; with the machine, and every minute.
    assert "New-ScheduledTaskPrincipal -UserId $User -LogonType S4U -RunLevel Limited" in before
    assert "New-ScheduledTaskTrigger -AtStartup" in before and "-Trigger @($withTheMachine, (New-AtdrEveryMinuteTrigger))" in before
    assert "RunLevel Highest" not in installer and "-Password" not in installer and "LogonType Password" not in installer
    # The helper is the only one of the three that needs a desktop; the user can start all three from an ordinary window.
    assert "New-ScheduledTaskPrincipal -UserId $User -LogonType Interactive -RunLevel Limited" in before
    assert "foreach ($name in @($taskName, $watchTaskName, $desktopTaskName)) {\n        try { Grant-AtdrTaskToUser -TaskName $name -UserName $User }" in before
    assert '$ace = "(A;;GRGX;;;$sid)"' in installer
    assert before.index("[void](Stop-AtdrWatcherProcess)") < before.index("Register-ScheduledTask -TaskName $watchTaskName") < before.index("Start-AtdrWatcherAfresh")
    # On record once the tasks are there: a task that could not be opened to the user is registered all the same.
    assert before.index("Register-ScheduledTask -TaskName $desktopTaskName") < before.index("Save-AtdrAutostartRecord @{ mode = \"before_sign_in\"") < before.index("try { Grant-AtdrTaskToUser")

    # The half with administrator rights registers or removes tasks and nothing else: it starts no part of ATDR
    # (which would then run with those rights) and changes no power setting.
    elevated = installer[installer.index("if ($Elevated) {"):installer.index("# Tasks that run without a sign-in were registered")]
    assert "Install-AtdrBeforeSignIn $user" in elevated and "Unregister-AtdrTasks" in elevated
    for left_alone in ("Move-AtdrPartsToWatcher", "Restart-AtdrThroughWatcher", "Undo-AtdrBeforeSignIn", "Set-AtdrMainsAwake", "Request-AtdrStart",
                       "start_system", "stop_system", "Install-AtdrForSignIn"):
        assert left_alone not in elevated, left_alone
    assert "-Verb RunAs" in installer and installer.count("-Verb RunAs") == 1
    # What it says, and what stopped it, reach the window the person is looking at through one file in one encoding.
    assert "} *>&1 | ForEach-Object { $said.Add([string]$_) }" in elevated and '$said.Add("Failed: $($_.Exception.Message)")' in elevated
    assert "if ($LogTo) { Set-Content -LiteralPath $LogTo -Value $said -Encoding UTF8 }" in elevated

    # What was asked for is looked at afterwards, not taken on the word of the run that made it: this folder's
    # record, and then the watcher itself, seen running where there is no desktop. Only after that is anything of
    # ATDR stopped: stopped first, nothing would be there to start it again.
    does = installer[installer.index("\nif ($Status) {"):]
    registered, seen_running, moved, sleep_set = (
        does.index("if (-not (Test-AtdrRunsWithoutSignIn)) {"), does.index("if (-not (Wait-AtdrWatcherWithoutDesktop)) {"),
        does.index("if (-not (Move-AtdrPartsToWatcher -WithoutDesktop)) {"), does.index("if ($StayAwakeOnMains) { Set-AtdrMainsAwake }"))
    assert registered < seen_running < moved < sleep_set
    waits = installer[installer.index("function Wait-AtdrWatcherWithoutDesktop"):installer.index("function Test-AtdrElevated")]
    assert "if ((Get-AtdrWatcherSession) -eq 0) { return $true }" in waits and "return $false" in waits
    # A watcher that Windows would not start that way: back to starting at sign-in, so that ATDR has a watcher at
    # all, with its parts left running as they are.
    not_started = does[seen_running:moved]
    assert "[void](Undo-AtdrBeforeSignIn $user)" in not_started and "exit 1" in not_started and "Restart-AtdrThroughWatcher" not in not_started
    # A watcher that runs so and could not start ATDR: ATDR is down then. Back, and started as it ran before.
    did_not_come_up = does[moved:does.index("\nelse {", moved)]
    assert (did_not_come_up.index("if (Undo-AtdrBeforeSignIn $user) {") < did_not_come_up.index("if (Restart-AtdrThroughWatcher) {")
            < did_not_come_up.index("exit 1"))
    undo = installer[installer.index("function Undo-AtdrBeforeSignIn"):installer.index("\nif ($Status) {")]
    assert (undo.index('Invoke-AtdrElevated -Switches @("-Remove")') < undo.index("if ((Get-AutostartState).without_sign_in) {")
            < undo.index("Install-AtdrForSignIn $User"))
    restart = installer[installer.index("function Restart-AtdrThroughWatcher"):installer.index("function Move-AtdrPartsToWatcher")]
    assert restart.index("$stop.WaitForExit()") < restart.index('$answer = Request-AtdrStart -By "autostart"')
    assert restart.count('Set-AtdrDesiredState -State "running" -By "autostart"') == 2, (
        "neither a stop that failed nor a watcher that did not answer leaves ATDR stopped for good")
    # Which parts are moved depends on where they run and where this install wants them. Going back moves them too:
    # without a desktop they would have nobody to show their notifications once the helper is gone.
    move = installer[installer.index("function Move-AtdrPartsToWatcher"):installer.index("function Undo-AtdrBeforeSignIn")]
    assert "((Get-Process -Id ([int]$_.pid)).SessionId -eq 0) -ne [bool]$WithoutDesktop" in move
    going_back = does[does.index("\nelse {", moved):sleep_set]
    assert going_back.index("Install-AtdrForSignIn $user") < going_back.index("if (-not (Move-AtdrPartsToWatcher)) {")
    # The helper goes with its task, and is not left showing notifications from the scripts of an older version.
    removal = installer[installer.index("function Unregister-AtdrTasks"):installer.index("function Register-AtdrSignInTask")]
    assert removal.index("Unregister-ScheduledTask -TaskName $desktopTaskName") < removal.index("[void](Stop-AtdrDesktopHelperProcess)")
    for_sign_in = installer[installer.index("function Install-AtdrForSignIn"):installer.index("function Install-AtdrBeforeSignIn")]
    assert "[void](Stop-AtdrDesktopHelperProcess)" in for_sign_in

    # The way that is installed stays unless another is asked for, and the sleep switch alone changes only the sleep.
    assert "$wantBefore = $BeforeSignIn -or ($installedBefore -and -not $AtSignIn)" in installer
    assert "$onlyPower = $StayAwakeOnMains -and -not $BeforeSignIn -and -not $AtSignIn -and -not $Remove -and $null -ne $already" in installer
    power = installer[installer.index("function Set-AtdrMainsAwake"):installer.index("function Restore-AtdrMainsSleep")]
    assert "foreach ($plan in @(Get-AtdrPowerPlans))" in power and "powercfg /setacvalueindex $plan SUB_SLEEP STANDBYIDLE 0" in power
    assert "setdcvalueindex" not in installer and "LIDACTION" not in installer, "on battery nothing changes, and the lid still puts it to sleep"
    assert "mains_sleep_before = $before" in power and "if ($known)" in power, "what was there before is kept once, to be put back"
    assert power.index("if (-not $before.Count) {") < power.index("Save-AtdrAutostartRecord"), "nothing read is nothing changed, and nothing claimed"
    restore = installer[installer.index("function Restore-AtdrMainsSleep"):installer.index("function Move-AtdrPartsToWatcher")]
    assert "powercfg /setacvalueindex $property.Name SUB_SLEEP STANDBYIDLE ([int]$property.Value)" in restore
    # Still refused in the folder ATDR is developed in, before anything is registered or removed.
    assert installer.index("$liveCopy = Get-AtdrLiveCopy") < installer.index("if ($Elevated) {") < installer.index("if ($Remove) {")


_INSTALLER_STAND_INS = r'''
# Stand-ins for what changes the machine: its tasks, and the half that runs with administrator rights. What they were
# asked to do is written down; whether the watcher's task still runs without a sign-in is a file.
function Write-Asked { param([string]$Line) Add-Content -LiteralPath (Join-Path (Get-AtdrRuntimeDirectory) "asked.txt") -Value $Line -Encoding UTF8 }
function Test-AtdrElevated { return $false }
function Get-AutostartState { return [pscustomobject]@{ without_sign_in = (Test-Path -LiteralPath (Join-Path (Get-AtdrRuntimeDirectory) "without-sign-in")) } }
function Invoke-AtdrElevated {
    param([string[]]$Switches, [string]$User)
    Write-Asked "administrator: $($Switches -join ' ') for $User"
    if (-not (Test-Path -LiteralPath (Join-Path (Get-AtdrRuntimeDirectory) "administrator-says-no"))) {
        Remove-Item -LiteralPath (Join-Path (Get-AtdrRuntimeDirectory) "without-sign-in") -Force -ErrorAction SilentlyContinue
    }
    return $true
}
function Unregister-AtdrTasks { Write-Asked "unregister" }
function Install-AtdrForSignIn { param([string]$User) Write-Asked "install for sign-in: $User" }
# A watcher that does not answer is waited for seconds here, not eight minutes.
$askTheWatcher = ${function:Request-AtdrStart}
function Request-AtdrStart { param([string]$By, [switch]$Release) & $askTheWatcher -By $By -Release:$Release -TimeoutSeconds 4 }
if ($RestartGoes) {
    function Restart-AtdrThroughWatcher { Write-Asked "restart through the watcher"; return ($RestartGoes -eq "yes") }
}
'''

_STOP_STAND_IN = '''. (Join-Path $PSScriptRoot "system_common.ps1")
Set-AtdrDesiredState -State "stopped" -By "stop_system"
$code = Join-Path (Get-AtdrRuntimeDirectory) "stop-exit-code"
if (Test-Path -LiteralPath $code) { exit [int](Get-Content -LiteralPath $code -Raw) }
exit 0
'''


def _installer_parts(root: Path) -> Path:
    """The installer's functions that move ATDR's parts and go back, run in a folder of their own with the machine
    left out: the installer itself is never run here."""

    installer = (SCRIPTS / "autostart.ps1").read_text(encoding="utf-8")
    parts = installer[installer.index("function Restart-AtdrThroughWatcher"):installer.index("\nif ($Status) {")]
    for machine in ("Register-ScheduledTask", "Unregister-ScheduledTask", "Start-ScheduledTask", "powercfg", "-Verb RunAs"):
        assert machine not in parts, f"{machine}: these functions would change this machine"
    script = root / "scripts" / "installer_parts.ps1"
    script.write_text('param([string]$Call, [string]$RestartGoes = "")\nSet-StrictMode -Version Latest\n$ErrorActionPreference = "Stop"\n'
                      '. (Join-Path $PSScriptRoot "system_common.ps1")\n' + parts + _INSTALLER_STAND_INS
                      + '$result = & ([scriptblock]::Create($Call))\nWrite-Output "RESULT=$($result -join \',\')"\n', encoding="utf-8")
    (root / "scripts" / "stop_system.ps1").write_text(_STOP_STAND_IN, encoding="utf-8")
    return script


def _call(script: Path, code: str, *, restart_goes: str = "") -> tuple[str, str, list[str]]:
    runtime = script.parent.parent / ".atdr_runtime"
    (runtime / "asked.txt").unlink(missing_ok=True)
    done = _script(script, "-Call", code, *(("-RestartGoes", restart_goes) if restart_goes else ()), timeout=120)
    assert done.returncode == 0, done.stderr or done.stdout
    result = [line[len("RESULT="):] for line in done.stdout.splitlines() if line.startswith("RESULT=")]
    asked = (runtime / "asked.txt").read_text(encoding="utf-8-sig").splitlines() if (runtime / "asked.txt").exists() else []
    return result[-1], done.stdout, asked


@windows_only
def test_the_installer_restarts_atdr_through_the_watcher_and_never_leaves_it_stopped(tmp_path):
    root = _own_folder(tmp_path)
    runtime = root / ".atdr_runtime"
    script = _installer_parts(root)
    user = "LAPTOP\\someone"

    # Stopped first, then started by the watcher that runs: the parts are the watcher's afterwards.
    asked: list[dict] = []
    watching = _answer_as_the_watcher(runtime, {"ok": True, "code": 0, "said": ""}, asked)
    result, said, _ = _call(script, "Restart-AtdrThroughWatcher")
    watching.join(timeout=5)
    assert result == "True", said
    assert (asked[0]["by"], asked[0]["release"], asked[0]["desired_then"]) == ("autostart", False, "stopped")

    # What the watcher could not start is said, and is no success.
    watching = _answer_as_the_watcher(runtime, {"ok": False, "code": 1, "said": "MongoDB is unavailable at 127.0.0.1:27017."}, asked)
    result, said, _ = _call(script, "Restart-AtdrThroughWatcher")
    watching.join(timeout=5)
    assert result == "False" and "ATDR did not start: MongoDB is unavailable at 127.0.0.1:27017." in said

    # A watcher that does not answer: ATDR is meant to run again, so the next watcher to look starts it.
    result, said, _ = _call(script, "Restart-AtdrThroughWatcher")
    assert result == "False" and "The watcher did not answer" in said
    assert _read(root, "desired-state.json")["state"] == "running" and _read(root, "desired-state.json")["by"] == "autostart"
    assert not (runtime / "start-request.json").exists(), "nobody finds the request later and starts ATDR unasked"

    # A stop that failed: nothing is asked of the watcher, and ATDR is not left meant to be stopped.
    (runtime / "stop-exit-code").write_text("3", encoding="utf-8")
    result, said, _ = _call(script, "Restart-AtdrThroughWatcher")
    assert result == "False" and "ATDR could not be stopped (exit code 3)." in said and "The watcher did not answer" not in said
    assert _read(root, "desired-state.json")["state"] == "running"
    (runtime / "stop-exit-code").unlink()

    # Only parts that run where this install does not want them are moved, and each by its own record.
    result, _, did = _call(script, "Move-AtdrPartsToWatcher -WithoutDesktop", restart_goes="yes")
    assert (result, did) == ("True", []), "no record, nothing to move"
    part, part_started = _sleeper()
    ended, ended_started = _sleeper()
    ended.kill()
    ended.wait()
    try:
        (runtime / "system-processes.json").write_text(json.dumps({"processes": [
            {"name": "atdr-backend", "pid": part.pid, "started_at": part_started},
            {"name": "atdr-worker", "pid": ended.pid, "started_at": ended_started}]}), encoding="utf-8")
        # These tests run at a desktop, so the part belongs to this sign-in: to be moved when ATDR is to run without one.
        result, said, did = _call(script, "Move-AtdrPartsToWatcher -WithoutDesktop", restart_goes="yes")
        assert (result, did) == ("True", ["restart through the watcher"])
        assert "(atdr-backend)" in said, "the part that has ended is not named"
        result, _, did = _call(script, "Move-AtdrPartsToWatcher -WithoutDesktop", restart_goes="no")
        assert (result, did) == ("False", ["restart through the watcher"])
        # Going back to starting at sign-in, parts that have a desktop are where they should be.
        result, _, did = _call(script, "Move-AtdrPartsToWatcher", restart_goes="yes")
        assert (result, did) == ("True", [])
    finally:
        part.kill()
        part.wait()

    # Going back takes the tasks that run without a sign-in away first, and installs for a sign-in only once they are.
    (runtime / "without-sign-in").write_text("", encoding="utf-8")
    result, _, did = _call(script, f"Undo-AtdrBeforeSignIn '{user}'")
    assert (result, did) == ("True", [f"administrator: -Remove for {user}", f"install for sign-in: {user}"])
    (runtime / "without-sign-in").write_text("", encoding="utf-8")
    (runtime / "administrator-says-no").write_text("", encoding="utf-8")
    result, said, did = _call(script, f"Undo-AtdrBeforeSignIn '{user}'")
    assert (result, did) == ("False", [f"administrator: -Remove for {user}"])
    assert "scripts\\autostart.cmd -AtSignIn" in said


@windows_only
def test_a_release_waits_for_windows_to_start_a_watcher_this_window_may_not_start(tmp_path):
    root = _own_folder(tmp_path)
    runtime = root / ".atdr_runtime"
    common = _quoted(root / "scripts" / "system_common.ps1")
    # The machine's real task is never asked: here Windows has the task, or not, and this window may start it, or not.
    stand_ins = ("function Get-ScheduledTask { [CmdletBinding()] param([string]$TaskName) "
                 "if ($env:TASK_THERE -eq 'yes') { return [pscustomobject]@{ State = 'Ready' } } return $null }; "
                 "function Start-AtdrWatcherTask { New-Item -ItemType File -Path (Join-Path (Get-AtdrRuntimeDirectory) 'asked-to-start') -Force | Out-Null; "
                 "return ($env:MAY_START -eq 'yes') }")

    def restart(task_there: str, may_start: str) -> tuple[str, float]:
        began = time.monotonic()
        said = subprocess.run(["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command",
                               f". {common}; {stand_ins}; \"$(Restart-AtdrWatcher)\""],
                              capture_output=True, text=True, timeout=180, check=False,
                              env={**os.environ, "TASK_THERE": task_there, "MAY_START": may_start})
        assert said.returncode == 0, said.stderr
        return said.stdout.strip(), time.monotonic() - began

    assert restart("yes", "yes")[0] == "True"
    (runtime / "asked-to-start").unlink()
    said, took = restart("no", "no")
    assert said == "False" and took < 30, "no task: nothing to wait for"
    assert not (runtime / "asked-to-start").exists()

    # Started by Windows within the minute: this folder's watcher writes its record, and that is waited for.
    watcher, watcher_started = _sleeper()
    try:
        def arrive_later() -> None:
            deadline = time.monotonic() + 60
            while time.monotonic() < deadline and not (runtime / "asked-to-start").exists():
                time.sleep(0.2)
            time.sleep(3)
            (runtime / "watch.lock").write_text(json.dumps({"pid": watcher.pid, "started_at": watcher_started}), encoding="utf-8")

        later = threading.Thread(target=arrive_later, daemon=True)
        later.start()
        said, _ = restart("yes", "no")
        later.join(timeout=5)
        assert said == "True"
    finally:
        watcher.kill()
        watcher.wait()


def test_what_the_other_scripts_do_without_a_desktop():
    common = (SCRIPTS / "system_common.ps1").read_text(encoding="utf-8")
    watcher = (SCRIPTS / "watch_system.ps1").read_text(encoding="utf-8")
    start = (SCRIPTS / "start_system.ps1").read_text(encoding="utf-8")
    # Ollama's app lives in the notification area: it is not started where there is none.
    assistant = common[common.index("function Start-AssistantModelIfStopped"):common.index("function Get-SafeDatabaseDialect")]
    assert assistant.index("if (-not (Test-AtdrHasDesktop)) { return $status }") < assistant.index("Start-Process -FilePath $app")
    assert "(Get-Process -Id $PID).SessionId -ne 0" in common
    # Every start the watcher makes says that it is the watcher's, and its first one waits for MongoDB.
    assert '"-NoBrowser", "-ByWatcher")' in watcher
    first = watcher[watcher.index('if ($decision.action -eq "start_all") {'):watcher.index('Write-WatchLog "Starting ATDR: $($decision.reason)."')]
    assert "$script:firstCheck -and -not (Test-TcpEndpoint -Port 27017)" in first and "Start-Sleep -Seconds 5" in first
    # A person's start is handed over after the refusals and before anything is locked or started.
    assert start.index("$unfinished = Get-AtdrUnfinishedRelease") < start.index("if ((Test-AtdrRunsWithoutSignIn) -and -not $ByWatcher -and -not $partial -and -not $DryRun) {") < start.index("$locked = Enter-AtdrStartLock")
    assert "if (-not (Test-AtdrWatcherAlive) -and -not (Start-AtdrWatcherTask)) {" in start
    helper = (SCRIPTS / "desktop_agent.ps1").read_text(encoding="utf-8")
    assert "Start-TrackedProcess" not in helper and "start_system" not in helper and "Stop-Process" not in helper, "it starts and stops nothing of ATDR"
    # A release changes the scripts: the watcher and the helper that go on are the new version's. A watcher's task
    # that this window may not start is started by Windows within the minute, and waited for.
    restart = common[common.index("function Restart-AtdrWatcher"):common.index("# ---- Releases")]
    assert (restart.index("[void](Stop-AtdrWatcherProcess)") < restart.index("[void](Stop-AtdrDesktopHelperProcess)")
            < restart.index("if (Start-AtdrWatcherTask) { return $true }") < restart.index("if (Test-AtdrWatcherAlive) { return $true }"))


@windows_only
def test_the_helper_and_the_watcher_are_found_by_the_record_each_keeps_not_by_a_number_alone(tmp_path):
    root = _own_folder(tmp_path)
    runtime = root / ".atdr_runtime"
    common = _quoted(root / "scripts" / "system_common.ps1")
    helper, helper_started = _sleeper()
    bystander, _ = _sleeper()
    try:
        # Windows gives a process number out again. A record whose number now belongs to something else is not ours.
        for name in ("desktop.lock", "watch.lock"):
            (runtime / name).write_text(json.dumps({"pid": bystander.pid, "started_at": "2001-01-01T00:00:00.0000000Z"}), encoding="utf-8")
        said = _powershell(f". {common}; \"$(Stop-AtdrDesktopHelperProcess)|$(Test-AtdrWatcherAlive)|$(Get-AtdrWatcherSession)|\"").strip()
        assert said == "False|False||"
        assert helper_at_the_desktop(runtime / "desktop.lock") is False
        assert bystander.poll() is None, "the process that has the number now is left alone"

        # The helper is ended by its own record, and the record goes with it.
        (runtime / "desktop.lock").write_text(json.dumps({"pid": helper.pid, "started_at": helper_started}), encoding="utf-8")
        assert _powershell(f". {common}; \"$(Stop-AtdrDesktopHelperProcess)\"").strip() == "True"
        helper.wait(timeout=30)
        assert not (runtime / "desktop.lock").exists()
        assert _powershell(f". {common}; \"$(Stop-AtdrDesktopHelperProcess)\"").strip() == "False", "nothing to end is not an error"
    finally:
        for process in (helper, bystander):
            process.kill()
            process.wait()
