"""A part of ATDR that has no desktop keeps running when a user signs out of Windows.

Installed to start with the machine (scripts/autostart.cmd -BeforeSignIn), ATDR's parts are in no sign-in session.
Windows still tells them when somebody signs out, Python passes that on as Ctrl+Break, and the API, the dashboard's
server and the log receiver take Ctrl+Break as a request to stop. Tried on 11 October 2026 before anything was
installed: a Python process with such a handler had it called by the sign-out event, with and without the mark
Windows puts on the event for a process outside the session. The parts would have stopped at every sign-out.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from atdr.app.core import desktop
from atdr.app.services import notification_channels as channels

ROOT = Path(__file__).resolve().parents[2]
windows_only = pytest.mark.skipif(sys.platform != "win32", reason="what Windows tells a console program")

# Windows delivers a console event by starting a thread in the process at a routine of its own. The child reads
# that routine's address from a real Ctrl+Break it sends itself, then calls it with the sign-out event (5) and with
# the machine shutting down (6), each carrying the mark (the top bit) Windows puts on them for a process that is
# not in the session concerned. Its Ctrl+Break handler stands for the one uvicorn installs.
CHILD = r'''
import ctypes, json, signal, sys, time
from ctypes import wintypes

from atdr.app.core import desktop

guarded, out = sys.argv[1] == "guarded", sys.argv[2]
seen = {"routine": False, "registered": None, "after_sign_out": None, "after_shutdown": None, "error": None}
breaks = []


def save():
    with open(out, "w", encoding="utf-8") as handle:
        json.dump(seen, handle)


try:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    ntdll = ctypes.WinDLL("ntdll")
    routine_type = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.DWORD)
    kernel32.GetCurrentThread.restype = wintypes.HANDLE
    kernel32.CreateThread.restype = wintypes.HANDLE
    kernel32.CreateThread.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p]
    kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    start = ctypes.c_void_p(0)

    @routine_type
    def probe(_event):
        # 9: the address this thread was started at.
        ntdll.NtQueryInformationThread(wintypes.HANDLE(kernel32.GetCurrentThread()), 9, ctypes.byref(start), ctypes.sizeof(start), None)
        return True

    kernel32.SetConsoleCtrlHandler(probe, True)
    kernel32.GenerateConsoleCtrlEvent(1, 0)
    for _ in range(100):
        if start.value:
            break
        time.sleep(0.05)
    kernel32.SetConsoleCtrlHandler(probe, False)
    seen["routine"] = bool(start.value)
    if not start.value:
        save()
        sys.exit(3)

    signal.signal(signal.SIGBREAK, lambda _signum, _frame: breaks.append(1))
    if guarded:
        seen["registered"] = desktop.stay_up_when_someone_signs_out(desktop=lambda: False)
        import gc

        gc.collect()
        seen["kept"] = len(desktop._registered)

    def told(event):
        thread = kernel32.CreateThread(None, 0, start, ctypes.c_void_p(event | 0x80000000), 0, None)
        kernel32.WaitForSingleObject(thread, 5000)
        # A Python handler runs in the main thread, between two of its instructions.
        for _ in range(20):
            time.sleep(0.05)
        return len(breaks)

    seen["after_sign_out"] = told(5)
    seen["after_shutdown"] = told(6)
except Exception as error:
    seen["error"] = repr(error)
save()
'''


def _child(tmp_path: Path, mode: str) -> dict:
    script = tmp_path / "told_by_windows.py"
    script.write_text(CHILD, encoding="utf-8")
    out = tmp_path / f"{mode}.json"
    hidden = subprocess.STARTUPINFO()
    hidden.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    hidden.wShowWindow = 0
    # A console of its own: the Ctrl+Break it sends itself reaches nobody else.
    subprocess.run([sys.executable, str(script), mode, str(out)], creationflags=subprocess.CREATE_NEW_CONSOLE, startupinfo=hidden,
                   env={**os.environ, "PYTHONPATH": str(ROOT)}, timeout=120, check=False)
    assert out.exists(), "the child did not get as far as saying anything"
    said = json.loads(out.read_text(encoding="utf-8"))
    if not said["routine"]:
        pytest.skip("this Windows gave the test no way to deliver a console event to its own process")
    assert said["error"] is None, said["error"]
    return said


@windows_only
def test_a_sign_out_elsewhere_does_not_reach_a_part_without_a_desktop_and_a_shutdown_still_does(tmp_path):
    exposed = _child(tmp_path, "exposed")
    assert exposed["after_sign_out"] == 1, "what this is about: without it, a sign-out is taken for Ctrl+Break and the part stops"
    assert exposed["after_shutdown"] == 2

    guarded = _child(tmp_path, "guarded")
    assert guarded["registered"] is True
    assert guarded["kept"] == 1, "Windows calls it for as long as the part runs: it is kept from being cleared away"
    assert guarded["after_sign_out"] == 0, "the part never hears of the sign-out"
    assert guarded["after_shutdown"] == 1, "the machine shutting down still asks it to stop, and it finishes its work in order"


def test_only_the_sign_out_is_answered_and_only_without_a_desktop(monkeypatch):
    assert desktop.SIGNED_OUT == 5
    # Ctrl+C, Ctrl+Break, a closed console window and the machine shutting down are left to whoever handles them.
    assert [desktop.dealt_with(event) for event in (0, 1, 2, 5, 6)] == [False, False, False, True, False]

    registered = []

    def register(answer) -> bool:
        registered.append(answer)
        return True

    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(desktop, "_registered", [])
    assert desktop.stay_up_when_someone_signs_out(desktop=lambda: True, register=register) is False and registered == [], (
        "at a desktop the sign-out is the part's own: Ctrl+Break lets it finish its work before Windows ends it")
    assert desktop.stay_up_when_someone_signs_out(desktop=lambda: False, register=register) is True
    assert registered == [desktop.dealt_with]
    assert desktop.stay_up_when_someone_signs_out(desktop=lambda: False, register=lambda _answer: False) is False, "Windows refused it"

    # Once is enough, however often a part asks.
    monkeypatch.setattr(desktop, "_registered", [object()])
    assert desktop.stay_up_when_someone_signs_out(desktop=lambda: False, register=register) is True and len(registered) == 1

    monkeypatch.setattr(desktop, "_registered", [])
    monkeypatch.setattr(sys, "platform", "linux")
    assert desktop.stay_up_when_someone_signs_out(desktop=lambda: False, register=register) is False and len(registered) == 1


def test_the_tests_run_at_a_desktop_and_register_nothing():
    assert desktop.has_desktop() is True
    before = list(desktop._registered)
    assert desktop.stay_up_when_someone_signs_out() is False and desktop._registered == before
    # One answer to "is there a desktop": the notification that is handed to the helper asks the same question.
    assert channels.has_desktop is desktop.has_desktop
    assert channels.send_windows.__kwdefaults__["desktop"] is desktop.has_desktop


def test_every_part_that_python_runs_asks_for_it():
    # The four parts start_system.ps1 runs with Python. The MFU sign-in shell's two run on Node, which does not
    # take the sign-out for anything.
    start = (ROOT / "scripts" / "start_system.ps1").read_text(encoding="utf-8")
    for module in ("uvicorn", "atdr.scripts.run_operation_worker", "atdr.scripts.run_syslog_receiver", "atdr.scripts.serve_dashboard"):
        assert f'-FilePath $python -Arguments @("-m", "{module}"' in start, module
    assert start.count("-FilePath $python -Arguments @(") == 4, "a fifth part run with Python has to ask for it too"

    api = (ROOT / "atdr" / "app" / "main.py").read_text(encoding="utf-8")
    lifespan = api[api.index("async def lifespan(app: FastAPI):"):api.index("app = FastAPI(")]
    assert lifespan.index("if stay_up_when_someone_signs_out():") < lifespan.index("yield")
    receiver = (ROOT / "atdr" / "scripts" / "run_syslog_receiver.py").read_text(encoding="utf-8")
    assert receiver.index("if stay_up_when_someone_signs_out():") < receiver.index("run_udp_syslog_receiver(\n")
    worker = (ROOT / "atdr" / "scripts" / "run_operation_worker.py").read_text(encoding="utf-8")
    assert worker.index("        stay_up_when_someone_signs_out()\n") < worker.index("result = run_worker_loop(")
    dashboard = (ROOT / "atdr" / "scripts" / "serve_dashboard.py").read_text(encoding="utf-8")
    assert dashboard.index("    stay_up_when_someone_signs_out()\n") < dashboard.index("uvicorn.run(")
