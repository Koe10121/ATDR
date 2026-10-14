"""A part of ATDR that runs without a desktop.

Installed to start with the machine (scripts/autostart.cmd -BeforeSignIn), ATDR's parts are started by a task that
Windows runs without anyone being signed in. They are then in session 0, the session Windows keeps for its
services: it has no desktop and belongs to no sign-in.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Callable

# What Windows tells a console program when a user signs out of Windows (CTRL_LOGOFF_EVENT).
SIGNED_OUT = 5
# Windows calls what was registered for as long as the process lives, so it is kept from being cleared away.
_registered: list[object] = []


def has_desktop() -> bool:
    """Whether this process runs in somebody's sign-in session."""

    if sys.platform != "win32":
        return True
    import ctypes

    session = ctypes.c_ulong(0)
    if not ctypes.windll.kernel32.ProcessIdToSessionId(os.getpid(), ctypes.byref(session)):
        return True
    return session.value != 0


def dealt_with(event: int) -> bool:
    """A part without a desktop on a piece of news from Windows: True says "dealt with, tell nobody else"."""

    return event == SIGNED_OUT


def _register(answer: Callable[[int], bool]) -> bool:
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    routine = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.DWORD)(answer)
    # Asked first of all that were registered before it, which includes Python's own.
    if not kernel32.SetConsoleCtrlHandler(routine, True):
        return False
    _registered.append(routine)
    return True


def stay_up_when_someone_signs_out(
    *, desktop: Callable[[], bool] = has_desktop, register: Callable[[Callable[[int], bool]], bool] = _register
) -> bool:
    """Keeps a part without a desktop running when a user signs out of Windows. True when it had to do something.

    Windows tells the console programs outside a session that the session's user signed out. Python passes that on
    as Ctrl+Break, which the API, the dashboard's server and the log receiver take as a request to stop: with
    nobody's desktop under them they would stop at every sign-out, and stay down until the watcher brought them
    back. A part without a desktop is in nobody's session, so the news is not for it; it answers before Python
    hears of it.

    A part at a desktop is left as it is: there the sign-out is its own, and Ctrl+Break lets it finish its work in
    the seconds Windows gives it. The machine shutting down is other news, and still stops every part in order.
    """

    if sys.platform != "win32" or desktop():
        return False
    if _registered:
        return True
    return register(dealt_with)
