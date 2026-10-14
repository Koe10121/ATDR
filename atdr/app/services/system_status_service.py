"""What the System panel says: whether ATDR's parts are kept running, its backups, its version and the dashboard's build.

The watcher (scripts/watch_system.ps1) is not part of this process. It writes what it sees and does to
.atdr_runtime/watch-status.json at every check, and start_system and stop_system write what ATDR is meant to be
to .atdr_runtime/desired-state.json; this reads both. A status the watcher has not refreshed for two minutes means
nothing is watching, and then nothing it says about the parts is repeated here: it may no longer be true.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import time
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from atdr.app.core.config import PROJECT_ROOT, Settings, get_settings
from atdr.app.db.models import OperationWorkerHeartbeat
from atdr.app.services.auto_detection_service import LIVE_WORKER_STATES
from atdr.app.services.dashboard_build_service import FRONTEND, build_state
from atdr.app.services.release_service import version_status
from atdr.app.services.scheduled_backup_service import backup_status, failure_words

RUNTIME = PROJECT_ROOT / ".atdr_runtime"
_BEYOND_MICROSECONDS = re.compile(r"(\.\d{6})\d+")
# The watcher writes at every check, half a minute apart.
WATCHER_SILENT_AFTER = timedelta(seconds=120)
RESTARTS_SHOWN_FOR = timedelta(hours=24)
# A part's name in the table, and in a sentence.
PARTS = {
    "atdr-backend": ("API server", "the API server"),
    "atdr-frontend": ("Dashboard", "the dashboard"),
    "atdr-worker": ("Background worker", "the background worker"),
    "atdr-syslog": ("Live syslog receiver", "the live syslog receiver"),
    "shell-backend": ("MFU sign-in service", "the MFU sign-in service"),
    "shell-frontend": ("MFU sign-in page", "the MFU sign-in page"),
}


def _utc(moment: datetime) -> datetime:
    return moment if moment.tzinfo is not None else moment.replace(tzinfo=timezone.utc)


def _time(value: Any) -> datetime | None:
    """A time as PowerShell wrote it: seven decimals of a second, and Z."""

    if not value:
        return None
    text = _BEYOND_MICROSECONDS.sub(r"\1", str(value).strip().replace("Z", "+00:00"))
    try:
        return _utc(datetime.fromisoformat(text))
    except ValueError:
        return None


def _read(path: Path) -> dict[str, Any] | None:
    try:
        # Windows PowerShell writes UTF-8 with a byte-order mark.
        value = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError):
        return None
    return value if isinstance(value, dict) else None


def _listed(names: list[str]) -> str:
    words = [PARTS.get(name, (name, name))[1] for name in names]
    return words[0] if len(words) == 1 else f"{', '.join(words[:-1])} and {words[-1]}"


def _action_words(action: dict[str, Any]) -> str:
    """What the watcher last did, to follow "it": "started the background worker again after it stopped"."""

    if action.get("all"):
        why = "the time it was to stay stopped had passed" if action.get("resumed") else "no part of it was running"
        return f"started ATDR, because {why}"
    started = [str(name) for name in action.get("started") or []]
    restarted = [str(name) for name in action.get("restarted") or []]
    said = []
    if started:
        said.append(f"started {_listed(started)} again after {'it' if len(started) == 1 else 'they'} stopped")
    if restarted:
        said.append(f"restarted {_listed(restarted)}, which {'was' if len(restarted) == 1 else 'were'} not answering")
    return " and ".join(said) if said else "looked and found nothing to do"


def keeping_running_status(*, now: datetime | None = None, runtime: Path = RUNTIME) -> dict[str, Any]:
    now = _utc(now or datetime.now(timezone.utc))
    desired = _read(runtime / "desired-state.json") or {}
    meant = desired.get("state") if desired.get("state") in ("running", "stopped") else "unknown"
    held_until = _time(desired.get("hold_until")) if meant == "stopped" else None
    status = _read(runtime / "watch-status.json") or {}
    watcher = status.get("watcher") if isinstance(status.get("watcher"), dict) else {}
    checked = _time(watcher.get("checked_at"))
    age = (now - checked).total_seconds() if checked is not None else None
    watching = age is not None and age <= WATCHER_SILENT_AFTER.total_seconds()

    parts = []
    for part in (status.get("parts") or []) if watching else []:
        if not isinstance(part, dict) or not part.get("name"):
            continue
        name = str(part["name"])
        restarts = sorted(moment for moment in (_time(value) for value in part.get("restarts") or [])
                          if moment is not None and now - moment <= RESTARTS_SHOWN_FOR)
        parts.append({
            "name": name,
            "label": PARTS.get(name, (name, name))[0],
            "running": bool(part.get("running")),
            "started_at": _time(part.get("started_at")),
            "answering": part.get("answering") if isinstance(part.get("answering"), bool) else None,
            "restarts_24h": len(restarts),
            "last_restart_at": restarts[-1] if restarts else None,
            "keeps_stopping": bool(part.get("keeps_stopping")),
        })
    action = status.get("last_action") if watching and isinstance(status.get("last_action"), dict) else None
    return {
        "meant_to_be": meant,
        "held_until": held_until if held_until is not None and held_until > now else None,
        "watching": watching,
        "checked_seconds_ago": None if age is None else int(max(0, age)),
        "interval_seconds": int(watcher["interval_seconds"]) if watching and watcher.get("interval_seconds") else None,
        "parts": parts,
        "last_action": None if action is None else {
            "at": _time(action.get("at")), "what": _action_words(action), "ok": bool(action.get("ok")),
        },
    }


_AC_SLEEP = re.compile(r"Current AC Power Setting Index:\s*0x([0-9a-fA-F]+)")
# The sleep time is asked of Windows at most this often: the System panel asks for the status every half minute.
_SLEEP_ASKED_EVERY = 60.0
_sleep_known: tuple[float, int | None] | None = None


def mains_sleep_seconds(*, run: Callable[..., Any] = subprocess.run) -> int | None:
    """After how long without use this machine goes to sleep on mains power; 0 is never, None when it cannot be said."""

    global _sleep_known
    if sys.platform != "win32":
        return None
    if _sleep_known is not None and time.monotonic() - _sleep_known[0] < _SLEEP_ASKED_EVERY:
        return _sleep_known[1]
    seconds: int | None = None
    try:
        asked = run(["powercfg", "/query", "SCHEME_CURRENT", "SUB_SLEEP", "STANDBYIDLE"], capture_output=True, text=True,
                    timeout=15, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        found = _AC_SLEEP.search(asked.stdout or "")
        seconds = int(found.group(1), 16) if found else None
    except (OSError, subprocess.SubprocessError, ValueError):
        seconds = None
    _sleep_known = (time.monotonic(), seconds)
    return seconds


def unattended_status(*, runtime: Path = RUNTIME, sleep_seconds: Callable[[], int | None] = mains_sleep_seconds) -> dict[str, Any] | None:
    """Whether ATDR runs with nobody at the machine; None where scripts/autostart.cmd has installed nothing.

    Installed for a sign-in, ATDR starts when someone signs in to Windows and ends when they sign out. Installed
    with -BeforeSignIn it starts with the machine. Either way it pauses while the machine sleeps.
    """

    record = _read(runtime / "autostart.json") or {}
    if record.get("mode") not in ("before_sign_in", "at_sign_in"):
        return None
    seconds = sleep_seconds()
    return {
        "before_sign_in": record["mode"] == "before_sign_in",
        # Asked for with -StayAwakeOnMains. A power plan that was changed or added since can have undone it.
        "stay_awake_wanted": bool(record.get("stay_awake_on_mains")),
        "sleeps_after_minutes_on_mains": None if seconds is None else int(round(seconds / 60)),
    }


def _worker_running(db: Session, settings: Settings, now: datetime) -> bool:
    fresh_since = now - timedelta(seconds=max(1, int(settings.operation_worker_heartbeat_seconds)) * 3)
    seen = db.scalar(
        select(func.max(OperationWorkerHeartbeat.last_seen_at)).where(OperationWorkerHeartbeat.status.in_(LIVE_WORKER_STATES))
    )
    return seen is not None and _utc(seen) >= fresh_since


def system_status(
    db: Session,
    *,
    settings: Settings | None = None,
    now: datetime | None = None,
    runtime: Path = RUNTIME,
    frontend: Path = FRONTEND,
    **backup_options: Any,
) -> dict[str, Any]:
    settings = settings or get_settings()
    now = _utc(now or datetime.now(timezone.utc))
    backups = backup_status(db, settings=settings, now=now, **backup_options)
    for failure in (backups["last_failure"], backups["offsite"]["last_failure"]):
        if failure is not None:
            failure["words"] = failure_words(failure["status"])
    # The worker takes the backups, so without it a schedule is only a setting.
    backups["worker_running"] = _worker_running(db, settings, now)
    build = build_state(frontend)
    # Imported here: the notification service reads this module's view of the parts.
    from atdr.app.services.notification_service import notification_status

    notifications = notification_status(db, settings=settings, now=now)
    # The worker sends them too.
    notifications["worker_running"] = backups["worker_running"]
    return {
        "keeping_running": keeping_running_status(now=now, runtime=runtime),
        "backups": backups,
        "dashboard_build": {key: build[key] for key in ("built", "built_at", "commit", "uncommitted", "stale")},
        "notifications": notifications,
        # Which released version this is; None where ATDR runs from the folder it is developed in.
        "version": version_status(runtime.parent),
        "unattended": unattended_status(runtime=runtime),
    }
