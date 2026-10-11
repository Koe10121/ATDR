"""Only a version that was committed and checked runs live.

ATDR used to run from the folder it is developed in. A part that restarted, or a sign-in, loaded whatever the
files held at that moment: on 10 October 2026 a held stop ran out overnight and the sign-in start brought ATDR up
on notification code that was neither finished nor committed. A hold only delays that.

Now ATDR runs from a copy of its own (C:\\ATDR-live): a clone of the development folder's repository, checked out
at one commit, with its own settings, database, models and Python environment. scripts\\release.cmd, run in the
development folder, moves that copy to a newer commit:

- the commit is checked first: GitHub's checks for exactly that commit are green, or, when it is not on GitHub,
  the whole test suite passes here on a folder that holds exactly that commit;
- everything slow or uncertain happens while ATDR still runs: fetching the commit, and installing a changed set
  of Python packages into an environment of its own;
- ATDR's own parts are then stopped, the files moved to the commit, the database migrated behind a checked
  backup, the dashboard built, and the parts started again by the watcher, so that they belong to it like any
  part it brings back;
- the new version is watched for a minute. A part that does not come up, stops, or does not answer puts
  everything back as it was: files, Python environment, database and dashboard.

The copy's record (.atdr_runtime/release.json) says which version runs, since when and how it was checked; the
System panel shows it. The API reads that record through this module, so nothing here needs more than the
standard library.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid
from collections.abc import Callable, Sequence
from contextlib import closing
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_LIVE_ROOT = Path("C:/ATDR-live")
RUNTIME = ".atdr_runtime"
# In the live copy: which version runs, and the release that is under way.
RECORD = "release.json"
MARKER = "release-in-progress.json"
# In the development folder: where its live copy is, and which commits passed their check.
LIVE_COPY = "live-copy.json"
CHECKS = "release-checks"
# Between a release and the watcher (scripts/watch_system.ps1).
START_REQUEST = "start-request.json"
START_RESULT = "start-result.json"
# The live copy keeps one Python environment per set of packages; .venv points at the one in use, so a version
# with other packages is ready before ATDR stops, and the one before it is still there to go back to.
ENVIRONMENTS = ".venvs"
ENVIRONMENT_LINK = ".venv"
ENVIRONMENT_MARK = ".atdr-environment.json"
INTERPRETERS = ".python"
INTERPRETER_FILE = "python.exe" if sys.platform == "win32" else "bin/python3"
# Under the runtime folder: lock files of environments being made, the dashboard and database of the version before.
WORK = "release"
HISTORY_KEPT = 30
# New files here are notes kept beside the documents, not part of the system.
LOOSE_NOTES = "docs/"
# What git does not track and the running system reads: trained models, and the evidence the pages show.
CARRIED_FOLDERS = ("atdr/models", "demo_exports", "ml_baseline_reviews")
CARRIED_FILES = ("frontend/.env", "frontend/.env.local", f"{RUNTIME}/team-config.json")
CARRIED_RUNTIME_FOLDERS = (f"{RUNTIME}/packages",)

OWN_PARTS = ("atdr-backend", "atdr-worker", "atdr-syslog", "atdr-frontend")
REQUIRED_PARTS = ("atdr-backend", "atdr-frontend", "shell-backend", "shell-frontend")
OPTIONAL_PARTS = (("OPERATION_WORKER_ENABLED", "atdr-worker"), ("SYSLOG_ENABLED", "atdr-syslog"))
ANSWERS_AT = {
    # Ready, not only alive: the database answers and its schema is the one this version expects.
    "atdr-backend": "http://127.0.0.1:8000/health/ready",
    "atdr-frontend": "http://127.0.0.1:5173/",
    "shell-backend": "http://127.0.0.1:8214/healthz",
    "shell-frontend": "http://localhost:8080/",
}
PART_WORDS = {
    "atdr-backend": "the API server", "atdr-frontend": "the dashboard", "atdr-worker": "the background worker",
    "atdr-syslog": "the live syslog receiver", "shell-backend": "the MFU sign-in service",
    "shell-frontend": "the MFU sign-in page",
}
SIGN_IN_TASK = "ATDR start at sign-in"
# A full start waits for the MFU sign-in page, which compiles for minutes after a cold start.
START_WAIT_SECONDS = 480.0
HEALTH_CHECKS = 3
HEALTH_EVERY_SECONDS = 20.0
STOP_HOLD_HOURS = 2.0
GITHUB_WAIT_MINUTES = 30
GITHUB_ASK_EVERY_SECONDS = 60.0
# In the development folder's own settings these make ATDR write or speak outside the folder. Once it runs from a
# live copy they belong to that copy alone.
OUTWARD_SETTINGS = {
    "ATDR_BACKUP_DIRECTORY": "",
    "ATDR_BACKUP_SCHEDULE_HOURS": "0",
    "ATDR_NOTIFY_EMAIL_TO": "",
    "ATDR_NOTIFY_CHAT_WEBHOOK_URL": "",
    "ATDR_NOTIFY_WINDOWS": "false",
}


# Set in the window a release is run from, these would send a live copy's own commands somewhere else: its
# migration to another database, its backup to another folder, its Python to another folder's code. A live copy
# takes its settings from its own .env and nothing from whoever releases into it.
NOT_INHERITED = frozenset({
    "DATABASE_URL", "ATDR_BACKUP_DIRECTORY", "ATDR_BACKUP_SCHEDULE_HOURS", "ATDR_BACKUP_OFFSITE_FOLDER",
    "PYTHONPATH", "PYTHONHOME", "VIRTUAL_ENV",
})


class ReleaseError(RuntimeError):
    """Why a release cannot go on, in words for the person who asked for it."""


@dataclass(frozen=True)
class Ran:
    code: int
    out: str = ""
    err: str = ""

    @property
    def ok(self) -> bool:
        return self.code == 0

    def last(self, lines: int = 1) -> str:
        """The end of what the command said: its errors when it wrote any, else its output."""

        said = [line.rstrip() for line in (self.err.strip() or self.out.strip()).splitlines() if line.strip()]
        return "\n".join(said[-lines:])


def run_command(
    command: Sequence[str], *, cwd: Path | None = None, env: dict[str, str] | None = None, timeout: float = 600
) -> Ran:
    """Runs one command and waits for it alone.

    What it says goes to files, never to a pipe: a script that leaves ATDR's parts running leaves them holding the
    pipe, and reading it would never end.
    """

    with tempfile.NamedTemporaryFile(prefix="atdr-release-", suffix=".out", delete=False) as out, \
            tempfile.NamedTemporaryFile(prefix="atdr-release-", suffix=".err", delete=False) as err:
        added = ""
        inherited = {name: value for name, value in os.environ.items() if name.upper() not in NOT_INHERITED}
        try:
            process = subprocess.Popen(  # noqa: S603 - the commands are this module's own
                [str(part) for part in command], cwd=cwd, env={**inherited, "GIT_TERMINAL_PROMPT": "0", **(env or {})},
                stdin=subprocess.DEVNULL, stdout=out, stderr=err,
            )
        except OSError as exc:
            code, added = 127, f"{exc.__class__.__name__}: {exc}"
        else:
            try:
                code = process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
                code, added = 124, f"stopped after {int(timeout)} seconds"
    said = []
    for file in (out, err):
        path = Path(file.name)
        said.append(path.read_text(encoding="utf-8", errors="replace"))
        try:
            path.unlink()
        except OSError:
            pass  # a process the command left running still holds it
    return Ran(code=code, out=said[0], err=f"{said[1]}\n{added}".strip() if added else said[1])


def fetch_json(url: str, *, timeout: float = 20) -> tuple[int, Any]:
    """An HTTP status and the JSON that came with it; status 0 when the address could not be reached."""

    request = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json", "User-Agent": "atdr-release"})  # noqa: S310
    try:
        with urllib.request.urlopen(request, timeout=timeout) as answer:  # noqa: S310 - https, GitHub's API
            return int(answer.status), json.loads(answer.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return int(exc.code), None
    except (OSError, ValueError):
        return 0, None


def http_answers(url: str, *, timeout: float = 10) -> bool:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as answer:  # noqa: S310 - ATDR's own parts on this machine
            return 200 <= int(answer.status) < 400
    except (OSError, ValueError):
        return False


_BEYOND_MICROSECONDS = re.compile(r"(\.\d{6})\d+")


def _time(value: Any) -> datetime | None:
    """A time as PowerShell or Python wrote it."""

    if not value:
        return None
    text = _BEYOND_MICROSECONDS.sub(r"\1", str(value).strip().replace("Z", "+00:00"))
    try:
        moment = datetime.fromisoformat(text)
    except ValueError:
        return None
    return moment if moment.tzinfo is not None else moment.replace(tzinfo=timezone.utc)


def _process_began(pid: int) -> datetime | None:
    """When the running process with this number was started (Windows); None when there is none."""

    import ctypes
    from ctypes import wintypes

    kernel = ctypes.windll.kernel32
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
    kernel.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    handle = kernel.OpenProcess(0x1000, False, int(pid))  # PROCESS_QUERY_LIMITED_INFORMATION
    if not handle:
        return None
    try:
        created, ended, in_kernel, in_user = (wintypes.FILETIME() for _ in range(4))
        code = wintypes.DWORD()
        if not kernel.GetProcessTimes(handle, ctypes.byref(created), ctypes.byref(ended), ctypes.byref(in_kernel), ctypes.byref(in_user)):
            return None
        if not kernel.GetExitCodeProcess(handle, ctypes.byref(code)) or code.value != 259:  # STILL_ACTIVE
            return None
    finally:
        kernel.CloseHandle(handle)
    return datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(
        microseconds=((created.dwHighDateTime << 32) | created.dwLowDateTime) // 10
    )


def process_alive(pid: int, started_at: str) -> bool:
    """Whether the process the start script recorded still runs: that number, started at that moment."""

    if sys.platform != "win32":
        try:
            os.kill(pid, 0)
        except OSError:
            return False
        return True
    began = _process_began(pid)
    recorded = _time(started_at)
    return began is not None and recorded is not None and abs((began - recorded).total_seconds()) <= 5


def this_process() -> dict[str, Any] | None:
    """This process as the launcher's scripts record one, so that they can tell whether it still runs."""

    began = _process_began(os.getpid()) if sys.platform == "win32" else None
    return {"pid": os.getpid(), "started_at": began.isoformat()} if began is not None else None


def _say(words: str) -> None:
    # With the time: how long each step took, and how long ATDR was down, can be read off afterwards.
    print(f"{time.strftime('%H:%M:%S')} {words}", flush=True)


def _lasted(seconds: float) -> str:
    whole = max(0, int(round(seconds)))
    minutes, rest = divmod(whole, 60)
    said = [f"{minutes} {'minute' if minutes == 1 else 'minutes'}"] if minutes else []
    if rest or not minutes:
        said.append(f"{rest} {'second' if rest == 1 else 'seconds'}")
    return " ".join(said)


@dataclass
class Tools:
    """What a release does to the machine. The tests put their own in."""

    run: Callable[..., Ran] = run_command
    fetch: Callable[[str], tuple[int, Any]] = fetch_json
    answers: Callable[[str], bool] = http_answers
    alive: Callable[[int, str], bool] = process_alive
    sleep: Callable[[float], None] = time.sleep
    now: Callable[[], datetime] = field(default=lambda: datetime.now(timezone.utc))
    say: Callable[[str], None] = _say
    npm: str | None = None
    # The live copy is started and watched by Windows tasks, and its Python is a copy of a Windows interpreter.
    windows: bool = sys.platform == "win32"

    def npm_command(self) -> str:
        found = self.npm or shutil.which("npm")
        if not found:
            raise ReleaseError("npm was not found, so the dashboard cannot be built. Install Node.js 20.19 or newer.")
        return found


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        # Windows PowerShell writes UTF-8 with a byte-order mark.
        value = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError):
        return None
    return value if isinstance(value, dict) else None


def _write_json(path: Path, value: dict[str, Any]) -> None:
    """Written whole, then moved into place: nothing ever reads half a file."""

    path.parent.mkdir(parents=True, exist_ok=True)
    arriving = path.with_name(f"{path.name}.arriving")
    arriving.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    os.replace(arriving, path)


def _text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8-sig", errors="replace")
    except OSError:
        return ""


def _json(text: str) -> dict[str, Any] | None:
    try:
        value = json.loads(text.strip() or "null")
    except ValueError:
        return None
    return value if isinstance(value, dict) else None


def _wait_for(tools: Tools, look: Callable[[], Any], seconds: float, *, every: float = 2.0) -> Any:
    """What `look` finds, as soon as it finds something; None when the time runs out."""

    # By the clock, not by the number of looks: a look at parts that do not answer yet takes seconds itself.
    until = tools.now() + timedelta(seconds=seconds)
    while True:
        found = look()
        if found:
            return found
        if tools.now() >= until:
            return None
        tools.sleep(every)


# ---- The repository ----


def git(tools: Tools, repo: Path, *arguments: str, check: bool = True, timeout: float = 600) -> Ran:
    ran = tools.run(["git", "-C", str(repo), *arguments], timeout=timeout)
    if check and not ran.ok:
        # git ends on "Aborting"; what it could not do is in the lines before.
        said = " ".join(line.strip() for line in ran.last(6).splitlines())
        raise ReleaseError(f"git {arguments[0]} did not work in {repo}: {said or 'it gave no reason'}")
    return ran


def resolve_commit(tools: Tools, repo: Path, name: str = "HEAD") -> str:
    ran = git(tools, repo, "rev-parse", "--verify", "--quiet", f"{name}^{{commit}}", check=False)
    commit = ran.out.strip()
    if not ran.ok or not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ReleaseError(f"'{name}' is not a commit in {repo}.")
    return commit


def commit_facts(tools: Tools, repo: Path, commit: str) -> dict[str, str]:
    shown = git(tools, repo, "show", "--no-patch", "--format=%H%x1f%h%x1f%s%x1f%cI", commit).out.strip().split("\x1f")
    return {"commit": shown[0], "short": shown[1], "subject": shown[2], "committed_at": shown[3]}


def is_ancestor(tools: Tools, repo: Path, older: str, newer: str) -> bool:
    return git(tools, repo, "merge-base", "--is-ancestor", older, newer, check=False).ok


def _status_entries(listed: str) -> list[tuple[str, str]]:
    """The state and the path of each entry of `git status --porcelain -z`."""

    entries, found, index = listed.split("\0"), [], 0
    while index < len(entries):
        entry = entries[index]
        index += 1
        if len(entry) < 4:
            continue
        if entry[0] in "RC":
            index += 1  # the name it was moved from follows
        found.append((entry[:2], entry[3:]))
    return found


def uncommitted(tools: Tools, repo: Path) -> list[str]:
    """What the folder holds that no commit does: changed files, and new files outside the documents' folder."""

    listed = git(tools, repo, "status", "--porcelain", "-z", "--untracked-files=all").out
    return [path for state, path in _status_entries(listed) if not (state == "??" and path.startswith(LOOSE_NOTES))]


def changed_by_hand(tools: Tools, repo: Path) -> list[str]:
    """Tracked files in a released copy that no longer hold what its commit holds."""

    listed = git(tools, repo, "status", "--porcelain", "-z", "--untracked-files=no", check=False)
    return [path for _state, path in _status_entries(listed.out)] if listed.ok else []


def file_at(tools: Tools, repo: Path, commit: str, path: str) -> str | None:
    shown = git(tools, repo, "show", f"{commit}:{path}", check=False)
    return shown.out if shown.ok else None


def _setting_names(text: str | None) -> set[str]:
    return set(re.findall(r"^([A-Z][A-Z0-9_]*)=", text or "", flags=re.MULTILINE))


@dataclass(frozen=True)
class Changes:
    """What differs between the version that runs and the one that is to run."""

    files: int = 0
    packages: bool = False
    dashboard_packages: bool = False
    schema: bool = False
    dashboard: bool = False
    settings: tuple[str, ...] = ()

    def words(self) -> list[str]:
        said = [f"{self.files} {'file differs' if self.files == 1 else 'files differ'}."]
        if self.packages:
            said.append("It needs other Python packages: they are installed into an environment of their own before ATDR stops.")
        if self.dashboard_packages:
            said.append("The dashboard's build tools changed: they are installed again.")
        if self.schema:
            said.append("It changes the database: a checked backup is taken first.")
        if self.settings:
            said.append(f"It knows settings the version before did not: {', '.join(self.settings)}. They keep their defaults "
                        "until they are put in the live copy's .env.")
        return said


def changes_between(tools: Tools, repo: Path, old: str, new: str) -> Changes:
    names = [name for name in git(tools, repo, "diff", "--name-only", old, new).out.splitlines() if name.strip()]
    settings = _setting_names(file_at(tools, repo, new, ".env.example")) - _setting_names(file_at(tools, repo, old, ".env.example"))
    return Changes(
        files=len(names),
        packages="requirements.lock.txt" in names,
        dashboard_packages=any(name in ("frontend/package.json", "frontend/package-lock.json") for name in names),
        schema=any(name.startswith("migrations/") for name in names),
        dashboard=any(name.startswith("frontend/") for name in names),
        settings=tuple(sorted(settings)),
    )


# ---- What is on record ----


def read_record(root: Path) -> dict[str, Any] | None:
    """Which version a live copy holds; None in a folder that is not one."""

    record = _read_json(root / RUNTIME / RECORD)
    return record if record and re.fullmatch(r"[0-9a-f]{40}", str(record.get("commit") or "")) else None


def checked_out(root: Path) -> str | None:
    """The commit a folder's files are at, read without starting git; None when they follow a branch or are no repository."""

    head = _text(root / ".git" / "HEAD").strip()
    return head if re.fullmatch(r"[0-9a-f]{40}", head) else None


def version_status(root: Path = PROJECT_ROOT) -> dict[str, Any] | None:
    """What the System panel says about the version: None where ATDR runs from the folder it is developed in."""

    record = read_record(root)
    if record is None:
        return None
    previous = record.get("previous") if isinstance(record.get("previous"), dict) else None
    return {
        "commit": str(record.get("short") or record["commit"][:7]),
        "subject": str(record.get("subject") or ""),
        "committed_at": _time(record.get("committed_at")),
        "released_at": _time(record.get("released_at")),
        "checked_by": str(record.get("checked_by") or ""),
        "check": str(record.get("check") or ""),
        "previous": str(previous.get("short") or "") if previous else None,
        # The files were moved to another commit by hand, past the check a release makes.
        "as_released": checked_out(root) == record["commit"],
        "unfinished": (root / RUNTIME / MARKER).is_file(),
    }


def files_changed(root: Path = PROJECT_ROOT, tools: Tools | None = None) -> dict[str, Any] | None:
    """What in a live copy's files is not the version on record: None when they are, and in a folder that is no live copy.

    A change made straight in the live copy runs at the next restart without having passed any check, which is the
    very thing the copy exists to prevent. The worker looks every few minutes and tells people (worker_problems).
    """

    record = read_record(root)
    if record is None or (root / RUNTIME / MARKER).is_file():
        # While a release is under way the files are between two versions on purpose.
        return None
    moved = checked_out(root) != record["commit"]
    edited = changed_by_hand(tools or Tools(), root)
    if not moved and not edited:
        return None
    return {"version": str(record.get("short") or record["commit"][:7]), "moved": moved, "files": edited}


def live_copy_of(dev: Path) -> Path | None:
    found = _read_json(dev / RUNTIME / LIVE_COPY)
    return Path(str(found["root"])) if found and found.get("root") else None


def _history(record: dict[str, Any] | None, entry: dict[str, Any]) -> list[dict[str, Any]]:
    before = [item for item in (record or {}).get("history") or [] if isinstance(item, dict)]
    return [*before, entry][-HISTORY_KEPT:]


# ---- Is this commit checked? ----


def github_repository(tools: Tools, repo: Path) -> str | None:
    url = git(tools, repo, "config", "--get", "remote.origin.url", check=False).out.strip()
    found = re.search(r"github\.com[:/]+([^/\s]+)/([^/\s]+?)(?:\.git)?/?$", url)
    return f"{found.group(1)}/{found.group(2)}" if found else None


def github_checks(tools: Tools, repository: str, commit: str) -> dict[str, Any]:
    """What GitHub's checks say about exactly this commit."""

    status, body = tools.fetch(f"https://api.github.com/repos/{repository}/commits/{commit}/check-runs?per_page=100")
    if status in (404, 422):
        return {"state": "not_there"}
    if status != 200 or not isinstance(body, dict):
        return {"state": "unreachable", "status": status}
    runs = [run for run in body.get("check_runs") or [] if isinstance(run, dict)]
    if not runs:
        return {"state": "no_checks"}
    failed = sorted(str(run.get("name")) for run in runs
                    if run.get("status") == "completed" and run.get("conclusion") not in ("success", "neutral", "skipped"))
    waiting = sorted(str(run.get("name")) for run in runs if run.get("status") != "completed")
    if failed:
        return {"state": "red", "names": failed}
    if waiting:
        return {"state": "running", "names": waiting}
    return {"state": "green", "count": len(runs)}


@dataclass(frozen=True)
class Step:
    name: str
    command: tuple[str, ...]
    folder: str = "."
    timeout: float = 900
    # The last "N passed" it prints is what the check says about it.
    counted: bool = False


def local_steps(tools: Tools, scratch: Path) -> list[Step]:
    """What GitHub's two main jobs run, here: the backend's tests and checks, then the dashboard's."""

    python, npm = sys.executable, tools.npm_command()
    return [
        Step("Python compiles", (python, "-m", "compileall", "-q", "atdr", "migrations")),
        Step("ruff", (python, "-m", "ruff", "check", "atdr", "migrations")),
        Step("backend tests", (python, "-m", "pytest", "atdr/tests", "-q", "-p", "no:cacheprovider",
                               f"--basetemp={scratch / 'pytest'}"), timeout=3600, counted=True),
        Step("migrations apply", (python, "-m", "alembic", "upgrade", "head")),
        Step("migrations match the models", (python, "-m", "alembic", "check")),
        Step("dashboard lint", (npm, "run", "lint"), folder="frontend"),
        Step("dashboard builds", (npm, "run", "build", "--", "--outDir", str(scratch / "dashboard"), "--emptyOutDir"),
             folder="frontend"),
        Step("browser tests", (npm, "run", "test:e2e", "--", "--reporter=line"), folder="frontend", timeout=1800, counted=True),
    ]


def _counted(text: str) -> str:
    found = {word: re.findall(rf"(\d+) {word}", text) for word in ("passed", "failed", "skipped")}
    return ", ".join(f"{numbers[-1]} {word}" for word, numbers in found.items() if numbers)


def local_tests(tools: Tools, dev: Path, commit: str) -> dict[str, Any]:
    """The whole test suite, on a folder that holds exactly the commit."""

    facts = commit_facts(tools, dev, commit)
    head = resolve_commit(tools, dev)
    if head != commit:
        return {"ok": False, "by": "local_tests", "words": (
            f"The tests run on the files in this folder, and the folder is at {head[:7]}, not at {facts['short']}. "
            "Release HEAD, or check that commit out first.")}
    loose = uncommitted(tools, dev)
    if loose:
        shown = ", ".join(loose[:3]) + (f" and {len(loose) - 3} more" if len(loose) > 3 else "")
        return {"ok": False, "by": "local_tests", "words": (
            f"The tests would not be testing commit {facts['short']}: {len(loose)} "
            f"{'file in this folder is' if len(loose) == 1 else 'files in this folder are'} not committed ({shown}). "
            "Commit them or put them aside, then try again.")}
    scratch = dev / ".tmp" / "release-check" / facts["short"]
    shutil.rmtree(scratch, ignore_errors=True)
    scratch.mkdir(parents=True)
    log = dev / RUNTIME / "logs" / "release-check.log"
    log.parent.mkdir(parents=True, exist_ok=True)
    log.write_text(f"Check of {commit}, begun {tools.now().isoformat()}\n", encoding="utf-8")
    # Its own empty database, as on GitHub: nothing the tests do can reach a database that is in use.
    env = {"DATABASE_URL": f"sqlite:///{(scratch / 'check.db').as_posix()}", "PYTHONIOENCODING": "utf-8"}
    passed = []
    for step in local_steps(tools, scratch):
        tools.say(f"  {step.name} ...")
        began = time.monotonic()
        ran = tools.run(list(step.command), cwd=dev / step.folder, env=env, timeout=step.timeout)
        with log.open("a", encoding="utf-8", errors="replace") as written:
            written.write(f"\n==== {step.name} (exit code {ran.code}) ====\n{ran.out}\n{ran.err}\n")
        said = _counted(ran.out) if step.counted else ""
        if not ran.ok:
            end = "\n".join(line for line in f"{ran.out}\n{ran.err}".splitlines() if line.strip())
            return {"ok": False, "by": "local_tests", "words": (
                f"{step.name} failed{f' ({said})' if said else ''}. Everything it said is in {log}; it ended:\n"
                + "\n".join(f"    {line}" for line in end.splitlines()[-12:]))}
        passed.append({"name": step.name, "seconds": round(time.monotonic() - began, 1), "said": said})
        tools.say(f"    passed{f' ({said})' if said else ''}")
    shutil.rmtree(scratch, ignore_errors=True)
    counts = "; ".join(f"{step['name']}: {step['said']}" for step in passed if step["said"])
    return {"ok": True, "by": "local_tests", "words": f"the tests passed on this machine ({counts})", "steps": passed}


def checked_before(dev: Path, commit: str) -> dict[str, Any] | None:
    found = _read_json(dev / RUNTIME / CHECKS / f"{commit}.json")
    return found if found and found.get("ok") is True and found.get("commit") == commit else None


def check_commit(tools: Tools, dev: Path, commit: str, *, local: bool = False, wait_minutes: float = GITHUB_WAIT_MINUTES) -> dict[str, Any]:
    """Whether the commit may go live: GitHub's checks for it are green, or the tests pass here."""

    earlier = checked_before(dev, commit)
    if earlier is not None:
        return {**earlier, "earlier": True}
    result: dict[str, Any] | None = None
    repository = None if local else github_repository(tools, dev)
    if repository:
        asked = 0
        while result is None:
            found = github_checks(tools, repository, commit)
            if found["state"] == "green":
                result = {"ok": True, "by": "github", "words": f"GitHub's {found['count']} checks passed"}
            elif found["state"] == "red":
                # On GitHub and red is red: tests that pass here do not make it green.
                return {"ok": False, "by": "github", "words": f"GitHub's checks failed for this commit: {', '.join(found['names'])}."}
            elif found["state"] == "running":
                if asked * GITHUB_ASK_EVERY_SECONDS >= wait_minutes * 60:
                    return {"ok": False, "by": "github", "words": (
                        f"GitHub is still checking this commit ({', '.join(found['names'])}). Try again when it has "
                        "finished, or add --local to run the tests here instead.")}
                if asked == 0:
                    tools.say(f"  GitHub is checking this commit ({len(found['names'])} still running); waiting for it.")
                asked += 1
                tools.sleep(GITHUB_ASK_EVERY_SECONDS)
            else:
                tools.say({
                    "not_there": "  This commit is not on GitHub, so the tests run here.",
                    "no_checks": "  GitHub ran no checks for exactly this commit, so the tests run here.",
                }.get(found["state"], "  GitHub could not be asked, so the tests run here."))
                break
    if result is None:
        result = local_tests(tools, dev, commit)
    result = {**result, "commit": commit, "at": tools.now().isoformat()}
    if result["ok"]:
        _write_json(dev / RUNTIME / CHECKS / f"{commit}.json", result)
    return result


# ---- The Python environment ----


def python_in(environment: Path) -> Path:
    return environment / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")


def environment_key(lock_text: str, interpreter: str) -> str:
    """One environment per set of packages and Python; line endings do not make another set."""

    return hashlib.sha256(f"{interpreter}\n{lock_text.replace(chr(13), '')}".encode("utf-8")).hexdigest()[:16]


def environment_ready(environment: Path) -> bool:
    return (environment / ENVIRONMENT_MARK).is_file() and python_in(environment).is_file()


def interpreter_name(interpreter: Path) -> str:
    """The folder an interpreter is in under .python, which says which Python it is."""

    return interpreter.relative_to(interpreter.parents[len(Path(INTERPRETER_FILE).parts)]).parts[0]


def make_environment(tools: Tools, live: Path, *, interpreter: Path, lock_text: str) -> Path:
    """The environment for these packages, made when the live copy does not have it yet. ATDR keeps running meanwhile."""

    name = interpreter_name(interpreter)
    environment = live / ENVIRONMENTS / environment_key(lock_text, name)
    if environment_ready(environment):
        return environment
    if environment.exists():
        shutil.rmtree(environment)  # one that was never finished
    work = live / RUNTIME / WORK
    work.mkdir(parents=True, exist_ok=True)
    lock = work / f"requirements.{environment.name}.txt"
    lock.write_text(lock_text.replace("\r", ""), encoding="utf-8", newline="\n")
    python = str(python_in(environment))
    for words, command, timeout in (
        ("make the Python environment", [str(interpreter), "-m", "venv", str(environment)], 900),
        ("install the Python packages", [python, "-m", "pip", "install", "--disable-pip-version-check", "--no-input",
                                         "--require-hashes", "-r", str(lock)], 3600),
        ("check the Python packages against each other", [python, "-m", "pip", "check", "--disable-pip-version-check"], 300),
    ):
        ran = tools.run(command, cwd=live, timeout=timeout)
        if not ran.ok:
            raise ReleaseError(f"Could not {words}: {ran.last(3)}")
    _write_json(environment / ENVIRONMENT_MARK, {"key": environment.name, "interpreter": name, "made_at": tools.now().isoformat()})
    return environment


def _is_link(path: Path) -> bool:
    if os.path.islink(path):
        return True
    try:
        return bool(getattr(os.lstat(path), "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT)
    except OSError:
        return False


def environment_in_use(live: Path) -> Path | None:
    link = live / ENVIRONMENT_LINK
    return Path(os.path.realpath(link)) if _is_link(link) else None


def use_environment(live: Path, environment: Path) -> None:
    """Points .venv at the environment. The scripts and every written command keep saying .venv."""

    link = live / ENVIRONMENT_LINK
    if _is_link(link):
        if sys.platform == "win32":
            os.rmdir(link)  # takes the pointer away, not what it points at
        else:
            os.unlink(link)
    elif link.exists():
        raise ReleaseError(f"{link} is a folder of its own, not a pointer into {ENVIRONMENTS}: this is not a live copy a release made.")
    if sys.platform == "win32":
        import _winapi

        _winapi.CreateJunction(str(environment), str(link))
    else:
        os.symlink(environment, link, target_is_directory=True)


def prune_environments(live: Path, keep: set[str]) -> list[str]:
    removed = []
    folder = live / ENVIRONMENTS
    for environment in folder.iterdir() if folder.is_dir() else []:
        if environment.is_dir() and environment.name not in keep:
            shutil.rmtree(environment, ignore_errors=True)
            removed.append(environment.name)
    return removed


def development_interpreter(dev: Path) -> Path | None:
    """The Python the development folder's environment was made from."""

    for line in _text(dev / ".venv" / "pyvenv.cfg").splitlines():
        name, _, value = line.partition("=")
        if name.strip() == "home" and value.strip():
            home = Path(value.strip())
            # On Windows `home` is the interpreter's own folder; elsewhere it is that folder's bin.
            return home if INTERPRETER_FILE == "python.exe" else home.parent
    return None


def ensure_interpreter(dev: Path, live: Path) -> Path:
    """The live copy's own Python: a copy of the one the tests ran on, so nothing it needs is in the development folder."""

    home = development_interpreter(dev)
    if home is None or not (home / INTERPRETER_FILE).is_file():
        raise ReleaseError("The development folder's .venv does not say which Python it was made from (pyvenv.cfg: home).")
    target = live / INTERPRETERS / home.name
    if not (target / INTERPRETER_FILE).is_file():
        if target.exists():
            shutil.rmtree(target)
        shutil.copytree(home, target)
    return target / INTERPRETER_FILE


# ---- The running system ----


def env_values(root: Path) -> dict[str, str]:
    """The names and values in a folder's .env. The values are never printed."""

    values: dict[str, str] = {}
    for line in _text(root / ".env").splitlines():
        clean = line.strip()
        if not clean or clean.startswith("#") or "=" not in clean:
            continue
        name, _, value = clean.partition("=")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        values[name.strip()] = value
    return values


def expected_parts(root: Path) -> list[str]:
    values = env_values(root)
    return [*REQUIRED_PARTS, *(part for setting, part in OPTIONAL_PARTS if values.get(setting, "").lower() == "true")]


def processes(root: Path) -> dict[str, dict[str, Any]]:
    recorded = (_read_json(root / RUNTIME / "system-processes.json") or {}).get("processes")
    # ConvertTo-Json writes a list of one as the one.
    listed = [recorded] if isinstance(recorded, dict) else recorded or []
    return {str(item["name"]): item for item in listed if isinstance(item, dict) and item.get("name")}


def alive_parts(tools: Tools, root: Path) -> list[str]:
    return [name for name, record in processes(root).items()
            if tools.alive(int(record.get("pid") or 0), str(record.get("started_at") or ""))]


def _script(tools: Tools, script: Path, arguments: Sequence[str] = (), *, timeout: float = 300) -> Ran:
    return tools.run(["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script), *arguments],
                     cwd=script.parent.parent, timeout=timeout)


def _powershell(tools: Tools, root: Path, command: str, *, timeout: float = 180) -> Ran:
    """A command with the folder's own launcher functions loaded (scripts/system_common.ps1)."""

    common = str(root / "scripts" / "system_common.ps1").replace("'", "''")
    return tools.run(["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", f". '{common}'; {command}"],
                     cwd=root, timeout=timeout)


def stop_parts(tools: Tools, root: Path, *, own_only: bool = True) -> None:
    """Stops ATDR, and keeps it stopped until the release starts it. The MFU sign-in page stays up where the folder's stop script can leave it."""

    script = root / "scripts" / "stop_system.ps1"
    arguments = ["-HoldHours", f"{STOP_HOLD_HOURS:g}"]
    partly = own_only and "[string[]]$Only" in _text(script)
    if partly:
        arguments += ["-Only", ",".join(OWN_PARTS)]
    ran = _script(tools, script, arguments)
    if not ran.ok:
        raise ReleaseError(f"ATDR could not be stopped: {ran.last()}")
    left = [name for name in alive_parts(tools, root) if name in OWN_PARTS or not partly]
    if left:
        raise ReleaseError(f"Still running after the stop: {', '.join(left)}.")


def health(tools: Tools, root: Path, *, since: dict[str, dict[str, Any]] | None = None) -> list[str]:
    """What is wrong with the running system; nothing when every part runs and answers."""

    wrong = []
    records = processes(root)
    for name in expected_parts(root):
        words = PART_WORDS.get(name, name)
        record = records.get(name)
        if record is None or not tools.alive(int(record.get("pid") or 0), str(record.get("started_at") or "")):
            # A part can run without being on the record (the record was lost, or something else started it). It
            # is not "not running" then: nothing ATDR does can stop or restart it, which is another kind of wrong.
            if name in ANSWERS_AT and tools.answers(ANSWERS_AT[name]):
                wrong.append(f"{words} answers but is not on the record of running parts")
            else:
                wrong.append(f"{words} is not running")
        elif since is not None and (since.get(name) or {}).get("pid") != record.get("pid"):
            wrong.append(f"{words} stopped and had to be started again")
        elif name in ANSWERS_AT and not tools.answers(ANSWERS_AT[name]):
            wrong.append(f"{words} does not answer at {ANSWERS_AT[name]}")
    return wrong


def start_parts(tools: Tools, root: Path, *, by: str = "release") -> dict[str, dict[str, Any]]:
    """Has ATDR started by what looks after it on this machine, never as a child of the release, and waits for it."""

    runtime = root / RUNTIME
    if START_REQUEST in _text(root / "scripts" / "system_common.ps1"):
        request = {"id": uuid.uuid4().hex, "by": by, "release": True, "at": tools.now().isoformat()}
        (runtime / START_RESULT).unlink(missing_ok=True)
        (runtime / START_REQUEST).unlink(missing_ok=True)
        # A fresh watcher first, and only then the request: the watcher that was running holds the scripts of the
        # version before, and one that had taken the request would be ended in the middle of answering it.
        restarted = _powershell(tools, root, "if (-not (Restart-AtdrWatcher)) { exit 4 }")
        if not restarted.ok:
            raise ReleaseError("ATDR was not started: the watcher (the task 'ATDR keep running') is not installed on this "
                               f"machine. Run {root}\\scripts\\autostart.cmd once.")
        _write_json(runtime / START_REQUEST, request)

        def answered() -> dict[str, Any] | None:
            result = _read_json(runtime / START_RESULT)
            return result if result and result.get("id") == request["id"] else None

        result = _wait_for(tools, answered, START_WAIT_SECONDS)
        (runtime / START_RESULT).unlink(missing_ok=True)
        if result is None:
            (runtime / START_REQUEST).unlink(missing_ok=True)
            raise ReleaseError(f"The watcher did not start ATDR within {int(START_WAIT_SECONDS / 60)} minutes "
                               f"(its log: {runtime}\\logs\\watch.log).")
        if not result.get("ok"):
            if int(result.get("code") or 0) != 3:
                raise ReleaseError(f"ATDR did not start: {result.get('said') or 'the start script gave no reason'}")
            # Another start was under way (exit code 3): left to it.
            if _wait_for(tools, lambda: not health(tools, root), START_WAIT_SECONDS) is None:
                raise ReleaseError("ATDR did not come up: " + "; ".join(health(tools, root)) + ".")
        return processes(root)

    # A version from before a release could ask the watcher. Its sign-in start brings up everything, and only
    # everything: what is still running is stopped first. The watcher that is running holds the scripts of the
    # version that was here a moment ago; it is ended, and the sign-in start (or Windows, within the minute) starts
    # the one that belongs to these files.
    if alive_parts(tools, root):
        stop_parts(tools, root, own_only=False)
    started = _powershell(tools, root, f"[void](Stop-AtdrWatcherProcess); Set-AtdrDesiredState -State running -By '{by}'; "
                                       f"Start-ScheduledTask -TaskName '{SIGN_IN_TASK}' -ErrorAction Stop")
    if not started.ok:
        raise ReleaseError(f"ATDR was not started: the task '{SIGN_IN_TASK}' is not installed on this machine. "
                           f"Run {root}\\scripts\\autostart.cmd once.")
    if _wait_for(tools, lambda: not health(tools, root), START_WAIT_SECONDS) is None:
        raise ReleaseError("ATDR did not come up: " + "; ".join(health(tools, root)) + ".")
    return processes(root)


def watch_health(tools: Tools, root: Path, started: dict[str, dict[str, Any]]) -> list[str]:
    """A version counts as running once every part has stayed up and answered for a minute."""

    for _ in range(HEALTH_CHECKS):
        tools.sleep(HEALTH_EVERY_SECONDS)
        wrong = health(tools, root, since=started)
        if wrong:
            return wrong
    return []


def tasks_installed(tools: Tools, root: Path) -> bool:
    """Whether the task that starts ATDR at sign-in and the watcher's task are this folder's: they start its scripts."""

    asked = _powershell(tools, root, (
        "$scripts = (Join-Path (Get-AtdrProjectRoot) 'scripts').ToLowerInvariant(); "
        f"foreach ($name in @($AtdrWatcherTaskName, '{SIGN_IN_TASK}')) {{ "
        "$task = Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue; "
        "if ($null -eq $task -or -not ((@($task.Actions | ForEach-Object { [string]$_.Arguments }) -join ' ').ToLowerInvariant().Contains($scripts))) { exit 4 } }"))
    return asked.ok


# ---- The database ----


def database_file(root: Path) -> Path | None:
    """The SQLite file a folder's settings name; None for another kind of database."""

    url = env_values(root).get("DATABASE_URL") or "sqlite:///./atdr.db"
    if not url.startswith("sqlite:///"):
        return None
    path = Path(url[len("sqlite:///"):].split("?", 1)[0])
    return path if path.is_absolute() else root / path


def _rows(connection: sqlite3.Connection) -> dict[str, int]:
    tables = [row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'")]
    return {table: int(connection.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0]) for table in sorted(tables)}


def copy_database(source: Path, target: Path, *, source_is_backup: bool = False) -> dict[str, int]:
    """A copy made by SQLite's own backup, kept only when it holds the same rows and SQLite finds it whole."""

    target.parent.mkdir(parents=True, exist_ok=True)
    for old in (target, Path(f"{target}-wal"), Path(f"{target}-shm")):
        old.unlink(missing_ok=True)
    # A backup file is read as it is; a database that was in use may still have changes in its -wal file.
    address = f"file:{source.as_posix()}?mode=ro{'&immutable=1' if source_is_backup else ''}"
    with closing(sqlite3.connect(address, uri=True)) as original, closing(sqlite3.connect(target)) as copy:
        original.backup(copy)
        rows, copied = _rows(original), _rows(copy)
        whole = copy.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    if rows != copied or not whole:
        target.unlink(missing_ok=True)
        raise ReleaseError(f"The copy of {source.name} is not the same as the original; it was removed.")
    return rows


def restore_database(backup: Path, database: Path, aside: Path) -> None:
    """Puts the backup in the database's place. What was there is kept beside it, not deleted."""

    if not backup.is_file():
        raise ReleaseError(f"The backup taken before the release is not there any more: {backup}")
    aside.mkdir(parents=True, exist_ok=True)
    for name in (database.name, f"{database.name}-wal", f"{database.name}-shm"):
        present = database.with_name(name)
        if present.is_file():
            os.replace(present, aside / name)
    copy_database(backup, database, source_is_backup=True)


def _revision(text: str) -> str | None:
    for line in text.splitlines():
        found = re.match(r"\s*([0-9a-f]{8,})\b", line)
        if found:
            return found.group(1)
    return None


def migrate(tools: Tools, live: Path, note: Callable[..., None]) -> str | None:
    """Brings the database to the version's schema behind a checked backup; None when it was there already."""

    python = str(python_in(live / ENVIRONMENT_LINK))
    current = tools.run([python, "-m", "alembic", "current"], cwd=live, timeout=300)
    heads = tools.run([python, "-m", "alembic", "heads"], cwd=live, timeout=300)
    for asked in (current, heads):
        if not asked.ok:
            raise ReleaseError(f"The database's version could not be read: {asked.last(3)}")
    wanted = _revision(heads.out)
    if wanted is not None and _revision(current.out) == wanted:
        return None
    tools.say("  This version changes the database: taking a checked backup first.")
    backup = tools.run([python, "-m", "atdr.scripts.backup_now", "--purpose", "before_release", "--json"], cwd=live, timeout=3600)
    taken = _json(backup.out) or {}
    if not backup.ok or not taken.get("backup_path"):
        raise ReleaseError("The database was not changed: the backup that comes first did not succeed "
                           f"({taken.get('words') or backup.last() or 'no reason given'}).")
    note(database_backup=str(taken["backup_path"]))
    upgraded = tools.run([python, "-m", "alembic", "upgrade", "head"], cwd=live, timeout=3600)
    if not upgraded.ok:
        raise ReleaseError(f"The database could not be brought to this version: {upgraded.last(3)}")
    return str(taken["backup_path"])


def build_dashboard(tools: Tools, live: Path) -> None:
    python = str(python_in(live / ENVIRONMENT_LINK))
    built = tools.run([python, "-m", "atdr.scripts.build_dashboard"], cwd=live, timeout=1500)
    state = _json(tools.run([python, "-m", "atdr.scripts.build_dashboard", "--check", "--json"], cwd=live, timeout=300).out) or {}
    if not built.ok or not state.get("built") or state.get("stale") or state.get("uncommitted"):
        raise ReleaseError(f"The dashboard could not be built from this version: {built.last(8) or built.out.strip()[-600:] or 'no reason given'}")


def install_dashboard_packages(tools: Tools, live: Path) -> None:
    ran = tools.run([tools.npm_command(), "ci", "--no-audit", "--no-fund"], cwd=live / "frontend", timeout=1800)
    if not ran.ok:
        raise ReleaseError(f"The dashboard's build tools could not be installed: {ran.last(5)}")


def _copy_folder(source: Path, target: Path) -> None:
    shutil.rmtree(target, ignore_errors=True)
    if source.is_dir():
        shutil.copytree(source, target)


# ---- Moving the live copy to a version ----


def under_way(tools: Tools, marker: dict[str, Any]) -> bool:
    """Whether the release a marker belongs to is still being made: the process that wrote it runs."""

    driver = marker.get("driver") if isinstance(marker.get("driver"), dict) else None
    return bool(driver) and tools.alive(int(driver.get("pid") or 0), str(driver.get("started_at") or ""))


def _require_live(live: Path) -> dict[str, Any]:
    record = read_record(live)
    if record is None:
        raise ReleaseError(f"{live} is not a live copy yet. Make it first: scripts\\release.cmd setup")
    return record


def switch(tools: Tools, dev: Path, live: Path, target: str, *, checked: dict[str, Any], outcome: str = "released") -> dict[str, Any]:
    """Moves the live copy to the commit and starts it; puts everything back when it does not come up healthy."""

    record = _require_live(live)
    current = str(record["commit"])
    runtime = live / RUNTIME
    if (runtime / MARKER).is_file():
        if under_way(tools, _read_json(runtime / MARKER) or {}):
            raise ReleaseError("Another release into this copy is under way right now. Wait for it to end.")
        raise ReleaseError("An earlier release did not finish. Put the version before it back first: scripts\\release.cmd recover")
    head = resolve_commit(tools, live)
    if head != current:
        raise ReleaseError(f"The live copy's files are at {head[:7]}, but its record says {current[:7]} is running. "
                           "Someone moved them by hand; `git -C` that folder back to the recorded commit first.")
    edited = changed_by_hand(tools, live)
    if edited:
        raise ReleaseError(f"{len(edited)} {'file' if len(edited) == 1 else 'files'} in the live copy were changed by hand "
                           f"({', '.join(edited[:3])}). A release would overwrite them: make the change in the development "
                           f"folder and commit it, then put the live copy's files back (git -C {live} checkout -- .).")
    if not tasks_installed(tools, live):
        raise ReleaseError("A release has ATDR started again by the watcher, and its tasks are not installed on this "
                           f"machine. Run {live}\\scripts\\autostart.cmd once.")
    git(tools, live, "fetch", "--quiet", "--no-tags", "origin")
    if not git(tools, live, "cat-file", "-e", f"{target}^{{commit}}", check=False).ok:
        raise ReleaseError(f"The live copy could not get commit {target[:7]} from {dev}.")
    facts = commit_facts(tools, live, target)
    changes = changes_between(tools, live, current, target)
    for words in changes.words():
        tools.say(f"  {words}")

    # Before ATDR stops: everything slow, and everything that can fail without anything having changed.
    before = environment_in_use(live)
    interpreter = live / str(record.get("interpreter") or "")
    lock_text = file_at(tools, live, target, "requirements.lock.txt")
    wanted = before
    if lock_text is not None and interpreter.is_file():
        if before is None or before.name != environment_key(lock_text, interpreter_name(interpreter)):
            tools.say("  Installing this version's Python packages; ATDR keeps running meanwhile.")
            wanted = make_environment(tools, live, interpreter=interpreter, lock_text=lock_text)

    # With the process that makes the release: while it runs the release is under way, not cut off.
    marker = {"from": current, "to": target, "started_at": tools.now().isoformat(), "source": str(dev),
              "driver": this_process(),
              "environment_before": before.name if before else None, "dashboard_packages": changes.dashboard_packages,
              "database_backup": None}

    def note(**changed: Any) -> None:
        marker.update(changed)
        _write_json(runtime / MARKER, marker)

    note()
    stopped_at = tools.now()
    try:
        tools.say("  Stopping ATDR's own parts.")
        stop_parts(tools, live)
        _copy_folder(live / "frontend" / "dist", runtime / WORK / "dashboard-before")
        # Forced: nothing tracked was changed by hand (that was refused above), and a file the copy carried that
        # this version now holds itself gives way to the commit's.
        git(tools, live, "checkout", "--quiet", "--detach", "--force", target)
        if wanted is not None and wanted != before:
            use_environment(live, wanted)
        if changes.dashboard_packages:
            tools.say("  Installing the dashboard's build tools.")
            install_dashboard_packages(tools, live)
        migrate(tools, live, note)
        tools.say("  Building the dashboard.")
        build_dashboard(tools, live)
        tools.say("  Starting ATDR.")
        started = start_parts(tools, live)
        down = (tools.now() - stopped_at).total_seconds()
        tools.say("  Watching the new version for a minute.")
        wrong = watch_health(tools, live, started)
        if wrong:
            raise ReleaseError("; ".join(wrong))
    except Exception as exc:  # noqa: BLE001 - whatever went wrong, the version before goes back
        why = str(exc) if isinstance(exc, ReleaseError) else f"{exc.__class__.__name__}: {exc}"
        return back_out(tools, live, marker, why=why, target=facts)

    released = {
        "version": 1, **facts, "released_at": tools.now().isoformat(), "checked_by": checked.get("by"),
        "check": checked.get("words"), "source": str(dev), "interpreter": record.get("interpreter"),
        "environment": wanted.name if wanted else None,
        "previous": {key: record.get(key) for key in ("commit", "short", "subject", "released_at", "checked_by", "check", "environment")},
        "history": _history(record, {"commit": target, "short": facts["short"], "at": tools.now().isoformat(), "outcome": outcome}),
    }
    _write_json(runtime / RECORD, released)
    (runtime / MARKER).unlink(missing_ok=True)
    prune_environments(live, {name for name in (released["environment"], marker["environment_before"]) if name})
    return {"ok": True, "commit": target, "short": facts["short"], "subject": facts["subject"], "changes": changes,
            "down_seconds": round(down),
            "words": f"ATDR runs version {facts['short']} ({facts['subject']}). Its own parts were down for {_lasted(down)}."}


def back_out(tools: Tools, live: Path, marker: dict[str, Any], *, why: str, target: dict[str, str] | None = None) -> dict[str, Any]:
    """Puts back the version that was running: its files, its Python environment, its database and its dashboard."""

    runtime = live / RUNTIME
    record = read_record(live) or {}
    back_to = str(marker["from"])
    short = (target or {}).get("short") or str(marker.get("to") or "")[:7]
    tools.say(f"  Version {short} did not go live: {why}")
    tools.say(f"  Putting version {back_to[:7]} back.")
    result = {"ok": False, "rolled_back": True, "commit": marker.get("to"), "short": short, "why": why}
    try:
        in_use = environment_in_use(live)
        untouched = (resolve_commit(tools, live) == back_to and not marker.get("database_backup")
                     and (not marker.get("environment_before") or (in_use is not None and in_use.name == marker["environment_before"])))
        try:
            stop_parts(tools, live)
        except ReleaseError:
            # A part that will not stop is the version before, still running, when nothing was changed yet: what
            # did stop is simply started again. With files already changed, nothing may go on running over them.
            if not untouched:
                raise
        if resolve_commit(tools, live) != back_to:
            git(tools, live, "checkout", "--quiet", "--detach", "--force", back_to)
        before = marker.get("environment_before")
        in_use = environment_in_use(live)
        if before and (in_use is None or in_use.name != before):
            use_environment(live, live / ENVIRONMENTS / str(before))
        if marker.get("dashboard_packages"):
            try:
                install_dashboard_packages(tools, live)
            except ReleaseError as exc:
                # The dashboard is served from its built files, which are put back below; only its next build needs these.
                tools.say(f"  {exc} ATDR runs without them; the next release installs them again.")
        if marker.get("database_backup"):
            database = database_file(live)
            if database is None:
                raise ReleaseError("the database is not a SQLite file, so its backup has to be restored by hand")
            tools.say("  Restoring the database from the backup taken before the release.")
            restore_database(Path(str(marker["database_backup"])), database, runtime / WORK / "database-of-failed-release")
        saved = runtime / WORK / "dashboard-before"
        if saved.is_dir():
            _copy_folder(saved, live / "frontend" / "dist")
        started = start_parts(tools, live)
        wrong = watch_health(tools, live, started)
        if wrong:
            raise ReleaseError("; ".join(wrong))
    except Exception as exc:  # noqa: BLE001 - said in words below; the marker stays, so nothing starts this folder by itself
        again = str(exc) if isinstance(exc, ReleaseError) else f"{exc.__class__.__name__}: {exc}"
        # Said as it is: the dashboard may well be up while a part is missing or the files are between two versions.
        state = ("ATDR'S API ANSWERS, BUT ATDR IS NOT IN ORDER: " + "; ".join(health(tools, live) or ["its files may not be one version"])
                 if tools.answers(ANSWERS_AT["atdr-backend"]) else "ATDR IS NOT RUNNING")
        return {**result, "live_down": True, "words": (
            f"Version {short} did not go live ({why}), and version {back_to[:7]} could not be put back either ({again}). "
            f"{state}. When the cause is fixed: scripts\\release.cmd recover")}
    if record:
        record["history"] = _history(record, {"commit": marker.get("to"), "short": short, "at": tools.now().isoformat(),
                                              "outcome": "put_back", "why": why[:500]})
        _write_json(runtime / RECORD, record)
    (runtime / MARKER).unlink(missing_ok=True)
    return {**result, "live_down": False, "words": (
        f"Version {short} did not go live: {why}. Version {back_to[:7]} was put back and is running.")}


def release(tools: Tools, dev: Path, live: Path, name: str = "HEAD", *, local: bool = False) -> dict[str, Any]:
    """Checks a commit and makes it the version that runs."""

    record = _require_live(live)
    target = resolve_commit(tools, dev, name)
    facts = commit_facts(tools, dev, target)
    if target == record["commit"]:
        return {"ok": True, "commit": target, "short": facts["short"], "nothing_to_do": True,
                "words": f"Version {facts['short']} is the one that runs already."}
    if resolve_commit(tools, dev, "main") != target and not is_ancestor(tools, dev, target, "main"):
        raise ReleaseError(f"Commit {facts['short']} is not on main. Only what is on main is released.")
    if not is_ancestor(tools, dev, str(record["commit"]), target):
        raise ReleaseError(f"Commit {facts['short']} does not contain the version that runs ({str(record['commit'])[:7]}): it is "
                           "older, or on another line of work. `scripts\\release.cmd back` goes to the version before.")
    tools.say(f"Checking {facts['short']} ({facts['subject']}).")
    checked = check_commit(tools, dev, target, local=local)
    if not checked["ok"]:
        return {"ok": False, "commit": target, "short": facts["short"], "refused": True, "words": checked["words"]}
    tools.say(f"  Checked: {checked['words']}{' (checked earlier)' if checked.get('earlier') else ''}.")
    tools.say(f"Releasing {facts['short']} to {live}.")
    return switch(tools, dev, live, target, checked=checked)


def go_back(tools: Tools, dev: Path, live: Path) -> dict[str, Any]:
    """Makes the version before the one that runs the version that runs. For a version that passed its check and is still wrong."""

    record = _require_live(live)
    previous = record.get("previous") if isinstance(record.get("previous"), dict) else None
    if not previous or not previous.get("commit"):
        raise ReleaseError("There is no version before this one on record.")
    target = str(previous["commit"])
    if changes_between(tools, live, target, str(record["commit"])).schema:
        raise ReleaseError(
            f"Version {str(record['commit'])[:7]} changed the database, and what was stored since would not fit version "
            f"{target[:7]}. Fix it with a new release instead; or, to give up everything stored since, restore the backup "
            "named 'before_release' by hand (docs/OPERATIONS_RUNBOOK.md, Restoring a backup).")
    tools.say(f"Going back to {target[:7]}.")
    checked = {"by": previous.get("checked_by"), "words": previous.get("check")}
    return switch(tools, dev, live, target, checked=checked, outcome="went_back")


def recover(tools: Tools, live: Path) -> dict[str, Any]:
    """After a release that was cut off: puts back the version that was running before it."""

    marker = _read_json(live / RUNTIME / MARKER)
    if marker is None or not marker.get("from"):
        return {"ok": True, "nothing_to_do": True, "words": "No release was cut off; there is nothing to put back."}
    if under_way(tools, marker):
        raise ReleaseError("A release into this copy is under way right now: it puts the version before back itself "
                           "when it has to. Wait for it to end.")
    result = back_out(tools, live, marker, why="the release was cut off before it finished")
    return {**result, "ok": not result.get("live_down"), "recovered": not result.get("live_down")}


# ---- Making the live copy ----


def _untracked(tools: Tools, repo: Path, folders: Sequence[str]) -> list[str]:
    present = [folder for folder in folders if (repo / folder).is_dir()]
    if not present:
        return []
    return [name for name in git(tools, repo, "ls-files", "--others", "-z", "--", *present).out.split("\0") if name]


def carry(tools: Tools, dev: Path, live: Path) -> int:
    """Copies what git does not track and the running system reads: models, the evidence the pages show, private settings."""

    copied = 0
    names = [*_untracked(tools, dev, CARRIED_FOLDERS), *(name for name in CARRIED_FILES if (dev / name).is_file())]
    for folder in CARRIED_RUNTIME_FOLDERS:
        names += [path.relative_to(dev).as_posix() for path in (dev / folder).rglob("*") if path.is_file()]
    for name in names:
        if "__pycache__/" in name:
            continue
        source, target = dev / name, live / name
        try:
            found, there = source.stat(), target.stat() if target.is_file() else None
        except OSError:
            continue
        if there is not None and there.st_size == found.st_size and int(there.st_mtime) == int(found.st_mtime):
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
        copied += 1
    return copied


def set_env_values(path: Path, values: dict[str, str]) -> list[str]:
    """Sets names in a .env file and leaves every other line as it is. Says which names changed, never a value."""

    raw = path.read_bytes().decode("utf-8-sig")
    ending = "\r\n" if "\r\n" in raw else "\n"
    lines, changed, seen = raw.split(ending), [], set()
    for index, line in enumerate(lines):
        found = re.match(r"\s*([A-Za-z_][A-Za-z0-9_]*)\s*=(.*)$", line)
        if not found or found.group(1) not in values:
            continue
        name = found.group(1)
        seen.add(name)
        if found.group(2).strip().strip("\"'") != values[name]:
            lines[index] = f'{name}="{values[name]}"'
            changed.append(name)
    missing = [name for name in values if name not in seen]
    if missing:
        while lines and not lines[-1].strip():
            lines.pop()
        lines += ["", "# ATDR runs from its live copy; this folder does not write or speak outside itself (scripts\\release.cmd).",
                  *(f'{name}="{values[name]}"' for name in missing), ""]
        changed += missing
    if changed:
        path.write_bytes(ending.join(lines).encode("utf-8"))
    return changed


def setup(tools: Tools, dev: Path, live: Path, name: str = "HEAD", *, local: bool = False) -> dict[str, Any]:
    """Makes the live copy from the development folder and moves ATDR to it.

    The development folder keeps everything it has, so when the copy does not come up ATDR is started from where
    it ran before. Every step before the stop can be made again: a setup that was cut off is simply run again.
    """

    from atdr.app.services.persistence_service import database_label
    from atdr.app.services.scheduled_backup_service import rename_source

    if not tools.windows:
        raise ReleaseError("A live copy is made on Windows: its start and its watcher are Windows tasks.")
    if read_record(dev) is not None:
        raise ReleaseError(f"{dev} is a live copy itself. Run this in the folder ATDR is developed in.")
    if read_record(live) is not None:
        raise ReleaseError(f"{live} is a live copy already. Put a new version there with: scripts\\release.cmd go")
    if dev.resolve() == live.resolve() or dev.resolve() in live.resolve().parents:
        raise ReleaseError("The live copy has to be a folder outside the development folder.")
    source_database = database_file(dev)
    if source_database is None or not source_database.is_file() or not source_database.resolve().is_relative_to(dev.resolve()):
        raise ReleaseError("The live copy can be made for a SQLite database inside the development folder (DATABASE_URL in .env).")
    target = resolve_commit(tools, dev, name)
    facts = commit_facts(tools, dev, target)
    tools.say(f"Checking {facts['short']} ({facts['subject']}).")
    checked = check_commit(tools, dev, target, local=local)
    if not checked["ok"]:
        return {"ok": False, "refused": True, "words": checked["words"]}
    tools.say(f"  Checked: {checked['words']}{' (checked earlier)' if checked.get('earlier') else ''}.")

    # While ATDR still runs where it is: the copy's files, its Python, its dashboard.
    tools.say(f"Making the live copy in {live} (ATDR keeps running meanwhile).")
    live.mkdir(parents=True, exist_ok=True)
    if not (live / ".git").exists():
        if any(live.iterdir()):
            raise ReleaseError(f"{live} holds something that is not a live copy. Choose an empty folder.")
        # No line-ending conversion: the copy's files are byte for byte what the commit holds, which is what the
        # checks on GitHub ran on. (A development folder on Windows has a mix of both endings.)
        ran = tools.run(["git", "clone", "--quiet", "--no-checkout", "-c", "core.autocrlf=false", str(dev), str(live)], timeout=1800)
        if not ran.ok:
            raise ReleaseError(f"The repository could not be copied to {live}: {ran.last(3)}")
    else:
        git(tools, live, "config", "core.autocrlf", "false")
        git(tools, live, "fetch", "--quiet", "--no-tags", "origin")
    git(tools, live, "checkout", "--quiet", "--detach", "--force", target)
    tools.say("  Its own Python and packages.")
    interpreter = ensure_interpreter(dev, live)
    lock_text = file_at(tools, live, target, "requirements.lock.txt")
    if lock_text is None:
        raise ReleaseError("This version has no requirements.lock.txt to install its packages from.")
    use_environment(live, make_environment(tools, live, interpreter=interpreter, lock_text=lock_text))
    tools.say("  Its settings, models and evidence.")
    shutil.copy2(dev / ".env", live / ".env")
    carry(tools, dev, live)
    tools.say("  Its dashboard.")
    if not (live / "frontend" / "node_modules" / "vite" / "bin" / "vite.js").is_file():
        install_dashboard_packages(tools, live)
    build_dashboard(tools, live)

    # From here ATDR is down until the copy runs, or until it is back where it was.
    tools.say("Stopping ATDR in the development folder and moving its database.")
    backup_folder = env_values(dev).get("ATDR_BACKUP_DIRECTORY", "").strip()
    target_database = live / source_database.resolve().relative_to(dev.resolve())
    was, now = database_label(f"sqlite:///{source_database.resolve().as_posix()}"), database_label(f"sqlite:///{target_database.as_posix()}")
    renamed = False
    try:
        stop_parts(tools, dev, own_only=False)
        rows = copy_database(source_database, target_database)
        shutil.copy2(dev / ".env", live / ".env")
        carry(tools, dev, live)
        if backup_folder and Path(backup_folder).is_dir():
            # The database moved: its backups name its new place, or the copy would count none as its own.
            rename_source(Path(backup_folder), was=was, now=now)
            renamed = True
        _write_json(live / RUNTIME / RECORD, {
            "version": 1, **facts, "released_at": tools.now().isoformat(), "checked_by": checked.get("by"),
            "check": checked.get("words"), "source": str(dev),
            "interpreter": interpreter.relative_to(live).as_posix(), "environment": environment_in_use(live).name,
            "previous": None,
            "history": [{"commit": target, "short": facts["short"], "at": tools.now().isoformat(), "outcome": "installed"}],
        })
        # The tasks first, then the end of the watcher that still runs from the development folder: ended before,
        # Windows would start it once more from there within the minute, and the copy's own would never get a turn.
        registered = _script(tools, live / "scripts" / "autostart.ps1", timeout=300)
        if not registered.ok or not tasks_installed(tools, live):
            raise ReleaseError(f"Windows did not take the live copy's start and watcher tasks: {registered.last(2)}")
        _powershell(tools, dev, "[void](Stop-AtdrWatcherProcess)")
        tools.say("  Starting ATDR from the live copy.")
        started = start_parts(tools, live, by="release setup")
        wrong = watch_health(tools, live, started)
        if wrong:
            raise ReleaseError("; ".join(wrong))
    except Exception as exc:  # noqa: BLE001 - whatever went wrong, ATDR goes back to where it ran
        why = str(exc) if isinstance(exc, ReleaseError) else f"{exc.__class__.__name__}: {exc}"
        tools.say(f"  The live copy did not come up: {why}")
        tools.say("  Starting ATDR from the development folder again.")
        (live / RUNTIME / RECORD).unlink(missing_ok=True)
        again = "it runs from the development folder again"
        try:
            if (live / "scripts" / "stop_system.ps1").is_file():
                _script(tools, live / "scripts" / "stop_system.ps1", ["-HoldHours", f"{STOP_HOLD_HOURS:g}"])
            if renamed:
                rename_source(Path(backup_folder), was=now, now=was)
            _script(tools, dev / "scripts" / "autostart.ps1", timeout=300)
            if (live / "scripts" / "system_common.ps1").is_file():
                _powershell(tools, live, "[void](Stop-AtdrWatcherProcess)")
            start_parts(tools, dev, by="release setup undone")
        except Exception as second:  # noqa: BLE001
            again = f"AND IT COULD NOT BE STARTED FROM THE DEVELOPMENT FOLDER EITHER ({second}). Run scripts\\start_system.cmd there"
        return {"ok": False, "words": f"The live copy was not put into use: {why}. ATDR was left as it was: {again}."}

    _write_json(dev / RUNTIME / LIVE_COPY, {"root": str(live), "since": tools.now().isoformat()})
    kept = dev / RUNTIME / "config-backups" / f"atdr.env.before-live-copy-{tools.now().strftime('%Y%m%d')}"
    kept.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(dev / ".env", kept)
    quieted = set_env_values(dev / ".env", OUTWARD_SETTINGS)
    return {"ok": True, "commit": target, "short": facts["short"], "rows": sum(rows.values()), "quieted": quieted,
            "words": f"ATDR runs from {live}, version {facts['short']} ({facts['subject']})."}


# ---- What a person sees ----


def status(tools: Tools, dev: Path, live: Path | None) -> dict[str, Any]:
    head = resolve_commit(tools, dev)
    found: dict[str, Any] = {
        "development": {"root": str(dev), **commit_facts(tools, dev, head), "uncommitted": uncommitted(tools, dev),
                        "checked": checked_before(dev, head)},
        "live": None,
    }
    record = read_record(live) if live is not None else None
    if live is None or record is None:
        return found
    behind = git(tools, dev, "rev-list", "--count", f"{record['commit']}..{head}", check=False)
    found["live"] = {
        "root": str(live), "record": record, "as_released": checked_out(live) == record["commit"],
        "changed_by_hand": changed_by_hand(tools, live), "unfinished": _read_json(live / RUNTIME / MARKER),
        "wrong": health(tools, live), "commits_not_live": int(behind.out.strip() or 0) if behind.ok else None,
    }
    return found
