"""Only a version that was committed and checked runs live (atdr/app/services/release_service.py).

The repositories here are real ones in a temporary folder, so every git step is the real one. The machine is not:
ATDR's parts, the watcher, pip, npm, alembic and the dashboard build are played by `Machine`, which records what a
release did, in which order, and can make any step fail.
"""

from __future__ import annotations

import json
import os
import sqlite3
import stat
import subprocess
import sys
import time
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from atdr.app.services import release_service as release
from atdr.app.services.release_service import Ran, ReleaseError, Tools

GREEN = (200, {"check_runs": [{"name": "backend", "status": "completed", "conclusion": "success"},
                              {"name": "CodeQL", "status": "completed", "conclusion": "neutral"}]})
RUNNING = (200, {"check_runs": [{"name": "backend", "status": "in_progress", "conclusion": None},
                                {"name": "frontend", "status": "completed", "conclusion": "success"}]})
RED = (200, {"check_runs": [{"name": "backend", "status": "completed", "conclusion": "failure"},
                            {"name": "frontend", "status": "completed", "conclusion": "success"}]})
PART_AT = {url: name for name, url in release.ANSWERS_AT.items()}
WITH_WORKER = [*release.REQUIRED_PARTS, "atdr-worker"]
OWN = ["atdr-backend", "atdr-worker", "atdr-frontend"]
BASE = {
    ".gitignore": ".atdr_runtime/\n.venv\n.venvs/\n.python/\n.env\natdr.db*\nbackups/\n.tmp/\nfrontend/dist/\nfrontend/node_modules/\natdr/models/*.joblib\nevidence/\n**/.env.local\n",
    ".env.example": "DATABASE_URL=sqlite:///./atdr.db\nOPERATION_WORKER_ENABLED=true\n",
    "requirements.lock.txt": "alpha==1.0 \\\n    --hash=sha256:aa\n",
    "frontend/package.json": "{}\n",
    "frontend/package-lock.json": "{}\n",
    "frontend/src/main.tsx": "one\n",
    "migrations/versions/0001_first.py": "",
    "atdr/app/main.py": "version = 1\n",
    "atdr/models/readme.txt": "models\n",
    "scripts/system_common.ps1": "# answers start-request.json\n",
    "scripts/stop_system.ps1": "param([double]$HoldHours = 0, [string[]]$Only = @())\n",
    "scripts/autostart.ps1": "",
    "docs/guide.md": "guide\n",
}


def _git(repo: Path, *arguments: str) -> str:
    done = subprocess.run(["git", "-C", str(repo), *arguments], capture_output=True, text=True, check=True)
    return done.stdout.strip()


def _commit(repo: Path, message: str, files: dict[str, str | None]) -> str:
    for name, content in files.items():
        path = repo / name
        if content is None:
            path.unlink()
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8", newline="\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "--quiet", "-m", message)
    return _git(repo, "rev-parse", "HEAD")


def _database(path: Path, rows: list[str]) -> None:
    with closing(sqlite3.connect(path)) as connection:
        connection.execute("CREATE TABLE things (name TEXT)")
        connection.executemany("INSERT INTO things VALUES (?)", [(row,) for row in rows])
        connection.commit()


def _things(path: Path) -> list[str]:
    with closing(sqlite3.connect(path)) as connection:
        return [row[0] for row in connection.execute("SELECT name FROM things ORDER BY rowid")]


def _head_revision(root: Path) -> str:
    return sorted(path.stem for path in (root / "migrations" / "versions").glob("*.py"))[-1][:4] + "a1b2c3d4"


class Machine:
    """ATDR's parts and everything a release runs besides git."""

    def __init__(self) -> None:
        self.did: list[str] = []
        self.said: list[str] = []
        self.asked: list[str] = []
        self.pids: dict[int, tuple[Path, str]] = {}
        self.next_pid = 4000
        self.clock = 0.0
        # The folder the start and watcher tasks belong to, and the folders whose watcher answers a start request.
        self.tasks: Path | None = None
        self.watching: set[Path] = set()
        # Steps that fail everywhere, and steps that fail while a folder is at one commit.
        self.fail: set[str] = set()
        self.fail_at: dict[str, set[str]] = {}
        # Parts that stop a moment after they were started at a commit; with comes_back the watcher starts them again.
        self.dies_at: dict[str, set[str]] = {}
        self.comes_back = False
        self.silent: set[str] = set()
        # Parts the stop script cannot end.
        self.stubborn: set[str] = set()
        self.dying: list[tuple[Path, str]] = []
        self.github: list[tuple[int, Any]] = [GREEN]
        self.revision: dict[Path, str] = {}
        self.local: dict[str, Ran] = {}
        self.envs: list[dict[str, str]] = []
        self.tools = Tools(run=self.run, fetch=self.fetch, answers=self.answers, alive=self.alive, sleep=self.sleep,
                           now=self.now, say=self.said.append, npm="npm", windows=True)

    # -- the parts

    def head(self, root: Path) -> str:
        return _git(root, "rev-parse", "HEAD")

    def fails(self, step: str, root: Path | None) -> bool:
        return step in self.fail or (root is not None and (root / ".git").exists() and self.head(root) in self.fail_at.get(step, set()))

    def running(self, root: Path) -> list[str]:
        return [name for where, name in self.pids.values() if where == root]

    def _record(self, root: Path) -> None:
        runtime = root / ".atdr_runtime"
        runtime.mkdir(exist_ok=True)
        processes = [{"name": name, "pid": pid, "started_at": "2026-10-10T06:00:00.0000000Z"}
                     for pid, (where, name) in self.pids.items() if where == root]
        if processes:
            (runtime / "system-processes.json").write_text(json.dumps({"processes": processes}), encoding="utf-8")
        else:
            (runtime / "system-processes.json").unlink(missing_ok=True)

    def start(self, root: Path, names: list[str]) -> None:
        for name in names:
            self.next_pid += 1
            self.pids[self.next_pid] = (root, name)
            if (root / ".git").exists() and name in self.dies_at.get(self.head(root), set()):
                self.dying.append((root, name))
        self._record(root)

    def stop(self, root: Path, names: list[str] | None, *, by_the_script: bool = False) -> None:
        for pid, (where, name) in list(self.pids.items()):
            if where == root and (names is None or name in names) and not (by_the_script and name in self.stubborn):
                del self.pids[pid]
        self._record(root)

    def alive(self, pid: int, started_at: str) -> bool:
        return pid in self.pids

    def answers(self, url: str) -> bool:
        name = PART_AT[url]
        return name not in self.silent and any(part == name for _where, part in self.pids.values())

    def now(self) -> datetime:
        return datetime(2026, 10, 10, 6, 0, tzinfo=timezone.utc) + timedelta(seconds=self.clock)

    def sleep(self, seconds: float) -> None:
        self.clock += seconds
        assert self.clock < 86400, "a release that waits a whole day has no limit on its waiting"
        for root, name in self.dying:
            self.stop(root, [name])
            if self.comes_back:
                self.start_quietly(root, [name])
        self.dying = []
        for root in list(self.watching):
            asked = root / ".atdr_runtime" / release.START_REQUEST
            if not asked.is_file():
                continue
            request = json.loads(asked.read_text(encoding="utf-8"))
            asked.unlink()
            expected = release.expected_parts(root)
            missing = [name for name in expected if name not in self.running(root)]
            if self.fails("start", root):
                result = {"id": request["id"], "ok": False, "code": 1, "said": "ATDR startup failed: atdr-backend stopped during startup."}
            else:
                self.start(root, missing)
                self.did.append(f"watcher started {'everything' if len(missing) == len(expected) else ', '.join(missing)} in {root.name}")
                result = {"id": request["id"], "ok": True, "code": 0, "said": ""}
            (root / ".atdr_runtime" / release.START_RESULT).write_text(json.dumps(result), encoding="utf-8")

    def start_quietly(self, root: Path, names: list[str]) -> None:
        for name in names:
            self.next_pid += 1
            self.pids[self.next_pid] = (root, name)
        self._record(root)

    def fetch(self, url: str) -> tuple[int, Any]:
        self.asked.append(url)
        return self.github[min(len(self.asked) - 1, len(self.github) - 1)]

    # -- what a release runs

    def run(self, command: list[str], *, cwd: Path | None = None, env: dict[str, str] | None = None, timeout: float = 600) -> Ran:
        command = [str(part) for part in command]
        if command[0] == "git":
            return release.run_command(command, cwd=cwd, env=env, timeout=timeout)
        root = Path(cwd) if cwd is not None else None
        if command[0] == "powershell.exe":
            return self._powershell(command, root)
        if command[0] == "npm":
            if command[1] == "ci":
                self.did.append(f"dashboard packages in {root.parent.name}")
                return Ran(1, err="npm ERR! network") if self.fails("npm", root.parent) else Ran(0)
            self.envs.append(env or {})
            self.did.append(f"npm {command[2]}")
            return self.local.get(command[2], Ran(0, out="  9 passed (12.0s)" if command[2] == "test:e2e" else ""))
        module = command[command.index("-m") + 1]
        if env and "DATABASE_URL" in env:
            # A step of the check, which gets a database of its own; everything below is done to a live copy.
            self.envs.append(env)
            self.did.append(f"python {module}")
            return self.local.get(module, Ran(0, out="12 passed, 1 skipped in 3.20s" if module == "pytest" else ""))
        if module == "venv":
            environment = Path(command[-1])
            release.python_in(environment).parent.mkdir(parents=True)
            release.python_in(environment).write_text("python", encoding="utf-8")
            self.did.append(f"environment {environment.name} made")
            return Ran(0)
        if module == "pip":
            if "install" in command:
                self.did.append("packages installed")
                return Ran(1, err="ERROR: No matching distribution found for alpha==2.0") if self.fails("pip", None) else Ran(0)
            return Ran(0, out="No broken requirements found.")
        if module == "alembic":
            database = release.database_file(root)
            if command[-1] == "current":
                return Ran(0, out=f"{self.revision.get(database, '')} (head)\n", err="INFO  [alembic.runtime.migration] Context impl SQLiteImpl.")
            if command[-1] == "heads":
                return Ran(0, out=f"{_head_revision(root)} (head)\n")
            if self.fails("upgrade", root):
                return Ran(1, err="sqlalchemy.exc.OperationalError: duplicate column name: seen")
            with closing(sqlite3.connect(database)) as connection:
                connection.execute("INSERT INTO things VALUES (?)", (f"schema {_head_revision(root)}",))
                connection.commit()
            self.revision[database] = _head_revision(root)
            self.did.append(f"database brought to {_head_revision(root)[:4]}")
            return Ran(0)
        if module == "atdr.scripts.backup_now":
            if self.fails("backup", root):
                return Ran(1, out=json.dumps({"ok": False, "status": "not_enough_free_space", "words": "there is not enough free space for it"}))
            target = root / "backups" / f"before-{len(self.did)}.sqlite3"
            target.parent.mkdir(exist_ok=True)
            with closing(sqlite3.connect(release.database_file(root))) as source, closing(sqlite3.connect(target)) as copy:
                source.backup(copy)
            self.did.append("database backed up")
            return Ran(0, out=json.dumps({"ok": True, "backup_path": str(target)}))
        if module == "atdr.scripts.build_dashboard":
            if "--check" in command:
                return Ran(0, out=json.dumps({"built": True, "stale": self.fails("build", root), "uncommitted": False}))
            if self.fails("build", root):
                return Ran(0, out="the dashboard build FAILED; ATDR serves the last good build", err="src/main.tsx(3,1): error TS1005: ';' expected.")
            dist = root / "frontend" / "dist"
            dist.mkdir(parents=True, exist_ok=True)
            (dist / "index.html").write_text(self.head(root), encoding="utf-8")
            self.did.append(f"dashboard built in {root.name}")
            return Ran(0, out="dashboard built in 21.0 s")
        raise AssertionError(f"a module the release has no business running: {module}")

    def _powershell(self, command: list[str], root: Path | None) -> Ran:
        if "-File" in command:
            script = Path(command[command.index("-File") + 1])
            root = script.parent.parent
            if script.name == "stop_system.ps1":
                if self.fails("stop", None):
                    return Ran(1, err="ATDR shutdown failed safely: Access is denied")
                only = command[command.index("-Only") + 1].split(",") if "-Only" in command else None
                # The stop script knows the parts by their record: what is not on it, it cannot stop.
                on_record = list(release.processes(root))
                if not on_record:
                    self.did.append(f"nothing on record to stop in {root.name}")
                    return Ran(0, out="No ATDR launcher-managed processes are recorded. Nothing was stopped.")
                self.stop(root, [name for name in on_record if only is None or name in only], by_the_script=True)
                self.did.append(f"{'own parts' if only else 'everything'} stopped in {root.name}")
                return Ran(0)
            if script.name == "autostart.ps1":
                if (root / ".atdr_runtime" / release.LIVE_COPY).is_file() or self.fails("tasks", None):
                    return Ran(1, err="Access is denied")
                self.tasks = root
                self.did.append(f"tasks belong to {root.name}")
                return Ran(0)
            raise AssertionError(f"a script the release has no business running: {script}")
        text = command[-1]
        if "Restart-AtdrWatcher" in text:
            if self.tasks != root:
                return Ran(4)
            # A request that is already there was taken by the watcher that is now being ended: it is never answered.
            (root / ".atdr_runtime" / release.START_REQUEST).unlink(missing_ok=True)
            self.watching.add(root)
            self.did.append(f"watcher started afresh in {root.name}")
            return Ran(0)
        if "Start-ScheduledTask" in text:
            if self.tasks != root:
                return Ran(1, err="The system cannot find the file specified.")
            if "Stop-AtdrWatcherProcess" in text:
                self.watching.discard(root)
                self.did.append(f"watcher ended in {root.name}")
            self.did.append(f"sign-in start in {root.name}")
            if not self.fails("start", root):
                self.start(root, [name for name in release.expected_parts(root) if name not in self.running(root)])
            return Ran(0)
        if "Stop-AtdrWatcherProcess" in text:
            self.watching.discard(root)
            self.did.append(f"watcher ended in {root.name}")
            return Ran(0)
        if "Get-ScheduledTask" in text:
            return Ran(0 if self.tasks == root else 4)
        raise AssertionError(f"a command the release has no business running: {text}")


@pytest.fixture()
def machine() -> Machine:
    return Machine()


@pytest.fixture()
def dev(tmp_path: Path) -> Path:
    """A development folder: a repository with one commit on main, its own settings and a database."""

    root = tmp_path / "development"
    root.mkdir()
    subprocess.run(["git", "init", "--quiet", "--initial-branch=main", str(root)], check=True)
    for name, value in (("user.name", "Tester"), ("user.email", "tester@example.invalid"), ("core.autocrlf", "false"),
                        ("commit.gpgsign", "false")):
        _git(root, "config", name, value)
    _git(root, "remote", "add", "origin", "https://github.com/example/atdr.git")
    _commit(root, "the first version", BASE)
    (root / ".env").write_text('DATABASE_URL="sqlite:///./atdr.db"\nOPERATION_WORKER_ENABLED=true\n', encoding="utf-8")
    _database(root / "atdr.db", ["a log", "an alert"])
    return root


def _key(root: Path, commit: str) -> str:
    return release.environment_key(release.file_at(Tools(), root, commit, "requirements.lock.txt"), "py311")


def _live(machine: Machine, dev: Path, commit: str) -> Path:
    """A live copy that runs the commit, as `setup` leaves it."""

    live = dev.parent / "live"
    subprocess.run(["git", "clone", "--quiet", "-c", "core.autocrlf=false", str(dev), str(live)], check=True)
    _git(live, "checkout", "--quiet", "--detach", commit)
    (live / ".env").write_text((dev / ".env").read_text(encoding="utf-8"), encoding="utf-8")
    release.copy_database(dev / "atdr.db", live / "atdr.db")
    interpreter = live / release.INTERPRETERS / "py311" / release.INTERPRETER_FILE
    interpreter.parent.mkdir(parents=True)
    interpreter.write_text("python", encoding="utf-8")
    environment = live / release.ENVIRONMENTS / _key(live, commit)
    release.python_in(environment).parent.mkdir(parents=True)
    release.python_in(environment).write_text("python", encoding="utf-8")
    (environment / release.ENVIRONMENT_MARK).write_text("{}", encoding="utf-8")
    release.use_environment(live, environment)
    (live / "frontend" / "dist").mkdir()
    (live / "frontend" / "dist" / "index.html").write_text(commit, encoding="utf-8")
    facts = release.commit_facts(machine.tools, live, commit)
    release._write_json(live / ".atdr_runtime" / release.RECORD, {
        "version": 1, **facts, "released_at": "2026-10-10T05:00:00+00:00", "checked_by": "github", "check": "GitHub's 2 checks passed",
        "source": str(dev), "interpreter": interpreter.relative_to(live).as_posix(), "environment": environment.name, "previous": None,
        "history": [{"commit": commit, "short": facts["short"], "at": "2026-10-10T05:00:00+00:00", "outcome": "installed"}],
    })
    machine.tasks = live
    machine.watching.add(live)
    machine.revision[live / "atdr.db"] = _head_revision(live)
    machine.start(live, release.expected_parts(live))
    return live


def _pids(machine: Machine, root: Path, names: list[str]) -> dict[str, int]:
    return {name: pid for pid, (where, name) in machine.pids.items() if where == root and name in names}


# ---- A release that goes well ----


def test_a_checked_commit_becomes_the_version_that_runs(machine, dev):
    first = _git(dev, "rev-parse", "HEAD")
    live = _live(machine, dev, first)
    second = _commit(dev, "a better detection rule", {"atdr/app/main.py": "version = 2\n", "frontend/src/main.tsx": "two\n"})
    sign_in_page = _pids(machine, live, ["shell-backend", "shell-frontend"])
    before = _pids(machine, live, OWN)

    result = release.release(machine.tools, dev, live)

    assert result["ok"] and result["commit"] == second, result
    assert result["words"] == f"ATDR runs version {second[:7]} (a better detection rule). Its own parts were down for 2 seconds."
    assert result["down_seconds"] == 2, "from the stop until the watcher had started them again"
    assert machine.head(live) == second and (live / "atdr" / "app" / "main.py").read_text(encoding="utf-8") == "version = 2\n"
    # Only ATDR's own parts were stopped, the files changed while they were down, and the watcher started them.
    assert machine.did == ["own parts stopped in live", "dashboard built in live", "watcher started afresh in live",
                           "watcher started atdr-backend, atdr-frontend, atdr-worker in live"]
    assert _pids(machine, live, ["shell-backend", "shell-frontend"]) == sign_in_page, "the MFU sign-in page stayed up"
    assert sorted(machine.running(live)) == sorted(WITH_WORKER) and not set(before.values()) & set(machine.pids)
    assert (live / "frontend" / "dist" / "index.html").read_text(encoding="utf-8") == second
    assert _things(live / "atdr.db") == ["a log", "an alert"], "a release without a schema change does not touch the database"

    record = release.read_record(live)
    assert (record["commit"], record["subject"], record["checked_by"], record["check"]) == (
        second, "a better detection rule", "github", "GitHub's 2 checks passed")
    assert record["released_at"] == machine.now().isoformat() and record["previous"]["commit"] == first
    assert [(entry["commit"], entry["outcome"]) for entry in record["history"]] == [(first, "installed"), (second, "released")]
    assert not (live / ".atdr_runtime" / release.MARKER).exists(), "nothing is left on record as under way"
    assert not (live / ".atdr_runtime" / release.START_RESULT).exists() and not (live / ".atdr_runtime" / release.START_REQUEST).exists()
    assert machine.asked == [f"https://api.github.com/repos/example/atdr/commits/{second}/check-runs?per_page=100"]
    assert machine.clock >= release.HEALTH_CHECKS * release.HEALTH_EVERY_SECONDS, "it was watched before it counted as running"

    # The same commit again: nothing is stopped.
    machine.did.clear()
    again = release.release(machine.tools, dev, live)
    assert again["ok"] and again["nothing_to_do"] and machine.did == []
    assert again["words"] == f"Version {second[:7]} is the one that runs already."


def test_other_python_packages_are_installed_before_atdr_stops_and_the_environment_before_is_kept(machine, dev):
    first = _git(dev, "rev-parse", "HEAD")
    live = _live(machine, dev, first)
    old_environment = release.environment_in_use(live)
    second = _commit(dev, "newer packages", {"requirements.lock.txt": "alpha==2.0 \\\n    --hash=sha256:bb\n"})

    result = release.release(machine.tools, dev, live)

    assert result["ok"] and result["changes"].packages
    new_environment = release.environment_in_use(live)
    assert new_environment.name == _key(live, second) != old_environment.name
    assert machine.did.index("packages installed") < machine.did.index("own parts stopped in live"), "ATDR ran while they were installed"
    assert release.environment_ready(new_environment) and old_environment.is_dir(), "the one before is there to go back to"
    lock = live / ".atdr_runtime" / "release" / f"requirements.{new_environment.name}.txt"
    assert lock.read_text(encoding="utf-8") == "alpha==2.0 \\\n    --hash=sha256:bb\n"
    assert release.read_record(live)["environment"] == new_environment.name
    assert "  It needs other Python packages: they are installed into an environment of their own before ATDR stops." in machine.said

    # The release after it has no use for the oldest one any more.
    third = _commit(dev, "newer still", {"requirements.lock.txt": "alpha==3.0 \\\n    --hash=sha256:cc\n"})
    assert release.release(machine.tools, dev, live)["ok"]
    kept = sorted(path.name for path in (live / release.ENVIRONMENTS).iterdir())
    assert kept == sorted([_key(live, second), _key(live, third)])


def test_a_version_that_changes_the_database_is_migrated_behind_a_checked_backup(machine, dev):
    first = _git(dev, "rev-parse", "HEAD")
    live = _live(machine, dev, first)
    _commit(dev, "a new table", {"migrations/versions/0002_second.py": ""})

    result = release.release(machine.tools, dev, live)

    assert result["ok"] and result["changes"].schema
    assert machine.did == ["own parts stopped in live", "database backed up", "database brought to 0002", "dashboard built in live",
                           "watcher started afresh in live", "watcher started atdr-backend, atdr-frontend, atdr-worker in live"]
    assert _things(live / "atdr.db") == ["a log", "an alert", "schema 0002a1b2c3d4"]
    assert "  It changes the database: a checked backup is taken first." in machine.said


def test_a_database_that_cannot_be_backed_up_is_not_migrated(machine, dev):
    first = _git(dev, "rev-parse", "HEAD")
    live = _live(machine, dev, first)
    second = _commit(dev, "a new table", {"migrations/versions/0002_second.py": ""})
    machine.fail.add("backup")

    result = release.release(machine.tools, dev, live)

    assert not result["ok"] and result["rolled_back"] and not result["live_down"]
    assert result["why"] == ("The database was not changed: the backup that comes first did not succeed "
                             "(there is not enough free space for it).")
    assert "database brought to 0002" not in machine.did and _things(live / "atdr.db") == ["a log", "an alert"]
    assert machine.head(live) == first and sorted(machine.running(live)) == sorted(WITH_WORKER)
    assert result["words"] == f"Version {second[:7]} did not go live: {result['why']}. Version {first[:7]} was put back and is running."


# ---- A release that does not come up: everything goes back ----


def _everything_changes(dev: Path) -> str:
    return _commit(dev, "a broken version", {
        "atdr/app/main.py": "version = 2\n", "frontend/src/main.tsx": "two\n", "migrations/versions/0002_second.py": "",
        "requirements.lock.txt": "alpha==2.0 \\\n    --hash=sha256:bb\n", "frontend/package-lock.json": '{"changed": true}\n',
    })


@pytest.mark.parametrize("comes_back", [False, True])
def test_a_part_that_stops_after_the_start_puts_the_version_before_back(machine, dev, comes_back):
    first = _git(dev, "rev-parse", "HEAD")
    live = _live(machine, dev, first)
    old_environment = release.environment_in_use(live)
    second = _everything_changes(dev)
    machine.dies_at[second] = {"atdr-worker"}
    # The watcher brings a part back within half a minute. It still stopped: the same part, another process.
    machine.comes_back = comes_back

    result = release.release(machine.tools, dev, live)

    assert not result["ok"] and result["rolled_back"] and not result["live_down"]
    assert result["why"] == ("the background worker stopped and had to be started again" if comes_back else "the background worker is not running")
    assert machine.head(live) == first, "the files"
    assert (live / "atdr" / "app" / "main.py").read_text(encoding="utf-8") == "version = 1\n"
    assert release.environment_in_use(live) == old_environment, "the Python environment"
    assert _things(live / "atdr.db") == ["a log", "an alert"], "the database, from the backup taken before it was changed"
    kept = live / ".atdr_runtime" / "release" / "database-of-failed-release" / "atdr.db"
    assert _things(kept) == ["a log", "an alert", "schema 0002a1b2c3d4"], "what the failed version left is put aside, not deleted"
    assert (live / "frontend" / "dist" / "index.html").read_text(encoding="utf-8") == first, "the dashboard"
    assert sorted(machine.running(live)) == sorted(WITH_WORKER), "and ATDR runs again"
    assert machine.did.count("dashboard packages in live") == 2, "the build tools of the version before are installed again"

    record = release.read_record(live)
    assert record["commit"] == first and record["previous"] is None, "the record still names the version that runs"
    assert [(entry["commit"], entry["outcome"]) for entry in record["history"]] == [(first, "installed"), (second, "put_back")]
    assert record["history"][-1]["why"] == result["why"]
    assert not (live / ".atdr_runtime" / release.MARKER).exists()
    assert f"  Version {second[:7]} did not go live: {result['why']}" in machine.said and f"  Putting version {first[:7]} back." in machine.said


@pytest.mark.parametrize(("step", "why"), [
    ("start", "ATDR did not start: ATDR startup failed: atdr-backend stopped during startup."),
    ("build", "The dashboard could not be built from this version: src/main.tsx(3,1): error TS1005: ';' expected."),
    ("upgrade", "The database could not be brought to this version: sqlalchemy.exc.OperationalError: duplicate column name: seen"),
    ("npm", "The dashboard's build tools could not be installed: npm ERR! network"),
])
def test_a_step_that_fails_while_atdr_is_stopped_puts_the_version_before_back(machine, dev, step, why):
    first = _git(dev, "rev-parse", "HEAD")
    live = _live(machine, dev, first)
    second = _everything_changes(dev)
    machine.fail_at[step] = {second}

    result = release.release(machine.tools, dev, live)

    assert not result["ok"] and result["rolled_back"] and not result["live_down"] and result["why"] == why
    assert machine.head(live) == first and sorted(machine.running(live)) == sorted(WITH_WORKER)
    assert _things(live / "atdr.db") == ["a log", "an alert"]
    assert (live / "frontend" / "dist" / "index.html").read_text(encoding="utf-8") == first
    assert release.read_record(live)["commit"] == first and not (live / ".atdr_runtime" / release.MARKER).exists()
    if step in ("build", "upgrade", "npm"):
        assert not any(did.startswith("watcher started") and second in machine.said for did in machine.did)
        assert machine.did.count("watcher started afresh in live") == 1, "the version that failed was never started"


def test_a_part_that_will_not_stop_costs_nothing_what_did_stop_is_started_again(machine, dev):
    first = _git(dev, "rev-parse", "HEAD")
    live = _live(machine, dev, first)
    second = _commit(dev, "next", {"atdr/app/main.py": "version = 2\n"})
    worker = _pids(machine, live, ["atdr-worker"])
    machine.stubborn.add("atdr-worker")

    result = release.release(machine.tools, dev, live)

    # Nothing had been changed, so the worker that kept running is the version before, and stays.
    assert not result["ok"] and result["rolled_back"] and not result["live_down"]
    assert result["why"] == "Still running after the stop: atdr-worker."
    assert machine.head(live) == first and _pids(machine, live, ["atdr-worker"]) == worker
    assert sorted(machine.running(live)) == sorted(WITH_WORKER) and not (live / ".atdr_runtime" / release.MARKER).exists()
    assert machine.did[-1] == "watcher started atdr-backend, atdr-frontend in live"
    assert result["words"] == f"Version {second[:7]} did not go live: {result['why']}. Version {first[:7]} was put back and is running."

    # With the files already moved on it is another matter: the new version's worker, which will not stop, must not
    # go on running over the files of the version before. That is said loudly, and nothing starts the folder.
    machine.stubborn.clear()
    machine.dies_at[second] = {"atdr-backend"}
    stops = iter([False, True])
    real_stop = machine.stop

    def stop_then_stick(root, names, *, by_the_script=False):
        if by_the_script and next(stops, True):
            machine.stubborn.add("atdr-worker")
        real_stop(root, names, by_the_script=by_the_script)

    machine.stop = stop_then_stick
    stuck = release.release(machine.tools, dev, live)
    assert not stuck["ok"] and stuck["live_down"], stuck
    assert "could not be put back either (Still running after the stop: atdr-worker.)" in stuck["words"]
    assert machine.head(live) == second and (live / ".atdr_runtime" / release.MARKER).exists()


def test_parts_that_run_without_being_on_record_are_said_to_be_that_and_not_down(machine, dev):
    # On 11 October 2026 a release lost the record of running parts while four of them ran. It said that none was
    # running and, when it could not put the version before back, that "ATDR IS NOT RUNNING": the dashboard was up.
    first = _git(dev, "rev-parse", "HEAD")
    live = _live(machine, dev, first)
    second = _commit(dev, "next", {"atdr/app/main.py": "version = 2\n"})
    machine.stop(live, ["atdr-worker"])
    (live / ".atdr_runtime" / "system-processes.json").unlink()
    assert release.health(machine.tools, live) == [
        "the API server answers but is not on the record of running parts",
        "the dashboard answers but is not on the record of running parts",
        "the MFU sign-in service answers but is not on the record of running parts",
        "the MFU sign-in page answers but is not on the record of running parts",
        "the background worker is not running",
    ]

    # A release into that: nothing on record can be stopped, so the start finds its addresses taken, twice.
    machine.fail.add("start")
    result = release.release(machine.tools, dev, live)
    assert not result["ok"] and result["live_down"]
    assert result["words"].startswith(f"Version {second[:7]} did not go live (ATDR did not start: ")
    assert "ATDR'S API ANSWERS, BUT ATDR IS NOT IN ORDER: the API server answers but is not on the record of running parts; " in result["words"]
    assert "ATDR IS NOT RUNNING" not in result["words"] and result["words"].endswith("When the cause is fixed: scripts\\release.cmd recover")


def test_packages_that_cannot_be_installed_stop_the_release_before_anything_is_stopped(machine, dev):
    first = _git(dev, "rev-parse", "HEAD")
    live = _live(machine, dev, first)
    before = dict(machine.pids)
    _commit(dev, "newer packages", {"requirements.lock.txt": "alpha==2.0 \\\n    --hash=sha256:bb\n"})
    machine.fail.add("pip")

    with pytest.raises(ReleaseError, match="Could not install the Python packages: ERROR: No matching distribution found for alpha==2.0"):
        release.release(machine.tools, dev, live)

    assert machine.pids == before and "own parts stopped in live" not in machine.did, "ATDR was never touched"
    assert machine.head(live) == first and not (live / ".atdr_runtime" / release.MARKER).exists()
    # What was left of the environment is made again, not used.
    machine.fail.clear()
    assert release.release(machine.tools, dev, live)["ok"]
    assert machine.did.count("packages installed") == 2


def test_when_the_version_before_does_not_come_back_either_it_is_said_loudly_and_nothing_starts_the_folder(machine, dev):
    first = _git(dev, "rev-parse", "HEAD")
    live = _live(machine, dev, first)
    second = _commit(dev, "a broken version", {"atdr/app/main.py": "version = 2\n"})
    machine.fail.add("start")

    result = release.release(machine.tools, dev, live)

    assert not result["ok"] and result["live_down"]
    assert result["words"] == (
        f"Version {second[:7]} did not go live (ATDR did not start: ATDR startup failed: atdr-backend stopped during startup.), "
        f"and version {first[:7]} could not be put back either (ATDR did not start: ATDR startup failed: atdr-backend stopped "
        "during startup.). ATDR IS NOT RUNNING. When the cause is fixed: scripts\\release.cmd recover")
    marker = json.loads((live / ".atdr_runtime" / release.MARKER).read_text(encoding="utf-8"))
    assert (marker["from"], marker["to"], marker["source"]) == (first, second, str(dev))
    assert marker["driver"] == release.this_process(), "the process that made the release, so that others can tell whether it runs"
    with pytest.raises(ReleaseError, match="An earlier release did not finish"):
        release.release(machine.tools, dev, live)

    # While the process that makes a release still runs, the release is under way: nobody else puts anything back.
    release._write_json(live / ".atdr_runtime" / release.MARKER, {**marker, "driver": {"pid": 777, "started_at": "2026-10-11T05:33:00+00:00"}})
    machine.pids[777] = (dev.parent, "the release itself")
    done_before = list(machine.did)
    with pytest.raises(ReleaseError, match="A release into this copy is under way right now"):
        release.recover(machine.tools, live)
    with pytest.raises(ReleaseError, match="Another release into this copy is under way right now. Wait for it to end."):
        release.release(machine.tools, dev, live)
    assert machine.did == done_before, "nothing was touched"
    del machine.pids[777]

    # Once what was wrong is fixed, recover finishes the way back.
    machine.fail.clear()
    recovered = release.recover(machine.tools, live)
    assert recovered["ok"] and recovered["recovered"] and not recovered["live_down"]
    assert machine.head(live) == first and sorted(machine.running(live)) == sorted(WITH_WORKER)
    assert not (live / ".atdr_runtime" / release.MARKER).exists()
    assert release.recover(machine.tools, live)["words"] == "No release was cut off; there is nothing to put back."
    assert release.release(machine.tools, dev, live)["ok"], "and the next release goes through"


def test_a_release_cut_off_in_the_middle_is_put_back_by_recover(machine, dev):
    first = _git(dev, "rev-parse", "HEAD")
    live = _live(machine, dev, first)
    second = _commit(dev, "a version", {"atdr/app/main.py": "version = 2\n", "migrations/versions/0002_second.py": ""})
    # The machine went down after the files and the database had moved on and before anything was started.
    machine.stop(live, None)
    backup = machine.run(["python", "-m", "atdr.scripts.backup_now"], cwd=live)
    _git(live, "fetch", "--quiet", "origin")
    _git(live, "checkout", "--quiet", "--detach", second)
    machine.run(["python", "-m", "alembic", "upgrade", "head"], cwd=live)
    release._write_json(live / ".atdr_runtime" / release.MARKER, {
        "from": first, "to": second, "started_at": "2026-10-10T05:30:00+00:00", "source": str(dev),
        "environment_before": release.environment_in_use(live).name, "dashboard_packages": False,
        "database_backup": json.loads(backup.out)["backup_path"],
    })
    assert release.version_status(live)["unfinished"] and not release.version_status(live)["as_released"]

    result = release.recover(machine.tools, live)

    assert result["ok"] and result["recovered"] and result["why"] == "the release was cut off before it finished"
    assert machine.head(live) == first and _things(live / "atdr.db") == ["a log", "an alert"]
    assert sorted(machine.running(live)) == sorted(WITH_WORKER)
    status = release.version_status(live)
    assert status["as_released"] and not status["unfinished"]


def test_a_file_the_copy_carried_gives_way_once_a_version_holds_it_itself(machine, dev):
    first = _git(dev, "rev-parse", "HEAD")
    live = _live(machine, dev, first)
    # Not tracked when the copy was made, so it was carried over; a later version commits it.
    (live / "atdr" / "models" / "card.json").write_text("carried", encoding="utf-8")
    second = _commit(dev, "the card is part of the version now", {"atdr/models/card.json": "committed\n"})

    assert release.release(machine.tools, dev, live)["ok"]
    assert machine.head(live) == second and (live / "atdr" / "models" / "card.json").read_text(encoding="utf-8") == "committed\n"
    assert release.changed_by_hand(machine.tools, live) == []


# ---- What a release refuses ----


def test_a_live_copy_that_was_changed_by_hand_is_not_released_over(machine, dev):
    first = _git(dev, "rev-parse", "HEAD")
    live = _live(machine, dev, first)
    _commit(dev, "next", {"atdr/app/main.py": "version = 2\n"})
    (live / "atdr" / "app" / "main.py").write_text("a quick fix on the live machine\n", encoding="utf-8")

    with pytest.raises(ReleaseError, match=r"1 file in the live copy were changed by hand \(atdr/app/main.py\)"):
        release.release(machine.tools, dev, live)
    assert release.changed_by_hand(machine.tools, live) == ["atdr/app/main.py"]
    assert machine.did == [] and (live / "atdr" / "app" / "main.py").read_text(encoding="utf-8") == "a quick fix on the live machine\n"

    # Its files moved to another commit by hand are found too, by the record.
    _git(live, "checkout", "--quiet", "--", ".")
    older = _commit(dev, "third", {"atdr/app/main.py": "version = 3\n"})
    _git(live, "fetch", "--quiet", "origin")
    _git(live, "checkout", "--quiet", "--detach", older)
    assert release.version_status(live)["as_released"] is False
    with pytest.raises(ReleaseError, match=f"The live copy's files are at {older[:7]}, but its record says {first[:7]} is running"):
        release.release(machine.tools, dev, live)


def test_only_a_newer_commit_on_main_is_released(machine, dev):
    first = _git(dev, "rev-parse", "HEAD")
    second = _commit(dev, "second", {"atdr/app/main.py": "version = 2\n"})
    live = _live(machine, dev, second)

    with pytest.raises(ReleaseError, match=f"Commit {first[:7]} does not contain the version that runs \\({second[:7]}\\)"):
        release.release(machine.tools, dev, live, first)

    _git(dev, "checkout", "--quiet", "-b", "experiment")
    side = _commit(dev, "an experiment", {"atdr/app/main.py": "version = 99\n"})
    with pytest.raises(ReleaseError, match=f"Commit {side[:7]} is not on main. Only what is on main is released."):
        release.release(machine.tools, dev, live)
    with pytest.raises(ReleaseError, match="'no-such-thing' is not a commit"):
        release.release(machine.tools, dev, live, "no-such-thing")
    assert machine.did == [] and machine.asked == [], "none of them got as far as a check"


def test_a_release_needs_the_tasks_that_start_atdr_and_a_folder_that_is_a_live_copy(machine, dev):
    first = _git(dev, "rev-parse", "HEAD")
    live = _live(machine, dev, first)
    _commit(dev, "next", {"atdr/app/main.py": "version = 2\n"})
    machine.tasks = None
    with pytest.raises(ReleaseError, match="its tasks are not installed on this machine"):
        release.release(machine.tools, dev, live)
    assert machine.did == [] and sorted(machine.running(live)) == sorted(WITH_WORKER)

    with pytest.raises(ReleaseError, match="is not a live copy yet. Make it first: scripts\\\\release.cmd setup"):
        release.release(machine.tools, dev, dev.parent / "nowhere")


def test_a_commit_that_is_not_checked_is_not_released(machine, dev):
    first = _git(dev, "rev-parse", "HEAD")
    live = _live(machine, dev, first)
    second = _commit(dev, "red on GitHub", {"atdr/app/main.py": "version = 2\n"})
    machine.github = [RED]

    result = release.release(machine.tools, dev, live)

    assert not result["ok"] and result["refused"] and result["words"] == "GitHub's checks failed for this commit: backend."
    assert machine.did == [] and machine.head(live) == first
    assert release.checked_before(dev, second) is None, "a check that failed is not kept as one that passed"


# ---- A version from before releases could ask the watcher ----


def test_a_version_whose_scripts_know_nothing_of_releases_is_stopped_whole_and_started_by_the_sign_in_start(machine, dev):
    old = _commit(dev, "before releases", {"scripts/system_common.ps1": "# the launcher's functions\n",
                                            "scripts/stop_system.ps1": "param([double]$HoldHours = 0)\n"})
    live = _live(machine, dev, old)
    machine.watching.clear()
    new = _commit(dev, "releases", {"scripts/system_common.ps1": BASE["scripts/system_common.ps1"],
                                    "scripts/stop_system.ps1": BASE["scripts/stop_system.ps1"]})

    assert release.release(machine.tools, dev, live)["ok"]
    # Its stop script cannot leave the sign-in page up, so everything stops; the new version's watcher starts everything.
    assert machine.did == ["everything stopped in live", "dashboard built in live", "watcher started afresh in live",
                           "watcher started everything in live"]

    # Going back to it: that version's own way of starting, the task that starts ATDR at sign-in.
    machine.did.clear()
    result = release.go_back(machine.tools, dev, live)
    assert result["ok"] and machine.head(live) == old
    # The watcher that is running holds the newer version's scripts: it is ended, and that version's own is started.
    assert machine.did == ["own parts stopped in live", "dashboard built in live", "everything stopped in live",
                           "watcher ended in live", "sign-in start in live"]
    assert sorted(machine.running(live)) == sorted(WITH_WORKER)
    record = release.read_record(live)
    assert record["previous"]["commit"] == new and record["history"][-1]["outcome"] == "went_back"


def test_going_back_is_refused_across_a_change_of_the_database(machine, dev):
    first = _git(dev, "rev-parse", "HEAD")
    live = _live(machine, dev, first)
    with pytest.raises(ReleaseError, match="There is no version before this one on record."):
        release.go_back(machine.tools, dev, live)
    second = _commit(dev, "a new table", {"migrations/versions/0002_second.py": ""})
    assert release.release(machine.tools, dev, live)["ok"]
    machine.did.clear()

    with pytest.raises(ReleaseError, match=f"Version {second[:7]} changed the database, and what was stored since would not fit version {first[:7]}"):
        release.go_back(machine.tools, dev, live)
    assert machine.did == [] and machine.head(live) == second


# ---- The check ----


def test_github_decides_for_a_commit_it_has_checked(machine, dev):
    commit = _git(dev, "rev-parse", "HEAD")
    assert release.github_repository(machine.tools, dev) == "example/atdr"

    machine.github = [RUNNING, RUNNING, GREEN]
    checked = release.check_commit(machine.tools, dev, commit)
    assert (checked["ok"], checked["by"], checked["words"]) == (True, "github", "GitHub's 2 checks passed")
    assert len(machine.asked) == 3 and machine.clock == 2 * release.GITHUB_ASK_EVERY_SECONDS
    assert "  GitHub is checking this commit (1 still running); waiting for it." in machine.said
    assert machine.did == [], "no test ran here"

    # A commit that passed is not asked about again.
    again = release.check_commit(machine.tools, dev, commit)
    assert again["earlier"] and again["words"] == "GitHub's 2 checks passed" and len(machine.asked) == 3


def test_github_still_checking_after_the_wait_is_not_a_pass(machine, dev):
    commit = _git(dev, "rev-parse", "HEAD")
    machine.github = [RUNNING]
    checked = release.check_commit(machine.tools, dev, commit, wait_minutes=3)
    assert not checked["ok"] and checked["words"] == (
        "GitHub is still checking this commit (backend). Try again when it has finished, or add --local to run the tests here instead.")
    assert machine.clock == 180 and machine.did == [] and release.checked_before(dev, commit) is None


@pytest.mark.parametrize(("answer", "said"), [
    ((422, None), "  This commit is not on GitHub, so the tests run here."),
    ((200, {"check_runs": []}), "  GitHub ran no checks for exactly this commit, so the tests run here."),
    ((0, None), "  GitHub could not be asked, so the tests run here."),
    ((403, None), "  GitHub could not be asked, so the tests run here."),
])
def test_a_commit_github_has_not_checked_is_tested_here(machine, dev, answer, said):
    commit = _git(dev, "rev-parse", "HEAD")
    machine.github = [answer]

    checked = release.check_commit(machine.tools, dev, commit)

    assert checked["ok"] and checked["by"] == "local_tests" and said in machine.said
    assert machine.did == ["python compileall", "python ruff", "python pytest", "python alembic", "python alembic",
                           "npm lint", "npm build", "npm test:e2e"]
    assert checked["words"] == "the tests passed on this machine (backend tests: 12 passed, 1 skipped; browser tests: 9 passed)"
    # Their own empty database, inside the folder's scratch space: never one that is in use.
    database = {env["DATABASE_URL"] for env in machine.envs}
    assert len(database) == 1 and database.pop().startswith(f"sqlite:///{(dev / '.tmp' / 'release-check').as_posix()}/")
    assert not (dev / ".tmp" / "release-check" / commit[:7]).exists(), "the scratch space is cleared after a pass"
    assert release.checked_before(dev, commit)["by"] == "local_tests"
    log = (dev / ".atdr_runtime" / "logs" / "release-check.log").read_text(encoding="utf-8")
    assert "==== backend tests (exit code 0) ====" in log and "12 passed, 1 skipped" in log


def test_the_tests_here_can_be_asked_for_and_a_failure_says_which_step_and_how_it_ended(machine, dev):
    commit = _git(dev, "rev-parse", "HEAD")
    machine.local["pytest"] = Ran(1, out="FAILED atdr/tests/test_x.py::test_y - assert 1 == 2\n1 failed, 11 passed in 4.00s")

    checked = release.check_commit(machine.tools, dev, commit, local=True)

    assert machine.asked == [], "--local does not ask GitHub"
    assert not checked["ok"] and checked["words"].startswith("backend tests failed (11 passed, 1 failed). Everything it said is in ")
    assert checked["words"].endswith("    FAILED atdr/tests/test_x.py::test_y - assert 1 == 2\n    1 failed, 11 passed in 4.00s")
    assert machine.did == ["python compileall", "python ruff", "python pytest"], "nothing ran after the step that failed"
    assert release.checked_before(dev, commit) is None

    machine.local.clear()
    machine.did.clear()
    assert release.check_commit(machine.tools, dev, commit, local=True)["ok"]
    assert release.check_commit(machine.tools, dev, commit, local=True)["earlier"] and len(machine.did) == 8


def test_the_tests_here_only_count_for_a_folder_that_holds_exactly_the_commit(machine, dev):
    first = _git(dev, "rev-parse", "HEAD")
    second = _commit(dev, "second", {"atdr/app/main.py": "version = 2\n"})

    older = release.local_tests(machine.tools, dev, first)
    assert not older["ok"] and older["words"] == (
        f"The tests run on the files in this folder, and the folder is at {second[:7]}, not at {first[:7]}. "
        "Release HEAD, or check that commit out first.")

    (dev / "atdr" / "app" / "main.py").write_text("version = 2 and something not committed\n", encoding="utf-8")
    (dev / "atdr" / "app" / "forgotten.py").write_text("a new module nobody added\n", encoding="utf-8")
    (dev / "docs" / "my notes.md").write_text("notes kept beside the documents\n", encoding="utf-8")
    loose = release.local_tests(machine.tools, dev, second)
    assert not loose["ok"] and loose["words"] == (
        f"The tests would not be testing commit {second[:7]}: 2 files in this folder are not committed "
        "(atdr/app/main.py, atdr/app/forgotten.py). Commit them or put them aside, then try again.")
    assert machine.did == [], "no test ran on files that are not the commit"

    # Notes beside the documents are not part of the system; a file anywhere else is.
    _git(dev, "checkout", "--quiet", "--", "atdr/app/main.py")
    (dev / "atdr" / "app" / "forgotten.py").unlink()
    assert release.uncommitted(machine.tools, dev) == []
    assert release.local_tests(machine.tools, dev, second)["ok"]


def test_what_is_not_committed_is_found_whatever_git_calls_it(machine, dev):
    (dev / "atdr" / "app" / "main.py").rename(dev / "atdr" / "app" / "moved to here.py")
    _git(dev, "add", "-A")
    (dev / "frontend" / "src" / "main.tsx").write_text("changed\n", encoding="utf-8")
    (dev / "scripts" / "autostart.ps1").unlink()
    (dev / "new folder").mkdir()
    (dev / "new folder" / "file.txt").write_text("new\n", encoding="utf-8")
    assert sorted(release.uncommitted(machine.tools, dev)) == [
        "atdr/app/moved to here.py", "frontend/src/main.tsx", "new folder/file.txt", "scripts/autostart.ps1"]


def test_what_differs_between_two_versions(machine, dev):
    first = _git(dev, "rev-parse", "HEAD")
    assert release.changes_between(machine.tools, dev, first, first) == release.Changes()
    code = _commit(dev, "code", {"atdr/app/main.py": "version = 2\n"})
    assert release.changes_between(machine.tools, dev, first, code) == release.Changes(files=1)
    assert release.Changes(files=1).words() == ["1 file differs."]
    everything = _commit(dev, "everything", {
        "requirements.lock.txt": "beta==1\n", "frontend/package.json": '{"a": 1}\n', "frontend/src/main.tsx": "two\n",
        "migrations/versions/0002_second.py": "", ".env.example": "DATABASE_URL=x\nOPERATION_WORKER_ENABLED=true\nNEW_SETTING=1\n# NOT_ONE=2\nANOTHER=3\n",
    })
    found = release.changes_between(machine.tools, dev, first, everything)
    assert found == release.Changes(files=6, packages=True, dashboard_packages=True, schema=True, dashboard=True, settings=("ANOTHER", "NEW_SETTING"))
    assert found.words()[-1] == ("It knows settings the version before did not: ANOTHER, NEW_SETTING. They keep their defaults "
                                 "until they are put in the live copy's .env.")
    assert release.changes_between(machine.tools, dev, code, everything).files == 5


# ---- The pieces ----


def test_an_environment_is_named_by_its_packages_and_the_pointer_moves_between_them(tmp_path):
    assert release.environment_key("a==1\nb==2\n", "py311") == release.environment_key("a==1\r\nb==2\r\n", "py311")
    assert release.environment_key("a==1\n", "py311") != release.environment_key("a==2\n", "py311")
    assert release.environment_key("a==1\n", "py311") != release.environment_key("a==1\n", "py312")

    live = tmp_path / "live"
    first, second = live / release.ENVIRONMENTS / "one", live / release.ENVIRONMENTS / "two"
    for environment in (first, second):
        release.python_in(environment).parent.mkdir(parents=True)
        release.python_in(environment).write_text(environment.name, encoding="utf-8")
    assert release.environment_in_use(live) is None
    release.use_environment(live, first)
    assert release.environment_in_use(live) == first.resolve()
    assert release.python_in(live / release.ENVIRONMENT_LINK).read_text(encoding="utf-8") == "one"
    release.use_environment(live, second)
    assert release.environment_in_use(live) == second.resolve()
    assert release.python_in(live / release.ENVIRONMENT_LINK).read_text(encoding="utf-8") == "two"
    assert release.python_in(first).read_text(encoding="utf-8") == "one", "moving the pointer away deletes nothing"
    assert release.prune_environments(live, {"two"}) == ["one"] and not first.exists() and second.is_dir()

    # A real folder named .venv is somebody's environment, not a pointer to replace.
    own = tmp_path / "development"
    (own / ".venv").mkdir(parents=True)
    with pytest.raises(ReleaseError, match="is a folder of its own, not a pointer into .venvs"):
        release.use_environment(own, first)


def test_an_environment_that_was_never_finished_is_made_again(machine, tmp_path):
    live = tmp_path / "live"
    interpreter = live / release.INTERPRETERS / "py311" / release.INTERPRETER_FILE
    interpreter.parent.mkdir(parents=True)
    interpreter.write_text("python", encoding="utf-8")
    assert release.interpreter_name(interpreter) == "py311"
    unfinished = live / release.ENVIRONMENTS / release.environment_key("a==1\n", "py311")
    (unfinished / "half").mkdir(parents=True)

    made = release.make_environment(machine.tools, live, interpreter=interpreter, lock_text="a==1\r\n")
    assert made == unfinished and not (made / "half").exists() and release.environment_ready(made)
    assert machine.did == [f"environment {made.name} made", "packages installed"]
    assert json.loads((made / release.ENVIRONMENT_MARK).read_text(encoding="utf-8"))["interpreter"] == "py311"
    # Ready means nothing is run again.
    assert release.make_environment(machine.tools, live, interpreter=interpreter, lock_text="a==1\n") == made
    assert len(machine.did) == 2


def test_a_database_copy_counts_only_when_it_holds_the_same_rows(tmp_path, monkeypatch):
    source, target = tmp_path / "atdr.db", tmp_path / "copy" / "atdr.db"
    _database(source, ["one", "two", "three"])
    target.parent.mkdir()
    Path(f"{target}-wal").write_text("left by a database that was here before", encoding="utf-8")
    assert release.copy_database(source, target) == {"things": 3}
    assert _things(target) == ["one", "two", "three"] and not Path(f"{target}-wal").exists()

    # Putting a backup in a database's place keeps what was there.
    with closing(sqlite3.connect(target)) as connection:
        connection.execute("INSERT INTO things VALUES ('written by a version that failed')")
        connection.commit()
    release.restore_database(source, target, tmp_path / "aside")
    assert _things(target) == ["one", "two", "three"]
    assert _things(tmp_path / "aside" / "atdr.db") == ["one", "two", "three", "written by a version that failed"]
    with pytest.raises(ReleaseError, match="The backup taken before the release is not there any more"):
        release.restore_database(tmp_path / "gone.sqlite3", target, tmp_path / "aside")
    assert _things(target) == ["one", "two", "three"], "a backup that is missing costs the database nothing"

    counts = iter([{"things": 3}, {"things": 2}])
    monkeypatch.setattr(release, "_rows", lambda connection: next(counts))
    with pytest.raises(ReleaseError, match="The copy of atdr.db is not the same as the original; it was removed."):
        release.copy_database(source, tmp_path / "short.db")
    assert not (tmp_path / "short.db").exists()


def test_settings_are_changed_by_name_and_every_other_line_is_left_alone(tmp_path):
    path = tmp_path / ".env"
    path.write_bytes(b'# ATDR\r\nJWT_SECRET_KEY="keep-this"\r\nATDR_BACKUP_DIRECTORY="D:/ATDR-backups"\r\n'
                     b"ATDR_NOTIFY_WINDOWS=false\r\n# ATDR_NOTIFY_EMAIL_TO=commented@example.invalid\r\nATDR_BACKUP_SCHEDULE_HOURS=24\r\n")
    changed = release.set_env_values(path, release.OUTWARD_SETTINGS)
    assert changed == ["ATDR_BACKUP_DIRECTORY", "ATDR_BACKUP_SCHEDULE_HOURS", "ATDR_NOTIFY_EMAIL_TO", "ATDR_NOTIFY_CHAT_WEBHOOK_URL"]
    assert path.read_bytes() == (
        b'# ATDR\r\nJWT_SECRET_KEY="keep-this"\r\nATDR_BACKUP_DIRECTORY=""\r\nATDR_NOTIFY_WINDOWS=false\r\n'
        b'# ATDR_NOTIFY_EMAIL_TO=commented@example.invalid\r\nATDR_BACKUP_SCHEDULE_HOURS="0"\r\n\r\n'
        b"# ATDR runs from its live copy; this folder does not write or speak outside itself (scripts\\release.cmd).\r\n"
        b'ATDR_NOTIFY_EMAIL_TO=""\r\nATDR_NOTIFY_CHAT_WEBHOOK_URL=""\r\n')
    assert release.set_env_values(path, release.OUTWARD_SETTINGS) == [], "a second time changes nothing"
    values = release.env_values(tmp_path)
    assert values["JWT_SECRET_KEY"] == "keep-this" and values["ATDR_BACKUP_SCHEDULE_HOURS"] == "0"
    assert "ATDR_NOTIFY_EMAIL_TO" in values and values["ATDR_NOTIFY_EMAIL_TO"] == ""
    assert release.database_file(tmp_path) == tmp_path / "atdr.db"
    (tmp_path / ".env").write_text("DATABASE_URL=postgresql+psycopg2://atdr@db/atdr\n", encoding="utf-8")
    assert release.database_file(tmp_path) is None


def test_health_names_what_is_wrong_in_words(machine, dev):
    live = _live(machine, dev, _git(dev, "rev-parse", "HEAD"))
    started = release.processes(live)
    assert sorted(started) == sorted(WITH_WORKER) and release.health(machine.tools, live, since=started) == []
    assert sorted(release.alive_parts(machine.tools, live)) == sorted(WITH_WORKER)
    machine.silent.add("atdr-backend")
    machine.stop(live, ["atdr-worker"])
    machine.start_quietly(live, ["atdr-worker"])
    machine.stop(live, ["shell-frontend"])
    assert release.health(machine.tools, live, since=started) == [
        "the API server does not answer at http://127.0.0.1:8000/health/ready", "the MFU sign-in page is not running",
        "the background worker stopped and had to be started again"]
    # A list of one part is written by PowerShell as the one.
    (live / ".atdr_runtime" / "system-processes.json").write_text(
        '\ufeff{"processes": {"name": "atdr-backend", "pid": 7, "started_at": "x"}}', encoding="utf-8")
    assert list(release.processes(live)) == ["atdr-backend"]


def test_the_version_the_system_panel_shows(machine, dev):
    commit = _git(dev, "rev-parse", "HEAD")
    assert release.version_status(dev) is None, "a folder ATDR is developed in has no released version"
    live = _live(machine, dev, commit)
    status = release.version_status(live)
    assert status == {
        "commit": commit[:7], "subject": "the first version", "committed_at": status["committed_at"],
        "released_at": datetime(2026, 10, 10, 5, 0, tzinfo=timezone.utc), "checked_by": "github", "check": "GitHub's 2 checks passed",
        "previous": None, "as_released": True, "unfinished": False,
    }
    assert status["committed_at"].tzinfo is not None
    assert release.checked_out(dev) is None, "a folder that follows a branch is not at a released commit"
    (live / ".atdr_runtime" / release.RECORD).write_text("{ not json", encoding="utf-8")
    assert release.version_status(live) is None


def test_files_that_are_not_the_released_version_are_found(machine, dev):
    first = _git(dev, "rev-parse", "HEAD")
    assert release.files_changed(dev) is None, "a folder ATDR is developed in is changed all day"
    live = _live(machine, dev, first)
    assert release.files_changed(live) is None

    (live / "atdr" / "app" / "main.py").write_text("a quick fix on the live machine\n", encoding="utf-8")
    (live / "scripts" / "autostart.ps1").unlink()
    (live / "atdr" / "models" / "detector.joblib").write_bytes(b"a model is not part of a version")
    (live / "notes.txt").write_text("neither is a file nobody committed\n", encoding="utf-8")
    assert release.files_changed(live) == {"version": first[:7], "moved": False, "files": ["atdr/app/main.py", "scripts/autostart.ps1"]}
    # While a release is under way the files are between two versions on purpose.
    release._write_json(live / ".atdr_runtime" / release.MARKER, {"from": first})
    assert release.files_changed(live) is None
    (live / ".atdr_runtime" / release.MARKER).unlink()

    _git(live, "checkout", "--quiet", "--", ".")
    assert release.files_changed(live) is None
    second = _commit(dev, "second", {"atdr/app/main.py": "version = 2\n"})
    _git(live, "fetch", "--quiet", "origin")
    _git(live, "checkout", "--quiet", "--detach", second)
    assert release.files_changed(live) == {"version": first[:7], "moved": True, "files": []}
    # Where git cannot be run, an edit cannot be seen; a move still can, from the folder's own files.
    without_git = Tools(run=lambda *_args, **_kwargs: Ran(127, err="FileNotFoundError"))
    assert release.files_changed(live, without_git) == {"version": first[:7], "moved": True, "files": []}


def test_a_command_is_waited_for_alone_and_what_it_said_is_read_from_files(tmp_path):
    said = release.run_command([sys.executable, "-c", "import sys; print('out'); print('err', file=sys.stderr); sys.exit(3)"])
    assert (said.code, said.out.strip(), said.err.strip(), said.ok) == (3, "out", "err", False)
    assert said.last() == "err" and Ran(0, out="a\n\nb\n").last(2) == "a\nb"
    assert release.run_command(["a-program-that-does-not-exist-anywhere"]).code == 127

    slow = release.run_command([sys.executable, "-c", "import time; time.sleep(30)"], timeout=1)
    assert slow.code == 124 and "stopped after 1 seconds" in slow.err

    # A process the command leaves running does not keep the command's caller waiting, as a pipe would.
    child = "import subprocess, sys; subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(20)']); print('started')"
    began = time.monotonic()
    left = release.run_command([sys.executable, "-c", child], cwd=tmp_path)
    assert left.ok and left.out.strip() == "started" and time.monotonic() - began < 15


def test_a_live_copys_commands_take_nothing_from_the_window_the_release_runs_in(monkeypatch):
    # A release is often run from a window set up for work on the development folder: a test database named in
    # DATABASE_URL, that folder on PYTHONPATH. Inherited, the live copy's migration would go to the test database
    # and its Python would run the development folder's code.
    for name in ("DATABASE_URL", "PYTHONPATH", "ATDR_BACKUP_DIRECTORY", "VIRTUAL_ENV"):
        monkeypatch.setenv(name, "of-the-window")
    monkeypatch.setenv("ATDR_SOMETHING_ELSE", "kept")
    show = ("import json, os; print(json.dumps({name: os.environ.get(name) for name in "
            "('DATABASE_URL', 'PYTHONPATH', 'ATDR_BACKUP_DIRECTORY', 'VIRTUAL_ENV', 'ATDR_SOMETHING_ELSE', 'GIT_TERMINAL_PROMPT')}))")
    seen = json.loads(release.run_command([sys.executable, "-c", show]).out)
    assert seen == {"DATABASE_URL": None, "PYTHONPATH": None, "ATDR_BACKUP_DIRECTORY": None, "VIRTUAL_ENV": None,
                    "ATDR_SOMETHING_ELSE": "kept", "GIT_TERMINAL_PROMPT": "0"}
    # What a step is given on purpose still reaches it: the check's tests get a database of their own.
    given = json.loads(release.run_command([sys.executable, "-c", show], env={"DATABASE_URL": "sqlite:///given.db"}).out)
    assert given["DATABASE_URL"] == "sqlite:///given.db" and given["PYTHONPATH"] is None
    assert {"DATABASE_URL", "PYTHONPATH", "PYTHONHOME", "VIRTUAL_ENV", "ATDR_BACKUP_DIRECTORY"} <= release.NOT_INHERITED


def test_progress_is_said_with_the_time_and_a_length_of_time_in_words(capsys):
    release._say("  Stopping ATDR's own parts.")
    said = capsys.readouterr().out
    assert said.rstrip("\r\n").endswith("   Stopping ATDR's own parts.") and said.count("\n") == 1
    assert said[2] == said[5] == ":" and said[:2].isdigit() and len(said.split()[0]) == 8, "it begins with the time, as 11:16:40"
    assert [release._lasted(seconds) for seconds in (0, 0.4, 1, 31.4, 59.6, 60, 104, 120, 3600)] == [
        "0 seconds", "0 seconds", "1 second", "31 seconds", "1 minute", "1 minute", "1 minute 44 seconds", "2 minutes", "60 minutes"]


def test_a_running_process_is_told_from_another_one_with_its_number():
    mine = os.getpid()
    if sys.platform != "win32":
        assert release.process_alive(mine, "2026-01-01T00:00:00Z") and not release.process_alive(2147483000, "x")
        return
    import ctypes
    from ctypes import wintypes

    created, other = wintypes.FILETIME(), (wintypes.FILETIME(), wintypes.FILETIME(), wintypes.FILETIME())
    kernel = ctypes.windll.kernel32
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
    assert kernel.GetProcessTimes(kernel.GetCurrentProcess(), ctypes.byref(created), *(ctypes.byref(item) for item in other))
    began = datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=((created.dwHighDateTime << 32) | created.dwLowDateTime) // 10)
    # As PowerShell writes a start time: seven decimals and Z.
    written = began.strftime("%Y-%m-%dT%H:%M:%S.%f") + "0Z"
    assert release.process_alive(mine, written)
    assert not release.process_alive(mine, (began - timedelta(minutes=5)).isoformat()), "the number was given to another process since"
    assert not release.process_alive(mine, "") and not release.process_alive(2147483000, written)
    # A release writes itself down in the same way, and is found running by it.
    me = release.this_process()
    assert me["pid"] == mine and release.process_alive(me["pid"], me["started_at"])
    assert release.under_way(Tools(), {"driver": me}) and not release.under_way(Tools(), {"driver": {"pid": 2147483000, "started_at": written}})
    assert not release.under_way(Tools(), {}) and not release.under_way(Tools(), {"driver": None})


# ---- Making the live copy ----


def _ready_for_setup(machine: Machine, dev: Path, tmp_path: Path) -> Path:
    """The development folder as ATDR runs from it today: its own Python, a model git does not track, backups elsewhere."""

    from atdr.app.services.persistence_service import database_label

    home = tmp_path / "pythons" / "py311"
    (home / release.INTERPRETER_FILE).parent.mkdir(parents=True)
    (home / release.INTERPRETER_FILE).write_text("python", encoding="utf-8")
    (home / "Lib").mkdir()
    (dev / ".venv").mkdir()
    named = home if release.INTERPRETER_FILE == "python.exe" else home / "bin"
    (dev / ".venv" / "pyvenv.cfg").write_text(f"home = {named}\nversion = 3.11.15\n", encoding="utf-8")
    (dev / "atdr" / "models" / "detector.joblib").write_bytes(b"a trained model")
    (dev / "evidence").mkdir()
    (dev / "frontend" / ".env.local").write_text("VITE_API=x\n", encoding="utf-8")
    (dev / ".atdr_runtime").mkdir(exist_ok=True)
    (dev / ".atdr_runtime" / "team-config.json").write_text('{"template_root": "C:/shell"}', encoding="utf-8")
    (dev / ".atdr_runtime" / "packages").mkdir()
    (dev / ".atdr_runtime" / "packages" / "shell.zip").write_bytes(b"zip")
    drive = tmp_path / "backups-drive"
    drive.mkdir()
    label = database_label(f"sqlite:///{(dev / 'atdr.db').resolve().as_posix()}")
    (drive / "atdr-sqlite-1.sqlite3.manifest.json").write_text(json.dumps({"artifact_name": "atdr-sqlite-1.sqlite3", "source": label}), encoding="utf-8")
    (drive / "atdr-sqlite-2.sqlite3.manifest.json").write_text(json.dumps({"artifact_name": "atdr-sqlite-2.sqlite3", "source": "another:db"}), encoding="utf-8")
    (drive / "offsite-copy.json").write_text(json.dumps({label: {"copied_at": "2026-10-09T00:00:00+00:00"}}), encoding="utf-8")
    (dev / ".env").write_text(
        f'DATABASE_URL="sqlite:///./atdr.db"\nOPERATION_WORKER_ENABLED=true\nATDR_BACKUP_DIRECTORY="{drive.as_posix()}"\n'
        'ATDR_BACKUP_SCHEDULE_HOURS=24\nATDR_NOTIFY_EMAIL_TO="team@example.invalid"\nJWT_SECRET_KEY="a-secret"\n', encoding="utf-8")
    machine.tasks = dev
    machine.watching.add(dev)
    machine.start(dev, release.expected_parts(dev))
    return drive


def _sources(drive: Path) -> list[str]:
    return [json.loads(path.read_text(encoding="utf-8"))["source"] for path in sorted(drive.glob("*.manifest.json"))]


def test_setup_makes_the_live_copy_and_moves_atdr_to_it(machine, dev, tmp_path):
    from atdr.app.services.persistence_service import database_label

    commit = _git(dev, "rev-parse", "HEAD")
    drive = _ready_for_setup(machine, dev, tmp_path)
    settings_before = (dev / ".env").read_text(encoding="utf-8")
    live = tmp_path / "ATDR-live"

    result = release.setup(machine.tools, dev, live)

    assert result["ok"] and result["words"] == f"ATDR runs from {live}, version {commit[:7]} (the first version)."
    assert result["rows"] == 2 and result["quieted"] == [
        "ATDR_BACKUP_DIRECTORY", "ATDR_BACKUP_SCHEDULE_HOURS", "ATDR_NOTIFY_EMAIL_TO", "ATDR_NOTIFY_CHAT_WEBHOOK_URL", "ATDR_NOTIFY_WINDOWS"]
    # The copy: the commit's files and nothing that was not committed, with what git does not track and ATDR reads.
    assert machine.head(live) == commit and release.changed_by_hand(machine.tools, live) == []
    assert _git(live, "config", "core.autocrlf") == "false" and _git(live, "remote", "get-url", "origin") == str(dev)
    assert (live / ".env").read_text(encoding="utf-8") == settings_before
    assert (live / "atdr" / "models" / "detector.joblib").read_bytes() == b"a trained model"
    assert (live / "frontend" / ".env.local").is_file() and (live / ".atdr_runtime" / "packages" / "shell.zip").is_file()
    assert json.loads((live / ".atdr_runtime" / "team-config.json").read_text(encoding="utf-8"))["template_root"] == "C:/shell"
    assert _things(live / "atdr.db") == ["a log", "an alert"] and _things(dev / "atdr.db") == ["a log", "an alert"]
    # Its own Python: a copy of the interpreter, and an environment the pointer names.
    assert (live / release.INTERPRETERS / "py311" / release.INTERPRETER_FILE).is_file() and (live / release.INTERPRETERS / "py311" / "Lib").is_dir()
    assert release.environment_in_use(live).name == _key(live, commit)
    record = release.read_record(live)
    assert (record["commit"], record["checked_by"], record["source"], record["previous"]) == (commit, "github", str(dev), None)
    assert record["interpreter"] == f"{release.INTERPRETERS}/py311/{release.INTERPRETER_FILE}" and record["history"][0]["outcome"] == "installed"

    # ATDR ran until the copy was ready, then moved: the tasks first, then the end of the old watcher.
    ready = machine.did.index("dashboard built in ATDR-live")
    assert machine.did[ready + 1:] == ["everything stopped in development", "tasks belong to ATDR-live", "watcher ended in development",
                                       "watcher started afresh in ATDR-live", "watcher started everything in ATDR-live"]
    assert machine.running(dev) == [] and sorted(machine.running(live)) == sorted(WITH_WORKER) and machine.tasks == live

    # Its backups followed the database; another database's did not.
    new_label = database_label(f"sqlite:///{(live / 'atdr.db').as_posix()}")
    assert _sources(drive) == [new_label, "another:db"]
    assert list(json.loads((drive / "offsite-copy.json").read_text(encoding="utf-8"))) == [new_label]

    # The development folder knows where ATDR runs, and no longer writes backups or sends messages.
    assert release.live_copy_of(dev) == live
    values = release.env_values(dev)
    assert (values["ATDR_BACKUP_DIRECTORY"], values["ATDR_BACKUP_SCHEDULE_HOURS"], values["ATDR_NOTIFY_EMAIL_TO"], values["ATDR_NOTIFY_WINDOWS"]) == ("", "0", "", "false")
    assert values["JWT_SECRET_KEY"] == "a-secret"
    kept = list((dev / ".atdr_runtime" / "config-backups").glob("atdr.env.before-live-copy-*"))
    assert len(kept) == 1 and kept[0].read_text(encoding="utf-8") == settings_before

    with pytest.raises(ReleaseError, match="is a live copy already"):
        release.setup(machine.tools, dev, live)
    with pytest.raises(ReleaseError, match="is a live copy itself"):
        release.setup(machine.tools, live, tmp_path / "another")

    # And from here a release goes there.
    second = _commit(dev, "the next version", {"atdr/app/main.py": "version = 2\n"})
    released = release.release(machine.tools, dev, live)
    assert released["ok"] and machine.head(live) == second, released.get("why")


def test_a_live_copy_that_does_not_come_up_leaves_atdr_running_where_it_was(machine, dev, tmp_path):
    from atdr.app.services.persistence_service import database_label

    commit = _git(dev, "rev-parse", "HEAD")
    drive = _ready_for_setup(machine, dev, tmp_path)
    settings_before = (dev / ".env").read_text(encoding="utf-8")
    live = tmp_path / "ATDR-live"
    machine.dies_at[commit] = {"atdr-backend"}

    result = release.setup(machine.tools, dev, live)

    # It dies in the copy and, started again where it ran before, dies there too in this test; what matters is where it was started.
    assert not result["ok"] and result["words"] == (
        "The live copy was not put into use: the API server is not running. ATDR was left as it was: it runs from the development folder again.")
    assert release.read_record(live) is None and release.live_copy_of(dev) is None
    assert machine.tasks == dev, "the tasks start the development folder again"
    assert machine.did[-5:] == ["everything stopped in ATDR-live", "tasks belong to development", "watcher ended in ATDR-live",
                                "watcher started afresh in development", "watcher started everything in development"]
    assert (dev / ".env").read_text(encoding="utf-8") == settings_before, "its settings were not touched"
    assert _sources(drive) == [database_label(f"sqlite:///{(dev / 'atdr.db').resolve().as_posix()}"), "another:db"], "the backups are its own again"

    # Run again once the cause is gone: what was made is used, not made twice.
    machine.dies_at.clear()
    machine.did.clear()
    again = release.setup(machine.tools, dev, live)
    assert again["ok"] and release.read_record(live)["commit"] == commit
    assert not any(did.startswith("environment") or did == "packages installed" for did in machine.did)


def test_setup_refuses_what_it_cannot_move(machine, dev, tmp_path):
    _ready_for_setup(machine, dev, tmp_path)
    with pytest.raises(ReleaseError, match="has to be a folder outside the development folder"):
        release.setup(machine.tools, dev, dev / "live")
    taken = tmp_path / "taken"
    taken.mkdir()
    (taken / "somebody's file.txt").write_text("x", encoding="utf-8")
    with pytest.raises(ReleaseError, match="holds something that is not a live copy. Choose an empty folder."):
        release.setup(machine.tools, dev, taken)
    machine.tools.windows = False
    with pytest.raises(ReleaseError, match="A live copy is made on Windows"):
        release.setup(machine.tools, dev, tmp_path / "ATDR-live")
    machine.tools.windows = True
    (dev / ".env").write_text("DATABASE_URL=postgresql+psycopg2://atdr@db/atdr\n", encoding="utf-8")
    with pytest.raises(ReleaseError, match="can be made for a SQLite database inside the development folder"):
        release.setup(machine.tools, dev, tmp_path / "ATDR-live")
    assert sorted(machine.running(dev)) == sorted(WITH_WORKER), "nothing was stopped"


def test_status_says_what_runs_and_what_is_waiting(machine, dev):
    from atdr.scripts.release import describe

    first = _git(dev, "rev-parse", "HEAD")
    nothing = describe(release.status(machine.tools, dev, dev.parent / "live"))
    assert nothing[0].startswith("ATDR has no live copy on this machine") and nothing[1] == "  Make the live copy once: scripts\\release.cmd setup"

    live = _live(machine, dev, first)
    said = describe(release.status(machine.tools, dev, live))
    assert said[0] == f"Live copy: {live}" and said[1].startswith(f"  Version {first[:7]} (the first version), live since ")
    assert said[2] == "  Checked before it went live: GitHub's 2 checks passed."
    assert said[3] == "  ATDR is running: every part is up and answers." and "  It is the version that runs." in said

    _commit(dev, "second", {"atdr/app/main.py": "version = 2\n"})
    _commit(dev, "third", {"atdr/app/main.py": "version = 3\n"})
    (dev / "atdr" / "app" / "main.py").write_text("version = 4, not committed\n", encoding="utf-8")
    (live / "atdr" / "app" / "main.py").write_text("edited on the live machine\n", encoding="utf-8")
    machine.stop(live, ["atdr-worker"])
    release._write_json(live / ".atdr_runtime" / release.MARKER, {"from": first, "to": first, "started_at": "2026-10-10T05:30:00+00:00"})
    said = describe(release.status(machine.tools, dev, live))
    assert "  2 commits are not live yet: scripts\\release.cmd go" in said
    assert "  1 file is not committed; a release takes commits only." in said
    assert "  1 of its files were changed by hand: atdr/app/main.py." in said
    assert "  ATDR: the background worker is not running." in said
    assert any(line.startswith("  A RELEASE DID NOT FINISH (it began ") and line.endswith("scripts\\release.cmd recover") for line in said)


def test_a_check_cut_off_earlier_does_not_stop_the_next_check_of_the_same_commit(machine, dev):
    # A release cut off during its tests (24 Oct 2026) left its scratch folder behind with the read-only object files
    # of the test repositories; checking the same commit again failed with FileExistsError.
    commit = _git(dev, "rev-parse", "HEAD")
    left = dev / ".tmp" / "release-check" / commit[:7] / "pytest" / "repo" / ".git" / "objects" / "ab"
    left.mkdir(parents=True)
    (left / "cdef").write_text("object", encoding="utf-8")
    os.chmod(left / "cdef", stat.S_IREAD)
    machine.github = [(422, None)]

    checked = release.check_commit(machine.tools, dev, commit)

    assert checked["ok"] and checked["by"] == "local_tests", checked["words"]
    assert not (dev / ".tmp" / "release-check" / commit[:7]).exists(), "the scratch space is cleared after a pass"
