"""The System panel is told how ATDR looks after itself: its parts, its backups and the dashboard's build."""

from __future__ import annotations

import json
import subprocess
from collections.abc import Generator
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from atdr.app.core.config import Settings
from atdr.app.db.database import Base, get_db
from atdr.app.db.models import AuditLog, OperationWorkerHeartbeat
from atdr.app.main import app
from atdr.app.services import system_status_service as status_service
from atdr.app.services.scheduled_backup_service import BACKUP_FAILED
from atdr.app.services.system_status_service import (
    _action_words,
    keeping_running_status,
    mains_sleep_seconds,
    system_status,
    unattended_status,
)
from atdr.app.services.user_service import create_user
from atdr.tests.test_detection_grouping import _session

NOW = datetime(2026, 10, 9, 5, 0, tzinfo=timezone.utc)


def _stamp(moment: datetime) -> str:
    # As Windows PowerShell writes a time: seven decimals of a second, and Z.
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond:06d}7Z"


def _runtime(tmp_path: Path, *, checked: datetime | None, desired: dict | None = None, **status) -> Path:
    runtime = tmp_path / ".atdr_runtime"
    runtime.mkdir(exist_ok=True)
    if desired is not None:
        (runtime / "desired-state.json").write_text(json.dumps(desired), encoding="utf-8-sig")
    if checked is not None:
        document = {
            "version": 1,
            "watcher": {"pid": 4242, "started_at": _stamp(NOW - timedelta(hours=3)), "checked_at": _stamp(checked), "interval_seconds": 30},
            "parts": [], "all_restarts": [], "last_action": None, **status,
        }
        (runtime / "watch-status.json").write_text(json.dumps(document), encoding="utf-8-sig")
    return runtime


def _part(name: str, **fields) -> dict:
    return {"name": name, "running": True, "started_at": _stamp(NOW - timedelta(hours=2)), "answering": True,
            "unanswered_checks": 0, "keeps_stopping": False, "restarts": [], **fields}


def test_the_parts_are_shown_as_the_watcher_last_saw_them(tmp_path):
    runtime = _runtime(
        tmp_path, checked=NOW - timedelta(seconds=12), desired={"state": "running", "since": _stamp(NOW - timedelta(hours=3)), "by": "start_system", "hold_until": None},
        parts=[
            _part("atdr-backend"),
            _part("atdr-worker", answering=None, started_at=_stamp(NOW - timedelta(minutes=50)),
                  restarts=[_stamp(NOW - timedelta(hours=25)), _stamp(NOW - timedelta(hours=3)), _stamp(NOW - timedelta(minutes=50))]),
            _part("shell-frontend", answering=False, unanswered_checks=4),
            _part("atdr-syslog", running=False, started_at=None, answering=None, keeps_stopping=True),
        ],
        last_action={"at": _stamp(NOW - timedelta(minutes=50)), "all": False, "started": ["atdr-worker"], "restarted": [], "ok": True, "said": ""},
    )
    keep = keeping_running_status(now=NOW, runtime=runtime)

    assert (keep["meant_to_be"], keep["held_until"], keep["watching"], keep["checked_seconds_ago"], keep["interval_seconds"]) == (
        "running", None, True, 12, 30)
    assert [(part["name"], part["label"], part["running"], part["answering"], part["restarts_24h"], part["keeps_stopping"]) for part in keep["parts"]] == [
        ("atdr-backend", "API server", True, True, 0, False),
        ("atdr-worker", "Background worker", True, None, 2, False),
        ("shell-frontend", "MFU sign-in page", True, False, 0, False),
        ("atdr-syslog", "Live syslog receiver", False, None, 0, True),
    ]
    worker = keep["parts"][1]
    assert worker["started_at"] == NOW - timedelta(minutes=50) and worker["last_restart_at"] == NOW - timedelta(minutes=50), (
        "a restart of more than a day ago is no longer counted")
    assert keep["last_action"] == {"at": NOW - timedelta(minutes=50), "what": "started the background worker again after it stopped", "ok": True}


def test_a_watcher_that_stopped_reporting_is_not_quoted(tmp_path):
    desired = {"state": "running", "since": _stamp(NOW - timedelta(hours=3)), "by": "start_system", "hold_until": None}
    still = _runtime(tmp_path, checked=NOW - timedelta(seconds=120), desired=desired, parts=[_part("atdr-backend")])
    assert keeping_running_status(now=NOW, runtime=still)["watching"] is True

    silent = _runtime(tmp_path, checked=NOW - timedelta(seconds=121), desired=desired, parts=[_part("atdr-backend")],
                      last_action={"at": _stamp(NOW - timedelta(hours=1)), "all": True, "ok": True})
    keep = keeping_running_status(now=NOW, runtime=silent)
    assert (keep["watching"], keep["checked_seconds_ago"], keep["parts"], keep["last_action"], keep["interval_seconds"]) == (False, 121, [], None, None)
    assert keep["meant_to_be"] == "running", "what ATDR is meant to be does not come from the watcher"


def test_without_the_watchers_files_nothing_is_claimed(tmp_path):
    empty = keeping_running_status(now=NOW, runtime=tmp_path / "nothing here")
    assert empty == {"meant_to_be": "unknown", "held_until": None, "watching": False, "checked_seconds_ago": None,
                     "interval_seconds": None, "parts": [], "last_action": None}
    damaged = _runtime(tmp_path, checked=None)
    (damaged / "watch-status.json").write_text("{ half a file", encoding="utf-8")
    (damaged / "desired-state.json").write_text('["not", "an", "object"]', encoding="utf-8")
    assert keeping_running_status(now=NOW, runtime=damaged) == empty


def test_a_held_stop_is_shown_until_its_time_has_passed(tmp_path):
    def held(until: datetime) -> dict:
        runtime = _runtime(tmp_path, checked=NOW, desired={"state": "stopped", "since": _stamp(NOW - timedelta(hours=1)), "by": "stop_system",
                                                           "hold_until": _stamp(until)})
        return keeping_running_status(now=NOW, runtime=runtime)

    assert (held(NOW + timedelta(hours=1))["meant_to_be"], held(NOW + timedelta(hours=1))["held_until"].replace(microsecond=0)) == (
        "stopped", NOW + timedelta(hours=1))
    assert held(NOW - timedelta(seconds=1))["held_until"] is None
    plain = _runtime(tmp_path, checked=NOW, desired={"state": "stopped", "since": _stamp(NOW), "by": "stop_system", "hold_until": None})
    assert (keeping_running_status(now=NOW, runtime=plain)["meant_to_be"], keeping_running_status(now=NOW, runtime=plain)["held_until"]) == ("stopped", None)


def test_what_the_watcher_did_is_said_in_words():
    assert _action_words({"all": True}) == "started ATDR, because no part of it was running"
    assert _action_words({"all": True, "resumed": True}) == "started ATDR, because the time it was to stay stopped had passed"
    assert _action_words({"started": ["atdr-worker"]}) == "started the background worker again after it stopped"
    assert _action_words({"started": ["atdr-backend", "atdr-frontend", "atdr-worker"]}) == (
        "started the API server, the dashboard and the background worker again after they stopped")
    assert _action_words({"restarted": ["shell-frontend"]}) == "restarted the MFU sign-in page, which was not answering"
    assert _action_words({"started": ["atdr-syslog"], "restarted": ["atdr-backend", "shell-backend"]}) == (
        "started the live syslog receiver again after it stopped and restarted the API server and the MFU sign-in service, which were not answering")
    assert _action_words({"started": ["a-part-from-a-later-version"]}) == "started a-part-from-a-later-version again after it stopped"


def _heartbeat(db: Session, seen: datetime, status: str = "watching") -> None:
    db.merge(OperationWorkerHeartbeat(worker_id="worker-1", status=status, started_at=seen, last_seen_at=seen, details_json={}))
    db.commit()


def test_the_status_puts_backups_the_worker_and_the_build_together(tmp_path):
    db = _session()
    settings = Settings(_env_file=None, ATDR_BACKUP_DIRECTORY=str(tmp_path / "backups"), ATDR_BACKUP_SCHEDULE_HOURS=24,
                        ATDR_BACKUP_OFFSITE_FOLDER="ATDR-backups")
    frontend = tmp_path / "frontend"
    (frontend / "dist").mkdir(parents=True)
    (frontend / "dist" / "index.html").write_text("built", encoding="utf-8")
    (frontend / "dist" / ".atdr-build.json").write_text(
        json.dumps({"built_at": "2026-10-09T04:12:36+00:00", "source_changed": 0, "commit": "e4ca530", "uncommitted": True,
                    "files": ["index.html"]}), encoding="utf-8")
    options = {"settings": settings, "now": NOW, "runtime": tmp_path / "none", "frontend": frontend, "find_offsite": lambda _settings: []}

    quiet = system_status(db, **options)
    assert set(quiet) == {"keeping_running", "backups", "dashboard_build", "notifications", "version", "unattended"}
    assert quiet["version"] is None, "a folder with no release on record is the one ATDR is developed in"
    assert quiet["unattended"] is None, "and one where scripts\\autostart.cmd installed nothing"
    assert quiet["notifications"]["enabled"] is True and quiet["notifications"]["worker_running"] is False
    assert set(quiet["notifications"]["channels"]) == {"windows", "email", "chat"}
    assert quiet["dashboard_build"] == {"built": True, "built_at": "2026-10-09T04:12:36+00:00", "commit": "e4ca530",
                                        "uncommitted": True, "stale": False}
    assert (quiet["backups"]["scheduled"], quiet["backups"]["worker_running"], quiet["backups"]["last"], quiet["backups"]["last_failure"]) == (
        True, False, None, None)

    # The worker counts as running while its heartbeat is fresh (three beats), and not once it has said it stopped.
    _heartbeat(db, NOW - timedelta(seconds=45))
    assert system_status(db, **options)["backups"]["worker_running"] is True
    _heartbeat(db, NOW - timedelta(seconds=46))
    assert system_status(db, **options)["backups"]["worker_running"] is False
    _heartbeat(db, NOW, status="stopped")
    assert system_status(db, **options)["backups"]["worker_running"] is False

    db.add(AuditLog(actor="scheduled_backup", action=BACKUP_FAILED, target_type="database_backup", target_value="scheduled",
                    details={"status": "not_enough_free_space"}, created_at=NOW - timedelta(minutes=5)))
    db.add(AuditLog(actor="scheduled_backup", action=BACKUP_FAILED, target_type="database_backup", target_value="offsite E:",
                    details={"status": "copy_failed"}, created_at=NOW - timedelta(minutes=4)))
    db.commit()
    from atdr.app.services.scheduled_backup_service import OffsiteFolder

    usb = tmp_path / "E" / "ATDR-backups"
    usb.mkdir(parents=True)
    failing = system_status(db, **{**options, "find_offsite": lambda _settings: [OffsiteFolder(path=usb, drive="E:", label="KINGSTON")]})
    assert failing["backups"]["last_failure"] == {"at": NOW - timedelta(minutes=5), "status": "not_enough_free_space",
                                                  "words": "there is not enough free space for it"}
    assert failing["backups"]["offsite"]["last_failure"] == {"at": NOW - timedelta(minutes=4), "status": "copy_failed", "drive": "E:",
                                                             "words": "the copy could not be written"}

    (frontend / "src").mkdir()
    (frontend / "src" / "main.tsx").write_text("changed since the build", encoding="utf-8")
    assert system_status(db, **options)["dashboard_build"]["stale"] is True

    # A live copy says which released version it holds, and whether its files are still at it.
    commit = "c4933319a38eca34fba6b587106fbdb4dfd3bb61"
    live = tmp_path / "live"
    (live / ".atdr_runtime").mkdir(parents=True)
    (live / ".git").mkdir()
    (live / ".git" / "HEAD").write_text(commit + "\n", encoding="utf-8")
    (live / ".atdr_runtime" / "release.json").write_text(json.dumps({
        "commit": commit, "short": "c493331", "subject": "fix: a test that depended on the machine's time zone",
        "committed_at": "2026-10-10T11:52:04+07:00", "released_at": "2026-10-10T08:40:00+00:00", "checked_by": "github",
        "check": "GitHub's 7 checks passed", "previous": {"commit": "4922c71" + "0" * 33, "short": "4922c71"},
    }), encoding="utf-8")
    released = system_status(db, **{**options, "runtime": live / ".atdr_runtime"})["version"]
    assert released == {
        "commit": "c493331", "subject": "fix: a test that depended on the machine's time zone",
        "committed_at": datetime(2026, 10, 10, 4, 52, 4, tzinfo=timezone.utc), "released_at": datetime(2026, 10, 10, 8, 40, tzinfo=timezone.utc),
        "checked_by": "github", "check": "GitHub's 7 checks passed", "previous": "4922c71", "as_released": True, "unfinished": False,
    }
    (live / ".git" / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    (live / ".atdr_runtime" / "release-in-progress.json").write_text("{}", encoding="utf-8")
    moved = system_status(db, **{**options, "runtime": live / ".atdr_runtime"})["version"]
    assert (moved["as_released"], moved["unfinished"]) == (False, True)


def test_whether_atdr_runs_with_nobody_at_the_machine_is_read_from_what_was_installed(tmp_path):
    runtime = tmp_path / ".atdr_runtime"
    runtime.mkdir()
    record = runtime / "autostart.json"

    def not_asked() -> int | None:
        raise AssertionError("Windows is not asked about its sleep where nothing is installed")

    assert unattended_status(runtime=runtime, sleep_seconds=not_asked) is None
    for unusable in ("{ not json", '{"mode": "something else"}', "[]"):
        record.write_text(unusable, encoding="utf-8")
        assert unattended_status(runtime=runtime, sleep_seconds=not_asked) is None, unusable

    # As scripts\autostart.ps1 writes it (PowerShell puts a mark at the start of the file).
    record.write_text('﻿{"mode": "at_sign_in", "user": "LAPTOP\\\\someone", "installed_at": "2026-10-10T03:00:00.0000000Z"}', encoding="utf-8")
    assert unattended_status(runtime=runtime, sleep_seconds=lambda: 3600) == {
        "before_sign_in": False, "stay_awake_wanted": False, "sleeps_after_minutes_on_mains": 60}
    record.write_text(json.dumps({"mode": "before_sign_in", "stay_awake_on_mains": True, "mains_sleep_before": {"381b4222": 3600}}), encoding="utf-8")
    assert unattended_status(runtime=runtime, sleep_seconds=lambda: 0) == {
        "before_sign_in": True, "stay_awake_wanted": True, "sleeps_after_minutes_on_mains": 0}
    assert unattended_status(runtime=runtime, sleep_seconds=lambda: None)["sleeps_after_minutes_on_mains"] is None, "Windows did not say"
    assert unattended_status(runtime=runtime, sleep_seconds=lambda: 180)["sleeps_after_minutes_on_mains"] == 3
    # Put back with -Remove: no longer wanted.
    record.write_text(json.dumps({"mode": "at_sign_in", "stay_awake_on_mains": False, "mains_sleep_before": None}), encoding="utf-8")
    assert unattended_status(runtime=runtime, sleep_seconds=lambda: 3600)["stay_awake_wanted"] is False

    # The status carries it for the folder it is asked about.
    db = _session()
    record.write_text(json.dumps({"mode": "before_sign_in", "stay_awake_on_mains": True}), encoding="utf-8")
    status_service._sleep_known = (status_service.time.monotonic(), 0)
    try:
        told = system_status(db, settings=Settings(_env_file=None, ATDR_BACKUP_DIRECTORY=str(tmp_path / "backups")), now=NOW, runtime=runtime,
                             frontend=tmp_path / "frontend", find_offsite=lambda _settings: [])["unattended"]
    finally:
        status_service._sleep_known = None
    if status_service.sys.platform == "win32":
        assert told == {"before_sign_in": True, "stay_awake_wanted": True, "sleeps_after_minutes_on_mains": 0}
    else:
        assert told == {"before_sign_in": True, "stay_awake_wanted": True, "sleeps_after_minutes_on_mains": None}


def test_the_sleep_time_on_mains_power_is_asked_of_windows_once_a_minute(monkeypatch):
    monkeypatch.setattr(status_service.sys, "platform", "win32")
    monkeypatch.setattr(status_service, "_sleep_known", None)
    clock = {"now": 1000.0}
    monkeypatch.setattr(status_service.time, "monotonic", lambda: clock["now"])
    asked = []

    def powercfg(says: str):
        def run(command, **kwargs):
            asked.append((command, kwargs.get("timeout")))
            return subprocess.CompletedProcess(command, 0, stdout=says, stderr="")
        return run

    printed = ("Power Scheme GUID: 6fecc5ae-f350-48a5-b669-b472cb895ccf  (Turbo)\n"
               "  Subgroup GUID: 238c9fa8-0aad-41ed-83f4-97be242c8f20  (Sleep)\n"
               "    Power Setting GUID: 29f6c1db-86da-48c5-9fdb-f2b67b1f44da  (Sleep after)\n"
               "      Minimum Possible Setting: 0x00000000\n      Maximum Possible Setting: 0xffffffff\n"
               "    Current AC Power Setting Index: 0x00000e10\n    Current DC Power Setting Index: 0x000000b4\n")
    assert mains_sleep_seconds(run=powercfg(printed)) == 3600, "on mains power, not on battery (180)"
    assert asked == [(["powercfg", "/query", "SCHEME_CURRENT", "SUB_SLEEP", "STANDBYIDLE"], 15)], "the plan in use, whichever it is"

    # The System panel asks for the status every half minute: Windows is asked again after a minute.
    clock["now"] += 59
    assert mains_sleep_seconds(run=powercfg(printed.replace("0x00000e10", "0x00000000"))) == 3600 and len(asked) == 1
    clock["now"] += 2
    assert mains_sleep_seconds(run=powercfg(printed.replace("0x00000e10", "0x00000000"))) == 0 and len(asked) == 2

    # What cannot be read is not guessed.
    def refuses(command, **_kwargs):
        raise FileNotFoundError(command[0])

    def hangs(command, **_kwargs):
        raise subprocess.TimeoutExpired(command, 15)

    for run in (powercfg("    Current DC Power Setting Index: 0x000000b4\n"), powercfg(""), refuses, hangs):
        clock["now"] += 61
        assert mains_sleep_seconds(run=run) is None

    monkeypatch.setattr(status_service.sys, "platform", "linux")
    clock["now"] += 61
    before = len(asked)
    assert mains_sleep_seconds(run=powercfg(printed)) is None and len(asked) == before, "only Windows is asked"


def test_only_an_admin_is_given_the_system_status(monkeypatch, tmp_path):
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool, future=True)
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
    with factory() as db:
        create_user(db, username="admin", password="admin123", role="admin", full_name="Test Admin")
        create_user(db, username="analyst", password="analyst123", role="analyst", full_name="Test Analyst")

    def override_get_db() -> Generator[Session, None, None]:
        session = factory()
        try:
            yield session
        finally:
            session.close()

    # Not this machine's own watcher and backups: the answer must not depend on where the tests run.
    monkeypatch.setattr(status_service, "RUNTIME", tmp_path / "runtime")
    real = status_service.system_status
    monkeypatch.setattr("atdr.app.routers.system.system_status",
                        lambda db: real(db, settings=Settings(_env_file=None, ATDR_BACKUP_DIRECTORY=str(tmp_path / "backups")),
                                        runtime=tmp_path / "runtime"))
    app.dependency_overrides[get_db] = override_get_db
    try:
        client = TestClient(app)

        def headers(name: str, password: str) -> dict[str, str]:
            return {"Authorization": f"Bearer {client.post('/api/auth/login', json={'username': name, 'password': password}).json()['access_token']}"}

        assert client.get("/api/system/status").status_code == 401
        assert client.get("/api/system/status", headers=headers("analyst", "analyst123")).status_code == 403
        answer = client.get("/api/system/status", headers=headers("admin", "admin123"))
        assert answer.status_code == 200
        body = answer.json()
        assert body["keeping_running"]["watching"] is False and body["keeping_running"]["meant_to_be"] == "unknown"
        assert body["backups"]["scheduled"] is False and body["backups"]["offsite"]["wanted"] is False
        assert set(body["dashboard_build"]) == {"built", "built_at", "commit", "uncommitted", "stale"}
        assert body["version"] is None
    finally:
        app.dependency_overrides.clear()
