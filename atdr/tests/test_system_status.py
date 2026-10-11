"""The System panel is told how ATDR looks after itself: its parts, its backups and the dashboard's build."""

from __future__ import annotations

import json
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
from atdr.app.services.system_status_service import _action_words, keeping_running_status, system_status
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
    assert set(quiet) == {"keeping_running", "backups", "dashboard_build", "notifications", "version"}
    assert quiet["version"] is None, "a folder with no release on record is the one ATDR is developed in"
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
