"""ATDR backs its own database up on a schedule, checks the copy, thins old ones out and copies them to another disk.

Backups were taken by hand: eleven in a month, all in the folder the database is in, on the laptop's only disk.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session, sessionmaker

from atdr.app.core.config import Settings, validate_runtime_settings
from atdr.app.db.database import Base
from atdr.app.db.models import AuditLog, RawLog
from atdr.app.services import operation_worker, scheduled_backup_service as backups
from atdr.app.services import persistence_service
from atdr.app.services.persistence_service import create_database_backup, database_label
from atdr.app.services.scheduled_backup_service import (
    BACKUP_COPIED,
    BACKUP_CREATED,
    BACKUP_FAILED,
    DRIVE_FIXED,
    DRIVE_REMOVABLE,
    BackupFile,
    Drive,
    OffsiteFolder,
    backup_status,
    backups_to_delete,
    list_backups,
    offsite_folders,
    run_scheduled_backup,
    take_backup,
)

START = datetime(2026, 10, 9, 3, 0, tzinfo=timezone.utc)
DAY = timedelta(days=1)
NO_DRIVE = lambda _settings: []  # noqa: E731


def _system(tmp_path: Path, **overrides) -> tuple[Settings, Session]:
    """A database file with a few logs, and where its backups go."""

    database = tmp_path / "C" / "atdr.db"
    database.parent.mkdir(parents=True, exist_ok=True)
    engine = create_engine(f"sqlite:///{database.as_posix()}", future=True)
    Base.metadata.create_all(engine)
    with engine.connect() as connection:
        # As the live database is; a copy of it is in this mode too.
        connection.exec_driver_sql("PRAGMA journal_mode=WAL")
    db = sessionmaker(bind=engine, future=True)()
    db.add_all(RawLog(raw_line=f"line {index}") for index in range(25))
    db.commit()
    # _env_file=None: nothing here may come from the settings of the machine the tests run on.
    settings = Settings(_env_file=None, **{
        "DATABASE_URL": f"sqlite:///{database.as_posix()}",
        "ATDR_BACKUP_DIRECTORY": str(tmp_path / "D" / "ATDR-backups"),
        "ATDR_BACKUP_SCHEDULE_HOURS": 24,
        "ATDR_BACKUP_OFFSITE_FOLDER": "ATDR-backups",
        **overrides,
    })
    return settings, db


def _other_database(tmp_path: Path, settings: Settings) -> tuple[Settings, Session]:
    """A second database whose backups go to the same folder: a copy named in the environment, say."""

    database = tmp_path / "scratch" / "copy_for_tests.db"
    database.parent.mkdir()
    engine = create_engine(f"sqlite:///{database.as_posix()}", future=True)
    Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine, future=True)()
    db.add(RawLog(raw_line="of the copy"))
    db.commit()
    return _with(settings, DATABASE_URL=f"sqlite:///{database.as_posix()}"), db


def _with(settings: Settings, **overrides) -> Settings:
    return Settings(_env_file=None, **{**settings.model_dump(by_alias=True), **overrides})


def _run(db: Session, settings: Settings, when: datetime, *, find_offsite=NO_DRIVE, **kwargs) -> dict:
    return run_scheduled_backup(db, settings=settings, now=when, find_offsite=find_offsite, zone=timezone.utc, **kwargs)


def _audit(db: Session, action: str) -> list[AuditLog]:
    return list(db.scalars(select(AuditLog).where(AuditLog.action == action).order_by(AuditLog.id)))


def _folder(settings: Settings) -> Path:
    return Path(settings.backup_directory)


def _names(folder: Path) -> list[str]:
    return sorted(path.name for path in folder.glob("*.sqlite3"))


def _usb(tmp_path: Path):
    usb = tmp_path / "E" / "ATDR-backups"
    usb.mkdir(parents=True)
    return usb, lambda _settings: [OffsiteFolder(path=usb, drive="E:", label="KINGSTON")]


def test_a_backup_is_taken_when_the_newest_scheduled_one_is_a_day_old_and_not_before(tmp_path):
    settings, db = _system(tmp_path)
    first = _run(db, settings, START)["backup"]
    assert first["ok"] and first["verified"] and first["purpose"] == "scheduled"

    backup = Path(first["backup_path"])
    assert backup.parent == _folder(settings)
    assert sorted(path.name for path in _folder(settings).iterdir()) == [backup.name, f"{backup.name}.manifest.json"], (
        "checking the copy leaves no -wal or -shm file beside it")
    with closing(sqlite3.connect(f"file:{backup.as_posix()}?mode=ro&immutable=1", uri=True)) as copy:
        assert copy.execute("select count(*) from raw_logs").fetchone() == (25,)
        assert copy.execute("pragma quick_check").fetchone() == ("ok",)
    assert backup.read_bytes()[18:20] == b"\x02\x02", "a WAL-mode file, the kind SQLite makes helper files for"
    manifest = json.loads(Path(first["manifest_path"]).read_text(encoding="utf-8"))
    assert (manifest["purpose"], manifest["created_at"], manifest["table_counts"]["raw_logs"]) == ("scheduled", START.isoformat(), 25)
    assert manifest["source"] == database_label(settings.database_url), "which database it is a copy of"
    assert manifest["source"].endswith(os.path.normcase(str((tmp_path / "C" / "atdr.db").resolve())))

    assert _run(db, settings, START + timedelta(hours=23, minutes=59))["backup"] is None
    assert _names(_folder(settings)) == [backup.name]
    second = _run(db, settings, START + DAY)["backup"]
    assert second["ok"] and _names(_folder(settings)) == sorted([backup.name, second["artifact_name"]])

    entries = _audit(db, BACKUP_CREATED)
    assert [(entry.actor, entry.created_at.replace(tzinfo=timezone.utc)) for entry in entries] == [
        ("scheduled_backup", START), ("scheduled_backup", START + DAY),
    ]
    assert entries[0].target_value == backup.name and entries[0].details == {
        "purpose": "scheduled", "size_bytes": backup.stat().st_size, "folder": str(_folder(settings)), "deleted": [],
    }


def test_a_backup_taken_by_hand_does_not_stand_in_for_the_scheduled_one(tmp_path):
    settings, db = _system(tmp_path)
    create_database_backup(settings=settings, output_dir=_folder(settings), execute=True, created_at=START - timedelta(minutes=1))
    take_backup(settings, purpose="before_reset", now=START - timedelta(minutes=1))
    assert _run(db, settings, START)["backup"]["ok"]
    assert sorted(backup.purpose for backup in list_backups(_folder(settings))) == ["before_reset", "manual", "scheduled"]


def test_each_database_manages_only_its_own_backups_in_a_shared_folder(tmp_path, monkeypatch):
    # The folder comes from .env, but a one-off script can name another database in the environment, and two
    # computers can share a folder or a drive. Neither may take the other's backup for its own, nor delete it.
    settings, db = _system(tmp_path, ATDR_BACKUP_KEEP_DAILY=1, ATDR_BACKUP_KEEP_WEEKLY=0, ATDR_BACKUP_KEEP_MONTHLY=0)
    other, other_db = _other_database(tmp_path, settings)
    usb, connected = _usb(tmp_path)
    folder = _folder(settings)

    mine = _run(db, settings, START, find_offsite=connected)["backup"]["artifact_name"]
    theirs = _run(other_db, other, START + DAY * 3, find_offsite=connected)
    their_name = theirs["backup"]["artifact_name"]
    assert theirs["backup"]["ok"] and [copy["ok"] for copy in theirs["offsite"]] == [True]
    assert _names(folder) == _names(usb) == sorted([mine, their_name]), "a ladder of one day thins out only its own"
    assert [entry.details["deleted"] for entry in _audit(other_db, BACKUP_CREATED)] == [[]]

    # A newer backup of another database does not stand in for this one's, three days old by now.
    later = START + DAY * 3 + timedelta(minutes=5)
    assert backups.backup_due(settings, now=later) and not backups.backup_due(other, now=later)
    status = backup_status(db, settings=settings, now=later, find_offsite=NO_DRIVE)
    assert (status["last"]["name"], status["kept"], status["other_backups"], status["overdue"]) == (mine, 1, 0, True)
    assert (status["offsite"]["last_copy"]["artifact_name"], status["offsite"]["last_copy"]["age_days"]) == (mine, 3.0)
    their_status = backup_status(other_db, settings=other, now=later, find_offsite=NO_DRIVE)
    assert (their_status["last"]["name"], their_status["kept"], their_status["offsite"]["last_copy"]["artifact_name"]) == (
        their_name, 1, their_name)

    # A drive connected now gets this database's newest backup, though the folder has a newer one.
    fresh = tmp_path / "F" / "ATDR-backups"
    fresh.mkdir(parents=True)
    copied = backups.copy_offsite(settings, OffsiteFolder(path=fresh, drive="F:", label="Elements"), now=later)
    assert copied["artifact_name"] == mine and _names(fresh) == [mine]

    # The backup before a reset of the other database is that database's, wherever it lands.
    before = backups.backup_before_deleting(other_db, settings=other, now=later)
    assert Path(before["folder"]) == folder
    assert backup_status(db, settings=settings, now=later, find_offsite=NO_DRIVE)["other_backups"] == 0
    assert backup_status(other_db, settings=other, now=later, find_offsite=NO_DRIVE)["other_backups"] == 1

    # This database's next backup thins out its own old one, in the folder and on the drive, and nothing else.
    second = _run(db, settings, later, find_offsite=connected)
    second_name = second["backup"]["artifact_name"]
    assert _audit(db, BACKUP_CREATED)[-1].details["deleted"] == [mine] and second["offsite"][0]["deleted"] == [mine]
    assert _names(folder) == sorted([their_name, before["artifact_name"], second_name])
    assert _names(usb) == sorted([their_name, second_name])

    # A full folder: room is made from this database's own old backups, and it has none to give.
    monkeypatch.setattr(backups, "_free_bytes", lambda _where: 0)
    assert _run(db, settings, later + DAY, find_offsite=NO_DRIVE)["backup"]["status"] == "not_enough_free_space"
    assert _names(folder) == sorted([their_name, before["artifact_name"], second_name])
    monkeypatch.undo()

    # A backup whose manifest names no database is nobody's: not counted by either, and so deleted by neither.
    manifest_path = folder / f"{second_name}.manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    del manifest["source"]
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    assert backups.own_backups(folder, settings) == []
    assert sorted(backup.path.name for backup in backups.own_backups(folder, other)) == sorted([their_name, before["artifact_name"]])
    assert len(list_backups(folder)) == 3


def test_another_databases_backup_does_not_end_the_wait_after_a_failed_one(tmp_path, monkeypatch):
    settings, db = _system(tmp_path)
    other, other_db = _other_database(tmp_path, settings)
    monkeypatch.setattr(backups, "_sqlite_integrity", lambda _path: False)
    assert _run(db, settings, START)["backup"]["status"] == "backup_failed_verification"
    monkeypatch.undo()
    assert _run(other_db, other, START + timedelta(minutes=10))["backup"]["ok"]

    assert _run(db, settings, START + timedelta(minutes=30))["backup"] is None, "an hour after its own failure, whatever else is in the folder"
    status = backup_status(db, settings=settings, now=START + timedelta(minutes=31), find_offsite=NO_DRIVE)
    assert (status["last"], status["last_failure"]["status"]) == (None, "backup_failed_verification")
    assert _run(db, settings, START + timedelta(hours=1))["backup"]["ok"]


def test_a_database_is_named_by_its_computer_and_file_or_by_its_server(monkeypatch):
    monkeypatch.setattr(persistence_service.platform, "node", lambda: "Laptop-A")
    here = os.path.normcase(str((backups.PROJECT_ROOT / "atdr.db").resolve()))
    assert database_label("sqlite:///./atdr.db") == f"laptop-a:{here}"
    assert database_label("sqlite://") == "sqlite in memory"
    label = database_label("postgresql+psycopg://atdr:not-in-the-label@db.example:5432/atdr")
    assert label == "postgresql://db.example:5432/atdr" and "not-in-the-label" not in label
    # A server reached as localhost is a different one on each computer.
    assert database_label("postgresql+psycopg://atdr@localhost/atdr") == "postgresql://laptop-a/atdr"
    assert database_label("postgresql://atdr@127.0.0.1:5433/atdr") == "postgresql://laptop-a:5433/atdr"
    # Two laptops with the project in the same place, sharing a drive, are two databases.
    monkeypatch.setattr(persistence_service.platform, "node", lambda: "Laptop-B")
    assert database_label("sqlite:///./atdr.db") == f"laptop-b:{here}"


def test_nothing_happens_while_the_schedule_is_off(tmp_path):
    settings, db = _system(tmp_path, ATDR_BACKUP_SCHEDULE_HOURS=0)
    usb, connected = _usb(tmp_path)
    assert _run(db, settings, START, find_offsite=connected) == {"backup": None, "offsite": []}
    assert not _folder(settings).exists() and not list(usb.iterdir())

    # Switched off after a backup was made: that backup is not copied to a drive connected later either.
    assert _run(db, _with(settings, ATDR_BACKUP_SCHEDULE_HOURS=24), START)["backup"]["ok"]
    assert _run(db, settings, START + DAY * 2, find_offsite=connected) == {"backup": None, "offsite": []}
    assert not list(usb.iterdir()) and len(_names(_folder(settings))) == 1


def test_the_folder_is_beside_the_database_when_none_is_named(tmp_path):
    database = tmp_path / "data" / "atdr.db"
    beside = Settings(DATABASE_URL=f"sqlite:///{database.as_posix()}", ATDR_BACKUP_DIRECTORY="")
    assert backups.backup_folder(beside) == database.parent / "backups" / "scheduled"
    # The configured database is in the project folder, so its backups are in the project's backups folder.
    assert backups.backup_folder(Settings(DATABASE_URL="sqlite:///./atdr.db", ATDR_BACKUP_DIRECTORY="")) == backups.PROJECT_ROOT / "backups" / "scheduled"
    server = Settings(DATABASE_URL="postgresql+psycopg://atdr@db.example/atdr", ATDR_BACKUP_DIRECTORY="")
    assert backups.backup_folder(server) == backups.PROJECT_ROOT / "backups" / "scheduled"
    assert backups.backup_folder(Settings(ATDR_BACKUP_DIRECTORY=" D:/ATDR-backups ")) == Path("D:/ATDR-backups")


def _backup_at(when: datetime, purpose: str = "scheduled") -> BackupFile:
    name = f"atdr-sqlite-{when:%Y%m%dT%H%M%SZ}.sqlite3"
    return BackupFile(path=Path(name), manifest_path=Path(f"{name}.manifest.json"), created_at=when, size_bytes=1, purpose=purpose)


def test_the_ladder_keeps_the_newest_of_each_day_week_and_month():
    # One backup every night for a hundred days up to Friday 9 October 2026, and a second one that last day.
    nightly = [_backup_at(START - DAY * back) for back in range(100)]
    extra = _backup_at(START + timedelta(hours=5))
    deleted = backups_to_delete([*nightly, extra], keep_daily=7, keep_weekly=4, keep_monthly=6, zone=timezone.utc)
    kept = sorted({backup.created_at for backup in [*nightly, extra]} - {backup.created_at for backup in deleted})

    assert [f"{moment:%d %b %H:%M}" for moment in kept] == [
        "31 May 03:00", "30 Jun 03:00", "31 Jul 03:00", "31 Aug 03:00",  # no nightly is older than 2 July; see below
        "20 Sep 03:00",  # the newest of the week that ended Sunday 20 September
        "27 Sep 03:00",  # of the week after
        "30 Sep 03:00",  # of September
        "03 Oct 03:00", "04 Oct 03:00",  # 4 October also ends its week
        "05 Oct 03:00", "06 Oct 03:00", "07 Oct 03:00", "08 Oct 03:00",
        "09 Oct 08:00",  # of the 9 October pair, the later one
    ][2:], "six months that have a backup: May and June have none in these hundred days"
    assert extra not in deleted and nightly[0] in deleted

    # A backup taken by hand or before a reset is never thinned out, however old.
    others = [_backup_at(START - DAY * 400, "manual"), _backup_at(START - DAY * 300, "before_reset")]
    assert not set(others) & set(backups_to_delete([*nightly, *others], keep_daily=1, keep_weekly=0, keep_monthly=0, zone=timezone.utc))
    assert len(backups_to_delete(nightly, keep_daily=1, keep_weekly=0, keep_monthly=0, zone=timezone.utc)) == 99
    assert backups_to_delete(nightly[:1], keep_daily=0, keep_weekly=0, keep_monthly=1, zone=timezone.utc) == []


def test_a_day_is_the_laptops_own_day():
    # 9 October 23:30 and 10 October 00:30 in Bangkok are both 9 October in UTC.
    bangkok = timezone(timedelta(hours=7))
    late, early = _backup_at(datetime(2026, 10, 9, 16, 30, tzinfo=timezone.utc)), _backup_at(datetime(2026, 10, 9, 17, 30, tzinfo=timezone.utc))
    assert backups_to_delete([late, early], keep_daily=7, keep_weekly=0, keep_monthly=0, zone=bangkok) == []
    assert backups_to_delete([late, early], keep_daily=7, keep_weekly=0, keep_monthly=0, zone=timezone.utc) == [late]


def test_old_scheduled_backups_are_deleted_and_the_others_left(tmp_path):
    settings, db = _system(tmp_path, ATDR_BACKUP_KEEP_DAILY=2, ATDR_BACKUP_KEEP_WEEKLY=0, ATDR_BACKUP_KEEP_MONTHLY=0)
    by_hand = create_database_backup(settings=settings, output_dir=_folder(settings), execute=True, created_at=START - DAY * 90)
    before_reset = take_backup(settings, purpose="before_reset", now=START - DAY * 60)
    names = []
    for day in range(5):
        names.append(_run(db, settings, START + DAY * day)["backup"]["artifact_name"])
        # Someone looked into the backup with a database program, which left its two helper files there.
        with closing(sqlite3.connect(_folder(settings) / names[-1])) as opened:
            opened.execute("select count(*) from raw_logs").fetchone()
        (_folder(settings) / f"{names[-1]}-wal").touch()
        (_folder(settings) / f"{names[-1]}-shm").touch()

    assert {backup.path.name: backup.purpose for backup in list_backups(_folder(settings))} == {
        Path(by_hand["backup_path"]).name: "manual", before_reset["artifact_name"]: "before_reset",
        names[3]: "scheduled", names[4]: "scheduled",
    }
    assert [entry.details["deleted"] for entry in _audit(db, BACKUP_CREATED)] == [[], [], [names[0]], [names[1]], [names[2]]]
    assert not list(_folder(settings).glob(f"{names[0]}*")), "the backup goes with its manifest and any helper files"


def test_a_backup_open_in_another_program_is_no_longer_counted_and_goes_later(tmp_path, monkeypatch):
    settings, db = _system(tmp_path, ATDR_BACKUP_KEEP_DAILY=1, ATDR_BACKUP_KEEP_WEEKLY=0, ATDR_BACKUP_KEEP_MONTHLY=0)
    first = _run(db, settings, START)["backup"]["artifact_name"]
    real_unlink = Path.unlink

    def in_use(self: Path, missing_ok: bool = False) -> None:
        if self.name == first:
            raise PermissionError("being used by another process")
        real_unlink(self, missing_ok=missing_ok)

    monkeypatch.setattr(Path, "unlink", in_use)
    second = _run(db, settings, START + DAY)["backup"]
    assert second["ok"], "the backup is not lost because an old one could not be deleted"
    assert [backup.path.name for backup in list_backups(_folder(settings))] == [second["artifact_name"]]
    assert (_folder(settings) / first).exists() and _audit(db, BACKUP_CREATED)[-1].details["deleted"] == [first]

    # Closed again: the stray file goes once it is an hour old, and never sooner (it could be a backup being written).
    monkeypatch.undo()
    _run(db, settings, START + DAY * 2)
    assert (_folder(settings) / first).exists()
    old = (START - DAY).timestamp()
    os.utime(_folder(settings) / first, (old, old))
    unrelated = _folder(settings) / "atdr-notes.txt"
    unrelated.write_text("not a backup", encoding="utf-8")
    os.utime(unrelated, (old, old))
    _run(db, settings, START + DAY * 3)
    assert not (_folder(settings) / first).exists() and unrelated.exists(), "only a file with a backup's name is removed"


def test_a_copy_that_is_not_a_healthy_database_is_removed_and_tried_again_an_hour_later(tmp_path, monkeypatch):
    settings, db = _system(tmp_path)
    monkeypatch.setattr(backups, "_sqlite_integrity", lambda _path: False)
    result = _run(db, settings, START)["backup"]
    assert (result["ok"], result["status"]) == (False, "backup_failed_verification")
    assert list(_folder(settings).iterdir()) == [], "nothing that is not a healthy backup is left in the folder"

    # No try at every look; one after an hour; and the same failure is entered in the audit log once a day.
    assert _run(db, settings, START + timedelta(minutes=59))["backup"] is None
    assert _run(db, settings, START + timedelta(hours=1))["backup"]["status"] == "backup_failed_verification"
    assert _run(db, settings, START + timedelta(hours=23))["backup"]["status"] == "backup_failed_verification"
    assert len(_audit(db, BACKUP_FAILED)) == 1
    assert _run(db, settings, START + timedelta(hours=24))["backup"]["status"] == "backup_failed_verification"
    failures = _audit(db, BACKUP_FAILED)
    assert [(entry.target_value, entry.details["status"]) for entry in failures] == [("scheduled", "backup_failed_verification")] * 2
    assert backup_status(db, settings=settings, now=START + timedelta(hours=24, minutes=1), find_offsite=NO_DRIVE)["last_failure"] == {
        "at": START + timedelta(hours=24), "status": "backup_failed_verification",
    }

    monkeypatch.undo()
    assert _run(db, settings, START + timedelta(hours=24, minutes=59))["backup"] is None, "an hour since the last failure, not since the first"
    assert _run(db, settings, START + timedelta(hours=25))["backup"]["ok"]
    status = backup_status(db, settings=settings, now=START + timedelta(hours=26), find_offsite=NO_DRIVE)
    assert status["last_failure"] is None and status["kept"] == 1

    # A failure after a success is a new one, entered again although the last entry is less than a day old.
    monkeypatch.setattr(backups, "_sqlite_integrity", lambda _path: False)
    assert _run(db, settings, START + timedelta(hours=49))["backup"]["status"] == "backup_failed_verification"
    assert len(_audit(db, BACKUP_FAILED)) == 3


def test_a_full_folder_loses_its_oldest_backups_but_never_its_newest(tmp_path, monkeypatch):
    settings, db = _system(tmp_path)
    names = [_run(db, settings, START + DAY * day)["backup"]["artifact_name"] for day in range(3)]
    folder = _folder(settings)

    def needed() -> int:
        return backups._database_bytes(settings) + backups.SPARE_BYTES

    # Room only once two of the three are gone.
    monkeypatch.setattr(backups, "_free_bytes", lambda _where: needed() if len(_names(folder)) <= 1 else needed() - 1)
    fourth = _run(db, settings, START + DAY * 3)["backup"]
    assert fourth["ok"] and _names(folder) == sorted([names[2], fourth["artifact_name"]])
    assert _audit(db, BACKUP_CREATED)[-1].details["deleted"] == [names[0], names[1]], "oldest first"

    # No room even with one left: that one stays, and the failure says what was needed.
    monkeypatch.setattr(backups, "_free_bytes", lambda _where: needed() - 1)
    failed = _run(db, settings, START + DAY * 4)["backup"]
    assert failed["status"] == "not_enough_free_space" and failed["needed_bytes"] - failed["free_bytes"] == 1
    assert failed["needed_bytes"] > backups.SPARE_BYTES, "the database's size and room to spare"
    assert _names(folder) == [fourth["artifact_name"]]


def test_a_folder_that_cannot_be_made_is_a_reported_failure_not_a_crash(tmp_path):
    blocker = tmp_path / "not-a-folder"
    blocker.write_text("a file where the folder should be", encoding="utf-8")
    settings, db = _system(tmp_path, ATDR_BACKUP_DIRECTORY=str(blocker / "backups"))
    assert _run(db, settings, START)["backup"]["status"] == "backup_folder_unavailable"
    assert _audit(db, BACKUP_FAILED)[0].details["status"] == "backup_folder_unavailable"


def test_a_database_that_cannot_be_read_is_a_reported_failure(tmp_path, monkeypatch):
    settings, db = _system(tmp_path)

    def unreadable(**_kwargs):
        raise sqlite3.OperationalError("disk I/O error")

    monkeypatch.setattr(backups, "create_database_backup", unreadable)
    assert _run(db, settings, START)["backup"] == {"ok": False, "status": "backup_failed", "error_type": "OperationalError"}
    assert _audit(db, BACKUP_FAILED)[0].details == {"status": "backup_failed", "error_type": "OperationalError"}


def _drives(tmp_path: Path) -> list[Drive]:
    roots = {name: tmp_path / name for name in ("C", "D", "E", "F", "G", "N", "R", "S")}
    for root in roots.values():
        root.mkdir(exist_ok=True)
    return [
        Drive(root=roots["C"], name="C:", kind=DRIVE_FIXED, disk=0, label="OS"),
        Drive(root=roots["D"], name="D:", kind=DRIVE_FIXED, disk=0, label=""),           # second partition, same disk
        Drive(root=roots["E"], name="E:", kind=DRIVE_REMOVABLE, disk=1, label="KINGSTON"),
        Drive(root=roots["F"], name="F:", kind=DRIVE_FIXED, disk=2, label="Elements"),    # a USB hard disk reports as fixed
        Drive(root=roots["G"], name="G:", kind=DRIVE_REMOVABLE, disk=3, label="NO FOLDER"),
        Drive(root=roots["N"], name="N:", kind=4, disk=None, label="share"),              # a network drive
        Drive(root=roots["R"], name="R:", kind=5, disk=1, label="DVD"),                   # a disc drive has a number of its own kind
        Drive(root=roots["S"], name="S:", kind=DRIVE_FIXED, disk=None, label="spanned"),  # the system will not say its disk
    ]


def test_only_a_drive_on_another_disk_with_the_folder_takes_the_copy(tmp_path):
    settings, _db = _system(tmp_path)
    drives = _drives(tmp_path)
    for name in ("C", "D", "E", "F", "N", "R", "S"):
        (tmp_path / name / "ATDR-backups").mkdir(exist_ok=True)

    found = offsite_folders(settings, drives=lambda: drives)
    assert [(item.drive, item.label, item.path) for item in found] == [
        ("E:", "KINGSTON", tmp_path / "E" / "ATDR-backups"), ("F:", "Elements", tmp_path / "F" / "ATDR-backups"),
    ], "not the database's own drive, its disk's other partition, a network or disc drive, or a drive with no folder"

    # Where the system names no disk for a drive, only a removable one is surely another disk.
    unknown = [Drive(root=drive.root, name=drive.name, kind=drive.kind, disk=None, label=drive.label) for drive in drives]
    assert [item.drive for item in offsite_folders(settings, drives=lambda: unknown)] == ["E:"]

    assert offsite_folders(_with(settings, ATDR_BACKUP_OFFSITE_FOLDER=""), drives=lambda: drives) == []
    # The folder the scheduled backups are in is never also the copy, wherever it is.
    elsewhere = _with(settings, ATDR_BACKUP_DIRECTORY=str(tmp_path / "F" / "ATDR-backups"))
    assert [item.drive for item in offsite_folders(elsewhere, drives=lambda: drives)] == ["E:"]


def test_the_real_drive_list_names_this_machines_disks_or_nothing_off_windows(tmp_path):
    settings, _db = _system(tmp_path)
    assert all(isinstance(item, OffsiteFolder) for item in offsite_folders(settings))
    if backups.sys.platform == "win32":
        listed = backups._windows_drives()
        system = next(drive for drive in listed if backups._holds(drive, Path(backups.PROJECT_ROOT)))
        assert system.kind == DRIVE_FIXED and system.disk is not None, "Windows names the project's disk without elevation"
    else:
        assert offsite_folders(settings) == []


def test_the_newest_backup_is_copied_to_a_connected_drive_once_and_checked_there(tmp_path):
    settings, db = _system(tmp_path)
    usb, connected = _usb(tmp_path)
    beats: list[int] = []

    done = _run(db, settings, START, find_offsite=connected, still_alive=lambda: beats.append(1))
    name = done["backup"]["artifact_name"]
    assert [(copy["ok"], copy["artifact_name"], copy["drive"]) for copy in done["offsite"]] == [(True, name, "E:")]
    assert (usb / name).read_bytes() == (_folder(settings) / name).read_bytes()
    assert json.loads((usb / f"{name}.manifest.json").read_text(encoding="utf-8"))["purpose"] == "scheduled"
    assert not list(usb.glob("*.partial")) and beats, "the worker is told it is alive while a long copy runs"
    records = json.loads((_folder(settings) / "offsite-copy.json").read_text(encoding="utf-8"))
    assert list(records) == [database_label(settings.database_url)], "one record for each database the folder serves"
    record = records[database_label(settings.database_url)]
    assert (record["artifact_name"], record["drive"], record["label"], record["copied_at"]) == (name, "E:", "KINGSTON", START.isoformat())
    assert not list(_folder(settings).glob("*.partial"))
    assert [(entry.target_value, entry.details["drive"], entry.details["label"]) for entry in _audit(db, BACKUP_COPIED)] == [(name, "E:", "KINGSTON")]

    # Connected again later the same day: it has that backup already.
    assert _run(db, settings, START + timedelta(hours=2), find_offsite=connected)["offsite"] == []
    assert len(_audit(db, BACKUP_COPIED)) == 1 and _names(usb) == [name]

    status = backup_status(db, settings=settings, now=START + timedelta(days=3), find_offsite=connected)["offsite"]
    assert status["connected"] == [{"drive": "E:", "label": "KINGSTON"}] and status["stale"] is False
    assert (status["last_copy"]["artifact_name"], status["last_copy"]["age_days"], status["last_copy"]["copied_at"]) == (name, 3.0, START)
    week_old = backup_status(db, settings=settings, now=START + timedelta(days=7), find_offsite=NO_DRIVE)["offsite"]
    assert week_old["stale"] is False
    unplugged = backup_status(db, settings=settings, now=START + timedelta(days=7, minutes=1), find_offsite=NO_DRIVE)["offsite"]
    assert unplugged["connected"] == [] and unplugged["stale"] is True and unplugged["last_copy"]["drive"] == "E:"

    # A drive connected for the first time a week later takes the newest backup, not the one of a week ago.
    later = _run(db, settings, START + DAY, find_offsite=NO_DRIVE)["backup"]["artifact_name"]
    other = tmp_path / "F" / "ATDR-backups"
    other.mkdir(parents=True)
    copied = _run(db, settings, START + DAY + timedelta(hours=1),
                  find_offsite=lambda _s: [OffsiteFolder(path=other, drive="F:", label="Elements")])["offsite"]
    assert [copy["artifact_name"] for copy in copied] == [later] and _names(other) == [later]


def test_a_copy_that_arrives_damaged_is_removed_and_reported(tmp_path, monkeypatch):
    settings, db = _system(tmp_path)
    usb, connected = _usb(tmp_path)

    def damaged(source: Path, target: Path, _still_alive) -> None:
        target.write_bytes(source.read_bytes()[:-1] + b"?")

    monkeypatch.setattr(backups, "_copy", damaged)
    copies = _run(db, settings, START, find_offsite=connected)["offsite"]
    assert [(copy["ok"], copy["status"]) for copy in copies] == [(False, "copy_failed_verification")]
    assert list(usb.iterdir()) == [] and not (_folder(settings) / "offsite-copy.json").exists()
    assert [(entry.target_value, entry.details["status"]) for entry in _audit(db, BACKUP_FAILED)] == [("offsite E:", "copy_failed_verification")]
    status = backup_status(db, settings=settings, now=START + timedelta(minutes=1), find_offsite=connected)
    assert status["offsite"]["last_failure"] == {"at": START, "status": "copy_failed_verification", "drive": "E:"}
    assert status["offsite"]["stale"] is True and status["last_failure"] is None, "the backup itself is fine"

    def pulled_out(_source: Path, target: Path, _still_alive) -> None:
        target.with_name(f"{target.name}.partial").write_bytes(b"half")
        raise OSError("the device is not ready")

    monkeypatch.setattr(backups, "_copy", pulled_out)
    copies = _run(db, settings, START + timedelta(minutes=5), find_offsite=connected)["offsite"]
    assert [(copy["status"], copy["error_type"]) for copy in copies] == [("copy_failed", "OSError")]
    assert list(usb.iterdir()) == [], "the half-written copy does not stay on the drive"
    assert len(_audit(db, BACKUP_FAILED)) == 2, "a different failure is entered"
    _run(db, settings, START + timedelta(minutes=10), find_offsite=connected)
    assert len(_audit(db, BACKUP_FAILED)) == 2, "the same one is not, at every look"

    monkeypatch.undo()
    assert _run(db, settings, START + timedelta(minutes=15), find_offsite=connected)["offsite"][0]["ok"]
    assert backup_status(db, settings=settings, now=START + timedelta(minutes=16), find_offsite=connected)["offsite"]["last_failure"] is None


def test_a_full_drive_loses_its_oldest_copies_and_keeps_the_last_good_one_when_that_is_not_enough(tmp_path, monkeypatch):
    settings, db = _system(tmp_path)
    usb, connected = _usb(tmp_path)
    first = _run(db, settings, START, find_offsite=connected)["backup"]["artifact_name"]
    second = _run(db, settings, START + DAY, find_offsite=connected)["backup"]["artifact_name"]
    assert _names(usb) == sorted([first, second])

    real_free = backups._free_bytes
    plenty = 10 * backups.SPARE_BYTES
    # Room for a third only once the oldest is gone.
    monkeypatch.setattr(backups, "_free_bytes", lambda where: (plenty if len(_names(usb)) <= 1 else 0) if where == usb else real_free(where))
    third = _run(db, settings, START + DAY * 2, find_offsite=connected)
    assert third["offsite"][0]["ok"] and third["offsite"][0]["deleted"] == [first]
    assert _names(usb) == sorted([second, third["backup"]["artifact_name"]])

    # No room at all: the newest copy on the drive stays, and the failure is reported.
    monkeypatch.setattr(backups, "_free_bytes", lambda where: 0 if where == usb else real_free(where))
    fourth = _run(db, settings, START + DAY * 3, find_offsite=connected)
    assert fourth["backup"]["ok"] and [(copy["ok"], copy["status"]) for copy in fourth["offsite"]] == [(False, "not_enough_free_space")]
    assert _names(usb) == [third["backup"]["artifact_name"]], "the last good copy is not given up for a copy that will not fit"


def test_the_status_says_when_the_backup_is_late(tmp_path):
    settings, db = _system(tmp_path)
    nothing = backup_status(db, settings=settings, now=START, find_offsite=NO_DRIVE)
    assert (nothing["scheduled"], nothing["every_hours"], nothing["last"], nothing["kept"], nothing["overdue"], nothing["folder_available"]) == (
        True, 24.0, None, 0, True, False)
    assert nothing["offsite"] == {"wanted": True, "folder_name": "ATDR-backups", "connected": [], "last_copy": None,
                                  "last_failure": None, "stale": True}

    made = _run(db, settings, START)["backup"]
    by_hand = create_database_backup(settings=settings, output_dir=_folder(settings), execute=True)
    assert by_hand["purpose"] == "manual"
    fresh = backup_status(db, settings=settings, now=START + timedelta(hours=30), find_offsite=NO_DRIVE)
    assert fresh["overdue"] is False and fresh["last"] == {
        "name": made["artifact_name"], "created_at": START, "size_bytes": made["size_bytes"], "age_hours": 30.0,
    }
    assert (fresh["kept"], fresh["kept_bytes"], fresh["other_backups"], fresh["folder"], fresh["folder_available"]) == (
        1, made["size_bytes"], 1, str(_folder(settings)), True)
    assert backup_status(db, settings=settings, now=START + timedelta(hours=30, minutes=1), find_offsite=NO_DRIVE)["overdue"] is True

    off = backup_status(db, settings=_with(settings, ATDR_BACKUP_SCHEDULE_HOURS=0), now=START + DAY * 30,
                        find_offsite=lambda _s: pytest.fail("no drive is looked for while the schedule is off"))
    assert (off["scheduled"], off["overdue"], off["offsite"]["wanted"], off["offsite"]["stale"]) == (False, False, False, False)


def test_the_worker_takes_the_backup_when_it_has_no_job_and_a_failure_never_stops_it(monkeypatch):
    calls: list[dict] = []

    class _Session:
        def __enter__(self):
            return object()

        def __exit__(self, *_exc):
            return False

    monkeypatch.setattr(operation_worker, "SessionLocal", _Session)
    monkeypatch.setattr(operation_worker, "get_settings", lambda: Settings(_env_file=None, ATDR_BACKUP_SCHEDULE_HOURS=24))
    monkeypatch.setattr(operation_worker, "record_worker_heartbeat", lambda *_args, **kwargs: calls.append({"heartbeat": kwargs["details"]}))

    def backup(_db, **kwargs):
        kwargs["still_alive"]()
        kwargs["still_alive"]()
        calls.append({"backup": True})
        return {}

    monkeypatch.setattr(operation_worker, "run_scheduled_backup", backup)
    before = operation_worker.time.monotonic()
    next_look = operation_worker._backup_look("worker-1", 0.0)
    assert next_look >= before + backups.BACKUP_LOOK_SECONDS - 1
    assert calls == [{"heartbeat": {"scheduled_backup": True, "external_services": "disabled"}}, {"backup": True}], "one heartbeat, not one a chunk"
    # Not time yet: nothing happens.
    assert operation_worker._backup_look("worker-1", next_look) == next_look and len(calls) == 2

    def broken(_db, **_kwargs):
        raise RuntimeError("the backup drive is gone")

    monkeypatch.setattr(operation_worker, "run_scheduled_backup", broken)
    assert operation_worker._backup_look("worker-1", 0.0) >= before + backups.BACKUP_LOOK_SECONDS - 1

    monkeypatch.setattr(operation_worker, "get_settings", lambda: Settings(_env_file=None, ATDR_BACKUP_SCHEDULE_HOURS=0))
    monkeypatch.setattr(operation_worker, "run_scheduled_backup", lambda *_a, **_k: pytest.fail("the schedule is off"))
    assert operation_worker._backup_look("worker-1", 0.0) == 0.0


def test_the_worker_loop_looks_for_a_due_backup(monkeypatch, tmp_path):
    settings, db = _system(tmp_path)
    monkeypatch.setattr(operation_worker, "SessionLocal", sessionmaker(bind=db.get_bind(), future=True))
    monkeypatch.setattr(operation_worker, "get_settings", lambda: settings)
    monkeypatch.setattr(operation_worker, "run_scheduled_backup",
                        lambda session, **kwargs: run_scheduled_backup(session, find_offsite=NO_DRIVE, **kwargs))
    stop = operation_worker.Event()
    looks = {"count": 0}
    real = operation_worker._backup_look

    def look(worker_id: str, next_look: float) -> float:
        looks["count"] += 1
        stop.set()
        return real(worker_id, next_look)

    monkeypatch.setattr(operation_worker, "_backup_look", look)
    # A loop that never looks would run for ever: stop it, and fail on the count below.
    give_up = threading.Timer(20.0, stop.set)
    give_up.start()
    try:
        operation_worker.run_worker_loop(worker_id="backup-test-worker", poll_seconds=0.1, stop_event=stop)
    finally:
        give_up.cancel()
    assert looks["count"] == 1
    assert [backup.purpose for backup in list_backups(_folder(settings))] == ["scheduled"]
    assert db.scalar(select(func.count(AuditLog.id)).where(AuditLog.action == BACKUP_CREATED)) == 1


def test_the_tests_never_use_the_backups_of_the_machine_they_run_on():
    # .env names the running system's folder and schedule; conftest.py clears them for every test.
    settings = Settings()
    assert (settings.backup_directory, settings.backup_schedule_hours, settings.backup_offsite_folder) == ("", 0.0, "")


def test_backup_settings_are_checked(monkeypatch):
    for name in ("ATDR_BACKUP_SCHEDULE_HOURS", "ATDR_BACKUP_KEEP_DAILY", "ATDR_BACKUP_KEEP_WEEKLY", "ATDR_BACKUP_KEEP_MONTHLY"):
        assert f"{name} cannot be negative." in validate_runtime_settings(Settings(**{name: -1}))
        assert f"{name} cannot be negative." not in validate_runtime_settings(Settings())
    none_kept = Settings(ATDR_BACKUP_KEEP_DAILY=0, ATDR_BACKUP_KEEP_WEEKLY=0, ATDR_BACKUP_KEEP_MONTHLY=0)
    assert any("cannot all be zero" in issue for issue in validate_runtime_settings(none_kept))
    assert not any("cannot all be zero" in issue for issue in validate_runtime_settings(Settings(ATDR_BACKUP_KEEP_WEEKLY=0, ATDR_BACKUP_KEEP_MONTHLY=0)))
    assert any("ATDR_BACKUP_OFFSITE_FOLDER" in issue for issue in validate_runtime_settings(Settings(ATDR_BACKUP_OFFSITE_FOLDER="E:/ATDR-backups")))
    assert not any("ATDR_BACKUP_OFFSITE_FOLDER" in issue for issue in validate_runtime_settings(Settings(ATDR_BACKUP_OFFSITE_FOLDER="")))
    for name in ("ATDR_BACKUP_DIRECTORY", "ATDR_BACKUP_SCHEDULE_HOURS", "ATDR_BACKUP_OFFSITE_FOLDER"):
        monkeypatch.delenv(name)
    defaults = Settings(_env_file=None)
    assert (defaults.backup_schedule_hours, defaults.backup_keep_daily, defaults.backup_keep_weekly, defaults.backup_keep_monthly,
            defaults.backup_offsite_folder, defaults.backup_directory) == (0.0, 7, 4, 6, "ATDR-backups", "")
