"""ATDR backs its own database up: on a schedule, checked, thinned out by age, and copied off the laptop.

Backups used to be taken by hand, when someone remembered, into the folder the database is in. Now the worker
takes one whenever the newest scheduled backup is ATDR_BACKUP_SCHEDULE_HOURS old:

- the copy is persistence_service.create_database_backup (SQLite's backup API: consistent while ATDR runs);
- it counts only once its checksum matches and SQLite finds the copy healthy; a bad copy is removed;
- scheduled backups are thinned to the newest of each of the last days, weeks and months; a backup taken by
  hand or before a reset is never deleted;
- a drive on another physical disk that has the ATDR_BACKUP_OFFSITE_FOLDER folder at its top gets the newest
  backup whenever it is connected. A second partition of the database's own disk does not count: it is lost
  with that disk;
- a folder or a drive can come to hold the backups of more than one database (two computers that share it, or a
  one-off script that names a copy of the database while the folder still comes from .env): each database
  counts, thins and copies only the backups whose manifest names it.
"""

from __future__ import annotations

import json
import re
import shutil
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone, tzinfo
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from atdr.app.core.config import PROJECT_ROOT, Settings, get_settings
from atdr.app.db.models import AuditLog
from atdr.app.services.persistence_service import (
    _sqlite_integrity,
    _sqlite_path,
    create_database_backup,
    database_label,
    verify_database_backup_artifact,
)

PURPOSE_SCHEDULED = "scheduled"
PURPOSE_BEFORE_RESET = "before_reset"
ACTOR = "scheduled_backup"
BACKUP_CREATED = "database_backup_created"
BACKUP_FAILED = "database_backup_failed"
BACKUP_COPIED = "database_backup_copied_offsite"
# What a failure entry is about: the scheduled backup itself, or the copy to one drive ("offsite E:").
SCHEDULED = "scheduled"
# Inside the folder the database file is in (the project folder, for the configured database).
DEFAULT_FOLDER = Path("backups") / "scheduled"
# Kept beside the backups: which one was last copied to another disk, and when. That drive is usually unplugged.
OFFSITE_RECORD = "offsite-copy.json"
# How often the worker looks for a due backup or a newly connected drive.
BACKUP_LOOK_SECONDS = 300.0
# After a failed backup the next try waits this long, so a full disk is not written to at every look.
RETRY_AFTER_FAILURE = timedelta(hours=1)
# A failure that lasts is entered in the audit log once a day, not at every try.
SAME_FAILURE = timedelta(hours=24)
# Room a backup needs beyond the database's own size.
SPARE_BYTES = 512 * 1024 * 1024
# The System panel warns when the copy on another disk is older than this.
OFFSITE_STALE = timedelta(days=7)
COPY_CHUNK = 8 * 1024 * 1024
# The names create_database_backup gives, and a copy of one that has not finished.
BACKUP_NAME = re.compile(r"^atdr-[a-z]+-\d{8}T\d{6}Z-[0-9a-f]{8}\.(sqlite3|dump|backup)(\.partial)?$")
# A file with such a name and no manifest is a backup being written, until it has been left alone this long.
STRAY_AFTER_SECONDS = 3600.0
DRIVE_REMOVABLE, DRIVE_FIXED = 2, 3


@dataclass(frozen=True)
class BackupFile:
    path: Path
    manifest_path: Path
    created_at: datetime
    size_bytes: int
    purpose: str
    # The database it is a copy of (persistence_service.database_label); None when the manifest names none.
    source: str | None = None


@dataclass(frozen=True)
class Drive:
    root: Path
    name: str
    kind: int
    # The physical disk the drive is on, or None when the system will not say (a spanned volume).
    disk: int | None
    label: str


@dataclass(frozen=True)
class OffsiteFolder:
    """A folder for backups on another physical disk than the database's."""

    path: Path
    drive: str
    label: str


def backup_folder(settings: Settings) -> Path:
    configured = settings.backup_directory.strip()
    if configured:
        return Path(configured).expanduser()
    database = _sqlite_path(settings.database_url)
    return (database.parent if database is not None else PROJECT_ROOT) / DEFAULT_FOLDER


def _utc(moment: datetime) -> datetime:
    return moment if moment.tzinfo is not None else moment.replace(tzinfo=timezone.utc)


def list_backups(folder: Path, *, of: str | None = None) -> list[BackupFile]:
    """Backups in the folder that have both their manifest and their file, newest first; with `of`, that database's."""

    found: list[BackupFile] = []
    if not folder.is_dir():
        return found
    for manifest_path in folder.glob("*.manifest.json"):
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            name = str(manifest["artifact_name"])
            path = folder / name
            source = str(manifest["source"]) if manifest.get("source") else None
            if Path(name).name != name or not path.is_file() or (of is not None and source != of):
                continue
            found.append(BackupFile(
                path=path, manifest_path=manifest_path,
                created_at=_utc(datetime.fromisoformat(str(manifest["created_at"]).replace("Z", "+00:00"))),
                size_bytes=int(manifest["artifact_size_bytes"]), purpose=str(manifest.get("purpose") or "manual"),
                source=source,
            ))
        except (OSError, ValueError, KeyError, TypeError):
            continue
    return sorted(found, key=lambda backup: backup.created_at, reverse=True)


def _scheduled(backups: list[BackupFile]) -> list[BackupFile]:
    return [backup for backup in backups if backup.purpose == PURPOSE_SCHEDULED]


def own_backups(folder: Path, settings: Settings) -> list[BackupFile]:
    """The folder's backups of this database, newest first.

    Everything here that counts, deletes or copies backups goes by these, so that a backup of another database in
    the same folder or on the same drive can neither stand in for this one's, nor be deleted to make room for it,
    nor hold it up. A backup whose manifest names no database is nobody's: left where it is.
    """

    return list_backups(folder, of=database_label(settings.database_url))


def backup_due(settings: Settings, *, now: datetime, folder: Path | None = None) -> bool:
    every = float(settings.backup_schedule_hours)
    if every <= 0:
        return False
    scheduled = _scheduled(own_backups(folder or backup_folder(settings), settings))
    return not scheduled or now - scheduled[0].created_at >= timedelta(hours=every)


def _database_bytes(settings: Settings) -> int:
    path = _sqlite_path(settings.database_url)
    if path is None:
        return 0
    return sum(candidate.stat().st_size for candidate in (path, Path(f"{path}-wal")) if candidate.is_file())


def _free_bytes(folder: Path) -> int:
    return int(shutil.disk_usage(folder).free)


# Why a backup did not happen, in words for the page and the audit log.
FAILURE_WORDS = {
    "not_enough_free_space": "there is not enough free space for it",
    "backup_folder_unavailable": "the backup folder cannot be used",
    "backup_failed_verification": "the copy did not pass its check",
    "backup_failed": "the database could not be copied",
    "pg_dump_unavailable": "pg_dump is not installed",
    "copy_failed": "the copy could not be written",
    "copy_failed_verification": "the copy did not arrive whole",
}


def failure_words(status: Any) -> str:
    return FAILURE_WORDS.get(str(status), str(status).replace("_", " "))


class BackupRequired(RuntimeError):
    """An action that deletes data was refused because the backup that must come first did not succeed."""

    def __init__(self, status: Any) -> None:
        super().__init__(f"Nothing was deleted: the backup that comes first did not succeed ({failure_words(status)}).")
        self.status = str(status)


def backup_before_deleting(db: Session, *, settings: Settings | None = None, now: datetime | None = None) -> dict[str, Any] | None:
    """A checked backup of the database this session is on, or BackupRequired.

    None when that database is not a file: one kept in memory (the tests') has nothing a copy could save.
    """

    bound = (settings or get_settings()).model_copy(
        update={"database_url": db.get_bind().url.render_as_string(hide_password=False)}
    )
    if bound.database_url.startswith("sqlite") and _sqlite_path(bound.database_url) is None:
        return None
    result = take_backup(bound, purpose=PURPOSE_BEFORE_RESET, now=now)
    if not result.get("ok"):
        raise BackupRequired(result.get("status"))
    return {"artifact_name": result["artifact_name"], "folder": str(backup_folder(bound)), "size_bytes": result.get("size_bytes")}


def _remove(path: Path, manifest_path: Path) -> bool:
    """Takes a backup away, manifest first: whatever cannot be deleted just now is at least no longer counted."""

    try:
        manifest_path.unlink(missing_ok=True)
    except OSError:
        return False
    # A program that opened the backup as a database may have left its -wal and -shm files beside it.
    for leftover in (path, Path(f"{path}-wal"), Path(f"{path}-shm")):
        try:
            leftover.unlink(missing_ok=True)
        except OSError:
            pass  # open in another program: left as a stray file, which a later pass removes
    return True


def _remove_strays(folder: Path) -> None:
    """Backup files left without a manifest: a removal or a copy that could not finish.

    Only files that carry a backup's name, and only once they are an hour old: a newer one may be a backup
    another process is still writing, whose manifest comes last.
    """

    for stray in folder.glob("atdr-*"):
        try:
            if (
                BACKUP_NAME.match(stray.name) is None
                or stray.with_name(f"{stray.name}.manifest.json").exists()
                or time.time() - stray.stat().st_mtime < STRAY_AFTER_SECONDS
            ):
                continue
            stray.unlink(missing_ok=True)
        except OSError:
            continue


def _make_room(folder: Path, needed: int, settings: Settings) -> list[str]:
    """Deletes this database's oldest scheduled backups, never its newest, until the bytes needed are free."""

    deleted = []
    scheduled = _scheduled(own_backups(folder, settings))
    while len(scheduled) > 1 and _free_bytes(folder) < needed:
        oldest = scheduled.pop()
        if _remove(oldest.path, oldest.manifest_path):
            deleted.append(oldest.path.name)
    return deleted


def take_backup(
    settings: Settings, *, purpose: str, folder: Path | None = None, now: datetime | None = None
) -> dict[str, Any]:
    """One checked backup in the folder. Whatever goes wrong, nothing that is not a healthy backup counts as one."""

    target = folder or backup_folder(settings)
    try:
        target.mkdir(parents=True, exist_ok=True)
        _remove_strays(target)
        needed = _database_bytes(settings) + SPARE_BYTES
        made_room = _make_room(target, needed, settings)
        free = _free_bytes(target)
    except OSError as exc:
        return {"ok": False, "status": "backup_folder_unavailable", "error_type": exc.__class__.__name__}
    if free < needed:
        return {"ok": False, "status": "not_enough_free_space", "needed_bytes": needed, "free_bytes": free}
    try:
        result = create_database_backup(settings=settings, output_dir=target, execute=True, purpose=purpose, created_at=now)
    except Exception as exc:  # an unreadable database, a disk that filled while copying
        _remove_strays(target)
        return {"ok": False, "status": "backup_failed", "error_type": exc.__class__.__name__}
    if not result.get("ok"):
        return result
    path = Path(result["backup_path"])
    checked = verify_database_backup_artifact(backup_path=path)
    healthy = bool(checked.get("ok")) and (result.get("dialect") != "sqlite" or _sqlite_integrity(path))
    if not healthy:
        _remove(path, Path(result["manifest_path"]))
        return {"ok": False, "status": "backup_failed_verification", "artifact_name": path.name}
    return {**result, "verified": True, "artifact_name": path.name, "deleted_for_room": made_room}


def backups_to_delete(
    backups: list[BackupFile], *, keep_daily: int, keep_weekly: int, keep_monthly: int, zone: tzinfo | None = None
) -> list[BackupFile]:
    """Scheduled backups outside the ladder: the newest of each of the last days, weeks and months that have one."""

    scheduled = sorted(_scheduled(backups), key=lambda backup: backup.created_at, reverse=True)
    keep: set[Path] = set()
    for limit, period_of in (
        (keep_daily, lambda local: local.date()),
        (keep_weekly, lambda local: local.isocalendar()[:2]),
        (keep_monthly, lambda local: (local.year, local.month)),
    ):
        periods: set[Any] = set()
        for backup in scheduled:
            period = period_of(backup.created_at.astimezone(zone))
            if period in periods:
                continue
            if len(periods) >= limit:
                break
            periods.add(period)
            keep.add(backup.path)
    return [backup for backup in scheduled if backup.path not in keep]


def prune_backups(folder: Path, settings: Settings, *, zone: tzinfo | None = None) -> list[str]:
    deleted = []
    for backup in backups_to_delete(
        own_backups(folder, settings), keep_daily=settings.backup_keep_daily, keep_weekly=settings.backup_keep_weekly,
        keep_monthly=settings.backup_keep_monthly, zone=zone,
    ):
        if _remove(backup.path, backup.manifest_path):
            deleted.append(backup.path.name)
    return deleted


def _windows_drives() -> list[Drive]:
    """Every drive letter with its type, physical disk and label, read without administrator rights."""

    import ctypes
    from ctypes import wintypes

    kernel = ctypes.windll.kernel32
    kernel.CreateFileW.restype = ctypes.c_void_p
    kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD,
                                   wintypes.DWORD, ctypes.c_void_p]
    kernel.DeviceIoControl.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p,
                                       wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
    kernel.CloseHandle.argtypes = [ctypes.c_void_p]

    class DeviceNumber(ctypes.Structure):
        _fields_ = [("DeviceType", wintypes.DWORD), ("DeviceNumber", wintypes.DWORD), ("PartitionNumber", wintypes.DWORD)]

    kernel.SetErrorMode(0x0001)  # an empty card reader answers "not there" instead of opening a dialog
    mask = int(kernel.GetLogicalDrives())
    drives = []
    for letter in (chr(65 + index) for index in range(26) if mask & (1 << index)):
        root = f"{letter}:\\"
        disk = None
        # Access 0 is enough to ask which disk a volume is on, and needs no elevation.
        handle = kernel.CreateFileW(f"\\\\.\\{letter}:", 0, 0x1 | 0x2, None, 3, 0, None)
        if handle and handle != ctypes.c_void_p(-1).value:
            try:
                found, returned = DeviceNumber(), wintypes.DWORD(0)
                # IOCTL_STORAGE_GET_DEVICE_NUMBER
                if kernel.DeviceIoControl(handle, 0x2D1080, None, 0, ctypes.byref(found), ctypes.sizeof(found),
                                          ctypes.byref(returned), None):
                    disk = int(found.DeviceNumber)
            finally:
                kernel.CloseHandle(handle)
        label = ctypes.create_unicode_buffer(261)
        kernel.GetVolumeInformationW(root, label, 261, None, None, None, None, 0)
        drives.append(Drive(root=Path(root), name=f"{letter}:", kind=int(kernel.GetDriveTypeW(root)), disk=disk, label=label.value))
    return drives


def _holds(drive: Drive, path: Path) -> bool:
    try:
        path.resolve().relative_to(drive.root.resolve())
    except (OSError, ValueError):
        return False
    return True


def offsite_folders(settings: Settings, *, drives: Callable[[], list[Drive]] | None = None) -> list[OffsiteFolder]:
    """Connected drives that take the copy: the marker folder at the top, on another disk than the database's."""

    name = settings.backup_offsite_folder.strip()
    if not name:
        return []
    if drives is None:
        if sys.platform != "win32":
            return []
        drives = _windows_drives
    listed = [drive for drive in drives() if drive.kind in (DRIVE_REMOVABLE, DRIVE_FIXED)]
    database = _sqlite_path(settings.database_url) or PROJECT_ROOT
    # The longest root that holds the database is its drive (on Windows there is only one).
    homes = sorted((drive for drive in listed if _holds(drive, database)), key=lambda drive: len(str(drive.root)), reverse=True)
    home = homes[0] if homes else None
    main = backup_folder(settings)
    found = []
    for drive in listed:
        if home is not None and drive.root == home.root:
            continue
        if home is not None and home.disk is not None and drive.disk is not None:
            other_disk = drive.disk != home.disk
        else:
            # Where the system will not say which disk a volume is on, only a removable drive is surely another one.
            other_disk = drive.kind == DRIVE_REMOVABLE
        folder = drive.root / name
        if other_disk and folder != main and folder.is_dir():
            found.append(OffsiteFolder(path=folder, drive=drive.name, label=drive.label))
    return found


def _copy(source: Path, target: Path, still_alive: Callable[[], None] | None) -> None:
    partial = target.with_name(f"{target.name}.partial")
    with source.open("rb") as reader, partial.open("wb") as writer:
        while chunk := reader.read(COPY_CHUNK):
            writer.write(chunk)
            if still_alive is not None:
                still_alive()
    partial.replace(target)


def _offsite_records(folder: Path) -> dict[str, Any]:
    try:
        records = json.loads((folder / OFFSITE_RECORD).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return records if isinstance(records, dict) else {}


def read_offsite_record(folder: Path, settings: Settings) -> dict[str, Any] | None:
    """This database's last copy to another disk; the file has a record for each database the folder serves."""

    record = _offsite_records(folder).get(database_label(settings.database_url))
    return record if isinstance(record, dict) and record.get("copied_at") else None


def _write_offsite_record(folder: Path, settings: Settings, record: dict[str, Any]) -> None:
    records = {**_offsite_records(folder), database_label(settings.database_url): record}
    partial = folder / f"{OFFSITE_RECORD}.partial"
    partial.write_text(json.dumps(records, indent=2) + "\n", encoding="utf-8")
    # In one step: the API reads this file while the worker writes it.
    partial.replace(folder / OFFSITE_RECORD)


def copy_offsite(
    settings: Settings,
    offsite: OffsiteFolder,
    *,
    now: datetime,
    folder: Path | None = None,
    still_alive: Callable[[], None] | None = None,
    zone: tzinfo | None = None,
) -> dict[str, Any] | None:
    """The newest scheduled backup onto the other disk, checked there; None when that disk already has it."""

    main = folder or backup_folder(settings)
    scheduled = _scheduled(own_backups(main, settings))
    if not scheduled:
        return None
    newest = scheduled[0]
    target = offsite.path / newest.path.name
    target_manifest = offsite.path / newest.manifest_path.name
    if target.is_file() and target_manifest.is_file():
        return None
    failed = {"ok": False, "drive": offsite.drive, "artifact_name": newest.path.name}
    try:
        _remove_strays(offsite.path)
        deleted = _make_room(offsite.path, newest.size_bytes + SPARE_BYTES, settings)
        if _free_bytes(offsite.path) < newest.size_bytes + SPARE_BYTES:
            return {**failed, "status": "not_enough_free_space"}
        _copy(newest.path, target, still_alive)
        shutil.copyfile(newest.manifest_path, target_manifest)
        if not verify_database_backup_artifact(backup_path=target).get("ok"):
            _remove(target, target_manifest)
            return {**failed, "status": "copy_failed_verification"}
        deleted += prune_backups(offsite.path, settings, zone=zone)
    except OSError as exc:  # the drive was pulled out, or is write-protected
        try:
            _remove(target, target_manifest)
            target.with_name(f"{target.name}.partial").unlink(missing_ok=True)
        except OSError:
            pass
        return {**failed, "status": "copy_failed", "error_type": exc.__class__.__name__}
    record = {"artifact_name": newest.path.name, "backup_created_at": newest.created_at.isoformat(),
              "copied_at": now.isoformat(), "drive": offsite.drive, "label": offsite.label}
    _write_offsite_record(main, settings, record)
    return {"ok": True, "status": "copied", **record, "size_bytes": newest.size_bytes, "deleted": deleted}


def _last_failure(db: Session, what: str) -> AuditLog | None:
    return db.scalar(
        select(AuditLog).where(AuditLog.action == BACKUP_FAILED, AuditLog.target_value == what)
        .order_by(AuditLog.id.desc()).limit(1)
    )


def _lasting(failure: AuditLog | None, *, since: datetime | None) -> AuditLog | None:
    """The failure, when nothing has succeeded since it."""

    if failure is None or (since is not None and since >= _utc(failure.created_at)):
        return None
    return failure


def _record_failure(db: Session, *, what: str, result: dict[str, Any], now: datetime, last_success: datetime | None) -> None:
    """One audit entry for a failure, not one for every try while its cause lasts."""

    lasting = _lasting(_last_failure(db, what), since=last_success)
    repeated = (
        lasting is not None and (lasting.details or {}).get("status") == result.get("status")
        and now - _utc(lasting.created_at) < SAME_FAILURE
    )
    if not repeated:
        db.add(AuditLog(actor=ACTOR, action=BACKUP_FAILED, target_type="database_backup", target_value=what,
                        details={key: value for key, value in result.items() if key != "ok"}, created_at=now))


def _copied_at(folder: Path, settings: Settings) -> datetime | None:
    record = read_offsite_record(folder, settings)
    return _utc(datetime.fromisoformat(record["copied_at"])) if record else None


def run_scheduled_backup(
    db: Session,
    *,
    settings: Settings | None = None,
    now: datetime | None = None,
    find_offsite: Callable[[Settings], list[OffsiteFolder]] = offsite_folders,
    still_alive: Callable[[], None] | None = None,
    zone: tzinfo | None = None,
) -> dict[str, Any]:
    """What the worker does at each look: the backup when one is due, then the copy to another disk when it can."""

    settings = settings or get_settings()
    now = _utc(now or datetime.now(timezone.utc))
    summary: dict[str, Any] = {"backup": None, "offsite": []}
    if float(settings.backup_schedule_hours) <= 0:
        return summary
    folder = backup_folder(settings)
    if backup_due(settings, now=now, folder=folder):
        scheduled = _scheduled(own_backups(folder, settings))
        last_success = scheduled[0].created_at if scheduled else None
        failure = _lasting(_last_failure(db, SCHEDULED), since=last_success)
        if failure is None or now - _utc(failure.created_at) >= RETRY_AFTER_FAILURE:
            if still_alive is not None:
                still_alive()
            result = take_backup(settings, purpose=PURPOSE_SCHEDULED, folder=folder, now=now)
            summary["backup"] = result
            if result.get("ok"):
                deleted = [*result["deleted_for_room"], *prune_backups(folder, settings, zone=zone)]
                db.add(AuditLog(actor=ACTOR, action=BACKUP_CREATED, target_type="database_backup",
                                target_value=str(result["artifact_name"]), created_at=now,
                                details={"purpose": PURPOSE_SCHEDULED, "size_bytes": result.get("size_bytes"),
                                         "folder": str(folder), "deleted": deleted}))
            else:
                _record_failure(db, what=SCHEDULED, result=result, now=now, last_success=last_success)
            db.commit()
    for offsite in find_offsite(settings):
        copied = copy_offsite(settings, offsite, now=now, folder=folder, still_alive=still_alive, zone=zone)
        if copied is None:
            continue
        summary["offsite"].append(copied)
        if copied.get("ok"):
            db.add(AuditLog(actor=ACTOR, action=BACKUP_COPIED, target_type="database_backup",
                            target_value=str(copied["artifact_name"]), created_at=now,
                            details={"drive": copied["drive"], "label": copied["label"],
                                     "size_bytes": copied["size_bytes"], "deleted": copied["deleted"]}))
        else:
            # Read before this try could have written it: the last copy that did work.
            _record_failure(db, what=f"offsite {offsite.drive}", result=copied, now=now,
                            last_success=_copied_at(folder, settings))
        db.commit()
    return summary


def backup_status(
    db: Session,
    *,
    settings: Settings | None = None,
    now: datetime | None = None,
    find_offsite: Callable[[Settings], list[OffsiteFolder]] = offsite_folders,
) -> dict[str, Any]:
    """What the System panel shows about backups."""

    settings = settings or get_settings()
    now = _utc(now or datetime.now(timezone.utc))
    folder = backup_folder(settings)
    every = float(settings.backup_schedule_hours)
    backups = own_backups(folder, settings)
    scheduled = _scheduled(backups)
    newest = scheduled[0] if scheduled else None
    age_hours = (now - newest.created_at).total_seconds() / 3600 if newest else None
    failure = _lasting(_last_failure(db, SCHEDULED), since=newest.created_at if newest else None)
    record = read_offsite_record(folder, settings)
    copied_at = _copied_at(folder, settings)
    wanted = bool(settings.backup_offsite_folder.strip()) and every > 0
    connected = find_offsite(settings) if wanted else []
    copy_failures = [
        lasting for lasting in (_lasting(_last_failure(db, f"offsite {item.drive}"), since=copied_at) for item in connected)
        if lasting is not None
    ]
    return {
        "scheduled": every > 0,
        "every_hours": every,
        "folder": str(folder),
        "folder_available": folder.is_dir(),
        "last": None if newest is None else {
            "name": newest.path.name, "created_at": newest.created_at, "size_bytes": newest.size_bytes,
            "age_hours": round(age_hours, 2),
        },
        "kept": len(scheduled),
        "kept_bytes": sum(backup.size_bytes for backup in scheduled),
        "other_backups": len(backups) - len(scheduled),
        "overdue": every > 0 and (age_hours is None or age_hours > float(settings.backup_max_age_hours)),
        "last_failure": None if failure is None else {
            "at": _utc(failure.created_at), "status": (failure.details or {}).get("status"),
        },
        "offsite": {
            "wanted": wanted,
            "folder_name": settings.backup_offsite_folder.strip(),
            "connected": [{"drive": item.drive, "label": item.label} for item in connected],
            "last_copy": None if record is None or copied_at is None else {
                "artifact_name": record.get("artifact_name"), "copied_at": copied_at, "drive": record.get("drive"),
                "label": record.get("label"), "age_days": round((now - copied_at).total_seconds() / 86400, 1),
            },
            "last_failure": None if not copy_failures else {
                "at": _utc(copy_failures[0].created_at), "status": (copy_failures[0].details or {}).get("status"),
                "drive": copy_failures[0].target_value.removeprefix("offsite "),
            },
            "stale": wanted and (copied_at is None or now - copied_at > OFFSITE_STALE),
        },
    }
