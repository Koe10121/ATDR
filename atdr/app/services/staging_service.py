from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import re
import shutil
import socket
from typing import Any, BinaryIO
from uuid import uuid4

from atdr.app.core.config import PROJECT_ROOT, get_settings


STAGING_ROOT = PROJECT_ROOT / ".atdr_runtime" / "operation-jobs"
_SAFE_FILENAME = re.compile(r"[^A-Za-z0-9._-]+")


class StagingPressureError(RuntimeError):
    """Raised when staging would exceed a configured storage safety boundary."""


class StagedInputError(ValueError):
    """Raised when a staged input is missing, unsafe, expired, or changed."""


@dataclass(frozen=True)
class StagedInputMetadata:
    path: Path
    storage_key: str
    storage_id: str
    safe_name: str
    byte_count: int
    fingerprint: str
    available_lines: int


def safe_filename(filename: str | None) -> str:
    candidate = Path(filename or "uploaded-log.txt").name
    candidate = _SAFE_FILENAME.sub("-", candidate).strip(".-")
    return (candidate or "uploaded-log.txt")[:120]


def configured_staging_root() -> Path:
    configured = get_settings().operation_staging_root.strip()
    if not configured:
        return STAGING_ROOT.resolve()
    path = Path(configured).expanduser()
    return (path if path.is_absolute() else PROJECT_ROOT / path).resolve()


def effective_staging_storage_id() -> str:
    settings = get_settings()
    configured = settings.operation_staging_storage_id.strip()[:96] or "local"
    if settings.operation_staging_shared:
        return configured
    hostname = _SAFE_FILENAME.sub("-", socket.gethostname().lower()).strip(".-")[:64] or "host"
    local_label = "" if configured.lower() == "local" else f":{configured}"
    return f"local{local_label}:{hostname}"[:128]


def staged_payload_fields(metadata: StagedInputMetadata) -> dict[str, str]:
    return {
        "staged_input_key": metadata.storage_key,
        "staging_storage_id": metadata.storage_id,
    }


def _resolved_staging_root() -> Path:
    return configured_staging_root()


def staging_usage_bytes() -> int:
    root = configured_staging_root()
    if not root.exists():
        return 0
    total = 0
    for entry in root.iterdir():
        try:
            if entry.is_file() and not entry.is_symlink():
                total += entry.stat().st_size
        except OSError:
            continue
    return total


def staging_pressure_state(*, max_total_bytes: int, min_free_bytes: int) -> dict[str, int | str | bool]:
    root = configured_staging_root()
    root.mkdir(parents=True, exist_ok=True)
    used = staging_usage_bytes()
    free = int(shutil.disk_usage(root).free)
    pressure = used >= max(1, int(max_total_bytes)) or free < max(0, int(min_free_bytes))
    return {
        "state": "pressure" if pressure else "healthy",
        "pressure": pressure,
        "used_bytes": used,
        "max_total_bytes": max(1, int(max_total_bytes)),
        "free_bytes": free,
        "min_free_bytes": max(0, int(min_free_bytes)),
    }


def _count_nonblank_lines(path: Path) -> int:
    with path.open("r", encoding="utf-8", errors="replace", newline="") as stream:
        return sum(1 for line in stream if line.strip())


def inspect_staged_path(path: Path, *, count_lines: bool = True) -> StagedInputMetadata:
    digest = hashlib.sha256()
    byte_count = 0
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
            byte_count += len(chunk)
    return StagedInputMetadata(
        path=path,
        storage_key=path.name,
        storage_id=effective_staging_storage_id(),
        safe_name=path.name.split("-", 1)[-1][:120] or "uploaded-log.txt",
        byte_count=byte_count,
        fingerprint=digest.hexdigest(),
        available_lines=_count_nonblank_lines(path) if count_lines else 0,
    )


def stage_upload_for_job(
    stream: BinaryIO,
    *,
    filename: str | None,
    max_bytes: int | None = None,
    staging_max_total_bytes: int | None = None,
    staging_min_free_bytes: int | None = None,
) -> StagedInputMetadata:
    """Stream an upload into ignored runtime storage while enforcing disk and size limits."""

    settings = get_settings()
    input_limit = int(max_bytes or settings.operation_job_max_input_bytes)
    total_limit = int(staging_max_total_bytes or settings.operation_staging_max_total_bytes)
    minimum_free = int(
        settings.operation_staging_min_free_bytes if staging_min_free_bytes is None else staging_min_free_bytes
    )
    if input_limit <= 0 or total_limit <= 0 or minimum_free < 0:
        raise ValueError("Queued upload storage limits are not configured safely.")

    safe_name = safe_filename(filename)
    root = configured_staging_root()
    root.mkdir(parents=True, exist_ok=True)
    pressure = staging_pressure_state(max_total_bytes=total_limit, min_free_bytes=minimum_free)
    if bool(pressure["pressure"]):
        raise StagingPressureError("Import staging is temporarily unavailable because storage safety limits were reached.")

    initial_usage = int(pressure["used_bytes"])
    target = root / f"{uuid4().hex}-{safe_name}"
    temporary = target.with_suffix(f"{target.suffix}.part")
    written = 0
    digest = hashlib.sha256()
    try:
        with temporary.open("wb") as handle:
            while True:
                chunk = stream.read(1024 * 1024)
                if not chunk:
                    break
                written += len(chunk)
                if written > input_limit:
                    raise ValueError(f"Queued upload exceeds the {input_limit // (1024 * 1024)} MB safety limit.")
                if initial_usage + written > total_limit:
                    raise StagingPressureError("Import staging total-size limit would be exceeded.")
                if shutil.disk_usage(root).free - len(chunk) < minimum_free:
                    raise StagingPressureError("Import staging stopped before the minimum free-space boundary was crossed.")
                digest.update(chunk)
                handle.write(chunk)
        os.replace(temporary, target)
        return StagedInputMetadata(
            path=target,
            storage_key=target.name,
            storage_id=effective_staging_storage_id(),
            safe_name=safe_name,
            byte_count=written,
            fingerprint=digest.hexdigest(),
            available_lines=_count_nonblank_lines(target),
        )
    except Exception:
        temporary.unlink(missing_ok=True)
        target.unlink(missing_ok=True)
        raise


def staged_path(payload: dict[str, Any], *, require_exists: bool = True) -> Path:
    expected_storage = effective_staging_storage_id()
    payload_storage = str(payload.get("staging_storage_id") or "").strip()
    if payload_storage and payload_storage != expected_storage:
        raise StagedInputError("Queued import belongs to a different staging storage deployment.")

    storage_key = str(payload.get("staged_input_key") or "").strip()
    if storage_key:
        key_path = Path(storage_key)
        if key_path.is_absolute() or len(key_path.parts) != 1 or key_path.name != storage_key:
            raise StagedInputError("Queued import staging key is invalid.")
        path = (_resolved_staging_root() / storage_key).resolve()
    else:
        raw = str(payload.get("staged_input") or "")
        if not raw:
            raise StagedInputError("Queued import has no staged input.")
        path = Path(raw).resolve()
    try:
        path.relative_to(_resolved_staging_root())
    except ValueError as exc:
        raise StagedInputError("Queued import staging location is invalid.") from exc
    if require_exists and (not path.exists() or not path.is_file() or path.is_symlink()):
        raise StagedInputError("Queued import staging file is unavailable. Upload the file again.")
    return path


def validate_staged_payload(payload: dict[str, Any]) -> tuple[Path, StagedInputMetadata]:
    path = staged_path(payload)
    metadata = inspect_staged_path(path)
    expected_size = payload.get("input_bytes")
    expected_fingerprint = str(payload.get("input_fingerprint") or "").strip().lower()
    if expected_size is not None and int(expected_size) != metadata.byte_count:
        raise StagedInputError("Queued import staging file size changed; resume is blocked.")
    if expected_fingerprint and expected_fingerprint != metadata.fingerprint:
        raise StagedInputError("Queued import staging fingerprint changed; resume is blocked.")
    return path, metadata


def cleanup_staged_payload(payload: dict[str, Any] | None) -> bool:
    if not isinstance(payload, dict) or not (payload.get("staged_input_key") or payload.get("staged_input")):
        return False
    try:
        path = staged_path(payload, require_exists=False)
    except StagedInputError:
        return False
    if not path.exists() or not path.is_file() or path.is_symlink():
        return False
    path.unlink(missing_ok=True)
    return True


def resume_window_open(expires_at: datetime | None) -> bool:
    if expires_at is None:
        return False
    value = expires_at if expires_at.tzinfo is not None else expires_at.replace(tzinfo=timezone.utc)
    return value > datetime.now(timezone.utc)
