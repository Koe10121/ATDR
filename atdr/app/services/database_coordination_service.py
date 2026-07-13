from __future__ import annotations

from sqlalchemy import text
from sqlalchemy.engine import Connection
from sqlalchemy.orm import Session


# Stable project-specific advisory-lock key. It coordinates ATDR workers and
# ATDR backup commands only; it is not a substitute for database permissions.
ATDR_OPERATION_ADVISORY_LOCK_KEY = 4_286_394_001


def acquire_worker_operation_lock(db: Session) -> bool:
    if db.get_bind().dialect.name != "postgresql":
        return True
    return bool(
        db.scalar(
            text("SELECT pg_try_advisory_lock_shared(:lock_key)"),
            {"lock_key": ATDR_OPERATION_ADVISORY_LOCK_KEY},
        )
    )


def release_worker_operation_lock(db: Session) -> None:
    if db.get_bind().dialect.name != "postgresql":
        return
    db.execute(
        text("SELECT pg_advisory_unlock_shared(:lock_key)"),
        {"lock_key": ATDR_OPERATION_ADVISORY_LOCK_KEY},
    )


def acquire_backup_exclusive_lock(connection: Connection) -> bool:
    if connection.dialect.name != "postgresql":
        return True
    return bool(
        connection.execute(
            text("SELECT pg_try_advisory_lock(:lock_key)"),
            {"lock_key": ATDR_OPERATION_ADVISORY_LOCK_KEY},
        ).scalar()
    )


def release_backup_exclusive_lock(connection: Connection) -> None:
    if connection.dialect.name != "postgresql":
        return
    connection.execute(
        text("SELECT pg_advisory_unlock(:lock_key)"),
        {"lock_key": ATDR_OPERATION_ADVISORY_LOCK_KEY},
    )
