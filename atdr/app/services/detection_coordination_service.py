from __future__ import annotations

import time

from sqlalchemy import text
from sqlalchemy.orm import Session


DETECTION_ADVISORY_LOCK_KEY = 4_286_394_017


class DetectionCoordinationTimeout(RuntimeError):
    """Raised when another PostgreSQL detection transaction owns the lock."""


def acquire_detection_transaction_lock(
    db: Session,
    *,
    timeout_seconds: float = 30.0,
    poll_seconds: float = 0.05,
) -> float:
    """Serialize PostgreSQL alert/dedup writes while leaving SQLite unchanged."""

    if db.get_bind().dialect.name != "postgresql":
        return 0.0

    started = time.perf_counter()
    deadline = started + max(0.1, float(timeout_seconds))
    while True:
        acquired = bool(
            db.scalar(
                text("SELECT pg_try_advisory_xact_lock(:lock_key)"),
                {"lock_key": DETECTION_ADVISORY_LOCK_KEY},
            )
        )
        if acquired:
            return time.perf_counter() - started
        if time.perf_counter() >= deadline:
            raise DetectionCoordinationTimeout(
                "Another detection transaction is still committing alert evidence."
            )
        time.sleep(max(0.01, float(poll_seconds)))
