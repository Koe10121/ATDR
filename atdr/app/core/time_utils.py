from __future__ import annotations

from datetime import UTC, datetime
from typing import Any


def parse_timestamp(value: Any) -> datetime | None:
    """Parse an ISO-8601 string (or pass through a datetime) to a UTC-aware datetime.

    Accepts a trailing "Z" as UTC. Returns None for anything unparseable.
    """
    if isinstance(value, datetime):
        parsed = value
    else:
        text = str(value or "").strip()
        if not text:
            return None
        try:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)
