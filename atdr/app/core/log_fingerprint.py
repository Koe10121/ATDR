from __future__ import annotations

import hashlib
from typing import Any


def raw_line_fingerprint(raw_line: str) -> str:
    """Return a stable content fingerprint without storing or exposing raw evidence."""

    return hashlib.sha256(raw_line.encode("utf-8", errors="surrogatepass")).hexdigest()


def raw_line_fingerprint_default(context: Any) -> str:
    """Populate fingerprints for direct ORM inserts as well as ingestion services."""

    parameters = context.get_current_parameters()
    return raw_line_fingerprint(str(parameters.get("raw_line") or ""))
