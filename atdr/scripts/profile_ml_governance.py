from __future__ import annotations

import argparse
import hashlib
import json
import time
from typing import Any

from sqlalchemy import event

from atdr.app.db.database import SessionLocal, engine
from atdr.app.services.ml_service import evaluation_report


def _fingerprint(value: dict[str, Any]) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        default=str,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Profile cold/warm AI Governance evaluation responses without "
            "mutating logs, labels, alerts, models, or responses."
        )
    )
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()

    query_count = 0
    query_seconds = 0.0
    starts: list[float] = []

    def before_cursor_execute(*_args) -> None:
        nonlocal query_count
        query_count += 1
        starts.append(time.perf_counter())

    def after_cursor_execute(*_args) -> None:
        nonlocal query_seconds
        query_seconds += time.perf_counter() - starts.pop()

    event.listen(engine, "before_cursor_execute", before_cursor_execute)
    event.listen(engine, "after_cursor_execute", after_cursor_execute)
    try:
        with SessionLocal() as db:
            cold_query_start = query_count
            cold_db_start = query_seconds
            started = time.perf_counter()
            cold = evaluation_report(db)
            cold_seconds = time.perf_counter() - started
            cold_db_seconds = query_seconds - cold_db_start

            warm_query_start = query_count
            warm_db_start = query_seconds
            started = time.perf_counter()
            warm = evaluation_report(db)
            warm_seconds = time.perf_counter() - started
    finally:
        event.remove(
            engine,
            "before_cursor_execute",
            before_cursor_execute,
        )
        event.remove(
            engine,
            "after_cursor_execute",
            after_cursor_execute,
        )

    cold_fingerprint = _fingerprint(cold)
    warm_fingerprint = _fingerprint(warm)
    result = {
        "ok": cold_fingerprint == warm_fingerprint,
        "status": (
            "cold_warm_responses_equivalent"
            if cold_fingerprint == warm_fingerprint
            else "cold_warm_response_mismatch"
        ),
        "cold": {
            "seconds": round(cold_seconds, 6),
            "database_seconds": round(cold_db_seconds, 6),
            "query_count": warm_query_start - cold_query_start,
        },
        "warm": {
            "seconds": round(warm_seconds, 6),
            "database_seconds": round(
                query_seconds - warm_db_start,
                6,
            ),
            "query_count": query_count - warm_query_start,
        },
        "responses_equivalent": cold_fingerprint == warm_fingerprint,
        "response_fingerprint_exposed": False,
        "raw_logs_included": False,
        "ip_addresses_included": False,
        "private_paths_included": False,
        "labels_accessed": False,
        "model_activated": False,
        "response_automation_allowed": False,
        "secrets_exposed": False,
    }
    print(
        json.dumps(
            result,
            indent=2 if args.pretty else None,
        )
    )
    raise SystemExit(0 if result["ok"] else 1)


if __name__ == "__main__":
    main()
