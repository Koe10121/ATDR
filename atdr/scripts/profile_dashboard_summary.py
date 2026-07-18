import argparse
import hashlib
import json
import math
import statistics
import time
from copy import deepcopy
from datetime import datetime
from typing import Any, Callable

from sqlalchemy import desc, event, func, select

from atdr.app.db.database import SessionLocal
from atdr.app.db.models import Alert, DetectionRun, IngestionRun, NormalizedLog, RawLog
from atdr.app.services import dashboard_service
from atdr.app.services.dashboard_service import (
    _dashboard_cache_signature_statement,
    _quality_app_counts_statement,
    _quality_missing_counts_statement,
    build_dashboard_summary,
    build_dashboard_summary_cached,
    clear_dashboard_summary_cache,
)


def _json_default(value: Any) -> str:
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def _timed(name: str, fn: Callable[[], Any]) -> dict[str, Any]:
    started = time.perf_counter()
    result = fn()
    seconds = round(time.perf_counter() - started, 4)
    return {"name": name, "seconds": seconds, "result": result}


def _compact_result(value: Any) -> Any:
    if isinstance(value, list):
        return {"rows": len(value), "sample": value[:3]}
    if isinstance(value, dict):
        keys = list(value.keys())
        compact = {key: value[key] for key in keys[:10]}
        if len(keys) > 10:
            compact["additional_keys"] = len(keys) - 10
        return compact
    return value


def _percentile(values: list[float], percentile: float) -> float:
    ordered = sorted(values)
    position = (len(ordered) - 1) * percentile
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    return ordered[lower] + ((ordered[upper] - ordered[lower]) * (position - lower))


def _distribution(values: list[float]) -> dict[str, float]:
    return {
        "min": round(min(values), 6),
        "median": round(statistics.median(values), 6),
        "p95": round(_percentile(values, 0.95), 6),
        "max": round(max(values), 6),
    }


def _stable_payload_fingerprint(payload: dict[str, Any]) -> str:
    stable = deepcopy(payload)
    stable.pop("performance", None)
    for alert in stable.get("recent_alerts", []):
        sla = alert.get("sla")
        if isinstance(sla, dict):
            sla.pop("age_minutes", None)
            sla.pop("minutes_remaining", None)
    rendered = json.dumps(stable, sort_keys=True, default=_json_default, separators=(",", ":"))
    return hashlib.sha256(rendered.encode("utf-8")).hexdigest()


def _measure_application_cache(runs: int) -> tuple[list[dict[str, Any]], str]:
    measurements: list[dict[str, Any]] = []
    dialect = "unknown"
    for run_number in range(1, max(1, runs) + 1):
        with SessionLocal() as db:
            bind = db.get_bind()
            dialect = bind.dialect.name
            query_count = 0
            query_seconds = 0.0

            def before_cursor_execute(conn, cursor, statement, parameters, context, executemany):
                nonlocal query_count
                query_count += 1
                context._atdr_profile_started = time.perf_counter()

            def after_cursor_execute(conn, cursor, statement, parameters, context, executemany):
                nonlocal query_seconds
                query_seconds += time.perf_counter() - context._atdr_profile_started

            event.listen(bind, "before_cursor_execute", before_cursor_execute)
            event.listen(bind, "after_cursor_execute", after_cursor_execute)
            try:
                clear_dashboard_summary_cache()
                cold_query_start = query_count
                cold_query_seconds_start = query_seconds
                started = time.perf_counter()
                cold_payload = build_dashboard_summary_cached(db)
                cold_seconds = time.perf_counter() - started
                cold_queries = query_count - cold_query_start
                cold_database_seconds = query_seconds - cold_query_seconds_start

                warm_query_start = query_count
                warm_query_seconds_start = query_seconds
                started = time.perf_counter()
                warm_payload = build_dashboard_summary_cached(db)
                warm_seconds = time.perf_counter() - started
                warm_queries = query_count - warm_query_start
                warm_database_seconds = query_seconds - warm_query_seconds_start
            finally:
                event.remove(bind, "after_cursor_execute", after_cursor_execute)
                event.remove(bind, "before_cursor_execute", before_cursor_execute)

        cold_fingerprint = _stable_payload_fingerprint(cold_payload)
        warm_fingerprint = _stable_payload_fingerprint(warm_payload)
        measurements.append(
            {
                "run": run_number,
                "cold_seconds": round(cold_seconds, 6),
                "cold_database_seconds": round(cold_database_seconds, 6),
                "cold_query_count": cold_queries,
                "warm_seconds": round(warm_seconds, 6),
                "warm_database_seconds": round(warm_database_seconds, 6),
                "warm_query_count": warm_queries,
                "response_field_count": len(cold_payload),
                "response_fingerprint": cold_fingerprint,
                "warm_response_equal": cold_fingerprint == warm_fingerprint,
            }
        )
    return measurements, dialect


def _sqlite_query_plans() -> dict[str, list[str]]:
    with SessionLocal() as db:
        bind = db.get_bind()
        if bind.dialect.name != "sqlite":
            return {}
        plans: dict[str, list[str]] = {}
        statements = {
            "quality_missing_counts": _quality_missing_counts_statement(),
            "quality_app_counts": _quality_app_counts_statement(),
            "cache_signature": _dashboard_cache_signature_statement(),
        }
        for name, statement in statements.items():
            compiled = statement.compile(bind, compile_kwargs={"literal_binds": True})
            rows = db.connection().exec_driver_sql(f"EXPLAIN QUERY PLAN {compiled}").all()
            plans[name] = [str(row[3]) for row in rows]
        return plans


def profile_dashboard_summary(*, include_full_summary: bool = True, runs: int = 1) -> dict[str, Any]:
    """Profile dashboard summary pieces without writing to the database."""

    with SessionLocal() as db:
        steps = [
            _timed("count_normalized_logs", lambda: int(db.scalar(select(func.count(NormalizedLog.id))) or 0)),
            _timed("count_raw_logs", lambda: int(db.scalar(select(func.count(RawLog.id))) or 0)),
            _timed("count_alerts", lambda: int(db.scalar(select(func.count(Alert.id))) or 0)),
            _timed(
                "alert_severity_counts",
                lambda: {
                    str(severity): int(count)
                    for severity, count in db.execute(select(Alert.severity, func.count(Alert.id)).group_by(Alert.severity)).all()
                },
            ),
            _timed(
                "alert_status_counts",
                lambda: {
                    str(status): int(count)
                    for status, count in db.execute(select(Alert.status, func.count(Alert.id)).group_by(Alert.status)).all()
                },
            ),
            _timed(
                "top_alert_types",
                lambda: [
                    {"name": str(alert_type), "count": int(count)}
                    for alert_type, count in db.execute(
                        select(Alert.alert_type, func.count(Alert.id))
                        .group_by(Alert.alert_type)
                        .order_by(desc(func.count(Alert.id)))
                        .limit(10)
                    ).all()
                ],
            ),
            _timed("quality_aggregate", lambda: dashboard_service._quality_aggregate(db)),
            _timed(
                "parser_error_count",
                lambda: dashboard_service._parser_error_count(
                    db,
                    int(db.scalar(select(func.count(NormalizedLog.id))) or 0),
                ),
            ),
            _timed(
                "ingestion_stats",
                lambda: dashboard_service._ingestion_stats(
                    db,
                    int(db.scalar(select(func.count(NormalizedLog.id))) or 0),
                    parse_failures=dashboard_service._parser_error_count(
                        db,
                        int(db.scalar(select(func.count(NormalizedLog.id))) or 0),
                    ),
                ),
            ),
            _timed("alert_occurrence_count", lambda: dashboard_service._alert_occurrence_count(db)),
            _timed(
                "latest_runs",
                lambda: {
                    "latest_ingestion_run_id": db.scalar(select(func.max(IngestionRun.id))),
                    "latest_detection_run_id": db.scalar(select(func.max(DetectionRun.id))),
                },
            ),
        ]
        if include_full_summary:
            steps.append(_timed("full_dashboard_summary_uncached", lambda: build_dashboard_summary(db)))
        clear_dashboard_summary_cache()
        first_cached = _timed("dashboard_summary_cached_first", lambda: build_dashboard_summary_cached(db))
        second_cached = _timed("dashboard_summary_cached_hit", lambda: build_dashboard_summary_cached(db))
        steps.extend([first_cached, second_cached])

    cache_runs, dialect = _measure_application_cache(runs)
    cache_distribution = {
        "cold_seconds": _distribution([item["cold_seconds"] for item in cache_runs]),
        "warm_seconds": _distribution([item["warm_seconds"] for item in cache_runs]),
    }
    timings = {step["name"]: step["seconds"] for step in steps}
    slowest_steps = sorted(
        ({"name": step["name"], "seconds": step["seconds"]} for step in steps),
        key=lambda item: item["seconds"],
        reverse=True,
    )[:8]
    warnings = [
        f"{name} took {seconds}s; investigate before production-like shared lab claims."
        for name, seconds in timings.items()
        if seconds > (2.0 if name.startswith("full_") or name.endswith("_first") else 1.0)
    ]
    if cache_distribution["cold_seconds"]["p95"] > 3.0:
        warnings.append("Cold application-cache Overview p95 exceeds the 3.0s v4.7 target.")
    if cache_distribution["warm_seconds"]["p95"] > 0.05:
        warnings.append("Warm cached Overview p95 exceeds the 0.05s v4.7 target.")
    return {
        "ok": True,
        "read_only": True,
        "database_dialect": dialect,
        "include_full_summary": include_full_summary,
        "measurement_runs": len(cache_runs),
        "timings": timings,
        "slowest_steps": slowest_steps,
        "step_results": {
            step["name"]: _compact_result(step["result"])
            for step in steps
            if not step["name"].startswith("full_dashboard_summary")
            and not step["name"].startswith("dashboard_summary_cached")
        },
        "application_cache_runs": cache_runs,
        "application_cache_distribution": cache_distribution,
        "all_responses_equal": len({item["response_fingerprint"] for item in cache_runs}) == 1
        and all(item["warm_response_equal"] for item in cache_runs),
        "query_plans": _sqlite_query_plans(),
        "warnings": warnings,
        "probable_cause": (
            "Use the slowest-step timings, query counts, and query plans above. The v4.7 query shape avoids a wide "
            "normalized_logs quality scan by using existing indexes and keeps cache freshness checks in one statement."
        ),
        "production_ready": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Profile ATDR dashboard summary query timing without mutating data.")
    parser.add_argument("--skip-full-summary", action="store_true")
    parser.add_argument("--runs", type=int, default=5)
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()
    result = profile_dashboard_summary(include_full_summary=not args.skip_full_summary, runs=max(1, args.runs))
    print(json.dumps(result, indent=2 if args.pretty else None, default=_json_default))
    raise SystemExit(0 if result.get("ok") else 1)


if __name__ == "__main__":
    main()
