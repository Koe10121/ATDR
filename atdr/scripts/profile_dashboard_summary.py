import argparse
import json
import time
from datetime import datetime
from typing import Any, Callable

from sqlalchemy import desc, func, select

from atdr.app.db.database import SessionLocal
from atdr.app.db.models import Alert, DetectionRun, IngestionRun, NormalizedLog, RawLog
from atdr.app.services import dashboard_service
from atdr.app.services.dashboard_service import (
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


def profile_dashboard_summary(*, include_full_summary: bool = True) -> dict[str, Any]:
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
    return {
        "ok": True,
        "read_only": True,
        "include_full_summary": include_full_summary,
        "timings": timings,
        "slowest_steps": slowest_steps,
        "step_results": {
            step["name"]: _compact_result(step["result"])
            for step in steps
            if not step["name"].startswith("full_dashboard_summary")
            and not step["name"].startswith("dashboard_summary_cached")
        },
        "warnings": warnings,
        "probable_cause": (
            "Cold Overview time is dominated by the slowest steps above. Cached summary hits should remain fast; "
            "if uncached summary is slow, prefer targeted query/index/caching work or PostgreSQL shared-lab validation."
        ),
        "production_ready": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Profile ATDR dashboard summary query timing without mutating data.")
    parser.add_argument("--skip-full-summary", action="store_true")
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()
    result = profile_dashboard_summary(include_full_summary=not args.skip_full_summary)
    print(json.dumps(result, indent=2 if args.pretty else None, default=_json_default))
    raise SystemExit(0 if result.get("ok") else 1)


if __name__ == "__main__":
    main()
