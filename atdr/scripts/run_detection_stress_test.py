import argparse
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from atdr.app.core.config import PROJECT_ROOT
from atdr.app.db.database import SessionLocal, init_db
from atdr.app.services.alert_service import list_alerts
from atdr.app.services.case_service import list_alert_cases
from atdr.app.services.dashboard_service import build_dashboard_summary
from atdr.app.services.detection_service import run_detection
from atdr.app.services.log_service import count_nonblank_log_lines, import_log_file
from atdr.app.services.source_service import get_or_create_source
from atdr.scripts.detection_reliability_common import RELIABILITY_OUTPUT_DIR, json_default, write_report_files
from atdr.scripts.run_source_scenario import SCENARIOS, _temp_session_factory


DEFAULT_SCENARIOS = ["normal_allowed_traffic", "port_scan_like_traffic", "mixed_small_subnet_validation"]
SCENARIO_DIR = PROJECT_ROOT / "data" / "samples" / "scenarios"


def _timed(fn) -> tuple[Any, float]:
    started = time.perf_counter()
    result = fn()
    return result, round(time.perf_counter() - started, 4)


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# ATDR Detection Stress Test",
        "",
        f"- Generated at: {report['generated_at']}",
        f"- Database mode: {'temporary SQLite' if report['use_temp_db'] else 'current local database'}",
        f"- Rows imported: {report['rows_imported']}",
        f"- Alerts created: {report['detection'].get('created_alerts')}",
        f"- Detection seconds: {report['timings']['detection_seconds']}",
        f"- Warnings: {len(report['warnings'])}",
        "",
        "## Warnings",
        "",
    ]
    for warning in report["warnings"] or ["None."]:
        lines.append(f"- {warning}")
    return "\n".join(lines)


def run_detection_stress_test(
    *,
    scenarios: list[str] | None = None,
    iterations: int = 10,
    use_temp_db: bool = True,
    write_output: bool = True,
    output_dir: Path = RELIABILITY_OUTPUT_DIR,
) -> dict[str, Any]:
    selected = scenarios or list(DEFAULT_SCENARIOS)
    unknown = sorted(set(selected) - set(SCENARIOS))
    if unknown:
        raise ValueError(f"Unknown scenario(s): {', '.join(unknown)}")
    temp_engine = None
    if use_temp_db:
        temp_engine, SessionFactory = _temp_session_factory()
    else:
        init_db()
        SessionFactory = SessionLocal

    try:
        with SessionFactory() as db:
            source = get_or_create_source(db, name="stress-validation-source", source_type="sample", parser_profile="palo_alto")
            db.commit()
            rows_available = sum(count_nonblank_log_lines(SCENARIO_DIR / SCENARIOS[name].filename) for name in selected)
            import_results: list[dict[str, Any]] = []

            def import_all() -> None:
                for _ in range(max(1, iterations)):
                    for name in selected:
                        spec = SCENARIOS[name]
                        import_results.append(
                            import_log_file(
                                db,
                                SCENARIO_DIR / spec.filename,
                                actor="detection_stress_test",
                                source_id=source.id,
                                parser_profile=spec.default_parser_profile,
                            )
                        )

            _, ingestion_seconds = _timed(import_all)
            rows_imported = sum(int(item.get("raw_logs_imported") or item.get("imported") or 0) for item in import_results)
            detection, detection_seconds = _timed(
                lambda: run_detection(
                    db,
                    limit=max(100, rows_imported * 2),
                    use_ml=False,
                    actor="detection_stress_test",
                    source_id=source.id,
                    source_name=source.name,
                    source_type=source.source_type,
                )
            )
            alerts, alert_query_seconds = _timed(lambda: list_alerts(db, source_id=source.id, limit=100))
            cases, case_query_seconds = _timed(lambda: list_alert_cases(db, source_id=source.id, limit=50))
            summary, dashboard_seconds = _timed(lambda: build_dashboard_summary(db))
    finally:
        if temp_engine is not None:
            temp_engine.dispose()

    timings = {
        "ingestion_seconds": ingestion_seconds,
        "detection_seconds": detection_seconds,
        "alert_query_seconds": alert_query_seconds,
        "case_query_seconds": case_query_seconds,
        "dashboard_summary_seconds": dashboard_seconds,
    }
    warnings: list[str] = []
    budgets = {
        "ingestion_seconds": max(5.0, rows_imported / 500),
        "detection_seconds": max(5.0, rows_imported / 500),
        "alert_query_seconds": 1.0,
        "case_query_seconds": 1.0,
        "dashboard_summary_seconds": 2.0,
    }
    for key, seconds in timings.items():
        if seconds > budgets[key]:
            warnings.append(f"{key} took {seconds}s; local lab budget is {budgets[key]}s.")

    report = {
        "ok": not warnings,
        "generated_at": datetime.now(timezone.utc),
        "validation_scope": "safe synthetic detection stress test",
        "use_temp_db": use_temp_db,
        "scenarios": selected,
        "iterations": iterations,
        "rows_available_per_iteration": rows_available,
        "rows_imported": rows_imported,
        "detection": detection,
        "alert_count": len(alerts),
        "case_count": len(cases),
        "dashboard_total_logs": summary.get("total_logs"),
        "timings": timings,
        "warnings": warnings,
        "safety": {
            "automatic_response_enabled": False,
            "real_firewall_blocking_enabled": False,
            "production_readiness_claim": False,
            "safe_synthetic_data_only": True,
        },
    }
    if write_output:
        report["paths"] = write_report_files(
            report,
            output_dir=output_dir,
            stem_prefix="detection_stress_test",
            markdown=render_markdown(report),
        )
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description="Run safe synthetic ATDR detection stress validation.")
    parser.add_argument("--scenario", action="append", choices=sorted(SCENARIOS))
    parser.add_argument("--iterations", type=int, default=10)
    parser.add_argument("--use-temp-db", action="store_true", default=True)
    parser.add_argument("--write-to-current-db", action="store_true")
    parser.add_argument("--no-report", action="store_true")
    parser.add_argument("--output-dir", default=None)
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()
    report = run_detection_stress_test(
        scenarios=args.scenario,
        iterations=args.iterations,
        use_temp_db=not args.write_to_current_db,
        write_output=not args.no_report,
        output_dir=Path(args.output_dir) if args.output_dir else RELIABILITY_OUTPUT_DIR,
    )
    print(json.dumps(report, default=json_default, indent=2 if args.pretty else None))
    raise SystemExit(0 if report["ok"] else 1)


if __name__ == "__main__":
    main()
