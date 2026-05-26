import argparse
import json
import time
from datetime import datetime
from typing import Any, Callable

from sqlalchemy import func, select

from atdr.app.db.database import SessionLocal
from atdr.app.db.models import Alert, NormalizedLog, RawLog
from atdr.app.ml.features import build_log_features
from atdr.app.services.alert_service import list_alerts
from atdr.app.services.case_service import list_alert_cases
from atdr.app.services.dashboard_service import build_dashboard_summary
from atdr.app.services.operation_run_service import list_detection_runs, list_ingestion_runs
from atdr.app.services.ml_service import evaluation_report
from atdr.app.detection.supervised_detector import supervised_model_report


def _json_default(value: Any) -> str:
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def _timed(label: str, fn: Callable[[], Any]) -> tuple[str, Any, float]:
    started = time.perf_counter()
    result = fn()
    return label, result, round(time.perf_counter() - started, 4)


def run_performance_smoke(*, feature_limit: int = 20) -> dict[str, Any]:
    with SessionLocal() as db:
        total_raw = int(db.scalar(select(func.count(RawLog.id))) or 0)
        total_normalized = int(db.scalar(select(func.count(NormalizedLog.id))) or 0)
        alert_count = int(db.scalar(select(func.count(Alert.id))) or 0)

        timings: dict[str, float] = {}
        _, summary, seconds = _timed("overview_summary", lambda: build_dashboard_summary(db))
        timings["overview_summary_seconds"] = seconds
        timings["ingestion_summary_query_seconds"] = seconds
        _, ingestion_runs, seconds = _timed("ingestion_run_history", lambda: list_ingestion_runs(db, limit=20))
        timings["ingestion_run_history_query_seconds"] = seconds
        _, detection_runs, seconds = _timed("detection_run_history", lambda: list_detection_runs(db, limit=20))
        timings["detection_run_history_query_seconds"] = seconds
        _, alerts, seconds = _timed("alert_list", lambda: list_alerts(db, limit=50))
        timings["alert_list_query_seconds"] = seconds
        _, cases, seconds = _timed("case_summary", lambda: list_alert_cases(db, limit=20))
        timings["case_summary_query_seconds"] = seconds
        _, ml_report, seconds = _timed("ml_governance_summary", lambda: evaluation_report(db))
        timings["ml_governance_lightweight_summary_seconds"] = seconds
        timings["ml_governance_summary_query_seconds"] = seconds
        _, supervised_report, seconds = _timed("ml_supervised_report", lambda: supervised_model_report(db))
        timings["ml_heavy_supervised_report_seconds"] = seconds

        feature_errors: list[str] = []
        logs = list(db.scalars(select(NormalizedLog).order_by(NormalizedLog.id.desc()).limit(max(0, feature_limit))))
        started = time.perf_counter()
        for log in logs:
            try:
                build_log_features(db, log)
            except Exception as exc:  # pragma: no cover - surfaced in smoke output
                feature_errors.append(f"log {log.id}: {exc.__class__.__name__}: {exc}")
                if len(feature_errors) >= 5:
                    break
        timings["feature_generation_seconds"] = round(time.perf_counter() - started, 4)

        warnings: list[str] = []
        budgets = {
            "overview_summary_seconds": 1.0,
            "ml_governance_lightweight_summary_seconds": 2.0,
            "ml_heavy_supervised_report_seconds": 5.0,
            "ingestion_run_history_query_seconds": 1.0,
            "detection_run_history_query_seconds": 1.0,
            "alert_list_query_seconds": 1.0,
            "case_summary_query_seconds": 1.0,
        }
        for key, value in timings.items():
            budget = budgets.get(key, 2.0)
            if value > budget:
                warnings.append(f"{key} took {value}s; budget is {budget}s for local lab use.")
        if feature_errors:
            warnings.append("Feature generation had errors; inspect feature_errors before relying on model scoring.")

        return {
            "ok": not feature_errors,
            "read_only": True,
            "total_raw_logs": total_raw,
            "normalized_logs": total_normalized,
            "alert_count": alert_count,
            "dashboard_total_logs": summary.get("total_logs"),
            "alert_rows_sampled": len(alerts),
            "case_rows_sampled": len(cases),
            "ingestion_runs_sampled": len(ingestion_runs),
            "detection_runs_sampled": len(detection_runs),
            "ml_anomaly_rate": ml_report.get("anomaly_rate"),
            "supervised_label_count": supervised_report.get("label_count"),
            "feature_rows_sampled": len(logs),
            "timings": timings,
            "feature_errors": feature_errors,
            "warnings": warnings,
        }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run a read-only ATDR performance smoke report.")
    parser.add_argument("--feature-limit", type=int, default=20)
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()
    result = run_performance_smoke(feature_limit=args.feature_limit)
    print(json.dumps(result, default=_json_default, indent=2 if args.pretty else None))
    raise SystemExit(0 if result.get("ok") else 1)


if __name__ == "__main__":
    main()
