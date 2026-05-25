import argparse
import json
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from atdr.app.core.config import PROJECT_ROOT, get_settings
from atdr.app.db.database import SessionLocal, init_db
from atdr.app.db.models import Alert, AuditLog, NormalizedLog
from atdr.app.detection.attack_mapping import infer_attack_type_from_rules
from atdr.app.ml.features import build_log_features
from atdr.app.services.dashboard_service import build_dashboard_summary
from atdr.app.services.demo_service import reset_and_seed_demo, resolve_demo_sample_path
from atdr.app.services.detection_service import run_detection
from atdr.app.services.log_service import import_log_file
from atdr.app.services.ml_service import apply_anomaly_scoring
from atdr.app.services.response_service import block_ip


def _json_default(value: Any) -> str:
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def _timed(fn: Callable[[], dict]) -> tuple[dict, float]:
    started = time.perf_counter()
    result = fn()
    return result, round(time.perf_counter() - started, 3)


def _resolve_input_path(*, use_sample_data: bool, sample_path: str | None) -> Path | None:
    if sample_path:
        return Path(sample_path) if Path(sample_path).is_absolute() else PROJECT_ROOT / sample_path
    if use_sample_data:
        return resolve_demo_sample_path(None)
    return None


def _top_attack_types(db: Session, limit: int = 10) -> list[dict[str, Any]]:
    rows = db.scalars(select(Alert).order_by(desc(Alert.threat_score), desc(Alert.id)).limit(500)).all()
    counts: dict[str, int] = {}
    for alert in rows:
        attack_type = infer_attack_type_from_rules(alert.matched_rules_json or [])
        counts[attack_type] = counts.get(attack_type, 0) + 1
    return [
        {"name": name, "count": count}
        for name, count in sorted(counts.items(), key=lambda item: (-item[1], item[0]))[:limit]
    ]


def _top_source_ips(db: Session, limit: int = 10) -> list[dict[str, Any]]:
    rows = db.execute(
        select(Alert.src_ip, func.count(Alert.id))
        .where(Alert.src_ip.is_not(None))
        .group_by(Alert.src_ip)
        .order_by(desc(func.count(Alert.id)))
        .limit(limit)
    ).all()
    return [{"name": str(name), "count": int(count)} for name, count in rows]


def _feature_generation_smoke(db: Session, limit: int) -> dict[str, Any]:
    logs = list(db.scalars(select(NormalizedLog).order_by(desc(NormalizedLog.id)).limit(limit)))
    started = time.perf_counter()
    errors: list[str] = []
    for log in logs:
        try:
            build_log_features(db, log)
        except Exception as exc:  # pragma: no cover - surfaced in scenario output
            errors.append(f"log {log.id}: {exc.__class__.__name__}: {exc}")
            if len(errors) >= 5:
                break
    duration = round(time.perf_counter() - started, 3)
    warning = None
    if logs and duration / len(logs) > 0.25:
        warning = "Feature generation is slow for this sample; review behavior-window query performance before larger lab use."
    return {"rows": len(logs), "duration_seconds": duration, "errors": errors, "warning": warning}


def _response_smoke(db: Session, *, actor: str) -> dict[str, Any]:
    alert = db.scalar(
        select(Alert)
        .where(Alert.src_ip.is_not(None))
        .order_by(desc(Alert.threat_score), desc(Alert.id))
        .limit(1)
    )
    if alert is None or not alert.src_ip:
        return {"skipped": True, "reason": "No alert with source IP is available."}
    action = block_ip(
        db,
        target_ip=alert.src_ip,
        reason=f"Optional lab scenario simulated response for alert {alert.id}.",
        alert_id=alert.id,
        actor=actor,
    )
    return {
        "skipped": False,
        "alert_id": alert.id,
        "target_ip": alert.src_ip,
        "status": action.status,
        "result_message": action.result_message,
    }


def run_lab_scenario(
    db: Session,
    *,
    dry_run: bool = False,
    use_sample_data: bool = False,
    sample_path: str | None = None,
    reset_demo: bool = False,
    limit: int | None = 5000,
    use_ml: bool = True,
    score_ml: bool = True,
    simulate_response: bool = False,
    feature_limit: int = 50,
    actor: str = "lab_scenario",
) -> dict[str, Any]:
    settings = get_settings()
    import_path = _resolve_input_path(use_sample_data=use_sample_data, sample_path=sample_path)
    normalized_limit = None if limit is not None and limit <= 0 else limit
    plan = {
        "reset_demo": reset_demo,
        "import_path": str(import_path) if import_path else None,
        "use_ml_for_detection": use_ml,
        "score_ml": score_ml,
        "simulate_response": simulate_response,
        "database_url": settings.database_url,
    }
    if dry_run:
        return {
            "ok": True,
            "dry_run": True,
            "message": "Dry run only. No database rows were imported, reset, detected, scored, or responded to.",
            "plan": plan,
        }

    result: dict[str, Any] = {"ok": True, "dry_run": False, "plan": plan, "timings": {}}

    if reset_demo:
        if import_path is None:
            import_path = resolve_demo_sample_path(None)
        reset_result, seconds = _timed(
            lambda: reset_and_seed_demo(db, sample_path=import_path, limit=normalized_limit, use_ml=use_ml, actor=actor)
        )
        result["reset_demo"] = reset_result
        result["timings"]["reset_import_detect_seconds"] = seconds
    else:
        if import_path is not None:
            if not import_path.exists():
                result["ok"] = False
                result["import"] = {"skipped": True, "error": f"Log file does not exist: {import_path}"}
                return result
            import_result, seconds = _timed(lambda: import_log_file(db, import_path, limit=normalized_limit, actor=actor))
            result["import"] = import_result
            result["timings"]["import_seconds"] = seconds
        else:
            result["import"] = {
                "skipped": True,
                "reason": "No import requested. Pass --use-sample-data or --sample-path to import logs.",
            }

        if score_ml:
            score_result, seconds = _timed(lambda: apply_anomaly_scoring(db, limit=normalized_limit, actor=actor))
            result["ml_scoring"] = score_result
            result["timings"]["ml_scoring_seconds"] = seconds

        detection_result, seconds = _timed(lambda: run_detection(db, limit=normalized_limit, use_ml=use_ml, actor=actor))
        result["detection"] = detection_result
        result["timings"]["detection_seconds"] = seconds

    feature_result = _feature_generation_smoke(db, max(1, feature_limit))
    result["feature_generation_smoke"] = feature_result
    result["timings"]["feature_generation_seconds"] = feature_result["duration_seconds"]

    if simulate_response:
        response_result, seconds = _timed(lambda: _response_smoke(db, actor=actor))
        result["simulated_response"] = response_result
        result["timings"]["simulated_response_seconds"] = seconds
    else:
        result["simulated_response"] = {"skipped": True, "reason": "Pass --simulate-response to record a simulated response action."}

    summary_result, seconds = _timed(lambda: build_dashboard_summary(db))
    audit_count = int(db.scalar(select(func.count(AuditLog.id))) or 0)
    result["dashboard_summary"] = {
        "total_logs": summary_result.get("total_logs"),
        "total_alerts": summary_result.get("total_alerts"),
        "active_alerts": summary_result.get("active_alerts"),
        "critical_open_alerts": summary_result.get("critical_open_alerts"),
        "anomaly_rate": summary_result.get("anomaly_rate"),
    }
    result["timings"]["dashboard_summary_seconds"] = seconds
    result["top_attack_types"] = _top_attack_types(db)
    result["top_source_ips"] = _top_source_ips(db)
    result["audit"] = {"entries": audit_count, "entries_exist": audit_count > 0}
    result["warnings"] = [
        "Response actions remain simulated and analyst-approved.",
        "This scenario runner is optional and never resets data unless --reset-demo is passed.",
    ]
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Run a safe optional ATDR lab scenario without disrupting local workflow.")
    parser.add_argument("--dry-run", action="store_true", help="Show planned actions without changing the database.")
    parser.add_argument("--use-sample-data", action="store_true", help="Import the safe sample file from DEMO_SAMPLE_LOG_PATH.")
    parser.add_argument("--sample-path", default=None, help="Explicit log path to import. Use only when you intend to touch that file.")
    parser.add_argument("--limit", type=int, default=5000, help="Import/detect/score limit. Use 0 for no limit.")
    parser.add_argument("--no-reset", action="store_true", help="Explicitly keep existing data. This is already the default.")
    parser.add_argument("--reset-demo", action="store_true", help="Explicitly clear demo data before importing and detecting.")
    parser.add_argument("--no-ml", action="store_true", help="Run rule-only detection.")
    parser.add_argument("--no-score-ml", action="store_true", help="Skip standalone anomaly scoring step.")
    parser.add_argument("--simulate-response", action="store_true", help="Record one simulated response action against the highest-risk alert.")
    parser.add_argument("--feature-limit", type=int, default=50, help="Rows to use for feature-generation timing smoke.")
    parser.add_argument("--actor", default="lab_scenario")
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()

    init_db()
    with SessionLocal() as db:
        result = run_lab_scenario(
            db,
            dry_run=args.dry_run,
            use_sample_data=args.use_sample_data,
            sample_path=args.sample_path,
            reset_demo=args.reset_demo,
            limit=args.limit,
            use_ml=not args.no_ml,
            score_ml=not args.no_score_ml,
            simulate_response=args.simulate_response,
            feature_limit=args.feature_limit,
            actor=args.actor,
        )
    print(json.dumps(result, default=_json_default, indent=2 if args.pretty else None))
    raise SystemExit(0 if result.get("ok") else 1)


if __name__ == "__main__":
    main()
