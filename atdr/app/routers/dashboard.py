import json
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from atdr.app.core.config import PROJECT_ROOT
from atdr.app.core.security import require_analyst_or_admin
from atdr.app.db.database import get_db
from atdr.app.db.models import User
from atdr.app.services.dashboard_service import build_dashboard_summary_cached

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])
VALIDATION_REPORT_DIR = PROJECT_ROOT / "demo_exports" / "detection_validation"
GENERALIZATION_REPORT_DIR = PROJECT_ROOT / "demo_exports" / "detection_generalization"
LAYERED_REPORT_DIR = PROJECT_ROOT / "demo_exports" / "layered_detection"
E2E_REPORT_DIR = PROJECT_ROOT / "demo_exports" / "e2e_validation"
RELIABILITY_REPORT_DIR = PROJECT_ROOT / "demo_exports" / "detection_reliability"
BENCHMARK_REPORT_DIR = PROJECT_ROOT / "demo_exports" / "benchmarks"


def _latest_validation_summary(report_dir: Path = VALIDATION_REPORT_DIR) -> dict[str, Any]:
    if not report_dir.exists():
        return {
            "available": False,
            "message": "No controlled validation report has been generated yet.",
        }
    candidates = sorted(
        (
            path
            for path in report_dir.glob("detection_validation_*.json")
            if not path.name.endswith("_risk_calibration.json")
        ),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    if not candidates:
        return {
            "available": False,
            "message": "No controlled validation report has been generated yet.",
        }

    latest = candidates[0]
    try:
        payload = json.loads(latest.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {
            "available": False,
            "message": f"Latest controlled validation report could not be read: {exc}",
            "latest_report_name": latest.name,
        }

    paths = payload.get("paths") or {}
    report_name = latest.name
    markdown_name = Path(paths.get("markdown") or latest.with_suffix(".md")).name
    risk_name = Path(paths.get("risk_calibration") or latest.with_name(f"{latest.stem}_risk_calibration.md")).name
    failed = [
        item.get("scenario")
        for item in payload.get("scenarios", [])
        if not bool(item.get("passed"))
    ]
    return {
        "available": True,
        "ok": bool(payload.get("ok")),
        "generated_at": payload.get("generated_at"),
        "scenario_count": int(payload.get("scenario_count") or 0),
        "passed_count": int(payload.get("passed_count") or 0),
        "failed_count": len(failed),
        "failed_scenarios": failed,
        "latest_report_name": report_name,
        "latest_markdown_name": markdown_name,
        "latest_risk_calibration_name": risk_name,
        "validation_scope": payload.get("validation_scope"),
        "response_mode": (payload.get("safety") or {}).get("response_mode", "simulated analyst-approved only"),
        "production_readiness_claim": bool((payload.get("safety") or {}).get("production_readiness_claim")),
    }


def _latest_generalization_summary(report_dir: Path = GENERALIZATION_REPORT_DIR) -> dict[str, Any]:
    if not report_dir.exists():
        return {
            "available": False,
            "message": "No detection generalization report has been generated yet.",
        }
    candidates = sorted(
        report_dir.glob("detection_generalization_*.json"),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    if not candidates:
        return {
            "available": False,
            "message": "No detection generalization report has been generated yet.",
        }

    latest = candidates[0]
    try:
        payload = json.loads(latest.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {
            "available": False,
            "message": f"Latest detection generalization report could not be read: {exc}",
            "latest_report_name": latest.name,
        }

    paths = payload.get("paths") or {}
    report_name = latest.name
    markdown_name = Path(paths.get("markdown") or latest.with_suffix(".md")).name
    failed_families = [
        item.get("scenario")
        for item in payload.get("families", [])
        if int(item.get("failed_count") or 0) > 0
    ]
    return {
        "available": True,
        "ok": bool(payload.get("ok")),
        "generated_at": payload.get("generated_at"),
        "scenario_count": int(payload.get("scenario_count") or 0),
        "variant_count": int(payload.get("variant_count") or 0),
        "passed_count": int(payload.get("passed_count") or 0),
        "failed_count": int(payload.get("failed_count") or 0),
        "false_positive_count": int(payload.get("false_positive_count") or 0),
        "false_negative_count": int(payload.get("false_negative_count") or 0),
        "failed_families": failed_families,
        "latest_report_name": report_name,
        "latest_markdown_name": markdown_name,
        "validation_scope": payload.get("validation_scope"),
        "use_temp_db": bool(payload.get("use_temp_db", True)),
        "response_mode": (payload.get("safety") or {}).get("response_mode", "simulated analyst-approved only"),
        "production_readiness_claim": bool((payload.get("safety") or {}).get("production_readiness_claim")),
        "synthetic_variants_only": bool((payload.get("safety") or {}).get("synthetic_variants_only", True)),
    }


def _latest_layered_summary(report_dir: Path = LAYERED_REPORT_DIR) -> dict[str, Any]:
    if not report_dir.exists():
        return {
            "available": False,
            "message": "No layered detection validation report has been generated yet.",
        }
    candidates = sorted(
        report_dir.glob("layered_detection_*.json"),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    if not candidates:
        return {
            "available": False,
            "message": "No layered detection validation report has been generated yet.",
        }

    latest = candidates[0]
    try:
        payload = json.loads(latest.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {
            "available": False,
            "message": f"Latest layered detection report could not be read: {exc}",
            "latest_report_name": latest.name,
        }

    paths = payload.get("paths") or {}
    report_name = latest.name
    markdown_name = Path(paths.get("markdown") or latest.with_suffix(".md")).name
    return {
        "available": True,
        "ok": bool(payload.get("ok")),
        "generated_at": payload.get("generated_at"),
        "scenario_count": int(payload.get("scenario_count") or 0),
        "variant_count": int(payload.get("variant_count") or 0),
        "mode_count": int(payload.get("mode_count") or 0),
        "mode_run_count": int(payload.get("mode_run_count") or 0),
        "passed_count": int(payload.get("passed_count") or 0),
        "failed_count": int(payload.get("failed_count") or 0),
        "false_positive_count": int(payload.get("false_positive_count") or 0),
        "false_negative_count": int(payload.get("false_negative_count") or 0),
        "mode_summary": payload.get("mode_summary") or [],
        "latest_report_name": report_name,
        "latest_markdown_name": markdown_name,
        "validation_scope": payload.get("validation_scope"),
        "use_temp_db": bool(payload.get("use_temp_db", True)),
        "response_mode": (payload.get("safety") or {}).get("response_mode", "simulated analyst-approved only"),
        "production_readiness_claim": bool((payload.get("safety") or {}).get("production_readiness_claim")),
    }


def _latest_e2e_summary(report_dir: Path = E2E_REPORT_DIR) -> dict[str, Any]:
    if not report_dir.exists():
        return {
            "available": False,
            "message": "No end-to-end workflow validation report has been generated yet.",
        }
    candidates = sorted(
        report_dir.glob("e2e_workflow_validation_*.json"),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    if not candidates:
        return {
            "available": False,
            "message": "No end-to-end workflow validation report has been generated yet.",
        }

    latest = candidates[0]
    try:
        payload = json.loads(latest.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {
            "available": False,
            "message": f"Latest end-to-end workflow report could not be read: {exc}",
            "latest_report_name": latest.name,
        }

    paths = payload.get("paths") or {}
    scenarios = payload.get("scenarios") or []
    return {
        "available": True,
        "ok": bool(payload.get("ok")),
        "generated_at": payload.get("generated_at"),
        "scenario_count": int(payload.get("scenario_count") or 0),
        "passed_count": int(payload.get("passed_count") or 0),
        "failed_count": int(payload.get("failed_count") or 0),
        "simulate_response": bool(payload.get("simulate_response")),
        "response_actions_created": sum(int((item.get("audit_summary") or {}).get("response_actions_created") or 0) for item in scenarios),
        "alert_count": sum(int(item.get("alert_count") or 0) for item in scenarios),
        "case_count": sum(int(item.get("case_count") or 0) for item in scenarios),
        "latest_report_name": latest.name,
        "latest_markdown_name": Path(paths.get("markdown") or latest.with_suffix(".md")).name,
        "validation_scope": payload.get("validation_scope"),
        "use_temp_db": bool(payload.get("use_temp_db", True)),
        "response_mode": (payload.get("safety") or {}).get("response_mode", "simulated analyst-approved only"),
        "production_readiness_claim": bool((payload.get("safety") or {}).get("production_readiness_claim")),
    }


def _latest_reliability_file_summary(report_dir: Path, pattern: str, *, missing_message: str) -> tuple[dict[str, Any], dict[str, Any] | None]:
    if not report_dir.exists():
        return {"available": False, "message": missing_message}, None
    candidates = sorted(report_dir.glob(pattern), key=lambda path: path.stat().st_mtime, reverse=True)
    if not candidates:
        return {"available": False, "message": missing_message}, None
    latest = candidates[0]
    try:
        payload = json.loads(latest.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {
            "available": False,
            "message": f"Latest reliability report could not be read: {exc}",
            "latest_report_name": latest.name,
        }, None
    paths = payload.get("paths") or {}
    return {
        "available": True,
        "ok": bool(payload.get("ok")),
        "generated_at": payload.get("generated_at"),
        "latest_report_name": latest.name,
        "latest_markdown_name": Path(paths.get("markdown") or latest.with_suffix(".md")).name,
        "validation_scope": payload.get("validation_scope"),
        "production_readiness_claim": bool((payload.get("safety") or {}).get("production_readiness_claim")),
    }, payload


def _latest_v11_reliability_summary(report_dir: Path = RELIABILITY_REPORT_DIR) -> dict[str, Any]:
    summary, payload = _latest_reliability_file_summary(
        report_dir,
        "detection_reliability_baseline_*.json",
        missing_message="No v1.1 detection reliability baseline has been generated yet.",
    )
    if payload is None:
        return summary
    scenario = payload.get("scenario_validation") or {}
    generalization = payload.get("generalization_validation") or {}
    layered = payload.get("layered_validation") or {}
    e2e = payload.get("e2e_workflow_validation") or {}
    return {
        **summary,
        "scenario_count": int(scenario.get("scenario_count") or 0),
        "scenario_passed_count": int(scenario.get("passed_count") or 0),
        "variant_count": int(generalization.get("variant_count") or 0),
        "variant_passed_count": int(generalization.get("passed_count") or 0),
        "mode_run_count": int(layered.get("mode_run_count") or 0),
        "mode_passed_count": int(layered.get("passed_count") or 0),
        "e2e_scenario_count": int(e2e.get("scenario_count") or 0),
        "e2e_passed_count": int(e2e.get("passed_count") or 0),
        "false_positive_count": int(payload.get("false_positive_count") or 0),
        "false_negative_count": int(payload.get("false_negative_count") or 0),
        "alert_volume": int(payload.get("alert_volume") or 0),
    }


def _latest_v11_benchmark_summary(report_dir: Path = RELIABILITY_REPORT_DIR, benchmark_dir: Path = BENCHMARK_REPORT_DIR) -> dict[str, Any]:
    summary, payload = _latest_reliability_file_summary(
        benchmark_dir,
        "benchmark_evaluation_*.json",
        missing_message="No mapped benchmark run has been generated yet.",
    )
    if payload is None:
        summary, payload = _latest_reliability_file_summary(
            report_dir,
            "detection_benchmark_*.json",
            missing_message="No mapped benchmark run has been generated yet.",
        )
    if payload is None:
        return summary
    metrics = payload.get("metrics") or {}
    dataset = payload.get("dataset") or {}
    readiness = payload.get("readiness_gate_v2") or {}
    return {
        **summary,
        "total_rows": int(payload.get("total_rows") or 0),
        "rows_mapped": int(payload.get("rows_mapped") or 0),
        "dataset_name": dataset.get("csv_name"),
        "snapshot_id": dataset.get("snapshot_id"),
        "detection_mode": payload.get("detection_mode"),
        "precision": metrics.get("precision"),
        "recall": metrics.get("recall"),
        "f1": metrics.get("f1"),
        "threat_positive_f1": metrics.get("threat_positive_f1") or metrics.get("f1"),
        "false_positive_count": int(metrics.get("false_positives") or 0),
        "false_negative_count": int(metrics.get("false_negatives") or 0),
        "alert_volume": int(payload.get("alert_volume") or 0),
        "readiness_decision": readiness.get("decision"),
    }


def _latest_v11_drift_summary(report_dir: Path = RELIABILITY_REPORT_DIR) -> dict[str, Any]:
    summary, payload = _latest_reliability_file_summary(
        report_dir,
        "drift_report_*.json",
        missing_message="No drift report has been generated yet.",
    )
    if payload is None:
        return summary
    return {
        **summary,
        "recent_rows": int(payload.get("recent_rows") or 0),
        "baseline_rows": int(payload.get("baseline_rows") or 0),
        "unknown_app_rate": payload.get("unknown_app_rate"),
        "parse_failure_rate": payload.get("parse_failure_rate"),
        "alert_rate": payload.get("alert_rate"),
        "warning_count": len(payload.get("warnings") or []),
    }


@router.get("/summary")
def dashboard_summary(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
) -> dict:
    return build_dashboard_summary_cached(db)


@router.get("/validation-summary")
def dashboard_validation_summary(
    current_user: User = Depends(require_analyst_or_admin),
) -> dict:
    summary = _latest_validation_summary(VALIDATION_REPORT_DIR)
    summary["generalization"] = _latest_generalization_summary(GENERALIZATION_REPORT_DIR)
    summary["layered"] = _latest_layered_summary(LAYERED_REPORT_DIR)
    summary["e2e_workflow"] = _latest_e2e_summary(E2E_REPORT_DIR)
    summary["reliability"] = _latest_v11_reliability_summary(RELIABILITY_REPORT_DIR)
    summary["benchmark"] = _latest_v11_benchmark_summary(RELIABILITY_REPORT_DIR, BENCHMARK_REPORT_DIR)
    summary["drift"] = _latest_v11_drift_summary(RELIABILITY_REPORT_DIR)
    return summary
