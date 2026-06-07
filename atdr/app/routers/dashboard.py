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
V13_REPORT_DIR = PROJECT_ROOT / "ml_baseline_reviews"


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


def _latest_v13_ai_summary(report_dir: Path = V13_REPORT_DIR) -> dict[str, Any]:
    audit_summary, audit = _latest_reliability_file_summary(
        report_dir,
        "training_data_quality_audit_*.json",
        missing_message="No v1.3 training-data audit has been generated yet.",
    )
    candidate_summary, candidate = _latest_reliability_file_summary(
        report_dir,
        "v1_3_supervised_candidate_report_*.json",
        missing_message="No v1.3 supervised candidate report has been generated yet.",
    )
    target_path = report_dir / "v1_3_label_target_plan.json"
    target = None
    if target_path.exists():
        try:
            target = json.loads(target_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            target = None
    if audit is None and candidate is None and target is None:
        return audit_summary
    readiness = (candidate or {}).get("readiness_gate_v3") or {}
    best = (candidate or {}).get("best_flat_candidate") or {}
    metrics = best.get("metrics") or {}
    training_readiness = (audit or {}).get("training_readiness") or {}
    class_rows = (target or {}).get("class_rows") or []
    return {
        "available": True,
        "ok": bool((audit or candidate or target or {}).get("ok", True)),
        "generated_at": (candidate or audit or target or {}).get("generated_at"),
        "reviewed_label_count": int(
            (audit or {}).get("reviewed_label_count")
            or (candidate or {}).get("reviewed_label_count")
            or 0
        ),
        "weak_label_count": int((audit or {}).get("weak_label_count") or 0),
        "minimum_target_classes_met": int(training_readiness.get("minimum_target_classes_met") or 0),
        "minimum_target_class_count": int(training_readiness.get("minimum_target_class_count") or 5),
        "minimum_label_gap": sum(int(row.get("minimum_gap") or 0) for row in class_rows),
        "best_candidate": best.get("name"),
        "threat_positive_f1": (metrics.get("threat_positive") or {}).get("f1"),
        "suspicious_recall": ((metrics.get("per_class") or {}).get("suspicious") or {}).get("recall"),
        "malicious_recall": ((metrics.get("per_class") or {}).get("malicious") or {}).get("recall"),
        "readiness_decision": readiness.get("decision") or "candidate_only",
        "production_status": readiness.get("production_status") or "not_production_promoted",
        "response_automation_allowed": False,
        "latest_audit_report_name": audit_summary.get("latest_report_name"),
        "latest_candidate_report_name": candidate_summary.get("latest_report_name"),
    }


def _latest_v14_ai_summary(report_dir: Path = V13_REPORT_DIR) -> dict[str, Any]:
    summary, payload = _latest_reliability_file_summary(
        report_dir,
        "v1_4_false_positive_reduction_*.json",
        missing_message="No v1.4 false-positive reduction report has been generated yet.",
    )
    if payload is None:
        return summary
    best_metrics = payload.get("best_metrics") or {}
    readiness = payload.get("readiness") or {}
    mitigation_summary, mitigation = _latest_reliability_file_summary(
        report_dir,
        "v1_4b_quic_false_positive_mitigation.json",
        missing_message="No v1.4b QUIC mitigation report has been generated yet.",
    )
    mitigation_analysis = (mitigation or {}).get("analysis") or {}
    actionable_review = (mitigation or {}).get("review_sample") or {}
    recovery_summary, recovery = _latest_reliability_file_summary(
        report_dir,
        "v1_4c_malicious_recall_recovery.json",
        missing_message="No v1.4c malicious-recall recovery report has been generated yet.",
    )
    effective_payload = recovery or payload
    effective_metrics = effective_payload.get("best_metrics") or best_metrics
    effective_readiness = effective_payload.get("readiness") or readiness
    selected_calibration = effective_payload.get("selected_calibration") or {}
    recovery_review = (recovery or {}).get("review_sample") or {}
    return {
        **summary,
        "best_strategy": effective_payload.get("best_strategy"),
        "best_profile": effective_payload.get("best_profile"),
        "threat_positive_precision": effective_metrics.get("threat_positive_precision"),
        "threat_positive_recall": effective_metrics.get("threat_positive_recall"),
        "threat_positive_f1": effective_metrics.get("threat_positive_f1"),
        "benign_like_false_positive_rate": effective_metrics.get(
            "benign_like_false_positive_rate"
        ),
        "suspicious_recall": effective_metrics.get("suspicious_recall"),
        "malicious_recall": effective_metrics.get("malicious_recall"),
        "calibration_status": (
            selected_calibration.get("status")
            or effective_payload.get("calibration_status")
            or "pending"
        ),
        "readiness_decision": effective_readiness.get("decision") or "candidate_only",
        "production_promoted": False,
        "response_automation_allowed": False,
        "false_positives_improved": mitigation is not None,
        "current_blocker": (
            "malicious recall and calibration"
            if recovery is not None
            else "false positives"
        ),
        "quic_mitigation_status": (
            "validated candidate; not activated"
            if mitigation is not None
            else "pending"
        ),
        "confirmed_noisy_pattern": (
            "normal QUIC/443"
            if mitigation_analysis.get("quic_false_positive_count") is not None
            else None
        ),
        "quic_false_positive_count": mitigation_analysis.get(
            "quic_false_positive_count"
        ),
        "actionable_review_rows": actionable_review.get("rows"),
        "actionable_review_excludes_manual": (
            int(actionable_review.get("protected_manual_rows") or 0) == 0
            if actionable_review
            else None
        ),
        "latest_mitigation_report_name": mitigation_summary.get(
            "latest_report_name"
        ),
        "malicious_recovery_review_rows": recovery_review.get("rows"),
        "latest_recovery_report_name": recovery_summary.get(
            "latest_report_name"
        ),
    }


def _latest_v15_ai_summary(report_dir: Path = V13_REPORT_DIR) -> dict[str, Any]:
    summary, payload = _latest_reliability_file_summary(
        report_dir,
        "final_ai_readiness_report_*.json",
        missing_message="No v1.5 final AI readiness report has been generated yet.",
    )
    if payload is None:
        return summary
    benchmark = payload.get("benchmark") or {}
    candidate = payload.get("best_benchmark_candidate") or {}
    metrics = candidate.get("metrics") or {}
    readiness = payload.get("readiness_gate_v4") or {}
    current = payload.get("current_v14c") or {}
    calibration = current.get("selected_calibration") or {}
    return {
        **summary,
        "benchmark_label_count": int(benchmark.get("row_count") or 0),
        "benchmark_target_met": bool(benchmark.get("target_met")),
        "best_candidate": candidate.get("candidate_name"),
        "best_profile": current.get("best_profile"),
        "threat_positive_f1": metrics.get("threat_positive_f1"),
        "threat_positive_recall": metrics.get("threat_positive_recall"),
        "benign_like_false_positive_rate": metrics.get(
            "benign_false_positive_rate"
        ),
        "suspicious_recall": (
            (metrics.get("per_class") or {}).get("suspicious") or {}
        ).get("recall"),
        "malicious_recall": (
            (metrics.get("per_class") or {}).get("malicious") or {}
        ).get("recall"),
        "calibration_status": calibration.get("status") or "missing",
        "readiness_decision": readiness.get("decision") or "candidate_only",
        "checks_passed": int(readiness.get("passed") or 0),
        "checks_total": int(readiness.get("total") or 0),
        "production_promoted": False,
        "model_activated": False,
        "response_automation_allowed": False,
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
    summary["v13_ai"] = _latest_v13_ai_summary(V13_REPORT_DIR)
    summary["v14_ai"] = _latest_v14_ai_summary(V13_REPORT_DIR)
    summary["v15_ai"] = _latest_v15_ai_summary(V13_REPORT_DIR)
    return summary
