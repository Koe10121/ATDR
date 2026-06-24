import json
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from atdr.app.benchmarks.readiness import readiness_gate_v9_production_readiness_track
from atdr.app.core.config import PROJECT_ROOT, get_settings
from atdr.app.core.security import require_analyst_or_admin
from atdr.app.db.database import get_db
from atdr.app.db.models import DetectionRun, LogSource, NormalizedLog, RawLog, User
from atdr.app.services.dashboard_service import build_dashboard_summary_cached
from atdr.app.services.source_service import source_health
from atdr.scripts.production_readiness_doctor import run_production_readiness_doctor

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


def _latest_v16_ai_summary(report_dir: Path = BENCHMARK_REPORT_DIR) -> dict[str, Any]:
    summary, payload = _latest_reliability_file_summary(
        report_dir,
        "external_benchmark_validation_*.json",
        missing_message="No v1.6 external holdout validation has been generated yet.",
    )
    if payload is None:
        return summary
    snapshot = payload.get("external_snapshot") or {}
    profile = snapshot.get("profile") or {}
    candidate = payload.get("cross_dataset_candidate") or {}
    metrics = candidate.get("metrics") or {}
    calibration = candidate.get("calibration") or {}
    overfitting = payload.get("overfitting_check") or {}
    readiness = payload.get("readiness_gate_v5") or {}
    return {
        **summary,
        "external_label_count": int(snapshot.get("benchmark_label_count") or 0),
        "preferred_target_met": bool(snapshot.get("preferred_target_met")),
        "source_count": int(profile.get("source_count") or 0),
        "scenario_count": int(profile.get("scenario_count") or 0),
        "candidate_name": candidate.get("candidate_name"),
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
        "overfitting_status": overfitting.get("status") or "not_evaluated",
        "overfitting_warning": bool(overfitting.get("overfitting_warning")),
        "threat_f1_gap": (
            (overfitting.get("metric_gaps") or {})
            .get("threat_positive_f1", {})
            .get("gap")
        ),
        "readiness_decision": readiness.get("decision") or "candidate_only",
        "checks_passed": int(readiness.get("passed") or 0),
        "checks_total": int(readiness.get("total") or 0),
        "external_benchmark_validated": bool(
            readiness.get("external_benchmark_validated")
        ),
        "production_promoted": False,
        "model_activated": False,
        "response_automation_allowed": False,
    }


def _latest_v17_ai_summary(report_dir: Path = BENCHMARK_REPORT_DIR) -> dict[str, Any]:
    summary, payload = _latest_reliability_file_summary(
        report_dir,
        "v1_7_external_generalization_*.json",
        missing_message="No v1.7 external generalization improvement report has been generated yet.",
    )
    if payload is None:
        return summary
    best = payload.get("best_profile") or {}
    metrics = best.get("metrics") or {}
    per_class = metrics.get("per_class") or {}
    calibration = best.get("calibration") or {}
    overfitting = payload.get("overfitting_guard") or {}
    readiness = payload.get("readiness_gate_v6") or {}
    review_sample = payload.get("review_sample") or {}
    failed_checks = [
        item.get("name")
        for item in readiness.get("checks", [])
        if not bool(item.get("passed")) and not bool(item.get("advisory"))
    ]
    return {
        **summary,
        "external_label_count": int(payload.get("external_label_count") or 0),
        "best_profile": best.get("profile"),
        "threat_positive_precision": metrics.get("threat_positive_precision"),
        "threat_positive_recall": metrics.get("threat_positive_recall"),
        "threat_positive_f1": metrics.get("threat_positive_f1"),
        "benign_like_false_positive_rate": metrics.get(
            "benign_false_positive_rate"
        ),
        "suspicious_recall": (per_class.get("suspicious") or {}).get("recall"),
        "malicious_recall": (per_class.get("malicious") or {}).get("recall"),
        "macro_f1": metrics.get("macro_f1"),
        "calibration_status": calibration.get("status") or "missing",
        "calibration_ece": calibration.get("expected_calibration_error"),
        "calibration_brier": calibration.get("brier_score_threat_positive"),
        "calibration_max_gap": calibration.get("max_confidence_accuracy_gap"),
        "queue_size": int(best.get("queue_size") or 0),
        "cost_sensitive_total": (best.get("cost_sensitive") or {}).get(
            "total_cost"
        ),
        "overfitting_status": overfitting.get("status") or "not_evaluated",
        "overfitting_warning": bool(overfitting.get("overfitting_warning")),
        "readiness_decision": readiness.get("decision") or "candidate_only",
        "checks_passed": int(readiness.get("passed") or 0),
        "checks_total": int(readiness.get("total") or 0),
        "external_benchmark_validated": bool(
            readiness.get("external_benchmark_validated")
        ),
        "failed_checks": failed_checks,
        "review_sample_rows": int(review_sample.get("rows") or 0),
        "production_promoted": False,
        "model_activated": False,
        "response_automation_allowed": False,
    }


def _latest_v18_ai_summary(report_dir: Path = BENCHMARK_REPORT_DIR) -> dict[str, Any]:
    summary, payload = _latest_reliability_file_summary(
        report_dir,
        "v1_8_external_benchmark_finalization_*.json",
        missing_message="No v1.8 external benchmark finalization report has been generated yet.",
    )
    if payload is None:
        return summary
    best = payload.get("best_profile") or {}
    metrics = best.get("metrics") or {}
    per_class = metrics.get("per_class") or {}
    calibration = best.get("calibration") or {}
    readiness = payload.get("readiness_gate_v6") or {}
    generalization = best.get("generalization") or {}
    miss_analysis = payload.get("miss_analysis") or {}
    failed_checks = [
        item.get("name")
        for item in readiness.get("checks", [])
        if not bool(item.get("passed")) and not bool(item.get("advisory"))
    ]
    return {
        **summary,
        "external_label_count": int(payload.get("external_label_count") or 0),
        "best_profile": best.get("profile"),
        "threat_positive_precision": metrics.get("threat_positive_precision"),
        "threat_positive_recall": metrics.get("threat_positive_recall"),
        "threat_positive_f1": metrics.get("threat_positive_f1"),
        "benign_like_false_positive_rate": metrics.get(
            "benign_false_positive_rate"
        ),
        "suspicious_recall": (per_class.get("suspicious") or {}).get("recall"),
        "malicious_recall": (per_class.get("malicious") or {}).get("recall"),
        "macro_f1": metrics.get("macro_f1"),
        "weighted_f1": metrics.get("weighted_f1"),
        "calibration_status": best.get("calibration_readiness_status")
        or calibration.get("status")
        or "missing",
        "calibration_method": best.get("calibration_method") or "none",
        "calibration_ece": calibration.get("expected_calibration_error"),
        "calibration_brier": calibration.get("brier_score_threat_positive"),
        "calibration_max_gap": calibration.get("max_confidence_accuracy_gap"),
        "queue_size": int(best.get("queue_size") or 0),
        "overfitting_status": generalization.get("status") or "not_evaluated",
        "overfitting_warning": bool(generalization.get("overfitting_warning")),
        "readiness_decision": readiness.get("decision") or "candidate_only",
        "readiness_version": readiness.get("version") or "v6",
        "checks_passed": int(readiness.get("passed") or 0),
        "checks_total": int(readiness.get("total") or 0),
        "external_benchmark_validated": bool(
            readiness.get("external_benchmark_validated")
        ),
        "failed_checks": failed_checks,
        "baseline_false_negatives": int(
            miss_analysis.get("before_threat_false_negatives") or 0
        ),
        "remaining_false_negatives": int(
            miss_analysis.get("after_threat_false_negatives") or 0
        ),
        "recovered_false_negatives": int(
            miss_analysis.get("recovered_threat_false_negatives") or 0
        ),
        "independent_revalidation_recommended": bool(
            payload.get("independent_revalidation_recommended")
        ),
        "production_promoted": False,
        "model_activated": False,
        "response_automation_allowed": False,
    }


def _latest_v19_ai_summary(report_dir: Path = BENCHMARK_REPORT_DIR) -> dict[str, Any]:
    summary, payload = _latest_reliability_file_summary(
        report_dir,
        "v1_9_independent_revalidation_*.json",
        missing_message="No v1.9 independent revalidation report has been generated yet.",
    )
    if payload is None:
        return summary
    best = payload.get("best_profile") or {}
    metrics = best.get("metrics") or {}
    per_class = metrics.get("per_class") or {}
    calibration = best.get("calibration") or {}
    readiness = payload.get("readiness_gate_v7") or {}
    holdout = payload.get("independent_holdout") or {}
    controlled = payload.get("controlled_real_source_validation") or {}
    gap = payload.get("generalization_gap") or {}
    failed_checks = [
        item.get("name")
        for item in readiness.get("checks", [])
        if not bool(item.get("passed"))
    ]
    return {
        **summary,
        "independent_label_count": int(holdout.get("row_count") or 0),
        "independent_source_count": int(holdout.get("source_count") or 0),
        "independent_scenario_count": int(holdout.get("scenario_count") or 0),
        "exact_overlap_rows": int(
            (holdout.get("previous_holdout_overlap") or {}).get(
                "exact_overlap_rows"
            )
            or 0
        ),
        "best_profile": best.get("profile"),
        "threat_positive_precision": metrics.get("threat_positive_precision"),
        "threat_positive_recall": metrics.get("threat_positive_recall"),
        "threat_positive_f1": metrics.get("threat_positive_f1"),
        "benign_like_false_positive_rate": metrics.get(
            "benign_false_positive_rate"
        ),
        "suspicious_recall": (per_class.get("suspicious") or {}).get("recall"),
        "malicious_recall": (per_class.get("malicious") or {}).get("recall"),
        "macro_f1": metrics.get("macro_f1"),
        "weighted_f1": metrics.get("weighted_f1"),
        "calibration_status": calibration.get("status") or "missing",
        "calibration_method": best.get("calibration_method") or "none",
        "calibration_ece": calibration.get("expected_calibration_error"),
        "calibration_brier": calibration.get("brier_score_threat_positive"),
        "calibration_max_gap": calibration.get(
            "max_confidence_accuracy_gap"
        ),
        "generalization_status": gap.get("status") or "not_evaluated",
        "controlled_real_source_available": bool(controlled.get("available")),
        "controlled_real_source_validated": bool(controlled.get("passed")),
        "readiness_decision": readiness.get("decision")
        or "analyst_review_eligible",
        "readiness_version": readiness.get("version") or "v7",
        "checks_passed": int(readiness.get("passed") or 0),
        "checks_total": int(readiness.get("total") or 0),
        "independent_holdout_validated": bool(
            readiness.get("independent_holdout_validated")
        ),
        "failed_checks": failed_checks,
        "production_promoted": False,
        "model_activated": False,
        "response_automation_allowed": False,
        "real_firewall_blocking_enabled": False,
    }


def _latest_v19b_ai_summary(report_dir: Path = BENCHMARK_REPORT_DIR) -> dict[str, Any]:
    summary, payload = _latest_reliability_file_summary(
        report_dir,
        "v1_9b_independent_fpr_stabilization_*.json",
        missing_message="No v1.9b FPR stabilization report has been generated yet.",
    )
    if payload is None:
        return summary
    best = payload.get("best_profile") or {}
    metrics = best.get("metrics") or {}
    per_class = metrics.get("per_class") or {}
    calibration = best.get("calibration") or {}
    readiness = payload.get("readiness_gate_v7b") or {}
    holdout = payload.get("independent_holdout") or {}
    controlled = payload.get("controlled_real_source_validation") or {}
    before_after = payload.get("before_after") or {}
    analysis = payload.get("false_positive_analysis") or {}
    failed_checks = [
        item.get("name")
        for item in readiness.get("checks", [])
        if not bool(item.get("passed"))
    ]
    fpr = metrics.get("benign_false_positive_rate")
    return {
        **summary,
        "independent_label_count": int(holdout.get("row_count") or 0),
        "independent_source_count": int(holdout.get("source_count") or 0),
        "independent_scenario_count": int(holdout.get("scenario_count") or 0),
        "exact_overlap_rows": int(
            (holdout.get("previous_holdout_overlap") or {}).get(
                "exact_overlap_rows"
            )
            or 0
        ),
        "best_profile": best.get("profile"),
        "threat_positive_precision": metrics.get("threat_positive_precision"),
        "threat_positive_recall": metrics.get("threat_positive_recall"),
        "threat_positive_f1": metrics.get("threat_positive_f1"),
        "benign_like_false_positive_rate": fpr,
        "suspicious_recall": (per_class.get("suspicious") or {}).get("recall"),
        "malicious_recall": (per_class.get("malicious") or {}).get("recall"),
        "macro_f1": metrics.get("macro_f1"),
        "weighted_f1": metrics.get("weighted_f1"),
        "calibration_status": calibration.get("status") or "missing",
        "calibration_method": best.get("calibration_method") or "none",
        "calibration_ece": calibration.get("expected_calibration_error"),
        "calibration_brier": calibration.get("brier_score_threat_positive"),
        "calibration_max_gap": calibration.get(
            "max_confidence_accuracy_gap"
        ),
        "controlled_real_source_available": bool(controlled.get("available")),
        "controlled_real_source_validated": bool(controlled.get("passed")),
        "readiness_decision": readiness.get("decision")
        or "analyst_review_eligible",
        "readiness_version": readiness.get("version") or "v7b",
        "checks_passed": int(readiness.get("passed") or 0),
        "checks_total": int(readiness.get("total") or 0),
        "independent_holdout_validated": bool(
            readiness.get("independent_holdout_validated")
        ),
        "failed_checks": failed_checks,
        "fpr_blocker_resolved": fpr is not None and float(fpr) <= 0.15,
        "false_positives_reduced": int(
            before_after.get("false_positives_reduced") or 0
        ),
        "analyst_review_boundary_count": int(
            best.get("analyst_review_boundary_count") or 0
        ),
        "minimum_false_positive_reduction_needed": int(
            analysis.get("minimum_reduction_needed") or 0
        ),
        "production_promoted": False,
        "model_activated": False,
        "response_automation_allowed": False,
        "real_firewall_blocking_enabled": False,
    }


def _latest_v20_ai_summary(report_dir: Path = BENCHMARK_REPORT_DIR) -> dict[str, Any]:
    summary, blind = _latest_reliability_file_summary(
        report_dir,
        "v2_0_fresh_blind_revalidation_*.json",
        missing_message="No v2.0 fresh blind revalidation report has been generated yet.",
    )
    if blind is None:
        return summary
    _final_summary, final_payload = _latest_reliability_file_summary(
        report_dir,
        "v2_0_final_controlled_source_acceptance_*.json",
        missing_message="No v2.0 final controlled acceptance report is available.",
    )
    final = final_payload or {}
    metrics = blind.get("metrics") or {}
    per_class = metrics.get("per_class") or {}
    calibration = (blind.get("calibration") or {}).get("metrics") or {}
    holdout = blind.get("fresh_blind_holdout") or {}
    candidate = blind.get("candidate") or {}
    readiness = (
        (final.get("readiness_gate_v8") or {})
        if final
        else (blind.get("readiness_gate_v8") or {})
    )
    controlled = (
        final.get("controlled_real_source_validation") or {}
        if final
        else blind.get("controlled_real_source_validation") or {}
    )
    failed_checks = [
        item.get("name")
        for item in readiness.get("checks", [])
        if not bool(item.get("passed"))
    ]
    fresh_passed = bool(readiness.get("fresh_blind_revalidated"))
    final_passed = bool(
        readiness.get("final_controlled_validation_passed")
    )
    return {
        **summary,
        "independent_label_count": int(holdout.get("row_count") or 0),
        "independent_source_count": int(holdout.get("source_count") or 0),
        "independent_scenario_count": int(holdout.get("scenario_count") or 0),
        "exact_overlap_rows": int(
            (holdout.get("previous_holdout_overlap") or {}).get(
                "exact_overlap_rows"
            )
            or 0
        ),
        "near_overlap_rows": int(
            (holdout.get("previous_holdout_overlap") or {}).get(
                "near_overlap_rows"
            )
            or 0
        ),
        "best_profile": candidate.get("name"),
        "candidate_hash": candidate.get("hash"),
        "threat_positive_precision": metrics.get("threat_positive_precision"),
        "threat_positive_recall": metrics.get("threat_positive_recall"),
        "threat_positive_f1": metrics.get("threat_positive_f1"),
        "benign_like_false_positive_rate": metrics.get(
            "benign_false_positive_rate"
        ),
        "suspicious_recall": (per_class.get("suspicious") or {}).get("recall"),
        "malicious_recall": (per_class.get("malicious") or {}).get("recall"),
        "macro_f1": metrics.get("macro_f1"),
        "weighted_f1": metrics.get("weighted_f1"),
        "calibration_status": calibration.get("status") or "missing",
        "calibration_method": (
            (blind.get("calibration") or {}).get("locked_method") or "none"
        ),
        "calibration_ece": calibration.get("expected_calibration_error"),
        "calibration_brier": calibration.get("brier_score_threat_positive"),
        "calibration_max_gap": calibration.get(
            "max_confidence_accuracy_gap"
        ),
        "controlled_real_source_available": bool(controlled),
        "controlled_real_source_validated": bool(
            controlled.get("controlled_real_source_validated")
            or readiness.get("controlled_real_source_validated")
        ),
        "readiness_decision": readiness.get("decision")
        or "analyst_review_eligible",
        "readiness_version": readiness.get("version") or "v8",
        "checks_passed": int(readiness.get("passed") or 0),
        "checks_total": int(readiness.get("total") or 0),
        "independent_holdout_validated": fresh_passed,
        "fresh_blind_revalidated": fresh_passed,
        "final_controlled_validation_passed": final_passed,
        "failed_checks": failed_checks,
        "threshold_tuning_performed": bool(
            blind.get("threshold_tuning_performed")
        ),
        "production_promoted": False,
        "model_activated": False,
        "response_automation_allowed": False,
        "real_firewall_blocking_enabled": False,
    }


def _v32_simulated_source_status(db: Session) -> dict[str, Any]:
    source = db.scalar(select(LogSource).where(LogSource.name == "lab-firewall-sim-1").limit(1))
    if source is None:
        return {
            "status": "not_run",
            "simulated_source_validated": False,
            "real_device_forwarding_validated": False,
            "source_name": "lab-firewall-sim-1",
            "message": "No no-hardware simulated source pilot has been run yet.",
        }
    source_id = int(source.id)
    raw_logs = int(db.scalar(select(func.count(RawLog.id)).where(RawLog.source_id == source_id)) or 0)
    normalized_logs = int(
        db.scalar(select(func.count(NormalizedLog.id)).join(RawLog).where(RawLog.source_id == source_id)) or 0
    )
    detection_runs = int(
        db.scalar(
            select(func.count(DetectionRun.id)).where(DetectionRun.details_json["source_id"].as_integer() == source_id)
        )
        or 0
    )
    health = source_health(source)
    validated = raw_logs >= 100 and normalized_logs > 0 and detection_runs > 0 and health["status"] in {"healthy", "warning"}
    return {
        "status": "validated" if validated else "review_required",
        "simulated_source_validated": validated,
        "real_device_forwarding_validated": False,
        "source_name": source.name,
        "source_health": health["status"],
        "raw_logs": raw_logs,
        "normalized_logs": normalized_logs,
        "parse_success_count": source.parse_success_count,
        "parse_failure_count": source.parse_failure_count,
        "detection_runs": detection_runs,
        "message": "No-hardware source pilot validates the ATDR source pipeline only; real device forwarding remains pending.",
    }


def _latest_v330_detection_ml_quality_summary(report_dir: Path = V13_REPORT_DIR) -> dict[str, Any]:
    summary, payload = _latest_reliability_file_summary(
        report_dir,
        "v3_30_detection_ml_quality_*.json",
        missing_message="No v3.30 detection/ML quality revalidation summary has been generated yet.",
    )
    if payload is None:
        return summary
    baseline = payload.get("baseline") or {}
    best = payload.get("best_profile") or {}
    best_summary = best.get("summary") or best
    calibration = payload.get("calibration") or {}
    readiness = payload.get("readiness") or {}
    safety = payload.get("safety") or {}
    return {
        **summary,
        "generated_at": payload.get("generated_at") or summary.get("generated_at"),
        "split": payload.get("split"),
        "model_type": payload.get("model_type"),
        "class_weight": payload.get("class_weight"),
        "training_rows": baseline.get("training_rows"),
        "test_rows": baseline.get("test_rows"),
        "baseline_profile": baseline.get("profile"),
        "baseline_threat_positive_precision": (baseline.get("threat_positive") or {}).get("precision"),
        "baseline_threat_positive_recall": (baseline.get("threat_positive") or {}).get("recall"),
        "baseline_threat_positive_f1": (baseline.get("threat_positive") or {}).get("f1"),
        "baseline_benign_like_false_positive_rate": baseline.get("benign_like_false_positive_rate"),
        "baseline_suspicious_recall": (baseline.get("suspicious") or {}).get("recall"),
        "baseline_malicious_recall": (baseline.get("malicious") or {}).get("recall"),
        "baseline_macro_f1": baseline.get("macro_f1"),
        "baseline_weighted_f1": baseline.get("weighted_f1"),
        "best_profile": best.get("profile"),
        "best_threat_positive_precision": best_summary.get("threat_positive_precision"),
        "best_threat_positive_recall": best_summary.get("threat_positive_recall"),
        "best_threat_positive_f1": best_summary.get("threat_positive_f1"),
        "best_benign_like_false_positive_rate": best_summary.get("benign_like_false_positive_rate"),
        "best_suspicious_recall": best_summary.get("suspicious_recall"),
        "best_malicious_recall": best_summary.get("malicious_recall"),
        "best_review_queue_size_estimate": best_summary.get("review_queue_size_estimate"),
        "calibration_status": calibration.get("status") or "missing",
        "calibration_ece": calibration.get("expected_calibration_error"),
        "calibration_brier": calibration.get("brier_score_threat_positive"),
        "calibration_max_gap": calibration.get("max_confidence_accuracy_gap"),
        "error_buckets": (payload.get("error_analysis") or {}).get("bucket_counts") or {},
        "top_patterns": (payload.get("error_analysis") or {}).get("top_patterns") or [],
        "signal_counts": (payload.get("detection_signal_comparison") or {}).get("counts") or {},
        "review_sample": payload.get("review_sample") or {},
        "readiness_decision": readiness.get("decision") or "candidate_only",
        "checks_passed": int(readiness.get("passed") or 0),
        "checks_total": int(readiness.get("total") or 0),
        "blockers": readiness.get("blockers") or [],
        "production_promoted": False,
        "model_activated": False,
        "response_automation_allowed": bool(safety.get("response_automation_allowed", False)),
        "real_firewall_blocking_enabled": bool(safety.get("real_firewall_blocking_enabled", False)),
        "diagnostic_only": True,
    }


def _latest_v355_soc_queue_summary(report_dir: Path = V13_REPORT_DIR) -> dict[str, Any]:
    summary, payload = _latest_reliability_file_summary(
        report_dir,
        "v3_55_severity_target_policy_reframing_latest.json",
        missing_message="No v3.55 SOC review-queue policy diagnostic has been generated yet.",
    )
    if payload is None:
        return summary
    best_strategy = payload.get("best_strategy")
    comparison = payload.get("strategy_comparison") or {}
    best = comparison.get(best_strategy) or {}
    stability = best.get("stability") or {}
    ranges = stability.get("metric_ranges") or {}
    calibration = best.get("best_calibration") or {}
    threshold_selection = best.get("threshold_selection") or {}
    readiness = payload.get("readiness") or {}
    safety = payload.get("safety") or {}
    policy = best.get("policy") or {}
    return {
        **summary,
        "phase": payload.get("phase") or "v3.55",
        "best_strategy": best_strategy,
        "policy_name": best.get("policy_name") or "binary_review_queue",
        "policy_description": policy.get("description"),
        "recommended_use": "diagnostic_soc_review_queue_score",
        "exact_severity_status": "explanation_or_ranking_only",
        "evaluated_splits": int(stability.get("evaluated_splits") or 0),
        "passing_splits": int(stability.get("passing_splits") or 0),
        "split_stability_passed": bool(stability.get("passed")),
        "queue_f1_min": (ranges.get("queue_f1") or {}).get("min"),
        "queue_f1_max": (ranges.get("queue_f1") or {}).get("max"),
        "queue_recall_min": (ranges.get("queue_recall") or {}).get("min"),
        "queue_precision_min": (ranges.get("queue_precision") or {}).get("min"),
        "benign_like_false_positive_rate_max": (ranges.get("benign_like_false_positive_rate") or {}).get("max"),
        "critical_recall_min": (ranges.get("critical_recall_min") or {}).get("min"),
        "macro_f1_min": (ranges.get("macro_f1") or {}).get("min"),
        "weighted_f1_min": (ranges.get("weighted_f1") or {}).get("min"),
        "calibration_status": calibration.get("status") or "missing",
        "calibration_ece": calibration.get("expected_calibration_error"),
        "calibration_brier": calibration.get("brier_score_threat_positive"),
        "calibration_max_gap": calibration.get("max_confidence_accuracy_gap"),
        "threshold_selected_on": threshold_selection.get("selected_on") or [],
        "readiness_decision": readiness.get("decision") or "candidate_only",
        "checks_passed": int(readiness.get("passed") or 0),
        "checks_total": int(readiness.get("total") or 0),
        "blockers": readiness.get("blockers") or [],
        "production_promoted": False,
        "model_activated": False,
        "model_artifact_written": bool(safety.get("model_artifact_written", False)),
        "labels_written": bool(safety.get("labels_written", False)),
        "response_automation_allowed": bool(safety.get("response_automation_allowed", False)),
        "diagnostic_only": True,
        "message": "Stable SOC review-queue diagnostic only; exact severity is not activated as a hard model decision.",
    }


def _latest_v357_queue_evidence_agreement_summary(report_dir: Path = V13_REPORT_DIR) -> dict[str, Any]:
    summary, payload = _latest_reliability_file_summary(
        report_dir,
        "v3_57_queue_rule_hybrid_agreement_latest.json",
        missing_message="No v3.57 queue-vs-rule/hybrid agreement diagnostic has been generated yet.",
    )
    if payload is None:
        return summary
    aggregate = payload.get("aggregate") or {}
    readiness = payload.get("readiness") or {}
    safety = payload.get("safety") or {}
    return {
        **summary,
        "phase": payload.get("phase") or "v3.57",
        "policy_name": payload.get("policy_name") or "binary_review_queue",
        "recommended_use": "diagnostic_queue_rule_hybrid_agreement_review",
        "evaluated_splits": int(aggregate.get("evaluated_splits") or 0),
        "passing_splits": int(aggregate.get("passing_splits") or 0),
        "queue_f1_min": aggregate.get("queue_f1_min"),
        "queue_recall_min": aggregate.get("queue_recall_min"),
        "queue_precision_min": aggregate.get("queue_precision_min"),
        "queue_false_positive_rate_max": aggregate.get("queue_false_positive_rate_max"),
        "agreement_rate_min": aggregate.get("agreement_rate_min"),
        "agreement_rate_max": aggregate.get("agreement_rate_max"),
        "calibration_ece_max": aggregate.get("calibration_ece_max"),
        "category_counts": aggregate.get("category_counts") or {},
        "top_queue_only_patterns": aggregate.get("top_queue_only_patterns") or [],
        "top_evidence_only_patterns": aggregate.get("top_evidence_only_patterns") or [],
        "aggregate_blockers": aggregate.get("blockers") or [],
        "readiness_decision": readiness.get("decision") or "diagnostic_only",
        "checks_passed": int(readiness.get("passed") or 0),
        "checks_total": int(readiness.get("total") or 0),
        "blockers": readiness.get("blockers") or [],
        "production_promoted": False,
        "model_activated": False,
        "model_artifact_written": bool(safety.get("model_artifact_written", False)),
        "labels_written": bool(safety.get("labels_written", False)),
        "raw_logs_included": bool(safety.get("raw_logs_included", False)),
        "response_automation_allowed": bool(safety.get("response_automation_allowed", False)),
        "diagnostic_only": True,
        "message": "Queue-vs-evidence agreement is diagnostic only; disagreements need analyst review and do not activate response.",
    }


def _v30_production_readiness_summary(db: Session) -> dict[str, Any]:
    docs = {
        "gap_assessment": PROJECT_ROOT / "docs" / "V3_0_PRODUCTION_READINESS_GAP_ASSESSMENT.md",
        "real_device_pilot": PROJECT_ROOT / "docs" / "V3_0_REAL_DEVICE_SYSLOG_PILOT_PLAN.md",
        "postgres_lab": PROJECT_ROOT / "docs" / "V3_0_POSTGRESQL_LAB_DEPLOYMENT_VALIDATION.md",
        "postgres_shared_lab_readiness": PROJECT_ROOT / "docs" / "V3_3_POSTGRESQL_SHARED_LAB_READINESS.md",
        "backup_restore_retention": PROJECT_ROOT / "docs" / "V3_3_BACKUP_RESTORE_AND_RETENTION_PLAN.md",
        "observability": PROJECT_ROOT / "docs" / "V3_0_OBSERVABILITY_AND_OPERATIONS_PLAN.md",
        "ml_monitoring": PROJECT_ROOT / "docs" / "V3_0_REAL_SOURCE_ML_MONITORING_PLAN.md",
        "track": PROJECT_ROOT / "docs" / "V3_0_PRODUCTION_READINESS_TRACK.md",
        "v32_no_hardware": PROJECT_ROOT / "docs" / "V3_2_NO_HARDWARE_SOURCE_PILOT.md",
    }
    settings = get_settings()
    database_kind = "postgresql" if settings.database_url.startswith("postgresql") else "sqlite" if settings.database_url.startswith("sqlite") else "other"
    postgres_lab_status = "pending" if database_kind == "postgresql" else "blocked_by_environment"
    doctor = run_production_readiness_doctor()
    v32_status = _v32_simulated_source_status(db)
    v20 = _latest_v20_ai_summary(BENCHMARK_REPORT_DIR)
    readiness = readiness_gate_v9_production_readiness_track(
        final_controlled_validation_passed=bool(v20.get("final_controlled_validation_passed")),
        real_source_pilot_validated=False,
        postgres_lab_validated=False,
        no_hardware_source_pilot_validated=bool(v32_status["simulated_source_validated"]),
        real_device_forwarding_validated=False,
        backup_restore_validated=False,
        production_doctor_blockers=list(doctor.get("blockers") or []),
        production_doctor_warnings=list(doctor.get("warnings") or []),
        observability_plan_exists=docs["observability"].exists(),
        ml_monitoring_plan_exists=docs["ml_monitoring"].exists(),
        runbook_updated=(PROJECT_ROOT / "docs" / "LAB_RUNBOOK.md").exists()
        and (PROJECT_ROOT / "docs" / "DEPLOYMENT_GUIDE.md").exists(),
    )
    return {
        "available": True,
        "status": readiness["decision"],
        "version": readiness["version"],
        "checks_passed": readiness["passed"],
        "checks_total": readiness["total"],
        "production_ready": False,
        "production_readiness_claim": False,
        "production_promoted": False,
        "model_activated": False,
        "response_automation_allowed": False,
        "real_firewall_blocking_enabled": False,
        "real_source_pilot_validated": False,
        "real_device_forwarding_validated": False,
        "simulated_source_pilot_status": v32_status["status"],
        "simulated_source_validated": v32_status["simulated_source_validated"],
        "simulated_source": v32_status,
        "postgres_lab_validated": False,
        "postgres_lab_status": postgres_lab_status,
        "database_kind": database_kind,
        "sqlite_local_workflow_valid": database_kind == "sqlite",
        "backup_restore_validated": False,
        "backup_restore_status": "planned",
        "production_doctor_status": doctor["status"],
        "production_doctor_blockers": doctor["blockers"],
        "production_doctor_warnings": doctor["warnings"],
        "docs": {name: path.exists() for name, path in docs.items()},
        "message": readiness["message"],
    }


@router.get("/summary")
def dashboard_summary(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
) -> dict:
    return build_dashboard_summary_cached(db)


@router.get("/validation-summary")
def dashboard_validation_summary(
    db: Session = Depends(get_db),
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
    summary["v16_ai"] = _latest_v16_ai_summary(BENCHMARK_REPORT_DIR)
    summary["v17_ai"] = _latest_v17_ai_summary(BENCHMARK_REPORT_DIR)
    summary["v18_ai"] = _latest_v18_ai_summary(BENCHMARK_REPORT_DIR)
    summary["v19_ai"] = _latest_v19_ai_summary(BENCHMARK_REPORT_DIR)
    summary["v19b_ai"] = _latest_v19b_ai_summary(BENCHMARK_REPORT_DIR)
    summary["v20_ai"] = _latest_v20_ai_summary(BENCHMARK_REPORT_DIR)
    summary["v330_detection_ml_quality"] = _latest_v330_detection_ml_quality_summary(V13_REPORT_DIR)
    summary["v355_soc_queue"] = _latest_v355_soc_queue_summary(V13_REPORT_DIR)
    summary["v357_queue_evidence_agreement"] = _latest_v357_queue_evidence_agreement_summary(V13_REPORT_DIR)
    summary["v30_production_readiness"] = _v30_production_readiness_summary(db)
    return summary
