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
    return summary
