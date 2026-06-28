import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from atdr.app.db.models import MLLabel, MLModelRun, ResponseAction
from atdr.app.detection.supervised_detector import TRAINABLE_LABELS
from atdr.app.detection.v330_detection_ml_quality import OUTPUT_DIR
from atdr.app.detection.v359_supervised_output_policy_contract import V359_LATEST
from atdr.app.detection.v362_supervised_training_target_contract import V362_LATEST
from atdr.scripts.validate_detection_quality import validate_detection_quality
from atdr.scripts.validate_rule_pack_contract import validate_rule_pack_contract


def _read_json(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def _db_counts(db: Session) -> dict[str, int]:
    return {
        "ml_labels": int(db.scalar(select(func.count(MLLabel.id))) or 0),
        "ml_model_runs": int(db.scalar(select(func.count(MLModelRun.id))) or 0),
        "response_actions": int(db.scalar(select(func.count(ResponseAction.id))) or 0),
    }


def _lightweight_training_diagnostics(db: Session) -> dict[str, Any]:
    total_label_rows = int(db.scalar(select(func.count(MLLabel.id))) or 0)
    trainable_label_rows = int(
        db.scalar(select(func.count(MLLabel.id)).where(MLLabel.label.in_(TRAINABLE_LABELS), MLLabel.log_id.is_not(None)))
        or 0
    )
    trainable_log_count = int(
        db.scalar(
            select(func.count(func.distinct(MLLabel.log_id))).where(
                MLLabel.label.in_(TRAINABLE_LABELS),
                MLLabel.log_id.is_not(None),
            )
        )
        or 0
    )
    reviewed_label_rows = int(db.scalar(select(func.count(MLLabel.id)).where(MLLabel.reviewed.is_(True))) or 0)
    weak_or_unreviewed_rows = total_label_rows - reviewed_label_rows
    return {
        "available": True,
        "mode": "lightweight_no_feature_generation",
        "total_label_rows": total_label_rows,
        "trainable_label_rows": trainable_label_rows,
        "trainable_log_count_estimate": trainable_log_count,
        "reviewed_label_rows": reviewed_label_rows,
        "weak_or_unreviewed_label_rows": weak_or_unreviewed_rows,
        "feature_generation_ran": False,
        "note": "The unified evaluator uses cheap counts by default so dashboard/CI checks do not trigger feature generation.",
    }


def _supervised_output_policy_summary(output_dir: Path) -> dict[str, Any]:
    path = output_dir / V359_LATEST
    payload = _read_json(path)
    if not payload:
        return {
            "available": False,
            "status": "missing",
            "path": str(path),
            "recommendation": "Run python -m atdr.scripts.run_v359_supervised_output_policy_contract --pretty.",
        }
    contract = payload.get("contract") or {}
    return {
        "available": True,
        "status": contract.get("decision") or "unknown",
        "path": str(path),
        "checks_passed": contract.get("checks_passed"),
        "checks_total": contract.get("checks_total"),
        "recommended_supervised_strategy": contract.get("recommended_supervised_strategy"),
        "exact_classification_policy": contract.get("exact_classification_policy"),
        "dashboard_guidance_ready": bool(contract.get("contract_ready_for_dashboard_guidance", False)),
        "runtime_activation_allowed": bool(contract.get("contract_ready_for_runtime_activation", False)),
        "blocked_uses": contract.get("blocked_uses") or [],
        "safety": {
            "production_promoted": bool((payload.get("safety") or {}).get("production_promoted", False)),
            "model_activated": bool((payload.get("safety") or {}).get("model_activated", False)),
            "model_artifact_written": bool((payload.get("safety") or {}).get("model_artifact_written", False)),
            "labels_written": bool((payload.get("safety") or {}).get("labels_written", False)),
            "response_automation_allowed": bool((payload.get("safety") or {}).get("response_automation_allowed", False)),
        },
    }


def _training_target_summary(output_dir: Path) -> dict[str, Any]:
    path = output_dir / V362_LATEST
    payload = _read_json(path)
    if not payload:
        return {
            "available": False,
            "status": "missing",
            "path": str(path),
            "recommendation": "Run python -m atdr.scripts.run_v362_supervised_training_target_contract --pretty.",
        }
    contract = payload.get("contract") or {}
    return {
        "available": True,
        "status": contract.get("decision") or "unknown",
        "path": str(path),
        "checks_passed": contract.get("checks_passed"),
        "checks_total": contract.get("checks_total"),
        "recommended_training_target": contract.get("recommended_training_target"),
        "exact_label_policy": contract.get("exact_label_policy"),
        "runtime_activation_allowed": bool(contract.get("runtime_activation_allowed", False)),
        "production_promotion_allowed": bool(contract.get("production_promotion_allowed", False)),
        "response_automation_allowed": bool(contract.get("response_automation_allowed", False)),
        "quality_warnings": contract.get("quality_warnings") or [],
        "safety": {
            "production_promoted": bool((payload.get("safety") or {}).get("production_promoted", False)),
            "model_activated": bool((payload.get("safety") or {}).get("model_activated", False)),
            "model_artifact_written": bool((payload.get("safety") or {}).get("model_artifact_written", False)),
            "labels_written": bool((payload.get("safety") or {}).get("labels_written", False)),
            "response_automation_allowed": bool((payload.get("safety") or {}).get("response_automation_allowed", False)),
        },
    }


def _scenario_quality_summary(
    *,
    include_scenarios: bool,
    scenarios: list[str] | None,
    use_ml: bool,
) -> dict[str, Any]:
    if not include_scenarios:
        return {
            "included": False,
            "status": "skipped",
            "recommendation": "Use --include-scenarios for temporary-DB controlled detection quality validation.",
        }
    report = validate_detection_quality(scenarios=scenarios, use_ml=use_ml)
    return {
        "included": True,
        "status": "passed" if report.get("ok") else "failed",
        "ok": bool(report.get("ok")),
        "use_ml": bool(report.get("use_ml")),
        "scenario_count": report.get("scenario_count"),
        "passed_count": report.get("passed_count"),
        "expected_alerts": report.get("expected_alerts"),
        "actual_alerts": report.get("actual_alerts"),
        "false_positive_scenario_count": report.get("false_positive_scenario_count"),
        "false_negative_scenario_count": report.get("false_negative_scenario_count"),
        "unexpected_attack_type_count": report.get("unexpected_attack_type_count"),
        "alerts_created": report.get("alerts_created"),
        "alerts_deduplicated": report.get("alerts_deduplicated"),
        "raw_logs_imported": report.get("raw_logs_imported"),
        "normalized_logs_created": report.get("normalized_logs_created"),
        "parse_failures": report.get("parse_failures"),
        "parser_warning_count": report.get("parser_warning_count"),
        "raw_fallback_count": report.get("raw_fallback_count"),
        "explanation_completeness_score": report.get("explanation_completeness_score"),
        "response_actions_created": report.get("response_actions_created"),
        "no_automatic_response_confirmed": report.get("no_automatic_response_confirmed"),
        "failed_scenarios": [item["scenario"] for item in report.get("scenarios", []) if not item.get("passed")],
        "safety": report.get("safety") or {},
    }


def _required_checks(
    *,
    rule_contract: dict[str, Any],
    scenario_quality: dict[str, Any],
    before: dict[str, int],
    after: dict[str, int],
    supervised_policy: dict[str, Any],
    training_target: dict[str, Any],
) -> list[dict[str, Any]]:
    no_side_effects = before == after
    checks = [
        {
            "name": "rule pack and scenario corpus contract passes",
            "required": True,
            "passed": bool(rule_contract.get("ok")),
            "value": rule_contract.get("issues") or [],
        },
        {
            "name": "current database unchanged by unified evaluation",
            "required": True,
            "passed": no_side_effects,
            "value": {"before": before, "after": after},
        },
        {
            "name": "supervised output policy does not allow runtime activation",
            "required": True,
            "passed": supervised_policy.get("runtime_activation_allowed") is not True,
            "value": supervised_policy.get("runtime_activation_allowed"),
        },
        {
            "name": "training target does not allow production promotion",
            "required": True,
            "passed": training_target.get("production_promotion_allowed") is not True,
            "value": training_target.get("production_promotion_allowed"),
        },
        {
            "name": "response automation remains disabled",
            "required": True,
            "passed": (
                supervised_policy.get("response_automation_allowed") is not True
                and training_target.get("response_automation_allowed") is not True
            ),
            "value": {
                "supervised_policy": supervised_policy.get("response_automation_allowed"),
                "training_target": training_target.get("response_automation_allowed"),
            },
        },
        {
            "name": "supervised output policy artifact available",
            "required": False,
            "passed": bool(supervised_policy.get("available")),
            "value": supervised_policy.get("status"),
        },
        {
            "name": "safe training target artifact available",
            "required": False,
            "passed": bool(training_target.get("available")),
            "value": training_target.get("status"),
        },
    ]
    if scenario_quality.get("included"):
        checks.append(
            {
                "name": "controlled scenario quality passes",
                "required": True,
                "passed": bool(scenario_quality.get("ok")),
                "value": {
                    "passed_count": scenario_quality.get("passed_count"),
                    "scenario_count": scenario_quality.get("scenario_count"),
                    "failed_scenarios": scenario_quality.get("failed_scenarios"),
                },
            }
        )
    else:
        checks.append(
            {
                "name": "controlled scenario quality included",
                "required": False,
                "passed": False,
                "value": "skipped",
            }
        )
    return checks


def _readiness_decision(checks: list[dict[str, Any]], supervised_policy: dict[str, Any], training_target: dict[str, Any]) -> str:
    required_ok = all(item["passed"] for item in checks if item["required"])
    if not required_ok:
        return "needs_work"
    if supervised_policy.get("available") and training_target.get("available"):
        return "diagnostic_evaluation_passed"
    return "diagnostic_evaluation_passed_missing_optional_ml_artifacts"


def run_v372_unified_detection_ml_evaluation(
    db: Session,
    *,
    output_dir: str | Path = OUTPUT_DIR,
    include_scenarios: bool = False,
    scenarios: list[str] | None = None,
    use_ml: bool = False,
) -> dict[str, Any]:
    before = _db_counts(db)
    output_path = Path(output_dir)
    rule_contract = validate_rule_pack_contract()
    scenario_quality = _scenario_quality_summary(
        include_scenarios=include_scenarios,
        scenarios=scenarios,
        use_ml=use_ml,
    )
    supervised_policy = _supervised_output_policy_summary(output_path)
    training_target = _training_target_summary(output_path)
    training_diagnostics = _lightweight_training_diagnostics(db)
    after = _db_counts(db)
    checks = _required_checks(
        rule_contract=rule_contract,
        scenario_quality=scenario_quality,
        before=before,
        after=after,
        supervised_policy=supervised_policy,
        training_target=training_target,
    )
    readiness = {
        "decision": _readiness_decision(checks, supervised_policy, training_target),
        "required_checks_passed": sum(1 for item in checks if item["required"] and item["passed"]),
        "required_checks_total": sum(1 for item in checks if item["required"]),
        "advisory_checks_passed": sum(1 for item in checks if not item["required"] and item["passed"]),
        "advisory_checks_total": sum(1 for item in checks if not item["required"]),
        "blockers": [item["name"] for item in checks if item["required"] and not item["passed"]],
        "advisories": [item["name"] for item in checks if not item["required"] and not item["passed"]],
        "production_ready": False,
        "model_activation_allowed": False,
        "response_automation_allowed": False,
    }
    return {
        "ok": not readiness["blockers"],
        "phase": "v3.72",
        "status": "completed",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "read_only": True,
        "readiness": readiness,
        "checks": checks,
        "rule_contract": rule_contract,
        "scenario_quality": scenario_quality,
        "supervised_output_policy": supervised_policy,
        "training_target_contract": training_target,
        "training_data": training_diagnostics,
        "safety": {
            "current_database_mutated": before != after,
            "counts_before": before,
            "counts_after": after,
            "production_promoted": False,
            "model_activated": False,
            "model_artifact_written": False,
            "labels_written": before["ml_labels"] != after["ml_labels"],
            "response_actions_created": after["response_actions"] - before["response_actions"],
            "response_automation_allowed": False,
            "real_firewall_blocking_enabled": False,
            "raw_logs_included": False,
        },
    }
