from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from atdr.app.detection import v548_manual_anchor_fixed_revalidation as v548


V549_VERSION = "v5.49-fixed-development-candidate-decision-v1"

METRIC_FIELDS = (
    "queue_precision",
    "queue_recall",
    "queue_f1",
    "threat_positive_precision",
    "threat_positive_recall",
    "threat_positive_f1",
    "benign_like_false_positive_rate",
    "suspicious_recall",
    "malicious_recall",
    "macro_f1",
    "weighted_f1",
    "review_queue_rate",
    "false_positive",
    "false_negative",
)

CALIBRATION_FIELDS = (
    "brier_score",
    "expected_calibration_error",
    "max_confidence_accuracy_gap",
)

REMAINING_SUPERVISED_PHASES = (
    "Obtain genuinely independent labeled evidence from a second physical source.",
    "Seal a new untouched future validation window before candidate access.",
    "Run one governed blind independent evaluation with duplicate-family isolation.",
    "Require separate human approval before any shadow candidate activation decision.",
)


class V549DecisionError(RuntimeError):
    pass


def _read_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError) as exc:
        raise V549DecisionError(
            "The private fixed-revalidation result failed integrity validation."
        ) from exc
    if not isinstance(payload, dict):
        raise V549DecisionError(
            "The private fixed-revalidation result failed integrity validation."
        )
    return payload


def _number(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _safety_projection() -> dict[str, bool]:
    return {
        "rules_alert_authoritative": True,
        "model_activated": False,
        "model_promoted": False,
        "active_artifact_written": False,
        "response_automation_allowed": False,
        "automatic_import_performed": False,
        "evaluation_labels_returned": False,
        "row_predictions_returned": False,
        "private_paths_returned": False,
        "fingerprints_returned": False,
        "secrets_exposed": False,
    }


def _expected_strategy_names() -> list[str]:
    return [
        str(spec["name"])
        for spec in v548.FIXED_CANDIDATE_STRATEGIES
    ]


def _validate_authority_invariants(result: dict[str, Any]) -> None:
    required_false = (
        "model_activated",
        "model_promoted",
        "active_artifact_written",
        "response_automation_allowed",
        "automatic_import_performed",
    )
    required_zero = (
        "labels_written",
        "model_runs_written",
        "detection_runs_written",
        "alerts_written",
        "response_actions_written",
    )
    if result.get("rules_alert_authoritative") is not True:
        raise V549DecisionError(
            "The fixed result does not preserve deterministic rule authority."
        )
    if any(bool(result.get(field)) for field in required_false):
        raise V549DecisionError(
            "The fixed result contains a forbidden authority-state mutation."
        )
    if any(int(result.get(field) or 0) != 0 for field in required_zero):
        raise V549DecisionError(
            "The fixed result contains a forbidden authoritative write."
        )


def _strategy_projection(row: dict[str, Any]) -> dict[str, Any]:
    metrics = row.get("metrics") or {}
    calibration = row.get("calibration") or {}
    gate = row.get("fixed_freeze_gate") or {}
    checks = {
        str(name): bool(value)
        for name, value in (gate.get("checks") or {}).items()
    }
    status = str(row.get("status") or "failed_closed")
    projected = {
        "name": str(row.get("name") or ""),
        "status": status,
        "model_type": row.get("model_type"),
        "target_mode": row.get("target_mode"),
        "calibration_method": row.get("applied_calibration_method"),
        "metrics": {
            field: metrics.get(field)
            for field in METRIC_FIELDS
        },
        "calibration": {
            field: calibration.get(field)
            for field in CALIBRATION_FIELDS
        },
        "fixed_gate": {
            "passed": bool(gate.get("passed")),
            "checks": checks,
            "failed_checks": sorted(
                name for name, passed in checks.items() if not passed
            ),
        },
    }
    if status != "evaluated":
        projected["failure_reason"] = str(
            row.get("reason") or "strategy evaluation failed closed"
        )
    return projected


def _leader(strategies: list[dict[str, Any]]) -> dict[str, Any] | None:
    evaluated = [row for row in strategies if row.get("status") == "evaluated"]
    return max(
        evaluated,
        key=lambda row: (
            int(bool((row.get("fixed_freeze_gate") or {}).get("passed"))),
            _number((row.get("metrics") or {}).get("queue_f1")),
            -_number(
                (row.get("metrics") or {}).get(
                    "benign_like_false_positive_rate"
                ),
                1.0,
            ),
        ),
        default=None,
    )


def build_fixed_candidate_decision(result: dict[str, Any]) -> dict[str, Any]:
    if (
        result.get("schema_version") != v548.V548_VERSION
        or result.get("status") != "fixed_development_revalidation_completed"
        or int(result.get("evaluation_execution_count") or 0) != 1
        or result.get("protocol_valid") is not True
        or result.get("review_closed") is not True
    ):
        raise V549DecisionError(
            "The fixed-revalidation completion contract is invalid."
        )
    _validate_authority_invariants(result)

    strategies = result.get("strategies")
    if not isinstance(strategies, list):
        raise V549DecisionError("The fixed strategy result set is unavailable.")
    expected_names = _expected_strategy_names()
    actual_names = [str(row.get("name") or "") for row in strategies]
    if actual_names != expected_names or len(set(actual_names)) != len(actual_names):
        raise V549DecisionError(
            "The fixed strategy result set does not match the locked protocol."
        )

    for row in strategies:
        if row.get("status") == "evaluated":
            gate = row.get("fixed_freeze_gate") or {}
            if gate.get("gates") != v548.FIXED_QUALITY_GATES:
                raise V549DecisionError(
                    "An evaluated strategy does not use the locked quality gates."
                )

    computed_leader = _leader(strategies)
    computed_name = computed_leader.get("name") if computed_leader else None
    if computed_name != result.get("diagnostic_leader"):
        raise V549DecisionError(
            "The stored diagnostic leader does not match the fixed ranking policy."
        )
    leader_passed = bool(
        computed_leader
        and (computed_leader.get("fixed_freeze_gate") or {}).get("passed")
    )
    if leader_passed != bool(result.get("leader_passed_fixed_gate")):
        raise V549DecisionError(
            "The stored fixed-gate decision is internally inconsistent."
        )

    projected = [_strategy_projection(row) for row in strategies]
    failed_checks = sorted(
        {
            check
            for row in projected
            for check in row["fixed_gate"]["failed_checks"]
        }
    )
    blockers = list(REMAINING_SUPERVISED_PHASES[:3])
    if not leader_passed:
        blockers.insert(
            0,
            "No fixed development strategy satisfies every predeclared quality gate.",
        )

    return {
        "version": V549_VERSION,
        "status": (
            "diagnostic_candidate_qualified"
            if leader_passed
            else "no_diagnostic_candidate"
        ),
        "evaluation_execution_count": 1,
        "strategy_count": len(projected),
        "evaluated_strategy_count": sum(
            row["status"] == "evaluated" for row in projected
        ),
        "strategies": projected,
        "diagnostic_candidate": computed_name if leader_passed else None,
        "diagnostic_candidate_qualified": leader_passed,
        "failed_gate_checks": failed_checks,
        "remaining_evidence_blockers": blockers,
        "remaining_supervised_phases": list(REMAINING_SUPERVISED_PHASES),
        "exact_next_action": (
            "Preserve this diagnostic candidate without activation and obtain "
            "a second-source untouched validation pack."
            if leader_passed
            else "Repair the failed development gates on new development evidence; "
            "do not reuse this evaluation partition for tuning."
        ),
        "lifecycle_state": "shadow_observation",
        "activation_allowed": False,
        **_safety_projection(),
    }


def get_public_v549_status(
    output_dir: Path = v548.V548_OUTPUT_DIR,
) -> dict[str, Any]:
    output_dir = Path(output_dir)
    upstream = v548.get_public_v548_status(output_dir)
    base = {
        "version": V549_VERSION,
        "evaluation_execution_count": int(
            upstream.get("evaluation_execution_count") or 0
        ),
        "lifecycle_state": "shadow_observation",
        "activation_allowed": False,
        **_safety_projection(),
    }
    if not bool((upstream.get("review") or {}).get("closed")):
        return {
            **base,
            "status": "blocked_review_incomplete",
            "diagnostic_candidate": None,
            "diagnostic_candidate_qualified": False,
            "exact_next_action": (
                "Complete and formally close genuine human review before the "
                "one-time fixed evaluation."
            ),
        }
    if not bool(
        (upstream.get("review") or {}).get("ready_for_fixed_revalidation")
    ):
        return {
            **base,
            "status": "blocked_class_support",
            "diagnostic_candidate": None,
            "diagnostic_candidate_qualified": False,
            "exact_next_action": (
                "The immutable human review lacks the predeclared class support; "
                "do not run the fixed evaluation."
            ),
        }
    result_path = output_dir / v548.V548_RESULT
    if not result_path.is_file():
        return {
            **base,
            "status": "ready_for_single_fixed_revalidation",
            "diagnostic_candidate": None,
            "diagnostic_candidate_qualified": False,
            "exact_next_action": (
                "Execute the immutable v5.48 development revalidation exactly once."
            ),
        }
    return build_fixed_candidate_decision(_read_json(result_path))
