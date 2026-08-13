from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from atdr.app.core.config import Settings
from atdr.app.detection.v530_supervised_evidence_closure import (
    FIXED_PROMOTION_GATES,
    run_v530_supervised_evidence_closure,
)
from atdr.app.services.v524_investigation_gemini_quality_service import (
    _authoritative_counts,
)
from atdr.app.services.v533_independent_acceptance_service import (
    DEFAULT_ASSISTANT_MANIFEST_PATH,
    DEFAULT_ASSISTANT_REVIEW_PATH,
    run_v533_independent_detection_assistant_acceptance,
)


PROJECT_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_OUTPUT_DIR = PROJECT_ROOT / "ml_baseline_reviews"
V536_VERSION = "v5.36.0"
V536_LATEST = "v5_36_independent_evidence_activation_decision_latest.json"


def _stamp() -> str:
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")


def _number(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _gate(
    *,
    observed: Any,
    threshold: Any,
    passed: bool,
    evaluated: bool = True,
    source: str,
) -> dict[str, Any]:
    return {
        "evaluated": evaluated,
        "passed": bool(passed) if evaluated else False,
        "observed": observed if evaluated else None,
        "threshold": threshold,
        "source": source,
    }


def _calibration_projection(calibration: dict[str, Any]) -> dict[str, Any]:
    return {
        "status": calibration.get("status") or "withheld",
        "passed": bool(calibration.get("passed")),
        "brier_score": _number(calibration.get("brier_score")),
        "expected_calibration_error": _number(
            calibration.get("expected_calibration_error")
        ),
        "max_confidence_accuracy_gap": _number(
            calibration.get("max_confidence_accuracy_gap")
        ),
        "confidence_buckets_returned": False,
    }


def _layer_projection(layer: dict[str, Any]) -> dict[str, Any]:
    metrics = layer.get("metrics") or {}
    return {
        "rows": int(layer.get("rows") or 0),
        "queue_precision": _number(metrics.get("queue_precision")),
        "queue_recall": _number(metrics.get("queue_recall")),
        "queue_f1": _number(metrics.get("queue_f1")),
        "benign_like_false_positive_rate": _number(
            metrics.get("benign_like_false_positive_rate")
        ),
        "suspicious_recall": _number(metrics.get("suspicious_recall")),
        "malicious_recall": _number(metrics.get("malicious_recall")),
        "macro_f1": _number(metrics.get("macro_f1")),
        "weighted_f1": _number(metrics.get("weighted_f1")),
        "review_queue_size": int(metrics.get("review_queue_size") or 0),
        "review_queue_rate": _number(metrics.get("review_queue_rate")),
        "calibration": _calibration_projection(layer.get("calibration") or {}),
        "row_predictions_returned": False,
        "private_error_rows_returned": False,
    }


def _blind_evaluation_projection(detection: dict[str, Any]) -> dict[str, Any]:
    permitted = bool(detection.get("frozen_evaluation_permitted"))
    frozen = detection.get("frozen_metrics") if permitted else None
    calculated = bool(isinstance(frozen, dict) and frozen.get("metrics_calculated"))
    if not calculated:
        return {
            "status": "withheld_pending_legitimate_human_review",
            "metrics_calculated": False,
            "metrics_returned": False,
            "reason": (
                "Frozen predictions remain hidden until the sealed review contract "
                "has enough legitimate human decisions and both queue classes."
            ),
            "layers": {},
            "predictions_returned": False,
        }

    roles = {
        "rule": "deterministic_alert_baseline",
        "isolation": "isolation_forest_advisory",
        "supervised": "frozen_supervised_candidate",
        "hybrid": "frozen_hybrid_decision_support",
    }
    layers = frozen.get("layers") or {}
    return {
        "status": str(frozen.get("status") or "locked_blind_metrics_calculated"),
        "metrics_calculated": True,
        "metrics_returned": True,
        "rows": int(frozen.get("rows") or 0),
        "layers": {
            name: {
                "role": roles[name],
                **_layer_projection(layers[name]),
            }
            for name in roles
            if isinstance(layers.get(name), dict)
        },
        "predictions_returned": False,
        "review_tokens_returned": False,
        "private_error_rows_returned": False,
    }


def _diagnostic_slice_projection(item: dict[str, Any]) -> dict[str, Any]:
    projection = _layer_projection(item)
    projection.update(
        {
            "name": item.get("name"),
            "status": item.get("status"),
            "promotion_evidence": False,
        }
    )
    return projection


def _registered_shadow_projection(closure: dict[str, Any]) -> dict[str, Any]:
    registered = closure.get("registered_shadow_diagnostics") or {}
    if not registered.get("available"):
        return {
            "available": False,
            "status": registered.get("status") or "registered_shadow_unavailable",
            "promotion_evidence": False,
        }
    all_rows = registered.get("all_rows_diagnostic") or {}
    return {
        "available": True,
        "status": registered.get("status"),
        "registered_artifact_only": bool(registered.get("registered_artifact_only")),
        "rows_considered": int(registered.get("rows_considered") or 0),
        "source_identity_count": int(registered.get("source_identity_count") or 0),
        "distinct_calendar_days": int(registered.get("distinct_calendar_days") or 0),
        "training_overlap_status": registered.get("training_overlap_status"),
        "independent_validation": bool(registered.get("independent_validation")),
        "all_rows_diagnostic": _diagnostic_slice_projection(all_rows),
        "splits": [
            _diagnostic_slice_projection(item)
            for item in registered.get("splits") or []
            if isinstance(item, dict)
        ],
        "promotion_evidence": False,
        "row_predictions_returned": False,
        "source_identifiers_returned": False,
        "fingerprints_returned": False,
    }


def _quality_gates(blind: dict[str, Any]) -> dict[str, dict[str, Any]]:
    supervised = (blind.get("layers") or {}).get("supervised") or {}
    metrics_available = bool(blind.get("metrics_calculated") and supervised)
    calibration = supervised.get("calibration") or {}
    definitions = {
        "queue_f1": (
            supervised.get("queue_f1"),
            FIXED_PROMOTION_GATES["queue_f1_min"],
            "minimum",
        ),
        "threat_recall": (
            supervised.get("queue_recall"),
            FIXED_PROMOTION_GATES["threat_recall_min"],
            "minimum",
        ),
        "benign_like_false_positive_rate": (
            supervised.get("benign_like_false_positive_rate"),
            FIXED_PROMOTION_GATES["benign_like_false_positive_rate_max"],
            "maximum",
        ),
        "suspicious_recall": (
            supervised.get("suspicious_recall"),
            FIXED_PROMOTION_GATES["suspicious_recall_min"],
            "minimum",
        ),
        "malicious_recall": (
            supervised.get("malicious_recall"),
            FIXED_PROMOTION_GATES["malicious_recall_min"],
            "minimum",
        ),
        "expected_calibration_error": (
            calibration.get("expected_calibration_error"),
            FIXED_PROMOTION_GATES["expected_calibration_error_max"],
            "maximum",
        ),
        "max_confidence_accuracy_gap": (
            calibration.get("max_confidence_accuracy_gap"),
            FIXED_PROMOTION_GATES["max_confidence_accuracy_gap_max"],
            "maximum",
        ),
    }
    result: dict[str, dict[str, Any]] = {}
    for name, (value, threshold, direction) in definitions.items():
        numeric = _number(value)
        evaluated = metrics_available and numeric is not None
        passed = bool(
            evaluated
            and (
                numeric >= float(threshold)
                if direction == "minimum"
                else numeric <= float(threshold)
            )
        )
        result[name] = _gate(
            observed=numeric,
            threshold={direction: threshold},
            passed=passed,
            evaluated=evaluated,
            source="sealed_blind_frozen_supervised_predictions",
        )
    return result


def build_activation_decision(
    *,
    detection: dict[str, Any],
    closure: dict[str, Any],
    blind: dict[str, Any],
) -> dict[str, Any]:
    decision_counts = detection.get("decision_class_counts") or {}
    queue_positive = sum(
        int(decision_counts.get(label) or 0)
        for label in ("needs_context", "suspicious", "malicious")
    )
    non_threat = sum(
        int(decision_counts.get(label) or 0)
        for label in ("benign", "benign_unusual")
    )
    binary_minimum = min(queue_positive, non_threat)
    valid_human = int(detection.get("valid_human_decisions") or 0)
    source_count = int(detection.get("configured_label_source_identity_count") or 0)
    time_windows = int(detection.get("sanitized_time_window_count") or 0)
    duplicates = detection.get("duplicate_or_leakage_findings") or {}
    closure_readiness = closure.get("promotion_readiness") or {}
    closure_evidence = closure_readiness.get("evidence_checks") or {}
    lock_ok = bool(
        detection.get("prediction_before_label_integrity")
        and not detection.get("blindness_compromised")
        and not any(bool(value) for value in duplicates.values())
    )
    evidence_gates = {
        "blind_prediction_and_custody_integrity": _gate(
            observed=lock_ok,
            threshold=True,
            passed=lock_ok,
            source="v5.26-v5.28 sealed evidence contracts",
        ),
        "genuine_human_blind_labels": _gate(
            observed=valid_human,
            threshold={
                "minimum": FIXED_PROMOTION_GATES[
                    "minimum_independent_human_blind_labels"
                ]
            },
            passed=valid_human
            >= int(FIXED_PROMOTION_GATES["minimum_independent_human_blind_labels"]),
            source="v5.27 strict human-provenance validator",
        ),
        "independent_comparable_rows": _gate(
            observed=valid_human,
            threshold={
                "minimum": FIXED_PROMOTION_GATES[
                    "minimum_independent_comparable_rows"
                ]
            },
            passed=valid_human
            >= int(FIXED_PROMOTION_GATES["minimum_independent_comparable_rows"]),
            source="sealed blind review intake",
        ),
        "rows_per_binary_class": _gate(
            observed={
                "minimum_class_rows": binary_minimum,
                "needs_review": queue_positive,
                "non_threat": non_threat,
            },
            threshold={
                "minimum_each": FIXED_PROMOTION_GATES[
                    "minimum_rows_per_binary_class"
                ]
            },
            passed=binary_minimum
            >= int(FIXED_PROMOTION_GATES["minimum_rows_per_binary_class"]),
            source="sealed blind human decision distribution",
        ),
        "independent_real_source_identities": _gate(
            observed=source_count,
            threshold={
                "minimum": FIXED_PROMOTION_GATES["minimum_real_source_identities"]
            },
            passed=source_count
            >= int(FIXED_PROMOTION_GATES["minimum_real_source_identities"]),
            source="configured human-label source provenance",
        ),
        "independent_labeled_time_windows": _gate(
            observed=time_windows,
            threshold={
                "minimum": FIXED_PROMOTION_GATES["minimum_independent_time_windows"]
            },
            passed=valid_human > 0
            and time_windows
            >= int(FIXED_PROMOTION_GATES["minimum_independent_time_windows"]),
            source="sanitized sealed blind review chronology",
        ),
        "registered_artifact_integrity": _gate(
            observed=bool(closure_evidence.get("registered_shadow_artifact_integrity")),
            threshold=True,
            passed=bool(closure_evidence.get("registered_shadow_artifact_integrity")),
            source="v5.28 registered artifact contract",
        ),
        "schema_abstention_fails_closed": _gate(
            observed=bool(closure_evidence.get("schema_abstention_fails_closed")),
            threshold=True,
            passed=bool(closure_evidence.get("schema_abstention_fails_closed")),
            source="v5.28 schema compatibility contract",
        ),
        "training_overlap_independently_excluded": _gate(
            observed=(
                (closure.get("registered_shadow_diagnostics") or {}).get(
                    "training_overlap_status"
                )
            ),
            threshold="independently_excluded",
            passed=(
                (closure.get("registered_shadow_diagnostics") or {}).get(
                    "training_overlap_status"
                )
                == "independently_excluded"
            ),
            source="registered shadow diagnostic provenance audit",
        ),
    }
    quality_gates = _quality_gates(blind)
    evidence_passed = all(item["passed"] for item in evidence_gates.values())
    quality_passed = all(
        item["evaluated"] and item["passed"] for item in quality_gates.values()
    )
    eligible = bool(evidence_passed and quality_passed)
    blockers = [name for name, item in evidence_gates.items() if not item["passed"]]
    blockers.extend(
        name if item["evaluated"] else f"{name}_not_evaluable"
        for name, item in quality_gates.items()
        if not item["passed"]
    )
    return {
        "decision": (
            "eligible_for_separate_manual_activation_review"
            if eligible
            else "shadow_observation"
        ),
        "eligible_for_manual_activation_review": eligible,
        "model_activated": False,
        "model_promoted": False,
        "production_promoted": False,
        "response_automation_allowed": False,
        "rules_remain_alert_authoritative": True,
        "fixed_gates": dict(FIXED_PROMOTION_GATES),
        "gates_frozen_before_human_label_opening": True,
        "blind_pack_used_for_threshold_or_model_selection": False,
        "evidence_gates": evidence_gates,
        "quality_gates": quality_gates,
        "evidence_gates_passed": sum(item["passed"] for item in evidence_gates.values()),
        "evidence_gates_total": len(evidence_gates),
        "quality_gates_passed": sum(item["passed"] for item in quality_gates.values()),
        "quality_gates_evaluated": sum(
            item["evaluated"] for item in quality_gates.values()
        ),
        "quality_gates_total": len(quality_gates),
        "blockers": blockers,
        "activation_requires_separate_explicit_change": True,
    }


def _human_handoff() -> dict[str, Any]:
    return {
        "detection_review": {
            "working_copy": "ml_baseline_reviews/v5_28_blind_human_review_working.csv",
            "reviewer_guide": "docs/detection/V5_27_BLIND_REVIEWER_GUIDE.md",
            "prepare_command": (
                ".\\.venv\\Scripts\\python.exe -m "
                "atdr.scripts.run_v528_blind_review_helper --prepare --pretty"
            ),
            "review_command": (
                ".\\.venv\\Scripts\\python.exe -m "
                "atdr.scripts.run_v528_blind_review_helper --interactive "
                "--reviewer \"<institutional-id>\" --pretty"
            ),
            "status_command": (
                ".\\.venv\\Scripts\\python.exe -m "
                "atdr.scripts.run_v528_blind_review_helper --status --pretty"
            ),
            "minimum_valid_rows": int(
                FIXED_PROMOTION_GATES["minimum_independent_human_blind_labels"]
            ),
            "ai_or_automated_reviewer_allowed": False,
        },
        "assistant_review": {
            "working_copy": "ml_baseline_reviews/v5_33_assistant_human_acceptance_working.csv",
            "required_cases": 8,
            "rating_scale": "1-5",
            "required_human_decision": "accept, revise, or reject",
            "ai_or_automated_reviewer_allowed": False,
        },
        "generated_files_are_import_ready": False,
        "absolute_private_paths_returned": False,
    }


def render_v536_report(report: dict[str, Any]) -> str:
    review = report.get("detection_human_review") or {}
    activation = report.get("activation_decision") or {}
    assistant = report.get("assistant_human_acceptance") or {}
    gemini = report.get("gemini_operational_readiness") or {}
    lines = [
        "# v5.36 Independent Evidence Execution And Activation Decision",
        "",
        f"- Status: `{report.get('status')}`",
        f"- Detection human review: `{review.get('valid_human_decisions', 0)}/{review.get('total_rows', 0)}`",
        f"- Frozen detection metrics returned: `{report.get('blind_layer_evaluation', {}).get('metrics_returned')}`",
        f"- Supervised lifecycle: `{activation.get('decision')}`",
        f"- Model activated: `{activation.get('model_activated')}`",
        f"- Assistant human acceptance: `{assistant.get('valid_human_reviews', 0)}/{assistant.get('total_rows', 0)}`",
        f"- Gemini provider ready: `{gemini.get('provider_ready')}`",
        "- Rules remain alert-authoritative: `true`",
        "- Response automation enabled: `false`",
        "",
        "## Activation Blockers",
        "",
    ]
    lines.extend(f"- `{item}`" for item in activation.get("blockers") or [])
    lines.extend(
        [
            "",
            "## External Evidence Still Required",
            "",
        ]
    )
    lines.extend(f"- {item}" for item in report.get("external_actions_required") or [])
    return "\n".join(lines) + "\n"


def run_v536_independent_evidence_activation_decision(
    db: Session,
    *,
    settings: Settings,
    output_dir: Path = DEFAULT_OUTPUT_DIR,
    detection_review_path: Path | None = None,
    assistant_review_path: Path = DEFAULT_ASSISTANT_REVIEW_PATH,
    assistant_manifest_path: Path = DEFAULT_ASSISTANT_MANIFEST_PATH,
    execute_provider: bool = False,
    provider_interval_seconds: float = 0.0,
    write_reports: bool = True,
) -> dict[str, Any]:
    before = _authoritative_counts(db)
    acceptance = run_v533_independent_detection_assistant_acceptance(
        db,
        settings=settings,
        output_dir=output_dir,
        detection_review_path=detection_review_path,
        prepare_detection_review=False,
        assistant_review_path=assistant_review_path,
        assistant_manifest_path=assistant_manifest_path,
        prepare_assistant_review=False,
        execute_provider=execute_provider,
        provider_interval_seconds=max(0.0, provider_interval_seconds),
        write_reports=False,
    )
    closure = run_v530_supervised_evidence_closure(
        db,
        output_dir=output_dir,
        evaluate_registered_shadow=True,
        write_reports=False,
    )
    detection = acceptance.get("detection_human_review") or {}
    blind = _blind_evaluation_projection(detection)
    registered = _registered_shadow_projection(closure)
    activation = build_activation_decision(
        detection=detection,
        closure=closure,
        blind=blind,
    )
    after = _authoritative_counts(db)
    mutation_deltas = {name: after[name] - before[name] for name in before}
    unchanged = all(value == 0 for value in mutation_deltas.values())
    report = {
        "ok": bool(acceptance.get("ok") and closure.get("ok") and unchanged),
        "version": V536_VERSION,
        "generated_at": datetime.now(UTC).isoformat(),
        "status": (
            "v5_36_candidate_eligible_for_separate_manual_activation_review"
            if activation["eligible_for_manual_activation_review"]
            else "v5_36_activation_withheld"
        ),
        "evidence_integrity": {
            "sealed_blind_rows": int(detection.get("total_rows") or 0),
            "prediction_before_label_integrity": bool(
                detection.get("prediction_before_label_integrity")
            ),
            "blindness_compromised": bool(detection.get("blindness_compromised")),
            "duplicate_or_leakage_findings": detection.get(
                "duplicate_or_leakage_findings"
            )
            or {},
            "evidence_lock_audit_passed": (
                (closure.get("evidence_lock_audit") or {}).get("status") == "passed"
            ),
            "checksums_verified_not_returned": True,
            "row_identities_verified_not_returned": True,
            "schema_contract_verified": bool(
                activation["evidence_gates"]["schema_abstention_fails_closed"][
                    "passed"
                ]
            ),
            "prediction_values_returned": False,
            "fingerprints_returned": False,
        },
        "detection_human_review": detection,
        "blind_layer_evaluation": blind,
        "registered_shadow_diagnostics": registered,
        "activation_decision": activation,
        "assistant_automated_acceptance": acceptance.get(
            "assistant_automated_acceptance"
        )
        or {},
        "assistant_human_acceptance": acceptance.get("assistant_human_acceptance")
        or {},
        "gemini_operational_readiness": acceptance.get(
            "gemini_operational_readiness"
        )
        or {},
        "human_handoff": _human_handoff(),
        "external_actions_required": [
            "A genuine independent reviewer must complete the sealed detection working copy.",
            "A genuine reviewer must score all eight Assistant acceptance cases.",
            "A second verified physical log source is required for source-holdout evidence.",
            "MFU/provider owners must approve Gemini privacy, retention, quota, cost, and key rotation.",
            "Any future model activation requires a separate explicit reviewed change after every fixed gate passes.",
        ],
        "major_programs_remaining": {
            "count": 4,
            "programs": [
                "qualified blind detection review and sufficient independent labeled support",
                "second verified physical-source validation",
                "Assistant human acceptance and Gemini institutional operations approval",
                "MFU/shared-preproduction operational acceptance",
            ],
        },
        "configured_database_mutation_deltas": mutation_deltas,
        "safety": {
            "configured_database_unchanged": unchanged,
            "labels_created_or_updated": 0,
            "model_runs_created": 0,
            "model_artifacts_written": 0,
            "model_activated": False,
            "model_promoted": False,
            "alerts_created": 0,
            "detection_runs_created": 0,
            "response_actions_created": 0,
            "users_created_or_updated": 0,
            "assistant_actions_executed": 0,
            "automatic_response_enabled": False,
            "real_firewall_blocking_enabled": False,
            "rules_remain_alert_authoritative": True,
            "blind_pack_used_for_tuning": False,
            "raw_logs_sent_to_provider": False,
            "secrets_exposed": False,
            "private_absolute_paths_returned": False,
            "row_predictions_returned": False,
        },
        "private_identifiers_returned": False,
        "reviewer_identities_returned": False,
        "fingerprints_returned": False,
        "secrets_exposed": False,
    }
    if write_reports:
        output_dir.mkdir(parents=True, exist_ok=True)
        serialized = json.dumps(report, indent=2, sort_keys=True, default=str)
        (output_dir / V536_LATEST).write_text(serialized, encoding="utf-8")
        stamp = _stamp()
        (output_dir / f"v5_36_independent_evidence_activation_decision_{stamp}.json").write_text(
            serialized,
            encoding="utf-8",
        )
        (output_dir / f"v5_36_independent_evidence_activation_decision_{stamp}.md").write_text(
            render_v536_report(report),
            encoding="utf-8",
        )
    return report
