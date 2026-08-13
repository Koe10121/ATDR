from __future__ import annotations

import json

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from atdr.app.core.config import Settings
from atdr.app.db.database import Base
from atdr.app.services import v536_independent_evidence_activation_service as v536


def _settings() -> Settings:
    return Settings(
        _env_file=None,
        ASSISTANT_LLM_ENABLED=False,
        ASSISTANT_LLM_PROVIDER="disabled",
        ASSISTANT_LLM_MODEL="",
        ASSISTANT_LLM_API_KEY="private-test-key",
        ASSISTANT_ALLOW_RAW_LOG_CONTEXT=False,
        ASSISTANT_REDACT_IPS=True,
    )


def _detection(*, valid_rows: int = 0) -> dict[str, object]:
    reviewed = valid_rows > 0
    return {
        "total_rows": 40 if not reviewed else valid_rows,
        "valid_human_decisions": valid_rows,
        "incomplete_rows": 40 if not reviewed else 0,
        "invalid_decisions": 0,
        "decision_class_counts": (
            {"benign": valid_rows // 2, "suspicious": valid_rows // 2}
            if reviewed
            else {}
        ),
        "class_coverage_count": 2 if reviewed else 0,
        "sanitized_time_window_count": 2 if reviewed else 1,
        "configured_label_source_identity_count": 2 if reviewed else 1,
        "second_verified_real_device_available": reviewed,
        "duplicate_or_leakage_findings": {
            "prediction_tokens_duplicated": False,
            "review_tokens_duplicated": False,
            "cross_role_exact_overlap": False,
            "cross_role_near_overlap": False,
            "prediction_before_label_failed": False,
        },
        "blindness_compromised": False,
        "prediction_before_label_integrity": True,
        "frozen_evaluation_permitted": reviewed,
        "metrics_calculated": reviewed,
        "frozen_metrics": (
            {
                "status": "locked_blind_metrics_calculated_without_prediction_rerun",
                "metrics_calculated": True,
                "rows": valid_rows,
                "layers": {
                    name: {
                        "rows": valid_rows,
                        "metrics": {
                            "queue_precision": 0.94,
                            "queue_recall": 0.91,
                            "queue_f1": 0.92,
                            "benign_like_false_positive_rate": 0.03,
                            "suspicious_recall": 0.85,
                            "malicious_recall": 0.82,
                            "macro_f1": 0.91,
                            "weighted_f1": 0.91,
                            "review_queue_size": valid_rows // 2,
                            "review_queue_rate": 0.5,
                        },
                        "calibration": {
                            "status": "passed",
                            "passed": True,
                            "brier_score": 0.08,
                            "expected_calibration_error": 0.06,
                            "max_confidence_accuracy_gap": 0.10,
                            "confidence_buckets": [{"private_row": "must-not-return"}],
                        },
                    }
                    for name in ("rule", "isolation", "supervised", "hybrid")
                },
                "private_predictions": ["must-not-return"],
            }
            if reviewed
            else None
        ),
    }


def _closure(*, independent: bool = False) -> dict[str, object]:
    return {
        "ok": True,
        "evidence_lock_audit": {"status": "passed"},
        "promotion_readiness": {
            "evidence_checks": {
                "registered_shadow_artifact_integrity": True,
                "schema_abstention_fails_closed": True,
            }
        },
        "registered_shadow_diagnostics": {
            "available": True,
            "status": "registered_shadow_scored_read_only",
            "registered_artifact_only": True,
            "rows_considered": 1000,
            "source_identity_count": 2,
            "distinct_calendar_days": 2,
            "training_overlap_status": (
                "independently_excluded" if independent else "not_independently_excludable"
            ),
            "independent_validation": independent,
            "all_rows_diagnostic": {
                "name": "all_rows",
                "status": "evaluated_diagnostic_only",
                "rows": 1000,
                "metrics": {"queue_f1": 0.99},
                "calibration": {
                    "status": "passed",
                    "passed": True,
                    "confidence_buckets": [{"private": "must-not-return"}],
                },
                "row_predictions": ["must-not-return"],
            },
            "splits": [],
            "promotion_evidence": False,
        },
    }


def test_v536_withholds_blind_metrics_and_predictions_before_human_gate() -> None:
    projection = v536._blind_evaluation_projection(_detection(valid_rows=0))
    serialized = json.dumps(projection)
    assert projection["metrics_calculated"] is False
    assert projection["metrics_returned"] is False
    assert projection["layers"] == {}
    assert projection["predictions_returned"] is False
    assert "must-not-return" not in serialized


def test_v536_returns_only_aggregate_frozen_layer_metrics_after_valid_review() -> None:
    projection = v536._blind_evaluation_projection(_detection(valid_rows=1000))
    serialized = json.dumps(projection)
    assert projection["metrics_calculated"] is True
    assert set(projection["layers"]) == {"rule", "isolation", "supervised", "hybrid"}
    assert projection["layers"]["supervised"]["role"] == "frozen_supervised_candidate"
    assert projection["layers"]["supervised"]["queue_f1"] == 0.92
    assert projection["layers"]["supervised"]["calibration"]["confidence_buckets_returned"] is False
    assert "must-not-return" not in serialized


def test_v536_fixed_gates_can_only_recommend_separate_manual_activation_review() -> None:
    detection = _detection(valid_rows=1000)
    blind = v536._blind_evaluation_projection(detection)
    decision = v536.build_activation_decision(
        detection=detection,
        closure=_closure(independent=True),
        blind=blind,
    )
    assert decision["eligible_for_manual_activation_review"] is True
    assert decision["decision"] == "eligible_for_separate_manual_activation_review"
    assert decision["model_activated"] is False
    assert decision["model_promoted"] is False
    assert decision["response_automation_allowed"] is False
    assert decision["blind_pack_used_for_threshold_or_model_selection"] is False
    assert decision["activation_requires_separate_explicit_change"] is True


def test_v536_real_current_shape_fails_closed_on_missing_human_and_independence() -> None:
    detection = _detection(valid_rows=0)
    blind = v536._blind_evaluation_projection(detection)
    decision = v536.build_activation_decision(
        detection=detection,
        closure=_closure(independent=False),
        blind=blind,
    )
    assert decision["decision"] == "shadow_observation"
    assert decision["eligible_for_manual_activation_review"] is False
    assert decision["quality_gates_evaluated"] == 0
    assert "genuine_human_blind_labels" in decision["blockers"]
    assert "training_overlap_independently_excluded" in decision["blockers"]
    assert "queue_f1_not_evaluable" in decision["blockers"]


def test_v536_registered_shadow_is_diagnostic_and_strips_row_level_details() -> None:
    projection = v536._registered_shadow_projection(_closure(independent=False))
    serialized = json.dumps(projection)
    assert projection["promotion_evidence"] is False
    assert projection["independent_validation"] is False
    assert projection["all_rows_diagnostic"]["queue_f1"] == 0.99
    assert projection["all_rows_diagnostic"]["row_predictions_returned"] is False
    assert "must-not-return" not in serialized


def test_v536_coordinator_is_read_only_and_never_exposes_provider_secret(
    monkeypatch,
) -> None:
    acceptance = {
        "ok": True,
        "detection_human_review": _detection(valid_rows=0),
        "assistant_automated_acceptance": {
            "ok": True,
            "provider_contract_passed_rows": 8,
            "raw_logs_returned": False,
            "answers_returned": False,
        },
        "assistant_human_acceptance": {
            "ok": True,
            "total_rows": 8,
            "valid_human_reviews": 0,
            "human_acceptance_permitted": False,
            "answers_returned": False,
            "secrets_exposed": False,
        },
        "gemini_operational_readiness": {
            "provider": "gemini",
            "provider_ready": True,
            "secret_configured": True,
            "secrets_exposed": False,
            "raw_log_context_allowed": False,
        },
    }
    monkeypatch.setattr(
        v536,
        "run_v533_independent_detection_assistant_acceptance",
        lambda *args, **kwargs: acceptance,
    )
    monkeypatch.setattr(
        v536,
        "run_v530_supervised_evidence_closure",
        lambda *args, **kwargs: _closure(independent=False),
    )
    engine = create_engine("sqlite://", future=True)
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        report = v536.run_v536_independent_evidence_activation_decision(
            db,
            settings=_settings(),
            write_reports=False,
        )
    serialized = json.dumps(report)
    assert report["ok"] is True
    assert report["status"] == "v5_36_activation_withheld"
    assert all(value == 0 for value in report["configured_database_mutation_deltas"].values())
    assert report["safety"]["configured_database_unchanged"] is True
    assert report["safety"]["assistant_actions_executed"] == 0
    assert report["safety"]["raw_logs_sent_to_provider"] is False
    assert report["safety"]["model_activated"] is False
    assert report["human_handoff"]["detection_review"]["ai_or_automated_reviewer_allowed"] is False
    assert "private-test-key" not in serialized
