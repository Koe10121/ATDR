
from atdr.app.benchmarks.readiness import (
    readiness_gate_v8_fresh_blind_validation,
)


def _metrics() -> dict:
    return {
        "threat_positive_precision": 0.89,
        "threat_positive_recall": 0.94,
        "threat_positive_f1": 0.91,
        "benign_false_positive_rate": 0.13,
        "macro_f1": 0.87,
        "weighted_f1": 0.88,
        "false_positives": 43,
        "false_negatives": 20,
        "confusion_matrix": [[287, 3, 40], [18, 171, 1], [2, 24, 154]],
        "per_class": {
            "suspicious": {"recall": 0.85},
            "malicious": {"recall": 0.9},
        },
    }










def test_readiness_v8_requires_blind_and_final_controlled_passes():
    result = readiness_gate_v8_fresh_blind_validation(
        candidate_lock_valid=True,
        fresh_blind_label_count=700,
        fresh_blind_source_count=7,
        fresh_blind_scenario_count=16,
        fresh_blind_metrics=_metrics(),
        calibration_status="passed",
        exact_overlap_passed=True,
        threshold_tuning_performed=False,
        uses_source_or_scenario_identity=False,
        controlled_real_source_passed=True,
        final_controlled_acceptance_passed=True,
        controlled_validations_passed=True,
        performance_smoke_healthy=True,
    )

    assert result["version"] == "v8"
    assert result["decision"] == "final_controlled_validation_candidate"
    assert result["fresh_blind_revalidated"] is True
    assert result["passed"] == result["total"]
    assert result["production_promoted"] is False
    assert result["model_activated"] is False
    assert result["response_automation_allowed"] is False


def test_readiness_v8_does_not_pass_blind_result_after_tuning():
    result = readiness_gate_v8_fresh_blind_validation(
        candidate_lock_valid=True,
        fresh_blind_label_count=700,
        fresh_blind_source_count=7,
        fresh_blind_scenario_count=16,
        fresh_blind_metrics=_metrics(),
        calibration_status="passed",
        exact_overlap_passed=True,
        threshold_tuning_performed=True,
        uses_source_or_scenario_identity=False,
        controlled_real_source_passed=True,
        final_controlled_acceptance_passed=True,
        controlled_validations_passed=True,
        performance_smoke_healthy=True,
    )

    assert result["fresh_blind_revalidated"] is False
    assert result["decision"] == "controlled_real_source_validated_candidate"
    assert result["production_promoted"] is False






