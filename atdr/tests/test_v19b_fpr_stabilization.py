import json

from atdr.app.benchmarks.adapter import BenchmarkRecord
from atdr.app.benchmarks.readiness import (
    readiness_gate_v7b_fpr_stabilization,
)
from atdr.app.routers.dashboard import _latest_v19b_ai_summary


def _record(
    *,
    label: str = "needs_context",
    app: str = "unknown-tcp",
    action: str = "allow",
    port: int = 5500,
    source: str = "sensor-a",
    scenario: str = "scenario-a",
) -> BenchmarkRecord:
    normalized = {
        "timestamp": "2026-06-14T00:00:00Z",
        "source_name": source,
        "scenario": scenario,
        "src_ip": "10.0.0.10",
        "dst_ip": "192.0.2.10",
        "dst_port": port,
        "app": app,
        "action": action,
    }
    return BenchmarkRecord(
        row_number=1,
        raw={key: str(value) for key, value in normalized.items()},
        normalized=normalized,
        label=label,
        attack_type="unknown",
    )


def _row(
    *,
    prediction: str = "suspicious",
    rule_class: str = "benign_like",
    rule_score: float = 0.2,
    behavior_evidence=None,
) -> dict:
    probabilities = {
        "benign_like": 0.42,
        "suspicious": 0.4,
        "malicious": 0.18,
    }
    return {
        "prediction": prediction,
        "confidence": 0.42,
        "probabilities": probabilities,
        "probability_row": [0.42, 0.18, 0.4],
        "threat_probability": 0.58,
        "rule": {"suggested_class": rule_class, "score": rule_score},
        "anomaly": {"score": 0.2},
        "behavior_evidence": behavior_evidence,
    }


def _metrics(*, fpr: float = 0.09) -> dict:
    return {
        "threat_positive_precision": 0.91,
        "threat_positive_recall": 0.93,
        "threat_positive_f1": 0.92,
        "benign_false_positive_rate": fpr,
        "macro_f1": 0.90,
        "weighted_f1": 0.90,
        "false_positives": 22,
        "false_negatives": 17,
        "per_class": {
            "suspicious": {"recall": 0.95},
            "malicious": {"recall": 0.87},
        },
    }












def test_readiness_v7b_passes_without_promotion_activation_or_automation():
    result = readiness_gate_v7b_fpr_stabilization(
        independent_label_count=500,
        independent_metrics=_metrics(),
        calibration_status="passed",
        external_benchmark_passed=True,
        independent_overlap_passed=True,
        controlled_real_source_passed=True,
        controlled_validations_passed=True,
        performance_smoke_healthy=True,
        uses_source_or_scenario_identity=False,
        preserves_behavior_evidence=True,
        ambiguous_rows_routed_to_review=True,
    )

    assert result["version"] == "v7b"
    assert result["decision"] == "controlled_real_source_validated_candidate"
    assert result["passed"] == result["total"]
    assert result["production_promoted"] is False
    assert result["model_activated"] is False
    assert result["response_automation_allowed"] is False
    assert result["real_firewall_blocking_enabled"] is False


def test_v19b_dashboard_summary_reports_resolved_fpr_without_promotion(tmp_path):
    payload = {
        "ok": True,
        "generated_at": "2026-06-14T00:00:00Z",
        "independent_holdout": {
            "row_count": 500,
            "source_count": 6,
            "scenario_count": 16,
            "previous_holdout_overlap": {"exact_overlap_rows": 0},
        },
        "false_positive_analysis": {"minimum_reduction_needed": 1},
        "best_profile": {
            "profile": "independent_fpr_stabilized",
            "metrics": _metrics(),
            "calibration": {
                "status": "passed",
                "expected_calibration_error": 0.01,
                "brier_score_threat_positive": 0.06,
                "max_confidence_accuracy_gap": 0.08,
            },
            "calibration_method": "bucket_smoothing",
            "analyst_review_boundary_count": 15,
        },
        "before_after": {"false_positives_reduced": 15},
        "controlled_real_source_validation": {
            "available": True,
            "passed": True,
        },
        "readiness_gate_v7b": {
            "version": "v7b",
            "decision": "controlled_real_source_validated_candidate",
            "passed": 20,
            "total": 20,
            "independent_holdout_validated": True,
            "checks": [],
        },
    }
    path = (
        tmp_path
        / "v1_9b_independent_fpr_stabilization_20260614T000000Z.json"
    )
    path.write_text(json.dumps(payload), encoding="utf-8")

    result = _latest_v19b_ai_summary(tmp_path)

    assert result["best_profile"] == "independent_fpr_stabilized"
    assert result["fpr_blocker_resolved"] is True
    assert result["false_positives_reduced"] == 15
    assert result["analyst_review_boundary_count"] == 15
    assert result["production_promoted"] is False
    assert result["response_automation_allowed"] is False
