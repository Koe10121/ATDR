from pathlib import Path

from atdr.app.benchmarks.readiness import readiness_gate_v5






def test_readiness_gate_v5_rejects_weak_external_transfer():
    result = readiness_gate_v5(
        external_label_count=320,
        external_metrics={
            "threat_positive_f1": 0.7278,
            "threat_positive_recall": 0.7471,
            "benign_false_positive_rate": 0.3467,
        },
        calibration_status="weak",
        controlled_validations_passed=True,
        internal_benchmark_validated=True,
    )

    assert result["decision"] == "internal_benchmark_validated_candidate"
    assert result["external_benchmark_validated"] is False
    assert result["production_promoted"] is False
    assert result["model_activated"] is False
    assert result["response_automation_allowed"] is False






def test_generated_v16_outputs_are_ignored():
    gitignore = Path(".gitignore").read_text(encoding="utf-8")
    assert "demo_exports/" in gitignore
    assert "ml_baseline_reviews/" in gitignore
