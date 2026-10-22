from pathlib import Path

from atdr.app.benchmarks.readiness import readiness_gate_v4




def test_readiness_gate_v4_is_benchmark_validated_but_never_promoted():
    result = readiness_gate_v4(
        benchmark_label_count=240,
        benchmark_label_distribution={
            "benign_like": 85,
            "suspicious": 55,
            "malicious": 85,
            "needs_context": 15,
        },
        benchmark_metrics={
            "threat_positive_f1": 0.91,
            "threat_positive_recall": 0.92,
            "benign_false_positive_rate": 0.08,
            "per_class": {
                "suspicious": {"recall": 0.9},
                "malicious": {"recall": 0.66},
            },
        },
        calibration_status="passed",
        controlled_validations_passed=True,
        response_automation_allowed=False,
    )

    assert result["decision"] == "benchmark_validated_candidate"
    assert result["benchmark_validated"] is True
    assert result["production_promoted"] is False
    assert result["model_activated"] is False
    assert result["response_automation_allowed"] is False
    assert result["advisory_metrics"]["malicious_recall_is_blocking"] is False




def test_generated_benchmark_outputs_are_ignored():
    gitignore = Path(".gitignore").read_text(encoding="utf-8")
    assert "demo_exports/" in gitignore
    assert "ml_baseline_reviews/" in gitignore
