import json
from pathlib import Path

from atdr.app.benchmarks.adapter import load_benchmark_csv
from atdr.app.benchmarks.readiness import readiness_gate_v4
from atdr.scripts.build_internal_ai_readiness_benchmark import (
    DEFAULT_MANIFEST,
    build_internal_ai_readiness_benchmark,
)
from atdr.scripts.run_v15_ai_readiness_validation import (
    run_v15_ai_readiness_validation,
)


def test_internal_benchmark_manifest_builds_safe_balanced_rows(tmp_path):
    output_path = tmp_path / "internal_benchmark.csv"
    result = build_internal_ai_readiness_benchmark(
        manifest_path=DEFAULT_MANIFEST,
        output_path=output_path,
    )
    records, summary = load_benchmark_csv(output_path)

    assert result["row_count"] == 240
    assert result["target_met"] is True
    assert result["private_raw_payloads_included"] is False
    assert result["model_activated"] is False
    assert result["response_automation_allowed"] is False
    assert len(records) == 240
    assert summary["mapping_errors"]
    labels = {record.label for record in records}
    assert {"benign_like", "suspicious", "malicious", "needs_context"} <= labels


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


def test_v15_final_report_generation_stays_candidate_only(tmp_path, monkeypatch):
    import atdr.scripts.run_v15_ai_readiness_validation as module

    benchmark_metrics = {
        "threat_positive_precision": 0.9,
        "threat_positive_recall": 0.9,
        "threat_positive_f1": 0.9,
        "benign_false_positive_rate": 0.1,
        "macro_f1": 0.82,
        "weighted_f1": 0.86,
        "per_class": {
            "benign_like": {"recall": 0.9},
            "suspicious": {"recall": 0.9},
            "malicious": {"recall": 0.65},
        },
    }
    monkeypatch.setattr(
        module,
        "compare_layered_benchmark_reliability",
        lambda **_kwargs: {
            "ok": True,
            "mode_results": [
                {
                    "mode": "hybrid",
                    "metrics": {
                        **benchmark_metrics,
                        "precision": 0.9,
                        "recall": 0.9,
                        "f1": 0.9,
                        "false_positives": 8,
                        "false_negatives": 9,
                        "suspicious_recall": 0.9,
                        "malicious_recall": 0.65,
                    },
                    "runtime_seconds": 0.1,
                }
            ],
            "safety": {"automatic_response_enabled": False},
        },
    )
    monkeypatch.setattr(
        module,
        "run_benchmark_ml_experiment",
        lambda **_kwargs: {
            "ok": True,
            "candidates": [
                {
                    "candidate_name": "hierarchical_two_stage_extra_trees",
                    "status": "evaluated",
                    "metrics": benchmark_metrics,
                    "model_activated": False,
                }
            ],
            "safety": {
                "model_activated": False,
                "automatic_response_enabled": False,
            },
        },
    )
    monkeypatch.setattr(
        module,
        "_latest_validation_status",
        lambda: {"passed": True, "checks": []},
    )
    monkeypatch.setattr(
        module,
        "_current_label_summary",
        lambda: {
            "latest_label_rows": 2672,
            "reviewed_label_count": 2235,
            "reviewed_label_distribution": {"malicious": 412},
        },
    )
    monkeypatch.setattr(
        module,
        "_load_json",
        lambda _path: {
            "best_profile": "malicious_recall_recovery",
            "best_metrics": {"threat_positive_f1": 0.9187},
            "selected_calibration": {"status": "passed"},
            "profiles": [],
        },
    )
    result = run_v15_ai_readiness_validation(
        manifest_path=DEFAULT_MANIFEST,
        benchmark_csv_path=tmp_path / "benchmark.csv",
        output_dir=tmp_path / "benchmark_outputs",
        final_output_dir=tmp_path / "final_outputs",
    )

    assert result["readiness_gate_v4"]["decision"] == "benchmark_validated_candidate"
    assert result["production_promoted"] is False
    assert result["model_activated"] is False
    assert result["response_automation_allowed"] is False
    assert Path(result["paths"]["final_markdown"]).exists()
    payload = json.loads(Path(result["paths"]["final_json"]).read_text(encoding="utf-8"))
    assert payload["readiness_gate_v4"]["production_promoted"] is False


def test_generated_benchmark_outputs_are_ignored():
    gitignore = Path(".gitignore").read_text(encoding="utf-8")
    assert "demo_exports/" in gitignore
    assert "ml_baseline_reviews/" in gitignore
