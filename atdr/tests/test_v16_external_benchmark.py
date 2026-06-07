import json
from pathlib import Path

from atdr.app.benchmarks.adapter import load_benchmark_csv
from atdr.app.benchmarks.readiness import readiness_gate_v5
from atdr.scripts.build_fixed_unseen_holdout import (
    DEFAULT_MANIFEST,
    build_fixed_unseen_holdout,
)
from atdr.scripts.prepare_external_benchmark_snapshot import (
    prepare_external_benchmark_snapshot,
)
from atdr.scripts.run_external_benchmark_validation import (
    _overfitting_analysis,
    run_external_benchmark_validation,
)


def test_fixed_unseen_holdout_is_separate_safe_and_large_enough(tmp_path):
    output_path = tmp_path / "external_unseen_holdout.csv"
    result = build_fixed_unseen_holdout(
        manifest_path=DEFAULT_MANIFEST,
        output_path=output_path,
    )
    records, summary = load_benchmark_csv(output_path)

    assert result["row_count"] == 320
    assert result["target_met"] is True
    assert result["label_distribution"] == {
        "benign_like": 120,
        "malicious": 90,
        "needs_context": 30,
        "suspicious": 80,
    }
    assert result["private_raw_payloads_included"] is False
    assert result["model_activated"] is False
    assert result["response_automation_allowed"] is False
    assert len(records) == 320
    assert len(result["source_distribution"]) == 5
    assert result["scenario_count"] == 14
    assert summary["total_rows"] == 320


def test_external_snapshot_from_approved_csv_stays_isolated(tmp_path):
    input_path = tmp_path / "approved.csv"
    build_fixed_unseen_holdout(
        manifest_path=DEFAULT_MANIFEST,
        output_path=input_path,
    )
    result = prepare_external_benchmark_snapshot(
        input_csv=input_path,
        output_dir=tmp_path / "snapshots",
    )

    assert result["source_kind"] == "external_csv"
    assert result["benchmark_label_count"] == 320
    assert result["minimum_target_met"] is True
    assert result["preferred_target_met"] is True
    assert result["private_raw_payloads_excluded"] is True
    assert result["training_contamination"] == "caller_controlled"
    assert result["model_activated"] is False
    assert result["response_automation_allowed"] is False


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


def test_overfitting_analysis_flags_material_transfer_gap():
    result = _overfitting_analysis(
        internal_metrics={
            "threat_positive_f1": 1.0,
            "threat_positive_recall": 1.0,
            "benign_false_positive_rate": 0.0,
            "per_class": {
                "benign_like": {"recall": 1.0},
                "suspicious": {"recall": 1.0},
                "malicious": {"recall": 1.0},
            },
        },
        external_metrics={
            "threat_positive_f1": 0.72,
            "threat_positive_recall": 0.74,
            "benign_false_positive_rate": 0.34,
            "per_class": {
                "benign_like": {"recall": 0.66},
                "suspicious": {"recall": 0.35},
                "malicious": {"recall": 0.89},
            },
        },
    )

    assert result["status"] == "significant_generalization_gap"
    assert result["overfitting_warning"] is True
    assert result["metric_gaps"]["threat_positive_f1"]["gap"] == 0.28
    assert result["class_recall_gaps"]["suspicious"]["gap"] == 0.65


def test_external_validation_report_never_activates_model(
    tmp_path,
    monkeypatch,
):
    import atdr.scripts.run_external_benchmark_validation as module

    external_snapshot = tmp_path / "external.json"
    internal_snapshot = tmp_path / "internal.json"
    external_snapshot.write_text("{}", encoding="utf-8")
    internal_snapshot.write_text("{}", encoding="utf-8")
    metrics = {
        "threat_positive_f1": 0.72,
        "threat_positive_recall": 0.74,
        "benign_false_positive_rate": 0.34,
        "per_class": {
            "benign_like": {"recall": 0.66},
            "suspicious": {"recall": 0.35},
            "malicious": {"recall": 0.89},
        },
    }
    monkeypatch.setattr(
        module,
        "prepare_external_benchmark_snapshot",
        lambda **_kwargs: {
            "ok": True,
            "source_kind": "fixed_safe_unseen_holdout",
            "snapshot_path": str(external_snapshot),
            "benchmark_label_count": 320,
            "profile": {"total_rows": 320},
        },
    )
    monkeypatch.setattr(
        module,
        "build_internal_ai_readiness_benchmark",
        lambda **_kwargs: {"ok": True},
    )
    monkeypatch.setattr(
        module,
        "prepare_benchmark_dataset",
        lambda **_kwargs: {
            "snapshot_path": str(internal_snapshot),
            "snapshot_id": "internal",
            "rows_selected": 240,
        },
    )
    monkeypatch.setattr(
        module,
        "compare_layered_benchmark_reliability",
        lambda **_kwargs: {
            "ok": True,
            "mode_results": [
                {"mode": "supervised_only", "metrics": metrics}
            ],
        },
    )
    monkeypatch.setattr(
        module,
        "_cross_dataset_candidate",
        lambda **_kwargs: {
            "ok": True,
            "candidate_name": "transfer_candidate",
            "holdout_rows": 320,
            "metrics": metrics,
            "calibration": {"status": "weak"},
            "model_artifact_written": False,
            "model_activated": False,
            "response_automation_allowed": False,
        },
    )
    monkeypatch.setattr(
        module,
        "_latest_json",
        lambda *_args, **_kwargs: {
            "best_benchmark_candidate": {
                "metrics": {
                    "threat_positive_f1": 1.0,
                    "threat_positive_recall": 1.0,
                    "benign_false_positive_rate": 0.0,
                    "per_class": {
                        "benign_like": {"recall": 1.0},
                        "suspicious": {"recall": 1.0},
                        "malicious": {"recall": 1.0},
                    },
                }
            },
            "readiness_gate_v4": {"benchmark_validated": True},
        },
    )
    monkeypatch.setattr(
        module,
        "_latest_validation_status",
        lambda: {"passed": True},
    )

    result = run_external_benchmark_validation(output_dir=tmp_path / "reports")

    assert result["readiness_gate_v5"]["external_benchmark_validated"] is False
    assert result["production_promoted"] is False
    assert result["model_activated"] is False
    assert result["model_artifact_written"] is False
    assert result["response_automation_allowed"] is False
    payload = json.loads(
        Path(result["paths"]["json"]).read_text(encoding="utf-8")
    )
    assert payload["model_activated"] is False
    assert payload["response_automation_allowed"] is False


def test_generated_v16_outputs_are_ignored():
    gitignore = Path(".gitignore").read_text(encoding="utf-8")
    assert "demo_exports/" in gitignore
    assert "ml_baseline_reviews/" in gitignore
