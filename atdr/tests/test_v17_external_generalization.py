import csv
import json
from datetime import datetime, timezone
from pathlib import Path

from atdr.app.benchmarks.adapter import BenchmarkRecord
from atdr.app.benchmarks.readiness import readiness_gate_v6_external_generalization
from atdr.scripts.run_v17_external_generalization import (
    _build_error_analysis,
    _profile_prediction,
    _write_review_sample,
    run_v17_external_generalization,
)


def _record(
    *,
    row_number: int = 2,
    label: str = "suspicious",
    attack_type: str = "policy_violation",
    app: str = "bittorrent",
    action: str = "allow",
    dst_port: int = 6881,
    scenario: str = "peer_to_peer_policy_violation",
) -> BenchmarkRecord:
    return BenchmarkRecord(
        row_number=row_number,
        raw={},
        normalized={
            "timestamp": datetime(2026, 4, 20, tzinfo=timezone.utc),
            "source_name": "holdout-edge-firewall",
            "scenario": scenario,
            "src_ip": "198.51.100.10",
            "dst_ip": "10.0.0.5",
            "src_port": 50000,
            "dst_port": dst_port,
            "protocol": "tcp",
            "action": action,
            "app": app,
            "bytes": 900,
            "packets": 5,
        },
        label=label,
        attack_type=attack_type,
    )


def test_v17_readiness_gate_blocks_external_validation_on_boundary_gaps():
    result = readiness_gate_v6_external_generalization(
        external_label_count=320,
        external_metrics={
            "threat_positive_f1": 0.8937,
            "threat_positive_recall": 0.8412,
            "benign_false_positive_rate": 0.0467,
            "per_class": {
                "suspicious": {"recall": 0.7875},
                "malicious": {"recall": 0.7222},
            },
        },
        calibration_status="weak",
        controlled_validations_passed=True,
        internal_benchmark_validated=True,
        overfitting_status="significant_generalization_gap",
    )

    assert result["decision"] == "internal_benchmark_validated_candidate"
    assert result["external_benchmark_validated"] is False
    assert result["production_promoted"] is False
    assert result["model_activated"] is False
    assert result["response_automation_allowed"] is False
    failed = {item["name"] for item in result["checks"] if not item["passed"]}
    assert "external_suspicious_recall" in failed
    assert "confidence_calibration" in failed
    assert "overfitting_gap_limited" in failed


def test_v17_profile_prediction_uses_boundary_rules_without_response():
    record = _record()
    prediction = _profile_prediction(
        record,
        {"benign_like": 0.7, "suspicious": 0.2, "malicious": 0.1},
        profile="suspicious_recall_external",
    )

    assert prediction["prediction"] == "suspicious"
    assert prediction["rule"]["suggested_class"] == "suspicious"
    assert prediction["hybrid_risk"] > 0


def test_v17_review_sample_has_importable_boundary_columns(tmp_path):
    records = [
        _record(row_number=2),
        _record(
            row_number=3,
            label="benign",
            attack_type="normal",
            app="unknown-udp",
            action="deny",
            dst_port=137,
            scenario="normal_blocked_background_noise",
        ),
    ]
    suspicious_prediction = {
        "prediction": "benign_like",
        "confidence": 0.55,
        "threat_probability": 0.48,
        "rule": {"label": "suspicious:0.72", "suggested_class": "suspicious", "reasons": ["policy signal"]},
        "anomaly": {"label": "anomaly:0.3", "reasons": ["rare app"]},
        "hybrid_risk": 0.63,
    }
    benign_prediction = {
        "prediction": "malicious",
        "confidence": 0.81,
        "threat_probability": 0.82,
        "rule": {"label": "benign_like:0.16", "suggested_class": "benign_like", "reasons": ["blocked background noise"]},
        "anomaly": {"label": "anomaly:0.2", "reasons": ["no high anomaly"]},
        "hybrid_risk": 0.72,
    }
    output_path = tmp_path / "review.csv"

    result = _write_review_sample(
        records=records,
        current_predictions=[suspicious_prediction, benign_prediction],
        best_predictions=[suspicious_prediction, benign_prediction],
        output_path=output_path,
        limit=10,
    )

    assert result["rows"] == 2
    with output_path.open("r", encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert {
        "review_dataset_kind",
        "review_import_workflow",
        "benchmark_row_id",
        "current_label",
        "expected_label",
        "model_prediction",
        "rule_signal",
        "anomaly_signal",
        "hybrid_risk",
        "human_review_decision",
        "human_review_note",
    }.issubset(rows[0].keys())
    assert rows[0]["review_dataset_kind"] == "external_holdout"
    assert rows[0]["review_import_workflow"] == "benchmark_review"
    assert rows[0]["human_review_decision"] == ""


def test_v17_error_analysis_summarizes_external_boundaries():
    records = [_record(), _record(row_number=3, label="benign", attack_type="normal")]
    current = [
        {"prediction": "benign_like", "rule": {"suggested_class": "suspicious"}},
        {"prediction": "malicious", "rule": {"suggested_class": "benign_like"}},
    ]
    best = [
        {"prediction": "suspicious", "rule": {"suggested_class": "suspicious"}},
        {"prediction": "benign_like", "rule": {"suggested_class": "benign_like"}},
    ]

    result = _build_error_analysis(
        records=records,
        current_predictions=current,
        best_predictions=best,
        best_profile="hybrid_external_balanced",
    )

    assert result["current_error_counts"]["suspicious_predicted_benign_like"] == 1
    assert result["current_error_counts"]["benign_predicted_malicious"] == 1
    assert "rule_supervised_hybrid_disagreement" in result


def test_v17_runner_writes_reports_without_activation(tmp_path, monkeypatch):
    import atdr.scripts.run_v17_external_generalization as module

    external_snapshot = tmp_path / "external_snapshot.json"
    external_snapshot.write_text("{}", encoding="utf-8")
    v16_path = tmp_path / "external_benchmark_validation.json"
    v16_path.write_text(
        json.dumps(
            {
                "external_snapshot": {"snapshot_path": str(external_snapshot)},
                "cross_dataset_candidate": {
                    "metrics": {
                        "threat_positive_f1": 0.72,
                        "benign_false_positive_rate": 0.34,
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    records = [_record(row_number=2), _record(row_number=3, label="benign", attack_type="normal")]
    profile_prediction = {
        "prediction": "suspicious",
        "confidence": 0.8,
        "threat_probability": 0.8,
        "rule": {"label": "suspicious:0.7", "suggested_class": "suspicious", "reasons": ["test"]},
        "anomaly": {"label": "anomaly:0.2", "reasons": ["test"]},
        "hybrid_risk": 0.7,
    }
    best = {
        "profile": "hybrid_external_balanced",
        "metrics": {
            "threat_positive_f1": 0.89,
            "threat_positive_recall": 0.84,
            "benign_false_positive_rate": 0.04,
            "per_class": {
                "suspicious": {"recall": 0.78},
                "malicious": {"recall": 0.72},
            },
        },
        "calibration": {"status": "weak"},
        "queue_size": 1,
        "cost_sensitive": {"total_cost": 1},
    }

    monkeypatch.setattr(module, "build_internal_ai_readiness_benchmark", lambda **_kwargs: {"ok": True})
    monkeypatch.setattr(
        module,
        "prepare_benchmark_dataset",
        lambda **_kwargs: {"snapshot_path": str(tmp_path / "internal.json")},
    )
    monkeypatch.setattr(
        module,
        "load_prepared_benchmark_snapshot",
        lambda path: (records, {"snapshot_id": Path(path).stem}),
    )
    monkeypatch.setattr(module, "_feature_frame", lambda *args, **kwargs: object())
    monkeypatch.setattr(
        module,
        "_run_profiles",
        lambda **_kwargs: {
            "profiles": [best],
            "best_profile": best,
            "predictions_by_profile": {
                "current_hybrid": [profile_prediction, profile_prediction],
                "hybrid_external_balanced": [profile_prediction, profile_prediction],
            },
        },
    )
    monkeypatch.setattr(
        module,
        "_overfitting_analysis",
        lambda **_kwargs: {
            "status": "significant_generalization_gap",
            "overfitting_warning": True,
        },
    )
    monkeypatch.setattr(module, "_latest_validation_status", lambda: {"passed": True})

    result = run_v17_external_generalization(
        external_report_path=v16_path,
        output_dir=tmp_path / "reports",
        review_output_dir=tmp_path / "reviews",
        review_limit=2,
    )

    assert result["ok"] is True
    assert Path(result["paths"]["json"]).exists()
    assert Path(result["paths"]["error_analysis_markdown"]).exists()
    assert Path(result["paths"]["review_sample_csv"]).exists()
    assert result["production_promoted"] is False
    assert result["model_activated"] is False
    assert result["response_automation_allowed"] is False
    assert result["readiness_gate_v6"]["external_benchmark_validated"] is False
