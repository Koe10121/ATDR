from pathlib import Path

import pandas as pd
from sqlalchemy import func, select

from atdr.app.db.models import MLModelRun, ResponseAction
from atdr.app.detection.v332_guard_validation import _load_base_dataset, _prepared_for_split
from atdr.app.detection.v337_evidence_feature_enrichment import enrich_v337_features
from atdr.app.detection.v340_suspicious_boundary_model import (
    _boundary_specs,
    _fit_boundary_candidate,
    apply_suspicious_boundary_overlay,
    run_v340_suspicious_boundary_model,
)
from atdr.tests.test_v331_noise_reduction import _seed_labels, _session


def _augmented_stub(row: dict) -> dict:
    return {"frame": pd.DataFrame([row])}


def test_v340_boundary_overlay_protects_low_signal_quic():
    augmented = _augmented_stub(
        {
            "v337_web_low_signal_flag": 1,
            "v337_utility_low_signal_flag": 0,
            "v337_rule_backed_allow_flag": 0,
            "v337_anomaly_signal_flag": 0,
            "v337_web_scan_context_flag": 0,
            "v337_incomplete_scan_context_flag": 0,
            "v337_unknown_scan_context_flag": 0,
            "v337_source_diversity_pressure": 1.0,
            "v337_repeated_service_flag": 0,
            "v337_behavior_evidence_strength": 0.4,
            "v337_benign_web_likelihood_score": 3.0,
        }
    )

    result = apply_suspicious_boundary_overlay(
        augmented,
        ["benign_like"],
        [{"benign_like": 0.01, "suspicious": 0.99}],
        [0],
        threshold=0.5,
        evidence_gate=True,
    )

    assert result == ["benign_like"]


def test_v340_boundary_overlay_raises_evidence_backed_scan_context():
    augmented = _augmented_stub(
        {
            "v337_web_low_signal_flag": 0,
            "v337_utility_low_signal_flag": 0,
            "v337_rule_backed_allow_flag": 0,
            "v337_anomaly_signal_flag": 0,
            "v337_web_scan_context_flag": 1,
            "v337_incomplete_scan_context_flag": 0,
            "v337_unknown_scan_context_flag": 0,
            "v337_source_diversity_pressure": 8.0,
            "v337_repeated_service_flag": 1,
            "v337_behavior_evidence_strength": 4.0,
            "v337_benign_web_likelihood_score": -1.0,
        }
    )

    result = apply_suspicious_boundary_overlay(
        augmented,
        ["benign_like"],
        [{"benign_like": 0.2, "suspicious": 0.8}],
        [0],
        threshold=0.5,
        evidence_gate=True,
    )

    assert result == ["suspicious"]


def test_v340_boundary_selection_uses_train_internal_calibration_only():
    with _session() as db:
        _seed_labels(db, rows_per_class=8)
        base = _load_base_dataset(db, min_samples=6)
        prepared = _prepared_for_split(base, split_mode="time", test_size=0.3)
        frame, meta = enrich_v337_features(prepared)
        augmented = {"frame": frame, **meta}
        spec = next(item for item in _boundary_specs() if item["name"] == "boundary_extra_trees_benign_protected")
        candidate = _fit_boundary_candidate(prepared, augmented, spec)

    assert candidate["status"] == "evaluated"
    selection = candidate["boundary_selection"]
    assert selection["selected_on"] == "train_internal_boundary_calibration"
    assert selection["used_test_for_boundary_selection"] is False
    assert selection["candidate_count"] > 0
    assert 0.1 <= selection["selected_threshold"] <= 0.9


def test_v340_suspicious_boundary_model_writes_reports_without_side_effects(tmp_path):
    with _session() as db:
        _seed_labels(db, rows_per_class=8)
        before_runs = db.scalar(select(func.count(MLModelRun.id)))
        before_responses = db.scalar(select(func.count(ResponseAction.id)))
        result = run_v340_suspicious_boundary_model(
            db,
            test_size=0.3,
            min_samples=6,
            output_dir=tmp_path,
        )
        after_runs = db.scalar(select(func.count(MLModelRun.id)))
        after_responses = db.scalar(select(func.count(ResponseAction.id)))

    assert result["ok"] is True
    assert result["status"] == "completed"
    assert result["readiness"]["decision"] == "candidate_only"
    assert result["safety"]["production_promoted"] is False
    assert result["safety"]["model_activated"] is False
    assert result["safety"]["model_artifact_written"] is False
    assert result["safety"]["response_automation_allowed"] is False
    assert result["safety"]["labels_written"] is False
    assert before_runs == after_runs == result["safety"]["ml_model_runs_after"]
    assert before_responses == after_responses == result["safety"]["response_actions_after"]
    assert Path(result["report_path"]).exists()
    assert Path(result["latest_summary_path"]).exists()

    report_text = Path(result["report_path"]).read_text(encoding="utf-8")
    assert "v3.40 Suspicious Boundary Model Redesign" in report_text
    assert "No labels were written" in report_text
