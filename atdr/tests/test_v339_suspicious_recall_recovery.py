from pathlib import Path
from types import SimpleNamespace

import pandas as pd
from sqlalchemy import func, select

from atdr.app.db.models import MLModelRun, ResponseAction
from atdr.app.detection.v332_guard_validation import _load_base_dataset, _prepared_for_split
from atdr.app.detection.v337_evidence_feature_enrichment import enrich_v337_features
from atdr.app.detection.v338_calibrated_threshold_search import _candidate_specs, _fit_candidate
from atdr.app.detection.v339_suspicious_recall_recovery import (
    _select_policy_on_calibration,
    apply_pattern_specific_suspicious_recall_floor,
    run_v339_suspicious_recall_recovery,
)
from atdr.tests.test_v331_noise_reduction import _seed_labels, _session


def _prepared_stub(log: SimpleNamespace | None = None) -> dict:
    return {
        "test_idx": [0],
        "test_logs": [
            log
            or SimpleNamespace(app="quic-base", action="allow", dst_port=443, is_anomaly=False, anomaly_score=0.0)
        ],
    }


def _augmented_stub(row: dict) -> dict:
    return {"frame": pd.DataFrame([row])}


def test_v339_recall_floor_does_not_raise_low_signal_quic():
    prepared = _prepared_stub()
    augmented = _augmented_stub(
        {
            "v337_traffic_family": "web_low_signal",
            "v337_web_low_signal_flag": 1,
            "v337_utility_low_signal_flag": 0,
            "v337_web_scan_context_flag": 0,
            "v337_incomplete_scan_context_flag": 0,
            "v337_unknown_scan_context_flag": 0,
            "v337_rule_backed_allow_flag": 0,
            "v337_anomaly_signal_flag": 0,
            "v337_repeated_service_flag": 0,
            "v337_behavior_evidence_strength": 0.5,
            "v337_source_diversity_pressure": 1.0,
            "v337_benign_web_likelihood_score": 3.0,
        }
    )

    result = apply_pattern_specific_suspicious_recall_floor(
        prepared,
        augmented,
        ["benign_like"],
        [{"suspicious": 0.35, "malicious": 0.02}],
        policy_name="scan_context_balanced",
    )

    assert result == ["benign_like"]


def test_v339_recall_floor_raises_scan_context_web_to_suspicious():
    prepared = _prepared_stub(SimpleNamespace(app="ssl", action="allow", dst_port=443, is_anomaly=False, anomaly_score=0.0))
    augmented = _augmented_stub(
        {
            "v337_traffic_family": "web_scan_context",
            "v337_web_low_signal_flag": 0,
            "v337_utility_low_signal_flag": 0,
            "v337_web_scan_context_flag": 1,
            "v337_incomplete_scan_context_flag": 0,
            "v337_unknown_scan_context_flag": 0,
            "v337_rule_backed_allow_flag": 0,
            "v337_anomaly_signal_flag": 0,
            "v337_repeated_service_flag": 1,
            "v337_behavior_evidence_strength": 3.2,
            "v337_source_diversity_pressure": 10.0,
            "v337_benign_web_likelihood_score": -1.0,
        }
    )

    result = apply_pattern_specific_suspicious_recall_floor(
        prepared,
        augmented,
        ["benign_like"],
        [{"suspicious": 0.09, "malicious": 0.04}],
        policy_name="scan_context_balanced",
    )

    assert result == ["suspicious"]


def test_v339_policy_selection_uses_train_internal_calibration_only():
    with _session() as db:
        _seed_labels(db, rows_per_class=8)
        base = _load_base_dataset(db, min_samples=6)
        prepared = _prepared_for_split(base, split_mode="time", test_size=0.3)
        frame, meta = enrich_v337_features(prepared)
        augmented = {"frame": frame, **meta}
        spec = next(
            item
            for item in _candidate_specs()
            if item["name"] == "three_class_v337_soc_queue_threshold_search_low_noise"
        )
        strategy = _fit_candidate(prepared, augmented, spec)

    selected = _select_policy_on_calibration(prepared, augmented, strategy)

    assert selected["selected_on"] == "train_internal_calibration"
    assert selected["used_test_for_policy_selection"] is False
    assert selected["candidate_count"] > 0
    assert selected["selected_policy"] in {"none", "scan_context_conservative", "scan_context_balanced", "unknown_incomplete_focus"}


def test_v339_suspicious_recall_recovery_writes_reports_without_side_effects(tmp_path):
    with _session() as db:
        _seed_labels(db, rows_per_class=8)
        before_runs = db.scalar(select(func.count(MLModelRun.id)))
        before_responses = db.scalar(select(func.count(ResponseAction.id)))
        result = run_v339_suspicious_recall_recovery(
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
    assert "v3.39 Pattern-Specific Suspicious Recall Recovery" in report_text
    assert "No labels were written" in report_text
