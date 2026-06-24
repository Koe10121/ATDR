from pathlib import Path

from sqlalchemy import func, select

from atdr.app.db.models import MLModelRun, ResponseAction
from atdr.app.detection.v332_guard_validation import _load_base_dataset, _prepared_for_split
from atdr.app.detection.v337_evidence_feature_enrichment import enrich_v337_features
from atdr.app.detection.v338_calibrated_threshold_search import (
    _candidate_specs,
    _fit_candidate,
    _map_labels,
    _select_thresholds,
    _split_train_calibration_indices,
    run_v338_calibrated_threshold_search,
)
from atdr.tests.test_v331_noise_reduction import _seed_labels, _session


def test_v338_train_internal_split_never_uses_test_rows():
    with _session() as db:
        _seed_labels(db, rows_per_class=8)
        base = _load_base_dataset(db, min_samples=6)
        prepared = _prepared_for_split(base, split_mode="time", test_size=0.3)

    target_values = _map_labels(prepared["y"], "flat")
    split = _split_train_calibration_indices(prepared, target_values)

    assert split["used_test_for_threshold_selection"] is False
    assert set(split["fit_idx"]).isdisjoint(split["calibration_idx"])
    assert set(split["fit_idx"]).isdisjoint(prepared["test_idx"])
    assert set(split["calibration_idx"]).isdisjoint(prepared["test_idx"])


def test_v338_threshold_selection_marks_train_internal_calibration():
    probability_rows = [
        {"benign": 0.8, "benign_unusual": 0.1, "needs_context": 0.1, "suspicious": 0.0, "malicious": 0.0},
        {"benign": 0.1, "benign_unusual": 0.1, "needs_context": 0.1, "suspicious": 0.6, "malicious": 0.1},
        {"benign": 0.1, "benign_unusual": 0.1, "needs_context": 0.1, "suspicious": 0.2, "malicious": 0.6},
        {"benign": 0.7, "benign_unusual": 0.2, "needs_context": 0.1, "suspicious": 0.0, "malicious": 0.0},
    ]
    prepared = {"imports": _load_base_dataset.__globals__["_optional_imports"]()}

    selected = _select_thresholds(
        prepared,
        y_true=["benign", "suspicious", "malicious", "benign_unusual"],
        probability_rows=probability_rows,
        target_mode="flat",
        fpr_budget=0.15,
    )

    assert selected["candidate_count"] > 0
    assert selected["selected_thresholds"]["threat_positive"] >= 0.3
    assert "threat_positive_f1" in selected["calibration_summary"]


def test_v338_candidate_fits_with_no_test_leakage_metadata():
    with _session() as db:
        _seed_labels(db, rows_per_class=8)
        base = _load_base_dataset(db, min_samples=6)
        prepared = _prepared_for_split(base, split_mode="time", test_size=0.3)
        frame, meta = enrich_v337_features(prepared)
        augmented = {"frame": frame, **meta}
        spec = next(
            item
            for item in _candidate_specs()
            if item["name"] == "flat_v337_extra_trees_strong_benign_threshold_search_low_noise"
        )
        result = _fit_candidate(prepared, augmented, spec)

    assert result["status"] == "evaluated"
    assert result["threshold_selection"]["used_test_for_threshold_selection"] is False
    assert result["threshold_selection"]["selected_on"] == "train_internal_calibration"
    assert result["threshold_selection"]["selection_fpr_budget"] == 0.05
    assert result["summary"]["benign_like_false_positive_rate"] is not None


def test_v338_calibrated_threshold_search_writes_reports_without_side_effects(tmp_path):
    with _session() as db:
        _seed_labels(db, rows_per_class=8)
        before_runs = db.scalar(select(func.count(MLModelRun.id)))
        before_responses = db.scalar(select(func.count(ResponseAction.id)))
        result = run_v338_calibrated_threshold_search(
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
    assert before_runs == after_runs == result["safety"]["ml_model_runs_after"]
    assert before_responses == after_responses == result["safety"]["response_actions_after"]
    assert Path(result["report_path"]).exists()
    assert Path(result["latest_summary_path"]).exists()

    best = result["strategy_comparison"][result["best_strategy"]]
    assert best["threshold_selection"]["used_test_for_threshold_selection"] is False
    report_text = Path(result["report_path"]).read_text(encoding="utf-8")
    assert "v3.38 Calibrated SOC Queue Threshold Search" in report_text
    assert "No model was activated" in report_text
