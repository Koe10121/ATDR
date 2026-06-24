from pathlib import Path

import pandas as pd
from sqlalchemy import func, select

from atdr.app.db.models import MLLabel, MLModelRun, ResponseAction
from atdr.app.detection.v348_repaired_queue_target_model import (
    _predict_queue,
    _select_threshold,
    queue_targets_for_mode,
    run_v348_repaired_queue_target_model,
)
from atdr.tests.test_v331_noise_reduction import _seed_labels, _session


def test_v348_queue_prediction_thresholding():
    predictions = _predict_queue(
        [{"needs_review": 0.9}, {"needs_review": 0.5}, {"needs_review": 0.1}],
        threshold=0.55,
    )

    assert predictions == ["needs_review", "non_threat", "non_threat"]


def test_v348_threshold_selection_uses_calibration_metrics_only():
    selected = _select_threshold(
        ["needs_review", "needs_review", "non_threat", "non_threat"],
        [{"needs_review": 0.9}, {"needs_review": 0.8}, {"needs_review": 0.2}, {"needs_review": 0.1}],
    )

    assert selected["selected_on"] == "train_internal_calibration"
    assert selected["used_test_for_threshold_selection"] is False
    assert selected["selected_threshold"] in {0.25, 0.35, 0.45, 0.55, 0.65, 0.75, 0.85, 0.95}


def test_v348_repaired_queue_target_changes_strong_evidence_non_threat():
    label = type("Label", (), {"label": "benign", "reviewed": True, "label_source": "manual"})()
    prepared = {"y": ["benign"], "labels": [label]}
    frame = pd.DataFrame(
        [
            {
                "v337_rule_backed_allow_flag": 1,
                "v337_anomaly_signal_flag": 0,
                "v337_behavior_evidence_strength": 3.5,
                "v337_benign_web_likelihood_score": -1.0,
                "v337_traffic_family": "web_rule_backed",
            }
        ]
    )

    original, original_meta = queue_targets_for_mode(prepared, frame, target_mode="original_queue_target")
    repaired, repaired_meta = queue_targets_for_mode(prepared, frame, target_mode="repaired_queue_target")

    assert original == ["non_threat"]
    assert original_meta["changed_rows"] == 0
    assert repaired == ["needs_review"]
    assert repaired_meta["changed_rows"] == 1


def test_v348_diagnostic_runs_without_side_effects(tmp_path):
    with _session() as db:
        _seed_labels(db, rows_per_class=8)
        before_labels = db.scalar(select(func.count(MLLabel.id)))
        before_runs = db.scalar(select(func.count(MLModelRun.id)))
        before_responses = db.scalar(select(func.count(ResponseAction.id)))
        result = run_v348_repaired_queue_target_model(
            db,
            test_size=0.3,
            min_samples=6,
            output_dir=tmp_path,
        )
        after_labels = db.scalar(select(func.count(MLLabel.id)))
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
    assert before_labels == after_labels == result["safety"]["ml_labels_after"]
    assert before_runs == after_runs == result["safety"]["ml_model_runs_after"]
    assert before_responses == after_responses == result["safety"]["response_actions_after"]
    assert Path(result["report_path"]).exists()
    assert Path(result["latest_summary_path"]).exists()
