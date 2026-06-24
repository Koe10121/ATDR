from pathlib import Path

import pandas as pd
from sqlalchemy import func, select

from atdr.app.db.models import MLModelRun, ResponseAction
from atdr.app.detection.v331_noise_reduction import _apply_low_signal_benign_guard
from atdr.app.detection.v332_guard_validation import run_v332_guard_validation
from atdr.tests.test_v331_noise_reduction import _seed_labels, _session


def test_v332_low_signal_guard_keeps_rule_bearing_quic_threat_prediction():
    prepared = {"test_idx": [0]}
    augmented = {
        "frame": pd.DataFrame(
            [
                {
                    "v331_quic_443_allow_no_rule_flag": 0,
                    "v331_quic_443_allow_with_rule_flag": 1,
                    "v331_benign_network_utility_no_rule_flag": 0,
                }
            ]
        )
    }

    predictions = _apply_low_signal_benign_guard(prepared, augmented, ["suspicious"])

    assert predictions == ["suspicious"]


def test_v332_guard_validation_writes_reports_without_side_effects(tmp_path):
    with _session() as db:
        _seed_labels(db, rows_per_class=12)
        before_runs = db.scalar(select(func.count(MLModelRun.id)))
        before_responses = db.scalar(select(func.count(ResponseAction.id)))
        result = run_v332_guard_validation(
            db,
            test_size=0.3,
            min_samples=6,
            review_limit=8,
            output_dir=tmp_path,
        )
        after_runs = db.scalar(select(func.count(MLModelRun.id)))
        after_responses = db.scalar(select(func.count(ResponseAction.id)))

    assert result["ok"] is True
    assert result["status"] == "completed"
    assert result["strategy"] == "flat_5class_extra_trees_current_with_low_signal_guard"
    assert result["profile"] == "threat_recall"
    assert result["stability"]["evaluated_splits"] >= 3
    assert result["best_calibration"]["status"] in {"passed", "weak", "unavailable"}
    assert result["readiness"]["decision"] == "candidate_only"
    assert result["safety"]["production_promoted"] is False
    assert result["safety"]["model_activated"] is False
    assert result["safety"]["model_artifact_written"] is False
    assert result["safety"]["response_automation_allowed"] is False
    assert before_runs == after_runs == result["safety"]["ml_model_runs_after"]
    assert before_responses == after_responses == result["safety"]["response_actions_after"]
    assert Path(result["validation_report_path"]).exists()
    assert Path(result["calibration_report_path"]).exists()
    assert Path(result["summary_path"]).exists()
    assert Path(result["latest_summary_path"]).exists()
    assert result["review_sample"]["import_ready"] is False

    validation_text = Path(result["validation_report_path"]).read_text(encoding="utf-8")
    calibration_text = Path(result["calibration_report_path"]).read_text(encoding="utf-8")
    assert "v3.32 Low-Signal Guard Independent Validation" in validation_text
    assert "Model activation: false" in validation_text
    assert "Response automation allowed: false" in validation_text
    assert "v3.32 Calibration Report" in calibration_text
