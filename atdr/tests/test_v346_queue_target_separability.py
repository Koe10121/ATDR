from pathlib import Path

import pandas as pd
from sqlalchemy import func, select

from atdr.app.db.models import MLLabel, MLModelRun, ResponseAction
from atdr.app.detection.v346_queue_target_separability import (
    _categorical_mix,
    _numeric_separability,
    run_v346_queue_target_separability,
)
from atdr.tests.test_v331_noise_reduction import _seed_labels, _session


def test_v346_categorical_mix_finds_ambiguous_queue_patterns():
    rows = [
        {"pattern": "app=ssl|action=allow|port=443", "queue_target": "non_threat"},
        {"pattern": "app=ssl|action=allow|port=443", "queue_target": "non_threat"},
        {"pattern": "app=ssl|action=allow|port=443", "queue_target": "needs_review"},
        {"pattern": "app=ssl|action=allow|port=443", "queue_target": "needs_review"},
        {"pattern": "app=unknown|action=deny|port=22", "queue_target": "needs_review"},
        {"pattern": "app=unknown|action=deny|port=22", "queue_target": "needs_review"},
    ]

    mixed = _categorical_mix(rows, "pattern", min_count=2)

    assert mixed[0]["value"] == "app=ssl|action=allow|port=443"
    assert mixed[0]["conflict_ratio"] == 0.5
    assert mixed[0]["non_threat"] == 2
    assert mixed[0]["needs_review"] == 2


def test_v346_numeric_separability_ranks_strong_separator():
    frame = pd.DataFrame(
        {
            "weak_feature": [1, 2, 1, 2, 1, 2],
            "strong_feature": [0, 1, 0, 10, 11, 12],
        }
    )
    rows = [
        {"index": 0, "queue_target": "non_threat"},
        {"index": 1, "queue_target": "non_threat"},
        {"index": 2, "queue_target": "non_threat"},
        {"index": 3, "queue_target": "needs_review"},
        {"index": 4, "queue_target": "needs_review"},
        {"index": 5, "queue_target": "needs_review"},
    ]

    ranked = _numeric_separability(frame, rows, ["weak_feature", "strong_feature"])

    assert ranked[0]["feature"] == "strong_feature"
    assert ranked[0]["effect_size"] > ranked[1]["effect_size"]


def test_v346_diagnostic_writes_reports_without_side_effects(tmp_path):
    with _session() as db:
        _seed_labels(db, rows_per_class=8)
        before_labels = db.scalar(select(func.count(MLLabel.id)))
        before_runs = db.scalar(select(func.count(MLModelRun.id)))
        before_responses = db.scalar(select(func.count(ResponseAction.id)))
        result = run_v346_queue_target_separability(
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
    assert result["assessment"]["decision"] == "diagnostic_only"
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

    report_text = Path(result["report_path"]).read_text(encoding="utf-8")
    assert "v3.46 Queue Target Separability" in report_text
    assert "diagnostic only" in report_text
