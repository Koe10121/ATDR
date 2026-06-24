from pathlib import Path

from sqlalchemy import func, select

from atdr.app.db.models import MLModelRun, ResponseAction
from atdr.app.detection.v334_soc_queue_redesign import run_v334_soc_queue_model_redesign
from atdr.tests.test_v331_noise_reduction import _seed_labels, _session


def test_v334_soc_queue_redesign_writes_reports_without_side_effects(tmp_path):
    with _session() as db:
        _seed_labels(db, rows_per_class=10)
        before_runs = db.scalar(select(func.count(MLModelRun.id)))
        before_responses = db.scalar(select(func.count(ResponseAction.id)))
        result = run_v334_soc_queue_model_redesign(
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
    assert "flat_5class_extra_trees_v331_guard_baseline" in result["model_comparison"]
    assert "three_class_soc_queue_extra_trees" in result["model_comparison"]
    assert "binary_threat_positive_extra_trees" in result["model_comparison"]
    assert result["best_non_guard_strategy"]
    assert Path(result["report_path"]).exists()
    assert Path(result["stability_report_path"]).exists()
    assert Path(result["latest_summary_path"]).exists()

    report_text = Path(result["report_path"]).read_text(encoding="utf-8")
    assert "v3.34 SOC Queue Model Redesign" in report_text
    assert "No model was activated" in report_text


def test_v334_binary_candidate_is_marked_limited_exact_class_output(tmp_path):
    with _session() as db:
        _seed_labels(db, rows_per_class=8)
        result = run_v334_soc_queue_model_redesign(
            db,
            test_size=0.3,
            min_samples=6,
            output_dir=tmp_path,
        )

    binary = result["model_comparison"]["binary_threat_positive_extra_trees"]
    assert binary["limited_exact_class_output"] is True
    assert binary["target_modes"] == ["binary"]
