from pathlib import Path

from sqlalchemy import func, select

from atdr.app.db.models import MLLabel, MLModelRun, ResponseAction
from atdr.app.detection.v336_label_semantics import map_label_to_soc_target, run_v336_label_semantics_analysis
from atdr.tests.test_v331_noise_reduction import _seed_labels, _session


def test_v336_low_evidence_web_threat_maps_to_needs_review():
    evidence = {
        "low_evidence_web_like": True,
    }

    assert map_label_to_soc_target("suspicious", evidence, design="soc_queue_three_state") == "needs_review"
    assert map_label_to_soc_target("malicious", evidence, design="soc_queue_four_state") == "needs_review"


def test_v336_evidence_backed_threat_keeps_soc_threat_target():
    evidence = {
        "low_evidence_web_like": False,
    }

    assert (
        map_label_to_soc_target("suspicious", evidence, design="soc_queue_three_state")
        == "evidence_backed_threat"
    )
    assert map_label_to_soc_target("malicious", evidence, design="soc_queue_four_state") == "malicious_evidence"


def test_v336_label_semantics_analysis_writes_reports_without_side_effects(tmp_path):
    with _session() as db:
        _seed_labels(db, rows_per_class=8)
        before_labels = db.scalar(select(func.count(MLLabel.id)))
        before_runs = db.scalar(select(func.count(MLModelRun.id)))
        before_responses = db.scalar(select(func.count(ResponseAction.id)))
        result = run_v336_label_semantics_analysis(
            db,
            test_size=0.3,
            min_samples=6,
            sample_limit=10,
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
    assert before_labels == after_labels == result["safety"]["ml_labels_after"]
    assert before_runs == after_runs == result["safety"]["ml_model_runs_after"]
    assert before_responses == after_responses == result["safety"]["response_actions_after"]
    assert result["sample"]["import_ready"] is False
    assert Path(result["report_path"]).exists()
    assert Path(result["latest_summary_path"]).exists()

    report_text = Path(result["report_path"]).read_text(encoding="utf-8")
    assert "v3.36 Label Semantics and SOC Queue Target Redesign" in report_text
    assert "No labels were changed" in report_text
