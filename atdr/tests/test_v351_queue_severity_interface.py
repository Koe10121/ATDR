from pathlib import Path

from sqlalchemy import func, select

from atdr.app.db.models import MLLabel, MLModelRun, ResponseAction
from atdr.app.detection.v351_queue_severity_interface import (
    LOW_CONFIDENCE_TARGET,
    repair_interface_target,
    run_v351_queue_severity_interface,
)
from atdr.tests.test_v331_noise_reduction import _seed_labels, _session


def test_v351_low_confidence_variant_maps_queued_non_threat_to_explicit_review_class():
    row = {"evidence_strength": 0.5, "rule_backed": False, "anomaly_signal": False, "scan_context": False, "evidence_bucket": "low_context"}

    target = repair_interface_target("non_threat", row, variant="low_confidence_review_class")

    assert target == LOW_CONFIDENCE_TARGET


def test_v351_demote_variant_removes_queued_non_threat_from_downstream_severity():
    row = {"evidence_strength": 0.5, "rule_backed": False, "anomaly_signal": False, "scan_context": False, "evidence_bucket": "low_context"}

    target = repair_interface_target("non_threat", row, variant="demote_non_threat_from_queue")

    assert target is None


def test_v351_evidence_promote_variant_keeps_review_worthy_non_threat_as_unusual():
    strong_row = {
        "evidence_strength": 3.2,
        "rule_backed": False,
        "anomaly_signal": False,
        "scan_context": False,
        "evidence_bucket": "evidence_strength_only",
    }
    weak_row = {
        "evidence_strength": 0.2,
        "rule_backed": False,
        "anomaly_signal": False,
        "scan_context": False,
        "evidence_bucket": "low_context",
    }

    assert repair_interface_target("non_threat", strong_row, variant="evidence_promote_or_demote") == "unusual_needs_review"
    assert repair_interface_target("non_threat", weak_row, variant="evidence_promote_or_demote") is None


def test_v351_diagnostic_runs_without_side_effects(tmp_path):
    with _session() as db:
        _seed_labels(db, rows_per_class=8)
        before_labels = db.scalar(select(func.count(MLLabel.id)))
        before_runs = db.scalar(select(func.count(MLModelRun.id)))
        before_responses = db.scalar(select(func.count(ResponseAction.id)))
        result = run_v351_queue_severity_interface(
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
    assert result["variant_comparison"]
    assert result["best_variant"] in {row["variant"] for row in result["variant_comparison"]}
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
