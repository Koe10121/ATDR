from pathlib import Path

import pandas as pd
from sqlalchemy import func, select

from atdr.app.db.models import MLLabel, MLModelRun, ResponseAction
from atdr.app.detection.v347_queue_target_repair_proposal import (
    propose_queue_target,
    run_v347_queue_target_repair_proposal,
)
from atdr.tests.test_v331_noise_reduction import _seed_labels, _session


def _row(values: dict):
    return pd.Series(values)


def test_v347_proposes_demotion_only_for_low_signal_review_queue_rows():
    proposed, reason = propose_queue_target(
        "needs_review",
        _row(
            {
                "v337_rule_backed_allow_flag": 0,
                "v337_anomaly_signal_flag": 0,
                "v337_web_scan_context_flag": 0,
                "v337_incomplete_scan_context_flag": 0,
                "v337_unknown_scan_context_flag": 0,
                "v337_low_signal_allow_flag": 1,
                "v337_web_low_signal_flag": 1,
                "v337_utility_low_signal_flag": 0,
                "v337_behavior_evidence_strength": 0.3,
                "v337_benign_web_likelihood_score": 2.0,
                "v337_traffic_family": "web_low_signal",
            }
        ),
    )

    assert proposed == "non_threat"
    assert reason == "propose_demote_low_signal_web_or_utility"


def test_v347_preserves_strong_evidence_needs_review_rows():
    proposed, reason = propose_queue_target(
        "needs_review",
        _row(
            {
                "v337_rule_backed_allow_flag": 1,
                "v337_anomaly_signal_flag": 0,
                "v337_web_scan_context_flag": 0,
                "v337_incomplete_scan_context_flag": 0,
                "v337_unknown_scan_context_flag": 1,
                "v337_low_signal_allow_flag": 0,
                "v337_web_low_signal_flag": 0,
                "v337_utility_low_signal_flag": 0,
                "v337_behavior_evidence_strength": 4.4,
                "v337_benign_web_likelihood_score": -1.0,
                "v337_traffic_family": "unknown_scan_context",
            }
        ),
    )

    assert proposed == "needs_review"
    assert reason == "preserve_needs_review_strong_evidence"


def test_v347_proposes_promotion_for_strong_evidence_non_threat_rows():
    proposed, reason = propose_queue_target(
        "non_threat",
        _row(
            {
                "v337_rule_backed_allow_flag": 1,
                "v337_anomaly_signal_flag": 0,
                "v337_web_scan_context_flag": 0,
                "v337_incomplete_scan_context_flag": 0,
                "v337_unknown_scan_context_flag": 0,
                "v337_low_signal_allow_flag": 0,
                "v337_web_low_signal_flag": 0,
                "v337_utility_low_signal_flag": 0,
                "v337_behavior_evidence_strength": 3.5,
                "v337_benign_web_likelihood_score": -1.0,
                "v337_traffic_family": "web_rule_backed",
            }
        ),
    )

    assert proposed == "needs_review"
    assert reason == "propose_promote_strong_evidence_non_threat"


def test_v347_diagnostic_writes_proposals_without_side_effects(tmp_path):
    with _session() as db:
        _seed_labels(db, rows_per_class=8)
        before_labels = db.scalar(select(func.count(MLLabel.id)))
        before_runs = db.scalar(select(func.count(MLModelRun.id)))
        before_responses = db.scalar(select(func.count(ResponseAction.id)))
        result = run_v347_queue_target_repair_proposal(
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
    assert result["proposal_csv"]["import_ready"] is False
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
    assert "v3.47 Queue Target Repair" in report_text
    assert "diagnostic only" in report_text
